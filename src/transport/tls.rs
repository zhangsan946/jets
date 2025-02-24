use crate::common::{new_io_error, Address, ConnectOpts, TcpStream, DEFAULT_CONTEXT};
use futures::ready;
use rustls::{ClientConfig, ClientConnection, KeyLogFile, RootCertStore};
use rustls_pki_types::ServerName;
use std::future::poll_fn;
use std::io::{BufRead, ErrorKind, Read, Result, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Debug)]
pub struct Tls {
    server_name: Option<String>,
    tls_config: ClientConfig,
}

impl Default for Tls {
    fn default() -> Self {
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        tls_config
            .alpn_protocols
            .extend([b"h2".to_vec(), b"http/1.1".to_vec()]);
        tls_config.key_log = Arc::new(KeyLogFile::new());
        //tls_config.max_fragment_size = Some(crate::common::DEFAULT_BUF_SIZE);
        Self {
            server_name: None,
            tls_config,
        }
    }
}

impl Tls {
    pub async fn connect(&self, addr: &Address, connect_opts: &ConnectOpts) -> Result<TlsStream> {
        let conn =
            TcpStream::connect_remote_with_opts(&DEFAULT_CONTEXT, addr, connect_opts).await?;
        let dnsname = if let Some(server_name) = &self.server_name {
            ServerName::try_from(server_name.to_owned()).map_err(new_io_error)?
        } else {
            ServerName::try_from(addr.host()).map_err(new_io_error)?
        };
        let session = ClientConnection::new(Arc::new(self.tls_config.to_owned()), dnsname)
            .map_err(new_io_error)?;
        let mut tls_stream = TlsStream::new(conn, session);
        poll_fn(|cx| tls_stream.handshake(cx)).await?;
        Ok(tls_stream)
    }
}

pub trait AsRawTcp {
    fn as_raw_tcp(&mut self) -> &mut TcpStream;
}

enum ReadState {
    ReadHead([u8; 5], usize),
    ReadBody(Vec<u8>, usize),
    RemainingBody(Vec<u8>, usize),
}

pub struct TlsStream {
    conn: TcpStream,
    session: ClientConnection,
    read_state: ReadState,
}

impl AsRawTcp for TlsStream {
    fn as_raw_tcp(&mut self) -> &mut TcpStream {
        &mut self.conn
    }
}

impl TlsStream {
    pub fn new(conn: TcpStream, session: ClientConnection) -> Self {
        Self {
            conn,
            session,
            read_state: ReadState::ReadHead([0u8; 5], 0),
        }
    }

    pub fn get_mut(&mut self) -> (&mut TcpStream, &mut ClientConnection) {
        (&mut self.conn, &mut self.session)
    }

    pub fn conn_read(&mut self, cx: &mut Context) -> Poll<Result<usize>> {
        let mut reader = SyncReadAdapter {
            io: &mut self.conn,
            cx,
            is_handshaking: self.session.is_handshaking(),
            read_state: &mut self.read_state,
        };

        let n = match self.session.read_tls(&mut reader) {
            Ok(n) => {
                if n == 0 {
                    return Poll::Ready(Err(std::io::Error::from(ErrorKind::UnexpectedEof)));
                }
                n
            }
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => return Poll::Pending,
            Err(err) => return Poll::Ready(Err(err)),
        };
        log::debug!("Tls read {} bytes encrypted data", n);
        let state = self
            .session
            .process_new_packets()
            .map_err(|err| std::io::Error::new(ErrorKind::InvalidData, err))?;
        log::debug!(
            "Tls has {} bytes plaintext to read, {} bytes plaintext to write",
            state.plaintext_bytes_to_read(),
            state.tls_bytes_to_write()
        );
        if state.plaintext_bytes_to_read() == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        Poll::Ready(Ok(n))
    }

    pub fn conn_write(&mut self, cx: &mut Context) -> Poll<Result<usize>> {
        let mut writer = SyncWriteAdapter {
            io: &mut self.conn,
            cx,
        };

        match self.session.write_tls(&mut writer) {
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    fn handshake(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        loop {
            if !self.session.is_handshaking() {
                while self.session.wants_write() {
                    ready!(self.conn_write(cx))?;
                }
                log::debug!("Tls handshake done");
                return Poll::Ready(Ok(()));
            }

            while self.session.wants_write() {
                ready!(self.conn_write(cx))?;
            }
            ready!(Pin::new(&mut self.conn).poll_flush(cx))?;

            if self.session.wants_read() {
                ready!(self.conn_read(cx))?;
            }
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        log::debug!("Reading tls data");
        let this = self.get_mut();
        if this.session.wants_read() {
            match this.conn_read(cx) {
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }
        match this.session.reader().into_first_chunk() {
            Ok(chunk) => {
                let mut len = buf.remaining();
                if len > chunk.len() {
                    len = chunk.len();
                }
                buf.put_slice(&chunk[..len]);
                this.session.reader().consume(len);
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        let this = self.get_mut();

        if let Err(e) = this.session.writer().write_all(buf) {
            return Poll::Ready(Err(e));
        }
        while this.session.wants_write() {
            match this.conn_write(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Ok(buf.len()).into()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        while self.session.wants_write() {
            ready!(self.conn_write(cx))?;
        }
        Pin::new(&mut self.conn).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}

struct SyncReadAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
    pub is_handshaking: bool,
    pub read_state: &'a mut ReadState,
}

impl<T: AsyncRead + Unpin> Read for SyncReadAdapter<'_, '_, T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut buffer = ReadBuf::new(buf);

        if self.is_handshaking {
            let result = match Pin::new(&mut self.io).poll_read(self.cx, &mut buffer) {
                Poll::Ready(Ok(())) => Ok(buffer.filled().len()),
                Poll::Ready(Err(err)) => Err(err),
                Poll::Pending => Err(ErrorKind::WouldBlock.into()),
            };
            return result;
        }
        // as xtls would switch to send raw tcp data after first tls application data package
        // make sure to only read one complete tls package each time
        // otherwise it may read later tcp package which does not need tls decryption
        loop {
            match &mut self.read_state {
                ReadState::ReadHead(tls13_header, read_len) => {
                    let mut tls13_header_read_buf = ReadBuf::new(&mut tls13_header[*read_len..]);
                    match Pin::new(&mut self.io).poll_read(self.cx, &mut tls13_header_read_buf) {
                        Poll::Ready(Ok(())) => {
                            *read_len += tls13_header_read_buf.filled().len();
                            if *read_len < tls13_header.len() {
                                continue;
                            }
                            if tls13_header[..3] != [0x17, 0x03, 0x03] {
                                log::error!("Tls read head type error {:?}", tls13_header);
                                return Err(ErrorKind::InvalidData.into());
                            }
                            let content_length =
                                u16::from_be_bytes([tls13_header[3], tls13_header[4]]);
                            let content = vec![0u8; content_length as usize];
                            *self.read_state = ReadState::ReadBody(content, 0);
                        }
                        Poll::Ready(Err(err)) => return Err(err),
                        Poll::Pending => return Err(ErrorKind::WouldBlock.into()),
                    }
                }
                ReadState::ReadBody(tls13_content, read_len) => {
                    let mut tls13_content_read_buf = ReadBuf::new(&mut tls13_content[*read_len..]);
                    match Pin::new(&mut self.io).poll_read(self.cx, &mut tls13_content_read_buf) {
                        Poll::Ready(Ok(())) => {
                            *read_len += tls13_content_read_buf.filled().len();
                            if *read_len < tls13_content.len() {
                                continue;
                            }
                            let len = (tls13_content.len() as u16).to_be_bytes();
                            buffer.put_slice(&[0x17, 0x03, 0x03]);
                            buffer.put_slice(&len);

                            // as rustls read_tls buffer size is const 4096
                            // https://github.com/rustls/rustls/blob/3ccfcece31d727f57e9ad3806e4652e146ac3eed/rustls/src/msgs/deframer/buffers.rs#L220
                            // slice the array to fit in
                            // 5 bytes for the header
                            *self.read_state =
                                ReadState::RemainingBody(tls13_content.split_off(0), 4096 - 5);
                        }
                        Poll::Ready(Err(err)) => return Err(err),
                        Poll::Pending => return Err(ErrorKind::WouldBlock.into()),
                    }
                }
                ReadState::RemainingBody(tls13_content, remaining_size) => {
                    let tls13_content_len = tls13_content.len();
                    let read_state = if tls13_content_len > *remaining_size {
                        let tls13_content_left = tls13_content.split_off(*remaining_size);
                        ReadState::RemainingBody(tls13_content_left, 4096)
                    } else {
                        ReadState::ReadHead([0u8; 5], 0)
                    };
                    buffer.put_slice(tls13_content);
                    *self.read_state = read_state;
                    return Ok(buffer.filled().len());
                }
            }
        }
    }
}

struct SyncWriteAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<T: Unpin> SyncWriteAdapter<'_, '_, T> {
    #[inline]
    fn poll_with<U>(
        &mut self,
        f: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<Result<U>>,
    ) -> Result<U> {
        match f(Pin::new(self.io), self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(ErrorKind::WouldBlock.into()),
        }
    }
}

impl<T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'_, '_, T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.poll_with(|io, cx| io.poll_write(cx, buf))
    }

    fn flush(&mut self) -> Result<()> {
        self.poll_with(|io, cx| io.poll_flush(cx))
    }
}
