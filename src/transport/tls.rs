use super::raw::TcpStream;
use crate::app::config::TlsSettings;
use crate::common::{invalid_data_error, invalid_input_error, Address};
use crate::proxy::LocalAddr;
use futures::ready;
use once_cell::sync::Lazy;
use rustls::{ClientConfig, ClientConnection, KeyLogFile, RootCertStore};
//use rustls_native_certs::CertificateResult;
use rustls_pki_types::ServerName;
use std::future::poll_fn;
use std::io::{BufRead, Error, ErrorKind, Read, Result, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub static ROOT_CERT_STORE: Lazy<Arc<RootCertStore>> = Lazy::new(|| {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // let CertificateResult { certs, errors, .. } =
    //     rustls_native_certs::load_native_certs();
    // if !errors.is_empty() {
    //     for error in errors {
    //         log::warn!("Failed to load cert (native), error: {}", error);
    //     }
    // }

    // for cert in certs {
    //     if let Err(err) = store.add(cert) {
    //         log::warn!("Failed to add cert (native), error: {}", err);
    //     }
    // }

    Arc::new(store)
});

#[derive(Clone, Debug)]
pub struct Tls {
    server_name: ServerName<'static>,
    tls_config: Arc<ClientConfig>,
}

impl Tls {
    pub fn new(tls_settings: TlsSettings, addr: &Address) -> Result<Self> {
        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(ROOT_CERT_STORE.clone())
            .with_no_client_auth();
        tls_config.alpn_protocols.extend(tls_settings.alpn);
        tls_config.key_log = Arc::new(KeyLogFile::new());
        let server_name = if let Some(server_name) = tls_settings.server_name {
            ServerName::try_from(server_name.clone()).map_err(|_| {
                invalid_input_error(format!(
                    "Invalid server name of {} in tls settings",
                    server_name
                ))
            })?
        } else {
            ServerName::try_from(addr.host()).map_err(|_| {
                invalid_data_error(format!("Got invalid server name: {}", addr.host()))
            })?
        };
        Ok(Self {
            server_name,
            tls_config: Arc::new(tls_config),
        })
    }
}

impl Tls {
    pub async fn connect(&self, conn: TcpStream, xtls: bool) -> Result<TlsStream> {
        let session = ClientConnection::new(self.tls_config.clone(), self.server_name.clone())
            .map_err(|e| Error::other(format!("Unable to create tls session: {}", e)))?;
        let mut tls_stream = TlsStream::new(conn, session, xtls);
        poll_fn(|cx| tls_stream.handshake(cx)).await?;
        Ok(tls_stream)
    }
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
    xtls: bool,
}

impl LocalAddr for TlsStream {
    fn local_addr(&self) -> Result<SocketAddr> {
        self.conn.local_addr()
    }
}

impl TlsStream {
    pub fn new(conn: TcpStream, session: ClientConnection, xtls: bool) -> Self {
        Self {
            conn,
            session,
            read_state: ReadState::ReadHead([0u8; 5], 0),
            xtls,
        }
    }

    pub fn as_mut_ref(&mut self) -> &mut TcpStream {
        &mut self.conn
    }

    pub fn conn_read(&mut self, cx: &mut Context) -> Poll<Result<usize>> {
        let mut reader = SyncAdapter {
            io: &mut self.conn,
            cx,
            xtls_mode: self.xtls && !self.session.is_handshaking(),
            read_state: &mut self.read_state,
        };

        let n = match self.session.read_tls(&mut reader) {
            Ok(n) => {
                if n == 0 {
                    return Poll::Ready(Err(Error::from(ErrorKind::UnexpectedEof)));
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
            .map_err(invalid_data_error)?;
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
        let mut writer = SyncAdapter {
            io: &mut self.conn,
            cx,
            xtls_mode: false,
            read_state: &mut self.read_state,
        };

        match self.session.write_tls(&mut writer) {
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    fn handshake(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let mut io = SyncAdapter {
            io: &mut self.conn,
            cx,
            xtls_mode: false,
            read_state: &mut self.read_state,
        };

        match self.session.complete_io(&mut io) {
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
            Ok(_) => Poll::Ready(Ok(())),
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
            // TODO:
            // handle eof separately
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

struct SyncAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
    pub xtls_mode: bool,
    pub read_state: &'a mut ReadState,
}

impl<T: AsyncRead + Unpin> Read for SyncAdapter<'_, '_, T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut buffer = ReadBuf::new(buf);

        if !self.xtls_mode {
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
                                log::error!("Tls read unkown head type {:?}", tls13_header);
                                return Err(invalid_data_error("Unknon tls application header"));
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

impl<T: Unpin> SyncAdapter<'_, '_, T> {
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

impl<T: AsyncWrite + Unpin> Write for SyncAdapter<'_, '_, T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.poll_with(|io, cx| io.poll_write(cx, buf))
    }

    fn flush(&mut self) -> Result<()> {
        self.poll_with(|io, cx| io.poll_flush(cx))
    }
}
