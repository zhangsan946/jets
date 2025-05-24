use super::{Outbound, ProxySocket, ProxyStream};
use crate::app::config::{OutboundProtocolOption, TlsSettings};
use crate::app::dns::DnsManager;
use crate::common::Address;
use crate::pre_check_addr;
use crate::transport::raw::ConnectOpts;
use crate::transport::tls::Tls;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use futures::{ready, FutureExt};
use sha2::{Digest, Sha224};
use std::io::{Cursor, Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;

pub mod request_command {
    pub const TCP: u8 = 1;
    pub const UDP: u8 = 3;
}

pub const ADDR_TYPE_IPV4: u8 = 0x01;
pub const ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
pub const ADDR_TYPE_IPV6: u8 = 0x04;

/// Trojan handshake
/// https://trojan-gfw.github.io/trojan/protocol
/// ```plain
/// +-----------------------+---------+---------+---------+
/// | hex(SHA224(password)) |   CRLF  | REQUEST |   CRLF  |
/// +-----------------------+---------+---------+---------+
/// |          56           | X'0D0A' |    V    | X'0D0A' |
/// +-----------------------+---------+---------+---------+
///
/// +-----+------+----------+----------+
/// | CMD | ATYP | DST.ADDR | DST.PORT |
/// +-----+------+----------+----------+
/// |  1  |  1   | Variable |    2     |
/// +-----+------+----------+----------+
/// ```
///  
/// - CMD
///   - CONNECT X'01'
///   - UDP ASSOCIATE X'03'
/// - ATYP address type of following address
///   - IP V4 address: X'01'
///   - DOMAINNAME: X'03'
///   - IP V6 address: X'04'
/// - DST.ADDR desired destination address
/// - DST.PORT desired destination port in network octet order
///
pub struct TrojanHandshake<'a> {
    addr: &'a Address,
    password: &'a String,
    command: u8,
}

impl<'a> TrojanHandshake<'a> {
    pub fn new(addr: &'a Address, password: &'a String, command: u8) -> Self {
        Self {
            addr,
            password,
            command,
        }
    }

    /// Write to a writer
    pub async fn write_to<W>(&self, w: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.password.as_bytes());
        buf.put_slice(b"\r\n");
        buf.put_u8(self.command);
        self.addr.write_to_buf(buf);
        buf.put_slice(b"\r\n");
    }

    /// Get length of bytes
    pub fn serialized_len(&self) -> usize {
        56 + 2 + 1 + self.addr.serialized_len() + 2
    }
}

#[derive(Clone, Debug)]
pub struct TrojanOutbound {
    addr: Address,
    password: String,
    connect_opts: ConnectOpts,
    tls: Tls,
}

impl TrojanOutbound {
    pub fn new(
        addr: Address,
        password: String,
        tls_settings: TlsSettings,
        connect_opts: ConnectOpts,
    ) -> Result<Self> {
        let tls = Tls::new(tls_settings, &addr)?;
        let password = Sha224::digest(password.as_bytes());
        let password = hex::encode(&password[..]);
        Ok(Self {
            addr,
            password,
            connect_opts,
            tls,
        })
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    fn protocol(&self) -> OutboundProtocolOption {
        OutboundProtocolOption::Trojan
    }

    async fn pre_connect(&self, dns: &DnsManager) -> Result<Option<Box<dyn Outbound>>> {
        if matches!(self.addr, Address::DomainNameAddress(_, _)) {
            let addr = dns.resolve(&self.addr).await?;
            let mut outbound = self.clone();
            outbound.addr = Address::SocketAddress(addr);
            Ok(Some(Box::new(outbound) as Box<dyn Outbound>))
        } else {
            Ok(None)
        }
    }

    async fn connect_tcp(&self, addr: Address) -> Result<Box<dyn ProxyStream>> {
        let server_addr = pre_check_addr!(self.addr);
        let mut stream = self
            .tls
            .connect(server_addr, &self.connect_opts, false)
            .await?;

        let handshake = TrojanHandshake::new(&addr, &self.password, request_command::TCP);
        let mut buffer = BytesMut::with_capacity(handshake.serialized_len());
        handshake.write_to_buf(&mut buffer);
        stream.write_all(&buffer).await?;

        Ok(Box::new(stream) as Box<dyn ProxyStream>)
    }

    async fn bind(&self, _peer: SocketAddr, target: Address) -> Result<Box<dyn ProxySocket>> {
        let server_addr = pre_check_addr!(self.addr);
        let mut stream = self
            .tls
            .connect(server_addr, &self.connect_opts, false)
            .await?;

        let handshake = TrojanHandshake::new(&target, &self.password, request_command::UDP);
        let mut buffer = BytesMut::with_capacity(handshake.serialized_len());
        handshake.write_to_buf(&mut buffer);
        stream.write_all(&buffer).await?;

        Ok(Box::new(TrojanUdpStream::new(stream)) as Box<dyn ProxySocket>)
    }
}

pub(crate) struct TrojanUdpStream<S> {
    stream: Mutex<S>,
}

impl<S> TrojanUdpStream<S>
where
    S: ProxyStream,
{
    pub fn new(stream: S) -> Self {
        Self {
            stream: Mutex::new(stream),
        }
    }
}

/// each UDP packet has the following format
/// ```plain
/// +------+----------+----------+--------+---------+----------+
/// | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
/// +------+----------+----------+--------+---------+----------+
/// |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
/// +------+----------+----------+--------+---------+----------+
/// ```
///
impl<S> ProxySocket for TrojanUdpStream<S>
where
    S: ProxyStream,
{
    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<Address>> {
        let mut stream_fut = Box::pin(self.stream.lock());
        let mut stream = ready!(stream_fut.poll_unpin(cx));
        let stream = stream.deref_mut();
        let mut buffer = BytesMut::with_capacity(1 + 16 + 2);
        let mut addr_type = [0u8; 1];
        ready!(Pin::new(&mut *stream).poll_read_exact(cx, &mut addr_type))?;
        buffer.put_slice(&addr_type);
        match addr_type[0] {
            ADDR_TYPE_IPV4 => {
                let mut addr = [0u8; 4 + 2];
                ready!(Pin::new(&mut *stream).poll_read_exact(cx, &mut addr))?;
                buffer.put_slice(&addr);
            }
            ADDR_TYPE_IPV6 => {
                let mut addr = [0u8; 16 + 2];
                ready!(Pin::new(&mut *stream).poll_read_exact(cx, &mut addr))?;
            }
            ADDR_TYPE_DOMAIN_NAME => {
                let mut len = [0u8; 1];
                ready!(Pin::new(&mut *stream).poll_read_exact(cx, &mut len))?;
                buffer.put_slice(&len);
                let mut addr = vec![0u8; (len[0] + 2) as usize];
                ready!(Pin::new(&mut *stream).poll_read_exact(cx, &mut addr))?;
            }
            _ => unreachable!("Unsupported addr type"),
        }
        let mut cur = Cursor::new(&buffer);
        let addr = Address::read_cursor(&mut cur)?;

        let mut buffer = [0u8; 4];
        ready!(Pin::new(&mut *stream).poll_read_exact(cx, &mut buffer))?;
        let payload_len = u16::from_be_bytes(buffer[..2].try_into().unwrap()) as usize;
        if buf.capacity() < payload_len {
            return Err(Error::new(ErrorKind::Interrupted, "Small buffer")).into();
        }
        Pin::new(&mut *stream)
            .poll_read_exact(cx, buf.initialize_unfilled_to(payload_len))
            .map_ok(|_| {
                buf.set_filled(payload_len);
                addr
            })
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: Address,
    ) -> Poll<Result<usize>> {
        let mut stream_fut = Box::pin(self.stream.lock());
        let mut stream = ready!(stream_fut.poll_unpin(cx));
        let stream = stream.deref_mut();

        let mut buffer = BytesMut::new();
        target.write_to_buf(&mut buffer);
        buffer.put_u16(buf.len() as u16);
        buffer.put_slice(b"\r\n");
        buffer.put_slice(buf);

        // TODO:
        // if the payload is too long, it need to be sent in multiple tcp packets
        Pin::new(stream)
            .poll_write(cx, &buffer)
            .map_ok(|_| buf.len())
    }
}
