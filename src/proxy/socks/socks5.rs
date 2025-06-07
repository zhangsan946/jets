// https://datatracker.ietf.org/doc/html/rfc1928

use super::super::net_manager::UdpInboundWrite;
use super::super::{Outbound, ProxySocket, ProxyStream};
use crate::app::config::{OutboundProtocolOption, SocksUser};
use crate::app::connect_tcp_host;
use crate::app::dns::DnsManager;
use crate::app::Context as AppContext;
use crate::common::{copy_bidirectional, invalid_data_error, Address, MAXIMUM_UDP_PAYLOAD_SIZE};
use crate::pre_check_addr;
use crate::proxy::net_manager::NatManager;
use crate::transport::raw::{ConnectOpts, TcpStream, UdpSocket};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use futures::ready;
use shadowsocks::relay::socks5::{
    self, Command, HandshakeRequest, HandshakeResponse, PasswdAuthRequest, PasswdAuthResponse,
    Reply, TcpRequestHeader, TcpResponseHeader, UdpAssociateHeader,
};
use std::collections::HashMap;
use std::io::{Cursor, Read, Result};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, ReadBuf};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time::{interval, sleep, Duration};

#[derive(Clone, Debug)]
pub struct Socks5Inbound {
    addr: SocketAddr,
    accounts: HashMap<String, String>,
    udp_enabled: bool,
}

impl Socks5Inbound {
    pub fn new(addr: SocketAddr, accounts: HashMap<String, String>, udp_enabled: bool) -> Self {
        Self {
            addr,
            accounts,
            udp_enabled,
        }
    }
}

impl Socks5Inbound {
    pub async fn handle_tcp(&self, mut stream: TokioTcpStream, context: AppContext) -> Result<()> {
        // 1. Handshake
        let request = match HandshakeRequest::read_from(&mut stream).await {
            Ok(r) => r,
            Err(err) => {
                return Err(err.into());
            }
        };

        match request.methods.first() {
            Some(&socks5::SOCKS5_AUTH_METHOD_NONE) => {
                if !self.accounts.is_empty() {
                    return Err(invalid_data_error("Socks5 authentication is enabled"));
                }
                let response = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
                response.write_to(&mut stream).await?;
            }
            Some(&socks5::SOCKS5_AUTH_METHOD_PASSWORD) => {
                let response = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_PASSWORD);
                response.write_to(&mut stream).await?;
                let _request = match PasswdAuthRequest::read_from(&mut stream).await {
                    Ok(p) => p,
                    Err(err) => {
                        let response = PasswdAuthResponse::new(err.as_reply().as_u8());
                        response.write_to(&mut stream).await?;

                        return Err(invalid_data_error(format!(
                            "Socks5 authentication request failed: {err}"
                        )));
                    }
                };
                todo!("socks5 auth");
            }
            method => {
                let response = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
                response.write_to(&mut stream).await?;
                return Err(invalid_data_error(format!(
                    "Unsupported socks5 authentication method {:?}",
                    method
                )));
            }
        }

        // 2. Fetch headers
        let peer_addr = stream.peer_addr()?;
        let request = match TcpRequestHeader::read_from(&mut stream).await {
            Ok(h) => h,
            Err(err) => {
                let response =
                    TcpResponseHeader::new(err.as_reply(), Address::SocketAddress(peer_addr));
                response.write_to(&mut stream).await?;
                return Err(err.into());
            }
        };
        let address = request.address;

        // 3. Handle Command
        match request.command {
            Command::TcpConnect => {
                let mut down_stream = connect_tcp_host(&peer_addr, address, context).await?;
                let addr = Address::SocketAddress(down_stream.local_addr()?);
                let response = TcpResponseHeader::new(Reply::Succeeded, addr);
                response.write_to(&mut stream).await?;
                let mut stream = Box::new(stream);
                copy_bidirectional(&mut stream, &mut down_stream)
                    .await
                    .map(|_| ())
            }
            Command::UdpAssociate => {
                if !self.udp_enabled {
                    let response = TcpResponseHeader::new(Reply::CommandNotSupported, address);
                    response.write_to(&mut stream).await?;
                    return Ok(());
                }
                let response = TcpResponseHeader::new(Reply::Succeeded, self.addr.into());
                response.write_to(&mut stream).await?;

                // Hold connection until EOF
                let mut buffer = [0u8; 2048];
                loop {
                    let n = stream.read(&mut buffer).await?;
                    if n == 0 {
                        break;
                    }
                }
                Ok(())
            }
            Command::TcpBind => {
                let response = TcpResponseHeader::new(Reply::CommandNotSupported, address);
                response.write_to(&mut stream).await?;
                Err(invalid_data_error("Socks5 tcp bind is not supported"))
            }
        }
    }

    pub async fn handle_udp(&self, socket: Arc<UdpSocket>, context: AppContext) -> Result<()> {
        let (mut manager, cleanup_interval, mut keepalive_rx) = NatManager::new(
            Socks5UdpInboundWriter {
                inbound: socket.clone(),
            },
            context,
        );
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let mut cleanup_timer = interval(cleanup_interval);
        loop {
            tokio::select! {
                recv_result = socket.recv_from(&mut buffer) => {
                    let (n, peer_addr) = match recv_result {
                        Ok(s) => s,
                        Err(err) => {
                            log::error!("udp server recv_from failed with error: {}", err);
                            sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    };

                    let data = &buffer[..n];

                    // PKT = UdpAssociateHeader + PAYLOAD
                    let mut cur = Cursor::new(data);
                    let header = match UdpAssociateHeader::read_from(&mut cur).await {
                        Ok(h) => h,
                        Err(..) => {
                            log::error!("received invalid UDP associate packet");
                            continue;
                        }
                    };

                    if header.frag != 0 {
                        log::error!("received UDP associate with frag != 0, which is not supported");
                        continue;
                    }

                    let pos = cur.position() as usize;
                    let payload = &data[pos..];

                    log::trace!(
                        "UDP ASSOCIATE {} -> {}, {} bytes",
                        peer_addr,
                        header.address,
                        payload.len()
                    );

                    if let Err(err) = manager.send_to(peer_addr, header.address, payload).await {
                        log::error!(
                            "udp packet from {} relay {} bytes failed, error: {}",
                            peer_addr,
                            data.len(),
                            err
                        );
                    }
                }

                _ = cleanup_timer.tick() => {
                    // cleanup expired associations. iter() will remove expired elements
                    manager.cleanup_expired().await;
                }

                peer_addr_opt = keepalive_rx.recv() => {
                    let peer_addr = peer_addr_opt.expect("keep-alive channel closed unexpectly");
                    manager.keep_alive(&peer_addr).await;
                }
            }
        }
    }
}

#[derive(Clone)]
struct Socks5UdpInboundWriter {
    inbound: Arc<UdpSocket>,
}

impl UdpInboundWrite for Socks5UdpInboundWriter {
    async fn send_to(
        &self,
        peer_addr: SocketAddr,
        remote_addr: &Address,
        data: &[u8],
    ) -> Result<()> {
        let remote_addr = match remote_addr {
            Address::SocketAddress(sa) => {
                // Try to convert IPv4 mapped IPv6 address if server is running on dual-stack mode
                let saddr = match *sa {
                    SocketAddr::V4(..) => *sa,
                    SocketAddr::V6(ref v6) => match Ipv6Addr::to_ipv4_mapped(v6.ip()) {
                        Some(v4) => SocketAddr::new(IpAddr::from(v4), v6.port()),
                        None => *sa,
                    },
                };

                Address::SocketAddress(saddr)
            }
            daddr => daddr.clone(),
        };

        // Reassemble packet
        let mut payload_buffer = BytesMut::new();
        let header = UdpAssociateHeader::new(0, remote_addr.clone());
        payload_buffer.reserve(header.serialized_len() + data.len());

        header.write_to_buf(&mut payload_buffer);
        payload_buffer.put_slice(data);

        self.inbound
            .send_to(&payload_buffer, peer_addr)
            .await
            .map(|_| ())
    }
}

#[derive(Clone, Debug)]
pub struct Socks5Outbound {
    addr: Address,
    accounts: HashMap<String, String>,
    connect_opts: ConnectOpts,
}

impl Socks5Outbound {
    pub fn new(addr: Address, accounts: Vec<SocksUser>, connect_opts: ConnectOpts) -> Self {
        let accounts: HashMap<_, _> = accounts.into_iter().map(|s| (s.user, s.pass)).collect();
        Self {
            addr,
            accounts,
            connect_opts,
        }
    }

    pub async fn connect(
        &self,
        addr: &SocketAddr,
        command: Command,
        target: Address,
    ) -> Result<(TcpResponseHeader, TcpStream)> {
        let mut stream = TcpStream::connect_with_opts(addr, &self.connect_opts).await?;

        let mut auth_method = socks5::SOCKS5_AUTH_METHOD_NONE;
        if !self.accounts.is_empty() {
            auth_method = socks5::SOCKS5_AUTH_METHOD_PASSWORD;
        }
        let request = HandshakeRequest::new(vec![auth_method]);
        request.write_to(&mut stream).await?;
        let response = HandshakeResponse::read_from(&mut stream).await?;

        if response.chosen_method != auth_method {
            return Err(invalid_data_error("Socks5 handshake method dose not match"));
        }

        if auth_method == socks5::SOCKS5_AUTH_METHOD_PASSWORD {
            todo!("socks5 auth");
        }

        // 2. Send request header
        let request = TcpRequestHeader::new(command, target);
        request.write_to(&mut stream).await?;
        let response = TcpResponseHeader::read_from(&mut stream).await?;
        Ok((response, stream))
    }
}

#[async_trait]
impl Outbound for Socks5Outbound {
    fn protocol(&self) -> OutboundProtocolOption {
        OutboundProtocolOption::Socks
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
        let (response, stream) = self.connect(server_addr, Command::TcpConnect, addr).await?;

        match response.reply {
            Reply::Succeeded => {
                log::debug!("Connected to socks5 tcp server: {}", response.address);
                let stream: Box<dyn ProxyStream> = Box::new(stream);
                Ok(stream)
            }
            reply => Err(invalid_data_error(format!(
                "Unable to connect to socks, reply error: {}",
                reply
            ))),
        }
    }

    async fn bind(&self, _peer: SocketAddr, _target: Address) -> Result<Box<dyn ProxySocket>> {
        let server_addr = pre_check_addr!(self.addr);
        let socket = UdpSocket::connect_any_with_opts(server_addr, &self.connect_opts).await?;
        let addr = socket.local_addr()?;
        let (response, stream) = self
            .connect(server_addr, Command::UdpAssociate, addr.into())
            .await?;
        match response.reply {
            Reply::Succeeded => {
                match response.address {
                    Address::SocketAddress(addr) => {
                        socket.connect(addr).await?;
                    }
                    Address::DomainNameAddress(_, _) => unimplemented!(),
                }
                log::debug!("Connected to socks5 udp server: {}", response.address);

                let socks5_socket = Socks5Socket::new(socket, stream);
                Ok(Box::new(socks5_socket) as Box<dyn ProxySocket>)
            }
            reply => Err(invalid_data_error(format!(
                "Inable to bind sock, reply error: {}",
                reply
            ))),
        }
    }
}

pub struct Socks5Socket {
    socket: UdpSocket,
    // Socks5 protocol requires to keep the TcpStream open
    _stream: TcpStream,
}

impl Socks5Socket {
    pub fn new(socket: UdpSocket, _stream: TcpStream) -> Self {
        Self { socket, _stream }
    }
}

impl ProxySocket for Socks5Socket {
    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<Address>> {
        let mut cache = vec![0u8; buf.remaining()];
        let mut buffer = ReadBuf::new(cache.as_mut());
        ready!(self.socket.poll_recv(cx, &mut buffer))?;
        let cache_len = buffer.filled().len();
        let mut cur = Cursor::new(buffer.filled());
        let mut buffer = [0u8; 3];
        Read::read_exact(&mut cur, &mut buffer)?;
        //let frag = buffer[2];
        let address = Address::read_cursor(&mut cur)?;
        let pos = cur.position() as usize;
        buf.put_slice(&cache[pos..cache_len]);
        Ok(address).into()
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: Address,
    ) -> Poll<Result<usize>> {
        // TODO: support frag
        let header = UdpAssociateHeader::new(0, target);
        let header_len = header.serialized_len();
        let mut send_buf = BytesMut::with_capacity(header.serialized_len() + buf.len());
        header.write_to_buf(&mut send_buf);
        send_buf.put_slice(buf);
        self.socket
            .poll_send(cx, &send_buf)
            .map_ok(|n| n.saturating_sub(header_len))
    }
}
