use super::{LocalAddr, Outbound, ProxySocket, ProxyStream};
use crate::app::config::OutboundProtocolOption;
use crate::app::dns::DnsManager;
use crate::common::{invalid_data_error, invalid_input_error, Address};
use crate::transport::raw::{ConnectOpts, UdpSocket};
use async_trait::async_trait;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use shadowsocks::config::{ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::relay::tcprelay::proxy_stream::client::ProxyClientStream;
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use shadowsocks::relay::udprelay::ProxySocket as SsProxySocket;
use shadowsocks_crypto::kind::CipherKind;
use std::cell::RefCell;
use std::io::Result;
use std::net::SocketAddr;
use std::task::{Context as StdContext, Poll};
use tokio::io::ReadBuf;

// https://github.com/shadowsocks/shadowsocks-rust/blob/701bd8df191245f4e06d0c24a43a046349d57c1e/crates/shadowsocks-service/src/local/net/udp/association.rs#L236-L249
thread_local! {
    static CLIENT_SESSION_RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_os_rng());
}

/// Generate an AEAD-2022 Client SessionID
#[inline]
pub fn generate_client_session_id() -> u64 {
    loop {
        let id = CLIENT_SESSION_RNG.with(|rng| rng.borrow_mut().random());
        if id != 0 {
            break id;
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShadowsocksOutbound {
    server_config: ServerConfig,
    connect_opts: ConnectOpts,
    context: SharedContext,
}

impl ShadowsocksOutbound {
    pub fn new(addr: Address, password: String, method: CipherKind) -> Result<Self> {
        let server_config =
            ServerConfig::new(addr, password, method).map_err(invalid_input_error)?;
        Ok(Self {
            server_config,
            connect_opts: ConnectOpts::default(),
            context: Context::new_shared(ServerType::Local),
        })
    }
}

impl LocalAddr for ProxyClientStream<crate::transport::raw::TcpStream> {
    fn local_addr(&self) -> Result<std::net::SocketAddr> {
        self.get_ref().local_addr()
    }
}

#[async_trait]
impl Outbound for ShadowsocksOutbound {
    fn protocol(&self) -> OutboundProtocolOption {
        OutboundProtocolOption::Shadowsocks
    }

    async fn pre_connect(&self, dns: &DnsManager) -> Result<Option<Box<dyn Outbound>>> {
        let addr = self.server_config.addr();
        if matches!(addr, ServerAddr::DomainName(_, _)) {
            let addr = Address::DomainNameAddress(addr.host(), addr.port());
            let addr = dns.resolve(&addr).await?;
            let mut outbound = self.clone();
            outbound.server_config.set_addr(addr);
            Ok(Some(Box::new(outbound) as Box<dyn Outbound>))
        } else {
            Ok(None)
        }
    }

    async fn connect_tcp(&self, addr: Address) -> Result<Box<dyn ProxyStream>> {
        let stream = ProxyClientStream::connect_with_opts(
            self.context.clone(),
            &self.server_config,
            addr,
            &self.connect_opts,
        )
        .await?;
        Ok(Box::new(stream) as Box<dyn ProxyStream>)
    }

    async fn bind(&self, _peer: SocketAddr, _target: SocketAddr) -> Result<Box<dyn ProxySocket>> {
        let socket = SsProxySocket::connect_with_opts(
            self.context.clone(),
            &self.server_config,
            &self.connect_opts,
        )
        .await?;
        Ok(Box::new(SsSocket {
            socket,
            client_session_id: generate_client_session_id(),
        }) as Box<dyn ProxySocket>)
    }
}

pub struct SsSocket {
    socket: SsProxySocket<UdpSocket>,
    client_session_id: u64,
}

impl ProxySocket for SsSocket {
    fn poll_recv_from(
        &self,
        cx: &mut StdContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<Address>> {
        // TODO:
        // https://github.com/shadowsocks/shadowsocks-rust/blob/25115477b2416eb7f2f69e63024d9f1eaf5e71df/crates/shadowsocks-service/src/local/net/udp/association.rs#L351-L378
        // https://github.com/shadowsocks/shadowsocks-rust/blob/master/crates/shadowsocks-service/src/net/packet_window.rs
        // To use recv_with_ctrl and implement anti-replay
        self.socket
            .poll_recv(cx, buf)
            .map_ok(|v| v.1)
            .map_err(invalid_data_error)
    }

    fn poll_send_to(
        &self,
        cx: &mut StdContext<'_>,
        buf: &[u8],
        target: Address,
    ) -> Poll<Result<usize>> {
        let mut control = UdpSocketControlData::default();
        control.client_session_id = self.client_session_id;
        // TODO:
        // verify this is a valid approach for packet_id
        let packet_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time is earlier than UNIX_EPOCH")
            .as_millis() as u64;
        control.packet_id = packet_id;
        self.socket
            .poll_send_with_ctrl(&target, &control, buf, cx)
            .map_err(invalid_data_error)
    }
}
