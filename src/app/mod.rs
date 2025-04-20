pub mod config;
pub mod dat {
    include!(concat!(env!("OUT_DIR"), "/xray.app.router.rs"));
}
pub mod dns;
pub mod proxy;
pub mod router;

use crate::app::config::OutboundProtocolOption;
use crate::common::{copy_bidirectional, invalid_input_error, Address};
use crate::proxy::{Outbound, ProxySocket, ProxyStream};
use actix_server::Server;
use actix_service::fn_service;
pub use config::Config;
use dns::DnsManager;
use proxy::{Inbounds, Outbounds};
use router::Router;
use std::collections::VecDeque;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

pub struct App {
    inbounds: Inbounds,
    outbounds: Arc<Outbounds>,
    router: Arc<Router>,
    dns: Arc<DnsManager>,
}

impl App {
    pub fn new(config: Config) -> Result<Self> {
        let inbounds = Inbounds::new(config.inbounds)?;
        let mut outbounds = Outbounds::new(config.outbounds)?;
        let router = Router::new(config.routing)?;
        router.validate(&outbounds)?;
        let dns = DnsManager::new(config.dns.clone(), &outbounds, &router)?;

        // pre_connect would replace server address with server socketaddr
        // which will make sure no outbound loopback in dns config
        let rt = Runtime::new()?;
        let mut outbounds_with_domain_addr: VecDeque<(String, Arc<Box<dyn Outbound>>)> =
            VecDeque::new();
        for (tag, outbound) in outbounds.iter_mut() {
            match rt.block_on(async { outbound.pre_connect(&dns).await }) {
                Ok(Some(new_outbound)) => {
                    *outbound = Arc::new(new_outbound);
                }
                Ok(None) => {
                    continue;
                }
                Err(_e) => {
                    outbounds_with_domain_addr.push_back((tag.clone(), outbound.clone()));
                }
            }
        }
        outbounds_with_domain_addr.iter().for_each(|(tag, _)| {
            outbounds.remove(tag);
        });
        let mut loop_time = outbounds_with_domain_addr.len();
        loop_time *= loop_time;
        while let Some((tag, outbound)) = outbounds_with_domain_addr.pop_front() {
            match rt.block_on(async { outbound.pre_connect(&dns).await }) {
                Ok(Some(new_outbound)) => {
                    outbounds.insert(tag, Arc::new(new_outbound));
                }
                Ok(None) => {
                    continue;
                }
                Err(_) => {
                    outbounds_with_domain_addr.push_back((tag, outbound));
                }
            }
            loop_time -= 1;
            if loop_time == 0 {
                return Err(invalid_input_error("DNS resolve failure or loopback happens, check dns, outbounds and router config"));
            }
        }
        // make the new dns with updated outbounds
        let dns = DnsManager::new(config.dns, &outbounds, &router)?;

        Ok(Self {
            inbounds,
            outbounds: Arc::new(outbounds),
            router: Arc::new(router),
            dns: Arc::new(dns),
        })
    }

    pub fn run(&self) -> Result<()> {
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        let dns = self.dns.clone();
        let inbounds = self.inbounds.iter();

        actix_rt::System::new().block_on(async move {
            let mut server = Server::build();
            server = server.backlog(4096);

            for (tag, inbound) in inbounds {
                let inbound_1 = inbound.to_owned();
                let context = Context::new(
                    tag.to_owned(),
                    outbounds.clone(),
                    router.clone(),
                    dns.clone(),
                );
                let inbound_2 = inbound_1.clone();
                let context_1 = context.clone();
                // TODO:
                // share backlog setting with tcp server
                // thread setting
                tokio::spawn(async move { inbound_2.run_udp_server(context_1).await });
                server = server.bind("in", inbound.addr(), move || {
                    let inbound = inbound_1.clone();
                    let context = context.clone();
                    fn_service(move |stream: TcpStream| {
                        let inbound = inbound.clone();
                        let context = context.clone();
                        async move {
                            let peer_addr = stream.peer_addr()?;
                            let local_addr = stream.local_addr()?;
                            log::debug!("{} -> {}", peer_addr, local_addr);
                            match inbound.handle_tcp(stream, context).await {
                                Ok(_) => Ok(()),
                                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                    log::info!(
                                        "{} to inbound {} blocked: {:#}",
                                        peer_addr,
                                        inbound.addr(),
                                        e
                                    );
                                    Ok(())
                                }
                                Err(e) => {
                                    log::error!(
                                        "{} to Inbound {} failed: {:#}",
                                        peer_addr,
                                        inbound.addr(),
                                        e
                                    );
                                    Err(e)
                                }
                            }
                        }
                    })
                })?;
            }

            server.run().await
        })
    }
}

#[derive(Clone)]
pub struct Context {
    inbound_tag: Option<String>,
    outbounds: Arc<Outbounds>,
    router: Arc<Router>,
    dns: Arc<DnsManager>,
}

impl Context {
    #[inline]
    pub fn new(
        inbound_tag: Option<String>,
        outbounds: Arc<Outbounds>,
        router: Arc<Router>,
        dns: Arc<DnsManager>,
    ) -> Self {
        Self {
            inbound_tag,
            outbounds,
            router,
            dns,
        }
    }

    #[inline]
    pub async fn get_outbound(&self, address: &Address) -> Result<&Arc<Box<dyn Outbound>>> {
        let outbound_tag = self
            .router
            .pick(&self.dns, address, &self.inbound_tag)
            .await?;
        Ok(self.outbounds.get(&outbound_tag).unwrap())
    }

    #[inline]
    pub async fn resolve(&self, address: &Address) -> Result<SocketAddr> {
        self.dns.resolve(address).await
    }
}

pub(crate) async fn establish_tcp_tunnel<S>(
    stream: &mut Box<S>,
    address: Address,
    context: Context,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    // TODO: connection pool
    // TODO: exponential retry connection
    let mut down_stream = connect_tcp_host(address, context).await?;
    return copy_bidirectional(stream, &mut down_stream)
        .await
        .map(|_| ());
}

pub(crate) async fn connect_tcp_host(
    address: Address,
    context: Context,
) -> Result<Box<dyn ProxyStream>> {
    let outbound = context.get_outbound(&address).await?;
    let addr = if outbound.protocol() == OutboundProtocolOption::Freedom {
        let addr = context.resolve(&address).await?;
        Address::SocketAddress(addr)
    } else {
        address
    };
    outbound
        .connect_tcp(addr.clone())
        .await
        .map_err(|e| Error::new(e.kind(), format!("Connection to {} failed: {}", addr, e)))
}

pub(crate) async fn bind_udp_socket(
    peer: SocketAddr,
    address: Address,
    context: Context,
) -> Result<Box<dyn ProxySocket>> {
    let outbound = context.get_outbound(&address).await?;
    let target = if outbound.protocol() == OutboundProtocolOption::Freedom {
        let addr = context.resolve(&address).await?;
        Address::SocketAddress(addr)
    } else {
        // For the rest of the protocols, it doesn't matter what the target is
        address
    };
    outbound
        .bind(peer, target.clone())
        .await
        .map_err(|e| Error::new(e.kind(), format!("Bind to {} failed: {}", target, e)))
}
