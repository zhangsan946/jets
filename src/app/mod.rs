pub mod config;
pub mod dat {
    include!(concat!(env!("OUT_DIR"), "/xray.app.router.rs"));
}
pub mod dns;
pub mod proxy;
pub mod router;

use crate::app::config::OutboundProtocolOption;
use crate::common::{copy_bidirectional, invalid_input_error, Address};
use crate::proxy::{Outbound, ProxySteam};
use actix_server::Server;
use actix_service::fn_service;
pub use config::Config;
use dns::DnsManager;
use proxy::{Inbounds, Outbounds};
use router::Router;
use std::collections::VecDeque;
use std::io::Result;
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
        let dns = DnsManager::new(config.dns, &outbounds, &router)?;

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
                let router = router.clone();
                let outbounds = outbounds.clone();
                let dns = dns.clone();
                let inbound_1 = inbound.to_owned();
                let inbound_tag = tag.to_owned();
                server = server.bind("in", inbound.addr(), move || {
                    let router = router.clone();
                    let outbounds = outbounds.clone();
                    let dns = dns.clone();
                    let inbound = inbound_1.clone();
                    let inbound_tag = inbound_tag.clone();
                    fn_service(move |stream: TcpStream| {
                        let router = router.clone();
                        let outbounds = outbounds.clone();
                        let dns = dns.clone();
                        let inbound = inbound.clone();
                        let inbound_tag = inbound_tag.clone();
                        async move {
                            let peer_addr = stream.peer_addr()?;
                            let local_addr = stream.local_addr()?;
                            log::debug!("{} -> {}", peer_addr, local_addr);
                            match inbound
                                .handle(stream, inbound_tag, outbounds, router, dns)
                                .await
                            {
                                Ok(_) => Ok(()),
                                Err(e) => {
                                    log::error!("Inbound {} failed: {:#}", inbound.addr(), e);
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

pub(crate) async fn establish_tcp_tunnel<S>(
    stream: &mut Box<S>,
    address: &Address,
    inbound_tag: &Option<String>,
    outbounds: Arc<Outbounds>,
    router: Arc<Router>,
    dns: Arc<DnsManager>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut down_stream = connect_host(address, inbound_tag, outbounds, router, dns).await?;
    return copy_bidirectional(stream, &mut down_stream)
        .await
        .map(|_| ());
}

pub(crate) async fn connect_host(
    address: &Address,
    inbound_tag: &Option<String>,
    outbounds: Arc<Outbounds>,
    router: Arc<Router>,
    dns: Arc<DnsManager>,
) -> Result<Box<dyn ProxySteam>> {
    let outbound_tag = router.pick(&dns, address, inbound_tag).await;
    let outbound = outbounds.get(&outbound_tag).unwrap();
    let addr = if outbound.protocol() == OutboundProtocolOption::Freedom {
        let addr = dns.resolve(address).await?;
        Some(Address::SocketAddress(addr))
    } else {
        None
    };
    let addr = if let Some(ref addr) = addr {
        addr
    } else {
        address
    };
    outbound.handle(addr).await.map_err(|e| {
        log::error!("Connection to {} failed: {:#}", address, e);
        e
    })
}
