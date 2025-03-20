pub mod config;
pub mod dat {
    include!(concat!(env!("OUT_DIR"), "/xray.app.router.rs"));
}
pub mod dns;
pub mod proxy;
pub mod router;

use crate::common::{copy_bidirectional, Address};
use crate::proxy::ProxySteam;
use actix_server::Server;
use actix_service::fn_service;
//use dns::DnsManager;
pub use config::Config;
use proxy::{Inbounds, Outbounds};
use router::{Router, DEFAULT_OUTBOUND_TAG};
use std::io::Result;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub struct App {
    inbounds: Inbounds,
    outbounds: Arc<Outbounds>,
    router: Arc<Router>,
    //dns: DnsManager,
}

impl App {
    pub fn new(config: Config) -> Result<Self> {
        let inbounds = Inbounds::new(config.inbounds)?;
        let outbounds = Outbounds::new(config.outbounds)?;
        let outbounds = Arc::new(outbounds);
        let router = Arc::new(Router::new(config.routing)?);
        //let dns = DnsManager::new(config.dns, outbounds.clone(), router.clone())?;

        // TODO:
        // To validate the outbound tag set in the routing rule does exist in the outbound list
        // Current behavior is to route to the first outbound if route to a orphaned tag.
        Ok(Self {
            inbounds,
            outbounds,
            router,
            //dns,
        })
    }

    pub fn run(&self) -> Result<()> {
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        let inbounds = self.inbounds.iter();

        actix_rt::System::new().block_on(async move {
            let mut server = Server::build();
            server = server.backlog(4096);

            for (tag, inbound) in inbounds {
                let router = router.clone();
                let outbounds = outbounds.clone();
                let inbound_1 = inbound.to_owned();
                let inbound_tag = tag.to_owned();
                server = server.bind("in", inbound.addr(), move || {
                    let router = router.clone();
                    let outbounds = outbounds.clone();
                    let inbound = inbound_1.clone();
                    let inbound_tag = inbound_tag.clone();
                    fn_service(move |stream: TcpStream| {
                        let router = router.clone();
                        let outbounds = outbounds.clone();
                        let inbound = inbound.clone();
                        let inbound_tag = inbound_tag.clone();
                        async move {
                            let peer_addr = stream.peer_addr()?;
                            let local_addr = stream.local_addr()?;
                            log::debug!("{} -> {}", peer_addr, local_addr);
                            match inbound.handle(stream, inbound_tag, outbounds, router).await {
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
    stream: &mut S,
    address: &Address,
    inbound_tag: &Option<String>,
    outbounds: Arc<Outbounds>,
    router: Arc<Router>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut down_stream = connect_host(address, inbound_tag, outbounds, router).await?;
    return copy_bidirectional(stream, &mut down_stream)
        .await
        .map(|_| ());
}

pub(crate) async fn connect_host(
    address: &Address,
    inbound_tag: &Option<String>,
    outbounds: Arc<Outbounds>,
    router: Arc<Router>,
) -> Result<Box<dyn ProxySteam>> {
    let outbound_tag = router.pick(address, inbound_tag).await;
    let outbound = outbounds.get(&outbound_tag).unwrap_or_else(|| {
        log::warn!("Routing to outbound with tag {} not found", outbound_tag);
        log::warn!("Using default outbound");
        outbounds
            .get(DEFAULT_OUTBOUND_TAG)
            .expect("default outbound")
    });
    outbound.handle(address).await.map_err(|e| {
        log::error!("Connection to {} failed: {:#}", address, e);
        e
    })
}
