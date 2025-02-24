mod config;
pub mod router;

use crate::common::{copy_bidirectional, new_io_error};
use crate::proxy::{Inbound, Outbound, ProxySteam};
use actix_server::Server;
use actix_service::fn_service;
pub use config::Config;
use log::{error, info};
use router::Router;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use tokio::net::TcpStream;

pub struct App {
    inbounds: Vec<Box<dyn Inbound>>,
    outbounds: Arc<HashMap<String, Box<dyn Outbound>>>,
    router: Arc<Router>,
}

impl App {
    pub fn new(config: Config) -> Self {
        let inbounds = config
            .socks_inbounds
            .into_iter()
            .map(|i| Box::new(i) as Box<dyn Inbound>)
            .collect();

        let mut outbounds: HashMap<String, Box<dyn Outbound>> = HashMap::new();
        config.freedom_outbounds.into_iter().for_each(|i| {
            outbounds.insert(i.0, Box::new(i.1) as Box<dyn Outbound>);
        });
        config.socks5_outbounds.into_iter().for_each(|i| {
            outbounds.insert(i.0, Box::new(i.1) as Box<dyn Outbound>);
        });
        config.shadowsocks_outbounds.into_iter().for_each(|i| {
            outbounds.insert(i.0, Box::new(i.1) as Box<dyn Outbound>);
        });
        config.vless_outbounds.into_iter().for_each(|i| {
            outbounds.insert(i.0, Box::new(i.1) as Box<dyn Outbound>);
        });

        Self {
            inbounds,
            outbounds: Arc::new(outbounds),
            router: Arc::new(Router::new("default")),
        }
    }

    pub fn run(&self) -> io::Result<()> {
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();

        actix_rt::System::new().block_on(async move {
            let mut server = Server::build();
            server = server.backlog(4096);

            for inbound in self.inbounds.iter() {
                let router = router.clone();
                let outbounds = outbounds.clone();
                let inbound_1 = inbound.to_owned();
                server = server.bind("in", inbound.addr(), move || {
                    let router = router.clone();
                    let outbounds = outbounds.clone();
                    let inbound = inbound_1.clone();
                    fn_service(move |stream: TcpStream| {
                        let router = router.clone();
                        let outbounds = outbounds.clone();
                        let inbound = inbound.clone();
                        async move {
                            let peer_addr = stream.peer_addr()?;
                            let local_addr = stream.local_addr()?;
                            info!("{} -> {}", peer_addr, local_addr);
                            let stream: Box<dyn ProxySteam> = Box::new(stream);
                            match inbound.handle(stream, &peer_addr).await {
                                Ok((mut stream, address)) => {
                                    let tag = router.match_addr(&address);
                                    let outbound = outbounds.get(tag).ok_or_else(|| {
                                        new_io_error(format!("Outbound with tag {} not found", tag))
                                    })?;
                                    let mut down_stream =
                                        outbound.handle(&address).await.map_err(|e| {
                                            error!("Connection to {} failed: {:#}", address, e);
                                            e
                                        })?;
                                    return copy_bidirectional(&mut stream, &mut down_stream).await;
                                }
                                Err(e) => {
                                    error!("Inbound {} failed: {:#}", inbound.addr(), e);
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
