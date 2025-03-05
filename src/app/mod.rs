pub mod config;
pub mod dat {
    include!(concat!(env!("OUT_DIR"), "/xray.app.router.rs"));
}
pub mod router;

use crate::common::{copy_bidirectional, invalid_input_error, Address};
use crate::proxy::{Inbound, Outbound, ProxySteam};
use actix_server::Server;
use actix_service::fn_service;
pub use config::Config;
use router::{Router, DEFAULT_OUTBOUND_TAG};
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind, Result};
use std::sync::Arc;
use tokio::net::TcpStream;

pub struct App {
    inbounds: Vec<(Option<String>, Box<dyn Inbound>)>,
    outbounds: Arc<HashMap<String, Arc<Box<dyn Outbound>>>>,
    router: Arc<Router>,
}

impl App {
    pub fn new(config: Config) -> Result<Self> {
        let mut inbounds: Vec<(Option<String>, Box<dyn Inbound>)> = Vec::new();
        let mut inbound_tags: HashSet<String> = HashSet::new();
        for inbound in config.inbounds.into_iter() {
            let tag = inbound.tag.clone();
            if let Some(ref val) = tag {
                if !inbound_tags.insert(val.clone()) {
                    return Err(Error::new(
                        ErrorKind::AlreadyExists,
                        format!("Duplicate inbound with tag {}", val),
                    ));
                }
            }
            inbounds.push((tag, parse_inbound(inbound)?));
        }

        let mut outbounds: HashMap<String, Arc<Box<dyn Outbound>>> = HashMap::new();
        for (index, outbound) in config.outbounds.into_iter().enumerate() {
            let tag = outbound.tag.clone();
            let outbound = Arc::new(parse_outbound(outbound)?);
            if index == 0 {
                outbounds.insert(DEFAULT_OUTBOUND_TAG.to_string(), outbound.clone());
            }
            if let Some(tag) = tag {
                if outbounds.insert(tag.clone(), outbound).is_some() {
                    return Err(Error::new(
                        ErrorKind::AlreadyExists,
                        format!("Duplicate outbound with tag {}", tag),
                    ));
                }
            }
        }

        // TODO:
        // To validate the outbound tag set in the router does exist in the outbound
        // Current behavior is to use the first outbound if route to a orphaned tag.
        Ok(Self {
            inbounds,
            outbounds: Arc::new(outbounds),
            router: Arc::new(Router::new(config.routing)?),
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

pub(crate) async fn establish_tcp_tunnel(
    mut stream: Box<dyn ProxySteam>,
    address: &Address,
    inbound_tag: &Option<String>,
    outbounds: Arc<HashMap<String, Arc<Box<dyn Outbound>>>>,
    router: Arc<Router>,
) -> Result<()> {
    let mut down_stream = connect_host(address, inbound_tag, outbounds, router).await?;
    return copy_bidirectional(&mut stream, &mut down_stream)
        .await
        .map(|_| ());
}

pub(crate) async fn connect_host(
    address: &Address,
    inbound_tag: &Option<String>,
    outbounds: Arc<HashMap<String, Arc<Box<dyn Outbound>>>>,
    router: Arc<Router>,
) -> Result<Box<dyn ProxySteam>> {
    let outbound_tag = router.pick(address, inbound_tag);
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

#[cfg(feature = "local-http")]
use crate::proxy::http::HttpInbound;
use crate::proxy::{
    blackhole::BlackholeOutbound,
    freedom::FreedomOutbound,
    shadowsocks::ShadowsocksOutbound,
    socks::{Socks5Outbound, SocksInbound},
    vless::VlessOutbound,
};
use config::{
    InboundConfig, InboundProtocolOption, InboundSettings, OutboundConfig, OutboundProtocolOption,
    OutboundSettings,
};
use std::str::FromStr;
fn parse_inbound(inbound: InboundConfig) -> Result<Box<dyn Inbound>> {
    match inbound.protocol {
        #[cfg(feature = "local-http")]
        InboundProtocolOption::Http => {
            let addr = format!("{}:{}", inbound.listen, inbound.port);
            let addr = Address::from_str(&addr).map_err(|_| invalid_input_error(addr))?;
            let accounts = if let InboundSettings::Http { accounts } = inbound.settings {
                accounts
            } else {
                Vec::new()
            };
            let http_inbound = HttpInbound::new(addr, accounts);
            Ok(Box::new(http_inbound) as Box<dyn Inbound>)
        }
        #[cfg(not(feature = "local-http"))]
        InboundProtocolOption::Http => Err(Error::new(
            ErrorKind::Unsupported,
            "Found http inbound but local-http is not enabled",
        )),
        InboundProtocolOption::Socks => {
            let addr = format!("{}:{}", inbound.listen, inbound.port);
            let addr = Address::from_str(&addr).map_err(|_| invalid_input_error(addr))?;
            let accounts = if let InboundSettings::Socks {
                auth: _,
                accounts,
                udp: _,
            } = inbound.settings
            {
                accounts
            } else {
                Vec::new()
            };
            let socks_inbound = SocksInbound::new(addr, accounts);
            Ok(Box::new(socks_inbound) as Box<dyn Inbound>)
        }
    }
}

fn parse_outbound(outbound: OutboundConfig) -> Result<Box<dyn Outbound>> {
    match outbound.protocol {
        OutboundProtocolOption::Blackhole => Ok(Box::new(BlackholeOutbound) as Box<dyn Outbound>),
        OutboundProtocolOption::Freedom => {
            Ok(Box::new(FreedomOutbound::default()) as Box<dyn Outbound>)
        }
        OutboundProtocolOption::Socks => {
            if let OutboundSettings::Socks { mut servers } = outbound.settings {
                if !servers.is_empty() {
                    let server = servers.remove(0);
                    let addr = format!("{}:{}", server.address, server.port);
                    let addr = Address::from_str(&addr).map_err(|_| invalid_input_error(addr))?;
                    let outbound = Socks5Outbound::new(addr, server.users);
                    return Ok(Box::new(outbound) as Box<dyn Outbound>);
                }
            }
            Err(invalid_input_error("Invalid socks outbound"))
        }
        OutboundProtocolOption::Shadowsocks => {
            if let OutboundSettings::Shadowsocks { mut servers } = outbound.settings {
                if !servers.is_empty() {
                    let server = servers.remove(0);
                    let addr = format!("{}:{}", server.address, server.port);
                    let addr = Address::from_str(&addr).map_err(|_| invalid_input_error(addr))?;
                    let outbound = ShadowsocksOutbound::new(addr, server.password, server.method)?;
                    return Ok(Box::new(outbound) as Box<dyn Outbound>);
                }
            }
            Err(invalid_input_error("Invalid shadowsocks outbound"))
        }
        OutboundProtocolOption::Vless => {
            if let OutboundSettings::Vless { mut vnext } = outbound.settings {
                if !vnext.is_empty() && !vnext[0].users.is_empty() {
                    let mut server = vnext.remove(0);
                    let addr = format!("{}:{}", server.address, server.port);
                    let addr = Address::from_str(&addr).map_err(|_| invalid_input_error(addr))?;
                    let user = server.users.remove(0);
                    let outbound = VlessOutbound::new(
                        addr,
                        user.id,
                        user.flow,
                        outbound.stream_settings.tls_settings,
                    )?;
                    return Ok(Box::new(outbound) as Box<dyn Outbound>);
                }
            }
            Err(invalid_input_error("Invalid vless outbound"))
        }
    }
}
