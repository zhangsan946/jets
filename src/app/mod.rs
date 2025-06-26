pub mod cli;
pub mod config;
pub mod dat {
    include!(concat!(env!("OUT_DIR"), "/xray.app.router.rs"));
}
pub mod dns;
pub mod proxy;
pub mod router;
pub mod sniff;
pub mod utils;

use crate::app::config::OutboundProtocolOption;
use crate::common::log::{Logger, Target, JETS_ACCESS_LIST};
use crate::common::{copy_bidirectional, invalid_data_error, invalid_input_error, Address};
use crate::proxy::{Outbound, ProxySocket, ProxyStream};
pub use config::Config;
use dns::DnsManager;
use futures::{future, FutureExt};
use hickory_resolver::proto::op::Message;
use proxy::{Inbounds, Outbounds};
use router::Router;
use std::collections::VecDeque;
use std::io::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use utils::{create_abort_signal, ServerHandle};

pub mod env_vars {
    pub const RESOURCES_DIR: &str = "JETS_RESOURCES_DIR";
}

pub struct App {
    inbounds: Inbounds,
    outbounds: Arc<Outbounds>,
    router: Arc<Router>,
    dns: Arc<DnsManager>,
}

impl App {
    pub async fn new(config: Config) -> Result<Self> {
        let inbounds = Inbounds::new(config.inbounds)?;
        let mut outbounds = Outbounds::new(config.outbounds)?;
        let router = Router::new(config.routing)?;
        router.validate(&outbounds)?;
        let dns = DnsManager::new(config.dns.clone(), &outbounds, &router).await?;

        // pre_connect would replace server address with server socketaddr
        // which will make sure no outbound loopback in dns config
        let mut outbounds_with_domain_addr: VecDeque<(String, Arc<Box<dyn Outbound>>)> =
            VecDeque::new();
        for (tag, outbound) in outbounds.iter_mut() {
            match outbound.pre_connect(&dns).await {
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
            match outbound.pre_connect(&dns).await {
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
        let dns = DnsManager::new(config.dns, &outbounds, &router).await?;

        Ok(Self {
            inbounds,
            outbounds: Arc::new(outbounds),
            router: Arc::new(router),
            dns: Arc::new(dns),
        })
    }

    pub async fn serve(&self, channel: Option<mpsc::Sender<String>>) -> Result<()> {
        let router = self.router.clone();
        let outbounds = self.outbounds.clone();
        let dns = self.dns.clone();
        let inbounds = self.inbounds.iter();

        let mut vfut = Vec::new();
        for (tag, inbound) in inbounds {
            let inbound = inbound.to_owned();
            let context = Context::new(
                tag.to_owned(),
                outbounds.clone(),
                router.clone(),
                dns.clone(),
            );
            let channel = channel.clone();
            vfut.push(ServerHandle(tokio::spawn(async move {
                inbound.run(context, channel).await
            })));
        }
        let (res, ..) = future::select_all(vfut).await;
        // TODO: abort all the spawned tasks when serving is done
        res
    }

    pub fn run(config: Config) -> Result<()> {
        let error_target = if let Some(ref error_file) = config.log.error {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(error_file)?;
            Target::Pipe(Box::new(file))
        } else {
            Target::Stdout
        };
        let access_target = if let Some(ref access_file) = config.log.access {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(access_file)?;
            Target::Pipe(Box::new(file))
        } else {
            Target::Stdout
        };
        Logger::new(&config.log.loglevel, error_target, access_target)
            .init()
            .map_err(|e| invalid_input_error(format!("Failed to init logger: {}", e)))?;

        // let mut builder = tokio::runtime::Builder::new_current_thread();
        // let rt = builder.enable_all().build()?;
        let rt = tokio::runtime::Runtime::new()?;

        let future = async {
            let app = Self::new(config).await?;

            let server = app.serve(None).fuse();
            let abort_signal = create_abort_signal().fuse();
            tokio::pin!(abort_signal);
            tokio::pin!(server);

            futures::select! {
                result = server => {
                    match result {
                        // Server future resolved without an error. This should never happen.
                        Ok(..) => Err(invalid_data_error("server exited unexpectedly")),
                        // Server future resolved with error, which are listener errors in most cases
                        Err(err) => Err(invalid_data_error(format!("server aborted with error: {err}"))),
                    }
                }
                // The abort signal future resolved. Means we should just exit.
                _ = abort_signal => {
                    log::info!("SIGINT received; starting forced shutdown");
                    Ok(())
                }
            }
        };

        rt.block_on(future)
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
    pub async fn get_outbound(
        &self,
        address: &Address,
    ) -> Result<(&Arc<Box<dyn Outbound>>, String)> {
        let outbound_tag = self
            .router
            .pick(&self.dns, address, &self.inbound_tag)
            .await?;
        Ok((self.outbounds.get(&outbound_tag).unwrap(), outbound_tag))
    }

    #[inline]
    pub async fn resolve(&self, address: &Address) -> Result<SocketAddr> {
        self.dns.resolve(address).await
    }

    #[inline]
    pub async fn query(&self, peer_addr: SocketAddr, request: &Message) -> Result<Message> {
        self.dns.query(peer_addr, request).await
    }
}

pub(crate) async fn establish_tcp_tunnel<S>(
    stream: &mut Box<S>,
    peer: &SocketAddr,
    address: Address,
    context: Context,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    // TODO: connection pool
    // TODO: exponential retry connection
    let mut down_stream = connect_tcp_host(peer, address, context).await?;
    return copy_bidirectional(stream, &mut down_stream)
        .await
        .map(|_| ());
}

pub(crate) async fn connect_tcp_host(
    peer: &SocketAddr,
    address: Address,
    context: Context,
) -> Result<Box<dyn ProxyStream>> {
    let (outbound, outbound_tag) = context.get_outbound(&address).await?;
    log::info!(target: JETS_ACCESS_LIST, "from tcp:{} accepted tcp:{} [{} -> {}]", peer, address, context.inbound_tag.as_ref().unwrap_or(&"".to_string()), outbound_tag);

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
    let (outbound, outbound_tag) = context.get_outbound(&address).await?;
    log::info!(target: JETS_ACCESS_LIST, "from udp:{} accepted udp:{} [{} -> {}]", peer, address, context.inbound_tag.as_ref().unwrap_or(&"".to_string()), outbound_tag);

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
