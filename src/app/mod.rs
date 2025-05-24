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
use crate::common::{copy_bidirectional, invalid_data_error, invalid_input_error, Address};
use crate::proxy::{Outbound, ProxySocket, ProxyStream};
pub use config::Config;
use dns::DnsManager;
use futures::{future, FutureExt};
use proxy::{Inbounds, Outbounds};
use router::Router;
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Runtime;
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
    pub fn new(config: Config) -> Result<Self> {
        let mut builder = env_logger::Builder::new();
        builder.parse_env(env_logger::Env::new().default_filter_or(config.log.loglevel));
        let target = if let Some(error_file) = config.log.error {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(error_file)?;
            env_logger::Target::Pipe(Box::new(file))
        } else {
            env_logger::Target::Stdout
        };
        builder.target(target);
        builder.init();

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

        //let mut builder = tokio::runtime::Builder::new_current_thread();
        //let rt = builder.enable_all().build()?;
        let rt = Runtime::new()?;

        let future = async move {
            let server = async move {
                let mut vfut = Vec::new();
                for (tag, inbound) in inbounds {
                    let inbound = inbound.to_owned();
                    let context = Context::new(
                        tag.to_owned(),
                        outbounds.clone(),
                        router.clone(),
                        dns.clone(),
                    );
                    vfut.push(ServerHandle(tokio::spawn(async move {
                        inbound.run(context).await
                    })));
                }
                let (res, ..) = future::select_all(vfut).await;
                res
            };

            let abort_signal = create_abort_signal().fuse();
            let server = server.fuse();
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
