mod http_client;
mod http_service;
mod http_stream;
mod utils;

use super::Inbound;
use crate::app::config::Account;
use crate::app::dns::DnsManager;
use crate::app::proxy::Outbounds;
use crate::app::router::Router;
use crate::common::Address;
use async_trait::async_trait;
use http_service::HttpService;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::io::Result;
use std::sync::Arc;
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub struct HttpInbound {
    addr: Address,
    accounts: HashMap<String, String>,
}

impl HttpInbound {
    pub fn new(addr: Address, accounts: Vec<Account>) -> Self {
        let accounts: HashMap<_, _> = accounts.into_iter().map(|a| (a.user, a.pass)).collect();
        Self { addr, accounts }
    }
}

#[async_trait]
impl Inbound for HttpInbound {
    fn addr(&self) -> &Address {
        &self.addr
    }

    fn clone_box(&self) -> Box<dyn Inbound> {
        Box::new(self.clone())
    }

    async fn handle(
        &self,
        stream: TcpStream,
        inbound_tag: Option<String>,
        outbounds: Arc<Outbounds>,
        router: Arc<Router>,
        dns: Arc<DnsManager>,
    ) -> Result<()> {
        let peer_addr = stream.peer_addr()?;
        let io = TokioIo::new(stream);
        let _ = http1::Builder::new()
            .keep_alive(true)
            .title_case_headers(true)
            .preserve_header_case(true)
            .serve_connection(
                io,
                service_fn(move |req| {
                    HttpService::new(peer_addr).serve_connection(
                        req,
                        &self.accounts,
                        inbound_tag.clone(),
                        outbounds.clone(),
                        router.clone(),
                        dns.clone(),
                    )
                }),
            )
            .with_upgrades()
            .await;
        Ok(())
    }
}
