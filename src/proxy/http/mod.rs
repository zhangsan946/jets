mod http_client;
mod http_service;
mod http_stream;
mod utils;

use super::Inbound;
use crate::app::config::Account;
use crate::app::Context;
use async_trait::async_trait;
use http_service::HttpService;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::io::Result;
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub struct HttpInbound {
    addr: SocketAddr,
    accounts: HashMap<String, String>,
}

impl HttpInbound {
    pub fn new(addr: SocketAddr, accounts: Vec<Account>) -> Self {
        let accounts: HashMap<_, _> = accounts.into_iter().map(|a| (a.user, a.pass)).collect();
        Self { addr, accounts }
    }
}

#[async_trait]
impl Inbound for HttpInbound {
    fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    fn clone_box(&self) -> Box<dyn Inbound> {
        Box::new(self.clone())
    }

    async fn handle_tcp(&self, stream: TcpStream, context: Context) -> Result<()> {
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
                        context.clone(),
                    )
                }),
            )
            .with_upgrades()
            .await;
        Ok(())
    }

    async fn run_udp_server(&self, _: Context) -> Result<()> {
        Ok(())
    }
}
