mod http_client;
mod http_service;
mod http_stream;
mod utils;

use super::Inbound;
use crate::app::config::Account;
use crate::app::Context;
use crate::transport::raw::{AcceptOpts, TcpListener};
use async_trait::async_trait;
use http_service::HttpService;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::io::{ErrorKind, Result};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

#[derive(Clone, Debug)]
pub struct HttpInbound {
    addr: SocketAddr,
    accounts: HashMap<String, String>,
    accept_opts: AcceptOpts,
}

impl HttpInbound {
    pub fn new(addr: SocketAddr, accounts: Vec<Account>, accept_opts: AcceptOpts) -> Self {
        let accounts: HashMap<_, _> = accounts.into_iter().map(|a| (a.user, a.pass)).collect();
        Self {
            addr,
            accounts,
            accept_opts,
        }
    }
}

#[async_trait]
impl Inbound for HttpInbound {
    fn clone_box(&self) -> Box<dyn Inbound> {
        Box::new(self.clone())
    }

    async fn run(&self, context: Context) -> Result<()> {
        let listener = TcpListener::bind_with_opts(&self.addr, self.accept_opts.clone()).await?;
        let addr = listener.local_addr()?;
        log::info!("Starting http server, listening on: {}", addr);

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    log::error!("failed to accept HTTP clients, err: {}", err);
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            log::debug!("{} -> {}", peer_addr, addr);

            let context = context.clone();
            let accounts = self.accounts.clone();
            tokio::spawn(async move {
                match handle_tcp(stream, context, &accounts).await {
                    Ok(_) => Ok(()),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        log::info!("{} to inbound {} blocked: {:#}", peer_addr, addr, e);
                        Ok(())
                    }
                    Err(e) => {
                        log::error!("{} to Inbound {} failed: {:#}", peer_addr, addr, e);
                        Err(e)
                    }
                }
            });
        }
    }
}

pub async fn handle_tcp(
    stream: TcpStream,
    context: Context,
    accounts: &HashMap<String, String>,
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
                HttpService::new(peer_addr).serve_connection(req, accounts, context.clone())
            }),
        )
        .with_upgrades()
        .await;
    Ok(())
}
