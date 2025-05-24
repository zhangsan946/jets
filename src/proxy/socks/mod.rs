pub mod socks5;

use super::http::handle_tcp as http_handle_tcp;
use super::Inbound;
use crate::app::config::Account;
use crate::app::Context;
use crate::common::invalid_data_error;
use crate::transport::raw::{AcceptOpts, TcpListener, UdpSocket};
use async_trait::async_trait;
use futures::{future, FutureExt};
use socks5::Socks5Inbound;
pub use socks5::Socks5Outbound;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

#[derive(Clone, Debug)]
pub struct SocksInbound {
    addr: SocketAddr,
    accounts: HashMap<String, String>,
    udp_enabled: bool,
    accept_opts: AcceptOpts,
}

impl SocksInbound {
    pub fn new(
        addr: SocketAddr,
        accounts: Vec<Account>,
        udp_enabled: bool,
        accept_opts: AcceptOpts,
    ) -> Self {
        let accounts: HashMap<_, _> = accounts.into_iter().map(|a| (a.user, a.pass)).collect();
        Self {
            addr,
            accounts,
            udp_enabled,
            accept_opts,
        }
    }
}

#[async_trait]
impl Inbound for SocksInbound {
    fn clone_box(&self) -> Box<dyn Inbound> {
        Box::new(self.clone())
    }

    async fn run(&self, context: Context) -> Result<()> {
        let run_tcp = async {
            let listener =
                TcpListener::bind_with_opts(&self.addr, self.accept_opts.clone()).await?;
            let addr = listener.local_addr()?;
            log::info!("Starting socks tcp server, listening on: {}", addr);

            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("socks server {} accept failed with error: {}", addr, e);
                        sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                log::debug!("{} -> {}", peer_addr, addr);
                let context = context.clone();
                let addr = self.addr;
                let accounts = self.accounts.clone();
                let udp_enabled = self.udp_enabled;
                tokio::spawn(async move {
                    match handle_tcp(stream, context, addr, accounts, udp_enabled).await {
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
        };

        let mut vfut = Vec::new();
        vfut.push(run_tcp.boxed());

        if self.udp_enabled {
            let run_udp = async {
                let socket =
                    UdpSocket::listen_with_opts(&self.addr, self.accept_opts.clone()).await?;
                let addr = socket.local_addr()?;
                log::info!("Starting socks5 udp server, listening on: {}", addr);
                let socket = Arc::new(socket);
                let socks5_inbound =
                    Socks5Inbound::new(self.addr, self.accounts.clone(), self.udp_enabled);
                socks5_inbound.handle_udp(socket, context.clone()).await
            };
            vfut.push(run_udp.boxed());
        }

        let (res, ..) = future::select_all(vfut).await;
        res
    }
}

pub async fn handle_tcp(
    stream: TcpStream,
    context: Context,
    addr: SocketAddr,
    accounts: HashMap<String, String>,
    udp_enabled: bool,
) -> Result<()> {
    let mut version_buffer = [0u8; 1];
    let n = stream.peek(&mut version_buffer).await?;
    if n == 0 {
        return Err(Error::from(ErrorKind::UnexpectedEof));
    }

    match version_buffer[0] {
        0x04 => {
            todo!("socks4 inbound");
        }
        0x05 => {
            let socks5_inbound = Socks5Inbound::new(addr, accounts, udp_enabled);
            socks5_inbound.handle_tcp(stream, context).await
        }
        b'G' | b'g' | b'H' | b'h' | b'P' | b'p' | b'D' | b'd' | b'C' | b'c' | b'O' | b'o'
        | b'T' | b't' => http_handle_tcp(stream, context, &accounts).await,
        version => Err(invalid_data_error(format!(
            "Socks version {:#x} is not supported",
            version
        ))),
    }
}
