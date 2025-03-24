pub mod socks5;

use super::Inbound;
use crate::app::config::Account;
use crate::app::dns::DnsManager;
use crate::app::proxy::Outbounds;
use crate::app::router::Router;
use crate::common::{invalid_data_error, Address};
use async_trait::async_trait;
use socks5::Socks5Inbound;
pub use socks5::Socks5Outbound;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::sync::Arc;
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub struct SocksInbound {
    addr: Address,
    accounts: HashMap<String, String>,
}

impl SocksInbound {
    pub fn new(addr: Address, accounts: Vec<Account>) -> Self {
        let accounts: HashMap<_, _> = accounts.into_iter().map(|a| (a.user, a.pass)).collect();
        Self { addr, accounts }
    }
}

#[async_trait]
impl Inbound for SocksInbound {
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
                let socks5_inbound = Socks5Inbound::from(self.clone());
                socks5_inbound
                    .handle(stream, inbound_tag, outbounds, router, dns)
                    .await
            }
            b'G' | b'g' | b'H' | b'h' | b'P' | b'p' | b'D' | b'd' | b'C' | b'c' | b'O' | b'o'
            | b'T' | b't' => {
                todo!("http inbound");
            }
            version => Err(invalid_data_error(format!(
                "Socks version {:#x} is not supported",
                version
            ))),
        }
    }
}
