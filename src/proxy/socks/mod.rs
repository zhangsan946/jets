pub mod socks5;

use crate::common::{new_io_error, Address};
use crate::proxy::{Inbound, ProxySteam};
use async_trait::async_trait;
use socks5::Socks5Inbound;
pub use socks5::Socks5Outbound;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub struct SocksInbound {
    addr: Address,
    accounts: HashMap<String, String>,
}

impl SocksInbound {
    pub fn new(addr: Address, accounts: Vec<(String, String)>) -> Self {
        let accounts: HashMap<_, _> = accounts.into_iter().collect();
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
        stream: Box<dyn ProxySteam>,
        peer_addr: &SocketAddr,
    ) -> Result<(Box<dyn ProxySteam>, Address)> {
        let conn = stream
            .as_any()
            .downcast_ref::<TcpStream>()
            .ok_or_else(|| new_io_error("Invalid tcp stream"))?;
        let mut version_buffer = [0u8; 1];
        let n = conn.peek(&mut version_buffer).await?;
        if n == 0 {
            return Err(Error::from(ErrorKind::UnexpectedEof));
        }

        match version_buffer[0] {
            0x04 => {
                todo!("socks4 inbound");
            }
            0x05 => {
                let socks5_inbound = Socks5Inbound::from(self.clone());
                socks5_inbound.handle(stream, peer_addr).await
            }
            b'G' | b'g' | b'H' | b'h' | b'P' | b'p' | b'D' | b'd' | b'C' | b'c' | b'O' | b'o'
            | b'T' | b't' => {
                todo!("http inbound");
            }
            version => Err(new_io_error(format!(
                "Socks version {:#x} is not supported",
                version
            ))),
        }
    }
}
