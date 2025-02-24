pub mod socks5;

use crate::common::{new_io_error, Address};
use crate::proxy::{Inbound, ProxySteam};
use anyhow::{Context, Result};
use async_trait::async_trait;
use socks5::Socks5Inbound;
pub use socks5::Socks5Outbound;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub struct SocksInbound {
    addr: Address,
    accounts: HashMap<String, String>,
}

impl SocksInbound {
    pub fn new(addr: &str, accounts: Vec<(String, String)>) -> Result<Self> {
        let addr =
            Address::from_str(addr).context(format!("Invalid socks inbound address: {addr}"))?;
        let accounts: HashMap<_, _> = accounts.into_iter().collect();
        Ok(Self { addr, accounts })
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
    ) -> std::io::Result<(Box<dyn ProxySteam>, Address)> {
        let io = stream
            .as_any()
            .downcast_ref::<TcpStream>()
            .ok_or_else(|| new_io_error("Invalid tcp stream"))?;
        let mut version_buffer = [0u8; 1];
        let n = io.peek(&mut version_buffer).await?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
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
