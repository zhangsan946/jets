use super::{Outbound, ProxySteam};
use crate::app::config::OutboundProtocolOption;
use crate::app::dns::DnsManager;
use crate::common::Address;
use crate::transport::raw::{ConnectOpts, TcpStream};
use async_trait::async_trait;
use std::io::Result;

#[derive(Clone, Debug, Default)]
pub struct FreedomOutbound {
    connect_opts: ConnectOpts,
}

#[async_trait]
impl Outbound for FreedomOutbound {
    async fn handle(&self, addr: &Address) -> Result<Box<dyn ProxySteam>> {
        if let Address::SocketAddress(addr) = addr {
            let stream = TcpStream::connect_with_opts(addr, &self.connect_opts).await?;
            Ok(Box::new(stream) as Box<dyn ProxySteam>)
        } else {
            unreachable!()
        }
    }

    fn protocol(&self) -> OutboundProtocolOption {
        OutboundProtocolOption::Freedom
    }

    async fn pre_connect(&self, _dns: &DnsManager) -> Result<Option<Box<dyn Outbound>>> {
        Ok(None)
    }
}
