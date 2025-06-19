use super::{Outbound, ProxySocket, ProxyStream};
use crate::app::config::OutboundProtocolOption;
use crate::app::dns::DnsManager;
use crate::common::Address;
use crate::transport::TransportSettings;
use async_trait::async_trait;
use std::io::Result;
use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct FreedomOutbound {
    transport_settings: TransportSettings,
}

impl FreedomOutbound {
    pub fn new(transport_settings: TransportSettings) -> Self {
        Self { transport_settings }
    }
}

#[async_trait]
impl Outbound for FreedomOutbound {
    fn protocol(&self) -> OutboundProtocolOption {
        OutboundProtocolOption::Freedom
    }

    async fn pre_connect(&self, _dns: &DnsManager) -> Result<Option<Box<dyn Outbound>>> {
        Ok(None)
    }

    async fn connect_tcp(&self, addr: Address) -> Result<Box<dyn ProxyStream>> {
        if let Address::SocketAddress(ref addr) = addr {
            self.transport_settings.connect_tcp(addr, false).await
        } else {
            unreachable!()
        }
    }

    async fn bind(&self, _peer: SocketAddr, target: Address) -> Result<Box<dyn ProxySocket>> {
        if let Address::SocketAddress(ref addr) = target {
            // TODO: Support to serve IPv4 and IPv6 at the same time
            self.transport_settings.bind(addr).await
        } else {
            unreachable!()
        }
    }
}
