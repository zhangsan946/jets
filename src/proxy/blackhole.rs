use super::{Outbound, ProxySteam};
use crate::app::config::OutboundProtocolOption;
use crate::app::dns::DnsManager;
use crate::common::Address;
use async_trait::async_trait;
use std::io::Result;

#[derive(Clone, Debug, Default)]
pub struct BlackholeOutbound;

#[async_trait]
impl Outbound for BlackholeOutbound {
    async fn handle(&self, addr: &Address) -> Result<Box<dyn ProxySteam>> {
        panic!("{} went into blackhole", addr);
    }

    fn protocol(&self) -> OutboundProtocolOption {
        OutboundProtocolOption::Blackhole
    }

    async fn pre_connect(&self, _dns: &DnsManager) -> Result<Option<Box<dyn Outbound>>> {
        Ok(None)
    }
}
