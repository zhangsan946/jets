use super::{Outbound, ProxySocket, ProxyStream};
use crate::app::config::OutboundProtocolOption;
use crate::app::dns::DnsManager;
use crate::common::Address;
use async_trait::async_trait;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;

#[derive(Clone, Debug, Default)]
pub struct BlackholeOutbound;

#[async_trait]
impl Outbound for BlackholeOutbound {
    fn protocol(&self) -> OutboundProtocolOption {
        OutboundProtocolOption::Blackhole
    }

    async fn pre_connect(&self, _dns: &DnsManager) -> Result<Option<Box<dyn Outbound>>> {
        Ok(None)
    }

    async fn connect_tcp(&self, addr: Address) -> Result<Box<dyn ProxyStream>> {
        Err(Error::new(
            ErrorKind::WouldBlock,
            format!("{} went into to blackhole", addr),
        ))
    }

    async fn bind(&self, _peer: SocketAddr, addr: SocketAddr) -> Result<Box<dyn ProxySocket>> {
        Err(Error::new(
            ErrorKind::WouldBlock,
            format!("{} went into to blackhole", addr),
        ))
    }
}
