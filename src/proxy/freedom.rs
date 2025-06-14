#[cfg(unix)]
use super::FdProtecter;
use super::{Outbound, ProxySocket, ProxyStream};
use crate::app::config::OutboundProtocolOption;
use crate::app::dns::DnsManager;
use crate::common::Address;
use crate::transport::raw::{ConnectOpts, TcpStream, UdpSocket};
use async_trait::async_trait;
use std::io::Result;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd;

#[derive(Clone, Debug)]
pub struct FreedomOutbound {
    connect_opts: ConnectOpts,
    #[cfg(unix)]
    protecter: Option<FdProtecter>,
}

impl FreedomOutbound {
    pub fn new(connect_opts: ConnectOpts, #[cfg(unix)] protecter: Option<FdProtecter>) -> Self {
        FreedomOutbound {
            connect_opts,
            #[cfg(unix)]
            protecter,
        }
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
            let stream = TcpStream::connect_with_opts(addr, &self.connect_opts).await?;
            #[cfg(unix)]
            if let Some(protecter) = &self.protecter {
                protecter.protect(stream.as_raw_fd());
            }
            Ok(Box::new(stream) as Box<dyn ProxyStream>)
        } else {
            unreachable!()
        }
    }

    async fn bind(&self, _peer: SocketAddr, target: Address) -> Result<Box<dyn ProxySocket>> {
        if let Address::SocketAddress(addr) = target {
            // TODO: IPv6
            let socket = UdpSocket::connect_any_with_opts(addr, &self.connect_opts).await?;
            #[cfg(unix)]
            if let Some(protecter) = &self.protecter {
                use std::ops::Deref;
                protecter.protect(socket.deref().as_raw_fd());
            }
            Ok(Box::new(socket) as Box<dyn ProxySocket>)
        } else {
            unreachable!()
        }
    }
}
