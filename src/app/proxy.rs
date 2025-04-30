use super::config::{
    InboundConfig, InboundProtocolOption, InboundSettings, OutboundConfig, OutboundProtocolOption,
    OutboundSettings,
};
use super::router::DEFAULT_OUTBOUND_TAG;
use crate::common::{invalid_input_error, Address};
#[cfg(feature = "inbound-http")]
use crate::proxy::http::HttpInbound;
#[cfg(feature = "outbound-trojan")]
use crate::proxy::trojan::TrojanOutbound;
use crate::proxy::{
    blackhole::BlackholeOutbound,
    freedom::FreedomOutbound,
    shadowsocks::ShadowsocksOutbound,
    socks::{Socks5Outbound, SocksInbound},
    vless::VlessOutbound,
};
use crate::proxy::{Inbound, Outbound};
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

pub struct Inbounds {
    inner: Vec<(Option<String>, Box<dyn Inbound>)>,
}

impl Inbounds {
    pub fn new(inbounds: Vec<InboundConfig>) -> Result<Self> {
        let mut inner: Vec<(Option<String>, Box<dyn Inbound>)> = Vec::new();
        let mut inbound_tags: HashSet<String> = HashSet::new();
        for inbound in inbounds.into_iter() {
            let tag = inbound.tag.clone();
            if let Some(ref val) = tag {
                if !inbound_tags.insert(val.clone()) {
                    return Err(Error::new(
                        ErrorKind::AlreadyExists,
                        format!("Duplicate inbound with tag {}", val),
                    ));
                }
            }
            inner.push((tag, parse_inbound(inbound)?));
        }
        Ok(Self { inner })
    }

    pub fn iter(&self) -> std::slice::Iter<'_, (Option<String>, Box<dyn Inbound>)> {
        self.inner.iter()
    }
}

pub struct Outbounds {
    inner: HashMap<String, Arc<Box<dyn Outbound>>>,
    freedom: Option<Arc<Box<dyn Outbound>>>,
}

impl Outbounds {
    pub fn new(outbounds: Vec<OutboundConfig>) -> Result<Self> {
        let mut inner: HashMap<String, Arc<Box<dyn Outbound>>> = HashMap::new();
        let mut freedom: Option<Arc<Box<dyn Outbound>>> = None;
        for (index, outbound) in outbounds.into_iter().enumerate() {
            let tag = outbound.tag.clone();
            let outbound = Arc::new(parse_outbound(outbound)?);
            if index == 0 {
                inner.insert(DEFAULT_OUTBOUND_TAG.to_string(), outbound.clone());
            }
            if freedom.is_none() && outbound.protocol() == OutboundProtocolOption::Freedom {
                let _ = freedom.insert(outbound.clone());
            }
            if let Some(tag) = tag {
                if inner.insert(tag.clone(), outbound).is_some() {
                    return Err(Error::new(
                        ErrorKind::AlreadyExists,
                        format!("Duplicate outbound with tag {}", tag),
                    ));
                }
            }
        }
        Ok(Self { inner, freedom })
    }

    pub fn from(
        inner: HashMap<String, Arc<Box<dyn Outbound>>>,
        freedom: Option<Arc<Box<dyn Outbound>>>,
    ) -> Self {
        Self { inner, freedom }
    }

    pub fn get(&self, tag: &str) -> Option<&Arc<Box<dyn Outbound>>> {
        self.inner.get(tag)
    }

    pub fn insert(
        &mut self,
        tag: String,
        outbound: Arc<Box<dyn Outbound>>,
    ) -> Option<Arc<Box<dyn Outbound>>> {
        self.inner.insert(tag, outbound)
    }

    pub fn remove(&mut self, tag: &str) -> Option<Arc<Box<dyn Outbound>>> {
        match self.inner.remove(tag) {
            Some(outbound) => {
                if let Some(ref freedom) = self.freedom {
                    if Arc::ptr_eq(freedom, &outbound) {
                        self.freedom = None;
                    }
                }
                Some(outbound)
            }
            None => None,
        }
    }

    pub fn iter_mut(
        &mut self,
    ) -> std::collections::hash_map::IterMut<'_, String, Arc<Box<dyn Outbound>>> {
        self.inner.iter_mut()
    }

    pub fn first_freedom(&self) -> Option<Arc<Box<dyn Outbound>>> {
        self.freedom.clone()
    }
}

fn parse_inbound(inbound: InboundConfig) -> Result<Box<dyn Inbound>> {
    match inbound.protocol {
        #[cfg(feature = "inbound-http")]
        InboundProtocolOption::Http => {
            let addr = format!("{}:{}", inbound.listen, inbound.port);
            let addr = SocketAddr::from_str(&addr).map_err(|_| invalid_input_error(addr))?;
            let accounts = if let InboundSettings::Http { accounts } = inbound.settings {
                accounts
            } else {
                Vec::new()
            };
            let http_inbound = HttpInbound::new(addr, accounts);
            Ok(Box::new(http_inbound) as Box<dyn Inbound>)
        }
        #[cfg(not(feature = "inbound-http"))]
        InboundProtocolOption::Http => Err(Error::new(
            ErrorKind::Unsupported,
            "Found http inbound but inbound-http is not enabled",
        )),
        InboundProtocolOption::Socks => {
            let addr = format!("{}:{}", inbound.listen, inbound.port);
            let addr = SocketAddr::from_str(&addr).map_err(|_| invalid_input_error(addr))?;
            let (accounts, udp_enabled) = if let InboundSettings::Socks {
                auth: _,
                accounts,
                udp,
            } = inbound.settings
            {
                (accounts, udp)
            } else {
                (Vec::new(), false)
            };
            let socks_inbound = SocksInbound::new(addr, accounts, udp_enabled);
            Ok(Box::new(socks_inbound) as Box<dyn Inbound>)
        }
    }
}

fn parse_outbound(outbound: OutboundConfig) -> Result<Box<dyn Outbound>> {
    match outbound.protocol {
        OutboundProtocolOption::Blackhole => Ok(Box::new(BlackholeOutbound) as Box<dyn Outbound>),
        OutboundProtocolOption::Freedom => {
            Ok(Box::new(FreedomOutbound::default()) as Box<dyn Outbound>)
        }
        OutboundProtocolOption::Shadowsocks => {
            if let OutboundSettings::Shadowsocks { mut servers } = outbound.settings {
                if !servers.is_empty() {
                    let server = servers.remove(0);
                    let addr = format!("{}:{}", server.address, server.port);
                    let addr = Address::from_str(&addr).map_err(|_| invalid_input_error(addr))?;
                    let outbound = ShadowsocksOutbound::new(addr, server.password, server.method)?;
                    return Ok(Box::new(outbound) as Box<dyn Outbound>);
                }
            }
            Err(invalid_input_error("Invalid shadowsocks outbound"))
        }
        OutboundProtocolOption::Socks => {
            if let OutboundSettings::Socks { mut servers } = outbound.settings {
                if !servers.is_empty() {
                    let server = servers.remove(0);
                    let addr = format!("{}:{}", server.address, server.port);
                    let addr = Address::from_str(&addr).map_err(|_| invalid_input_error(addr))?;
                    let outbound = Socks5Outbound::new(addr, server.users);
                    return Ok(Box::new(outbound) as Box<dyn Outbound>);
                }
            }
            Err(invalid_input_error("Invalid socks outbound"))
        }
        #[cfg(feature = "outbound-trojan")]
        OutboundProtocolOption::Trojan => {
            if let OutboundSettings::Trojan { mut servers } = outbound.settings {
                if !servers.is_empty() {
                    let server = servers.remove(0);
                    let addr = format!("{}:{}", server.address, server.port);
                    let addr = Address::from_str(&addr).map_err(|_| invalid_input_error(addr))?;
                    let outbound = TrojanOutbound::new(
                        addr,
                        server.password,
                        outbound.stream_settings.tls_settings,
                    )?;
                    return Ok(Box::new(outbound) as Box<dyn Outbound>);
                }
            }
            Err(invalid_input_error("Invalid trojan outbound"))
        }
        #[cfg(not(feature = "outbound-trojan"))]
        OutboundProtocolOption::Trojan => Err(Error::new(
            ErrorKind::Unsupported,
            "Found trojan outbound but outbound-trojan is not enabled",
        )),
        OutboundProtocolOption::Vless => {
            if let OutboundSettings::Vless { mut vnext } = outbound.settings {
                if !vnext.is_empty() && !vnext[0].users.is_empty() {
                    let mut server = vnext.remove(0);
                    let addr = format!("{}:{}", server.address, server.port);
                    let addr = Address::from_str(&addr).map_err(|_| invalid_input_error(addr))?;
                    let user = server.users.remove(0);
                    let outbound = VlessOutbound::new(
                        addr,
                        user.id,
                        user.flow,
                        outbound.stream_settings.tls_settings,
                    )?;
                    return Ok(Box::new(outbound) as Box<dyn Outbound>);
                }
            }
            Err(invalid_input_error("Invalid vless outbound"))
        }
    }
}
