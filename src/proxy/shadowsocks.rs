use super::{Outbound, ProxySteam};
use crate::common::DEFAULT_CONTEXT;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use shadowsocks::config::{ServerAddr, ServerConfig};
use shadowsocks::relay::tcprelay::proxy_stream::client::ProxyClientStream;
use shadowsocks::relay::Address;
use shadowsocks_crypto::kind::CipherKind;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct ShadowsocksOutbound {
    server_config: ServerConfig,
}

impl ShadowsocksOutbound {
    pub fn new(addr: &str, password: &str, method: &str) -> Result<Self> {
        let addr = ServerAddr::from_str(addr)
            .map_err(|_| anyhow!("Invalid shadowsocks addr: {}", addr))?;
        let method = CipherKind::from_str(method)
            .map_err(|_| anyhow!("Invalid shadowsocks method: {}", method))?;
        let server_config =
            ServerConfig::new(addr, password, method).context("Invalid shadowsocks config")?;
        Ok(Self { server_config })
    }
}

#[async_trait]
impl Outbound for ShadowsocksOutbound {
    async fn handle(&self, addr: &Address) -> std::io::Result<Box<dyn ProxySteam>> {
        let stream =
            ProxyClientStream::connect(DEFAULT_CONTEXT.clone(), &self.server_config, addr).await?;
        let stream: Box<dyn ProxySteam> = Box::new(stream);
        Ok(stream)
    }
}
