use super::{Outbound, ProxySteam};
use crate::common::{Address, DEFAULT_CONTEXT};
use async_trait::async_trait;
use shadowsocks::config::ServerConfig;
use shadowsocks::relay::tcprelay::proxy_stream::client::ProxyClientStream;
use shadowsocks_crypto::kind::CipherKind;
use std::io::{Error, ErrorKind, Result};

#[derive(Clone, Debug)]
pub struct ShadowsocksOutbound {
    server_config: ServerConfig,
}

impl ShadowsocksOutbound {
    pub fn new(addr: Address, password: &str, method: CipherKind) -> Result<Self> {
        let server_config = ServerConfig::new(addr, password, method)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
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
