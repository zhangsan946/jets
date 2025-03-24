use super::{Outbound, ProxySteam};
use crate::app::config::OutboundProtocolOption;
use crate::app::dns::DnsManager;
use crate::common::{invalid_input_error, Address};
use async_trait::async_trait;
use shadowsocks::config::{ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::relay::tcprelay::proxy_stream::client::ProxyClientStream;
use shadowsocks_crypto::kind::CipherKind;
use std::io::Result;

#[derive(Clone, Debug)]
pub struct ShadowsocksOutbound {
    server_config: ServerConfig,
    context: SharedContext,
}

impl ShadowsocksOutbound {
    pub fn new(addr: Address, password: String, method: CipherKind) -> Result<Self> {
        let server_config =
            ServerConfig::new(addr, password, method).map_err(invalid_input_error)?;
        Ok(Self {
            server_config,
            context: Context::new_shared(ServerType::Local),
        })
    }
}

#[async_trait]
impl Outbound for ShadowsocksOutbound {
    async fn handle(&self, addr: &Address) -> Result<Box<dyn ProxySteam>> {
        let stream =
            ProxyClientStream::connect(self.context.clone(), &self.server_config, addr).await?;
        Ok(Box::new(stream) as Box<dyn ProxySteam>)
    }

    fn protocol(&self) -> OutboundProtocolOption {
        OutboundProtocolOption::Shadowsocks
    }

    async fn pre_connect(&self, dns: &DnsManager) -> Result<Option<Box<dyn Outbound>>> {
        let addr = self.server_config.addr();
        if matches!(addr, ServerAddr::DomainName(_, _)) {
            let addr = Address::DomainNameAddress(addr.host(), addr.port());
            let addr = dns.resolve(&addr).await?;
            let mut outbound = self.clone();
            outbound.server_config.set_addr(addr);
            Ok(Some(Box::new(outbound) as Box<dyn Outbound>))
        } else {
            Ok(None)
        }
    }
}
