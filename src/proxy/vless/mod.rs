pub mod addons {
    include!(concat!(env!("OUT_DIR"), "/xray.proxy.vless.encoding.rs"));
}
pub mod stream;
pub mod xtls;

use super::{Outbound, ProxySteam};
use crate::app::config::{OutboundProtocolOption, TlsSettings, VlessFlow};
use crate::app::dns::DnsManager;
use crate::common::Address;
use crate::pre_check_addr;
use crate::transport::raw::ConnectOpts;
use crate::transport::tls::Tls;
use async_trait::async_trait;
use bytes::BytesMut;
use std::io::Result;
use stream::{VlessHeaderRequest, VlessStream};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct VlessOutbound {
    addr: Address,
    id: Uuid,
    flow: VlessFlow,
    connect_opts: ConnectOpts,
    tls: Tls,
}

impl VlessOutbound {
    pub fn new(
        addr: Address,
        id: Uuid,
        flow: VlessFlow,
        tls_settings: TlsSettings,
    ) -> Result<Self> {
        let tls = Tls::new(tls_settings, &addr)?;
        Ok(Self {
            addr,
            id,
            flow,
            connect_opts: ConnectOpts::default(),
            tls,
        })
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    async fn handle(&self, addr: &Address) -> Result<Box<dyn ProxySteam>> {
        let server_addr = pre_check_addr!(self.addr);
        let mut stream = self
            .tls
            .connect(
                server_addr,
                &self.connect_opts,
                self.flow != VlessFlow::None,
            )
            .await?;

        let stream_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time is earlier than UNIX_EPOCH")
            .as_millis() as u32;

        let request = VlessHeaderRequest::new(addr.clone(), self.id, self.flow);
        let mut buffer = BytesMut::with_capacity(request.serialized_len());
        request.write_to_buf(&mut buffer);
        stream.write_all(&buffer).await?;
        log::debug!(
            "{} Writing request header with flow {:?}",
            stream_id,
            self.flow
        );

        Ok(Box::new(VlessStream::new(
            stream,
            addr.clone(),
            self.id,
            self.flow,
            stream_id,
        )))
    }

    fn protocol(&self) -> OutboundProtocolOption {
        OutboundProtocolOption::Vless
    }

    async fn pre_connect(&self, dns: &DnsManager) -> Result<Option<Box<dyn Outbound>>> {
        if matches!(self.addr, Address::DomainNameAddress(_, _)) {
            let addr = dns.resolve(&self.addr).await?;
            let mut outbound = self.clone();
            outbound.addr = Address::SocketAddress(addr);
            Ok(Some(Box::new(outbound) as Box<dyn Outbound>))
        } else {
            Ok(None)
        }
    }
}
