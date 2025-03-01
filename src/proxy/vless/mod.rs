pub mod addons {
    include!(concat!(env!("OUT_DIR"), "/xray.proxy.vless.encoding.rs"));
}
pub mod stream;
pub mod xtls;

use super::{Outbound, ProxySteam};
use crate::app::config::VlessFlow;
use crate::common::{Address, ConnectOpts};
use crate::transport::tls::Tls;
use async_trait::async_trait;
use bytes::BytesMut;
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
    pub fn new(addr: Address, id: Uuid, flow: VlessFlow) -> Self {
        Self {
            addr,
            id,
            flow,
            connect_opts: ConnectOpts::default(),
            tls: Tls::default(),
        }
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    async fn handle(&self, addr: &Address) -> std::io::Result<Box<dyn ProxySteam>> {
        let mut stream = self
            .tls
            .connect(&self.addr, &self.connect_opts, self.flow != VlessFlow::None)
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
}
