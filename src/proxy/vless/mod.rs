pub mod addons {
    include!(concat!(env!("OUT_DIR"), "/xray.proxy.vless.encoding.rs"));
}
pub mod stream;
pub mod xtls;

use super::{Outbound, ProxySteam};
use crate::common::{Address, ConnectOpts};
use crate::transport::tls::Tls;
use anyhow::{anyhow, Context as _};
use async_trait::async_trait;
use bytes::BytesMut;
use std::str::FromStr;
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
    pub fn new(addr: &str, id: &str, flow: &str) -> anyhow::Result<Self> {
        let addr =
            Address::from_str(addr).context(format!("Invalid vless outbound address: {addr}"))?;

        // generate uuid with nil uuid as namespace and id as name
        // https://github.com/XTLS/Xray-core/issues/158
        let id = Uuid::parse_str(id).unwrap_or_else(|_| Uuid::new_v5(&Uuid::nil(), id.as_bytes()));
        let flow = VlessFlow::from_str(flow).map_err(|e| anyhow!("{}: {}", e, flow))?;
        Ok(Self {
            addr,
            id,
            flow,
            connect_opts: ConnectOpts::default(),
            tls: Tls::default(),
        })
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    async fn handle(&self, addr: &Address) -> std::io::Result<Box<dyn ProxySteam>> {
        let mut stream = self.tls.connect(&self.addr, &self.connect_opts).await?;

        let stream_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time is earlier than UNIX_EPOCH")
            .as_millis() as u32;

        let request = VlessHeaderRequest::new(addr.clone(), self.id, self.flow);
        let mut buffer = BytesMut::with_capacity(request.serialized_len());
        request.write_to_buf(&mut buffer);
        stream.write_all(&buffer).await?;
        log::debug!(
            "{} Writing request header with flow {}",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VlessFlow {
    None,
    XtlsRprxVision,
    XtlsRprxVisionUdp,
}

impl FromStr for VlessFlow {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" => Ok(VlessFlow::None),
            "xtls-rprx-vision" => Ok(VlessFlow::XtlsRprxVision),
            "xtls-rprx-vision-udp443" => Ok(VlessFlow::XtlsRprxVisionUdp),
            _ => Err("Invalid vless flow"),
        }
    }
}

impl std::fmt::Display for VlessFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VlessFlow::None => f.write_str(""),
            VlessFlow::XtlsRprxVision => f.write_str("xtls-rprx-vision"),
            VlessFlow::XtlsRprxVisionUdp => f.write_str("xtls-rprx-vision-udp443"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::VlessOutbound;
    use uuid::Uuid;

    #[test]
    fn test_map_str_to_uuidv5() {
        let example = "example";
        let uuid = Uuid::parse_str("feb54431-301b-52bb-a6dd-e1e93e81bb9e").unwrap();
        let outbound = VlessOutbound::new("127.0.0.1:1080", example, "").unwrap();
        assert_eq!(uuid, outbound.id);
    }
}
