pub mod addons {
    include!(concat!(env!("OUT_DIR"), "/xray.proxy.vless.encoding.rs"));
}
pub mod stream;
pub mod xtls;

use super::{request_command, Outbound, ProxySocket, ProxyStream};
use crate::app::config::{OutboundProtocolOption, VlessFlow};
use crate::app::dns::DnsManager;
use crate::common::{invalid_data_error, Address};
use crate::pre_check_addr;
use crate::transport::TransportSettings;
use async_trait::async_trait;
use bytes::BytesMut;
use once_cell::sync::Lazy;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use std::io::Result;
use std::net::SocketAddr;
use stream::{VlessHeaderRequest, VlessMuxStream, VlessStream, VlessUdpStream};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

// https://github.com/XTLS/Xray-core/blob/907a182f6436e717b56daf52f41f63e630fa9cf5/common/xudp/xudp.go#L50-L64
static BASE_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let mut rng = SmallRng::from_os_rng();
    rng.random()
});

fn get_global_id(peer: SocketAddr) -> [u8; 8] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BASE_KEY.as_slice());
    hasher.update(peer.to_string().as_bytes());
    let mut output = [0u8; 8];
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(&mut output);
    output
}

#[derive(Clone, Debug)]
pub struct VlessOutbound {
    addr: Address,
    id: Uuid,
    flow: VlessFlow,
    transport_settings: TransportSettings,
}

impl VlessOutbound {
    pub fn new(
        addr: Address,
        id: Uuid,
        flow: VlessFlow,
        transport_settings: TransportSettings,
    ) -> Result<Self> {
        Ok(Self {
            addr,
            id,
            flow,
            transport_settings,
        })
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
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

    async fn connect_tcp(&self, addr: Address) -> Result<Box<dyn ProxyStream>> {
        let server_addr = pre_check_addr!(self.addr);
        let mut stream = self
            .transport_settings
            .connect_tcp(server_addr, self.flow != VlessFlow::None)
            .await?;

        let stream_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time is earlier than UNIX_EPOCH")
            .as_millis() as u32;

        let request = VlessHeaderRequest::new(&addr, &self.id, &self.flow, request_command::TCP);
        let mut buffer = BytesMut::with_capacity(request.serialized_len());
        request.write_to_buf(&mut buffer);
        stream.write_all(&buffer).await?;
        log::debug!(
            "{} Writing request header with flow {:?}",
            stream_id,
            self.flow
        );

        Ok(Box::new(VlessStream::new(
            stream, addr, self.id, self.flow, stream_id,
        )))
    }

    async fn bind(&self, peer: SocketAddr, target: Address) -> Result<Box<dyn ProxySocket>> {
        if target.port() == 443 && self.flow == VlessFlow::XtlsRprxVision {
            return Err(invalid_data_error("XTLS rejected UDP/443 traffic"));
        }
        let server_addr = pre_check_addr!(self.addr);
        let mut stream = self
            .transport_settings
            .connect_tcp(server_addr, self.flow != VlessFlow::None)
            .await?;

        // https://github.com/XTLS/Xray-core/discussions/252
        // TODO: use mux to proxy none flow UDP packets
        // if request.Command == protocol.RequestCommandUDP && (requestAddons.Flow == vless.XRV || (h.cone && request.Port != 53 && request.Port != 443)) {
        //     request.Command = protocol.RequestCommandMux
        //     request.Address = net.DomainAddress("v1.mux.cool")
        //     request.Port = net.Port(666)
        // }
        let (address, command) = match self.flow {
            VlessFlow::None => (target.clone(), request_command::UDP),
            _ => (
                Address::DomainNameAddress("v1.mux.cool".to_string(), 666),
                request_command::MUX,
            ),
        };
        let flow = match self.flow {
            VlessFlow::XtlsRprxVisionUdp => VlessFlow::XtlsRprxVision,
            val => val,
        };
        let request = VlessHeaderRequest::new(&address, &self.id, &flow, command);
        let mut buffer = BytesMut::with_capacity(request.serialized_len());
        request.write_to_buf(&mut buffer);
        stream.write_all(&buffer).await?;
        log::debug!("Writing request header with flow {:?}", self.flow);
        match self.flow {
            VlessFlow::None => Ok(Box::new(VlessUdpStream::new(stream, target))),
            _ => {
                let stream_id = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("System time is earlier than UNIX_EPOCH")
                    .as_millis() as u32;
                let global_id = get_global_id(peer);
                Ok(Box::new(VlessMuxStream::new(
                    stream, self.id, global_id, stream_id,
                )))
            }
        }
    }
}
