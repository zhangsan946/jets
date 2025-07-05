use super::Inbound;
use crate::app::Context as AppContext;
use crate::common::{Address, MAXIMUM_UDP_PAYLOAD_SIZE};
use crate::transport::raw::{AcceptOpts, UdpSocket};
use async_trait::async_trait;
use hickory_resolver::proto::op::header::MessageType;
use hickory_resolver::proto::op::response_code::ResponseCode;
use hickory_resolver::proto::op::{Message, OpCode};
use hickory_resolver::proto::rr::{
    rdata::{A, AAAA},
    DNSClass, RData, Record,
};
use std::io::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

#[derive(Clone, Debug)]
pub struct DnsInbound {
    addr: SocketAddr,
    accept_opts: AcceptOpts,
}

impl DnsInbound {
    pub fn new(addr: SocketAddr, accept_opts: AcceptOpts) -> Self {
        Self { addr, accept_opts }
    }
}

#[async_trait]
impl Inbound for DnsInbound {
    fn clone_box(&self) -> Box<dyn Inbound> {
        Box::new(self.clone())
    }

    async fn run(&self, context: AppContext, channel: Option<mpsc::Sender<String>>) -> Result<()> {
        let socket = UdpSocket::listen_with_opts(&self.addr, self.accept_opts.clone()).await?;
        let addr = socket.local_addr()?;
        log::info!("Starting dns udp server, listening on: {}", addr);
        if let Some(channel) = channel {
            let _ = channel.send("dns_udp".to_string()).await;
        }
        let socket = Arc::new(socket);

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let recv_result = socket.recv_from(&mut buffer).await;
            let (n, peer_addr) = match recv_result {
                Ok(s) => s,
                Err(err) => {
                    log::error!("udp server recv_from failed with error: {}", err);
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let data = &buffer[..n];
            let message = match Message::from_vec(data) {
                Ok(m) => m,
                Err(err) => {
                    log::error!("dns udp {} query message parse error: {}", peer_addr, err);
                    continue;
                }
            };

            tokio::spawn(handle_udp_packet(
                socket.clone(),
                message,
                peer_addr,
                context.clone(),
            ));
        }
    }
}

pub async fn resolve(request: Message, peer_addr: SocketAddr, context: AppContext) -> Message {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_recursion_desired(true);
    response.set_recursion_available(true);
    response.set_message_type(MessageType::Response);

    if !request.recursion_desired() {
        // RD is required by default. Otherwise it may not get valid respond from remote servers
        response.set_recursion_desired(false);
        response.set_response_code(ResponseCode::NotImp);
    } else if request.op_code() != OpCode::Query || request.message_type() != MessageType::Query {
        // Other ops are not supported
        response.set_response_code(ResponseCode::NotImp);
    } else if request.query_count() > 0 {
        let query = &request.queries()[0];
        log::debug!("DNS lookup {:?} {}", query.query_type(), query.name());
        response.add_query(query.clone());
        if query.query_type().is_ip_addr() {
            let domain_name = query.name().to_string().trim_end_matches('.').to_string();
            let addr = Address::DomainNameAddress(domain_name, 0);
            match context.resolve(&addr).await {
                Ok(addr) => {
                    let rdata = match addr.ip() {
                        IpAddr::V4(addr) => RData::A(A::from(addr)),
                        IpAddr::V6(addr) => RData::AAAA(AAAA::from(addr)),
                    };
                    let mut record = Record::from_rdata(query.name().clone(), 80, rdata);
                    record.set_dns_class(DNSClass::IN);
                    response.add_answer(record);
                }
                _ => {
                    response.set_response_code(ResponseCode::ServFail);
                }
            }
        } else {
            match context.query(peer_addr, &request).await {
                Ok(message) => response = message,
                Err(e) => {
                    log::error!("failed to resolve dns request {} due to {}", request, e);
                    response.set_response_code(ResponseCode::ServFail);
                }
            }
        }
    }
    response
}

async fn handle_udp_packet(
    socket: Arc<UdpSocket>,
    request: Message,
    peer_addr: SocketAddr,
    context: AppContext,
) -> Result<()> {
    let response = resolve(request, peer_addr, context).await;
    let buf = response.to_vec()?;
    socket.send_to(&buf, peer_addr).await?;
    Ok(())
}
