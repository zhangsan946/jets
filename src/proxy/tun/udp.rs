use super::super::dns::resolve;
use super::super::net_manager::{NatManager, UdpInboundWrite};
use crate::app::Context;
use crate::common::{invalid_data_error, Address};
use bytes::{BufMut, BytesMut};
use etherparse::PacketBuilder;
use hickory_resolver::proto::op::Message;
use log::debug;
use std::{
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::sync::mpsc;

pub struct UdpTun {
    context: Context,
    intercept_dns: Option<SocketAddr>,
    tun_rx: mpsc::Receiver<BytesMut>,
    manager: NatManager<UdpTunInboundWriter>,
    response_writer: UdpTunInboundWriter,
}

impl UdpTun {
    pub fn new(
        context: Context,
        intercept_dns: Option<SocketAddr>,
    ) -> (UdpTun, Duration, mpsc::Receiver<SocketAddr>) {
        let (tun_tx, tun_rx) = mpsc::channel(64);
        let response_writer = UdpTunInboundWriter::new(tun_tx);
        let (manager, cleanup_interval, keepalive_rx) =
            NatManager::new(response_writer.clone(), context.clone());

        (
            UdpTun {
                context,
                intercept_dns,
                tun_rx,
                manager,
                response_writer,
            },
            cleanup_interval,
            keepalive_rx,
        )
    }

    pub async fn handle_packet(
        &mut self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        debug!(
            "UDP {} -> {} payload.size: {} bytes",
            src_addr,
            dst_addr,
            payload.len()
        );
        if let Some(dns_server) = self.intercept_dns {
            if dst_addr == dns_server {
                let message = match Message::from_vec(payload) {
                    Ok(m) => m,
                    Err(err) => {
                        return Err(invalid_data_error(format!(
                            "tun dns udp {} query message parse error: {}",
                            src_addr, err
                        )));
                    }
                };
                let context = self.context.clone();
                let response_writer = self.response_writer.clone();
                tokio::spawn(async move {
                    let response = resolve(message, src_addr, context).await;
                    let buf = response.to_vec()?;
                    response_writer
                        .send_to(src_addr, &Address::SocketAddress(dst_addr), &buf)
                        .await?;
                    Ok::<(), Error>(())
                });
                return Ok(());
            }
        }
        if let Err(err) = self
            .manager
            .send_to(src_addr, dst_addr.into(), payload)
            .await
        {
            debug!(
                "UDP {} -> {} payload.size: {} bytes failed, error: {}",
                src_addr,
                dst_addr,
                payload.len(),
                err,
            );
        }
        Ok(())
    }

    pub async fn recv_packet(&mut self) -> BytesMut {
        match self.tun_rx.recv().await {
            Some(b) => b,
            None => unreachable!("channel closed unexpectedly"),
        }
    }

    #[inline(always)]
    pub async fn cleanup_expired(&mut self) {
        self.manager.cleanup_expired().await;
    }

    #[inline(always)]
    pub async fn keep_alive(&mut self, peer_addr: &SocketAddr) {
        self.manager.keep_alive(peer_addr).await;
    }
}

#[derive(Clone)]
struct UdpTunInboundWriter {
    tun_tx: mpsc::Sender<BytesMut>,
}

impl UdpTunInboundWriter {
    fn new(tun_tx: mpsc::Sender<BytesMut>) -> UdpTunInboundWriter {
        UdpTunInboundWriter { tun_tx }
    }
}

impl UdpInboundWrite for UdpTunInboundWriter {
    async fn send_to(
        &self,
        peer_addr: SocketAddr,
        remote_addr: &Address,
        data: &[u8],
    ) -> io::Result<()> {
        let addr = match *remote_addr {
            Address::SocketAddress(sa) => {
                // Try to convert IPv4 mapped IPv6 address if server is running on dual-stack mode
                match (peer_addr, sa) {
                    (SocketAddr::V4(..), SocketAddr::V4(..))
                    | (SocketAddr::V6(..), SocketAddr::V6(..)) => sa,
                    (SocketAddr::V4(..), SocketAddr::V6(v6)) => {
                        // If peer is IPv4, then remote_addr can only be IPv4-mapped-IPv6
                        match Ipv6Addr::to_ipv4_mapped(v6.ip()) {
                            Some(v4) => SocketAddr::new(IpAddr::from(v4), v6.port()),
                            None => {
                                return Err(io::Error::new(
                                    ErrorKind::InvalidData,
                                    "source and destination type unmatch",
                                ));
                            }
                        }
                    }
                    (SocketAddr::V6(..), SocketAddr::V4(v4)) => {
                        // Convert remote_addr to IPv4-mapped-IPv6
                        SocketAddr::new(IpAddr::from(v4.ip().to_ipv6_mapped()), v4.port())
                    }
                }
            }
            Address::DomainNameAddress(..) => {
                let err = io::Error::new(
                    ErrorKind::InvalidInput,
                    "tun destination must not be an domain name address",
                );
                return Err(err);
            }
        };

        let packet = match (peer_addr, addr) {
            (SocketAddr::V4(peer), SocketAddr::V4(remote)) => {
                let builder = PacketBuilder::ipv4(remote.ip().octets(), peer.ip().octets(), 47)
                    .udp(remote.port(), peer.port());

                let packet = BytesMut::with_capacity(builder.size(data.len()));
                let mut packet_writer = packet.writer();
                builder
                    .write(&mut packet_writer, data)
                    .expect("PacketBuilder::write");

                packet_writer.into_inner()
            }
            (SocketAddr::V6(peer), SocketAddr::V6(remote)) => {
                let builder = PacketBuilder::ipv6(remote.ip().octets(), peer.ip().octets(), 20)
                    .udp(remote.port(), peer.port());

                let packet = BytesMut::with_capacity(builder.size(data.len()));
                let mut packet_writer = packet.writer();
                builder
                    .write(&mut packet_writer, data)
                    .expect("PacketBuilder::write");

                packet_writer.into_inner()
            }
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "source and destination type unmatch",
                ));
            }
        };

        self.tun_tx.send(packet).await.expect("tun_tx::send");
        Ok(())
    }
}
