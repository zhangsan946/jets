use crate::app::{bind_udp_socket, Context};
use crate::common::{Address, MAXIMUM_UDP_PAYLOAD_SIZE};
use crate::proxy::ProxySocket;
use bytes::Bytes;
use futures::future;
use lru_time_cache::LruCache;
use std::future::poll_fn;
use std::io::{Error, Result};
use std::marker::PhantomData;
use std::net::SocketAddr;
use tokio::io::ReadBuf;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

/// Default UDP session's expire duration
const DEFAULT_UDP_SESSION_EXPIRY_DURATION: Duration = Duration::from_secs(5 * 60);
/// Keep-alive channel size for UDP sessions' manager
const UDP_SESSION_KEEP_ALIVE_CHANNEL_SIZE: usize = 64;
/// Packet size for all UDP sessions' send queue
const UDP_SESSION_SEND_CHANNEL_SIZE: usize = 1024;

#[trait_variant::make(Send)]
pub trait UdpInboundWrite {
    /// Sends packet `data` received from `remote_addr` back to `peer_addr`
    async fn send_to(
        &self,
        peer_addr: SocketAddr,
        remote_addr: &Address,
        data: &[u8],
    ) -> Result<()>;
}

pub struct NatManager<W>
where
    W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static,
{
    respond_writer: W,
    udp_session_map: LruCache<SocketAddr, UdpSession<W>>,
    keepalive_tx: Sender<SocketAddr>,
    context: Context,
}

impl<W> NatManager<W>
where
    W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static,
{
    /// Create a new `NatManager`
    ///
    /// Returns (`UdpAssociationManager`, Cleanup Interval, Keep-alive Receiver<SocketAddr>)
    pub fn new(
        respond_writer: W,
        context: Context,
    ) -> (NatManager<W>, Duration, Receiver<SocketAddr>) {
        // TODO: allow to customize
        let time_to_live = DEFAULT_UDP_SESSION_EXPIRY_DURATION;
        // LruCache::with_expiry_duration_and_capacity(time_to_live, capacity)
        let udp_session_map = LruCache::with_expiry_duration(time_to_live);

        let (keepalive_tx, keepalive_rx) = channel(UDP_SESSION_KEEP_ALIVE_CHANNEL_SIZE);

        (
            NatManager {
                respond_writer,
                udp_session_map,
                keepalive_tx,
                context,
            },
            time_to_live,
            keepalive_rx,
        )
    }

    /// Sends `data` from `peer_addr` to `target_addr`
    pub async fn send_to(
        &mut self,
        peer_addr: SocketAddr,
        target_addr: Address,
        data: &[u8],
    ) -> Result<()> {
        // Check or (re)create an association

        if let Some(session) = self.udp_session_map.get(&peer_addr) {
            return session.try_send((target_addr, Bytes::copy_from_slice(data)));
        }

        let session = UdpSession::new(
            peer_addr,
            self.keepalive_tx.clone(),
            self.respond_writer.clone(),
            self.context.clone(),
        );

        log::debug!("created udp association for {}", peer_addr);

        session.try_send((target_addr, Bytes::copy_from_slice(data)))?;
        self.udp_session_map.insert(peer_addr, session);

        Ok(())
    }

    /// Cleanup expired associations
    pub async fn cleanup_expired(&mut self) {
        self.udp_session_map.iter();
    }

    /// Keep-alive association
    pub async fn keep_alive(&mut self, peer_addr: &SocketAddr) {
        self.udp_session_map.get(peer_addr);
    }
}

struct UdpSession<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    handle: JoinHandle<()>,
    sender: Sender<(Address, Bytes)>,
    writer: PhantomData<W>,
}

impl<W> Drop for UdpSession<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl<W> UdpSession<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn new(
        peer_addr: SocketAddr,
        keepalive_tx: Sender<SocketAddr>,
        respond_writer: W,
        context: Context,
    ) -> UdpSession<W> {
        // Pending packets UDP_ASSOCIATION_SEND_CHANNEL_SIZE for each association should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping excessive packets is a good way to protect the server from
        // being OOM.
        let (sender, receiver) = channel(UDP_SESSION_SEND_CHANNEL_SIZE);

        let handle = tokio::spawn(async move {
            dispatch_packet(respond_writer, receiver, peer_addr, keepalive_tx, context).await
        });

        UdpSession {
            handle,
            sender,
            writer: PhantomData,
        }
    }

    fn try_send(&self, data: (Address, Bytes)) -> Result<()> {
        if self.sender.try_send(data).is_err() {
            let err = Error::other("udp relay channel full");
            return Err(err);
        }
        Ok(())
    }
}

async fn dispatch_packet<W>(
    respond_writer: W,
    mut receiver: Receiver<(Address, Bytes)>,
    peer_addr: SocketAddr,
    keepalive_tx: Sender<SocketAddr>,
    context: Context,
) where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    let mut proxy_socket: Option<Box<dyn ProxySocket>> = None;
    let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
    let mut keepalive_interval = interval(Duration::from_secs(1));
    let mut keepalive_flag = false;
    loop {
        tokio::select! {
            packet_received_opt = receiver.recv() => {
                let (target_addr, data) = match packet_received_opt {
                    Some(d) => d,
                    None => {
                        log::trace!("udp association for {} -> ... channel closed", peer_addr);
                        break;
                    }
                };
                log::trace!(
                    "udp relay {} -> {} with {} bytes",
                    peer_addr,
                    target_addr,
                    data.len()
                );

                if let Err(err) = dispatch_received_packet(&mut proxy_socket, peer_addr, target_addr.clone(), &data, context.clone()).await {
                    log::error!(
                        "udp relay {} -> {} with {} bytes, error: {}",
                        peer_addr,
                        target_addr,
                        data.len(),
                        err
                    );
                }
            }

            received_opt = receive_from_proxy_socket(&proxy_socket, &mut buffer), if proxy_socket.is_some() => {
                let (n, addr) = match received_opt {
                    Ok(r) => r,
                    Err(err) => {
                        log::error!("udp relay {} <- ... (proxied) failed, error: {}", peer_addr, err);
                        // Socket failure. Reset for recreation.
                        proxy_socket = None;
                        continue;
                    }
                };

                log::trace!(
                    "udp relay {} <- {} received {} bytes",
                    peer_addr,
                    addr,
                    n,
                );

                // Keep association alive in map
                keepalive_flag = true;

                // Send back to client
                match respond_writer.send_to(peer_addr, &addr, &buffer[..n]).await {
                    Err(err) => {
                        log::warn!(
                            "udp failed to send back {} bytes to client {}, from target {}, error: {}",
                            n,
                            peer_addr,
                            addr,
                            err
                        );
                    }
                    Ok(..) => {
                        log::trace!(
                            "udp relay {} <- {} with {} bytes",
                            peer_addr,
                            addr,
                            n
                        );
                    }
                }
            }

            _ = keepalive_interval.tick() => {
                if keepalive_flag {
                    if keepalive_tx.try_send(peer_addr).is_err() {
                        log::debug!("udp relay {} keep-alive failed, channel full or closed", peer_addr);
                    } else {
                        keepalive_flag = false;
                    }
                }
            }
        }
    }
}

async fn dispatch_received_packet(
    proxy_socket: &mut Option<Box<dyn ProxySocket>>,
    peer_addr: SocketAddr,
    target_addr: Address,
    data: &[u8],
    context: Context,
) -> Result<()> {
    let socket = match proxy_socket {
        Some(ref mut socket) => socket,
        None => {
            let socket = bind_udp_socket(peer_addr, target_addr.clone(), context).await?;

            proxy_socket.insert(socket)
        }
    };

    poll_fn(move |cx| socket.poll_send_to(cx, data, target_addr.clone()))
        .await
        .map(|_| ())
}

#[inline]
async fn receive_from_proxy_socket(
    socket: &Option<Box<dyn ProxySocket>>,
    buf: &mut [u8],
) -> Result<(usize, Address)> {
    match *socket {
        None => future::pending().await,
        Some(ref s) => {
            let mut buffer = ReadBuf::new(buf);
            poll_fn(|cx| s.poll_recv_from(cx, &mut buffer))
                .await
                .map(|a| (buffer.filled().len(), a))
        }
    }
}
