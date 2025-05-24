use super::virt_device::{TokenBuffer, VirtTunDevice};
use crate::app::establish_tcp_tunnel;
use crate::app::sniff::{SniffResult, Sniffer};
use crate::app::Context as AppContext;
use crate::common::{Address, DEFAULT_BUF_SIZE};
use crate::transport::raw::{AcceptOpts, TcpSocketOpts};
use bytes::BytesMut;
use log::{debug, error, trace};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, PollResult, SocketHandle, SocketSet},
    phy::{Checksum, DeviceCapabilities, Medium},
    socket::tcp::{
        CongestionControl, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
    },
    storage::RingBuffer,
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address, TcpPacket},
};
use spin::Mutex as SpinMutex;
use std::{
    collections::HashMap,
    future::Future,
    io::{self, ErrorKind},
    mem,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
    thread::{self, JoinHandle, Thread},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};

// NOTE: Default buffer could contain 5 AEAD packets
const DEFAULT_TCP_SEND_BUFFER_SIZE: u32 = (0x3FFFu32 * 5).next_power_of_two();
const DEFAULT_TCP_RECV_BUFFER_SIZE: u32 = (0x3FFFu32 * 5).next_power_of_two();

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TcpSocketState {
    Normal,
    Close,
    Closing,
    Closed,
}

struct TcpSocketControl {
    send_buffer: RingBuffer<'static, u8>,
    send_waker: Option<Waker>,
    recv_buffer: RingBuffer<'static, u8>,
    recv_waker: Option<Waker>,
    recv_state: TcpSocketState,
    send_state: TcpSocketState,
}

struct ManagerNotify {
    thread: Thread,
}

impl ManagerNotify {
    fn new(thread: Thread) -> ManagerNotify {
        ManagerNotify { thread }
    }

    fn notify(&self) {
        self.thread.unpark();
    }
}

struct TcpSocketManager {
    device: VirtTunDevice,
    iface: Interface,
    sockets: HashMap<SocketHandle, SharedTcpConnectionControl>,
    socket_creation_rx: mpsc::UnboundedReceiver<TcpSocketCreation>,
}

type SharedTcpConnectionControl = Arc<SpinMutex<TcpSocketControl>>;

struct TcpSocketCreation {
    control: SharedTcpConnectionControl,
    socket: TcpSocket<'static>,
    socket_created_tx: oneshot::Sender<()>,
}

struct TcpConnection {
    control: SharedTcpConnectionControl,
    manager_notify: Arc<ManagerNotify>,
    buffer: BytesMut,
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        let mut control = self.control.lock();

        if matches!(control.recv_state, TcpSocketState::Normal) {
            control.recv_state = TcpSocketState::Close;
        }

        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        self.manager_notify.notify();
    }
}

impl TcpConnection {
    fn new(
        socket: TcpSocket<'static>,
        socket_creation_tx: &mpsc::UnboundedSender<TcpSocketCreation>,
        manager_notify: Arc<ManagerNotify>,
        tcp_opts: &TcpSocketOpts,
        sniffer: Sniffer,
    ) -> impl Future<Output = (TcpConnection, SniffResult)> + use<> {
        let send_buffer_size = tcp_opts
            .send_buffer_size
            .unwrap_or(DEFAULT_TCP_SEND_BUFFER_SIZE);
        let recv_buffer_size = tcp_opts
            .recv_buffer_size
            .unwrap_or(DEFAULT_TCP_RECV_BUFFER_SIZE);

        let control = Arc::new(SpinMutex::new(TcpSocketControl {
            send_buffer: RingBuffer::new(vec![0u8; send_buffer_size as usize]),
            send_waker: None,
            recv_buffer: RingBuffer::new(vec![0u8; recv_buffer_size as usize]),
            recv_waker: None,
            recv_state: TcpSocketState::Normal,
            send_state: TcpSocketState::Normal,
        }));
        let (tx, rx) = oneshot::channel();
        let _ = socket_creation_tx.send(TcpSocketCreation {
            control: control.clone(),
            socket,
            socket_created_tx: tx,
        });
        async move {
            // waiting socket add to SocketSet
            let _ = rx.await;

            // peak first payload for sniffing
            let buffer = BytesMut::with_capacity(DEFAULT_BUF_SIZE);
            let mut connection = TcpConnection {
                control,
                manager_notify,
                buffer,
            };
            let mut buffer = [0u8; DEFAULT_BUF_SIZE];
            let n = connection.read(&mut buffer).await.unwrap();
            let sniff_result = sniffer.sniff(&buffer[..n]);

            connection.buffer.extend_from_slice(&buffer[..n]);
            (connection, sniff_result)
        }
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.buffer.is_empty() {
            buf.put_slice(&this.buffer.split());
            this.manager_notify.notify();
            return Ok(()).into();
        }

        let mut control = this.control.lock();

        // Read from buffer
        if control.recv_buffer.is_empty() {
            // If socket is already closed / half closed, just return EOF directly.
            if matches!(control.recv_state, TcpSocketState::Closed) {
                return Ok(()).into();
            }

            // Nothing could be read. Wait for notify.
            if let Some(old_waker) = control.recv_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let recv_buf =
            unsafe { mem::transmute::<&mut [mem::MaybeUninit<u8>], &mut [u8]>(buf.unfilled_mut()) };
        let n = control.recv_buffer.dequeue_slice(recv_buf);
        buf.advance(n);

        if n > 0 {
            this.manager_notify.notify();
        }
        Ok(()).into()
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut control = self.control.lock();

        // If state == Close | Closing | Closed, the TCP stream WR half is closed.
        if !matches!(control.send_state, TcpSocketState::Normal) {
            return Err(io::ErrorKind::BrokenPipe.into()).into();
        }

        // Write to buffer

        if control.send_buffer.is_full() {
            if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let n = control.send_buffer.enqueue_slice(buf);

        if n > 0 {
            self.manager_notify.notify();
        }
        Ok(n).into()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Ok(()).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut control = self.control.lock();

        if matches!(control.send_state, TcpSocketState::Closed) {
            return Ok(()).into();
        }

        // SHUT_WR
        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
            if !old_waker.will_wake(cx.waker()) {
                old_waker.wake();
            }
        }

        self.manager_notify.notify();
        Poll::Pending
    }
}

pub struct TcpTun {
    context: AppContext,
    accept_opts: AcceptOpts,
    sniffer: Sniffer,
    manager_handle: Option<JoinHandle<()>>,
    manager_notify: Arc<ManagerNotify>,
    manager_socket_creation_tx: mpsc::UnboundedSender<TcpSocketCreation>,
    manager_running: Arc<AtomicBool>,
    iface_rx: mpsc::UnboundedReceiver<TokenBuffer>,
    iface_tx: mpsc::UnboundedSender<TokenBuffer>,
    iface_tx_avail: Arc<AtomicBool>,
}

impl Drop for TcpTun {
    fn drop(&mut self) {
        self.manager_running.store(false, Ordering::Relaxed);
        self.manager_notify.notify();
        let _ = self.manager_handle.take().unwrap().join();
    }
}

impl TcpTun {
    pub fn new(context: AppContext, accept_opts: AcceptOpts, sniffer: Sniffer, mtu: u32) -> TcpTun {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = mtu as usize;
        capabilities.checksum.ipv4 = Checksum::Tx;
        capabilities.checksum.tcp = Checksum::Tx;
        capabilities.checksum.udp = Checksum::Tx;
        capabilities.checksum.icmpv4 = Checksum::Tx;
        capabilities.checksum.icmpv6 = Checksum::Tx;

        let (mut device, iface_rx, iface_tx, iface_tx_avail) = VirtTunDevice::new(capabilities);

        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface = Interface::new(iface_config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                .expect("iface IPv4");
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                .expect("iface IPv6");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .expect("IPv4 default route");
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .expect("IPv6 default route");
        iface.set_any_ip(true);

        let (manager_socket_creation_tx, manager_socket_creation_rx) = mpsc::unbounded_channel();
        let mut manager = TcpSocketManager {
            device,
            iface,
            sockets: HashMap::new(),
            socket_creation_rx: manager_socket_creation_rx,
        };

        let manager_running = Arc::new(AtomicBool::new(true));

        let manager_handle = {
            let manager_running = manager_running.clone();

            thread::Builder::new()
                .name("smoltcp-poll".to_owned())
                .spawn(move || {
                    let TcpSocketManager {
                        ref mut device,
                        ref mut iface,
                        ref mut sockets,
                        ref mut socket_creation_rx,
                        ..
                    } = manager;

                    let mut socket_set = SocketSet::new(vec![]);

                    while manager_running.load(Ordering::Relaxed) {
                        while let Ok(TcpSocketCreation {
                            control,
                            socket,
                            socket_created_tx: socket_create_tx,
                        }) = socket_creation_rx.try_recv()
                        {
                            let handle = socket_set.add(socket);
                            let _ = socket_create_tx.send(());
                            sockets.insert(handle, control);
                        }

                        let before_poll = SmolInstant::now();
                        if let PollResult::SocketStateChanged =
                            iface.poll(before_poll, device, &mut socket_set)
                        {
                            trace!(
                                "VirtDevice::poll costed {}",
                                SmolInstant::now() - before_poll
                            );
                        }

                        // Check all the sockets' status
                        let mut sockets_to_remove = Vec::new();

                        for (socket_handle, control) in sockets.iter() {
                            let socket_handle = *socket_handle;
                            let socket = socket_set.get_mut::<TcpSocket>(socket_handle);
                            let mut control = control.lock();

                            // Remove the socket only when it is in the closed state.
                            if socket.state() == TcpState::Closed {
                                sockets_to_remove.push(socket_handle);

                                control.send_state = TcpSocketState::Closed;
                                control.recv_state = TcpSocketState::Closed;

                                if let Some(waker) = control.send_waker.take() {
                                    waker.wake();
                                }
                                if let Some(waker) = control.recv_waker.take() {
                                    waker.wake();
                                }

                                trace!("closed TCP connection");
                                continue;
                            }

                            // SHUT_WR
                            if matches!(control.send_state, TcpSocketState::Close)
                                && socket.send_queue() == 0
                                && control.send_buffer.is_empty()
                            {
                                trace!("closing TCP Write Half, {:?}", socket.state());

                                // Close the socket. Set to FIN state
                                socket.close();
                                control.send_state = TcpSocketState::Closing;

                                // We can still process the pending buffer.
                            }

                            // Check if readable
                            let mut wake_receiver = false;
                            while socket.can_recv() && !control.recv_buffer.is_full() {
                                let result = socket.recv(|buffer| {
                                    let n = control.recv_buffer.enqueue_slice(buffer);
                                    (n, ())
                                });

                                match result {
                                    Ok(..) => {
                                        wake_receiver = true;
                                    }
                                    Err(err) => {
                                        error!(
                                            "socket recv error: {:?}, {:?}",
                                            err,
                                            socket.state()
                                        );

                                        // Don't know why. Abort the connection.
                                        socket.abort();

                                        if matches!(control.recv_state, TcpSocketState::Normal) {
                                            control.recv_state = TcpSocketState::Closed;
                                        }
                                        wake_receiver = true;

                                        // The socket will be recycled in the next poll.
                                        break;
                                    }
                                }
                            }

                            // If socket is not in ESTABLISH, FIN-WAIT-1, FIN-WAIT-2,
                            // the local client have closed our receiver.
                            if matches!(control.recv_state, TcpSocketState::Normal)
                                && !socket.may_recv()
                                && !matches!(
                                    socket.state(),
                                    TcpState::Listen
                                        | TcpState::SynReceived
                                        | TcpState::Established
                                        | TcpState::FinWait1
                                        | TcpState::FinWait2
                                )
                            {
                                trace!("closed TCP Read Half, {:?}", socket.state());

                                // Let TcpConnection::poll_read returns EOF.
                                control.recv_state = TcpSocketState::Closed;
                                wake_receiver = true;
                            }

                            if wake_receiver && control.recv_waker.is_some() {
                                if let Some(waker) = control.recv_waker.take() {
                                    waker.wake();
                                }
                            }

                            // Check if writable
                            let mut wake_sender = false;
                            while socket.can_send() && !control.send_buffer.is_empty() {
                                let result = socket.send(|buffer| {
                                    let n = control.send_buffer.dequeue_slice(buffer);
                                    (n, ())
                                });

                                match result {
                                    Ok(..) => {
                                        wake_sender = true;
                                    }
                                    Err(err) => {
                                        error!(
                                            "socket send error: {:?}, {:?}",
                                            err,
                                            socket.state()
                                        );

                                        // Don't know why. Abort the connection.
                                        socket.abort();

                                        if matches!(control.send_state, TcpSocketState::Normal) {
                                            control.send_state = TcpSocketState::Closed;
                                        }
                                        wake_sender = true;

                                        // The socket will be recycled in the next poll.
                                        break;
                                    }
                                }
                            }

                            if wake_sender && control.send_waker.is_some() {
                                if let Some(waker) = control.send_waker.take() {
                                    waker.wake();
                                }
                            }
                        }

                        for socket_handle in sockets_to_remove {
                            sockets.remove(&socket_handle);
                            socket_set.remove(socket_handle);
                        }

                        if !device.recv_available() {
                            let next_duration = iface
                                .poll_delay(before_poll, &socket_set)
                                .unwrap_or(SmolDuration::from_millis(5));
                            if next_duration != SmolDuration::ZERO {
                                thread::park_timeout(Duration::from(next_duration));
                            }
                        }
                    }

                    trace!("VirtDevice::poll thread exited");
                })
                .unwrap()
        };

        let manager_notify = Arc::new(ManagerNotify::new(manager_handle.thread().clone()));

        TcpTun {
            context,
            accept_opts,
            sniffer,
            manager_handle: Some(manager_handle),
            manager_notify,
            manager_socket_creation_tx,
            manager_running,
            iface_rx,
            iface_tx,
            iface_tx_avail,
        }
    }

    pub async fn handle_packet(
        &mut self,
        src_addr: SocketAddr,
        mut dst_addr: SocketAddr,
        tcp_packet: &TcpPacket<&[u8]>,
    ) -> io::Result<()> {
        // TCP first handshake packet, create a new Connection
        if tcp_packet.syn() && !tcp_packet.ack() {
            let send_buffer_size = self
                .accept_opts
                .tcp
                .send_buffer_size
                .unwrap_or(DEFAULT_TCP_SEND_BUFFER_SIZE);
            let recv_buffer_size = self
                .accept_opts
                .tcp
                .recv_buffer_size
                .unwrap_or(DEFAULT_TCP_RECV_BUFFER_SIZE);

            let mut socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; recv_buffer_size as usize]),
                TcpSocketBuffer::new(vec![0u8; send_buffer_size as usize]),
            );
            socket.set_keep_alive(self.accept_opts.tcp.keepalive.map(From::from));
            // FIXME: It should follow system's setting. 7200 is Linux's default.
            socket.set_timeout(Some(SmolDuration::from_secs(7200)));
            // NO ACK delay
            // socket.set_ack_delay(None);
            // Enable Cubic congestion control
            socket.set_congestion_control(CongestionControl::Cubic);

            if let Err(err) = socket.listen(dst_addr) {
                return Err(io::Error::new(
                    ErrorKind::Other,
                    format!("listen error: {:?}", err),
                ));
            }

            debug!("created TCP connection for {} <-> {}", src_addr, dst_addr);

            let connection = TcpConnection::new(
                socket,
                &self.manager_socket_creation_tx,
                self.manager_notify.clone(),
                &self.accept_opts.tcp,
                self.sniffer.clone(),
            );

            // establish a tunnel
            let context = self.context.clone();
            tokio::spawn(async move {
                let (connection, sniff_result) = connection.await;
                let address = match sniff_result {
                    SniffResult::Http(host) => Address::DomainNameAddress(host, dst_addr.port()),
                    SniffResult::Tls(host) => Address::DomainNameAddress(host, dst_addr.port()),
                    SniffResult::Other => {
                        // Get forward address from socket
                        //
                        // Try to convert IPv4 mapped IPv6 address for dual-stack mode.
                        if let SocketAddr::V6(ref a) = dst_addr {
                            if let Some(v4) = Ipv6Addr::to_ipv4_mapped(a.ip()) {
                                dst_addr = SocketAddr::new(IpAddr::from(v4), a.port());
                            }
                        }
                        Address::SocketAddress(dst_addr)
                    }
                };
                let mut stream = Box::new(connection);
                // TODO:
                // Support sniff route only
                if let Err(err) = establish_tcp_tunnel(&mut stream, address.clone(), context).await
                {
                    error!(
                        "TCP tunnel failure, {} <-> {}({}), error: {}",
                        src_addr, address, dst_addr, err
                    );
                }
            });
        }

        Ok(())
    }

    pub async fn drive_interface_state(&mut self, frame: TokenBuffer) {
        if self.iface_tx.send(frame).is_err() {
            panic!("interface send channel closed unexpectedly");
        }

        // Wake up and poll the interface.
        self.iface_tx_avail.store(true, Ordering::Release);
        self.manager_notify.notify();
    }

    pub async fn recv_packet(&mut self) -> TokenBuffer {
        match self.iface_rx.recv().await {
            Some(v) => v,
            None => unreachable!("channel closed unexpectedly"),
        }
    }
}
