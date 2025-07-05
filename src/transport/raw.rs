use crate::common::Address;
use crate::proxy::{LocalAddr, ProxySocket};
// For inbound
pub use shadowsocks::net::{AcceptOpts, TcpListener};
// For outbound
pub use shadowsocks::net::{ConnectOpts, TcpSocketOpts, TcpStream, UdpSocket, UdpSocketOpts};
use std::io::Result;
use std::net::SocketAddr;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

impl LocalAddr for TcpStream {
    fn local_addr(&self) -> Result<SocketAddr> {
        self.local_addr()
    }
}

impl ProxySocket for UdpSocket {
    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<Address>> {
        self.poll_recv_from(cx, buf).map_ok(Address::SocketAddress)
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: Address,
    ) -> Poll<Result<usize>> {
        if let Address::SocketAddress(addr) = target {
            self.poll_send_to(cx, buf, addr)
        } else {
            unreachable!()
        }
    }
}
