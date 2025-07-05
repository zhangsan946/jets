pub mod blackhole;
pub mod dns;
pub mod freedom;
#[cfg(feature = "inbound-http")]
pub mod http;
pub mod net_manager;
pub mod shadowsocks;
pub mod socks;
#[cfg(feature = "outbound-trojan")]
pub mod trojan;
#[cfg(feature = "inbound-tun")]
pub mod tun;
pub mod vless;

use crate::app::config::OutboundProtocolOption;
use crate::app::dns::DnsManager;
use crate::app::Context as AppContext;
use crate::common::Address;
use async_trait::async_trait;
use bytes::BufMut;
use futures::ready;
//use std::future::poll_fn;
use std::io::{ErrorKind, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

pub trait AsAny: 'static {
    fn as_any(&self) -> &dyn std::any::Any;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any>;
}

impl<T: 'static> AsAny for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

pub trait LocalAddr {
    fn local_addr(&self) -> Result<SocketAddr>;
}

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin + AsAny + LocalAddr {
    fn poll_read_exact(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize>>;
}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + AsAny + LocalAddr> ProxyStream for T {
    fn poll_read_exact(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize>> {
        let size = buf.len();
        if size == 0 {
            return Err(ErrorKind::InvalidInput.into()).into();
        }

        let mut read_size = 0;
        let mut buf = ReadBuf::new(buf);

        while read_size < size {
            let remaining = size - read_size;
            let buffer = &mut buf.chunk_mut()[..remaining];

            let mut read_buf = ReadBuf::uninit(unsafe {
                std::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut _, remaining)
            });
            ready!(Pin::new(&mut *self).poll_read(cx, &mut read_buf))?;

            let n = read_buf.filled().len();
            if n == 0 {
                if read_size > 0 {
                    return Err(ErrorKind::UnexpectedEof.into()).into();
                } else {
                    return Ok(0).into();
                }
            }
            read_size += n;
            unsafe {
                buf.advance_mut(n);
            }
        }

        Ok(size).into()
    }
}

// use futures::FutureExt;
// use std::ops::DerefMut;
// use tokio::sync::Mutex;
// pub struct SyncProxyStream<S> {
//     stream: Arc<Mutex<S>>,
// }

// impl<S> SyncProxyStream<S>
// where
//     S: AsyncRead + AsyncWrite + Unpin + Send,
// {
//     pub fn new(stream: S) -> Self {
//         Self {
//             stream: Arc::new(Mutex::new(stream)),
//         }
//     }
// }

// macro_rules! forward_call {
//     ($self:expr, $method:ident, $cx:expr $(, $param:expr)*) => {{
//         let mut stream_fut = Box::pin($self.get_mut().stream.lock());
//         let mut stream = ready!(stream_fut.as_mut().poll_unpin($cx));
//         let mut stream = stream.deref_mut();
//         Pin::new(&mut stream).$method($cx, $($param),*)
//     }};
// }

// impl<S> AsyncRead for SyncProxyStream<S>
// where
//     S: AsyncRead + Unpin + Send,
// {
//     fn poll_read(
//         self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         buf: &mut ReadBuf<'_>,
//     ) -> Poll<Result<()>> {
//         forward_call!(self, poll_read, cx, buf)
//     }
// }

// impl<S> AsyncWrite for SyncProxyStream<S>
// where
//     S: AsyncWrite + Unpin + Send,
// {
//     fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
//         forward_call!(self, poll_write, cx, buf)
//     }

//     fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
//         forward_call!(self, poll_flush, cx)
//     }

//     fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
//         forward_call!(self, poll_shutdown, cx)
//     }
// }

pub trait ProxySocket: Send + Sync + Unpin {
    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<Address>>;

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: Address,
    ) -> Poll<Result<usize>>;

    // fn recv_from(&self, buf: &mut ReadBuf<'_>) -> impl std::future::Future<Output = Result<Address>> + Send {
    //     async {
    //         poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    //     }
    // }

    // fn send_to(&self, buf: &[u8], target: Address) -> impl std::future::Future<Output = Result<usize>> + Send {
    //     async move {
    //         let mut target = Some(target);
    //         poll_fn(move |cx| {
    //             let target = target.take().unwrap();
    //             self.poll_send_to(cx, buf, target)
    //         }).await
    //     }
    // }
}

#[async_trait]
pub trait Inbound: Send + Sync {
    fn clone_box(&self) -> Box<dyn Inbound>;
    async fn run(&self, context: AppContext, channel: Option<mpsc::Sender<String>>) -> Result<()>;
}

impl Clone for Box<dyn Inbound> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[async_trait]
pub trait Outbound: Send + Sync {
    fn protocol(&self) -> OutboundProtocolOption;
    async fn pre_connect(&self, dns: &DnsManager) -> Result<Option<Box<dyn Outbound>>>;
    async fn connect_tcp(&self, addr: Address) -> Result<Box<dyn ProxyStream>>;
    async fn bind(&self, peer: SocketAddr, target: Address) -> Result<Box<dyn ProxySocket>>;
}

// for vmess & vless
pub mod request_command {
    pub const TCP: u8 = 1;
    pub const UDP: u8 = 2;
    pub const MUX: u8 = 3;
}
pub mod address_type {
    pub const IPV4: u8 = 1;
    pub const DOMAIN: u8 = 2;
    pub const IPV6: u8 = 3;
}
pub mod mux_command {
    pub const NEW: u8 = 1;
    pub const KEEP: u8 = 2;
    pub const END: u8 = 3;
    pub const KEEP_ALIVE: u8 = 4;
}
