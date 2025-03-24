pub mod blackhole;
pub mod freedom;
#[cfg(feature = "local-http")]
pub mod http;
pub mod shadowsocks;
pub mod socks;
pub mod vless;

use crate::app::config::OutboundProtocolOption;
use crate::app::dns::DnsManager;
use crate::app::proxy::Outbounds;
use crate::app::router::Router;
use crate::common::Address;
use async_trait::async_trait;
use bytes::BufMut;
use futures::{ready, FutureExt};
use std::io::{ErrorKind, Result};
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub trait AsAny: 'static {
    fn as_any(&self) -> &dyn std::any::Any;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

impl<T: 'static> AsAny for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

pub trait ProxySteam: AsyncRead + AsyncWrite + Unpin + Send + AsAny {
    fn poll_read_exact(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize>>;
}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + AsAny> ProxySteam for T {
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

pub struct SyncProxyStream<S> {
    stream: Arc<Mutex<S>>,
}

impl<S> SyncProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub fn new(stream: S) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
        }
    }
}

impl<S> AsyncRead for SyncProxyStream<S>
where
    S: AsyncRead + Unpin + Send,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();
        let mut stream_fut = Box::pin(this.stream.lock());
        let mut stream = ready!(stream_fut.as_mut().poll_unpin(cx));
        let mut stream = stream.deref_mut();
        Pin::new(&mut stream).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for SyncProxyStream<S>
where
    S: AsyncWrite + Unpin + Send,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        let this = self.get_mut();
        let mut stream_fut = Box::pin(this.stream.lock());
        let mut stream = ready!(stream_fut.as_mut().poll_unpin(cx));
        let mut stream = stream.deref_mut();
        Pin::new(&mut stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        let mut stream_fut = Box::pin(this.stream.lock());
        let mut stream = ready!(stream_fut.as_mut().poll_unpin(cx));
        let mut stream = stream.deref_mut();
        Pin::new(&mut stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        let mut stream_fut = Box::pin(this.stream.lock());
        let mut stream = ready!(stream_fut.as_mut().poll_unpin(cx));
        let mut stream = stream.deref_mut();
        Pin::new(&mut stream).poll_shutdown(cx)
    }
}

#[async_trait]
pub trait Inbound: Sync + Send {
    fn addr(&self) -> &Address;
    fn clone_box(&self) -> Box<dyn Inbound>;
    async fn handle(
        &self,
        stream: TcpStream,
        inbound_tag: Option<String>,
        outbounds: Arc<Outbounds>,
        router: Arc<Router>,
        dns: Arc<DnsManager>,
    ) -> Result<()>;
}

impl Clone for Box<dyn Inbound> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[async_trait]
pub trait Outbound: Sync + Send {
    async fn handle(&self, addr: &Address) -> Result<Box<dyn ProxySteam>>;
    fn protocol(&self) -> OutboundProtocolOption;
    async fn pre_connect(&self, dns: &DnsManager) -> Result<Option<Box<dyn Outbound>>>;
}

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
