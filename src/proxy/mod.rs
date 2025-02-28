pub mod blackhole;
pub mod freedom;
pub mod shadowsocks;
pub mod socks;
pub mod vless;

use crate::common::Address;
use async_trait::async_trait;
use bytes::BufMut;
use futures::ready;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
    fn poll_read_exact(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>>;
}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + AsAny> ProxySteam for T {
    fn poll_read_exact(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let size = buf.len();
        if size == 0 {
            return Err(io::ErrorKind::InvalidInput.into()).into();
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
                    return Err(io::ErrorKind::UnexpectedEof.into()).into();
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

#[async_trait]
pub trait Inbound: Sync + Send {
    fn addr(&self) -> &Address;
    fn clone_box(&self) -> Box<dyn Inbound>;
    async fn handle(
        &self,
        mut stream: Box<dyn ProxySteam>,
        peer_addr: &SocketAddr,
    ) -> std::io::Result<(Box<dyn ProxySteam>, Address)>;
}

impl Clone for Box<dyn Inbound> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[async_trait]
pub trait Outbound: Sync + Send {
    async fn handle(&self, addr: &Address) -> std::io::Result<Box<dyn ProxySteam>>;
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
