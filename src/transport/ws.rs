use crate::app::config::WsSettings;
use crate::common::{invalid_data_error, invalid_input_error, Address};
use crate::proxy::{LocalAddr, ProxyStream};
use bytes::{Bytes, BytesMut};
use futures::sink::Sink;
use futures::stream::Stream;
use futures::{
    ready,
    task::{Context, Poll},
};
use hyper::http::{HeaderName, HeaderValue};
use std::cmp::min;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{client_async_with_config, WebSocketStream};
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::client::Request;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::Message;

#[derive(Clone, Debug)]
pub struct Ws {
    request: Request,
    ws_config: WebSocketConfig,
}

impl Ws {
    pub fn new(ws_settings: WsSettings, addr: &Address, secure: bool) -> Result<Self> {
        let host = if !ws_settings.host.is_empty() {
            &ws_settings.host
        } else if let Some(val) = ws_settings.headers.get("HOST") {
            val
        } else {
            &addr.host()
        };
        let protocol = if secure { "wss" } else { "ws" };
        let url = format!("{}://{}{}", protocol, host, ws_settings.path);
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|_| invalid_input_error(format!("invalid ws url {}", url)))?;
        for (k, v) in ws_settings.headers.iter() {
            if k.to_uppercase() != "HOST" {
                request.headers_mut().insert(
                    HeaderName::try_from(k).map_err(|_| {
                        invalid_input_error(format!("invalid ws header name: {}", k))
                    })?,
                    HeaderValue::from_str(v).map_err(|_| {
                        invalid_input_error(format!("invalid ws header value: {}", v))
                    })?,
                );
            }
        }
        request.headers_mut().insert(
            "Host",
            HeaderValue::from_str(host)
                .map_err(|_| invalid_input_error(format!("invalid ws host: {}", host)))?,
        );
        let ws_config = WebSocketConfig::default().write_buffer_size(0);
        Ok(Self { request, ws_config })
    }

    pub async fn connect<S>(&self, stream: S) -> Result<WsStream<S>>
    where
        S: ProxyStream,
    {
        log::debug!("Sending ws request to {}", self.request.uri());
        let (s, _) = client_async_with_config(self.request.clone(), stream, Some(self.ws_config))
            .await
            .map_err(|e| {
                Error::other(format!("connect ws {} failed: {}", self.request.uri(), e))
            })?;

        Ok(WsStream::new(s))
    }
}

pub struct WsStream<S> {
    buf: BytesMut,
    inner: WebSocketStream<S>,
}

impl<S> WsStream<S> {
    pub fn new(stream: WebSocketStream<S>) -> Self {
        Self {
            buf: BytesMut::new(),
            inner: stream,
        }
    }
}

fn broken_pipe() -> Error {
    Error::new(ErrorKind::Interrupted, "broken pipe")
}

fn invalid_frame() -> Error {
    Error::new(ErrorKind::Interrupted, "invalid frame")
}

impl<S: ProxyStream> AsyncRead for WsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<Result<()>> {
        if !self.buf.is_empty() {
            let to_read = min(buf.remaining(), self.buf.len());
            let for_read = self.buf.split_to(to_read);
            buf.put_slice(&for_read[..to_read]);
            return Poll::Ready(Ok(()));
        }
        Poll::Ready(ready!(Pin::new(&mut self.inner).poll_next(cx)).map_or(
            Err(broken_pipe()),
            |item| {
                item.map_or(Err(broken_pipe()), |msg| match msg {
                    Message::Binary(data) => {
                        let to_read = min(buf.remaining(), data.len());
                        buf.put_slice(&data[..to_read]);
                        if data.len() > to_read {
                            self.buf.extend_from_slice(&data[to_read..]);
                        }
                        log::trace!("poll_read {} bytes", buf.filled().len());
                        Ok(())
                    }
                    Message::Close(_) => Ok(()),
                    _ => Err(invalid_frame()),
                })
            },
        ))
    }
}

impl<S: ProxyStream> AsyncWrite for WsStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize>> {
        log::trace!("poll_write {} bytes", buf.len());
        ready!(Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map_err(|_| broken_pipe()))?;

        let msg = Message::Binary(Bytes::copy_from_slice(buf));
        Pin::new(&mut self.inner)
            .start_send(msg)
            .map_err(|_| broken_pipe())?;

        let _ = Pin::new(&mut self.inner).poll_flush(cx);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|_| broken_pipe())
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(invalid_data_error)
    }
}

impl<S: ProxyStream> LocalAddr for WsStream<S> {
    fn local_addr(&self) -> Result<SocketAddr> {
        self.inner.get_ref().local_addr()
    }
}
