// https://github.com/shadowsocks/shadowsocks-rust/blob/8865992ac52a9a866021f0fd9744cc411baac58d/crates/shadowsocks-service/src/local/http/http_stream.rs

use crate::common::invalid_input_error;
use crate::proxy::ProxyStream;
use crate::transport::tls::ROOT_CERT_STORE;
use once_cell::sync::Lazy;
use pin_project::pin_project;
use std::{
    io::Result,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig},
    TlsConnector,
};

#[allow(clippy::large_enum_variant)]
#[pin_project(project = ProxyHttpStreamProj)]
pub enum ProxyHttpStream {
    Http(#[pin] Box<dyn ProxyStream>),
    Https(
        #[pin] tokio_rustls::client::TlsStream<Box<dyn ProxyStream>>,
        bool,
    ),
}

impl ProxyHttpStream {
    pub fn connect_http(stream: Box<dyn ProxyStream>) -> ProxyHttpStream {
        ProxyHttpStream::Http(stream)
    }

    pub async fn connect_https(
        stream: Box<dyn ProxyStream>,
        domain: &str,
    ) -> Result<ProxyHttpStream> {
        static TLS_CONFIG: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
            let mut config = ClientConfig::builder()
                .with_root_certificates(ROOT_CERT_STORE.clone())
                .with_no_client_auth();

            // Try to negotiate HTTP/2
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Arc::new(config)
        });
        let connector = TlsConnector::from(TLS_CONFIG.clone());

        let host = match ServerName::try_from(domain) {
            Ok(n) => n,
            Err(_) => {
                return Err(invalid_input_error(format!("invalid dnsname \"{domain}\"")));
            }
        };

        let tls_stream = connector.connect(host.to_owned(), stream).await?;

        let (_, session) = tls_stream.get_ref();
        let negotiated_http2 = matches!(session.alpn_protocol(), Some(b"h2"));

        Ok(ProxyHttpStream::Https(tls_stream, negotiated_http2))
    }

    pub fn negotiated_http2(&self) -> bool {
        match *self {
            ProxyHttpStream::Http(..) => false,
            ProxyHttpStream::Https(_, n) => n,
        }
    }
}

macro_rules! forward_call {
    ($self:expr, $method:ident $(, $param:expr)*) => {
        match $self.as_mut().project() {
            ProxyHttpStreamProj::Http(stream) => stream.$method($($param),*),
            ProxyHttpStreamProj::Https(stream, ..) => stream.$method($($param),*),
        }
    };
}

impl AsyncRead for ProxyHttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        forward_call!(self, poll_read, cx, buf)
    }
}

impl AsyncWrite for ProxyHttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        forward_call!(self, poll_write, cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        forward_call!(self, poll_flush, cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        forward_call!(self, poll_shutdown, cx)
    }
}
