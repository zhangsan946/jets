// https://github.com/shadowsocks/shadowsocks-rust/blob/8865992ac52a9a866021f0fd9744cc411baac58d/crates/shadowsocks-service/src/local/http/http_client.rs#L1

use super::super::ProxyStream;
use super::{
    http_stream::ProxyHttpStream,
    utils::{check_keep_alive, host_addr},
};
use crate::app::{connect_tcp_host, Context as AppContext};
use crate::common::{invalid_data_error, invalid_input_error, Address};
use hyper::http::{HeaderValue, Method as HttpMethod, Uri, Version as HttpVersion};
use hyper::{
    body::{Body, Incoming},
    client::conn::{http1, http2},
    http::uri::Scheme,
    rt::{Sleep, Timer},
    Request, Response,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::{error, trace};
use lru_time_cache::LruCache;
use pin_project::pin_project;
use std::{
    borrow::Cow,
    collections::VecDeque,
    fmt::Debug,
    future::Future,
    io::{Error, Result},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const CONNECTION_EXPIRE_DURATION: Duration = Duration::from_secs(20);

#[derive(Clone, Debug)]
pub struct TokioTimer;

impl Timer for TokioTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep {
            inner: tokio::time::sleep(duration),
        })
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep {
            inner: tokio::time::sleep_until(deadline.into()),
        })
    }

    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
        if let Some(sleep) = sleep.as_mut().downcast_mut_pin::<TokioSleep>() {
            sleep.reset(new_deadline)
        }
    }
}

#[pin_project]
pub(crate) struct TokioSleep {
    #[pin]
    pub(crate) inner: tokio::time::Sleep,
}

impl Future for TokioSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}
impl Sleep for TokioSleep {}

impl TokioSleep {
    pub fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.project().inner.as_mut().reset(deadline.into());
    }
}

/// HTTPClient, supporting HTTP/1.1 and H2, HTTPS.
pub struct HttpClient<B> {
    #[allow(clippy::type_complexity)]
    cache_conn: Arc<Mutex<LruCache<Address, VecDeque<(HttpConnection<B>, Instant)>>>>,
}

impl<B> Clone for HttpClient<B> {
    fn clone(&self) -> Self {
        HttpClient {
            cache_conn: self.cache_conn.clone(),
        }
    }
}

impl<B> Default for HttpClient<B>
where
    B: Body + Send + Unpin + Debug + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    fn default() -> Self {
        HttpClient::new()
    }
}

impl<B> HttpClient<B>
where
    B: Body + Send + Unpin + Debug + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    /// Create a new HttpClient
    pub fn new() -> HttpClient<B> {
        HttpClient {
            cache_conn: Arc::new(Mutex::new(LruCache::with_expiry_duration(
                CONNECTION_EXPIRE_DURATION,
            ))),
        }
    }

    /// Make HTTP requests
    #[inline]
    pub async fn send_request(
        &self,
        peer_addr: &SocketAddr,
        req: Request<B>,
        context: AppContext,
    ) -> Result<Response<Incoming>> {
        let host = match host_addr(req.uri()) {
            Some(h) => h,
            None => panic!("URI missing host: {}", req.uri()),
        };

        // Set Host header if it was missing in the Request
        let (mut req_parts, req_body) = req.into_parts();
        if let Some(authority) = req_parts.uri.authority() {
            let headers = &mut req_parts.headers;
            if !headers.contains_key("Host") {
                let uri = &req_parts.uri;
                let host_value = if (uri.scheme_str() == Some("http")
                    && matches!(authority.port_u16(), None | Some(80)))
                    || (uri.scheme_str() == Some("https")
                        && matches!(authority.port_u16(), None | Some(443)))
                {
                    HeaderValue::from_str(authority.host()).map_err(invalid_data_error)?
                } else {
                    HeaderValue::from_str(authority.as_str()).map_err(invalid_data_error)?
                };

                headers.insert("Host", host_value);
            }
        }
        let req = Request::from_parts(req_parts, req_body);

        // 1. Check if there is an available client
        //
        // FIXME: If the cached connection is closed unexpectedly, this request will fail immediately.
        if let Some(c) = self.get_cached_connection(&host).await {
            trace!("HTTP client for host: {} taken from cache", host);
            return self.send_request_conn(host, c, req).await;
        }

        // 2. If no. Make a new connection
        let scheme = match req.uri().scheme() {
            Some(s) => s,
            None => &Scheme::HTTP,
        };

        let domain = match host {
            Address::DomainNameAddress(ref domain, _) => Cow::Borrowed(domain.as_str()),
            Address::SocketAddress(ref saddr) => Cow::Owned(saddr.ip().to_string()),
        };

        let c = match HttpConnection::connect(scheme, host.clone(), &domain, peer_addr, context)
            .await
        {
            Ok(c) => c,
            Err(err) => {
                error!("failed to connect to host: {}, error: {}", host, err);
                return Err(err);
            }
        };

        self.send_request_conn(host, c, req).await
    }

    async fn get_cached_connection(&self, host: &Address) -> Option<HttpConnection<B>> {
        if let Some(q) = self.cache_conn.lock().await.get_mut(host) {
            while let Some((c, inst)) = q.pop_front() {
                let now = Instant::now();
                if now - inst >= CONNECTION_EXPIRE_DURATION {
                    continue;
                }
                if c.is_closed() {
                    continue;
                }
                return Some(c);
            }
        }
        None
    }

    async fn send_request_conn(
        &self,
        host: Address,
        mut c: HttpConnection<B>,
        req: Request<B>,
    ) -> Result<Response<Incoming>> {
        trace!("HTTP making request to host: {}, request: {:?}", host, req);
        let response = c.send_request(req).await?;
        trace!(
            "HTTP received response from host: {}, response: {:?}",
            host,
            response
        );

        // Check keep-alive
        if check_keep_alive(response.version(), response.headers(), false) {
            trace!(
                "HTTP connection keep-alive for host: {}, response: {:?}",
                host,
                response
            );
            self.cache_conn
                .lock()
                .await
                .entry(host)
                .or_insert_with(VecDeque::new)
                .push_back((c, Instant::now()));
        }

        Ok(response)
    }
}

enum HttpConnection<B> {
    Http1(http1::SendRequest<B>),
    Http2(http2::SendRequest<B>),
}

impl<B> HttpConnection<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    async fn connect(
        scheme: &Scheme,
        host: Address,
        domain: &str,
        peer_addr: &SocketAddr,
        context: AppContext,
    ) -> Result<HttpConnection<B>> {
        if *scheme != Scheme::HTTP && *scheme != Scheme::HTTPS {
            return Err(invalid_input_error("invalid scheme"));
        }

        let stream = connect_tcp_host(peer_addr, host.clone(), context).await?;

        if *scheme == Scheme::HTTP {
            HttpConnection::connect_http_http1(scheme, host, stream).await
        } else if *scheme == Scheme::HTTPS {
            HttpConnection::connect_https(scheme, host, domain, stream).await
        } else {
            unreachable!()
        }
    }

    async fn connect_http_http1(
        scheme: &Scheme,
        host: Address,
        stream: Box<dyn ProxyStream>,
    ) -> Result<HttpConnection<B>> {
        trace!(
            "HTTP making new HTTP/1.1 connection to host: {}, scheme: {}",
            host,
            scheme
        );

        let stream = ProxyHttpStream::connect_http(stream);

        // HTTP/1.x
        let (send_request, connection) = match http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(TokioIo::new(stream))
            .await
        {
            Ok(s) => s,
            Err(err) => return Err(Error::other(err)),
        };

        tokio::spawn(async move {
            if let Err(err) = connection.await {
                error!(
                    "HTTP/1.x connection to host: {} aborted with error: {}",
                    host, err
                );
            }
        });

        Ok(HttpConnection::Http1(send_request))
    }

    async fn connect_https(
        scheme: &Scheme,
        host: Address,
        domain: &str,
        stream: Box<dyn ProxyStream>,
    ) -> Result<HttpConnection<B>> {
        trace!(
            "HTTP making new TLS connection to host: {}, scheme: {}",
            host,
            scheme
        );

        // TLS handshake, check alpn for h2 support.
        let stream = ProxyHttpStream::connect_https(stream, domain).await?;

        if stream.negotiated_http2() {
            // H2 connection
            let (send_request, connection) = match http2::Builder::new(TokioExecutor::default())
                .timer(TokioTimer)
                .keep_alive_interval(Duration::from_secs(15))
                .handshake(TokioIo::new(stream))
                .await
            {
                Ok(s) => s,
                Err(err) => return Err(Error::other(err)),
            };

            tokio::spawn(async move {
                if let Err(err) = connection.await {
                    error!(
                        "HTTP/2 TLS connection to host: {} aborted with error: {}",
                        host, err
                    );
                }
            });

            Ok(HttpConnection::Http2(send_request))
        } else {
            // HTTP/1.x TLS
            let (send_request, connection) = match http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(TokioIo::new(stream))
                .await
            {
                Ok(s) => s,
                Err(err) => return Err(Error::other(err)),
            };

            tokio::spawn(async move {
                if let Err(err) = connection.await {
                    error!(
                        "HTTP/1.x TLS connection to host: {} aborted with error: {}",
                        host, err
                    );
                }
            });

            Ok(HttpConnection::Http1(send_request))
        }
    }

    #[inline]
    pub async fn send_request(&mut self, mut req: Request<B>) -> Result<Response<Incoming>> {
        match self {
            HttpConnection::Http1(r) => {
                if !matches!(
                    req.version(),
                    HttpVersion::HTTP_09 | HttpVersion::HTTP_10 | HttpVersion::HTTP_11
                ) {
                    trace!(
                        "HTTP client changed Request.version to HTTP/1.1 from {:?}",
                        req.version()
                    );

                    *req.version_mut() = HttpVersion::HTTP_11;
                }

                // Remove Scheme, Host part from URI
                if req.method() != HttpMethod::CONNECT
                    && (req.uri().scheme().is_some() || req.uri().authority().is_some())
                {
                    let mut builder = Uri::builder();
                    if let Some(path_and_query) = req.uri().path_and_query() {
                        builder = builder.path_and_query(path_and_query.as_str());
                    } else {
                        builder = builder.path_and_query("/");
                    }
                    *(req.uri_mut()) = builder.build().map_err(invalid_data_error)?;
                }

                r.send_request(req).await.map_err(invalid_data_error)
            }
            HttpConnection::Http2(r) => {
                if !matches!(req.version(), HttpVersion::HTTP_2) {
                    trace!(
                        "HTTP client changed Request.version to HTTP/2 from {:?}",
                        req.version()
                    );

                    *req.version_mut() = HttpVersion::HTTP_2;
                }

                r.send_request(req).await.map_err(invalid_data_error)
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        match self {
            HttpConnection::Http1(r) => r.is_closed(),
            HttpConnection::Http2(r) => r.is_closed(),
        }
    }
}
