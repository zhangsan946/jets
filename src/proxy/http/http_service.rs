// https://github.com/shadowsocks/shadowsocks-rust/blob/8865992ac52a9a866021f0fd9744cc411baac58d/crates/shadowsocks-service/src/local/http/http_service.rs

use super::{
    http_client::HttpClient,
    utils::{authority_addr, check_keep_alive, host_addr},
};
use crate::app::establish_tcp_tunnel;
use crate::app::Context;
use crate::common::Address;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::{
    body::Incoming,
    header::{GetAll, HeaderValue},
    http::uri::{Authority, Scheme},
    HeaderMap, Method, Request, Response, StatusCode, Uri, Version,
};
use hyper_util::rt::TokioIo;
use log::{debug, error, trace};
use std::{collections::HashMap, net::SocketAddr, str::FromStr};

const BASIC_AUTH_BASE64_ENGINE: base64::engine::GeneralPurpose =
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_encode_padding(true)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

pub(crate) struct HttpService {
    peer_addr: SocketAddr,
    http_client: HttpClient<Incoming>,
}

impl HttpService {
    pub fn new(peer_addr: SocketAddr) -> Self {
        Self {
            peer_addr,
            http_client: HttpClient::new(),
        }
    }

    pub async fn serve_connection(
        self,
        mut req: Request<Incoming>,
        accounts: &HashMap<String, String>,
        context: Context,
    ) -> hyper::Result<Response<BoxBody<Bytes, hyper::Error>>> {
        trace!("request {} {:?}", self.peer_addr, req);

        // Parse URI
        //
        // Proxy request URI must contains a host
        let host = match host_addr(req.uri()) {
            None => {
                if req.uri().authority().is_some() {
                    // URI has authority but invalid
                    error!(
                        "HTTP {} URI {} doesn't have a valid host",
                        req.method(),
                        req.uri()
                    );
                    return make_bad_request();
                } else {
                    trace!(
                        "HTTP {} URI {} doesn't have a valid host",
                        req.method(),
                        req.uri()
                    );
                }

                match get_addr_from_header(&mut req) {
                    Ok(h) => h,
                    Err(()) => return make_bad_request(),
                }
            }
            Some(h) => h,
        };

        if !accounts.is_empty() {
            match req.headers().get("Proxy-Authorization") {
                Some(val) => {
                    if !auth(accounts, val.as_bytes()) {
                        error!("HTTP authentication failed from {}", self.peer_addr);
                        return make_error_407();
                    }
                }
                None => {
                    error!("Http authentication is enabled");
                    return make_error_407();
                }
            }
        }

        if req.method() == Method::CONNECT {
            // Establish a TCP tunnel
            // https://tools.ietf.org/html/draft-luotonen-web-proxy-tunneling-01

            debug!("HTTP CONNECT {}", host);

            let client_addr = self.peer_addr;
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        trace!(
                            "CONNECT tunnel upgrade success, {} <-> {}",
                            client_addr,
                            host
                        );

                        let upgraded_io = TokioIo::new(upgraded);
                        let mut stream = Box::new(upgraded_io);
                        let _ =
                            establish_tcp_tunnel(&mut stream, &self.peer_addr, host, context).await;
                    }
                    Err(err) => {
                        error!("failed to upgrade CONNECT request, error: {}", err);
                    }
                }
            });

            return Ok(Response::new(empty_body()));
        }

        // Traditional HTTP Proxy request

        let method = req.method().clone();
        let version = req.version();
        debug!("HTTP {} {} {:?}", method, host, version);

        // Check if client wants us to keep long connection
        let conn_keep_alive = check_keep_alive(version, req.headers(), true);

        // Remove non-forwardable headers
        clear_hop_headers(req.headers_mut());

        // Set keep-alive for connection with remote
        set_conn_keep_alive(version, req.headers_mut(), conn_keep_alive);

        let mut res = match self
            .http_client
            .send_request(&self.peer_addr, req, context)
            .await
        {
            Ok(resp) => resp,
            Err(_) => return make_internal_server_error(),
        };

        trace!("received {} <- {} {:?}", self.peer_addr, host, res);

        let res_keep_alive =
            conn_keep_alive && check_keep_alive(res.version(), res.headers(), false);

        // Clear unforwardable headers
        clear_hop_headers(res.headers_mut());

        if res.version() != version {
            // Reset version to matches req's version
            trace!("response version {:?} => {:?}", res.version(), version);
            *res.version_mut() = version;
        }

        // Set Connection header
        set_conn_keep_alive(res.version(), res.headers_mut(), res_keep_alive);

        trace!("response {} <- {} {:?}", self.peer_addr, host, res);

        debug!(
            "HTTP {} relay {} <-> {} finished",
            method, self.peer_addr, host
        );

        Ok(res.map(|b| b.boxed()))
    }
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body(body: Bytes) -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Full::new(body)
        .map_err(|never| match never {})
        .boxed()
}

fn make_bad_request() -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(empty_body())
        .unwrap())
}

fn make_internal_server_error() -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(empty_body())
        .unwrap())
}

fn make_error_407() -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("Proxy-Authenticate", "Basic realm=\"Proxy\"")
        .body(full_body("Proxy Authentication Required".into()))
        .unwrap())
}

fn get_extra_headers(headers: GetAll<HeaderValue>) -> Vec<String> {
    let mut extra_headers = Vec::new();
    for connection in headers {
        if let Ok(conn) = connection.to_str() {
            // close is a command instead of a header
            if conn.eq_ignore_ascii_case("close") {
                continue;
            }
            for header in conn.split(',') {
                let header = header.trim();
                extra_headers.push(header.to_owned());
            }
        }
    }
    extra_headers
}

fn clear_hop_headers(headers: &mut HeaderMap<HeaderValue>) {
    // Clear headers indicated by Connection and Proxy-Connection
    let mut extra_headers = get_extra_headers(headers.get_all("Connection"));
    extra_headers.extend(get_extra_headers(headers.get_all("Proxy-Connection")));

    for header in extra_headers {
        while headers.remove(&header).is_some() {}
    }

    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
    const HOP_BY_HOP_HEADERS: [&str; 9] = [
        "Keep-Alive",
        "Transfer-Encoding",
        "TE",
        "Connection",
        "Trailer",
        "Upgrade",
        "Proxy-Authorization",
        "Proxy-Authenticate",
        "Proxy-Connection", // Not standard, but many implementations do send this header
    ];

    for header in &HOP_BY_HOP_HEADERS {
        while headers.remove(*header).is_some() {}
    }
}

fn auth(accounts: &HashMap<String, String>, val: &[u8]) -> bool {
    if let Ok(val) = std::str::from_utf8(val) {
        if let Some(val) = val.strip_prefix("Basic ") {
            if let Ok(val) = BASIC_AUTH_BASE64_ENGINE.decode(val) {
                if let Ok(val) = String::from_utf8(val) {
                    if let Some(i) = val.find(':') {
                        let username = &val[..i];
                        let password = &val[i + 1..];
                        if let Some(pwd) = accounts.get(username) {
                            return pwd == password;
                        }
                    }
                }
            }
        }
    }
    false
}

fn set_conn_keep_alive(version: Version, headers: &mut HeaderMap<HeaderValue>, keep_alive: bool) {
    match version {
        Version::HTTP_09 | Version::HTTP_10 => {
            // HTTP/1.0 close connection by default
            if keep_alive {
                headers.insert("Connection", HeaderValue::from_static("keep-alive"));
            }
        }
        _ => {
            // HTTP/1.1, HTTP/2, HTTP/3 keep-alive connection by default
            if !keep_alive {
                headers.insert("Connection", HeaderValue::from_static("close"));
            }
        }
    }
}

fn get_addr_from_header(req: &mut Request<Incoming>) -> Result<Address, ()> {
    // Try to be compatible as a transparent HTTP proxy
    match req.headers().get("Host") {
        Some(hhost) => match hhost.to_str() {
            Ok(shost) => {
                match Authority::from_str(shost) {
                    Ok(authority) => match authority_addr(req.uri().scheme_str(), &authority) {
                        Some(host) => {
                            trace!(
                                "HTTP {} URI {} got host from header: {}",
                                req.method(),
                                req.uri(),
                                host
                            );

                            // Reassemble URI
                            let mut parts = req.uri().clone().into_parts();
                            if parts.scheme.is_none() {
                                // Use http as default.
                                parts.scheme = Some(Scheme::HTTP);
                            }
                            parts.authority = Some(authority);

                            // Replaces URI
                            *req.uri_mut() = Uri::from_parts(parts).expect("Reassemble URI failed");

                            debug!("reassembled URI from \"Host\", {}", req.uri());

                            Ok(host)
                        }
                        None => {
                            error!(
                                "HTTP {} URI {} \"Host\" header invalid, value: {}",
                                req.method(),
                                req.uri(),
                                shost
                            );

                            Err(())
                        }
                    },
                    Err(..) => {
                        error!(
                            "HTTP {} URI {} \"Host\" header is not an Authority, value: {:?}",
                            req.method(),
                            req.uri(),
                            hhost
                        );

                        Err(())
                    }
                }
            }
            Err(..) => {
                error!(
                    "HTTP {} URI {} \"Host\" header invalid encoding, value: {:?}",
                    req.method(),
                    req.uri(),
                    hhost
                );

                Err(())
            }
        },
        None => {
            error!(
                "HTTP {} URI doesn't have valid host and missing the \"Host\" header, URI: {}",
                req.method(),
                req.uri()
            );

            Err(())
        }
    }
}
