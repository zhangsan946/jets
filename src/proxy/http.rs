use super::{Inbound, Outbound, ProxySteam};
use crate::app::establish_tcp_tunnel;
use crate::app::router::Router;
use crate::common::{new_io_error, Address};
use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::Incoming;
use hyper::http::{Method, Request, Response, StatusCode, Uri};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::io::Result;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub struct HttpInbound {
    addr: Address,
    accounts: HashMap<String, String>,
}

impl HttpInbound {
    pub fn new(addr: Address, accounts: Vec<(String, String)>) -> Self {
        let accounts: HashMap<_, _> = accounts.into_iter().collect();
        Self { addr, accounts }
    }
}

#[async_trait]
impl Inbound for HttpInbound {
    fn addr(&self) -> &Address {
        &self.addr
    }

    fn clone_box(&self) -> Box<dyn Inbound> {
        Box::new(self.clone())
    }

    async fn handle(
        &self,
        stream: TcpStream,
        inbound_tag: Option<String>,
        outbounds: Arc<HashMap<String, Arc<Box<dyn Outbound>>>>,
        router: Arc<Router>,
    ) -> Result<()> {
        let peer_addr = stream.peer_addr().expect("peer addr");
        let io = TokioIo::new(stream);
        http1::Builder::new()
            .keep_alive(true)
            .title_case_headers(true)
            .preserve_header_case(true)
            .serve_connection(
                io,
                service_fn(move |req| {
                    serve_connection(
                        req,
                        peer_addr,
                        inbound_tag.clone(),
                        outbounds.clone(),
                        router.clone(),
                    )
                }),
            )
            .with_upgrades()
            .await
            .map_err(new_io_error)
    }
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn make_bad_request() -> hyper::Result<Response<BoxBody<Bytes, hyper::Error>>> {
    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(empty_body())
        .unwrap())
}

async fn serve_connection(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    inbound_tag: Option<String>,
    outbounds: Arc<HashMap<String, Arc<Box<dyn Outbound>>>>,
    router: Arc<Router>,
) -> hyper::Result<Response<BoxBody<Bytes, hyper::Error>>> {
    log::debug!("request: {:?}", req);
    let host = if let Some(addr) = host_addr(req.uri()) {
        addr
    } else {
        return make_bad_request();
    };

    if req.method() == Method::CONNECT {
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    log::debug!("CONNECT tunnel upgrade success, {} <-> {}", peer_addr, host);

                    let upgraded_io = TokioIo::new(upgraded);
                    let stream: Box<dyn ProxySteam> = Box::new(upgraded_io);
                    let _ =
                        establish_tcp_tunnel(stream, host, inbound_tag, outbounds, router).await;
                }
                Err(err) => log::error!("failed to upgrade CONNECT request, error: {}", err),
            }
        });
        Ok(Response::new(empty_body()))
    } else {
        todo!("handle http request");
    }
}

fn host_addr(uri: &Uri) -> Option<Address> {
    uri.authority()
        .and_then(|auth| Address::from_str(auth.as_str()).map(Some).unwrap_or(None))
}
