use super::super::{Inbound, Outbound, ProxySteam};
use super::SocksInbound;
use crate::app::config::SocksUser;
use crate::app::establish_tcp_tunnel;
use crate::app::router::Router;
use crate::common::{invalid_data_error, Address, ConnectOpts, TcpStream, DEFAULT_CONTEXT};
use async_trait::async_trait;
use shadowsocks::relay::socks5::{
    self, Command, HandshakeRequest, HandshakeResponse, PasswdAuthRequest, PasswdAuthResponse,
    Reply, TcpRequestHeader, TcpResponseHeader,
};
use std::collections::HashMap;
use std::io::Result;
use std::sync::Arc;
use tokio::net::TcpStream as TokioTcpStream;

#[derive(Clone, Debug)]
pub struct Socks5Inbound {
    addr: Address,
    accounts: HashMap<String, String>,
}

impl Socks5Inbound {
    pub fn new(addr: Address, accounts: Vec<(String, String)>) -> Self {
        let accounts: HashMap<_, _> = accounts.into_iter().collect();
        Self { addr, accounts }
    }
}

impl From<SocksInbound> for Socks5Inbound {
    fn from(value: SocksInbound) -> Self {
        Socks5Inbound {
            addr: value.addr,
            accounts: value.accounts,
        }
    }
}

#[async_trait]
impl Inbound for Socks5Inbound {
    fn addr(&self) -> &Address {
        &self.addr
    }

    fn clone_box(&self) -> Box<dyn Inbound> {
        Box::new(self.clone())
    }

    async fn handle(
        &self,
        mut stream: TokioTcpStream,
        inbound_tag: Option<String>,
        outbounds: Arc<HashMap<String, Arc<Box<dyn Outbound>>>>,
        router: Arc<Router>,
    ) -> Result<()> {
        // 1. Handshake
        let request = match HandshakeRequest::read_from(&mut stream).await {
            Ok(r) => r,
            Err(err) => {
                return Err(err.into());
            }
        };

        match request.methods.first() {
            Some(&socks5::SOCKS5_AUTH_METHOD_NONE) => {
                if !self.accounts.is_empty() {
                    return Err(invalid_data_error("Socks5 authentication is enabled"));
                }
                let response = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
                response.write_to(&mut stream).await?;
            }
            Some(&socks5::SOCKS5_AUTH_METHOD_PASSWORD) => {
                let response = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_PASSWORD);
                response.write_to(&mut stream).await?;
                let _request = match PasswdAuthRequest::read_from(&mut stream).await {
                    Ok(p) => p,
                    Err(err) => {
                        let response = PasswdAuthResponse::new(err.as_reply().as_u8());
                        response.write_to(&mut stream).await?;

                        return Err(invalid_data_error(format!(
                            "Socks5 authentication request failed: {err}"
                        )));
                    }
                };
                todo!("socks5 auth");
            }
            method => {
                let response = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
                response.write_to(&mut stream).await?;
                return Err(invalid_data_error(format!(
                    "Unsupported socks5 authentication method {:?}",
                    method
                )));
            }
        }

        // 2. Fetch headers
        let request = match TcpRequestHeader::read_from(&mut stream).await {
            Ok(h) => h,
            Err(err) => {
                let response = TcpResponseHeader::new(
                    err.as_reply(),
                    Address::SocketAddress(stream.peer_addr()?),
                );
                response.write_to(&mut stream).await?;
                return Err(err.into());
            }
        };
        let address = request.address;

        // 3. Handle Command
        match request.command {
            Command::TcpConnect => {
                let response = TcpResponseHeader::new(Reply::Succeeded, self.addr.clone());
                response.write_to(&mut stream).await?;
            }
            Command::UdpAssociate => {
                todo!("socks5 udp");
            }
            Command::TcpBind => {
                let response = TcpResponseHeader::new(Reply::CommandNotSupported, address);
                response.write_to(&mut stream).await?;
                return Err(invalid_data_error("Socks5 tcp bind is not supported"));
            }
        }
        let stream: Box<dyn ProxySteam> = Box::new(stream);
        establish_tcp_tunnel(stream, &address, &inbound_tag, outbounds, router).await
    }
}

#[derive(Clone, Debug)]
pub struct Socks5Outbound {
    addr: Address,
    accounts: HashMap<String, String>,
    connect_opts: ConnectOpts,
}

impl Socks5Outbound {
    pub fn new(addr: Address, accounts: Vec<SocksUser>) -> Self {
        let accounts: HashMap<_, _> = accounts.into_iter().map(|s| (s.user, s.pass)).collect();
        Self {
            addr,
            accounts,
            connect_opts: ConnectOpts::default(),
        }
    }
}
#[async_trait]
impl Outbound for Socks5Outbound {
    async fn handle(&self, addr: &Address) -> Result<Box<dyn ProxySteam>> {
        let mut stream =
            TcpStream::connect_remote_with_opts(&DEFAULT_CONTEXT, &self.addr, &self.connect_opts)
                .await?;

        let mut auth_method = socks5::SOCKS5_AUTH_METHOD_NONE;
        if !self.accounts.is_empty() {
            auth_method = socks5::SOCKS5_AUTH_METHOD_PASSWORD;
        }
        let request = HandshakeRequest::new(vec![auth_method]);
        request.write_to(&mut stream).await?;
        let response = HandshakeResponse::read_from(&mut stream).await?;

        if response.chosen_method != auth_method {
            return Err(invalid_data_error("Socks5 handshake method dose not match"));
        }

        if auth_method == socks5::SOCKS5_AUTH_METHOD_PASSWORD {
            todo!("socks5 auth");
        }

        // 2. Send request header
        let request = TcpRequestHeader::new(Command::TcpConnect, addr.to_owned());
        request.write_to(&mut stream).await?;
        let response = TcpResponseHeader::read_from(&mut stream).await?;

        match response.reply {
            Reply::Succeeded => {
                log::debug!("Connected to socks5 server: {}", response.address);
                let stream: Box<dyn ProxySteam> = Box::new(stream);
                Ok(stream)
            }
            reply => Err(invalid_data_error(format!(
                "Sock server reply error: {}",
                reply
            ))),
        }
    }
}
