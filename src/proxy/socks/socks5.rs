use super::super::{Inbound, Outbound, ProxySteam};
use super::SocksInbound;
use crate::common::{new_io_error, Address};
use async_trait::async_trait;
use shadowsocks::relay::socks5::{
    self, Command, HandshakeRequest, HandshakeResponse, PasswdAuthRequest, PasswdAuthResponse,
    Reply, TcpRequestHeader, TcpResponseHeader,
};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::net::TcpStream;

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
        mut stream: Box<dyn ProxySteam>,
        peer_addr: &SocketAddr,
    ) -> std::io::Result<(Box<dyn ProxySteam>, Address)> {
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
                    return Err(new_io_error("Socks5 authentication is enabled"));
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

                        return Err(new_io_error(format!(
                            "Socks5 authentication request failed: {err}"
                        )));
                    }
                };
                todo!("socks5 auth");
            }
            method => {
                let response = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
                response.write_to(&mut stream).await?;
                return Err(new_io_error(format!(
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
                    Address::SocketAddress(peer_addr.to_owned()),
                );
                response.write_to(&mut stream).await?;
                return Err(err.into());
            }
        };
        let address = request.address;

        // 3. Handle Command
        match request.command {
            Command::TcpConnect => {
                let response = TcpResponseHeader::new(socks5::Reply::Succeeded, self.addr.clone());
                response.write_to(&mut stream).await?;
            }
            Command::UdpAssociate => {
                todo!("socks5 udp");
            }
            Command::TcpBind => {
                let response = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, address);
                response.write_to(&mut stream).await?;
                return Err(new_io_error("Socks5 tcp bind is not supported"));
            }
        }

        Ok((stream, address))
    }
}

#[derive(Clone, Debug)]
pub struct Socks5Outbound {
    addr: Address,
    accounts: HashMap<String, String>,
}

impl Socks5Outbound {
    pub fn new(addr: Address, accounts: Vec<(String, String)>) -> Self {
        let accounts: HashMap<_, _> = accounts.into_iter().collect();
        Self { addr, accounts }
    }
}
#[async_trait]
impl Outbound for Socks5Outbound {
    async fn handle(&self, addr: &Address) -> std::io::Result<Box<dyn ProxySteam>> {
        let d = self.addr.to_socket_addrs()?.next().ok_or_else(|| {
            new_io_error(format!(
                "Sock5 outbound address {} has to be a socket address",
                self.addr
            ))
        })?;
        let mut stream = TcpStream::connect(d).await?;

        let mut auth_method = socks5::SOCKS5_AUTH_METHOD_NONE;
        if !self.accounts.is_empty() {
            auth_method = socks5::SOCKS5_AUTH_METHOD_PASSWORD;
        }
        let request = HandshakeRequest::new(vec![auth_method]);
        request.write_to(&mut stream).await?;
        let response = HandshakeResponse::read_from(&mut stream).await?;

        if response.chosen_method != auth_method {
            return Err(new_io_error("Socks5 handshake method dose not match"));
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
                log::info!("Socks5 outbound: {}", response.address);
                let stream: Box<dyn ProxySteam> = Box::new(stream);
                Ok(stream)
            }
            reply => Err(new_io_error(reply.to_string())),
        }
    }
}
