pub mod raw;
pub mod tls;
pub mod ws;

use crate::app::config::{NetworkOption, SecurityOption, StreamSettings};
use crate::common::Address;
use crate::proxy::{ProxySocket, ProxyStream};
use raw::{ConnectOpts, TcpStream, UdpSocket};
use std::io::Result;
use std::net::SocketAddr;
use tls::Tls;
use ws::Ws;

#[derive(Clone, Debug)]
pub struct TransportSettings {
    network: NetworkOption,
    security: SecurityOption,
    connect_opts: ConnectOpts,
    tls: Tls,
    ws: Ws,
}

impl TransportSettings {
    pub fn new(mut stream_settings: StreamSettings, server_addr: &Address) -> Result<Self> {
        let connect_opts = ConnectOpts::try_from(stream_settings.sockopt)?;

        if stream_settings.network == NetworkOption::Websocket {
            stream_settings.tls_settings.alpn = vec![b"http/1.1".to_vec()]
        }
        let tls = Tls::new(stream_settings.tls_settings, server_addr)?;
        let ws = Ws::new(
            stream_settings.ws_settings,
            server_addr,
            stream_settings.security != SecurityOption::None,
        )?;

        Ok(Self {
            network: stream_settings.network,
            security: stream_settings.security,
            connect_opts,
            tls,
            ws,
        })
    }

    pub fn get_connect_opts(&self) -> &ConnectOpts {
        &self.connect_opts
    }

    pub async fn connect_tcp(
        &self,
        server_addr: &SocketAddr,
        xtls: bool,
    ) -> Result<Box<dyn ProxyStream>> {
        let stream = TcpStream::connect_with_opts(server_addr, &self.connect_opts).await?;
        match self.security {
            SecurityOption::Tls => {
                let stream = self.tls.connect(stream, xtls).await?;
                match self.network {
                    NetworkOption::Tcp => Ok(Box::new(stream) as Box<dyn ProxyStream>),
                    NetworkOption::Websocket => {
                        Ok(Box::new(self.ws.connect(stream).await?) as Box<dyn ProxyStream>)
                    }
                }
            }
            _ => match self.network {
                NetworkOption::Tcp => Ok(Box::new(stream) as Box<dyn ProxyStream>),
                NetworkOption::Websocket => {
                    Ok(Box::new(self.ws.connect(stream).await?) as Box<dyn ProxyStream>)
                }
            },
        }
    }

    pub async fn bind(&self, server_addr: &SocketAddr) -> Result<Box<dyn ProxySocket>> {
        let socket = UdpSocket::connect_any_with_opts(server_addr, &self.connect_opts).await?;
        Ok(Box::new(socket) as Box<dyn ProxySocket>)
    }
}
