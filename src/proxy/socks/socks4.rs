use crate::app::connect_tcp_host;
use crate::app::Context as AppContext;
use crate::common::{copy_bidirectional, invalid_data_error, Address};
use shadowsocks_service::local::socks::socks4::{
    Address as Socks4Address, Command, Error as Socks4Error, HandshakeRequest, HandshakeResponse,
    ResultCode,
};
use std::io::{ErrorKind, Result};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream as TokioTcpStream,
};

#[derive(Clone, Debug)]
pub struct Socks4aInbound;

impl Socks4aInbound {
    pub async fn handle_tcp(
        &self,
        stream: TokioTcpStream,
        peer_addr: SocketAddr,
        context: AppContext,
    ) -> Result<()> {
        // 1. Handshake

        // NOTE: Wraps it with BufReader for reading NULL terminated information in HandshakeRequest
        let mut s = BufReader::new(stream);
        let request = match HandshakeRequest::read_from(&mut s).await {
            Ok(r) => r,
            Err(Socks4Error::IoError(ref err)) if err.kind() == ErrorKind::UnexpectedEof => {
                log::trace!("socks4 handshake early eof. peer: {}", peer_addr);
                return Ok(());
            }
            Err(err) => {
                log::error!("socks4 handshake error: {}", err);
                return Err(err.into());
            }
        };

        let address = match request.dst {
            Socks4Address::SocketAddress(addr) => Address::SocketAddress(SocketAddr::V4(addr)),
            Socks4Address::DomainNameAddress(addr, port) => Address::DomainNameAddress(addr, port),
        };

        // 3. Handle Command
        match request.cd {
            Command::Connect => {
                let mut down_stream = match connect_tcp_host(&peer_addr, address, context).await {
                    Ok(stream) => {
                        let response = HandshakeResponse::new(ResultCode::RequestGranted);
                        response.write_to(&mut s).await?;
                        stream
                    }
                    Err(e) => {
                        let response = HandshakeResponse::new(ResultCode::RequestRejectedOrFailed);
                        response.write_to(&mut s).await?;
                        return Err(e);
                    }
                };

                // NOTE: Transfer all buffered data before unwrap, or these data will be lost
                let buffer = s.buffer();
                if !buffer.is_empty() {
                    down_stream.write_all(buffer).await?;
                }

                let stream = s.into_inner();
                let mut stream = Box::new(stream);
                copy_bidirectional(&mut stream, &mut down_stream)
                    .await
                    .map(|_| ())
            }
            Command::Bind => {
                let response = HandshakeResponse::new(ResultCode::RequestRejectedOrFailed);
                response.write_to(&mut s).await?;
                Err(invalid_data_error("Socks4 tcp bind is not supported"))
            }
        }
    }
}
