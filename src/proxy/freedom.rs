use super::{Outbound, ProxySteam};
use crate::common::{Address, ConnectOpts, TcpStream, DEFAULT_CONTEXT};

use async_trait::async_trait;

#[derive(Clone, Debug, Default)]
pub struct FreedomOutbound {
    connect_opts: ConnectOpts,
}

#[async_trait]
impl Outbound for FreedomOutbound {
    async fn handle(&self, addr: &Address) -> std::io::Result<Box<dyn ProxySteam>> {
        let stream =
            TcpStream::connect_remote_with_opts(&DEFAULT_CONTEXT, addr, &self.connect_opts).await?;
        let stream: Box<dyn ProxySteam> = Box::new(stream);
        Ok(stream)
    }
}
