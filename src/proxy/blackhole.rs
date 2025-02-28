use super::{Outbound, ProxySteam};
use crate::common::Address;

use async_trait::async_trait;

#[derive(Clone, Debug, Default)]
pub struct BlackholeOutbound;

#[async_trait]
impl Outbound for BlackholeOutbound {
    async fn handle(&self, addr: &Address) -> std::io::Result<Box<dyn ProxySteam>> {
        panic!("{} went into blackhole", addr);
    }
}
