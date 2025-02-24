use crate::common::Address;
use log::info;

pub struct Router {
    default: String,
}

impl Router {
    pub fn new<S: Into<String>>(default: S) -> Self {
        Self {
            default: default.into(),
        }
    }

    pub fn match_addr(&self, addr: &Address) -> &String {
        info!("route {} to {}", addr, self.default);
        &self.default
    }
}
