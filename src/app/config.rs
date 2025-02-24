use crate::proxy::{
    freedom::FreedomOutbound,
    shadowsocks::ShadowsocksOutbound,
    socks::{Socks5Outbound, SocksInbound},
    vless::VlessOutbound,
};

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub freedom_outbounds: Vec<(String, FreedomOutbound)>,
    pub shadowsocks_outbounds: Vec<(String, ShadowsocksOutbound)>,
    pub socks_inbounds: Vec<SocksInbound>,
    pub socks5_outbounds: Vec<(String, Socks5Outbound)>,
    pub vless_outbounds: Vec<(String, VlessOutbound)>,
}

impl Config {
    pub fn add_freedom_outbound<S: Into<String>>(mut self, tag: S) -> Self {
        self.freedom_outbounds
            .push((tag.into(), FreedomOutbound::default()));
        self
    }

    pub fn add_shadowsocks_outbound<S: Into<String>>(
        mut self,
        tag: S,
        addr: &str,
        password: &str,
        method: &str,
    ) -> Self {
        let ss_outbound =
            ShadowsocksOutbound::new(addr, password, method).expect("Invalid shadowsocks outbound");
        self.shadowsocks_outbounds.push((tag.into(), ss_outbound));
        self
    }

    pub fn add_socks_inbound(mut self, addr: &str, accounts: Vec<(String, String)>) -> Self {
        let socks_inbound = SocksInbound::new(addr, accounts).expect("Invalid socks inbound");
        self.socks_inbounds.push(socks_inbound);
        self
    }

    pub fn add_socks5_outbound<S: Into<String>>(
        mut self,
        tag: S,
        addr: &str,
        accounts: Vec<(String, String)>,
    ) -> Self {
        let socks5_outbound = Socks5Outbound::new(addr, accounts).expect("Invalid socks5 outbound");
        self.socks5_outbounds.push((tag.into(), socks5_outbound));
        self
    }

    pub fn add_vless_outbound<S: Into<String>>(
        mut self,
        tag: S,
        addr: &str,
        id: &str,
        flow: &str,
    ) -> Self {
        let vless_outbound = VlessOutbound::new(addr, id, flow).expect("Invalid vless outbound");
        self.vless_outbounds.push((tag.into(), vless_outbound));
        self
    }
}
