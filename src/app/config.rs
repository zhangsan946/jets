use crate::common::log::JETS_ACCESS_LIST;
use crate::common::{invalid_input_error, TCP_DEFAULT_KEEPALIVE_TIMEOUT};
use crate::impl_display;
use crate::transport::raw::{AcceptOpts, ConnectOpts, TcpSocketOpts, UdpSocketOpts};
use serde::de::{Deserializer, Error};
use serde::{Deserialize, Serialize};
pub use shadowsocks_crypto::kind::CipherKind;
use std::collections::HashMap;
use std::fs;
use std::io::{Error as IoError, Result as IoResult};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub log: LogConfig,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub routing: RoutingConfig,
    pub dns: DnsConfig,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> IoResult<Self> {
        let config = fs::read_to_string(path)
            .map_err(|e| invalid_input_error(format!("Failed to load config file: {:#}", e)))?;
        Ok(serde_json::from_str(&config)?)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LogConfig {
    pub access: Option<String>,
    pub error: Option<String>,
    pub loglevel: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            access: None,
            error: None,
            loglevel: format!("{}=info, warn", JETS_ACCESS_LIST),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkOption {
    #[serde(alias = "raw")]
    Tcp,
    #[serde(alias = "ws")]
    Websocket,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecurityOption {
    None,
    Tls,
    Reality,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct TlsSettings {
    pub server_name: Option<String>,
    pub alpn: Vec<Vec<u8>>,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            server_name: None,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WsSettings {
    pub path: String,
    pub host: String,
    pub headers: HashMap<String, String>,
}

impl Default for WsSettings {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: "".to_string(),
            headers: HashMap::new(),
        }
    }
}

#[cfg(target_os = "android")]
mod android {
    use std::fmt;

    type SocketProtect = Box<dyn Fn(std::os::fd::RawFd) -> std::io::Result<()> + Send + Sync>;

    pub struct SocketProtectFn {
        pub f: SocketProtect,
    }

    impl fmt::Debug for SocketProtectFn {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("SocketProtect").finish_non_exhaustive()
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SocketOption {
    pub mark: Option<u32>,
    pub interface: Option<String>,
    pub bind_addr: Option<String>,
    pub tcp_keep_alive_interval: Option<u64>,
    pub tcp_fast_open: bool,
    pub tcp_no_delay: bool,
    pub tcp_mptcp: bool,
    pub tcp_send_buffer_size: Option<u32>,
    pub tcp_recv_buffer_size: Option<u32>,
    pub udp_mtu: Option<usize>,
    pub udp_fragment: bool,
    pub v6_only: bool,
    #[cfg(target_os = "android")]
    #[serde(skip_deserializing)]
    pub vpn_socket_protect: Option<std::sync::Arc<android::SocketProtectFn>>,
}

impl Default for SocketOption {
    fn default() -> Self {
        Self {
            mark: None,
            interface: None,
            bind_addr: None,
            // https://github.com/shadowsocks/shadowsocks-rust/blob/22791eed3cb32425fed831c44f8bb644051c74ce/crates/shadowsocks-service/src/local/mod.rs#L148
            // https://github.com/shadowsocks/shadowsocks-rust/blob/22791eed3cb32425fed831c44f8bb644051c74ce/crates/shadowsocks-service/src/local/mod.rs#L162
            tcp_keep_alive_interval: Some(TCP_DEFAULT_KEEPALIVE_TIMEOUT.as_secs()),
            tcp_fast_open: false,
            tcp_no_delay: false,
            tcp_mptcp: false,
            tcp_send_buffer_size: None,
            tcp_recv_buffer_size: None,
            udp_mtu: None,
            udp_fragment: false,
            v6_only: false,
            #[cfg(target_os = "android")]
            vpn_socket_protect: None,
        }
    }
}

#[cfg(target_os = "android")]
impl SocketOption {
    pub fn set_vpn_socket_protect<F>(&mut self, f: F)
    where
        F: Fn(std::os::fd::RawFd) -> std::io::Result<()> + Send + Sync + 'static,
    {
        self.vpn_socket_protect = Some(std::sync::Arc::new(android::SocketProtectFn {
            f: Box::new(f),
        }));
    }
}

impl From<SocketOption> for TcpSocketOpts {
    fn from(value: SocketOption) -> Self {
        TcpSocketOpts {
            send_buffer_size: value.tcp_send_buffer_size,
            recv_buffer_size: value.tcp_recv_buffer_size,
            nodelay: value.tcp_no_delay,
            fastopen: value.tcp_fast_open,
            keepalive: value.tcp_keep_alive_interval.map(Duration::from_secs),
            mptcp: value.tcp_mptcp,
        }
    }
}

impl From<SocketOption> for UdpSocketOpts {
    fn from(value: SocketOption) -> Self {
        UdpSocketOpts {
            mtu: value.udp_mtu,
            allow_fragmentation: value.udp_fragment,
        }
    }
}

impl From<SocketOption> for AcceptOpts {
    fn from(value: SocketOption) -> Self {
        let tcp = TcpSocketOpts::from(value.clone());
        let udp = UdpSocketOpts::from(value.clone());
        AcceptOpts {
            tcp,
            udp,
            ipv6_only: value.v6_only,
        }
    }
}

impl TryFrom<SocketOption> for ConnectOpts {
    type Error = IoError;
    fn try_from(value: SocketOption) -> IoResult<Self> {
        let tcp = TcpSocketOpts::from(value.clone());
        let udp = UdpSocketOpts::from(value.clone());
        let bind_local_addr =
            if let Some(addr) = value.bind_addr {
                Some(SocketAddr::from_str(&addr).map_err(|_| {
                    invalid_input_error(format!("Invalid socket address: {}", addr))
                })?)
            } else {
                None
            };
        #[allow(unused_mut)]
        let mut opts = ConnectOpts {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            fwmark: value.mark,
            bind_local_addr,
            bind_interface: value.interface,
            tcp,
            udp,
            #[cfg(target_os = "freebsd")]
            user_cookie: None,
            #[cfg(target_os = "android")]
            vpn_protect_path: None,
            #[cfg(target_os = "android")]
            vpn_socket_protect: None,
        };
        #[cfg(target_os = "android")]
        if let Some(protect_fn) = value.vpn_socket_protect {
            use std::sync::Arc;
            let protect_fn = Arc::into_inner(protect_fn).unwrap();
            opts.set_vpn_socket_protect(protect_fn.f);
        }
        Ok(opts)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct StreamSettings {
    pub network: NetworkOption,
    pub security: SecurityOption,
    pub tls_settings: TlsSettings,
    pub ws_settings: WsSettings,
    pub sockopt: SocketOption,
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            network: NetworkOption::Tcp,
            security: SecurityOption::None,
            tls_settings: TlsSettings::default(),
            ws_settings: WsSettings::default(),
            sockopt: SocketOption::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InboundProtocolOption {
    Socks,
    Http,
    Tun,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SocksAuthOption {
    #[default]
    NoAuth,
    Password,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Account {
    pub user: String,
    pub pass: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(untagged)]
pub enum InboundSettings {
    Socks {
        #[serde(default)]
        auth: SocksAuthOption,
        #[serde(default)]
        accounts: Vec<Account>,
        #[serde(default)]
        udp: bool,
    },
    Http {
        #[serde(default)]
        accounts: Vec<Account>,
    },
    Tun {
        name: String,
        address: String,
        destination: String,
        #[cfg(unix)]
        #[serde(default)]
        fd: Option<i32>,
    },
    #[default]
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum DestOverrideOption {
    Http,
    Tls,
    Quic,
    Fakedns,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sniffing {
    pub enabled: bool,
    pub dest_override: Vec<DestOverrideOption>,
}

fn default_listen() -> String {
    "0.0.0.0".to_string()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    pub protocol: InboundProtocolOption,
    #[serde(default)]
    pub settings: InboundSettings,
    #[serde(default)]
    pub stream_settings: StreamSettings,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub sniffing: Sniffing,
}

impl InboundConfig {
    pub fn new<S: Into<String>>(listen: S, port: u16, protocol: InboundProtocolOption) -> Self {
        Self {
            listen: listen.into(),
            port,
            protocol,
            settings: Default::default(),
            stream_settings: Default::default(),
            tag: None,
            sniffing: Default::default(),
        }
    }

    pub fn new_socks<S: Into<String>>(listen: S, port: u16) -> Self {
        Self::new(listen, port, InboundProtocolOption::Socks)
    }

    #[cfg(feature = "inbound-http")]
    pub fn new_http<S: Into<String>>(listen: S, port: u16) -> Self {
        Self::new(listen, port, InboundProtocolOption::Http)
    }

    #[cfg(feature = "inbound-tun")]
    pub fn new_tun<S: Into<String>>(
        name: S,
        address: S,
        destination: S,
        #[cfg(unix)] fd: Option<i32>,
    ) -> Self {
        let mut inbound = Self::new("0.0.0.0", 0, InboundProtocolOption::Tun);
        inbound.settings = InboundSettings::Tun {
            name: name.into(),
            address: address.into(),
            destination: destination.into(),
            #[cfg(unix)]
            fd,
        };
        inbound.sniffing.enabled = true;
        inbound.sniffing.dest_override = vec![DestOverrideOption::Tls, DestOverrideOption::Http];
        inbound
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutboundProtocolOption {
    Blackhole,
    Freedom,
    Shadowsocks,
    Socks,
    Trojan,
    Vless,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VlessEncryptionOption {
    None,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VlessFlow {
    #[default]
    #[serde(rename = "")]
    None,
    #[serde(rename = "xtls-rprx-vision")]
    XtlsRprxVision,
    #[serde(rename = "xtls-rprx-vision-udp443")]
    XtlsRprxVisionUdp,
}
impl_display!(VlessFlow);

pub fn uuid_from_str(id: &str) -> Uuid {
    Uuid::parse_str(id).unwrap_or_else(|_| Uuid::new_v5(&Uuid::nil(), id.as_bytes()))
}

fn deserialize_uuid_from_str<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: Deserializer<'de>,
{
    let id = String::deserialize(deserializer)?;
    Ok(uuid_from_str(&id))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VlessUser {
    #[serde(deserialize_with = "deserialize_uuid_from_str")]
    pub id: Uuid,
    pub encryption: VlessEncryptionOption,
    #[serde(default)]
    pub flow: VlessFlow,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VlessServer {
    pub address: String,
    pub port: u16,
    pub users: Vec<VlessUser>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SocksUser {
    pub user: String,
    pub pass: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SocksServer {
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub users: Vec<SocksUser>,
}

fn deserialize_method_from_str<'de, D>(deserializer: D) -> Result<CipherKind, D::Error>
where
    D: Deserializer<'de>,
{
    let id = String::deserialize(deserializer)?;
    CipherKind::from_str(&id).map_err(Error::custom)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShadowsocksServer {
    pub address: String,
    pub port: u16,
    #[serde(deserialize_with = "deserialize_method_from_str")]
    pub method: CipherKind,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrojanServer {
    pub address: String,
    pub port: u16,
    pub password: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum OutboundSettings {
    Shadowsocks {
        servers: Vec<ShadowsocksServer>,
    },
    Socks {
        servers: Vec<SocksServer>,
    },
    Trojan {
        servers: Vec<TrojanServer>,
    },
    Vless {
        vnext: Vec<VlessServer>,
    },
    #[default]
    None,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundConfig {
    #[serde(default = "default_listen")]
    pub send_through: String,
    pub protocol: OutboundProtocolOption,
    #[serde(default)]
    pub settings: OutboundSettings,
    #[serde(default)]
    pub stream_settings: StreamSettings,
    #[serde(default)]
    pub tag: Option<String>,
}

impl OutboundConfig {
    pub fn new(protocol: OutboundProtocolOption) -> Self {
        Self {
            send_through: default_listen(),
            protocol,
            settings: Default::default(),
            stream_settings: Default::default(),
            tag: None,
        }
    }

    pub fn new_socks<S: Into<String>>(addr: S, port: u16) -> Self {
        let mut outbound = Self::new(OutboundProtocolOption::Socks);
        outbound.settings = OutboundSettings::Socks {
            servers: vec![SocksServer {
                address: addr.into(),
                port,
                users: vec![],
            }],
        };
        outbound
    }

    pub fn new_shadowsocks<S: Into<String>>(
        addr: S,
        port: u16,
        method: CipherKind,
        password: &str,
    ) -> Self {
        let mut outbound = Self::new(OutboundProtocolOption::Shadowsocks);
        outbound.settings = OutboundSettings::Shadowsocks {
            servers: vec![ShadowsocksServer {
                address: addr.into(),
                port,
                method,
                password: password.to_string(),
            }],
        };
        outbound
    }

    #[cfg(feature = "outbound-trojan")]
    pub fn new_trojan<S: Into<String>>(addr: S, port: u16, password: S) -> Self {
        let mut outbound = Self::new(OutboundProtocolOption::Trojan);
        outbound.settings = OutboundSettings::Trojan {
            servers: vec![TrojanServer {
                address: addr.into(),
                port,
                password: password.into(),
            }],
        };
        outbound.stream_settings.security = SecurityOption::Tls;
        outbound
    }

    pub fn new_vless<S: Into<String>>(addr: S, port: u16, id: &str, flow: VlessFlow) -> Self {
        let mut outbound = Self::new(OutboundProtocolOption::Vless);
        outbound.settings = OutboundSettings::Vless {
            vnext: vec![VlessServer {
                address: addr.into(),
                port,
                users: vec![VlessUser {
                    id: uuid_from_str(id),
                    encryption: VlessEncryptionOption::None,
                    flow,
                }],
            }],
        };
        outbound.stream_settings.security = SecurityOption::Tls;
        outbound
    }

    pub fn new_freedom(tag: Option<String>) -> Self {
        let mut outbound = Self::new(OutboundProtocolOption::Freedom);
        outbound.tag = tag;
        outbound
    }

    pub fn new_blackhole(tag: Option<String>) -> Self {
        let mut outbound = Self::new(OutboundProtocolOption::Blackhole);
        outbound.tag = tag;
        outbound
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum DomainStrategy {
    AsIs,
    IPIfNonMatch,
    IPOnDemand,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingRule {
    pub r#type: String,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub inbound_tag: Vec<String>,
    pub outbound_tag: String,
}

impl RoutingRule {
    pub fn new(outbound_tag: String) -> Self {
        Self {
            r#type: "field".to_string(),
            domain: vec![],
            ip: vec![],
            inbound_tag: vec![],
            outbound_tag,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RoutingConfig {
    pub domain_strategy: DomainStrategy,
    pub rules: Vec<RoutingRule>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            domain_strategy: DomainStrategy::AsIs,
            rules: Vec::new(),
        }
    }
}

fn default_dns_port() -> u16 {
    53
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsServer {
    pub address: String,
    #[serde(default = "default_dns_port")]
    pub port: u16,
    #[serde(default)]
    pub domains: Vec<String>,
}

impl DnsServer {
    pub fn new(address: String) -> IoResult<Self> {
        // TODO: To support https://a.b.c.d:8443/my-dns-query
        let (address, port) = match address.rfind(":") {
            Some(i) if (address.len() > i + 1) && (address.get(i..(i + 2)) != Some(":/")) => {
                let (addr, port_str) = address.split_at(i);
                let port = port_str[1..].parse::<u16>().map_err(|_| {
                    invalid_input_error(format!(
                        "Invalid port number in DNS server address: {}",
                        address
                    ))
                })?;
                (addr.to_string(), port)
            }
            _ => (address, default_dns_port()),
        };

        Ok(Self {
            address,
            port,
            domains: Vec::new(),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum QueryStrategy {
    #[default]
    UseIP,
    UseIPv4,
    UseIPv6,
}

fn deserialize_hosts_from_one_or_many_string<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrManyString {
        One(String),
        Many(Vec<String>),
    }

    let hosts = HashMap::<String, OneOrManyString>::deserialize(deserializer)?;
    Ok(hosts
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                match v {
                    OneOrManyString::One(s) => vec![s],
                    OneOrManyString::Many(s) => s,
                },
            )
        })
        .collect())
}

fn deserialize_servers_from_struct_or_string<'de, D>(
    deserializer: D,
) -> Result<Vec<DnsServer>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DeEither {
        DnsServer(DnsServer),
        String(String),
    }

    let servers = Vec::<DeEither>::deserialize(deserializer)?;
    let mut output = Vec::new();
    for server in servers {
        match server {
            DeEither::DnsServer(s) => output.push(s),
            DeEither::String(s) => {
                output.push(DnsServer::new(s).map_err(Error::custom)?);
            }
        }
    }
    Ok(output)
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DnsConfig {
    #[serde(deserialize_with = "deserialize_hosts_from_one_or_many_string")]
    pub hosts: HashMap<String, Vec<String>>,
    #[serde(deserialize_with = "deserialize_servers_from_struct_or_string")]
    pub servers: Vec<DnsServer>,
    pub query_strategy: QueryStrategy,
    pub local_outbound_tag: Option<String>,
    pub tag: Option<String>,
}

#[cfg(test)]
mod test {
    use super::uuid_from_str;
    use uuid::Uuid;

    #[test]
    fn test_map_str_to_uuidv5() {
        let example = "example";
        let uuid = Uuid::parse_str("feb54431-301b-52bb-a6dd-e1e93e81bb9e").unwrap();
        let new_uuid = uuid_from_str(example);
        assert_eq!(uuid, new_uuid);
    }
}
