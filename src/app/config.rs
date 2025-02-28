use crate::impl_display;
use serde::de::{Deserializer, Error};
use serde::{Deserialize, Serialize};
pub use shadowsocks_crypto::kind::CipherKind;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub log: LogConfig,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub routing: RoutingConfig,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let config = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&config)?)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevelOption {
    Error,
    #[serde(alias = "warning")]
    Warn,
    Info,
    Debug,
    Trace,
    #[serde(alias = "none")]
    Off,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LogConfig {
    pub access: Option<String>,
    pub error: Option<String>,
    pub loglevel: LogLevelOption,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            access: None,
            error: None,
            loglevel: LogLevelOption::Warn,
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
}

#[derive(Clone, Debug, Deserialize)]
pub struct StreamSettings {
    pub network: NetworkOption,
    pub security: SecurityOption,
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            network: NetworkOption::Tcp,
            security: SecurityOption::None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InboundProtocolOption {
    Socks,
    Http,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SocksAuthOption {
    NoAuth,
    Password,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SocksAccount {
    pub user: String,
    pub pass: String,
}

fn default_socks_auth() -> SocksAuthOption {
    SocksAuthOption::NoAuth
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(untagged)]
pub enum InboundSettings {
    Socks {
        #[serde(default = "default_socks_auth")]
        auth: SocksAuthOption,
        #[serde(default)]
        accounts: Vec<SocksAccount>,
        #[serde(default)]
        udp: bool,
    },
    #[default]
    None,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Sniffing {
    pub enabled: bool,
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
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutboundProtocolOption {
    Blackhole,
    Freedom,
    Shadowsocks,
    Socks,
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
    #[serde(default)]
    pub level: u16,
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
    #[serde(default)]
    pub level: u16,
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
    pub uot: bool,
    #[serde(default)]
    pub level: u16,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum OutboundSettings {
    Vless {
        vnext: Vec<VlessServer>,
    },
    Socks {
        servers: Vec<SocksServer>,
    },
    Shadowsocks {
        servers: Vec<ShadowsocksServer>,
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
                uot: false,
                level: 0,
            }],
        };
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
                    level: 0,
                }],
            }],
        };
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
