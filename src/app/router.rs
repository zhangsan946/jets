use super::config::RoutingConfig;
use super::dat::{Cidr, Domain as ProtoDomain, GeoIpList, GeoSiteList};
use crate::common::{new_io_error, Address};
use prost::Message;
use regex::Regex;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

pub const DEFAULT_OUTBOUND_TAG: &str = "some_implicit_default_outbound_tag";

pub struct Router {
    domain_sites: HashMap<String, Vec<Domain>>,
    ip_sites: HashMap<String, Vec<IpRange>>,
    rules: Vec<Rule>,
}

impl Router {
    pub fn new(config: RoutingConfig) -> Result<Self> {
        let mut domain_sites: HashMap<String, Vec<Domain>> = HashMap::new();
        let mut ip_sites: HashMap<String, Vec<IpRange>> = HashMap::new();
        let mut rules: Vec<Rule> = Vec::new();

        for (index, rule) in config.rules.into_iter().enumerate() {
            // for a new rule
            let mut domains: Vec<String> = Vec::new();
            let mut ips: Vec<String> = Vec::new();
            let mut inbound_tags: HashSet<String> = HashSet::new();

            rule.inbound_tag.into_iter().for_each(|tag| {
                inbound_tags.insert(tag);
            });

            // https://xtls.github.io/config/routing.html#ruleobject
            let mut new_domain_site: Vec<Domain> = Vec::new();
            for mut domain in rule.domain.into_iter() {
                if domain.starts_with("geosite:") {
                    let code = domain.split_off(8).to_lowercase();
                    // https://github.com/Loyalsoldier/v2ray-rules-dat?tab=readme-ov-file#%E9%AB%98%E7%BA%A7%E7%94%A8%E6%B3%95
                    let real_code = if let Some(i) = code.find('@') {
                        code[..i].to_string()
                    } else {
                        code.clone()
                    };
                    if let Entry::Vacant(vacant) = domain_sites.entry(real_code.clone()) {
                        match geo_site()
                            .entry
                            .iter()
                            .find(|item| item.country_code.to_lowercase() == real_code)
                        {
                            Some(geo_site) => {
                                let mut domain_site: Vec<Domain> = Vec::new();
                                for item in geo_site.domain.iter() {
                                    match Domain::try_from(item.clone()) {
                                        Ok(domain) => {
                                            domain_site.push(domain);
                                        }
                                        Err(e) => {
                                            log::warn!(
                                                "Invalid domain {} convention, error: {}",
                                                item.value,
                                                e
                                            );
                                        }
                                    }
                                }
                                vacant.insert(domain_site);
                                domains.push(code);
                            }
                            None => {
                                return Err(Error::new(
                                    ErrorKind::InvalidInput,
                                    format!("Geosite does not contain the code of {}", real_code),
                                ))
                            }
                        }
                    }
                } else if domain.starts_with("regexp:") {
                    let regex = &domain.split_off(7);
                    let regex = Regex::new(regex).map_err(|_| {
                        Error::new(
                            ErrorKind::InvalidData,
                            format!("Invalid regex value of {}", regex),
                        )
                    })?;
                    let new_domain = Domain::new(MatchType::Regex(regex));
                    new_domain_site.push(new_domain);
                } else if domain.starts_with("domain:") {
                    let new_domain = Domain::new(MatchType::SubDomain(domain.split_off(7)));
                    new_domain_site.push(new_domain);
                } else if domain.starts_with("full:") {
                    let new_domain = Domain::new(MatchType::FullDomain(domain.split_off(5)));
                    new_domain_site.push(new_domain);
                } else {
                    let new_domain = Domain::new(MatchType::Substr(domain));
                    new_domain_site.push(new_domain);
                }
            }
            if !new_domain_site.is_empty() {
                let code = format!("new_domain_site_{}", index);
                domain_sites.insert(code.clone(), new_domain_site);
                domains.push(code);
            }

            let mut new_ip_site: Vec<IpRange> = Vec::new();
            for mut ip in rule.ip.into_iter() {
                if ip.starts_with("geoip:") {
                    let code = ip.split_off(6).to_lowercase();
                    if let Entry::Vacant(vacant) = ip_sites.entry(code.clone()) {
                        match geo_ip()
                            .entry
                            .iter()
                            .find(|item| item.country_code.to_lowercase() == code)
                        {
                            Some(geo_ip) => {
                                let mut ip_site: Vec<IpRange> = Vec::new();
                                for item in geo_ip.cidr.iter() {
                                    match IpRange::try_from(item.clone()) {
                                        Ok(ip) => {
                                            ip_site.push(ip);
                                        }
                                        Err(e) => {
                                            log::warn!(
                                                "Invalid ip {:?} convention, error: {}",
                                                item.ip,
                                                e
                                            );
                                        }
                                    }
                                }
                                vacant.insert(ip_site);
                                ips.push(code);
                            }
                            None => {
                                return Err(Error::new(
                                    ErrorKind::InvalidInput,
                                    format!("Geoip does not contain the code of {}", code),
                                ))
                            }
                        }
                    }
                } else if let Some(index) = ip.find('/') {
                    let prefix = u32::from_str(&ip[(index + 1)..]).map_err(|_| {
                        Error::new(
                            ErrorKind::InvalidInput,
                            format!("Invalid ip prefix of {}", ip),
                        )
                    })?;
                    let ip = &ip[..index];
                    let ip = IpAddr::from_str(ip).map_err(|_| {
                        Error::new(ErrorKind::InvalidInput, format!("Invalid ip of {}", ip))
                    })?;
                    new_ip_site.push(IpRange { ip, prefix });
                } else {
                    let ip = IpAddr::from_str(&ip)
                        .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
                    let prefix = match ip {
                        IpAddr::V4(_) => 32,
                        IpAddr::V6(_) => 128,
                    };
                    new_ip_site.push(IpRange { ip, prefix });
                }
            }
            if !new_ip_site.is_empty() {
                let code = format!("new_ip_site_{}", index);
                ip_sites.insert(code.clone(), new_ip_site);
                ips.push(code);
            }

            let rule = Rule {
                domains,
                ips,
                inbound_tags,
                outbound_tag: rule.outbound_tag,
            };
            rules.push(rule);
        }
        Ok(Self {
            domain_sites,
            ip_sites,
            rules,
        })
    }

    pub fn pick(&self, addr: &Address, tag: &Option<String>) -> String {
        for rule in self.rules.iter() {
            if let Some(outbound_tag) = rule.matches(addr, tag, &self.domain_sites, &self.ip_sites)
            {
                log::debug!("Route {} to tag: {}", addr, outbound_tag);
                return outbound_tag;
            }
        }
        log::info!("Route {} to the first outbound", addr);
        DEFAULT_OUTBOUND_TAG.to_string()
    }
}

struct Rule {
    domains: Vec<String>,
    ips: Vec<String>,
    inbound_tags: HashSet<String>,
    outbound_tag: String,
}

impl Rule {
    pub fn matches(
        &self,
        addr: &Address,
        tag: &Option<String>,
        domain_sites: &HashMap<String, Vec<Domain>>,
        ip_sites: &HashMap<String, Vec<IpRange>>,
    ) -> Option<String> {
        let mut hit = false;
        if !self.inbound_tags.is_empty() {
            if let Some(tag) = tag {
                if self.inbound_tags.contains(tag) {
                    hit = true;
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }

        if !self.domains.is_empty() {
            if let Address::DomainNameAddress(host, _) = addr {
                for domain in self.domains.iter() {
                    let (code, attr) = match domain.find('@') {
                        Some(i) => (&domain[..i], Some(&domain[(i + 1)..])),
                        None => (domain.as_str(), None),
                    };
                    let domains = domain_sites.get(code).expect("should never happen");
                    if domains.iter().any(|domain| domain.matches(host, attr)) {
                        hit = true;
                        break;
                    }
                }
                if !hit {
                    return None;
                }
            } else {
                return None;
            }
        }

        if !self.ips.is_empty() {
            if let Address::SocketAddress(socket_addr) = addr {
                let ip_addr = match socket_addr {
                    SocketAddr::V4(s) => IpAddr::V4(*s.ip()),
                    SocketAddr::V6(s) => IpAddr::V6(*s.ip()),
                };
                for ip in self.ips.iter() {
                    let ips = ip_sites.get(ip).expect("should never happen");
                    if ips.iter().any(|ip_range| ip_range.contains(ip_addr)) {
                        hit = true;
                        break;
                    }
                }
                if !hit {
                    return None;
                }
            } else {
                return None;
            }
        }

        if hit {
            return Some(self.outbound_tag.clone());
        }
        None
    }
}

fn geo_ip() -> &'static GeoIpList {
    static LIST: std::sync::OnceLock<GeoIpList> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let path = PathBuf::from(std::env::var("DAT_DIR").expect("DAT_DIR"));
        let bytes = std::fs::read(path.join("geoip.dat")).expect("geoip.dat");
        GeoIpList::decode(bytes.as_ref()).expect("geo_ip_list")
    })
}

fn geo_site() -> &'static GeoSiteList {
    static LIST: std::sync::OnceLock<GeoSiteList> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let path = PathBuf::from(std::env::var("DAT_DIR").expect("DAT_DIR"));
        let bytes = std::fs::read(path.join("geosite.dat")).expect("geosite.dat");
        GeoSiteList::decode(bytes.as_ref()).expect("geo_site_list")
    })
}

#[derive(Debug)]
enum MatchType {
    Substr(String),
    Regex(Regex),
    SubDomain(String),
    FullDomain(String),
}

struct Domain {
    match_type: MatchType,
    attrs: Vec<String>,
}

// type
// 0: The value is used as is.
// 1: The value is used as a regular expression.
// 2: The value is a root domain.
// 3: The value is a domain.
impl TryFrom<ProtoDomain> for Domain {
    type Error = Error;
    fn try_from(value: ProtoDomain) -> Result<Self> {
        let match_type = match value.r#type {
            0 => MatchType::Substr(value.value),
            1 => MatchType::Regex(
                Regex::new(&value.value).map_err(|e| Error::new(ErrorKind::InvalidData, e))?,
            ),
            2 => MatchType::SubDomain(value.value),
            3 => MatchType::FullDomain(value.value),
            _ => return Err(new_io_error("Proto Domain definiation error")),
        };
        let attrs: Vec<String> = value.attribute.into_iter().map(|attr| attr.key).collect();
        Ok(Self { match_type, attrs })
    }
}

impl Domain {
    pub fn new(match_type: MatchType) -> Self {
        Self {
            match_type,
            attrs: vec![],
        }
    }

    pub fn matches(&self, addr: &String, attr: Option<&str>) -> bool {
        if let Some(attr) = attr {
            if !self.attrs.iter().any(|item| *item == *attr) {
                return false;
            }
        }
        match &self.match_type {
            MatchType::Substr(sub) => addr.contains(sub),
            MatchType::Regex(regex) => regex.is_match(addr),
            MatchType::SubDomain(sub) => {
                if *sub == *addr {
                    true
                } else {
                    addr.ends_with(&format!(".{}", sub))
                }
            }
            MatchType::FullDomain(full) => *full == *addr,
        }
    }
}

#[derive(Debug)]
struct IpRange {
    ip: IpAddr,
    prefix: u32,
}

impl TryFrom<Cidr> for IpRange {
    type Error = Error;
    fn try_from(value: Cidr) -> Result<Self> {
        let ip = if value.ip.len() == 4 {
            let ip: [u8; 4] = value.ip.try_into().map_err(|e: Vec<u8>| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Expect 4 bytes, got {}", e.len()),
                )
            })?;
            if value.prefix > 32 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Invalid prefix of {} for ipv4 address", value.prefix),
                ));
            }
            IpAddr::from(ip)
        } else if value.ip.len() == 16 {
            let ip: [u8; 16] = value.ip.try_into().map_err(|e: Vec<u8>| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Expect 16 bytes, got {}", e.len()),
                )
            })?;
            if value.prefix > 128 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Invalid prefix of {} for ipv6 address", value.prefix),
                ));
            }
            IpAddr::from(ip)
        } else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unexpected IP length {}", value.ip.len()),
            ));
        };
        Ok(Self {
            ip,
            prefix: value.prefix,
        })
    }
}

impl IpRange {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            // Thanks to https://github.com/achanda/ipnetwork/blob/0deb2abd8b28ea746e9922207f4d8c6703899783/src/ipv4.rs#L241
            IpAddr::V4(ip) => {
                if let IpAddr::V4(self_ip) = self.ip {
                    let mask = !(0xffff_ffff_u64 >> self.prefix) as u32;
                    let net = self_ip.to_bits() & mask;
                    return (ip.to_bits() & mask) == net;
                }
            }
            // Thanks to https://github.com/achanda/ipnetwork/blob/0deb2abd8b28ea746e9922207f4d8c6703899783/src/ipv6.rs#L262
            IpAddr::V6(ip) => {
                if let IpAddr::V6(self_ip) = self.ip {
                    let mask_ip = if self.prefix == 0 {
                        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)
                    } else {
                        let mask = u128::MAX << (128 - self.prefix);
                        Ipv6Addr::from_bits(mask)
                    };
                    let mask = mask_ip.to_bits();
                    let net = self_ip.to_bits() & mask;
                    return (ip.to_bits() & mask) == net;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod test {
    use super::{Router, DEFAULT_OUTBOUND_TAG};
    use crate::app::config::{RoutingConfig, RoutingRule};
    use crate::common::Address;
    use std::str::FromStr;

    #[test]
    fn test_route_domain_pick() {
        let proxy_tag = "proxy";
        let direct_tag = "direct";
        let block_tag = "block";
        let mixed_tag = "mixed";

        let mut routing_config = RoutingConfig::default();
        let mut proxy_routing_rule = RoutingRule::new(proxy_tag.to_string());
        let mut direct_routing_rule = RoutingRule::new(direct_tag.to_string());
        let mut block_routing_rule = RoutingRule::new(block_tag.to_string());
        let mut mixed_routing_rule = RoutingRule::new(mixed_tag.to_string());

        proxy_routing_rule.domain.append(
            &mut [
                "facebook.co".to_string(),
                r#"regexp:\.goo.*\.com$"#.to_string(),
                "domain:youtube.com".to_string(),
                "full:www.openai.com".to_string(),
            ]
            .to_vec(),
        );

        direct_routing_rule.domain.append(
            &mut [
                "domain:baidu.com".to_string(),
                "full:www.sina.com".to_string(),
            ]
            .to_vec(),
        );

        block_routing_rule
            .domain
            .append(&mut ["domain:ads.com".to_string()].to_vec());

        mixed_routing_rule
            .domain
            .append(&mut ["domain:wechat.com".to_string()].to_vec());
        mixed_routing_rule
            .inbound_tag
            .append(&mut ["inbound1".to_string()].to_vec());

        routing_config.rules.append(
            &mut [
                proxy_routing_rule,
                direct_routing_rule,
                block_routing_rule,
                mixed_routing_rule,
            ]
            .to_vec(),
        );

        let router = Router::new(routing_config).unwrap();

        assert_eq!(
            proxy_tag,
            router.pick(&Address::from_str("www.facebook.com:0").unwrap(), &None)
        );
        assert_eq!(
            proxy_tag,
            router.pick(&Address::from_str("www.facebook.com.cn:0").unwrap(), &None)
        );
        assert_eq!(
            proxy_tag,
            router.pick(&Address::from_str("www.google.com:0").unwrap(), &None)
        );
        assert_eq!(
            proxy_tag,
            router.pick(&Address::from_str("fonts.googleapis.com:0").unwrap(), &None)
        );
        assert_eq!(
            DEFAULT_OUTBOUND_TAG,
            router.pick(&Address::from_str("google.com:0").unwrap(), &None)
        );
        assert_eq!(
            proxy_tag,
            router.pick(&Address::from_str("video.youtube.com:0").unwrap(), &None)
        );
        assert_eq!(
            proxy_tag,
            router.pick(&Address::from_str("youtube.com:0").unwrap(), &None)
        );
        assert_eq!(
            proxy_tag,
            router.pick(&Address::from_str("www.openai.com:0").unwrap(), &None)
        );
        assert_eq!(
            DEFAULT_OUTBOUND_TAG,
            router.pick(&Address::from_str("openai.com:0").unwrap(), &None)
        );

        assert_eq!(
            direct_tag,
            router.pick(&Address::from_str("www.baidu.com:0").unwrap(), &None)
        );
        assert_eq!(
            direct_tag,
            router.pick(&Address::from_str("baidu.com:0").unwrap(), &None)
        );
        assert_eq!(
            direct_tag,
            router.pick(&Address::from_str("www.sina.com:0").unwrap(), &None)
        );
        assert_eq!(
            DEFAULT_OUTBOUND_TAG,
            router.pick(&Address::from_str("www.sina.com.cn:0").unwrap(), &None)
        );

        assert_eq!(
            block_tag,
            router.pick(&Address::from_str("www.ads.com:0").unwrap(), &None)
        );

        assert_eq!(
            mixed_tag,
            router.pick(
                &Address::from_str("www.wechat.com:0").unwrap(),
                &Some("inbound1".to_string())
            )
        );

        assert_eq!(
            DEFAULT_OUTBOUND_TAG,
            router.pick(
                &Address::from_str("www.wechat.com:0").unwrap(),
                &Some("inbound2".to_string())
            )
        );

        assert_eq!(
            DEFAULT_OUTBOUND_TAG,
            router.pick(&Address::from_str("www.wechat.com:0").unwrap(), &None,)
        );
    }

    #[test]
    fn test_route_ip_pick() {
        let proxy_tag = "proxy";
        let direct_tag = "direct";
        let block_tag = "block";

        let mut routing_config = RoutingConfig::default();
        let mut proxy_routing_rule = RoutingRule::new(proxy_tag.to_string());
        let mut direct_routing_rule = RoutingRule::new(direct_tag.to_string());
        let mut block_routing_rule = RoutingRule::new(block_tag.to_string());

        proxy_routing_rule
            .ip
            .append(&mut ["1.32.197.0/24".to_string(), "8.8.8.8".to_string()].to_vec());

        direct_routing_rule
            .ip
            .append(&mut ["5.10.143.0/24".to_string(), "114.114.114.114".to_string()].to_vec());

        block_routing_rule
            .ip
            .append(&mut ["192.168.0.0/16".to_string(), "172.0.0.100".to_string()].to_vec());

        routing_config
            .rules
            .append(&mut [proxy_routing_rule, direct_routing_rule, block_routing_rule].to_vec());

        let router = Router::new(routing_config).unwrap();

        assert_eq!(
            proxy_tag,
            router.pick(&Address::from_str("1.32.197.100:0").unwrap(), &None)
        );
        assert_eq!(
            proxy_tag,
            router.pick(&Address::from_str("8.8.8.8:0").unwrap(), &None)
        );
        assert_eq!(
            DEFAULT_OUTBOUND_TAG,
            router.pick(&Address::from_str("1.32.166.1:0").unwrap(), &None)
        );
        assert_eq!(
            direct_tag,
            router.pick(&Address::from_str("5.10.143.100:0").unwrap(), &None)
        );
        assert_eq!(
            direct_tag,
            router.pick(&Address::from_str("5.10.143.100:0").unwrap(), &None)
        );
        assert_eq!(
            direct_tag,
            router.pick(&Address::from_str("114.114.114.114:0").unwrap(), &None)
        );
        assert_eq!(
            block_tag,
            router.pick(&Address::from_str("192.168.16.16:0").unwrap(), &None)
        );
    }
}
