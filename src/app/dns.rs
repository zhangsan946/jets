use super::config::{DnsConfig, QueryStrategy};
use super::dat::GeoSiteList;
use super::env_vars::RESOURCES_DIR;
use super::router::{Domain, MatchType, Router};
use crate::app::proxy::Outbounds;
use crate::common::{far_future_instant, invalid_input_error, Address};
use crate::proxy::{Outbound, ProxySocket, ProxyStream};
use futures::ready;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::GenericConnector;
use hickory_resolver::proto::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::proto::runtime::{RuntimeProvider, TokioHandle, TokioTime};
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::Resolver;
use prost::Message;
use regex::Regex;
use std::cell::LazyCell;
use std::collections::HashMap;
use std::future::Future;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::ReadBuf;
use tokio::sync::RwLock;

pub struct DnsManager {
    // TODO: replace with other Cache
    cache: RwLock<HashMap<String, (Instant, IpAddr)>>,
    hosts: Vec<(Domain, Vec<IpAddr>)>,
    // Try to use these resolvers if domain matches
    servers_pior: Vec<(Domain, Arc<DnsResolver>)>,
    servers: Vec<Arc<DnsResolver>>,
}

impl DnsManager {
    pub async fn new(config: DnsConfig, outbounds: &Outbounds, router: &Router) -> Result<Self> {
        let mut cache: HashMap<String, (Instant, IpAddr)> = HashMap::new();
        let mut hosts: Vec<(Domain, Vec<IpAddr>)> = Vec::new();
        for host in config.hosts {
            let mut ips: Vec<IpAddr> = Vec::new();
            for ip in host.1 {
                let ip = ip
                    .parse()
                    .map_err(|_| invalid_input_error(format!("Invalid ip: {}", ip)))?;
                ips.push(ip);
            }
            let domains = parse_domain(host.0)?;
            for domain in domains.into_iter() {
                match domain.match_type {
                    MatchType::FullDomain(domain) => {
                        cache.insert(domain, (far_future_instant(), pick_up_ip(ips.clone())?));
                    }
                    _ => hosts.push((domain, ips.clone())),
                }
            }
        }

        let mut servers_pior: Vec<(Domain, Arc<DnsResolver>)> = Vec::new();
        let mut servers: Vec<Arc<DnsResolver>> = Vec::new();

        if config.servers.is_empty() {
            if let Ok((sys_config, sys_opts)) = read_system_conf() {
                let mut resolvers = Vec::new();
                for server in sys_config.name_servers() {
                    let mut resolver_config = ResolverConfig::from_parts(
                        sys_config.domain().cloned(),
                        sys_config.search().to_owned(),
                        NameServerConfigGroup::new(),
                    );
                    resolver_config.add_name_server(server.clone());
                    resolvers.push(
                        build_resolver(
                            false,
                            server.socket_addr,
                            &config.tag,
                            &config.local_outbound_tag,
                            outbounds,
                            router,
                            resolver_config,
                            sys_opts.clone(),
                        )
                        .await?,
                    );
                }
                resolvers
                    .into_iter()
                    .for_each(|resolver| servers.push(resolver));
            }
        }

        let mut options = ResolverOpts::default();
        options.edns0 = true;
        options.ip_strategy = LookupIpStrategy::from(config.query_strategy);

        // TODO: Support pre-defined dns config e.g. google/cloudflare/quad9 https/tls
        for server in config.servers {
            let mut resolver_config = ResolverConfig::new();

            let resolvers = if let Some(i) = server.address.find("://") {
                let prefix = server.address[..i].to_string();
                let addr = format!("{}:{}", &server.address[(i + 3)..], server.port);
                let addr = SocketAddr::from_str(&addr).map_err(|_| {
                    invalid_input_error(format!("Invalid socket address: {}", addr))
                })?;
                let routable = !prefix.contains("local");
                let protocol = if prefix == "local" {
                    Protocol::Udp
                } else if prefix.contains("tcp") {
                    Protocol::Tcp
                } else if prefix.contains("udp") {
                    Protocol::Udp
                } else {
                    todo!("support doh/doq")
                };
                let name_server = NameServerConfig::new(addr, protocol);
                resolver_config.add_name_server(name_server);
                vec![
                    build_resolver(
                        routable,
                        addr,
                        &config.tag,
                        &config.local_outbound_tag,
                        outbounds,
                        router,
                        resolver_config,
                        options.clone(),
                    )
                    .await?,
                ]
            } else if server.address == "localhost" {
                let mut output = Vec::new();
                if let Ok((sys_config, sys_opts)) = read_system_conf() {
                    for server in sys_config.name_servers() {
                        let mut resolver_config = ResolverConfig::from_parts(
                            sys_config.domain().cloned(),
                            sys_config.search().to_owned(),
                            NameServerConfigGroup::new(),
                        );
                        resolver_config.add_name_server(server.clone());
                        output.push(
                            build_resolver(
                                false,
                                server.socket_addr,
                                &config.tag,
                                &config.local_outbound_tag,
                                outbounds,
                                router,
                                resolver_config,
                                sys_opts.clone(),
                            )
                            .await?,
                        );
                    }
                }
                output
            } else {
                let addr = format!("{}:{}", server.address, server.port);
                let addr = SocketAddr::from_str(&addr).map_err(|_| {
                    invalid_input_error(format!("Invalid socket address: {}", addr))
                })?;
                let protocol = Protocol::Udp;
                let name_server = NameServerConfig::new(addr, protocol);
                resolver_config.add_name_server(name_server);
                vec![
                    build_resolver(
                        true,
                        addr,
                        &config.tag,
                        &config.local_outbound_tag,
                        outbounds,
                        router,
                        resolver_config,
                        options.clone(),
                    )
                    .await?,
                ]
            };

            if server.domains.is_empty() {
                resolvers
                    .into_iter()
                    .for_each(|resolver| servers.push(resolver));
            } else {
                for domain in server.domains {
                    let domains = parse_domain(domain)?;
                    domains.into_iter().for_each(|d: Domain| {
                        resolvers
                            .iter()
                            .for_each(|resolver| servers_pior.push((d.clone(), resolver.clone())));
                    });
                }
            }
        }
        Ok(Self {
            cache: RwLock::new(cache),
            hosts,
            servers_pior,
            servers,
        })
    }

    pub async fn resolve(&self, addr: &Address) -> Result<SocketAddr> {
        let (domain, port) = match addr {
            Address::DomainNameAddress(domain, port) => (domain, port),
            Address::SocketAddress(addr) => return Ok(*addr),
        };
        let read_lock = self.cache.read().await;
        let ip_entry = read_lock.get(domain).map(|v| v.to_owned());
        drop(read_lock);

        if let Some(v) = ip_entry {
            if v.0 < Instant::now() {
                self.cache.write().await.remove(domain);
            } else {
                let v = SocketAddr::new(v.1, *port);
                log::debug!("Hit dns cache {:?} for addr: {}:{}", v, domain, port);
                return Ok(v);
            }
        }
        for host in self.hosts.iter() {
            if host.0.matches(domain, None) {
                let ip = pick_up_ip(host.1.clone())?;
                let addr = SocketAddr::new(ip, *port);
                log::debug!(
                    "Found static dns record {:?} for addr: {}:{}",
                    addr,
                    domain,
                    port
                );
                self.cache
                    .write()
                    .await
                    .insert(domain.clone(), (far_future_instant(), ip));
                return Ok(addr);
            }
        }
        for server in self.servers_pior.iter() {
            if server.0.matches(domain, None) {
                match server.1.lookup_ip(domain).await {
                    Ok(result) => {
                        let validity: Instant = result.valid_until();
                        let ips: Vec<IpAddr> = result.into_iter().collect();
                        let ip = pick_up_ip(ips)?;
                        let addr = SocketAddr::new(ip, *port);
                        log::debug!("Got dns record {:?} for addr: {}:{}", addr, domain, port);
                        self.cache
                            .write()
                            .await
                            .insert(domain.clone(), (validity, ip));
                        return Ok(addr);
                    }
                    Err(e) => {
                        log::warn!("Failed to lookup ip for {}, error: {}", domain, e)
                    }
                }
            }
        }
        for server in self.servers.iter() {
            match server.lookup_ip(domain).await {
                Ok(result) => {
                    let validity: Instant = result.valid_until();
                    let ips: Vec<IpAddr> = result.into_iter().collect();
                    let ip = pick_up_ip(ips)?;
                    let addr = SocketAddr::new(ip, *port);
                    log::debug!("Got dns record {:?} for addr: {}:{}", addr, domain, port);
                    self.cache
                        .write()
                        .await
                        .insert(domain.clone(), (validity, ip));
                    return Ok(addr);
                }
                Err(e) => {
                    log::warn!("Failed to lookup ip for {}, error: {}", domain, e)
                }
            }
        }

        Err(Error::new(
            ErrorKind::NotFound,
            format!("Unable to resolve ip for addr: {}:{}", domain, port),
        ))
    }
}

fn pick_up_ip(ips: Vec<IpAddr>) -> Result<IpAddr> {
    // TODO:
    // Happy Eyeballs, RFC6555, RFC8305
    //
    // RFC6555 gives an example that Chrome and Firefox uses 300ms
    if ips.is_empty() {
        Err(invalid_input_error("Unable to pick up an ip address"))
    } else {
        for ip in ips {
            if ip.is_ipv4() {
                return Ok(ip);
            }
        }
        Err(invalid_input_error("Unable to pick up an ipv4 adress"))
    }
}

#[allow(clippy::too_many_arguments)]
async fn build_resolver(
    routable: bool,
    dns_server_addr: SocketAddr,
    dns_tag: &Option<String>,
    dns_outbound_tag: &Option<String>,
    outbounds: &Outbounds,
    router: &Router,
    resolver_config: ResolverConfig,
    resolver_opts: ResolverOpts,
) -> Result<Arc<Resolver<GenericConnector<DnsRuntimeProvider>>>> {
    let outbound = if routable {
        let addr = Address::SocketAddress(dns_server_addr);
        let tag = router.pick_as_is(&addr, dns_tag).await;
        outbounds.get(&tag).unwrap().clone()
    } else if let Some(tag) = dns_outbound_tag {
        outbounds
            .get(tag)
            .ok_or_else(|| {
                invalid_input_error(format!("Invalid local outbound tag of {} set for dns", tag))
            })?
            .clone()
    } else {
        outbounds.first_freedom().ok_or_else(|| {
            invalid_input_error("Freedom outbound is required for current dns config")
        })?
    };
    Ok(Arc::new(create_resolver(
        resolver_config,
        resolver_opts,
        outbound,
    )))
}

impl From<QueryStrategy> for LookupIpStrategy {
    fn from(value: QueryStrategy) -> Self {
        match value {
            QueryStrategy::UseIP => LookupIpStrategy::Ipv4AndIpv6,
            QueryStrategy::UseIPv4 => LookupIpStrategy::Ipv4Only,
            QueryStrategy::UseIPv6 => LookupIpStrategy::Ipv6Only,
        }
    }
}

fn parse_domain(mut domain: String) -> Result<Vec<Domain>> {
    let geo_site_list: LazyCell<GeoSiteList> = LazyCell::new(|| {
        let path = PathBuf::from(std::env::var(RESOURCES_DIR).expect(RESOURCES_DIR));
        let bytes = std::fs::read(path.join("geosite.dat")).expect("geosite.dat");
        GeoSiteList::decode(bytes.as_ref()).expect("geo_site_list")
    });
    let domains = if domain.starts_with("regexp:") {
        let regex = domain.split_off(7).to_lowercase();
        let regex = Regex::new(&regex)
            .map_err(|_| invalid_input_error(format!("Invalid regex value of {}", regex)))?;
        vec![Domain::new(MatchType::Regex(regex))]
    } else if domain.starts_with("domain:") {
        let domain = domain.split_off(7).to_lowercase();
        vec![Domain::new(MatchType::SubDomain(domain))]
    } else if domain.starts_with("keyword:") {
        let domain = domain.split_off(8).to_lowercase();
        vec![Domain::new(MatchType::Substr(domain))]
    } else if domain.starts_with("geosite:") {
        let code = domain.split_off(8).to_lowercase();
        match geo_site_list
            .entry
            .iter()
            .find(|item| item.country_code.to_lowercase() == code)
        {
            Some(geo_site) => {
                let mut domains = Vec::<Domain>::new();
                for item in geo_site.domain.iter() {
                    match Domain::try_from(item.to_owned()) {
                        Ok(domain) => {
                            domains.push(domain);
                        }
                        Err(e) => {
                            log::warn!(
                                "Invalid domain {} in code {}, error: {}",
                                item.value,
                                code,
                                e
                            );
                        }
                    }
                }
                domains
            }
            None => {
                return Err(invalid_input_error(format!(
                    "Geosite does not contain the code of {}",
                    code
                )))
            }
        }
    } else {
        vec![Domain::new(MatchType::FullDomain(domain))]
    };
    Ok(domains)
}

#[derive(Clone)]
struct DnsRuntimeProvider {
    handle: TokioHandle,
    outbound: Arc<Box<dyn Outbound>>,
}

impl DnsRuntimeProvider {
    pub fn new(outbound: Arc<Box<dyn Outbound>>) -> Self {
        Self {
            handle: TokioHandle::default(),
            outbound,
        }
    }
}

impl RuntimeProvider for DnsRuntimeProvider {
    type Handle = TokioHandle;
    //type Tcp = AsyncIoTokioAsStd<SyncProxyStream<Box<dyn ProxyStream>>>;
    type Tcp = AsyncIoTokioAsStd<Box<dyn ProxyStream>>;
    type Timer = TokioTime;
    type Udp = Box<dyn ProxySocket>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp>>>> {
        let wait_for = wait_for.unwrap_or_else(|| Duration::from_secs(5));
        let outbound = self.outbound.clone();

        Box::pin(async move {
            let addr = Address::SocketAddress(server_addr);
            let stream = match tokio::time::timeout(wait_for, outbound.connect_tcp(addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(err)) => return Err(err),
                Err(_) => return Err(ErrorKind::TimedOut.into()),
            };
            //let stream = SyncProxyStream::new(stream);
            Ok(AsyncIoTokioAsStd(stream))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp>>>> {
        let outbound = self.outbound.clone();
        Box::pin(async move {
            // It doesn't matter what passed as peer to outbound.bind, as:
            // 1. NAT type doesn't matter
            // 2. It is one-time back and forth communication
            // so just pass local_addr to meet the requirement
            let target = Address::SocketAddress(server_addr);
            let udp = outbound.bind(local_addr, target).await?;
            Ok(udp)
        })
    }
}

type DnsConnectionProvider = GenericConnector<DnsRuntimeProvider>;
type DnsResolver = Resolver<DnsConnectionProvider>;

fn create_resolver(
    config: ResolverConfig,
    options: ResolverOpts,
    outbound: Arc<Box<dyn Outbound>>,
) -> DnsResolver {
    let mut builder = DnsResolver::builder_with_config(
        config,
        DnsConnectionProvider::new(DnsRuntimeProvider::new(outbound)),
    );
    *builder.options_mut() = options;
    builder.build()
}

use hickory_resolver::proto::udp::DnsUdpSocket;
use std::task::{Context, Poll};
impl DnsUdpSocket for Box<dyn ProxySocket> {
    type Time = hickory_resolver::proto::runtime::TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, SocketAddr)>> {
        let mut buffer = ReadBuf::new(buf);
        let addr = ready!(ProxySocket::poll_recv_from(self.as_ref(), cx, &mut buffer))?;
        let len = buffer.filled().len();
        let socket_addr = match addr {
            Address::SocketAddress(addr) => addr,
            Address::DomainNameAddress(_, _) => unreachable!(),
        };
        Poll::Ready(Ok((len, socket_addr)))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<Result<usize>> {
        ProxySocket::poll_send_to(self.as_ref(), cx, buf, Address::SocketAddress(target))
    }
}
