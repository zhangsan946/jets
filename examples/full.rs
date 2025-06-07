use jets::app::config::{DnsServer, InboundConfig, OutboundConfig, RoutingRule};
use jets::app::env_vars::RESOURCES_DIR;
use jets::app::{App, Config};

fn main() -> std::io::Result<()> {
    // std::env::set_var("RUST_BACKTRACE", "full");

    // // export tls key material for wireshark analysis
    // std::env::set_var("SSLKEYLOGFILE", "d:\\sslkey.log");

    std::env::set_var(
        RESOURCES_DIR,
        "C:\\Users\\zhangsan946\\AppData\\Local\\Spaceship\\resources",
    );

    // let path = "C:\\Users\\zhangsan946\\AppData\\Roaming\\Spaceship\\spaceship.json";
    // let config = Config::load(path)?;
    // println!("json config: {:?}", config);

    let mut config = Config::default();
    config.log.loglevel = "jets=trace,info".to_string();
    // config.log.error = Some("error.log".to_string());
    // config.log.access = Some("access.log".to_string());

    let mut socks_inbound = InboundConfig::new_socks("127.0.0.1", 1080);
    socks_inbound.settings = jets::app::config::InboundSettings::Socks {
        auth: Default::default(),
        accounts: vec![],
        udp: true,
    };
    config.inbounds.push(socks_inbound);
    // config
    //     .inbounds
    //     .push(InboundConfig::new_http("127.0.0.1", 1090));
    // config
    //     .inbounds
    //     .push(InboundConfig::new_tun("wintun", "198.18.0.2/24", "198.18.0.1"));

    // config
    //     .outbounds
    //     .push(OutboundConfig::new_socks("127.0.0.1", 18000));
    // let mut ss_outbound = OutboundConfig::new_shadowsocks(
    //     "ss_server",
    //     1234,
    //     jets::app::config::CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
    //     "ss_pass",
    // );
    // ss_outbound.stream_settings.sockopt.interface = Some("WiFi".to_string());
    // config.outbounds.push(ss_outbound);
    // config.outbounds.push(OutboundConfig::new_trojan(
    //     "trojan_server",
    //     1234,
    //     "trojan_password",
    // ));
    // config.outbounds.push(OutboundConfig::new_vless(
    //     "vless_server",
    //     1234,
    //     "vless_uuid",
    //     jets::app::config::VlessFlow::None,
    // ));
    config.outbounds.push(OutboundConfig::new_vless(
        "vless_vision_server",
        1234,
        "vless_uuid",
        jets::app::config::VlessFlow::XtlsRprxVision,
    ));
    config
        .outbounds
        .push(OutboundConfig::new_freedom(Some("direct".to_string())));
    config
        .outbounds
        .push(OutboundConfig::new_blackhole(Some("block".to_string())));

    let mut routing_rule = RoutingRule::new("direct".to_string());
    routing_rule
        .domain
        .append(&mut ["geosite:cn".to_string()].to_vec());
    config.routing.rules.push(routing_rule);
    let mut routing_rule = RoutingRule::new("direct".to_string());
    routing_rule
        .ip
        .append(&mut ["geoip:cn".to_string(), "geoip:private".to_string()].to_vec());
    config.routing.rules.push(routing_rule);
    let mut routing_rule = RoutingRule::new("block".to_string());
    routing_rule
        .domain
        .append(&mut ["geosite:category-ads-all".to_string()].to_vec());
    config.routing.rules.push(routing_rule);
    config.routing.domain_strategy = jets::app::config::DomainStrategy::IPIfNonMatch;

    let dns_server = DnsServer::new("1.1.1.1".to_string())?;
    config.dns.servers.push(dns_server);
    let mut dns_server = DnsServer::new("114.114.114.114".to_string())?;
    dns_server.domains.push("geosite:cn".to_string());
    config.dns.servers.push(dns_server);
    let dns_server = DnsServer::new("114.114.115.115".to_string())?;
    config.dns.servers.push(dns_server);
    let dns_server = DnsServer::new("localhost".to_string())?;
    config.dns.servers.push(dns_server);

    App::run(config)
}
