use jets::app::config::{DnsServer, InboundConfig, InboundSettings, OutboundConfig, RoutingRule};
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
    //config.log.error = Some("d:\\error.log".to_string());
    config.log.loglevel = "jets=debug,info".to_string();

    let mut socks_inbound = InboundConfig::new_socks("127.0.0.1", 1080);
    socks_inbound.settings = InboundSettings::Socks {
        auth: Default::default(),
        accounts: vec![],
        udp: true,
    };
    config.inbounds.push(socks_inbound);
    config
        .inbounds
        .push(InboundConfig::new_http("127.0.0.1", 1090));
    // config
    //     .inbounds
    //     .push(InboundConfig::new_tun("wintun", Some("198.18.0.1/24")));

    // config
    //     .outbounds
    //     .push(OutboundConfig::new_socks("127.0.0.1", 18000));
    // config.outbounds.push(OutboundConfig::new_shadowsocks(
    //     "ss_server",
    //     1234,
    //     jets::app::config::CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
    //     "ss_pass",
    // ));
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

    let dns_server = DnsServer::new("1.1.1.1".to_string());
    config.dns.servers.push(dns_server);
    let mut dns_server = DnsServer::new("114.114.114.114".to_string());
    dns_server.domains.push("geosite:cn".to_string());
    config.dns.servers.push(dns_server);
    let dns_server = DnsServer::new("114.114.115.115".to_string());
    config.dns.servers.push(dns_server);

    let app = App::new(config)?;
    app.run()
}
