use jets::app::config::{DnsServer, InboundConfig, OutboundConfig, RoutingRule, VlessFlow};
use jets::app::{App, Config};

fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("jets=debug,info"));
    // std::env::set_var("RUST_BACKTRACE", "full");

    // // export tls key material for wireshark analysis
    // std::env::set_var("SSLKEYLOGFILE", "d:\\sslkey.log");

    std::env::set_var(
        "DAT_DIR",
        "C:\\Users\\zhangsan946\\AppData\\Local\\Spaceship\\resources",
    );

    // let path = "C:\\Users\\zhangsan946\\AppData\\Roaming\\Spaceship\\spaceship.json";
    // let config = Config::load(path)?;
    // println!("json config: {:?}", config);

    let mut config = Config::default();
    config
        .inbounds
        .push(InboundConfig::new_socks("127.0.0.1", 1080));
    config
        .inbounds
        .push(InboundConfig::new_http("127.0.0.1", 1090));

    // config.outbounds.push(OutboundConfig::new_socks("127.0.0.1", 18000));
    // config.outbounds.push(OutboundConfig::new_shadowsocks("127.0.0.1", 1234, method, "password"));
    config.outbounds.push(OutboundConfig::new_vless(
        "server",
        1234,
        "uuid",
        VlessFlow::XtlsRprxVision,
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

    let dns_server = DnsServer::new("tcp://1.1.1.1".to_string());
    config.dns.servers.push(dns_server);
    let mut dns_server = DnsServer::new("tcp://114.114.114.114".to_string());
    dns_server.domains.push("geosite:cn".to_string());
    config.dns.servers.push(dns_server);
    let dns_server = DnsServer::new("tcp://114.114.115.115".to_string());
    config.dns.servers.push(dns_server);

    let app = App::new(config)?;
    app.run()
}
