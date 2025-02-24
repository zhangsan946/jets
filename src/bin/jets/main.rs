use jets::app::{App, Config};

fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("jets=debug,info"));
    let config = Config::default()
        .add_socks_inbound("127.0.0.1:1080", vec![])
        .add_freedom_outbound("freedom")
        .add_socks5_outbound("socks5", "127.0.0.1:18000", vec![])
        .add_shadowsocks_outbound(
            "shadowsocks",
            "127.0.0.1:18000",
            "base64pass1:base64pass2",
            "2022-blake3-aes-256-gcm",
        )
        .add_vless_outbound("default", "127.0.0.1:18000", "pass", "");

    let app = App::new(config);
    app.run()
}
