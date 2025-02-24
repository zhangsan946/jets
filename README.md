# jets
A Rust rule-based tunnel targeting to enduser for secure & reliable network access.

## Features
This project is still in an very early development stage. Welcome anyone with interest.

- Inbound
	- socks(✅ socks5, ❌ socks4)
	- ❌ http
	- ❌ tun

- Outbound
	- freedom
	- socks(✅ socks5)
	- vless(✅ v2fly, ✅ xtls)
	- ✅ shadowsocks
	- ❌ trojan
	- ❌ vmess

- ❌ DNS & Router

- Other
	- ❌ Connection timeout & options
	- ❌ socks auth
	- ❌ UDP
	- ❌ more protocols & configurations

## Development
1. Install protocol compiler by downloading a pre-built binary from [Protocol Buffers releases](https://github.com/protocolbuffers/protobuf/releases)
2. [Intall Rust](https://www.rust-lang.org/tools/install)
3. Build the code or run the sample code:
	```Rust
	cargo build
	cargo run
	```

## Limitation
1. shadowsocks doesn't support password with '-'

## Credits
1. [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
2. [v2ray-rust](https://github.com/Qv2ray/v2ray-rust)
3. [Xray-core](https://github.com/XTLS/Xray-core)
