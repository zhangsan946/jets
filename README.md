# jets
A Rust rule-based tunnel targeting to enduser for secure & reliable network access in high speed.

## Features
This project is still in the very early development stage. Welcome anyone interested to join.

- Inbound
	- socks(✅ socks5, ❌ socks4)
	- ✅ http
	- ❌ tun

- Outbound
	- freedom
	- socks(✅ socks5)
	- vless(✅ v2fly, ✅ xtls)
	- ✅ shadowsocks
	- ❌ trojan
	- ❌ vmess

- Routing
	- ✅ InboundTag, Ip, Domain
	- ❌ source, protocpl, balancerTag
	- ✅ AsIs
	- ❌ IPIfNonMatch & IPOnDemand

- ❌ DNS

- Other
	- ❌ Connection timeout & options
	- ❌ socks & http auth
	- ❌ UDP
	- ❌ more protocols & configurations

## Development
1. Install protocol compiler by downloading a pre-built binary from [Protocol Buffers releases](https://github.com/protocolbuffers/protobuf/releases).
2. [Intall Rust 1.80.0+](https://www.rust-lang.org/tools/install).
3. Build or run the code.
	```Rust
	cargo build
	cargo run
	```

## Limitation
1. shadowsocks using 2022 cipher doesn't support password containing '-'.

## Credits
1. [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
2. [v2ray-rust](https://github.com/Qv2ray/v2ray-rust)
3. [Xray-core](https://github.com/XTLS/Xray-core)
