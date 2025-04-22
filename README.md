# jets

[![Release](https://github.com/zhangsan946/jets/actions/workflows/release.yml/badge.svg)](https://github.com/zhangsan946/jets/actions/workflows/release.yml)
[![crates.io](https://img.shields.io/crates/v/jets?logo=rust)](https://crates.io/crates/jets)
[![docs.rs](https://docs.rs/jets/badge.svg)](https://docs.rs/jets)

A Rust rule-based tunnel targeting to enduser for secure & reliable network access in high speed.

## Features
This project is still in the very early development stage. Welcome anyone interested to join.

✅ Implemented 🚧 Under construction ❌ Not yet implemented

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
	- ❌ source, protocol, balancerTag
	- ✅ AsIs, ❌ IPIfNonMatch & IPOnDemand

- DNS
	- ✅ UDP
	- ✅ DNS over TCP
	- ❌ doh/doq/dot

- Transport
	- ✅ raw
	- ✅ tls ❌ config, e.g. server name, certificate, ...
	- ❌ reality
	- ❌ http, websocket, gprc

- Other
	- ❌ Connection option, e.g. bind interface, tcp fast open, ...
	- ❌ socks & http authentication
	- ✅ UDP Full Cone
	- ❌ fakedns
	- ❌ more protocols & configurations

## Development
1. Install protocol compiler by downloading a pre-built binary from [Protocol Buffers releases](https://github.com/protocolbuffers/protobuf/releases).
2. [Intall Rust 1.80.0+](https://www.rust-lang.org/tools/install).
3. Run the example code.
	```Rust
	cargo run --example full
	```

## Limitation
1. shadowsocks using 2022 cipher doesn't support password containing '-'.

## Credits
1. [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
2. [v2ray-rust](https://github.com/Qv2ray/v2ray-rust)
3. [Xray-core](https://github.com/XTLS/Xray-core)
4. [leaf](https://github.com/eycorsican/leaf)
