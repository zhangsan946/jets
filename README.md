# jets

[![Release](https://github.com/zhangsan946/jets/actions/workflows/release.yml/badge.svg)](https://github.com/zhangsan946/jets/actions/workflows/release.yml)
[![crates.io](https://img.shields.io/crates/v/jets?logo=rust)](https://crates.io/crates/jets)
[![docs.rs](https://docs.rs/jets/badge.svg)](https://docs.rs/jets)

A Rust rule-based tunnel targeting to enduser for secure & reliable network access in high speed.

## Features
This project still has many features to be implemented. Welcome anyone interested in this project to PR to accelerate.

✅ Implemented 🚧 Partial Implemented  ❌ Not yet implemented

- Inbound
	- socks(✅ socks5, ❌ socks4)
	- ✅ http
	- ✅ tun

- Outbound
	- ✅ freedom
	- ✅ blackhole
	- socks(✅ socks5)
	- vless(✅ v2fly, ✅ xtls-vision)
	- ✅ shadowsocks
	- ✅ trojan
	- ❌ vmess

- Routing
	- ✅ InboundTag, Ip, Domain
	- ❌ source, protocol, balancerTag
	- ✅ AsIs, IPIfNonMatch, IPOnDemand

- DNS
	- ✅ UDP
	- ✅ DNS over TCP
	- ❌ doh/doq/dot

- Transport
	- ✅ raw/tcp
	- ✅ tls
	- ✅ websocket
	- ❌ reality
	- ❌ http, gprc, xhttp, ...

- Other
	- ✅ Connection option, e.g. bind interface, tcp fast open, ...
	- ✅ UDP Full Cone
	- ❌ Connection retry logic
	- ❌ socks & http authentication
	- 🚧 tls config, e.g. server name, certificate, ...
	- ❌ fakedns
	- ❌ more protocols & configurations

## Getting Started
Create a Jets' configuration file named `config.json`. Detailed explanation of the configuration file could be found on the [Wiki page](https://github.com/zhangsan946/jets/wiki). Then run the following command:

```bash
jet -c config.json
```

### Use **tun** inbound on Windows

Need to copy the [wintun.dll](https://wintun.net/) file which matches the system's architecture to 
the same directory as `jets.exe` and run as administrator.

## Development
1. Install protocol compiler by downloading a pre-built binary from [Protocol Buffers releases](https://github.com/protocolbuffers/protobuf/releases).

2. [Intall Rust 1.80.0+](https://www.rust-lang.org/tools/install).

3. Check and run the example code. e.g.

	```bash
	cargo run --example full
	```

4. Build from source. Then `jets` will appear in `./target/release/` folder.

	```
	cargo build --release
	```
	PS: If you are building `jets` for your own CPU platform (for example, build and run on your PC only), it is recommended to set `target-cpu=native` feature to let `rustc` generate and optimize code for the specific CPU.
	```
	export RUSTFLAGS="-C target-cpu=native"
	```

## Limitation
1. Shadowsocks using 2022 cipher only support **32 bytes length** password
2. On Android, it cannot get system dns config which means config of `localhost` in dns servers won't work. May refer to https://github.com/hickory-dns/hickory-dns/issues/652#issuecomment-1783178552 for possbile workaround.

## Credits
1. [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
2. [v2ray-rust](https://github.com/Qv2ray/v2ray-rust)
3. [Xray-core](https://github.com/XTLS/Xray-core)
4. [leaf](https://github.com/eycorsican/leaf)
