use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["src/proxy/vless/addons.proto"], &["src/proxy/vless/"])
}
