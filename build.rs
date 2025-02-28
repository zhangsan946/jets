use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(
        &["src/app/dat.proto", "src/proxy/vless/addons.proto"],
        &["src/app/", "src/proxy/vless/"],
    )
}
