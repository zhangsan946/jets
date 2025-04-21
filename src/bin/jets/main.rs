use clap::Parser;
use jets::app::cli::Args;
use jets::app::env_vars::RESOURCES_DIR;
use jets::app::{App, Config};
use std::env;
use std::io::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args = Args::parse();
    let cwd = env::current_dir()?;
    let config = match args.config {
        Some(config) => PathBuf::from(config),
        None => cwd.join("config.json"),
    };
    if env::var(RESOURCES_DIR).is_err() {
        env::set_var(RESOURCES_DIR, cwd.to_str().unwrap());
    }
    let config = Config::load(config)?;
    let app = App::new(config)?;
    app.run()
}
