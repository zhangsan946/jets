use clap::Parser;
use jets::app::cli::Args;
use jets::app::env_vars::RESOURCES_DIR;
use jets::app::{App, Config};
use std::env;
use std::io::Result;

fn main() -> Result<()> {
    // mainly used for the github workflow
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 && args[1] == "-v" {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let cwd = env::current_dir()?;
    if env::var(RESOURCES_DIR).is_err() {
        env::set_var(RESOURCES_DIR, cwd.to_str().unwrap());
    }
    let args = Args::parse();
    let config = Config::load(args.get_config()?)?;
    let app = App::new(config)?;
    app.run()
}
