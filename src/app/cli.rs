use clap::Parser;
use std::env;
use std::io::Result;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(about, long_about = None, version)]
pub struct Args {
    /// Specify the config file in json format. By default, it will look for "config.json" in the current working directory.
    #[arg(short, long)]
    config: Option<String>,
}

impl Args {
    pub fn get_config(&self) -> Result<PathBuf> {
        let cwd = env::current_dir()?;
        let config = match &self.config {
            Some(config) => PathBuf::from(config),
            None => cwd.join("config.json"),
        };
        Ok(config)
    }
}
