use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Specify the config file in json format. By default, it will look for "config.json" in the current working directory.
    #[arg(short, long)]
    pub config: Option<String>,
}
