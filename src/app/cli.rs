use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Explicitly specify the config file with json format. If not set, it will look for `config.json` in the current working directory.
    #[arg(short, long)]
    pub config: Option<String>,
}
