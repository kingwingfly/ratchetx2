use clap::Parser;

#[derive(Debug, Parser)]
#[clap(version, about, long_about)]
pub struct Cli {
    /// The E2EE chat server address.
    #[arg(short, long)]
    pub server_addr: String,
}
