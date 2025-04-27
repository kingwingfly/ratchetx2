use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[clap(version, about, long_about)]
pub struct Cli {
    /// The path to self-sign CA pem (only for https and test).
    #[arg(short, long)]
    pub ca: Option<PathBuf>,
    /// The E2EE chat server address.
    pub server_addr: String,
}
