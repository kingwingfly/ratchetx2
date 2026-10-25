use clap::Parser;

#[derive(Debug, Parser)]
#[clap(version, about, long_about)]
pub struct Cli {
    /// The E2EE chat server's address, e.g. the Worker's: https://e2ee-chat.example.workers.dev
    pub server_addr: String,
    /// Where saved files go.
    #[arg(long, default_value = ".")]
    pub downloads: std::path::PathBuf,
}
