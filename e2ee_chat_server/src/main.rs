use std::fs;
use std::path::PathBuf;

use clap::Parser;
use ratchetx2::Identity;
use ratchetx2::server::RpcServer;
use tracing::{error, info};

#[derive(Debug, Parser)]
#[clap(version, about, long_about)]
pub struct Cli {
    /// The path to cert(pem)
    #[arg(short, long)]
    pub cert: Option<PathBuf>,
    /// The path to key(pem)
    #[arg(short, long)]
    pub key: Option<PathBuf>,
    /// The E2EE chat server address.
    pub listening_on: String,
}

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::filter::EnvFilter::from_default_env()
        .add_directive("tonic=debug".parse().unwrap())
        .add_directive("e2ee_chat_server=info".parse().unwrap());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        .pretty()
        .init();
    let args = Cli::parse();

    info!("Listening on {}", args.listening_on);
    if let Err(e) = RpcServer::run(
        args.listening_on,
        match (args.cert, args.key) {
            (Some(cert), Some(key)) => {
                let cert = fs::read(cert).unwrap();
                let key = fs::read(key).unwrap();
                Some(Identity::from_pem(cert, key))
            }
            (None, None) => None,
            _ => panic!("Both cert and key or none of both should be provided."),
        },
    )
    .await
    {
        error!("{}", e);
    }
}
