use std::{fs, path::PathBuf};

use clap::Parser;
use protocol::{
    grpc::{Identity, TcpIncoming, serve},
    handshake::HandshakeServer,
    mailbox::MailboxServer,
};
use storage::MemoryStore;
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
    /// The address to listen on, e.g. 0.0.0.0:443.
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

    let address = match args.listening_on.parse() {
        Ok(address) => address,
        Err(e) => {
            error!("Invalid address {}: {}", args.listening_on, e);
            return;
        }
    };
    let incoming = match TcpIncoming::bind(address) {
        Ok(incoming) => incoming,
        Err(e) => {
            error!("Cannot listen on {}: {}", address, e);
            return;
        }
    };
    info!("Listening on {}", address);
    if let Err(e) = serve(
        incoming,
        match (args.cert, args.key) {
            (Some(cert), Some(key)) => {
                let cert = fs::read(cert).unwrap();
                let key = fs::read(key).unwrap();
                Some(Identity::from_pem(cert, key))
            }
            (None, None) => None,
            _ => panic!("Both cert and key or none of both should be provided."),
        },
        HandshakeServer::new(MemoryStore::default()),
        MailboxServer::new(MemoryStore::default()),
    )
    .await
    {
        error!("{:?}", e);
    }
}
