use clap::Parser;
use ratchetx2::server::RpcServer;
use tracing::info;

#[derive(Debug, Parser)]
#[clap(version, about, long_about)]
pub struct Cli {
    /// The E2EE chat server address.
    #[arg(default_value = "127.0.0.1:8080")]
    pub listening_on: String,
}

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::filter::EnvFilter::from_default_env()
        .add_directive("e2ee_chat_server=info".parse().unwrap());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        .pretty()
        .init();
    let args = Cli::parse();

    info!("Listening on {}", args.listening_on);
    RpcServer::run(args.listening_on).await.unwrap();
}
