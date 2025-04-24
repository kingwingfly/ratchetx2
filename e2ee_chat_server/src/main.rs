use clap::Parser;
use ratchetx2::server::RpcServer;

#[derive(Debug, Parser)]
#[clap(version, about, long_about)]
pub struct Cli {
    /// The E2EE chat server address.
    #[arg(default_value = "127.0.0.1:8080")]
    pub listening_on: String,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    println!("Listening on {}", args.listening_on);
    RpcServer::run(args.listening_on).await.unwrap();
}
