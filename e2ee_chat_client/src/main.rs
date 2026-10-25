use clap::Parser;

mod cli;
mod client;
pub mod message;
mod navi;
mod save;
pub mod screen;
mod transport;
mod widget;

#[tokio::main]
async fn main() {
    let args = cli::Cli::parse();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("no other TLS provider is installed");
    client::Client::new()
        .unwrap()
        .run(args.server_addr, args.downloads)
        .await
        .unwrap();
}
