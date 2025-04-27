use std::fs;

use clap::Parser;
use ratchetx2::Certificate;

mod cli;
mod client;
pub mod message;
mod navi;
pub mod screen;
mod widget;

#[tokio::main]
async fn main() {
    let args = cli::Cli::parse();
    client::Client::new()
        .unwrap()
        .run(
            args.server_addr,
            args.ca.map(|p| Certificate::from_pem(fs::read(p).unwrap())),
        )
        .await
        .unwrap();
}
