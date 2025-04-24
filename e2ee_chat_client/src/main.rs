use clap::Parser;

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
        .run(args.server_addr)
        .await
        .unwrap();
}
