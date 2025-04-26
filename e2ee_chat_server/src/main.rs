use std::env;
use std::fs;

use ratchetx2::server::RpcServer;
use tracing::info;

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::filter::EnvFilter::from_default_env()
        .add_directive("e2ee_chat_ingress=info".parse().unwrap());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        .pretty()
        .without_time()
        .init();

    let upstream_addr = env::var("UPSTREAM_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let cert_path = env::var("TLS_CERT_PATH").unwrap_or_else(|_| "cert/cert.pem".to_string());
    let key_path = env::var("TLS_KEY_PATH").unwrap_or_else(|_| "cert/key.pem".to_string());

    info!("Listening on {}", upstream_addr);
    RpcServer::run(
        upstream_addr,
        fs::read_to_string(cert_path).unwrap(),
        fs::read_to_string(key_path).unwrap(),
    )
    .await
    .unwrap();
}
