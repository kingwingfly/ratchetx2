use async_trait::async_trait;
use pingora::prelude::*;
use std::env;
use tracing::info;

#[cfg(not(windows))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

struct ReverseProxy {
    upstream_addr: String,
}

#[async_trait]
impl ProxyHttp for ReverseProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = Box::new(HttpPeer::new(&self.upstream_addr, false, "".to_string()));
        Ok(peer)
    }
}

fn main() {
    let filter = tracing_subscriber::filter::EnvFilter::from_default_env()
        .add_directive("ingress=info".parse().unwrap());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        .pretty()
        .without_time()
        .init();

    // Load configuration from environment variables
    let cert_path = env::var("TLS_CERT_PATH").unwrap_or_else(|_| "cert/cert.pem".to_string());
    let key_path = env::var("TLS_KEY_PATH").unwrap_or_else(|_| "cert/key.pem".to_string());
    let upstream_addr = env::var("UPSTREAM_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:443".to_string());

    info!(
        "TLS_CERT_PATH: {}\nTLS_KEY_PATH: {}\nUPSTREAM_ADDR: {}\nBIND_ADDR: {}",
        cert_path, key_path, upstream_addr, bind_addr,
    );

    let mut my_server = Server::new(Some(Opt::parse_args())).unwrap();
    my_server.bootstrap();

    let mut reverse_proxy =
        http_proxy_service(&my_server.configuration, ReverseProxy { upstream_addr });
    reverse_proxy
        .add_tls(&bind_addr, &cert_path, &key_path)
        .unwrap();
    my_server.add_service(reverse_proxy);

    my_server.run_forever();
}
