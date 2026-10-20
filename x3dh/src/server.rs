//! The gRPC server combines the Message and X3DH.

use primitives::{
    error::{Result, TransportError},
    transport::RpcMessageServer,
};
use tonic::transport::{Identity, Server, ServerTlsConfig};

use crate::{RpcX3DHInner, x3dh_rpc::x3dh_service_server::X3dhServiceServer};

/// The gRPC server combines the Message and X3DH.
pub struct RpcServer {}

impl RpcServer {
    /// Run the gRPC server.
    pub async fn run(addr: impl AsRef<str>, identity: Option<Identity>) -> Result<()> {
        let addr = addr
            .as_ref()
            .parse()
            .unwrap_or_else(|_| panic!("Invalid SocketAddr"));
        let mut server = Server::builder();
        if let Some(identity) = identity {
            server = server
                .tls_config(ServerTlsConfig::new().identity(identity))
                .unwrap()
        }
        server
            .add_routes(
                RpcMessageServer::routes()
                    .add_service(X3dhServiceServer::new(RpcX3DHInner::default())),
            )
            .serve(addr)
            .await
            .map_err(|_| TransportError::Server)?;
        Ok(())
    }
}
