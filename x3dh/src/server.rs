//! The gRPC server combines the Message and X3DH.

use primitives::transport::RpcMessageServer;
use tonic::transport::{Identity, Server, ServerTlsConfig};

use crate::{
    RpcX3DHInner,
    error::{Error, ErrorKind, Result},
    x3dh_rpc::x3dh_service_server::X3dhServiceServer,
};

/// The gRPC server combines the Message and X3DH.
pub struct RpcServer {}

impl RpcServer {
    /// Run the gRPC server.
    pub async fn run(addr: impl AsRef<str>, identity: Option<Identity>) -> Result<()> {
        let addr = addr
            .as_ref()
            .parse()
            .map_err(|e| Error::new(ErrorKind::InvalidAddress, e))?;
        let mut server = Server::builder();
        if let Some(identity) = identity {
            server = server
                .tls_config(ServerTlsConfig::new().identity(identity))
                .map_err(|e| Error::new(ErrorKind::Server, e))?;
        }
        server
            .add_routes(
                RpcMessageServer::routes()
                    .add_service(X3dhServiceServer::new(RpcX3DHInner::default())),
            )
            .serve(addr)
            .await
            .map_err(|e| Error::new(ErrorKind::Server, e))?;
        Ok(())
    }
}
