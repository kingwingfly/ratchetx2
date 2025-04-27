//! The gRPC server combines the Message and X3DH.

use tonic::transport::{Identity, Server, ServerTlsConfig};

use super::error::{Result, TransportError};
use crate::transport::grpc::{
    RpcMessageServerInner, message_rpc::message_service_server::MessageServiceServer,
};
use crate::x3dh::{RpcX3DHInner, x3dh_rpc::x3dh_service_server::X3dhServiceServer};

/// The gRPC server combines the Message and X3DH.
pub struct RpcServer {}

impl RpcServer {
    /// Run the gRPC server.
    pub async fn run(addr: impl AsRef<str>, identity: Option<Identity>) -> Result<()> {
        let addr = addr.as_ref().parse().unwrap();
        let mut server = Server::builder();
        if let Some(identity) = identity {
            server = server
                .tls_config(ServerTlsConfig::new().identity(identity))
                .unwrap()
        }
        server
            .add_service(X3dhServiceServer::new(RpcX3DHInner::default()))
            .add_service(MessageServiceServer::new(RpcMessageServerInner::default()))
            .serve(addr)
            .await
            .map_err(|_| TransportError::Server)?;
        Ok(())
    }
}
