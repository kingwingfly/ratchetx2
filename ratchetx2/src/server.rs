//! The gRPC server combines the Message and X3DH.

use tonic::transport::Server;

use super::error::{Result, TransportError};
use crate::init::{RpcX3DHInner, x3dh::x3dh_service_server::X3dhServiceServer};
use crate::transport::grpc::{RpcMessageServerInner, chat::chat_service_server::ChatServiceServer};

/// The gRPC server combines the Message and X3DH.
pub struct RpcServer {}

impl RpcServer {
    /// Run the gRPC server.
    pub async fn run(addr: impl AsRef<str>) -> Result<()> {
        let addr = addr.as_ref().parse().unwrap();
        Server::builder()
            .add_service(X3dhServiceServer::new(RpcX3DHInner::default()))
            .add_service(ChatServiceServer::new(RpcMessageServerInner::default()))
            .serve(addr)
            .await
            .map_err(|_| TransportError::Server)?;
        Ok(())
    }
}
