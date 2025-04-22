//! Transport implementation with gRPC (by [tonic](https://crates.io/crates/tonic)).

/// Tonic generated gRPC module.
mod chat {
    tonic::include_proto!("chat");
}

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chat::chat_service_client::ChatServiceClient;
use chat::chat_service_server::{ChatService, ChatServiceServer};
use chat::{FetchMessagesRequest, FetchMessagesResponse, PushMessageRequest, PushMessageResponse};
use tonic::transport::Channel;
use tonic::transport::Server;
use tonic::{Request, Response, Result as RpcResult};

use super::Transport;
use super::error::{Result, TransportError};

/// Transport implementation with gRPC (by [tonic](https://crates.io/crates/tonic)).
pub struct RpcTransport {
    rpc_client: ChatServiceClient<Channel>,
    last_sync_timestamp: Arc<AtomicU64>,
}

impl RpcTransport {
    /// Connect to a gRPC server.
    pub async fn new(dst: impl AsRef<str>) -> Self {
        Self {
            rpc_client: ChatServiceClient::connect(dst.as_ref().to_owned())
                .await
                .unwrap(),
            last_sync_timestamp: Arc::new(AtomicU64::default()),
        }
    }
}

#[allow(clippy::manual_async_fn)]
impl Transport for RpcTransport {
    fn push_bytes(&mut self, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + Send + 'static {
        let req = PushMessageRequest { enc_message: bytes };
        let mut client = self.rpc_client.clone();
        async move {
            let _resp = client
                .push_message(req)
                .await
                .map_err(|_| TransportError::Push)?;
            Ok(())
        }
    }

    fn fetch_bytes(&mut self) -> impl Future<Output = Result<Vec<Vec<u8>>>> + Send + 'static {
        let req = FetchMessagesRequest {
            last_sync_timestamp: self.last_sync_timestamp.load(Ordering::Relaxed),
        };
        let mut client = self.rpc_client.clone();
        let last_sync_timestamp = self.last_sync_timestamp.clone();
        async move {
            let resp = client
                .fetch_messages(req)
                .await
                .map_err(|_| TransportError::Fetch)?;
            last_sync_timestamp.store(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                Ordering::Relaxed,
            );
            Ok(resp.into_inner().enc_messages)
        }
    }
}

/// The gRPC server to store and distribute encrypted messages.
///
/// Using BTreeMap as a data structure to store encrypted messages.
pub struct RpcServer {}

impl RpcServer {
    /// Run a RpcServer listening on addr.
    pub async fn run(addr: impl AsRef<str>) -> Result<()> {
        let addr = addr.as_ref().parse().unwrap();
        Server::builder()
            .add_service(ChatServiceServer::new(RpcServerInner::default()))
            .serve(addr)
            .await
            .map_err(|_| TransportError::Server)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct RpcServerInner {
    db: std::sync::RwLock<std::collections::BTreeMap<u64, Vec<u8>>>,
}

#[tonic::async_trait]
impl ChatService for RpcServerInner {
    async fn push_message(
        &self,
        request: Request<PushMessageRequest>,
    ) -> RpcResult<Response<PushMessageResponse>> {
        let enc_msg = request.into_inner().enc_message;
        self.db.write().unwrap().insert(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            enc_msg,
        );
        Ok(Response::new(PushMessageResponse {}))
    }

    async fn fetch_messages(
        &self,
        request: Request<FetchMessagesRequest>,
    ) -> RpcResult<Response<FetchMessagesResponse>> {
        let last_sync_timestamp = request.into_inner().last_sync_timestamp;
        let enc_messages = self
            .db
            .read()
            .unwrap()
            .range(last_sync_timestamp..)
            .map(|(_, v)| v.clone())
            .collect::<Vec<_>>();
        Ok(Response::new(FetchMessagesResponse { enc_messages }))
    }
}

#[cfg(test)]
mod test {
    use crate::transport::EncryptedMessage;

    use super::*;

    #[tokio::test]
    async fn grpc_transport() {
        tokio::spawn(async {
            RpcServer::run("[::1]:3000").await.unwrap();
        });
        // wait server start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut alice = RpcTransport::new("http://[::1]:3000").await;
        let mut bob = RpcTransport::new("http://[::1]:3000").await;
        let msg = EncryptedMessage {
            enc_header: vec![1, 2, 3],
            enc_content: vec![4, 5, 6],
        };
        alice.push(msg.clone()).await.unwrap();
        assert_eq!(bob.fetch().await.unwrap()[0], msg);
        let msg = EncryptedMessage {
            enc_header: vec![4, 5, 6],
            enc_content: vec![1, 2, 3],
        };
        alice.push(msg.clone()).await.unwrap();
        assert_eq!(bob.fetch().await.unwrap()[0], msg);
    }
}
