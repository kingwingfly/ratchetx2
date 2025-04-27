//! Transport implementation with gRPC (by [tonic](https://crates.io/crates/tonic)).

/// Tonic generated gRPC module.
pub(crate) mod message_rpc {
    tonic::include_proto!("message");
}

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use message_rpc::message_service_client::MessageServiceClient;
use message_rpc::message_service_server::{MessageService, MessageServiceServer};
use message_rpc::{
    FetchMessagesRequest, FetchMessagesResponse, PushMessageRequest, PushMessageResponse,
};
use tonic::transport::Server;
use tonic::transport::{Channel, ClientTlsConfig};
use tonic::{Request, Response, Result as RpcResult};

use super::Transport;
use crate::error::{Result, TransportError};

/// Message transport gRPC client.
pub struct RpcTransport {
    rpc_client: MessageServiceClient<Channel>,
    last_sync_id: Arc<AtomicU64>,
    push_target: Vec<u8>,
    fetch_target: Vec<u8>,
}

impl RpcTransport {
    /// Connect to a message gRPC server.
    pub async fn connect(
        msg_server_addr: impl AsRef<str>,
        my_identity_key: &[u8],
        peer_identity_key: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            rpc_client: MessageServiceClient::new(
                Channel::builder(msg_server_addr.as_ref().try_into().unwrap())
                    .tls_config(ClientTlsConfig::new().with_native_roots())
                    .map_err(|_| TransportError::Connect)?
                    .connect()
                    .await
                    .map_err(|_| TransportError::Connect)?,
            ),
            last_sync_id: Arc::new(AtomicU64::default()),
            push_target: [my_identity_key, peer_identity_key].concat().to_vec(),
            fetch_target: [peer_identity_key, my_identity_key].concat().to_vec(),
        })
    }
}

#[allow(clippy::manual_async_fn)]
impl Transport for RpcTransport {
    fn push_bytes(&mut self, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + Send + 'static {
        let req = PushMessageRequest {
            target: self.push_target.clone(),
            enc_message: bytes,
        };
        let mut client = self.rpc_client.clone();
        async move {
            let _resp = client
                .push_message(req)
                .await
                .map_err(|_| TransportError::Push)?;
            Ok(())
        }
    }

    fn fetch_bytes(
        &mut self,
        limit: Option<usize>,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>>> + Send + 'static {
        let req = FetchMessagesRequest {
            target: self.fetch_target.clone(),
            last_sync_id: self.last_sync_id.load(Ordering::Relaxed),
            limit: limit.map(|limit| limit as u64),
        };
        let mut client = self.rpc_client.clone();
        let last_sync_id = self.last_sync_id.clone();
        async move {
            let resp = client
                .fetch_messages(req)
                .await
                .map_err(|_| TransportError::Fetch)?;
            last_sync_id.fetch_add(resp.get_ref().enc_messages.len() as u64, Ordering::Relaxed);
            Ok(resp.into_inner().enc_messages)
        }
    }
}

/// The gRPC server to store and distribute encrypted messages.
///
/// Using Vec as a data structure to store encrypted messages.
pub struct RpcMessageServer {}

impl RpcMessageServer {
    /// Run a RpcMessageServer listening on addr.
    pub async fn run(addr: impl AsRef<str>) -> Result<()> {
        let addr = addr.as_ref().parse().unwrap();
        Server::builder()
            .add_service(MessageServiceServer::new(RpcMessageServerInner::default()))
            .serve(addr)
            .await
            .map_err(|_| TransportError::Server)?;
        Ok(())
    }
}

#[allow(clippy::type_complexity)]
#[derive(Debug, Default)]
pub(crate) struct RpcMessageServerInner {
    db: RwLock<HashMap<Vec<u8>, Arc<RwLock<Vec<Vec<u8>>>>>>,
}

#[tonic::async_trait]
impl MessageService for RpcMessageServerInner {
    async fn push_message(
        &self,
        request: Request<PushMessageRequest>,
    ) -> RpcResult<Response<PushMessageResponse>> {
        let req = request.into_inner();
        let q = self.db.write().entry(req.target).or_default().clone();
        q.write().push(req.enc_message);
        Ok(Response::new(PushMessageResponse {}))
    }

    async fn fetch_messages(
        &self,
        request: Request<FetchMessagesRequest>,
    ) -> RpcResult<Response<FetchMessagesResponse>> {
        let req = request.into_inner();
        let q = self.db.write().entry(req.target).or_default().clone();
        let q = q.read();
        let enc_messages = q
            .get(
                req.last_sync_id as usize
                    ..req
                        .limit
                        .map(|limit| ((req.last_sync_id + limit) as usize).max(q.len()))
                        .unwrap_or(q.len()),
            )
            .map(|x| x.to_vec())
            .unwrap_or_default();
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
            RpcMessageServer::run("[::1]:3000").await.unwrap();
        });
        // wait server start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut alice = RpcTransport::connect("http://[::1]:3000", b"Alice", b"Bob")
            .await
            .unwrap();
        let mut bob = RpcTransport::connect("http://[::1]:3000", b"Bob", b"Alice")
            .await
            .unwrap();
        let msg = EncryptedMessage {
            enc_header: vec![1, 2, 3],
            enc_content: vec![4, 5, 6],
        };
        alice.push(msg.clone()).await.unwrap();
        assert_eq!(bob.fetch(None).await.unwrap()[0], msg);
        alice.push(msg.clone()).await.unwrap();
        assert_eq!(bob.fetch(None).await.unwrap()[0], msg);
        let msg = EncryptedMessage {
            enc_header: vec![4, 5, 6],
            enc_content: vec![1, 2, 3],
        };
        alice.push(msg.clone()).await.unwrap();
        assert_eq!(bob.fetch(None).await.unwrap()[0], msg);
    }
}
