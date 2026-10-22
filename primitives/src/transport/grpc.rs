//! Transport implementation with gRPC (by [tonic](https://crates.io/crates/tonic)).

/// Tonic generated gRPC module.
pub(crate) mod message_rpc {
    tonic::include_proto!("message");
}

use std::{collections::HashMap, sync::Arc};

use message_rpc::{
    FetchMessagesRequest, FetchMessagesResponse, PushMessageRequest, PushMessageResponse,
};
use message_rpc::{
    message_service_client::MessageServiceClient,
    message_service_server::{MessageService, MessageServiceServer},
};
use parking_lot::RwLock;
use tonic::{
    Request, Response, Result as RpcResult,
    service::Routes,
    transport::{Certificate, Channel, ClientTlsConfig, Identity, Server, ServerTlsConfig, Uri},
};

use super::Transport;
use crate::error::{Error, ErrorKind, Result};

/// Message transport gRPC client.
pub struct RpcTransport {
    rpc_client: MessageServiceClient<Channel>,
    last_sync_id: u64,
    push_target: Vec<u8>,
    fetch_target: Vec<u8>,
}

impl RpcTransport {
    /// Connect to a message gRPC server.
    pub async fn connect(
        msg_server_addr: impl TryInto<Uri>,
        my_identity_key: &[u8],
        peer_identity_key: &[u8],
        ca: Option<Certificate>,
    ) -> Result<Self> {
        let uri: Uri = msg_server_addr
            .try_into()
            .map_err(|_| ErrorKind::InvalidAddress)?;
        let mut endpoint = Channel::builder(uri.clone());
        if uri.scheme_str() == Some("https") {
            endpoint = endpoint
                .tls_config({
                    let mut config = ClientTlsConfig::new().with_native_roots();
                    if let Some(ca) = ca {
                        config = config.ca_certificate(ca);
                    }
                    config
                })
                .map_err(|e| Error::new(ErrorKind::Connect, e))?;
        }
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| Error::new(ErrorKind::Connect, e))?;
        let rpc_client = MessageServiceClient::new(channel);
        Ok(Self {
            rpc_client,
            last_sync_id: 0,
            push_target: [my_identity_key, peer_identity_key].concat().to_vec(),
            fetch_target: [peer_identity_key, my_identity_key].concat().to_vec(),
        })
    }
}

impl Transport for RpcTransport {
    async fn push_bytes(&mut self, bytes: Vec<u8>) -> Result<()> {
        let req = PushMessageRequest {
            target: self.push_target.clone(),
            enc_message: bytes,
        };
        let _resp = self
            .rpc_client
            .push_message(req)
            .await
            .map_err(|status| Error::new(ErrorKind::Push, status))?;
        Ok(())
    }

    async fn fetch_bytes(&mut self, limit: Option<usize>) -> Result<Vec<Vec<u8>>> {
        let req = FetchMessagesRequest {
            target: self.fetch_target.clone(),
            last_sync_id: self.last_sync_id,
            limit: limit.map(|limit| limit as u64),
        };
        let resp = self
            .rpc_client
            .fetch_messages(req)
            .await
            .map_err(|status| Error::new(ErrorKind::Fetch, status))?;
        self.last_sync_id += resp.get_ref().enc_messages.len() as u64;
        Ok(resp.into_inner().enc_messages)
    }
}

/// The gRPC server to store and distribute encrypted messages.
///
/// Using Vec as a data structure to store encrypted messages.
pub struct RpcMessageServer {}

impl RpcMessageServer {
    /// Run a RpcMessageServer listening on addr.
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
            .add_routes(Self::routes())
            .serve(addr)
            .await
            .map_err(|e| Error::new(ErrorKind::Server, e))?;
        Ok(())
    }

    /// The message service as tonic [`Routes`], to serve it together with other services.
    pub fn routes() -> Routes {
        Routes::new(MessageServiceServer::new(RpcMessageServerInner::default()))
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
        // Both numbers come from the client: clamp them to the queue instead of trusting them.
        let start = usize::try_from(req.last_sync_id)
            .unwrap_or(usize::MAX)
            .min(q.len());
        let end = req.limit.map_or(q.len(), |limit| {
            start
                .saturating_add(usize::try_from(limit).unwrap_or(usize::MAX))
                .min(q.len())
        });
        let enc_messages = q[start..end].to_vec();
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
            RpcMessageServer::run("[::1]:3000", None).await.unwrap();
        });
        // wait server start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut alice = RpcTransport::connect("http://[::1]:3000", b"Alice", b"Bob", None)
            .await
            .unwrap();
        let mut bob = RpcTransport::connect("http://[::1]:3000", b"Bob", b"Alice", None)
            .await
            .unwrap();
        let msg = EncryptedMessage {
            enc_header: vec![1, 2, 3],
            enc_content: vec![4, 5, 6],
        };
        alice.push(msg.clone()).await.unwrap();
        assert_eq!(bob.fetch(None).await.unwrap().remove(0).unwrap(), msg);
        alice.push(msg.clone()).await.unwrap();
        assert_eq!(bob.fetch(None).await.unwrap().remove(0).unwrap(), msg);
        let msg = EncryptedMessage {
            enc_header: vec![4, 5, 6],
            enc_content: vec![1, 2, 3],
        };
        alice.push(msg.clone()).await.unwrap();
        assert_eq!(bob.fetch(None).await.unwrap().remove(0).unwrap(), msg);
    }

    #[tokio::test]
    async fn fetch_respects_limit() {
        tokio::spawn(async {
            RpcMessageServer::run("[::1]:3010", None).await.unwrap();
        });
        // wait server start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut alice = RpcTransport::connect("http://[::1]:3010", b"Alice", b"Bob", None)
            .await
            .unwrap();
        let mut bob = RpcTransport::connect("http://[::1]:3010", b"Bob", b"Alice", None)
            .await
            .unwrap();
        for i in 0..3 {
            alice.push_bytes(vec![i]).await.unwrap();
        }
        assert_eq!(bob.fetch_bytes(Some(1)).await.unwrap(), vec![vec![0]]);
        assert_eq!(
            bob.fetch_bytes(Some(5)).await.unwrap(),
            vec![vec![1], vec![2]]
        );
        assert!(bob.fetch_bytes(None).await.unwrap().is_empty());
    }
}
