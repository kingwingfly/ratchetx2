//! gRPC (tonic) clients, and with the `server` feature, services for the servers.

pub use tonic::transport::{Certificate, Channel, Identity, Uri};
use tonic::{Code, Response, Status, transport::ClientTlsConfig};

use crate::{
    error::{Error, ErrorKind, Result},
    handshake::{
        self, FetchBundleRequest, FetchBundleResponse, IntroduceRequest, IntroduceResponse,
        PublishRequest, PublishResponse, TakeIntroductionsRequest, TakeIntroductionsResponse,
        handshake_service_client::HandshakeServiceClient,
    },
    mailbox::{
        self, FetchRequest, FetchResponse, PushRequest, PushResponse,
        mailbox_service_client::MailboxServiceClient,
    },
};

/// Connect to a server. With an `https` address, its certificate is checked against the native
/// roots and `ca`, if given.
pub async fn connect(address: impl TryInto<Uri>, ca: Option<Certificate>) -> Result<Channel> {
    let uri: Uri = address.try_into().map_err(|_| ErrorKind::InvalidAddress)?;
    let mut endpoint = Channel::builder(uri.clone());
    if uri.scheme_str() == Some("https") {
        let mut config = ClientTlsConfig::new().with_native_roots();
        if let Some(ca) = ca {
            config = config.ca_certificate(ca);
        }
        endpoint = endpoint
            .tls_config(config)
            .map_err(|e| Error::new(ErrorKind::Connect, e))?;
    }
    endpoint
        .connect()
        .await
        .map_err(|e| Error::new(ErrorKind::Connect, e))
}

/// A handshake client over gRPC.
#[derive(Debug, Clone)]
pub struct GrpcHandshake(HandshakeServiceClient<Channel>);

impl GrpcHandshake {
    /// A client over `channel`, see [`connect`].
    pub fn new(channel: Channel) -> Self {
        Self(HandshakeServiceClient::new(channel))
    }
}

impl handshake::Handshake for GrpcHandshake {
    async fn publish(&self, request: PublishRequest) -> Result<PublishResponse> {
        response(self.0.clone().publish(request).await)
    }

    async fn fetch_bundle(&self, request: FetchBundleRequest) -> Result<FetchBundleResponse> {
        response(self.0.clone().fetch_bundle(request).await)
    }

    async fn introduce(&self, request: IntroduceRequest) -> Result<IntroduceResponse> {
        response(self.0.clone().introduce(request).await)
    }

    async fn take_introductions(
        &self,
        request: TakeIntroductionsRequest,
    ) -> Result<TakeIntroductionsResponse> {
        response(self.0.clone().take_introductions(request).await)
    }
}

/// A mailbox client over gRPC.
#[derive(Debug, Clone)]
pub struct GrpcMailbox(MailboxServiceClient<Channel>);

impl GrpcMailbox {
    /// A client over `channel`, see [`connect`].
    pub fn new(channel: Channel) -> Self {
        Self(MailboxServiceClient::new(channel))
    }
}

impl mailbox::Mailbox for GrpcMailbox {
    async fn push(&self, request: PushRequest) -> Result<PushResponse> {
        response(self.0.clone().push(request).await)
    }

    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse> {
        response(self.0.clone().fetch(request).await)
    }
}

fn response<T>(result: core::result::Result<Response<T>, Status>) -> Result<T> {
    result.map(Response::into_inner).map_err(|status| {
        let kind = match status.code() {
            Code::InvalidArgument => ErrorKind::Malformed,
            Code::Unauthenticated => ErrorKind::InvalidSignature,
            Code::FailedPrecondition => ErrorKind::StaleTimestamp,
            Code::NotFound => ErrorKind::NotFound,
            Code::ResourceExhausted => ErrorKind::LimitExceeded,
            _ => ErrorKind::Server,
        };
        Error::new(kind, status)
    })
}

#[cfg(feature = "server")]
pub use server::serve;
#[cfg(feature = "server")]
pub use tonic::transport::server::TcpIncoming;

#[cfg(feature = "server")]
mod server {
    use storage::{HandshakeStore, MailboxStore};
    use tonic::{
        Request, Response, Status,
        transport::{Server, ServerTlsConfig, server::TcpIncoming},
    };

    use super::*;
    use crate::{
        handshake::{HandshakeServer, LocalHandshake as _, handshake_service_server},
        mailbox::{LocalMailbox as _, MailboxServer, mailbox_service_server},
    };

    /// Serve the handshake and mailbox servers over gRPC on `incoming`, e.g.
    /// `TcpIncoming::bind(address)?`, with TLS if `identity` is given.
    pub async fn serve<H, M>(
        incoming: TcpIncoming,
        identity: Option<Identity>,
        handshake: HandshakeServer<H>,
        mailbox: MailboxServer<M>,
    ) -> Result<()>
    where
        H: HandshakeStore + Sync + 'static,
        M: MailboxStore + Sync + 'static,
    {
        let mut server = Server::builder();
        if let Some(identity) = identity {
            server = server
                .tls_config(ServerTlsConfig::new().identity(identity))
                .map_err(|e| Error::new(ErrorKind::Server, e))?;
        }
        server
            .add_service(handshake_service_server::HandshakeServiceServer::new(
                HandshakeService(handshake),
            ))
            .add_service(mailbox_service_server::MailboxServiceServer::new(
                MailboxService(mailbox),
            ))
            .serve_with_incoming(incoming)
            .await
            .map_err(|e| Error::new(ErrorKind::Server, e))
    }

    struct HandshakeService<S>(HandshakeServer<S>);

    #[tonic::async_trait]
    impl<S: HandshakeStore + Sync + 'static> handshake_service_server::HandshakeService
        for HandshakeService<S>
    {
        async fn publish(
            &self,
            request: Request<PublishRequest>,
        ) -> core::result::Result<Response<PublishResponse>, Status> {
            reply(self.0.publish(request.into_inner()).await)
        }

        async fn fetch_bundle(
            &self,
            request: Request<FetchBundleRequest>,
        ) -> core::result::Result<Response<FetchBundleResponse>, Status> {
            reply(self.0.fetch_bundle(request.into_inner()).await)
        }

        async fn introduce(
            &self,
            request: Request<IntroduceRequest>,
        ) -> core::result::Result<Response<IntroduceResponse>, Status> {
            reply(self.0.introduce(request.into_inner()).await)
        }

        async fn take_introductions(
            &self,
            request: Request<TakeIntroductionsRequest>,
        ) -> core::result::Result<Response<TakeIntroductionsResponse>, Status> {
            reply(self.0.take_introductions(request.into_inner()).await)
        }
    }

    struct MailboxService<S>(MailboxServer<S>);

    #[tonic::async_trait]
    impl<S: MailboxStore + Sync + 'static> mailbox_service_server::MailboxService
        for MailboxService<S>
    {
        async fn push(
            &self,
            request: Request<PushRequest>,
        ) -> core::result::Result<Response<PushResponse>, Status> {
            reply(self.0.push(request.into_inner()).await)
        }

        async fn fetch(
            &self,
            request: Request<FetchRequest>,
        ) -> core::result::Result<Response<FetchResponse>, Status> {
            reply(self.0.fetch(request.into_inner()).await)
        }
    }

    /// The gRPC reply; error kinds become the status codes the clients map back.
    fn reply<T>(result: Result<T>) -> core::result::Result<Response<T>, Status> {
        result.map(Response::new).map_err(|error| {
            let message = error.to_string();
            match error.kind() {
                ErrorKind::Malformed => Status::invalid_argument(message),
                ErrorKind::InvalidSignature => Status::unauthenticated(message),
                ErrorKind::StaleTimestamp => Status::failed_precondition(message),
                ErrorKind::NotFound => Status::not_found(message),
                ErrorKind::LimitExceeded => Status::resource_exhausted(message),
                ErrorKind::Storage => Status::unavailable(message),
                _ => Status::internal(message),
            }
        })
    }

    #[cfg(test)]
    mod test {
        use bytes::Bytes;
        use party::EncryptedMessage;
        use storage::MemoryStore;

        use super::*;

        #[tokio::test]
        async fn over_grpc() {
            // Bound before serving, so connecting needs no waiting, on a port the OS picks.
            let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let address = incoming.local_addr().unwrap();
            tokio::spawn(serve(
                incoming,
                None,
                HandshakeServer::new(MemoryStore::default()),
                MailboxServer::new(MemoryStore::default()),
            ));
            let channel = connect(format!("http://{address}"), None).await.unwrap();
            let (handshake, mailbox) = (
                GrpcHandshake::new(channel.clone()),
                GrpcMailbox::new(channel),
            );

            // Error kinds survive the trip through gRPC status codes.
            let request = FetchBundleRequest {
                identity_key: Bytes::from_static(&[1; 32]),
            };
            let error = handshake.fetch_bundle(request).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::NotFound);
            let request = FetchBundleRequest {
                identity_key: Bytes::from_static(&[1; 31]),
            };
            let error = handshake.fetch_bundle(request).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Malformed);

            let message = EncryptedMessage {
                header: Bytes::from_static(b"header"),
                content: Bytes::from_static(b"content"),
            };
            let request = PushRequest {
                sender: Bytes::from_static(&[1; 32]),
                recipient: Bytes::from_static(&[2; 32]),
                message: Some(message.clone()),
            };
            assert_eq!(mailbox.push(request).await.unwrap().sequence, 1);
            let request = FetchRequest {
                sender: Bytes::from_static(&[1; 32]),
                recipient: Bytes::from_static(&[2; 32]),
                after: 0,
                limit: 0,
            };
            let messages = mailbox.fetch(request).await.unwrap().messages;
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].message, Some(message));

            let error = connect("not an address", None).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidAddress);
        }
    }
}
