//! The [Connect protocol](https://connectrpc.com/docs/protocol)'s unary calls: protobuf over
//! plain HTTP `POST`, for where gRPC cannot go, such as browsers and Cloudflare Workers.
//!
//! A call is a `POST` to its procedure's path, e.g. `/handshake.v1.HandshakeService/Publish`,
//! with `Content-Type: application/proto`, `Connect-Protocol-Version: 1` and the protobuf
//! request as the body. A success is `200 OK` with the protobuf response. An error has another
//! status and a JSON body such as `{"code":"not_found","message":"not found"}`, whose code maps
//! to an [`ErrorKind`] as gRPC's status codes do. So any Connect client can call these services,
//! and the clients here can call any Connect server of them.
//!
//! This module does no I/O: [`ConnectClient`] runs on any HTTP client that implements
//! [`LocalPost`], and [`handle`] answers a call with any [`LocalHandshake`], [`LocalMailbox`]
//! and [`LocalAttachments`], such as the servers, inside any HTTP server.

use std::fmt;

use prost::Message;

use crate::{
    attachment::{
        CancelUploadRequest, CancelUploadResponse, GetChunkRequest, GetChunkResponse,
        LocalAttachments, PutChunkRequest, PutChunkResponse, StartUploadRequest,
        StartUploadResponse,
    },
    error::{Error, ErrorKind, Result},
    handshake::{
        FetchBundleRequest, FetchBundleResponse, LocalHandshake, PublishRequest, PublishResponse,
        SendInitialMessageRequest, SendInitialMessageResponse, TakeInitialMessagesRequest,
        TakeInitialMessagesResponse,
    },
    mailbox::{FetchRequest, FetchResponse, LocalMailbox, PushRequest, PushResponse},
};

/// The content type of requests and successful responses: binary protobuf.
pub const CONTENT_TYPE: &str = "application/proto";
/// The content type of error responses.
pub const ERROR_CONTENT_TYPE: &str = "application/json";
/// The header naming the protocol's version, which clients send.
pub const PROTOCOL_VERSION_HEADER: &str = "connect-protocol-version";
/// The protocol's version.
pub const PROTOCOL_VERSION: &str = "1";

/// A procedure: a method of the handshake, mailbox or attachment service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Procedure {
    /// [`LocalHandshake::publish`].
    Publish,
    /// [`LocalHandshake::fetch_bundle`].
    FetchBundle,
    /// [`LocalHandshake::send_initial_message`].
    SendInitialMessage,
    /// [`LocalHandshake::take_initial_messages`].
    TakeInitialMessages,
    /// [`LocalMailbox::push`].
    Push,
    /// [`LocalMailbox::fetch`].
    Fetch,
    /// [`LocalAttachments::start_upload`].
    StartUpload,
    /// [`LocalAttachments::put_chunk`].
    PutChunk,
    /// [`LocalAttachments::get_chunk`].
    GetChunk,
    /// [`LocalAttachments::cancel_upload`].
    CancelUpload,
}

impl Procedure {
    /// Every procedure.
    pub const ALL: [Self; 10] = [
        Self::Publish,
        Self::FetchBundle,
        Self::SendInitialMessage,
        Self::TakeInitialMessages,
        Self::Push,
        Self::Fetch,
        Self::StartUpload,
        Self::PutChunk,
        Self::GetChunk,
        Self::CancelUpload,
    ];

    /// The path of its calls: `/` ‖ the service's full name ‖ `/` ‖ the method's name.
    pub fn path(self) -> &'static str {
        match self {
            Self::Publish => "/handshake.v1.HandshakeService/Publish",
            Self::FetchBundle => "/handshake.v1.HandshakeService/FetchBundle",
            Self::SendInitialMessage => "/handshake.v1.HandshakeService/SendInitialMessage",
            Self::TakeInitialMessages => "/handshake.v1.HandshakeService/TakeInitialMessages",
            Self::Push => "/mailbox.v1.MailboxService/Push",
            Self::Fetch => "/mailbox.v1.MailboxService/Fetch",
            Self::StartUpload => "/attachment.v1.AttachmentService/StartUpload",
            Self::PutChunk => "/attachment.v1.AttachmentService/PutChunk",
            Self::GetChunk => "/attachment.v1.AttachmentService/GetChunk",
            Self::CancelUpload => "/attachment.v1.AttachmentService/CancelUpload",
        }
    }

    /// The procedure whose calls go to `path`, if any.
    pub fn from_path(path: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|procedure| procedure.path() == path)
    }
}

/// The HTTP response to a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The `Content-Type`.
    pub content_type: &'static str,
    /// The body.
    pub body: Vec<u8>,
}

/// Answer a call to `procedure`, whose request has `content_type` and `body`, with `handshake`,
/// `mailbox` and `attachments`.
///
/// Routing and the method are up to the HTTP server: find the procedure with
/// [`Procedure::from_path`], and only take `POST`. A body of another content type is answered
/// with `415 Unsupported Media Type`.
pub async fn handle(
    handshake: &impl LocalHandshake,
    mailbox: &impl LocalMailbox,
    attachments: &impl LocalAttachments,
    procedure: Procedure,
    content_type: Option<&str>,
    body: &[u8],
) -> Response {
    let essence = content_type.and_then(|content_type| content_type.split(';').next());
    if !essence.is_some_and(|essence| essence.trim().eq_ignore_ascii_case(CONTENT_TYPE)) {
        return Response {
            status: 415,
            content_type: ERROR_CONTENT_TYPE,
            body: error_body(Code::InvalidArgument, "unsupported content type"),
        };
    }
    let reply = match procedure {
        Procedure::Publish => reply(decode(body).map(|r| handshake.publish(r))).await,
        Procedure::FetchBundle => reply(decode(body).map(|r| handshake.fetch_bundle(r))).await,
        Procedure::SendInitialMessage => {
            reply(decode(body).map(|r| handshake.send_initial_message(r))).await
        }
        Procedure::TakeInitialMessages => {
            reply(decode(body).map(|r| handshake.take_initial_messages(r))).await
        }
        Procedure::Push => reply(decode(body).map(|r| mailbox.push(r))).await,
        Procedure::Fetch => reply(decode(body).map(|r| mailbox.fetch(r))).await,
        Procedure::StartUpload => reply(decode(body).map(|r| attachments.start_upload(r))).await,
        Procedure::PutChunk => reply(decode(body).map(|r| attachments.put_chunk(r))).await,
        Procedure::GetChunk => reply(decode(body).map(|r| attachments.get_chunk(r))).await,
        Procedure::CancelUpload => reply(decode(body).map(|r| attachments.cancel_upload(r))).await,
    };
    match reply {
        Ok(body) => Response {
            status: 200,
            content_type: CONTENT_TYPE,
            body,
        },
        Err(error) => self::error(error.kind(), &error.to_string()),
    }
}

/// The response to a call that fails with `kind` before [`handle`] could answer it, e.g. as its
/// body is too large to read.
pub fn error(kind: ErrorKind, message: &str) -> Response {
    let code = Code::from(kind);
    Response {
        status: code.status(),
        content_type: ERROR_CONTENT_TYPE,
        body: error_body(code, message),
    }
}

/// A request's body, decoded.
fn decode<T: Message + Default>(body: &[u8]) -> Result<T> {
    T::decode(body).map_err(|e| Error::new(ErrorKind::Malformed, e))
}

/// The response to a decoded request, encoded.
async fn reply<T: Message>(response: Result<impl Future<Output = Result<T>>>) -> Result<Vec<u8>> {
    Ok(response?.await?.encode_to_vec())
}

/// The JSON body of an error response.
fn error_body(code: Code, message: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "code": code.name(), "message": message }))
        .expect("strings serialize to JSON")
}

/// Posts calls: the HTTP client a [`ConnectClient`] runs on.
#[trait_variant::make(Post: Send)]
pub trait LocalPost {
    /// `POST` `body` to `path`, appended to the server's address, with the headers
    /// `Content-Type: application/proto` and `Connect-Protocol-Version: 1`. Returns the
    /// response's status and body.
    ///
    /// Fail with [`ErrorKind::Connect`] if the server cannot be reached.
    async fn post(&self, path: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)>;
}

/// A handshake, mailbox and attachment client over Connect, on the HTTP client `P`.
///
/// Its futures are not `Send`, which suits single-threaded runtimes, such as the browser's.
#[derive(Debug, Clone)]
pub struct ConnectClient<P>(P);

impl<P> ConnectClient<P> {
    /// A client posting with `post`.
    pub fn new(post: P) -> Self {
        Self(post)
    }
}

impl<P: LocalPost> ConnectClient<P> {
    /// Call `procedure` with `request`.
    async fn call<T: Message + Default>(
        &self,
        procedure: Procedure,
        request: impl Message,
    ) -> Result<T> {
        let (status, body) = self
            .0
            .post(procedure.path(), request.encode_to_vec())
            .await?;
        if status == 200 {
            return T::decode(body.as_slice()).map_err(|e| Error::new(ErrorKind::Malformed, e));
        }
        let error = match serde_json::from_slice::<CallError>(&body) {
            Ok(error) => error,
            // Without a valid error body, the status tells the code. A sign-in is asked for only
            // by the server's own error, as a 403 without one comes from something in front of
            // it, e.g. a firewall's rule, which signing in does not get past.
            Err(_) => {
                let code = match Code::from_status(status) {
                    Code::PermissionDenied => Code::Unknown,
                    code => code,
                };
                CallError {
                    code: code.name().to_string(),
                    message: format!("HTTP status {status}"),
                }
            }
        };
        let kind = Code::from_name(&error.code).map_or(ErrorKind::Server, ErrorKind::from);
        Err(Error::new(kind, error))
    }
}

impl<P: LocalPost> LocalHandshake for ConnectClient<P> {
    async fn publish(&self, request: PublishRequest) -> Result<PublishResponse> {
        self.call(Procedure::Publish, request).await
    }

    async fn fetch_bundle(&self, request: FetchBundleRequest) -> Result<FetchBundleResponse> {
        self.call(Procedure::FetchBundle, request).await
    }

    async fn send_initial_message(
        &self,
        request: SendInitialMessageRequest,
    ) -> Result<SendInitialMessageResponse> {
        self.call(Procedure::SendInitialMessage, request).await
    }

    async fn take_initial_messages(
        &self,
        request: TakeInitialMessagesRequest,
    ) -> Result<TakeInitialMessagesResponse> {
        self.call(Procedure::TakeInitialMessages, request).await
    }
}

impl<P: LocalPost> LocalMailbox for ConnectClient<P> {
    async fn push(&self, request: PushRequest) -> Result<PushResponse> {
        self.call(Procedure::Push, request).await
    }

    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse> {
        self.call(Procedure::Fetch, request).await
    }
}

impl<P: LocalPost> LocalAttachments for ConnectClient<P> {
    async fn start_upload(&self, request: StartUploadRequest) -> Result<StartUploadResponse> {
        self.call(Procedure::StartUpload, request).await
    }

    async fn put_chunk(&self, request: PutChunkRequest) -> Result<PutChunkResponse> {
        self.call(Procedure::PutChunk, request).await
    }

    async fn get_chunk(&self, request: GetChunkRequest) -> Result<GetChunkResponse> {
        self.call(Procedure::GetChunk, request).await
    }

    async fn cancel_upload(&self, request: CancelUploadRequest) -> Result<CancelUploadResponse> {
        self.call(Procedure::CancelUpload, request).await
    }
}

/// The error a server answered a call with.
#[derive(Debug, serde::Deserialize)]
struct CallError {
    code: String,
    #[serde(default)]
    message: String,
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CallError {}

/// The Connect error codes that the servers answer with or that clients infer from a status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Code {
    InvalidArgument,
    Unauthenticated,
    FailedPrecondition,
    NotFound,
    ResourceExhausted,
    Unavailable,
    Internal,
    PermissionDenied,
    Unimplemented,
    Unknown,
}

impl Code {
    const ALL: [Self; 10] = [
        Self::InvalidArgument,
        Self::Unauthenticated,
        Self::FailedPrecondition,
        Self::NotFound,
        Self::ResourceExhausted,
        Self::Unavailable,
        Self::Internal,
        Self::PermissionDenied,
        Self::Unimplemented,
        Self::Unknown,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::Unauthenticated => "unauthenticated",
            Self::FailedPrecondition => "failed_precondition",
            Self::NotFound => "not_found",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
            Self::PermissionDenied => "permission_denied",
            Self::Unimplemented => "unimplemented",
            Self::Unknown => "unknown",
        }
    }

    /// The code named `name`, if it is one of these. Other codes, such as `aborted`, are
    /// [`ErrorKind::Server`] errors to the clients.
    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.name() == name)
    }

    /// The HTTP status of an error response with this code.
    fn status(self) -> u16 {
        match self {
            Self::InvalidArgument | Self::FailedPrecondition => 400,
            Self::Unauthenticated => 401,
            Self::PermissionDenied => 403,
            Self::NotFound => 404,
            Self::ResourceExhausted => 429,
            Self::Unimplemented => 501,
            Self::Unavailable => 503,
            Self::Internal | Self::Unknown => 500,
        }
    }

    /// The code a client infers from the status of a response without a valid error body.
    fn from_status(status: u16) -> Self {
        match status {
            400 => Self::Internal,
            401 => Self::Unauthenticated,
            403 => Self::PermissionDenied,
            404 => Self::Unimplemented,
            429 | 502 | 503 | 504 => Self::Unavailable,
            _ => Self::Unknown,
        }
    }
}

impl From<ErrorKind> for Code {
    /// The code a server answers an error with; clients map it back.
    fn from(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::Malformed => Self::InvalidArgument,
            ErrorKind::InvalidSignature => Self::Unauthenticated,
            ErrorKind::StaleTimestamp => Self::FailedPrecondition,
            ErrorKind::NotFound => Self::NotFound,
            ErrorKind::LimitExceeded => Self::ResourceExhausted,
            ErrorKind::SignInRequired => Self::PermissionDenied,
            ErrorKind::Storage => Self::Unavailable,
            _ => Self::Internal,
        }
    }
}

impl From<Code> for ErrorKind {
    fn from(code: Code) -> Self {
        match code {
            Code::InvalidArgument => Self::Malformed,
            Code::Unauthenticated => Self::InvalidSignature,
            Code::FailedPrecondition => Self::StaleTimestamp,
            Code::NotFound => Self::NotFound,
            Code::ResourceExhausted => Self::LimitExceeded,
            Code::PermissionDenied => Self::SignInRequired,
            _ => Self::Server,
        }
    }
}

#[cfg(all(test, feature = "server"))]
mod test {
    use bytes::Bytes;
    use party::EncryptedMessage;
    use storage::MemoryStore;

    use super::*;
    use crate::{attachment::AttachmentServer, handshake::HandshakeServer, mailbox::MailboxServer};

    /// Posts to the servers in-process, through `handle`.
    struct InProcess {
        handshake: HandshakeServer<MemoryStore>,
        mailbox: MailboxServer<MemoryStore>,
        attachments: AttachmentServer<MemoryStore>,
    }

    impl LocalPost for InProcess {
        async fn post(&self, path: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
            let Some(procedure) = Procedure::from_path(path) else {
                return Ok((404, b"no such page".to_vec()));
            };
            let response = handle(
                &self.handshake,
                &self.mailbox,
                &self.attachments,
                procedure,
                Some(CONTENT_TYPE),
                &body,
            )
            .await;
            Ok((response.status, response.body))
        }
    }

    #[tokio::test]
    async fn over_connect() {
        let client = ConnectClient::new(InProcess {
            handshake: HandshakeServer::new(MemoryStore::default()),
            mailbox: MailboxServer::new(MemoryStore::default()),
            attachments: AttachmentServer::new(MemoryStore::default()),
        });

        // Error kinds survive the trip through Connect's error codes.
        let request = FetchBundleRequest {
            identity_key: Bytes::from_static(&[1; 32]),
        };
        let error = client.fetch_bundle(request).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        let request = FetchBundleRequest {
            identity_key: Bytes::from_static(&[1; 31]),
        };
        let error = client.fetch_bundle(request).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Malformed);

        let message = EncryptedMessage {
            header: Bytes::from_static(b"header"),
            content: Bytes::from_static(b"content"),
        };
        let request = PushRequest {
            sender: Bytes::from_static(&[1; 32]),
            recipient: Bytes::from_static(&[2; 32]),
            message: Some(message.clone()),
            initial_message: None,
            delivery_hash: Bytes::new(),
        };
        assert_eq!(client.push(request).await.unwrap().sequence, 1);
        let request = FetchRequest {
            sender: Bytes::from_static(&[1; 32]),
            recipient: Bytes::from_static(&[2; 32]),
            after: 0,
            limit: 0,
            delivered: vec![],
        };
        let messages = client.fetch(request).await.unwrap().messages;
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message, Some(message));
    }

    /// Answers every call with `status` and `body`, as something in front of a server may.
    struct Answering(u16, &'static [u8]);

    impl LocalPost for Answering {
        async fn post(&self, _path: &str, _body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
            Ok((self.0, self.1.to_vec()))
        }
    }

    #[tokio::test]
    async fn only_the_servers_own_refusal_asks_to_sign_in() {
        let request = || PushRequest::default();
        let refused = br#"{"code":"permission_denied","message":"sign in"}"#;
        for (status, body, kind) in [
            (403, &refused[..], ErrorKind::SignInRequired),
            // A firewall's page, or none.
            (403, b"<html>blocked</html>", ErrorKind::Server),
            (403, b"", ErrorKind::Server),
            (429, b"", ErrorKind::Server),
        ] {
            let client = ConnectClient::new(Answering(status, body));
            assert_eq!(client.push(request()).await.unwrap_err().kind(), kind);
        }
    }

    #[tokio::test]
    async fn rejects_other_content_types() {
        let (handshake, mailbox, attachments) = (
            HandshakeServer::new(MemoryStore::default()),
            MailboxServer::new(MemoryStore::default()),
            AttachmentServer::new(MemoryStore::default()),
        );
        let response = handle(
            &handshake,
            &mailbox,
            &attachments,
            Procedure::Fetch,
            Some("application/json"),
            b"{}",
        )
        .await;
        assert_eq!(response.status, 415);
        let response = handle(
            &handshake,
            &mailbox,
            &attachments,
            Procedure::Fetch,
            Some("Application/Proto; charset=binary"),
            &[],
        )
        .await;
        assert_eq!(response.status, 400);
    }

    /// The paths are those of the services in the `.proto` files, which Connect clients in other
    /// languages are generated from.
    #[test]
    fn paths_follow_the_services() {
        let files = protox::compile(
            [
                "proto/attachment.proto",
                "proto/handshake.proto",
                "proto/mailbox.proto",
            ],
            ["proto", "../party/proto"],
        )
        .unwrap();
        let mut services: Vec<_> = files
            .file
            .iter()
            .flat_map(|file| {
                file.service.iter().flat_map(move |service| {
                    service.method.iter().map(move |method| {
                        format!("/{}.{}/{}", file.package(), service.name(), method.name())
                    })
                })
            })
            .collect();
        let mut paths = Procedure::ALL.map(|procedure| procedure.path().to_string());
        services.sort();
        paths.sort();
        assert_eq!(services, paths);
    }
}
