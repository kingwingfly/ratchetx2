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
//! [`LocalPost`], [`handle_attachments`] answers attachment calls with [`LocalAttachments`], and
//! (with the `pq` feature) `handle_v2` answers `handshake.v2` and `mailbox.v2` calls.
//! [`is_legacy_v1_path`] identifies legacy `/handshake.v1.*` and `/mailbox.v1.*` routes so servers
//! can reject them cleanly without instantiating deprecated v1 servers.

use std::fmt;

use prost::Message;

use crate::{
    attachment::{
        DeleteAttachmentRequest, DeleteAttachmentResponse, GetChunkRequest, GetChunkResponse,
        LocalAttachments, PutChunkRequest, PutChunkResponse, StartUploadRequest,
        StartUploadResponse,
    },
    error::{Error, ErrorKind, Result},
    handshake::{
        FetchBundleRequest, FetchBundleResponse, PublishRequest, PublishResponse,
        SendInitialMessageRequest, SendInitialMessageResponse, TakeInitialMessagesRequest,
        TakeInitialMessagesResponse,
    },
    mailbox::{FetchRequest, FetchResponse, PushRequest, PushResponse},
};
#[allow(deprecated)]
use crate::{handshake::LocalHandshake, mailbox::LocalMailbox};
#[cfg(feature = "pq")]
use crate::{
    handshake_v2::{
        AckInitialMessagesRequest, AckInitialMessagesResponse, ClaimBundleRequest,
        ClaimBundleResponse, GetManifestRequest, GetManifestResponse, GetServerInfoRequest,
        GetServerInfoResponse, ListInitialMessagesRequest, ListInitialMessagesResponse,
        LocalHandshakeV2, PublishV2Request, PublishV2Response, RefillPrekeysRequest,
        RefillPrekeysResponse, SendInitialV2Request, SendInitialV2Response,
    },
    mailbox_v2::{
        FetchSignedRequest, FetchSignedResponse, LocalMailboxV2, PushV2Request, PushV2Response,
    },
};

/// The content type of requests and successful responses: binary protobuf.
pub const CONTENT_TYPE: &str = "application/proto";
/// The content type of error responses.
pub const ERROR_CONTENT_TYPE: &str = "application/json";
/// The header naming the protocol's version, which clients send.
pub const PROTOCOL_VERSION_HEADER: &str = "connect-protocol-version";
/// The protocol's version.
pub const PROTOCOL_VERSION: &str = "1";

/// A procedure of the attachment service (`/attachment.v1.AttachmentService/*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttachmentProcedure {
    /// [`LocalAttachments::start_upload`].
    StartUpload,
    /// [`LocalAttachments::put_chunk`].
    PutChunk,
    /// [`LocalAttachments::get_chunk`].
    GetChunk,
    /// [`LocalAttachments::delete_attachment`].
    DeleteAttachment,
}

impl AttachmentProcedure {
    /// Every attachment procedure.
    pub const ALL: [Self; 4] = [
        Self::StartUpload,
        Self::PutChunk,
        Self::GetChunk,
        Self::DeleteAttachment,
    ];

    /// The path of its calls: `/` ‖ the service's full name ‖ `/` ‖ the method's name.
    pub fn path(self) -> &'static str {
        match self {
            Self::StartUpload => "/attachment.v1.AttachmentService/StartUpload",
            Self::PutChunk => "/attachment.v1.AttachmentService/PutChunk",
            Self::GetChunk => "/attachment.v1.AttachmentService/GetChunk",
            Self::DeleteAttachment => "/attachment.v1.AttachmentService/DeleteAttachment",
        }
    }

    /// The attachment procedure whose calls go to `path`, if any.
    pub fn from_path(path: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|procedure| procedure.path() == path)
    }
}

/// Returns `true` if `path` targets a legacy v1 handshake or mailbox Connect route
/// (`/handshake.v1.*` or `/mailbox.v1.*`).
///
/// Servers can use this to return an upgrade-required / unimplemented error without importing
/// deprecated v1 handshake or mailbox servers. Attachment routes (`/attachment.v1.*`) return
/// `false`.
pub fn is_legacy_v1_path(path: &str) -> bool {
    path.starts_with("/handshake.v1.") || path.starts_with("/mailbox.v1.")
}

/// A combined legacy v1 + attachment procedure: a method of the legacy handshake, legacy mailbox,
/// or attachment service.
///
/// New servers should route [`AttachmentProcedure`] with [`handle_attachments`] and (with the `pq`
/// feature) `ProcedureV2` with `handle_v2`, using [`is_legacy_v1_path`] to reject legacy v1 paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Procedure {
    /// Legacy v1 [`LocalHandshake::publish`].
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use handshake.v2, mailbox.v2, and audience-bound SubscribeRequest v2 (see git tag archive/legacy-v1)"
    )]
    Publish,
    /// Legacy v1 [`LocalHandshake::fetch_bundle`].
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use handshake.v2, mailbox.v2, and audience-bound SubscribeRequest v2 (see git tag archive/legacy-v1)"
    )]
    FetchBundle,
    /// Legacy v1 [`LocalHandshake::send_initial_message`].
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use handshake.v2, mailbox.v2, and audience-bound SubscribeRequest v2 (see git tag archive/legacy-v1)"
    )]
    SendInitialMessage,
    /// Legacy v1 [`LocalHandshake::take_initial_messages`].
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use handshake.v2, mailbox.v2, and audience-bound SubscribeRequest v2 (see git tag archive/legacy-v1)"
    )]
    TakeInitialMessages,
    /// Legacy v1 [`LocalMailbox::push`].
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use handshake.v2, mailbox.v2, and audience-bound SubscribeRequest v2 (see git tag archive/legacy-v1)"
    )]
    Push,
    /// Legacy v1 [`LocalMailbox::fetch`].
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use handshake.v2, mailbox.v2, and audience-bound SubscribeRequest v2 (see git tag archive/legacy-v1)"
    )]
    Fetch,
    /// [`LocalAttachments::start_upload`].
    StartUpload,
    /// [`LocalAttachments::put_chunk`].
    PutChunk,
    /// [`LocalAttachments::get_chunk`].
    GetChunk,
    /// [`LocalAttachments::delete_attachment`].
    DeleteAttachment,
}

#[allow(deprecated)]
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
        Self::DeleteAttachment,
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
            Self::DeleteAttachment => "/attachment.v1.AttachmentService/DeleteAttachment",
        }
    }

    /// The procedure whose calls go to `path`, if any.
    pub fn from_path(path: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|procedure| procedure.path() == path)
    }
}

/// A v2 procedure: a method of `handshake.v2.HandshakeService` or `mailbox.v2.MailboxService`.
#[cfg(feature = "pq")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcedureV2 {
    /// [`LocalHandshakeV2::get_server_info`].
    GetServerInfo,
    /// [`LocalHandshakeV2::publish_v2`].
    PublishV2,
    /// [`LocalHandshakeV2::refill_prekeys`].
    RefillPrekeys,
    /// [`LocalHandshakeV2::get_manifest`].
    GetManifest,
    /// [`LocalHandshakeV2::claim_bundle`].
    ClaimBundle,
    /// [`LocalHandshakeV2::send_initial_v2`].
    SendInitialV2,
    /// [`LocalHandshakeV2::list_initial_messages`].
    ListInitialMessages,
    /// [`LocalHandshakeV2::ack_initial_messages`].
    AckInitialMessages,
    /// [`LocalMailboxV2::push_v2`].
    PushV2,
    /// [`LocalMailboxV2::fetch_signed`].
    FetchSigned,
}

#[cfg(feature = "pq")]
impl ProcedureV2 {
    /// Every v2 procedure.
    pub const ALL: [Self; 10] = [
        Self::GetServerInfo,
        Self::PublishV2,
        Self::RefillPrekeys,
        Self::GetManifest,
        Self::ClaimBundle,
        Self::SendInitialV2,
        Self::ListInitialMessages,
        Self::AckInitialMessages,
        Self::PushV2,
        Self::FetchSigned,
    ];

    /// The path of its calls: `/` ‖ the service's full name ‖ `/` ‖ the method's name.
    pub fn path(self) -> &'static str {
        match self {
            Self::GetServerInfo => "/handshake.v2.HandshakeService/GetServerInfo",
            Self::PublishV2 => "/handshake.v2.HandshakeService/PublishV2",
            Self::RefillPrekeys => "/handshake.v2.HandshakeService/RefillPrekeys",
            Self::GetManifest => "/handshake.v2.HandshakeService/GetManifest",
            Self::ClaimBundle => "/handshake.v2.HandshakeService/ClaimBundle",
            Self::SendInitialV2 => "/handshake.v2.HandshakeService/SendInitialV2",
            Self::ListInitialMessages => "/handshake.v2.HandshakeService/ListInitialMessages",
            Self::AckInitialMessages => "/handshake.v2.HandshakeService/AckInitialMessages",
            Self::PushV2 => "/mailbox.v2.MailboxService/PushV2",
            Self::FetchSigned => "/mailbox.v2.MailboxService/FetchSigned",
        }
    }

    /// The v2 procedure whose calls go to `path`, if any.
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

fn check_content_type(content_type: Option<&str>) -> Option<Response> {
    let essence = content_type.and_then(|content_type| content_type.split(';').next());
    if !essence.is_some_and(|essence| essence.trim().eq_ignore_ascii_case(CONTENT_TYPE)) {
        return Some(Response {
            status: 415,
            content_type: ERROR_CONTENT_TYPE,
            body: error_body(Code::InvalidArgument, "unsupported content type"),
        });
    }
    None
}

fn finish_reply(reply: Result<Vec<u8>>) -> Response {
    match reply {
        Ok(body) => Response {
            status: 200,
            content_type: CONTENT_TYPE,
            body,
        },
        Err(error) => self::error(error.kind(), &error.to_string()),
    }
}

/// Answer a call to an attachment `procedure`, whose request has `content_type` and `body`, with
/// `attachments` (`/attachment.v1.AttachmentService/*` only, without requiring legacy v1 handshake
/// or mailbox servers).
///
/// Routing and the method are up to the HTTP server: find the procedure with
/// [`AttachmentProcedure::from_path`], and only take `POST`. A body of another content type is
/// answered with `415 Unsupported Media Type`.
pub async fn handle_attachments(
    attachments: &impl LocalAttachments,
    procedure: AttachmentProcedure,
    content_type: Option<&str>,
    body: &[u8],
) -> Response {
    if let Some(response) = check_content_type(content_type) {
        return response;
    }
    let reply = match procedure {
        AttachmentProcedure::StartUpload => {
            reply(decode(body).map(|r| attachments.start_upload(r))).await
        }
        AttachmentProcedure::PutChunk => {
            reply(decode(body).map(|r| attachments.put_chunk(r))).await
        }
        AttachmentProcedure::GetChunk => {
            reply(decode(body).map(|r| attachments.get_chunk(r))).await
        }
        AttachmentProcedure::DeleteAttachment => {
            reply(decode(body).map(|r| attachments.delete_attachment(r))).await
        }
    };
    finish_reply(reply)
}

/// Answer a call to `procedure`, whose request has `content_type` and `body`, with `handshake`,
/// `mailbox` and `attachments`.
///
/// Routing and the method are up to the HTTP server: find the procedure with
/// [`Procedure::from_path`], and only take `POST`. A body of another content type is answered
/// with `415 Unsupported Media Type`.
#[deprecated(
    note = "legacy v1 protocol is deprecated; use handshake.v2, mailbox.v2, and audience-bound SubscribeRequest v2 (see git tag archive/legacy-v1)"
)]
#[allow(deprecated)]
pub async fn handle(
    handshake: &impl LocalHandshake,
    mailbox: &impl LocalMailbox,
    attachments: &impl LocalAttachments,
    procedure: Procedure,
    content_type: Option<&str>,
    body: &[u8],
) -> Response {
    if let Some(response) = check_content_type(content_type) {
        return response;
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
        Procedure::DeleteAttachment => {
            reply(decode(body).map(|r| attachments.delete_attachment(r))).await
        }
    };
    finish_reply(reply)
}

/// Answer a call to a v2 `procedure`, whose request has `content_type` and `body`, with
/// `handshake` and `mailbox`.
#[cfg(feature = "pq")]
pub async fn handle_v2(
    handshake: &impl LocalHandshakeV2,
    mailbox: &impl LocalMailboxV2,
    procedure: ProcedureV2,
    content_type: Option<&str>,
    body: &[u8],
) -> Response {
    if let Some(response) = check_content_type(content_type) {
        return response;
    }
    let reply = match procedure {
        ProcedureV2::GetServerInfo => {
            reply(decode(body).map(|r| handshake.get_server_info(r))).await
        }
        ProcedureV2::PublishV2 => reply(decode(body).map(|r| handshake.publish_v2(r))).await,
        ProcedureV2::RefillPrekeys => {
            reply(decode(body).map(|r| handshake.refill_prekeys(r))).await
        }
        ProcedureV2::GetManifest => reply(decode(body).map(|r| handshake.get_manifest(r))).await,
        ProcedureV2::ClaimBundle => reply(decode(body).map(|r| handshake.claim_bundle(r))).await,
        ProcedureV2::SendInitialV2 => {
            reply(decode(body).map(|r| handshake.send_initial_v2(r))).await
        }
        ProcedureV2::ListInitialMessages => {
            reply(decode(body).map(|r| handshake.list_initial_messages(r))).await
        }
        ProcedureV2::AckInitialMessages => {
            reply(decode(body).map(|r| handshake.ack_initial_messages(r))).await
        }
        ProcedureV2::PushV2 => reply(decode(body).map(|r| mailbox.push_v2(r))).await,
        ProcedureV2::FetchSigned => reply(decode(body).map(|r| mailbox.fetch_signed(r))).await,
    };
    finish_reply(reply)
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
    /// Call a procedure at `path` with `request`.
    async fn call_path<T: Message + Default>(
        &self,
        path: &str,
        request: impl Message,
    ) -> Result<T> {
        let (status, body) = self
            .0
            .post(path, request.encode_to_vec())
            .await
            .map_err(|e| {
                if e.kind() == ErrorKind::Connect {
                    e
                } else {
                    Error::ambiguous_response(ErrorKind::InvalidResponse, e)
                }
            })?;
        if status == 200 {
            return T::decode(body.as_slice())
                .map_err(|e| Error::ambiguous_response(ErrorKind::InvalidResponse, e));
        }
        if let Ok(error) = serde_json::from_slice::<CallError>(&body) {
            let kind = Code::from_name(&error.code).map_or(ErrorKind::Server, ErrorKind::from);
            return Err(Error::new(kind, error));
        }
        // A proxy can generate this status. Only the server's own 403 asks for sign-in.
        let code = match Code::from_status(status) {
            Code::PermissionDenied => Code::Unknown,
            code => code,
        };
        Err(Error::from_http_status(
            code.into(),
            CallError {
                code: code.name().to_string(),
                message: format!("HTTP status {status}"),
            },
        ))
    }

    /// Call `procedure` with `request`.
    async fn call<T: Message + Default>(
        &self,
        procedure: Procedure,
        request: impl Message,
    ) -> Result<T> {
        self.call_path(procedure.path(), request).await
    }

    /// Call attachment `procedure` with `request`.
    async fn call_attachment<T: Message + Default>(
        &self,
        procedure: AttachmentProcedure,
        request: impl Message,
    ) -> Result<T> {
        self.call_path(procedure.path(), request).await
    }

    /// Call v2 `procedure` with `request`.
    #[cfg(feature = "pq")]
    async fn call_v2<T: Message + Default>(
        &self,
        procedure: ProcedureV2,
        request: impl Message,
    ) -> Result<T> {
        self.call_path(procedure.path(), request).await
    }
}

#[allow(deprecated)]
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

#[allow(deprecated)]
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
        self.call_attachment(AttachmentProcedure::StartUpload, request)
            .await
    }

    async fn put_chunk(&self, request: PutChunkRequest) -> Result<PutChunkResponse> {
        self.call_attachment(AttachmentProcedure::PutChunk, request)
            .await
    }

    async fn get_chunk(&self, request: GetChunkRequest) -> Result<GetChunkResponse> {
        self.call_attachment(AttachmentProcedure::GetChunk, request)
            .await
    }

    async fn delete_attachment(
        &self,
        request: DeleteAttachmentRequest,
    ) -> Result<DeleteAttachmentResponse> {
        self.call_attachment(AttachmentProcedure::DeleteAttachment, request)
            .await
    }
}

#[cfg(feature = "pq")]
impl<P: LocalPost> LocalHandshakeV2 for ConnectClient<P> {
    async fn get_server_info(
        &self,
        request: GetServerInfoRequest,
    ) -> Result<GetServerInfoResponse> {
        self.call_v2(ProcedureV2::GetServerInfo, request).await
    }

    async fn publish_v2(&self, request: PublishV2Request) -> Result<PublishV2Response> {
        self.call_v2(ProcedureV2::PublishV2, request).await
    }

    async fn refill_prekeys(&self, request: RefillPrekeysRequest) -> Result<RefillPrekeysResponse> {
        self.call_v2(ProcedureV2::RefillPrekeys, request).await
    }

    async fn get_manifest(&self, request: GetManifestRequest) -> Result<GetManifestResponse> {
        self.call_v2(ProcedureV2::GetManifest, request).await
    }

    async fn claim_bundle(&self, request: ClaimBundleRequest) -> Result<ClaimBundleResponse> {
        self.call_v2(ProcedureV2::ClaimBundle, request).await
    }

    async fn send_initial_v2(
        &self,
        request: SendInitialV2Request,
    ) -> Result<SendInitialV2Response> {
        self.call_v2(ProcedureV2::SendInitialV2, request).await
    }

    async fn list_initial_messages(
        &self,
        request: ListInitialMessagesRequest,
    ) -> Result<ListInitialMessagesResponse> {
        self.call_v2(ProcedureV2::ListInitialMessages, request)
            .await
    }

    async fn ack_initial_messages(
        &self,
        request: AckInitialMessagesRequest,
    ) -> Result<AckInitialMessagesResponse> {
        self.call_v2(ProcedureV2::AckInitialMessages, request).await
    }
}

#[cfg(feature = "pq")]
impl<P: LocalPost> LocalMailboxV2 for ConnectClient<P> {
    async fn push_v2(&self, request: PushV2Request) -> Result<PushV2Response> {
        self.call_v2(ProcedureV2::PushV2, request).await
    }

    async fn fetch_signed(&self, request: FetchSignedRequest) -> Result<FetchSignedResponse> {
        self.call_v2(ProcedureV2::FetchSigned, request).await
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
            ErrorKind::Unimplemented => Self::Unimplemented,
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
            Code::Unimplemented => Self::Unimplemented,
            _ => Self::Server,
        }
    }
}

#[cfg(all(test, feature = "server"))]
#[allow(deprecated)]
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

    #[cfg(feature = "pq")]
    #[tokio::test]
    async fn unimplemented_distinguishes_connect_errors_from_proxy_statuses() {
        for (body, is_connect) in [
            (&b"<html>404 Not Found</html>"[..], false),
            (
                &br#"{"code":"unimplemented","message":"upgrade required"}"#[..],
                true,
            ),
        ] {
            let error = ConnectClient::new(Answering(404, body))
                .get_server_info(GetServerInfoRequest {})
                .await
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Unimplemented);
            assert!(error.is_server_refusal());
            assert_eq!(error.is_connect_error(), is_connect);
        }
        assert!(Error::from(ErrorKind::Unimplemented).is_connect_error());
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
    async fn refusals_and_ambiguous_responses_remain_distinct() {
        struct ResponseError(ErrorKind);
        impl LocalPost for ResponseError {
            async fn post(&self, _: &str, _: Vec<u8>) -> Result<(u16, Vec<u8>)> {
                Err(self.0.into())
            }
        }
        struct Reply(Code);
        impl LocalPost for Reply {
            async fn post(&self, _: &str, _: Vec<u8>) -> Result<(u16, Vec<u8>)> {
                Ok((self.0.status(), error_body(self.0, "failure")))
            }
        }
        for code in Code::ALL {
            let error = ConnectClient::new(Reply(code))
                .push(PushRequest::default())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::from(code));
            assert_eq!(
                error.is_server_refusal(),
                !matches!(code, Code::Internal | Code::Unavailable | Code::Unknown)
            );
        }
        for kind in [
            ErrorKind::LimitExceeded,
            ErrorKind::Malformed,
            ErrorKind::Connect,
        ] {
            let error = ConnectClient::new(ResponseError(kind))
                .push(PushRequest::default())
                .await
                .unwrap_err();
            assert_eq!(
                error.kind(),
                if kind == ErrorKind::Connect {
                    kind
                } else {
                    ErrorKind::InvalidResponse
                }
            );
            assert!(!error.is_server_refusal());
            assert!(!error.is_connect_error());
            assert!(!Error::ambiguous_response(kind, "response read failed").is_server_refusal());
        }
        let error = ConnectClient::new(Answering(200, &[0xff]))
            .push(PushRequest::default())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);
        assert!(!error.is_server_refusal());
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

    #[cfg(feature = "pq")]
    #[test]
    fn v2_paths_follow_the_services() {
        let files = protox::compile(
            ["proto/handshake_v2.proto", "proto/mailbox_v2.proto"],
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
        let mut paths = ProcedureV2::ALL.map(|procedure| procedure.path().to_string());
        services.sort();
        paths.sort();
        assert_eq!(services, paths);
    }

    #[cfg(feature = "pq")]
    #[tokio::test]
    async fn v2_over_connect_roundtrip() {
        use std::sync::Arc;

        use x3dh::{PqSuite, pq_prekey_id, sign_pq_spk};
        use xeddsa::XEdDSAPrivateKey;

        use crate::{
            handshake_v2::{
                CapabilityManifest, HandshakeV2Server, PqLastResortCommitment, PqPrekey,
                ServerInfoConfig, sign_manifest,
            },
            mailbox_v2::MailboxV2Server,
        };

        #[derive(Clone)]
        struct Shared(Arc<MemoryStore>);

        impl storage::LocalPqHandshakeStore for Shared {
            async fn publish_v2(
                &self,
                r: storage::PublishV2Record,
            ) -> storage::Result<storage::PublishV2Status> {
                storage::PqHandshakeStore::publish_v2(&*self.0, r).await
            }
            async fn refill_prekeys(
                &self,
                r: storage::RefillPrekeysRecord,
            ) -> storage::Result<storage::RefillStatus> {
                storage::PqHandshakeStore::refill_prekeys(&*self.0, r).await
            }
            async fn get_manifest(
                &self,
                id: &x3dh::PublicKey,
            ) -> storage::Result<Option<storage::StoredCapabilityManifest>> {
                storage::PqHandshakeStore::get_manifest(&*self.0, id).await
            }
            async fn claim_bundle(
                &self,
                id: &x3dh::PublicKey,
                suites: &[u8],
            ) -> storage::Result<Option<storage::ClaimedPqBundle>> {
                storage::PqHandshakeStore::claim_bundle(&*self.0, id, suites).await
            }
            async fn add_initial_message_v2(
                &self,
                m: storage::StoredInitialMessageV2,
                limit: usize,
            ) -> storage::Result<Option<u64>> {
                storage::PqHandshakeStore::add_initial_message_v2(&*self.0, m, limit).await
            }
            async fn list_initial_messages(
                &self,
                id: &x3dh::PublicKey,
                limit: usize,
            ) -> storage::Result<Vec<storage::StoredInitialMessageV2>> {
                storage::PqHandshakeStore::list_initial_messages(&*self.0, id, limit).await
            }
            async fn ack_initial_messages(
                &self,
                id: &x3dh::PublicKey,
                ids: &[u64],
            ) -> storage::Result<usize> {
                storage::PqHandshakeStore::ack_initial_messages(&*self.0, id, ids).await
            }
            async fn pq_snapshot(
                &self,
                id: &x3dh::PublicKey,
            ) -> storage::Result<storage::PqStorageSnapshot> {
                storage::PqHandshakeStore::pq_snapshot(&*self.0, id).await
            }
        }

        impl storage::LocalIdempotentMailboxStore for Shared {
            async fn append_idempotent(
                &self,
                s: &x3dh::PublicKey,
                r: &x3dh::PublicKey,
                h: Bytes,
                c: Bytes,
                i: Option<Bytes>,
                d: Option<[u8; 32]>,
                cid: Option<[u8; 16]>,
            ) -> storage::Result<u64> {
                storage::IdempotentMailboxStore::append_idempotent(&*self.0, s, r, h, c, i, d, cid)
                    .await
            }
            async fn delete_delivered(
                &self,
                s: &x3dh::PublicKey,
                r: &x3dh::PublicKey,
                h: &[[u8; 32]],
            ) -> storage::Result<()> {
                storage::IdempotentMailboxStore::delete_delivered(&*self.0, s, r, h).await
            }
            async fn read(
                &self,
                s: &x3dh::PublicKey,
                r: &x3dh::PublicKey,
                a: u64,
                l: u32,
            ) -> storage::Result<Vec<storage::StoredMessage>> {
                storage::IdempotentMailboxStore::read(&*self.0, s, r, a, l).await
            }
        }

        struct InProcessV2 {
            handshake: HandshakeV2Server<Shared>,
            mailbox: MailboxV2Server<Shared>,
        }

        impl LocalPost for InProcessV2 {
            async fn post(&self, path: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
                let Some(proc_v2) = ProcedureV2::from_path(path) else {
                    return Ok((404, b"no such procedure".to_vec()));
                };
                let resp = handle_v2(
                    &self.handshake,
                    &self.mailbox,
                    proc_v2,
                    Some(CONTENT_TYPE),
                    &body,
                )
                .await;
                Ok((resp.status, resp.body))
            }
        }

        let store = Shared(Arc::new(MemoryStore::default()));
        let client = ConnectClient::new(InProcessV2 {
            handshake: HandshakeV2Server::new(store.clone(), ServerInfoConfig::new("connect.test")),
            mailbox: MailboxV2Server::new(store, "connect.test"),
        });

        let info = client
            .get_server_info(GetServerInfoRequest {})
            .await
            .unwrap();
        assert!(info.pq_enabled);
        assert_eq!(info.server_id, "connect.test");

        let bob = XEdDSAPrivateKey::generate();
        let bob_pk = bob.compute_public_key().to_bytes();
        let alice = XEdDSAPrivateKey::generate();
        let alice_pk = alice.compute_public_key().to_bytes();
        let now = crate::now_millis();

        let ek = vec![0x99; PqSuite::MlKem1024.ek_len()];
        let id = pq_prekey_id(PqSuite::MlKem1024.as_u8(), &ek);
        let lr = PqPrekey {
            suite: 1,
            prekey_id: Bytes::copy_from_slice(&id),
            encapsulation_key: Bytes::from(ek),
            signature: Bytes::copy_from_slice(
                &sign_pq_spk(&bob, PqSuite::MlKem1024, &[0x99; 1568]).unwrap(),
            ),
        };
        let mut manifest = CapabilityManifest {
            audience: "connect.test".into(),
            identity_key: Bytes::new(),
            manifest_seq: 1,
            generation: 1,
            issued_at: now,
            expires_at: now + 60_000,
            pq_enabled: true,
            strict_pq: false,
            pq_ratchet_supported: true,
            offered_suites: vec![1],
            signed_prekey: Bytes::from_static(&[0x11; 32]),
            pq_last_resort: vec![PqLastResortCommitment {
                suite: 1,
                prekey_id: Bytes::copy_from_slice(&id),
            }],
            signature: Bytes::new(),
        };
        sign_manifest(&bob, &mut manifest).unwrap();

        let pub_req = PublishV2Request::sign(
            &bob,
            manifest.clone(),
            Some(bob.sign([0x11; 32])),
            &[[0x22; 32]],
            vec![lr],
            vec![],
            now,
        )
        .unwrap();
        client.publish_v2(pub_req).await.unwrap();

        let got = client
            .get_manifest(GetManifestRequest {
                identity_key: Bytes::copy_from_slice(&bob_pk),
            })
            .await
            .unwrap();
        assert_eq!(got.manifest, Some(manifest));

        let claimed = client
            .claim_bundle(ClaimBundleRequest {
                identity_key: Bytes::copy_from_slice(&bob_pk),
                preferred_suites: vec![1],
            })
            .await
            .unwrap();
        assert!(claimed.pq_last_resort.is_some());

        let pushed = client
            .push_v2(PushV2Request {
                sender: Bytes::copy_from_slice(&alice_pk),
                recipient: Bytes::copy_from_slice(&bob_pk),
                message: Some(EncryptedMessage {
                    header: Bytes::from_static(b"hdr"),
                    content: Bytes::from_static(b"body"),
                }),
                initial_message: None,
                delivery_hash: Bytes::new(),
                client_message_id: Bytes::from_static(&[7; 16]),
            })
            .await
            .unwrap();
        assert_eq!(pushed.sequence, 1);

        let fetched = client
            .fetch_signed(
                FetchSignedRequest::sign(&bob, "connect.test", &alice_pk, 0, 10, 0, vec![], now)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fetched.messages.len(), 1);
    }

    #[test]
    fn attachment_paths_follow_the_service_and_legacy_v1_path_detection() {
        let files =
            protox::compile(["proto/attachment.proto"], ["proto", "../party/proto"]).unwrap();
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
        let mut paths = AttachmentProcedure::ALL.map(|procedure| procedure.path().to_string());
        services.sort();
        paths.sort();
        assert_eq!(services, paths);
        for procedure in AttachmentProcedure::ALL {
            assert_eq!(
                AttachmentProcedure::from_path(procedure.path()),
                Some(procedure)
            );
            assert!(!is_legacy_v1_path(procedure.path()));
        }
        assert_eq!(
            AttachmentProcedure::from_path("/handshake.v1.HandshakeService/Publish"),
            None
        );

        for legacy in [
            "/handshake.v1.HandshakeService/Publish",
            "/handshake.v1.HandshakeService/FetchBundle",
            "/handshake.v1.HandshakeService/SendInitialMessage",
            "/handshake.v1.HandshakeService/TakeInitialMessages",
            "/mailbox.v1.MailboxService/Push",
            "/mailbox.v1.MailboxService/Fetch",
        ] {
            assert!(is_legacy_v1_path(legacy), "expected legacy: {legacy}");
        }
        for modern in [
            "/handshake.v2.HandshakeService/GetServerInfo",
            "/handshake.v2.HandshakeService/PublishV2",
            "/mailbox.v2.MailboxService/PushV2",
            "/mailbox.v2.MailboxService/FetchSigned",
            "/attachment.v1.AttachmentService/StartUpload",
            "/notifications",
            "/auth",
        ] {
            assert!(!is_legacy_v1_path(modern), "expected non-legacy: {modern}");
        }
    }

    #[tokio::test]
    async fn attachments_over_connect_roundtrip() {
        use sha2::{Digest, Sha256};

        struct AttachmentsOnly(AttachmentServer<MemoryStore>);

        impl LocalPost for AttachmentsOnly {
            async fn post(&self, path: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
                let Some(procedure) = AttachmentProcedure::from_path(path) else {
                    return Ok((404, b"no such procedure".to_vec()));
                };
                let response =
                    handle_attachments(&self.0, procedure, Some(CONTENT_TYPE), &body).await;
                Ok((response.status, response.body))
            }
        }

        let server = AttachmentServer::new(MemoryStore::default());
        let bad_ct = handle_attachments(
            &server,
            AttachmentProcedure::StartUpload,
            Some("application/json"),
            b"{}",
        )
        .await;
        assert_eq!(bad_ct.status, 415);

        let client = ConnectClient::new(AttachmentsOnly(server));
        let delete_token = Bytes::from_static(&[0x5A; crate::attachment::TOKEN_LENGTH]);
        let started = client
            .start_upload(StartUploadRequest {
                chunks: 1,
                delete_hash: Bytes::from(Sha256::digest(&delete_token).to_vec()),
            })
            .await
            .unwrap();
        client
            .put_chunk(PutChunkRequest {
                id: started.id.clone(),
                upload_token: started.upload_token.clone(),
                index: 0,
                data: Bytes::from_static(b"chunk-0"),
            })
            .await
            .unwrap();
        let got = client
            .get_chunk(GetChunkRequest {
                id: started.id.clone(),
                index: 0,
            })
            .await
            .unwrap();
        assert!(got.uploaded);
        assert_eq!(got.data, Bytes::from_static(b"chunk-0"));
        client
            .delete_attachment(DeleteAttachmentRequest {
                id: started.id,
                token: delete_token,
            })
            .await
            .unwrap();
    }
}
