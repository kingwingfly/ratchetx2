//! The [Connect protocol](https://connectrpc.com/docs/protocol)'s unary calls: protobuf over
//! plain HTTP `POST`, for where gRPC cannot go, such as browsers and Cloudflare Workers.
//!
//! A call is a `POST` to its procedure's path, e.g. `/handshake.v2.HandshakeService/PublishV2`,
//! with `Content-Type: application/proto`, `Connect-Protocol-Version: 1` and the protobuf
//! request as the body. A success is `200 OK` with the protobuf response. An error has another
//! status and a JSON body such as `{"code":"not_found","message":"not found"}`, whose code maps
//! to an [`ErrorKind`] as gRPC's status codes do. So any Connect client can call these services,
//! and the clients here can call any Connect server of them.
//!
//! This module does no I/O: [`ConnectClient`] runs on any HTTP client that implements
//! [`LocalPost`], [`handle_attachments`] answers attachment calls with [`LocalAttachments`], and
//! [`handle_v2`] answers `handshake.v2` and `mailbox.v2` calls.

use std::fmt;

use bytes::Buf;
use prost::Message;

use crate::{
    attachment::{
        DeleteAttachmentRequest, DeleteAttachmentResponse, GetChunkRequest, GetChunkResponse,
        LocalAttachments, PutChunkRequest, PutChunkResponse, StartUploadRequest,
        StartUploadResponse,
    },
    error::{Error, ErrorKind, Result},
    handshake_v2::{
        AckInitialMessagesRequest, AckInitialMessagesResponse, ClaimBundleRequest,
        ClaimBundleResponse, GetManifestRequest, GetManifestResponse, GetServerInfoRequest,
        GetServerInfoResponse, ListInitialMessagesRequest, ListInitialMessagesResponse,
        LocalHandshakeV2, PublishV2Request, PublishV2Response, RefillPrekeysRequest,
        RefillPrekeysResponse, SendInitialV2Request, SendInitialV2Response,
    },
    mailbox_v2::{
        AckMessagesRequest, AckMessagesResponse, FetchSignedRequest, FetchSignedResponse,
        LocalMailboxV2, PushV2Request, PushV2Response, RegisterWriteTokenRequest,
        RegisterWriteTokenResponse, RevokeWriteTokenRequest, RevokeWriteTokenResponse,
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

/// A Connect RPC procedure mapping a typed enum variant to its HTTP path.
trait ConnectProcedure: Copy {
    fn path(self) -> &'static str;
}

macro_rules! define_procedures {
    (
        $(#[$enum_meta:meta])*
        pub enum $name:ident {
            $(
                $(#[$var_meta:meta])*
                $variant:ident => $path:literal,
            )*
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $(
                $(#[$var_meta])*
                $variant,
            )*
        }

        impl $name {
            /// Every procedure in this service set.
            pub const ALL: [Self; [$($path),*].len()] = [
                $(Self::$variant,)*
            ];

            /// The path of its calls: `/` ‖ the service's full name ‖ `/` ‖ the method's name.
            pub const fn path(self) -> &'static str {
                match self {
                    $(Self::$variant => $path,)*
                }
            }

            /// The procedure whose calls go to `path`, if any.
            pub fn from_path(path: &str) -> Option<Self> {
                match path {
                    $($path => Some(Self::$variant),)*
                    _ => None,
                }
            }
        }

        impl ConnectProcedure for $name {
            fn path(self) -> &'static str {
                Self::path(self)
            }
        }
    };
}

define_procedures! {
    /// A procedure of the attachment service (`/attachment.v1.AttachmentService/*`).
    pub enum AttachmentProcedure {
        /// [`LocalAttachments::start_upload`].
        StartUpload => "/attachment.v1.AttachmentService/StartUpload",
        /// [`LocalAttachments::put_chunk`].
        PutChunk => "/attachment.v1.AttachmentService/PutChunk",
        /// [`LocalAttachments::get_chunk`].
        GetChunk => "/attachment.v1.AttachmentService/GetChunk",
        /// [`LocalAttachments::delete_attachment`].
        DeleteAttachment => "/attachment.v1.AttachmentService/DeleteAttachment",
    }
}

define_procedures! {
    /// A v2 procedure: a method of `handshake.v2.HandshakeService` or `mailbox.v2.MailboxService`.
    pub enum ProcedureV2 {
        /// [`LocalHandshakeV2::get_server_info`].
        GetServerInfo => "/handshake.v2.HandshakeService/GetServerInfo",
        /// [`LocalHandshakeV2::publish_v2`].
        PublishV2 => "/handshake.v2.HandshakeService/PublishV2",
        /// [`LocalHandshakeV2::refill_prekeys`].
        RefillPrekeys => "/handshake.v2.HandshakeService/RefillPrekeys",
        /// [`LocalHandshakeV2::get_manifest`].
        GetManifest => "/handshake.v2.HandshakeService/GetManifest",
        /// [`LocalHandshakeV2::claim_bundle`].
        ClaimBundle => "/handshake.v2.HandshakeService/ClaimBundle",
        /// [`LocalHandshakeV2::send_initial_v2`].
        SendInitialV2 => "/handshake.v2.HandshakeService/SendInitialV2",
        /// [`LocalHandshakeV2::list_initial_messages`].
        ListInitialMessages => "/handshake.v2.HandshakeService/ListInitialMessages",
        /// [`LocalHandshakeV2::ack_initial_messages`].
        AckInitialMessages => "/handshake.v2.HandshakeService/AckInitialMessages",
        /// [`LocalMailboxV2::push_v2`].
        PushV2 => "/mailbox.v2.MailboxService/PushV2",
        /// [`LocalMailboxV2::fetch_signed`].
        FetchSigned => "/mailbox.v2.MailboxService/FetchSigned",
        /// [`LocalMailboxV2::ack_messages`].
        AckMessages => "/mailbox.v2.MailboxService/AckMessages",
        /// [`LocalMailboxV2::register_write_token`].
        RegisterWriteToken => "/mailbox.v2.MailboxService/RegisterWriteToken",
        /// [`LocalMailboxV2::revoke_write_token`].
        RevokeWriteToken => "/mailbox.v2.MailboxService/RevokeWriteToken",
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

/// Validate the Connect request `Content-Type` header (`application/proto`), returning a
/// `415 Unsupported Media Type` error response before buffering the body if it does not match.
pub fn check_content_type(content_type: Option<&str>) -> Option<Response> {
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
/// `attachments` (`/attachment.v1.AttachmentService/*`).
///
/// Accepting `impl Buf` allows callers with an owned [`bytes::Bytes`] buffer to slice fields
/// zero-copy and drop the raw outer buffer as soon as prost finishes decoding.
///
/// Routing and the method are up to the HTTP server: find the procedure with
/// [`AttachmentProcedure::from_path`], and only take `POST`. A body of another content type is
/// answered with `415 Unsupported Media Type`.
pub async fn handle_attachments(
    attachments: &impl LocalAttachments,
    procedure: AttachmentProcedure,
    content_type: Option<&str>,
    body: impl Buf,
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

/// Answer a call to a v2 `procedure`, whose request has `content_type` and `body`, with
/// `handshake` and `mailbox`.
///
/// Accepting `impl Buf` allows callers with an owned [`bytes::Bytes`] buffer to slice fields
/// zero-copy and drop the raw outer buffer as soon as prost finishes decoding.
pub async fn handle_v2(
    handshake: &impl LocalHandshakeV2,
    mailbox: &impl LocalMailboxV2,
    procedure: ProcedureV2,
    content_type: Option<&str>,
    body: impl Buf,
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
        ProcedureV2::AckMessages => reply(decode(body).map(|r| mailbox.ack_messages(r))).await,
        ProcedureV2::RegisterWriteToken => {
            reply(decode(body).map(|r| mailbox.register_write_token(r))).await
        }
        ProcedureV2::RevokeWriteToken => {
            reply(decode(body).map(|r| mailbox.revoke_write_token(r))).await
        }
    };
    finish_reply(reply)
}

/// The response to a call that fails with `kind` before [`handle_v2`] or [`handle_attachments`]
/// could answer it, e.g. as its body is too large to read.
pub fn error(kind: ErrorKind, message: &str) -> Response {
    let code = Code::from(kind);
    Response {
        status: code.status(),
        content_type: ERROR_CONTENT_TYPE,
        body: error_body(code, message),
    }
}

/// A request's body, decoded.
fn decode<T: Message + Default>(body: impl Buf) -> Result<T> {
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
        procedure: impl ConnectProcedure,
        request: impl Message,
    ) -> Result<T> {
        let (status, body) = self
            .0
            .post(procedure.path(), request.encode_to_vec())
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
        // A proxy can generate 403 or 409 without a Connect JSON body. Only decoded Connect
        // JSON error bodies produce SignInRequired or WriteTokenRejected.
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
}

impl<P: LocalPost> LocalAttachments for ConnectClient<P> {
    async fn start_upload(&self, request: StartUploadRequest) -> Result<StartUploadResponse> {
        self.call(AttachmentProcedure::StartUpload, request).await
    }

    async fn put_chunk(&self, request: PutChunkRequest) -> Result<PutChunkResponse> {
        self.call(AttachmentProcedure::PutChunk, request).await
    }

    async fn get_chunk(&self, request: GetChunkRequest) -> Result<GetChunkResponse> {
        self.call(AttachmentProcedure::GetChunk, request).await
    }

    async fn delete_attachment(
        &self,
        request: DeleteAttachmentRequest,
    ) -> Result<DeleteAttachmentResponse> {
        self.call(AttachmentProcedure::DeleteAttachment, request)
            .await
    }
}

impl<P: LocalPost> LocalHandshakeV2 for ConnectClient<P> {
    async fn get_server_info(
        &self,
        request: GetServerInfoRequest,
    ) -> Result<GetServerInfoResponse> {
        self.call(ProcedureV2::GetServerInfo, request).await
    }

    async fn publish_v2(&self, request: PublishV2Request) -> Result<PublishV2Response> {
        self.call(ProcedureV2::PublishV2, request).await
    }

    async fn refill_prekeys(&self, request: RefillPrekeysRequest) -> Result<RefillPrekeysResponse> {
        self.call(ProcedureV2::RefillPrekeys, request).await
    }

    async fn get_manifest(&self, request: GetManifestRequest) -> Result<GetManifestResponse> {
        self.call(ProcedureV2::GetManifest, request).await
    }

    async fn claim_bundle(&self, request: ClaimBundleRequest) -> Result<ClaimBundleResponse> {
        self.call(ProcedureV2::ClaimBundle, request).await
    }

    async fn send_initial_v2(
        &self,
        request: SendInitialV2Request,
    ) -> Result<SendInitialV2Response> {
        self.call(ProcedureV2::SendInitialV2, request).await
    }

    async fn list_initial_messages(
        &self,
        request: ListInitialMessagesRequest,
    ) -> Result<ListInitialMessagesResponse> {
        self.call(ProcedureV2::ListInitialMessages, request).await
    }

    async fn ack_initial_messages(
        &self,
        request: AckInitialMessagesRequest,
    ) -> Result<AckInitialMessagesResponse> {
        self.call(ProcedureV2::AckInitialMessages, request).await
    }
}

impl<P: LocalPost> LocalMailboxV2 for ConnectClient<P> {
    async fn push_v2(&self, request: PushV2Request) -> Result<PushV2Response> {
        self.call(ProcedureV2::PushV2, request).await
    }

    async fn fetch_signed(&self, request: FetchSignedRequest) -> Result<FetchSignedResponse> {
        self.call(ProcedureV2::FetchSigned, request).await
    }

    async fn ack_messages(&self, request: AckMessagesRequest) -> Result<AckMessagesResponse> {
        self.call(ProcedureV2::AckMessages, request).await
    }

    async fn register_write_token(
        &self,
        request: RegisterWriteTokenRequest,
    ) -> Result<RegisterWriteTokenResponse> {
        self.call(ProcedureV2::RegisterWriteToken, request).await
    }

    async fn revoke_write_token(
        &self,
        request: RevokeWriteTokenRequest,
    ) -> Result<RevokeWriteTokenResponse> {
        self.call(ProcedureV2::RevokeWriteToken, request).await
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
    Aborted,
    NotFound,
    ResourceExhausted,
    Unavailable,
    Internal,
    PermissionDenied,
    Unimplemented,
    Unknown,
}

impl Code {
    #[cfg(all(test, feature = "server"))]
    const ALL: [Self; 11] = [
        Self::InvalidArgument,
        Self::Unauthenticated,
        Self::FailedPrecondition,
        Self::Aborted,
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
            Self::Aborted => "aborted",
            Self::NotFound => "not_found",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
            Self::PermissionDenied => "permission_denied",
            Self::Unimplemented => "unimplemented",
            Self::Unknown => "unknown",
        }
    }

    /// The code named `name`, if it is one of these. Other codes are [`ErrorKind::Server`] errors
    /// to the clients.
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "invalid_argument" => Some(Self::InvalidArgument),
            "unauthenticated" => Some(Self::Unauthenticated),
            "failed_precondition" => Some(Self::FailedPrecondition),
            "aborted" => Some(Self::Aborted),
            "not_found" => Some(Self::NotFound),
            "resource_exhausted" => Some(Self::ResourceExhausted),
            "unavailable" => Some(Self::Unavailable),
            "internal" => Some(Self::Internal),
            "permission_denied" => Some(Self::PermissionDenied),
            "unimplemented" => Some(Self::Unimplemented),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    /// The HTTP status of an error response with this code.
    fn status(self) -> u16 {
        match self {
            Self::InvalidArgument | Self::FailedPrecondition => 400,
            Self::Unauthenticated => 401,
            Self::PermissionDenied => 403,
            Self::NotFound => 404,
            Self::Aborted => 409,
            Self::ResourceExhausted => 429,
            Self::Unimplemented => 501,
            Self::Unavailable => 503,
            Self::Internal | Self::Unknown => 500,
        }
    }

    /// The code a client infers from the status of a response without a valid error body.
    ///
    /// Bare HTTP `409` intentionally maps to `Code::Unknown` (so only a decoded Connect JSON
    /// `"aborted"` body produces [`ErrorKind::WriteTokenRejected`]).
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
            ErrorKind::WriteTokenRejected => Self::Aborted,
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
            Code::Aborted => Self::WriteTokenRejected,
            Code::NotFound => Self::NotFound,
            Code::ResourceExhausted => Self::LimitExceeded,
            Code::PermissionDenied => Self::SignInRequired,
            Code::Unimplemented => Self::Unimplemented,
            _ => Self::Server,
        }
    }
}

#[cfg(all(test, feature = "server"))]
mod test {
    use std::sync::Arc;

    use bytes::Bytes;
    use party::EncryptedMessage;
    use sha2::{Digest, Sha256};
    use storage::MemoryStore;
    use x3dh::{PqSuite, pq_prekey_id, sign_pq_spk};
    use xeddsa::XEdDSAPrivateKey;

    use super::*;
    use crate::{
        attachment::AttachmentServer,
        handshake_v2::{
            CapabilityManifest, HandshakeV2Server, PqLastResortCommitment, PqPrekey,
            ServerInfoConfig, sign_manifest,
        },
        mailbox_v2::{MailboxV2Server, PEER_SLOT_ID_LENGTH, WRITE_TOKEN_LENGTH},
    };

    /// Answers every call with `status` and `body`, as something in front of a server may.
    struct Answering(u16, &'static [u8]);

    impl LocalPost for Answering {
        async fn post(&self, _path: &str, _body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
            Ok((self.0, self.1.to_vec()))
        }
    }

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
            assert_eq!(error.is_server_refusal(), is_connect);
            assert_eq!(error.is_connect_error(), is_connect);
        }
        assert!(Error::from(ErrorKind::Unimplemented).is_connect_error());
        assert!(Error::from(ErrorKind::Unimplemented).is_server_refusal());
    }

    #[tokio::test]
    async fn only_the_servers_own_refusal_asks_to_sign_in_or_rejects_write_token() {
        let request = || PushV2Request::default();
        let sign_in = br#"{"code":"permission_denied","message":"sign in"}"#;
        let aborted = br#"{"code":"aborted","message":"write token rejected"}"#;
        for (status, body, kind, is_refusal) in [
            (403, &sign_in[..], ErrorKind::SignInRequired, true),
            // A firewall's page, or none.
            (403, b"<html>blocked</html>", ErrorKind::Server, false),
            (403, b"", ErrorKind::Server, false),
            (429, b"", ErrorKind::Server, false),
            // Decoded Connect 409 aborted -> WriteTokenRejected (server refusal).
            (409, &aborted[..], ErrorKind::WriteTokenRejected, true),
            // Bare HTTP 409 without Connect JSON body -> Server (NOT a refusal).
            (409, b"<html>conflict</html>", ErrorKind::Server, false),
            (409, b"", ErrorKind::Server, false),
        ] {
            let client = ConnectClient::new(Answering(status, body));
            let err = client.push_v2(request()).await.unwrap_err();
            assert_eq!(err.kind(), kind, "status={status}");
            assert_eq!(err.is_server_refusal(), is_refusal, "status={status}");
            assert_eq!(err.is_connect_error(), is_refusal, "status={status}");
        }
        // Server-side `connect::error` emits HTTP 409 JSON for WriteTokenRejected.
        let resp = error(ErrorKind::WriteTokenRejected, "write token rejected");
        assert_eq!(resp.status, 409);
        assert_eq!(resp.content_type, ERROR_CONTENT_TYPE);
        let parsed: CallError = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(parsed.code, "aborted");
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
                .push_v2(PushV2Request::default())
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
                .push_v2(PushV2Request::default())
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
            .push_v2(PushV2Request::default())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);
        assert!(!error.is_server_refusal());
    }

    #[tokio::test]
    async fn rejects_other_content_types() {
        let handshake = HandshakeV2Server::new(
            MemoryStore::default(),
            ServerInfoConfig::new("connect.test"),
        );
        let mailbox = MailboxV2Server::new(MemoryStore::default(), "connect.test");
        let response = handle_v2(
            &handshake,
            &mailbox,
            ProcedureV2::FetchSigned,
            Some("application/json"),
            &b"{}"[..],
        )
        .await;
        assert_eq!(response.status, 415);
        let response = handle_v2(
            &handshake,
            &mailbox,
            ProcedureV2::FetchSigned,
            Some("Application/Proto; charset=binary"),
            Bytes::new(),
        )
        .await;
        assert_eq!(response.status, 400);
    }

    #[test]
    fn v2_paths_follow_the_services() {
        assert_eq!(ProcedureV2::ALL.len(), 13);
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

    #[test]
    fn attachment_paths_follow_the_service() {
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
        }
        assert_eq!(
            AttachmentProcedure::from_path("/handshake.v2.HandshakeService/PublishV2"),
            None
        );
    }

    #[tokio::test]
    async fn v2_over_connect_roundtrip() {
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
            async fn claim_bundle_checked(
                &self,
                id: &x3dh::PublicKey,
                suites: &[u8],
                reject_pq_on_manifest: bool,
            ) -> storage::Result<storage::ClaimOutcome> {
                storage::PqHandshakeStore::claim_bundle_checked(
                    &*self.0,
                    id,
                    suites,
                    reject_pq_on_manifest,
                )
                .await
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
                after_id: u64,
                limit: usize,
            ) -> storage::Result<Vec<storage::StoredInitialMessageV2>> {
                storage::PqHandshakeStore::list_initial_messages(&*self.0, id, after_id, limit)
                    .await
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
                r: &x3dh::PublicKey,
                token_hash: &[u8; 32],
                h: Bytes,
                c: Bytes,
                i: Option<Bytes>,
                cid: Option<[u8; 16]>,
            ) -> storage::Result<u64> {
                storage::IdempotentMailboxStore::append_idempotent(
                    &*self.0, r, token_hash, h, c, i, cid,
                )
                .await
            }
            async fn read_mailbox(
                &self,
                r: &x3dh::PublicKey,
                after_sequence: u64,
                limit: u32,
                max_size: usize,
                ack_up_to_sequence: u64,
            ) -> storage::Result<storage::MailboxPage> {
                storage::IdempotentMailboxStore::read_mailbox(
                    &*self.0,
                    r,
                    after_sequence,
                    limit,
                    max_size,
                    ack_up_to_sequence,
                )
                .await
            }
            async fn ack_messages(
                &self,
                r: &x3dh::PublicKey,
                up_to_sequence: u64,
            ) -> storage::Result<u64> {
                storage::IdempotentMailboxStore::ack_messages(&*self.0, r, up_to_sequence).await
            }
            async fn register_write_token(
                &self,
                record: storage::RegisterWriteTokenRecord,
            ) -> storage::Result<()> {
                storage::IdempotentMailboxStore::register_write_token(&*self.0, record).await
            }
            async fn revoke_write_token(
                &self,
                record: storage::RevokeWriteTokenRecord,
            ) -> storage::Result<u32> {
                storage::IdempotentMailboxStore::revoke_write_token(&*self.0, record).await
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
                // Pass owned `Bytes` directly to exercise zero-copy `impl Buf` handling.
                let resp = handle_v2(
                    &self.handshake,
                    &self.mailbox,
                    proc_v2,
                    Some(CONTENT_TYPE),
                    Bytes::from(body),
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
        let bob_spk = crate::test_public_key(0x11);
        let bob_opk = crate::test_public_key(0x22);
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
            signed_prekey: Bytes::copy_from_slice(&bob_spk),
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
            Some(bob.sign(bob_spk)),
            &[bob_opk],
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

        // Unauthorized PushV2 surfaces WriteTokenRejected over Connect Code::Aborted (409 JSON).
        let token = [0x42; WRITE_TOKEN_LENGTH];
        let token_hash: [u8; 32] = Sha256::digest(token).into();
        let peer_slot = [0x99; PEER_SLOT_ID_LENGTH];
        let err = client
            .push_v2(PushV2Request {
                recipient: Bytes::copy_from_slice(&bob_pk),
                message: Some(EncryptedMessage {
                    header: Bytes::from_static(b"hdr"),
                    content: Bytes::from_static(b"body"),
                }),
                initial_message: None,
                client_message_id: Bytes::from_static(&[7; 16]),
                write_token: Bytes::copy_from_slice(&token),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WriteTokenRejected);
        assert!(err.is_server_refusal());

        // RegisterWriteToken -> PushV2 -> FetchSigned -> AckMessages -> RevokeWriteToken.
        client
            .register_write_token(
                RegisterWriteTokenRequest::sign(
                    &bob,
                    "connect.test",
                    &peer_slot,
                    &token_hash,
                    1,
                    true,
                    now,
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let pushed = client
            .push_v2(PushV2Request {
                recipient: Bytes::copy_from_slice(&bob_pk),
                message: Some(EncryptedMessage {
                    header: Bytes::from_static(b"hdr"),
                    content: Bytes::from_static(b"body"),
                }),
                initial_message: None,
                client_message_id: Bytes::from_static(&[7; 16]),
                write_token: Bytes::copy_from_slice(&token),
            })
            .await
            .unwrap();
        assert_eq!(pushed.sequence, 1);

        let fetched = client
            .fetch_signed(FetchSignedRequest::sign(&bob, "connect.test", 0, 10, 0, 0, now).unwrap())
            .await
            .unwrap();
        assert_eq!(fetched.messages.len(), 1);
        assert!(!fetched.has_more);
        assert_eq!(fetched.messages[0].token_hash.as_ref(), &token_hash);

        let acked = client
            .ack_messages(AckMessagesRequest::sign(&bob, "connect.test", 1, now).unwrap())
            .await
            .unwrap();
        assert_eq!(acked.deleted, 1);

        let revoked = client
            .revoke_write_token(
                RevokeWriteTokenRequest::sign(&bob, "connect.test", &peer_slot, None, 2, now)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked.revoked, 1);
    }

    #[tokio::test]
    async fn attachments_over_connect_roundtrip() {
        struct AttachmentsOnly(AttachmentServer<MemoryStore>);

        impl LocalPost for AttachmentsOnly {
            async fn post(&self, path: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
                let Some(procedure) = AttachmentProcedure::from_path(path) else {
                    return Ok((404, b"no such procedure".to_vec()));
                };
                let response =
                    handle_attachments(&self.0, procedure, Some(CONTENT_TYPE), Bytes::from(body))
                        .await;
                Ok((response.status, response.body))
            }
        }

        let server = AttachmentServer::new(MemoryStore::default());
        let bad_ct = handle_attachments(
            &server,
            AttachmentProcedure::StartUpload,
            Some("application/json"),
            &b"{}"[..],
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
        let chunk_payload = b"encrypted-chunk-0";
        client
            .put_chunk(PutChunkRequest {
                id: started.id.clone(),
                upload_token: started.upload_token.clone(),
                index: 0,
                data: Bytes::from_static(chunk_payload),
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
        assert_eq!(got.data, Bytes::from_static(chunk_payload));
        client
            .delete_attachment(DeleteAttachmentRequest {
                id: started.id.clone(),
                token: delete_token,
            })
            .await
            .unwrap();
    }
}
