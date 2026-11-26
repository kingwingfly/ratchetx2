//! Error types.
//!
//! Like [`std::io::Error`]: an [`Error`] has an [`ErrorKind`] to match on, and carries the
//! underlying error, from the lower crates, as its [`source`](std::error::Error::source).
use std::error::Error as StdError;

/// The error type of this crate.
#[derive(Debug, thiserror::Error)]
#[error("{kind}")]
pub struct Error {
    kind: ErrorKind,
    source: Option<Box<dyn StdError + Send + Sync>>,
    server_refusal: bool,
    connect_error: bool,
}

impl Error {
    /// New an error of `kind`, caused by `source`.
    pub fn new(kind: ErrorKind, source: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        Self {
            source: Some(source.into()),
            ..kind.into()
        }
    }

    /// The kind of this error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Whether the server definitively refused the request. Only this outcome permits
    /// rolling back private prekeys prepared for publication.
    pub fn is_server_refusal(&self) -> bool {
        self.server_refusal
    }

    /// Whether the underlying protocol handler returned an error directly or the relay sent
    /// a decodable Connect error body.
    pub fn is_connect_error(&self) -> bool {
        self.connect_error
    }

    /// Whether this error originated from [`x3dh::ErrorKind::Replayed`] (the initial message's
    /// ephemeral key was already confirmed in a retained local prekey generation, e.g. on
    /// post-persist/pre-ack crash replay).
    pub fn is_replayed(&self) -> bool {
        self.source
            .as_deref()
            .and_then(|src| src.downcast_ref::<x3dh::Error>())
            .is_some_and(|err| err.kind() == x3dh::ErrorKind::Replayed)
    }

    pub(crate) fn from_protocol_with_kind(kind: ErrorKind, error: protocol::Error) -> Self {
        Self {
            server_refusal: error.is_server_refusal(),
            connect_error: error.is_connect_error(),
            ..Self::new(kind, error)
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            source: None,
            server_refusal: false,
            connect_error: false,
        }
    }
}

impl From<protocol::Error> for Error {
    fn from(error: protocol::Error) -> Self {
        use protocol::ErrorKind as Kind;
        let kind = match error.kind() {
            Kind::InvalidResponse => ErrorKind::InvalidResponse,
            Kind::NotFound => ErrorKind::NotFound,
            Kind::LimitExceeded => ErrorKind::LimitExceeded,
            Kind::SignInRequired => ErrorKind::SignInRequired,
            Kind::WriteTokenRejected => ErrorKind::WriteTokenRejected,
            Kind::Unimplemented => ErrorKind::Unimplemented,
            Kind::Malformed | Kind::InvalidSignature | Kind::StaleTimestamp => ErrorKind::Protocol,
            _ => ErrorKind::Server,
        };
        Self::from_protocol_with_kind(kind, error)
    }
}

impl From<x3dh::Error> for Error {
    fn from(error: x3dh::Error) -> Self {
        use x3dh::ErrorKind as Kind;
        let kind = match error.kind() {
            Kind::InvalidPublicKey | Kind::InvalidSignature => ErrorKind::InvalidKeys,
            Kind::UnexpectedIdentity => ErrorKind::UnexpectedPeer,
            Kind::MalformedState => ErrorKind::MalformedState,
            Kind::UnsupportedSuite => ErrorKind::UnsupportedSuite,
            _ => ErrorKind::InvalidInitialMessage,
        };
        Self::new(kind, error)
    }
}

impl From<party::error::Error> for Error {
    fn from(error: party::error::Error) -> Self {
        use party::error::ErrorKind as Kind;
        let kind = match error.kind() {
            Kind::NoSendingChain => ErrorKind::NoSendingChain,
            Kind::Undecryptable => ErrorKind::Undecryptable,
            Kind::DuplicateMessage => ErrorKind::DuplicateMessage,
            Kind::EvictedMessage => ErrorKind::EvictedMessage,
            Kind::MalformedState => ErrorKind::MalformedState,
            _ => ErrorKind::InvalidMessage,
        };
        Self::new(kind, error)
    }
}

impl From<ratchetx2::error::CryptoError> for Error {
    fn from(error: ratchetx2::error::CryptoError) -> Self {
        Self::new(ErrorKind::InvalidKeys, error)
    }
}

/// The kinds of [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The server cannot be reached, or failed.
    #[error("server error")]
    Server,
    /// The client could not read or decode the server's response.
    #[error("invalid server response")]
    InvalidResponse,
    /// Nobody published keys for this identity.
    #[error("no keys published for this identity")]
    NotFound,
    /// The peer's inbox is full, or a message or an attachment is too large.
    #[error("limit exceeded")]
    LimitExceeded,
    /// The server stores this only for clients signed in to it, e.g. with its password: a pushed
    /// message, or an attachment.
    #[error("sign-in required")]
    SignInRequired,
    /// The recipient's mailbox rejected the write token (not yet approved or revoked).
    #[error("write token rejected")]
    WriteTokenRejected,
    /// The server rejected a request, or sent a malformed reply.
    #[error("protocol error")]
    Protocol,
    /// The peer's keys are invalid, e.g. a prekey not signed by the peer's identity key.
    #[error("invalid keys")]
    InvalidKeys,
    /// The initial message cannot be accepted: its first message does not decrypt, so it is not
    /// from the peer it claims, or it was accepted already, or its prekeys are gone.
    #[error("invalid initial message")]
    InvalidInitialMessage,
    /// The initial message is not from the expected peer, or a session to
    /// [keep](crate::Session::keep) is with another peer.
    #[error("not the expected peer")]
    UnexpectedPeer,
    /// Bob can only send after he has received Alice's first message.
    #[error("no sending chain yet, wait for the peer's first message")]
    NoSendingChain,
    /// The session has none to send on, as the peers kept missing each other: start a new one,
    /// see [`Session::needs_new_session`](crate::Session::needs_new_session).
    #[error("no session to send on, start a new one")]
    NoSession,
    /// A received message cannot be decrypted.
    #[error("cannot decrypt the message")]
    Undecryptable,
    /// A received message was received already.
    #[error("duplicate message")]
    DuplicateMessage,
    /// A received message's skipped decryption key was evicted before it arrived; the message is
    /// permanently lost.
    #[error("message skipped key was evicted")]
    EvictedMessage,
    /// A received message is malformed.
    #[error("invalid message")]
    InvalidMessage,
    /// A saved client or session state is malformed.
    #[error("malformed saved state")]
    MalformedState,
    /// The server does not implement this v2 procedure.
    #[error("procedure not implemented by server")]
    Unimplemented,
    /// A peer-initiated session was rejected because its `session_seq` was stale (rollback).
    #[error("stale peer-initiated session rejected")]
    StaleSession,
    /// An attachment chunk was requested to be encrypted again with different data or below the
    /// resumed sealed-chunk watermark, which would reuse an AES-GCM nonce.
    #[error("attachment chunk nonce reuse refused")]
    NonceReuse,
    /// An argument to a local operation was out of range or malformed (e.g. out-of-range chunk
    /// index, short non-last attachment chunk, or invalid cursor/grant version).
    #[error("invalid argument")]
    InvalidArgument,
    /// Local policy requires post-quantum security (strict PQ mode), refusing classical fallback.
    #[error("post-quantum security is required")]
    PqRequired,
    /// A post-quantum downgrade, manifest replay, audience mismatch, missing manifest, or prekey
    /// stripping attack was detected.
    #[error("post-quantum downgrade detected")]
    DowngradeDetected,
    /// A peer's signed capability manifest is cryptographically valid and not rolled back, but
    /// its validity window has expired (or lies beyond clock skew), e.g. the peer has been
    /// offline past its manifest TTL.
    #[error("peer capability manifest has expired")]
    PeerManifestExpired,
    /// Peer published a signed `OFF` manifest (or relay rolled back PQ while peer is unpinned)
    /// while local PQ is enabled, and no classical exception has been approved yet.
    #[error("classical fallback requires explicit user approval")]
    ClassicalApprovalRequired,
    /// No mutually supported post-quantum suite is available.
    #[error("unsupported post-quantum suite")]
    UnsupportedSuite,
    /// The local device clock is invalid or disagrees with the server clock by more than the
    /// trusted drift threshold ([`crate::DEFAULT_MAX_TRUSTED_DRIFT_MS`]).
    #[error("device clock disagrees with server clock")]
    ClockSkew,
}

/// Result type with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
