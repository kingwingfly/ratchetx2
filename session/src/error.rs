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
}

impl Error {
    /// New an error of `kind`, caused by `source`.
    pub fn new(kind: ErrorKind, source: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    /// The kind of this error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self { kind, source: None }
    }
}

impl From<protocol::Error> for Error {
    fn from(error: protocol::Error) -> Self {
        use protocol::ErrorKind as Kind;
        let kind = match error.kind() {
            Kind::NotFound => ErrorKind::NotFound,
            Kind::LimitExceeded => ErrorKind::LimitExceeded,
            Kind::Malformed | Kind::InvalidSignature | Kind::StaleTimestamp => ErrorKind::Protocol,
            _ => ErrorKind::Server,
        };
        Self::new(kind, error)
    }
}

impl From<x3dh::Error> for Error {
    fn from(error: x3dh::Error) -> Self {
        use x3dh::ErrorKind as Kind;
        let kind = match error.kind() {
            Kind::InvalidPublicKey | Kind::InvalidSignature => ErrorKind::InvalidKeys,
            Kind::UnexpectedIdentity => ErrorKind::UnexpectedPeer,
            Kind::MalformedState => ErrorKind::MalformedState,
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
    /// Nobody published keys for this identity.
    #[error("no keys published for this identity")]
    NotFound,
    /// The peer's inbox is full, or a message or an attachment is too large.
    #[error("limit exceeded")]
    LimitExceeded,
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
    /// A received message cannot be decrypted.
    #[error("cannot decrypt the message")]
    Undecryptable,
    /// A received message was received already.
    #[error("duplicate message")]
    DuplicateMessage,
    /// A received message is malformed.
    #[error("invalid message")]
    InvalidMessage,
    /// A saved client or session state is malformed.
    #[error("malformed saved state")]
    MalformedState,
}

/// Result type with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
