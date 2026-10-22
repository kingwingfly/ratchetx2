//! Error types.
//!
//! Like [`std::io::Error`]: an [`Error`] has an [`ErrorKind`] to match on, and may carry the
//! underlying error as its [`source`](std::error::Error::source).
use std::error::Error as StdError;

use ratchetx2::error::CryptoError;

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

impl From<CryptoError> for Error {
    /// In X3DH, X25519 only fails on an invalid peer public key.
    fn from(error: CryptoError) -> Self {
        Self::new(ErrorKind::InvalidPublicKey, error)
    }
}

impl From<xeddsa::Error> for Error {
    fn from(error: xeddsa::Error) -> Self {
        let kind = match error {
            xeddsa::Error::InvalidPublicKey => ErrorKind::InvalidPublicKey,
            xeddsa::Error::Signature => ErrorKind::InvalidSignature,
        };
        Self::new(kind, error)
    }
}

impl From<primitives::error::Error> for Error {
    fn from(error: primitives::error::Error) -> Self {
        use primitives::error::ErrorKind as Kind;
        let kind = match error.kind() {
            Kind::Connect => ErrorKind::Connect,
            Kind::Push => ErrorKind::Push,
            Kind::Fetch => ErrorKind::Fetch,
            Kind::Server => ErrorKind::Server,
            Kind::InvalidAddress => ErrorKind::InvalidAddress,
            _ => ErrorKind::Other,
        };
        Self::new(kind, error)
    }
}

/// The kinds of [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Failed to connect to the server.
    #[error("failed to connect")]
    Connect,
    /// Failed to push keys or a message.
    #[error("failed to push")]
    Push,
    /// Failed to fetch keys or a message.
    #[error("failed to fetch")]
    Fetch,
    /// The server failed.
    #[error("server error")]
    Server,
    /// The server address is invalid.
    #[error("invalid server address")]
    InvalidAddress,
    /// A peer's identity key, prekey or ephemeral key is invalid.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// The signature on Bob's prekey does not verify.
    #[error("invalid prekey signature")]
    InvalidSignature,
    /// Alice's initial message has not arrived.
    #[error("no initial message found")]
    InitialMessageNotFound,
    /// Alice's initial message does not parse.
    #[error("invalid initial message")]
    InvalidInitialMessage,
    /// The initial message is not from the identity key Bob expects.
    #[error("the initial message is not from the expected identity key")]
    UnexpectedIdentity,
    /// The initial message uses a prekey Bob does not have.
    #[error("prekey not found")]
    PrekeyNotFound,
    /// The initial message uses a one-time prekey Bob does not have, e.g. one used already.
    #[error("one-time prekey not found")]
    OneTimePrekeyNotFound,
    /// Any other error; see its [`source`](std::error::Error::source).
    #[error("other error")]
    Other,
}

/// Result type with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
