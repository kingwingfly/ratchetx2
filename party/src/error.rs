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
    fn from(error: CryptoError) -> Self {
        Self::new(ErrorKind::Crypto, error)
    }
}

/// The kinds of [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Bob has no sending chain until he has received Alice's first message.
    #[error("no sending chain yet, wait for the peer's first message")]
    NoSendingChain,
    /// No known header key opens the message, or its content failed authentication.
    #[error("cannot decrypt the message")]
    Undecryptable,
    /// The message was received already.
    #[error("duplicate message")]
    DuplicateMessage,
    /// The message header does not parse, or its counters are out of range.
    #[error("invalid message header")]
    InvalidHeader,
    /// Receiving the message would skip more than [`SKIP_MAX`](crate::party::SKIP_MAX) message keys.
    #[error("too many skipped messages")]
    TooManySkipped,
    /// The peer's public key is invalid.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// Another cryptographic operation failed.
    #[error("crypto error")]
    Crypto,
}

/// Result type with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
