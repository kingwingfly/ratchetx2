//! Error types.
//!
//! Like [`std::io::Error`]: an [`Error`] has an [`ErrorKind`] to match on, and may carry the
//! underlying error as its [`source`](std::error::Error::source).
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

impl From<xeddsa::Error> for Error {
    fn from(error: xeddsa::Error) -> Self {
        let kind = match error {
            xeddsa::Error::InvalidPublicKey => ErrorKind::Malformed,
            xeddsa::Error::Signature => ErrorKind::InvalidSignature,
        };
        Self::new(kind, error)
    }
}

#[cfg(feature = "server")]
impl From<storage::Error> for Error {
    fn from(error: storage::Error) -> Self {
        Self::new(ErrorKind::Storage, error)
    }
}

/// The kinds of [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The server address is invalid.
    #[error("invalid server address")]
    InvalidAddress,
    /// Failed to connect to the server.
    #[error("failed to connect")]
    Connect,
    /// A request or response is malformed, e.g. a key of the wrong length.
    #[error("malformed message")]
    Malformed,
    /// A request's or a prekey's signature does not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// A signed request's timestamp is not greater than the previous request's.
    #[error("stale timestamp")]
    StaleTimestamp,
    /// Nobody published keys for this identity.
    #[error("not found")]
    NotFound,
    /// Too many one-time prekeys or initial messages, or a message too large.
    #[error("limit exceeded")]
    LimitExceeded,
    /// The server's storage failed.
    #[error("storage error")]
    Storage,
    /// Another server or network failure.
    #[error("server error")]
    Server,
}

/// Result type with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
