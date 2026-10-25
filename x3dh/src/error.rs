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
            xeddsa::Error::InvalidPublicKey => ErrorKind::InvalidPublicKey,
            xeddsa::Error::Signature => ErrorKind::InvalidSignature,
        };
        Self::new(kind, error)
    }
}

/// The kinds of [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A peer's identity key, prekey or ephemeral key is invalid.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// The signature on Bob's signed prekey does not verify.
    #[error("invalid prekey signature")]
    InvalidSignature,
    /// The initial message is not from the identity key Bob expects.
    #[error("the initial message is not from the expected identity key")]
    UnexpectedIdentity,
    /// The initial message uses a signed prekey Bob does not have.
    #[error("prekey not found")]
    PrekeyNotFound,
    /// The initial message uses a one-time prekey Bob does not have, e.g. one used already.
    #[error("one-time prekey not found")]
    OneTimePrekeyNotFound,
    /// The initial message was confirmed already, and is sent again.
    #[error("initial message replayed")]
    Replayed,
    /// The protobuf state of the local prekeys is malformed, e.g. a key of the wrong length.
    #[error("malformed prekey state")]
    MalformedState,
}

/// Result type with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
