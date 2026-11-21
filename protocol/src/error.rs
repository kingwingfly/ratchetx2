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
    origin: ErrorOrigin,
}

#[derive(Debug, PartialEq, Eq)]
enum ErrorOrigin {
    Protocol,
    #[cfg(feature = "connect")]
    HttpStatus,
    Transport,
}

impl Error {
    /// New an error of `kind`, caused by `source`.
    pub fn new(kind: ErrorKind, source: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        Self {
            source: Some(source.into()),
            ..kind.into()
        }
    }

    /// A failure reading the response, after the server may already have committed the request.
    pub fn ambiguous_response(
        kind: ErrorKind,
        source: impl Into<Box<dyn StdError + Send + Sync>>,
    ) -> Self {
        Self {
            origin: ErrorOrigin::Transport,
            ..Self::new(kind, source)
        }
    }

    #[cfg(feature = "connect")]
    pub(crate) fn from_http_status(
        kind: ErrorKind,
        source: impl Into<Box<dyn StdError + Send + Sync>>,
    ) -> Self {
        Self {
            origin: ErrorOrigin::HttpStatus,
            ..Self::new(kind, source)
        }
    }

    /// Whether the error came directly from the protocol handler or from a decoded Connect
    /// error body. Transport failures and errors inferred from a bare HTTP status return false.
    pub fn is_connect_error(&self) -> bool {
        self.origin == ErrorOrigin::Protocol
    }

    /// Whether the server definitively refused the request, so locally prepared keys can be
    /// rolled back. Transport, response-decoding and internal server errors leave this unknown.
    pub fn is_server_refusal(&self) -> bool {
        self.origin != ErrorOrigin::Transport
            && matches!(
                self.kind,
                ErrorKind::SignInRequired
                    | ErrorKind::LimitExceeded
                    | ErrorKind::Unimplemented
                    | ErrorKind::NotFound
                    | ErrorKind::Malformed
                    | ErrorKind::InvalidSignature
                    | ErrorKind::StaleTimestamp
            )
    }

    /// The kind of this error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            source: None,
            origin: match kind {
                ErrorKind::Connect | ErrorKind::InvalidResponse => ErrorOrigin::Transport,
                _ => ErrorOrigin::Protocol,
            },
        }
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

impl From<x3dh::Error> for Error {
    fn from(error: x3dh::Error) -> Self {
        let kind = match error.kind() {
            x3dh::ErrorKind::InvalidSignature => ErrorKind::InvalidSignature,
            _ => ErrorKind::Malformed,
        };
        Self::new(kind, error)
    }
}

#[cfg(feature = "server")]
impl From<storage::Error> for Error {
    fn from(error: storage::Error) -> Self {
        let kind = match error.kind() {
            storage::ErrorKind::LimitExceeded => ErrorKind::LimitExceeded,
            storage::ErrorKind::InvalidArgument => ErrorKind::Malformed,
            _ => ErrorKind::Storage,
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
    /// The client could not read or decode the response. The server may have committed the request.
    #[error("invalid response")]
    InvalidResponse,
    /// A request or response is malformed, e.g. a key of the wrong length.
    #[error("malformed message")]
    Malformed,
    /// A request's or a prekey's signature, or an upload token, does not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// A signed request's timestamp is not greater than the previous request's, or a
    /// subscription's is too far from the server's clock.
    #[error("stale timestamp")]
    StaleTimestamp,
    /// Nobody published keys for this identity, or there is no such attachment or chunk.
    #[error("not found")]
    NotFound,
    /// Too many one-time prekeys, initial messages or chunks, or a message or chunk too large.
    #[error("limit exceeded")]
    LimitExceeded,
    /// The server stores this only for clients signed in to it, e.g. with its password: a large
    /// message, or an attachment, which cost it storage.
    #[error("sign-in required")]
    SignInRequired,
    /// The server's storage failed.
    #[error("storage error")]
    Storage,
    /// The server does not implement or has disabled this procedure.
    #[error("unimplemented")]
    Unimplemented,
    /// Another server or network failure.
    #[error("server error")]
    Server,
}

/// Result type with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
