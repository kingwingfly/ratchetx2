//! Error types.
use thiserror::Error;

use ring::error::Unspecified;

/// Error types.
#[derive(Debug, Error)]
pub enum Error {
    /// Transport error.
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),
    /// Crypto error.
    #[error("Crypto error")]
    Crypto(#[from] Unspecified),
    /// Signature verify failed.
    #[error("Signature verify failed.")]
    Signature,
    /// Failed
    #[error("Failed: {0}")]
    Failed(String),
}

/// Error type for transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Failed to push.
    #[error("Failed to push.")]
    Push,
    /// Failed to fetch.
    #[error("Failed to fetch.")]
    Fetch,
    /// Server error.
    #[error("Server error.")]
    Server,
}

pub(crate) type Result<T> = core::result::Result<T, Error>;
