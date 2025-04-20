//! Error types.
use thiserror::Error;

use crate::transport::error::TransportError;
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
    /// Failed
    #[error("Failed: {0}")]
    Failed(String),
}

pub(crate) type Result<T> = core::result::Result<T, Error>;
