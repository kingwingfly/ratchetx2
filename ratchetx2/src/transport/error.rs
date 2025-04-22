//! Error type for transport operations.

use thiserror::Error;

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

pub(super) type Result<T> = core::result::Result<T, TransportError>;
