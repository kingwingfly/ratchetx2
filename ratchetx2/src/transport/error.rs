//! Error type for transport operations.

use thiserror::Error;

/// Error type for transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Failed to send.
    #[error("Failed to send.")]
    Send,
    /// Failed to receive.
    #[error("Failed to receive.")]
    Recv,
    /// Server error.
    #[error("Server error.")]
    Server,
}

pub(super) type Result<T> = core::result::Result<T, TransportError>;
