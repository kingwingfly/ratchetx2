//! Error types.
use thiserror::Error;

/// A cryptographic operation failed, e.g. a malformed public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("crypto error")]
pub struct CryptoError;
