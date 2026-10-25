//! Error types.
use thiserror::Error;

/// A cryptographic operation failed, e.g. a malformed public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("crypto error")]
pub struct CryptoError;

/// A ratchet's protobuf state is malformed, e.g. a key of the wrong length or a missing field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("malformed ratchet state")]
pub struct MalformedState;
