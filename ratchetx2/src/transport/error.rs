//! Error type for transport operations.

use thiserror::Error;

/// Error type for transport operations.
#[derive(Debug, Error)]
pub enum TransportError {}

pub(super) type Result<T> = core::result::Result<T, TransportError>;
