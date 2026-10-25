//! The state of a [`Ratchet`](crate::Ratchet) as protobuf messages, generated from
//! `proto/ratchetx2.proto` (package `ratchetx2.v1`), so other languages can read it.
//!
//! Convert with `proto::Ratchet::from(&ratchet)` and `Ratchet::try_from(&message)`. The messages
//! hold the session's secret keys, so keep them secret: they are zeroized on drop, and their
//! `Debug` shows no keys.
use core::fmt;

use crate::error::MalformedState;

include!(concat!(env!("OUT_DIR"), "/ratchetx2.v1.rs"));

impl fmt::Debug for Ratchet {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ratchet").finish_non_exhaustive()
    }
}

impl fmt::Debug for DhRootRatchet {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhRootRatchet").finish_non_exhaustive()
    }
}

impl fmt::Debug for MessageRatchet {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageRatchet").finish_non_exhaustive()
    }
}

impl fmt::Debug for Chain {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chain").finish_non_exhaustive()
    }
}

/// Read a key field, which must be `N` bytes.
pub(crate) fn key<const N: usize>(bytes: &[u8]) -> Result<[u8; N], MalformedState> {
    bytes.try_into().map_err(|_| MalformedState)
}
