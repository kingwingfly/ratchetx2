#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod attachment;
#[cfg(feature = "connect")]
pub mod connect;
pub mod content;
pub mod error;
pub mod handshake;
#[cfg(feature = "pq")]
pub mod handshake_v2;
pub mod mailbox;
#[cfg(feature = "pq")]
pub mod mailbox_v2;
pub mod notify;

pub use error::{Error, ErrorKind, Result};

/// How far, in milliseconds, the timestamp of a signed request or subscription may be from the
/// server's clock, as a signature would otherwise stay good forever or lock out an identity.
/// Clients sign them with the server's time, as its responses tell it, since a device's clock
/// may be off.
pub const MAX_CLOCK_SKEW: u64 = 5 * 60 * 1000;

/// JavaScript's largest exact integer (`2^53 - 1`); timestamps, sequences, and IDs above this
/// are rejected rather than clamped.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Read a fixed-size bytes field, such as a 32-byte key.
///
/// Fails with [`ErrorKind::Malformed`] if it has another length.
pub fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| ErrorKind::Malformed.into())
}

/// Validates that a 32-byte key is a canonical non-zero Curve25519 encoding.
#[cfg(any(feature = "server", feature = "pq"))]
pub(crate) fn check_canonical_key(key: &x3dh::PublicKey) -> Result<()> {
    if !xeddsa::is_canonical_public_key(key) || *key == [0u8; xeddsa::PUBLIC_KEY_LENGTH] {
        return Err(ErrorKind::Malformed.into());
    }
    Ok(())
}

/// Validates that `timestamp` does not exceed [`MAX_SAFE_INTEGER`].
pub(crate) fn check_safe_integer(value: u64) -> Result<()> {
    if value > MAX_SAFE_INTEGER {
        return Err(ErrorKind::Malformed.into());
    }
    Ok(())
}

/// Current wall-clock time in milliseconds since the Unix epoch.
#[cfg(feature = "server")]
pub(crate) fn now_millis() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(MAX_SAFE_INTEGER))
}

/// Validates that a monotonically increasing timestamp does not exceed [`MAX_SAFE_INTEGER`] or
/// lie more than [`MAX_CLOCK_SKEW`] in the future.
#[cfg(feature = "server")]
pub(crate) fn check_monotonic_timestamp(timestamp: u64, now: u64) -> Result<()> {
    check_safe_integer(timestamp)?;
    if timestamp > now.saturating_add(MAX_CLOCK_SKEW) {
        return Err(ErrorKind::StaleTimestamp.into());
    }
    Ok(())
}

/// The identity key of a request it signed, such as a subscription or a v2 signed call, once
/// `signature`, by that key, of `message(identity key)` verifies and `timestamp` does not exceed
/// [`MAX_SAFE_INTEGER`] and is within [`MAX_CLOCK_SKEW`] of `now`, in milliseconds since the
/// Unix epoch.
pub(crate) fn verify_recent(
    identity_key: &[u8],
    signature: &[u8],
    timestamp: u64,
    now: u64,
    message: impl FnOnce(&x3dh::PublicKey) -> Result<Vec<u8>>,
) -> Result<x3dh::PublicKey> {
    check_safe_integer(timestamp)?;
    let identity_key = fixed(identity_key)?;
    xeddsa::XEdDSAPublicKey::new(&identity_key)?.verify(message(&identity_key)?, signature)?;
    if timestamp.abs_diff(now) > MAX_CLOCK_SKEW {
        return Err(ErrorKind::StaleTimestamp.into());
    }
    Ok(identity_key)
}
