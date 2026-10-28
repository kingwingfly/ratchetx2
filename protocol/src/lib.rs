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
pub mod mailbox;
pub mod notify;

pub use error::{Error, ErrorKind, Result};

/// How far, in milliseconds, the timestamp of a subscription may be from the server's clock, as a
/// signature would otherwise stay good forever. Clients sign them with the server's time, as its
/// responses tell it, since a device's clock may be off.
pub const MAX_CLOCK_SKEW: u64 = 5 * 60 * 1000;

/// Read a fixed-size bytes field, such as a 32-byte key.
///
/// Fails with [`ErrorKind::Malformed`] if it has another length.
pub fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| ErrorKind::Malformed.into())
}

/// The identity key of a request it signed, such as a subscription or an upload's start, once
/// `signature`, by that key, of `message(identity key)` verifies and `timestamp` is within
/// [`MAX_CLOCK_SKEW`] of `now`, in milliseconds since the Unix epoch.
fn verify_recent(
    identity_key: &[u8],
    signature: &[u8],
    timestamp: u64,
    now: u64,
    message: impl FnOnce(&x3dh::PublicKey) -> Vec<u8>,
) -> Result<x3dh::PublicKey> {
    let identity_key = fixed(identity_key)?;
    xeddsa::XEdDSAPublicKey::new(&identity_key)?.verify(message(&identity_key), signature)?;
    if timestamp.abs_diff(now) > MAX_CLOCK_SKEW {
        return Err(ErrorKind::StaleTimestamp.into());
    }
    Ok(identity_key)
}
