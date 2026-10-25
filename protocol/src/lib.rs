#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod attachment;
#[cfg(feature = "connect")]
pub mod connect;
pub mod error;
pub mod handshake;
pub mod mailbox;
pub mod notify;

pub use error::{Error, ErrorKind, Result};

/// How far, in milliseconds, the timestamp of a subscription or an upload may be from the
/// server's clock.
pub const MAX_CLOCK_SKEW: u64 = 5 * 60 * 1000;

/// Read a fixed-size bytes field, such as a 32-byte key.
///
/// Fails with [`ErrorKind::Malformed`] if it has another length.
pub fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| ErrorKind::Malformed.into())
}
