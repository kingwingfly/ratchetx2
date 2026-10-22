#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod error;
#[cfg(feature = "grpc")]
pub mod grpc;
pub mod handshake;
pub mod mailbox;
pub mod signing;

pub use error::{Error, ErrorKind, Result};

/// Read a fixed-size bytes field, such as a 32-byte key.
///
/// Fails with [`ErrorKind::Malformed`] if it has another length.
pub fn fixed<const N: usize>(field: &[u8]) -> Result<[u8; N]> {
    field.try_into().map_err(|_| ErrorKind::Malformed.into())
}
