#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod error;
pub mod party;
pub mod transport;

/// Re-export tonic.
#[cfg(feature = "grpc")]
pub use tonic::transport::{Certificate, Identity, Uri};

pub use party::Party;
