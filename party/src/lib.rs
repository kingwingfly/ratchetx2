#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod error;
pub mod party;

/// The message format, generated from `proto/party.proto` (package `party.v1`).
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/party.v1.rs"));
}

pub use party::Party;
pub use proto::EncryptedMessage;
