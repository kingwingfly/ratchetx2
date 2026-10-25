//! Some documents and examples are hidden here: [`document`].
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod document;
pub mod error;
pub mod key;
#[cfg(feature = "prost")]
pub mod proto;
pub mod ratchet;

pub use key::{DhPrivateKey, SharedKeys};
pub use ratchet::Ratchet;
