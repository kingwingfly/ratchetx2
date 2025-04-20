#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod error;
pub mod key;
pub mod party;
pub mod ratchet;
pub mod transport;

pub use key::SharedKeys;
pub use ratchet::Ratchetx2;
pub use transport::Transport;
