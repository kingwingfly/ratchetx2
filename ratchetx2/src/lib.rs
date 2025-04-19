#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

mod error;
mod key;
mod ratchet;

const SKIP: usize = 1024;

pub use ratchet::Ratchetx2;
