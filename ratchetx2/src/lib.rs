//! Some documents and examples are hidden here: [`document`].
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod document;
pub mod error;
pub mod key;
pub mod party;
pub mod ratchet;
pub mod server;
pub mod transport;
pub mod x3dh;
pub mod xeddsa;

/// Re-export.
pub use ring::{agreement, rand};

pub use key::SharedKeys;
pub use party::Party;
pub use ratchet::Ratchetx2;
pub use server::RpcServer;
pub use x3dh::X3DHClient;
