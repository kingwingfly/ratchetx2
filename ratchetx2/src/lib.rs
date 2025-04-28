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
#[cfg(feature = "grpc")]
pub mod server;
pub mod transport;
#[cfg(feature = "grpc")]
pub mod x3dh;
pub mod xeddsa;

/// Re-export ring.
pub use ring::{agreement, rand};
/// Re-export tonic.
#[cfg(feature = "grpc")]
pub use tonic::transport::{Certificate, Identity, Uri};

pub use key::SharedKeys;
pub use party::Party;
pub use ratchet::Ratchetx2;
#[cfg(feature = "grpc")]
pub use server::RpcServer;
#[cfg(feature = "grpc")]
pub use x3dh::X3DHClient;
