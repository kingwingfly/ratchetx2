#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod error;
pub mod party;

/// The message format, generated from `proto/party.proto` (package `party.v1`), and with the
/// `prost` feature the party's state, from `proto/party_state.proto`, zeroized on drop.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/party.v1.rs"));

    #[cfg(feature = "prost")]
    mod state {
        use core::fmt;

        use super::{MessageKey, Party, SkippedChain};

        impl fmt::Debug for Party {
            /// Shows no keys.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("Party")
                    .field("previous_chain_length", &self.previous_chain_length)
                    .field("message_number_sender", &self.message_number_sender)
                    .field("message_number_receiver", &self.message_number_receiver)
                    .field("skipped_chains", &self.skipped_chains.len())
                    .finish_non_exhaustive()
            }
        }

        impl fmt::Debug for SkippedChain {
            /// Shows no keys.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("SkippedChain")
                    .field("message_keys", &self.message_keys.len())
                    .field("age", &self.age)
                    .finish_non_exhaustive()
            }
        }

        impl fmt::Debug for MessageKey {
            /// Shows no key.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("MessageKey")
                    .field("message_number", &self.message_number)
                    .finish_non_exhaustive()
            }
        }
    }
}

pub use party::Party;
pub use proto::EncryptedMessage;
