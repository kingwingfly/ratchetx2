//! The party who participates in the E2EE chat.

use crate::{key::HeaderKey, transport::Transport};
use std::collections::HashMap;

use bincode::{Decode, Encode};

use crate::{Ratchetx2, key::MessageKey};

#[derive(Debug, Encode, Decode)]
struct Header {
    /// UnparsedPublicKey: AsRef<[u8]>
    public_key: Vec<u8>,
    /// Number of msg keys in revious msg chain block.
    pn: usize,
    /// Index in current msg chain block.
    n: usize,
}

/// The party who participates in the E2EE chat.
#[derive(Debug)]
pub struct Party<T: Transport> {
    ratchetx2: Ratchetx2,
    transport: T,
    /// (HeaderKey, N)
    skipped_mk: HashMap<(HeaderKey, usize), MessageKey>,
}

impl<T: Transport> Party<T> {
    /// New a party.
    pub fn new(ratchetx2: Ratchetx2, transport: T) -> Self {
        Self {
            ratchetx2,
            transport,
            skipped_mk: HashMap::new(),
        }
    }
}
