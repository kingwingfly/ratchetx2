use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::key::{ChainKey, HeaderKey, MessageKey};

#[derive(Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct MessageRatchet {
    chain_key: ChainKey,
    pub header_key: HeaderKey,
    pub next_header_key: HeaderKey,
}

impl MessageRatchet {
    /// New a MessageRatchet.
    pub fn from_key(
        chain_key: ChainKey,
        header_key: HeaderKey,
        next_header_key: HeaderKey,
    ) -> Self {
        Self {
            chain_key,
            header_key,
            next_header_key,
        }
    }

    /// New a empty MessageRatchet, supposed to be only used in initialization.
    pub fn empty(next_header_key: HeaderKey) -> Self {
        Self {
            chain_key: ChainKey::default(),
            header_key: HeaderKey::default(),
            next_header_key,
        }
    }

    /// Perform ratchet step, update ChainKey, and return MessageKey.
    pub fn step(&mut self) -> MessageKey {
        let message_key = hmac_sha256(&self.chain_key, &[1]);
        self.chain_key = hmac_sha256(&self.chain_key, &[2]);
        message_key
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
