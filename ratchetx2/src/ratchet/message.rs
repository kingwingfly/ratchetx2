use crate::key::{ChainKey, HeaderKey, MessageKey};
use ring::hmac::{HMAC_SHA256, Key, sign};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub(super) struct MessageRatchet {
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
        let key = Key::new(HMAC_SHA256, &self.chain_key);
        let message_key = sign(&key, &[1]).as_ref().try_into().unwrap();
        self.chain_key = sign(&key, &[2]).as_ref().try_into().unwrap();
        message_key
    }
}
