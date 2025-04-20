//! Key types.
#![allow(missing_docs)]

use crate::Ratchetx2;

/// The first shared RootKey.
pub type SecretKey = [u8; 32];
pub type RootKey = [u8; 32];
pub type MessageKey = [u8; 32];
pub type ChainKey = [u8; 32];
pub type HeaderKey = [u8; 32];

/// Shared keys to initialize Ratchetx2.
pub struct SharedKeys {
    /// The first shared RootKey.
    pub secret_key: SecretKey,
    pub header_key_alice: HeaderKey,
    pub header_key_bob: HeaderKey,
}

impl SharedKeys {
    /// New Alice and Bob.
    pub fn init(&self) -> (Ratchetx2, Ratchetx2) {
        let bob = self.bob();
        let alice = self.alice(bob.public_key());
        (alice, bob)
    }

    /// New a party who sends message first.
    pub fn alice(&self, public_key: Vec<u8>) -> Ratchetx2 {
        Ratchetx2::alice(
            self.secret_key,
            public_key,
            self.header_key_alice,
            self.header_key_bob,
        )
    }

    /// New a party who waits for the message first.
    pub fn bob(&self) -> Ratchetx2 {
        Ratchetx2::bob(self.secret_key, self.header_key_alice, self.header_key_bob)
    }
}
