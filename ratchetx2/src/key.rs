//! Key types.
#![allow(missing_docs)]

use ring::agreement::EphemeralPrivateKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Ratchetx2;

/// The first shared RootKey.
pub type SecretKey = [u8; 32];
pub type RootKey = [u8; 32];
pub type MessageKey = [u8; 32];
pub type ChainKey = [u8; 32];
pub type HeaderKey = [u8; 32];

/// Shared keys to initialize Ratchetx2.
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug))]
pub struct SharedKeys {
    /// The first shared RootKey.
    pub secret_key: SecretKey,
    pub header_key_alice: HeaderKey,
    pub header_key_bob: HeaderKey,
}

impl SharedKeys {
    /// New a party who sends message first.
    pub fn alice(&self, public_key: impl AsRef<[u8]>) -> Ratchetx2 {
        Ratchetx2::alice(
            self.secret_key,
            public_key,
            self.header_key_alice,
            self.header_key_bob,
        )
    }

    /// New a party who waits for the message first.
    pub fn bob(&self, private_key: EphemeralPrivateKey) -> Ratchetx2 {
        Ratchetx2::bob(
            self.secret_key,
            private_key,
            self.header_key_alice,
            self.header_key_bob,
        )
    }
}
