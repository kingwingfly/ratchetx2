//! Key types.
#![allow(missing_docs)]

use core::fmt;

use curve25519_dalek::MontgomeryPoint;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Ratchetx2;
use crate::error::CryptoError;

/// The first shared RootKey.
pub type SecretKey = [u8; 32];
pub type RootKey = [u8; 32];
pub type MessageKey = [u8; 32];
pub type ChainKey = [u8; 32];
pub type HeaderKey = [u8; 32];

/// X25519 private key of a DH ratchet key pair.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DhPrivateKey([u8; 32]);

impl DhPrivateKey {
    /// Generate a random private key.
    pub fn generate() -> Self {
        let mut key = Self([0; 32]);
        getrandom::fill(&mut key.0).expect("the system random number generator failed");
        key
    }

    /// The X25519 public key for the key pair.
    pub fn public_key(&self) -> [u8; 32] {
        MontgomeryPoint::mul_base_clamped(self.0).to_bytes()
    }

    /// X25519 Diffie-Hellman with the peer's public key.
    ///
    /// Fails if the public key is not 32 bytes or the shared secret is all zeros
    /// (a low-order public key).
    pub fn diffie_hellman(&self, peer_public_key: &[u8]) -> Result<[u8; 32], CryptoError> {
        let peer_public_key = MontgomeryPoint(peer_public_key.try_into().map_err(|_| CryptoError)?);
        let shared_secret = peer_public_key.mul_clamped(self.0).to_bytes();
        if shared_secret == [0; 32] {
            return Err(CryptoError);
        }
        Ok(shared_secret)
    }
}

impl From<[u8; 32]> for DhPrivateKey {
    /// Use the given bytes as the private key (clamped on use, per RFC 7748).
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for DhPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhPrivateKey").finish_non_exhaustive()
    }
}

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
    /// New a double-ratchet who sends message first.
    pub fn alice(&self, public_key: &[u8]) -> Ratchetx2 {
        Ratchetx2::alice(
            self.secret_key,
            public_key,
            self.header_key_alice,
            self.header_key_bob,
        )
    }

    /// New a double-ratchet who waits for the message first.
    pub fn bob(&self, private_key: DhPrivateKey) -> Ratchetx2 {
        Ratchetx2::bob(
            self.secret_key,
            private_key,
            self.header_key_alice,
            self.header_key_bob,
        )
    }
}
