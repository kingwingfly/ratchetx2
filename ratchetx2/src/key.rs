//! Key types.
#![allow(missing_docs)]

use core::fmt;

use curve25519_dalek::{MontgomeryPoint, constants::X25519_BASEPOINT};
use hkdf::Hkdf;
use sha2::Sha256;
use sha2::digest::{OutputSizeUser, typenum::Unsigned};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Ratchet;
use crate::error::CryptoError;

/// Length of the keys below: the output size of SHA-256, as HKDF-SHA256 and HMAC-SHA256
/// derive them.
pub const KEY_LENGTH: usize = <Sha256 as OutputSizeUser>::OutputSize::USIZE;
/// Length of X25519 keys, public or private, as curve25519-dalek encodes them.
pub const DH_KEY_LENGTH: usize = X25519_BASEPOINT.as_bytes().len();

/// The first shared RootKey.
pub type SecretKey = [u8; KEY_LENGTH];
pub type RootKey = [u8; KEY_LENGTH];
pub type MessageKey = [u8; KEY_LENGTH];
pub type ChainKey = [u8; KEY_LENGTH];
pub type HeaderKey = [u8; KEY_LENGTH];

/// X25519 private key of a DH ratchet key pair.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DhPrivateKey([u8; DH_KEY_LENGTH]);

impl DhPrivateKey {
    /// Generate a random private key.
    pub fn generate() -> Self {
        let mut key = Self([0; _]);
        getrandom::fill(&mut key.0).expect("the system random number generator failed");
        key
    }

    /// The X25519 public key for the key pair.
    pub fn public_key(&self) -> [u8; DH_KEY_LENGTH] {
        MontgomeryPoint::mul_base_clamped(self.0).to_bytes()
    }

    /// X25519 Diffie-Hellman with the peer's public key.
    ///
    /// Fails if the public key is not [`DH_KEY_LENGTH`] bytes or the shared secret is all
    /// zeros (a low-order public key).
    pub fn diffie_hellman(
        &self,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<[u8; DH_KEY_LENGTH]>, CryptoError> {
        let peer_public_key = MontgomeryPoint(peer_public_key.try_into().map_err(|_| CryptoError)?);
        let shared_secret = Zeroizing::new(peer_public_key.mul_clamped(self.0).to_bytes());
        if *shared_secret == [0; DH_KEY_LENGTH] {
            return Err(CryptoError);
        }
        Ok(shared_secret)
    }
}

impl From<[u8; DH_KEY_LENGTH]> for DhPrivateKey {
    /// Use the given bytes as the private key (clamped on use, per RFC 7748).
    fn from(bytes: [u8; DH_KEY_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for DhPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhPrivateKey").finish_non_exhaustive()
    }
}

/// Shared keys to initialize a [`Ratchet`].
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug))]
pub struct SharedKeys {
    /// The first shared RootKey.
    pub secret_key: SecretKey,
    pub header_key_alice: HeaderKey,
    pub header_key_bob: HeaderKey,
}

impl SharedKeys {
    /// Derive the shared keys from a shared secret, such as X3DH's SK:
    /// HKDF-SHA256 with [`KEY_LENGTH`] zero bytes as salt and `"ratchetx2.v1"` as info.
    pub fn from_secret(secret: &SecretKey) -> Self {
        let mut keys = Zeroizing::new([[0; KEY_LENGTH]; 3]);
        Hkdf::<Sha256>::new(Some(&[0; KEY_LENGTH]), secret)
            .expand(b"ratchetx2.v1", keys.as_flattened_mut())
            .expect("three keys are a valid HKDF-SHA256 output length");
        let [secret_key, header_key_alice, header_key_bob] = *keys;
        Self {
            secret_key,
            header_key_alice,
            header_key_bob,
        }
    }

    /// New a double-ratchet who sends message first.
    ///
    /// Fails if `public_key` (Bob's) is not a valid X25519 public key.
    pub fn alice(&self, public_key: &[u8]) -> Result<Ratchet, CryptoError> {
        Ratchet::alice(
            self.secret_key,
            public_key,
            self.header_key_alice,
            self.header_key_bob,
        )
    }

    /// New a double-ratchet who waits for the message first.
    pub fn bob(&self, private_key: DhPrivateKey) -> Ratchet {
        Ratchet::bob(
            self.secret_key,
            private_key,
            self.header_key_alice,
            self.header_key_bob,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_secret_derives_distinct_keys() {
        let keys = SharedKeys::from_secret(&[7; 32]);
        assert_ne!(keys.secret_key, keys.header_key_alice);
        assert_ne!(keys.header_key_alice, keys.header_key_bob);
        assert_ne!(
            SharedKeys::from_secret(&[8; 32]).secret_key,
            keys.secret_key
        );
    }
}
