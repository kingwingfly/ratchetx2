//! Key types.
#![allow(missing_docs)]

use core::fmt;

use curve25519_dalek::{MontgomeryPoint, constants::X25519_BASEPOINT};
use hkdf::Hkdf;
use sha2::{
    Sha256,
    digest::{OutputSizeUser, typenum::Unsigned},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;

/// Length of the keys below: the output size of SHA-256, as HKDF-SHA256 and HMAC-SHA256
/// derive them.
pub const KEY_LENGTH: usize = <Sha256 as OutputSizeUser>::OutputSize::USIZE;
/// Length of X25519 keys, public or private, as curve25519-dalek encodes them.
pub const DH_KEY_LENGTH: usize = X25519_BASEPOINT.as_bytes().len();

/// Check whether `bytes` is a canonical little-endian Curve25519 field encoding (`< 2^255 - 19`,
/// with bit 255 cleared).
pub(crate) fn is_canonical_dh_public_key(bytes: &[u8; DH_KEY_LENGTH]) -> bool {
    if bytes[DH_KEY_LENGTH - 1] & 0x80 != 0 {
        return false;
    }
    // p = 2^255 - 19 = [0xED, 0xFF, ..., 0xFF, 0x7F] in little-endian.
    if bytes[DH_KEY_LENGTH - 1] == 0x7F
        && bytes[1..DH_KEY_LENGTH - 1].iter().all(|&b| b == 0xFF)
        && bytes[0] >= 0xED
    {
        return false;
    }
    true
}

/// The first shared RootKey.
pub type SecretKey = [u8; KEY_LENGTH];
pub type RootKey = [u8; KEY_LENGTH];
pub type MessageKey = [u8; KEY_LENGTH];
pub type ChainKey = [u8; KEY_LENGTH];
pub type HeaderKey = [u8; KEY_LENGTH];

/// X25519 private key of a DH ratchet key pair.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DhPrivateKey([u8; DH_KEY_LENGTH]);

impl DhPrivateKey {
    /// Generate a random private key.
    pub fn generate() -> Self {
        Self::try_generate().expect("the system random number generator failed")
    }

    /// Generate a random private key, returning [`CryptoError`] if the OS RNG fails.
    pub fn try_generate() -> Result<Self, CryptoError> {
        let mut key = Self([0; _]);
        getrandom::fill(&mut key.0).map_err(|_| CryptoError)?;
        Ok(key)
    }

    /// Constant-time equality on the private key bytes.
    pub(crate) fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }

    /// The private key's bytes.
    #[cfg(feature = "prost")]
    pub(crate) fn as_bytes(&self) -> &[u8; DH_KEY_LENGTH] {
        &self.0
    }

    /// The X25519 public key for the key pair.
    pub fn public_key(&self) -> [u8; DH_KEY_LENGTH] {
        MontgomeryPoint::mul_base_clamped(self.0).to_bytes()
    }

    /// X25519 Diffie-Hellman with the peer's public key.
    ///
    /// Fails if the public key is not [`DH_KEY_LENGTH`] bytes, is non-canonical
    /// (bit 255 set or `>= 2^255 - 19`), is all zeros, or produces an all-zero shared
    /// secret (a low-order public key).
    pub fn diffie_hellman(
        &self,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<[u8; DH_KEY_LENGTH]>, CryptoError> {
        let peer_bytes: [u8; DH_KEY_LENGTH] =
            peer_public_key.try_into().map_err(|_| CryptoError)?;
        if !is_canonical_dh_public_key(&peer_bytes)
            || bool::from(peer_bytes.ct_eq(&[0; DH_KEY_LENGTH]))
        {
            return Err(CryptoError);
        }
        let peer_public_key = MontgomeryPoint(peer_bytes);
        let shared_secret = Zeroizing::new(peer_public_key.mul_clamped(self.0).to_bytes());
        if bool::from(shared_secret.ct_eq(&[0; DH_KEY_LENGTH])) {
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

/// Shared keys to initialize a [`Ratchet`](crate::Ratchet), with
/// [`Ratchet::alice`](crate::Ratchet::alice) and [`Ratchet::bob`](crate::Ratchet::bob).
#[derive(Zeroize, ZeroizeOnDrop)]
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
        let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(&[0; KEY_LENGTH]), secret);
        prk.zeroize();
        hkdf.expand(b"ratchetx2.v1", keys.as_flattened_mut())
            .expect("three keys are a valid HKDF-SHA256 output length");
        let [secret_key, header_key_alice, header_key_bob] = *keys;
        Self {
            secret_key,
            header_key_alice,
            header_key_bob,
        }
    }
}
