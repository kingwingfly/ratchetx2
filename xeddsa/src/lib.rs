#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

use core::fmt;

/// Re-export curve25519_dalek.
pub use curve25519_dalek::Scalar;
use curve25519_dalek::{EdwardsPoint, MontgomeryPoint, constants::X25519_BASEPOINT};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
use subtle::{Choice, ConditionallyNegatable};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length of a public key, a Montgomery u-coordinate as curve25519-dalek encodes it. A DH
/// output is as long.
pub const PUBLIC_KEY_LENGTH: usize = X25519_BASEPOINT.as_bytes().len();
/// Length of a signature, which is an Ed25519 signature.
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;
/// Length of a private key, a scalar as curve25519-dalek encodes it.
pub const PRIVATE_KEY_LENGTH: usize = Scalar::ZERO.as_bytes().len();

/// hash1's prefix, 2^b - 2 in b bits (little-endian): 0xFE, then 0xFF bytes up to the length
/// of an encoded Ed25519 point.
const HASH1_PREFIX: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = {
    let mut prefix = [0xFF; ed25519_dalek::PUBLIC_KEY_LENGTH];
    prefix[0] = 0xFE;
    prefix
};

/// XEdDSA errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Error {
    /// The DH public key is not [`PUBLIC_KEY_LENGTH`] bytes, not on the curve, or not in the
    /// prime-order subgroup.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// The signature does not verify.
    #[error("invalid signature")]
    Signature,
}

/// Result type with [`Error`](enum@Error).
pub type Result<T> = core::result::Result<T, Error>;

/// XEdDSA private key.
///
/// With the `serde` or `rkyv` feature, it serializes as its scalar, like
/// [`to_bytes`](Self::to_bytes): keep the output secret.
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct XEdDSAPrivateKey {
    #[cfg_attr(feature = "rkyv", rkyv(with = ScalarDef))]
    private_key: Scalar,
}

/// Archives a [`Scalar`] as its canonical bytes.
#[cfg(feature = "rkyv")]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(remote = Scalar)]
struct ScalarDef {
    #[rkyv(getter = Scalar::to_bytes)]
    bytes: [u8; PRIVATE_KEY_LENGTH],
}

#[cfg(feature = "rkyv")]
impl From<ScalarDef> for Scalar {
    fn from(scalar: ScalarDef) -> Self {
        Scalar::from_bytes_mod_order(scalar.bytes)
    }
}

impl fmt::Debug for XEdDSAPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XEdDSAPrivateKey").finish_non_exhaustive()
    }
}

impl From<Scalar> for XEdDSAPrivateKey {
    /// New a XEdDSAPrivateKey with give Scalar (private key).
    fn from(private_key: Scalar) -> Self {
        XEdDSAPrivateKey { private_key }
    }
}

impl XEdDSAPrivateKey {
    /// Generate a new XEdDSA private key.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0; _]);
        getrandom::fill(bytes.as_mut_slice()).expect("the system random number generator failed");
        XEdDSAPrivateKey {
            private_key: Scalar::from_bytes_mod_order(*bytes),
        }
    }

    /// The private key's bytes, its scalar's canonical encoding, e.g. to keep it between runs:
    /// keep them secret.
    pub fn to_bytes(&self) -> Zeroizing<[u8; PRIVATE_KEY_LENGTH]> {
        Zeroizing::new(self.private_key.to_bytes())
    }

    /// The private key whose [`to_bytes`](Self::to_bytes) are `bytes`; `None` unless they are a
    /// canonical scalar encoding.
    pub fn from_bytes(bytes: [u8; PRIVATE_KEY_LENGTH]) -> Option<Self> {
        Scalar::from_canonical_bytes(bytes)
            .into_option()
            .map(|private_key| Self { private_key })
    }

    /// The XEdDSA public key for the key pair.
    pub fn compute_public_key(&self) -> XEdDSAPublicKey {
        XEdDSAPublicKey {
            montgomery_public_key: MontgomeryPoint::mul_base(&self.private_key),
        }
    }

    /// DH, as X25519, with the key pair's private key.
    ///
    /// The key pair is long-term, so this may be called any number of times.
    pub fn diffie_hellman(
        &self,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<[u8; PUBLIC_KEY_LENGTH]>> {
        let peer_public_key = MontgomeryPoint(
            peer_public_key
                .try_into()
                .map_err(|_| Error::InvalidPublicKey)?,
        );
        // The private scalar is not clamped, so a point on the twist or with a small-order
        // component would let the peer learn the private key modulo the cofactor.
        if !peer_public_key
            .to_edwards(0)
            .is_some_and(|point| point.is_torsion_free())
        {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Zeroizing::new(
            (self.private_key * peer_public_key).to_bytes(),
        ))
    }

    /// Sign, as Ed25519, with the key pair's private key.
    pub fn sign(&self, message: impl AsRef<[u8]>) -> [u8; SIGNATURE_LENGTH] {
        let message = message.as_ref();
        let mut private_key = Zeroizing::new(self.private_key);
        let mut edwards_public_key_y = EdwardsPoint::mul_base(&private_key).compress().to_bytes();
        // The sign bit is the top bit of the last byte. The verifier takes the Edwards point
        // with sign 0, so if ours is 1, negate the key: -A = (-x, y) has the same y and sign 0.
        // Branch-free, as the sign bit is secret.
        let sign = Choice::from(edwards_public_key_y[ed25519_dalek::PUBLIC_KEY_LENGTH - 1] >> 7);
        private_key.conditional_negate(sign);
        edwards_public_key_y[ed25519_dalek::PUBLIC_KEY_LENGTH - 1] &= 0x7F;
        // Z: 64 random bytes, per the XEdDSA spec.
        let mut random = Zeroizing::new([0; 64]);
        getrandom::fill(random.as_mut_slice()).expect("the system random number generator failed");
        // r = hash1(a || M || Z)
        let mut to_digest = Zeroizing::new(Vec::with_capacity(
            HASH1_PREFIX.len() + private_key.as_bytes().len() + message.len() + random.len(),
        ));
        to_digest.extend(HASH1_PREFIX);
        to_digest.extend(private_key.as_bytes());
        to_digest.extend(message);
        to_digest.extend(random.iter());
        let digest: Zeroizing<[u8; _]> =
            Zeroizing::new(Sha512::digest(to_digest.as_slice()).into());
        let r = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&digest));
        let r_ = EdwardsPoint::mul_base(&r).compress();
        let mut to_digest = r_.to_bytes().to_vec();
        to_digest.extend(edwards_public_key_y);
        to_digest.extend(message);
        let h = Scalar::from_bytes_mod_order_wide(&Sha512::digest(&to_digest).into());
        let s = *r + h * *private_key;
        Signature::from_components(r_.to_bytes(), s.to_bytes()).to_bytes()
    }
}

/// XEdDSA public key.
#[derive(Debug)]
pub struct XEdDSAPublicKey {
    montgomery_public_key: MontgomeryPoint,
}

impl XEdDSAPublicKey {
    /// Create a new XEdDSA public key from bytes; fails unless they are [`PUBLIC_KEY_LENGTH`]
    /// bytes.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        Ok(XEdDSAPublicKey {
            montgomery_public_key: MontgomeryPoint(
                bytes.try_into().map_err(|_| Error::InvalidPublicKey)?,
            ),
        })
    }

    /// The public key's bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.montgomery_public_key.to_bytes()
    }

    /// Verify with the Ed25519(Edwards) public key for the key pair.
    pub fn verify(&self, message: impl AsRef<[u8]>, signature: &[u8]) -> Result<()> {
        let signature = Signature::from_slice(signature).map_err(|_| Error::Signature)?;
        let edwards_public_key = self
            .montgomery_public_key
            .to_edwards(0)
            .ok_or(Error::Signature)?;
        // Use ed25519-dalek's implementation of Ed25519 verification.
        VerifyingKey::from_bytes(edwards_public_key.compress().as_bytes())
            .and_then(|key| key.verify(message.as_ref(), &signature))
            .map_err(|_| Error::Signature)?;
        Ok(())
    }
}

impl AsRef<[u8]> for XEdDSAPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.montgomery_public_key.as_bytes()
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY};

    use super::*;

    /// Encoding of an Ed25519 point of order 8.
    const ORDER_8: [u8; 32] = [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ];

    #[test]
    fn diffie_hellman_known_answer() {
        let alice = XEdDSAPrivateKey::from(Scalar::from_bytes_mod_order([11; 32]));
        let bob = XEdDSAPrivateKey::from(Scalar::from_bytes_mod_order([13; 32]));
        let shared = alice
            .diffie_hellman(bob.compute_public_key().as_ref())
            .unwrap();
        let expected = "67d234661315d06ead7a5cf135ffaaba27ac631d757d724f25900c5d1a196344";
        let hex: String = shared.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
    }

    #[test]
    fn signs_whatever_the_edwards_sign_bit() {
        // k and -k share a public key, and their Edwards public keys have opposite sign bits.
        let key = Scalar::from_bytes_mod_order([7; 32]);
        let public_key = XEdDSAPrivateKey::from(key).compute_public_key();
        for key in [key, -key] {
            let key = XEdDSAPrivateKey::from(key);
            assert_eq!(key.compute_public_key().to_bytes(), public_key.to_bytes());
            public_key.verify("hello", &key.sign("hello")).unwrap();
        }
    }

    #[test]
    fn diffie_hellman_rejects_points_outside_the_prime_order_subgroup() {
        let bob = XEdDSAPrivateKey::generate();
        let order_8 = CompressedEdwardsY(ORDER_8).decompress().unwrap();
        assert!(order_8.is_small_order());
        let honest = ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order([3; 32]);
        assert!(
            bob.diffie_hellman(honest.to_montgomery().as_bytes())
                .is_ok()
        );

        // An honest-looking key plus a small-order component (small-subgroup attack).
        let attack = (honest + order_8).to_montgomery();
        assert_eq!(
            bob.diffie_hellman(attack.as_bytes()).unwrap_err(),
            Error::InvalidPublicKey
        );
        // Small-order points themselves.
        let order_8 = order_8.to_montgomery();
        assert_eq!(
            bob.diffie_hellman(order_8.as_bytes()).unwrap_err(),
            Error::InvalidPublicKey
        );
        assert_eq!(
            bob.diffie_hellman(&[0; 32]).unwrap_err(),
            Error::InvalidPublicKey
        );
        // A point on the twist, not on the curve.
        let twist = (2..=255)
            .map(|u| {
                let mut bytes = [0; 32];
                bytes[0] = u;
                bytes
            })
            .find(|bytes| MontgomeryPoint(*bytes).to_edwards(0).is_none())
            .unwrap();
        assert_eq!(
            bob.diffie_hellman(&twist).unwrap_err(),
            Error::InvalidPublicKey
        );
    }
}
