#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

use core::fmt;

use curve25519_dalek::{EdwardsPoint, MontgomeryPoint};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Re-export curve25519_dalek.
pub use curve25519_dalek::Scalar;

/// XEdDSA errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Error {
    /// The DH public key is not 32 bytes, not on the curve, or not in the prime-order subgroup.
    #[error("Invalid DH public key.")]
    InvalidPublicKey,
    /// Signature verify failed.
    #[error("Signature verify failed.")]
    Signature,
}

type Result<T> = core::result::Result<T, Error>;

/// XEdDSA private key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct XEdDSAPrivateKey {
    montgomery_private_key: Scalar,
}

impl fmt::Debug for XEdDSAPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XEdDSAPrivateKey").finish_non_exhaustive()
    }
}

impl From<Scalar> for XEdDSAPrivateKey {
    /// New a XEdDSAPrivateKey with give Scalar (private key).
    fn from(montgomery_private_key: Scalar) -> Self {
        XEdDSAPrivateKey {
            montgomery_private_key,
        }
    }
}

impl XEdDSAPrivateKey {
    /// Generate a new XEdDSA private key.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut_slice()).expect("the system random number generator failed");
        XEdDSAPrivateKey {
            montgomery_private_key: Scalar::from_bytes_mod_order(*bytes),
        }
    }

    /// The XEdDSA public key for the key pair.
    pub fn compute_public_key(&self) -> XEdDSAPublicKey {
        XEdDSAPublicKey {
            montgomery_public_key: MontgomeryPoint::mul_base(&self.montgomery_private_key),
        }
    }

    /// DH with the X25519(Montgomery) private key for the key pair.
    ///
    /// The key pair is long-term, so this may be called any number of times.
    pub fn diffie_hellman(&self, peer_public_key: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
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
            (self.montgomery_private_key * peer_public_key).to_bytes(),
        ))
    }

    /// Sign with the Ed25519(Edwards) private key for the key pair.
    pub fn sign(&self, message: impl AsRef<[u8]>) -> Vec<u8> {
        let message = message.as_ref();
        let mut edwards_private_key = Zeroizing::new(self.montgomery_private_key);
        let edwards_public_key = EdwardsPoint::mul_base(&edwards_private_key);
        let mut edwards_public_key_y = edwards_public_key.compress().to_bytes();
        if edwards_public_key_y[31] >= 0x80 {
            *edwards_private_key = -self.montgomery_private_key;
            let edwards_public_key = EdwardsPoint::mul_base(&edwards_private_key);
            edwards_public_key_y = edwards_public_key.compress().to_bytes();
        }
        let mut random = Zeroizing::new([0; 64]);
        getrandom::fill(random.as_mut_slice()).expect("the system random number generator failed");
        // r = hash1(a || M || Z): hash1 prefixes 2^256 - 2, i.e. 0xFE then 31 0xFF bytes.
        let mut to_digest = Zeroizing::new(Vec::with_capacity(32 + 32 + message.len() + 64));
        to_digest.push(0xFE);
        to_digest.extend([0xFF; 31]);
        to_digest.extend(edwards_private_key.as_bytes());
        to_digest.extend(message);
        to_digest.extend(random.iter());
        let digest: Zeroizing<[u8; 64]> =
            Zeroizing::new(Sha512::digest(to_digest.as_slice()).into());
        let r = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&digest));
        let r_ = EdwardsPoint::mul_base(&r);
        let mut to_digest = r_.compress().as_bytes().to_vec();
        to_digest.extend(edwards_public_key_y);
        to_digest.extend(message);
        let h = Scalar::from_bytes_mod_order_wide(&Sha512::digest(&to_digest).into());
        let s = *r + h * *edwards_private_key;
        let mut res = r_.compress().as_bytes().to_vec();
        res.extend(s.as_bytes());
        res
    }
}

/// XEdDSA public key.
#[derive(Debug)]
pub struct XEdDSAPublicKey {
    montgomery_public_key: MontgomeryPoint,
}

impl XEdDSAPublicKey {
    /// Create a new XEdDSA public key from bytes; fails unless they are 32 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        Ok(XEdDSAPublicKey {
            montgomery_public_key: MontgomeryPoint(
                bytes.try_into().map_err(|_| Error::InvalidPublicKey)?,
            ),
        })
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
        // // Below is manual verification.
        // let r_check = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&signature[..32])
        //     .map_err(|_| Error::Signature)?
        //     .decompress()
        //     .ok_or(Error::Signature)?;
        // let mut to_digest = r_check.compress().as_bytes().to_vec();
        // to_digest.extend(edwards_public_key.compress().as_bytes());
        // to_digest.extend(message);
        // let h = Scalar::from_bytes_mod_order_wide(&Sha512::digest(&to_digest).into());
        // let s = Scalar::from_bytes_mod_order(signature[32..].try_into().unwrap());
        // // -h * edwards_public_key + s * basepoint == r_check
        // if EdwardsPoint::vartime_double_scalar_mul_basepoint(&-h, &edwards_public_key, &s)
        //     != r_check
        // {
        //     return Err(Error::Signature);
        // }
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
    fn signature_round_trip_and_redacted_debug() {
        let key = XEdDSAPrivateKey::generate();
        let public_key = XEdDSAPublicKey::new(key.compute_public_key().as_ref()).unwrap();
        let signature = key.sign("hello");
        public_key.verify("hello", &signature).unwrap();
        assert_eq!(
            public_key.verify("hellO", &signature),
            Err(Error::Signature)
        );
        assert_eq!(
            XEdDSAPublicKey::new(&[0; 31]).unwrap_err(),
            Error::InvalidPublicKey
        );
        assert_eq!(format!("{key:?}"), "XEdDSAPrivateKey { .. }");
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
        // Wrong length.
        assert_eq!(
            bob.diffie_hellman(&[9; 31]).unwrap_err(),
            Error::InvalidPublicKey
        );
    }
}
