//! [XEdDSA](https://signal.org/docs/specifications/xeddsa/) enables use of a single key pair format for both elliptic curve Diffie-Hellman and signatures.
//!
//! Based on Ed25519 and X25519.

use crate::error::{Error, Result};

use curve25519_dalek::{EdwardsPoint, MontgomeryPoint, Scalar};
use ring::digest::{SHA512, digest};
use ring::rand::{SecureRandom, SystemRandom, generate};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// XEdDSA private key.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct XEdDSAPrivateKey {
    montgomery_private_key: Scalar,
}

impl XEdDSAPrivateKey {
    /// Generate a new XEdDSA private key.
    pub fn generate(rng: &impl SecureRandom) -> Self {
        XEdDSAPrivateKey {
            montgomery_private_key: Scalar::from_bytes_mod_order(generate(rng).unwrap().expose()),
        }
    }

    /// The XEdDSA public key for the key pair.
    pub fn compute_public_key(&self) -> XEdDSAPublicKey {
        XEdDSAPublicKey {
            montgomery_public_key: MontgomeryPoint::mul_base(&self.montgomery_private_key),
        }
    }

    /// DH with the X25519(Montgomery) private key for the key pair.
    pub fn agree_ephemeral(&self, peer_public_key: &XEdDSAPublicKey) -> Vec<u8> {
        (self.montgomery_private_key * peer_public_key.montgomery_public_key)
            .to_bytes()
            .to_vec()
    }

    /// Sign with the Ed25519(Edwards) private key for the key pair.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let edwards_public_key = EdwardsPoint::mul_base(&self.montgomery_private_key);
        let edwards_public_key_y = edwards_public_key.compress().to_bytes();
        let edwards_private_key = if edwards_public_key_y[31] >= 0x80 {
            -self.montgomery_private_key
        } else {
            self.montgomery_private_key
        };
        let mut to_digest = vec![0xFF; 32];
        to_digest.extend(edwards_private_key.to_bytes().to_vec());
        to_digest.extend(msg);
        to_digest.extend(generate::<[u8; 64]>(&SystemRandom::new()).unwrap().expose());
        let r = Scalar::from_bytes_mod_order_wide(
            &digest(&SHA512, &to_digest).as_ref().try_into().unwrap(),
        );
        let r_ = EdwardsPoint::mul_base(&r);
        let mut to_digest = r_.compress().to_bytes().to_vec();
        to_digest.extend(edwards_public_key_y);
        to_digest.extend(msg);
        let h = Scalar::from_bytes_mod_order_wide(
            &digest(&SHA512, &to_digest).as_ref().try_into().unwrap(),
        );
        let s = r + h * edwards_private_key;
        let mut res = r_.compress().to_bytes().to_vec();
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
    /// Create a new XEdDSA public key from bytes.
    pub fn new(bytes: &[u8]) -> Self {
        XEdDSAPublicKey {
            montgomery_public_key: MontgomeryPoint(bytes.try_into().unwrap()),
        }
    }

    /// Verify with the Ed25519(Edwards) public key for the key pair.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let edwards_point = self
            .montgomery_public_key
            .to_edwards(0)
            .ok_or(Error::Signature)?;
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            edwards_point.compress().as_bytes(),
        )
        .verify(message, signature)
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
    use super::*;

    #[test]
    fn xdedsa() {
        let xdedsa = XEdDSAPrivateKey::generate(&SystemRandom::new());
        let signature = xdedsa.sign(b"hello world");
        let public_key = xdedsa.compute_public_key();
        public_key.verify(b"hello world", &signature).unwrap();
        assert!(public_key.verify(b"goodbye world", &signature).is_err());
    }
}
