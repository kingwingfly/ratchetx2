use core::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    error::CryptoError,
    key::{ChainKey, DH_KEY_LENGTH, DhPrivateKey, HeaderKey, RootKey, SecretKey},
};

/// Domain-separated HKDF info labels when mixing an additional secret (e.g. a post-quantum KEM
/// shared secret) into a DH-root ratchet step.
const HYBRID_ROOT_KEY_INFO: &[u8] = b"ratchetx2.v1/hybrid/RootKey";
const HYBRID_CHAIN_KEY_INFO: &[u8] = b"ratchetx2.v1/hybrid/ChainKey";
const HYBRID_HEADER_KEY_INFO: &[u8] = b"ratchetx2.v1/hybrid/HeaderKey";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct DhRootRatchet {
    root_key: RootKey,
    private_key: DhPrivateKey,
    /// - true: next step will update private key
    /// - false: next step will not update private key
    update_private_key: bool,
}

impl fmt::Debug for DhRootRatchet {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhRootRatchet")
            .field("update_private_key", &self.update_private_key)
            .finish_non_exhaustive()
    }
}

impl PartialEq for DhRootRatchet {
    fn eq(&self, other: &Self) -> bool {
        let shared = (
            self.private_key
                .diffie_hellman(&other.private_key.public_key()),
            other
                .private_key
                .diffie_hellman(&self.private_key.public_key()),
        );
        let root_eq = self.root_key.ct_eq(&other.root_key);
        let dh_eq = match shared {
            (Ok(a), Ok(b)) => a.ct_eq(b.as_slice()),
            _ => Choice::from(0),
        };
        bool::from(root_eq & dh_eq)
    }
}

impl DhRootRatchet {
    /// New a DhRootRatchet for Alice.
    pub fn alice(secret_key: SecretKey) -> Self {
        Self {
            root_key: secret_key,
            private_key: DhPrivateKey::generate(),
            update_private_key: false,
        }
    }

    /// New a DhRootRatchet for Bob.
    pub fn bob(secret_key: SecretKey, private_key: DhPrivateKey) -> Self {
        Self {
            root_key: secret_key,
            private_key,
            update_private_key: true,
        }
    }

    /// Get current public key.
    pub fn public_key(&self) -> [u8; DH_KEY_LENGTH] {
        self.private_key.public_key()
    }

    /// Whether the next step rotates the local DH private key.
    #[cfg(any(feature = "serde", feature = "prost"))]
    pub(crate) fn update_private_key(&self) -> bool {
        self.update_private_key
    }

    /// Perform a DH-root ratchet step, optionally mixing `extra_secret` into the HKDF with
    /// distinct domain separation when `extra_secret` is non-empty.
    ///
    /// On an invalid peer public key or RNG failure, returns an error and leaves the state
    /// unchanged.
    pub fn step_with(
        &mut self,
        public_key: &[u8],
        extra_secret: &[u8],
    ) -> Result<(ChainKey, HeaderKey), CryptoError> {
        // The DH always uses the current key; a step that updates the pair replaces it afterwards.
        let dh_shared = self.private_key.diffie_hellman(public_key)?;
        // Generate the replacement DH key pair (if needed) before mutating any state so errors
        // leave `self` untouched.
        let next_private_key = if self.update_private_key {
            Some(DhPrivateKey::try_generate()?)
        } else {
            None
        };

        let mut root_key = Zeroizing::new(RootKey::default());
        let mut chain_key = Zeroizing::new(ChainKey::default());
        let mut header_key = Zeroizing::new(HeaderKey::default());

        if extra_secret.is_empty() {
            let hkdf = Hkdf::<Sha256>::new(Some(&self.root_key), dh_shared.as_slice());
            hkdf.expand(b"RootKey", root_key.as_mut_slice()).unwrap();
            hkdf.expand(b"ChainKey", chain_key.as_mut_slice()).unwrap();
            hkdf.expand(b"HeaderKey", header_key.as_mut_slice())
                .unwrap();
        } else {
            let mut ikm = Zeroizing::new(Vec::with_capacity(DH_KEY_LENGTH + extra_secret.len()));
            ikm.extend_from_slice(dh_shared.as_slice());
            ikm.extend_from_slice(extra_secret);
            let hkdf = Hkdf::<Sha256>::new(Some(&self.root_key), ikm.as_slice());
            hkdf.expand(HYBRID_ROOT_KEY_INFO, root_key.as_mut_slice())
                .unwrap();
            hkdf.expand(HYBRID_CHAIN_KEY_INFO, chain_key.as_mut_slice())
                .unwrap();
            hkdf.expand(HYBRID_HEADER_KEY_INFO, header_key.as_mut_slice())
                .unwrap();
        }

        if let Some(next_private_key) = next_private_key {
            self.private_key = next_private_key;
        }
        self.update_private_key = !self.update_private_key;
        self.root_key.zeroize();
        self.root_key = *root_key;
        Ok((*chain_key, *header_key))
    }
}

#[cfg(feature = "rkyv")]
impl ArchivedDhRootRatchet {
    pub(crate) fn update_private_key(&self) -> bool {
        self.update_private_key
    }
}

#[cfg(feature = "prost")]
impl From<&DhRootRatchet> for crate::proto::DhRootRatchet {
    fn from(dh_root: &DhRootRatchet) -> Self {
        Self {
            root_key: dh_root.root_key.to_vec(),
            private_key: dh_root.private_key.as_bytes().to_vec(),
            update_private_key: dh_root.update_private_key,
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&crate::proto::DhRootRatchet> for DhRootRatchet {
    type Error = crate::error::MalformedState;

    fn try_from(dh_root: &crate::proto::DhRootRatchet) -> Result<Self, Self::Error> {
        Ok(Self {
            root_key: crate::proto::key(&dh_root.root_key)?,
            private_key: DhPrivateKey::from(crate::proto::key(&dh_root.private_key)?),
            update_private_key: dh_root.update_private_key,
        })
    }
}
