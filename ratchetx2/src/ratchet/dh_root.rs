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
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct DhRootRatchet {
    root_key: RootKey,
    private_key: DhPrivateKey,
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
#[serde(rename = "DhRootRatchet")]
pub(crate) struct DhRootRatchetWireRef<'a> {
    root_key: &'a RootKey,
    private_key: &'a DhPrivateKey,
    update_private_key: bool,
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename = "DhRootRatchet")]
pub(crate) struct DhRootRatchetWire {
    root_key: RootKey,
    private_key: DhPrivateKey,
    update_private_key: bool,
}

impl fmt::Debug for DhRootRatchet {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhRootRatchet").finish_non_exhaustive()
    }
}

impl PartialEq for DhRootRatchet {
    fn eq(&self, other: &Self) -> bool {
        bool::from(
            self.root_key.ct_eq(&other.root_key) & self.private_key.ct_eq(&other.private_key),
        )
    }
}

impl Eq for DhRootRatchet {}

impl DhRootRatchet {
    /// New a DhRootRatchet for Alice.
    pub fn alice(secret_key: SecretKey) -> Self {
        Self {
            root_key: secret_key,
            private_key: DhPrivateKey::generate(),
        }
    }

    /// New a DhRootRatchet for Bob.
    pub fn bob(secret_key: SecretKey, private_key: DhPrivateKey) -> Self {
        Self {
            root_key: secret_key,
            private_key,
        }
    }

    /// Get current public key.
    pub fn public_key(&self) -> [u8; DH_KEY_LENGTH] {
        self.private_key.public_key()
    }

    /// Constant-time root-key equality for peer-pairing checks.
    pub(crate) fn root_key_ct_eq(&self, other: &Self) -> Choice {
        self.root_key.ct_eq(&other.root_key)
    }

    /// Perform a DH-root ratchet step, optionally mixing `extra_secret` into the HKDF with
    /// distinct domain separation when `extra_secret` is non-empty.
    ///
    /// When `rotate_private_key` is `true`, replaces the local DH keypair after computing the DH
    /// output with the current key. On an invalid peer public key or RNG failure, returns an error
    /// and leaves the state unchanged.
    pub fn step_with(
        &mut self,
        public_key: &[u8],
        extra_secret: &[u8],
        rotate_private_key: bool,
    ) -> Result<(Zeroizing<ChainKey>, Zeroizing<HeaderKey>), CryptoError> {
        // The DH always uses the current key; a step that updates the pair replaces it afterwards.
        let dh_shared = self.private_key.diffie_hellman(public_key)?;
        // Generate the replacement DH key pair (if needed) before mutating any state so errors
        // leave `self` untouched.
        let next_private_key = if rotate_private_key {
            Some(DhPrivateKey::try_generate()?)
        } else {
            None
        };

        let mut root_key = Zeroizing::new(RootKey::default());
        let mut chain_key = Zeroizing::new(ChainKey::default());
        let mut header_key = Zeroizing::new(HeaderKey::default());

        if extra_secret.is_empty() {
            let (mut prk, hkdf) =
                Hkdf::<Sha256>::extract(Some(&self.root_key), dh_shared.as_slice());
            prk.zeroize();
            hkdf.expand(b"RootKey", root_key.as_mut_slice()).unwrap();
            hkdf.expand(b"ChainKey", chain_key.as_mut_slice()).unwrap();
            hkdf.expand(b"HeaderKey", header_key.as_mut_slice())
                .unwrap();
        } else {
            let mut ikm = Zeroizing::new(Vec::with_capacity(DH_KEY_LENGTH + extra_secret.len()));
            ikm.extend_from_slice(dh_shared.as_slice());
            ikm.extend_from_slice(extra_secret);
            let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(&self.root_key), ikm.as_slice());
            prk.zeroize();
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
        self.root_key.zeroize();
        self.root_key = *root_key;
        Ok((chain_key, header_key))
    }

    #[cfg(feature = "serde")]
    pub(crate) fn as_wire(&self, update_private_key: bool) -> DhRootRatchetWireRef<'_> {
        DhRootRatchetWireRef {
            root_key: &self.root_key,
            private_key: &self.private_key,
            update_private_key,
        }
    }

    #[cfg(feature = "serde")]
    pub(crate) fn from_wire(wire: DhRootRatchetWire) -> (Self, bool) {
        let update_private_key = wire.update_private_key;
        let dh_root = Self {
            root_key: wire.root_key,
            private_key: wire.private_key.clone(),
        };
        (dh_root, update_private_key)
    }

    #[cfg(feature = "prost")]
    pub(crate) fn to_proto(&self, update_private_key: bool) -> crate::proto::DhRootRatchet {
        crate::proto::DhRootRatchet {
            root_key: self.root_key.to_vec(),
            private_key: self.private_key.as_bytes().to_vec(),
            update_private_key,
        }
    }

    #[cfg(feature = "prost")]
    pub(crate) fn from_proto(
        dh_root: &crate::proto::DhRootRatchet,
    ) -> Result<(Self, bool), crate::error::MalformedState> {
        let root_key = Zeroizing::new(crate::proto::key(&dh_root.root_key)?);
        let priv_bytes = Zeroizing::new(crate::proto::key(&dh_root.private_key)?);
        Ok((
            Self {
                root_key: *root_key,
                private_key: DhPrivateKey::from(*priv_bytes),
            },
            dh_root.update_private_key,
        ))
    }
}
