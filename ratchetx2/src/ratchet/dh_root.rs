use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::CryptoError,
    key::{ChainKey, DH_KEY_LENGTH, DhPrivateKey, HeaderKey, RootKey, SecretKey},
};

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
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

impl PartialEq for DhRootRatchet {
    fn eq(&self, other: &Self) -> bool {
        let shared = (
            self.private_key
                .diffie_hellman(&other.private_key.public_key()),
            other
                .private_key
                .diffie_hellman(&self.private_key.public_key()),
        );
        self.root_key == other.root_key && matches!(shared, (Ok(a), Ok(b)) if *a == *b)
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

    /// Perform ratchet step, update DH pair if needed, update RootKey, and return current ChainKey, next HeaderKey.
    ///
    /// On an invalid peer public key, returns an error and leaves the state unchanged.
    pub fn step(&mut self, public_key: &[u8]) -> Result<(ChainKey, HeaderKey), CryptoError> {
        // The DH always uses the current key; a step that updates the pair replaces it afterwards.
        let dh_shared = self.private_key.diffie_hellman(public_key)?;
        if self.update_private_key {
            self.private_key = DhPrivateKey::generate();
        }
        self.update_private_key = !self.update_private_key;
        let hkdf = Hkdf::<Sha256>::new(Some(&self.root_key), dh_shared.as_slice());
        let mut root_key = RootKey::default();
        hkdf.expand(b"RootKey", &mut root_key).unwrap();
        self.root_key = root_key;
        let mut chain_key = ChainKey::default();
        hkdf.expand(b"ChainKey", &mut chain_key).unwrap();
        let mut header_key = HeaderKey::default();
        hkdf.expand(b"HeaderKey", &mut header_key).unwrap();
        Ok((chain_key, header_key))
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
