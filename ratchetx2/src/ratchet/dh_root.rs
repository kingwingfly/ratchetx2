use crate::key::{ChainKey, DhPrivateKey, HeaderKey, RootKey, SecretKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct DhRootRatchet {
    root_key: RootKey,
    private_key: DhPrivateKey,
    /// - true: next step will update private key
    /// - false: next step will not update private key
    update_private_key: bool,
}

impl PartialEq for DhRootRatchet {
    fn eq(&self, other: &Self) -> bool {
        self.root_key == other.root_key
            && self
                .private_key
                .diffie_hellman(&other.private_key.public_key())
                == other
                    .private_key
                    .diffie_hellman(&self.private_key.public_key())
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

    /// Get current publict key.
    pub fn public_key(&self) -> Vec<u8> {
        self.private_key.public_key().to_vec()
    }

    /// Perform ratchet step, update DH pair if needed, update RootKey, and return current ChainKey, next HeaderKey.
    pub fn step(&mut self, public_key: &[u8]) -> (ChainKey, HeaderKey) {
        let old_private_key;
        let private_key = match self.update_private_key {
            true => {
                old_private_key =
                    core::mem::replace(&mut self.private_key, DhPrivateKey::generate());
                &old_private_key
            }
            false => &self.private_key,
        };
        self.update_private_key = !self.update_private_key;
        let dh_shared = Zeroizing::new(private_key.diffie_hellman(public_key).unwrap());
        let hkdf = Hkdf::<Sha256>::new(Some(&self.root_key), dh_shared.as_slice());
        let mut root_key = RootKey::default();
        hkdf.expand(b"RootKey", &mut root_key).unwrap();
        self.root_key = root_key;
        let mut chain_key = ChainKey::default();
        hkdf.expand(b"ChainKey", &mut chain_key).unwrap();
        let mut header_key = HeaderKey::default();
        hkdf.expand(b"HeaderKey", &mut header_key).unwrap();
        (chain_key, header_key)
    }
}
