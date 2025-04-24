use crate::key::{ChainKey, HeaderKey, RootKey, SecretKey};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral};
use ring::hkdf::{HKDF_SHA256, Salt};
use ring::rand::SystemRandom;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub(super) struct DhRootRatchet {
    root_key: RootKey,
    #[zeroize(skip)]
    private_key: EphemeralPrivateKey,
    /// - true: next step will update private key
    /// - false: next step will not update private key
    update_private_key: bool,
}

impl PartialEq for DhRootRatchet {
    fn eq(&self, other: &Self) -> bool {
        let self_public_key =
            UnparsedPublicKey::new(&X25519, self.private_key.compute_public_key().unwrap());
        let other_public_key =
            UnparsedPublicKey::new(&X25519, other.private_key.compute_public_key().unwrap());
        let self_private_key = unsafe { core::mem::transmute_copy(&self.private_key) };
        let other_private_key = unsafe { core::mem::transmute_copy(&other.private_key) };
        self.root_key == other.root_key
            && agree_ephemeral(self_private_key, &other_public_key, |k| k.to_vec())
                == agree_ephemeral(other_private_key, &self_public_key, |k| k.to_vec())
    }
}

impl DhRootRatchet {
    /// New a DhRootRatchet for Alice.
    pub fn alice(secret_key: SecretKey) -> Self {
        Self {
            root_key: secret_key,
            private_key: EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).unwrap(),
            update_private_key: false,
        }
    }

    /// New a DhRootRatchet for Bob.
    pub fn bob(secret_key: SecretKey, private_key: EphemeralPrivateKey) -> Self {
        Self {
            root_key: secret_key,
            private_key,
            update_private_key: true,
        }
    }

    /// Get current publict key.
    pub fn public_key(&self) -> Vec<u8> {
        self.private_key
            .compute_public_key()
            .unwrap()
            .as_ref()
            .to_vec()
    }

    /// Perform ratchet step, update DH pair if needed, update RootKey, and return current ChainKey, next HeaderKey.
    pub fn step(&mut self, public_key: &[u8]) -> (ChainKey, HeaderKey) {
        let private_key = match self.update_private_key {
            true => core::mem::replace(
                &mut self.private_key,
                EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).unwrap(),
            ),
            // EphemeralPrivateKey is not `Clone`
            false => unsafe { core::mem::transmute_copy(&self.private_key) },
        };
        self.update_private_key = !self.update_private_key;
        agree_ephemeral(
            private_key,
            &UnparsedPublicKey::new(&X25519, public_key),
            |dh_shared| {
                let salt = Salt::new(HKDF_SHA256, &self.root_key);
                let prk = salt.extract(dh_shared);
                let okm = prk.expand(&[b"RootKey"], HKDF_SHA256).unwrap();
                let mut root_key = RootKey::default();
                okm.fill(&mut root_key).unwrap();
                self.root_key = root_key;
                let okm = prk.expand(&[b"ChainKey"], HKDF_SHA256).unwrap();
                let mut chain_key = ChainKey::default();
                okm.fill(&mut chain_key).unwrap();
                let okm = prk.expand(&[b"HeaderKey"], HKDF_SHA256).unwrap();
                let mut header_key = HeaderKey::default();
                okm.fill(&mut header_key).unwrap();
                (chain_key, header_key)
            },
        )
        .unwrap()
    }
}
