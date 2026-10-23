#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod error;

use core::fmt;
use std::collections::{HashMap, VecDeque};

pub use error::{Error, ErrorKind, Result};
use hkdf::Hkdf;
use sha2::{
    Sha256,
    digest::{OutputSizeUser, typenum::Unsigned},
};
use x25519_dalek::SharedSecret;
/// Re-export x25519_dalek's private key, which [`LocalPrekeys::accept`] returns.
pub use x25519_dalek::StaticSecret;
use xeddsa::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, XEdDSAPrivateKey, XEdDSAPublicKey};
use zeroize::Zeroizing;

/// An X25519 (or XEdDSA identity) public key.
pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];
/// An XEdDSA signature.
pub type Signature = [u8; SIGNATURE_LENGTH];

/// Length of the shared secret key (SK), as the X3DH spec sets it.
pub const SECRET_KEY_LENGTH: usize = 32;
/// Length of SHA-256's output, and so of the HKDF salt.
const HASH_LENGTH: usize = <Sha256 as OutputSizeUser>::OutputSize::USIZE;

/// The info of the KDF deriving the shared secret key.
const INFO: &[u8] = b"x3dh.v1";

/// How many generations of prekeys [`LocalPrekeys`] keeps: the latest, and the one before it
/// for initial messages that were on their way when the latest was published.
pub const KEPT_GENERATIONS: usize = 2;

/// Bob's prekeys, as Alice receives them to start a session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct PrekeyBundle {
    /// Bob's signed prekey.
    pub signed_prekey: PublicKey,
    /// Bob's identity key's signature of `signed_prekey`.
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub signed_prekey_signature: Signature,
    /// One of Bob's one-time prekeys, if any is left.
    pub one_time_prekey: Option<PublicKey>,
}

/// Alice's initial message to Bob, which lets him derive the same shared secret.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct InitialMessage {
    /// Alice's identity key.
    pub identity_key: PublicKey,
    /// Alice's ephemeral key.
    pub ephemeral_key: PublicKey,
    /// Bob's signed prekey that Alice used.
    pub signed_prekey: PublicKey,
    /// Bob's one-time prekey that Alice used, if any.
    pub one_time_prekey: Option<PublicKey>,
}

/// The outcome of X3DH, the same for Alice and Bob.
pub struct Agreement {
    /// The shared secret key (SK).
    pub secret_key: Zeroizing<[u8; SECRET_KEY_LENGTH]>,
    /// The associated data (AD): Alice's identity key, then Bob's.
    pub associated_data: [u8; 2 * PUBLIC_KEY_LENGTH],
}

impl fmt::Debug for Agreement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agreement")
            .field("associated_data", &self.associated_data)
            .finish_non_exhaustive()
    }
}

/// Keys Bob publishes after [`LocalPrekeys::generate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPrekeys {
    /// The new signed prekey.
    pub signed_prekey: PublicKey,
    /// The identity key's signature of `signed_prekey`.
    pub signed_prekey_signature: Signature,
    /// The new one-time prekeys.
    pub one_time_prekeys: Vec<PublicKey>,
}

/// Bob's private prekeys, kept on his device.
///
/// Each [`generate`](Self::generate) starts a generation of prekeys, and only the last
/// [`KEPT_GENERATIONS`] are kept, so a deleted private key cannot reveal anything later. An
/// initial message using an older generation can no longer be accepted.
#[derive(Default)]
pub struct LocalPrekeys {
    /// Oldest first.
    generations: VecDeque<Generation>,
}

/// The prekeys of one [`LocalPrekeys::generate`].
struct Generation {
    signed_prekey: PublicKey,
    signed_secret: StaticSecret,
    /// The ones not used yet.
    one_time: HashMap<PublicKey, StaticSecret>,
}

impl fmt::Debug for LocalPrekeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalPrekeys")
            .field("signed", &self.generations.len())
            .field(
                "one_time",
                &self
                    .generations
                    .iter()
                    .map(|g| g.one_time.len())
                    .sum::<usize>(),
            )
            .finish()
    }
}

impl LocalPrekeys {
    /// No prekeys yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a signed prekey, signed by `identity`, and `one_time_count` one-time prekeys, as
    /// a new generation.
    ///
    /// Deletes the private keys of the generations before the last [`KEPT_GENERATIONS`].
    pub fn generate(
        &mut self,
        identity: &XEdDSAPrivateKey,
        one_time_count: usize,
    ) -> PublishedPrekeys {
        let (signed_prekey, signed_secret) = generate_key_pair();
        let signed_prekey_signature = identity.sign(signed_prekey);
        let mut one_time = HashMap::with_capacity(one_time_count);
        let one_time_prekeys = (0..one_time_count)
            .map(|_| {
                let (public_key, secret) = generate_key_pair();
                one_time.insert(public_key, secret);
                public_key
            })
            .collect();
        while self.generations.len() >= KEPT_GENERATIONS {
            self.generations.pop_front();
        }
        self.generations.push_back(Generation {
            signed_prekey,
            signed_secret,
            one_time,
        });
        PublishedPrekeys {
            signed_prekey,
            signed_prekey_signature,
            one_time_prekeys,
        }
    }

    /// Bob's side: accept Alice's initial message, which must come from `alice_identity_key`.
    ///
    /// Consumes the one-time prekey it uses, which must be of the same generation as its signed
    /// prekey. Returns the agreement and the private key of the signed prekey it uses, which is
    /// Bob's first ratchet key pair.
    pub fn accept(
        &mut self,
        identity: &XEdDSAPrivateKey,
        alice_identity_key: &PublicKey,
        message: &InitialMessage,
    ) -> Result<(Agreement, StaticSecret)> {
        if message.identity_key != *alice_identity_key {
            return Err(ErrorKind::UnexpectedIdentity.into());
        }
        let generation = self
            .generations
            .iter_mut()
            .find(|generation| generation.signed_prekey == message.signed_prekey)
            .ok_or(ErrorKind::PrekeyNotFound)?;

        let mut key_material = KeyMaterial::new();
        key_material
            .extend(diffie_hellman(&generation.signed_secret, alice_identity_key)?.as_bytes());
        key_material.extend(&*identity.diffie_hellman(&message.ephemeral_key)?);
        key_material
            .extend(diffie_hellman(&generation.signed_secret, &message.ephemeral_key)?.as_bytes());
        if let Some(one_time_prekey) = &message.one_time_prekey {
            let secret = generation
                .one_time
                .remove(one_time_prekey)
                .ok_or(ErrorKind::OneTimePrekeyNotFound)?;
            key_material.extend(diffie_hellman(&secret, &message.ephemeral_key)?.as_bytes());
        }

        let agreement = key_material.agree(
            alice_identity_key,
            &identity.compute_public_key().to_bytes(),
        );
        Ok((agreement, generation.signed_secret.clone()))
    }
}

impl PrekeyBundle {
    /// Alice's side: start a session with Bob, whose identity key is `bob_identity_key`, from
    /// his bundle.
    ///
    /// Returns the initial message to send to Bob, and the agreement. Alice's first ratchet uses
    /// `self.signed_prekey` as Bob's public key.
    pub fn initiate(
        &self,
        identity: &XEdDSAPrivateKey,
        bob_identity_key: &PublicKey,
    ) -> Result<(InitialMessage, Agreement)> {
        XEdDSAPublicKey::new(bob_identity_key)?
            .verify(self.signed_prekey, &self.signed_prekey_signature)?;

        let (ephemeral_key, ephemeral_secret) = generate_key_pair();
        let mut key_material = KeyMaterial::new();
        key_material.extend(&*identity.diffie_hellman(&self.signed_prekey)?);
        key_material.extend(diffie_hellman(&ephemeral_secret, bob_identity_key)?.as_bytes());
        key_material.extend(diffie_hellman(&ephemeral_secret, &self.signed_prekey)?.as_bytes());
        if let Some(one_time_prekey) = &self.one_time_prekey {
            key_material.extend(diffie_hellman(&ephemeral_secret, one_time_prekey)?.as_bytes());
        }

        let identity_key = identity.compute_public_key().to_bytes();
        let message = InitialMessage {
            identity_key,
            ephemeral_key,
            signed_prekey: self.signed_prekey,
            one_time_prekey: self.one_time_prekey,
        };
        Ok((message, key_material.agree(&identity_key, bob_identity_key)))
    }
}

/// X3DH key material: the X25519 domain separator, 0xFF bytes as many as in a key, then the DH
/// outputs, each as long as a key.
struct KeyMaterial(Zeroizing<Vec<u8>>);

impl KeyMaterial {
    fn new() -> Self {
        // Room for the separator and all four DH outputs, so growing never leaves copies behind.
        let mut key_material = Zeroizing::new(Vec::with_capacity(5 * PUBLIC_KEY_LENGTH));
        key_material.extend([0xFF; PUBLIC_KEY_LENGTH]);
        Self(key_material)
    }

    fn extend(&mut self, dh_output: &[u8; PUBLIC_KEY_LENGTH]) {
        self.0.extend_from_slice(dh_output);
    }

    /// SK = HKDF-SHA256(salt = zero bytes as long as a hash, ikm = key material, info =
    /// "x3dh.v1").
    fn agree(self, alice_identity_key: &PublicKey, bob_identity_key: &PublicKey) -> Agreement {
        let mut secret_key = Zeroizing::new([0; SECRET_KEY_LENGTH]);
        Hkdf::<Sha256>::new(Some(&[0; HASH_LENGTH]), &self.0)
            .expand(INFO, secret_key.as_mut_slice())
            .expect("SK's length is a valid HKDF-SHA256 output length");
        let mut associated_data = [0; 2 * PUBLIC_KEY_LENGTH];
        let (alice, bob) = associated_data.split_at_mut(PUBLIC_KEY_LENGTH);
        alice.copy_from_slice(alice_identity_key);
        bob.copy_from_slice(bob_identity_key);
        Agreement {
            secret_key,
            associated_data,
        }
    }
}

/// X25519, rejecting a public key that makes the shared secret all zeros.
fn diffie_hellman(secret: &StaticSecret, public_key: &PublicKey) -> Result<SharedSecret> {
    let shared_secret = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*public_key));
    if !shared_secret.was_contributory() {
        return Err(ErrorKind::InvalidPublicKey.into());
    }
    Ok(shared_secret)
}

fn generate_key_pair() -> (PublicKey, StaticSecret) {
    let mut bytes = Zeroizing::new([0; _]);
    getrandom::fill(bytes.as_mut_slice()).expect("the system random number generator failed");
    let secret = StaticSecret::from(*bytes);
    (x25519_dalek::PublicKey::from(&secret).to_bytes(), secret)
}

#[cfg(test)]
mod test {
    use super::*;

    fn public_key(identity: &XEdDSAPrivateKey) -> PublicKey {
        identity.compute_public_key().to_bytes()
    }

    fn bob_setup(one_time_count: usize) -> (XEdDSAPrivateKey, LocalPrekeys, PrekeyBundle) {
        let bob = XEdDSAPrivateKey::generate();
        let mut prekeys = LocalPrekeys::new();
        let published = prekeys.generate(&bob, one_time_count);
        let bundle = PrekeyBundle {
            signed_prekey: published.signed_prekey,
            signed_prekey_signature: published.signed_prekey_signature,
            one_time_prekey: published.one_time_prekeys.first().copied(),
        };
        (bob, prekeys, bundle)
    }

    #[test]
    fn alice_and_bob_agree() {
        for one_time_count in [0, 1] {
            let alice = XEdDSAPrivateKey::generate();
            let (bob, mut prekeys, bundle) = bob_setup(one_time_count);
            let alice_key = public_key(&alice);
            let bob_key = public_key(&bob);

            let (message, alice_agreement) = bundle.initiate(&alice, &bob_key).unwrap();
            assert_eq!(message.one_time_prekey, bundle.one_time_prekey);
            let (bob_agreement, signed_prekey) =
                prekeys.accept(&bob, &alice_key, &message).unwrap();
            assert_eq!(*alice_agreement.secret_key, *bob_agreement.secret_key);
            assert_eq!(
                alice_agreement.associated_data,
                bob_agreement.associated_data
            );
            assert_eq!(
                alice_agreement.associated_data[..PUBLIC_KEY_LENGTH],
                alice_key
            );
            // Bob's first ratchet key pair is his signed prekey.
            assert_eq!(
                x25519_dalek::PublicKey::from(&signed_prekey).to_bytes(),
                bundle.signed_prekey
            );
        }
    }

    #[test]
    fn rejections() {
        let alice = XEdDSAPrivateKey::generate();
        let (bob, mut prekeys, bundle) = bob_setup(1);
        let alice_key = public_key(&alice);
        let bob_key = public_key(&bob);

        // A bundle whose signature is not by the identity Alice asked for.
        let other = XEdDSAPrivateKey::generate();
        let error = bundle.initiate(&alice, &public_key(&other)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidSignature);
        // A low-order signed prekey, signed by Bob.
        let low_order = PrekeyBundle {
            signed_prekey: [0; 32],
            signed_prekey_signature: bob.sign([0; 32]),
            one_time_prekey: None,
        };
        let error = low_order.initiate(&alice, &bob_key).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidPublicKey);

        let (message, _) = bundle.initiate(&alice, &bob_key).unwrap();
        let error = prekeys.accept(&bob, &bob_key, &message).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::UnexpectedIdentity);
        let unknown_prekey = InitialMessage {
            signed_prekey: [9; 32],
            ..message.clone()
        };
        let error = prekeys
            .accept(&bob, &alice_key, &unknown_prekey)
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::PrekeyNotFound);
        // The one-time prekey works once.
        prekeys.accept(&bob, &alice_key, &message).unwrap();
        let error = prekeys.accept(&bob, &alice_key, &message).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::OneTimePrekeyNotFound);
    }

    #[test]
    fn keeps_the_last_generations() {
        let alice = XEdDSAPrivateKey::generate();
        let (bob, mut prekeys, first) = bob_setup(2);
        let alice_key = public_key(&alice);
        let bob_key = public_key(&bob);
        let (message, _) = first.initiate(&alice, &bob_key).unwrap();

        // Bob publishes again before taking Alice's message: it still works.
        let second = prekeys.generate(&bob, 1);
        prekeys.accept(&bob, &alice_key, &message).unwrap();
        // A one-time prekey must be of the same generation as the signed prekey.
        let mixed = PrekeyBundle {
            one_time_prekey: second.one_time_prekeys.first().copied(),
            ..first.clone()
        };
        let (message, _) = mixed.initiate(&alice, &bob_key).unwrap();
        let error = prekeys.accept(&bob, &alice_key, &message).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::OneTimePrekeyNotFound);

        // After one more, the first generation is deleted.
        let without_one_time_prekey = PrekeyBundle {
            one_time_prekey: None,
            ..first
        };
        let (message, _) = without_one_time_prekey.initiate(&alice, &bob_key).unwrap();
        prekeys.generate(&bob, 1);
        let error = prekeys.accept(&bob, &alice_key, &message).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::PrekeyNotFound);
        assert_eq!(
            format!("{prekeys:?}"),
            "LocalPrekeys { signed: 2, one_time: 2 }"
        );
    }
}
