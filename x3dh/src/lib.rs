#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod error;
#[cfg(all(test, any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
mod kat;
#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
mod kem;
pub mod pq;
#[cfg(feature = "prost")]
pub mod proto;

use core::fmt;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

pub use error::{Error, ErrorKind, Result};
use hkdf::Hkdf;
use pq::PqPrekeySecret;
pub use pq::{
    PQ_PREKEY_ID_LENGTH, PQ_SEED_LENGTH, PQ_SHARED_SECRET_LENGTH, PQXDH_ASSOCIATED_DATA_LENGTH,
    PQXDH_VERSION, PqAgreement, PqInitialMessage, PqPrekeyBundle, PqPrekeyId, PqSuite,
    PublishedPqPrekey, PublishedPqPrekeys, pq_opk_signing_input, pq_prekey_id,
    pq_spk_signing_input, sign_pq_opk, sign_pq_spk, verify_pq_opk_signature,
    verify_pq_spk_signature,
};
use sha2::{
    Sha256,
    digest::{OutputSizeUser, typenum::Unsigned},
};
use x25519_dalek::SharedSecret;
/// Re-export x25519_dalek's private key, which [`LocalPrekeys::accept`] returns.
pub use x25519_dalek::StaticSecret;
use xeddsa::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, XEdDSAPrivateKey, XEdDSAPublicKey};
use zeroize::Zeroizing;
#[cfg(feature = "rkyv")]
use zeroize::{Zeroize, ZeroizeOnDrop};

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
/// Each [`generate`](Self::generate) (or `generate_pq` when a PQ feature is enabled) starts a
/// generation of prekeys, and only the last [`KEPT_GENERATIONS`] are kept, so a deleted private
/// key cannot reveal anything later. An initial message using an older generation can no longer
/// be accepted.
///
/// Accepting an initial message takes two steps: [`accept`](Self::accept) agrees on it without
/// changing anything, and once the caller has checked that it is Alice's, e.g. as the first
/// message of the session decrypts, [`confirm`](Self::confirm) uses up its one-time prekey and
/// keeps it from being accepted again. So an initial message anyone could have sent, claiming
/// to be Alice's, uses up nothing.
///
/// With the `serde` or `rkyv` feature, it serializes with its private keys, and with `prost` it
/// converts to and from `proto::LocalPrekeys`: keep the output secret.
#[derive(Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "RawLocalPrekeys"))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[cfg_attr(feature = "rkyv", rkyv(bytecheck(verify)))]
pub struct LocalPrekeys {
    /// Oldest first.
    generations: VecDeque<Generation>,
}

/// The prekeys of one [`LocalPrekeys::generate`].
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
struct Generation {
    signed_prekey: PublicKey,
    #[cfg_attr(feature = "rkyv", rkyv(with = StaticSecretDef))]
    signed_secret: StaticSecret,
    /// The ones not used yet.
    #[cfg_attr(feature = "serde", serde(with = "pairs"))]
    #[cfg_attr(
        feature = "rkyv",
        rkyv(with = rkyv::with::MapKV<rkyv::with::Identity, StaticSecretDef>)
    )]
    one_time: HashMap<PublicKey, StaticSecret>,
    /// The canonical ephemeral keys of the initial messages confirmed, so that none is accepted
    /// twice, e.g. one without a one-time prekey sent again. They go with the generation.
    confirmed: HashSet<PublicKey>,
    /// Last-resort PQSPK seeds for this generation, at most one per suite.
    #[cfg_attr(feature = "serde", serde(with = "pq_last_resort_pairs"))]
    pq_last_resort: BTreeMap<PqSuite, PqPrekeySecret>,
    /// Unused PQOPK seeds for this generation, keyed by deterministic [`PqPrekeyId`].
    #[cfg_attr(feature = "serde", serde(with = "pq_one_time_pairs"))]
    pq_one_time: HashMap<PqPrekeyId, PqPrekeySecret>,
}

/// Archives a [`StaticSecret`] as its bytes, zeroizing temporary copies on drop.
#[cfg(feature = "rkyv")]
#[derive(Zeroize, ZeroizeOnDrop, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(remote = StaticSecret)]
struct StaticSecretDef {
    #[rkyv(getter = StaticSecret::to_bytes)]
    bytes: [u8; PUBLIC_KEY_LENGTH],
}

#[cfg(feature = "rkyv")]
impl From<StaticSecretDef> for StaticSecret {
    fn from(secret: StaticSecretDef) -> Self {
        StaticSecret::from(secret.bytes)
    }
}

#[cfg(feature = "rkyv")]
#[derive(Debug, thiserror::Error)]
#[error("malformed archived LocalPrekeys state")]
struct InvalidArchivedPrekeys;

#[cfg(feature = "rkyv")]
fn archived_suite(suite: &pq::ArchivedPqSuite) -> PqSuite {
    match suite {
        pq::ArchivedPqSuite::MlKem1024 => PqSuite::MlKem1024,
        pq::ArchivedPqSuite::MlKem768 => PqSuite::MlKem768,
    }
}

#[cfg(feature = "rkyv")]
unsafe impl<C> rkyv::bytecheck::Verify<C> for ArchivedLocalPrekeys
where
    C: rkyv::rancor::Fallible + ?Sized,
    C::Error: rkyv::rancor::Source,
{
    fn verify(&self, _context: &mut C) -> core::result::Result<(), C::Error> {
        if self.generations.len() > KEPT_GENERATIONS {
            rkyv::rancor::fail!(InvalidArchivedPrekeys);
        }
        let mut seen_spks = HashSet::with_capacity(self.generations.len());
        for generation in self.generations.iter() {
            if !seen_spks.insert(generation.signed_prekey) {
                rkyv::rancor::fail!(InvalidArchivedPrekeys);
            }
            let spk_secret_bytes = Zeroizing::new(generation.signed_secret.bytes);
            let spk_secret = StaticSecret::from(*spk_secret_bytes);
            if x25519_dalek::PublicKey::from(&spk_secret).to_bytes() != generation.signed_prekey {
                rkyv::rancor::fail!(InvalidArchivedPrekeys);
            }
            for (opk_pub, opk_secret_def) in generation.one_time.iter() {
                let opk_secret_bytes = Zeroizing::new(opk_secret_def.bytes);
                let opk_secret = StaticSecret::from(*opk_secret_bytes);
                if x25519_dalek::PublicKey::from(&opk_secret).to_bytes() != *opk_pub {
                    rkyv::rancor::fail!(InvalidArchivedPrekeys);
                }
            }
            for ek in generation.confirmed.iter() {
                if !xeddsa::is_canonical_public_key(ek) {
                    rkyv::rancor::fail!(InvalidArchivedPrekeys);
                }
            }
            let mut last_resort_ids = HashSet::with_capacity(generation.pq_last_resort.len());
            for (k_suite, pq) in generation.pq_last_resort.iter() {
                let key_suite = archived_suite(k_suite);
                let val_suite = archived_suite(&pq.suite);
                if key_suite != val_suite {
                    rkyv::rancor::fail!(InvalidArchivedPrekeys);
                }
                let ek = pq.ek.as_slice();
                if ek.len() != val_suite.ek_len() {
                    rkyv::rancor::fail!(InvalidArchivedPrekeys);
                }
                let seed = Zeroizing::new(pq.seed.bytes);
                if validate_pq_seed_ek(val_suite, ek, &seed).is_err() {
                    rkyv::rancor::fail!(InvalidArchivedPrekeys);
                }
                let id = pq_prekey_id(val_suite.as_u8(), ek);
                if !last_resort_ids.insert(id) {
                    rkyv::rancor::fail!(InvalidArchivedPrekeys);
                }
            }
            for (id, pq) in generation.pq_one_time.iter() {
                let suite = archived_suite(&pq.suite);
                let ek = pq.ek.as_slice();
                if ek.len() != suite.ek_len() {
                    rkyv::rancor::fail!(InvalidArchivedPrekeys);
                }
                if pq_prekey_id(suite.as_u8(), ek) != *id {
                    rkyv::rancor::fail!(InvalidArchivedPrekeys);
                }
                if last_resort_ids.contains(id) {
                    rkyv::rancor::fail!(InvalidArchivedPrekeys);
                }
                let seed = Zeroizing::new(pq.seed.bytes);
                if validate_pq_seed_ek(suite, ek, &seed).is_err() {
                    rkyv::rancor::fail!(InvalidArchivedPrekeys);
                }
            }
        }
        Ok(())
    }
}

/// Validates that a stored PQ seed derives `ek` when `suite` is compiled into this build.
#[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
#[allow(unused_variables)]
fn validate_pq_seed_ek(suite: PqSuite, ek: &[u8], seed: &[u8; PQ_SEED_LENGTH]) -> Result<()> {
    if ek.len() != suite.ek_len() {
        return Err(ErrorKind::MalformedState.into());
    }
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    if suite.is_supported() {
        let derived = kem::derive_ek(suite, seed)?;
        if derived.as_slice() != ek {
            return Err(ErrorKind::MalformedState.into());
        }
    }
    Ok(())
}

/// Serializes a map as a sequence of key-value pairs, since formats such as JSON only take
/// string keys.
#[cfg(feature = "serde")]
mod pairs {
    use std::collections::HashMap;

    use serde::Serializer;

    use crate::{PublicKey, StaticSecret};

    pub(super) fn serialize<S: Serializer>(
        map: &HashMap<PublicKey, StaticSecret>,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        serializer.collect_seq(map)
    }
}

#[cfg(feature = "serde")]
mod pq_last_resort_pairs {
    use std::collections::BTreeMap;

    use serde::Serializer;

    use crate::{PqSuite, pq::PqPrekeySecret};

    pub(super) fn serialize<S: Serializer>(
        map: &BTreeMap<PqSuite, PqPrekeySecret>,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        serializer.collect_seq(map)
    }
}

#[cfg(feature = "serde")]
mod pq_one_time_pairs {
    use std::collections::HashMap;

    use serde::Serializer;

    use crate::{PqPrekeyId, pq::PqPrekeySecret};

    pub(super) fn serialize<S: Serializer>(
        map: &HashMap<PqPrekeyId, PqPrekeySecret>,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        serializer.collect_seq(map)
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(rename = "LocalPrekeys")]
struct RawLocalPrekeys {
    generations: VecDeque<RawGeneration>,
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(rename = "Generation")]
struct RawGeneration {
    signed_prekey: PublicKey,
    signed_secret: StaticSecret,
    one_time: Vec<(PublicKey, StaticSecret)>,
    confirmed: HashSet<PublicKey>,
    #[serde(default)]
    pq_last_resort: Vec<(PqSuite, PqPrekeySecret)>,
    #[serde(default)]
    pq_one_time: Vec<(PqPrekeyId, PqPrekeySecret)>,
}

#[cfg(feature = "serde")]
impl TryFrom<RawLocalPrekeys> for LocalPrekeys {
    type Error = Error;

    fn try_from(raw: RawLocalPrekeys) -> Result<Self> {
        if raw.generations.len() > KEPT_GENERATIONS {
            return Err(ErrorKind::MalformedState.into());
        }
        let mut seen_spks = HashSet::with_capacity(raw.generations.len());
        let mut generations = VecDeque::with_capacity(raw.generations.len());
        for raw_gen in raw.generations {
            if !seen_spks.insert(raw_gen.signed_prekey) {
                return Err(ErrorKind::MalformedState.into());
            }
            if x25519_dalek::PublicKey::from(&raw_gen.signed_secret).to_bytes()
                != raw_gen.signed_prekey
            {
                return Err(ErrorKind::MalformedState.into());
            }
            let mut one_time = HashMap::with_capacity(raw_gen.one_time.len());
            for (opk_pub, opk_secret) in raw_gen.one_time {
                if x25519_dalek::PublicKey::from(&opk_secret).to_bytes() != opk_pub {
                    return Err(ErrorKind::MalformedState.into());
                }
                if one_time.insert(opk_pub, opk_secret).is_some() {
                    return Err(ErrorKind::MalformedState.into());
                }
            }
            for ek in &raw_gen.confirmed {
                if !xeddsa::is_canonical_public_key(ek) {
                    return Err(ErrorKind::MalformedState.into());
                }
            }
            let mut pq_last_resort = BTreeMap::new();
            let mut last_resort_ids = HashSet::with_capacity(raw_gen.pq_last_resort.len());
            for (suite, secret) in raw_gen.pq_last_resort {
                if secret.suite != suite {
                    return Err(ErrorKind::MalformedState.into());
                }
                validate_pq_seed_ek(suite, &secret.ek, &secret.seed)?;
                let id = pq_prekey_id(suite.as_u8(), &secret.ek);
                if pq_last_resort.insert(suite, secret).is_some() || !last_resort_ids.insert(id) {
                    return Err(ErrorKind::MalformedState.into());
                }
            }
            let mut pq_one_time = HashMap::with_capacity(raw_gen.pq_one_time.len());
            for (id, secret) in raw_gen.pq_one_time {
                validate_pq_seed_ek(secret.suite, &secret.ek, &secret.seed)?;
                if pq_prekey_id(secret.suite.as_u8(), &secret.ek) != id {
                    return Err(ErrorKind::MalformedState.into());
                }
                if last_resort_ids.contains(&id) {
                    return Err(ErrorKind::MalformedState.into());
                }
                if pq_one_time.insert(id, secret).is_some() {
                    return Err(ErrorKind::MalformedState.into());
                }
            }
            generations.push_back(Generation {
                signed_prekey: raw_gen.signed_prekey,
                signed_secret: raw_gen.signed_secret,
                one_time,
                confirmed: raw_gen.confirmed,
                pq_last_resort,
                pq_one_time,
            });
        }
        Ok(Self { generations })
    }
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
            .field(
                "pq_last_resort",
                &self
                    .generations
                    .iter()
                    .map(|g| g.pq_last_resort.len())
                    .sum::<usize>(),
            )
            .field(
                "pq_one_time",
                &self
                    .generations
                    .iter()
                    .map(|g| g.pq_one_time.len())
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

    /// Number of retained prekey generations (at most [`KEPT_GENERATIONS`]).
    pub fn generation_count(&self) -> usize {
        self.generations.len()
    }

    /// The current (latest) generation's signed prekey, if any generation exists.
    pub fn current_signed_prekey(&self) -> Option<PublicKey> {
        self.generations.back().map(|g| g.signed_prekey)
    }

    /// The current (latest) generation's last-resort PQSPK identifier for `suite`, if present.
    pub fn current_pq_last_resort_id(&self, suite: PqSuite) -> Option<PqPrekeyId> {
        self.generations
            .back()
            .and_then(|g| g.pq_last_resort.get(&suite))
            .map(|pq| pq_prekey_id(suite.as_u8(), &pq.ek))
    }

    /// Number of unused classical one-time prekeys in the latest generation.
    pub fn current_one_time_count(&self) -> usize {
        self.generations.back().map_or(0, |g| g.one_time.len())
    }

    /// Number of unused post-quantum one-time prekeys for `suite` in the latest generation.
    pub fn current_pq_one_time_count(&self, suite: PqSuite) -> usize {
        self.generations.back().map_or(0, |g| {
            g.pq_one_time
                .values()
                .filter(|pq| pq.suite == suite)
                .count()
        })
    }

    /// Add `one_time_count` one-time prekeys to the last generation, to publish with its signed
    /// prekey, signed again by `identity`: for when publishing it may have failed, though the
    /// server may have it, or to replenish one-time prekeys without rotating the signed prekey.
    /// Generates a generation if there is none.
    pub fn extend(
        &mut self,
        identity: &XEdDSAPrivateKey,
        one_time_count: usize,
    ) -> PublishedPrekeys {
        let Some(generation) = self.generations.back_mut() else {
            return self.generate(identity, one_time_count);
        };
        let one_time_prekeys = (0..one_time_count)
            .map(|_| {
                let (public_key, secret) = generate_key_pair();
                generation.one_time.insert(public_key, secret);
                public_key
            })
            .collect();
        PublishedPrekeys {
            signed_prekey: generation.signed_prekey,
            signed_prekey_signature: identity.sign(generation.signed_prekey),
            one_time_prekeys,
        }
    }

    /// Forget `one_time_prekeys` of the last generation, which [`extend`](Self::extend) added:
    /// for when the server refused them, keeping none, so that publishing again, refused each
    /// time, does not add up keys.
    pub fn retract(&mut self, one_time_prekeys: &[PublicKey]) {
        if let Some(generation) = self.generations.back_mut() {
            for prekey in one_time_prekeys {
                generation.one_time.remove(prekey);
            }
        }
    }

    /// Forget classical `one_time_prekeys` and post-quantum `pq_one_time_prekeys` of the last
    /// generation (for when a publish/refill request was refused by the server).
    pub fn retract_pq(
        &mut self,
        one_time_prekeys: &[PublicKey],
        pq_one_time_prekeys: &[PqPrekeyId],
    ) {
        if let Some(generation) = self.generations.back_mut() {
            for prekey in one_time_prekeys {
                generation.one_time.remove(prekey);
            }
            for id in pq_one_time_prekeys {
                generation.pq_one_time.remove(id);
            }
        }
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
            confirmed: HashSet::new(),
            pq_last_resort: BTreeMap::new(),
            pq_one_time: HashMap::new(),
        });
        PublishedPrekeys {
            signed_prekey,
            signed_prekey_signature,
            one_time_prekeys,
        }
    }

    /// Generate a new prekey generation containing classical X3DH prekeys plus a last-resort
    /// PQSPK and `pq_one_time_count` PQOPKs for `suite`, storing only 64-byte FIPS 203 seeds.
    ///
    /// Fails with [`ErrorKind::UnsupportedSuite`] if `suite` is not enabled at compile time.
    /// Deletes generations older than the last [`KEPT_GENERATIONS`].
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    pub fn generate_pq(
        &mut self,
        identity: &XEdDSAPrivateKey,
        suite: PqSuite,
        one_time_count: usize,
        pq_one_time_count: usize,
    ) -> Result<PublishedPqPrekeys> {
        if !suite.is_supported() {
            return Err(ErrorKind::UnsupportedSuite.into());
        }
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

        let (lr_ek, lr_seed) = kem::generate_keypair(suite)?;
        let lr_id = pq_prekey_id(suite.as_u8(), &lr_ek);
        let lr_sig = sign_pq_spk(identity, suite, &lr_ek)?;
        let pq_last_resort_pub = PublishedPqPrekey {
            suite,
            id: lr_id,
            encapsulation_key: lr_ek.clone(),
            signature: lr_sig,
        };
        let mut pq_last_resort = BTreeMap::new();
        pq_last_resort.insert(
            suite,
            PqPrekeySecret {
                suite,
                ek: lr_ek,
                seed: lr_seed,
            },
        );

        let mut pq_one_time = HashMap::with_capacity(pq_one_time_count);
        let mut pq_one_time_prekeys = Vec::with_capacity(pq_one_time_count);
        for _ in 0..pq_one_time_count {
            let (ek, seed) = kem::generate_keypair(suite)?;
            let id = pq_prekey_id(suite.as_u8(), &ek);
            let signature = sign_pq_opk(identity, suite, &ek)?;
            pq_one_time_prekeys.push(PublishedPqPrekey {
                suite,
                id,
                encapsulation_key: ek.clone(),
                signature,
            });
            pq_one_time.insert(id, PqPrekeySecret { suite, ek, seed });
        }

        while self.generations.len() >= KEPT_GENERATIONS {
            self.generations.pop_front();
        }
        self.generations.push_back(Generation {
            signed_prekey,
            signed_secret,
            one_time,
            confirmed: HashSet::new(),
            pq_last_resort,
            pq_one_time,
        });

        Ok(PublishedPqPrekeys {
            classical: PublishedPrekeys {
                signed_prekey,
                signed_prekey_signature,
                one_time_prekeys,
            },
            pq_last_resort: pq_last_resort_pub,
            pq_one_time_prekeys,
        })
    }

    /// Replenish classical OPKs and/or PQOPKs in the latest generation without rotating the
    /// signed prekey or existing last-resort PQSPK for `suite`.
    ///
    /// If no generation exists yet, behaves like [`generate_pq`](Self::generate_pq). If the
    /// latest generation has no last-resort PQSPK for `suite` (e.g. when upgrading an existing
    /// classical generation to PQXDH), generates one for `suite` in that generation.
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    pub fn extend_pq(
        &mut self,
        identity: &XEdDSAPrivateKey,
        suite: PqSuite,
        one_time_count: usize,
        pq_one_time_count: usize,
    ) -> Result<PublishedPqPrekeys> {
        if !suite.is_supported() {
            return Err(ErrorKind::UnsupportedSuite.into());
        }
        let Some(generation) = self.generations.back_mut() else {
            return self.generate_pq(identity, suite, one_time_count, pq_one_time_count);
        };

        let one_time_prekeys = (0..one_time_count)
            .map(|_| {
                let (public_key, secret) = generate_key_pair();
                generation.one_time.insert(public_key, secret);
                public_key
            })
            .collect();

        let pq_last_resort_pub = if let Some(existing) = generation.pq_last_resort.get(&suite) {
            let id = pq_prekey_id(suite.as_u8(), &existing.ek);
            let signature = sign_pq_spk(identity, suite, &existing.ek)?;
            PublishedPqPrekey {
                suite,
                id,
                encapsulation_key: existing.ek.clone(),
                signature,
            }
        } else {
            let (ek, seed) = kem::generate_keypair(suite)?;
            let id = pq_prekey_id(suite.as_u8(), &ek);
            let signature = sign_pq_spk(identity, suite, &ek)?;
            generation.pq_last_resort.insert(
                suite,
                PqPrekeySecret {
                    suite,
                    ek: ek.clone(),
                    seed,
                },
            );
            PublishedPqPrekey {
                suite,
                id,
                encapsulation_key: ek,
                signature,
            }
        };

        let mut pq_one_time_prekeys = Vec::with_capacity(pq_one_time_count);
        for _ in 0..pq_one_time_count {
            let (ek, seed) = kem::generate_keypair(suite)?;
            let id = pq_prekey_id(suite.as_u8(), &ek);
            let signature = sign_pq_opk(identity, suite, &ek)?;
            pq_one_time_prekeys.push(PublishedPqPrekey {
                suite,
                id,
                encapsulation_key: ek.clone(),
                signature,
            });
            generation
                .pq_one_time
                .insert(id, PqPrekeySecret { suite, ek, seed });
        }

        Ok(PublishedPqPrekeys {
            classical: PublishedPrekeys {
                signed_prekey: generation.signed_prekey,
                signed_prekey_signature: identity.sign(generation.signed_prekey),
                one_time_prekeys,
            },
            pq_last_resort: pq_last_resort_pub,
            pq_one_time_prekeys,
        })
    }

    /// Bob's side: agree on Alice's initial message, which must come from `alice_identity_key`,
    /// without using it up.
    ///
    /// Its one-time prekey must be of the same generation as its signed prekey. Returns the
    /// agreement and the private key of the signed prekey it uses, which is Bob's first ratchet
    /// key pair.
    ///
    /// Anyone can send an initial message claiming to be Alice's, and nothing in it shows that
    /// it is: only Alice can encrypt with the agreement, as it takes her identity key's private
    /// key. Once something encrypted with it decrypts, [`confirm`](Self::confirm) the message.
    pub fn accept(
        &self,
        identity: &XEdDSAPrivateKey,
        alice_identity_key: &PublicKey,
        message: &InitialMessage,
    ) -> Result<(Agreement, StaticSecret)> {
        if message.identity_key != *alice_identity_key {
            return Err(ErrorKind::UnexpectedIdentity.into());
        }
        check_canonical_keys(
            alice_identity_key,
            &message.ephemeral_key,
            &message.signed_prekey,
            message.one_time_prekey.as_ref(),
        )?;
        XEdDSAPublicKey::new(alice_identity_key)?;
        let generation = &self.generations[self.generation(message)?];

        let mut key_material = KeyMaterial::new_classical();
        key_material
            .extend(diffie_hellman(&generation.signed_secret, alice_identity_key)?.as_bytes());
        key_material.extend(&*identity.diffie_hellman(&message.ephemeral_key)?);
        key_material
            .extend(diffie_hellman(&generation.signed_secret, &message.ephemeral_key)?.as_bytes());
        if let Some(one_time_prekey) = &message.one_time_prekey {
            let secret = generation
                .one_time
                .get(one_time_prekey)
                .ok_or(ErrorKind::OneTimePrekeyNotFound)?;
            key_material.extend(diffie_hellman(secret, &message.ephemeral_key)?.as_bytes());
        }

        let agreement = key_material.agree(
            alice_identity_key,
            &identity.compute_public_key().to_bytes(),
        );
        Ok((agreement, generation.signed_secret.clone()))
    }

    /// Bob's side (PQXDH): agree on Alice's post-quantum initial message, which must come from
    /// `alice_identity_key`, without mutating prekey state.
    ///
    /// Verifies that:
    /// - `message.version == PQXDH_VERSION` and `message.pq_suite` is enabled in this build,
    /// - all X25519 keys are canonically encoded and contributory/prime-order,
    /// - `message.ephemeral_key` has not already been confirmed in that generation,
    /// - any classical OPK AND the referenced PQ prekey (last-resort PQSPK or one-time PQOPK)
    ///   belong to the SAME generation as `message.signed_prekey`.
    ///
    /// Once the caller decrypts Alice's first message under the returned [`PqAgreement`], call
    /// [`confirm_pq`](Self::confirm_pq) to delete any consumed OPK / PQOPK seed (preserving
    /// last-resort PQSPK seeds) and record the canonical ephemeral key against replay.
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    pub fn accept_pq(
        &self,
        identity: &XEdDSAPrivateKey,
        alice_identity_key: &PublicKey,
        message: &PqInitialMessage,
        manifest_digest: Option<&[u8]>,
    ) -> Result<(PqAgreement, StaticSecret)> {
        if message.identity_key != *alice_identity_key {
            return Err(ErrorKind::UnexpectedIdentity.into());
        }
        if message.version != PQXDH_VERSION {
            return Err(ErrorKind::UnsupportedVersion.into());
        }
        if !message.pq_suite.is_supported() {
            return Err(ErrorKind::UnsupportedSuite.into());
        }
        check_canonical_keys(
            alice_identity_key,
            &message.ephemeral_key,
            &message.signed_prekey,
            message.one_time_prekey.as_ref(),
        )?;
        XEdDSAPublicKey::new(alice_identity_key)?;
        if let Some(digest) = manifest_digest
            && (digest.is_empty() || u8::try_from(digest.len()).is_err())
        {
            return Err(ErrorKind::MalformedState.into());
        }
        if message.pq_ciphertext.len() != message.pq_suite.ct_len() {
            return Err(ErrorKind::InvalidCiphertext.into());
        }

        let index = self.pq_generation(message)?;
        let generation = &self.generations[index];
        let pq_secret = lookup_pq_prekey(generation, message)?;

        let mut key_material = KeyMaterial::new_pq();
        key_material
            .extend(diffie_hellman(&generation.signed_secret, alice_identity_key)?.as_bytes());
        key_material.extend(&*identity.diffie_hellman(&message.ephemeral_key)?);
        key_material
            .extend(diffie_hellman(&generation.signed_secret, &message.ephemeral_key)?.as_bytes());
        if let Some(one_time_prekey) = &message.one_time_prekey {
            let secret = generation
                .one_time
                .get(one_time_prekey)
                .ok_or(ErrorKind::OneTimePrekeyNotFound)?;
            key_material.extend(diffie_hellman(secret, &message.ephemeral_key)?.as_bytes());
        }
        let pq_ss = kem::decapsulate(pq_secret.suite, &pq_secret.seed, &message.pq_ciphertext)?;
        key_material.extend(&pq_ss);

        let bob_identity_key = identity.compute_public_key().to_bytes();
        let transcript_hash = pq::compute_transcript_hash(
            alice_identity_key,
            &bob_identity_key,
            &message.signed_prekey,
            message.one_time_prekey.as_ref(),
            &message.ephemeral_key,
            message.pq_suite,
            message.pq_last_resort,
            &message.pq_prekey_id,
            &message.pq_ciphertext,
            message.version,
            manifest_digest,
        )?;
        let agreement = key_material.agree_pq(
            message.pq_suite,
            alice_identity_key,
            &bob_identity_key,
            transcript_hash,
        );
        Ok((agreement, generation.signed_secret.clone()))
    }

    /// Use up an initial message [accepted](Self::accept) and shown to be Alice's: delete the
    /// private key of its one-time prekey, and keep it from being accepted again.
    ///
    /// Fails if it cannot be accepted any more, e.g. it was confirmed already or contains
    /// non-canonical keys.
    pub fn confirm(&mut self, message: &InitialMessage) -> Result<()> {
        check_canonical_keys(
            &message.identity_key,
            &message.ephemeral_key,
            &message.signed_prekey,
            message.one_time_prekey.as_ref(),
        )?;
        XEdDSAPublicKey::new(&message.identity_key)?;
        let index = self.generation(message)?;
        let generation = &mut self.generations[index];
        if let Some(one_time_prekey) = &message.one_time_prekey {
            generation.one_time.remove(one_time_prekey);
        }
        generation.confirmed.insert(message.ephemeral_key);
        Ok(())
    }

    /// Use up a post-quantum initial message accepted via `accept_pq` and shown to be Alice's:
    /// delete the private key of its classical one-time prekey (if any), delete its PQOPK seed
    /// (preserving last-resort PQSPK seeds), and record its canonical ephemeral key against
    /// replay.
    ///
    /// Fails if it cannot be accepted any more (e.g. replayed, wrong version, missing prekey,
    /// or non-canonical keys).
    pub fn confirm_pq(&mut self, message: &PqInitialMessage) -> Result<()> {
        if message.version != PQXDH_VERSION {
            return Err(ErrorKind::UnsupportedVersion.into());
        }
        check_canonical_keys(
            &message.identity_key,
            &message.ephemeral_key,
            &message.signed_prekey,
            message.one_time_prekey.as_ref(),
        )?;
        XEdDSAPublicKey::new(&message.identity_key)?;
        if message.pq_ciphertext.len() != message.pq_suite.ct_len() {
            return Err(ErrorKind::InvalidCiphertext.into());
        }
        let index = self.pq_generation(message)?;
        let generation = &mut self.generations[index];
        if let Some(one_time_prekey) = &message.one_time_prekey {
            generation.one_time.remove(one_time_prekey);
        }
        if !message.pq_last_resort {
            generation.pq_one_time.remove(&message.pq_prekey_id);
        }
        generation.confirmed.insert(message.ephemeral_key);
        Ok(())
    }

    /// The index of the generation of `message`'s prekeys, if it can be accepted.
    fn generation(&self, message: &InitialMessage) -> Result<usize> {
        let index = self
            .generations
            .iter()
            .position(|generation| generation.signed_prekey == message.signed_prekey)
            .ok_or(ErrorKind::PrekeyNotFound)?;
        let generation = &self.generations[index];
        if generation.confirmed.contains(&message.ephemeral_key) {
            return Err(ErrorKind::Replayed.into());
        }
        if let Some(one_time_prekey) = &message.one_time_prekey
            && !generation.one_time.contains_key(one_time_prekey)
        {
            return Err(ErrorKind::OneTimePrekeyNotFound.into());
        }
        Ok(index)
    }

    /// The index of the generation of `message`'s classical + PQ prekeys, verifying same-gen
    /// membership and replay status.
    fn pq_generation(&self, message: &PqInitialMessage) -> Result<usize> {
        let index = self
            .generations
            .iter()
            .position(|generation| generation.signed_prekey == message.signed_prekey)
            .ok_or(ErrorKind::PrekeyNotFound)?;
        let generation = &self.generations[index];
        if generation.confirmed.contains(&message.ephemeral_key) {
            return Err(ErrorKind::Replayed.into());
        }
        if let Some(one_time_prekey) = &message.one_time_prekey
            && !generation.one_time.contains_key(one_time_prekey)
        {
            return Err(ErrorKind::OneTimePrekeyNotFound.into());
        }
        let _ = lookup_pq_prekey(generation, message)?;
        Ok(index)
    }
}

/// Looks up the PQ prekey referenced by `message` strictly within `generation`, enforcing both
/// role (`pq_last_resort` vs `pq_one_time`) and suite match.
fn lookup_pq_prekey<'a>(
    generation: &'a Generation,
    message: &PqInitialMessage,
) -> Result<&'a PqPrekeySecret> {
    if message.pq_last_resort {
        let pq = generation
            .pq_last_resort
            .get(&message.pq_suite)
            .ok_or(ErrorKind::PqPrekeyNotFound)?;
        if pq.suite != message.pq_suite
            || pq_prekey_id(message.pq_suite.as_u8(), &pq.ek) != message.pq_prekey_id
        {
            return Err(ErrorKind::PqPrekeyNotFound.into());
        }
        Ok(pq)
    } else {
        let pq = generation
            .pq_one_time
            .get(&message.pq_prekey_id)
            .ok_or(ErrorKind::PqPrekeyNotFound)?;
        if pq.suite != message.pq_suite
            || pq_prekey_id(message.pq_suite.as_u8(), &pq.ek) != message.pq_prekey_id
        {
            return Err(ErrorKind::PqPrekeyNotFound.into());
        }
        Ok(pq)
    }
}

#[cfg(feature = "prost")]
impl From<&LocalPrekeys> for proto::LocalPrekeys {
    fn from(prekeys: &LocalPrekeys) -> Self {
        let generations = prekeys
            .generations
            .iter()
            .map(|generation| {
                let signed_secret = Zeroizing::new(generation.signed_secret.to_bytes());
                proto::Generation {
                    signed_prekey: generation.signed_prekey.to_vec(),
                    signed_secret: signed_secret.to_vec(),
                    one_time_prekeys: generation
                        .one_time
                        .iter()
                        .map(|(public_key, secret)| {
                            let secret_bytes = Zeroizing::new(secret.to_bytes());
                            proto::OneTimePrekey {
                                public_key: public_key.to_vec(),
                                secret: secret_bytes.to_vec(),
                            }
                        })
                        .collect(),
                    confirmed_ephemeral_keys: generation
                        .confirmed
                        .iter()
                        .map(|ephemeral_key| ephemeral_key.to_vec())
                        .collect(),
                    pq_last_resort: generation
                        .pq_last_resort
                        .values()
                        .map(|pq| proto::PqPrekey {
                            suite: u32::from(pq.suite.as_u8()),
                            id: pq_prekey_id(pq.suite.as_u8(), &pq.ek).to_vec(),
                            encapsulation_key: pq.ek.clone(),
                            seed: pq.seed.to_vec(),
                        })
                        .collect(),
                    pq_one_time_prekeys: generation
                        .pq_one_time
                        .iter()
                        .map(|(id, pq)| proto::PqPrekey {
                            suite: u32::from(pq.suite.as_u8()),
                            id: id.to_vec(),
                            encapsulation_key: pq.ek.clone(),
                            seed: pq.seed.to_vec(),
                        })
                        .collect(),
                }
            })
            .collect();
        Self { generations }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&proto::LocalPrekeys> for LocalPrekeys {
    type Error = Error;

    fn try_from(prekeys: &proto::LocalPrekeys) -> Result<Self> {
        /// A public key field, which must be 32 bytes.
        fn key(bytes: &[u8]) -> Result<[u8; PUBLIC_KEY_LENGTH]> {
            bytes
                .try_into()
                .map_err(|_| ErrorKind::MalformedState.into())
        }

        /// A secret key field, which must be 32 bytes and is zeroized on drop.
        fn secret_key(bytes: &[u8]) -> Result<Zeroizing<[u8; PUBLIC_KEY_LENGTH]>> {
            let mut out = Zeroizing::new([0u8; PUBLIC_KEY_LENGTH]);
            if bytes.len() != PUBLIC_KEY_LENGTH {
                return Err(ErrorKind::MalformedState.into());
            }
            out.copy_from_slice(bytes);
            Ok(out)
        }

        /// Parse and validate a `proto::PqPrekey`.
        fn parse_pq(pq: &proto::PqPrekey) -> Result<(PqPrekeyId, PqPrekeySecret)> {
            let suite_u8 = u8::try_from(pq.suite).map_err(|_| ErrorKind::MalformedState)?;
            let suite = PqSuite::from_u8(suite_u8).ok_or(ErrorKind::MalformedState)?;
            let id: PqPrekeyId = pq
                .id
                .as_slice()
                .try_into()
                .map_err(|_| ErrorKind::MalformedState)?;
            if pq.encapsulation_key.len() != suite.ek_len() {
                return Err(ErrorKind::MalformedState.into());
            }
            if pq_prekey_id(suite.as_u8(), &pq.encapsulation_key) != id {
                return Err(ErrorKind::MalformedState.into());
            }
            if pq.seed.len() != PQ_SEED_LENGTH {
                return Err(ErrorKind::MalformedState.into());
            }
            let mut seed = Zeroizing::new([0u8; PQ_SEED_LENGTH]);
            seed.copy_from_slice(&pq.seed);
            validate_pq_seed_ek(suite, &pq.encapsulation_key, &seed)?;
            Ok((
                id,
                PqPrekeySecret {
                    suite,
                    ek: pq.encapsulation_key.clone(),
                    seed,
                },
            ))
        }

        if prekeys.generations.len() > KEPT_GENERATIONS {
            return Err(ErrorKind::MalformedState.into());
        }

        let mut seen_spks = HashSet::with_capacity(prekeys.generations.len());
        let mut generations = VecDeque::with_capacity(prekeys.generations.len());
        for generation in &prekeys.generations {
            let signed_prekey = key(&generation.signed_prekey)?;
            if !seen_spks.insert(signed_prekey) {
                return Err(ErrorKind::MalformedState.into());
            }
            let signed_secret_bytes = secret_key(&generation.signed_secret)?;
            let signed_secret = StaticSecret::from(*signed_secret_bytes);
            if x25519_dalek::PublicKey::from(&signed_secret).to_bytes() != signed_prekey {
                return Err(ErrorKind::MalformedState.into());
            }

            let mut one_time = HashMap::with_capacity(generation.one_time_prekeys.len());
            for opk in &generation.one_time_prekeys {
                let pub_key = key(&opk.public_key)?;
                let sec_bytes = secret_key(&opk.secret)?;
                let sec = StaticSecret::from(*sec_bytes);
                if x25519_dalek::PublicKey::from(&sec).to_bytes() != pub_key {
                    return Err(ErrorKind::MalformedState.into());
                }
                if one_time.insert(pub_key, sec).is_some() {
                    return Err(ErrorKind::MalformedState.into());
                }
            }

            let mut confirmed = HashSet::with_capacity(generation.confirmed_ephemeral_keys.len());
            for ephemeral_key in &generation.confirmed_ephemeral_keys {
                let ek = key(ephemeral_key)?;
                if !xeddsa::is_canonical_public_key(&ek) {
                    return Err(ErrorKind::MalformedState.into());
                }
                confirmed.insert(ek);
            }

            let mut pq_last_resort = BTreeMap::new();
            let mut last_resort_ids = HashSet::with_capacity(generation.pq_last_resort.len());
            for pq in &generation.pq_last_resort {
                let (id, secret) = parse_pq(pq)?;
                if pq_last_resort.insert(secret.suite, secret).is_some()
                    || !last_resort_ids.insert(id)
                {
                    return Err(ErrorKind::MalformedState.into());
                }
            }

            let mut pq_one_time = HashMap::with_capacity(generation.pq_one_time_prekeys.len());
            for pq in &generation.pq_one_time_prekeys {
                let (id, secret) = parse_pq(pq)?;
                if last_resort_ids.contains(&id) {
                    return Err(ErrorKind::MalformedState.into());
                }
                if pq_one_time.insert(id, secret).is_some() {
                    return Err(ErrorKind::MalformedState.into());
                }
            }

            generations.push_back(Generation {
                signed_prekey,
                signed_secret,
                one_time,
                confirmed,
                pq_last_resort,
                pq_one_time,
            });
        }
        Ok(Self { generations })
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
        if !xeddsa::is_canonical_public_key(bob_identity_key)
            || !xeddsa::is_canonical_public_key(&self.signed_prekey)
            || self
                .one_time_prekey
                .as_ref()
                .is_some_and(|k| !xeddsa::is_canonical_public_key(k))
        {
            return Err(ErrorKind::InvalidPublicKey.into());
        }
        XEdDSAPublicKey::new(bob_identity_key)?
            .verify(self.signed_prekey, &self.signed_prekey_signature)?;

        let (ephemeral_key, ephemeral_secret) = generate_key_pair();
        let mut key_material = KeyMaterial::new_classical();
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

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
impl PqPrekeyBundle {
    /// Alice's side (PQXDH): start a post-quantum session with Bob, whose identity key is
    /// `bob_identity_key`, from his bundle.
    ///
    /// Verifies:
    /// - `self.pq_suite` is enabled in this build,
    /// - all X25519 keys are canonically encoded,
    /// - `self.signed_prekey_signature` when `Some` (compat mode), or requires
    ///   `manifest_digest.is_some()` when `None` (strict mode where SPK is bound by a verified
    ///   capability manifest),
    /// - `self.pq_prekey_signature` under the distinct domain separator for last-resort PQSPK
    ///   (`pqxdh.v1/pqspk\0`) vs one-time PQOPK (`pqxdh.v1/pqopk\0`),
    /// - FIPS 203 encapsulation key validity during ML-KEM encapsulation.
    ///
    /// Returns the [`PqInitialMessage`] to send to Bob and the [`PqAgreement`].
    pub fn initiate_pq(
        &self,
        identity: &XEdDSAPrivateKey,
        bob_identity_key: &PublicKey,
        manifest_digest: Option<&[u8]>,
    ) -> Result<(PqInitialMessage, PqAgreement)> {
        if !self.pq_suite.is_supported() {
            return Err(ErrorKind::UnsupportedSuite.into());
        }
        if !xeddsa::is_canonical_public_key(bob_identity_key)
            || !xeddsa::is_canonical_public_key(&self.signed_prekey)
            || self
                .one_time_prekey
                .as_ref()
                .is_some_and(|k| !xeddsa::is_canonical_public_key(k))
        {
            return Err(ErrorKind::InvalidPublicKey.into());
        }
        if let Some(digest) = manifest_digest
            && (digest.is_empty() || u8::try_from(digest.len()).is_err())
        {
            return Err(ErrorKind::MalformedState.into());
        }

        let bob_pk = XEdDSAPublicKey::new(bob_identity_key)?;
        match &self.signed_prekey_signature {
            Some(sig) => bob_pk.verify(self.signed_prekey, sig)?,
            None => {
                if manifest_digest.is_none_or(|d| d.is_empty()) {
                    return Err(ErrorKind::InvalidSignature.into());
                }
            }
        }
        if self.pq_last_resort {
            verify_pq_spk_signature(
                bob_identity_key,
                self.pq_suite.as_u8(),
                &self.pq_prekey,
                &self.pq_prekey_signature,
            )?;
        } else {
            verify_pq_opk_signature(
                bob_identity_key,
                self.pq_suite.as_u8(),
                &self.pq_prekey,
                &self.pq_prekey_signature,
            )?;
        }

        let pq_id = pq_prekey_id(self.pq_suite.as_u8(), &self.pq_prekey);
        let (ephemeral_key, ephemeral_secret) = generate_key_pair();

        let mut key_material = KeyMaterial::new_pq();
        key_material.extend(&*identity.diffie_hellman(&self.signed_prekey)?);
        key_material.extend(diffie_hellman(&ephemeral_secret, bob_identity_key)?.as_bytes());
        key_material.extend(diffie_hellman(&ephemeral_secret, &self.signed_prekey)?.as_bytes());
        if let Some(one_time_prekey) = &self.one_time_prekey {
            key_material.extend(diffie_hellman(&ephemeral_secret, one_time_prekey)?.as_bytes());
        }
        let (pq_ciphertext, pq_ss) = kem::encapsulate(self.pq_suite, &self.pq_prekey)?;
        key_material.extend(&pq_ss);

        let identity_key = identity.compute_public_key().to_bytes();
        let transcript_hash = pq::compute_transcript_hash(
            &identity_key,
            bob_identity_key,
            &self.signed_prekey,
            self.one_time_prekey.as_ref(),
            &ephemeral_key,
            self.pq_suite,
            self.pq_last_resort,
            &pq_id,
            &pq_ciphertext,
            PQXDH_VERSION,
            manifest_digest,
        )?;
        let agreement = key_material.agree_pq(
            self.pq_suite,
            &identity_key,
            bob_identity_key,
            transcript_hash,
        );
        let message = PqInitialMessage {
            version: PQXDH_VERSION,
            identity_key,
            ephemeral_key,
            signed_prekey: self.signed_prekey,
            one_time_prekey: self.one_time_prekey,
            pq_suite: self.pq_suite,
            pq_last_resort: self.pq_last_resort,
            pq_prekey_id: pq_id,
            pq_ciphertext,
        };
        Ok((message, agreement))
    }
}

/// Checks canonical Curve25519 encoding of all X25519 public keys in an initial message.
fn check_canonical_keys(
    identity_key: &PublicKey,
    ephemeral_key: &PublicKey,
    signed_prekey: &PublicKey,
    one_time_prekey: Option<&PublicKey>,
) -> Result<()> {
    if !xeddsa::is_canonical_public_key(identity_key)
        || !xeddsa::is_canonical_public_key(ephemeral_key)
        || !xeddsa::is_canonical_public_key(signed_prekey)
        || one_time_prekey.is_some_and(|k| !xeddsa::is_canonical_public_key(k))
    {
        return Err(ErrorKind::InvalidPublicKey.into());
    }
    Ok(())
}

/// X3DH / PQXDH key material: the X25519 domain separator (`0xFF` × 32), then the DH outputs
/// (and, for PQXDH, the 32-byte ML-KEM shared secret).
struct KeyMaterial(Zeroizing<Vec<u8>>);

impl KeyMaterial {
    fn new_classical() -> Self {
        // Room for the separator and all four DH outputs, so growing never leaves copies behind.
        let mut key_material = Zeroizing::new(Vec::with_capacity(5 * PUBLIC_KEY_LENGTH));
        key_material.extend([0xFF; PUBLIC_KEY_LENGTH]);
        Self(key_material)
    }

    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    fn new_pq() -> Self {
        // Room for the separator, up to four DH outputs, and the 32-byte ML-KEM shared secret.
        let mut key_material = Zeroizing::new(Vec::with_capacity(
            5 * PUBLIC_KEY_LENGTH + PQ_SHARED_SECRET_LENGTH,
        ));
        key_material.extend([0xFF; PUBLIC_KEY_LENGTH]);
        Self(key_material)
    }

    fn extend(&mut self, component: &[u8; PUBLIC_KEY_LENGTH]) {
        self.0.extend_from_slice(component);
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

    /// PQXDH derivation:
    /// `SK = HKDF-SHA256(salt=[0; 32], ikm=IKM, info="pqxdh.v1/X25519/" || suite_name || "/SHA-256" || TH)`
    /// `AD = IK_A || IK_B || TH` (96 bytes).
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    fn agree_pq(
        self,
        suite: PqSuite,
        alice_identity_key: &PublicKey,
        bob_identity_key: &PublicKey,
        transcript_hash: [u8; 32],
    ) -> PqAgreement {
        let suite_name = suite.label().as_bytes();
        let mut info = Vec::with_capacity(
            b"pqxdh.v1/X25519/".len() + suite_name.len() + b"/SHA-256".len() + 32,
        );
        info.extend_from_slice(b"pqxdh.v1/X25519/");
        info.extend_from_slice(suite_name);
        info.extend_from_slice(b"/SHA-256");
        info.extend_from_slice(&transcript_hash);

        let mut secret_key = Zeroizing::new([0u8; SECRET_KEY_LENGTH]);
        Hkdf::<Sha256>::new(Some(&[0u8; HASH_LENGTH]), &self.0)
            .expand(&info, secret_key.as_mut_slice())
            .expect("SK's length is a valid HKDF-SHA256 output length");

        let mut associated_data = [0u8; PQXDH_ASSOCIATED_DATA_LENGTH];
        associated_data[..PUBLIC_KEY_LENGTH].copy_from_slice(alice_identity_key);
        associated_data[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(bob_identity_key);
        associated_data[2 * PUBLIC_KEY_LENGTH..].copy_from_slice(&transcript_hash);

        PqAgreement {
            secret_key,
            transcript_hash,
            associated_data,
            suite,
        }
    }
}

/// X25519, rejecting non-canonical encodings and public keys that make the shared secret all
/// zeros.
fn diffie_hellman(secret: &StaticSecret, public_key: &PublicKey) -> Result<SharedSecret> {
    if !xeddsa::is_canonical_public_key(public_key) {
        return Err(ErrorKind::InvalidPublicKey.into());
    }
    let shared_secret = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*public_key));
    if !shared_secret.was_contributory() {
        return Err(ErrorKind::InvalidPublicKey.into());
    }
    Ok(shared_secret)
}

fn generate_key_pair() -> (PublicKey, StaticSecret) {
    let mut bytes = Zeroizing::new([0u8; PUBLIC_KEY_LENGTH]);
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
    fn retracted_one_time_prekeys_go() {
        let (bob, mut prekeys, _) = bob_setup(2);
        let extended = prekeys.extend(&bob, 3);
        let one_time = |prekeys: &LocalPrekeys| prekeys.generations.back().unwrap().one_time.len();
        assert_eq!(one_time(&prekeys), 5);
        prekeys.retract(&extended.one_time_prekeys);
        assert_eq!(one_time(&prekeys), 2);
        assert_eq!(prekeys.generations.len(), 1);
    }

    #[test]
    fn alice_and_bob_agree() {
        for one_time_count in [0, 1] {
            let alice = XEdDSAPrivateKey::generate();
            let (bob, prekeys, bundle) = bob_setup(one_time_count);
            let alice_key = public_key(&alice);
            let bob_key = public_key(&bob);

            let (message, alice_agreement) = bundle.initiate(&alice, &bob_key).unwrap();
            let (bob_agreement, _) = prekeys.accept(&bob, &alice_key, &message).unwrap();
            assert_eq!(*alice_agreement.secret_key, *bob_agreement.secret_key);
            assert_eq!(
                alice_agreement.associated_data,
                bob_agreement.associated_data
            );
        }
    }

    #[test]
    fn extending_keeps_the_prekeys_handed_out() {
        let alice = XEdDSAPrivateKey::generate();
        let (bob, mut prekeys, first) = bob_setup(1);
        let (alice_key, bob_key) = (public_key(&alice), public_key(&bob));
        // Published again, as the reply to the first publish was lost: the same signed prekey,
        // and new one-time prekeys; one handed out before still works.
        let again = prekeys.extend(&bob, 1);
        assert_eq!(again.signed_prekey, first.signed_prekey);
        assert_ne!(
            again.one_time_prekeys.first().copied(),
            first.one_time_prekey
        );
        let second = PrekeyBundle {
            signed_prekey: again.signed_prekey,
            signed_prekey_signature: again.signed_prekey_signature,
            one_time_prekey: again.one_time_prekeys.first().copied(),
        };
        for bundle in [first, second] {
            let (message, _) = bundle.initiate(&alice, &bob_key).unwrap();
            prekeys.accept(&bob, &alice_key, &message).unwrap();
        }
    }

    #[test]
    fn rejections() {
        let alice = XEdDSAPrivateKey::generate();
        let (bob, _, bundle) = bob_setup(1);
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
    }

    #[test]
    fn classical_rejects_non_canonical_keys_and_ek_replay_bypass() {
        let alice = XEdDSAPrivateKey::generate();
        let (bob, mut prekeys, bundle) = bob_setup(1);
        let alice_key = public_key(&alice);
        let bob_key = public_key(&bob);

        // Non-canonical Bob IK fails initiate.
        let mut nc_bob = bob_key;
        nc_bob[31] |= 0x80;
        assert_eq!(
            bundle.initiate(&alice, &nc_bob).unwrap_err().kind(),
            ErrorKind::InvalidPublicKey
        );

        // Non-canonical SPK (even signed by Bob) fails initiate.
        let mut nc_spk = bundle.signed_prekey;
        nc_spk[31] |= 0x80;
        let nc_spk_bundle = PrekeyBundle {
            signed_prekey: nc_spk,
            signed_prekey_signature: bob.sign(nc_spk),
            one_time_prekey: None,
        };
        assert_eq!(
            nc_spk_bundle.initiate(&alice, &bob_key).unwrap_err().kind(),
            ErrorKind::InvalidPublicKey
        );

        // Non-canonical OPK fails initiate.
        let mut nc_opk = bundle.one_time_prekey.unwrap();
        nc_opk[31] |= 0x80;
        let nc_opk_bundle = PrekeyBundle {
            one_time_prekey: Some(nc_opk),
            ..bundle.clone()
        };
        assert_eq!(
            nc_opk_bundle.initiate(&alice, &bob_key).unwrap_err().kind(),
            ErrorKind::InvalidPublicKey
        );

        // H-1: Confirm a no-OPK initial message, then try to bypass `confirmed` with bit-255-set EK.
        let no_opk = PrekeyBundle {
            one_time_prekey: None,
            ..bundle
        };
        let (message, _) = no_opk.initiate(&alice, &bob_key).unwrap();
        prekeys.accept(&bob, &alice_key, &message).unwrap();
        prekeys.confirm(&message).unwrap();

        assert_eq!(
            prekeys
                .accept(&bob, &alice_key, &message)
                .err()
                .unwrap()
                .kind(),
            ErrorKind::Replayed
        );
        let mut aliased = message.clone();
        aliased.ephemeral_key[31] |= 0x80;
        assert_eq!(
            prekeys
                .accept(&bob, &alice_key, &aliased)
                .err()
                .unwrap()
                .kind(),
            ErrorKind::InvalidPublicKey
        );
        assert_eq!(
            prekeys.confirm(&aliased).unwrap_err().kind(),
            ErrorKind::InvalidPublicKey
        );

        // Non-canonical Alice IK fails accept.
        let (fresh, _) = no_opk.initiate(&alice, &bob_key).unwrap();
        let mut nc_alice = alice_key;
        nc_alice[31] |= 0x80;
        let mut nc_msg = fresh.clone();
        nc_msg.identity_key = nc_alice;
        assert_eq!(
            prekeys
                .accept(&bob, &nc_alice, &nc_msg)
                .err()
                .unwrap()
                .kind(),
            ErrorKind::InvalidPublicKey
        );

        // Mixed-order (B + order_8) and twist (u = 2) Alice IKs fail accept and confirm even
        // though they are canonically encoded and contributory under clamped X25519.
        let mixed_order_ik: PublicKey = [
            52, 252, 108, 183, 200, 222, 88, 151, 119, 112, 217, 82, 22, 204, 220, 108, 133, 144,
            190, 205, 145, 156, 7, 89, 148, 20, 86, 59, 75, 164, 71, 15,
        ];
        let mut twist_ik = [0u8; 32];
        twist_ik[0] = 2;
        for bad_ik in [mixed_order_ik, twist_ik] {
            assert!(xeddsa::is_canonical_public_key(&bad_ik));
            assert!(XEdDSAPublicKey::new(&bad_ik).is_err());
            let mut bad_msg = fresh.clone();
            bad_msg.identity_key = bad_ik;
            assert_eq!(
                prekeys
                    .accept(&bob, &bad_ik, &bad_msg)
                    .err()
                    .unwrap()
                    .kind(),
                ErrorKind::InvalidPublicKey
            );
            assert_eq!(
                prekeys.confirm(&bad_msg).unwrap_err().kind(),
                ErrorKind::InvalidPublicKey
            );
        }
    }

    #[test]
    fn only_confirming_uses_up() {
        let alice = XEdDSAPrivateKey::generate();
        let (bob, mut prekeys, bundle) = bob_setup(1);
        let alice_key = public_key(&alice);
        let bob_key = public_key(&bob);
        let (message, _) = bundle.initiate(&alice, &bob_key).unwrap();

        // Accepting changes nothing, so a message that turns out not to be Alice's uses up
        // nothing.
        prekeys.accept(&bob, &alice_key, &message).unwrap();
        prekeys.accept(&bob, &alice_key, &message).unwrap();
        prekeys.confirm(&message).unwrap();
        // Confirmed, it cannot be accepted again, and its one-time prekey is gone.
        let error = prekeys.accept(&bob, &alice_key, &message).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::Replayed);
        let (other, _) = bundle.initiate(&alice, &bob_key).unwrap();
        let error = prekeys.accept(&bob, &alice_key, &other).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::OneTimePrekeyNotFound);

        // Without a one-time prekey, one sent again is refused too.
        let without_one_time_prekey = PrekeyBundle {
            one_time_prekey: None,
            ..bundle
        };
        let (message, _) = without_one_time_prekey.initiate(&alice, &bob_key).unwrap();
        prekeys.accept(&bob, &alice_key, &message).unwrap();
        prekeys.confirm(&message).unwrap();
        let error = prekeys.accept(&bob, &alice_key, &message).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::Replayed);
        assert_eq!(
            prekeys.confirm(&message).unwrap_err().kind(),
            ErrorKind::Replayed
        );
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
    }

    #[test]
    fn pq_suite_metadata_and_unconditional_signature_helpers() {
        assert_eq!(PqSuite::from_u8(1), Some(PqSuite::MlKem1024));
        assert_eq!(PqSuite::from_u8(2), Some(PqSuite::MlKem768));
        assert_eq!(PqSuite::from_u8(0), None);
        assert_eq!(PqSuite::from_u8(3), None);

        assert_eq!(PqSuite::MlKem1024.as_u8(), 1);
        assert_eq!(PqSuite::MlKem1024.ek_len(), 1568);
        assert_eq!(PqSuite::MlKem1024.ct_len(), 1568);
        assert_eq!(PqSuite::MlKem1024.label(), "ML-KEM-1024");
        assert_eq!(
            PqSuite::MlKem1024.is_supported(),
            cfg!(feature = "ml-kem-1024")
        );

        assert_eq!(PqSuite::MlKem768.as_u8(), 2);
        assert_eq!(PqSuite::MlKem768.ek_len(), 1184);
        assert_eq!(PqSuite::MlKem768.ct_len(), 1088);
        assert_eq!(PqSuite::MlKem768.label(), "ML-KEM-768");
        assert_eq!(
            PqSuite::MlKem768.is_supported(),
            cfg!(feature = "ml-kem-768")
        );

        // Deterministic pq_prekey_id differs across suites even for identical bytes.
        let fake_ek = vec![0x42u8; 1568];
        let id1 = pq_prekey_id(1, &fake_ek);
        let id1_again = pq_prekey_id(1, &fake_ek);
        let id2 = pq_prekey_id(2, &fake_ek);
        assert_eq!(id1, id1_again);
        assert_ne!(id1, id2);

        // Domain-separated signing inputs and verifiers work without ml-kem.
        let bob = XEdDSAPrivateKey::generate();
        let bob_ik = public_key(&bob);
        for suite in [PqSuite::MlKem1024, PqSuite::MlKem768] {
            let ek = vec![0x33u8; suite.ek_len()];
            let spk_input = pq_spk_signing_input(suite.as_u8(), &ek);
            let opk_input = pq_opk_signing_input(suite.as_u8(), &ek);
            assert!(spk_input.starts_with(b"pqxdh.v1/pqspk\0"));
            assert!(opk_input.starts_with(b"pqxdh.v1/pqopk\0"));
            assert_ne!(spk_input, opk_input);

            let spk_sig = sign_pq_spk(&bob, suite, &ek).unwrap();
            let opk_sig = sign_pq_opk(&bob, suite, &ek).unwrap();

            verify_pq_spk_signature(&bob_ik, suite.as_u8(), &ek, &spk_sig).unwrap();
            verify_pq_opk_signature(&bob_ik, suite.as_u8(), &ek, &opk_sig).unwrap();

            // Cross-domain replay must fail!
            assert_eq!(
                verify_pq_opk_signature(&bob_ik, suite.as_u8(), &ek, &spk_sig)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSignature
            );
            assert_eq!(
                verify_pq_spk_signature(&bob_ik, suite.as_u8(), &ek, &opk_sig)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSignature
            );

            // Wrong length fails with InvalidPublicKey.
            assert_eq!(
                verify_pq_spk_signature(&bob_ik, suite.as_u8(), &ek[..ek.len() - 1], &spk_sig)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidPublicKey
            );
            assert_eq!(
                verify_pq_opk_signature(&bob_ik, suite.as_u8(), &ek[..ek.len() - 1], &opk_sig)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidPublicKey
            );
        }

        // Unknown suite fails with UnsupportedSuite.
        assert_eq!(
            verify_pq_spk_signature(&bob_ik, 99, &[0u8; 32], &[0u8; 64])
                .unwrap_err()
                .kind(),
            ErrorKind::UnsupportedSuite
        );
        assert_eq!(
            verify_pq_opk_signature(&bob_ik, 0, &[0u8; 32], &[0u8; 64])
                .unwrap_err()
                .kind(),
            ErrorKind::UnsupportedSuite
        );
    }

    /// `prekeys` saved and restored, once through each format enabled.
    #[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
    fn restored(prekeys: &LocalPrekeys) -> Vec<LocalPrekeys> {
        Vec::from([
            #[cfg(feature = "serde")]
            serde_json::from_str(&serde_json::to_string(prekeys).unwrap()).unwrap(),
            #[cfg(feature = "rkyv")]
            rkyv::from_bytes::<_, rkyv::rancor::Error>(
                &rkyv::to_bytes::<rkyv::rancor::Error>(prekeys).unwrap(),
            )
            .unwrap(),
            #[cfg(feature = "prost")]
            LocalPrekeys::try_from(&proto::LocalPrekeys::from(prekeys)).unwrap(),
        ])
    }

    #[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
    #[test]
    fn restored_prekeys_accept() {
        let alice = XEdDSAPrivateKey::generate();
        let (bob, mut prekeys, first) = bob_setup(1);
        let second = prekeys.generate(&bob, 2);
        // An initial message for each generation, with one of its one-time prekeys.
        let second = PrekeyBundle {
            signed_prekey: second.signed_prekey,
            signed_prekey_signature: second.signed_prekey_signature,
            one_time_prekey: second.one_time_prekeys.get(1).copied(),
        };
        // And one confirmed before saving, which cannot be accepted again.
        let (confirmed, _) = PrekeyBundle {
            one_time_prekey: None,
            ..second.clone()
        }
        .initiate(&alice, &public_key(&bob))
        .unwrap();
        prekeys.confirm(&confirmed).unwrap();
        let initiated = [first, second].map(|bundle| bundle.initiate(&alice, &public_key(&bob)));
        for restored in restored(&prekeys) {
            for (message, agreement) in initiated.iter().map(|result| result.as_ref().unwrap()) {
                let (accepted, _) = restored.accept(&bob, &public_key(&alice), message).unwrap();
                assert_eq!(*accepted.secret_key, *agreement.secret_key);
            }
            let error = restored
                .accept(&bob, &public_key(&alice), &confirmed)
                .err()
                .unwrap();
            assert_eq!(error.kind(), ErrorKind::Replayed);
        }
    }

    #[cfg(feature = "prost")]
    #[test]
    fn prost_deserialization_hardening() {
        let bob = XEdDSAPrivateKey::generate();
        let mut prekeys = LocalPrekeys::new();
        prekeys.generate(&bob, 2);
        prekeys.generate(&bob, 1);

        // 1. Too many generations (> KEPT_GENERATIONS).
        let mut p = proto::LocalPrekeys::from(&prekeys);
        let extra = p.generations[0].clone();
        p.generations.push(extra);
        assert_eq!(
            LocalPrekeys::try_from(&p).unwrap_err().kind(),
            ErrorKind::MalformedState
        );

        // 2. Duplicate signed_prekey across generations.
        let mut p = proto::LocalPrekeys::from(&prekeys);
        p.generations[1] = p.generations[0].clone();
        assert_eq!(
            LocalPrekeys::try_from(&p).unwrap_err().kind(),
            ErrorKind::MalformedState
        );

        // 3. Mismatched signed_prekey vs signed_secret.
        let mut p = proto::LocalPrekeys::from(&prekeys);
        p.generations[0].signed_prekey[0] ^= 0x01;
        assert_eq!(
            LocalPrekeys::try_from(&p).unwrap_err().kind(),
            ErrorKind::MalformedState
        );

        // 4. Mismatched one-time prekey pub vs secret.
        let mut p = proto::LocalPrekeys::from(&prekeys);
        p.generations[0].one_time_prekeys[0].public_key[0] ^= 0x01;
        assert_eq!(
            LocalPrekeys::try_from(&p).unwrap_err().kind(),
            ErrorKind::MalformedState
        );

        // 5. Duplicate one-time prekey in same generation.
        let mut p = proto::LocalPrekeys::from(&prekeys);
        let dup = p.generations[0].one_time_prekeys[0].clone();
        p.generations[0].one_time_prekeys.push(dup);
        assert_eq!(
            LocalPrekeys::try_from(&p).unwrap_err().kind(),
            ErrorKind::MalformedState
        );

        // 6. Non-canonical confirmed ephemeral key.
        let mut p = proto::LocalPrekeys::from(&prekeys);
        let mut bad_ek = [0u8; 32];
        bad_ek[31] = 0x80;
        p.generations[0]
            .confirmed_ephemeral_keys
            .push(bad_ek.to_vec());
        assert_eq!(
            LocalPrekeys::try_from(&p).unwrap_err().kind(),
            ErrorKind::MalformedState
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_deserialization_hardening() {
        let bob = XEdDSAPrivateKey::generate();
        let mut prekeys = LocalPrekeys::new();
        prekeys.generate(&bob, 1);
        prekeys.generate(&bob, 1);

        // Legacy classical JSON (without pq_last_resort / pq_one_time) still loads cleanly.
        let mut val: serde_json::Value = serde_json::to_value(&prekeys).unwrap();
        for g in val["generations"].as_array_mut().unwrap() {
            g.as_object_mut().unwrap().remove("pq_last_resort");
            g.as_object_mut().unwrap().remove("pq_one_time");
        }
        let legacy_loaded: LocalPrekeys = serde_json::from_value(val.clone()).unwrap();
        assert_eq!(legacy_loaded.generation_count(), 2);

        // > KEPT_GENERATIONS fails.
        let mut too_many = val.clone();
        let extra = too_many["generations"][0].clone();
        too_many["generations"].as_array_mut().unwrap().push(extra);
        assert!(serde_json::from_value::<LocalPrekeys>(too_many).is_err());

        // Mismatched signed_prekey fails.
        let mut bad_spk = val.clone();
        let b0 = bad_spk["generations"][0]["signed_prekey"][0]
            .as_u64()
            .unwrap();
        bad_spk["generations"][0]["signed_prekey"][0] = serde_json::json!((b0 ^ 1) as u8);
        assert!(serde_json::from_value::<LocalPrekeys>(bad_spk).is_err());

        // Non-canonical confirmed EK fails.
        let mut bad_ek = val;
        let mut ek = [0u8; 32];
        ek[31] = 0x80;
        bad_ek["generations"][0]["confirmed"] = serde_json::json!([ek]);
        assert!(serde_json::from_value::<LocalPrekeys>(bad_ek).is_err());
    }

    #[cfg(feature = "rkyv")]
    #[test]
    fn rkyv_deserialization_hardening() {
        let bob = XEdDSAPrivateKey::generate();
        let mut prekeys = LocalPrekeys::new();
        prekeys.generate(&bob, 1);

        // Corrupt a byte of the signed_prekey inside an in-memory invalid LocalPrekeys and archive.
        let mut bad = LocalPrekeys::new();
        bad.generate(&bob, 1);
        bad.generations[0].signed_prekey[0] ^= 0x01;
        let bad_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&bad).unwrap();
        assert!(rkyv::from_bytes::<LocalPrekeys, rkyv::rancor::Error>(&bad_bytes).is_err());

        // Too many generations fails Verify.
        let mut too_many = LocalPrekeys::new();
        too_many.generate(&bob, 0);
        too_many.generate(&bob, 0);
        let (spk, sec) = generate_key_pair();
        too_many.generations.push_back(Generation {
            signed_prekey: spk,
            signed_secret: sec,
            one_time: HashMap::new(),
            confirmed: HashSet::new(),
            pq_last_resort: BTreeMap::new(),
            pq_one_time: HashMap::new(),
        });
        let too_many_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&too_many).unwrap();
        assert!(rkyv::from_bytes::<LocalPrekeys, rkyv::rancor::Error>(&too_many_bytes).is_err());

        // Non-canonical confirmed EK fails Verify.
        let mut bad_ek = LocalPrekeys::new();
        bad_ek.generate(&bob, 0);
        let mut ek = [0u8; 32];
        ek[31] = 0x80;
        bad_ek.generations[0].confirmed.insert(ek);
        let bad_ek_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&bad_ek).unwrap();
        assert!(rkyv::from_bytes::<LocalPrekeys, rkyv::rancor::Error>(&bad_ek_bytes).is_err());
    }

    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    mod pq_tests {

        use super::*;

        fn enabled_suites() -> Vec<PqSuite> {
            vec![
                #[cfg(feature = "ml-kem-1024")]
                PqSuite::MlKem1024,
                #[cfg(feature = "ml-kem-768")]
                PqSuite::MlKem768,
            ]
        }

        #[test]
        fn pqxdh_initiate_accept_all_modes() {
            for suite in enabled_suites() {
                let alice = XEdDSAPrivateKey::generate();
                let bob = XEdDSAPrivateKey::generate();
                let alice_ik = public_key(&alice);
                let bob_ik = public_key(&bob);

                let mut prekeys = LocalPrekeys::new();
                let published = prekeys.generate_pq(&bob, suite, 2, 2).unwrap();
                assert_eq!(
                    prekeys.current_signed_prekey(),
                    Some(published.classical.signed_prekey)
                );
                assert_eq!(
                    prekeys.current_pq_last_resort_id(suite),
                    Some(published.pq_last_resort.id)
                );
                assert_eq!(prekeys.current_one_time_count(), 2);
                assert_eq!(prekeys.current_pq_one_time_count(suite), 2);

                let manifest = [0xabu8; 32];
                for use_opk in [false, true] {
                    for use_last_resort in [false, true] {
                        for (spk_sig, manifest_digest) in [
                            (Some(published.classical.signed_prekey_signature), None),
                            (
                                Some(published.classical.signed_prekey_signature),
                                Some(manifest.as_slice()),
                            ),
                            (None, Some(manifest.as_slice())),
                        ] {
                            let pq_key = if use_last_resort {
                                &published.pq_last_resort
                            } else {
                                &published.pq_one_time_prekeys[0]
                            };
                            let bundle = PqPrekeyBundle {
                                signed_prekey: published.classical.signed_prekey,
                                signed_prekey_signature: spk_sig,
                                one_time_prekey: use_opk
                                    .then(|| published.classical.one_time_prekeys[0]),
                                pq_suite: suite,
                                pq_prekey: pq_key.encapsulation_key.clone(),
                                pq_prekey_signature: pq_key.signature,
                                pq_last_resort: use_last_resort,
                            };

                            let (msg, alice_ag) = bundle
                                .initiate_pq(&alice, &bob_ik, manifest_digest)
                                .unwrap();
                            assert_eq!(msg.version, PQXDH_VERSION);
                            assert_eq!(msg.pq_suite, suite);
                            assert_eq!(msg.pq_last_resort, use_last_resort);
                            assert_eq!(msg.pq_prekey_id, pq_key.id);
                            assert_eq!(msg.pq_ciphertext.len(), suite.ct_len());

                            let (bob_ag, _) = prekeys
                                .accept_pq(&bob, &alice_ik, &msg, manifest_digest)
                                .unwrap();
                            assert_eq!(*alice_ag.secret_key, *bob_ag.secret_key);
                            assert_eq!(alice_ag.transcript_hash, bob_ag.transcript_hash);
                            assert_eq!(alice_ag.associated_data, bob_ag.associated_data);
                            assert_eq!(&alice_ag.associated_data[..32], &alice_ik);
                            assert_eq!(&alice_ag.associated_data[32..64], &bob_ik);
                            assert_eq!(
                                &alice_ag.associated_data[64..96],
                                &alice_ag.transcript_hash
                            );
                            assert_eq!(alice_ag.suite, suite);

                            // Mismatched manifest digest changes TH and SK.
                            let wrong_manifest = [0xcdu8; 32];
                            let (wrong_ag, _) = prekeys
                                .accept_pq(&bob, &alice_ik, &msg, Some(&wrong_manifest))
                                .unwrap();
                            assert_ne!(wrong_ag.transcript_hash, alice_ag.transcript_hash);
                            assert_ne!(*wrong_ag.secret_key, *alice_ag.secret_key);
                        }
                    }
                }

                // Strict mode without manifest_digest is rejected (SPK would be unauthenticated).
                let unauth_bundle = PqPrekeyBundle {
                    signed_prekey: published.classical.signed_prekey,
                    signed_prekey_signature: None,
                    one_time_prekey: None,
                    pq_suite: suite,
                    pq_prekey: published.pq_last_resort.encapsulation_key.clone(),
                    pq_prekey_signature: published.pq_last_resort.signature,
                    pq_last_resort: true,
                };
                assert_eq!(
                    unauth_bundle
                        .initiate_pq(&alice, &bob_ik, None)
                        .unwrap_err()
                        .kind(),
                    ErrorKind::InvalidSignature
                );

                // Empty manifest_digest Some(&[]) must NOT bypass strict mode or collide with None.
                assert_eq!(
                    unauth_bundle
                        .initiate_pq(&alice, &bob_ik, Some(&[]))
                        .unwrap_err()
                        .kind(),
                    ErrorKind::MalformedState
                );
                let compat_bundle = PqPrekeyBundle {
                    signed_prekey_signature: Some(published.classical.signed_prekey_signature),
                    ..unauth_bundle
                };
                assert_eq!(
                    compat_bundle
                        .initiate_pq(&alice, &bob_ik, Some(&[]))
                        .unwrap_err()
                        .kind(),
                    ErrorKind::MalformedState
                );
                assert_eq!(
                    compat_bundle
                        .initiate_pq(&alice, &bob_ik, Some(&[0u8; 256]))
                        .unwrap_err()
                        .kind(),
                    ErrorKind::MalformedState
                );

                let (valid_msg, _) = compat_bundle.initiate_pq(&alice, &bob_ik, None).unwrap();
                assert_eq!(
                    prekeys
                        .accept_pq(&bob, &alice_ik, &valid_msg, Some(&[]))
                        .err()
                        .unwrap()
                        .kind(),
                    ErrorKind::MalformedState
                );
                assert_eq!(
                    prekeys
                        .accept_pq(&bob, &alice_ik, &valid_msg, Some(&[0u8; 256]))
                        .err()
                        .unwrap()
                        .kind(),
                    ErrorKind::MalformedState
                );

                // Mixed-order (B + order_8) and twist (u = 2) Alice IKs fail accept_pq and confirm_pq.
                let mixed_order_ik: PublicKey = [
                    52, 252, 108, 183, 200, 222, 88, 151, 119, 112, 217, 82, 22, 204, 220, 108,
                    133, 144, 190, 205, 145, 156, 7, 89, 148, 20, 86, 59, 75, 164, 71, 15,
                ];
                let mut twist_ik = [0u8; 32];
                twist_ik[0] = 2;
                for bad_ik in [mixed_order_ik, twist_ik] {
                    let mut bad_msg = valid_msg.clone();
                    bad_msg.identity_key = bad_ik;
                    assert_eq!(
                        prekeys
                            .accept_pq(&bob, &bad_ik, &bad_msg, None)
                            .err()
                            .unwrap()
                            .kind(),
                        ErrorKind::InvalidPublicKey
                    );
                    assert_eq!(
                        prekeys.confirm_pq(&bad_msg).unwrap_err().kind(),
                        ErrorKind::InvalidPublicKey
                    );
                }
            }
        }

        #[test]
        fn pqxdh_confirm_replay_and_last_resort_preservation() {
            for suite in enabled_suites() {
                let alice = XEdDSAPrivateKey::generate();
                let bob = XEdDSAPrivateKey::generate();
                let alice_ik = public_key(&alice);
                let bob_ik = public_key(&bob);

                let mut prekeys = LocalPrekeys::new();
                let published = prekeys.generate_pq(&bob, suite, 1, 1).unwrap();

                // 1. PQOPK: accept is read-only; confirm consumes PQOPK + OPK and blocks replay.
                let pqopk_bundle = PqPrekeyBundle {
                    signed_prekey: published.classical.signed_prekey,
                    signed_prekey_signature: Some(published.classical.signed_prekey_signature),
                    one_time_prekey: Some(published.classical.one_time_prekeys[0]),
                    pq_suite: suite,
                    pq_prekey: published.pq_one_time_prekeys[0].encapsulation_key.clone(),
                    pq_prekey_signature: published.pq_one_time_prekeys[0].signature,
                    pq_last_resort: false,
                };
                let (msg1, ag1) = pqopk_bundle.initiate_pq(&alice, &bob_ik, None).unwrap();
                let (bob_ag1, _) = prekeys.accept_pq(&bob, &alice_ik, &msg1, None).unwrap();
                assert_eq!(*ag1.secret_key, *bob_ag1.secret_key);
                // Second accept before confirm still succeeds.
                prekeys.accept_pq(&bob, &alice_ik, &msg1, None).unwrap();

                prekeys.confirm_pq(&msg1).unwrap();
                assert_eq!(prekeys.current_one_time_count(), 0);
                assert_eq!(prekeys.current_pq_one_time_count(suite), 0);

                // Replay fails with Replayed; aliased EK fails with InvalidPublicKey.
                assert_eq!(
                    prekeys
                        .accept_pq(&bob, &alice_ik, &msg1, None)
                        .err()
                        .unwrap()
                        .kind(),
                    ErrorKind::Replayed
                );
                assert_eq!(
                    prekeys.confirm_pq(&msg1).unwrap_err().kind(),
                    ErrorKind::Replayed
                );
                let mut aliased = msg1.clone();
                aliased.ephemeral_key[31] |= 0x80;
                assert_eq!(
                    prekeys
                        .accept_pq(&bob, &alice_ik, &aliased, None)
                        .err()
                        .unwrap()
                        .kind(),
                    ErrorKind::InvalidPublicKey
                );

                // A fresh initiation against the already-consumed PQOPK fails with PqPrekeyNotFound.
                let pqopk_no_opk = PqPrekeyBundle {
                    one_time_prekey: None,
                    ..pqopk_bundle
                };
                let (msg2, _) = pqopk_no_opk.initiate_pq(&alice, &bob_ik, None).unwrap();
                assert_eq!(
                    prekeys
                        .accept_pq(&bob, &alice_ik, &msg2, None)
                        .err()
                        .unwrap()
                        .kind(),
                    ErrorKind::PqPrekeyNotFound
                );

                // 2. Last-resort PQSPK: confirm preserves its seed so a second fresh EK succeeds,
                // while replaying the first message fails.
                let lr_bundle = PqPrekeyBundle {
                    signed_prekey: published.classical.signed_prekey,
                    signed_prekey_signature: Some(published.classical.signed_prekey_signature),
                    one_time_prekey: None,
                    pq_suite: suite,
                    pq_prekey: published.pq_last_resort.encapsulation_key.clone(),
                    pq_prekey_signature: published.pq_last_resort.signature,
                    pq_last_resort: true,
                };
                let (lr_msg1, lr_ag1) = lr_bundle.initiate_pq(&alice, &bob_ik, None).unwrap();
                let (bob_lr1, _) = prekeys.accept_pq(&bob, &alice_ik, &lr_msg1, None).unwrap();
                assert_eq!(*lr_ag1.secret_key, *bob_lr1.secret_key);
                prekeys.confirm_pq(&lr_msg1).unwrap();

                // Replaying lr_msg1 fails (canonical EK in `confirmed`).
                assert_eq!(
                    prekeys
                        .accept_pq(&bob, &alice_ik, &lr_msg1, None)
                        .err()
                        .unwrap()
                        .kind(),
                    ErrorKind::Replayed
                );
                // Replaying lr_msg1 with non-canonical EK fails with InvalidPublicKey.
                let mut lr_aliased = lr_msg1.clone();
                lr_aliased.ephemeral_key[31] |= 0x80;
                assert_eq!(
                    prekeys
                        .accept_pq(&bob, &alice_ik, &lr_aliased, None)
                        .err()
                        .unwrap()
                        .kind(),
                    ErrorKind::InvalidPublicKey
                );

                // A fresh initiation using the SAME last-resort PQSPK still succeeds!
                let (lr_msg2, lr_ag2) = lr_bundle.initiate_pq(&alice, &bob_ik, None).unwrap();
                let (bob_lr2, _) = prekeys.accept_pq(&bob, &alice_ik, &lr_msg2, None).unwrap();
                assert_eq!(*lr_ag2.secret_key, *bob_lr2.secret_key);
                assert_ne!(*lr_ag1.secret_key, *lr_ag2.secret_key);
            }
        }

        #[test]
        fn pqxdh_rejects_cross_gen_wrong_domain_and_tampering() {
            for suite in enabled_suites() {
                let alice = XEdDSAPrivateKey::generate();
                let bob = XEdDSAPrivateKey::generate();
                let alice_ik = public_key(&alice);
                let bob_ik = public_key(&bob);

                let mut prekeys = LocalPrekeys::new();
                let gen1 = prekeys.generate_pq(&bob, suite, 1, 1).unwrap();
                let gen2 = prekeys.generate_pq(&bob, suite, 1, 1).unwrap();

                // 1. Cross-generation mix: gen1 SPK + gen2 PQOPK fails accept_pq.
                let cross_opk = PqPrekeyBundle {
                    signed_prekey: gen1.classical.signed_prekey,
                    signed_prekey_signature: Some(gen1.classical.signed_prekey_signature),
                    one_time_prekey: None,
                    pq_suite: suite,
                    pq_prekey: gen2.pq_one_time_prekeys[0].encapsulation_key.clone(),
                    pq_prekey_signature: gen2.pq_one_time_prekeys[0].signature,
                    pq_last_resort: false,
                };
                let (cross_msg, _) = cross_opk.initiate_pq(&alice, &bob_ik, None).unwrap();
                assert_eq!(
                    prekeys
                        .accept_pq(&bob, &alice_ik, &cross_msg, None)
                        .err()
                        .unwrap()
                        .kind(),
                    ErrorKind::PqPrekeyNotFound
                );

                // 2. Cross-generation mix: gen1 SPK + gen2 last-resort PQSPK fails accept_pq.
                let cross_lr = PqPrekeyBundle {
                    signed_prekey: gen1.classical.signed_prekey,
                    signed_prekey_signature: Some(gen1.classical.signed_prekey_signature),
                    one_time_prekey: None,
                    pq_suite: suite,
                    pq_prekey: gen2.pq_last_resort.encapsulation_key.clone(),
                    pq_prekey_signature: gen2.pq_last_resort.signature,
                    pq_last_resort: true,
                };
                let (cross_lr_msg, _) = cross_lr.initiate_pq(&alice, &bob_ik, None).unwrap();
                assert_eq!(
                    prekeys
                        .accept_pq(&bob, &alice_ik, &cross_lr_msg, None)
                        .err()
                        .unwrap()
                        .kind(),
                    ErrorKind::PqPrekeyNotFound
                );

                // 3. Wrong signature domain: PQOPK key presented with pq_last_resort = true.
                let wrong_domain_1 = PqPrekeyBundle {
                    signed_prekey: gen2.classical.signed_prekey,
                    signed_prekey_signature: Some(gen2.classical.signed_prekey_signature),
                    one_time_prekey: None,
                    pq_suite: suite,
                    pq_prekey: gen2.pq_one_time_prekeys[0].encapsulation_key.clone(),
                    pq_prekey_signature: gen2.pq_one_time_prekeys[0].signature,
                    pq_last_resort: true,
                };
                assert_eq!(
                    wrong_domain_1
                        .initiate_pq(&alice, &bob_ik, None)
                        .unwrap_err()
                        .kind(),
                    ErrorKind::InvalidSignature
                );

                // 4. Wrong signature domain: last-resort PQSPK presented with pq_last_resort = false.
                let wrong_domain_2 = PqPrekeyBundle {
                    signed_prekey: gen2.classical.signed_prekey,
                    signed_prekey_signature: Some(gen2.classical.signed_prekey_signature),
                    one_time_prekey: None,
                    pq_suite: suite,
                    pq_prekey: gen2.pq_last_resort.encapsulation_key.clone(),
                    pq_prekey_signature: gen2.pq_last_resort.signature,
                    pq_last_resort: false,
                };
                assert_eq!(
                    wrong_domain_2
                        .initiate_pq(&alice, &bob_ik, None)
                        .unwrap_err()
                        .kind(),
                    ErrorKind::InvalidSignature
                );

                // 5. Role-flag flip on PqInitialMessage fails accept_pq.
                let valid_bundle = PqPrekeyBundle {
                    signed_prekey: gen2.classical.signed_prekey,
                    signed_prekey_signature: Some(gen2.classical.signed_prekey_signature),
                    one_time_prekey: None,
                    pq_suite: suite,
                    pq_prekey: gen2.pq_one_time_prekeys[0].encapsulation_key.clone(),
                    pq_prekey_signature: gen2.pq_one_time_prekeys[0].signature,
                    pq_last_resort: false,
                };
                let (valid_msg, alice_ag) =
                    valid_bundle.initiate_pq(&alice, &bob_ik, None).unwrap();

                let mut flipped_role = valid_msg.clone();
                flipped_role.pq_last_resort = true;
                assert_eq!(
                    prekeys
                        .accept_pq(&bob, &alice_ik, &flipped_role, None)
                        .err()
                        .unwrap()
                        .kind(),
                    ErrorKind::PqPrekeyNotFound
                );

                // 6. Wrong protocol version fails accept_pq.
                let mut bad_ver = valid_msg.clone();
                bad_ver.version = 1;
                assert_eq!(
                    prekeys
                        .accept_pq(&bob, &alice_ik, &bad_ver, None)
                        .err()
                        .unwrap()
                        .kind(),
                    ErrorKind::UnsupportedVersion
                );

                // 7. Truncated ciphertext fails accept_pq with InvalidCiphertext.
                let mut bad_ct_len = valid_msg.clone();
                bad_ct_len.pq_ciphertext.pop();
                assert_eq!(
                    prekeys
                        .accept_pq(&bob, &alice_ik, &bad_ct_len, None)
                        .err()
                        .unwrap()
                        .kind(),
                    ErrorKind::InvalidCiphertext
                );

                // 8. Tampered ciphertext bit yields different SK and TH (implicit rejection + TH).
                let mut tampered_ct = valid_msg;
                tampered_ct.pq_ciphertext[0] ^= 0x80;
                let (bob_tampered, _) = prekeys
                    .accept_pq(&bob, &alice_ik, &tampered_ct, None)
                    .unwrap();
                assert_ne!(bob_tampered.transcript_hash, alice_ag.transcript_hash);
                assert_ne!(*bob_tampered.secret_key, *alice_ag.secret_key);
            }
        }

        #[test]
        fn pqxdh_extend_and_retract() {
            for suite in enabled_suites() {
                let alice = XEdDSAPrivateKey::generate();
                let bob = XEdDSAPrivateKey::generate();
                let alice_ik = public_key(&alice);
                let bob_ik = public_key(&bob);

                // Upgrade an existing classical generation via extend_pq without rotating SPK.
                let mut prekeys = LocalPrekeys::new();
                let classical = prekeys.generate(&bob, 1);
                let upgraded = prekeys.extend_pq(&bob, suite, 2, 2).unwrap();
                assert_eq!(upgraded.classical.signed_prekey, classical.signed_prekey);
                assert_eq!(prekeys.generation_count(), 1);
                assert_eq!(prekeys.current_one_time_count(), 3);
                assert_eq!(prekeys.current_pq_one_time_count(suite), 2);

                // Second extend_pq keeps BOTH SPK and last-resort PQSPK.
                let refilled = prekeys.extend_pq(&bob, suite, 1, 3).unwrap();
                assert_eq!(refilled.classical.signed_prekey, classical.signed_prekey);
                assert_eq!(refilled.pq_last_resort.id, upgraded.pq_last_resort.id);
                assert_eq!(prekeys.current_one_time_count(), 4);
                assert_eq!(prekeys.current_pq_one_time_count(suite), 5);

                // Retracting removes only the retracted batch.
                let retract_pq_ids: Vec<PqPrekeyId> =
                    refilled.pq_one_time_prekeys.iter().map(|k| k.id).collect();
                prekeys.retract_pq(&refilled.classical.one_time_prekeys, &retract_pq_ids);
                assert_eq!(prekeys.current_one_time_count(), 3);
                assert_eq!(prekeys.current_pq_one_time_count(suite), 2);

                // Earlier PQOPK still works.
                let bundle = PqPrekeyBundle {
                    signed_prekey: upgraded.classical.signed_prekey,
                    signed_prekey_signature: Some(upgraded.classical.signed_prekey_signature),
                    one_time_prekey: Some(classical.one_time_prekeys[0]),
                    pq_suite: suite,
                    pq_prekey: upgraded.pq_one_time_prekeys[0].encapsulation_key.clone(),
                    pq_prekey_signature: upgraded.pq_one_time_prekeys[0].signature,
                    pq_last_resort: false,
                };
                let (msg, alice_ag) = bundle.initiate_pq(&alice, &bob_ik, None).unwrap();
                let (bob_ag, _) = prekeys.accept_pq(&bob, &alice_ik, &msg, None).unwrap();
                assert_eq!(*alice_ag.secret_key, *bob_ag.secret_key);
            }
        }

        #[test]
        fn unsupported_suite_rejected_in_single_suite_builds() {
            let bob = XEdDSAPrivateKey::generate();
            let mut prekeys = LocalPrekeys::new();
            for suite in [PqSuite::MlKem1024, PqSuite::MlKem768] {
                if !suite.is_supported() {
                    assert_eq!(
                        prekeys.generate_pq(&bob, suite, 1, 1).unwrap_err().kind(),
                        ErrorKind::UnsupportedSuite
                    );
                }
            }
        }

        #[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
        #[test]
        fn pq_restored_prekeys_round_trip_and_tamper_checks() {
            for suite in enabled_suites() {
                let alice = XEdDSAPrivateKey::generate();
                let bob = XEdDSAPrivateKey::generate();
                let alice_ik = public_key(&alice);
                let bob_ik = public_key(&bob);

                let mut prekeys = LocalPrekeys::new();
                let gen1 = prekeys.generate_pq(&bob, suite, 1, 1).unwrap();
                let gen2 = prekeys.generate_pq(&bob, suite, 1, 2).unwrap();

                let b1 = PqPrekeyBundle {
                    signed_prekey: gen1.classical.signed_prekey,
                    signed_prekey_signature: Some(gen1.classical.signed_prekey_signature),
                    one_time_prekey: Some(gen1.classical.one_time_prekeys[0]),
                    pq_suite: suite,
                    pq_prekey: gen1.pq_one_time_prekeys[0].encapsulation_key.clone(),
                    pq_prekey_signature: gen1.pq_one_time_prekeys[0].signature,
                    pq_last_resort: false,
                };
                let b2_lr = PqPrekeyBundle {
                    signed_prekey: gen2.classical.signed_prekey,
                    signed_prekey_signature: Some(gen2.classical.signed_prekey_signature),
                    one_time_prekey: None,
                    pq_suite: suite,
                    pq_prekey: gen2.pq_last_resort.encapsulation_key.clone(),
                    pq_prekey_signature: gen2.pq_last_resort.signature,
                    pq_last_resort: true,
                };
                let (confirmed_msg, _) = b2_lr.initiate_pq(&alice, &bob_ik, None).unwrap();
                prekeys.confirm_pq(&confirmed_msg).unwrap();

                let (m1, ag1) = b1.initiate_pq(&alice, &bob_ik, None).unwrap();
                let (m2, ag2) = b2_lr.initiate_pq(&alice, &bob_ik, None).unwrap();

                for restored in restored(&prekeys) {
                    let (r1, _) = restored.accept_pq(&bob, &alice_ik, &m1, None).unwrap();
                    assert_eq!(*r1.secret_key, *ag1.secret_key);
                    let (r2, _) = restored.accept_pq(&bob, &alice_ik, &m2, None).unwrap();
                    assert_eq!(*r2.secret_key, *ag2.secret_key);
                    assert_eq!(
                        restored
                            .accept_pq(&bob, &alice_ik, &confirmed_msg, None)
                            .err()
                            .unwrap()
                            .kind(),
                        ErrorKind::Replayed
                    );
                }

                // Tampered PQ seed (no longer matches stored EK) must be rejected on restore.
                #[cfg(feature = "prost")]
                {
                    let mut p = proto::LocalPrekeys::from(&prekeys);
                    p.generations[0].pq_last_resort[0].seed[0] ^= 0x01;
                    assert_eq!(
                        LocalPrekeys::try_from(&p).unwrap_err().kind(),
                        ErrorKind::MalformedState
                    );

                    let mut p = proto::LocalPrekeys::from(&prekeys);
                    p.generations[0].pq_one_time_prekeys[0].id[0] ^= 0x01;
                    assert_eq!(
                        LocalPrekeys::try_from(&p).unwrap_err().kind(),
                        ErrorKind::MalformedState
                    );
                }

                #[cfg(feature = "serde")]
                {
                    let mut val: serde_json::Value = serde_json::to_value(&prekeys).unwrap();
                    let s0 = val["generations"][0]["pq_last_resort"][0][1]["seed"][0]
                        .as_u64()
                        .unwrap();
                    val["generations"][0]["pq_last_resort"][0][1]["seed"][0] =
                        serde_json::json!((s0 ^ 1) as u8);
                    assert!(serde_json::from_value::<LocalPrekeys>(val).is_err());
                }

                #[cfg(feature = "rkyv")]
                {
                    let mut tampered = LocalPrekeys::new();
                    tampered.generate_pq(&bob, suite, 0, 1).unwrap();
                    let entry = tampered.generations[0]
                        .pq_last_resort
                        .get_mut(&suite)
                        .unwrap();
                    entry.seed[0] ^= 0x01;
                    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&tampered).unwrap();
                    assert!(rkyv::from_bytes::<LocalPrekeys, rkyv::rancor::Error>(&bytes).is_err());
                }
            }
        }
    }
}
