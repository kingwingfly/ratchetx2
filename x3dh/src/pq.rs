//! Post-quantum X3DH (PQXDH) suite metadata, domain-separated XEdDSA signature helpers,
//! and wire/agreement types.
//!
//! Everything in this module is available unconditionally — even when neither `ml-kem-1024` nor
//! `ml-kem-768` is enabled — so callers such as relays and protocol layers can validate PQ suite
//! sizes, prekey IDs, and XEdDSA signatures without pulling in any ML-KEM dependency.

use core::fmt;

use sha2::{Digest, Sha256};
use xeddsa::{PUBLIC_KEY_LENGTH, XEdDSAPrivateKey, XEdDSAPublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{ErrorKind, PublicKey, PublishedPrekeys, Result, SECRET_KEY_LENGTH, Signature};

/// Length of a deterministic post-quantum prekey identifier (SHA-256).
pub const PQ_PREKEY_ID_LENGTH: usize = 32;
/// Length of a FIPS 203 ML-KEM `(d, z)` decapsulation seed.
pub const PQ_SEED_LENGTH: usize = 64;
/// Length of an ML-KEM shared secret.
pub const PQ_SHARED_SECRET_LENGTH: usize = 32;
/// Protocol version bound into PQXDH transcripts and initial messages.
pub const PQXDH_VERSION: u32 = 2;
/// Length of PQXDH associated data: `IK_A || IK_B || TH` (96 bytes).
pub const PQXDH_ASSOCIATED_DATA_LENGTH: usize = 2 * PUBLIC_KEY_LENGTH + 32;

/// A deterministic 32-byte identifier for a post-quantum prekey.
pub type PqPrekeyId = [u8; PQ_PREKEY_ID_LENGTH];

/// Domain separator for [`pq_prekey_id`].
const PQ_ID_DOMAIN: &[u8] = b"pqxdh.v1/id\0";
/// Domain separator for last-resort PQSPK signatures ([`pq_spk_signing_input`]).
const PQ_SPK_DOMAIN: &[u8] = b"pqxdh.v1/pqspk\0";
/// Domain separator for one-time PQOPK signatures ([`pq_opk_signing_input`]).
const PQ_OPK_DOMAIN: &[u8] = b"pqxdh.v1/pqopk\0";

/// Supported ML-KEM parameter sets for PQXDH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))
)]
#[repr(u8)]
pub enum PqSuite {
    /// FIPS 203 ML-KEM-1024 (NIST security category 5; ek = 1568 B, ct = 1568 B).
    MlKem1024 = 1,
    /// FIPS 203 ML-KEM-768 (NIST security category 3; ek = 1184 B, ct = 1088 B).
    MlKem768 = 2,
}

impl PqSuite {
    /// Parses a wire suite identifier byte into a [`PqSuite`].
    pub const fn from_u8(id: u8) -> Option<Self> {
        match id {
            1 => Some(Self::MlKem1024),
            2 => Some(Self::MlKem768),
            _ => None,
        }
    }

    /// Returns the wire identifier byte of this suite.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Exact byte length of an encapsulation key for this suite.
    pub const fn ek_len(self) -> usize {
        match self {
            Self::MlKem1024 => 1568,
            Self::MlKem768 => 1184,
        }
    }

    /// Exact byte length of a ciphertext for this suite.
    pub const fn ct_len(self) -> usize {
        match self {
            Self::MlKem1024 => 1568,
            Self::MlKem768 => 1088,
        }
    }

    /// Canonical suite name bound into the PQXDH KDF `info` label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::MlKem1024 => "ML-KEM-1024",
            Self::MlKem768 => "ML-KEM-768",
        }
    }

    /// Returns `true` if the ML-KEM implementation for this suite is compiled into this build.
    pub const fn is_supported(self) -> bool {
        match self {
            Self::MlKem1024 => cfg!(feature = "ml-kem-1024"),
            Self::MlKem768 => cfg!(feature = "ml-kem-768"),
        }
    }
}

/// Computes the deterministic 32-byte identifier for a post-quantum prekey:
/// `SHA-256(b"pqxdh.v1/id\0" || [suite] || ek)`.
pub fn pq_prekey_id(suite: u8, ek: &[u8]) -> PqPrekeyId {
    let mut hasher = Sha256::new();
    hasher.update(PQ_ID_DOMAIN);
    hasher.update([suite]);
    hasher.update(ek);
    hasher.finalize().into()
}

/// Builds the domain-separated XEdDSA signing input for a last-resort PQSPK:
/// `b"pqxdh.v1/pqspk\0" || [suite] || ek`.
pub fn pq_spk_signing_input(suite: u8, ek: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PQ_SPK_DOMAIN.len() + 1 + ek.len());
    out.extend_from_slice(PQ_SPK_DOMAIN);
    out.push(suite);
    out.extend_from_slice(ek);
    out
}

/// Builds the domain-separated XEdDSA signing input for a one-time PQOPK:
/// `b"pqxdh.v1/pqopk\0" || [suite] || ek`.
pub fn pq_opk_signing_input(suite: u8, ek: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PQ_OPK_DOMAIN.len() + 1 + ek.len());
    out.extend_from_slice(PQ_OPK_DOMAIN);
    out.push(suite);
    out.extend_from_slice(ek);
    out
}

/// Signs a last-resort PQSPK encapsulation key with `identity` under the `pqxdh.v1/pqspk\0`
/// domain separator, after checking that `ek.len()` matches `suite.ek_len()`.
pub fn sign_pq_spk(identity: &XEdDSAPrivateKey, suite: PqSuite, ek: &[u8]) -> Result<Signature> {
    if ek.len() != suite.ek_len() {
        return Err(ErrorKind::InvalidPublicKey.into());
    }
    Ok(identity.sign(pq_spk_signing_input(suite.as_u8(), ek)))
}

/// Signs a one-time PQOPK encapsulation key with `identity` under the `pqxdh.v1/pqopk\0`
/// domain separator, after checking that `ek.len()` matches `suite.ek_len()`.
pub fn sign_pq_opk(identity: &XEdDSAPrivateKey, suite: PqSuite, ek: &[u8]) -> Result<Signature> {
    if ek.len() != suite.ek_len() {
        return Err(ErrorKind::InvalidPublicKey.into());
    }
    Ok(identity.sign(pq_opk_signing_input(suite.as_u8(), ek)))
}

/// Verifies a last-resort PQSPK XEdDSA signature under `pqxdh.v1/pqspk\0`, checking that `suite`
/// is a known [`PqSuite`] (1 or 2), `ek.len()` matches the suite's exact encapsulation key size,
/// and `identity_key` is a valid canonical prime-order XEdDSA key.
pub fn verify_pq_spk_signature(
    identity_key: &PublicKey,
    suite: u8,
    ek: &[u8],
    signature: &[u8],
) -> Result<()> {
    let suite_enum = PqSuite::from_u8(suite).ok_or(ErrorKind::UnsupportedSuite)?;
    if ek.len() != suite_enum.ek_len() {
        return Err(ErrorKind::InvalidPublicKey.into());
    }
    XEdDSAPublicKey::new(identity_key)?.verify(pq_spk_signing_input(suite, ek), signature)?;
    Ok(())
}

/// Verifies a one-time PQOPK XEdDSA signature under `pqxdh.v1/pqopk\0`, checking that `suite`
/// is a known [`PqSuite`] (1 or 2), `ek.len()` matches the suite's exact encapsulation key size,
/// and `identity_key` is a valid canonical prime-order XEdDSA key.
pub fn verify_pq_opk_signature(
    identity_key: &PublicKey,
    suite: u8,
    ek: &[u8],
    signature: &[u8],
) -> Result<()> {
    let suite_enum = PqSuite::from_u8(suite).ok_or(ErrorKind::UnsupportedSuite)?;
    if ek.len() != suite_enum.ek_len() {
        return Err(ErrorKind::InvalidPublicKey.into());
    }
    XEdDSAPublicKey::new(identity_key)?.verify(pq_opk_signing_input(suite, ek), signature)?;
    Ok(())
}

/// A published post-quantum prekey (either a last-resort PQSPK or a one-time PQOPK), signed by
/// Bob's identity key under its role-specific domain separator.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct PublishedPqPrekey {
    /// The ML-KEM suite.
    pub suite: PqSuite,
    /// Deterministic 32-byte identifier: `pq_prekey_id(suite.as_u8(), &encapsulation_key)`.
    pub id: PqPrekeyId,
    /// ML-KEM encapsulation key bytes (`suite.ek_len()` bytes).
    pub encapsulation_key: Vec<u8>,
    /// XEdDSA signature over [`pq_spk_signing_input`] (if last-resort) or
    /// [`pq_opk_signing_input`] (if one-time).
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub signature: Signature,
}

/// Keys Bob publishes after `LocalPrekeys::generate_pq` or `LocalPrekeys::extend_pq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPqPrekeys {
    /// Classical signed prekey and classical one-time prekeys (compatible with v1/classical).
    pub classical: PublishedPrekeys,
    /// The generation's last-resort PQSPK for the selected suite.
    pub pq_last_resort: PublishedPqPrekey,
    /// Newly generated one-time PQOPKs for the selected suite.
    pub pq_one_time_prekeys: Vec<PublishedPqPrekey>,
}

/// Bob's post-quantum prekey bundle, as Alice receives it to start a PQXDH session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct PqPrekeyBundle {
    /// Bob's classical signed prekey.
    pub signed_prekey: PublicKey,
    /// Optional legacy raw XEdDSA signature over `signed_prekey`.
    ///
    /// When `Some`, `initiate_pq` verifies it (compat mode). When `None` (strict mode), a
    /// verified `manifest_digest` binding `signed_prekey` MUST be supplied to `initiate_pq`.
    #[cfg_attr(feature = "serde", serde(with = "opt_signature_serde"))]
    pub signed_prekey_signature: Option<Signature>,
    /// One of Bob's classical one-time prekeys, if any is left.
    pub one_time_prekey: Option<PublicKey>,
    /// The ML-KEM suite of `pq_prekey`.
    pub pq_suite: PqSuite,
    /// Bob's ML-KEM encapsulation key (either a PQOPK or his last-resort PQSPK).
    pub pq_prekey: Vec<u8>,
    /// Bob's identity key's domain-separated XEdDSA signature over `pq_prekey`.
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub pq_prekey_signature: Signature,
    /// `true` if `pq_prekey` is Bob's last-resort PQSPK (signed under `pqxdh.v1/pqspk\0`),
    /// `false` if it is a one-time PQOPK (signed under `pqxdh.v1/pqopk\0`).
    pub pq_last_resort: bool,
}

/// Alice's post-quantum initial message to Bob, which lets him derive the same PQXDH secret.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct PqInitialMessage {
    /// PQXDH protocol version ([`PQXDH_VERSION`] = 2).
    pub version: u32,
    /// Alice's identity key.
    pub identity_key: PublicKey,
    /// Alice's ephemeral X25519 key.
    pub ephemeral_key: PublicKey,
    /// Bob's signed prekey that Alice used.
    pub signed_prekey: PublicKey,
    /// Bob's classical one-time prekey that Alice used, if any.
    pub one_time_prekey: Option<PublicKey>,
    /// The ML-KEM suite used.
    pub pq_suite: PqSuite,
    /// `true` if Bob's last-resort PQSPK was used; `false` if a PQOPK was used.
    pub pq_last_resort: bool,
    /// Deterministic 32-byte ID of the PQ prekey Alice encapsulated to.
    pub pq_prekey_id: PqPrekeyId,
    /// ML-KEM ciphertext (`pq_suite.ct_len()` bytes).
    pub pq_ciphertext: Vec<u8>,
}

/// The outcome of PQXDH, the same for Alice and Bob.
pub struct PqAgreement {
    /// The shared secret key (SK, 32 bytes).
    pub secret_key: Zeroizing<[u8; SECRET_KEY_LENGTH]>,
    /// The PQXDH transcript hash (TH, 32 bytes).
    pub transcript_hash: [u8; 32],
    /// The associated data (AD): `IK_A || IK_B || TH` (96 bytes).
    pub associated_data: [u8; PQXDH_ASSOCIATED_DATA_LENGTH],
    /// The ML-KEM suite that was agreed upon.
    pub suite: PqSuite,
}

impl fmt::Debug for PqAgreement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqAgreement")
            .field("suite", &self.suite)
            .field("transcript_hash", &self.transcript_hash)
            .field("associated_data", &self.associated_data)
            .finish_non_exhaustive()
    }
}

/// Locally persisted post-quantum prekey material (seed-only, 64-byte FIPS 203 `(d, z)`).
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct PqPrekeySecret {
    #[zeroize(skip)]
    pub(crate) suite: PqSuite,
    #[zeroize(skip)]
    pub(crate) ek: Vec<u8>,
    #[cfg_attr(feature = "serde", serde(with = "seed64_serde"))]
    #[cfg_attr(feature = "rkyv", rkyv(with = Seed64Def))]
    pub(crate) seed: Zeroizing<[u8; PQ_SEED_LENGTH]>,
}

#[cfg(feature = "rkyv")]
#[derive(Zeroize, ZeroizeOnDrop, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(remote = Zeroizing<[u8; PQ_SEED_LENGTH]>)]
pub(crate) struct Seed64Def {
    #[rkyv(getter = seed64_bytes)]
    pub(crate) bytes: [u8; PQ_SEED_LENGTH],
}

#[cfg(feature = "rkyv")]
fn seed64_bytes(seed: &Zeroizing<[u8; PQ_SEED_LENGTH]>) -> [u8; PQ_SEED_LENGTH] {
    **seed
}

#[cfg(feature = "rkyv")]
impl From<Seed64Def> for Zeroizing<[u8; PQ_SEED_LENGTH]> {
    fn from(def: Seed64Def) -> Self {
        Zeroizing::new(def.bytes)
    }
}

#[cfg(feature = "serde")]
mod opt_signature_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::Signature;

    #[derive(Serialize, Deserialize)]
    struct Wrapper(#[serde(with = "serde_big_array::BigArray")] Signature);

    pub(super) fn serialize<S: Serializer>(
        value: &Option<Signature>,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        value.map(Wrapper).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Option<Signature>, D::Error> {
        Ok(Option::<Wrapper>::deserialize(deserializer)?.map(|w| w.0))
    }
}

#[cfg(feature = "serde")]
mod seed64_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

    use crate::PQ_SEED_LENGTH;

    #[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
    struct Wrapper(#[serde(with = "serde_big_array::BigArray")] [u8; PQ_SEED_LENGTH]);

    pub(super) fn serialize<S: Serializer>(
        value: &Zeroizing<[u8; PQ_SEED_LENGTH]>,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        Wrapper(**value).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Zeroizing<[u8; PQ_SEED_LENGTH]>, D::Error> {
        let wrapper = Wrapper::deserialize(deserializer)?;
        Ok(Zeroizing::new(wrapper.0))
    }
}

/// Computes the PQXDH transcript hash:
/// `SHA-256(IK_A || IK_B || SPK || opk_flag(1B) [|| OPK] || EK_canon || suite(1B) || last_resort_flag(1B) || pq_prekey_id(32B) || CT || version_u32be(2) || manifest_digest_len_u8 [|| manifest_digest])`.
#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_transcript_hash(
    alice_identity_key: &PublicKey,
    bob_identity_key: &PublicKey,
    signed_prekey: &PublicKey,
    one_time_prekey: Option<&PublicKey>,
    ephemeral_key: &PublicKey,
    suite: PqSuite,
    pq_last_resort: bool,
    pq_prekey_id: &PqPrekeyId,
    pq_ciphertext: &[u8],
    version: u32,
    manifest_digest: Option<&[u8]>,
) -> Result<[u8; 32]> {
    let manifest_len: u8 = match manifest_digest {
        Some(digest) => {
            if digest.is_empty() {
                return Err(ErrorKind::MalformedState.into());
            }
            u8::try_from(digest.len()).map_err(|_| ErrorKind::MalformedState)?
        }
        None => 0,
    };

    let mut hasher = Sha256::new();
    hasher.update(alice_identity_key);
    hasher.update(bob_identity_key);
    hasher.update(signed_prekey);
    match one_time_prekey {
        Some(opk) => {
            hasher.update([1u8]);
            hasher.update(opk);
        }
        None => {
            hasher.update([0u8]);
        }
    }
    hasher.update(ephemeral_key);
    hasher.update([suite.as_u8()]);
    hasher.update([u8::from(pq_last_resort)]);
    hasher.update(pq_prekey_id);
    hasher.update(pq_ciphertext);
    hasher.update(version.to_be_bytes());
    hasher.update([manifest_len]);
    if let Some(digest) = manifest_digest {
        hasher.update(digest);
    }
    Ok(hasher.finalize().into())
}
