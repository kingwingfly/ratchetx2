//! Optional post-quantum KEM ratchet (periodic PQ3-style epoch state machine) using FIPS 203
//! ML-KEM.
//!
//! Enabled via the `ml-kem-1024`, `ml-kem-768`, or `pq` features. Default builds of `ratchetx2`
//! pull zero post-quantum dependencies.

use core::fmt;
use std::collections::VecDeque;

#[cfg(feature = "ml-kem-768")]
use ml_kem::MlKem768;
#[cfg(feature = "ml-kem-1024")]
use ml_kem::MlKem1024;
use ml_kem::{B32, Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, Seed, TryKeyInit};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;
#[cfg(any(feature = "serde", feature = "prost"))]
use crate::error::MalformedState;

/// Length of an ML-KEM `(d, z)` seed in bytes.
pub const KEM_SEED_LENGTH: usize = 64;
/// Length of a KEM encapsulation key identifier in bytes.
pub const KEM_KEY_ID_LENGTH: usize = 16;
/// Length of an ML-KEM shared secret in bytes.
pub const KEM_SHARED_SECRET_LENGTH: usize = 32;
/// Maximum byte length of any supported ML-KEM encapsulation key or ciphertext (ML-KEM-1024).
#[cfg(feature = "serde")]
const MAX_KEM_BYTES: usize = 1568;
/// Zeroizing 32-byte ML-KEM shared secret.
pub type KemSharedSecret = Zeroizing<[u8; KEM_SHARED_SECRET_LENGTH]>;
/// Maximum number of concurrent pending local KEM offers retained per session.
pub const MAX_PENDING_OFFERS: usize = 4;
/// Maximum number of recently encapsulated peer key IDs tracked to ignore retransmits.
pub const MAX_ENCAPSULATED_HISTORY: usize = 8;
/// Default message count (sent or received) between periodic PQ KEM offers.
pub const DEFAULT_REKEY_MESSAGES: u64 = 20;
/// Default DH turn count without a KEM mix between periodic PQ KEM offers.
pub const DEFAULT_REKEY_TURNS: u64 = 4;

/// Domain-separation prefix for deriving [`KEM_KEY_ID_LENGTH`]-byte KEM key identifiers.
const KEM_ID_DOMAIN: &[u8] = b"ratchetx2.pq.v1/id\0";

/// Supported post-quantum KEM parameter suites.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqSuite {
    /// FIPS 203 ML-KEM-1024 (NIST Category 5: 1568-byte ek, 1568-byte ct, 32-byte ss).
    #[cfg(feature = "ml-kem-1024")]
    MlKem1024 = 1,
    /// FIPS 203 ML-KEM-768 (NIST Category 3: 1184-byte ek, 1088-byte ct, 32-byte ss).
    #[cfg(feature = "ml-kem-768")]
    MlKem768 = 2,
}

impl PqSuite {
    /// Wire identifier for this suite (`1` for ML-KEM-1024, `2` for ML-KEM-768).
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Look up a compiled suite by wire identifier.
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            #[cfg(feature = "ml-kem-1024")]
            1 => Some(Self::MlKem1024),
            #[cfg(feature = "ml-kem-768")]
            2 => Some(Self::MlKem768),
            _ => None,
        }
    }

    /// Encoded ML-KEM encapsulation key length in bytes.
    pub const fn encapsulation_key_len(self) -> usize {
        match self {
            #[cfg(feature = "ml-kem-1024")]
            Self::MlKem1024 => 1568,
            #[cfg(feature = "ml-kem-768")]
            Self::MlKem768 => 1184,
        }
    }

    /// Encoded ML-KEM ciphertext length in bytes.
    pub const fn ciphertext_len(self) -> usize {
        match self {
            #[cfg(feature = "ml-kem-1024")]
            Self::MlKem1024 => 1568,
            #[cfg(feature = "ml-kem-768")]
            Self::MlKem768 => 1088,
        }
    }

    /// Shared secret length in bytes (always 32 for ML-KEM).
    pub const fn shared_secret_len(self) -> usize {
        KEM_SHARED_SECRET_LENGTH
    }

    /// Seed length in bytes (always 64 for FIPS 203 `(d, z)` seeds).
    pub const fn seed_len(self) -> usize {
        KEM_SEED_LENGTH
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PqSuite {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.id())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PqSuite {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SuiteVisitor;

        impl serde::de::Visitor<'_> for SuiteVisitor {
            type Value = PqSuite;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an enabled ML-KEM suite identifier")
            }

            fn visit_u8<E: serde::de::Error>(self, id: u8) -> Result<PqSuite, E> {
                PqSuite::from_id(id).ok_or_else(|| E::custom("unknown or disabled ML-KEM suite"))
            }

            fn visit_u64<E: serde::de::Error>(self, id: u64) -> Result<PqSuite, E> {
                self.visit_u8(u8::try_from(id).map_err(E::custom)?)
            }

            fn visit_i64<E: serde::de::Error>(self, id: i64) -> Result<PqSuite, E> {
                self.visit_u8(u8::try_from(id).map_err(E::custom)?)
            }

            fn visit_str<E: serde::de::Error>(self, name: &str) -> Result<PqSuite, E> {
                match name {
                    "MlKem1024" => self.visit_u8(1),
                    "MlKem768" => self.visit_u8(2),
                    _ => Err(E::unknown_variant(name, &["MlKem1024", "MlKem768"])),
                }
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_any(SuiteVisitor)
        } else {
            deserializer.deserialize_u8(SuiteVisitor)
        }
    }
}

/// Compute the deterministic 16-byte key identifier for an encapsulation key:
/// `SHA-256(b"ratchetx2.pq.v1/id\0" || [suite.id()] || ek)[..16]`.
pub fn kem_key_id(suite: PqSuite, ek: &[u8]) -> [u8; KEM_KEY_ID_LENGTH] {
    let mut hasher = Sha256::new();
    hasher.update(KEM_ID_DOMAIN);
    hasher.update([suite.id()]);
    hasher.update(ek);
    let digest = hasher.finalize();
    let mut id = [0u8; KEM_KEY_ID_LENGTH];
    id.copy_from_slice(&digest[..KEM_KEY_ID_LENGTH]);
    id
}

/// Outbound/inbound PQ KEM fields carried inside an encrypted ratchet header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KemHeader {
    /// PQ KEM suite identifier ([`PqSuite::id`]), present whenever `ek` or `ct` is set.
    pub suite: Option<u8>,
    /// Fresh ML-KEM encapsulation key offered to the peer for a future KEM ratchet step.
    pub ek: Option<Vec<u8>>,
    /// ML-KEM ciphertext encapsulating a shared secret to the peer's offered `ek_id`.
    pub ct: Option<Vec<u8>>,
    /// 16-byte identifier of the peer's encapsulation key that `ct` was encapsulated to.
    pub ek_id: Option<[u8; KEM_KEY_ID_LENGTH]>,
}

impl KemHeader {
    /// Whether this header carries no PQ fields.
    pub fn is_empty(&self) -> bool {
        self.suite.is_none() && self.ek.is_none() && self.ct.is_none() && self.ek_id.is_none()
    }
}

/// Rekey cadence configuration for [`KemRatchet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KemRatchetConfig {
    /// Number of messages sent or received since the last KEM mix before offering a fresh KEM key.
    /// Set to `0` to disable message-count-triggered rekeying.
    pub rekey_messages: u64,
    /// Number of DH chain transitions without a KEM mix before offering a fresh KEM key.
    /// Set to `1` to offer on every turn; set to `0` to disable turn-count-triggered rekeying.
    pub rekey_turns: u64,
}

impl Default for KemRatchetConfig {
    fn default() -> Self {
        Self {
            rekey_messages: DEFAULT_REKEY_MESSAGES,
            rekey_turns: DEFAULT_REKEY_TURNS,
        }
    }
}

impl KemRatchetConfig {
    /// Offer a fresh KEM key on every sending turn.
    pub const fn every_turn() -> Self {
        Self {
            rekey_messages: 0,
            rekey_turns: 1,
        }
    }
}

/// 64-byte FIPS 203 `(d, z)` seed wrapper that zeroizes on drop and never prints secrets.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct KemSeed([u8; KEM_SEED_LENGTH]);

impl KemSeed {
    fn try_generate() -> Result<Self, CryptoError> {
        let mut seed = Self([0u8; KEM_SEED_LENGTH]);
        getrandom::fill(&mut seed.0).map_err(|_| CryptoError)?;
        Ok(seed)
    }

    fn as_bytes(&self) -> &[u8; KEM_SEED_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for KemSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemSeed").finish_non_exhaustive()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for KemSeed {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for KemSeed {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SeedVisitor;

        impl<'de> serde::de::Visitor<'de> for SeedVisitor {
            type Value = KemSeed;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{KEM_SEED_LENGTH} bytes")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                let bytes: [u8; KEM_SEED_LENGTH] = v
                    .try_into()
                    .map_err(|_| E::invalid_length(v.len(), &self))?;
                Ok(KemSeed(bytes))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = Zeroizing::new([0u8; KEM_SEED_LENGTH]);
                for (i, slot) in bytes.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(KEM_SEED_LENGTH + 1, &self));
                }
                Ok(KemSeed(*bytes))
            }
        }

        deserializer.deserialize_bytes(SeedVisitor)
    }
}

/// Pending local KEM offer awaiting encapsulation by the peer.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct PendingOffer {
    id: [u8; KEM_KEY_ID_LENGTH],
    seed: KemSeed,
}

impl fmt::Debug for PendingOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingOffer")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "serde")]
fn deserialize_bounded_bytes<'de, D, const MAX: usize>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BoundedBytesVisitor<const MAX: usize>;

    impl<'de, const MAX: usize> serde::de::Visitor<'de> for BoundedBytesVisitor<MAX> {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {MAX} bytes")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
            if v.len() > MAX {
                return Err(E::invalid_length(v.len(), &self));
            }
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
            if v.len() > MAX {
                return Err(E::invalid_length(v.len(), &self));
            }
            Ok(v)
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let cap = seq.size_hint().unwrap_or(0).min(MAX);
            let mut out = Vec::with_capacity(cap);
            while let Some(byte) = seq.next_element::<u8>()? {
                if out.len() >= MAX {
                    return Err(serde::de::Error::invalid_length(MAX + 1, &self));
                }
                out.push(byte);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(BoundedBytesVisitor::<MAX>)
}

#[cfg(feature = "serde")]
fn deserialize_bounded_vecdeque<'de, D, T, const MAX: usize>(
    deserializer: D,
) -> Result<VecDeque<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct BoundedDequeVisitor<T, const MAX: usize>(core::marker::PhantomData<T>);

    impl<'de, T, const MAX: usize> serde::de::Visitor<'de> for BoundedDequeVisitor<T, MAX>
    where
        T: serde::Deserialize<'de>,
    {
        type Value = VecDeque<T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a sequence of at most {MAX} items")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<VecDeque<T>, A::Error> {
            let cap = seq.size_hint().unwrap_or(0).min(MAX);
            let mut out = VecDeque::with_capacity(cap);
            while let Some(item) = seq.next_element::<T>()? {
                if out.len() >= MAX {
                    return Err(serde::de::Error::invalid_length(MAX + 1, &self));
                }
                out.push_back(item);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(BoundedDequeVisitor::<T, MAX>(core::marker::PhantomData))
}

/// Ciphertext retransmitted on every message of the current sending chain.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct ActiveSendCt {
    ek_id: [u8; KEM_KEY_ID_LENGTH],
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "deserialize_bounded_bytes::<_, MAX_KEM_BYTES>")
    )]
    ct: Vec<u8>,
}

impl fmt::Debug for ActiveSendCt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActiveSendCt")
            .field("ek_id", &self.ek_id)
            .field("ct_len", &self.ct.len())
            .finish()
    }
}

/// Peer's offered encapsulation key queued for our next sending chain.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct PeerPendingEk {
    ek_id: [u8; KEM_KEY_ID_LENGTH],
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "deserialize_bounded_bytes::<_, MAX_KEM_BYTES>")
    )]
    ek: Vec<u8>,
}

impl fmt::Debug for PeerPendingEk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerPendingEk")
            .field("ek_id", &self.ek_id)
            .field("ek_len", &self.ek.len())
            .finish()
    }
}

/// Digest pin of the `(ek_id, SHA-256(ct))` observed at the start of the current receiving chain.
type RecvCtPin = Option<([u8; KEM_KEY_ID_LENGTH], [u8; 32])>;

fn header_ct_pin(header: &KemHeader) -> RecvCtPin {
    match (header.ek_id, header.ct.as_deref()) {
        (Some(ek_id), Some(ct)) => Some((ek_id, Sha256::digest(ct).into())),
        _ => None,
    }
}

/// Periodic PQ3-style post-quantum KEM ratchet state machine.
///
/// Stores only 64-byte FIPS 203 `(d, z)` seeds (never expanded decapsulation keys) and tracks up
/// to [`MAX_PENDING_OFFERS`] pending local offers keyed by 16-byte `ek_id` so crossed rekey
/// offers resolve deterministically without deadlocking.
///
/// Supports [`Clone`] for tentative execution before AEAD verification and serializes with
/// `prost` and `serde`.
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "KemRatchetUnchecked")
)]
pub struct KemRatchet {
    suite: PqSuite,
    rekey_messages: u64,
    rekey_turns: u64,
    pending_offers: VecDeque<PendingOffer>,
    active_offer_id: Option<[u8; KEM_KEY_ID_LENGTH]>,
    active_send_ct: Option<ActiveSendCt>,
    peer_pending_ek: Option<PeerPendingEk>,
    encapsulated_ek_ids: VecDeque<[u8; KEM_KEY_ID_LENGTH]>,
    messages_since_rekey: u64,
    turns_since_rekey: u64,
    initial_offer_needed: bool,
    /// Transient in-memory cache of the active offer's expanded encapsulation key so repeated
    /// `prepare_send` calls do not re-expand from seed. Skipped on serialization to keep wire
    /// state seed-only and postcard-compatible.
    #[cfg_attr(feature = "serde", serde(skip))]
    active_offer_ek: Option<([u8; KEM_KEY_ID_LENGTH], Vec<u8>)>,
    /// Transient pin of the `(ek_id, SHA-256(ct))` seen on the current receiving chain so
    /// mid-chain retransmissions with a mismatched `ek_id` or `ct` are rejected.
    #[cfg_attr(feature = "serde", serde(skip))]
    current_recv_ct_pin: Option<RecvCtPin>,
}

impl Zeroize for KemRatchet {
    fn zeroize(&mut self) {
        for offer in &mut self.pending_offers {
            offer.zeroize();
        }
        self.pending_offers.clear();
        self.active_offer_id.zeroize();
        if let Some(active) = self.active_send_ct.as_mut() {
            active.zeroize();
        }
        self.active_send_ct = None;
        if let Some(peer) = self.peer_pending_ek.as_mut() {
            peer.zeroize();
        }
        self.peer_pending_ek = None;
        for id in &mut self.encapsulated_ek_ids {
            id.zeroize();
        }
        self.encapsulated_ek_ids.clear();
        self.messages_since_rekey.zeroize();
        self.turns_since_rekey.zeroize();
        self.initial_offer_needed.zeroize();
        if let Some((id, ek)) = self.active_offer_ek.as_mut() {
            id.zeroize();
            ek.zeroize();
        }
        self.active_offer_ek = None;
        self.current_recv_ct_pin = None;
    }
}

impl Drop for KemRatchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KemRatchet {}

impl fmt::Debug for KemRatchet {
    /// Shows metadata only, never seeds or key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemRatchet")
            .field("suite", &self.suite)
            .field("rekey_messages", &self.rekey_messages)
            .field("rekey_turns", &self.rekey_turns)
            .field("pending_offers", &self.pending_offers.len())
            .field("has_active_offer", &self.active_offer_id.is_some())
            .field("has_active_send_ct", &self.active_send_ct.is_some())
            .field("has_peer_pending_ek", &self.peer_pending_ek.is_some())
            .field("messages_since_rekey", &self.messages_since_rekey)
            .field("turns_since_rekey", &self.turns_since_rekey)
            .finish_non_exhaustive()
    }
}

impl KemRatchet {
    /// Create a new [`KemRatchet`] with default rekey cadence ([`KemRatchetConfig::default`]).
    ///
    /// Schedules an immediate initial KEM offer on the first outbound message so PQ-PCS starts
    /// promptly.
    pub fn new(suite: PqSuite) -> Self {
        Self::with_config(suite, KemRatchetConfig::default())
    }

    /// Create a new [`KemRatchet`] with custom rekey cadence.
    pub fn with_config(suite: PqSuite, config: KemRatchetConfig) -> Self {
        Self {
            suite,
            rekey_messages: config.rekey_messages,
            rekey_turns: config.rekey_turns,
            pending_offers: VecDeque::new(),
            active_offer_id: None,
            active_send_ct: None,
            peer_pending_ek: None,
            encapsulated_ek_ids: VecDeque::new(),
            messages_since_rekey: 0,
            turns_since_rekey: 0,
            initial_offer_needed: true,
            active_offer_ek: None,
            current_recv_ct_pin: None,
        }
    }

    /// The configured post-quantum KEM suite.
    pub fn suite(&self) -> PqSuite {
        self.suite
    }

    /// The configured rekey cadence.
    pub fn config(&self) -> KemRatchetConfig {
        KemRatchetConfig {
            rekey_messages: self.rekey_messages,
            rekey_turns: self.rekey_turns,
        }
    }

    /// Number of local pending KEM offers awaiting peer encapsulation.
    pub fn pending_offer_count(&self) -> usize {
        self.pending_offers.len()
    }

    /// Immediately generate and advertise a fresh local KEM offer on subsequent outbound messages,
    /// retaining earlier pending offers up to [`MAX_PENDING_OFFERS`].
    pub fn force_rekey(&mut self) -> Result<[u8; KEM_KEY_ID_LENGTH], CryptoError> {
        let (id, _ek) = self.create_offer()?;
        Ok(id)
    }

    /// Prepare PQ header fields for an outbound message on the current sending chain.
    ///
    /// Retransmits the active sending-chain ciphertext (`ct` + `ek_id`) and any unacknowledged
    /// local offer (`ek`), generating a new local offer if the rekey cadence (or initial offer
    /// flag) triggers.
    ///
    /// Call on a cloned [`KemRatchet`] and commit only after AEAD encryption succeeds.
    pub fn prepare_send(&mut self) -> Result<KemHeader, CryptoError> {
        let mut fresh_ek: Option<Vec<u8>> = None;
        if self.active_offer_id.is_none() && self.should_offer() {
            let (_id, ek) = self.create_offer()?;
            fresh_ek = Some(ek);
        }

        let ek = if let Some(ek) = fresh_ek {
            Some(ek)
        } else if let Some(active_id) = self.active_offer_id {
            if let Some((cached_id, cached_ek)) = &self.active_offer_ek
                && *cached_id == active_id
            {
                Some(cached_ek.clone())
            } else {
                let offer = self
                    .pending_offers
                    .iter()
                    .find(|offer| offer.id == active_id)
                    .ok_or(CryptoError)?;
                let expanded = expand_ek(self.suite, offer.seed.as_bytes());
                self.active_offer_ek = Some((active_id, expanded.clone()));
                Some(expanded)
            }
        } else {
            None
        };

        let (ct, ek_id) = match &self.active_send_ct {
            Some(active) => (Some(active.ct.clone()), Some(active.ek_id)),
            None => (None, None),
        };

        let suite = if ek.is_some() || ct.is_some() {
            Some(self.suite.id())
        } else {
            None
        };

        self.messages_since_rekey = self.messages_since_rekey.saturating_add(1);

        Ok(KemHeader {
            suite,
            ek,
            ct,
            ek_id,
        })
    }

    /// Process an incoming [`KemHeader`] on a new peer chain (the two DH-root steps).
    ///
    /// Returns `(recv_secret, send_secret)`:
    /// - `recv_secret`: decapsulated from `header.ct` using the pending local offer matching
    ///   `header.ek_id`, to be passed to the first `Ratchet::step_dh_root_with` (receiving chain).
    ///   The consumed offer seed is removed from `self`.
    /// - `send_secret`: encapsulated to `header.ek` (or a peer offer queued from the peer's
    ///   previous chain), to be passed to the second `Ratchet::step_dh_root_with` (new sending
    ///   chain). The resulting ciphertext is stored for outbound messages on the new sending
    ///   chain.
    ///
    /// All fallible decapsulation and encapsulation operations complete before `self` is mutated,
    /// so an error always leaves `self` untouched. Call on a cloned [`KemRatchet`] and commit
    /// only after message AEAD verification succeeds.
    pub fn receive_chain_step(
        &mut self,
        header: &KemHeader,
    ) -> Result<(Option<KemSharedSecret>, Option<KemSharedSecret>), CryptoError> {
        self.validate_incoming_header(header)?;

        // 1. Compute receiver decapsulation without mutating `self`.
        let recv_outcome = if let (Some(ct), Some(ek_id)) = (&header.ct, header.ek_id) {
            let pos = self
                .pending_offers
                .iter()
                .position(|offer| offer.id == ek_id)
                .ok_or(CryptoError)?;
            let ss = decapsulate(self.suite, self.pending_offers[pos].seed.as_bytes(), ct)?;
            Some((pos, ek_id, ss))
        } else {
            None
        };

        // 2. Determine which peer encapsulation key will be encapsulated for our next sending
        // chain, and perform the fallible encapsulation BEFORE mutating `self`.
        let incoming_peer_ek = header.ek.as_deref().and_then(|ek| {
            let ek_id = kem_key_id(self.suite, ek);
            if self.encapsulated_ek_ids.contains(&ek_id) {
                None
            } else {
                Some((ek_id, ek))
            }
        });
        let encap_target: Option<([u8; KEM_KEY_ID_LENGTH], &[u8])> =
            incoming_peer_ek.or_else(|| {
                self.peer_pending_ek
                    .as_ref()
                    .map(|pending| (pending.ek_id, pending.ek.as_slice()))
            });
        let send_outcome = match encap_target {
            Some((ek_id, ek)) => {
                let (ct, ss) = encapsulate(self.suite, ek)?;
                Some((ActiveSendCt { ek_id, ct }, ss))
            }
            None => None,
        };

        // 3. All fallible operations succeeded; commit state mutations atomically.
        let recv_secret = if let Some((pos, ek_id, ss)) = recv_outcome {
            // Removing drops PendingOffer -> KemSeed::drop zeroizes the 64-byte seed.
            self.pending_offers.remove(pos);
            if self.active_offer_id == Some(ek_id) {
                self.active_offer_id = None;
                self.active_offer_ek = None;
            }
            Some(ss)
        } else {
            None
        };

        self.peer_pending_ek = None;
        let send_secret = match send_outcome {
            Some((active, ss)) => {
                let ek_id = active.ek_id;
                self.active_send_ct = Some(active);
                self.record_encapsulated_ek_id(ek_id);
                Some(ss)
            }
            None => {
                self.active_send_ct = None;
                None
            }
        };

        // Pin the chain-start `(ek_id, ct)` for subsequent messages on this receiving chain.
        self.current_recv_ct_pin = Some(header_ct_pin(header));

        // 4. Update rekey cadence state.
        if recv_secret.is_some() || send_secret.is_some() {
            self.messages_since_rekey = 0;
            self.turns_since_rekey = 0;
            self.initial_offer_needed = false;
        } else {
            self.turns_since_rekey = self.turns_since_rekey.saturating_add(1);
            self.messages_since_rekey = self.messages_since_rekey.saturating_add(1);
        }

        Ok((recv_secret, send_secret))
    }

    /// Process an incoming [`KemHeader`] on the current receiving chain (no DH step).
    ///
    /// Validates the PQ fields, verifies that any retransmitted ciphertext and `ek_id` match the
    /// chain-start ciphertext observed for this receiving chain, queues any new peer encapsulation
    /// key for our next sending chain, and updates the message counter.
    ///
    /// Call on a cloned [`KemRatchet`] and commit only after message AEAD verification succeeds.
    pub fn receive_current_chain(&mut self, header: &KemHeader) -> Result<(), CryptoError> {
        self.validate_incoming_header(header)?;
        let pin = header_ct_pin(header);
        match self.current_recv_ct_pin {
            Some(expected) if expected != pin => return Err(CryptoError),
            None => self.current_recv_ct_pin = Some(pin),
            Some(_) => {}
        }
        if let Some(ek) = &header.ek {
            self.record_peer_ek(ek);
        }
        self.messages_since_rekey = self.messages_since_rekey.saturating_add(1);
        Ok(())
    }

    /// Process an incoming [`KemHeader`] on a decrypted skipped (out-of-order) message: validates
    /// the PQ fields and accounts for the message in the rekey cadence without adopting `header.ek`.
    ///
    /// A skipped message is strictly older than a message already received from the peer. Because
    /// [`prepare_send`](Self::prepare_send) retransmits the active offer on every message until it
    /// is acknowledged or superseded, any `ek` carried by a skipped message is already known,
    /// superseded by a fresher offer, or evicted from the peer's bounded `pending_offers` ring;
    /// adopting it could overwrite a fresher offer or cause encapsulation to an evicted/consumed
    /// peer key (`InvalidHeader` on the next chain).
    ///
    /// Call on a cloned [`KemRatchet`] and commit only after message AEAD verification succeeds.
    pub fn receive_skipped_header(&mut self, header: &KemHeader) -> Result<(), CryptoError> {
        self.validate_incoming_header(header)?;
        self.messages_since_rekey = self.messages_since_rekey.saturating_add(1);
        Ok(())
    }

    /// Account for a decrypted skipped message in the message-count rekey cadence.
    pub fn note_skipped_received(&mut self) {
        self.messages_since_rekey = self.messages_since_rekey.saturating_add(1);
    }

    fn should_offer(&self) -> bool {
        if self.initial_offer_needed {
            return true;
        }
        if self.rekey_turns > 0
            && (self.rekey_turns == 1 || self.turns_since_rekey >= self.rekey_turns)
        {
            return true;
        }
        if self.rekey_messages > 0 && self.messages_since_rekey >= self.rekey_messages {
            return true;
        }
        false
    }

    fn create_offer(&mut self) -> Result<([u8; KEM_KEY_ID_LENGTH], Vec<u8>), CryptoError> {
        let seed = KemSeed::try_generate()?;
        let ek = expand_ek(self.suite, seed.as_bytes());
        let id = kem_key_id(self.suite, &ek);
        while self.pending_offers.len() >= MAX_PENDING_OFFERS {
            self.pending_offers.pop_front();
        }
        self.pending_offers.push_back(PendingOffer { id, seed });
        self.active_offer_id = Some(id);
        self.active_offer_ek = Some((id, ek.clone()));
        self.initial_offer_needed = false;
        Ok((id, ek))
    }

    fn record_peer_ek(&mut self, ek: &[u8]) {
        let ek_id = kem_key_id(self.suite, ek);
        if self.encapsulated_ek_ids.contains(&ek_id) {
            return;
        }
        if self
            .peer_pending_ek
            .as_ref()
            .is_some_and(|existing| existing.ek_id == ek_id)
        {
            return;
        }
        self.peer_pending_ek = Some(PeerPendingEk {
            ek_id,
            ek: ek.to_vec(),
        });
    }

    fn record_encapsulated_ek_id(&mut self, ek_id: [u8; KEM_KEY_ID_LENGTH]) {
        if self.encapsulated_ek_ids.contains(&ek_id) {
            return;
        }
        while self.encapsulated_ek_ids.len() >= MAX_ENCAPSULATED_HISTORY {
            self.encapsulated_ek_ids.pop_front();
        }
        self.encapsulated_ek_ids.push_back(ek_id);
    }

    fn validate_incoming_header(&self, header: &KemHeader) -> Result<(), CryptoError> {
        if header.is_empty() {
            return Ok(());
        }
        if header.suite != Some(self.suite.id()) {
            return Err(CryptoError);
        }
        if header.ek.is_none() && header.ct.is_none() {
            return Err(CryptoError);
        }
        if header.ct.is_some() != header.ek_id.is_some() {
            return Err(CryptoError);
        }
        if let Some(ct) = &header.ct
            && ct.len() != self.suite.ciphertext_len()
        {
            return Err(CryptoError);
        }
        if let Some(ek) = &header.ek {
            validate_ek(self.suite, ek)?;
        }
        Ok(())
    }

    #[cfg(any(feature = "serde", feature = "prost"))]
    fn validate(&self) -> Result<(), MalformedState> {
        validate_kem_ratchet_state(
            self.suite,
            self.pending_offers
                .iter()
                .map(|offer| (offer.id, offer.seed.as_bytes())),
            self.active_offer_id,
            self.active_send_ct
                .as_ref()
                .map(|a| (a.ek_id, a.ct.as_slice())),
            self.peer_pending_ek
                .as_ref()
                .map(|p| (p.ek_id, p.ek.as_slice())),
            self.encapsulated_ek_ids.iter().copied(),
        )
    }
}

#[cfg(any(feature = "serde", feature = "prost"))]
fn validate_kem_ratchet_state<'a>(
    suite: PqSuite,
    pending_offers: impl Iterator<Item = ([u8; KEM_KEY_ID_LENGTH], &'a [u8; KEM_SEED_LENGTH])>,
    active_offer_id: Option<[u8; KEM_KEY_ID_LENGTH]>,
    active_send_ct: Option<([u8; KEM_KEY_ID_LENGTH], &'a [u8])>,
    peer_pending_ek: Option<([u8; KEM_KEY_ID_LENGTH], &'a [u8])>,
    encapsulated_ek_ids: impl Iterator<Item = [u8; KEM_KEY_ID_LENGTH]>,
) -> Result<(), MalformedState> {
    let mut offer_ids = Vec::new();
    for (id, seed) in pending_offers {
        if offer_ids.len() >= MAX_PENDING_OFFERS {
            return Err(MalformedState);
        }
        let derived_ek = expand_ek(suite, seed);
        if kem_key_id(suite, &derived_ek) != id {
            return Err(MalformedState);
        }
        if offer_ids.contains(&id) {
            return Err(MalformedState);
        }
        offer_ids.push(id);
    }
    if let Some(active_id) = active_offer_id
        && !offer_ids.contains(&active_id)
    {
        return Err(MalformedState);
    }
    if let Some((_ek_id, ct)) = active_send_ct
        && ct.len() != suite.ciphertext_len()
    {
        return Err(MalformedState);
    }
    if let Some((ek_id, ek)) = peer_pending_ek {
        validate_ek(suite, ek).map_err(|_| MalformedState)?;
        if kem_key_id(suite, ek) != ek_id {
            return Err(MalformedState);
        }
    }
    let mut seen_encap = Vec::new();
    for id in encapsulated_ek_ids {
        if seen_encap.len() >= MAX_ENCAPSULATED_HISTORY {
            return Err(MalformedState);
        }
        if seen_encap.contains(&id) {
            return Err(MalformedState);
        }
        seen_encap.push(id);
    }
    Ok(())
}

/// Dispatches an operation over the compiled [`PqSuite`] parameter sets without duplicating
/// `MlKem1024`/`MlKem768` arms.
macro_rules! dispatch_suite {
    ($suite:expr, |$k:ident| $body:expr) => {
        match $suite {
            #[cfg(feature = "ml-kem-1024")]
            PqSuite::MlKem1024 => {
                type $k = MlKem1024;
                $body
            }
            #[cfg(feature = "ml-kem-768")]
            PqSuite::MlKem768 => {
                type $k = MlKem768;
                $body
            }
        }
    };
}

/// Expand a 64-byte FIPS 203 `(d, z)` seed into its encoded encapsulation key bytes.
fn expand_ek(suite: PqSuite, seed: &[u8; KEM_SEED_LENGTH]) -> Vec<u8> {
    let seed = Zeroizing::new(Seed::from(*seed));
    dispatch_suite!(suite, |K| {
        let dk = DecapsulationKey::<K>::from_seed(*seed);
        dk.encapsulation_key().to_bytes().as_slice().to_vec()
    })
}

/// Validate an encoded ML-KEM encapsulation key (exact length + FIPS 203 modulus check).
fn validate_ek(suite: PqSuite, ek: &[u8]) -> Result<(), CryptoError> {
    dispatch_suite!(suite, |K| {
        EncapsulationKey::<K>::new_from_slice(ek).map_err(|_| CryptoError)?;
        Ok(())
    })
}

/// Encapsulate a fresh shared secret to an encoded ML-KEM encapsulation key.
fn encapsulate(
    suite: PqSuite,
    ek: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; KEM_SHARED_SECRET_LENGTH]>), CryptoError> {
    let mut m = Zeroizing::new(B32::default());
    getrandom::fill(m.as_mut_slice()).map_err(|_| CryptoError)?;
    dispatch_suite!(suite, |K| {
        let ek = EncapsulationKey::<K>::new_from_slice(ek).map_err(|_| CryptoError)?;
        let (ct, mut ss) = ek.encapsulate_deterministic(&m);
        let mut out = Zeroizing::new([0u8; KEM_SHARED_SECRET_LENGTH]);
        out.copy_from_slice(ss.as_slice());
        ss.zeroize();
        Ok((ct.as_slice().to_vec(), out))
    })
}

/// Decapsulate an ML-KEM ciphertext using a 64-byte `(d, z)` seed.
fn decapsulate(
    suite: PqSuite,
    seed: &[u8; KEM_SEED_LENGTH],
    ct: &[u8],
) -> Result<Zeroizing<[u8; KEM_SHARED_SECRET_LENGTH]>, CryptoError> {
    let seed = Zeroizing::new(Seed::from(*seed));
    dispatch_suite!(suite, |K| {
        let dk = DecapsulationKey::<K>::from_seed(*seed);
        let mut ss = dk.decapsulate_slice(ct).map_err(|_| CryptoError)?;
        let mut out = Zeroizing::new([0u8; KEM_SHARED_SECRET_LENGTH]);
        out.copy_from_slice(ss.as_slice());
        ss.zeroize();
        Ok(out)
    })
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(rename = "KemRatchet")]
struct KemRatchetUnchecked {
    suite: PqSuite,
    rekey_messages: u64,
    rekey_turns: u64,
    #[serde(deserialize_with = "deserialize_bounded_vecdeque::<_, _, MAX_PENDING_OFFERS>")]
    pending_offers: VecDeque<PendingOffer>,
    active_offer_id: Option<[u8; KEM_KEY_ID_LENGTH]>,
    active_send_ct: Option<ActiveSendCt>,
    peer_pending_ek: Option<PeerPendingEk>,
    #[serde(deserialize_with = "deserialize_bounded_vecdeque::<_, _, MAX_ENCAPSULATED_HISTORY>")]
    encapsulated_ek_ids: VecDeque<[u8; KEM_KEY_ID_LENGTH]>,
    messages_since_rekey: u64,
    turns_since_rekey: u64,
    initial_offer_needed: bool,
}

#[cfg(feature = "serde")]
impl TryFrom<KemRatchetUnchecked> for KemRatchet {
    type Error = MalformedState;

    fn try_from(raw: KemRatchetUnchecked) -> Result<Self, Self::Error> {
        let ratchet = Self {
            suite: raw.suite,
            rekey_messages: raw.rekey_messages,
            rekey_turns: raw.rekey_turns,
            pending_offers: raw.pending_offers,
            active_offer_id: raw.active_offer_id,
            active_send_ct: raw.active_send_ct,
            peer_pending_ek: raw.peer_pending_ek,
            encapsulated_ek_ids: raw.encapsulated_ek_ids,
            messages_since_rekey: raw.messages_since_rekey,
            turns_since_rekey: raw.turns_since_rekey,
            initial_offer_needed: raw.initial_offer_needed,
            active_offer_ek: None,
            current_recv_ct_pin: None,
        };
        ratchet.validate()?;
        Ok(ratchet)
    }
}

#[cfg(feature = "prost")]
impl From<&KemRatchet> for crate::proto::KemRatchet {
    fn from(kem: &KemRatchet) -> Self {
        Self {
            suite: u32::from(kem.suite.id()),
            rekey_messages: kem.rekey_messages,
            rekey_turns: kem.rekey_turns,
            pending_offers: kem
                .pending_offers
                .iter()
                .map(|offer| crate::proto::KemPendingOffer {
                    id: offer.id.to_vec(),
                    seed: offer.seed.as_bytes().to_vec(),
                })
                .collect(),
            active_offer_id: kem.active_offer_id.map_or_else(Vec::new, |id| id.to_vec()),
            active_send_ct: kem.active_send_ct.as_ref().map(|active| {
                crate::proto::KemActiveSendCt {
                    ek_id: active.ek_id.to_vec(),
                    ciphertext: active.ct.clone(),
                }
            }),
            peer_pending_ek: kem.peer_pending_ek.as_ref().map(|peer| {
                crate::proto::KemPeerPendingEk {
                    ek_id: peer.ek_id.to_vec(),
                    encapsulation_key: peer.ek.clone(),
                }
            }),
            encapsulated_ek_ids: kem
                .encapsulated_ek_ids
                .iter()
                .map(|id| id.to_vec())
                .collect(),
            messages_since_rekey: kem.messages_since_rekey,
            turns_since_rekey: kem.turns_since_rekey,
            initial_offer_needed: kem.initial_offer_needed,
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&crate::proto::KemRatchet> for KemRatchet {
    type Error = MalformedState;

    fn try_from(proto: &crate::proto::KemRatchet) -> Result<Self, Self::Error> {
        let suite_id = u8::try_from(proto.suite).map_err(|_| MalformedState)?;
        let suite = PqSuite::from_id(suite_id).ok_or(MalformedState)?;

        if proto.pending_offers.len() > MAX_PENDING_OFFERS
            || proto.encapsulated_ek_ids.len() > MAX_ENCAPSULATED_HISTORY
        {
            return Err(MalformedState);
        }

        let mut pending_offers = VecDeque::with_capacity(proto.pending_offers.len());
        for offer in &proto.pending_offers {
            pending_offers.push_back(PendingOffer {
                id: crate::proto::key(&offer.id)?,
                seed: KemSeed(crate::proto::key(&offer.seed)?),
            });
        }

        let active_offer_id = if proto.active_offer_id.is_empty() {
            None
        } else {
            Some(crate::proto::key(&proto.active_offer_id)?)
        };

        let active_send_ct = match &proto.active_send_ct {
            Some(active) => Some(ActiveSendCt {
                ek_id: crate::proto::key(&active.ek_id)?,
                ct: active.ciphertext.clone(),
            }),
            None => None,
        };

        let peer_pending_ek = match &proto.peer_pending_ek {
            Some(peer) => Some(PeerPendingEk {
                ek_id: crate::proto::key(&peer.ek_id)?,
                ek: peer.encapsulation_key.clone(),
            }),
            None => None,
        };

        let mut encapsulated_ek_ids = VecDeque::with_capacity(proto.encapsulated_ek_ids.len());
        for id in &proto.encapsulated_ek_ids {
            encapsulated_ek_ids.push_back(crate::proto::key(id)?);
        }

        let restored = Self {
            suite,
            rekey_messages: proto.rekey_messages,
            rekey_turns: proto.rekey_turns,
            pending_offers,
            active_offer_id,
            active_send_ct,
            peer_pending_ek,
            encapsulated_ek_ids,
            messages_since_rekey: proto.messages_since_rekey,
            turns_since_rekey: proto.turns_since_rekey,
            initial_offer_needed: proto.initial_offer_needed,
            active_offer_ek: None,
            current_recv_ct_pin: None,
        };
        restored.validate()?;
        Ok(restored)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{DhPrivateKey, Ratchet, SharedKeys};

    fn enabled_suites() -> Vec<PqSuite> {
        vec![
            #[cfg(feature = "ml-kem-1024")]
            PqSuite::MlKem1024,
            #[cfg(feature = "ml-kem-768")]
            PqSuite::MlKem768,
        ]
    }

    #[cfg(feature = "serde")]
    #[test]
    fn suite_serde_ids_are_stable_across_builds() {
        for (id, name, compiled) in [
            (1, "MlKem1024", cfg!(feature = "ml-kem-1024")),
            (2, "MlKem768", cfg!(feature = "ml-kem-768")),
        ] {
            let suite = postcard::from_bytes::<PqSuite>(&[id]).ok();
            assert_eq!(suite.is_some(), compiled);
            assert_eq!(serde_json::from_str::<PqSuite>(&id.to_string()).ok(), suite);
            assert_eq!(
                serde_json::from_value::<PqSuite>(serde_json::json!(name)).ok(),
                suite
            );
            if let Some(suite) = suite {
                assert_eq!(suite.id(), id);
                assert_eq!(postcard::to_allocvec(&suite).unwrap(), [id]);
                assert_eq!(serde_json::to_string(&suite).unwrap(), id.to_string());
            }
        }
        #[cfg(feature = "ml-kem-1024")]
        assert_eq!(postcard::to_allocvec(&PqSuite::MlKem1024).unwrap(), [1]);
        #[cfg(feature = "ml-kem-768")]
        assert_eq!(postcard::to_allocvec(&PqSuite::MlKem768).unwrap(), [2]);

        for id in [0, 3, 255] {
            assert!(postcard::from_bytes::<PqSuite>(&[id]).is_err());
            assert!(serde_json::from_str::<PqSuite>(&id.to_string()).is_err());
        }
        for invalid in ["-255", "257", "1.0", r#""Other""#] {
            assert!(serde_json::from_str::<PqSuite>(invalid).is_err());
        }
    }

    #[cfg(all(feature = "serde", feature = "ml-kem-768"))]
    #[test]
    fn ml_kem_768_ratchet_postcard_fixture() {
        let bytes = [2, 20, 4, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            postcard::to_allocvec(&KemRatchet::new(PqSuite::MlKem768)).unwrap(),
            bytes
        );
        assert_eq!(
            postcard::from_bytes::<KemRatchet>(&bytes).unwrap().suite(),
            PqSuite::MlKem768
        );
    }

    #[test]
    fn ml_kem_roundtrip_and_validation() {
        for suite in enabled_suites() {
            let seed = KemSeed::try_generate().unwrap();
            let ek = expand_ek(suite, seed.as_bytes());
            assert_eq!(ek.len(), suite.encapsulation_key_len());
            validate_ek(suite, &ek).unwrap();

            let (ct, ss_enc) = encapsulate(suite, &ek).unwrap();
            assert_eq!(ct.len(), suite.ciphertext_len());
            let ss_dec = decapsulate(suite, seed.as_bytes(), &ct).unwrap();
            assert_eq!(*ss_enc, *ss_dec);

            // Tampered ciphertext implicitly rejects to a different shared secret.
            let mut bad_ct = ct.clone();
            bad_ct[0] ^= 0x01;
            let ss_bad = decapsulate(suite, seed.as_bytes(), &bad_ct).unwrap();
            assert_ne!(*ss_enc, *ss_bad);

            // Wrong-length ek and ct fail cleanly.
            assert!(validate_ek(suite, &ek[..ek.len() - 1]).is_err());
            assert!(decapsulate(suite, seed.as_bytes(), &ct[..ct.len() - 1]).is_err());

            // Non-canonical 12-bit coefficient (>= 3329 = 0xD01) in ek fails FIPS 203 check.
            let mut bad_ek = ek.clone();
            bad_ek[0] = 0xFF;
            bad_ek[1] = 0xFF;
            assert!(validate_ek(suite, &bad_ek).is_err());
        }
    }

    #[test]
    fn kem_ratchet_syncs_with_dh_ratchet_across_turns() {
        let keys = SharedKeys {
            secret_key: [7; 32],
            header_key_alice: [8; 32],
            header_key_bob: [9; 32],
        };
        for suite in enabled_suites() {
            let mut bob = Ratchet::bob(&keys, DhPrivateKey::generate());
            let mut alice = Ratchet::alice(&keys, &bob.public_key()).unwrap();
            let mut alice_kem = KemRatchet::with_config(suite, KemRatchetConfig::every_turn());
            let mut bob_kem = KemRatchet::with_config(suite, KemRatchetConfig::every_turn());

            // Alice sends first (initial offer ek_A0).
            let h_a0 = alice_kem.prepare_send().unwrap();
            assert!(h_a0.ek.is_some());
            assert!(h_a0.ct.is_none());

            // Bob receives A0 -> receiver step classical, sender step encapsulates to ek_A0.
            let (recv_ss, send_ss) = bob_kem.receive_chain_step(&h_a0).unwrap();
            assert!(recv_ss.is_none());
            assert!(send_ss.is_some());
            bob.step_dh_root(&alice.public_key()).unwrap();
            assert!(alice.is_paired_with(&bob));
            bob.step_dh_root_with(&alice.public_key(), send_ss.as_deref().unwrap())
                .unwrap();

            // Bob sends B0 (carries ct_A0 + fresh ek_B0 because every_turn).
            let h_b0 = bob_kem.prepare_send().unwrap();
            assert!(h_b0.ct.is_some());
            assert!(h_b0.ek.is_some());

            // Alice receives B0 -> decapsulates ct_A0 AND encapsulates to ek_B0.
            let (recv_ss, send_ss) = alice_kem.receive_chain_step(&h_b0).unwrap();
            assert!(recv_ss.is_some());
            assert!(send_ss.is_some());
            alice
                .step_dh_root_with(&bob.public_key(), recv_ss.as_deref().unwrap())
                .unwrap();
            assert!(alice.is_paired_with(&bob));
            // Alice consumed her initial pending offer on commit.
            assert_eq!(alice_kem.pending_offer_count(), 0);
            alice
                .step_dh_root_with(&bob.public_key(), send_ss.as_deref().unwrap())
                .unwrap();

            // Alice sends A1 (carries ct_B0 + fresh ek_A1).
            let h_a1 = alice_kem.prepare_send().unwrap();
            let (recv_ss, send_ss) = bob_kem.receive_chain_step(&h_a1).unwrap();
            assert!(recv_ss.is_some());
            assert!(send_ss.is_some());
            bob.step_dh_root_with(&alice.public_key(), recv_ss.as_deref().unwrap())
                .unwrap();
            assert!(alice.is_paired_with(&bob));
            assert_eq!(bob_kem.pending_offer_count(), 0);
        }
    }

    #[test]
    fn mid_chain_ct_pin_rejects_mismatch_and_malformed_headers() {
        for suite in enabled_suites() {
            let mut alice = KemRatchet::new(suite);
            let mut bob = KemRatchet::new(suite);
            let h_a0 = alice.prepare_send().unwrap();
            bob.receive_chain_step(&h_a0).unwrap();
            let h_b0 = bob.prepare_send().unwrap();
            let h_b1 = bob.prepare_send().unwrap();

            // Alice receives B0 on a new chain, pinning B0's (ek_id, ct).
            let (recv_ss, _) = alice.receive_chain_step(&h_b0).unwrap();
            assert!(recv_ss.is_some());
            // Replaying B0 on another chain step fails because offer was consumed.
            assert_eq!(alice.receive_chain_step(&h_b0).unwrap_err(), CryptoError);
            // Unknown ek_id also fails cleanly without mutating state.
            let mut unknown_id = h_b0.clone();
            unknown_id.ek_id = Some([0xFF; KEM_KEY_ID_LENGTH]);
            assert_eq!(
                alice.receive_chain_step(&unknown_id).unwrap_err(),
                CryptoError
            );

            // Legitimate retransmission on current chain succeeds.
            alice.receive_current_chain(&h_b1).unwrap();

            // Mid-chain mismatch on ek_id or ct bytes MUST be rejected.
            let mut mismatched_id = h_b1.clone();
            mismatched_id.ek_id = Some([0xEE; KEM_KEY_ID_LENGTH]);
            assert_eq!(
                alice.receive_current_chain(&mismatched_id).unwrap_err(),
                CryptoError
            );
            let mut mismatched_ct = h_b1.clone();
            mismatched_ct.ct.as_mut().unwrap()[0] ^= 0x01;
            assert_eq!(
                alice.receive_current_chain(&mismatched_ct).unwrap_err(),
                CryptoError
            );
            let stripped_ct = KemHeader::default();
            assert_eq!(
                alice.receive_current_chain(&stripped_ct).unwrap_err(),
                CryptoError
            );

            // Malformed headers: suite without ek/ct, ct without ek_id, wrong suite, bad ct len.
            let suite_only = KemHeader {
                suite: Some(suite.id()),
                ..KemHeader::default()
            };
            assert_eq!(
                alice.receive_current_chain(&suite_only).unwrap_err(),
                CryptoError
            );
            let ct_without_id = KemHeader {
                suite: Some(suite.id()),
                ct: h_b1.ct.clone(),
                ..KemHeader::default()
            };
            assert_eq!(
                alice.receive_current_chain(&ct_without_id).unwrap_err(),
                CryptoError
            );
            let mut wrong_suite = h_b1.clone();
            wrong_suite.suite = Some(99);
            assert_eq!(
                alice.receive_current_chain(&wrong_suite).unwrap_err(),
                CryptoError
            );
            let mut short_ct = h_b1.clone();
            short_ct.ct.as_mut().unwrap().pop();
            assert_eq!(
                alice.receive_current_chain(&short_ct).unwrap_err(),
                CryptoError
            );
        }
    }

    #[test]
    fn default_cadence_and_skipped_header_ignores_stale_ek() {
        for suite in enabled_suites() {
            let mut alice = KemRatchet::new(suite);
            let mut bob = KemRatchet::new(suite);
            assert_eq!(alice.config(), KemRatchetConfig::default());

            // Initial offer on first send; second send reuses cached ek without regenerating.
            let h_a0 = alice.prepare_send().unwrap();
            let h_a1 = alice.prepare_send().unwrap();
            assert_eq!(h_a0.ek, h_a1.ek);

            // Skipped headers validate PQ fields and bump message cadence, but NEVER adopt a
            // stale/delayed `ek` into `peer_pending_ek` (neither when empty nor when fresher
            // offers are pending).
            let mut bob_skipped = KemRatchet::new(suite);
            bob_skipped.receive_skipped_header(&h_a0).unwrap();
            assert_eq!(bob_skipped.messages_since_rekey, 1);
            assert!(bob_skipped.peer_pending_ek.is_none());
            let mut malformed = h_a0.clone();
            malformed.suite = Some(99);
            assert_eq!(
                bob_skipped.receive_skipped_header(&malformed).unwrap_err(),
                CryptoError
            );
            let (recv_ss, send_ss) = bob_skipped
                .receive_chain_step(&KemHeader::default())
                .unwrap();
            assert!(recv_ss.is_none());
            assert!(send_ss.is_none());

            // Default cadence: after initial exchange, no offer is emitted for < 4 turns / < 20 msgs.
            bob.receive_chain_step(&h_a0).unwrap();
            let h_b0 = bob.prepare_send().unwrap();
            assert!(h_b0.ek.is_none());
            alice.receive_chain_step(&h_b0).unwrap();
            let h_a2 = alice.prepare_send().unwrap();
            assert!(h_a2.ek.is_none());

            // After DEFAULT_REKEY_TURNS empty turns without a KEM mix, a fresh offer triggers.
            for _ in 0..DEFAULT_REKEY_TURNS {
                let h_empty = KemHeader::default();
                let (r, s) = bob.receive_chain_step(&h_empty).unwrap();
                assert!(r.is_none() && s.is_none());
            }
            let h_rekey = bob.prepare_send().unwrap();
            assert!(h_rekey.ek.is_some());
        }
    }

    #[test]
    fn crossed_offers_resolve_without_deadlock() {
        for suite in enabled_suites() {
            let mut alice = KemRatchet::new(suite);
            let mut bob = KemRatchet::new(suite);

            // Both sides independently generate pending offers before hearing from each other.
            let id_a = alice.force_rekey().unwrap();
            let id_b = bob.force_rekey().unwrap();
            let h_a = alice.prepare_send().unwrap();
            let h_b = bob.prepare_send().unwrap();

            // Bob receives Alice's offer mid-chain, then Alice receives Bob's offer on next chain.
            bob.receive_current_chain(&h_a).unwrap();
            let (a_recv, a_send) = alice.receive_chain_step(&h_b).unwrap();
            assert!(a_recv.is_none());
            assert!(a_send.is_some());
            let h_a_reply = alice.prepare_send().unwrap();
            assert_eq!(h_a_reply.ek_id, Some(id_b));
            assert!(h_a_reply.ek.is_some()); // Alice still advertises id_a until acked.

            // Bob receives Alice's reply: decapsulates id_b AND encapsulates id_a.
            let (b_recv, b_send) = bob.receive_chain_step(&h_a_reply).unwrap();
            assert!(b_recv.is_some());
            assert_eq!(b_recv.as_deref(), a_send.as_deref());
            assert!(b_send.is_some());
            assert_eq!(bob.pending_offer_count(), 0);

            let h_b_reply = bob.prepare_send().unwrap();
            assert_eq!(h_b_reply.ek_id, Some(id_a));
            let (a_recv2, _) = alice.receive_chain_step(&h_b_reply).unwrap();
            assert_eq!(a_recv2.as_deref(), b_send.as_deref());
            assert_eq!(alice.pending_offer_count(), 0);
        }
    }

    #[test]
    #[cfg(any(feature = "serde", feature = "prost"))]
    fn serialization_roundtrip_and_invalid_state_rejection() {
        for suite in enabled_suites() {
            let mut alice = KemRatchet::new(suite);
            let mut bob = KemRatchet::new(suite);
            let h_a0 = alice.prepare_send().unwrap();
            bob.receive_chain_step(&h_a0).unwrap();
            let h_b0 = bob.prepare_send().unwrap();

            #[cfg(feature = "serde")]
            {
                let json = serde_json::to_string(&alice).unwrap();
                let mut restored: KemRatchet = serde_json::from_str(&json).unwrap();
                let (ss, _) = restored.receive_chain_step(&h_b0).unwrap();
                assert!(ss.is_some());

                // Corrupt active_offer_id so it doesn't match pending_offers.
                let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
                value["active_offer_id"] = serde_json::to_value([0u8; 16]).unwrap();
                assert!(serde_json::from_value::<KemRatchet>(value).is_err());

                // Oversized encapsulated_ek_ids fails bounded Serde deserialization.
                let mut oversized: serde_json::Value = serde_json::from_str(&json).unwrap();
                oversized["encapsulated_ek_ids"] =
                    serde_json::to_value(vec![[1u8; 16]; MAX_ENCAPSULATED_HISTORY + 1]).unwrap();
                assert!(serde_json::from_value::<KemRatchet>(oversized).is_err());
            }

            #[cfg(feature = "prost")]
            {
                let proto = crate::proto::KemRatchet::from(&alice);
                let mut restored = KemRatchet::try_from(&proto).unwrap();
                let (ss, _) = restored.receive_chain_step(&h_b0).unwrap();
                assert!(ss.is_some());

                // Corrupt offer ID -> must fail validation.
                let mut bad = proto.clone();
                bad.pending_offers[0].id[0] ^= 0xFF;
                assert_eq!(KemRatchet::try_from(&bad).unwrap_err(), MalformedState);

                // Unknown suite -> must fail validation.
                let mut bad_suite = proto.clone();
                bad_suite.suite = 99;
                assert_eq!(
                    KemRatchet::try_from(&bad_suite).unwrap_err(),
                    MalformedState
                );
            }
        }
    }
}
