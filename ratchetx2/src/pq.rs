//! Optional post-quantum KEM ratchet (periodic PQ3-style epoch state machine) using FIPS 203
//! ML-KEM.
//!
//! Enabled via the `ml-kem-1024`, `ml-kem-768`, or `pq` features. Default builds of `ratchetx2`
//! pull zero post-quantum dependencies.

use core::fmt;
use std::collections::VecDeque;

use ml_kem::{
    B32, Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, Seed,
};
#[cfg(feature = "ml-kem-768")]
use ml_kem::MlKem768;
#[cfg(feature = "ml-kem-1024")]
use ml_kem::MlKem1024;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;
#[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
use crate::error::MalformedState;

/// Length of an ML-KEM `(d, z)` seed in bytes.
pub const KEM_SEED_LENGTH: usize = 64;
/// Length of a KEM encapsulation key identifier in bytes.
pub const KEM_KEY_ID_LENGTH: usize = 16;
/// Length of an ML-KEM shared secret in bytes.
pub const KEM_SHARED_SECRET_LENGTH: usize = 32;
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
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
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

#[cfg(feature = "rkyv")]
impl ArchivedPqSuite {
    fn to_suite(&self) -> PqSuite {
        match self {
            #[cfg(feature = "ml-kem-1024")]
            ArchivedPqSuite::MlKem1024 => PqSuite::MlKem1024,
            #[cfg(feature = "ml-kem-768")]
            ArchivedPqSuite::MlKem768 => PqSuite::MlKem768,
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
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
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
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
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
                    return Err(serde::de::Error::invalid_length(
                        KEM_SEED_LENGTH + 1,
                        &self,
                    ));
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
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
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

/// Ciphertext retransmitted on every message of the current sending chain.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
struct ActiveSendCt {
    ek_id: [u8; KEM_KEY_ID_LENGTH],
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
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
struct PeerPendingEk {
    ek_id: [u8; KEM_KEY_ID_LENGTH],
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

/// Periodic PQ3-style post-quantum KEM ratchet state machine.
///
/// Stores only 64-byte FIPS 203 `(d, z)` seeds (never expanded decapsulation keys) and tracks up
/// to [`MAX_PENDING_OFFERS`] pending local offers keyed by 16-byte `ek_id` so crossed rekey
/// offers resolve deterministically without deadlocking.
///
/// Supports [`Clone`] for tentative execution before AEAD verification and serializes with
/// `serde`, `rkyv`, and `prost`.
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "KemRatchetUnchecked")
)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    rkyv(bytecheck(verify))
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
            let offer = self
                .pending_offers
                .iter()
                .find(|offer| offer.id == active_id)
                .ok_or(CryptoError)?;
            Some(expand_ek(self.suite, offer.seed.as_bytes()))
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
    /// Call on a cloned [`KemRatchet`] and commit only after message AEAD verification succeeds.
    pub fn receive_chain_step(
        &mut self,
        header: &KemHeader,
    ) -> Result<(Option<KemSharedSecret>, Option<KemSharedSecret>), CryptoError> {
        self.validate_incoming_header(header)?;

        // 1. Receiver DH step: decapsulate peer ciphertext if present.
        let recv_secret = if let (Some(ct), Some(ek_id)) = (&header.ct, header.ek_id) {
            let pos = self
                .pending_offers
                .iter()
                .position(|offer| offer.id == ek_id)
                .ok_or(CryptoError)?;
            let ss = decapsulate(self.suite, self.pending_offers[pos].seed.as_bytes(), ct)?;
            // Removing drops PendingOffer -> KemSeed::drop zeroizes the 64-byte seed.
            self.pending_offers.remove(pos);
            if self.active_offer_id == Some(ek_id) {
                self.active_offer_id = None;
            }
            Some(ss)
        } else {
            None
        };

        // 2. Record any newly offered peer encapsulation key.
        if let Some(ek) = &header.ek {
            self.record_peer_ek(ek);
        }

        // 3. Sender DH step: starting a brand-new sending chain replaces any prior send ct.
        self.active_send_ct = None;
        let send_secret = if let Some(peer_ek) = self.peer_pending_ek.take() {
            let (ct, ss) = encapsulate(self.suite, &peer_ek.ek)?;
            self.active_send_ct = Some(ActiveSendCt {
                ek_id: peer_ek.ek_id,
                ct,
            });
            self.record_encapsulated_ek_id(peer_ek.ek_id);
            Some(ss)
        } else {
            None
        };

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
    /// Validates the PQ fields, queues any new peer encapsulation key for our next sending chain,
    /// and updates the message counter. Retransmitted ciphertexts belonging to the current chain
    /// are validated structurally without attempting a second decapsulation.
    ///
    /// Call on a cloned [`KemRatchet`] and commit only after message AEAD verification succeeds.
    pub fn receive_current_chain(&mut self, header: &KemHeader) -> Result<(), CryptoError> {
        self.validate_incoming_header(header)?;
        if let Some(ek) = &header.ek {
            self.record_peer_ek(ek);
        }
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
        if self.rekey_turns > 0 && (self.rekey_turns == 1 || self.turns_since_rekey >= self.rekey_turns)
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

#[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
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

/// Expand a 64-byte FIPS 203 `(d, z)` seed into its encoded encapsulation key bytes.
fn expand_ek(suite: PqSuite, seed: &[u8; KEM_SEED_LENGTH]) -> Vec<u8> {
    let seed = Zeroizing::new(Seed::from(*seed));
    match suite {
        #[cfg(feature = "ml-kem-1024")]
        PqSuite::MlKem1024 => {
            let dk = DecapsulationKey::<MlKem1024>::from_seed(*seed);
            dk.encapsulation_key().to_bytes().as_slice().to_vec()
        }
        #[cfg(feature = "ml-kem-768")]
        PqSuite::MlKem768 => {
            let dk = DecapsulationKey::<MlKem768>::from_seed(*seed);
            dk.encapsulation_key().to_bytes().as_slice().to_vec()
        }
    }
}

/// Validate an encoded ML-KEM encapsulation key (exact length + FIPS 203 modulus check).
fn validate_ek(suite: PqSuite, ek: &[u8]) -> Result<(), CryptoError> {
    match suite {
        #[cfg(feature = "ml-kem-1024")]
        PqSuite::MlKem1024 => {
            let arr = ek.try_into().map_err(|_| CryptoError)?;
            EncapsulationKey::<MlKem1024>::new(arr).map_err(|_| CryptoError)?;
            Ok(())
        }
        #[cfg(feature = "ml-kem-768")]
        PqSuite::MlKem768 => {
            let arr = ek.try_into().map_err(|_| CryptoError)?;
            EncapsulationKey::<MlKem768>::new(arr).map_err(|_| CryptoError)?;
            Ok(())
        }
    }
}

/// Encapsulate a fresh shared secret to an encoded ML-KEM encapsulation key.
fn encapsulate(
    suite: PqSuite,
    ek: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; KEM_SHARED_SECRET_LENGTH]>), CryptoError> {
    let mut m = Zeroizing::new(B32::default());
    getrandom::fill(m.as_mut_slice()).map_err(|_| CryptoError)?;
    match suite {
        #[cfg(feature = "ml-kem-1024")]
        PqSuite::MlKem1024 => {
            let arr = ek.try_into().map_err(|_| CryptoError)?;
            let ek = EncapsulationKey::<MlKem1024>::new(arr).map_err(|_| CryptoError)?;
            let (ct, mut ss) = ek.encapsulate_deterministic(&m);
            let mut out = Zeroizing::new([0u8; KEM_SHARED_SECRET_LENGTH]);
            out.copy_from_slice(ss.as_slice());
            ss.zeroize();
            Ok((ct.as_slice().to_vec(), out))
        }
        #[cfg(feature = "ml-kem-768")]
        PqSuite::MlKem768 => {
            let arr = ek.try_into().map_err(|_| CryptoError)?;
            let ek = EncapsulationKey::<MlKem768>::new(arr).map_err(|_| CryptoError)?;
            let (ct, mut ss) = ek.encapsulate_deterministic(&m);
            let mut out = Zeroizing::new([0u8; KEM_SHARED_SECRET_LENGTH]);
            out.copy_from_slice(ss.as_slice());
            ss.zeroize();
            Ok((ct.as_slice().to_vec(), out))
        }
    }
}

/// Decapsulate an ML-KEM ciphertext using a 64-byte `(d, z)` seed.
fn decapsulate(
    suite: PqSuite,
    seed: &[u8; KEM_SEED_LENGTH],
    ct: &[u8],
) -> Result<Zeroizing<[u8; KEM_SHARED_SECRET_LENGTH]>, CryptoError> {
    let seed = Zeroizing::new(Seed::from(*seed));
    match suite {
        #[cfg(feature = "ml-kem-1024")]
        PqSuite::MlKem1024 => {
            let dk = DecapsulationKey::<MlKem1024>::from_seed(*seed);
            let mut ss = dk.decapsulate_slice(ct).map_err(|_| CryptoError)?;
            let mut out = Zeroizing::new([0u8; KEM_SHARED_SECRET_LENGTH]);
            out.copy_from_slice(ss.as_slice());
            ss.zeroize();
            Ok(out)
        }
        #[cfg(feature = "ml-kem-768")]
        PqSuite::MlKem768 => {
            let dk = DecapsulationKey::<MlKem768>::from_seed(*seed);
            let mut ss = dk.decapsulate_slice(ct).map_err(|_| CryptoError)?;
            let mut out = Zeroizing::new([0u8; KEM_SHARED_SECRET_LENGTH]);
            out.copy_from_slice(ss.as_slice());
            ss.zeroize();
            Ok(out)
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct KemRatchetUnchecked {
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
        };
        ratchet.validate()?;
        Ok(ratchet)
    }
}

#[cfg(feature = "rkyv")]
unsafe impl<C> rkyv::bytecheck::Verify<C> for ArchivedKemRatchet
where
    C: rkyv::rancor::Fallible + ?Sized,
    C::Error: rkyv::rancor::Source,
{
    fn verify(&self, _context: &mut C) -> Result<(), C::Error> {
        use rkyv::rancor::Source;
        let suite = self.suite.to_suite();
        validate_kem_ratchet_state(
            suite,
            self.pending_offers
                .iter()
                .map(|offer| (offer.id, &offer.seed.0)),
            self.active_offer_id.as_ref().copied(),
            self.active_send_ct
                .as_ref()
                .map(|a| (a.ek_id, a.ct.as_slice())),
            self.peer_pending_ek
                .as_ref()
                .map(|p| (p.ek_id, p.ek.as_slice())),
            self.encapsulated_ek_ids.iter().copied(),
        )
        .map_err(C::Error::new)
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
            active_offer_id: kem
                .active_offer_id
                .map_or_else(Vec::new, |id| id.to_vec()),
            active_send_ct: kem
                .active_send_ct
                .as_ref()
                .map(|active| crate::proto::KemActiveSendCt {
                    ek_id: active.ek_id.to_vec(),
                    ciphertext: active.ct.clone(),
                }),
            peer_pending_ek: kem
                .peer_pending_ek
                .as_ref()
                .map(|peer| crate::proto::KemPeerPendingEk {
                    ek_id: peer.ek_id.to_vec(),
                    encapsulation_key: peer.ek.clone(),
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
            assert_eq!(alice, bob);
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
            assert_eq!(alice, bob);
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
            assert_eq!(alice, bob);
            assert_eq!(bob_kem.pending_offer_count(), 0);
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
    #[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
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
            }

            #[cfg(feature = "rkyv")]
            {
                let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&alice).unwrap();
                let mut restored =
                    rkyv::from_bytes::<KemRatchet, rkyv::rancor::Error>(&bytes).unwrap();
                let (ss, _) = restored.receive_chain_step(&h_b0).unwrap();
                assert!(ss.is_some());
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
                assert_eq!(KemRatchet::try_from(&bad_suite).unwrap_err(), MalformedState);
            }
        }
    }
}
