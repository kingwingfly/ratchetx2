//! Optional post-quantum handshake and idempotent mailbox storage records and traits.
//!
//! This module contains only data structures and async storage traits; it pulls zero ML-KEM
//! cryptography dependencies so relays only validate sizes and signatures.

use bytes::Bytes;

use crate::{PublicKey, Result, Signature};

/// Length of a deterministic post-quantum prekey identifier (SHA-256).
pub const PQ_PREKEY_ID_LENGTH: usize = 32;

/// A deterministic 32-byte post-quantum prekey identifier.
pub type PqPrekeyId = [u8; PQ_PREKEY_ID_LENGTH];

/// Commitment to one last-resort post-quantum signed prekey inside a [`StoredCapabilityManifest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqLastResortCommitment {
    /// Wire ML-KEM suite identifier (`1` = ML-KEM-1024, `2` = ML-KEM-768).
    pub suite: u8,
    /// Deterministic 32-byte prekey identifier.
    pub prekey_id: PqPrekeyId,
}

/// An identity-signed post-quantum capability manifest stored for a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCapabilityManifest {
    /// Relay audience / server identifier bound into the signature.
    pub audience: String,
    /// The owner's canonical XEdDSA identity public key.
    pub identity_key: PublicKey,
    /// Strictly increasing manifest sequence number per identity.
    pub manifest_seq: u64,
    /// Prekey generation identifier.
    pub generation: u64,
    /// Issuance timestamp in milliseconds since the Unix epoch.
    pub issued_at: u64,
    /// Expiration timestamp in milliseconds since the Unix epoch.
    pub expires_at: u64,
    /// Affirmative post-quantum policy (`true` = enabled, `false` = affirmative OFF).
    pub pq_enabled: bool,
    /// Strict PQ mode (`true` blocks legacy v1 bundle fetches).
    pub strict_pq: bool,
    /// Whether continuous PQ KEM ratcheting is advertised.
    pub pq_ratchet_supported: bool,
    /// Offered ML-KEM suite identifiers in preference order.
    pub offered_suites: Vec<u8>,
    /// Current classical X25519 signed prekey committed by the manifest.
    pub signed_prekey: PublicKey,
    /// Last-resort PQSPK commitments per offered suite.
    pub pq_last_resort: Vec<PqLastResortCommitment>,
    /// Owner's XEdDSA signature over the canonical manifest signing input.
    pub signature: Signature,
}

/// A stored post-quantum prekey (either a last-resort PQSPK or a one-time PQOPK).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPqPrekey {
    /// Wire ML-KEM suite identifier (`1` = ML-KEM-1024, `2` = ML-KEM-768).
    pub suite: u8,
    /// Deterministic 32-byte prekey identifier.
    pub id: PqPrekeyId,
    /// Raw ML-KEM encapsulation key bytes.
    pub encapsulation_key: Bytes,
    /// Domain-separated XEdDSA signature by the owner's identity key.
    pub signature: Signature,
}

/// Full v2 prekey publication payload passed to [`LocalPqHandshakeStore::publish_v2`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishV2Record {
    /// Verified signed capability manifest.
    pub manifest: StoredCapabilityManifest,
    /// Optional legacy raw XEdDSA signature over `manifest.signed_prekey` for v1 compatibility.
    /// Must be `None` when `manifest.strict_pq` is `true`.
    pub signed_prekey_signature: Option<Signature>,
    /// Fresh classical X25519 one-time prekeys replacing the previous pool.
    pub one_time_prekeys: Vec<PublicKey>,
    /// Last-resort PQSPKs (empty when `!manifest.pq_enabled`).
    pub pq_last_resort: Vec<StoredPqPrekey>,
    /// One-time PQOPKs (empty when `!manifest.pq_enabled`).
    pub pq_one_time_prekeys: Vec<StoredPqPrekey>,
    /// Request timestamp in milliseconds since the Unix epoch.
    pub timestamp: u64,
}

/// Outcome of [`LocalPqHandshakeStore::publish_v2`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishV2Status {
    /// The manifest and prekeys were stored atomically.
    Stored,
    /// Rejected because `manifest.manifest_seq` was not strictly greater than the stored one.
    StaleSequence,
    /// Rejected because duplicate classical or post-quantum one-time prekeys were supplied.
    DuplicatePrekey,
}

/// Prekey replenishment payload passed to [`LocalPqHandshakeStore::refill_prekeys`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefillPrekeysRecord {
    /// The owner's identity key.
    pub identity_key: PublicKey,
    /// Generation being replenished (must match the stored manifest's current generation).
    pub generation: u64,
    /// Fresh classical X25519 one-time prekeys to append.
    pub one_time_prekeys: Vec<PublicKey>,
    /// Fresh signed post-quantum one-time prekeys to append.
    pub pq_one_time_prekeys: Vec<StoredPqPrekey>,
    /// Maximum total classical one-time prekeys allowed in the current generation.
    pub max_one_time_prekeys: usize,
    /// Maximum total post-quantum one-time prekeys allowed in the current generation.
    pub max_pq_one_time_prekeys: usize,
    /// Strictly increasing request timestamp in milliseconds since the Unix epoch.
    pub timestamp: u64,
}

/// Outcome of [`LocalPqHandshakeStore::refill_prekeys`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefillStatus {
    /// Fresh prekeys were appended to the current generation.
    Stored {
        /// Total classical one-time prekeys now stored.
        classical_count: usize,
        /// Total post-quantum one-time prekeys now stored per suite `(suite, count)`.
        pq_counts: Vec<(u8, usize)>,
    },
    /// No manifest has been published for this identity.
    NotFound,
    /// The supplied generation does not match the currently published manifest's generation,
    /// or PQOPKs were supplied while PQ is disabled in the current manifest.
    StaleGeneration,
    /// The request timestamp was not strictly greater than the previous accepted refill's.
    StaleTimestamp,
    /// One or more supplied prekeys collided with existing or sibling prekeys.
    DuplicatePrekey,
    /// Appending the supplied prekeys would exceed the configured pool cap.
    LimitExceeded,
}

/// Result of atomically claiming a peer's bundle via [`LocalPqHandshakeStore::claim_bundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedPqBundle {
    /// The peer's identity key.
    pub identity_key: PublicKey,
    /// The peer's signed manifest, or `None` when falling back to a legacy classical v1 bundle.
    pub manifest: Option<StoredCapabilityManifest>,
    /// The peer's classical X25519 signed prekey.
    pub signed_prekey: PublicKey,
    /// Legacy raw XEdDSA signature over `signed_prekey`, if available (absent in strict PQ mode).
    pub signed_prekey_signature: Option<Signature>,
    /// Popped classical one-time prekey, if any remained.
    pub one_time_prekey: Option<PublicKey>,
    /// Matching last-resort PQSPK for the negotiated suite, if PQ was negotiated.
    pub pq_last_resort: Option<StoredPqPrekey>,
    /// Popped one-time PQOPK for the negotiated suite, if any remained.
    pub pq_one_time_prekey: Option<StoredPqPrekey>,
}

/// An initial message (classical v1 or PQXDH v2) stored in a recipient's inbox with a stable ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredInitialMessageV2 {
    /// Stable monotonic inbox ID assigned by the store (`0` on insert, positive when listed).
    pub id: u64,
    /// Protocol version (`1` = classical X3DH, `2` = PQXDH).
    pub version: u32,
    /// The sender's identity key.
    pub sender: PublicKey,
    /// The recipient's identity key.
    pub recipient: PublicKey,
    /// The sender's ephemeral X25519 key.
    pub ephemeral_key: PublicKey,
    /// The recipient's signed prekey used.
    pub signed_prekey: PublicKey,
    /// The recipient's classical one-time prekey used, if any.
    pub one_time_prekey: Option<PublicKey>,
    /// The encrypted header of the session's first message.
    pub header: Bytes,
    /// The encrypted content of the session's first message.
    pub content: Bytes,
    /// ML-KEM suite identifier (`Some(1)` or `Some(2)` for version 2; `None` for version 1).
    pub pq_suite: Option<u8>,
    /// Whether the recipient's last-resort PQSPK was used (`false` for PQOPK or version 1).
    pub pq_last_resort: bool,
    /// Deterministic 32-byte ID of the PQ prekey encapsulated to (`Some` for version 2).
    pub pq_prekey_id: Option<PqPrekeyId>,
    /// ML-KEM ciphertext (`Some` for version 2).
    pub pq_ciphertext: Option<Bytes>,
    /// Optional SHA-256 digest of the recipient's verified [`StoredCapabilityManifest`].
    pub manifest_digest: Option<[u8; 32]>,
}

/// Non-consuming diagnostic snapshot of an identity's v2 handshake storage state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PqStorageSnapshot {
    /// Stored capability manifest, if any.
    pub manifest: Option<StoredCapabilityManifest>,
    /// Number of classical one-time prekeys currently stored.
    pub classical_one_time_count: usize,
    /// Suites that currently have a last-resort PQSPK stored.
    pub pq_last_resort_suites: Vec<u8>,
    /// Counts of stored PQOPKs per suite `(suite, count)`.
    pub pq_one_time_counts: Vec<(u8, usize)>,
    /// Total pending initial messages (both v1 and v2) in the inbox.
    pub pending_initial_messages: usize,
}

/// Storage for the v2 post-quantum handshake service. Every method is atomic.
#[trait_variant::make(PqHandshakeStore: Send)]
pub trait LocalPqHandshakeStore {
    /// Atomically publish a signed capability manifest and its classical + PQ prekeys.
    ///
    /// When `record.manifest.pq_enabled` is `false`, clears stored PQ prekeys while persisting
    /// the signed `OFF` manifest. When `record.manifest.strict_pq` is `true`, clears any stored
    /// legacy v1 bundle so v1 `take_bundle` fails closed.
    async fn publish_v2(&self, record: PublishV2Record) -> Result<PublishV2Status>;

    /// Append fresh classical OPKs and/or signed PQOPKs to the current generation without
    /// rotating the signed prekey or last-resort PQSPKs.
    async fn refill_prekeys(&self, record: RefillPrekeysRecord) -> Result<RefillStatus>;

    /// Non-consuming read of `identity_key`'s signed capability manifest.
    async fn get_manifest(
        &self,
        identity_key: &PublicKey,
    ) -> Result<Option<StoredCapabilityManifest>>;

    /// Atomically claim `identity_key`'s bundle, preferring the first suite in
    /// `preferred_suites` offered by its manifest (falling back gracefully to a legacy classical
    /// v1 bundle with `manifest: None` if no manifest has been published).
    async fn claim_bundle(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
    ) -> Result<Option<ClaimedPqBundle>>;

    /// Insert a v1 or v2 initial message into its recipient's inbox unless the inbox already
    /// holds `limit` messages. Returns `Some(assigned_id)` on success or `None` if full.
    async fn add_initial_message_v2(
        &self,
        initial_message: StoredInitialMessageV2,
        limit: usize,
    ) -> Result<Option<u64>>;

    /// Non-destructively list up to `limit` pending initial messages (both v1 and v2) for
    /// `recipient`, oldest first. Must not allocate persistent storage for unknown identities.
    async fn list_initial_messages(
        &self,
        recipient: &PublicKey,
        limit: usize,
    ) -> Result<Vec<StoredInitialMessageV2>>;

    /// Explicitly delete only the inbox initial messages with IDs in `ids` for `recipient`.
    /// Returns the number of messages deleted. Must not allocate persistent storage for unknown
    /// identities.
    async fn ack_initial_messages(&self, recipient: &PublicKey, ids: &[u64]) -> Result<usize>;

    /// Non-consuming snapshot of an identity's v2 handshake state.
    async fn pq_snapshot(&self, identity_key: &PublicKey) -> Result<PqStorageSnapshot>;
}

/// Optional idempotent mailbox append extension sharing the same underlying queue as
/// [`LocalMailboxStore`](crate::LocalMailboxStore).
#[trait_variant::make(IdempotentMailboxStore: Send)]
pub trait LocalIdempotentMailboxStore {
    /// Append a message to the queue from `sender` to `recipient`, deduplicating retries when
    /// `client_message_id` is `Some` and has already been committed for `(sender, recipient)`.
    #[allow(clippy::too_many_arguments)]
    async fn append_idempotent(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        delivery_hash: Option<[u8; 32]>,
        client_message_id: Option<[u8; 16]>,
    ) -> Result<u64>;
}
