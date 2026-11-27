//! Post-quantum handshake and unified idempotent mailbox storage records and traits.
//!
//! This module contains only data structures and async storage traits; it pulls zero ML-KEM
//! cryptography dependencies so relays only validate sizes and signatures.

use bytes::Bytes;

use crate::{MailboxPage, PeerSlotId, PublicKey, Result, Signature, WriteTokenHash};

/// Length of a deterministic post-quantum prekey identifier (SHA-256).
pub const PQ_PREKEY_ID_LENGTH: usize = 32;

/// A deterministic 32-byte post-quantum prekey identifier.
pub type PqPrekeyId = [u8; PQ_PREKEY_ID_LENGTH];

/// Commitment to one last-resort post-quantum signed prekey inside a [`StoredCapabilityManifest`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PqLastResortCommitment {
    /// Wire ML-KEM suite identifier (`1` = ML-KEM-1024, `2` = ML-KEM-768).
    pub suite: u8,
    /// Deterministic 32-byte prekey identifier.
    pub prekey_id: PqPrekeyId,
}

/// An identity-signed post-quantum capability manifest stored for a user.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    /// Strict PQ mode (`true` omits raw classical SPK signature).
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
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub signature: Signature,
}

/// A stored post-quantum prekey (either a last-resort PQSPK or a one-time PQOPK).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StoredPqPrekey {
    /// Wire ML-KEM suite identifier (`1` = ML-KEM-1024, `2` = ML-KEM-768).
    pub suite: u8,
    /// Deterministic 32-byte prekey identifier.
    pub id: PqPrekeyId,
    /// Raw ML-KEM encapsulation key bytes.
    pub encapsulation_key: Bytes,
    /// Domain-separated XEdDSA signature by the owner's identity key.
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub signature: Signature,
}

/// Full v2 prekey publication payload passed to [`LocalPqHandshakeStore::publish_v2`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublishV2Record {
    /// Verified signed capability manifest.
    pub manifest: StoredCapabilityManifest,
    /// Optional raw XEdDSA signature over `manifest.signed_prekey` for intentional classical X3DH
    /// inside v2. Must be `None` when `manifest.strict_pq` is `true`.
    #[cfg_attr(feature = "serde", serde(with = "crate::opt_signature"))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClaimedPqBundle {
    /// The peer's identity key.
    pub identity_key: PublicKey,
    /// The peer's signed manifest.
    pub manifest: Option<StoredCapabilityManifest>,
    /// The peer's classical X25519 signed prekey.
    pub signed_prekey: PublicKey,
    /// Raw XEdDSA signature over `signed_prekey`, if available (absent in strict PQ mode).
    #[cfg_attr(feature = "serde", serde(with = "crate::opt_signature"))]
    pub signed_prekey_signature: Option<Signature>,
    /// Popped classical one-time prekey, if any remained.
    pub one_time_prekey: Option<PublicKey>,
    /// Matching last-resort PQSPK for the negotiated suite, if PQ was negotiated.
    pub pq_last_resort: Option<StoredPqPrekey>,
    /// Popped one-time PQOPK for the negotiated suite, if any remained.
    pub pq_one_time_prekey: Option<StoredPqPrekey>,
}

/// An initial message (classical X3DH version 1 or PQXDH version 2) stored in a recipient's inbox
/// with a stable monotonic ID.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PqStorageSnapshot {
    /// Stored capability manifest, if any.
    pub manifest: Option<StoredCapabilityManifest>,
    /// Number of classical one-time prekeys currently stored.
    pub classical_one_time_count: usize,
    /// Suites that currently have a last-resort PQSPK stored.
    pub pq_last_resort_suites: Vec<u8>,
    /// Counts of stored PQOPKs per suite `(suite, count)`.
    pub pq_one_time_counts: Vec<(u8, usize)>,
    /// Total pending initial messages in the inbox.
    pub pending_initial_messages: usize,
}

/// Outcome of [`LocalPqHandshakeStore::claim_bundle_checked`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ClaimOutcome {
    /// No manifest exists for this identity.
    NotFound,
    /// The caller requested PQ suites while the server has PQ disabled, and the target identity
    /// currently publishes a PQ-enabled manifest; no one-time prekeys were consumed.
    PqDisabledForPqManifest,
    /// A bundle was claimed (possibly without OPKs when strict/suite policy yielded no match).
    Claimed(Box<ClaimedPqBundle>),
}

/// Outcome of [`LocalPqHandshakeStore::add_initial_message_v2_checked`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum InitialDisposition {
    /// Stored or matched idempotently (live inbox row or unexpired delivery tombstone) at `id`.
    Added(u64),
    /// Rejected because the inbox is full or an unexpired ACK tombstone was capacity-evicted and
    /// stale-prekey proof is temporarily unavailable.
    InboxFull,
    /// Not found as a live row or tombstone and `allow_insert` was `false` (e.g., PQ disabled on
    /// the relay while probing an existing PQ greeting).
    InsertDisallowed,
}

/// A bounded page of pending initial messages returned by
/// [`LocalPqHandshakeStore::list_initial_messages_page`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InitialMessagePage {
    /// Pending initial messages returned on this page (marked as `listed` in storage).
    pub messages: Vec<StoredInitialMessageV2>,
    /// Whether additional pending initial messages exist strictly after the last returned ID.
    pub has_more: bool,
}

/// Write-token registration payload passed to [`LocalIdempotentMailboxStore::register_write_token`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RegisterWriteTokenRecord {
    /// Recipient's canonical identity key.
    pub recipient: PublicKey,
    /// Opaque 32-byte client-derived per-peer slot identifier.
    pub peer_slot_id: PeerSlotId,
    /// SHA-256 of the 32-byte write token to authorize.
    pub token_hash: WriteTokenHash,
    /// Strictly positive monotonic grant version (`1..=MAX_SAFE_INTEGER`).
    pub grant_version: u64,
    /// Whether to pin this token as the peer's active (never-evicted) grant when `grant_version`
    /// exceeds the peer's `max_version` or no active grant is currently pinned.
    pub pin_active: bool,
    /// Signed request timestamp in milliseconds since the Unix epoch (`0` if omitted in direct
    /// unit tests). When non-zero, storage backends re-verify freshness at commit time so delayed
    /// registrations can never outlive revocation-floor tombstones.
    #[cfg_attr(feature = "serde", serde(default))]
    pub timestamp: u64,
}

/// Write-token revocation payload passed to [`LocalIdempotentMailboxStore::revoke_write_token`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RevokeWriteTokenRecord {
    /// Recipient's canonical identity key.
    pub recipient: PublicKey,
    /// Opaque 32-byte client-derived per-peer slot identifier.
    pub peer_slot_id: PeerSlotId,
    /// Specific token hash to revoke, or `None` to revoke all grants for `peer_slot_id`.
    pub token_hash: Option<WriteTokenHash>,
    /// Strictly positive monotonic version floor (`1..=MAX_SAFE_INTEGER`): registrations with
    /// `grant_version <= min_grant_version` are rejected with [`ErrorKind::StaleVersion`](crate::ErrorKind::StaleVersion).
    pub min_grant_version: u64,
}

/// Storage for the v2 post-quantum handshake service. Every method is atomic.
#[allow(async_fn_in_trait)]
pub trait LocalPqHandshakeStore {
    /// Atomically publish a signed capability manifest and its classical + PQ prekeys.
    ///
    /// When `record.manifest.pq_enabled` is `false`, clears stored PQ prekeys while persisting
    /// the signed `OFF` manifest and optional `signed_prekey_signature`.
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
    /// `preferred_suites` offered by its manifest.
    async fn claim_bundle(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
    ) -> Result<Option<ClaimedPqBundle>>;

    /// Like [`claim_bundle`](Self::claim_bundle), but when `reject_pq_on_manifest` is `true`
    /// atomically rejects a PQ-enabled manifest with [`ClaimOutcome::PqDisabledForPqManifest`]
    /// before popping any classical or PQ one-time prekey.
    async fn claim_bundle_checked(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
        reject_pq_on_manifest: bool,
    ) -> Result<ClaimOutcome> {
        if reject_pq_on_manifest
            && self
                .get_manifest(identity_key)
                .await?
                .is_some_and(|m| m.pq_enabled)
        {
            return Ok(ClaimOutcome::PqDisabledForPqManifest);
        }
        match self.claim_bundle(identity_key, preferred_suites).await? {
            None => Ok(ClaimOutcome::NotFound),
            Some(claimed) => {
                if reject_pq_on_manifest && claimed.manifest.as_ref().is_some_and(|m| m.pq_enabled)
                {
                    return Ok(ClaimOutcome::PqDisabledForPqManifest);
                }
                Ok(ClaimOutcome::Claimed(Box::new(claimed)))
            }
        }
    }

    /// Insert a v1 or v2 initial message into its recipient's inbox unless the inbox already
    /// holds `limit` unexpired messages.
    ///
    /// Idempotent on `(sender, ephemeral_key)`: if an unexpired row for `(sender, ephemeral_key)`
    /// already exists, returns `Ok(Some(existing_id))` when the full payload matches (consuming
    /// strictly 1 slot even at cap) or `Err(ErrorKind::InvalidArgument)` on payload mismatch.
    /// Returns `Err(ErrorKind::NotFound)` without allocating storage if the recipient has no
    /// published manifest.
    async fn add_initial_message_v2(
        &self,
        initial_message: StoredInitialMessageV2,
        limit: usize,
    ) -> Result<Option<u64>>;

    /// Like [`add_initial_message_v2`](Self::add_initial_message_v2), with explicit control over
    /// whether a brand-new row may be inserted (`allow_insert == false` performs a read-only
    /// duplicate / ACK-tombstone / SPK-retention disposition check when `PQ_ENABLED="false"`).
    async fn add_initial_message_v2_checked(
        &self,
        initial_message: StoredInitialMessageV2,
        limit: usize,
        allow_insert: bool,
    ) -> Result<InitialDisposition> {
        if !allow_insert {
            return Ok(InitialDisposition::InsertDisallowed);
        }
        Ok(
            match self.add_initial_message_v2(initial_message, limit).await? {
                Some(id) => InitialDisposition::Added(id),
                None => InitialDisposition::InboxFull,
            },
        )
    }

    /// Non-destructively list up to `limit` pending initial messages for `recipient` with
    /// `id > after_id`, oldest first. Must not allocate persistent storage for unknown identities.
    async fn list_initial_messages(
        &self,
        recipient: &PublicKey,
        after_id: u64,
        limit: usize,
    ) -> Result<Vec<StoredInitialMessageV2>>;

    /// Like [`list_initial_messages`](Self::list_initial_messages), returning an exact `has_more`
    /// flag while marking **only** the returned messages as `listed`.
    async fn list_initial_messages_page(
        &self,
        recipient: &PublicKey,
        after_id: u64,
        limit: usize,
    ) -> Result<InitialMessagePage> {
        let mut messages = self
            .list_initial_messages(recipient, after_id, limit.saturating_add(1))
            .await?;
        let has_more = messages.len() > limit;
        messages.truncate(limit);
        Ok(InitialMessagePage { messages, has_more })
    }

    /// Explicitly delete only the inbox initial messages with IDs in `ids` for `recipient`.
    /// Returns the number of messages deleted. Must not allocate persistent storage for unknown
    /// identities.
    async fn ack_initial_messages(&self, recipient: &PublicKey, ids: &[u64]) -> Result<usize>;

    /// Non-consuming snapshot of an identity's v2 handshake state.
    async fn pq_snapshot(&self, identity_key: &PublicKey) -> Result<PqStorageSnapshot>;
}

/// `Send` variant of [`LocalPqHandshakeStore`].
pub trait PqHandshakeStore: Send {
    /// Atomically publish a signed capability manifest and its classical + PQ prekeys.
    fn publish_v2(
        &self,
        record: PublishV2Record,
    ) -> impl std::future::Future<Output = Result<PublishV2Status>> + Send;

    /// Append fresh classical OPKs and/or signed PQOPKs to the current generation without
    /// rotating the signed prekey or last-resort PQSPKs.
    fn refill_prekeys(
        &self,
        record: RefillPrekeysRecord,
    ) -> impl std::future::Future<Output = Result<RefillStatus>> + Send;

    /// Non-consuming read of `identity_key`'s signed capability manifest.
    fn get_manifest(
        &self,
        identity_key: &PublicKey,
    ) -> impl std::future::Future<Output = Result<Option<StoredCapabilityManifest>>> + Send;

    /// Atomically claim `identity_key`'s bundle.
    fn claim_bundle(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
    ) -> impl std::future::Future<Output = Result<Option<ClaimedPqBundle>>> + Send;

    /// Like [`claim_bundle`](Self::claim_bundle), atomically rejecting PQ-enabled manifests when
    /// `reject_pq_on_manifest` is `true` before popping any one-time prekey.
    fn claim_bundle_checked(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
        reject_pq_on_manifest: bool,
    ) -> impl std::future::Future<Output = Result<ClaimOutcome>> + Send;

    /// Insert a v1 or v2 initial message into its recipient's inbox idempotently.
    fn add_initial_message_v2(
        &self,
        initial_message: StoredInitialMessageV2,
        limit: usize,
    ) -> impl std::future::Future<Output = Result<Option<u64>>> + Send;

    /// Like [`add_initial_message_v2`](Self::add_initial_message_v2), supporting read-only
    /// disposition lookup when `allow_insert == false`.
    fn add_initial_message_v2_checked(
        &self,
        initial_message: StoredInitialMessageV2,
        limit: usize,
        allow_insert: bool,
    ) -> impl std::future::Future<Output = Result<InitialDisposition>> + Send;

    /// Non-destructively list up to `limit` pending initial messages with `id > after_id`.
    fn list_initial_messages(
        &self,
        recipient: &PublicKey,
        after_id: u64,
        limit: usize,
    ) -> impl std::future::Future<Output = Result<Vec<StoredInitialMessageV2>>> + Send;

    /// Like [`list_initial_messages`](Self::list_initial_messages), returning an exact `has_more`
    /// flag while marking only the returned messages as `listed`.
    fn list_initial_messages_page(
        &self,
        recipient: &PublicKey,
        after_id: u64,
        limit: usize,
    ) -> impl std::future::Future<Output = Result<InitialMessagePage>> + Send;

    /// Explicitly delete only the inbox initial messages with IDs in `ids` for `recipient`.
    fn ack_initial_messages(
        &self,
        recipient: &PublicKey,
        ids: &[u64],
    ) -> impl std::future::Future<Output = Result<usize>> + Send;

    /// Non-consuming snapshot of an identity's v2 handshake state.
    fn pq_snapshot(
        &self,
        identity_key: &PublicKey,
    ) -> impl std::future::Future<Output = Result<PqStorageSnapshot>> + Send;
}

impl<T: PqHandshakeStore> LocalPqHandshakeStore for T {
    async fn publish_v2(&self, record: PublishV2Record) -> Result<PublishV2Status> {
        PqHandshakeStore::publish_v2(self, record).await
    }

    async fn refill_prekeys(&self, record: RefillPrekeysRecord) -> Result<RefillStatus> {
        PqHandshakeStore::refill_prekeys(self, record).await
    }

    async fn get_manifest(
        &self,
        identity_key: &PublicKey,
    ) -> Result<Option<StoredCapabilityManifest>> {
        PqHandshakeStore::get_manifest(self, identity_key).await
    }

    async fn claim_bundle(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
    ) -> Result<Option<ClaimedPqBundle>> {
        PqHandshakeStore::claim_bundle(self, identity_key, preferred_suites).await
    }

    async fn claim_bundle_checked(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
        reject_pq_on_manifest: bool,
    ) -> Result<ClaimOutcome> {
        PqHandshakeStore::claim_bundle_checked(
            self,
            identity_key,
            preferred_suites,
            reject_pq_on_manifest,
        )
        .await
    }

    async fn add_initial_message_v2(
        &self,
        initial_message: StoredInitialMessageV2,
        limit: usize,
    ) -> Result<Option<u64>> {
        PqHandshakeStore::add_initial_message_v2(self, initial_message, limit).await
    }

    async fn add_initial_message_v2_checked(
        &self,
        initial_message: StoredInitialMessageV2,
        limit: usize,
        allow_insert: bool,
    ) -> Result<InitialDisposition> {
        PqHandshakeStore::add_initial_message_v2_checked(self, initial_message, limit, allow_insert)
            .await
    }

    async fn list_initial_messages(
        &self,
        recipient: &PublicKey,
        after_id: u64,
        limit: usize,
    ) -> Result<Vec<StoredInitialMessageV2>> {
        PqHandshakeStore::list_initial_messages(self, recipient, after_id, limit).await
    }

    async fn list_initial_messages_page(
        &self,
        recipient: &PublicKey,
        after_id: u64,
        limit: usize,
    ) -> Result<InitialMessagePage> {
        PqHandshakeStore::list_initial_messages_page(self, recipient, after_id, limit).await
    }

    async fn ack_initial_messages(&self, recipient: &PublicKey, ids: &[u64]) -> Result<usize> {
        PqHandshakeStore::ack_initial_messages(self, recipient, ids).await
    }

    async fn pq_snapshot(&self, identity_key: &PublicKey) -> Result<PqStorageSnapshot> {
        PqHandshakeStore::pq_snapshot(self, identity_key).await
    }
}

/// Storage for the v2 unified sealed-sender-lite mailbox and write-token grant service.
/// Every method is atomic.
#[allow(async_fn_in_trait)]
pub trait LocalIdempotentMailboxStore {
    /// Append a message to `recipient`'s unified mailbox authorized by `token_hash`
    /// (`SHA-256(write_token)`), enforcing **auth-before-dedup**:
    ///
    /// 1. Verify `token_hash` is registered for `recipient` using constant-time comparison,
    ///    returning [`ErrorKind::WriteTokenRejected`](crate::ErrorKind::WriteTokenRejected)
    ///    without allocating storage if unknown or revoked — strictly BEFORE checking
    ///    deduplication tombstones.
    /// 2. If `client_message_id` is `Some` and matches an unexpired tombstone for
    ///    `(recipient, token_hash, client_message_id)`, return the original sequence without
    ///    inserting a duplicate row (even after the message has been ACKed).
    /// 3. Enforce per-peer ([`MAX_QUEUE_MESSAGES`](crate::MAX_QUEUE_MESSAGES) /
    ///    [`MAX_QUEUE_BYTES`](crate::MAX_QUEUE_BYTES)) and recipient-wide
    ///    ([`MAX_RECIPIENT_BYTES`](crate::MAX_RECIPIENT_BYTES)) quotas, allocate the next
    ///    unified monotonic sequence, insert the message, and record the tombstone.
    async fn append_idempotent(
        &self,
        recipient: &PublicKey,
        token_hash: &WriteTokenHash,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        client_message_id: Option<[u8; 16]>,
    ) -> Result<u64>;

    /// Read a bounded page of messages from `recipient`'s unified mailbox strictly after
    /// `after_sequence`, optionally atomically deleting all messages with
    /// `sequence <= ack_up_to_sequence` first (when `ack_up_to_sequence > 0`).
    ///
    /// Rejects `ack_up_to_sequence > last_sequence` with
    /// [`ErrorKind::InvalidArgument`](crate::ErrorKind::InvalidArgument). Must not allocate
    /// persistent storage for unknown identities.
    async fn read_mailbox(
        &self,
        recipient: &PublicKey,
        after_sequence: u64,
        limit: u32,
        max_size: usize,
        ack_up_to_sequence: u64,
    ) -> Result<MailboxPage>;

    /// Atomically delete all messages for `recipient` with `sequence <= up_to_sequence`,
    /// preserving the recipient's monotonic high-water mark (`last_sequence`) and updating
    /// per-peer and recipient-wide usage counters.
    ///
    /// Rejects `up_to_sequence == 0` or `up_to_sequence > last_sequence` with
    /// [`ErrorKind::InvalidArgument`](crate::ErrorKind::InvalidArgument). Returns the number of
    /// messages deleted (idempotent for already-deleted prefixes).
    async fn ack_messages(&self, recipient: &PublicKey, up_to_sequence: u64) -> Result<u64>;

    /// Register a write-token hash for `(record.recipient, record.peer_slot_id)` under recipient
    /// grant versioning.
    ///
    /// Enforces:
    /// - Recipient must have a published manifest (`NotFound`, zero storage allocation).
    /// - `grant_version` must be in `1..=MAX_SAFE_INTEGER` (`InvalidArgument`) and strictly
    ///   greater than the peer's `revoked_below_version` (`StaleVersion`).
    /// - Cross-peer `token_hash` collisions are rejected with `InvalidArgument`.
    /// - Duplicate `token_hash` for the same `peer_slot_id` never overwrites stored
    ///   `grant_version` or `created_at`.
    /// - Hard cap [`MAX_AUTHORIZED_PEERS`](crate::MAX_AUTHORIZED_PEERS) on peers transitioning
    ///   `0 -> 1` live tokens (`LimitExceeded`).
    /// - Cap [`MAX_GRANTS_PER_PEER`](crate::MAX_GRANTS_PER_PEER) per peer, evicting lowest
    ///   `grant_version` rows strictly excluding the pinned `active_token_hash`.
    async fn register_write_token(&self, record: RegisterWriteTokenRecord) -> Result<()>;

    /// Revoke one or all write tokens for `(record.recipient, record.peer_slot_id)` and advance
    /// `revoked_below_version` and `max_version` to at least `record.min_grant_version`.
    ///
    /// Returns the number of revoked write tokens. Requires the recipient to have a published
    /// manifest (`NotFound`, zero storage allocation).
    async fn revoke_write_token(&self, record: RevokeWriteTokenRecord) -> Result<u32>;
}

/// `Send` variant of [`LocalIdempotentMailboxStore`].
pub trait IdempotentMailboxStore: Send {
    /// Append a message to `recipient`'s unified mailbox authorized by `token_hash`.
    fn append_idempotent(
        &self,
        recipient: &PublicKey,
        token_hash: &WriteTokenHash,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        client_message_id: Option<[u8; 16]>,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;

    /// Read a bounded page of messages from `recipient`'s unified mailbox with optional prefix ACK.
    fn read_mailbox(
        &self,
        recipient: &PublicKey,
        after_sequence: u64,
        limit: u32,
        max_size: usize,
        ack_up_to_sequence: u64,
    ) -> impl std::future::Future<Output = Result<MailboxPage>> + Send;

    /// Delete all messages for `recipient` with `sequence <= up_to_sequence`.
    fn ack_messages(
        &self,
        recipient: &PublicKey,
        up_to_sequence: u64,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;

    /// Register a write-token hash for a peer slot.
    fn register_write_token(
        &self,
        record: RegisterWriteTokenRecord,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Revoke one or all write tokens for a peer slot.
    fn revoke_write_token(
        &self,
        record: RevokeWriteTokenRecord,
    ) -> impl std::future::Future<Output = Result<u32>> + Send;
}

impl<T: IdempotentMailboxStore> LocalIdempotentMailboxStore for T {
    async fn append_idempotent(
        &self,
        recipient: &PublicKey,
        token_hash: &WriteTokenHash,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        client_message_id: Option<[u8; 16]>,
    ) -> Result<u64> {
        IdempotentMailboxStore::append_idempotent(
            self,
            recipient,
            token_hash,
            header,
            content,
            initial_message,
            client_message_id,
        )
        .await
    }

    async fn read_mailbox(
        &self,
        recipient: &PublicKey,
        after_sequence: u64,
        limit: u32,
        max_size: usize,
        ack_up_to_sequence: u64,
    ) -> Result<MailboxPage> {
        IdempotentMailboxStore::read_mailbox(
            self,
            recipient,
            after_sequence,
            limit,
            max_size,
            ack_up_to_sequence,
        )
        .await
    }

    async fn ack_messages(&self, recipient: &PublicKey, up_to_sequence: u64) -> Result<u64> {
        IdempotentMailboxStore::ack_messages(self, recipient, up_to_sequence).await
    }

    async fn register_write_token(&self, record: RegisterWriteTokenRecord) -> Result<()> {
        IdempotentMailboxStore::register_write_token(self, record).await
    }

    async fn revoke_write_token(&self, record: RevokeWriteTokenRecord) -> Result<u32> {
        IdempotentMailboxStore::revoke_write_token(self, record).await
    }
}
