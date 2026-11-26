//! In-memory backend.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    time::Duration,
};

use bytes::Bytes;
use parking_lot::Mutex;
use subtle::ConstantTimeEq;
use web_time::Instant;

use crate::{
    AttachmentId, AttachmentStore, ClaimOutcome, ClaimedPqBundle, ErrorKind,
    IdempotentMailboxStore, MAX_AUTHORIZED_PEERS, MAX_GRANTS_PER_PEER, MAX_QUEUE_BYTES,
    MAX_QUEUE_MESSAGES, MAX_RECIPIENT_BYTES, MAX_SAFE_INTEGER, MailboxPage, PeerSlotId,
    PqHandshakeStore, PqPrekeyId, PqStorageSnapshot, PublicKey, PublishV2Record, PublishV2Status,
    RefillPrekeysRecord, RefillStatus, RegisterWriteTokenRecord, Result, RevokeWriteTokenRecord,
    Signature, StoredAttachment, StoredCapabilityManifest, StoredInitialMessageV2, StoredMessage,
    StoredPqPrekey, WriteTokenHash,
};

/// How long a mailbox retry can recover the original sequence after insertion.
pub const DEFAULT_DEDUP_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Maximum retained client-message IDs per `(recipient, token_hash)`.
pub const DEFAULT_MAX_DEDUP_TOMBSTONES: usize = 4096;
/// Maximum number of distinct `(recipient, token_hash)` deduplication buckets retained globally.
pub const DEFAULT_MAX_DEDUP_BUCKETS: usize = 4096;
/// Default retention for inbox initial messages before expiry pruning (30 days).
pub const DEFAULT_INITIAL_MESSAGE_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Default retention for empty revoked `peer_grants` tombstones (matches protocol `MAX_CLOCK_SKEW`:
/// 5 minutes, preventing in-flight `RegisterWriteToken` replays within ±5m).
pub const DEFAULT_REVOCATION_TOMBSTONE_TTL: Duration = Duration::from_secs(5 * 60);

const DEDUP_SWEEP_BUDGET: usize = 8;

#[derive(Debug)]
struct DedupLimits {
    ttl: Duration,
    max_per_token: usize,
    max_buckets: usize,
}

impl Default for DedupLimits {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_DEDUP_TTL,
            max_per_token: DEFAULT_MAX_DEDUP_TOMBSTONES,
            max_buckets: DEFAULT_MAX_DEDUP_BUCKETS,
        }
    }
}

#[derive(Debug)]
struct Tombstone {
    id: [u8; 16],
    sequence: u64,
    inserted: Instant,
}

#[derive(Debug)]
struct DedupBucket {
    entries: VecDeque<Tombstone>,
    /// O(1) lookup index from `client_message_id` to its committed sequence number.
    index: HashMap<[u8; 16], u64>,
    sweep_index: usize,
}

/// Keeps everything in memory until dropped. Implements [`PqHandshakeStore`],
/// [`IdempotentMailboxStore`], and [`AttachmentStore`].
#[derive(Debug)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
    dedup: DedupLimits,
    initial_ttl: Duration,
    revocation_tombstone_ttl: Duration,
    max_authorized_peers: usize,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            inner: Mutex::default(),
            dedup: DedupLimits::default(),
            initial_ttl: DEFAULT_INITIAL_MESSAGE_TTL,
            revocation_tombstone_ttl: DEFAULT_REVOCATION_TOMBSTONE_TTL,
            max_authorized_peers: MAX_AUTHORIZED_PEERS,
        }
    }
}

impl MemoryStore {
    /// Create a store with a fixed retry window and tombstone cap per `(recipient, token_hash)`.
    /// A zero TTL or cap disables deduplication.
    pub fn with_dedup_limits(ttl: Duration, max_per_token: usize) -> Self {
        Self {
            dedup: DedupLimits {
                ttl,
                max_per_token,
                max_buckets: DEFAULT_MAX_DEDUP_BUCKETS,
            },
            ..Self::default()
        }
    }

    /// Create a store with custom retry window, per-token tombstone cap, and global bucket cap.
    pub fn with_dedup_limits_and_buckets(
        ttl: Duration,
        max_per_token: usize,
        max_buckets: usize,
    ) -> Self {
        Self {
            dedup: DedupLimits {
                ttl,
                max_per_token,
                max_buckets,
            },
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone)]
struct PublishedManifest {
    manifest: StoredCapabilityManifest,
    signed_prekey_signature: Option<Signature>,
}

#[derive(Debug, Default)]
struct PeerGrant {
    max_version: u64,
    revoked_below_version: u64,
    revoked_at: Option<Instant>,
    active_token_hash: Option<WriteTokenHash>,
    live_tokens: usize,
    message_count: usize,
    total_bytes: u64,
}

#[derive(Debug, Clone)]
struct WriteTokenEntry {
    token_hash: WriteTokenHash,
    peer_slot_id: PeerSlotId,
    grant_version: u64,
    #[allow(dead_code)]
    created_at: Instant,
    insert_order: u64,
}

#[derive(Debug)]
struct QueuedMessage {
    peer_slot_id: PeerSlotId,
    bytes: u64,
    message: StoredMessage,
}

#[derive(Debug, Default)]
struct RecipientMailbox {
    last_sequence: u64,
    message_count: usize,
    total_bytes: u64,
    authorized_peer_count: usize,
    next_insert_order: u64,
    peer_grants: HashMap<PeerSlotId, PeerGrant>,
    write_tokens: HashMap<WriteTokenHash, WriteTokenEntry>,
    messages: Vec<QueuedMessage>,
}

#[derive(Debug, Default)]
struct Inbox {
    next_id: u64,
    initial_messages: Vec<InboxEntry>,
}

#[derive(Debug, Clone)]
struct InboxEntry {
    created_at: Instant,
    message: StoredInitialMessageV2,
}

#[derive(Debug, Default)]
struct Inner {
    /// Post-quantum v2 capability manifests (with folded optional classical SPK signature).
    manifests: HashMap<PublicKey, PublishedManifest>,
    /// Per-identity strictly increasing refill watermark (blocks refill replays within ±5 min).
    last_refill_ts: HashMap<PublicKey, u64>,
    /// Classical X25519 one-time prekeys per identity.
    one_time_prekeys: HashMap<PublicKey, VecDeque<PublicKey>>,
    /// Last-resort PQSPKs per identity, keyed by suite ID.
    pq_last_resort: HashMap<PublicKey, HashMap<u8, StoredPqPrekey>>,
    /// One-time PQOPKs per identity, FIFO order.
    pq_one_time: HashMap<PublicKey, VecDeque<StoredPqPrekey>>,
    /// Per-identity inboxes holding v1 (classical X3DH) and v2 (PQXDH) initial messages.
    inboxes: HashMap<PublicKey, Inbox>,
    /// Unified per-recipient mailboxes and write-token grant state.
    mailboxes: HashMap<PublicKey, RecipientMailbox>,
    /// Tombstones in insertion order per `(recipient, token_hash)`, independent of message rows.
    mailbox_dedup: HashMap<(PublicKey, WriteTokenHash), DedupBucket>,
    dedup_keys: Vec<(PublicKey, WriteTokenHash)>,
    dedup_sweep_cursor: usize,
    /// Attachments and their uploaded chunks.
    attachments: HashMap<AttachmentId, (StoredAttachment, HashMap<u32, Bytes>)>,
}

fn check_safe_int(value: u64) -> Result<()> {
    if value > MAX_SAFE_INTEGER {
        return Err(ErrorKind::InvalidArgument.into());
    }
    Ok(())
}

fn check_positive_safe_int(value: u64) -> Result<()> {
    if value == 0 || value > MAX_SAFE_INTEGER {
        return Err(ErrorKind::InvalidArgument.into());
    }
    Ok(())
}

fn message_bytes(header: &Bytes, content: &Bytes, initial_message: Option<&Bytes>) -> u64 {
    (header.len() as u64)
        .saturating_add(content.len() as u64)
        .saturating_add(initial_message.map_or(0, |m| m.len() as u64))
}

fn same_initial_payload(a: &StoredInitialMessageV2, b: &StoredInitialMessageV2) -> bool {
    a.version == b.version
        && a.sender == b.sender
        && a.recipient == b.recipient
        && a.ephemeral_key == b.ephemeral_key
        && a.signed_prekey == b.signed_prekey
        && a.one_time_prekey == b.one_time_prekey
        && a.header == b.header
        && a.content == b.content
        && a.pq_suite == b.pq_suite
        && a.pq_last_resort == b.pq_last_resort
        && a.pq_prekey_id == b.pq_prekey_id
        && a.pq_ciphertext == b.pq_ciphertext
        && a.manifest_digest == b.manifest_digest
}

fn prune_expired_initials(inbox: &mut Inbox, now: Instant, ttl: Duration) {
    inbox
        .initial_messages
        .retain(|entry| now.duration_since(entry.created_at) < ttl);
}

fn prune_expired_peer_grants(mailbox: &mut RecipientMailbox, now: Instant, ttl: Duration) {
    mailbox.peer_grants.retain(|_, grant| {
        !(grant.live_tokens == 0
            && grant.message_count == 0
            && grant
                .revoked_at
                .is_some_and(|revoked_at| now.duration_since(revoked_at) > ttl))
    });
}

fn suite_counts(queue: &VecDeque<StoredPqPrekey>) -> Vec<(u8, usize)> {
    let mut counts: BTreeMap<u8, usize> = BTreeMap::new();
    for key in queue {
        *counts.entry(key.suite).or_default() += 1;
    }
    counts.into_iter().collect()
}

impl Inner {
    /// Remove a dedup bucket by key and update the swap-remove sweep index.
    fn remove_dedup_bucket(&mut self, key: &(PublicKey, WriteTokenHash)) {
        let Some(bucket) = self.mailbox_dedup.remove(key) else {
            return;
        };
        let index = bucket.sweep_index;
        self.dedup_keys.swap_remove(index);
        if let Some(moved) = self.dedup_keys.get(index) {
            self.mailbox_dedup.get_mut(moved).unwrap().sweep_index = index;
        }
    }

    /// Expire the oldest tombstones. Return true if this removed the bucket.
    fn prune_dedup(
        &mut self,
        key: &(PublicKey, WriteTokenHash),
        now: Instant,
        ttl: Duration,
    ) -> bool {
        let Some(bucket) = self.mailbox_dedup.get_mut(key) else {
            return false;
        };
        while bucket
            .entries
            .front()
            .is_some_and(|entry| now.duration_since(entry.inserted) >= ttl)
        {
            if let Some(expired) = bucket.entries.pop_front() {
                bucket.index.remove(&expired.id);
            }
        }
        if !bucket.entries.is_empty() {
            return false;
        }
        self.remove_dedup_bucket(key);
        true
    }

    fn sweep_dedup(&mut self, now: Instant, ttl: Duration) {
        for _ in 0..DEDUP_SWEEP_BUDGET.min(self.dedup_keys.len()) {
            if self.dedup_sweep_cursor >= self.dedup_keys.len() {
                self.dedup_sweep_cursor = 0;
            }
            let key = self.dedup_keys[self.dedup_sweep_cursor];
            // A swap removal leaves a different bucket at the cursor to visit next.
            if !self.prune_dedup(&key, now, ttl) {
                self.dedup_sweep_cursor += 1;
            }
        }
    }

    fn ack_messages_inner(&mut self, recipient: &PublicKey, up_to_sequence: u64) -> Result<u64> {
        check_positive_safe_int(up_to_sequence)?;
        let Some(mailbox) = self.mailboxes.get_mut(recipient) else {
            // Uninitialized recipient has high-water mark 0, so any up_to_sequence > 0 is invalid.
            return Err(ErrorKind::InvalidArgument.into());
        };
        if up_to_sequence > mailbox.last_sequence {
            return Err(ErrorKind::InvalidArgument.into());
        }
        let split = mailbox
            .messages
            .partition_point(|queued| queued.message.sequence <= up_to_sequence);
        if split == 0 {
            return Ok(0);
        }
        let mut deleted = 0u64;
        for removed in mailbox.messages.drain(..split) {
            deleted += 1;
            mailbox.message_count = mailbox.message_count.saturating_sub(1);
            mailbox.total_bytes = mailbox.total_bytes.saturating_sub(removed.bytes);
            if let Some(peer) = mailbox.peer_grants.get_mut(&removed.peer_slot_id) {
                peer.message_count = peer.message_count.saturating_sub(1);
                peer.total_bytes = peer.total_bytes.saturating_sub(removed.bytes);
            }
        }
        Ok(deleted)
    }
}

impl PqHandshakeStore for MemoryStore {
    async fn publish_v2(&self, record: PublishV2Record) -> Result<PublishV2Status> {
        check_safe_int(record.timestamp)?;
        check_safe_int(record.manifest.manifest_seq)?;
        check_safe_int(record.manifest.generation)?;
        check_safe_int(record.manifest.issued_at)?;
        check_safe_int(record.manifest.expires_at)?;

        // Reject duplicate classical OPKs within the publish request.
        let mut seen_opks = HashSet::with_capacity(record.one_time_prekeys.len());
        for opk in &record.one_time_prekeys {
            if !seen_opks.insert(*opk) {
                return Ok(PublishV2Status::DuplicatePrekey);
            }
        }
        // Reject duplicate PQ last-resort suites and duplicate PQ prekey IDs (last-resort and
        // one-time).
        let mut seen_lr_suites = HashSet::with_capacity(record.pq_last_resort.len());
        let mut seen_pq_ids =
            HashSet::with_capacity(record.pq_last_resort.len() + record.pq_one_time_prekeys.len());
        for lr in &record.pq_last_resort {
            if !seen_lr_suites.insert(lr.suite) || !seen_pq_ids.insert(lr.id) {
                return Ok(PublishV2Status::DuplicatePrekey);
            }
        }
        for pq_opk in &record.pq_one_time_prekeys {
            if !seen_pq_ids.insert(pq_opk.id) {
                return Ok(PublishV2Status::DuplicatePrekey);
            }
        }

        let mut inner = self.inner.lock();
        let id = record.manifest.identity_key;
        if let Some(existing) = inner.manifests.get(&id)
            && existing.manifest.manifest_seq >= record.manifest.manifest_seq
        {
            return Ok(PublishV2Status::StaleSequence);
        }

        let signed_prekey_signature = if record.manifest.strict_pq {
            None
        } else {
            record.signed_prekey_signature
        };

        inner
            .one_time_prekeys
            .insert(id, record.one_time_prekeys.into());

        if record.manifest.pq_enabled {
            let mut lr_map = HashMap::with_capacity(record.pq_last_resort.len());
            for lr in record.pq_last_resort {
                lr_map.insert(lr.suite, lr);
            }
            inner.pq_last_resort.insert(id, lr_map);
            inner
                .pq_one_time
                .insert(id, record.pq_one_time_prekeys.into());
        } else {
            // Affirmative OFF clears stored PQ prekeys while persisting the signed OFF manifest.
            inner.pq_last_resort.remove(&id);
            inner.pq_one_time.remove(&id);
        }

        inner.manifests.insert(
            id,
            PublishedManifest {
                manifest: record.manifest,
                signed_prekey_signature,
            },
        );
        Ok(PublishV2Status::Stored)
    }

    async fn refill_prekeys(&self, record: RefillPrekeysRecord) -> Result<RefillStatus> {
        check_safe_int(record.generation)?;
        check_safe_int(record.timestamp)?;
        let mut inner = self.inner.lock();
        let id = record.identity_key;
        let Some(manifest) = inner.manifests.get(&id).map(|m| m.manifest.clone()) else {
            return Ok(RefillStatus::NotFound);
        };
        if manifest.generation != record.generation {
            return Ok(RefillStatus::StaleGeneration);
        }
        if !record.pq_one_time_prekeys.is_empty() && !manifest.pq_enabled {
            return Ok(RefillStatus::StaleGeneration);
        }
        if inner
            .last_refill_ts
            .get(&id)
            .is_some_and(|&ts| ts >= record.timestamp)
        {
            return Ok(RefillStatus::StaleTimestamp);
        }

        // Check duplicate classical OPKs against existing pool and siblings.
        let existing_opks = inner.one_time_prekeys.get(&id);
        let existing_opk_count = existing_opks.map_or(0, VecDeque::len);
        if existing_opk_count.saturating_add(record.one_time_prekeys.len())
            > record.max_one_time_prekeys
        {
            return Ok(RefillStatus::LimitExceeded);
        }
        let mut seen_opks: HashSet<PublicKey> = existing_opks
            .into_iter()
            .flat_map(|q| q.iter().copied())
            .collect();
        for opk in &record.one_time_prekeys {
            if !seen_opks.insert(*opk) {
                return Ok(RefillStatus::DuplicatePrekey);
            }
        }

        // Check PQOPKs against offered suites, existing PQOPKs, last-resort PQSPKs, and cap.
        let existing_pq = inner.pq_one_time.get(&id);
        let existing_pq_count = existing_pq.map_or(0, VecDeque::len);
        if existing_pq_count.saturating_add(record.pq_one_time_prekeys.len())
            > record.max_pq_one_time_prekeys
        {
            return Ok(RefillStatus::LimitExceeded);
        }
        let mut seen_pq_ids: HashSet<PqPrekeyId> = existing_pq
            .into_iter()
            .flat_map(|q| q.iter().map(|k| k.id))
            .collect();
        if let Some(lr_map) = inner.pq_last_resort.get(&id) {
            for lr in lr_map.values() {
                seen_pq_ids.insert(lr.id);
            }
        }
        for pq_opk in &record.pq_one_time_prekeys {
            if !manifest.offered_suites.contains(&pq_opk.suite) {
                return Ok(RefillStatus::StaleGeneration);
            }
            if !seen_pq_ids.insert(pq_opk.id) {
                return Ok(RefillStatus::DuplicatePrekey);
            }
        }

        // Append atomically without rotating SPK or last-resort PQSPKs.
        inner.last_refill_ts.insert(id, record.timestamp);
        let opk_queue = inner.one_time_prekeys.entry(id).or_default();
        opk_queue.extend(record.one_time_prekeys);
        let classical_count = opk_queue.len();

        let pq_queue = inner.pq_one_time.entry(id).or_default();
        pq_queue.extend(record.pq_one_time_prekeys);
        let pq_counts = suite_counts(pq_queue);

        Ok(RefillStatus::Stored {
            classical_count,
            pq_counts,
        })
    }

    async fn get_manifest(
        &self,
        identity_key: &PublicKey,
    ) -> Result<Option<StoredCapabilityManifest>> {
        let inner = self.inner.lock();
        Ok(inner
            .manifests
            .get(identity_key)
            .map(|m| m.manifest.clone()))
    }

    async fn claim_bundle(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
    ) -> Result<Option<ClaimedPqBundle>> {
        match self
            .claim_bundle_checked(identity_key, preferred_suites, false)
            .await?
        {
            ClaimOutcome::Claimed(bundle) => Ok(Some(*bundle)),
            ClaimOutcome::NotFound | ClaimOutcome::PqDisabledForPqManifest => Ok(None),
        }
    }

    async fn claim_bundle_checked(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
        reject_pq_on_manifest: bool,
    ) -> Result<ClaimOutcome> {
        let mut inner = self.inner.lock();
        let Some(published) = inner.manifests.get(identity_key).cloned() else {
            return Ok(ClaimOutcome::NotFound);
        };
        let manifest = published.manifest;
        if reject_pq_on_manifest && manifest.pq_enabled {
            return Ok(ClaimOutcome::PqDisabledForPqManifest);
        }

        let signed_prekey_signature = if manifest.strict_pq {
            None
        } else {
            published.signed_prekey_signature
        };

        let chosen_suite = if manifest.pq_enabled && !preferred_suites.is_empty() {
            preferred_suites.iter().copied().find(|suite| {
                manifest.offered_suites.contains(suite)
                    && inner
                        .pq_last_resort
                        .get(identity_key)
                        .is_some_and(|m| m.contains_key(suite))
            })
        } else {
            None
        };

        // Determine whether this claim yields a usable handshake bundle BEFORE popping any
        // classical or PQ one-time prekey:
        // - strict_pq requires a mutually negotiated PQ suite.
        // - a PQ-ON peer with non-empty caller suites and no mutual suite must not burn OPKs.
        // - a classical claim (no mutual PQ suite) requires a matching raw SPK signature.
        let can_pop_opk =
            if manifest.strict_pq || (manifest.pq_enabled && !preferred_suites.is_empty()) {
                chosen_suite.is_some()
            } else {
                signed_prekey_signature.is_some()
            };

        if !can_pop_opk {
            return Ok(ClaimOutcome::Claimed(Box::new(ClaimedPqBundle {
                identity_key: *identity_key,
                signed_prekey: manifest.signed_prekey,
                manifest: Some(manifest),
                signed_prekey_signature,
                one_time_prekey: None,
                pq_last_resort: None,
                pq_one_time_prekey: None,
            })));
        }

        let (pq_last_resort, pq_one_time_prekey) = if let Some(suite) = chosen_suite {
            let lr = inner
                .pq_last_resort
                .get(identity_key)
                .and_then(|m| m.get(&suite))
                .cloned();
            let pq_opk = inner.pq_one_time.get_mut(identity_key).and_then(|q| {
                let idx = q.iter().position(|k| k.suite == suite)?;
                q.remove(idx)
            });
            (lr, pq_opk)
        } else {
            (None, None)
        };
        let one_time_prekey = inner
            .one_time_prekeys
            .get_mut(identity_key)
            .and_then(VecDeque::pop_front);

        Ok(ClaimOutcome::Claimed(Box::new(ClaimedPqBundle {
            identity_key: *identity_key,
            signed_prekey: manifest.signed_prekey,
            manifest: Some(manifest),
            signed_prekey_signature,
            one_time_prekey,
            pq_last_resort,
            pq_one_time_prekey,
        })))
    }

    async fn add_initial_message_v2(
        &self,
        mut initial_message: StoredInitialMessageV2,
        limit: usize,
    ) -> Result<Option<u64>> {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        if !inner.manifests.contains_key(&initial_message.recipient) {
            return Err(ErrorKind::NotFound.into());
        }
        let inbox = inner.inboxes.entry(initial_message.recipient).or_default();
        // Prune expired rows BEFORE (sender, ephemeral_key) lookup/insert so an expired entry
        // never collides with a new initial or blocks the cap.
        prune_expired_initials(inbox, now, self.initial_ttl);

        if let Some(existing) = inbox.initial_messages.iter().find(|entry| {
            entry.message.sender == initial_message.sender
                && entry.message.ephemeral_key == initial_message.ephemeral_key
        }) {
            if same_initial_payload(&existing.message, &initial_message) {
                return Ok(Some(existing.message.id));
            }
            return Err(ErrorKind::InvalidArgument.into());
        }

        if inbox.initial_messages.len() >= limit {
            return Ok(None);
        }
        let next_id = inbox
            .next_id
            .checked_add(1)
            .filter(|&id| id <= MAX_SAFE_INTEGER)
            .ok_or(ErrorKind::LimitExceeded)?;
        inbox.next_id = next_id;
        initial_message.id = next_id;
        inbox.initial_messages.push(InboxEntry {
            created_at: now,
            message: initial_message,
        });
        Ok(Some(next_id))
    }

    async fn list_initial_messages(
        &self,
        recipient: &PublicKey,
        after_id: u64,
        limit: usize,
    ) -> Result<Vec<StoredInitialMessageV2>> {
        check_safe_int(after_id)?;
        let now = Instant::now();
        let mut inner = self.inner.lock();
        let Some(inbox) = inner.inboxes.get_mut(recipient) else {
            return Ok(vec![]);
        };
        prune_expired_initials(inbox, now, self.initial_ttl);
        let start = inbox
            .initial_messages
            .partition_point(|entry| entry.message.id <= after_id);
        Ok(inbox.initial_messages[start..]
            .iter()
            .take(limit)
            .map(|entry| entry.message.clone())
            .collect())
    }

    async fn ack_initial_messages(&self, recipient: &PublicKey, ids: &[u64]) -> Result<usize> {
        for &id in ids {
            check_safe_int(id)?;
        }
        if ids.is_empty() {
            return Ok(0);
        }
        let mut inner = self.inner.lock();
        let Some(inbox) = inner.inboxes.get_mut(recipient) else {
            return Ok(0);
        };
        let before = inbox.initial_messages.len();
        let id_set: Option<HashSet<u64>> = (ids.len() > 4).then(|| ids.iter().copied().collect());
        inbox.initial_messages.retain(|entry| match &id_set {
            Some(set) => !set.contains(&entry.message.id),
            None => !ids.contains(&entry.message.id),
        });
        Ok(before - inbox.initial_messages.len())
    }

    async fn pq_snapshot(&self, identity_key: &PublicKey) -> Result<PqStorageSnapshot> {
        let now = Instant::now();
        let inner = self.inner.lock();
        let manifest = inner
            .manifests
            .get(identity_key)
            .map(|m| m.manifest.clone());
        let classical_one_time_count = inner
            .one_time_prekeys
            .get(identity_key)
            .map_or(0, VecDeque::len);
        let mut pq_last_resort_suites: Vec<u8> = inner
            .pq_last_resort
            .get(identity_key)
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default();
        pq_last_resort_suites.sort_unstable();
        let pq_one_time_counts = inner
            .pq_one_time
            .get(identity_key)
            .map(suite_counts)
            .unwrap_or_default();
        let pending_initial_messages = inner.inboxes.get(identity_key).map_or(0, |inbox| {
            inbox
                .initial_messages
                .iter()
                .filter(|entry| now.duration_since(entry.created_at) < self.initial_ttl)
                .count()
        });
        Ok(PqStorageSnapshot {
            manifest,
            classical_one_time_count,
            pq_last_resort_suites,
            pq_one_time_counts,
            pending_initial_messages,
        })
    }
}

impl IdempotentMailboxStore for MemoryStore {
    async fn append_idempotent(
        &self,
        recipient: &PublicKey,
        token_hash: &WriteTokenHash,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        client_message_id: Option<[u8; 16]>,
    ) -> Result<u64> {
        let mut inner = self.inner.lock();

        // 1. Auth-before-dedup: verify write_token hash in constant time without allocating state
        //    for unknown recipients or unauthorized/revoked tokens.
        let peer_slot_id = {
            let Some(mailbox) = inner.mailboxes.get(recipient) else {
                return Err(ErrorKind::WriteTokenRejected.into());
            };
            let Some(entry) = mailbox.write_tokens.get(token_hash) else {
                return Err(ErrorKind::WriteTokenRejected.into());
            };
            if !bool::from(entry.token_hash.ct_eq(token_hash)) {
                return Err(ErrorKind::WriteTokenRejected.into());
            }
            entry.peer_slot_id
        };

        // 2. Deduplication lookup (scoped to `(recipient, token_hash, client_message_id)`).
        let dedup_enabled =
            !self.dedup.ttl.is_zero() && self.dedup.max_per_token > 0 && self.dedup.max_buckets > 0;
        let dedup_key = (*recipient, *token_hash);
        let now = Instant::now();
        if dedup_enabled {
            inner.sweep_dedup(now, self.dedup.ttl);
            inner.prune_dedup(&dedup_key, now, self.dedup.ttl);
            if let Some(cid) = client_message_id
                && let Some(bucket) = inner.mailbox_dedup.get(&dedup_key)
                && let Some(&seq) = bucket.index.get(&cid)
            {
                return Ok(seq);
            }
        }

        // 3. Enforce per-peer and recipient-wide quotas in O(1), allocate sequence, and insert.
        let incoming_bytes = message_bytes(&header, &content, initial_message.as_ref());
        let seq = {
            let mailbox = inner
                .mailboxes
                .get_mut(recipient)
                .expect("verified above under mutex");
            let peer = mailbox
                .peer_grants
                .get(&peer_slot_id)
                .ok_or(ErrorKind::WriteTokenRejected)?;
            if peer.message_count >= MAX_QUEUE_MESSAGES
                || peer.total_bytes.saturating_add(incoming_bytes) > MAX_QUEUE_BYTES
                || mailbox.total_bytes.saturating_add(incoming_bytes) > MAX_RECIPIENT_BYTES
            {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let next = mailbox
                .last_sequence
                .checked_add(1)
                .filter(|&seq| seq <= MAX_SAFE_INTEGER)
                .ok_or(ErrorKind::LimitExceeded)?;
            mailbox.last_sequence = next;
            mailbox.message_count += 1;
            mailbox.total_bytes = mailbox.total_bytes.saturating_add(incoming_bytes);
            let peer_mut = mailbox
                .peer_grants
                .get_mut(&peer_slot_id)
                .expect("checked above");
            peer_mut.message_count += 1;
            peer_mut.total_bytes = peer_mut.total_bytes.saturating_add(incoming_bytes);
            mailbox.messages.push(QueuedMessage {
                peer_slot_id,
                bytes: incoming_bytes,
                message: StoredMessage {
                    sequence: next,
                    token_hash: *token_hash,
                    header,
                    content,
                    initial_message,
                },
            });
            next
        };

        // 4. Record dedup tombstone (if enabled and client_message_id supplied).
        if dedup_enabled && let Some(cid) = client_message_id {
            if !inner.mailbox_dedup.contains_key(&dedup_key)
                && inner.mailbox_dedup.len() >= self.dedup.max_buckets
                && !inner.dedup_keys.is_empty()
            {
                let cursor = inner.dedup_sweep_cursor % inner.dedup_keys.len();
                let victim = inner.dedup_keys[cursor];
                inner.remove_dedup_bucket(&victim);
            }
            let Inner {
                mailbox_dedup,
                dedup_keys,
                mailboxes,
                ..
            } = &mut *inner;
            let bucket = mailbox_dedup.entry(dedup_key).or_insert_with(|| {
                let sweep_index = dedup_keys.len();
                dedup_keys.push(dedup_key);
                DedupBucket {
                    entries: VecDeque::new(),
                    index: HashMap::new(),
                    sweep_index,
                }
            });
            if bucket.entries.len() == self.dedup.max_per_token {
                // Prefer evicting the oldest already-acknowledged message.
                let oldest_acked = mailboxes.get(recipient).map_or(Some(0), |mailbox| {
                    bucket.entries.iter().position(|entry| {
                        mailbox
                            .messages
                            .binary_search_by_key(&entry.sequence, |row| row.message.sequence)
                            .is_err()
                    })
                });
                if let Some(evicted) = bucket.entries.remove(oldest_acked.unwrap_or(0)) {
                    bucket.index.remove(&evicted.id);
                }
            }
            bucket.index.insert(cid, seq);
            bucket.entries.push_back(Tombstone {
                id: cid,
                sequence: seq,
                inserted: now,
            });
        }

        Ok(seq)
    }

    async fn read_mailbox(
        &self,
        recipient: &PublicKey,
        after_sequence: u64,
        limit: u32,
        max_size: usize,
        ack_up_to_sequence: u64,
    ) -> Result<MailboxPage> {
        check_safe_int(after_sequence)?;
        check_safe_int(ack_up_to_sequence)?;
        let mut inner = self.inner.lock();
        if ack_up_to_sequence > 0 {
            inner.ack_messages_inner(recipient, ack_up_to_sequence)?;
        }
        let Some(mailbox) = inner.mailboxes.get(recipient) else {
            return Ok(MailboxPage::default());
        };
        let start = mailbox
            .messages
            .partition_point(|queued| queued.message.sequence <= after_sequence);
        if limit == 0 {
            return Ok(MailboxPage {
                messages: vec![],
                has_more: start < mailbox.messages.len(),
            });
        }
        let max_bytes = max_size as u64;
        let mut messages = Vec::new();
        let mut bytes = 0u64;
        let mut has_more = false;
        for queued in &mailbox.messages[start..] {
            if messages.len() >= limit as usize {
                has_more = true;
                break;
            }
            let next_bytes = bytes.saturating_add(queued.bytes);
            if !messages.is_empty() && next_bytes > max_bytes {
                has_more = true;
                break;
            }
            bytes = next_bytes;
            messages.push(queued.message.clone());
        }
        Ok(MailboxPage { messages, has_more })
    }

    async fn ack_messages(&self, recipient: &PublicKey, up_to_sequence: u64) -> Result<u64> {
        self.inner
            .lock()
            .ack_messages_inner(recipient, up_to_sequence)
    }

    async fn register_write_token(&self, record: RegisterWriteTokenRecord) -> Result<()> {
        check_positive_safe_int(record.grant_version)?;
        let now = Instant::now();
        let mut inner = self.inner.lock();
        // Requires an existing published manifest (zero mailbox allocation for unknown identities).
        if !inner.manifests.contains_key(&record.recipient) {
            return Err(ErrorKind::NotFound.into());
        }

        // Prune expired empty revocation tombstones before enforcing version/peer invariants.
        if let Some(mailbox) = inner.mailboxes.get_mut(&record.recipient) {
            prune_expired_peer_grants(mailbox, now, self.revocation_tombstone_ttl);

            // Check cross-peer token_hash collision before any mutation.
            if let Some(existing) = mailbox.write_tokens.get(&record.token_hash)
                && existing.peer_slot_id != record.peer_slot_id
            {
                return Err(ErrorKind::InvalidArgument.into());
            }

            // Check revoked_below_version floor before any mutation.
            if let Some(peer) = mailbox.peer_grants.get(&record.peer_slot_id)
                && record.grant_version <= peer.revoked_below_version
            {
                return Err(ErrorKind::StaleVersion.into());
            }

            // Duplicate token_hash for the same peer_slot_id: NEVER overwrite stored grant_version
            // or created_at; only pin active_token_hash if pin_active && (grant_version > max_version
            // || active_token_hash.is_none()), and advance max_version on pin.
            if mailbox.write_tokens.contains_key(&record.token_hash) {
                let peer = mailbox
                    .peer_grants
                    .get_mut(&record.peer_slot_id)
                    .expect("peer grant exists for existing token");
                if record.pin_active
                    && (record.grant_version > peer.max_version || peer.active_token_hash.is_none())
                {
                    peer.active_token_hash = Some(record.token_hash);
                    peer.max_version = peer.max_version.max(record.grant_version);
                }
                return Ok(());
            }

            // New token_hash: enforce authorized peer cap on 0 -> 1 live token transition.
            let currently_has_tokens = mailbox
                .peer_grants
                .get(&record.peer_slot_id)
                .is_some_and(|p| p.live_tokens > 0);
            if !currently_has_tokens && mailbox.authorized_peer_count >= self.max_authorized_peers {
                return Err(ErrorKind::LimitExceeded.into());
            }
        }

        let mailbox = inner.mailboxes.entry(record.recipient).or_default();
        let insert_order = mailbox.next_insert_order;
        mailbox.next_insert_order = mailbox.next_insert_order.wrapping_add(1);

        let peer = mailbox.peer_grants.entry(record.peer_slot_id).or_default();
        if peer.live_tokens == 0 {
            mailbox.authorized_peer_count += 1;
        }
        peer.live_tokens += 1;
        if record.pin_active
            && (record.grant_version > peer.max_version || peer.active_token_hash.is_none())
        {
            peer.active_token_hash = Some(record.token_hash);
        }
        peer.max_version = peer.max_version.max(record.grant_version);
        let pinned_active = peer.active_token_hash;
        let peer_live_tokens = peer.live_tokens;

        mailbox.write_tokens.insert(
            record.token_hash,
            WriteTokenEntry {
                token_hash: record.token_hash,
                peer_slot_id: record.peer_slot_id,
                grant_version: record.grant_version,
                created_at: now,
                insert_order,
            },
        );

        // Enforce MAX_GRANTS_PER_PEER, evicting lowest (grant_version, insert_order) rows strictly
        // excluding the pinned active_token_hash.
        if peer_live_tokens > MAX_GRANTS_PER_PEER {
            let mut candidates: Vec<(u64, u64, WriteTokenHash)> = mailbox
                .write_tokens
                .values()
                .filter(|entry| {
                    entry.peer_slot_id == record.peer_slot_id
                        && Some(entry.token_hash) != pinned_active
                })
                .map(|entry| (entry.grant_version, entry.insert_order, entry.token_hash))
                .collect();
            candidates.sort_unstable();
            let to_evict = peer_live_tokens - MAX_GRANTS_PER_PEER;
            let mut evicted = 0usize;
            for (_, _, victim_hash) in candidates.into_iter().take(to_evict) {
                if mailbox.write_tokens.remove(&victim_hash).is_some() {
                    evicted += 1;
                }
            }
            if let Some(peer) = mailbox.peer_grants.get_mut(&record.peer_slot_id) {
                peer.live_tokens = peer.live_tokens.saturating_sub(evicted);
            }
        }

        Ok(())
    }

    async fn revoke_write_token(&self, record: RevokeWriteTokenRecord) -> Result<u32> {
        check_positive_safe_int(record.min_grant_version)?;
        let now = Instant::now();
        let mut inner = self.inner.lock();
        if !inner.manifests.contains_key(&record.recipient) {
            return Err(ErrorKind::NotFound.into());
        }

        let mailbox = inner.mailboxes.entry(record.recipient).or_default();
        prune_expired_peer_grants(mailbox, now, self.revocation_tombstone_ttl);

        let had_live_tokens = mailbox
            .peer_grants
            .get(&record.peer_slot_id)
            .is_some_and(|p| p.live_tokens > 0);

        let revoked: u32 = match record.token_hash {
            None => {
                let to_remove: Vec<WriteTokenHash> = mailbox
                    .write_tokens
                    .values()
                    .filter(|entry| entry.peer_slot_id == record.peer_slot_id)
                    .map(|entry| entry.token_hash)
                    .collect();
                for hash in &to_remove {
                    mailbox.write_tokens.remove(hash);
                }
                to_remove.len() as u32
            }
            Some(hash) => {
                if mailbox
                    .write_tokens
                    .get(&hash)
                    .is_some_and(|entry| entry.peer_slot_id == record.peer_slot_id)
                {
                    mailbox.write_tokens.remove(&hash);
                    1
                } else {
                    0
                }
            }
        };

        // Recompute remaining highest-version token for promotion if active_token_hash was deleted.
        let highest_remaining = mailbox
            .write_tokens
            .values()
            .filter(|entry| entry.peer_slot_id == record.peer_slot_id)
            .max_by_key(|entry| (entry.grant_version, entry.insert_order))
            .map(|entry| entry.token_hash);
        let remaining_count = mailbox
            .write_tokens
            .values()
            .filter(|entry| entry.peer_slot_id == record.peer_slot_id)
            .count();

        let peer = mailbox.peer_grants.entry(record.peer_slot_id).or_default();
        peer.revoked_below_version = peer.revoked_below_version.max(record.min_grant_version);
        peer.max_version = peer.max_version.max(record.min_grant_version);
        peer.revoked_at = Some(now);
        peer.live_tokens = remaining_count;
        if let Some(active) = peer.active_token_hash
            && !mailbox.write_tokens.contains_key(&active)
        {
            peer.active_token_hash = highest_remaining;
        }
        if had_live_tokens && remaining_count == 0 {
            mailbox.authorized_peer_count = mailbox.authorized_peer_count.saturating_sub(1);
        }

        Ok(revoked)
    }
}

impl AttachmentStore for MemoryStore {
    async fn add_attachment(&self, attachment: StoredAttachment) -> Result<bool> {
        let mut inner = self.inner.lock();
        if inner.attachments.contains_key(&attachment.id) {
            return Ok(false);
        }
        inner
            .attachments
            .insert(attachment.id, (attachment, HashMap::new()));
        Ok(true)
    }

    async fn attachment(&self, id: &AttachmentId) -> Result<Option<StoredAttachment>> {
        let inner = self.inner.lock();
        Ok(inner
            .attachments
            .get(id)
            .map(|(attachment, _)| attachment.clone()))
    }

    async fn put_chunk(&self, id: &AttachmentId, index: u32, data: Bytes) -> Result<()> {
        let mut inner = self.inner.lock();
        let (attachment, chunks) = inner.attachments.get_mut(id).ok_or(ErrorKind::NotFound)?;
        chunks.entry(index).or_insert(data);
        attachment.uploaded |= crate::uploaded_bit(index);
        Ok(())
    }

    async fn chunk(&self, id: &AttachmentId, index: u32) -> Result<Option<Bytes>> {
        let inner = self.inner.lock();
        Ok(inner
            .attachments
            .get(id)
            .and_then(|(_, chunks)| chunks.get(&index).cloned()))
    }

    async fn delete_attachment(&self, id: &AttachmentId) -> Result<()> {
        self.inner.lock().attachments.remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_manifest(identity_key: PublicKey, seq: u64) -> StoredCapabilityManifest {
        StoredCapabilityManifest {
            audience: "chat.example".to_string(),
            identity_key,
            manifest_seq: seq,
            generation: seq,
            issued_at: 1000 + seq,
            expires_at: 100_000 + seq,
            pq_enabled: true,
            strict_pq: false,
            pq_ratchet_supported: true,
            offered_suites: vec![1],
            signed_prekey: [0x20; 32],
            pq_last_resort: vec![crate::PqLastResortCommitment {
                suite: 1,
                prekey_id: [0xA1; 32],
            }],
            signature: [0x55; 64],
        }
    }

    async fn register_identity(store: &MemoryStore, id: PublicKey) {
        let pq_key = StoredPqPrekey {
            suite: 1,
            id: [0xA1; 32],
            encapsulation_key: Bytes::from(vec![0xA1; 1568]),
            signature: [0xA1; 64],
        };
        assert_eq!(
            store
                .publish_v2(PublishV2Record {
                    manifest: test_manifest(id, 1),
                    signed_prekey_signature: Some([0x44; 64]),
                    one_time_prekeys: vec![],
                    pq_last_resort: vec![pq_key],
                    pq_one_time_prekeys: vec![],
                    timestamp: 1001,
                })
                .await
                .unwrap(),
            PublishV2Status::Stored
        );
    }

    async fn register_grant(
        store: &MemoryStore,
        recipient: PublicKey,
        peer_slot_id: PeerSlotId,
        token_hash: WriteTokenHash,
        grant_version: u64,
        pin_active: bool,
    ) {
        store
            .register_write_token(RegisterWriteTokenRecord {
                recipient,
                peer_slot_id,
                token_hash,
                grant_version,
                pin_active,
            })
            .await
            .unwrap();
    }

    async fn append_id(
        store: &MemoryStore,
        recipient: &PublicKey,
        token_hash: &WriteTokenHash,
        id: Option<u8>,
    ) -> u64 {
        store
            .append_idempotent(
                recipient,
                token_hash,
                Bytes::new(),
                Bytes::new(),
                None,
                id.map(|n| [n; 16]),
            )
            .await
            .unwrap()
    }

    #[test]
    fn conformance() {
        futures::executor::block_on(async {
            crate::testing::attachment_store(&MemoryStore::default()).await;
            crate::testing::pq_handshake_store(&MemoryStore::default()).await;
            crate::testing::idempotent_mailbox_store(&MemoryStore::default()).await;
        });
    }

    #[test]
    fn unknown_identity_operations_do_not_allocate_state() {
        futures::executor::block_on(async {
            let store = MemoryStore::default();
            let ghost = [0x99; 32];
            assert!(
                store
                    .list_initial_messages(&ghost, 0, 10)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(store.ack_initial_messages(&ghost, &[1]).await.unwrap(), 0);
            assert_eq!(
                store.read_mailbox(&ghost, 0, 10, 1024, 0).await.unwrap(),
                MailboxPage::default()
            );
            assert_eq!(
                store.ack_messages(&ghost, 1).await.unwrap_err().kind(),
                ErrorKind::InvalidArgument
            );
            assert_eq!(
                store
                    .append_idempotent(&ghost, &[0x11; 32], Bytes::new(), Bytes::new(), None, None)
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::WriteTokenRejected
            );
            assert_eq!(
                store
                    .register_write_token(RegisterWriteTokenRecord {
                        recipient: ghost,
                        peer_slot_id: [0x01; 32],
                        token_hash: [0x02; 32],
                        grant_version: 1,
                        pin_active: true,
                    })
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::NotFound
            );
            assert_eq!(
                store
                    .revoke_write_token(RevokeWriteTokenRecord {
                        recipient: ghost,
                        peer_slot_id: [0x01; 32],
                        token_hash: None,
                        min_grant_version: 1,
                    })
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::NotFound
            );
            let inner = store.inner.lock();
            assert!(inner.inboxes.is_empty());
            assert!(inner.mailboxes.is_empty());
        });
    }

    #[test]
    fn disabled_dedup_keeps_no_tombstones() {
        futures::executor::block_on(async {
            let recipient = [2; 32];
            let token = [0x10; 32];
            for (ttl, cap) in [(Duration::ZERO, 4), (DEFAULT_DEDUP_TTL, 0)] {
                let store = MemoryStore::with_dedup_limits(ttl, cap);
                register_identity(&store, recipient).await;
                register_grant(&store, recipient, [1; 32], token, 1, true).await;
                assert_eq!(append_id(&store, &recipient, &token, Some(1)).await, 1);
                assert_eq!(append_id(&store, &recipient, &token, Some(1)).await, 2);
                let inner = store.inner.lock();
                assert!(inner.mailbox_dedup.is_empty());
                assert!(inner.dedup_keys.is_empty());
            }
        });
    }

    #[test]
    fn idle_dedup_buckets_expire_with_bounded_sweeps() {
        futures::executor::block_on(async {
            let ttl = Duration::from_secs(60);
            let store = MemoryStore::with_dedup_limits(ttl, 4);
            let recipient = [2; 32];
            register_identity(&store, recipient).await;

            let active_token = [255u8; 32];
            register_grant(&store, recipient, [255u8; 32], active_token, 1, true).await;
            let active_key = (recipient, active_token);

            let idle_keys: Vec<_> = (0..2 * DEDUP_SWEEP_BUDGET + 1)
                .map(|i| (recipient, [i as u8; 32]))
                .collect();
            for &(_, tok) in &idle_keys {
                register_grant(&store, recipient, tok, tok, 1, true).await;
                append_id(&store, &recipient, &tok, Some(1)).await;
                append_id(&store, &recipient, &tok, Some(2)).await;
            }
            let active_seq = append_id(&store, &recipient, &active_token, Some(3)).await;
            {
                let mut inner = store.inner.lock();
                for key in &idle_keys {
                    for entry in &mut inner.mailbox_dedup.get_mut(key).unwrap().entries {
                        entry.inserted -= ttl;
                    }
                }
            }
            for pass in 0..4 {
                assert_eq!(
                    append_id(&store, &recipient, &active_token, Some(3)).await,
                    active_seq
                );
                let inner = store.inner.lock();
                assert_eq!(inner.dedup_keys.len(), inner.mailbox_dedup.len());
                for (i, key) in inner.dedup_keys.iter().enumerate() {
                    assert_eq!(inner.mailbox_dedup[key].sweep_index, i);
                }
                if pass == 0 {
                    assert!(inner.dedup_keys.len() >= idle_keys.len() + 1 - DEDUP_SWEEP_BUDGET);
                }
            }
            let inner = store.inner.lock();
            assert_eq!(inner.dedup_keys, [active_key]);
            assert!(
                idle_keys
                    .iter()
                    .all(|key| !inner.mailbox_dedup.contains_key(key))
            );
        });
    }

    #[test]
    fn append_without_an_id_removes_an_expired_active_bucket_outside_the_sweep() {
        futures::executor::block_on(async {
            let ttl = Duration::from_secs(60);
            let store = MemoryStore::with_dedup_limits(ttl, 4);
            let recipient = [2; 32];
            register_identity(&store, recipient).await;
            for i in 0..=DEDUP_SWEEP_BUDGET {
                let tok = [i as u8; 32];
                register_grant(&store, recipient, tok, tok, 1, true).await;
                append_id(&store, &recipient, &tok, Some(1)).await;
            }
            let key = {
                let mut inner = store.inner.lock();
                let key = inner.dedup_keys
                    [(inner.dedup_sweep_cursor + DEDUP_SWEEP_BUDGET) % inner.dedup_keys.len()];
                inner.mailbox_dedup.get_mut(&key).unwrap().entries[0].inserted -= ttl;
                key
            };
            let seq = append_id(&store, &key.0, &key.1, None).await;
            assert!(seq > 1);
            let inner = store.inner.lock();
            assert!(!inner.mailbox_dedup.contains_key(&key));
            assert_eq!(inner.dedup_keys.len(), inner.mailbox_dedup.len());
        });
    }

    #[test]
    fn tombstones_expire_at_the_configured_age_and_evict_acked_first() {
        futures::executor::block_on(async {
            let ttl = Duration::from_secs(60);
            let store = MemoryStore::with_dedup_limits(ttl, 2);
            let bob = [2; 32];
            let token_a = [0xAA; 32];
            let token_b = [0xBB; 32];
            register_identity(&store, bob).await;
            register_grant(&store, bob, [1; 32], token_a, 1, true).await;
            register_grant(&store, bob, [2; 32], token_b, 1, true).await;

            // Append seq 1 (token_a, cid 1), seq 2 (token_a, cid 2), seq 3 (token_b, cid 1).
            assert_eq!(append_id(&store, &bob, &token_a, Some(1)).await, 1);
            assert_eq!(append_id(&store, &bob, &token_a, Some(2)).await, 2);
            assert_eq!(append_id(&store, &bob, &token_b, Some(1)).await, 3);

            // ACK seq 1 (so seq 1 is acked while seq 2 is still queued).
            assert_eq!(store.ack_messages(&bob, 1).await.unwrap(), 1);
            // Tombstone for seq 1 survives ACK until TTL/eviction.
            assert_eq!(append_id(&store, &bob, &token_a, Some(1)).await, 1);

            // Appending cid 3 under token_a evicts the already-acked seq 1 tombstone BEFORE queued seq 2!
            assert_eq!(append_id(&store, &bob, &token_a, Some(3)).await, 4);
            assert_eq!(append_id(&store, &bob, &token_a, Some(2)).await, 2);
            assert_eq!(append_id(&store, &bob, &token_b, Some(1)).await, 3);
            // cid 1 was evicted, so retrying cid 1 allocates a fresh sequence.
            assert_eq!(append_id(&store, &bob, &token_a, Some(1)).await, 5);

            // Age out token_a's tombstones and verify expiry allows fresh allocation.
            {
                let mut inner = store.inner.lock();
                for entry in &mut inner
                    .mailbox_dedup
                    .get_mut(&(bob, token_a))
                    .unwrap()
                    .entries
                {
                    entry.inserted -= ttl;
                }
            }
            assert_eq!(append_id(&store, &bob, &token_a, Some(3)).await, 6);
            assert_eq!(
                store.inner.lock().mailbox_dedup[&(bob, token_a)]
                    .entries
                    .len(),
                1
            );
        });
    }

    #[test]
    fn claim_bundle_preserves_opks_on_strict_pq_and_suite_mismatch() {
        futures::executor::block_on(async {
            let store = MemoryStore::default();
            let bob = [0x22; 32];
            let pq_key = |suite: u8, tag: u8| StoredPqPrekey {
                suite,
                id: [tag; 32],
                encapsulation_key: Bytes::from(vec![tag; if suite == 1 { 1568 } else { 1184 }]),
                signature: [tag; 64],
            };
            let manifest = StoredCapabilityManifest {
                audience: "chat.example".to_string(),
                identity_key: bob,
                manifest_seq: 1,
                generation: 1,
                issued_at: 1000,
                expires_at: 100_000,
                pq_enabled: true,
                strict_pq: true,
                pq_ratchet_supported: true,
                offered_suites: vec![1],
                signed_prekey: [0x23; 32],
                pq_last_resort: vec![crate::PqLastResortCommitment {
                    suite: 1,
                    prekey_id: [0xA1; 32],
                }],
                signature: [0x55; 64],
            };
            assert_eq!(
                store
                    .publish_v2(PublishV2Record {
                        manifest,
                        signed_prekey_signature: None,
                        one_time_prekeys: vec![[0x40; 32], [0x41; 32]],
                        pq_last_resort: vec![pq_key(1, 0xA1)],
                        pq_one_time_prekeys: vec![pq_key(1, 0xB1)],
                        timestamp: 1001,
                    })
                    .await
                    .unwrap(),
                PublishV2Status::Stored
            );

            // Empty preferred_suites on strict_pq MUST NOT burn classical OPKs or PQOPKs.
            let empty_claim = store.claim_bundle(&bob, &[]).await.unwrap().unwrap();
            assert_eq!(empty_claim.one_time_prekey, None);
            assert_eq!(empty_claim.pq_last_resort, None);
            assert_eq!(empty_claim.pq_one_time_prekey, None);
            assert_eq!(
                store
                    .pq_snapshot(&bob)
                    .await
                    .unwrap()
                    .classical_one_time_count,
                2
            );

            // Disjoint suite [2] on strict_pq MUST NOT burn classical OPKs or PQOPKs.
            let disjoint_claim = store.claim_bundle(&bob, &[2]).await.unwrap().unwrap();
            assert_eq!(disjoint_claim.one_time_prekey, None);
            assert_eq!(disjoint_claim.pq_last_resort, None);
            assert_eq!(disjoint_claim.pq_one_time_prekey, None);
            assert_eq!(
                store
                    .pq_snapshot(&bob)
                    .await
                    .unwrap()
                    .classical_one_time_count,
                2
            );

            // Atomic pq_enabled=false rejection MUST NOT burn any OPKs.
            assert_eq!(
                store.claim_bundle_checked(&bob, &[1], true).await.unwrap(),
                ClaimOutcome::PqDisabledForPqManifest
            );
            assert_eq!(
                store
                    .pq_snapshot(&bob)
                    .await
                    .unwrap()
                    .classical_one_time_count,
                2
            );

            // Matching suite [1] pops both classical OPK and PQOPK atomically.
            let matched = store.claim_bundle(&bob, &[1]).await.unwrap().unwrap();
            assert_eq!(matched.one_time_prekey, Some([0x40; 32]));
            assert_eq!(matched.pq_one_time_prekey, Some(pq_key(1, 0xB1)));
            assert_eq!(
                store
                    .pq_snapshot(&bob)
                    .await
                    .unwrap()
                    .classical_one_time_count,
                1
            );
        });
    }

    #[test]
    fn authorized_peer_cap_revocation_tombstone_pruning_and_initial_expiry() {
        futures::executor::block_on(async {
            let store = MemoryStore {
                max_authorized_peers: 2,
                revocation_tombstone_ttl: Duration::from_secs(60),
                initial_ttl: Duration::from_secs(60),
                ..MemoryStore::default()
            };

            let bob = [0x02; 32];
            let alice = [0x01; 32];
            register_identity(&store, bob).await;

            // Fill authorized_peer_count to cap (2 peers).
            register_grant(&store, bob, [1; 32], [11; 32], 1, true).await;
            register_grant(&store, bob, [2; 32], [22; 32], 1, true).await;

            // Adding a second token to an existing peer succeeds even at peer cap.
            register_grant(&store, bob, [1; 32], [12; 32], 2, false).await;

            // Adding a 3rd peer fails with LimitExceeded without mutating peer_grants.
            assert_eq!(
                store
                    .register_write_token(RegisterWriteTokenRecord {
                        recipient: bob,
                        peer_slot_id: [3; 32],
                        token_hash: [33; 32],
                        grant_version: 1,
                        pin_active: true,
                    })
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::LimitExceeded
            );

            // Revoking peer 2 frees an authorized peer slot so peer 3 can register.
            assert_eq!(
                store
                    .revoke_write_token(RevokeWriteTokenRecord {
                        recipient: bob,
                        peer_slot_id: [2; 32],
                        token_hash: None,
                        min_grant_version: 5,
                    })
                    .await
                    .unwrap(),
                1
            );
            register_grant(&store, bob, [3; 32], [33; 32], 1, true).await;

            // Peer 2's tombstone blocks grant_version <= 5 while unexpired.
            assert_eq!(
                store
                    .register_write_token(RegisterWriteTokenRecord {
                        recipient: bob,
                        peer_slot_id: [2; 32],
                        token_hash: [23; 32],
                        grant_version: 5,
                        pin_active: true,
                    })
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::StaleVersion
            );

            // Once peer 2's empty tombstone expires (> revocation_tombstone_ttl), it is pruned.
            {
                let mut inner = store.inner.lock();
                let peer2 = inner
                    .mailboxes
                    .get_mut(&bob)
                    .unwrap()
                    .peer_grants
                    .get_mut(&[2; 32])
                    .unwrap();
                peer2.revoked_at = Some(Instant::now() - Duration::from_secs(61));
            }
            // Trigger pruning via another grant op; peer 2 tombstone is removed.
            assert_eq!(
                store
                    .revoke_write_token(RevokeWriteTokenRecord {
                        recipient: bob,
                        peer_slot_id: [3; 32],
                        token_hash: None,
                        min_grant_version: 1,
                    })
                    .await
                    .unwrap(),
                1
            );
            assert!(
                !store.inner.lock().mailboxes[&bob]
                    .peer_grants
                    .contains_key(&[2; 32])
            );

            // Expired initial message is pruned before (sender, ephemeral_key) uniqueness check!
            let init = StoredInitialMessageV2 {
                id: 0,
                version: 1,
                sender: alice,
                recipient: bob,
                ephemeral_key: [0xEE; 32],
                signed_prekey: [0x20; 32],
                one_time_prekey: None,
                header: Bytes::from_static(b"h1"),
                content: Bytes::from_static(b"c1"),
                pq_suite: None,
                pq_last_resort: false,
                pq_prekey_id: None,
                pq_ciphertext: None,
                manifest_digest: None,
            };
            let id1 = store
                .add_initial_message_v2(init.clone(), 1)
                .await
                .unwrap()
                .unwrap();
            // Age out the initial message.
            store
                .inner
                .lock()
                .inboxes
                .get_mut(&bob)
                .unwrap()
                .initial_messages[0]
                .created_at -= Duration::from_secs(61);
            // Re-inserting with the same (sender, ephemeral_key) and DIFFERENT payload succeeds
            // because the expired row was pruned first, AND does not hit the limit=1 cap.
            let mut init2 = init;
            init2.content = Bytes::from_static(b"c2-after-expiry");
            let id2 = store
                .add_initial_message_v2(init2, 1)
                .await
                .unwrap()
                .unwrap();
            assert!(id2 > id1);

            // Bounded global dedup buckets cap.
            let bounded = MemoryStore::with_dedup_limits_and_buckets(DEFAULT_DEDUP_TTL, 4, 2);
            register_identity(&bounded, bob).await;
            for i in 0u8..5 {
                let tok = [i; 32];
                register_grant(&bounded, bob, tok, tok, 1, true).await;
                append_id(&bounded, &bob, &tok, Some(1)).await;
            }
            assert!(bounded.inner.lock().mailbox_dedup.len() <= 2);
        });
    }
}
