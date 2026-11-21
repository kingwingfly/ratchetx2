//! In-memory backend.

use std::collections::{HashMap, VecDeque};
#[cfg(feature = "pq")]
use std::{collections::HashSet, time::Duration};

use bytes::Bytes;
use parking_lot::Mutex;
// The memory feature enables the clock dependency in both builds. Only PQ keeps tombstones.
#[cfg(not(feature = "pq"))]
use web_time as _;
#[cfg(feature = "pq")]
use web_time::Instant;

use crate::{
    AttachmentId, AttachmentStore, Bundle, ErrorKind, MAX_QUEUE_BYTES, MAX_QUEUE_MESSAGES,
    MAX_SAFE_INTEGER, PublicKey, Result, StoredAttachment, StoredInitialMessage, StoredMessage,
};
#[cfg(feature = "pq")]
use crate::{
    ClaimedPqBundle, IdempotentMailboxStore, PqHandshakeStore, PqPrekeyId, PqStorageSnapshot,
    PublishV2Record, PublishV2Status, RefillPrekeysRecord, RefillStatus, StoredCapabilityManifest,
    StoredInitialMessageV2, StoredPqPrekey,
};
#[allow(deprecated)]
use crate::{HandshakeStore, MailboxStore};

/// How long a mailbox retry can recover the original sequence after insertion.
#[cfg(feature = "pq")]
pub const DEFAULT_DEDUP_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Maximum retained client-message IDs per sender and recipient.
#[cfg(feature = "pq")]
pub const DEFAULT_MAX_DEDUP_TOMBSTONES: usize = 4096;

#[cfg(feature = "pq")]
const DEDUP_SWEEP_BUDGET: usize = 8;

#[cfg(feature = "pq")]
#[derive(Debug)]
struct DedupLimits {
    ttl: Duration,
    max_per_queue: usize,
}

#[cfg(feature = "pq")]
impl Default for DedupLimits {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_DEDUP_TTL,
            max_per_queue: DEFAULT_MAX_DEDUP_TOMBSTONES,
        }
    }
}

#[cfg(feature = "pq")]
#[derive(Debug)]
struct Tombstone {
    id: [u8; 16],
    sequence: u64,
    inserted: Instant,
}

#[cfg(feature = "pq")]
#[derive(Debug)]
struct DedupBucket {
    entries: VecDeque<Tombstone>,
    sweep_index: usize,
}

/// Keeps everything in memory until dropped. Implements [`HandshakeStore`], [`MailboxStore`],
/// [`AttachmentStore`], and the PQ handshake and idempotent mailbox traits with the `pq` feature.
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
    #[cfg(feature = "pq")]
    dedup: DedupLimits,
}

#[cfg(feature = "pq")]
impl MemoryStore {
    /// Create a store with a fixed retry window and tombstone cap for each mailbox queue.
    /// A zero TTL or cap disables deduplication.
    pub fn with_dedup_limits(ttl: Duration, max_per_queue: usize) -> Self {
        Self {
            dedup: DedupLimits { ttl, max_per_queue },
            ..Self::default()
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    /// Legacy classical v1 bundles (cleared when v2 `strict_pq` is enabled).
    bundles: HashMap<PublicKey, Bundle>,
    /// Persistent v1 publish replay watermark per identity (survives v1 bundle removal).
    last_v1_publish_ts: HashMap<PublicKey, u64>,
    /// Classical X25519 one-time prekeys per identity (shared between v1 and v2).
    one_time_prekeys: HashMap<PublicKey, VecDeque<PublicKey>>,
    /// Per-identity inboxes holding both classical v1 and (when `pq`) v2 initial messages.
    inboxes: HashMap<PublicKey, Inbox>,
    /// Mailbox queues per `(sender, recipient)`.
    queues: HashMap<(PublicKey, PublicKey), Vec<Queued>>,
    /// The last sequence number of each queue, which goes on once its messages are deleted.
    last_sequences: HashMap<(PublicKey, PublicKey), u64>,
    /// Attachments and their uploaded chunks.
    attachments: HashMap<AttachmentId, (StoredAttachment, HashMap<u32, Bytes>)>,
    /// Post-quantum v2 capability manifests.
    #[cfg(feature = "pq")]
    manifests: HashMap<PublicKey, StoredCapabilityManifest>,
    /// Per-identity strictly increasing refill watermark (blocks refill replays within ±5 min).
    #[cfg(feature = "pq")]
    last_refill_ts: HashMap<PublicKey, u64>,
    /// Last-resort PQSPKs per identity, keyed by suite ID.
    #[cfg(feature = "pq")]
    pq_last_resort: HashMap<PublicKey, HashMap<u8, StoredPqPrekey>>,
    /// One-time PQOPKs per identity, FIFO order.
    #[cfg(feature = "pq")]
    pq_one_time: HashMap<PublicKey, VecDeque<StoredPqPrekey>>,
    /// Tombstones in insertion order for each queue, independent of queued message rows.
    #[cfg(feature = "pq")]
    mailbox_dedup: HashMap<(PublicKey, PublicKey), DedupBucket>,
    #[cfg(feature = "pq")]
    dedup_keys: Vec<(PublicKey, PublicKey)>,
    #[cfg(feature = "pq")]
    dedup_sweep_cursor: usize,
}

/// A message of a queue, with SHA-256 of its delivery token, if any.
#[derive(Debug)]
struct Queued {
    message: StoredMessage,
    delivery_hash: Option<[u8; 32]>,
    bytes: u64,
}

#[derive(Debug, Default)]
struct Inbox {
    last_take: Option<u64>,
    next_id: u64,
    initial_messages: Vec<InboxEntry>,
}

#[derive(Debug, Clone)]
struct InboxEntry {
    #[cfg_attr(not(feature = "pq"), allow(dead_code))]
    id: u64,
    #[cfg_attr(not(feature = "pq"), allow(dead_code))]
    version: u32,
    classical: StoredInitialMessage,
    #[cfg(feature = "pq")]
    pq_suite: Option<u8>,
    #[cfg(feature = "pq")]
    pq_last_resort: bool,
    #[cfg(feature = "pq")]
    pq_prekey_id: Option<PqPrekeyId>,
    #[cfg(feature = "pq")]
    pq_ciphertext: Option<Bytes>,
    #[cfg(feature = "pq")]
    manifest_digest: Option<[u8; 32]>,
}

fn check_safe_int(value: u64) -> Result<()> {
    if value > MAX_SAFE_INTEGER {
        return Err(ErrorKind::InvalidArgument.into());
    }
    Ok(())
}

fn message_bytes(header: &Bytes, content: &Bytes, initial_message: Option<&Bytes>) -> u64 {
    (header.len() as u64)
        .saturating_add(content.len() as u64)
        .saturating_add(initial_message.map_or(0, |m| m.len() as u64))
}

impl Inner {
    fn has_identity(&self, identity_key: &PublicKey) -> bool {
        let classical =
            self.bundles.contains_key(identity_key) || self.inboxes.contains_key(identity_key);
        #[cfg(feature = "pq")]
        {
            classical || self.manifests.contains_key(identity_key)
        }
        #[cfg(not(feature = "pq"))]
        {
            classical
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn append_inner(
        &mut self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        delivery_hash: Option<[u8; 32]>,
    ) -> Result<u64> {
        let incoming_bytes = message_bytes(&header, &content, initial_message.as_ref());
        let key = (*sender, *recipient);
        if let Some(queue) = self.queues.get(&key) {
            if queue.len() >= MAX_QUEUE_MESSAGES {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let current_bytes: u64 = queue
                .iter()
                .fold(0u64, |acc, q| acc.saturating_add(q.bytes));
            if current_bytes.saturating_add(incoming_bytes) > MAX_QUEUE_BYTES {
                return Err(ErrorKind::LimitExceeded.into());
            }
        } else if incoming_bytes > MAX_QUEUE_BYTES {
            return Err(ErrorKind::LimitExceeded.into());
        }

        let last = self.last_sequences.entry(key).or_default();
        let next = last
            .checked_add(1)
            .filter(|&seq| seq <= MAX_SAFE_INTEGER)
            .ok_or(ErrorKind::LimitExceeded)?;
        *last = next;
        let message = StoredMessage {
            sender: *sender,
            recipient: *recipient,
            sequence: next,
            header,
            content: Some(content),
            initial_message,
        };
        self.queues.entry(key).or_default().push(Queued {
            message,
            delivery_hash,
            bytes: incoming_bytes,
        });
        Ok(next)
    }

    fn delete_delivered_inner(
        &mut self,
        sender: &PublicKey,
        recipient: &PublicKey,
        hashes: &[[u8; 32]],
    ) {
        if let Some(queue) = self.queues.get_mut(&(*sender, *recipient)) {
            queue.retain(|queued| {
                !queued
                    .delivery_hash
                    .is_some_and(|hash| hashes.contains(&hash))
            });
        }
    }

    fn read_inner(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
    ) -> Vec<StoredMessage> {
        let Some(queue) = self.queues.get(&(*sender, *recipient)) else {
            return vec![];
        };
        // In order, with gaps where messages were delivered or expired.
        let start = queue.partition_point(|queued| queued.message.sequence <= after);
        queue[start..]
            .iter()
            .take(limit as usize)
            .map(|queued| queued.message.clone())
            .collect()
    }
}

#[allow(deprecated)]
impl HandshakeStore for MemoryStore {
    async fn publish(&self, bundle: Bundle, one_time_prekeys: Vec<PublicKey>) -> Result<bool> {
        check_safe_int(bundle.timestamp)?;
        let mut inner = self.inner.lock();
        let id = bundle.identity_key;
        // Once an identity has upgraded to a v2 CapabilityManifest, legacy v1 Publish is refused
        // so old or cross-generation v1 publishes can neither restore a strict-PQ v1 bundle nor
        // overwrite the shared classical OPK pool.
        #[cfg(feature = "pq")]
        if inner.manifests.contains_key(&id) {
            return Ok(false);
        }
        if inner
            .last_v1_publish_ts
            .get(&id)
            .is_some_and(|&ts| ts >= bundle.timestamp)
        {
            return Ok(false);
        }
        if let Some(stored) = inner.bundles.get(&id)
            && stored.timestamp >= bundle.timestamp
        {
            return Ok(false);
        }
        inner.last_v1_publish_ts.insert(id, bundle.timestamp);
        inner.bundles.insert(id, bundle);
        inner.one_time_prekeys.insert(id, one_time_prekeys.into());
        Ok(true)
    }

    async fn take_bundle(
        &self,
        identity_key: &PublicKey,
    ) -> Result<Option<(Bundle, Option<PublicKey>)>> {
        let mut inner = self.inner.lock();
        let Some(bundle) = inner.bundles.get(identity_key).cloned() else {
            return Ok(None);
        };
        // Legacy v1 FetchBundle pops only a classical OPK and NEVER consumes PQOPKs.
        let opk = inner
            .one_time_prekeys
            .get_mut(identity_key)
            .and_then(VecDeque::pop_front);
        Ok(Some((bundle, opk)))
    }

    async fn add_initial_message(
        &self,
        initial_message: StoredInitialMessage,
        limit: usize,
    ) -> Result<bool> {
        let mut inner = self.inner.lock();
        let inbox = inner.inboxes.entry(initial_message.recipient).or_default();
        if inbox.initial_messages.len() >= limit {
            return Ok(false);
        }
        inbox.next_id += 1;
        let id = inbox.next_id;
        inbox.initial_messages.push(InboxEntry {
            id,
            version: 1,
            classical: initial_message,
            #[cfg(feature = "pq")]
            pq_suite: None,
            #[cfg(feature = "pq")]
            pq_last_resort: false,
            #[cfg(feature = "pq")]
            pq_prekey_id: None,
            #[cfg(feature = "pq")]
            pq_ciphertext: None,
            #[cfg(feature = "pq")]
            manifest_digest: None,
        });
        Ok(true)
    }

    async fn take_initial_messages(
        &self,
        recipient: &PublicKey,
        timestamp: u64,
    ) -> Result<Option<Vec<StoredInitialMessage>>> {
        check_safe_int(timestamp)?;
        let mut inner = self.inner.lock();
        // Do not allocate persistent inbox state for unknown identities.
        if !inner.has_identity(recipient) {
            return Ok(Some(vec![]));
        }
        let inbox = inner.inboxes.entry(*recipient).or_default();
        if inbox.last_take.is_some_and(|last| last >= timestamp) {
            return Ok(None);
        }
        inbox.last_take = Some(timestamp);
        // Legacy v1 take ONLY drains classical v1 initial messages and NEVER drains v2 PQ initials.
        let mut taken = Vec::new();
        let mut retained = Vec::new();
        for entry in std::mem::take(&mut inbox.initial_messages) {
            if entry.version == 1 {
                taken.push(entry.classical);
            } else {
                retained.push(entry);
            }
        }
        inbox.initial_messages = retained;
        Ok(Some(taken))
    }
}

#[cfg(feature = "pq")]
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
            && existing.manifest_seq >= record.manifest.manifest_seq
        {
            return Ok(PublishV2Status::StaleSequence);
        }

        // Advance persistent v1 publish replay watermark so old captured v1 publishes cannot replay
        // even if `bundles` is cleared under `strict_pq`.
        inner
            .last_v1_publish_ts
            .entry(id)
            .and_modify(|ts| *ts = (*ts).max(record.timestamp))
            .or_insert(record.timestamp);

        // Classical v1 bundle handling: strict_pq or missing raw signature clears v1 bundle so
        // Bob unilaterally blocks legacy v1 FetchBundle.
        if record.manifest.strict_pq {
            inner.bundles.remove(&id);
        } else if let Some(sig) = record.signed_prekey_signature {
            let next_ts = inner
                .bundles
                .get(&id)
                .map_or(record.timestamp, |old| old.timestamp.max(record.timestamp));
            inner.bundles.insert(
                id,
                Bundle {
                    identity_key: id,
                    signed_prekey: record.manifest.signed_prekey,
                    signed_prekey_signature: sig,
                    timestamp: next_ts,
                },
            );
        } else {
            inner.bundles.remove(&id);
        }

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

        inner.manifests.insert(id, record.manifest);
        Ok(PublishV2Status::Stored)
    }

    async fn refill_prekeys(&self, record: RefillPrekeysRecord) -> Result<RefillStatus> {
        check_safe_int(record.generation)?;
        check_safe_int(record.timestamp)?;
        let mut inner = self.inner.lock();
        let id = record.identity_key;
        let Some(manifest) = inner.manifests.get(&id).cloned() else {
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
        Ok(inner.manifests.get(identity_key).cloned())
    }

    async fn claim_bundle(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
    ) -> Result<Option<ClaimedPqBundle>> {
        let mut inner = self.inner.lock();
        if let Some(manifest) = inner.manifests.get(identity_key).cloned() {
            let signed_prekey_signature = if manifest.strict_pq {
                None
            } else {
                inner
                    .bundles
                    .get(identity_key)
                    .filter(|b| b.signed_prekey == manifest.signed_prekey)
                    .map(|b| b.signed_prekey_signature)
            };
            let one_time_prekey = inner
                .one_time_prekeys
                .get_mut(identity_key)
                .and_then(VecDeque::pop_front);

            let (pq_last_resort, pq_one_time_prekey) =
                if manifest.pq_enabled && !preferred_suites.is_empty() {
                    let chosen_suite = preferred_suites.iter().copied().find(|suite| {
                        manifest.offered_suites.contains(suite)
                            && inner
                                .pq_last_resort
                                .get(identity_key)
                                .is_some_and(|m| m.contains_key(suite))
                    });
                    if let Some(suite) = chosen_suite {
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
                    }
                } else {
                    (None, None)
                };

            return Ok(Some(ClaimedPqBundle {
                identity_key: *identity_key,
                signed_prekey: manifest.signed_prekey,
                manifest: Some(manifest),
                signed_prekey_signature,
                one_time_prekey,
                pq_last_resort,
                pq_one_time_prekey,
            }));
        }

        // Graceful fallback for classical-only v1 users.
        let Some(bundle) = inner.bundles.get(identity_key).cloned() else {
            return Ok(None);
        };
        let one_time_prekey = inner
            .one_time_prekeys
            .get_mut(identity_key)
            .and_then(VecDeque::pop_front);
        Ok(Some(ClaimedPqBundle {
            identity_key: *identity_key,
            manifest: None,
            signed_prekey: bundle.signed_prekey,
            signed_prekey_signature: Some(bundle.signed_prekey_signature),
            one_time_prekey,
            pq_last_resort: None,
            pq_one_time_prekey: None,
        }))
    }

    async fn add_initial_message_v2(
        &self,
        initial_message: StoredInitialMessageV2,
        limit: usize,
    ) -> Result<Option<u64>> {
        let mut inner = self.inner.lock();
        let inbox = inner.inboxes.entry(initial_message.recipient).or_default();
        if inbox.initial_messages.len() >= limit {
            return Ok(None);
        }
        let next_id = inbox
            .next_id
            .checked_add(1)
            .filter(|&id| id <= MAX_SAFE_INTEGER)
            .ok_or(ErrorKind::LimitExceeded)?;
        inbox.next_id = next_id;
        inbox.initial_messages.push(InboxEntry {
            id: next_id,
            version: initial_message.version,
            classical: StoredInitialMessage {
                sender: initial_message.sender,
                recipient: initial_message.recipient,
                ephemeral_key: initial_message.ephemeral_key,
                signed_prekey: initial_message.signed_prekey,
                one_time_prekey: initial_message.one_time_prekey,
                header: initial_message.header,
                content: initial_message.content,
            },
            pq_suite: initial_message.pq_suite,
            pq_last_resort: initial_message.pq_last_resort,
            pq_prekey_id: initial_message.pq_prekey_id,
            pq_ciphertext: initial_message.pq_ciphertext,
            manifest_digest: initial_message.manifest_digest,
        });
        Ok(Some(next_id))
    }

    async fn list_initial_messages(
        &self,
        recipient: &PublicKey,
        limit: usize,
    ) -> Result<Vec<StoredInitialMessageV2>> {
        let inner = self.inner.lock();
        let Some(inbox) = inner.inboxes.get(recipient) else {
            return Ok(vec![]);
        };
        Ok(inbox
            .initial_messages
            .iter()
            .take(limit)
            .map(|entry| StoredInitialMessageV2 {
                id: entry.id,
                version: entry.version,
                sender: entry.classical.sender,
                recipient: entry.classical.recipient,
                ephemeral_key: entry.classical.ephemeral_key,
                signed_prekey: entry.classical.signed_prekey,
                one_time_prekey: entry.classical.one_time_prekey,
                header: entry.classical.header.clone(),
                content: entry.classical.content.clone(),
                pq_suite: entry.pq_suite,
                pq_last_resort: entry.pq_last_resort,
                pq_prekey_id: entry.pq_prekey_id,
                pq_ciphertext: entry.pq_ciphertext.clone(),
                manifest_digest: entry.manifest_digest,
            })
            .collect())
    }

    async fn ack_initial_messages(&self, recipient: &PublicKey, ids: &[u64]) -> Result<usize> {
        for &id in ids {
            check_safe_int(id)?;
        }
        let mut inner = self.inner.lock();
        let Some(inbox) = inner.inboxes.get_mut(recipient) else {
            return Ok(0);
        };
        let before = inbox.initial_messages.len();
        inbox
            .initial_messages
            .retain(|entry| !ids.contains(&entry.id));
        Ok(before - inbox.initial_messages.len())
    }

    async fn pq_snapshot(&self, identity_key: &PublicKey) -> Result<PqStorageSnapshot> {
        let inner = self.inner.lock();
        let manifest = inner.manifests.get(identity_key).cloned();
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
        let pending_initial_messages = inner
            .inboxes
            .get(identity_key)
            .map_or(0, |i| i.initial_messages.len());
        Ok(PqStorageSnapshot {
            manifest,
            classical_one_time_count,
            pq_last_resort_suites,
            pq_one_time_counts,
            pending_initial_messages,
        })
    }
}

#[cfg(feature = "pq")]
fn suite_counts(queue: &VecDeque<StoredPqPrekey>) -> Vec<(u8, usize)> {
    let mut counts: std::collections::BTreeMap<u8, usize> = std::collections::BTreeMap::new();
    for key in queue {
        *counts.entry(key.suite).or_default() += 1;
    }
    counts.into_iter().collect()
}

#[allow(deprecated)]
impl MailboxStore for MemoryStore {
    async fn append(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        delivery_hash: Option<[u8; 32]>,
    ) -> Result<u64> {
        let mut inner = self.inner.lock();
        inner.append_inner(
            sender,
            recipient,
            header,
            content,
            initial_message,
            delivery_hash,
        )
    }

    async fn delete_delivered(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        hashes: &[[u8; 32]],
    ) -> Result<()> {
        self.inner
            .lock()
            .delete_delivered_inner(sender, recipient, hashes);
        Ok(())
    }

    async fn read(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
    ) -> Result<Vec<StoredMessage>> {
        Ok(self
            .inner
            .lock()
            .read_inner(sender, recipient, after, limit))
    }
}

#[cfg(feature = "pq")]
impl Inner {
    /// Expire the oldest tombstones. Return true if this removed the bucket.
    fn prune_dedup(&mut self, key: &(PublicKey, PublicKey), now: Instant, ttl: Duration) -> bool {
        let Some(bucket) = self.mailbox_dedup.get_mut(key) else {
            return false;
        };
        while bucket
            .entries
            .front()
            .is_some_and(|entry| now.duration_since(entry.inserted) >= ttl)
        {
            bucket.entries.pop_front();
        }
        if !bucket.entries.is_empty() {
            return false;
        }
        let index = bucket.sweep_index;
        self.mailbox_dedup.remove(key);
        self.dedup_keys.swap_remove(index);
        if let Some(moved) = self.dedup_keys.get(index) {
            self.mailbox_dedup.get_mut(moved).unwrap().sweep_index = index;
        }
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
}

#[cfg(feature = "pq")]
impl IdempotentMailboxStore for MemoryStore {
    async fn append_idempotent(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        delivery_hash: Option<[u8; 32]>,
        client_message_id: Option<[u8; 16]>,
    ) -> Result<u64> {
        let mut inner = self.inner.lock();
        let dedup_enabled = !self.dedup.ttl.is_zero() && self.dedup.max_per_queue > 0;
        if !dedup_enabled {
            return inner.append_inner(
                sender,
                recipient,
                header,
                content,
                initial_message,
                delivery_hash,
            );
        }
        let key = (*sender, *recipient);
        let now = Instant::now();
        inner.sweep_dedup(now, self.dedup.ttl);
        inner.prune_dedup(&key, now, self.dedup.ttl);
        if let Some(id) = client_message_id
            && let Some(bucket) = inner.mailbox_dedup.get(&key)
            && let Some(entry) = bucket.entries.iter().find(|entry| entry.id == id)
        {
            return Ok(entry.sequence);
        }
        let seq = inner.append_inner(
            sender,
            recipient,
            header,
            content,
            initial_message,
            delivery_hash,
        )?;
        if let Some(id) = client_message_id {
            let Inner {
                mailbox_dedup,
                dedup_keys,
                queues,
                ..
            } = &mut *inner;
            let bucket = mailbox_dedup.entry(key).or_insert_with(|| {
                let sweep_index = dedup_keys.len();
                dedup_keys.push(key);
                DedupBucket {
                    entries: VecDeque::new(),
                    sweep_index,
                }
            });
            let entries = &mut bucket.entries;
            if entries.len() == self.dedup.max_per_queue {
                // Prefer the oldest delivered message. Queue rows are sorted by sequence.
                let queue = &queues[&key];
                let oldest_delivered = entries.iter().position(|entry| {
                    queue
                        .binary_search_by_key(&entry.sequence, |row| row.message.sequence)
                        .is_err()
                });
                entries.remove(oldest_delivered.unwrap_or(0));
            }
            entries.push_back(Tombstone {
                id,
                sequence: seq,
                inserted: now,
            });
        }
        Ok(seq)
    }

    async fn delete_delivered(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        hashes: &[[u8; 32]],
    ) -> Result<()> {
        self.inner
            .lock()
            .delete_delivered_inner(sender, recipient, hashes);
        Ok(())
    }

    async fn read(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
    ) -> Result<Vec<StoredMessage>> {
        Ok(self
            .inner
            .lock()
            .read_inner(sender, recipient, after, limit))
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
        let (attachment, chunks) = inner.attachments.get_mut(id).ok_or(ErrorKind::Other)?;
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
#[allow(deprecated)]
mod test {
    use super::*;

    #[test]
    fn conformance() {
        futures::executor::block_on(async {
            crate::testing::handshake_store(&MemoryStore::default()).await;
            crate::testing::mailbox_store(&MemoryStore::default()).await;
            crate::testing::attachment_store(&MemoryStore::default()).await;
            #[cfg(feature = "pq")]
            {
                crate::testing::pq_handshake_store(&MemoryStore::default()).await;
                crate::testing::idempotent_mailbox_store(&MemoryStore::default()).await;
            }
        });
    }

    #[test]
    fn unknown_identity_take_does_not_allocate_inbox() {
        futures::executor::block_on(async {
            let store = MemoryStore::default();
            let ghost = [0x99; 32];
            assert_eq!(
                store.take_initial_messages(&ghost, 100).await.unwrap(),
                Some(vec![])
            );
            // Still does not allocate an inbox entry or record a replay watermark.
            assert!(store.inner.lock().inboxes.is_empty());
            assert_eq!(
                store.take_initial_messages(&ghost, 50).await.unwrap(),
                Some(vec![])
            );
            assert!(store.inner.lock().inboxes.is_empty());
        });
    }

    #[cfg(feature = "pq")]
    async fn append_id(store: &MemoryStore, key: &(PublicKey, PublicKey), id: Option<u8>) -> u64 {
        store
            .append_idempotent(
                &key.0,
                &key.1,
                Bytes::new(),
                Bytes::new(),
                None,
                None,
                id.map(|n| [n; 16]),
            )
            .await
            .unwrap()
    }

    #[cfg(feature = "pq")]
    #[test]
    fn disabled_dedup_keeps_no_tombstones() {
        futures::executor::block_on(async {
            let key = ([1; 32], [2; 32]);
            for (ttl, cap) in [(Duration::ZERO, 4), (DEFAULT_DEDUP_TTL, 0)] {
                let store = MemoryStore::with_dedup_limits(ttl, cap);
                assert_eq!(append_id(&store, &key, Some(1)).await, 1);
                assert_eq!(append_id(&store, &key, Some(1)).await, 2);
                let inner = store.inner.lock();
                assert!(inner.mailbox_dedup.is_empty());
                assert!(inner.dedup_keys.is_empty());
            }
        });
    }

    #[cfg(feature = "pq")]
    #[test]
    fn idle_dedup_buckets_expire_with_bounded_sweeps() {
        futures::executor::block_on(async {
            let ttl = Duration::from_secs(60);
            let store = MemoryStore::with_dedup_limits(ttl, 4);
            let active = ([1; 32], [255; 32]);
            let idle: Vec<_> = (0..2 * DEDUP_SWEEP_BUDGET + 1)
                .map(|i| ([1; 32], [i as u8; 32]))
                .collect();
            for key in &idle {
                append_id(&store, key, Some(1)).await;
                append_id(&store, key, Some(2)).await;
            }
            append_id(&store, &active, Some(3)).await;
            {
                let mut inner = store.inner.lock();
                for key in &idle {
                    for entry in &mut inner.mailbox_dedup.get_mut(key).unwrap().entries {
                        entry.inserted -= ttl;
                    }
                }
            }
            for pass in 0..4 {
                assert_eq!(append_id(&store, &active, Some(3)).await, 1);
                let inner = store.inner.lock();
                assert_eq!(inner.dedup_keys.len(), inner.mailbox_dedup.len());
                for (i, key) in inner.dedup_keys.iter().enumerate() {
                    assert_eq!(inner.mailbox_dedup[key].sweep_index, i);
                }
                if pass == 0 {
                    assert!(inner.dedup_keys.len() >= idle.len() + 1 - DEDUP_SWEEP_BUDGET);
                }
            }
            let inner = store.inner.lock();
            assert_eq!(inner.dedup_keys, [active]);
            assert!(
                idle.iter()
                    .all(|key| !inner.mailbox_dedup.contains_key(key))
            );
        });
    }

    #[cfg(feature = "pq")]
    #[test]
    fn append_without_an_id_removes_an_expired_active_bucket_outside_the_sweep() {
        futures::executor::block_on(async {
            let ttl = Duration::from_secs(60);
            let store = MemoryStore::with_dedup_limits(ttl, 4);
            for i in 0..=DEDUP_SWEEP_BUDGET {
                append_id(&store, &([1; 32], [i as u8; 32]), Some(1)).await;
            }
            let key = {
                let mut inner = store.inner.lock();
                let key = inner.dedup_keys
                    [(inner.dedup_sweep_cursor + DEDUP_SWEEP_BUDGET) % inner.dedup_keys.len()];
                inner.mailbox_dedup.get_mut(&key).unwrap().entries[0].inserted -= ttl;
                key
            };
            assert_eq!(append_id(&store, &key, None).await, 2);
            let inner = store.inner.lock();
            assert!(!inner.mailbox_dedup.contains_key(&key));
            assert_eq!(inner.dedup_keys.len(), inner.mailbox_dedup.len());
        });
    }

    #[cfg(feature = "pq")]
    #[test]
    fn tombstones_expire_at_the_configured_age() {
        futures::executor::block_on(async {
            let ttl = Duration::from_secs(60);
            let store = MemoryStore::with_dedup_limits(ttl, 4);
            let (alice, bob) = ([1; 32], [2; 32]);
            let append = || {
                store.append_idempotent(
                    &alice,
                    &bob,
                    Bytes::new(),
                    Bytes::new(),
                    None,
                    Some([3; 32]),
                    Some([4; 16]),
                )
            };
            let seq = append().await.unwrap();
            IdempotentMailboxStore::delete_delivered(&store, &alice, &bob, &[[3; 32]])
                .await
                .unwrap();
            assert_eq!(append().await.unwrap(), seq);
            assert!(
                IdempotentMailboxStore::read(&store, &alice, &bob, 0, 10)
                    .await
                    .unwrap()
                    .is_empty()
            );
            store
                .inner
                .lock()
                .mailbox_dedup
                .get_mut(&(alice, bob))
                .unwrap()
                .entries[0]
                .inserted -= ttl;
            assert_eq!(append().await.unwrap(), seq + 1);
            assert_eq!(
                store.inner.lock().mailbox_dedup[&(alice, bob)]
                    .entries
                    .len(),
                1
            );
        });
    }

    #[cfg(feature = "pq")]
    #[test]
    fn tombstone_cap_is_per_queue_and_evicts_delivered_messages_first() {
        futures::executor::block_on(async {
            let store = MemoryStore::with_dedup_limits(DEFAULT_DEDUP_TTL, 2);
            let (alice, bob, carol) = ([1; 32], [2; 32], [3; 32]);
            let append = async |recipient: &PublicKey, id: u8| {
                store
                    .append_idempotent(
                        &alice,
                        recipient,
                        Bytes::new(),
                        Bytes::new(),
                        None,
                        Some([id; 32]),
                        Some([id; 16]),
                    )
                    .await
                    .unwrap()
            };
            assert_eq!(append(&bob, 1).await, 1);
            assert_eq!(append(&carol, 1).await, 1);
            assert_eq!(append(&bob, 2).await, 2);
            for id in 3..=20 {
                IdempotentMailboxStore::delete_delivered(&store, &alice, &bob, &[[id - 1; 32]])
                    .await
                    .unwrap();
                assert_eq!(append(&bob, id).await, u64::from(id));
                assert_eq!(
                    store.inner.lock().mailbox_dedup[&(alice, bob)]
                        .entries
                        .len(),
                    2
                );
            }
            assert_eq!(append(&bob, 1).await, 1);
            assert_eq!(append(&carol, 1).await, 1);
            assert_eq!(append(&bob, 2).await, 21);
        });
    }

    #[cfg(feature = "pq")]
    #[test]
    fn legacy_v1_and_v2_memory_store_isolation() {
        futures::executor::block_on(async {
            let store = MemoryStore::default();
            let (alice, bob, carol) = ([11; 32], [12; 32], [13; 32]);
            let pq_key = |suite: u8, tag: u8| StoredPqPrekey {
                suite,
                id: [tag; 32],
                encapsulation_key: Bytes::from(vec![tag; if suite == 1 { 1568 } else { 1184 }]),
                signature: [tag; 64],
            };
            let manifest = |seq: u64, generation: u64, strict_pq: bool| StoredCapabilityManifest {
                audience: "chat.example".to_string(),
                identity_key: bob,
                manifest_seq: seq,
                generation,
                issued_at: 1000 + seq,
                expires_at: 100_000 + seq,
                pq_enabled: true,
                strict_pq,
                pq_ratchet_supported: true,
                offered_suites: vec![1, 2],
                signed_prekey: [20 + (generation as u8); 32],
                pq_last_resort: vec![
                    crate::PqLastResortCommitment {
                        suite: 1,
                        prekey_id: [0xA1; 32],
                    },
                    crate::PqLastResortCommitment {
                        suite: 2,
                        prekey_id: [0xA2; 32],
                    },
                ],
                signature: [0x55; 64],
            };

            // Legacy v1 user falls back in v2 claim_bundle with manifest = None.
            assert!(
                store
                    .publish(
                        Bundle {
                            identity_key: carol,
                            signed_prekey: [30; 32],
                            signed_prekey_signature: [31; 64],
                            timestamp: 10,
                        },
                        vec![[32; 32]],
                    )
                    .await
                    .unwrap()
            );
            let claimed_v1 = store.claim_bundle(&carol, &[1, 2]).await.unwrap().unwrap();
            assert_eq!(claimed_v1.manifest, None);
            assert_eq!(claimed_v1.signed_prekey, [30; 32]);

            // Legacy v1 take_bundle never consumes PQOPKs, and v1 publish is refused once a v2 manifest exists.
            assert_eq!(
                store
                    .publish_v2(PublishV2Record {
                        manifest: manifest(1, 1, false),
                        signed_prekey_signature: Some([0x44; 64]),
                        one_time_prekeys: vec![[40; 32], [41; 32]],
                        pq_last_resort: vec![pq_key(1, 0xA1), pq_key(2, 0xA2)],
                        pq_one_time_prekeys: vec![pq_key(1, 0xB1), pq_key(2, 0xB2)],
                        timestamp: 1001,
                    })
                    .await
                    .unwrap(),
                PublishV2Status::Stored
            );
            let (v1_bundle, v1_opk) = store.take_bundle(&bob).await.unwrap().unwrap();
            assert_eq!(v1_bundle.signed_prekey, [21; 32]);
            assert_eq!(v1_opk, Some([40; 32]));
            assert_eq!(
                store.pq_snapshot(&bob).await.unwrap().pq_one_time_counts,
                vec![(1, 1), (2, 1)]
            );
            assert!(
                !store
                    .publish(
                        Bundle {
                            identity_key: bob,
                            signed_prekey: [99; 32],
                            signed_prekey_signature: [98; 64],
                            timestamp: 2000,
                        },
                        vec![[42; 32]],
                    )
                    .await
                    .unwrap()
            );

            // Strict PQ publish clears legacy v1 bundle.
            assert_eq!(
                store
                    .publish_v2(PublishV2Record {
                        manifest: manifest(2, 2, true),
                        signed_prekey_signature: None,
                        one_time_prekeys: vec![[60; 32]],
                        pq_last_resort: vec![pq_key(1, 0xA1), pq_key(2, 0xA2)],
                        pq_one_time_prekeys: vec![pq_key(1, 0xB4)],
                        timestamp: 2002,
                    })
                    .await
                    .unwrap(),
                PublishV2Status::Stored
            );
            assert_eq!(store.take_bundle(&bob).await.unwrap(), None);

            // Legacy v1 take_initial_messages drains only v1 messages, leaving v2 PQ intact.
            assert!(
                store
                    .add_initial_message(
                        StoredInitialMessage {
                            sender: alice,
                            recipient: bob,
                            ephemeral_key: [80; 32],
                            signed_prekey: [22; 32],
                            one_time_prekey: None,
                            header: Bytes::from_static(b"v1-h"),
                            content: Bytes::from_static(b"v1-c"),
                        },
                        10,
                    )
                    .await
                    .unwrap()
            );
            let pq_id = store
                .add_initial_message_v2(
                    StoredInitialMessageV2 {
                        id: 0,
                        version: 2,
                        sender: alice,
                        recipient: bob,
                        ephemeral_key: [81; 32],
                        signed_prekey: [22; 32],
                        one_time_prekey: None,
                        header: Bytes::from_static(b"v2-h"),
                        content: Bytes::from_static(b"v2-c"),
                        pq_suite: Some(1),
                        pq_last_resort: false,
                        pq_prekey_id: Some([0xB4; 32]),
                        pq_ciphertext: Some(Bytes::from(vec![0xCC; 1568])),
                        manifest_digest: Some([0xDD; 32]),
                    },
                    10,
                )
                .await
                .unwrap()
                .unwrap();
            let v1_taken = store
                .take_initial_messages(&bob, 3000)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(v1_taken.len(), 1);
            assert_eq!(v1_taken[0].header, Bytes::from_static(b"v1-h"));
            let remaining = store.list_initial_messages(&bob, 10).await.unwrap();
            assert_eq!(remaining.len(), 1);
            assert_eq!(remaining[0].id, pq_id);

            // Legacy MailboxStore::append shares queue with IdempotentMailboxStore.
            let seq1 = store
                .append_idempotent(
                    &alice,
                    &bob,
                    Bytes::from_static(b"h1"),
                    Bytes::from_static(b"c1"),
                    None,
                    None,
                    Some([0x42; 16]),
                )
                .await
                .unwrap();
            let seq2 = store
                .append(
                    &alice,
                    &bob,
                    Bytes::from_static(b"h2"),
                    Bytes::from_static(b"c2"),
                    None,
                    None,
                )
                .await
                .unwrap();
            assert_eq!(seq2, seq1 + 1);
            assert_eq!(
                IdempotentMailboxStore::read(&store, &alice, &bob, 0, 10)
                    .await
                    .unwrap()
                    .len(),
                2
            );
        });
    }
}
