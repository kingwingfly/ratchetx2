//! Per-sender message queues, recipient-wide O(1) storage caps, and durable R2 delivery cleanup.

use storage::{MAX_QUEUE_BYTES, MAX_QUEUE_MESSAGES, MAX_SAFE_INTEGER};
use worker::{Date, Error, Result, console_error};

use super::{AlarmUpdate, Identity, IdentityStore, rows::*};
use crate::objects::{
    AppendOutcome, Content, RETRY_ALARM, StoredRow,
    sql::{Blob, SqlExec, params},
};

pub(super) const DEDUP_TTL_MS: u64 = 24 * 60 * 60 * 1000;
pub(super) const MAX_DEDUP_TOMBSTONES_PER_QUEUE: u64 = 4096;
/// Maximum distinct active sender queues per recipient Identity Durable Object.
pub(super) const MAX_QUEUES_PER_RECIPIENT: u64 = 1024;
/// Maximum total queued bytes across all senders for one recipient Identity Durable Object
/// (256 MiB, well below Cloudflare Durable Object SQLite limits).
pub(super) const MAX_RECIPIENT_BYTES: u64 = 256 << 20;
/// Maximum R2-backed message rows returned in a single read page so `Store::read` stays safely
/// below Cloudflare Workers Free-plan subrequest limits (50/invocation) even when `delete_delivered`
/// runs in the same `FetchSigned` call.
const MAX_READ_R2_OBJECTS: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueueQuotaSnapshot {
    queue_count: u64,
    queue_bytes: u64,
    is_new_queue: bool,
    recipient_queues: u64,
    recipient_bytes: u64,
}

fn within_mailbox_quotas(snapshot: QueueQuotaSnapshot, incoming_bytes: u64) -> bool {
    if snapshot.queue_count >= MAX_QUEUE_MESSAGES as u64
        || snapshot.queue_bytes.saturating_add(incoming_bytes) > MAX_QUEUE_BYTES
    {
        return false;
    }
    if snapshot.is_new_queue && snapshot.recipient_queues >= MAX_QUEUES_PER_RECIPIENT {
        return false;
    }
    if snapshot.recipient_bytes.saturating_add(incoming_bytes) > MAX_RECIPIENT_BYTES {
        return false;
    }
    true
}

impl<S: SqlExec> IdentityStore<'_, S> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn append(
        &self,
        sender: &[u8],
        header: &[u8],
        content: &Content,
        size: u64,
        initial_message: Option<&[u8]>,
        delivery_hash: Option<&[u8]>,
        client_message_id: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<AppendOutcome> {
        self.sql.transaction_sync(|sql| {
            let mut replacing_expired_dedup = false;
            if let Some(cid) = client_message_id
                && let Some(existing) = sql.query_opt::<DedupRow>(
                    "SELECT sequence, expires_at FROM mailbox_dedup \
                     WHERE sender = ? AND client_message_id = ?",
                    params![sender, cid]?,
                )?
            {
                if existing.expires_at > now_ms {
                    return Ok(AppendOutcome::Deduplicated(existing.sequence));
                }
                replacing_expired_dedup = true;
            }

            // Enforce per-queue and per-recipient row/byte caps in O(1) using maintained counters
            // BEFORE allocating a sequence number or inserting any row.
            let incoming_bytes = (header.len() as u64)
                .saturating_add(size)
                .saturating_add(initial_message.map_or(0, |m| m.len() as u64));
            let stats = sql
                .query_opt::<RecipientStatsRow>(
                    "SELECT queue_count, total_bytes, sequence_floor FROM recipient_stats WHERE only = 0",
                    vec![],
                )?
                .unwrap_or(RecipientStatsRow {
                    queue_count: 0,
                    total_bytes: 0,
                    sequence_floor: 0,
                });
            let queue = sql.query_opt::<QueueStateRow>(
                "SELECT last_sequence, message_count, total_bytes FROM queues WHERE sender = ?",
                params![sender]?,
            )?;
            let (queue_count, queue_bytes, is_new_queue) = match &queue {
                Some(q) => (q.message_count, q.total_bytes, false),
                None => (0, 0, true),
            };
            let quota = QueueQuotaSnapshot {
                queue_count,
                queue_bytes,
                is_new_queue,
                recipient_queues: stats.queue_count,
                recipient_bytes: stats.total_bytes,
            };
            if !within_mailbox_quotas(quota, incoming_bytes) {
                return Ok(AppendOutcome::LimitExceeded);
            }

            // Keep sequence numbers strictly monotonic even after empty queues are pruned: any
            // pruned sender's prior sequences are <= `stats.sequence_floor`.
            let base_sequence = queue
                .as_ref()
                .map_or(stats.sequence_floor, |q| q.last_sequence);
            let Some(next_sequence) = base_sequence
                .checked_add(1)
                .filter(|&seq| seq <= MAX_SAFE_INTEGER)
            else {
                return Ok(AppendOutcome::LimitExceeded);
            };

            let next_queue_count = queue_count.saturating_add(1);
            let next_queue_bytes = queue_bytes.saturating_add(incoming_bytes);
            sql.exec(
                "INSERT INTO queues (sender, last_sequence, message_count, total_bytes) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT (sender) DO UPDATE SET \
                 last_sequence = excluded.last_sequence, \
                 message_count = excluded.message_count, \
                 total_bytes = excluded.total_bytes",
                params![sender, next_sequence, next_queue_count, next_queue_bytes]?,
            )?;
            let next_recipient_queues = stats.queue_count.saturating_add(u64::from(is_new_queue));
            let next_recipient_bytes = stats.total_bytes.saturating_add(incoming_bytes);
            sql.exec(
                "INSERT INTO recipient_stats (only, queue_count, total_bytes, sequence_floor) \
                 VALUES (0, ?, ?, ?) \
                 ON CONFLICT (only) DO UPDATE SET \
                 queue_count = excluded.queue_count, \
                 total_bytes = excluded.total_bytes, \
                 sequence_floor = max(recipient_stats.sequence_floor, excluded.sequence_floor)",
                params![
                    next_recipient_queues,
                    next_recipient_bytes,
                    stats.sequence_floor
                ]?,
            )?;

            let (inline, object): (Option<&[u8]>, Option<&str>) = match content {
                Content::Inline(bytes) => (Some(bytes.as_slice()), None),
                Content::Object(key) => (None, Some(key.as_str())),
            };
            sql.exec(
                "INSERT INTO messages (sender, sequence, header, content, object, size, \
                 initial_message, delivery_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    sender,
                    next_sequence,
                    header,
                    inline,
                    object,
                    size,
                    initial_message,
                    delivery_hash,
                    now_ms
                ]?,
            )?;
            if let Some(cid) = client_message_id {
                record_tombstone(
                    sql,
                    sender,
                    cid,
                    next_sequence,
                    now_ms,
                    replacing_expired_dedup,
                )?;
            }
            Ok(AppendOutcome::Appended(next_sequence))
        })
    }

    /// Reads unexpired messages incrementally without materializing all rows before enforcing
    /// `max_size`, counting `header.len() + initial_message.len() + size` accurately.
    pub(super) fn read(
        &self,
        sender: &[u8],
        after: u64,
        limit: u32,
        max_size: u64,
        now_ms: u64,
    ) -> Result<Vec<StoredRow>> {
        if !self.has_tables()? || limit == 0 || after > MAX_SAFE_INTEGER {
            return Ok(vec![]);
        }
        let cutoff = now_ms.saturating_sub(self.retention_ms);
        // Step 1: query lightweight integer metadata only (no BLOBs materialized!).
        let metas: Vec<MessageMetaRow> = self.sql.query(
            "SELECT sequence, length(header) AS header_len, size, \
             coalesce(length(initial_message), 0) AS init_len, \
             (object IS NOT NULL) AS is_object \
             FROM messages WHERE sender = ? AND sequence > ? AND created_at >= ? \
             ORDER BY sequence LIMIT ?",
            params![sender, after, cutoff, limit]?,
        )?;
        if metas.is_empty() {
            return Ok(vec![]);
        }

        let mut total_bytes = 0u64;
        let mut r2_count = 0usize;
        let mut cutoff_sequence = metas[0].sequence;
        for (take_count, meta) in metas.iter().enumerate() {
            let row_bytes = meta
                .header_len
                .saturating_add(meta.init_len)
                .saturating_add(meta.size);
            total_bytes = total_bytes.saturating_add(row_bytes);
            r2_count += usize::from(meta.is_object != 0);
            if take_count > 0 && (total_bytes > max_size || r2_count > MAX_READ_R2_OBJECTS) {
                break;
            }
            cutoff_sequence = meta.sequence;
        }

        // Step 2: materialize ONLY the exact unexpired rows that fit within the byte budget.
        let rows: Vec<MessageRow> = self.sql.query(
            "SELECT sequence, header, content, object, initial_message FROM messages \
             WHERE sender = ? AND sequence > ? AND sequence <= ? AND created_at >= ? \
             ORDER BY sequence",
            params![sender, after, cutoff_sequence, cutoff]?,
        )?;
        let mut page = Vec::with_capacity(rows.len());
        for row in rows {
            let content = match (row.content, row.object) {
                (Some(content), _) => Content::Inline(content.into_vec()),
                (None, Some(object)) => Content::Object(object),
                (None, None) => return Err(Error::RustError("a message without content".into())),
            };
            page.push(StoredRow {
                sequence: row.sequence,
                header: row.header.into_vec(),
                content,
                initial_message: row.initial_message.map(Blob::into_vec),
            });
        }
        Ok(page)
    }

    pub(super) fn delivered_objects(
        &self,
        sender: &[u8],
        hashes: &[Vec<u8>],
    ) -> Result<Vec<String>> {
        if hashes.is_empty() || !self.has_tables()? {
            return Ok(vec![]);
        }
        let rows: Vec<ObjectRow> = self.sql.query(
            "SELECT object FROM messages WHERE sender = ? AND object IS NOT NULL \
             AND delivery_hash IN (SELECT unhex(value) FROM json_each(?))",
            params![sender, hashes_json(hashes)]?,
        )?;
        Ok(rows.into_iter().filter_map(|row| row.object).collect())
    }

    /// Legacy rolling-deploy handler (`IdentityCall::DeleteDelivered`, tag `7`).
    pub(super) fn delete_delivered(
        &self,
        sender: &[u8],
        hashes: &[Vec<u8>],
        objects: &[String],
    ) -> Result<()> {
        if hashes.is_empty() || !self.has_tables()? {
            return Ok(());
        }
        self.ensure_v2_tables()?;
        let objects =
            serde_json::to_string(objects).map_err(|e| Error::RustError(e.to_string()))?;
        let hashes_param = hashes_json(hashes);
        self.sql.transaction_sync(|sql| {
            let deleted: Vec<DeletedMessageRow> = sql.query(
                "DELETE FROM messages WHERE sender = ? \
                 AND delivery_hash IN (SELECT unhex(value) FROM json_each(?)) \
                 AND (object IS NULL OR object IN (SELECT value FROM json_each(?))) \
                 RETURNING (length(header) + size + coalesce(length(initial_message), 0)) AS bytes, object",
                params![sender, hashes_param, objects]?,
            )?;
            let count = deleted.len() as u64;
            let bytes = deleted
                .iter()
                .fold(0u64, |acc, row| acc.saturating_add(row.bytes));
            subtract_queue_usage(sql, sender, count, bytes)
        })
    }

    /// Atomically deletes delivered queue rows, updates O(1) queue/recipient counters (pruning
    /// empty queues safely via `sequence_floor`), and durably enqueues any R2 object keys into
    /// `pending_r2_deletes`, returning those R2 object keys for immediate deletion.
    pub(super) fn commit_delete_delivered_atomic(
        &self,
        sender: &[u8],
        hashes: &[Vec<u8>],
        now_ms: u64,
    ) -> Result<Vec<String>> {
        let hashes_param = hashes_json(hashes);
        self.sql.transaction_sync(|sql| {
            let deleted: Vec<DeletedMessageRow> = sql.query(
                "DELETE FROM messages WHERE sender = ? \
                 AND delivery_hash IN (SELECT unhex(value) FROM json_each(?)) \
                 RETURNING (length(header) + size + coalesce(length(initial_message), 0)) AS bytes, object",
                params![sender, hashes_param]?,
            )?;
            let count = deleted.len() as u64;
            let bytes = deleted
                .iter()
                .fold(0u64, |acc, row| acc.saturating_add(row.bytes));
            let mut objects = Vec::new();
            for row in deleted {
                if let Some(object) = row.object {
                    sql.exec(
                        "INSERT OR IGNORE INTO pending_r2_deletes (object, created_at) VALUES (?, ?)",
                        params![object.as_str(), now_ms]?,
                    )?;
                    objects.push(object);
                }
            }
            subtract_queue_usage(sql, sender, count, bytes)?;
            Ok(objects)
        })
    }

    /// Removes successfully deleted R2 object keys from `pending_r2_deletes`.
    pub(super) fn clear_pending_r2_deletes(&self, objects: &[String]) -> Result<()> {
        if objects.is_empty() {
            return Ok(());
        }
        let objects_json =
            serde_json::to_string(objects).map_err(|e| Error::RustError(e.to_string()))?;
        self.sql.exec(
            "DELETE FROM pending_r2_deletes WHERE object IN (SELECT value FROM json_each(?))",
            params![objects_json]?,
        )
    }

    /// Expires `mailbox_dedup` rows and keeps `dedup_counts` synchronized in one transaction.
    pub(super) fn expire_dedup(&self, now_ms: u64) -> Result<()> {
        self.sql.transaction_sync(|sql| {
            let expired: Vec<SenderCountRow> = sql.query(
                "SELECT sender, count(*) AS count FROM mailbox_dedup \
                 WHERE expires_at <= ? GROUP BY sender",
                params![now_ms]?,
            )?;
            if expired.is_empty() {
                return Ok(());
            }
            sql.exec(
                "DELETE FROM mailbox_dedup WHERE expires_at <= ?",
                params![now_ms]?,
            )?;
            for row in expired {
                adjust_dedup_count(sql, &row.sender, -(row.count as i64))?;
            }
            Ok(())
        })
    }
}

impl Identity {
    /// Atomically deletes delivered queue rows, updates O(1) queue/recipient counters (pruning
    /// empty queues safely via `sequence_floor`), and durably enqueues any R2 object keys into
    /// `pending_r2_deletes` before attempting immediate R2 deletion.
    ///
    /// If R2 deletion fails transiently, the message rows are already deleted (no stale receipts or
    /// quota retention) and the armed DO alarm retries `pending_r2_deletes`.
    pub(super) async fn delete_delivered_atomic(
        &self,
        sender: &[u8],
        hashes: &[Vec<u8>],
    ) -> Result<()> {
        if hashes.is_empty() || !self.with_store(|store| store.has_tables())? {
            return Ok(());
        }
        let now = Date::now().as_millis();
        // Arm the retry alarm BEFORE committing `pending_r2_deletes` when matching R2 objects exist
        // (DO storage ops keep the input gate closed, so no concurrent request interleaves).
        let has_r2 = self.with_store(|store| {
            store.ensure_v2_tables()?;
            Ok(!store.delivered_objects(sender, hashes)?.is_empty())
        })?;
        if has_r2 {
            self.update_alarm(AlarmUpdate::PullEarlier(now.saturating_add(RETRY_ALARM)))
                .await?;
        }
        let r2_objects =
            self.with_store(|store| store.commit_delete_delivered_atomic(sender, hashes, now))?;
        if r2_objects.is_empty() {
            return Ok(());
        }
        if !has_r2 {
            self.update_alarm(AlarmUpdate::PullEarlier(now.saturating_add(RETRY_ALARM)))
                .await?;
        }
        let deleted = match self.env.bucket(crate::BUCKET) {
            Ok(bucket) => crate::store::delete_objects(&bucket, r2_objects.clone()).await,
            Err(e) => Err(e),
        };
        match deleted {
            Ok(()) => {
                self.with_store(|store| store.clear_pending_r2_deletes(&r2_objects))?;
            }
            Err(e) => {
                console_error!(
                    "cannot delete delivered R2 objects immediately; queued for alarm retry: {e}"
                );
            }
        }
        Ok(())
    }
}

/// Decrements per-queue and recipient-wide byte/message counters after rows are deleted from
/// `messages`, pruning empty `queues` rows while raising `recipient_stats.sequence_floor`.
pub(super) fn subtract_queue_usage<S: SqlExec>(
    sql: &S,
    sender: &[u8],
    removed_count: u64,
    removed_bytes: u64,
) -> Result<()> {
    if removed_count == 0 {
        return Ok(());
    }
    let Some(queue) = sql.query_opt::<QueueStateRow>(
        "SELECT last_sequence, message_count, total_bytes FROM queues WHERE sender = ?",
        params![sender]?,
    )?
    else {
        return Ok(());
    };
    let next_count = queue.message_count.saturating_sub(removed_count);
    if next_count == 0 {
        sql.exec("DELETE FROM queues WHERE sender = ?", params![sender]?)?;
        sql.exec(
            "INSERT INTO recipient_stats (only, queue_count, total_bytes, sequence_floor) \
             VALUES (0, 0, 0, ?) \
             ON CONFLICT (only) DO UPDATE SET \
             queue_count = max(0, recipient_stats.queue_count - 1), \
             total_bytes = max(0, recipient_stats.total_bytes - ?), \
             sequence_floor = max(recipient_stats.sequence_floor, excluded.sequence_floor)",
            params![queue.last_sequence, queue.total_bytes]?,
        )?;
    } else {
        let next_bytes = queue.total_bytes.saturating_sub(removed_bytes);
        let actual_removed = queue.total_bytes.saturating_sub(next_bytes);
        sql.exec(
            "UPDATE queues SET message_count = ?, total_bytes = ? WHERE sender = ?",
            params![next_count, next_bytes, sender]?,
        )?;
        sql.exec(
            "INSERT INTO recipient_stats (only, queue_count, total_bytes, sequence_floor) \
             VALUES (0, 1, 0, 0) \
             ON CONFLICT (only) DO UPDATE SET \
             total_bytes = max(0, recipient_stats.total_bytes - ?)",
            params![actual_removed]?,
        )?;
    }
    Ok(())
}

fn adjust_dedup_count<S: SqlExec>(sql: &S, sender: &[u8], delta: i64) -> Result<()> {
    let current = sql
        .query_opt::<CountRow>(
            "SELECT count FROM dedup_counts WHERE sender = ?",
            params![sender]?,
        )?
        .map_or(0, |row| row.count);
    let next = if delta >= 0 {
        current.saturating_add(delta as u64)
    } else {
        current.saturating_sub(delta.unsigned_abs())
    };
    if next == 0 {
        sql.exec(
            "DELETE FROM dedup_counts WHERE sender = ?",
            params![sender]?,
        )?;
    } else {
        sql.exec(
            "INSERT INTO dedup_counts (sender, count) VALUES (?, ?) \
             ON CONFLICT (sender) DO UPDATE SET count = excluded.count",
            params![sender, next]?,
        )?;
    }
    Ok(())
}

fn record_tombstone<S: SqlExec>(
    sql: &S,
    sender: &[u8],
    cid: &[u8],
    sequence: u64,
    now: u64,
    replacing_existing: bool,
) -> Result<()> {
    if !replacing_existing {
        let mut count = sql
            .query_opt::<CountRow>(
                "SELECT count FROM dedup_counts WHERE sender = ?",
                params![sender]?,
            )?
            .map_or(0, |row| row.count);
        if count >= MAX_DEDUP_TOMBSTONES_PER_QUEUE {
            // Reclaim expired tombstones for this sender before evicting live entries.
            sql.exec(
                "DELETE FROM mailbox_dedup WHERE sender = ? AND expires_at <= ?",
                params![sender, now]?,
            )?;
            let pruned = sql
                .query_opt::<CountRow>("SELECT changes() AS count", vec![])?
                .map_or(0, |row| row.count);
            count = count.saturating_sub(pruned);
            if count >= MAX_DEDUP_TOMBSTONES_PER_QUEUE {
                let to_evict = count - MAX_DEDUP_TOMBSTONES_PER_QUEUE + 1;
                sql.exec(
                    "DELETE FROM mailbox_dedup WHERE sender = ? AND client_message_id IN ( \
                        SELECT d.client_message_id FROM mailbox_dedup d WHERE d.sender = ? \
                        ORDER BY CASE WHEN EXISTS (SELECT 1 FROM messages m \
                            WHERE m.sender = d.sender AND m.sequence = d.sequence) THEN 1 ELSE 0 END ASC, \
                            d.created_at ASC, d.sequence ASC LIMIT ?)",
                    params![sender, sender, to_evict]?,
                )?;
                let evicted = sql
                    .query_opt::<CountRow>("SELECT changes() AS count", vec![])?
                    .map_or(0, |row| row.count);
                count = count.saturating_sub(evicted);
            }
        }
        let next_count = count.saturating_add(1);
        sql.exec(
            "INSERT INTO dedup_counts (sender, count) VALUES (?, ?) \
             ON CONFLICT (sender) DO UPDATE SET count = excluded.count",
            params![sender, next_count]?,
        )?;
    }
    let expires_at = now.saturating_add(DEDUP_TTL_MS).min(MAX_SAFE_INTEGER);
    sql.exec(
        "INSERT INTO mailbox_dedup (sender, client_message_id, sequence, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?) ON CONFLICT (sender, client_message_id) DO UPDATE SET \
         sequence = excluded.sequence, created_at = excluded.created_at, \
         expires_at = excluded.expires_at",
        params![sender, cid, sequence, now, expires_at]?,
    )?;
    Ok(())
}

/// `hashes` as a JSON array of hex strings, which need no escaping, for `json_each`.
fn hashes_json(hashes: &[Vec<u8>]) -> String {
    let mut out = String::with_capacity(2 + hashes.len() * 67);
    out.push('[');
    for (idx, hash) in hashes.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&crate::hex(hash));
        out.push('"');
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_quotas_enforce_per_queue_and_per_recipient_caps() {
        let base = QueueQuotaSnapshot {
            queue_count: 0,
            queue_bytes: 0,
            is_new_queue: true,
            recipient_queues: 0,
            recipient_bytes: 0,
        };
        assert!(within_mailbox_quotas(base, 1024));
        // Per-queue message cap.
        assert!(!within_mailbox_quotas(
            QueueQuotaSnapshot {
                queue_count: MAX_QUEUE_MESSAGES as u64,
                is_new_queue: false,
                ..base
            },
            1
        ));
        // Per-queue byte cap.
        assert!(!within_mailbox_quotas(
            QueueQuotaSnapshot {
                queue_bytes: MAX_QUEUE_BYTES,
                is_new_queue: false,
                ..base
            },
            1
        ));
        // Per-recipient distinct queue cap blocks NEW senders but lets existing queues append.
        assert!(!within_mailbox_quotas(
            QueueQuotaSnapshot {
                is_new_queue: true,
                recipient_queues: MAX_QUEUES_PER_RECIPIENT,
                ..base
            },
            1
        ));
        assert!(within_mailbox_quotas(
            QueueQuotaSnapshot {
                is_new_queue: false,
                recipient_queues: MAX_QUEUES_PER_RECIPIENT,
                ..base
            },
            1
        ));
        // Per-recipient total byte cap blocks both new and existing queues.
        assert!(!within_mailbox_quotas(
            QueueQuotaSnapshot {
                is_new_queue: false,
                recipient_bytes: MAX_RECIPIENT_BYTES,
                ..base
            },
            1
        ));
        assert!(within_mailbox_quotas(
            QueueQuotaSnapshot {
                is_new_queue: false,
                recipient_bytes: MAX_RECIPIENT_BYTES - 10,
                ..base
            },
            10
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native_sqlite_tests {
        use super::*;
        use crate::objects::{InitialMessageV2Wire, identity::TestIdentity};

        fn sender_key(n: u32) -> [u8; 32] {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&n.to_be_bytes());
            key
        }

        fn hash_n(n: u8) -> Vec<u8> {
            vec![n; 32]
        }

        fn stats(env: &TestIdentity) -> RecipientStatsRow {
            env.sql
                .query_one(
                    "SELECT queue_count, total_bytes, sequence_floor FROM recipient_stats WHERE only = 0",
                    vec![],
                )
                .unwrap()
        }

        #[test]
        fn append_dedup_reuses_sequence_until_expiry_and_replaces_without_double_counting() {
            let env = TestIdentity::new(100_000);
            let store = env.store();
            store.ensure_v2_tables().unwrap();

            let alice = sender_key(1);
            let bob = sender_key(2);
            let cid = [0x42u8; 16];

            let first = store
                .append(
                    &alice,
                    b"hdr",
                    &Content::Inline(b"hello".to_vec()),
                    5,
                    None,
                    Some(&hash_n(1)),
                    Some(&cid),
                    1_000,
                )
                .unwrap();
            assert!(matches!(first, AppendOutcome::Appended(1)));

            // Same sender + cid before expires_at -> Deduplicated(1), no second row or counter bump.
            let dup = store
                .append(
                    &alice,
                    b"hdr",
                    &Content::Inline(b"hello".to_vec()),
                    5,
                    None,
                    Some(&hash_n(1)),
                    Some(&cid),
                    1_000 + DEDUP_TTL_MS - 1,
                )
                .unwrap();
            assert!(matches!(dup, AppendOutcome::Deduplicated(1)));

            // Different sender with same cid is independent.
            let bob_first = store
                .append(
                    &bob,
                    b"hdr",
                    &Content::Object("messages/bob-1".into()),
                    128,
                    None,
                    Some(&hash_n(2)),
                    Some(&cid),
                    2_000,
                )
                .unwrap();
            assert!(matches!(bob_first, AppendOutcome::Appended(1)));

            let dedup_count: CountRow = env
                .sql
                .query_one(
                    "SELECT count FROM dedup_counts WHERE sender = ?",
                    params![alice.as_slice()].unwrap(),
                )
                .unwrap();
            assert_eq!(dedup_count.count, 1);

            // At or past expires_at (1_000 + DEDUP_TTL_MS), same cid replaces tombstone cleanly.
            let replaced = store
                .append(
                    &alice,
                    b"hdr",
                    &Content::Inline(b"again".to_vec()),
                    5,
                    None,
                    Some(&hash_n(3)),
                    Some(&cid),
                    1_000 + DEDUP_TTL_MS,
                )
                .unwrap();
            assert!(matches!(replaced, AppendOutcome::Appended(2)));

            let dedup_count_after: CountRow = env
                .sql
                .query_one(
                    "SELECT count FROM dedup_counts WHERE sender = ?",
                    params![alice.as_slice()].unwrap(),
                )
                .unwrap();
            assert_eq!(dedup_count_after.count, 1);
        }

        #[test]
        fn counters_enforce_max_queues_per_recipient_and_max_recipient_bytes() {
            // 1) MAX_RECIPIENT_BYTES across multiple senders using R2 metadata sizes.
            let env_bytes = TestIdentity::new(100_000);
            let store_bytes = env_bytes.store();
            store_bytes.ensure_v2_tables().unwrap();

            let chunk = MAX_QUEUE_BYTES; // 64 MiB per sender
            let senders_to_fill = MAX_RECIPIENT_BYTES / chunk;
            for i in 0..senders_to_fill {
                let s = sender_key(i as u32 + 1);
                let out = store_bytes
                    .append(
                        &s,
                        b"",
                        &Content::Object(format!("messages/big-{i}")),
                        chunk,
                        None,
                        None,
                        None,
                        1_000,
                    )
                    .unwrap();
                assert!(matches!(out, AppendOutcome::Appended(1)));
            }
            let st = stats(&env_bytes);
            assert_eq!(st.queue_count, senders_to_fill);
            assert_eq!(st.total_bytes, MAX_RECIPIENT_BYTES);

            // 1 more byte from either a new or existing sender is rejected.
            let rejected = store_bytes
                .append(
                    &sender_key(999),
                    b"x",
                    &Content::Inline(vec![]),
                    0,
                    None,
                    None,
                    None,
                    1_000,
                )
                .unwrap();
            assert!(matches!(rejected, AppendOutcome::LimitExceeded));

            // 2) MAX_QUEUES_PER_RECIPIENT (1024 distinct queues).
            let env_q = TestIdentity::new(100_000);
            let store_q = env_q.store();
            store_q.ensure_v2_tables().unwrap();

            for i in 0..MAX_QUEUES_PER_RECIPIENT {
                let s = sender_key(i as u32 + 1);
                let out = store_q
                    .append(
                        &s,
                        b"h",
                        &Content::Inline(b"c".to_vec()),
                        1,
                        None,
                        None,
                        None,
                        1_000,
                    )
                    .unwrap();
                assert!(matches!(out, AppendOutcome::Appended(1)));
            }
            assert_eq!(stats(&env_q).queue_count, MAX_QUEUES_PER_RECIPIENT);

            // A 1025th distinct sender is blocked...
            let blocked_new = store_q
                .append(
                    &sender_key(MAX_QUEUES_PER_RECIPIENT as u32 + 1),
                    b"h",
                    &Content::Inline(b"c".to_vec()),
                    1,
                    None,
                    None,
                    None,
                    1_000,
                )
                .unwrap();
            assert!(matches!(blocked_new, AppendOutcome::LimitExceeded));

            // ...while an existing sender can still append.
            let existing_ok = store_q
                .append(
                    &sender_key(1),
                    b"h",
                    &Content::Inline(b"c".to_vec()),
                    1,
                    None,
                    None,
                    None,
                    1_000,
                )
                .unwrap();
            assert!(matches!(existing_ok, AppendOutcome::Appended(2)));
        }

        #[test]
        fn read_enforces_byte_cap_r2_object_cap_after_cursor_and_retention() {
            let retention = 10_000;
            let env = TestIdentity::new(retention);
            let store = env.store();

            // Unallocated DB returns empty without creating tables.
            assert!(
                store
                    .read(&sender_key(1), 0, 10, 1024, 1_000)
                    .unwrap()
                    .is_empty()
            );
            assert!(!store.has_tables().unwrap());

            store.ensure_v2_tables().unwrap();
            let alice = sender_key(1);

            // 1 expired inline message at t = 1_000 (header 4 + size 10 + init 6 = 20 bytes).
            store
                .append(
                    &alice,
                    b"hdr1",
                    &Content::Inline(vec![1; 10]),
                    10,
                    Some(b"init01"),
                    None,
                    None,
                    1_000,
                )
                .unwrap();
            // 3 live inline messages at t = 20_000, each 20 bytes total (hdr 4 + body 10 + init 6).
            for seq in 2..=4u8 {
                store
                    .append(
                        &alice,
                        b"hdr!",
                        &Content::Inline(vec![seq; 10]),
                        10,
                        Some(b"init!!"),
                        None,
                        None,
                        20_000,
                    )
                    .unwrap();
            }

            // At now = 25_000, cutoff = 15_000: seq 1 is excluded.
            // With max_size = 5 (smaller than 1st row's 20 bytes), still returns the 1st live row.
            let first_only = store.read(&alice, 0, 10, 5, 25_000).unwrap();
            assert_eq!(first_only.len(), 1);
            assert_eq!(first_only[0].sequence, 2);
            assert_eq!(
                first_only[0].initial_message.as_deref(),
                Some(b"init!!".as_slice())
            );

            // With max_size = 45, fits 2 rows (40 <= 45) but stops before 3rd (60 > 45).
            let two_rows = store.read(&alice, 0, 10, 45, 25_000).unwrap();
            assert_eq!(
                two_rows.iter().map(|r| r.sequence).collect::<Vec<_>>(),
                vec![2, 3]
            );

            // Cursor `after = 3` returns seq 4.
            let tail = store.read(&alice, 3, 10, 1024, 25_000).unwrap();
            assert_eq!(tail.iter().map(|r| r.sequence).collect::<Vec<_>>(), vec![4]);

            // MAX_READ_R2_OBJECTS (40) cap across 45 R2 messages.
            let bob = sender_key(2);
            for i in 1..=45u32 {
                store
                    .append(
                        &bob,
                        b"h",
                        &Content::Object(format!("messages/r2-{i}")),
                        16,
                        None,
                        None,
                        None,
                        20_000,
                    )
                    .unwrap();
            }
            let r2_page1 = store.read(&bob, 0, 100, 10 << 20, 25_000).unwrap();
            assert_eq!(r2_page1.len(), MAX_READ_R2_OBJECTS);
            assert_eq!(
                r2_page1.last().unwrap().sequence,
                MAX_READ_R2_OBJECTS as u64
            );

            let r2_page2 = store
                .read(&bob, MAX_READ_R2_OBJECTS as u64, 100, 10 << 20, 25_000)
                .unwrap();
            assert_eq!(r2_page2.len(), 5);
            assert_eq!(r2_page2[0].sequence, 41);
            assert_eq!(r2_page2[4].sequence, 45);
        }

        #[test]
        fn delete_delivered_atomic_enqueues_pending_r2_prunes_queue_and_advances_sequence_floor() {
            let env = TestIdentity::new(100_000);
            let store = env.store();
            store.ensure_v2_tables().unwrap();

            let alice = sender_key(1);
            let h1 = hash_n(0x11);
            let h2 = hash_n(0x22);
            let h3 = hash_n(0x33);

            // Seq 1: inline (hdr 2 + body 8 = 10 bytes).
            store
                .append(
                    &alice,
                    b"h1",
                    &Content::Inline(vec![1; 8]),
                    8,
                    None,
                    Some(&h1),
                    None,
                    1_000,
                )
                .unwrap();
            // Seq 2: R2 object (hdr 2 + size 100 = 102 bytes).
            store
                .append(
                    &alice,
                    b"h2",
                    &Content::Object("messages/obj-2".into()),
                    100,
                    None,
                    Some(&h2),
                    None,
                    1_000,
                )
                .unwrap();
            // Seq 3: R2 object (hdr 2 + size 200 = 202 bytes).
            store
                .append(
                    &alice,
                    b"h3",
                    &Content::Object("messages/obj-3".into()),
                    200,
                    None,
                    Some(&h3),
                    None,
                    1_000,
                )
                .unwrap();

            assert_eq!(
                store
                    .delivered_objects(&alice, &[h1.clone(), h2.clone()])
                    .unwrap(),
                vec!["messages/obj-2".to_string()]
            );

            // Partial atomic delete of seq 1 + seq 2 leaves seq 3 in queue.
            let r2_keys = store
                .commit_delete_delivered_atomic(&alice, &[h1, h2], 5_000)
                .unwrap();
            assert_eq!(r2_keys, vec!["messages/obj-2".to_string()]);
            assert_eq!(
                store.list_pending_r2_deletes(10).unwrap(),
                vec!["messages/obj-2".to_string()]
            );

            let st = stats(&env);
            assert_eq!(st.queue_count, 1);
            assert_eq!(st.total_bytes, 202);
            assert_eq!(st.sequence_floor, 0);

            // Clearing pending R2 delete removes it.
            store.clear_pending_r2_deletes(&r2_keys).unwrap();
            assert!(store.list_pending_r2_deletes(10).unwrap().is_empty());

            // Deleting last remaining message (seq 3) prunes the empty queue row and raises
            // `sequence_floor = 3`.
            let r2_last = store
                .commit_delete_delivered_atomic(&alice, &[h3], 6_000)
                .unwrap();
            assert_eq!(r2_last, vec!["messages/obj-3".to_string()]);
            let st_empty = stats(&env);
            assert_eq!(st_empty.queue_count, 0);
            assert_eq!(st_empty.total_bytes, 0);
            assert_eq!(st_empty.sequence_floor, 3);

            let q_after: Option<QueueStateRow> = env
                .sql
                .query_opt(
                    "SELECT last_sequence, message_count, total_bytes FROM queues WHERE sender = ?",
                    params![alice.as_slice()].unwrap(),
                )
                .unwrap();
            assert!(q_after.is_none());

            // Next append from alice MUST start at sequence 4 (never reusing 1..=3).
            let next = store
                .append(
                    &alice,
                    b"h4",
                    &Content::Inline(b"new".to_vec()),
                    3,
                    None,
                    None,
                    None,
                    7_000,
                )
                .unwrap();
            assert!(matches!(next, AppendOutcome::Appended(4)));
        }

        #[test]
        fn expire_dedup_prunes_expired_tombstones_and_updates_dedup_counts() {
            let env = TestIdentity::new(100_000);
            let store = env.store();
            store.ensure_v2_tables().unwrap();

            let alice = sender_key(1);
            let bob = sender_key(2);

            // Alice: two tombstones at t=1_000 and t=5_000.
            store
                .append(
                    &alice,
                    b"h",
                    &Content::Inline(b"a".to_vec()),
                    1,
                    None,
                    None,
                    Some(&[1u8; 16]),
                    1_000,
                )
                .unwrap();
            store
                .append(
                    &alice,
                    b"h",
                    &Content::Inline(b"b".to_vec()),
                    1,
                    None,
                    None,
                    Some(&[2u8; 16]),
                    5_000,
                )
                .unwrap();
            // Bob: one tombstone at t=1_000.
            store
                .append(
                    &bob,
                    b"h",
                    &Content::Inline(b"c".to_vec()),
                    1,
                    None,
                    None,
                    Some(&[3u8; 16]),
                    1_000,
                )
                .unwrap();

            // Expire at t = 1_000 + DEDUP_TTL_MS -> expires t=1_000 entries (alice: 1 left, bob: deleted).
            store.expire_dedup(1_000 + DEDUP_TTL_MS).unwrap();

            let alice_count: CountRow = env
                .sql
                .query_one(
                    "SELECT count FROM dedup_counts WHERE sender = ?",
                    params![alice.as_slice()].unwrap(),
                )
                .unwrap();
            assert_eq!(alice_count.count, 1);

            let bob_count: Option<CountRow> = env
                .sql
                .query_opt(
                    "SELECT count FROM dedup_counts WHERE sender = ?",
                    params![bob.as_slice()].unwrap(),
                )
                .unwrap();
            assert!(bob_count.is_none());

            // Expire remaining tombstone.
            store.expire_dedup(5_000 + DEDUP_TTL_MS).unwrap();
            let remaining: CountRow = env
                .sql
                .query_one("SELECT count(*) AS count FROM mailbox_dedup", vec![])
                .unwrap();
            assert_eq!(remaining.count, 0);
        }

        #[test]
        fn expire_messages_handles_inline_initials_and_batched_r2_json_each_cleanup() {
            let retention = 10_000;
            let env = TestIdentity::new(retention);
            let store = env.store();
            store.ensure_v2_tables().unwrap();

            let alice = sender_key(1);
            let bob = sender_key(2);

            // Expired inline (t = 1_000, 12 bytes) + fresh inline (t = 20_000, 14 bytes) for alice.
            store
                .append(
                    &alice,
                    b"hh",
                    &Content::Inline(vec![1; 10]),
                    10,
                    None,
                    None,
                    None,
                    1_000,
                )
                .unwrap();
            store
                .append(
                    &alice,
                    b"hhhh",
                    &Content::Inline(vec![2; 10]),
                    10,
                    None,
                    None,
                    None,
                    20_000,
                )
                .unwrap();
            // Expired R2 (t = 2_000, 52 bytes) for bob and expired R2 (t = 2_000, 62 bytes) for alice.
            store
                .append(
                    &bob,
                    b"bh",
                    &Content::Object("messages/bob-exp".into()),
                    50,
                    None,
                    None,
                    None,
                    2_000,
                )
                .unwrap();
            store
                .append(
                    &alice,
                    b"ah",
                    &Content::Object("messages/alice-exp".into()),
                    60,
                    None,
                    None,
                    None,
                    2_000,
                )
                .unwrap();
            // Expired PQ initial message (t = 1_000) + fresh PQ initial message (t = 20_000).
            let mk_init = |marker: u8| InitialMessageV2Wire {
                id: 0,
                version: 2,
                sender: vec![marker; 32],
                ephemeral_key: vec![2; 32],
                signed_prekey: vec![3; 32],
                one_time_prekey: None,
                header: b"h".to_vec(),
                content: b"c".to_vec(),
                pq_suite: Some(1),
                pq_last_resort: false,
                pq_prekey_id: Some(vec![marker; 8]),
                pq_ciphertext: Some(vec![9; 16]),
                manifest_digest: None,
            };
            let expired_init_id = store
                .add_initial_message_v2(&mk_init(1), 10, 1_000)
                .unwrap()
                .unwrap();
            let fresh_init_id = store
                .add_initial_message_v2(&mk_init(2), 10, 20_000)
                .unwrap()
                .unwrap();

            // Phase 1: expire inline messages and initial messages at now = 25_000 (cutoff = 15_000).
            store.expire_inline_and_initials(25_000).unwrap();

            // Alice's expired inline is gone; fresh inline + expired R2 remain.
            let alice_rows = store.read(&alice, 0, 10, 1024, 25_000).unwrap();
            assert_eq!(alice_rows.len(), 1);
            assert_eq!(alice_rows[0].sequence, 2);

            // Expired initial_messages AND its initial_messages_pq orphan row are gone; fresh stays.
            let remaining_inits = store.list_initial_messages(10, 25_000).unwrap();
            assert_eq!(remaining_inits.len(), 1);
            assert_eq!(remaining_inits[0].id, fresh_init_id);
            let pq_left: CountRow = env
                .sql
                .query_one(
                    "SELECT count(*) AS count FROM initial_messages_pq WHERE initial_message_id = ?",
                    params![expired_init_id].unwrap(),
                )
                .unwrap();
            assert_eq!(pq_left.count, 0);

            // Phase 2: list and batch-delete expired R2 messages via json_each + unhex.
            let expired_r2 = store.list_expired_r2_messages(25_000, 500).unwrap();
            assert_eq!(expired_r2.len(), 2);
            store.delete_expired_r2_messages(&expired_r2).unwrap();

            // Bob's queue is pruned (sequence_floor >= 1), Alice retains only her fresh inline (14 bytes).
            let final_stats = stats(&env);
            assert_eq!(final_stats.queue_count, 1);
            assert_eq!(final_stats.total_bytes, 14);
            assert!(final_stats.sequence_floor >= 1);
            assert!(
                store
                    .list_expired_r2_messages(25_000, 500)
                    .unwrap()
                    .is_empty()
            );
        }

        #[test]
        fn append_rolls_back_queues_and_recipient_stats_on_mid_transaction_error() {
            let env = TestIdentity::new(100_000);
            let store = env.store();
            store.ensure_v2_tables().unwrap();

            let alice = sender_key(1);
            // Seed one good message so we verify rollback restores prior non-empty state too.
            store
                .append(
                    &alice,
                    b"ok",
                    &Content::Inline(b"1234".to_vec()),
                    4,
                    None,
                    None,
                    None,
                    1_000,
                )
                .unwrap();
            let stats_before = stats(&env);
            assert_eq!(stats_before.queue_count, 1);
            assert_eq!(stats_before.total_bytes, 6);

            // Install a SQLite trigger that aborts AFTER `queues` and `recipient_stats` have
            // already been updated inside `append`'s `transaction_sync`.
            env.sql
                .exec_batch(
                    "CREATE TRIGGER fail_messages_insert BEFORE INSERT ON messages \
                     BEGIN SELECT RAISE(ABORT, 'injected mid-tx failure'); END;",
                )
                .unwrap();

            let err = store
                .append(
                    &sender_key(2),
                    b"hdr",
                    &Content::Inline(b"boom".to_vec()),
                    4,
                    None,
                    None,
                    Some(&[9u8; 16]),
                    2_000,
                )
                .unwrap_err();
            assert!(err.to_string().contains("injected mid-tx failure"));

            // Every earlier write inside `append` (queues, recipient_stats, dedup_counts) rolled back!
            let stats_after = stats(&env);
            assert_eq!(stats_after.queue_count, 1);
            assert_eq!(stats_after.total_bytes, 6);

            let bob_queue: Option<QueueStateRow> = env
                .sql
                .query_opt(
                    "SELECT last_sequence, message_count, total_bytes FROM queues WHERE sender = ?",
                    params![sender_key(2).as_slice()].unwrap(),
                )
                .unwrap();
            assert!(bob_queue.is_none());

            let alice_queue: QueueStateRow = env
                .sql
                .query_one(
                    "SELECT last_sequence, message_count, total_bytes FROM queues WHERE sender = ?",
                    params![alice.as_slice()].unwrap(),
                )
                .unwrap();
            assert_eq!(alice_queue.last_sequence, 1);
            assert_eq!(alice_queue.message_count, 1);
            assert_eq!(alice_queue.total_bytes, 6);
        }

        #[test]
        fn dedup_tombstone_cap_evicts_delivered_entries_before_live_ones_and_legacy_delete_filters_objects()
         {
            let env = TestIdentity::new(100_000);
            let store = env.store();
            store.ensure_v2_tables().unwrap();

            let alice = sender_key(1);
            let cid_delivered = [1u8; 16];
            let cid_live = [2u8; 16];
            let cid_new = [3u8; 16];

            // Seq 1 (delivered inline) + Seq 2 (live R2) + Seq 3 (live R2 not in delete list).
            store
                .append(
                    &alice,
                    b"h",
                    &Content::Inline(b"1".to_vec()),
                    1,
                    None,
                    Some(&hash_n(1)),
                    Some(&cid_delivered),
                    1_000,
                )
                .unwrap();
            store
                .append(
                    &alice,
                    b"h",
                    &Content::Object("messages/obj-live".into()),
                    10,
                    None,
                    Some(&hash_n(2)),
                    Some(&cid_live),
                    2_000,
                )
                .unwrap();
            store
                .append(
                    &alice,
                    b"h",
                    &Content::Object("messages/obj-keep".into()),
                    10,
                    None,
                    Some(&hash_n(3)),
                    None,
                    3_000,
                )
                .unwrap();

            // Legacy delete_delivered deletes seq 1 (inline) and leaves seq 3 because obj-keep
            // is not listed in `objects`.
            store
                .delete_delivered(&alice, &[hash_n(1), hash_n(3)], &[])
                .unwrap();
            let after_legacy = store.read(&alice, 0, 10, 1024, 3_000).unwrap();
            assert_eq!(
                after_legacy.iter().map(|r| r.sequence).collect::<Vec<_>>(),
                vec![2, 3]
            );

            // Simulate reaching MAX_DEDUP_TOMBSTONES_PER_QUEUE so the next append triggers
            // `record_tombstone`'s eviction query (delivered tombstone seq 1 evicted before live seq 2).
            env.sql
                .exec(
                    "UPDATE dedup_counts SET count = ? WHERE sender = ?",
                    params![MAX_DEDUP_TOMBSTONES_PER_QUEUE, alice.as_slice()].unwrap(),
                )
                .unwrap();
            store
                .append(
                    &alice,
                    b"h",
                    &Content::Inline(b"new".to_vec()),
                    3,
                    None,
                    None,
                    Some(&cid_new),
                    4_000,
                )
                .unwrap();

            // Delivered cid_delivered was evicted; live cid_live and newly inserted cid_new remain!
            assert!(
                env.sql
                    .query_opt::<DedupRow>(
                        "SELECT sequence, expires_at FROM mailbox_dedup \
                         WHERE sender = ? AND client_message_id = ?",
                        params![alice.as_slice(), cid_delivered.as_slice()].unwrap()
                    )
                    .unwrap()
                    .is_none()
            );
            assert!(
                env.sql
                    .query_opt::<DedupRow>(
                        "SELECT sequence, expires_at FROM mailbox_dedup \
                         WHERE sender = ? AND client_message_id = ?",
                        params![alice.as_slice(), cid_live.as_slice()].unwrap()
                    )
                    .unwrap()
                    .is_some()
            );
            assert!(
                env.sql
                    .query_opt::<DedupRow>(
                        "SELECT sequence, expires_at FROM mailbox_dedup \
                         WHERE sender = ? AND client_message_id = ?",
                        params![alice.as_slice(), cid_new.as_slice()].unwrap()
                    )
                    .unwrap()
                    .is_some()
            );
        }
    }
}
