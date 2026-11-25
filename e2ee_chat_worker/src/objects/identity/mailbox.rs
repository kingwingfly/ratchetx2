//! Per-sender message queues, recipient-wide O(1) storage caps, and durable R2 delivery cleanup.

use storage::{MAX_QUEUE_BYTES, MAX_QUEUE_MESSAGES, MAX_SAFE_INTEGER};
use worker::{Date, Error, Result, SqlStorage, console_error};

use super::{AlarmUpdate, Identity, rows::*};
use crate::objects::{
    AppendOutcome, Content, RETRY_ALARM, StoredRow,
    sql::{Blob, exec, params, query, query_opt},
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

impl Identity {
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
    ) -> Result<AppendOutcome> {
        let now = Date::now().as_millis();
        self.transaction_sync(|sql| {
            let mut replacing_expired_dedup = false;
            if let Some(cid) = client_message_id
                && let Some(existing) = query_opt::<DedupRow>(
                    sql,
                    "SELECT sequence, expires_at FROM mailbox_dedup \
                     WHERE sender = ? AND client_message_id = ?",
                    params![sender, cid]?,
                )?
            {
                if existing.expires_at > now {
                    return Ok(AppendOutcome::Deduplicated(existing.sequence));
                }
                replacing_expired_dedup = true;
            }

            // Enforce per-queue and per-recipient row/byte caps in O(1) using maintained counters
            // BEFORE allocating a sequence number or inserting any row.
            let incoming_bytes = (header.len() as u64)
                .saturating_add(size)
                .saturating_add(initial_message.map_or(0, |m| m.len() as u64));
            let stats = query_opt::<RecipientStatsRow>(
                sql,
                "SELECT queue_count, total_bytes, sequence_floor FROM recipient_stats WHERE only = 0",
                vec![],
            )?
            .unwrap_or(RecipientStatsRow {
                queue_count: 0,
                total_bytes: 0,
                sequence_floor: 0,
            });
            let queue = query_opt::<QueueStateRow>(
                sql,
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
            exec(
                sql,
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
            exec(
                sql,
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
            exec(
                sql,
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
                    now
                ]?,
            )?;
            if let Some(cid) = client_message_id {
                record_tombstone(sql, sender, cid, next_sequence, now, replacing_expired_dedup)?;
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
    ) -> Result<Vec<StoredRow>> {
        if !self.has_tables()? || limit == 0 || after > MAX_SAFE_INTEGER {
            return Ok(vec![]);
        }
        let sql = self.sql();
        let cutoff = Date::now().as_millis().saturating_sub(self.retention());
        // Step 1: query lightweight integer metadata only (no BLOBs materialized!).
        let metas: Vec<MessageMetaRow> = query(
            &sql,
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
        let rows: Vec<MessageRow> = query(
            &sql,
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
        let rows: Vec<ObjectRow> = query(
            &self.sql(),
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
        self.transaction_sync(|sql| {
            let deleted: Vec<DeletedMessageRow> = query(
                sql,
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
    /// `pending_r2_deletes` before attempting immediate R2 deletion.
    ///
    /// If R2 deletion fails transiently, the message rows are already deleted (no stale receipts or
    /// quota retention) and the armed DO alarm retries `pending_r2_deletes`.
    pub(super) async fn delete_delivered_atomic(
        &self,
        sender: &[u8],
        hashes: &[Vec<u8>],
    ) -> Result<()> {
        if hashes.is_empty() || !self.has_tables()? {
            return Ok(());
        }
        self.ensure_v2_tables()?;
        let now = Date::now().as_millis();
        // Arm the retry alarm BEFORE committing `pending_r2_deletes` when matching R2 objects exist
        // (DO storage ops keep the input gate closed, so no concurrent request interleaves).
        let has_r2 = !self.delivered_objects(sender, hashes)?.is_empty();
        if has_r2 {
            self.update_alarm(AlarmUpdate::PullEarlier(now.saturating_add(RETRY_ALARM)))
                .await?;
        }
        let hashes_param = hashes_json(hashes);
        let r2_objects: Vec<String> = self.transaction_sync(|sql| {
            let deleted: Vec<DeletedMessageRow> = query(
                sql,
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
                    exec(
                        sql,
                        "INSERT OR IGNORE INTO pending_r2_deletes (object, created_at) VALUES (?, ?)",
                        params![object.as_str(), now]?,
                    )?;
                    objects.push(object);
                }
            }
            subtract_queue_usage(sql, sender, count, bytes)?;
            Ok(objects)
        })?;
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
                let objects_json = serde_json::to_string(&r2_objects)
                    .map_err(|e| Error::RustError(e.to_string()))?;
                exec(
                    &self.sql(),
                    "DELETE FROM pending_r2_deletes WHERE object IN (SELECT value FROM json_each(?))",
                    params![objects_json]?,
                )?;
            }
            Err(e) => {
                console_error!(
                    "cannot delete delivered R2 objects immediately; queued for alarm retry: {e}"
                );
            }
        }
        Ok(())
    }

    /// Expires `mailbox_dedup` rows and keeps `dedup_counts` synchronized in one transaction.
    pub(super) fn expire_dedup(&self, now: u64) -> Result<()> {
        self.transaction_sync(|sql| {
            let expired: Vec<SenderCountRow> = query(
                sql,
                "SELECT sender, count(*) AS count FROM mailbox_dedup \
                 WHERE expires_at <= ? GROUP BY sender",
                params![now]?,
            )?;
            if expired.is_empty() {
                return Ok(());
            }
            exec(
                sql,
                "DELETE FROM mailbox_dedup WHERE expires_at <= ?",
                params![now]?,
            )?;
            for row in expired {
                adjust_dedup_count(sql, &row.sender, -(row.count as i64))?;
            }
            Ok(())
        })
    }
}

/// Decrements per-queue and recipient-wide byte/message counters after rows are deleted from
/// `messages`, pruning empty `queues` rows while raising `recipient_stats.sequence_floor`.
pub(super) fn subtract_queue_usage(
    sql: &SqlStorage,
    sender: &[u8],
    removed_count: u64,
    removed_bytes: u64,
) -> Result<()> {
    if removed_count == 0 {
        return Ok(());
    }
    let Some(queue) = query_opt::<QueueStateRow>(
        sql,
        "SELECT last_sequence, message_count, total_bytes FROM queues WHERE sender = ?",
        params![sender]?,
    )?
    else {
        return Ok(());
    };
    let next_count = queue.message_count.saturating_sub(removed_count);
    if next_count == 0 {
        exec(sql, "DELETE FROM queues WHERE sender = ?", params![sender]?)?;
        exec(
            sql,
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
        exec(
            sql,
            "UPDATE queues SET message_count = ?, total_bytes = ? WHERE sender = ?",
            params![next_count, next_bytes, sender]?,
        )?;
        exec(
            sql,
            "INSERT INTO recipient_stats (only, queue_count, total_bytes, sequence_floor) \
             VALUES (0, 1, 0, 0) \
             ON CONFLICT (only) DO UPDATE SET \
             total_bytes = max(0, recipient_stats.total_bytes - ?)",
            params![actual_removed]?,
        )?;
    }
    Ok(())
}

fn adjust_dedup_count(sql: &SqlStorage, sender: &[u8], delta: i64) -> Result<()> {
    let current = query_opt::<CountRow>(
        sql,
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
        exec(
            sql,
            "DELETE FROM dedup_counts WHERE sender = ?",
            params![sender]?,
        )?;
    } else {
        exec(
            sql,
            "INSERT INTO dedup_counts (sender, count) VALUES (?, ?) \
             ON CONFLICT (sender) DO UPDATE SET count = excluded.count",
            params![sender, next]?,
        )?;
    }
    Ok(())
}

fn record_tombstone(
    sql: &SqlStorage,
    sender: &[u8],
    cid: &[u8],
    sequence: u64,
    now: u64,
    replacing_existing: bool,
) -> Result<()> {
    if !replacing_existing {
        let mut count = query_opt::<CountRow>(
            sql,
            "SELECT count FROM dedup_counts WHERE sender = ?",
            params![sender]?,
        )?
        .map_or(0, |row| row.count);
        if count >= MAX_DEDUP_TOMBSTONES_PER_QUEUE {
            // Reclaim expired tombstones for this sender before evicting live entries.
            exec(
                sql,
                "DELETE FROM mailbox_dedup WHERE sender = ? AND expires_at <= ?",
                params![sender, now]?,
            )?;
            let pruned = query_opt::<CountRow>(sql, "SELECT changes() AS count", vec![])?
                .map_or(0, |row| row.count);
            count = count.saturating_sub(pruned);
            if count >= MAX_DEDUP_TOMBSTONES_PER_QUEUE {
                let to_evict = count - MAX_DEDUP_TOMBSTONES_PER_QUEUE + 1;
                exec(
                    sql,
                    "DELETE FROM mailbox_dedup WHERE sender = ? AND client_message_id IN ( \
                        SELECT d.client_message_id FROM mailbox_dedup d WHERE d.sender = ? \
                        ORDER BY CASE WHEN EXISTS (SELECT 1 FROM messages m \
                            WHERE m.sender = d.sender AND m.sequence = d.sequence) THEN 1 ELSE 0 END ASC, \
                            d.created_at ASC, d.sequence ASC LIMIT ?)",
                    params![sender, sender, to_evict]?,
                )?;
                let evicted = query_opt::<CountRow>(sql, "SELECT changes() AS count", vec![])?
                    .map_or(0, |row| row.count);
                count = count.saturating_sub(evicted);
            }
        }
        let next_count = count.saturating_add(1);
        exec(
            sql,
            "INSERT INTO dedup_counts (sender, count) VALUES (?, ?) \
             ON CONFLICT (sender) DO UPDATE SET count = excluded.count",
            params![sender, next_count]?,
        )?;
    }
    let expires_at = now.saturating_add(DEDUP_TTL_MS).min(MAX_SAFE_INTEGER);
    exec(
        sql,
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
}
