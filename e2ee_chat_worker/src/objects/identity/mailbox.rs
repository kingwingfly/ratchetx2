//! Per-sender message queues and idempotent delivery receipts.

use storage::{MAX_QUEUE_BYTES, MAX_QUEUE_MESSAGES, MAX_SAFE_INTEGER};
use worker::{Date, Error, Result, SqlStorage, SqlStorageValue};

use super::{Identity, rows::*};
use crate::objects::{AppendOutcome, Content, StoredRow, blob, checked_integer};

pub(super) const DEDUP_TTL_MS: u64 = 24 * 60 * 60 * 1000;
pub(super) const MAX_DEDUP_TOMBSTONES_PER_QUEUE: u64 = 4096;
/// Maximum R2-backed message rows returned in a single read page so `Store::read` stays safely
/// below Cloudflare Workers Free-plan subrequest limits (50/invocation) even when `delete_delivered`
/// runs in the same `FetchSigned` call.
const MAX_READ_R2_OBJECTS: usize = 40;

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
        let now_val = checked_integer(now)?;
        let dedup_id = {
            let sql = self.sql();
            if client_message_id.is_some() && crate::objects::has_table(&sql, "mailbox_dedup")? {
                self.ensure_mailbox_dedup_schema(&sql)?;
                client_message_id
            } else {
                None
            }
        };

        self.transaction_sync(|sql| {
            if let Some(cid) = dedup_id {
                sql.exec(
                    "DELETE FROM mailbox_dedup WHERE sender = ? AND expires_at <= ?",
                    vec![blob(sender), now_val.clone()],
                )?;
                let existing = sql
                    .exec(
                        "SELECT sequence FROM mailbox_dedup \
                         WHERE sender = ? AND client_message_id = ? AND expires_at > ?",
                        vec![blob(sender), blob(cid), now_val.clone()],
                    )?
                    .to_array::<SequenceRow>()?;
                if let Some(row) = existing.first() {
                    return Ok(AppendOutcome::Deduplicated(row.sequence));
                }
            }

            // Enforce per-queue row and total byte caps BEFORE allocating sequence or inserting.
            let incoming_bytes = (header.len() as u64)
                .saturating_add(size)
                .saturating_add(initial_message.map_or(0, |m| m.len() as u64));
            let usage: QueueUsageRow = sql
                .exec(
                    "SELECT count(*) AS count, \
                     coalesce(sum(length(header) + size + coalesce(length(initial_message), 0)), 0) AS total_bytes \
                     FROM messages WHERE sender = ?",
                    vec![blob(sender)],
                )?
                .one()?;
            if usage.count >= MAX_QUEUE_MESSAGES as u64
                || usage.total_bytes.saturating_add(incoming_bytes) > MAX_QUEUE_BYTES
            {
                return Ok(AppendOutcome::LimitExceeded);
            }

            let queue: SequenceRow = sql
                .exec(
                    "INSERT INTO queues (sender, last_sequence) VALUES (?, 1) \
                     ON CONFLICT (sender) DO UPDATE SET last_sequence = last_sequence + 1 \
                     RETURNING last_sequence AS sequence",
                    vec![blob(sender)],
                )?
                .one()?;
            let (inline, object) = match content {
                Content::Inline(content) => (blob(content), SqlStorageValue::Null),
                Content::Object(object) => (SqlStorageValue::Null, object.as_str().into()),
            };
            sql.exec(
                "INSERT INTO messages (sender, sequence, header, content, object, size, \
                 initial_message, delivery_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    blob(sender),
                    checked_integer(queue.sequence)?,
                    blob(header),
                    inline,
                    object,
                    checked_integer(size)?,
                    initial_message.map_or(SqlStorageValue::Null, blob),
                    delivery_hash.map_or(SqlStorageValue::Null, blob),
                    now_val,
                ],
            )?;
            if let Some(cid) = dedup_id {
                record_tombstone(sql, sender, cid, queue.sequence, now)?;
            }
            Ok(AppendOutcome::Appended(queue.sequence))
        })
    }

    /// Reads messages incrementally without materializing all rows before enforcing `max_size`,
    /// counting `header.len() + initial_message.len() + size` accurately.
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
        // Step 1: query lightweight integer metadata only (no BLOBs materialized!).
        let metas: Vec<MessageMetaRow> = sql
            .exec(
                "SELECT sequence, length(header) AS header_len, size, \
                 coalesce(length(initial_message), 0) AS init_len, \
                 (object IS NOT NULL) AS is_object \
                 FROM messages WHERE sender = ? AND sequence > ? ORDER BY sequence LIMIT ?",
                vec![
                    blob(sender),
                    checked_integer(after)?,
                    checked_integer(limit.into())?,
                ],
            )?
            .to_array()?;
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

        // Step 2: materialize ONLY the exact rows that fit within the byte budget.
        let rows: Vec<MessageRow> = sql
            .exec(
                "SELECT sequence, header, content, object, initial_message FROM messages \
                 WHERE sender = ? AND sequence > ? AND sequence <= ? ORDER BY sequence",
                vec![
                    blob(sender),
                    checked_integer(after)?,
                    checked_integer(cutoff_sequence)?,
                ],
            )?
            .to_array()?;
        let mut page = Vec::with_capacity(rows.len());
        for row in rows {
            let content = match (row.content, row.object) {
                (Some(content), _) => Content::Inline(content),
                (None, Some(object)) => Content::Object(object),
                (None, None) => return Err(Error::RustError("a message without content".into())),
            };
            page.push(StoredRow {
                sequence: row.sequence,
                header: row.header,
                content,
                initial_message: row.initial_message,
            });
        }
        Ok(page)
    }

    pub(super) fn delivered_objects(
        &self,
        sender: &[u8],
        hashes: &[Vec<u8>],
    ) -> Result<Vec<String>> {
        if !self.has_tables()? {
            return Ok(vec![]);
        }
        let rows: Vec<ObjectRow> = self
            .sql()
            .exec(
                "SELECT object FROM messages WHERE sender = ? AND object IS NOT NULL \
                 AND delivery_hash IN (SELECT unhex(value) FROM json_each(?))",
                vec![blob(sender), hashes_json(hashes).into()],
            )?
            .to_array()?;
        Ok(rows.into_iter().filter_map(|row| row.object).collect())
    }

    pub(super) fn delete_delivered(
        &self,
        sender: &[u8],
        hashes: &[Vec<u8>],
        objects: &[String],
    ) -> Result<()> {
        if !self.has_tables()? {
            return Ok(());
        }
        let objects =
            serde_json::to_string(objects).map_err(|e| Error::RustError(e.to_string()))?;
        self.sql().exec(
            "DELETE FROM messages WHERE sender = ? \
             AND delivery_hash IN (SELECT unhex(value) FROM json_each(?)) \
             AND (object IS NULL OR object IN (SELECT value FROM json_each(?)))",
            vec![blob(sender), hashes_json(hashes).into(), objects.into()],
        )?;
        Ok(())
    }
}

fn record_tombstone(
    sql: &SqlStorage,
    sender: &[u8],
    cid: &[u8],
    sequence: u64,
    now: u64,
) -> Result<()> {
    let count: CountRow = sql
        .exec(
            "SELECT count(*) AS count FROM mailbox_dedup WHERE sender = ?",
            vec![blob(sender)],
        )?
        .one()?;
    if count.count >= MAX_DEDUP_TOMBSTONES_PER_QUEUE {
        let to_evict = count.count - MAX_DEDUP_TOMBSTONES_PER_QUEUE + 1;
        sql.exec(
            "DELETE FROM mailbox_dedup WHERE sender = ? AND client_message_id IN ( \
                SELECT d.client_message_id FROM mailbox_dedup d WHERE d.sender = ? \
                ORDER BY CASE WHEN EXISTS (SELECT 1 FROM messages m \
                    WHERE m.sender = d.sender AND m.sequence = d.sequence) THEN 1 ELSE 0 END ASC, \
                    d.created_at ASC, d.sequence ASC LIMIT ?)",
            vec![blob(sender), blob(sender), checked_integer(to_evict)?],
        )?;
    }
    let expires_at = now.saturating_add(DEDUP_TTL_MS).min(MAX_SAFE_INTEGER);
    sql.exec(
        "INSERT INTO mailbox_dedup (sender, client_message_id, sequence, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?) ON CONFLICT (sender, client_message_id) DO UPDATE SET \
         sequence = excluded.sequence, created_at = excluded.created_at, \
         expires_at = excluded.expires_at",
        vec![
            blob(sender),
            blob(cid),
            checked_integer(sequence)?,
            checked_integer(now)?,
            checked_integer(expires_at)?,
        ],
    )?;
    Ok(())
}

/// `hashes` as a JSON array of hex strings, which need no escaping, for `json_each`.
fn hashes_json(hashes: &[Vec<u8>]) -> String {
    let quoted: Vec<_> = hashes
        .iter()
        .map(|hash| format!("\"{}\"", crate::hex(hash)))
        .collect();
    format!("[{}]", quoted.join(","))
}
