//! Unified sealed-sender-lite mailbox queue, recipient-versioned write-token grants, O(1) quotas,
//! monotonic prefix ACK, and `token_hash`-keyed deduplication (zero R2 dependency).

use std::collections::HashMap;

use protocol::MAX_CLOCK_SKEW;
use storage::{
    MAX_AUTHORIZED_PEERS, MAX_GRANTS_PER_PEER, MAX_QUEUE_BYTES, MAX_QUEUE_MESSAGES,
    MAX_RECIPIENT_BYTES, MAX_SAFE_INTEGER, MailboxPage, RegisterWriteTokenRecord,
    RevokeWriteTokenRecord, StoredMessage, WriteTokenHash,
};
use subtle::ConstantTimeEq;
use worker::Result;

use super::{IdentityStore, rows::*};
use crate::objects::{
    AckMessagesOutcome, AppendOutcome, ReadMailboxOutcome, RegisterWriteTokenOutcome,
    RevokeWriteTokenOutcome,
    sql::{SqlExec, checked_integer, params},
};

pub(super) const DEDUP_TTL_MS: u64 = 24 * 60 * 60 * 1000;
pub(super) const MAX_DEDUP_TOMBSTONES_PER_TOKEN: u64 = 4096;
/// Retention for empty revoked `peer_grants` tombstones: covers the full `2 * MAX_CLOCK_SKEW`
/// bidirectional `verify_recent` window plus a 1-minute safety margin (11 minutes) so a
/// pre-revocation `RegisterWriteToken` signed by a fast clock can never outlive its floor.
pub(super) const REVOCATION_TOMBSTONE_TTL_MS: u64 = 2 * MAX_CLOCK_SKEW + 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MailboxQuotaSnapshot {
    peer_message_count: u64,
    peer_bytes: u64,
    recipient_bytes: u64,
}

fn within_mailbox_quotas(snapshot: MailboxQuotaSnapshot, incoming_bytes: u64) -> bool {
    snapshot.peer_message_count < MAX_QUEUE_MESSAGES as u64
        && snapshot.peer_bytes.saturating_add(incoming_bytes) <= MAX_QUEUE_BYTES
        && snapshot.recipient_bytes.saturating_add(incoming_bytes) <= MAX_RECIPIENT_BYTES
}

/// Decrements `peer_grants.{message_count, total_bytes}` and `recipient_stats.{message_count,
/// total_bytes}` after rows are deleted from `messages` (by prefix ACK or retention expiry),
/// preserving `recipient_stats.last_sequence` monotonically.
pub(super) fn apply_deleted_usage<S: SqlExec>(
    sql: &S,
    deleted: Vec<DeletedPeerBytesRow>,
) -> Result<u64> {
    if deleted.is_empty() {
        return Ok(0);
    }
    let total_count = deleted.len() as u64;
    let mut total_bytes = 0u64;
    let mut by_peer: HashMap<Vec<u8>, (u64, u64)> = HashMap::new();
    for row in deleted {
        total_bytes = total_bytes.saturating_add(row.bytes);
        let entry = by_peer.entry(row.peer_slot_id.into_vec()).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.saturating_add(row.bytes);
    }
    for (peer_slot_id, (count, bytes)) in by_peer {
        sql.exec(
            "UPDATE peer_grants \
             SET message_count = max(0, message_count - ?), \
                 total_bytes = max(0, total_bytes - ?) \
             WHERE peer_slot_id = ?",
            params![count, bytes, peer_slot_id.as_slice()]?,
        )?;
    }
    sql.exec(
        "UPDATE recipient_stats \
         SET message_count = max(0, message_count - ?), \
             total_bytes = max(0, total_bytes - ?) \
         WHERE only = 0",
        params![total_count, total_bytes]?,
    )?;
    Ok(total_count)
}

/// Prunes empty revoked `peer_grants` tombstones once `revoked_at + REVOCATION_TOMBSTONE_TTL_MS < now_ms`.
pub(super) fn prune_expired_peer_grants_sql<S: SqlExec>(sql: &S, now_ms: u64) -> Result<()> {
    if now_ms <= REVOCATION_TOMBSTONE_TTL_MS {
        return Ok(());
    }
    let cutoff = now_ms - REVOCATION_TOMBSTONE_TTL_MS;
    sql.exec(
        "DELETE FROM peer_grants \
         WHERE revoked_at > 0 \
           AND revoked_at < ? \
           AND message_count = 0 \
           AND NOT EXISTS ( \
               SELECT 1 FROM write_tokens w WHERE w.peer_slot_id = peer_grants.peer_slot_id \
           )",
        params![cutoff]?,
    )
}

fn ack_messages_sql<S: SqlExec>(sql: &S, up_to_sequence: u64) -> Result<Option<u64>> {
    if up_to_sequence == 0 || up_to_sequence > MAX_SAFE_INTEGER {
        return Ok(None);
    }
    let last_sequence = sql
        .query_opt::<LastSequenceRow>(
            "SELECT last_sequence FROM recipient_stats WHERE only = 0",
            vec![],
        )?
        .map_or(0, |row| row.last_sequence);
    if up_to_sequence > last_sequence {
        return Ok(None);
    }
    let deleted: Vec<DeletedPeerBytesRow> = sql.query(
        "DELETE FROM messages WHERE sequence <= ? RETURNING peer_slot_id, bytes",
        params![up_to_sequence]?,
    )?;
    let count = apply_deleted_usage(sql, deleted)?;
    Ok(Some(count))
}

impl<S: SqlExec> IdentityStore<'_, S> {
    /// Returns `true` iff the identity's tables exist and `token_hash` matches a live grant
    /// (constant-time comparison). Used before arming expiry alarms so rejected `PushV2` calls
    /// never schedule alarms on idle recipients.
    pub(super) fn has_write_token(&self, token_hash: &WriteTokenHash) -> Result<bool> {
        if !self.has_tables()? {
            return Ok(false);
        }
        let Some(row) = self.sql.query_opt::<WriteTokenAuthRow>(
            "SELECT token_hash, peer_slot_id, grant_version \
             FROM write_tokens WHERE token_hash = ?",
            params![token_hash.as_slice()]?,
        )?
        else {
            return Ok(false);
        };
        if !bool::from(row.token_hash.as_ref().ct_eq(token_hash.as_slice())) {
            return Ok(false);
        }
        let Some(peer) = self.sql.query_opt::<PeerGrantRow>(
            "SELECT max_version, revoked_below_version, active_token_hash, \
             message_count, total_bytes \
             FROM peer_grants WHERE peer_slot_id = ?",
            params![row.peer_slot_id.as_ref()]?,
        )?
        else {
            return Ok(false);
        };
        Ok(row.grant_version > peer.revoked_below_version)
    }

    /// Auth-before-dedup unified append into `messages` authorized by `token_hash`.
    /// Never allocates DO tables for unknown identities or unauthorized/revoked tokens.
    pub(super) fn append_idempotent(
        &self,
        token_hash: &WriteTokenHash,
        header: &[u8],
        content: &[u8],
        initial_message: Option<&[u8]>,
        client_message_id: Option<&[u8; 16]>,
        now_ms: u64,
    ) -> Result<AppendOutcome> {
        if !self.has_tables()? {
            return Ok(AppendOutcome::WriteTokenRejected);
        }
        self.sql.transaction_sync(|sql| {
            // 1. Auth-before-dedup: verify `write_tokens` with constant-time comparison AND
            //    verify `grant_version > peer_grants.revoked_below_version` strictly BEFORE
            //    inspecting `mailbox_dedup`.
            let Some(token_row) = sql.query_opt::<WriteTokenAuthRow>(
                "SELECT token_hash, peer_slot_id, grant_version \
                 FROM write_tokens WHERE token_hash = ?",
                params![token_hash.as_slice()]?,
            )?
            else {
                return Ok(AppendOutcome::WriteTokenRejected);
            };
            if !bool::from(token_row.token_hash.as_ref().ct_eq(token_hash.as_slice())) {
                return Ok(AppendOutcome::WriteTokenRejected);
            }
            let peer_slot_id = token_row.peer_slot_id;
            let Some(peer) = sql.query_opt::<PeerGrantRow>(
                "SELECT max_version, revoked_below_version, active_token_hash, \
                 message_count, total_bytes \
                 FROM peer_grants WHERE peer_slot_id = ?",
                params![peer_slot_id.as_ref()]?,
            )?
            else {
                return Ok(AppendOutcome::WriteTokenRejected);
            };
            if token_row.grant_version <= peer.revoked_below_version {
                return Ok(AppendOutcome::WriteTokenRejected);
            }

            // 2. Deduplication lookup scoped to `(token_hash, client_message_id)`.
            let mut replacing_expired_dedup = false;
            if let Some(cid) = client_message_id
                && let Some(existing) = sql.query_opt::<DedupRow>(
                    "SELECT sequence, expires_at FROM mailbox_dedup \
                     WHERE token_hash = ? AND client_message_id = ?",
                    params![token_hash.as_slice(), cid.as_slice()]?,
                )?
            {
                if existing.expires_at > now_ms {
                    return Ok(AppendOutcome::Deduplicated(existing.sequence));
                }
                replacing_expired_dedup = true;
            }

            // 3. Enforce per-peer and recipient-wide quotas in O(1) before allocating sequence.
            let incoming_bytes = (header.len() as u64)
                .saturating_add(content.len() as u64)
                .saturating_add(initial_message.map_or(0, |m| m.len() as u64));
            let stats = sql
                .query_opt::<RecipientStatsRow>(
                    "SELECT last_sequence, total_bytes, authorized_peer_count \
                     FROM recipient_stats WHERE only = 0",
                    vec![],
                )?
                .unwrap_or(RecipientStatsRow {
                    last_sequence: 0,
                    total_bytes: 0,
                    authorized_peer_count: 0,
                });

            let quota = MailboxQuotaSnapshot {
                peer_message_count: peer.message_count,
                peer_bytes: peer.total_bytes,
                recipient_bytes: stats.total_bytes,
            };
            if !within_mailbox_quotas(quota, incoming_bytes) {
                return Ok(AppendOutcome::MailboxFull);
            }

            let Some(next_sequence) = stats
                .last_sequence
                .checked_add(1)
                .filter(|&seq| seq <= MAX_SAFE_INTEGER)
            else {
                return Ok(AppendOutcome::LimitExceeded);
            };

            // 4. Insert message row and update counters atomically.
            sql.exec(
                "INSERT INTO messages \
                 (sequence, peer_slot_id, token_hash, header, content, initial_message, bytes, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    next_sequence,
                    peer_slot_id.as_ref(),
                    token_hash.as_slice(),
                    header,
                    content,
                    initial_message,
                    incoming_bytes,
                    now_ms
                ]?,
            )?;
            sql.exec(
                "UPDATE peer_grants \
                 SET message_count = message_count + 1, total_bytes = total_bytes + ? \
                 WHERE peer_slot_id = ?",
                params![incoming_bytes, peer_slot_id.as_ref()]?,
            )?;
            sql.exec(
                "INSERT INTO recipient_stats \
                 (only, last_sequence, message_count, total_bytes, authorized_peer_count) \
                 VALUES (0, ?, 1, ?, ?) \
                 ON CONFLICT (only) DO UPDATE SET \
                 last_sequence = excluded.last_sequence, \
                 message_count = recipient_stats.message_count + 1, \
                 total_bytes = recipient_stats.total_bytes + ?",
                params![
                    next_sequence,
                    incoming_bytes,
                    stats.authorized_peer_count,
                    incoming_bytes
                ]?,
            )?;

            if let Some(cid) = client_message_id {
                record_tombstone(
                    sql,
                    token_hash,
                    cid,
                    next_sequence,
                    now_ms,
                    replacing_expired_dedup,
                )?;
            }
            Ok(AppendOutcome::Appended(next_sequence))
        })
    }

    /// Reads unexpired unified mailbox messages strictly after `after_sequence`, optionally
    /// atomically executing a piggybacked monotonic prefix ACK (`sequence <= ack_up_to_sequence`)
    /// first. Never allocates DO tables for unknown identities.
    pub(super) fn read_mailbox(
        &self,
        after_sequence: u64,
        limit: u32,
        max_size: u64,
        ack_up_to_sequence: u64,
        now_ms: u64,
    ) -> Result<ReadMailboxOutcome> {
        let _ = checked_integer(after_sequence)?;
        let _ = checked_integer(ack_up_to_sequence)?;
        if !self.has_tables()? {
            if ack_up_to_sequence > 0 {
                return Ok(ReadMailboxOutcome::InvalidAckSequence);
            }
            return Ok(ReadMailboxOutcome::Page(MailboxPage::default()));
        }

        let cutoff = now_ms.saturating_sub(self.retention_ms);
        self.sql.transaction_sync(|sql| {
            if ack_up_to_sequence > 0 && ack_messages_sql(sql, ack_up_to_sequence)?.is_none() {
                return Ok(ReadMailboxOutcome::InvalidAckSequence);
            }

            if limit == 0 {
                let any_more = sql
                    .query_opt::<SequenceRow>(
                        "SELECT sequence FROM messages \
                         WHERE sequence > ? AND created_at >= ? \
                         ORDER BY sequence LIMIT 1",
                        params![after_sequence, cutoff]?,
                    )?
                    .is_some();
                return Ok(ReadMailboxOutcome::Page(MailboxPage {
                    messages: vec![],
                    has_more: any_more,
                }));
            }

            // Step 1: lightweight metadata query (limit + 1 so `has_more` is exact).
            let query_limit = u64::from(limit).saturating_add(1);
            let metas: Vec<MessageMetaRow> = sql.query(
                "SELECT sequence, bytes FROM messages \
                 WHERE sequence > ? AND created_at >= ? \
                 ORDER BY sequence LIMIT ?",
                params![after_sequence, cutoff, query_limit]?,
            )?;
            if metas.is_empty() {
                return Ok(ReadMailboxOutcome::Page(MailboxPage::default()));
            }

            let mut total_bytes = 0u64;
            let mut cutoff_sequence = metas[0].sequence;
            let mut has_more = false;
            for (taken, meta) in metas.iter().enumerate() {
                if taken >= limit as usize {
                    has_more = true;
                    break;
                }
                let next_bytes = total_bytes.saturating_add(meta.bytes);
                if taken > 0 && next_bytes > max_size {
                    has_more = true;
                    break;
                }
                total_bytes = next_bytes;
                cutoff_sequence = meta.sequence;
            }

            // Step 2: materialize ONLY the exact rows within `limit` and `max_size`.
            let rows: Vec<MessageRow> = sql.query(
                "SELECT sequence, token_hash, header, content, initial_message \
                 FROM messages \
                 WHERE sequence > ? AND sequence <= ? AND created_at >= ? \
                 ORDER BY sequence",
                params![after_sequence, cutoff_sequence, cutoff]?,
            )?;
            let messages = rows
                .into_iter()
                .map(StoredMessage::try_from)
                .collect::<Result<Vec<_>>>()?;
            Ok(ReadMailboxOutcome::Page(MailboxPage { messages, has_more }))
        })
    }

    /// Explicitly deletes all messages with `sequence <= up_to_sequence`, preserving
    /// `recipient_stats.last_sequence` monotonically.
    pub(super) fn ack_messages(&self, up_to_sequence: u64) -> Result<AckMessagesOutcome> {
        if up_to_sequence == 0 || up_to_sequence > MAX_SAFE_INTEGER {
            return Ok(AckMessagesOutcome::InvalidSequence);
        }
        if !self.has_tables()? {
            return Ok(AckMessagesOutcome::InvalidSequence);
        }
        self.sql
            .transaction_sync(|sql| match ack_messages_sql(sql, up_to_sequence)? {
                Some(deleted) => Ok(AckMessagesOutcome::Acked(deleted)),
                None => Ok(AckMessagesOutcome::InvalidSequence),
            })
    }

    /// Registers a write-token hash for `record.peer_slot_id` under recipient grant versioning.
    pub(super) fn register_write_token(
        &self,
        record: &RegisterWriteTokenRecord,
        now_ms: u64,
    ) -> Result<RegisterWriteTokenOutcome> {
        self.register_write_token_with_cap(record, now_ms, MAX_AUTHORIZED_PEERS as u64)
    }

    pub(super) fn register_write_token_with_cap(
        &self,
        record: &RegisterWriteTokenRecord,
        now_ms: u64,
        max_authorized_peers: u64,
    ) -> Result<RegisterWriteTokenOutcome> {
        if record.grant_version == 0 || record.grant_version > MAX_SAFE_INTEGER {
            return Ok(RegisterWriteTokenOutcome::InvalidArgument);
        }
        if !self.has_tables()? {
            return Ok(RegisterWriteTokenOutcome::NotFound);
        }

        self.sql.transaction_sync(|sql| {
            if !Self::has_manifest_sql(sql)? {
                return Ok(RegisterWriteTokenOutcome::NotFound);
            }
            // Enforce signed timestamp freshness at DO commit time so a delayed registration can
            // never outlive `REVOCATION_TOMBSTONE_TTL_MS` (2 * MAX_CLOCK_SKEW + 60s).
            if now_ms.abs_diff(record.timestamp) > MAX_CLOCK_SKEW {
                return Ok(RegisterWriteTokenOutcome::StaleTimestamp);
            }
            prune_expired_peer_grants_sql(sql, now_ms)?;

            // Check cross-peer `token_hash` PK collision before any mutation.
            let existing_token = sql.query_opt::<WriteTokenRow>(
                "SELECT peer_slot_id FROM write_tokens WHERE token_hash = ?",
                params![record.token_hash.as_slice()]?,
            )?;
            if let Some(ref existing) = existing_token
                && existing.peer_slot_id.as_ref() != record.peer_slot_id.as_slice()
            {
                return Ok(RegisterWriteTokenOutcome::InvalidArgument);
            }

            let peer = sql.query_opt::<PeerGrantRow>(
                "SELECT max_version, revoked_below_version, active_token_hash, \
                 message_count, total_bytes \
                 FROM peer_grants WHERE peer_slot_id = ?",
                params![record.peer_slot_id.as_slice()]?,
            )?;
            if let Some(ref p) = peer
                && record.grant_version <= p.revoked_below_version
            {
                return Ok(RegisterWriteTokenOutcome::StaleVersion);
            }

            // Duplicate `token_hash` for the same `peer_slot_id`: NEVER overwrite stored
            // `grant_version` or `created_at`; only pin `active_token_hash` (advancing
            // `max_version`) when `pin_active && (grant_version > max_version || active is NULL)`.
            if existing_token.is_some() {
                if let Some(ref p) = peer
                    && record.pin_active
                    && (record.grant_version > p.max_version || p.active_token_hash.is_none())
                {
                    let next_max = p.max_version.max(record.grant_version);
                    sql.exec(
                        "UPDATE peer_grants \
                         SET active_token_hash = ?, max_version = ? \
                         WHERE peer_slot_id = ?",
                        params![
                            record.token_hash.as_slice(),
                            next_max,
                            record.peer_slot_id.as_slice()
                        ]?,
                    )?;
                }
                return Ok(RegisterWriteTokenOutcome::Registered);
            }

            // New `token_hash`: enforce authorized-peer cap on 0 -> 1 live token transition.
            let live_tokens: CountRow = sql.query_one(
                "SELECT count(*) AS count FROM write_tokens WHERE peer_slot_id = ?",
                params![record.peer_slot_id.as_slice()]?,
            )?;
            if live_tokens.count == 0 {
                let authorized = sql
                    .query_opt::<RecipientStatsRow>(
                        "SELECT last_sequence, total_bytes, authorized_peer_count \
                         FROM recipient_stats WHERE only = 0",
                        vec![],
                    )?
                    .map_or(0, |s| s.authorized_peer_count);
                if authorized >= max_authorized_peers {
                    return Ok(RegisterWriteTokenOutcome::LimitExceeded);
                }
                sql.exec(
                    "INSERT INTO recipient_stats \
                     (only, last_sequence, message_count, total_bytes, authorized_peer_count) \
                     VALUES (0, 0, 0, 0, 1) \
                     ON CONFLICT (only) DO UPDATE SET \
                     authorized_peer_count = recipient_stats.authorized_peer_count + 1",
                    vec![],
                )?;
            }

            let should_pin = record.pin_active
                && peer.as_ref().is_none_or(|p| {
                    record.grant_version > p.max_version || p.active_token_hash.is_none()
                });
            let next_active: Option<Vec<u8>> = if should_pin {
                Some(record.token_hash.to_vec())
            } else {
                peer.as_ref()
                    .and_then(|p| p.active_token_hash.as_ref().map(|b| b.as_ref().to_vec()))
            };
            let next_max_version = peer.as_ref().map_or(record.grant_version, |p| {
                p.max_version.max(record.grant_version)
            });

            sql.exec(
                "INSERT INTO peer_grants \
                 (peer_slot_id, max_version, revoked_below_version, revoked_at, \
                  active_token_hash, message_count, total_bytes) \
                 VALUES (?, ?, 0, 0, ?, 0, 0) \
                 ON CONFLICT (peer_slot_id) DO UPDATE SET \
                 max_version = excluded.max_version, \
                 active_token_hash = excluded.active_token_hash",
                params![
                    record.peer_slot_id.as_slice(),
                    next_max_version,
                    next_active.as_deref()
                ]?,
            )?;
            sql.exec(
                "INSERT INTO write_tokens (token_hash, peer_slot_id, grant_version, created_at) \
                 VALUES (?, ?, ?, ?)",
                params![
                    record.token_hash.as_slice(),
                    record.peer_slot_id.as_slice(),
                    record.grant_version,
                    now_ms
                ]?,
            )?;

            // Enforce `MAX_GRANTS_PER_PEER`, evicting lowest `(grant_version, created_at, rowid)`
            // rows strictly excluding the pinned `active_token_hash`.
            let total_for_peer = live_tokens.count.saturating_add(1);
            if total_for_peer > MAX_GRANTS_PER_PEER as u64 {
                let to_evict = total_for_peer - MAX_GRANTS_PER_PEER as u64;
                sql.exec(
                    "DELETE FROM write_tokens WHERE token_hash IN ( \
                         SELECT token_hash FROM write_tokens \
                         WHERE peer_slot_id = ? \
                           AND (? IS NULL OR token_hash != ?) \
                         ORDER BY grant_version ASC, created_at ASC, rowid ASC \
                         LIMIT ? \
                     )",
                    params![
                        record.peer_slot_id.as_slice(),
                        next_active.as_deref(),
                        next_active.as_deref(),
                        to_evict
                    ]?,
                )?;
                // If the just-inserted token itself was immediately evicted (e.g., delayed
                // lower-version grant against a full peer slot with a newer pinned token),
                // return `StaleVersion` instead of `Registered` so the client keeps sends gated
                // and re-stages at a higher version.
                let survived = sql
                    .query_opt::<WriteTokenRow>(
                        "SELECT peer_slot_id FROM write_tokens WHERE token_hash = ?",
                        params![record.token_hash.as_slice()]?,
                    )?
                    .is_some();
                if !survived {
                    return Ok(RegisterWriteTokenOutcome::StaleVersion);
                }
            }

            Ok(RegisterWriteTokenOutcome::Registered)
        })
    }

    /// Revokes one or all write tokens for `record.peer_slot_id` and advances
    /// `revoked_below_version` and `max_version` to at least `record.min_grant_version`.
    pub(super) fn revoke_write_token(
        &self,
        record: &RevokeWriteTokenRecord,
        now_ms: u64,
    ) -> Result<RevokeWriteTokenOutcome> {
        if record.min_grant_version == 0 || record.min_grant_version > MAX_SAFE_INTEGER {
            return Ok(RevokeWriteTokenOutcome::InvalidArgument);
        }
        if !self.has_tables()? {
            return Ok(RevokeWriteTokenOutcome::NotFound);
        }

        self.sql.transaction_sync(|sql| {
            if !Self::has_manifest_sql(sql)? {
                return Ok(RevokeWriteTokenOutcome::NotFound);
            }
            prune_expired_peer_grants_sql(sql, now_ms)?;

            let before_count: CountRow = sql.query_one(
                "SELECT count(*) AS count FROM write_tokens WHERE peer_slot_id = ?",
                params![record.peer_slot_id.as_slice()]?,
            )?;
            let had_live_tokens = before_count.count > 0;

            // Enforce the monotonic revocation floor strictly in both modes:
            // - `token_hash == None`: revoke only grants with `grant_version <= min_grant_version`
            //   so a delayed revoke never deletes a newly registered higher-version grant.
            // - `token_hash == Some(h)`: revoke `h` AND every grant with
            //   `grant_version <= min_grant_version` so no below-floor token survives or gets
            //   promoted to `active_token_hash`.
            let deleted: Vec<TokenHashRow> = match &record.token_hash {
                None => sql.query(
                    "DELETE FROM write_tokens \
                     WHERE peer_slot_id = ? AND grant_version <= ? \
                     RETURNING token_hash",
                    params![record.peer_slot_id.as_slice(), record.min_grant_version]?,
                )?,
                Some(hash) => sql.query(
                    "DELETE FROM write_tokens \
                     WHERE peer_slot_id = ? AND (token_hash = ? OR grant_version <= ?) \
                     RETURNING token_hash",
                    params![
                        record.peer_slot_id.as_slice(),
                        hash.as_slice(),
                        record.min_grant_version
                    ]?,
                )?,
            };
            let revoked = deleted.len() as u32;

            let remaining: CountRow = sql.query_one(
                "SELECT count(*) AS count FROM write_tokens WHERE peer_slot_id = ?",
                params![record.peer_slot_id.as_slice()]?,
            )?;
            let highest_remaining = sql
                .query_opt::<TokenHashRow>(
                    "SELECT token_hash FROM write_tokens \
                     WHERE peer_slot_id = ? \
                     ORDER BY grant_version DESC, rowid DESC LIMIT 1",
                    params![record.peer_slot_id.as_slice()]?,
                )?
                .map(|row| row.token_hash.into_vec());

            let existing_active = sql
                .query_opt::<PeerGrantRow>(
                    "SELECT max_version, revoked_below_version, active_token_hash, \
                     message_count, total_bytes \
                     FROM peer_grants WHERE peer_slot_id = ?",
                    params![record.peer_slot_id.as_slice()]?,
                )?
                .and_then(|p| p.active_token_hash.map(|b| b.into_vec()));

            let next_active = match existing_active {
                Some(active)
                    if sql
                        .query_opt::<TokenHashRow>(
                            "SELECT token_hash FROM write_tokens WHERE token_hash = ?",
                            params![active.as_slice()]?,
                        )?
                        .is_some() =>
                {
                    Some(active)
                }
                _ => highest_remaining,
            };

            sql.exec(
                "INSERT INTO peer_grants \
                 (peer_slot_id, max_version, revoked_below_version, revoked_at, \
                  active_token_hash, message_count, total_bytes) \
                 VALUES (?, ?, ?, ?, ?, 0, 0) \
                 ON CONFLICT (peer_slot_id) DO UPDATE SET \
                 max_version = max(peer_grants.max_version, excluded.max_version), \
                 revoked_below_version = max(peer_grants.revoked_below_version, excluded.revoked_below_version), \
                 revoked_at = max(peer_grants.revoked_at, excluded.revoked_at), \
                 active_token_hash = excluded.active_token_hash",
                params![
                    record.peer_slot_id.as_slice(),
                    record.min_grant_version,
                    record.min_grant_version,
                    now_ms,
                    next_active.as_deref()
                ]?,
            )?;

            if had_live_tokens && remaining.count == 0 {
                sql.exec(
                    "UPDATE recipient_stats \
                     SET authorized_peer_count = max(0, authorized_peer_count - 1) \
                     WHERE only = 0",
                    vec![],
                )?;
            }

            Ok(RevokeWriteTokenOutcome::Revoked(revoked))
        })
    }

    /// Expires `mailbox_dedup` rows, updates `dedup_counts`, and prunes zeroed `dedup_counts` rows
    /// (`DELETE FROM dedup_counts WHERE count <= 0`) in one transaction.
    pub(super) fn expire_dedup(&self, now_ms: u64) -> Result<()> {
        self.sql.transaction_sync(|sql| {
            let expired: Vec<TokenCountRow> = sql.query(
                "SELECT token_hash, count(*) AS count FROM mailbox_dedup \
                 WHERE expires_at <= ? GROUP BY token_hash",
                params![now_ms]?,
            )?;
            if !expired.is_empty() {
                sql.exec(
                    "DELETE FROM mailbox_dedup WHERE expires_at <= ?",
                    params![now_ms]?,
                )?;
                for row in expired {
                    sql.exec(
                        "UPDATE dedup_counts SET count = max(0, count - ?) WHERE token_hash = ?",
                        params![row.count, row.token_hash.as_ref()]?,
                    )?;
                }
            }
            sql.exec("DELETE FROM dedup_counts WHERE count <= 0", vec![])?;
            Ok(())
        })
    }

    /// Prunes empty revoked `peer_grants` tombstones past `MAX_CLOCK_SKEW`.
    pub(super) fn prune_expired_peer_grants(&self, now_ms: u64) -> Result<()> {
        prune_expired_peer_grants_sql(self.sql, now_ms)
    }
}

fn record_tombstone<S: SqlExec>(
    sql: &S,
    token_hash: &[u8; 32],
    cid: &[u8; 16],
    sequence: u64,
    now: u64,
    replacing_existing: bool,
) -> Result<()> {
    if !replacing_existing {
        let mut count = sql
            .query_opt::<CountRow>(
                "SELECT count FROM dedup_counts WHERE token_hash = ?",
                params![token_hash.as_slice()]?,
            )?
            .map_or(0, |row| row.count);
        if count >= MAX_DEDUP_TOMBSTONES_PER_TOKEN {
            // Reclaim expired tombstones for this token before evicting live entries.
            sql.exec(
                "DELETE FROM mailbox_dedup WHERE token_hash = ? AND expires_at <= ?",
                params![token_hash.as_slice(), now]?,
            )?;
            let pruned = sql
                .query_opt::<CountRow>("SELECT changes() AS count", vec![])?
                .map_or(0, |row| row.count);
            count = count.saturating_sub(pruned);
            if count >= MAX_DEDUP_TOMBSTONES_PER_TOKEN {
                let to_evict = count - MAX_DEDUP_TOMBSTONES_PER_TOKEN + 1;
                sql.exec(
                    "DELETE FROM mailbox_dedup WHERE token_hash = ? AND client_message_id IN ( \
                        SELECT d.client_message_id FROM mailbox_dedup d WHERE d.token_hash = ? \
                        ORDER BY CASE WHEN EXISTS (SELECT 1 FROM messages m \
                            WHERE m.sequence = d.sequence) THEN 1 ELSE 0 END ASC, \
                            d.created_at ASC, d.sequence ASC LIMIT ?)",
                    params![token_hash.as_slice(), token_hash.as_slice(), to_evict]?,
                )?;
                let evicted = sql
                    .query_opt::<CountRow>("SELECT changes() AS count", vec![])?
                    .map_or(0, |row| row.count);
                count = count.saturating_sub(evicted);
            }
        }
        let next_count = count.saturating_add(1);
        sql.exec(
            "INSERT INTO dedup_counts (token_hash, count) VALUES (?, ?) \
             ON CONFLICT (token_hash) DO UPDATE SET count = excluded.count",
            params![token_hash.as_slice(), next_count]?,
        )?;
    }
    let expires_at = now.saturating_add(DEDUP_TTL_MS).min(MAX_SAFE_INTEGER);
    sql.exec(
        "INSERT INTO mailbox_dedup (token_hash, client_message_id, sequence, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?) ON CONFLICT (token_hash, client_message_id) DO UPDATE SET \
         sequence = excluded.sequence, created_at = excluded.created_at, \
         expires_at = excluded.expires_at",
        params![
            token_hash.as_slice(),
            cid.as_slice(),
            sequence,
            now,
            expires_at
        ]?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_quotas_enforce_per_peer_and_per_recipient_caps() {
        let base = MailboxQuotaSnapshot {
            peer_message_count: 0,
            peer_bytes: 0,
            recipient_bytes: 0,
        };
        assert!(within_mailbox_quotas(base, 1024));
        assert!(!within_mailbox_quotas(
            MailboxQuotaSnapshot {
                peer_message_count: MAX_QUEUE_MESSAGES as u64,
                ..base
            },
            1
        ));
        assert!(!within_mailbox_quotas(
            MailboxQuotaSnapshot {
                peer_bytes: MAX_QUEUE_BYTES,
                ..base
            },
            1
        ));
        assert!(!within_mailbox_quotas(
            MailboxQuotaSnapshot {
                recipient_bytes: MAX_RECIPIENT_BYTES,
                ..base
            },
            1
        ));
        assert!(within_mailbox_quotas(
            MailboxQuotaSnapshot {
                recipient_bytes: MAX_RECIPIENT_BYTES - 10,
                ..base
            },
            10
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native_sqlite_tests {
        use storage::{
            PeerSlotId, PublicKey, PublishV2Record, PublishV2Status, StoredCapabilityManifest,
        };

        use super::*;
        use crate::objects::identity::TestIdentity;

        const BOB: PublicKey = [0x22; 32];

        fn publish_bob(env: &TestIdentity) {
            let manifest = StoredCapabilityManifest {
                audience: "relay.example".into(),
                identity_key: BOB,
                manifest_seq: 1,
                generation: 1,
                issued_at: 1_000,
                expires_at: 100_000,
                pq_enabled: false,
                strict_pq: false,
                pq_ratchet_supported: false,
                offered_suites: vec![],
                signed_prekey: [0x33; 32],
                pq_last_resort: vec![],
                signature: [0x44; 64],
            };
            assert_eq!(
                env.store()
                    .publish_v2(&PublishV2Record {
                        manifest,
                        signed_prekey_signature: Some([0x55; 64]),
                        one_time_prekeys: vec![],
                        pq_last_resort: vec![],
                        pq_one_time_prekeys: vec![],
                        timestamp: 1_000,
                    })
                    .unwrap(),
                PublishV2Status::Stored
            );
        }

        fn slot(n: u32) -> PeerSlotId {
            let mut out = [0u8; 32];
            out[..4].copy_from_slice(&n.to_be_bytes());
            out
        }

        fn tok(n: u32) -> WriteTokenHash {
            let mut out = [0xAA; 32];
            out[..4].copy_from_slice(&n.to_be_bytes());
            out
        }

        #[derive(serde::Deserialize)]
        struct FullRecipientStatsRow {
            last_sequence: u64,
            message_count: u64,
            total_bytes: u64,
            authorized_peer_count: u64,
        }

        fn stats(env: &TestIdentity) -> FullRecipientStatsRow {
            env.sql
                .query_one(
                    "SELECT last_sequence, message_count, total_bytes, authorized_peer_count \
                     FROM recipient_stats WHERE only = 0",
                    vec![],
                )
                .unwrap()
        }

        #[test]
        fn unregistered_recipient_leaves_tables_unallocated_and_fails_closed() {
            let env = TestIdentity::new(100_000);
            let store = env.store();

            assert_eq!(
                store
                    .register_write_token(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: tok(1),
                            grant_version: 1,
                            pin_active: true,
                            timestamp: 0,
                        },
                        1_000
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::NotFound
            );
            assert_eq!(
                store
                    .revoke_write_token(
                        &RevokeWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: None,
                            min_grant_version: 1,
                        },
                        1_000
                    )
                    .unwrap(),
                RevokeWriteTokenOutcome::NotFound
            );
            assert_eq!(
                store
                    .append_idempotent(&tok(1), b"h", b"c", None, None, 1_000)
                    .unwrap(),
                AppendOutcome::WriteTokenRejected
            );
            assert_eq!(
                store.read_mailbox(0, 10, 1024, 0, 1_000).unwrap(),
                ReadMailboxOutcome::Page(MailboxPage::default())
            );
            assert_eq!(
                store.read_mailbox(0, 10, 1024, 1, 1_000).unwrap(),
                ReadMailboxOutcome::InvalidAckSequence
            );
            assert_eq!(
                store.ack_messages(1).unwrap(),
                AckMessagesOutcome::InvalidSequence
            );
            assert!(!store.has_tables().unwrap());
        }

        #[test]
        fn grant_invariants_pin_active_collision_cap_revocation_and_tombstone_prune() {
            let env = TestIdentity::new(100_000);
            publish_bob(&env);
            let store = env.store();

            // Register active tok(1) v1 for peer 1.
            assert_eq!(
                store
                    .register_write_token(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: tok(1),
                            grant_version: 1,
                            pin_active: true,
                            timestamp: 1_000,
                        },
                        1_000
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::Registered
            );
            // Cross-peer token_hash collision -> InvalidArgument.
            assert_eq!(
                store
                    .register_write_token(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(2),
                            token_hash: tok(1),
                            grant_version: 1,
                            pin_active: true,
                            timestamp: 1_000,
                        },
                        1_000
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::InvalidArgument
            );
            // Add v2, v3, v4 non-pinned.
            for ver in 2..=4 {
                assert_eq!(
                    store
                        .register_write_token(
                            &RegisterWriteTokenRecord {
                                recipient: BOB,
                                peer_slot_id: slot(1),
                                token_hash: tok(ver),
                                grant_version: u64::from(ver),
                                pin_active: false,
                                timestamp: 1_000 + u64::from(ver),
                            },
                            1_000 + u64::from(ver)
                        )
                        .unwrap(),
                    RegisterWriteTokenOutcome::Registered
                );
            }
            // Duplicate tok(2) with v99 must NOT bump its eviction priority.
            assert_eq!(
                store
                    .register_write_token(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: tok(2),
                            grant_version: 99,
                            pin_active: false,
                            timestamp: 2_000,
                        },
                        2_000
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::Registered
            );
            // 5th grant tok(5) v5 evicts tok(2) (lowest non-active), strictly preserving tok(1)!
            assert_eq!(
                store
                    .register_write_token(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: tok(5),
                            grant_version: 5,
                            pin_active: false,
                            timestamp: 2_001,
                        },
                        2_001
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::Registered
            );
            assert_eq!(
                store
                    .append_idempotent(&tok(2), b"h", b"c", None, None, 2_002)
                    .unwrap(),
                AppendOutcome::WriteTokenRejected
            );
            let cid = [0x99u8; 16];
            assert_eq!(
                store
                    .append_idempotent(&tok(1), b"h", b"c", None, Some(&cid), 2_002)
                    .unwrap(),
                AppendOutcome::Appended(1)
            );

            // Targeted revoke of tok(1) with min_grant_version = 2 deletes only tok(1), leaving
            // tok(3), tok(4), tok(5) live; auth-before-dedup rejects cid retry!
            assert_eq!(
                store
                    .revoke_write_token(
                        &RevokeWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: Some(tok(1)),
                            min_grant_version: 2,
                        },
                        3_000
                    )
                    .unwrap(),
                RevokeWriteTokenOutcome::Revoked(1)
            );
            assert_eq!(
                store
                    .append_idempotent(&tok(1), b"h", b"c", None, Some(&cid), 3_001)
                    .unwrap(),
                AppendOutcome::WriteTokenRejected
            );

            // Targeted revoke of tok(5) with min_grant_version = 10 deletes tok(3), tok(4), tok(5)
            // in the same transaction so no below-floor token survives or gets promoted to active!
            assert_eq!(
                store
                    .revoke_write_token(
                        &RevokeWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: Some(tok(5)),
                            min_grant_version: 10,
                        },
                        3_500
                    )
                    .unwrap(),
                RevokeWriteTokenOutcome::Revoked(3)
            );
            assert_eq!(stats(&env).authorized_peer_count, 0);
            for revoked_tok in [tok(3), tok(4), tok(5)] {
                assert!(!store.has_write_token(&revoked_tok).unwrap());
                assert_eq!(
                    store
                        .append_idempotent(&revoked_tok, b"h", b"c", None, None, 3_501)
                        .unwrap(),
                    AppendOutcome::WriteTokenRejected
                );
            }
            // grant_version <= 10 -> StaleVersion.
            assert_eq!(
                store
                    .register_write_token(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: tok(99),
                            grant_version: 10,
                            pin_active: true,
                            timestamp: 3_501,
                        },
                        3_501
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::StaleVersion
            );

            // Register newer grant v11, then replay a delayed unconditional revoke with
            // min_grant_version = 10 -> MUST NOT delete v11!
            assert_eq!(
                store
                    .register_write_token(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: tok(11),
                            grant_version: 11,
                            pin_active: true,
                            timestamp: 3_600,
                        },
                        3_600
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::Registered
            );
            assert_eq!(
                store
                    .revoke_write_token(
                        &RevokeWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: None,
                            min_grant_version: 10,
                        },
                        3_700
                    )
                    .unwrap(),
                RevokeWriteTokenOutcome::Revoked(0)
            );
            assert!(store.has_write_token(&tok(11)).unwrap());

            // Unconditional revoke with min_grant_version = 12 removes tok(11) -> authorized_peer_count -> 0.
            assert_eq!(
                store
                    .revoke_write_token(
                        &RevokeWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: None,
                            min_grant_version: 12,
                        },
                        4_000
                    )
                    .unwrap(),
                RevokeWriteTokenOutcome::Revoked(1)
            );
            assert_eq!(stats(&env).authorized_peer_count, 0);

            // Still has 1 queued message, so peer_grants tombstone is NOT pruned even past TTL.
            store
                .prune_expired_peer_grants(4_000 + REVOCATION_TOMBSTONE_TTL_MS + 10)
                .unwrap();
            let remaining_grants: CountRow = env
                .sql
                .query_one("SELECT count(*) AS count FROM peer_grants", vec![])
                .unwrap();
            assert_eq!(remaining_grants.count, 1);

            // After ACK empties messages, tombstone stays through `revoked_at + REVOCATION_TOMBSTONE_TTL_MS`
            // (covering the full 2*MAX_CLOCK_SKEW + 60s window) and is pruned strictly past it.
            assert_eq!(store.ack_messages(1).unwrap(), AckMessagesOutcome::Acked(1));
            store
                .prune_expired_peer_grants(4_000 + MAX_CLOCK_SKEW + 1)
                .unwrap();
            let still_protected_past_5m: CountRow = env
                .sql
                .query_one("SELECT count(*) AS count FROM peer_grants", vec![])
                .unwrap();
            assert_eq!(still_protected_past_5m.count, 1);

            store
                .prune_expired_peer_grants(4_000 + REVOCATION_TOMBSTONE_TTL_MS)
                .unwrap();
            let still_protected: CountRow = env
                .sql
                .query_one("SELECT count(*) AS count FROM peer_grants", vec![])
                .unwrap();
            assert_eq!(still_protected.count, 1);

            // Once pruned past REVOCATION_TOMBSTONE_TTL_MS, a pre-revocation registration signed
            // even +MAX_CLOCK_SKEW ahead of `revoked_at` (4_000 + MAX_CLOCK_SKEW) is STILL
            // rejected at DO commit time with `StaleTimestamp`!
            let after_prune = 4_000 + REVOCATION_TOMBSTONE_TTL_MS + 1;
            store.prune_expired_peer_grants(after_prune).unwrap();
            let pruned: CountRow = env
                .sql
                .query_one("SELECT count(*) AS count FROM peer_grants", vec![])
                .unwrap();
            assert_eq!(pruned.count, 0);
            assert_eq!(
                store
                    .register_write_token(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: tok(1),
                            grant_version: 1,
                            pin_active: true,
                            timestamp: 4_000 + MAX_CLOCK_SKEW,
                        },
                        after_prune
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::StaleTimestamp
            );

            // Authorized peer cap enforcement.
            assert_eq!(
                store
                    .register_write_token_with_cap(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(10),
                            token_hash: tok(10),
                            grant_version: 1,
                            pin_active: true,
                            timestamp: 5_000,
                        },
                        5_000,
                        1
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::Registered
            );
            assert_eq!(
                store
                    .register_write_token_with_cap(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(11),
                            token_hash: tok(11),
                            grant_version: 1,
                            pin_active: true,
                            timestamp: 5_000,
                        },
                        5_000,
                        1
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::LimitExceeded
            );
        }

        #[test]
        fn unified_queue_pagination_prefix_ack_and_dedup_count_pruning() {
            let env = TestIdentity::new(100_000);
            publish_bob(&env);
            let store = env.store();

            for (peer_id, token_id) in [(1u32, 1u32), (2u32, 2u32)] {
                assert_eq!(
                    store
                        .register_write_token(
                            &RegisterWriteTokenRecord {
                                recipient: BOB,
                                peer_slot_id: slot(peer_id),
                                token_hash: tok(token_id),
                                grant_version: 1,
                                pin_active: true,
                                timestamp: 1_000,
                            },
                            1_000
                        )
                        .unwrap(),
                    RegisterWriteTokenOutcome::Registered
                );
            }

            let cid = [0x11u8; 16];
            assert_eq!(
                store
                    .append_idempotent(&tok(1), b"h1", b"body1", Some(b"init"), Some(&cid), 1_000)
                    .unwrap(),
                AppendOutcome::Appended(1)
            );
            assert_eq!(
                store
                    .append_idempotent(&tok(1), b"h1", b"body1", Some(b"init"), Some(&cid), 1_500)
                    .unwrap(),
                AppendOutcome::Deduplicated(1)
            );
            assert_eq!(
                store
                    .append_idempotent(&tok(2), b"h2", b"body2", None, Some(&cid), 2_000)
                    .unwrap(),
                AppendOutcome::Appended(2)
            );

            // Read page with limit=1 sets has_more=true.
            let ReadMailboxOutcome::Page(p1) = store.read_mailbox(0, 1, 1024, 0, 2_000).unwrap()
            else {
                panic!("expected page");
            };
            assert!(p1.has_more);
            assert_eq!(p1.messages.len(), 1);
            assert_eq!(p1.messages[0].sequence, 1);
            assert_eq!(p1.messages[0].token_hash, tok(1));

            // Piggybacked ack_up_to_sequence=1 + after_sequence=1 deletes seq 1 and returns seq 2.
            let ReadMailboxOutcome::Page(p2) = store.read_mailbox(1, 10, 1024, 1, 2_000).unwrap()
            else {
                panic!("expected page");
            };
            assert!(!p2.has_more);
            assert_eq!(p2.messages.len(), 1);
            assert_eq!(p2.messages[0].sequence, 2);
            assert_eq!(p2.messages[0].token_hash, tok(2));
            assert_eq!(stats(&env).message_count, 1);
            assert_eq!(stats(&env).last_sequence, 2);

            // Reject future ACK (> last_sequence) and 0.
            assert_eq!(
                store.ack_messages(0).unwrap(),
                AckMessagesOutcome::InvalidSequence
            );
            assert_eq!(
                store.ack_messages(3).unwrap(),
                AckMessagesOutcome::InvalidSequence
            );
            assert_eq!(
                store.read_mailbox(0, 10, 1024, 3, 2_000).unwrap(),
                ReadMailboxOutcome::InvalidAckSequence
            );

            // Explicit ACK through seq 2 deletes seq 2 and keeps last_sequence=2 monotonically.
            assert_eq!(store.ack_messages(2).unwrap(), AckMessagesOutcome::Acked(1));
            assert_eq!(store.ack_messages(2).unwrap(), AckMessagesOutcome::Acked(0));
            assert_eq!(stats(&env).message_count, 0);
            assert_eq!(stats(&env).total_bytes, 0);
            assert_eq!(stats(&env).last_sequence, 2);

            // Expiring mailbox_dedup prunes zeroed `dedup_counts` rows (`count <= 0`).
            store.expire_dedup(2_000 + DEDUP_TTL_MS).unwrap();
            let dedup_counts_left: CountRow = env
                .sql
                .query_one("SELECT count(*) AS count FROM dedup_counts", vec![])
                .unwrap();
            assert_eq!(dedup_counts_left.count, 0);
        }

        #[test]
        fn r3_p2_2_and_r3_p3_2_self_evicted_grant_returns_stale_version_and_zero_ts_rejected() {
            let env = TestIdentity::new(100_000);
            publish_bob(&env);
            let store = env.store();
            let now_ms = 500_000;

            // R3-P3-2: timestamp == 0 is unconditionally rejected with StaleTimestamp.
            assert_eq!(
                store
                    .register_write_token(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: tok(1),
                            grant_version: 1,
                            pin_active: true,
                            timestamp: 0,
                        },
                        now_ms,
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::StaleTimestamp
            );

            // R3-P2-2: Fill peer slot with 4 tokens (pinned v10 + non-pinned v6, v7, v8).
            assert_eq!(
                store
                    .register_write_token(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: tok(10),
                            grant_version: 10,
                            pin_active: true,
                            timestamp: now_ms,
                        },
                        now_ms,
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::Registered
            );
            for ver in 6..=8u32 {
                assert_eq!(
                    store
                        .register_write_token(
                            &RegisterWriteTokenRecord {
                                recipient: BOB,
                                peer_slot_id: slot(1),
                                token_hash: tok(ver),
                                grant_version: u64::from(ver),
                                pin_active: false,
                                timestamp: now_ms,
                            },
                            now_ms,
                        )
                        .unwrap(),
                    RegisterWriteTokenOutcome::Registered
                );
            }

            // A delayed `pin_active: true` grant at lower version v5 is immediately evicted and
            // MUST return `StaleVersion` (NOT `Registered`).
            assert_eq!(
                store
                    .register_write_token(
                        &RegisterWriteTokenRecord {
                            recipient: BOB,
                            peer_slot_id: slot(1),
                            token_hash: tok(5),
                            grant_version: 5,
                            pin_active: true,
                            timestamp: now_ms,
                        },
                        now_ms,
                    )
                    .unwrap(),
                RegisterWriteTokenOutcome::StaleVersion
            );
            assert!(!store.has_write_token(&tok(5)).unwrap());
            assert!(store.has_write_token(&tok(10)).unwrap());
        }
    }
}
