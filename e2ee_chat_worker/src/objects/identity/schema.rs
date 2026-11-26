//! Identity tables and in-place v1/v2/v3 -> v4 schema upgrades.
//!
//! Cloudflare Durable Object SQLite does not support `PRAGMA user_version`, so persistent schema
//! migrations are gated on `meta.schema_version` and cached per Durable Object instance in
//! `Identity::schema_ready` (`Cell<bool>`), eliminating per-write DDL and `sqlite_master` lookups.

use storage::MAX_SAFE_INTEGER;
use worker::{Result, SqlStorage};

use super::{
    Identity,
    mailbox::DEDUP_TTL_MS,
    rows::{OldestRow, SchemaVersionRow, TableInfoRow},
};
use crate::objects::{
    has_table,
    sql::{exec, params, query, query_opt},
};

const CURRENT_SCHEMA_VERSION: u64 = 4;

const _: () = assert!(MAX_SAFE_INTEGER > DEDUP_TTL_MS);

/// Core v1 tables (unchanged layout so existing deployed DO instances auto-migrate cleanly
/// without losing rows).
const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS bundle (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    signed_prekey BLOB NOT NULL,
    signature BLOB NOT NULL,
    timestamp INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    position INTEGER PRIMARY KEY,
    prekey BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS inbox (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    last_take INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS initial_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender BLOB NOT NULL,
    ephemeral_key BLOB NOT NULL,
    signed_prekey BLOB NOT NULL,
    one_time_prekey BLOB,
    header BLOB NOT NULL,
    content BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS queues (
    sender BLOB PRIMARY KEY,
    last_sequence INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    sender BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    header BLOB NOT NULL,
    content BLOB,
    object TEXT,
    size INTEGER NOT NULL,
    initial_message BLOB,
    delivery_hash BLOB,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (sender, sequence),
    CHECK ((content IS NULL) != (object IS NULL))
);
CREATE INDEX IF NOT EXISTS messages_by_age ON messages (created_at);
";

/// Additive v2 side tables and schema version marker. Never relies on SQLite foreign_keys pragma:
/// orphan cleanup is performed explicitly in ack/alarm.
const SCHEMA_V2: &str = "
CREATE TABLE IF NOT EXISTS meta (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    schema_version INTEGER NOT NULL
);
INSERT INTO meta (only, schema_version) VALUES (0, 2)
    ON CONFLICT (only) DO NOTHING;
CREATE TABLE IF NOT EXISTS capability_manifest (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    audience TEXT NOT NULL,
    identity_key BLOB NOT NULL,
    manifest_seq INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    pq_enabled INTEGER NOT NULL,
    strict_pq INTEGER NOT NULL,
    pq_ratchet_supported INTEGER NOT NULL,
    offered_suites BLOB NOT NULL,
    signed_prekey BLOB NOT NULL,
    pq_last_resort_commitments BLOB NOT NULL,
    signature BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS pq_last_resort (
    suite INTEGER PRIMARY KEY,
    prekey_id BLOB NOT NULL,
    encapsulation_key BLOB NOT NULL,
    signature BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS pq_one_time_prekeys (
    position INTEGER PRIMARY KEY AUTOINCREMENT,
    suite INTEGER NOT NULL,
    prekey_id BLOB NOT NULL UNIQUE,
    encapsulation_key BLOB NOT NULL,
    signature BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS initial_messages_pq (
    initial_message_id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL,
    pq_suite INTEGER NOT NULL,
    pq_last_resort INTEGER NOT NULL,
    pq_prekey_id BLOB NOT NULL,
    pq_ciphertext BLOB NOT NULL,
    manifest_digest BLOB
);
CREATE TABLE IF NOT EXISTS mailbox_dedup (
    sender BLOB NOT NULL,
    client_message_id BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (sender, client_message_id)
);
CREATE INDEX IF NOT EXISTS mailbox_dedup_by_age ON mailbox_dedup (created_at);
CREATE TABLE IF NOT EXISTS publish_watermarks (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    last_v1_publish_ts INTEGER NOT NULL DEFAULT 0,
    last_refill_ts INTEGER NOT NULL DEFAULT 0
);
";

/// V2 -> V3 in-place migration statements for `mailbox_dedup` expiry support.
const MIGRATE_DEDUP_ADD_EXPIRES_AT: &str =
    "ALTER TABLE mailbox_dedup ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0";
const MIGRATE_DEDUP_BACKFILL_EXPIRES_AT: &str = "UPDATE mailbox_dedup SET expires_at = CASE \
     WHEN created_at >= ? THEN ? ELSE created_at + ? END WHERE expires_at = 0";
const MIGRATE_DEDUP_INDEXES: &str = "CREATE INDEX IF NOT EXISTS mailbox_dedup_by_expiry ON mailbox_dedup (expires_at); \
     CREATE INDEX IF NOT EXISTS mailbox_dedup_by_sender \
     ON mailbox_dedup (sender, created_at, sequence);";

/// Additive v4 tables and partial/age indexes:
/// - `recipient_stats`: O(1) recipient-wide queue count, byte total, and monotonic sequence floor
///   so empty `queues` rows can be safely pruned without reusing sequence numbers.
/// - `dedup_counts`: O(1) per-sender dedup tombstone count avoiding `count(*)` scans.
/// - `pending_r2_deletes`: durable queue of R2 object keys retried by `alarm()` after atomic SQL
///   deletion of delivered messages.
/// - `opk_claim_budget`: per-identity hourly one-time prekey claim budget.
/// - Partial indexes on `messages` (`WHERE object IS NULL` / `WHERE object IS NOT NULL`) and
///   `initial_messages (created_at)` so expiry alarm `min(created_at)` queries are O(1) seeks.
const SCHEMA_V4: &str = "
CREATE TABLE IF NOT EXISTS recipient_stats (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    queue_count INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    sequence_floor INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dedup_counts (
    sender BLOB PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pending_r2_deletes (
    object TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS pending_r2_deletes_by_age ON pending_r2_deletes (created_at);
CREATE TABLE IF NOT EXISTS opk_claim_budget (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    window_start INTEGER NOT NULL,
    claims INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_inline_by_age ON messages (created_at) WHERE object IS NULL;
CREATE INDEX IF NOT EXISTS messages_object_by_age ON messages (created_at) WHERE object IS NOT NULL;
CREATE INDEX IF NOT EXISTS initial_messages_by_age ON initial_messages (created_at);
";

/// Tracks verified audience-bound v2 subscriptions for replay protection.
pub(super) const SCHEMA_SEEN_SUBSCRIBES: &str = "
CREATE TABLE IF NOT EXISTS seen_subscribes (
    sig_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS seen_subscribes_by_expiry ON seen_subscribes (expires_at);
";

impl Identity {
    /// Whether core tables exist (used to avoid allocating storage on unknown-identity reads).
    pub(super) fn has_tables(&self) -> Result<bool> {
        if self.schema_ready.get() {
            return Ok(true);
        }
        has_table(&self.sql(), "messages")
    }

    /// Whether a v2/v3/v4 side table exists, skipping `sqlite_master` once schema init succeeded.
    pub(super) fn has_v2_table(&self, sql: &SqlStorage, name: &str) -> Result<bool> {
        if self.schema_ready.get() {
            return Ok(true);
        }
        has_table(sql, name)
    }

    /// Whether the `seen_subscribes` replay table exists, cached once observed.
    pub(super) fn has_seen_subscribes(&self, sql: &SqlStorage) -> Result<bool> {
        if self.seen_subscribes_ready.get() {
            return Ok(true);
        }
        let exists = has_table(sql, "seen_subscribes")?;
        if exists {
            self.seen_subscribes_ready.set(true);
        }
        Ok(exists)
    }

    /// Ensures all v1/v2/v3/v4 tables, columns, indexes, and counters exist.
    ///
    /// Fast path: zero SQL statements after the first check in this DO instance, and zero DDL
    /// statements on cold start when `meta.schema_version >= CURRENT_SCHEMA_VERSION`.
    pub(super) fn ensure_v2_tables(&self) -> Result<()> {
        if self.schema_ready.get() {
            return Ok(());
        }
        let sql = self.sql();
        if has_table(&sql, "meta")?
            && query_opt::<SchemaVersionRow>(
                &sql,
                "SELECT schema_version FROM meta WHERE only = 0",
                vec![],
            )?
            .is_some_and(|row| row.schema_version >= CURRENT_SCHEMA_VERSION)
        {
            self.schema_ready.set(true);
            return Ok(());
        }

        self.transaction_sync(|sql| {
            let current_version = if has_table(sql, "meta")? {
                query_opt::<SchemaVersionRow>(
                    sql,
                    "SELECT schema_version FROM meta WHERE only = 0",
                    vec![],
                )?
                .map_or(0, |row| row.schema_version)
            } else {
                0
            };
            if current_version >= CURRENT_SCHEMA_VERSION {
                return Ok(());
            }

            sql.exec(SCHEMA_V1, None)?;
            sql.exec(SCHEMA_V2, None)?;

            let dedup_columns: Vec<TableInfoRow> =
                query(sql, "PRAGMA table_info(mailbox_dedup)", vec![])?;
            if !dedup_columns.iter().any(|column| column.name == "expires_at") {
                sql.exec(MIGRATE_DEDUP_ADD_EXPIRES_AT, None)?;
                exec(
                    sql,
                    MIGRATE_DEDUP_BACKFILL_EXPIRES_AT,
                    params![
                        MAX_SAFE_INTEGER - DEDUP_TTL_MS,
                        MAX_SAFE_INTEGER,
                        DEDUP_TTL_MS
                    ]?,
                )?;
            }
            sql.exec(MIGRATE_DEDUP_INDEXES, None)?;

            let queue_columns: Vec<TableInfoRow> =
                query(sql, "PRAGMA table_info(queues)", vec![])?;
            if !queue_columns
                .iter()
                .any(|column| column.name == "message_count")
            {
                sql.exec(
                    "ALTER TABLE queues ADD COLUMN message_count INTEGER NOT NULL DEFAULT 0",
                    None,
                )?;
            }
            if !queue_columns
                .iter()
                .any(|column| column.name == "total_bytes")
            {
                sql.exec(
                    "ALTER TABLE queues ADD COLUMN total_bytes INTEGER NOT NULL DEFAULT 0",
                    None,
                )?;
            }

            sql.exec(SCHEMA_V4, None)?;

            // Backfill per-queue counters, prune empty pre-v4 queues while capturing the maximum
            // historical sequence into `recipient_stats.sequence_floor`, and backfill dedup counts.
            sql.exec(
                "UPDATE queues SET \
                 message_count = coalesce((SELECT count(*) FROM messages m WHERE m.sender = queues.sender), 0), \
                 total_bytes = coalesce((SELECT sum(length(m.header) + m.size + coalesce(length(m.initial_message), 0)) \
                     FROM messages m WHERE m.sender = queues.sender), 0)",
                None,
            )?;
            let pre_prune_max = query_opt::<OldestRow>(
                sql,
                "SELECT max(last_sequence) AS oldest FROM queues",
                vec![],
            )?
            .and_then(|row| row.oldest)
            .unwrap_or(0);
            sql.exec("DELETE FROM queues WHERE message_count = 0", None)?;
            exec(
                sql,
                "INSERT INTO recipient_stats (only, queue_count, total_bytes, sequence_floor) \
                 SELECT 0, count(*), coalesce(sum(total_bytes), 0), ? FROM queues WHERE true \
                 ON CONFLICT (only) DO UPDATE SET \
                 queue_count = excluded.queue_count, \
                 total_bytes = excluded.total_bytes, \
                 sequence_floor = max(recipient_stats.sequence_floor, excluded.sequence_floor)",
                params![pre_prune_max]?,
            )?;
            sql.exec("DELETE FROM dedup_counts", None)?;
            sql.exec(
                "INSERT INTO dedup_counts (sender, count) \
                 SELECT sender, count(*) FROM mailbox_dedup GROUP BY sender",
                None,
            )?;

            exec(
                sql,
                "INSERT INTO meta (only, schema_version) VALUES (0, ?) \
                 ON CONFLICT (only) DO UPDATE SET schema_version = excluded.schema_version",
                params![CURRENT_SCHEMA_VERSION]?,
            )?;
            Ok(())
        })?;
        self.schema_ready.set(true);
        Ok(())
    }

    /// Explicit orphan cleanup for `initial_messages_pq` (no reliance on SQLite foreign_keys).
    pub(super) fn cleanup_orphan_pq_initials_sql(sql: &SqlStorage) -> Result<()> {
        if has_table(sql, "initial_messages_pq")? {
            sql.exec(
                "DELETE FROM initial_messages_pq \
                 WHERE NOT EXISTS (SELECT 1 FROM initial_messages WHERE id = initial_messages_pq.initial_message_id)",
                None,
            )?;
        }
        Ok(())
    }
}
