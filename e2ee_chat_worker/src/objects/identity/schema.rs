//! Identity tables and in-place v1/v2/v3 -> v4 schema upgrades.
//!
//! Cloudflare Durable Object SQLite does not support `PRAGMA user_version`, so persistent schema
//! migrations are gated on `meta.schema_version` and cached per Durable Object instance in
//! `SchemaCache::schema_ready` (`Cell<bool>`), eliminating per-write DDL and `sqlite_master`
//! lookups.

use storage::MAX_SAFE_INTEGER;
use worker::{Error, Result};

use super::{
    IdentityStore,
    mailbox::DEDUP_TTL_MS,
    rows::{OldestRow, SchemaVersionRow, TableInfoRow},
};
use crate::objects::{
    has_table,
    sql::{SqlExec, params},
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

impl<S: SqlExec> IdentityStore<'_, S> {
    /// Whether core tables exist (used to avoid allocating storage on unknown-identity reads).
    pub(super) fn has_tables(&self) -> Result<bool> {
        if self.cache.schema_ready.get() {
            return Ok(true);
        }
        has_table(self.sql, "messages")
    }

    /// Whether a v2/v3/v4 side table exists, skipping `sqlite_master` once schema init succeeded.
    pub(super) fn has_v2_table(&self, sql: &S, name: &str) -> Result<bool> {
        if self.cache.schema_ready.get() {
            return Ok(true);
        }
        has_table(sql, name)
    }

    /// Whether the `seen_subscribes` replay table exists, cached once observed.
    pub(super) fn has_seen_subscribes(&self) -> Result<bool> {
        if self.cache.seen_subscribes_ready.get() {
            return Ok(true);
        }
        let exists = has_table(self.sql, "seen_subscribes")?;
        if exists {
            self.cache.seen_subscribes_ready.set(true);
        }
        Ok(exists)
    }

    /// Ensures all v1/v2/v3/v4 tables, columns, indexes, and counters exist.
    ///
    /// Fast path: zero SQL statements after the first check in this DO instance, and zero DDL
    /// statements on cold start when `meta.schema_version == CURRENT_SCHEMA_VERSION`.
    /// Rejects unsupported future `meta.schema_version > CURRENT_SCHEMA_VERSION` fail-closed.
    pub(super) fn ensure_v2_tables(&self) -> Result<()> {
        if self.cache.schema_ready.get() {
            return Ok(());
        }
        if has_table(self.sql, "meta")?
            && let Some(row) = self.sql.query_opt::<SchemaVersionRow>(
                "SELECT schema_version FROM meta WHERE only = 0",
                vec![],
            )?
        {
            if row.schema_version == CURRENT_SCHEMA_VERSION {
                self.cache.schema_ready.set(true);
                return Ok(());
            }
            if row.schema_version > CURRENT_SCHEMA_VERSION {
                return Err(Error::RustError(format!(
                    "unsupported identity schema version {} (expected {})",
                    row.schema_version, CURRENT_SCHEMA_VERSION
                )));
            }
        }

        self.sql.transaction_sync(|sql| {
            let current_version = if has_table(sql, "meta")? {
                sql.query_opt::<SchemaVersionRow>(
                    "SELECT schema_version FROM meta WHERE only = 0",
                    vec![],
                )?
                .map_or(0, |row| row.schema_version)
            } else {
                0
            };
            if current_version == CURRENT_SCHEMA_VERSION {
                return Ok(());
            }
            if current_version > CURRENT_SCHEMA_VERSION {
                return Err(Error::RustError(format!(
                    "unsupported identity schema version {current_version} (expected {CURRENT_SCHEMA_VERSION})"
                )));
            }

            sql.exec_batch(SCHEMA_V1)?;
            sql.exec_batch(SCHEMA_V2)?;

            let dedup_columns: Vec<TableInfoRow> =
                sql.query("PRAGMA table_info(mailbox_dedup)", vec![])?;
            if !dedup_columns.iter().any(|column| column.name == "expires_at") {
                sql.exec_batch(MIGRATE_DEDUP_ADD_EXPIRES_AT)?;
                sql.exec(
                    MIGRATE_DEDUP_BACKFILL_EXPIRES_AT,
                    params![
                        MAX_SAFE_INTEGER - DEDUP_TTL_MS,
                        MAX_SAFE_INTEGER,
                        DEDUP_TTL_MS
                    ]?,
                )?;
            }
            sql.exec_batch(MIGRATE_DEDUP_INDEXES)?;

            let queue_columns: Vec<TableInfoRow> =
                sql.query("PRAGMA table_info(queues)", vec![])?;
            if !queue_columns
                .iter()
                .any(|column| column.name == "message_count")
            {
                sql.exec_batch(
                    "ALTER TABLE queues ADD COLUMN message_count INTEGER NOT NULL DEFAULT 0",
                )?;
            }
            if !queue_columns
                .iter()
                .any(|column| column.name == "total_bytes")
            {
                sql.exec_batch(
                    "ALTER TABLE queues ADD COLUMN total_bytes INTEGER NOT NULL DEFAULT 0",
                )?;
            }

            sql.exec_batch(SCHEMA_V4)?;

            // Backfill per-queue counters, prune empty pre-v4 queues while capturing the maximum
            // historical sequence into `recipient_stats.sequence_floor`, and backfill dedup counts.
            sql.exec(
                "UPDATE queues SET \
                 message_count = coalesce((SELECT count(*) FROM messages m WHERE m.sender = queues.sender), 0), \
                 total_bytes = coalesce((SELECT sum(length(m.header) + m.size + coalesce(length(m.initial_message), 0)) \
                     FROM messages m WHERE m.sender = queues.sender), 0)",
                vec![],
            )?;
            let pre_prune_max = sql
                .query_opt::<OldestRow>("SELECT max(last_sequence) AS oldest FROM queues", vec![])?
                .and_then(|row| row.oldest)
                .unwrap_or(0);
            sql.exec("DELETE FROM queues WHERE message_count = 0", vec![])?;
            sql.exec(
                "INSERT INTO recipient_stats (only, queue_count, total_bytes, sequence_floor) \
                 SELECT 0, count(*), coalesce(sum(total_bytes), 0), ? FROM queues WHERE true \
                 ON CONFLICT (only) DO UPDATE SET \
                 queue_count = excluded.queue_count, \
                 total_bytes = excluded.total_bytes, \
                 sequence_floor = max(recipient_stats.sequence_floor, excluded.sequence_floor)",
                params![pre_prune_max]?,
            )?;
            sql.exec("DELETE FROM dedup_counts", vec![])?;
            sql.exec(
                "INSERT INTO dedup_counts (sender, count) \
                 SELECT sender, count(*) FROM mailbox_dedup GROUP BY sender",
                vec![],
            )?;

            sql.exec(
                "INSERT INTO meta (only, schema_version) VALUES (0, ?) \
                 ON CONFLICT (only) DO UPDATE SET schema_version = excluded.schema_version",
                params![CURRENT_SCHEMA_VERSION]?,
            )?;
            Ok(())
        })?;
        self.cache.schema_ready.set(true);
        Ok(())
    }

    /// Explicit orphan cleanup for `initial_messages_pq` (no reliance on SQLite foreign_keys).
    pub(super) fn cleanup_orphan_pq_initials_sql(sql: &S) -> Result<()> {
        if has_table(sql, "initial_messages_pq")? {
            sql.exec(
                "DELETE FROM initial_messages_pq \
                 WHERE NOT EXISTS (SELECT 1 FROM initial_messages WHERE id = initial_messages_pq.initial_message_id)",
                vec![],
            )?;
        }
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::objects::{
        Content,
        identity::{SchemaCache, TestIdentity},
    };

    #[derive(Debug, Deserialize)]
    struct NameSqlRow {
        name: String,
        sql: Option<String>,
    }

    #[test]
    fn fresh_init_creates_all_tables_indexes_and_sets_schema_version() {
        let env = TestIdentity::new(30_000);
        let store = env.store();

        assert!(!store.has_tables().unwrap());
        assert!(!store.has_seen_subscribes().unwrap());
        assert!(!env.cache.schema_ready.get());

        store.ensure_v2_tables().unwrap();
        assert!(env.cache.schema_ready.get());
        assert!(store.has_tables().unwrap());

        let version: SchemaVersionRow = env
            .sql
            .query_one("SELECT schema_version FROM meta WHERE only = 0", vec![])
            .unwrap();
        assert_eq!(version.schema_version, CURRENT_SCHEMA_VERSION);

        for table in [
            "bundle",
            "one_time_prekeys",
            "inbox",
            "initial_messages",
            "queues",
            "messages",
            "meta",
            "capability_manifest",
            "pq_last_resort",
            "pq_one_time_prekeys",
            "initial_messages_pq",
            "mailbox_dedup",
            "publish_watermarks",
            "recipient_stats",
            "dedup_counts",
            "pending_r2_deletes",
            "opk_claim_budget",
        ] {
            assert!(
                has_table(&env.sql, table).unwrap(),
                "missing expected table {table}"
            );
        }

        let indexes: Vec<NameSqlRow> = env
            .sql
            .query(
                "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL",
                vec![],
            )
            .unwrap();
        let index_map: std::collections::HashMap<String, String> = indexes
            .into_iter()
            .filter_map(|r| r.sql.map(|s| (r.name, s)))
            .collect();
        for idx in [
            "messages_by_age",
            "messages_inline_by_age",
            "messages_object_by_age",
            "initial_messages_by_age",
            "mailbox_dedup_by_age",
            "mailbox_dedup_by_expiry",
            "mailbox_dedup_by_sender",
            "pending_r2_deletes_by_age",
        ] {
            assert!(index_map.contains_key(idx), "missing expected index {idx}");
        }
        assert!(index_map["messages_inline_by_age"].contains("WHERE object IS NULL"));
        assert!(index_map["messages_object_by_age"].contains("WHERE object IS NOT NULL"));
    }

    #[test]
    fn repeated_init_is_idempotent_across_warm_and_cold_starts() {
        let env = TestIdentity::new(30_000);
        let store = env.store();
        store.ensure_v2_tables().unwrap();

        let sender = [7u8; 32];
        store
            .append(
                &sender,
                b"hdr",
                &Content::Inline(b"hello".to_vec()),
                5,
                None,
                None,
                None,
                1_000,
            )
            .unwrap();

        // Warm-cache repeated call.
        store.ensure_v2_tables().unwrap();

        // Cold-start instance against the same SQLite database hits the version fast path.
        let cold_cache = SchemaCache::default();
        let cold_store = env.store_with_cache(&cold_cache);
        assert!(!cold_cache.schema_ready.get());
        cold_store.ensure_v2_tables().unwrap();
        assert!(cold_cache.schema_ready.get());

        // Existing rows survive untouched.
        let rows = cold_store.read(&sender, 0, 10, 1024, 1_000).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].sequence, 1);
    }

    #[test]
    fn schema_enforces_singleton_message_content_and_unique_constraints() {
        let env = TestIdentity::new(30_000);
        let store = env.store();
        store.ensure_v2_tables().unwrap();

        // Singleton CHECK (only = 0) rejects only = 1.
        assert!(
            env.sql
                .exec(
                    "INSERT INTO meta (only, schema_version) VALUES (1, 4)",
                    vec![]
                )
                .is_err()
        );
        assert!(
            env.sql
                .exec(
                    "INSERT INTO recipient_stats (only, queue_count, total_bytes, sequence_floor) \
                     VALUES (1, 0, 0, 0)",
                    vec![]
                )
                .is_err()
        );
        assert!(
            env.sql
                .exec(
                    "INSERT INTO opk_claim_budget (only, window_start, claims) VALUES (1, 0, 0)",
                    vec![]
                )
                .is_err()
        );

        // messages CHECK ((content IS NULL) != (object IS NULL)):
        // Both NULL -> rejected.
        assert!(
            env.sql
                .exec(
                    "INSERT INTO messages (sender, sequence, header, content, object, size, created_at) \
                     VALUES (?, 1, ?, NULL, NULL, 0, 100)",
                    params![[1u8; 32].as_slice(), b"h".as_slice()].unwrap()
                )
                .is_err()
        );
        // Both non-NULL -> rejected.
        assert!(
            env.sql
                .exec(
                    "INSERT INTO messages (sender, sequence, header, content, object, size, created_at) \
                     VALUES (?, 1, ?, ?, 'messages/obj', 1, 100)",
                    params![[1u8; 32].as_slice(), b"h".as_slice(), b"x".as_slice()].unwrap()
                )
                .is_err()
        );

        // pq_one_time_prekeys UNIQUE(prekey_id) rejects duplicate prekey IDs.
        env.sql
            .exec(
                "INSERT INTO pq_one_time_prekeys (suite, prekey_id, encapsulation_key, signature) \
                 VALUES (1, ?, ?, ?)",
                params![b"id-1".as_slice(), b"ek".as_slice(), b"sig".as_slice()].unwrap(),
            )
            .unwrap();
        assert!(
            env.sql
                .exec(
                    "INSERT INTO pq_one_time_prekeys (suite, prekey_id, encapsulation_key, signature) \
                     VALUES (1, ?, ?, ?)",
                    params![b"id-1".as_slice(), b"ek2".as_slice(), b"sig2".as_slice()].unwrap(),
                )
                .is_err()
        );
    }

    #[test]
    fn incompatible_schema_version_fails_closed_and_empty_meta_reinitializes() {
        // Future/incompatible schema version > CURRENT_SCHEMA_VERSION fails closed without
        // setting schema_ready or overwriting meta.schema_version.
        let future_env = TestIdentity::new(30_000);
        future_env
            .sql
            .exec_batch(
                "CREATE TABLE meta (only INTEGER PRIMARY KEY CHECK (only = 0), schema_version INTEGER NOT NULL); \
                 INSERT INTO meta (only, schema_version) VALUES (0, 99);",
            )
            .unwrap();
        let err = future_env.store().ensure_v2_tables().unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported identity schema version 99")
        );
        assert!(!future_env.cache.schema_ready.get());
        let ver: SchemaVersionRow = future_env
            .sql
            .query_one("SELECT schema_version FROM meta WHERE only = 0", vec![])
            .unwrap();
        assert_eq!(ver.schema_version, 99);

        // Empty `meta` table (e.g. interrupted init with schema_version missing) cleanly
        // re-initializes to CURRENT_SCHEMA_VERSION.
        let empty_meta = TestIdentity::new(30_000);
        empty_meta
            .sql
            .exec_batch(
                "CREATE TABLE meta (only INTEGER PRIMARY KEY CHECK (only = 0), schema_version INTEGER NOT NULL);",
            )
            .unwrap();
        empty_meta.store().ensure_v2_tables().unwrap();
        assert!(empty_meta.cache.schema_ready.get());
        let ver: SchemaVersionRow = empty_meta
            .sql
            .query_one("SELECT schema_version FROM meta WHERE only = 0", vec![])
            .unwrap();
        assert_eq!(ver.schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn cleanup_orphan_pq_initials_removes_only_unlinked_rows() {
        let env = TestIdentity::new(30_000);
        let store = env.store();
        store.ensure_v2_tables().unwrap();

        // Insert one real initial_messages row (id = 1) and two initial_messages_pq rows (1 and 99).
        env.sql
            .exec(
                "INSERT INTO initial_messages (id, sender, ephemeral_key, signed_prekey, header, content, created_at) \
                 VALUES (1, ?, ?, ?, ?, ?, 100)",
                params![
                    [1u8; 32].as_slice(),
                    [2u8; 32].as_slice(),
                    [3u8; 32].as_slice(),
                    b"h".as_slice(),
                    b"c".as_slice()
                ]
                .unwrap(),
            )
            .unwrap();
        for id in [1u64, 99u64] {
            env.sql
                .exec(
                    "INSERT INTO initial_messages_pq \
                     (initial_message_id, version, pq_suite, pq_last_resort, pq_prekey_id, pq_ciphertext) \
                     VALUES (?, 2, 1, 0, ?, ?)",
                    params![id, b"pk".as_slice(), b"ct".as_slice()].unwrap(),
                )
                .unwrap();
        }

        IdentityStore::cleanup_orphan_pq_initials_sql(&env.sql).unwrap();

        #[derive(Deserialize)]
        struct PqIdRow {
            initial_message_id: u64,
        }
        let remaining: Vec<PqIdRow> = env
            .sql
            .query(
                "SELECT initial_message_id FROM initial_messages_pq ORDER BY initial_message_id",
                vec![],
            )
            .unwrap();
        assert_eq!(
            remaining
                .into_iter()
                .map(|r| r.initial_message_id)
                .collect::<Vec<_>>(),
            vec![1]
        );
    }
}
