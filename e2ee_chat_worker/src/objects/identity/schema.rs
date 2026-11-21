//! Identity tables and in-place v1/v2 -> v3 schema upgrades.

use storage::MAX_SAFE_INTEGER;
use worker::{Result, SqlStorage};

use super::{Identity, mailbox::DEDUP_TTL_MS, rows::TableInfoRow};
use crate::objects::{checked_integer, has_table};

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
const MIGRATE_META_TO_V3: &str =
    "UPDATE meta SET schema_version = 3 WHERE only = 0 AND schema_version < 3";

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
        has_table(&self.sql(), "messages")
    }

    /// Creates core v1 tables and additive v2/v3 side tables on first write (upgrading existing
    /// v1/v2 DO instances in-place without losing rows).
    pub(super) fn create_tables(&self) -> Result<()> {
        let sql = self.sql();
        sql.exec(SCHEMA_V1, None)?;
        sql.exec(SCHEMA_V2, None)?;
        self.ensure_mailbox_dedup_schema(&sql)
    }

    /// Ensures additive v2/v3 side tables exist (for upgrading an existing v1/v2 DO in-place on
    /// first write).
    pub(super) fn ensure_v2_tables(&self) -> Result<()> {
        self.create_tables()
    }

    /// Commit the expiry column, backfill, indexes, and version together on the first access.
    pub(super) fn ensure_mailbox_dedup_schema(&self, sql: &SqlStorage) -> Result<()> {
        if self.dedup_schema_ready.get() || !has_table(sql, "mailbox_dedup")? {
            return Ok(());
        }
        self.transaction_sync(|sql| {
            let columns = sql
                .exec("PRAGMA table_info(mailbox_dedup)", None)?
                .to_array::<TableInfoRow>()?;
            if !columns.iter().any(|column| column.name == "expires_at") {
                sql.exec(MIGRATE_DEDUP_ADD_EXPIRES_AT, None)?;
                sql.exec(
                    MIGRATE_DEDUP_BACKFILL_EXPIRES_AT,
                    vec![
                        checked_integer(MAX_SAFE_INTEGER - DEDUP_TTL_MS)?,
                        checked_integer(MAX_SAFE_INTEGER)?,
                        checked_integer(DEDUP_TTL_MS)?,
                    ],
                )?;
            }
            sql.exec(MIGRATE_DEDUP_INDEXES, None)?;
            if has_table(sql, "meta")? {
                sql.exec(MIGRATE_META_TO_V3, None)?;
            }
            Ok(())
        })?;
        self.dedup_schema_ready.set(true);
        Ok(())
    }

    /// Explicit orphan cleanup for `initial_messages_pq` (no reliance on SQLite foreign_keys).
    pub(super) fn cleanup_orphan_pq_initials(&self) -> Result<()> {
        let sql = self.sql();
        if has_table(&sql, "initial_messages_pq")? {
            sql.exec(
                "DELETE FROM initial_messages_pq \
                 WHERE NOT EXISTS (SELECT 1 FROM initial_messages WHERE id = initial_messages_pq.initial_message_id)",
                None,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_v1_v2_v3_migration_schema_is_preserved_intact() {
        for table in [
            "CREATE TABLE IF NOT EXISTS bundle",
            "CREATE TABLE IF NOT EXISTS one_time_prekeys",
            "CREATE TABLE IF NOT EXISTS inbox",
            "CREATE TABLE IF NOT EXISTS initial_messages",
            "CREATE TABLE IF NOT EXISTS queues",
            "CREATE TABLE IF NOT EXISTS messages",
        ] {
            assert!(SCHEMA_V1.contains(table), "missing v1 table: {table}");
        }

        for table in [
            "CREATE TABLE IF NOT EXISTS meta",
            "INSERT INTO meta (only, schema_version) VALUES (0, 2)",
            "CREATE TABLE IF NOT EXISTS capability_manifest",
            "CREATE TABLE IF NOT EXISTS pq_last_resort",
            "CREATE TABLE IF NOT EXISTS pq_one_time_prekeys",
            "CREATE TABLE IF NOT EXISTS initial_messages_pq",
            "CREATE TABLE IF NOT EXISTS mailbox_dedup",
            "CREATE TABLE IF NOT EXISTS publish_watermarks",
        ] {
            assert!(SCHEMA_V2.contains(table), "missing v2 table: {table}");
        }

        assert!(MIGRATE_DEDUP_ADD_EXPIRES_AT.contains("ADD COLUMN expires_at"));
        assert!(MIGRATE_DEDUP_BACKFILL_EXPIRES_AT.contains("SET expires_at = CASE"));
        assert!(MIGRATE_DEDUP_INDEXES.contains("mailbox_dedup_by_expiry"));
        assert!(MIGRATE_DEDUP_INDEXES.contains("mailbox_dedup_by_sender"));
        assert!(MIGRATE_META_TO_V3.contains("schema_version = 3"));
        assert!(SCHEMA_SEEN_SUBSCRIBES.contains("CREATE TABLE IF NOT EXISTS seen_subscribes"));
        assert!(MAX_SAFE_INTEGER > DEDUP_TTL_MS);
    }
}
