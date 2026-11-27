//! Canonical `SCHEMA_V5` identity tables (`CURRENT_SCHEMA_VERSION = 5`, fail-closed on version
//! mismatch).
//!
//! Cloudflare Durable Object SQLite does not support `PRAGMA user_version`, so schema readiness
//! is persisted in `meta.schema_version` and cached per Durable Object instance in
//! `SchemaCache::schema_ready` (`Cell<bool>`), eliminating per-write DDL and `sqlite_master`
//! lookups.

use storage::MAX_SAFE_INTEGER;
use worker::{Error, Result};

use super::{
    IdentityStore,
    mailbox::DEDUP_TTL_MS,
    rows::{CountRow, SchemaVersionRow},
};
use crate::objects::{
    has_table,
    sql::{SqlExec, params},
};

pub(super) const CURRENT_SCHEMA_VERSION: u64 = 5;

const _: () = assert!(MAX_SAFE_INTEGER > DEDUP_TTL_MS);

/// Canonical `SCHEMA_V5` tables and indexes for `IdentityV2` (zero legacy v1/v4 migration tables,
/// zero mailbox R2 columns or tables).
const SCHEMA_V5: &str = "
CREATE TABLE IF NOT EXISTS meta (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    schema_version INTEGER NOT NULL
);
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
    prev_signed_prekey BLOB,
    signed_prekey_signature BLOB,
    pq_last_resort_commitments BLOB NOT NULL,
    signature BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    position INTEGER PRIMARY KEY,
    prekey BLOB NOT NULL
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
CREATE TABLE IF NOT EXISTS opk_claim_budget (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    window_start INTEGER NOT NULL,
    claims INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS publish_watermarks (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    last_refill_ts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS initial_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version INTEGER NOT NULL,
    sender BLOB NOT NULL,
    ephemeral_key BLOB NOT NULL,
    signed_prekey BLOB NOT NULL,
    one_time_prekey BLOB,
    header BLOB NOT NULL,
    content BLOB NOT NULL,
    pq_suite INTEGER,
    pq_last_resort INTEGER NOT NULL DEFAULT 0,
    pq_prekey_id BLOB,
    pq_ciphertext BLOB,
    manifest_digest BLOB,
    payload_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (sender, ephemeral_key)
);
CREATE INDEX IF NOT EXISTS initial_messages_by_age ON initial_messages (created_at);
CREATE TABLE IF NOT EXISTS recipient_stats (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    last_sequence INTEGER NOT NULL DEFAULT 0,
    message_count INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    authorized_peer_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS peer_grants (
    peer_slot_id BLOB PRIMARY KEY,
    max_version INTEGER NOT NULL DEFAULT 0,
    revoked_below_version INTEGER NOT NULL DEFAULT 0,
    revoked_at INTEGER NOT NULL DEFAULT 0,
    active_token_hash BLOB,
    message_count INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS write_tokens (
    token_hash BLOB PRIMARY KEY,
    peer_slot_id BLOB NOT NULL,
    grant_version INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS write_tokens_by_peer ON write_tokens (peer_slot_id, grant_version);
CREATE TABLE IF NOT EXISTS messages (
    sequence INTEGER PRIMARY KEY,
    peer_slot_id BLOB NOT NULL,
    token_hash BLOB NOT NULL,
    header BLOB NOT NULL,
    content BLOB NOT NULL,
    initial_message BLOB,
    bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_by_age ON messages (created_at);
CREATE INDEX IF NOT EXISTS messages_by_peer ON messages (peer_slot_id, sequence);
CREATE TABLE IF NOT EXISTS mailbox_dedup (
    token_hash BLOB NOT NULL,
    client_message_id BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (token_hash, client_message_id)
);
CREATE INDEX IF NOT EXISTS mailbox_dedup_by_expiry ON mailbox_dedup (expires_at);
CREATE INDEX IF NOT EXISTS mailbox_dedup_by_token ON mailbox_dedup (token_hash, created_at, sequence);
CREATE TABLE IF NOT EXISTS dedup_counts (
    token_hash BLOB PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0
);
";

/// Tracks verified audience- and nonce-bound v2 subscriptions for replay protection (lazy table).
pub(super) const SCHEMA_SEEN_SUBSCRIBES: &str = "
CREATE TABLE IF NOT EXISTS seen_subscribes (
    sig_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS seen_subscribes_by_expiry ON seen_subscribes (expires_at);
";

fn version_mismatch_error(found: u64) -> Error {
    Error::RustError(format!(
        "unsupported identity schema version {found} (expected {CURRENT_SCHEMA_VERSION})"
    ))
}

/// Idempotently add `capability_manifest.prev_signed_prekey` when opening an earlier `SCHEMA_V5`
/// database created prior to retired-SPK tracking so neither reads nor writes fail with
/// `"no such column: prev_signed_prekey"`.
fn ensure_v5_prev_spk_column<S: SqlExec>(sql: &S) -> Result<()> {
    let col: CountRow = sql.query_one(
        "SELECT count(*) AS count FROM pragma_table_info('capability_manifest') \
         WHERE name = 'prev_signed_prekey'",
        vec![],
    )?;
    if col.count == 0 {
        sql.exec(
            "ALTER TABLE capability_manifest ADD COLUMN prev_signed_prekey BLOB",
            vec![],
        )?;
    }
    Ok(())
}

impl<S: SqlExec> IdentityStore<'_, S> {
    /// Whether canonical `SCHEMA_V5` tables exist, leaving unknown-identity DOs unallocated and
    /// failing closed if `meta.schema_version != 5`.
    pub(super) fn has_tables(&self) -> Result<bool> {
        if self.cache.schema_ready.get() {
            return Ok(true);
        }
        if !has_table(self.sql, "meta")? {
            return Ok(false);
        }
        match self.sql.query_opt::<SchemaVersionRow>(
            "SELECT schema_version FROM meta WHERE only = 0",
            vec![],
        )? {
            Some(row) if row.schema_version == CURRENT_SCHEMA_VERSION => {
                ensure_v5_prev_spk_column(self.sql)?;
                self.cache.schema_ready.set(true);
                Ok(true)
            }
            Some(row) => Err(version_mismatch_error(row.schema_version)),
            None => Ok(false),
        }
    }

    /// Whether the lazy `seen_subscribes` replay table exists, cached once observed.
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

    /// Ensures all `SCHEMA_V5` tables and indexes exist, failing closed on any
    /// `meta.schema_version != 5`.
    ///
    /// Fast path: zero SQL statements after the first check in this DO instance, and zero DDL
    /// statements on cold start when `meta.schema_version == 5` and `prev_signed_prekey` exists.
    pub(super) fn ensure_v5_tables(&self) -> Result<()> {
        if self.has_tables()? {
            return Ok(());
        }
        self.sql.transaction_sync(|sql| {
            if has_table(sql, "meta")?
                && let Some(row) = sql.query_opt::<SchemaVersionRow>(
                    "SELECT schema_version FROM meta WHERE only = 0",
                    vec![],
                )?
            {
                if row.schema_version == CURRENT_SCHEMA_VERSION {
                    ensure_v5_prev_spk_column(sql)?;
                    return Ok(());
                }
                return Err(version_mismatch_error(row.schema_version));
            }
            sql.exec_batch(SCHEMA_V5)?;
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
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::objects::identity::{SchemaCache, TestIdentity};

    #[derive(Debug, Deserialize)]
    struct NameSqlRow {
        name: String,
        sql: Option<String>,
    }

    #[test]
    fn fresh_init_creates_canonical_v5_tables_and_indexes_without_legacy_tables() {
        let env = TestIdentity::new(30_000);
        let store = env.store();

        assert!(!store.has_tables().unwrap());
        assert!(!store.has_seen_subscribes().unwrap());
        assert!(!env.cache.schema_ready.get());

        store.ensure_v5_tables().unwrap();
        assert!(env.cache.schema_ready.get());
        assert!(store.has_tables().unwrap());

        let version: SchemaVersionRow = env
            .sql
            .query_one("SELECT schema_version FROM meta WHERE only = 0", vec![])
            .unwrap();
        assert_eq!(version.schema_version, CURRENT_SCHEMA_VERSION);

        for table in [
            "meta",
            "capability_manifest",
            "one_time_prekeys",
            "pq_last_resort",
            "pq_one_time_prekeys",
            "opk_claim_budget",
            "publish_watermarks",
            "initial_messages",
            "recipient_stats",
            "peer_grants",
            "write_tokens",
            "messages",
            "mailbox_dedup",
            "dedup_counts",
        ] {
            assert!(
                has_table(&env.sql, table).unwrap(),
                "missing expected SCHEMA_V5 table {table}"
            );
        }

        // Legacy v1-v4 / mailbox R2 tables must NOT exist.
        for deleted_table in [
            "bundle",
            "inbox",
            "queues",
            "initial_messages_pq",
            "pending_r2_deletes",
        ] {
            assert!(
                !has_table(&env.sql, deleted_table).unwrap(),
                "unexpected legacy table {deleted_table}"
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
            "initial_messages_by_age",
            "write_tokens_by_peer",
            "messages_by_age",
            "messages_by_peer",
            "mailbox_dedup_by_expiry",
            "mailbox_dedup_by_token",
        ] {
            assert!(index_map.contains_key(idx), "missing expected index {idx}");
        }
    }

    #[test]
    fn repeated_init_is_idempotent_across_warm_and_cold_starts() {
        let env = TestIdentity::new(30_000);
        let store = env.store();
        store.ensure_v5_tables().unwrap();

        // Warm-cache repeated call.
        store.ensure_v5_tables().unwrap();

        // Cold-start instance against the same SQLite database hits the version fast path.
        let cold_cache = SchemaCache::default();
        let cold_store = env.store_with_cache(&cold_cache);
        assert!(!cold_cache.schema_ready.get());
        cold_store.ensure_v5_tables().unwrap();
        assert!(cold_cache.schema_ready.get());
    }

    #[test]
    fn schema_enforces_singleton_and_unique_constraints() {
        let env = TestIdentity::new(30_000);
        let store = env.store();
        store.ensure_v5_tables().unwrap();

        // Singleton CHECK (only = 0) rejects only = 1.
        assert!(
            env.sql
                .exec(
                    "INSERT INTO meta (only, schema_version) VALUES (1, 5)",
                    vec![]
                )
                .is_err()
        );
        assert!(
            env.sql
                .exec(
                    "INSERT INTO recipient_stats (only, last_sequence, message_count, total_bytes, authorized_peer_count) \
                     VALUES (1, 0, 0, 0, 0)",
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

        // initial_messages UNIQUE(sender, ephemeral_key) rejects duplicates.
        env.sql
            .exec(
                "INSERT INTO initial_messages \
                 (version, sender, ephemeral_key, signed_prekey, header, content, payload_hash, created_at) \
                 VALUES (1, ?, ?, ?, ?, ?, ?, 100)",
                params![
                    [1u8; 32].as_slice(),
                    [2u8; 32].as_slice(),
                    [3u8; 32].as_slice(),
                    b"h".as_slice(),
                    b"c".as_slice(),
                    [4u8; 32].as_slice()
                ]
                .unwrap(),
            )
            .unwrap();
        assert!(
            env.sql
                .exec(
                    "INSERT INTO initial_messages \
                     (version, sender, ephemeral_key, signed_prekey, header, content, payload_hash, created_at) \
                     VALUES (1, ?, ?, ?, ?, ?, ?, 101)",
                    params![
                        [1u8; 32].as_slice(),
                        [2u8; 32].as_slice(),
                        [3u8; 32].as_slice(),
                        b"h".as_slice(),
                        b"c".as_slice(),
                        [4u8; 32].as_slice()
                    ]
                    .unwrap(),
                )
                .is_err()
        );
    }

    #[test]
    fn incompatible_schema_version_fails_closed_for_both_older_and_newer_versions() {
        for bad_version in [4u64, 6u64, 99u64] {
            let env = TestIdentity::new(30_000);
            env.sql
                .exec_batch(&format!(
                    "CREATE TABLE meta (only INTEGER PRIMARY KEY CHECK (only = 0), schema_version INTEGER NOT NULL); \
                     INSERT INTO meta (only, schema_version) VALUES (0, {bad_version});"
                ))
                .unwrap();

            // Both reads (`has_tables`) and writes (`ensure_v5_tables`) fail closed.
            let err_read = env.store().has_tables().unwrap_err();
            assert!(err_read.to_string().contains(&format!(
                "unsupported identity schema version {bad_version}"
            )));
            let err_write = env.store().ensure_v5_tables().unwrap_err();
            assert!(err_write.to_string().contains(&format!(
                "unsupported identity schema version {bad_version}"
            )));
            assert!(!env.cache.schema_ready.get());
            let ver: SchemaVersionRow = env
                .sql
                .query_one("SELECT schema_version FROM meta WHERE only = 0", vec![])
                .unwrap();
            assert_eq!(ver.schema_version, bad_version);
        }

        // Empty `meta` table (e.g. interrupted init with schema_version missing) cleanly
        // re-initializes to CURRENT_SCHEMA_VERSION.
        let empty_meta = TestIdentity::new(30_000);
        empty_meta
            .sql
            .exec_batch(
                "CREATE TABLE meta (only INTEGER PRIMARY KEY CHECK (only = 0), schema_version INTEGER NOT NULL);",
            )
            .unwrap();
        assert!(!empty_meta.store().has_tables().unwrap());
        empty_meta.store().ensure_v5_tables().unwrap();
        assert!(empty_meta.cache.schema_ready.get());
        let ver: SchemaVersionRow = empty_meta
            .sql
            .query_one("SELECT schema_version FROM meta WHERE only = 0", vec![])
            .unwrap();
        assert_eq!(ver.schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn r3_p2_10_existing_v5_schema_without_prev_spk_column_auto_migrates() {
        use storage::{
            Bytes, PublishV2Record, PublishV2Status, StoredCapabilityManifest,
            StoredInitialMessageV2,
        };

        let env = TestIdentity::new(30_000);
        // Create a pre-4f88786 SCHEMA_V5 table layout lacking `prev_signed_prekey`.
        let legacy_v5 = SCHEMA_V5.replace("prev_signed_prekey BLOB,\n", "");
        assert!(!legacy_v5.contains("prev_signed_prekey"));
        env.sql.exec_batch(&legacy_v5).unwrap();
        env.sql
            .exec(
                "INSERT INTO meta (only, schema_version) VALUES (0, ?)",
                params![CURRENT_SCHEMA_VERSION].unwrap(),
            )
            .unwrap();

        // Cold-start `has_tables()` detects the missing column and runs idempotent ALTER TABLE.
        assert!(env.store().has_tables().unwrap());
        assert!(env.cache.schema_ready.get());
        let col: CountRow = env
            .sql
            .query_one(
                "SELECT count(*) AS count FROM pragma_table_info('capability_manifest') \
                 WHERE name = 'prev_signed_prekey'",
                vec![],
            )
            .unwrap();
        assert_eq!(col.count, 1);

        // Cold-start `ensure_v5_tables()` on a fresh cache is also idempotent and publish + initial
        // insert work end-to-end with `prev_signed_prekey` tracking.
        let fresh_cache = SchemaCache::default();
        let store = env.store_with_cache(&fresh_cache);
        store.ensure_v5_tables().unwrap();

        let bob = [0x22; 32];
        let alice = [0x11; 32];
        let mk_manifest = |seq: u64, spk: [u8; 32]| StoredCapabilityManifest {
            audience: "relay.example".into(),
            identity_key: bob,
            manifest_seq: seq,
            generation: seq,
            issued_at: 1_000,
            expires_at: 100_000,
            pq_enabled: false,
            strict_pq: false,
            pq_ratchet_supported: false,
            offered_suites: vec![],
            signed_prekey: spk,
            pq_last_resort: vec![],
            signature: [0x44; 64],
        };
        assert_eq!(
            store
                .publish_v2(&PublishV2Record {
                    manifest: mk_manifest(1, [0x31; 32]),
                    signed_prekey_signature: Some([0x55; 64]),
                    one_time_prekeys: vec![],
                    pq_last_resort: vec![],
                    pq_one_time_prekeys: vec![],
                    timestamp: 1_000,
                })
                .unwrap(),
            PublishV2Status::Stored
        );
        assert_eq!(
            store
                .publish_v2(&PublishV2Record {
                    manifest: mk_manifest(2, [0x32; 32]),
                    signed_prekey_signature: Some([0x55; 64]),
                    one_time_prekeys: vec![],
                    pq_last_resort: vec![],
                    pq_one_time_prekeys: vec![],
                    timestamp: 2_000,
                })
                .unwrap(),
            PublishV2Status::Stored
        );
        assert!(matches!(
            store
                .add_initial_message_v2(
                    &StoredInitialMessageV2 {
                        id: 0,
                        version: 1,
                        sender: alice,
                        recipient: bob,
                        ephemeral_key: [0x77; 32],
                        signed_prekey: [0x31; 32],
                        one_time_prekey: None,
                        header: Bytes::from_static(b"h"),
                        content: Bytes::from_static(b"c"),
                        pq_suite: None,
                        pq_last_resort: false,
                        pq_prekey_id: None,
                        pq_ciphertext: None,
                        manifest_digest: None,
                    },
                    10,
                    2_100,
                )
                .unwrap(),
            crate::objects::identity::AddInitialOutcome::Added { inserted: true, .. }
        ));
    }
}
