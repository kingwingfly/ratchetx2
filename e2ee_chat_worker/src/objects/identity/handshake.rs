//! V2 capability manifests, classical and post-quantum prekeys, and the two-phase handshake inbox.

use std::collections::HashSet;

use worker::{Error, Result};

use super::{IdentityStore, rows::*};
use crate::objects::{
    ClaimBundleOutcome, ClaimedBundleWire, InitialMessageV2Wire, ManifestWire, PqCommitmentWire,
    PqPrekeyWire, PqSnapshotWire, PublishV2Outcome, RefillOutcome,
    sql::{SqlExec, checked_integer, params},
};

/// Sliding window for the per-identity one-time prekey claim budget (1 hour).
const OPK_BUDGET_WINDOW_MS: u64 = 60 * 60 * 1000;
/// Maximum OPK-consuming `ClaimBundle` calls per identity within [`OPK_BUDGET_WINDOW_MS`].
/// Past this cap, bundles are still returned (with SPK and PQ last-resort) without popping OPKs.
const MAX_OPK_CLAIMS_PER_HOUR: u64 = 32;

#[derive(Clone, Copy)]
enum PqPrekeyTable {
    LastResort,
    OneTime,
}

fn insert_pq_prekey<S: SqlExec>(sql: &S, table: PqPrekeyTable, key: &PqPrekeyWire) -> Result<()> {
    let stmt = match table {
        PqPrekeyTable::LastResort => {
            "INSERT INTO pq_last_resort (suite, prekey_id, encapsulation_key, signature) \
             VALUES (?, ?, ?, ?)"
        }
        PqPrekeyTable::OneTime => {
            "INSERT INTO pq_one_time_prekeys (suite, prekey_id, encapsulation_key, signature) \
             VALUES (?, ?, ?, ?)"
        }
    };
    sql.exec(
        stmt,
        params![
            key.suite,
            key.id.as_slice(),
            key.encapsulation_key.as_slice(),
            key.signature.as_slice()
        ]?,
    )
}

/// Evaluates the per-identity hourly OPK claim budget.
/// Returns `(allowed, next_window_start, next_claims)`.
fn opk_budget_step(current: Option<(u64, u64)>, now_ms: u64) -> (bool, u64, u64) {
    match current {
        Some((window_start, claims))
            if now_ms >= window_start
                && now_ms.saturating_sub(window_start) < OPK_BUDGET_WINDOW_MS =>
        {
            if claims >= MAX_OPK_CLAIMS_PER_HOUR {
                (false, window_start, claims)
            } else {
                (true, window_start, claims + 1)
            }
        }
        _ => (true, now_ms, 1),
    }
}

impl<S: SqlExec> IdentityStore<'_, S> {
    fn pop_classical_opk_sql(sql: &S) -> Result<Option<Vec<u8>>> {
        let prekey: Option<PrekeyRow> = sql.query_opt(
            "SELECT position, prekey FROM one_time_prekeys ORDER BY position LIMIT 1",
            vec![],
        )?;
        if let Some(ref prekey) = prekey {
            sql.exec(
                "DELETE FROM one_time_prekeys WHERE position = ?",
                params![prekey.position]?,
            )?;
        }
        Ok(prekey.map(|p| p.prekey.into_vec()))
    }

    fn negotiate_last_resort(
        &self,
        sql: &S,
        manifest: &ManifestWire,
        preferred_suites: &[u8],
    ) -> Result<Option<PqPrekeyWire>> {
        if !manifest.pq_enabled
            || preferred_suites.is_empty()
            || !self.has_v2_table(sql, "pq_last_resort")?
        {
            return Ok(None);
        }
        for &suite in preferred_suites {
            if !manifest.offered_suites.contains(&suite) {
                continue;
            }
            if let Some(lr) = sql.query_opt::<PqLastResortRow>(
                "SELECT suite, prekey_id, encapsulation_key, signature \
                 FROM pq_last_resort WHERE suite = ?",
                params![suite]?,
            )? {
                return Ok(Some(PqPrekeyWire::from(lr)));
            }
        }
        Ok(None)
    }

    fn pop_pq_otpk(&self, sql: &S, suite: u8) -> Result<Option<PqPrekeyWire>> {
        if !self.has_v2_table(sql, "pq_one_time_prekeys")? {
            return Ok(None);
        }
        let row: Option<PqOneTimeRow> = sql.query_opt(
            "SELECT position, suite, prekey_id, encapsulation_key, signature \
             FROM pq_one_time_prekeys WHERE suite = ? ORDER BY position LIMIT 1",
            params![suite]?,
        )?;
        if let Some(ref r) = row {
            sql.exec(
                "DELETE FROM pq_one_time_prekeys WHERE position = ?",
                params![r.position]?,
            )?;
        }
        Ok(row.map(PqPrekeyWire::from))
    }

    fn get_manifest_sql(&self, sql: &S) -> Result<Option<ManifestWire>> {
        if !self.has_v2_table(sql, "capability_manifest")? {
            return Ok(None);
        }
        let Some(row) = sql.query_opt::<ManifestRow>(
            "SELECT audience, identity_key, manifest_seq, generation, issued_at, expires_at, \
             pq_enabled, strict_pq, pq_ratchet_supported, offered_suites, signed_prekey, \
             pq_last_resort_commitments, signature FROM capability_manifest",
            vec![],
        )?
        else {
            return Ok(None);
        };
        let pq_last_resort: Vec<PqCommitmentWire> =
            postcard::from_bytes(&row.pq_last_resort_commitments)
                .map_err(|e| Error::RustError(e.to_string()))?;
        Ok(Some(ManifestWire {
            audience: row.audience,
            identity_key: row.identity_key.into_vec(),
            manifest_seq: row.manifest_seq,
            generation: row.generation,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            pq_enabled: row.pq_enabled != 0,
            strict_pq: row.strict_pq != 0,
            pq_ratchet_supported: row.pq_ratchet_supported != 0,
            offered_suites: row.offered_suites.into_vec(),
            signed_prekey: row.signed_prekey.into_vec(),
            pq_last_resort,
            signature: row.signature.into_vec(),
        }))
    }

    fn pq_one_time_counts_sql(&self, sql: &S) -> Result<Vec<(u8, u64)>> {
        if !self.has_v2_table(sql, "pq_one_time_prekeys")? {
            return Ok(vec![]);
        }
        let rows: Vec<SuiteCountRow> = sql.query(
            "SELECT suite, count(*) AS count FROM pq_one_time_prekeys GROUP BY suite ORDER BY suite",
            vec![],
        )?;
        Ok(rows.into_iter().map(|r| (r.suite as u8, r.count)).collect())
    }

    pub(super) fn publish_v2(
        &self,
        manifest: &ManifestWire,
        signed_prekey_signature: Option<&[u8]>,
        one_time_prekeys: &[Vec<u8>],
        pq_last_resort: &[PqPrekeyWire],
        pq_one_time_prekeys: &[PqPrekeyWire],
        timestamp: u64,
    ) -> Result<PublishV2Outcome> {
        // Validate and prepare ALL fallible values BEFORE executing any mutating SQL statement so
        // no partial wipe can occur on a validation or serialization failure.
        let _ = checked_integer(timestamp)?;
        let _ = checked_integer(manifest.manifest_seq)?;
        let _ = checked_integer(manifest.generation)?;
        let _ = checked_integer(manifest.issued_at)?;
        let _ = checked_integer(manifest.expires_at)?;

        // Check duplicate classical OPKs, duplicate PQ last-resort suites, and duplicate PQ IDs.
        let mut seen_opks = HashSet::with_capacity(one_time_prekeys.len());
        for (pos, opk) in one_time_prekeys.iter().enumerate() {
            if !seen_opks.insert(opk.as_slice()) {
                return Ok(PublishV2Outcome::DuplicatePrekey);
            }
            let _ = checked_integer(pos as u64)?;
        }
        let mut seen_lr_suites = HashSet::with_capacity(pq_last_resort.len());
        let mut seen_pq = HashSet::with_capacity(pq_last_resort.len() + pq_one_time_prekeys.len());
        for lr in pq_last_resort {
            if !seen_lr_suites.insert(lr.suite) || !seen_pq.insert(lr.id.as_slice()) {
                return Ok(PublishV2Outcome::DuplicatePrekey);
            }
        }
        for opk in pq_one_time_prekeys {
            if !seen_pq.insert(opk.id.as_slice()) {
                return Ok(PublishV2Outcome::DuplicatePrekey);
            }
        }

        let commitments_blob = postcard::to_allocvec(&manifest.pq_last_resort)
            .map_err(|e| Error::RustError(e.to_string()))?;

        self.sql.transaction_sync(|sql| {
            if sql
                .query_opt::<ManifestSeqRow>("SELECT manifest_seq FROM capability_manifest", vec![])?
                .is_some_and(|row| row.manifest_seq >= manifest.manifest_seq)
            {
                return Ok(PublishV2Outcome::StaleSequence);
            }

            // Store or clear classical SPK signature row depending on strict_pq and signature presence.
            if !manifest.strict_pq
                && let Some(sig) = signed_prekey_signature
            {
                let next_ts = sql
                    .query_opt::<TimestampRow>("SELECT timestamp FROM bundle", vec![])?
                    .map_or(timestamp, |r| r.timestamp.max(timestamp));
                sql.exec(
                    "INSERT INTO bundle (only, signed_prekey, signature, timestamp) VALUES (0, ?, ?, ?) \
                     ON CONFLICT (only) DO UPDATE SET signed_prekey = excluded.signed_prekey, \
                     signature = excluded.signature, timestamp = excluded.timestamp",
                    params![manifest.signed_prekey.as_slice(), sig, next_ts]?,
                )?;
            } else {
                sql.exec("DELETE FROM bundle", vec![])?;
            }

            // Replace classical OPKs.
            sql.exec("DELETE FROM one_time_prekeys", vec![])?;
            for (pos, prekey) in one_time_prekeys.iter().enumerate() {
                sql.exec(
                    "INSERT INTO one_time_prekeys (position, prekey) VALUES (?, ?)",
                    params![pos as u64, prekey.as_slice()]?,
                )?;
            }

            // Replace or clear PQ prekeys depending on affirmative pq_enabled flag.
            sql.exec("DELETE FROM pq_last_resort", vec![])?;
            sql.exec("DELETE FROM pq_one_time_prekeys", vec![])?;
            if manifest.pq_enabled {
                for lr in pq_last_resort {
                    insert_pq_prekey(sql, PqPrekeyTable::LastResort, lr)?;
                }
                for opk in pq_one_time_prekeys {
                    insert_pq_prekey(sql, PqPrekeyTable::OneTime, opk)?;
                }
            }

            sql.exec(
                "INSERT INTO capability_manifest \
                 (only, audience, identity_key, manifest_seq, generation, issued_at, expires_at, \
                  pq_enabled, strict_pq, pq_ratchet_supported, offered_suites, signed_prekey, \
                  pq_last_resort_commitments, signature) \
                 VALUES (0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (only) DO UPDATE SET \
                  audience = excluded.audience, identity_key = excluded.identity_key, \
                  manifest_seq = excluded.manifest_seq, generation = excluded.generation, \
                  issued_at = excluded.issued_at, expires_at = excluded.expires_at, \
                  pq_enabled = excluded.pq_enabled, strict_pq = excluded.strict_pq, \
                  pq_ratchet_supported = excluded.pq_ratchet_supported, \
                  offered_suites = excluded.offered_suites, signed_prekey = excluded.signed_prekey, \
                  pq_last_resort_commitments = excluded.pq_last_resort_commitments, \
                  signature = excluded.signature",
                params![
                    manifest.audience.as_str(),
                    manifest.identity_key.as_slice(),
                    manifest.manifest_seq,
                    manifest.generation,
                    manifest.issued_at,
                    manifest.expires_at,
                    manifest.pq_enabled,
                    manifest.strict_pq,
                    manifest.pq_ratchet_supported,
                    manifest.offered_suites.as_slice(),
                    manifest.signed_prekey.as_slice(),
                    commitments_blob.as_slice(),
                    manifest.signature.as_slice()
                ]?,
            )?;
            sql.exec(
                "INSERT INTO publish_watermarks (only, last_v1_publish_ts, last_refill_ts) \
                 VALUES (0, ?, 0) \
                 ON CONFLICT (only) DO UPDATE SET \
                 last_v1_publish_ts = max(publish_watermarks.last_v1_publish_ts, excluded.last_v1_publish_ts)",
                params![timestamp]?,
            )?;
            Ok(PublishV2Outcome::Stored)
        })
    }

    pub(super) fn refill_prekeys(
        &self,
        generation: u64,
        one_time_prekeys: &[Vec<u8>],
        pq_one_time_prekeys: &[PqPrekeyWire],
        max_one_time_prekeys: u64,
        max_pq_one_time_prekeys: u64,
        timestamp: u64,
    ) -> Result<RefillOutcome> {
        let _ = checked_integer(generation)?;
        let _ = checked_integer(timestamp)?;
        if !self.has_tables()? {
            return Ok(RefillOutcome::NotFound);
        }

        self.sql.transaction_sync(|sql| {
            let Some(manifest) = self.get_manifest_sql(sql)? else {
                return Ok(RefillOutcome::NotFound);
            };
            if manifest.generation != generation {
                return Ok(RefillOutcome::StaleGeneration);
            }
            if !pq_one_time_prekeys.is_empty() && !manifest.pq_enabled {
                return Ok(RefillOutcome::SuiteNotOffered);
            }

            if sql
                .query_opt::<WatermarkRow>("SELECT last_refill_ts FROM publish_watermarks", vec![])?
                .is_some_and(|row| row.last_refill_ts >= timestamp)
            {
                return Ok(RefillOutcome::StaleTimestamp);
            }
            let existing_opks: Vec<PrekeyRow> = sql.query(
                "SELECT position, prekey FROM one_time_prekeys ORDER BY position",
                vec![],
            )?;
            if (existing_opks.len() as u64).saturating_add(one_time_prekeys.len() as u64)
                > max_one_time_prekeys
            {
                return Ok(RefillOutcome::LimitExceeded);
            }
            let mut seen_opks: HashSet<&[u8]> =
                existing_opks.iter().map(|r| r.prekey.as_ref()).collect();
            for opk in one_time_prekeys {
                if !seen_opks.insert(opk.as_slice()) {
                    return Ok(RefillOutcome::DuplicatePrekey);
                }
            }

            let existing_pq_ids: Vec<IdBlobRow> =
                sql.query("SELECT prekey_id FROM pq_one_time_prekeys", vec![])?;
            if (existing_pq_ids.len() as u64).saturating_add(pq_one_time_prekeys.len() as u64)
                > max_pq_one_time_prekeys
            {
                return Ok(RefillOutcome::LimitExceeded);
            }
            let lr_ids: Vec<IdBlobRow> =
                sql.query("SELECT prekey_id FROM pq_last_resort", vec![])?;
            let mut seen_pq_ids: HashSet<&[u8]> = existing_pq_ids
                .iter()
                .chain(lr_ids.iter())
                .map(|r| r.prekey_id.as_ref())
                .collect();
            for pq in pq_one_time_prekeys {
                if !manifest.offered_suites.contains(&pq.suite) {
                    return Ok(RefillOutcome::SuiteNotOffered);
                }
                if !seen_pq_ids.insert(pq.id.as_slice()) {
                    return Ok(RefillOutcome::DuplicatePrekey);
                }
            }

            // Pre-validate position integer bindings before mutating SQLite.
            let start_pos = existing_opks.last().map_or(0, |r| r.position + 1);
            for offset in 0..one_time_prekeys.len() {
                let _ = checked_integer(start_pos.saturating_add(offset as u64))?;
            }

            // Record monotonic refill watermark and append OPKs/PQOPKs without rotating SPK.
            sql.exec(
                "INSERT INTO publish_watermarks (only, last_v1_publish_ts, last_refill_ts) \
                 VALUES (0, 0, ?) \
                 ON CONFLICT (only) DO UPDATE SET last_refill_ts = excluded.last_refill_ts",
                params![timestamp]?,
            )?;
            for (offset, opk) in one_time_prekeys.iter().enumerate() {
                sql.exec(
                    "INSERT INTO one_time_prekeys (position, prekey) VALUES (?, ?)",
                    params![start_pos.saturating_add(offset as u64), opk.as_slice()]?,
                )?;
            }
            for pq in pq_one_time_prekeys {
                insert_pq_prekey(sql, PqPrekeyTable::OneTime, pq)?;
            }

            let classical_count = existing_opks.len() as u64 + one_time_prekeys.len() as u64;
            let pq_counts = self.pq_one_time_counts_sql(sql)?;
            Ok(RefillOutcome::Stored {
                classical_count,
                pq_counts,
            })
        })
    }

    pub(super) fn get_manifest(&self) -> Result<Option<ManifestWire>> {
        if !self.has_tables()? {
            return Ok(None);
        }
        self.get_manifest_sql(self.sql)
    }

    /// Atomically validates `reject_pq_on_manifest`, `strict_pq`, suite negotiation, and the
    /// per-identity hourly OPK claim budget BEFORE popping any classical or PQ one-time prekey.
    pub(super) fn claim_bundle_checked(
        &self,
        preferred_suites: &[u8],
        reject_pq_on_manifest: bool,
        now_ms: u64,
    ) -> Result<ClaimBundleOutcome> {
        if !self.has_tables()? {
            return Ok(ClaimBundleOutcome::NotFound);
        }
        self.ensure_v2_tables()?;
        self.sql.transaction_sync(|sql| {
            let current_budget = sql
                .query_opt::<OpkBudgetRow>(
                    "SELECT window_start, claims FROM opk_claim_budget WHERE only = 0",
                    vec![],
                )?
                .map(|row| (row.window_start, row.claims));
            let (budget_allows, next_window_start, next_claims) =
                opk_budget_step(current_budget, now_ms);

            if let Some(manifest) = self.get_manifest_sql(sql)? {
                if reject_pq_on_manifest && manifest.pq_enabled {
                    return Ok(ClaimBundleOutcome::PqDisabledForPqManifest);
                }

                let signed_prekey_signature = if manifest.strict_pq {
                    None
                } else {
                    sql.query_opt::<BundleRow>(
                        "SELECT signed_prekey, signature FROM bundle",
                        vec![],
                    )?
                    .filter(|b| b.signed_prekey.as_ref() == manifest.signed_prekey.as_slice())
                    .map(|b| b.signature.into_vec())
                };
                let pq_last_resort =
                    self.negotiate_last_resort(sql, &manifest, preferred_suites)?;

                // Validate policy & negotiation BEFORE popping any OPK (matches Wave 1 MemoryStore).
                let can_pop_opk = if manifest.strict_pq
                    || (manifest.pq_enabled && !preferred_suites.is_empty())
                {
                    pq_last_resort.is_some()
                } else {
                    signed_prekey_signature.is_some()
                };
                if !can_pop_opk {
                    return Ok(ClaimBundleOutcome::Claimed(Box::new(ClaimedBundleWire {
                        signed_prekey: manifest.signed_prekey.clone(),
                        manifest: Some(manifest),
                        signed_prekey_signature,
                        one_time_prekey: None,
                        pq_last_resort: None,
                        pq_one_time_prekey: None,
                    })));
                }

                let (one_time_prekey, pq_one_time_prekey) = if budget_allows {
                    let pq_opk = match pq_last_resort.as_ref() {
                        Some(lr) => self.pop_pq_otpk(sql, lr.suite)?,
                        None => None,
                    };
                    let classical_opk = Self::pop_classical_opk_sql(sql)?;
                    if classical_opk.is_some() || pq_opk.is_some() {
                        record_opk_budget(sql, next_window_start, next_claims)?;
                    }
                    (classical_opk, pq_opk)
                } else {
                    (None, None)
                };

                return Ok(ClaimBundleOutcome::Claimed(Box::new(ClaimedBundleWire {
                    signed_prekey: manifest.signed_prekey.clone(),
                    manifest: Some(manifest),
                    signed_prekey_signature,
                    one_time_prekey,
                    pq_last_resort,
                    pq_one_time_prekey,
                })));
            }

            // Preserve read compatibility for pre-existing DOs that still have a classical bundle row.
            let Some(bundle) =
                sql.query_opt::<BundleRow>("SELECT signed_prekey, signature FROM bundle", vec![])?
            else {
                return Ok(ClaimBundleOutcome::NotFound);
            };
            let one_time_prekey = if budget_allows {
                let popped = Self::pop_classical_opk_sql(sql)?;
                if popped.is_some() {
                    record_opk_budget(sql, next_window_start, next_claims)?;
                }
                popped
            } else {
                None
            };
            Ok(ClaimBundleOutcome::Claimed(Box::new(ClaimedBundleWire {
                manifest: None,
                signed_prekey: bundle.signed_prekey.into_vec(),
                signed_prekey_signature: Some(bundle.signature.into_vec()),
                one_time_prekey,
                pq_last_resort: None,
                pq_one_time_prekey: None,
            })))
        })
    }

    pub(super) fn add_initial_message_v2(
        &self,
        message: &InitialMessageV2Wire,
        limit: u64,
        now_ms: u64,
    ) -> Result<Option<u64>> {
        let initial_bindings = params![
            message.sender.as_slice(),
            message.ephemeral_key.as_slice(),
            message.signed_prekey.as_slice(),
            message.one_time_prekey.as_deref(),
            message.header.as_slice(),
            message.content.as_slice(),
            now_ms
        ]?;
        let has_pq = message.version != 1;
        if has_pq {
            let _ = checked_integer(u64::from(message.version))?;
        }
        self.sql.transaction_sync(|sql| {
            let count: CountRow =
                sql.query_one("SELECT count(*) AS count FROM initial_messages", vec![])?;
            if count.count >= limit {
                return Ok(None);
            }
            let inserted: IdRow = sql.query_one(
                "INSERT INTO initial_messages (sender, ephemeral_key, signed_prekey, \
                 one_time_prekey, header, content, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
                 RETURNING id",
                initial_bindings,
            )?;
            if has_pq {
                sql.exec(
                    "INSERT INTO initial_messages_pq \
                     (initial_message_id, version, pq_suite, pq_last_resort, pq_prekey_id, \
                      pq_ciphertext, manifest_digest) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    params![
                        inserted.id,
                        message.version,
                        message.pq_suite.unwrap_or(0),
                        message.pq_last_resort,
                        message.pq_prekey_id.as_deref().unwrap_or_default(),
                        message.pq_ciphertext.as_deref().unwrap_or_default(),
                        message.manifest_digest.as_deref()
                    ]?,
                )?;
            }
            Ok(Some(inserted.id))
        })
    }

    pub(super) fn list_initial_messages(
        &self,
        limit: u64,
        now_ms: u64,
    ) -> Result<Vec<InitialMessageV2Wire>> {
        if !self.has_tables()? || limit == 0 {
            return Ok(vec![]);
        }
        let cutoff = now_ms.saturating_sub(self.retention_ms);
        if self.has_v2_table(self.sql, "initial_messages_pq")? {
            let rows: Vec<InitialMessageJoinedRow> = self.sql.query(
                "SELECT m.id, m.sender, m.ephemeral_key, m.signed_prekey, m.one_time_prekey, \
                 m.header, m.content, p.version, p.pq_suite, p.pq_last_resort, \
                 p.pq_prekey_id, p.pq_ciphertext, p.manifest_digest \
                 FROM initial_messages m \
                 LEFT JOIN initial_messages_pq p ON p.initial_message_id = m.id \
                 WHERE m.created_at >= ? \
                 ORDER BY m.id LIMIT ?",
                params![cutoff, limit]?,
            )?;
            Ok(rows.into_iter().map(InitialMessageV2Wire::from).collect())
        } else {
            let rows: Vec<InitialMessageWithIdRow> = self.sql.query(
                "SELECT id, sender, ephemeral_key, signed_prekey, one_time_prekey, header, content \
                 FROM initial_messages WHERE created_at >= ? ORDER BY id LIMIT ?",
                params![cutoff, limit]?,
            )?;
            Ok(rows.into_iter().map(InitialMessageV2Wire::from).collect())
        }
    }

    pub(super) fn ack_initial_messages(&self, ids: &[u64]) -> Result<u64> {
        for &id in ids {
            let _ = checked_integer(id)?;
        }
        if !self.has_tables()? || ids.is_empty() {
            return Ok(0);
        }
        let ids_json = serde_json::to_string(ids).map_err(|e| Error::RustError(e.to_string()))?;
        self.sql.transaction_sync(|sql| {
            if self.has_v2_table(sql, "initial_messages_pq")? {
                sql.exec(
                    "DELETE FROM initial_messages_pq \
                     WHERE initial_message_id IN (SELECT value FROM json_each(?))",
                    params![ids_json.as_str()]?,
                )?;
            }
            let deleted: Vec<IdRow> = sql.query(
                "DELETE FROM initial_messages \
                 WHERE id IN (SELECT value FROM json_each(?)) RETURNING id",
                params![ids_json.as_str()]?,
            )?;
            Self::cleanup_orphan_pq_initials_sql(sql)?;
            Ok(deleted.len() as u64)
        })
    }

    pub(super) fn pq_snapshot(&self, now_ms: u64) -> Result<PqSnapshotWire> {
        if !self.has_tables()? {
            return Ok(PqSnapshotWire {
                manifest: None,
                classical_one_time_count: 0,
                pq_last_resort_suites: vec![],
                pq_one_time_counts: vec![],
                pending_initial_messages: 0,
            });
        }
        let cutoff = now_ms.saturating_sub(self.retention_ms);
        let manifest = self.get_manifest_sql(self.sql)?;
        let classical: CountRow = self
            .sql
            .query_one("SELECT count(*) AS count FROM one_time_prekeys", vec![])?;
        let pq_last_resort_suites = if self.has_v2_table(self.sql, "pq_last_resort")? {
            self.sql
                .query::<SuiteRow>("SELECT suite FROM pq_last_resort ORDER BY suite", vec![])?
                .into_iter()
                .map(|r| r.suite as u8)
                .collect()
        } else {
            vec![]
        };
        let pq_one_time_counts = self.pq_one_time_counts_sql(self.sql)?;
        let pending: CountRow = self.sql.query_one(
            "SELECT count(*) AS count FROM initial_messages WHERE created_at >= ?",
            params![cutoff]?,
        )?;
        Ok(PqSnapshotWire {
            manifest,
            classical_one_time_count: classical.count,
            pq_last_resort_suites,
            pq_one_time_counts,
            pending_initial_messages: pending.count,
        })
    }
}

fn record_opk_budget<S: SqlExec>(sql: &S, window_start: u64, claims: u64) -> Result<()> {
    sql.exec(
        "INSERT INTO opk_claim_budget (only, window_start, claims) VALUES (0, ?, ?) \
         ON CONFLICT (only) DO UPDATE SET window_start = excluded.window_start, \
         claims = excluded.claims",
        params![window_start, claims]?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opk_claim_budget_caps_hourly_claims_and_resets_across_windows() {
        let start = 10_000;
        let mut state = None;
        for expected in 1..=MAX_OPK_CLAIMS_PER_HOUR {
            let (allowed, ws, claims) = opk_budget_step(state, start + expected);
            assert!(allowed);
            assert_eq!(ws, start + 1);
            assert_eq!(claims, expected);
            state = Some((ws, claims));
        }
        // Past the hourly cap within the same window -> denied, state unchanged.
        let (allowed, ws, claims) = opk_budget_step(state, start + OPK_BUDGET_WINDOW_MS);
        assert!(!allowed);
        assert_eq!(ws, start + 1);
        assert_eq!(claims, MAX_OPK_CLAIMS_PER_HOUR);

        // Once the window rolls over -> allowed again from 1.
        let rolled = start + 1 + OPK_BUDGET_WINDOW_MS;
        let (allowed, ws, claims) = opk_budget_step(state, rolled);
        assert!(allowed);
        assert_eq!(ws, rolled);
        assert_eq!(claims, 1);

        // Clock regression resets safely instead of locking out forever.
        let (allowed, ws, claims) = opk_budget_step(state, start - 5);
        assert!(allowed);
        assert_eq!(ws, start - 5);
        assert_eq!(claims, 1);
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native_sqlite_tests {
        use super::*;
        use crate::objects::identity::TestIdentity;

        fn mk_manifest(
            seq: u64,
            generation: u64,
            pq_enabled: bool,
            strict_pq: bool,
        ) -> ManifestWire {
            ManifestWire {
                audience: "relay.example".into(),
                identity_key: vec![0x11; 32],
                manifest_seq: seq,
                generation,
                issued_at: 1_000,
                expires_at: 100_000,
                pq_enabled,
                strict_pq,
                pq_ratchet_supported: pq_enabled,
                offered_suites: if pq_enabled { vec![1, 2] } else { vec![] },
                signed_prekey: vec![0x22; 32],
                pq_last_resort: if pq_enabled {
                    vec![
                        PqCommitmentWire {
                            suite: 1,
                            prekey_id: b"lr-1".to_vec(),
                        },
                        PqCommitmentWire {
                            suite: 2,
                            prekey_id: b"lr-2".to_vec(),
                        },
                    ]
                } else {
                    vec![]
                },
                signature: vec![0x33; 64],
            }
        }

        fn mk_pq_key(suite: u8, id: &[u8]) -> PqPrekeyWire {
            PqPrekeyWire {
                suite,
                id: id.to_vec(),
                encapsulation_key: vec![suite; 32],
                signature: vec![0x44; 64],
            }
        }

        fn mk_opk(idx: u32) -> Vec<u8> {
            let mut key = vec![0u8; 32];
            key[..4].copy_from_slice(&idx.to_be_bytes());
            key
        }

        #[test]
        fn publish_v2_and_refill_enforce_sequences_duplicates_generations_and_caps() {
            let env = TestIdentity::new(50_000);
            let store = env.store();

            // Unknown identity returns None / NotFound without creating tables.
            assert!(store.get_manifest().unwrap().is_none());
            assert!(matches!(
                store.refill_prekeys(1, &[], &[], 10, 10, 1_000).unwrap(),
                RefillOutcome::NotFound
            ));
            assert!(!store.has_tables().unwrap());

            store.ensure_v2_tables().unwrap();

            // Duplicate classical OPK rejected before writing.
            let m1 = mk_manifest(1, 1, true, false);
            assert!(matches!(
                store
                    .publish_v2(
                        &m1,
                        Some(&[0xaa; 64]),
                        &[mk_opk(1), mk_opk(1)],
                        &[mk_pq_key(1, b"lr-1")],
                        &[],
                        1_000
                    )
                    .unwrap(),
                PublishV2Outcome::DuplicatePrekey
            ));
            assert!(store.get_manifest().unwrap().is_none());

            // Duplicate PQ prekey ID (colliding with last-resort) rejected.
            assert!(matches!(
                store
                    .publish_v2(
                        &m1,
                        Some(&[0xaa; 64]),
                        &[mk_opk(1)],
                        &[mk_pq_key(1, b"lr-1")],
                        &[mk_pq_key(1, b"lr-1")],
                        1_000
                    )
                    .unwrap(),
                PublishV2Outcome::DuplicatePrekey
            ));

            // Valid publish succeeds.
            assert!(matches!(
                store
                    .publish_v2(
                        &m1,
                        Some(&[0xaa; 64]),
                        &[mk_opk(1), mk_opk(2)],
                        &[mk_pq_key(1, b"lr-1"), mk_pq_key(2, b"lr-2")],
                        &[mk_pq_key(1, b"opk-1")],
                        1_000
                    )
                    .unwrap(),
                PublishV2Outcome::Stored
            ));
            assert_eq!(store.get_manifest().unwrap().unwrap().manifest_seq, 1);

            // Stale manifest_seq rejected.
            assert!(matches!(
                store
                    .publish_v2(&m1, Some(&[0xaa; 64]), &[], &[], &[], 2_000)
                    .unwrap(),
                PublishV2Outcome::StaleSequence
            ));

            // Refill validations: wrong generation, unoffered suite, duplicate OPK, limit exceeded.
            assert!(matches!(
                store
                    .refill_prekeys(99, &[mk_opk(3)], &[], 10, 10, 2_000)
                    .unwrap(),
                RefillOutcome::StaleGeneration
            ));
            assert!(matches!(
                store
                    .refill_prekeys(1, &[], &[mk_pq_key(9, b"bad-suite")], 10, 10, 2_000)
                    .unwrap(),
                RefillOutcome::SuiteNotOffered
            ));
            assert!(matches!(
                store
                    .refill_prekeys(1, &[mk_opk(1)], &[], 10, 10, 2_000)
                    .unwrap(),
                RefillOutcome::DuplicatePrekey
            ));
            assert!(matches!(
                store
                    .refill_prekeys(1, &[], &[mk_pq_key(1, b"lr-1")], 10, 10, 2_000)
                    .unwrap(),
                RefillOutcome::DuplicatePrekey
            ));
            assert!(matches!(
                store
                    .refill_prekeys(1, &[mk_opk(3), mk_opk(4)], &[], 3, 10, 2_000)
                    .unwrap(),
                RefillOutcome::LimitExceeded
            ));

            // Valid refill appends OPKs and PQ OPKs and updates watermark.
            let refilled = store
                .refill_prekeys(
                    1,
                    &[mk_opk(3)],
                    &[mk_pq_key(1, b"opk-2"), mk_pq_key(2, b"opk-3")],
                    10,
                    10,
                    2_000,
                )
                .unwrap();
            assert!(matches!(
                refilled,
                RefillOutcome::Stored {
                    classical_count: 3,
                    ref pq_counts,
                } if pq_counts == &vec![(1, 2), (2, 1)]
            ));

            // Non-increasing refill timestamp rejected.
            assert!(matches!(
                store
                    .refill_prekeys(1, &[mk_opk(4)], &[], 10, 10, 2_000)
                    .unwrap(),
                RefillOutcome::StaleTimestamp
            ));

            // Re-publish with pq_enabled = false clears PQ tables and rejects PQ refills.
            let m2_off = mk_manifest(2, 2, false, false);
            assert!(matches!(
                store
                    .publish_v2(&m2_off, Some(&[0xbb; 64]), &[mk_opk(10)], &[], &[], 3_000)
                    .unwrap(),
                PublishV2Outcome::Stored
            ));
            let snap = store.pq_snapshot(3_000).unwrap();
            assert_eq!(snap.classical_one_time_count, 1);
            assert!(snap.pq_last_resort_suites.is_empty());
            assert!(snap.pq_one_time_counts.is_empty());
            assert!(matches!(
                store
                    .refill_prekeys(2, &[], &[mk_pq_key(1, b"nope")], 10, 10, 4_000)
                    .unwrap(),
                RefillOutcome::SuiteNotOffered
            ));
        }

        #[test]
        fn claim_bundle_checked_handles_reject_pq_opk_depletion_and_hourly_budget_reset() {
            let env = TestIdentity::new(50_000);
            let store = env.store();

            // Unallocated DO -> NotFound without creating tables.
            assert!(matches!(
                store.claim_bundle_checked(&[1], false, 1_000).unwrap(),
                ClaimBundleOutcome::NotFound
            ));
            assert!(!store.has_tables().unwrap());

            store.ensure_v2_tables().unwrap();

            // Publish 36 classical OPKs + 36 PQ OPKs so we can exercise the 32/hr budget cap
            // and subsequent window reset + full depletion.
            let opks: Vec<Vec<u8>> = (1..=36u32).map(mk_opk).collect();
            let pq_opks: Vec<PqPrekeyWire> = (1..=36u32)
                .map(|i| mk_pq_key(2, format!("pq-{i:02}").as_bytes()))
                .collect();
            let manifest = mk_manifest(1, 1, true, false);
            store
                .publish_v2(
                    &manifest,
                    Some(&[0xaa; 64]),
                    &opks,
                    &[mk_pq_key(1, b"lr-1"), mk_pq_key(2, b"lr-2")],
                    &pq_opks,
                    1_000,
                )
                .unwrap();

            // 1) reject_pq_on_manifest = true MUST fail atomically without popping OPKs or budget.
            assert!(matches!(
                store.claim_bundle_checked(&[2], true, 10_000).unwrap(),
                ClaimBundleOutcome::PqDisabledForPqManifest
            ));
            assert_eq!(
                store.pq_snapshot(10_000).unwrap().classical_one_time_count,
                36
            );
            assert!(
                env.sql
                    .query_opt::<OpkBudgetRow>(
                        "SELECT window_start, claims FROM opk_claim_budget WHERE only = 0",
                        vec![]
                    )
                    .unwrap()
                    .is_none()
            );

            // 2) Unnegotiable preferred suite ([99]) does not pop any OPK.
            let unneg = store.claim_bundle_checked(&[99], false, 10_000).unwrap();
            match unneg {
                ClaimBundleOutcome::Claimed(b) => {
                    assert!(b.pq_last_resort.is_none());
                    assert!(b.one_time_prekey.is_none());
                    assert!(b.pq_one_time_prekey.is_none());
                }
                other => panic!("expected Claimed without OPKs, got {other:?}"),
            }
            assert_eq!(
                store.pq_snapshot(10_000).unwrap().classical_one_time_count,
                36
            );

            // 3) First MAX_OPK_CLAIMS_PER_HOUR (32) claims pop classical + PQ OPKs in FIFO order.
            let window_start = 100_000;
            for i in 1..=MAX_OPK_CLAIMS_PER_HOUR {
                let claimed = store
                    .claim_bundle_checked(&[2, 1], false, window_start + i)
                    .unwrap();
                match claimed {
                    ClaimBundleOutcome::Claimed(b) => {
                        assert_eq!(
                            b.one_time_prekey.as_deref(),
                            Some(mk_opk(i as u32).as_slice())
                        );
                        assert_eq!(b.pq_last_resort.as_ref().unwrap().id, b"lr-2");
                        assert_eq!(
                            b.pq_one_time_prekey.as_ref().unwrap().id,
                            format!("pq-{i:02}").as_bytes()
                        );
                    }
                    other => panic!("expected Claimed on claim {i}, got {other:?}"),
                }
            }

            // Budget row persisted at claims == 32.
            let budget: OpkBudgetRow = env
                .sql
                .query_one(
                    "SELECT window_start, claims FROM opk_claim_budget WHERE only = 0",
                    vec![],
                )
                .unwrap();
            assert_eq!(budget.window_start, window_start + 1);
            assert_eq!(budget.claims, MAX_OPK_CLAIMS_PER_HOUR);

            // 4) 33rd claim within same hour still succeeds (SPK + PQ last-resort) WITHOUT popping OPKs!
            let capped = store
                .claim_bundle_checked(&[2], false, window_start + OPK_BUDGET_WINDOW_MS)
                .unwrap();
            match capped {
                ClaimBundleOutcome::Claimed(b) => {
                    assert!(b.pq_last_resort.is_some());
                    assert!(b.one_time_prekey.is_none());
                    assert!(b.pq_one_time_prekey.is_none());
                }
                other => panic!("expected Claimed without OPKs at budget cap, got {other:?}"),
            }
            assert_eq!(
                store
                    .pq_snapshot(window_start)
                    .unwrap()
                    .classical_one_time_count,
                4
            );

            // 5) After 1-hour window rolls over, OPK popping resumes and depletes remaining 4 OPKs.
            let next_window = window_start + 1 + OPK_BUDGET_WINDOW_MS;
            for i in 33..=36u32 {
                let claimed = store
                    .claim_bundle_checked(&[2], false, next_window + u64::from(i))
                    .unwrap();
                match claimed {
                    ClaimBundleOutcome::Claimed(b) => {
                        assert_eq!(b.one_time_prekey.as_deref(), Some(mk_opk(i).as_slice()));
                        assert!(b.pq_one_time_prekey.is_some());
                    }
                    other => panic!("expected Claimed after window reset, got {other:?}"),
                }
            }

            // 6) Depleted pool still returns SPK + PQ last-resort with None OPKs.
            let depleted = store
                .claim_bundle_checked(&[2], false, next_window + 50)
                .unwrap();
            match depleted {
                ClaimBundleOutcome::Claimed(b) => {
                    assert!(b.pq_last_resort.is_some());
                    assert!(b.one_time_prekey.is_none());
                    assert!(b.pq_one_time_prekey.is_none());
                }
                other => panic!("expected Claimed when depleted, got {other:?}"),
            }
            let budget_after: OpkBudgetRow = env
                .sql
                .query_one(
                    "SELECT window_start, claims FROM opk_claim_budget WHERE only = 0",
                    vec![],
                )
                .unwrap();
            // Depleted claim popped 0 OPKs so claims stayed at 4 in the new window.
            assert_eq!(budget_after.claims, 4);
        }

        #[test]
        fn initial_messages_add_list_ack_and_expiry_lifecycle() {
            let retention = 10_000;
            let env = TestIdentity::new(retention);
            let store = env.store();
            store.ensure_v2_tables().unwrap();

            let v1 = InitialMessageV2Wire {
                id: 0,
                version: 1,
                sender: vec![1; 32],
                ephemeral_key: vec![2; 32],
                signed_prekey: vec![3; 32],
                one_time_prekey: Some(vec![4; 32]),
                header: b"v1-h".to_vec(),
                content: b"v1-c".to_vec(),
                pq_suite: None,
                pq_last_resort: false,
                pq_prekey_id: None,
                pq_ciphertext: None,
                manifest_digest: None,
            };
            let v2_pq = InitialMessageV2Wire {
                id: 0,
                version: 2,
                sender: vec![5; 32],
                ephemeral_key: vec![6; 32],
                signed_prekey: vec![7; 32],
                one_time_prekey: None,
                header: b"v2-h".to_vec(),
                content: b"v2-c".to_vec(),
                pq_suite: Some(2),
                pq_last_resort: true,
                pq_prekey_id: Some(b"lr-2".to_vec()),
                pq_ciphertext: Some(vec![0xef; 24]),
                manifest_digest: Some(vec![0xab; 32]),
            };

            let id1 = store
                .add_initial_message_v2(&v1, 2, 1_000)
                .unwrap()
                .unwrap();
            let id2 = store
                .add_initial_message_v2(&v2_pq, 2, 20_000)
                .unwrap()
                .unwrap();
            assert!(id2 > id1);

            // Inbox limit == 2 blocks a 3rd insert.
            assert!(
                store
                    .add_initial_message_v2(&v2_pq, 2, 20_000)
                    .unwrap()
                    .is_none()
            );

            // At now = 25_000 (cutoff = 15_000), id1 is expired and omitted from list & pq_snapshot.
            let listed = store.list_initial_messages(10, 25_000).unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].id, id2);
            assert_eq!(listed[0].version, 2);
            assert_eq!(listed[0].pq_suite, Some(2));
            assert!(listed[0].pq_last_resort);
            assert_eq!(listed[0].pq_prekey_id.as_deref(), Some(b"lr-2".as_slice()));
            assert_eq!(
                listed[0].manifest_digest.as_deref(),
                Some([0xab; 32].as_slice())
            );
            assert_eq!(
                store.pq_snapshot(25_000).unwrap().pending_initial_messages,
                1
            );

            // At now = 5_000 both rows are live; verify v1 row fields too.
            let both = store.list_initial_messages(10, 5_000).unwrap();
            assert_eq!(both.len(), 2);
            assert_eq!(both[0].id, id1);
            assert_eq!(both[0].version, 1);
            assert_eq!(both[0].pq_suite, None);
            assert_eq!(
                both[0].one_time_prekey.as_deref(),
                Some([4u8; 32].as_slice())
            );

            // Ack deletes both initial_messages and initial_messages_pq cleanly.
            assert_eq!(store.ack_initial_messages(&[id2, 999]).unwrap(), 1);
            let pq_remaining: CountRow = env
                .sql
                .query_one("SELECT count(*) AS count FROM initial_messages_pq", vec![])
                .unwrap();
            assert_eq!(pq_remaining.count, 0);
            assert_eq!(store.ack_initial_messages(&[id1]).unwrap(), 1);
            assert!(store.list_initial_messages(10, 5_000).unwrap().is_empty());
        }

        #[test]
        fn strict_pq_clears_classical_bundle_and_legacy_bundle_only_do_claims_classically() {
            // 1) strict_pq = true deletes any prior classical bundle signature row.
            let env = TestIdentity::new(50_000);
            let store = env.store();
            store.ensure_v2_tables().unwrap();

            let hybrid = mk_manifest(1, 1, true, false);
            store
                .publish_v2(
                    &hybrid,
                    Some(&[0xaa; 64]),
                    &[mk_opk(1)],
                    &[mk_pq_key(1, b"lr-1")],
                    &[],
                    1_000,
                )
                .unwrap();
            assert!(
                env.sql
                    .query_opt::<BundleRow>("SELECT signed_prekey, signature FROM bundle", vec![])
                    .unwrap()
                    .is_some()
            );

            let strict = mk_manifest(2, 2, true, true);
            store
                .publish_v2(
                    &strict,
                    Some(&[0xbb; 64]),
                    &[mk_opk(2)],
                    &[mk_pq_key(1, b"lr-1")],
                    &[],
                    2_000,
                )
                .unwrap();
            assert!(
                env.sql
                    .query_opt::<BundleRow>("SELECT signed_prekey, signature FROM bundle", vec![])
                    .unwrap()
                    .is_none()
            );
            // strict_pq with empty preferred_suites cannot negotiate PQ -> does not pop classical OPK.
            match store.claim_bundle_checked(&[], false, 3_000).unwrap() {
                ClaimBundleOutcome::Claimed(b) => {
                    assert!(b.signed_prekey_signature.is_none());
                    assert!(b.pq_last_resort.is_none());
                    assert!(b.one_time_prekey.is_none());
                }
                other => panic!("expected Claimed without OPK, got {other:?}"),
            }
            assert_eq!(
                store.pq_snapshot(3_000).unwrap().classical_one_time_count,
                1
            );

            // 2) Pre-existing classical-only DO (bundle row without capability_manifest).
            let legacy_env = TestIdentity::new(50_000);
            let legacy_store = legacy_env.store();
            legacy_store.ensure_v2_tables().unwrap();
            legacy_env
                .sql
                .exec(
                    "INSERT INTO bundle (only, signed_prekey, signature, timestamp) VALUES (0, ?, ?, 100)",
                    params![[0x55u8; 32].as_slice(), [0x66u8; 64].as_slice()].unwrap(),
                )
                .unwrap();
            legacy_env
                .sql
                .exec(
                    "INSERT INTO one_time_prekeys (position, prekey) VALUES (0, ?)",
                    params![mk_opk(7).as_slice()].unwrap(),
                )
                .unwrap();

            match legacy_store
                .claim_bundle_checked(&[1], true, 5_000)
                .unwrap()
            {
                ClaimBundleOutcome::Claimed(b) => {
                    assert!(b.manifest.is_none());
                    assert_eq!(b.signed_prekey, vec![0x55; 32]);
                    assert_eq!(
                        b.signed_prekey_signature.as_deref(),
                        Some([0x66; 64].as_slice())
                    );
                    assert_eq!(b.one_time_prekey.as_deref(), Some(mk_opk(7).as_slice()));
                    assert!(b.pq_last_resort.is_none());
                }
                other => panic!("expected legacy classical Claimed, got {other:?}"),
            }
        }
    }
}
