//! V2 capability manifests, classical and post-quantum prekeys, and the two-phase handshake inbox.

use std::collections::HashSet;

use worker::{Date, Error, Result, SqlStorage};

use super::{Identity, rows::*};
use crate::objects::{
    ClaimBundleOutcome, ClaimedBundleWire, InitialMessageV2Wire, ManifestWire, PqCommitmentWire,
    PqPrekeyWire, PqSnapshotWire, PublishV2Outcome, RefillOutcome,
    sql::{checked_integer, exec, params, query, query_one, query_opt},
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

fn insert_pq_prekey(sql: &SqlStorage, table: PqPrekeyTable, key: &PqPrekeyWire) -> Result<()> {
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
    exec(
        sql,
        stmt,
        params![
            key.suite,
            key.id.as_slice(),
            key.encapsulation_key.as_slice(),
            key.signature.as_slice()
        ]?,
    )?;
    Ok(())
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

impl Identity {
    fn pop_classical_opk_sql(sql: &SqlStorage) -> Result<Option<Vec<u8>>> {
        let prekey: Option<PrekeyRow> = query_opt(
            sql,
            "SELECT position, prekey FROM one_time_prekeys ORDER BY position LIMIT 1",
            vec![],
        )?;
        if let Some(ref prekey) = prekey {
            exec(
                sql,
                "DELETE FROM one_time_prekeys WHERE position = ?",
                params![prekey.position]?,
            )?;
        }
        Ok(prekey.map(|p| p.prekey.into_vec()))
    }

    fn negotiate_last_resort(
        &self,
        sql: &SqlStorage,
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
            if let Some(lr) = query_opt::<PqLastResortRow>(
                sql,
                "SELECT suite, prekey_id, encapsulation_key, signature \
                 FROM pq_last_resort WHERE suite = ?",
                params![suite]?,
            )? {
                return Ok(Some(PqPrekeyWire::from(lr)));
            }
        }
        Ok(None)
    }

    fn pop_pq_otpk(&self, sql: &SqlStorage, suite: u8) -> Result<Option<PqPrekeyWire>> {
        if !self.has_v2_table(sql, "pq_one_time_prekeys")? {
            return Ok(None);
        }
        let row: Option<PqOneTimeRow> = query_opt(
            sql,
            "SELECT position, suite, prekey_id, encapsulation_key, signature \
             FROM pq_one_time_prekeys WHERE suite = ? ORDER BY position LIMIT 1",
            params![suite]?,
        )?;
        if let Some(ref r) = row {
            exec(
                sql,
                "DELETE FROM pq_one_time_prekeys WHERE position = ?",
                params![r.position]?,
            )?;
        }
        Ok(row.map(PqPrekeyWire::from))
    }

    fn get_manifest_sql(&self, sql: &SqlStorage) -> Result<Option<ManifestWire>> {
        if !self.has_v2_table(sql, "capability_manifest")? {
            return Ok(None);
        }
        let Some(row) = query_opt::<ManifestRow>(
            sql,
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

    fn pq_one_time_counts_sql(&self, sql: &SqlStorage) -> Result<Vec<(u8, u64)>> {
        if !self.has_v2_table(sql, "pq_one_time_prekeys")? {
            return Ok(vec![]);
        }
        let rows: Vec<SuiteCountRow> = query(
            sql,
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

        self.transaction_sync(|sql| {
            if query_opt::<ManifestSeqRow>(sql, "SELECT manifest_seq FROM capability_manifest", vec![])?
                .is_some_and(|row| row.manifest_seq >= manifest.manifest_seq)
            {
                return Ok(PublishV2Outcome::StaleSequence);
            }

            // Store or clear classical SPK signature row depending on strict_pq and signature presence.
            if !manifest.strict_pq
                && let Some(sig) = signed_prekey_signature
            {
                let next_ts = query_opt::<TimestampRow>(sql, "SELECT timestamp FROM bundle", vec![])?
                    .map_or(timestamp, |r| r.timestamp.max(timestamp));
                exec(
                    sql,
                    "INSERT INTO bundle (only, signed_prekey, signature, timestamp) VALUES (0, ?, ?, ?) \
                     ON CONFLICT (only) DO UPDATE SET signed_prekey = excluded.signed_prekey, \
                     signature = excluded.signature, timestamp = excluded.timestamp",
                    params![manifest.signed_prekey.as_slice(), sig, next_ts]?,
                )?;
            } else {
                exec(sql, "DELETE FROM bundle", vec![])?;
            }

            // Replace classical OPKs.
            exec(sql, "DELETE FROM one_time_prekeys", vec![])?;
            for (pos, prekey) in one_time_prekeys.iter().enumerate() {
                exec(
                    sql,
                    "INSERT INTO one_time_prekeys (position, prekey) VALUES (?, ?)",
                    params![pos as u64, prekey.as_slice()]?,
                )?;
            }

            // Replace or clear PQ prekeys depending on affirmative pq_enabled flag.
            exec(sql, "DELETE FROM pq_last_resort", vec![])?;
            exec(sql, "DELETE FROM pq_one_time_prekeys", vec![])?;
            if manifest.pq_enabled {
                for lr in pq_last_resort {
                    insert_pq_prekey(sql, PqPrekeyTable::LastResort, lr)?;
                }
                for opk in pq_one_time_prekeys {
                    insert_pq_prekey(sql, PqPrekeyTable::OneTime, opk)?;
                }
            }

            exec(
                sql,
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
            exec(
                sql,
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

        self.transaction_sync(|sql| {
            let Some(manifest) = self.get_manifest_sql(sql)? else {
                return Ok(RefillOutcome::NotFound);
            };
            if manifest.generation != generation {
                return Ok(RefillOutcome::StaleGeneration);
            }
            if !pq_one_time_prekeys.is_empty() && !manifest.pq_enabled {
                return Ok(RefillOutcome::SuiteNotOffered);
            }

            if query_opt::<WatermarkRow>(
                sql,
                "SELECT last_refill_ts FROM publish_watermarks",
                vec![],
            )?
            .is_some_and(|row| row.last_refill_ts >= timestamp)
            {
                return Ok(RefillOutcome::StaleTimestamp);
            }
            let existing_opks: Vec<PrekeyRow> = query(
                sql,
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
                query(sql, "SELECT prekey_id FROM pq_one_time_prekeys", vec![])?;
            if (existing_pq_ids.len() as u64).saturating_add(pq_one_time_prekeys.len() as u64)
                > max_pq_one_time_prekeys
            {
                return Ok(RefillOutcome::LimitExceeded);
            }
            let lr_ids: Vec<IdBlobRow> =
                query(sql, "SELECT prekey_id FROM pq_last_resort", vec![])?;
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
            exec(
                sql,
                "INSERT INTO publish_watermarks (only, last_v1_publish_ts, last_refill_ts) \
                 VALUES (0, 0, ?) \
                 ON CONFLICT (only) DO UPDATE SET last_refill_ts = excluded.last_refill_ts",
                params![timestamp]?,
            )?;
            for (offset, opk) in one_time_prekeys.iter().enumerate() {
                exec(
                    sql,
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
        self.get_manifest_sql(&self.sql())
    }

    /// Atomically validates `reject_pq_on_manifest`, `strict_pq`, suite negotiation, and the
    /// per-identity hourly OPK claim budget BEFORE popping any classical or PQ one-time prekey.
    pub(super) fn claim_bundle_checked(
        &self,
        preferred_suites: &[u8],
        reject_pq_on_manifest: bool,
    ) -> Result<ClaimBundleOutcome> {
        if !self.has_tables()? {
            return Ok(ClaimBundleOutcome::NotFound);
        }
        self.ensure_v2_tables()?;
        let now_ms = Date::now().as_millis();
        self.transaction_sync(|sql| {
            let current_budget = query_opt::<OpkBudgetRow>(
                sql,
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
                    query_opt::<BundleRow>(
                        sql,
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
                query_opt::<BundleRow>(sql, "SELECT signed_prekey, signature FROM bundle", vec![])?
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
    ) -> Result<Option<u64>> {
        let now = Date::now().as_millis();
        let initial_bindings = params![
            message.sender.as_slice(),
            message.ephemeral_key.as_slice(),
            message.signed_prekey.as_slice(),
            message.one_time_prekey.as_deref(),
            message.header.as_slice(),
            message.content.as_slice(),
            now
        ]?;
        let has_pq = message.version != 1;
        if has_pq {
            let _ = checked_integer(u64::from(message.version))?;
        }
        self.transaction_sync(|sql| {
            let count: CountRow = query_one(
                sql,
                "SELECT count(*) AS count FROM initial_messages",
                vec![],
            )?;
            if count.count >= limit {
                return Ok(None);
            }
            let inserted: IdRow = query_one(
                sql,
                "INSERT INTO initial_messages (sender, ephemeral_key, signed_prekey, \
                 one_time_prekey, header, content, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
                 RETURNING id",
                initial_bindings,
            )?;
            if has_pq {
                exec(
                    sql,
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

    pub(super) fn list_initial_messages(&self, limit: u64) -> Result<Vec<InitialMessageV2Wire>> {
        if !self.has_tables()? || limit == 0 {
            return Ok(vec![]);
        }
        let sql = self.sql();
        let cutoff = Date::now().as_millis().saturating_sub(self.retention());
        if self.has_v2_table(&sql, "initial_messages_pq")? {
            let rows: Vec<InitialMessageJoinedRow> = query(
                &sql,
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
            let rows: Vec<InitialMessageWithIdRow> = query(
                &sql,
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
        self.transaction_sync(|sql| {
            if self.has_v2_table(sql, "initial_messages_pq")? {
                exec(
                    sql,
                    "DELETE FROM initial_messages_pq \
                     WHERE initial_message_id IN (SELECT value FROM json_each(?))",
                    params![ids_json.as_str()]?,
                )?;
            }
            let deleted: Vec<IdRow> = query(
                sql,
                "DELETE FROM initial_messages \
                 WHERE id IN (SELECT value FROM json_each(?)) RETURNING id",
                params![ids_json.as_str()]?,
            )?;
            Self::cleanup_orphan_pq_initials_sql(sql)?;
            Ok(deleted.len() as u64)
        })
    }

    pub(super) fn pq_snapshot(&self) -> Result<PqSnapshotWire> {
        if !self.has_tables()? {
            return Ok(PqSnapshotWire {
                manifest: None,
                classical_one_time_count: 0,
                pq_last_resort_suites: vec![],
                pq_one_time_counts: vec![],
                pending_initial_messages: 0,
            });
        }
        let sql = self.sql();
        let cutoff = Date::now().as_millis().saturating_sub(self.retention());
        let manifest = self.get_manifest_sql(&sql)?;
        let classical: CountRow = query_one(
            &sql,
            "SELECT count(*) AS count FROM one_time_prekeys",
            vec![],
        )?;
        let pq_last_resort_suites = if self.has_v2_table(&sql, "pq_last_resort")? {
            query::<SuiteRow>(
                &sql,
                "SELECT suite FROM pq_last_resort ORDER BY suite",
                vec![],
            )?
            .into_iter()
            .map(|r| r.suite as u8)
            .collect()
        } else {
            vec![]
        };
        let pq_one_time_counts = self.pq_one_time_counts_sql(&sql)?;
        let pending: CountRow = query_one(
            &sql,
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

fn record_opk_budget(sql: &SqlStorage, window_start: u64, claims: u64) -> Result<()> {
    exec(
        sql,
        "INSERT INTO opk_claim_budget (only, window_start, claims) VALUES (0, ?, ?) \
         ON CONFLICT (only) DO UPDATE SET window_start = excluded.window_start, \
         claims = excluded.claims",
        params![window_start, claims]?,
    )?;
    Ok(())
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
}
