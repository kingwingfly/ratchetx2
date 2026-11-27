//! V2 capability manifests (with folded nullable classical SPK signature), classical and
//! post-quantum prekeys, and the two-phase idempotent handshake inbox.

use std::collections::HashSet;

use sha2::{Digest, Sha256};
use storage::{
    ClaimOutcome, ClaimedPqBundle, MAX_SAFE_INTEGER, PqLastResortCommitment, PqStorageSnapshot,
    PublicKey, PublishV2Record, PublishV2Status, RefillPrekeysRecord, Signature,
    StoredCapabilityManifest, StoredInitialMessageV2, StoredPqPrekey,
};
use worker::{Error, Result};

use super::{IdentityStore, rows::*};
use crate::objects::{
    AddInitialOutcome, RefillOutcome,
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

fn insert_pq_prekey<S: SqlExec>(sql: &S, table: PqPrekeyTable, key: &StoredPqPrekey) -> Result<()> {
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
            key.encapsulation_key.as_ref(),
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

/// Canonical SHA-256 payload digest of a [`StoredInitialMessageV2`] (excluding `id`) for
/// idempotency equality checking on `(sender, ephemeral_key)`.
fn initial_message_payload_hash(msg: &StoredInitialMessageV2) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"initial_v2/payload_hash\0");
    h.update(msg.version.to_be_bytes());
    h.update(msg.sender);
    h.update(msg.recipient);
    h.update(msg.ephemeral_key);
    h.update(msg.signed_prekey);
    match &msg.one_time_prekey {
        Some(opk) => {
            h.update([1]);
            h.update(opk);
        }
        None => h.update([0]),
    }
    h.update((msg.header.len() as u32).to_be_bytes());
    h.update(&msg.header);
    h.update((msg.content.len() as u32).to_be_bytes());
    h.update(&msg.content);
    match msg.pq_suite {
        Some(suite) => h.update([1, suite]),
        None => h.update([0]),
    }
    h.update([u8::from(msg.pq_last_resort)]);
    match &msg.pq_prekey_id {
        Some(id) => {
            h.update([1]);
            h.update(id);
        }
        None => h.update([0]),
    }
    match &msg.pq_ciphertext {
        Some(ct) => {
            h.update([1]);
            h.update((ct.len() as u32).to_be_bytes());
            h.update(ct);
        }
        None => h.update([0]),
    }
    match &msg.manifest_digest {
        Some(digest) => {
            h.update([1]);
            h.update(digest);
        }
        None => h.update([0]),
    }
    h.finalize().into()
}

impl<S: SqlExec> IdentityStore<'_, S> {
    fn pop_classical_opk_sql(sql: &S) -> Result<Option<PublicKey>> {
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
        prekey
            .map(|p| fixed_blob(p.prekey, "one_time_prekey"))
            .transpose()
    }

    fn negotiate_last_resort(
        sql: &S,
        manifest: &StoredCapabilityManifest,
        preferred_suites: &[u8],
    ) -> Result<Option<StoredPqPrekey>> {
        if !manifest.pq_enabled || preferred_suites.is_empty() {
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
                return Ok(Some(StoredPqPrekey::try_from(lr)?));
            }
        }
        Ok(None)
    }

    fn pop_pq_otpk(sql: &S, suite: u8) -> Result<Option<StoredPqPrekey>> {
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
        row.map(StoredPqPrekey::try_from).transpose()
    }

    fn get_manifest_with_spk_sig_sql(
        sql: &S,
    ) -> Result<Option<(StoredCapabilityManifest, Option<Signature>)>> {
        let Some(row) = sql.query_opt::<ManifestRow>(
            "SELECT audience, identity_key, manifest_seq, generation, issued_at, expires_at, \
             pq_enabled, strict_pq, pq_ratchet_supported, offered_suites, signed_prekey, \
             signed_prekey_signature, pq_last_resort_commitments, signature \
             FROM capability_manifest WHERE only = 0",
            vec![],
        )?
        else {
            return Ok(None);
        };
        let pq_last_resort: Vec<PqLastResortCommitment> =
            postcard::from_bytes(&row.pq_last_resort_commitments)
                .map_err(|e| Error::RustError(e.to_string()))?;
        let spk_sig = row
            .signed_prekey_signature
            .map(|b| fixed_blob(b, "signed_prekey_signature"))
            .transpose()?;
        let manifest = StoredCapabilityManifest {
            audience: row.audience,
            identity_key: fixed_blob(row.identity_key, "identity_key")?,
            manifest_seq: row.manifest_seq,
            generation: row.generation,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            pq_enabled: row.pq_enabled != 0,
            strict_pq: row.strict_pq != 0,
            pq_ratchet_supported: row.pq_ratchet_supported != 0,
            offered_suites: row.offered_suites.into_vec(),
            signed_prekey: fixed_blob(row.signed_prekey, "signed_prekey")?,
            pq_last_resort,
            signature: fixed_blob(row.signature, "manifest signature")?,
        };
        Ok(Some((manifest, spk_sig)))
    }

    /// Whether a capability manifest is currently stored (without allocating DO tables).
    pub(super) fn has_manifest(&self) -> Result<bool> {
        if !self.has_tables()? {
            return Ok(false);
        }
        Ok(self
            .sql
            .query_opt::<ManifestSeqRow>(
                "SELECT manifest_seq FROM capability_manifest WHERE only = 0",
                vec![],
            )?
            .is_some())
    }

    pub(super) fn has_manifest_sql(sql: &S) -> Result<bool> {
        Ok(sql
            .query_opt::<ManifestSeqRow>(
                "SELECT manifest_seq FROM capability_manifest WHERE only = 0",
                vec![],
            )?
            .is_some())
    }

    fn pq_one_time_counts_sql(sql: &S) -> Result<Vec<(u8, u64)>> {
        let rows: Vec<SuiteCountRow> = sql.query(
            "SELECT suite, count(*) AS count FROM pq_one_time_prekeys GROUP BY suite ORDER BY suite",
            vec![],
        )?;
        Ok(rows.into_iter().map(|r| (r.suite as u8, r.count)).collect())
    }

    pub(super) fn publish_v2(&self, record: &PublishV2Record) -> Result<PublishV2Status> {
        // Validate and prepare ALL fallible values BEFORE executing any mutating SQL statement so
        // no partial wipe can occur on a validation or serialization failure.
        let manifest = &record.manifest;
        let _ = checked_integer(record.timestamp)?;
        let _ = checked_integer(manifest.manifest_seq)?;
        let _ = checked_integer(manifest.generation)?;
        let _ = checked_integer(manifest.issued_at)?;
        let _ = checked_integer(manifest.expires_at)?;

        // Check duplicate classical OPKs, duplicate PQ last-resort suites, and duplicate PQ IDs.
        let mut seen_opks = HashSet::with_capacity(record.one_time_prekeys.len());
        for (pos, opk) in record.one_time_prekeys.iter().enumerate() {
            if !seen_opks.insert(opk.as_slice()) {
                return Ok(PublishV2Status::DuplicatePrekey);
            }
            let _ = checked_integer(pos as u64)?;
        }
        let mut seen_lr_suites = HashSet::with_capacity(record.pq_last_resort.len());
        let mut seen_pq =
            HashSet::with_capacity(record.pq_last_resort.len() + record.pq_one_time_prekeys.len());
        for lr in &record.pq_last_resort {
            if !seen_lr_suites.insert(lr.suite) || !seen_pq.insert(lr.id.as_slice()) {
                return Ok(PublishV2Status::DuplicatePrekey);
            }
        }
        for opk in &record.pq_one_time_prekeys {
            if !seen_pq.insert(opk.id.as_slice()) {
                return Ok(PublishV2Status::DuplicatePrekey);
            }
        }

        let commitments_blob = postcard::to_allocvec(&manifest.pq_last_resort)
            .map_err(|e| Error::RustError(e.to_string()))?;
        let signed_prekey_signature = if manifest.strict_pq {
            None
        } else {
            record
                .signed_prekey_signature
                .as_ref()
                .map(|s| s.as_slice())
        };

        self.ensure_v5_tables()?;
        self.sql.transaction_sync(|sql| {
            let existing = sql.query_opt::<ManifestSpkRow>(
                "SELECT manifest_seq, signed_prekey, prev_signed_prekey \
                 FROM capability_manifest WHERE only = 0",
                vec![],
            )?;
            if existing
                .as_ref()
                .is_some_and(|row| row.manifest_seq >= manifest.manifest_seq)
            {
                return Ok(PublishV2Status::StaleSequence);
            }
            let prev_signed_prekey: Option<Vec<u8>> = existing.and_then(|row| {
                let old_spk = row.signed_prekey.into_vec();
                if old_spk.as_slice() != manifest.signed_prekey.as_slice() {
                    Some(old_spk)
                } else {
                    row.prev_signed_prekey.map(crate::objects::sql::Blob::into_vec)
                }
            });

            // Replace classical OPKs.
            sql.exec("DELETE FROM one_time_prekeys", vec![])?;
            for (pos, prekey) in record.one_time_prekeys.iter().enumerate() {
                sql.exec(
                    "INSERT INTO one_time_prekeys (position, prekey) VALUES (?, ?)",
                    params![pos as u64, prekey.as_slice()]?,
                )?;
            }

            // Replace or clear PQ prekeys depending on affirmative pq_enabled flag.
            sql.exec("DELETE FROM pq_last_resort", vec![])?;
            sql.exec("DELETE FROM pq_one_time_prekeys", vec![])?;
            if manifest.pq_enabled {
                for lr in &record.pq_last_resort {
                    insert_pq_prekey(sql, PqPrekeyTable::LastResort, lr)?;
                }
                for opk in &record.pq_one_time_prekeys {
                    insert_pq_prekey(sql, PqPrekeyTable::OneTime, opk)?;
                }
            }

            sql.exec(
                "INSERT INTO capability_manifest \
                 (only, audience, identity_key, manifest_seq, generation, issued_at, expires_at, \
                  pq_enabled, strict_pq, pq_ratchet_supported, offered_suites, signed_prekey, \
                  prev_signed_prekey, signed_prekey_signature, pq_last_resort_commitments, signature) \
                 VALUES (0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (only) DO UPDATE SET \
                  audience = excluded.audience, identity_key = excluded.identity_key, \
                  manifest_seq = excluded.manifest_seq, generation = excluded.generation, \
                  issued_at = excluded.issued_at, expires_at = excluded.expires_at, \
                  pq_enabled = excluded.pq_enabled, strict_pq = excluded.strict_pq, \
                  pq_ratchet_supported = excluded.pq_ratchet_supported, \
                  offered_suites = excluded.offered_suites, signed_prekey = excluded.signed_prekey, \
                  prev_signed_prekey = excluded.prev_signed_prekey, \
                  signed_prekey_signature = excluded.signed_prekey_signature, \
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
                    prev_signed_prekey.as_deref(),
                    signed_prekey_signature,
                    commitments_blob.as_slice(),
                    manifest.signature.as_slice()
                ]?,
            )?;
            Ok(PublishV2Status::Stored)
        })
    }

    pub(super) fn refill_prekeys(&self, record: &RefillPrekeysRecord) -> Result<RefillOutcome> {
        let _ = checked_integer(record.generation)?;
        let _ = checked_integer(record.timestamp)?;
        if !self.has_tables()? {
            return Ok(RefillOutcome::NotFound);
        }

        let max_one_time_prekeys = record.max_one_time_prekeys as u64;
        let max_pq_one_time_prekeys = record.max_pq_one_time_prekeys as u64;

        self.sql.transaction_sync(|sql| {
            let Some((manifest, _)) = Self::get_manifest_with_spk_sig_sql(sql)? else {
                return Ok(RefillOutcome::NotFound);
            };
            if manifest.generation != record.generation {
                return Ok(RefillOutcome::StaleGeneration);
            }
            if !record.pq_one_time_prekeys.is_empty() && !manifest.pq_enabled {
                return Ok(RefillOutcome::SuiteNotOffered);
            }

            if sql
                .query_opt::<WatermarkRow>(
                    "SELECT last_refill_ts FROM publish_watermarks WHERE only = 0",
                    vec![],
                )?
                .is_some_and(|row| row.last_refill_ts >= record.timestamp)
            {
                return Ok(RefillOutcome::StaleTimestamp);
            }
            let existing_opks: Vec<PrekeyRow> = sql.query(
                "SELECT position, prekey FROM one_time_prekeys ORDER BY position",
                vec![],
            )?;
            if (existing_opks.len() as u64).saturating_add(record.one_time_prekeys.len() as u64)
                > max_one_time_prekeys
            {
                return Ok(RefillOutcome::LimitExceeded);
            }
            let mut seen_opks: HashSet<&[u8]> =
                existing_opks.iter().map(|r| r.prekey.as_ref()).collect();
            for opk in &record.one_time_prekeys {
                if !seen_opks.insert(opk.as_slice()) {
                    return Ok(RefillOutcome::DuplicatePrekey);
                }
            }

            let existing_pq_ids: Vec<IdBlobRow> =
                sql.query("SELECT prekey_id FROM pq_one_time_prekeys", vec![])?;
            if (existing_pq_ids.len() as u64)
                .saturating_add(record.pq_one_time_prekeys.len() as u64)
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
            for pq in &record.pq_one_time_prekeys {
                if !manifest.offered_suites.contains(&pq.suite) {
                    return Ok(RefillOutcome::SuiteNotOffered);
                }
                if !seen_pq_ids.insert(pq.id.as_slice()) {
                    return Ok(RefillOutcome::DuplicatePrekey);
                }
            }

            // Pre-validate position integer bindings before mutating SQLite.
            let start_pos = existing_opks.last().map_or(0, |r| r.position + 1);
            for offset in 0..record.one_time_prekeys.len() {
                let _ = checked_integer(start_pos.saturating_add(offset as u64))?;
            }

            // Record monotonic refill watermark and append OPKs/PQOPKs without rotating SPK.
            sql.exec(
                "INSERT INTO publish_watermarks (only, last_refill_ts) VALUES (0, ?) \
                 ON CONFLICT (only) DO UPDATE SET last_refill_ts = excluded.last_refill_ts",
                params![record.timestamp]?,
            )?;
            for (offset, opk) in record.one_time_prekeys.iter().enumerate() {
                sql.exec(
                    "INSERT INTO one_time_prekeys (position, prekey) VALUES (?, ?)",
                    params![start_pos.saturating_add(offset as u64), opk.as_slice()]?,
                )?;
            }
            for pq in &record.pq_one_time_prekeys {
                insert_pq_prekey(sql, PqPrekeyTable::OneTime, pq)?;
            }

            let classical_count = existing_opks.len() as u64 + record.one_time_prekeys.len() as u64;
            let pq_counts = Self::pq_one_time_counts_sql(sql)?;
            Ok(RefillOutcome::Stored {
                classical_count,
                pq_counts,
            })
        })
    }

    pub(super) fn get_manifest(&self) -> Result<Option<StoredCapabilityManifest>> {
        if !self.has_tables()? {
            return Ok(None);
        }
        Ok(Self::get_manifest_with_spk_sig_sql(self.sql)?.map(|(m, _)| m))
    }

    /// Atomically validates `reject_pq_on_manifest`, `strict_pq`, suite negotiation, and the
    /// per-identity hourly OPK claim budget BEFORE popping any classical or PQ one-time prekey.
    pub(super) fn claim_bundle_checked(
        &self,
        preferred_suites: &[u8],
        reject_pq_on_manifest: bool,
        now_ms: u64,
    ) -> Result<ClaimOutcome> {
        if !self.has_tables()? {
            return Ok(ClaimOutcome::NotFound);
        }
        self.sql.transaction_sync(|sql| {
            let Some((manifest, folded_spk_sig)) = Self::get_manifest_with_spk_sig_sql(sql)? else {
                return Ok(ClaimOutcome::NotFound);
            };
            if reject_pq_on_manifest && manifest.pq_enabled {
                return Ok(ClaimOutcome::PqDisabledForPqManifest);
            }

            let current_budget = sql
                .query_opt::<OpkBudgetRow>(
                    "SELECT window_start, claims FROM opk_claim_budget WHERE only = 0",
                    vec![],
                )?
                .map(|row| (row.window_start, row.claims));
            let (budget_allows, next_window_start, next_claims) =
                opk_budget_step(current_budget, now_ms);

            let signed_prekey_signature = if manifest.strict_pq {
                None
            } else {
                folded_spk_sig
            };
            let pq_last_resort = Self::negotiate_last_resort(sql, &manifest, preferred_suites)?;

            // Validate policy & negotiation BEFORE popping any OPK.
            let can_pop_opk =
                if manifest.strict_pq || (manifest.pq_enabled && !preferred_suites.is_empty()) {
                    pq_last_resort.is_some()
                } else {
                    signed_prekey_signature.is_some()
                };
            if !can_pop_opk {
                return Ok(ClaimOutcome::Claimed(Box::new(ClaimedPqBundle {
                    identity_key: manifest.identity_key,
                    signed_prekey: manifest.signed_prekey,
                    manifest: Some(manifest),
                    signed_prekey_signature,
                    one_time_prekey: None,
                    pq_last_resort: None,
                    pq_one_time_prekey: None,
                })));
            }

            let (one_time_prekey, pq_one_time_prekey) = if budget_allows {
                let pq_opk = match pq_last_resort.as_ref() {
                    Some(lr) => Self::pop_pq_otpk(sql, lr.suite)?,
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

            Ok(ClaimOutcome::Claimed(Box::new(ClaimedPqBundle {
                identity_key: manifest.identity_key,
                signed_prekey: manifest.signed_prekey,
                manifest: Some(manifest),
                signed_prekey_signature,
                one_time_prekey,
                pq_last_resort,
                pq_one_time_prekey,
            })))
        })
    }

    pub(super) fn add_initial_message_v2(
        &self,
        message: &StoredInitialMessageV2,
        limit: u64,
        now_ms: u64,
    ) -> Result<AddInitialOutcome> {
        if !self.has_tables()? {
            return Ok(AddInitialOutcome::NotFound);
        }
        let payload_hash = initial_message_payload_hash(message);
        let cutoff = now_ms.saturating_sub(self.retention_ms);
        let bindings = params![
            message.version,
            message.sender.as_slice(),
            message.ephemeral_key.as_slice(),
            message.signed_prekey.as_slice(),
            message.one_time_prekey.as_ref().map(|k| k.as_slice()),
            message.header.as_ref(),
            message.content.as_ref(),
            message.pq_suite,
            message.pq_last_resort,
            message.pq_prekey_id.as_ref().map(|id| id.as_slice()),
            message.pq_ciphertext.as_deref(),
            message.manifest_digest.as_ref().map(|d| d.as_slice()),
            payload_hash.as_slice(),
            now_ms
        ]?;

        self.sql.transaction_sync(|sql| {
            let Some(retained) = sql.query_opt::<RetainedSpkRow>(
                "SELECT signed_prekey, prev_signed_prekey FROM capability_manifest WHERE only = 0",
                vec![],
            )?
            else {
                return Ok(AddInitialOutcome::NotFound);
            };
            // Prune expired rows BEFORE `(sender, ephemeral_key)` lookup/insert so an expired row
            // never collides with UNIQUE(sender, ephemeral_key) or occupies an inbox slot.
            sql.exec(
                "DELETE FROM initial_messages WHERE created_at < ?",
                params![cutoff]?,
            )?;

            // Check `(sender, ephemeral_key)` idempotency BEFORE SPK retention so retrying an
            // already-accepted row after subsequent SPK rotations preserves idempotent delivery.
            if let Some(existing) = sql.query_opt::<InitialPayloadRow>(
                "SELECT id, payload_hash FROM initial_messages \
                 WHERE sender = ? AND ephemeral_key = ?",
                params![message.sender.as_slice(), message.ephemeral_key.as_slice()]?,
            )? {
                if existing.payload_hash.as_ref() == payload_hash.as_slice() {
                    return Ok(AddInitialOutcome::Added {
                        id: existing.id,
                        inserted: false,
                    });
                }
                return Ok(AddInitialOutcome::PayloadMismatch);
            }

            let spk_retained = retained.signed_prekey.as_ref() == message.signed_prekey.as_slice()
                || retained
                    .prev_signed_prekey
                    .as_ref()
                    .is_some_and(|prev| prev.as_ref() == message.signed_prekey.as_slice());
            if !spk_retained {
                return Ok(AddInitialOutcome::StalePrekey);
            }

            let count: CountRow =
                sql.query_one("SELECT count(*) AS count FROM initial_messages", vec![])?;
            if count.count >= limit {
                return Ok(AddInitialOutcome::LimitExceeded);
            }

            let inserted: IdRow = sql.query_one(
                "INSERT INTO initial_messages \
                 (version, sender, ephemeral_key, signed_prekey, one_time_prekey, header, content, \
                  pq_suite, pq_last_resort, pq_prekey_id, pq_ciphertext, manifest_digest, \
                  payload_hash, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 RETURNING id",
                bindings,
            )?;
            if inserted.id > MAX_SAFE_INTEGER {
                sql.exec(
                    "DELETE FROM initial_messages WHERE id = ?",
                    params![inserted.id]?,
                )?;
                return Ok(AddInitialOutcome::SequenceOverflow);
            }
            Ok(AddInitialOutcome::Added {
                id: inserted.id,
                inserted: true,
            })
        })
    }

    pub(super) fn list_initial_messages(
        &self,
        recipient: PublicKey,
        after_id: u64,
        limit: u64,
        now_ms: u64,
    ) -> Result<Vec<StoredInitialMessageV2>> {
        let _ = checked_integer(after_id)?;
        if !self.has_tables()? || limit == 0 {
            return Ok(vec![]);
        }
        let cutoff = now_ms.saturating_sub(self.retention_ms);
        let rows: Vec<InitialMessageRow> = self.sql.query(
            "SELECT id, version, sender, ephemeral_key, signed_prekey, one_time_prekey, \
             header, content, pq_suite, pq_last_resort, pq_prekey_id, pq_ciphertext, \
             manifest_digest \
             FROM initial_messages \
             WHERE id > ? AND created_at >= ? \
             ORDER BY id LIMIT ?",
            params![after_id, cutoff, limit]?,
        )?;
        rows.into_iter()
            .map(|row| row.into_stored(recipient))
            .collect()
    }

    pub(super) fn ack_initial_messages(&self, ids: &[u64]) -> Result<u64> {
        for &id in ids {
            let _ = checked_integer(id)?;
        }
        if !self.has_tables()? || ids.is_empty() {
            return Ok(0);
        }
        let ids_json = serde_json::to_string(ids).map_err(|e| Error::RustError(e.to_string()))?;
        let deleted: Vec<IdRow> = self.sql.query(
            "DELETE FROM initial_messages \
             WHERE id IN (SELECT value FROM json_each(?)) RETURNING id",
            params![ids_json.as_str()]?,
        )?;
        Ok(deleted.len() as u64)
    }

    pub(super) fn pq_snapshot(&self, now_ms: u64) -> Result<PqStorageSnapshot> {
        if !self.has_tables()? {
            return Ok(PqStorageSnapshot::default());
        }
        let cutoff = now_ms.saturating_sub(self.retention_ms);
        let manifest = Self::get_manifest_with_spk_sig_sql(self.sql)?.map(|(m, _)| m);
        let classical: CountRow = self
            .sql
            .query_one("SELECT count(*) AS count FROM one_time_prekeys", vec![])?;
        let pq_last_resort_suites: Vec<u8> = self
            .sql
            .query::<SuiteRow>("SELECT suite FROM pq_last_resort ORDER BY suite", vec![])?
            .into_iter()
            .map(|r| r.suite as u8)
            .collect();
        let pq_one_time_counts = Self::pq_one_time_counts_sql(self.sql)?
            .into_iter()
            .map(|(suite, count)| (suite, count as usize))
            .collect();
        let pending: CountRow = self.sql.query_one(
            "SELECT count(*) AS count FROM initial_messages WHERE created_at >= ?",
            params![cutoff]?,
        )?;
        Ok(PqStorageSnapshot {
            manifest,
            classical_one_time_count: classical.count as usize,
            pq_last_resort_suites,
            pq_one_time_counts,
            pending_initial_messages: pending.count as usize,
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
        use storage::Bytes;

        use super::*;
        use crate::objects::identity::TestIdentity;

        const BOB: PublicKey = [0x11; 32];
        const ALICE: PublicKey = [0x22; 32];

        fn mk_manifest(
            seq: u64,
            generation: u64,
            pq_enabled: bool,
            strict_pq: bool,
        ) -> StoredCapabilityManifest {
            StoredCapabilityManifest {
                audience: "relay.example".into(),
                identity_key: BOB,
                manifest_seq: seq,
                generation,
                issued_at: 1_000,
                expires_at: 100_000,
                pq_enabled,
                strict_pq,
                pq_ratchet_supported: pq_enabled,
                offered_suites: if pq_enabled { vec![1, 2] } else { vec![] },
                signed_prekey: [0x22; 32],
                pq_last_resort: if pq_enabled {
                    vec![
                        PqLastResortCommitment {
                            suite: 1,
                            prekey_id: [0xA1; 32],
                        },
                        PqLastResortCommitment {
                            suite: 2,
                            prekey_id: [0xA2; 32],
                        },
                    ]
                } else {
                    vec![]
                },
                signature: [0x33; 64],
            }
        }

        fn mk_pq_key(suite: u8, tag: u8) -> StoredPqPrekey {
            StoredPqPrekey {
                suite,
                id: [tag; 32],
                encapsulation_key: Bytes::from(vec![suite; 32]),
                signature: [0x44; 64],
            }
        }

        fn mk_opk(idx: u32) -> PublicKey {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&idx.to_be_bytes());
            key
        }

        fn mk_initial(eph: u8, version: u32, content: &'static [u8]) -> StoredInitialMessageV2 {
            StoredInitialMessageV2 {
                id: 0,
                version,
                sender: ALICE,
                recipient: BOB,
                ephemeral_key: [eph; 32],
                signed_prekey: [0x22; 32],
                one_time_prekey: None,
                header: Bytes::from_static(b"hdr"),
                content: Bytes::from_static(content),
                pq_suite: (version == 2).then_some(1),
                pq_last_resort: false,
                pq_prekey_id: (version == 2).then_some([0xB1; 32]),
                pq_ciphertext: (version == 2).then(|| Bytes::from_static(b"pq-ct")),
                manifest_digest: (version == 2).then_some([0xDD; 32]),
            }
        }

        #[test]
        fn publish_v2_and_refill_enforce_sequences_duplicates_generations_and_caps() {
            let env = TestIdentity::new(50_000);
            let store = env.store();

            // Unknown identity returns None / NotFound without creating tables.
            assert!(store.get_manifest().unwrap().is_none());
            assert_eq!(
                store
                    .refill_prekeys(&RefillPrekeysRecord {
                        identity_key: BOB,
                        generation: 1,
                        one_time_prekeys: vec![],
                        pq_one_time_prekeys: vec![],
                        max_one_time_prekeys: 10,
                        max_pq_one_time_prekeys: 10,
                        timestamp: 1_000,
                    })
                    .unwrap(),
                RefillOutcome::NotFound
            );
            assert!(!store.has_tables().unwrap());

            // Duplicate classical OPK rejected before creating/mutating manifest.
            let m1 = mk_manifest(1, 1, true, false);
            assert_eq!(
                store
                    .publish_v2(&PublishV2Record {
                        manifest: m1.clone(),
                        signed_prekey_signature: Some([0xAA; 64]),
                        one_time_prekeys: vec![mk_opk(1), mk_opk(1)],
                        pq_last_resort: vec![mk_pq_key(1, 0xA1), mk_pq_key(2, 0xA2)],
                        pq_one_time_prekeys: vec![],
                        timestamp: 1_000,
                    })
                    .unwrap(),
                PublishV2Status::DuplicatePrekey
            );
            assert!(!store.has_tables().unwrap());

            // Valid publish stores folded signed_prekey_signature on capability_manifest.
            assert_eq!(
                store
                    .publish_v2(&PublishV2Record {
                        manifest: m1.clone(),
                        signed_prekey_signature: Some([0xAA; 64]),
                        one_time_prekeys: vec![mk_opk(1), mk_opk(2)],
                        pq_last_resort: vec![mk_pq_key(1, 0xA1), mk_pq_key(2, 0xA2)],
                        pq_one_time_prekeys: vec![mk_pq_key(1, 0xB1)],
                        timestamp: 1_000,
                    })
                    .unwrap(),
                PublishV2Status::Stored
            );
            assert_eq!(store.get_manifest().unwrap(), Some(m1));

            // Stale manifest_seq rejected.
            assert_eq!(
                store
                    .publish_v2(&PublishV2Record {
                        manifest: mk_manifest(1, 2, true, false),
                        signed_prekey_signature: Some([0xAA; 64]),
                        one_time_prekeys: vec![],
                        pq_last_resort: vec![mk_pq_key(1, 0xA1), mk_pq_key(2, 0xA2)],
                        pq_one_time_prekeys: vec![],
                        timestamp: 2_000,
                    })
                    .unwrap(),
                PublishV2Status::StaleSequence
            );

            // Refill: wrong generation, unoffered suite, duplicate, cap, valid, stale ts.
            assert_eq!(
                store
                    .refill_prekeys(&RefillPrekeysRecord {
                        identity_key: BOB,
                        generation: 99,
                        one_time_prekeys: vec![mk_opk(3)],
                        pq_one_time_prekeys: vec![],
                        max_one_time_prekeys: 10,
                        max_pq_one_time_prekeys: 10,
                        timestamp: 2_000,
                    })
                    .unwrap(),
                RefillOutcome::StaleGeneration
            );
            assert_eq!(
                store
                    .refill_prekeys(&RefillPrekeysRecord {
                        identity_key: BOB,
                        generation: 1,
                        one_time_prekeys: vec![],
                        pq_one_time_prekeys: vec![mk_pq_key(9, 0xC9)],
                        max_one_time_prekeys: 10,
                        max_pq_one_time_prekeys: 10,
                        timestamp: 2_000,
                    })
                    .unwrap(),
                RefillOutcome::SuiteNotOffered
            );
            assert_eq!(
                store
                    .refill_prekeys(&RefillPrekeysRecord {
                        identity_key: BOB,
                        generation: 1,
                        one_time_prekeys: vec![mk_opk(1)],
                        pq_one_time_prekeys: vec![],
                        max_one_time_prekeys: 10,
                        max_pq_one_time_prekeys: 10,
                        timestamp: 2_000,
                    })
                    .unwrap(),
                RefillOutcome::DuplicatePrekey
            );
            assert_eq!(
                store
                    .refill_prekeys(&RefillPrekeysRecord {
                        identity_key: BOB,
                        generation: 1,
                        one_time_prekeys: vec![mk_opk(3), mk_opk(4)],
                        pq_one_time_prekeys: vec![mk_pq_key(2, 0xB2)],
                        max_one_time_prekeys: 10,
                        max_pq_one_time_prekeys: 10,
                        timestamp: 2_000,
                    })
                    .unwrap(),
                RefillOutcome::Stored {
                    classical_count: 4,
                    pq_counts: vec![(1, 1), (2, 1)],
                }
            );
            assert_eq!(
                store
                    .refill_prekeys(&RefillPrekeysRecord {
                        identity_key: BOB,
                        generation: 1,
                        one_time_prekeys: vec![mk_opk(5)],
                        pq_one_time_prekeys: vec![],
                        max_one_time_prekeys: 10,
                        max_pq_one_time_prekeys: 10,
                        timestamp: 2_000,
                    })
                    .unwrap(),
                RefillOutcome::StaleTimestamp
            );
        }

        #[test]
        fn claim_bundle_preserves_classical_spk_sig_and_enforces_opk_budget() {
            let env = TestIdentity::new(50_000);
            let store = env.store();

            assert_eq!(
                store.claim_bundle_checked(&[1], false, 1_000).unwrap(),
                ClaimOutcome::NotFound
            );
            assert!(!store.has_tables().unwrap());

            let opks: Vec<PublicKey> = (0..40).map(mk_opk).collect();
            assert_eq!(
                store
                    .publish_v2(&PublishV2Record {
                        manifest: mk_manifest(1, 1, true, false),
                        signed_prekey_signature: Some([0x77; 64]),
                        one_time_prekeys: opks,
                        pq_last_resort: vec![mk_pq_key(1, 0xA1), mk_pq_key(2, 0xA2)],
                        pq_one_time_prekeys: vec![mk_pq_key(1, 0xB1)],
                        timestamp: 1_000,
                    })
                    .unwrap(),
                PublishV2Status::Stored
            );

            // reject_pq_on_manifest refuses PQ-ON manifest without popping OPKs.
            assert_eq!(
                store.claim_bundle_checked(&[1], true, 1_000).unwrap(),
                ClaimOutcome::PqDisabledForPqManifest
            );
            assert_eq!(
                store.pq_snapshot(1_000).unwrap().classical_one_time_count,
                40
            );

            // Classical claim (empty suites) preserves folded signed_prekey_signature.
            let ClaimOutcome::Claimed(classical) =
                store.claim_bundle_checked(&[], false, 1_000).unwrap()
            else {
                panic!("expected claimed");
            };
            assert_eq!(classical.signed_prekey_signature, Some([0x77; 64]));
            assert_eq!(classical.one_time_prekey, Some(mk_opk(0)));
            assert!(classical.pq_last_resort.is_none());

            // Exhaust remaining 31 hourly OPK claims; 33rd claim returns bundle with OPK=None.
            for i in 1..MAX_OPK_CLAIMS_PER_HOUR {
                let ClaimOutcome::Claimed(c) =
                    store.claim_bundle_checked(&[2], false, 1_000 + i).unwrap()
                else {
                    panic!("expected claimed");
                };
                assert!(c.one_time_prekey.is_some());
            }
            let ClaimOutcome::Claimed(throttled) = store
                .claim_bundle_checked(&[2], false, 1_000 + MAX_OPK_CLAIMS_PER_HOUR)
                .unwrap()
            else {
                panic!("expected claimed");
            };
            assert!(throttled.one_time_prekey.is_none());
            assert_eq!(throttled.pq_last_resort, Some(mk_pq_key(2, 0xA2)));
        }

        #[test]
        fn initial_messages_require_manifest_deduplicate_prune_expired_and_paginate() {
            let env = TestIdentity::new(10_000);
            let store = env.store();

            // Unregistered recipient returns NotFound without creating tables.
            assert_eq!(
                store
                    .add_initial_message_v2(&mk_initial(1, 1, b"hi"), 10, 1_000)
                    .unwrap(),
                AddInitialOutcome::NotFound
            );
            assert!(!store.has_tables().unwrap());

            // Publish manifest.
            assert_eq!(
                store
                    .publish_v2(&PublishV2Record {
                        manifest: mk_manifest(1, 1, true, false),
                        signed_prekey_signature: Some([0x77; 64]),
                        one_time_prekeys: vec![],
                        pq_last_resort: vec![mk_pq_key(1, 0xA1), mk_pq_key(2, 0xA2)],
                        pq_one_time_prekeys: vec![],
                        timestamp: 1_000,
                    })
                    .unwrap(),
                PublishV2Status::Stored
            );

            // Insert initial 1 (v1) and retry idempotently.
            let m1 = mk_initial(1, 1, b"first");
            let AddInitialOutcome::Added {
                id: id1,
                inserted: true,
            } = store.add_initial_message_v2(&m1, 2, 1_000).unwrap()
            else {
                panic!("expected fresh insert");
            };
            assert_eq!(
                store.add_initial_message_v2(&m1, 2, 1_100).unwrap(),
                AddInitialOutcome::Added {
                    id: id1,
                    inserted: false
                }
            );
            // Mismatched payload on same (sender, ephemeral_key) -> PayloadMismatch.
            assert_eq!(
                store
                    .add_initial_message_v2(&mk_initial(1, 1, b"tampered"), 2, 1_200)
                    .unwrap(),
                AddInitialOutcome::PayloadMismatch
            );

            // Insert initial 2 (v2 PQ) -> fills cap 2.
            let m2 = mk_initial(2, 2, b"second");
            let AddInitialOutcome::Added {
                id: id2,
                inserted: true,
            } = store.add_initial_message_v2(&m2, 2, 5_000).unwrap()
            else {
                panic!("expected fresh insert");
            };
            assert!(id2 > id1);
            // Distinct 3rd message hits cap while both unexpired.
            assert_eq!(
                store
                    .add_initial_message_v2(&mk_initial(3, 1, b"third"), 2, 6_000)
                    .unwrap(),
                AddInitialOutcome::LimitExceeded
            );

            // Cursor pagination via after_id.
            let p1 = store.list_initial_messages(BOB, 0, 1, 6_000).unwrap();
            assert_eq!(p1.len(), 1);
            assert_eq!(p1[0].id, id1);
            let p2 = store.list_initial_messages(BOB, id1, 10, 6_000).unwrap();
            assert_eq!(p2.len(), 1);
            assert_eq!(p2[0].id, id2);
            assert_eq!(p2[0].pq_suite, Some(1));
            assert_eq!(p2[0].pq_ciphertext, Some(Bytes::from_static(b"pq-ct")));
            assert!(
                store
                    .list_initial_messages(BOB, MAX_SAFE_INTEGER + 1, 10, 6_000)
                    .is_err()
            );

            // Advance past m1's retention (1_000 + 10_000 = 11_000): m1 is pruned BEFORE
            // `(sender, ephemeral_key)` lookup so reusing eph=1 with a NEW payload succeeds!
            let AddInitialOutcome::Added {
                id: id3,
                inserted: true,
            } = store
                .add_initial_message_v2(&mk_initial(1, 1, b"fresh-after-expiry"), 2, 11_001)
                .unwrap()
            else {
                panic!("expected fresh insert after expiry prune");
            };
            assert!(id3 > id2);

            // Ack deletes only specified IDs.
            assert_eq!(store.ack_initial_messages(&[id2]).unwrap(), 1);
            let rem = store.list_initial_messages(BOB, 0, 10, 11_001).unwrap();
            assert_eq!(rem.len(), 1);
            assert_eq!(rem[0].id, id3);
        }

        #[test]
        fn publish_v2_tracks_prev_signed_prekey_and_rejects_retired_spk() {
            let env = TestIdentity::new(100_000);
            let store = env.store();

            let publish_spk = |seq: u64, spk: PublicKey| {
                let mut m = mk_manifest(seq, seq, true, false);
                m.signed_prekey = spk;
                PublishV2Record {
                    manifest: m,
                    signed_prekey_signature: Some([0x77; 64]),
                    one_time_prekeys: vec![],
                    pq_last_resort: vec![mk_pq_key(1, 0xA1), mk_pq_key(2, 0xA2)],
                    pq_one_time_prekeys: vec![],
                    timestamp: 1_000 + seq,
                }
            };
            let mk_spk_init = |eph: u8, spk: PublicKey| {
                let mut msg = mk_initial(eph, 1, b"hello");
                msg.signed_prekey = spk;
                msg
            };

            let spk1 = [0x22; 32];
            let spk2 = [0x33; 32];
            let spk3 = [0x44; 32];

            // Publish spk1, then republish spk1 -> accepts spk1, rejects unrelated spk2.
            assert_eq!(
                store.publish_v2(&publish_spk(1, spk1)).unwrap(),
                PublishV2Status::Stored
            );
            assert_eq!(
                store.publish_v2(&publish_spk(2, spk1)).unwrap(),
                PublishV2Status::Stored
            );
            assert!(matches!(
                store
                    .add_initial_message_v2(&mk_spk_init(1, spk1), 10, 2_000)
                    .unwrap(),
                AddInitialOutcome::Added { inserted: true, .. }
            ));
            assert_eq!(
                store
                    .add_initial_message_v2(&mk_spk_init(2, spk2), 10, 2_000)
                    .unwrap(),
                AddInitialOutcome::StalePrekey
            );

            // Rotate spk1 -> spk2, then republish spk2: prev_signed_prekey stays spk1.
            assert_eq!(
                store.publish_v2(&publish_spk(3, spk2)).unwrap(),
                PublishV2Status::Stored
            );
            assert_eq!(
                store.publish_v2(&publish_spk(4, spk2)).unwrap(),
                PublishV2Status::Stored
            );
            assert!(matches!(
                store
                    .add_initial_message_v2(&mk_spk_init(3, spk1), 10, 2_100)
                    .unwrap(),
                AddInitialOutcome::Added { inserted: true, .. }
            ));
            assert!(matches!(
                store
                    .add_initial_message_v2(&mk_spk_init(4, spk2), 10, 2_100)
                    .unwrap(),
                AddInitialOutcome::Added { inserted: true, .. }
            ));

            // Rotate spk2 -> spk3: spk3 & spk2 accepted, brand-new retired spk1 returns
            // StalePrekey, while retrying ALREADY-ACCEPTED `mk_spk_init(1, spk1)` preserves
            // strict `(sender, ephemeral_key)` idempotency (`Added { inserted: false }`)!
            assert_eq!(
                store.publish_v2(&publish_spk(5, spk3)).unwrap(),
                PublishV2Status::Stored
            );
            assert!(matches!(
                store
                    .add_initial_message_v2(&mk_spk_init(1, spk1), 10, 2_150)
                    .unwrap(),
                AddInitialOutcome::Added {
                    inserted: false,
                    ..
                }
            ));
            assert!(matches!(
                store
                    .add_initial_message_v2(&mk_spk_init(5, spk2), 10, 2_200)
                    .unwrap(),
                AddInitialOutcome::Added { inserted: true, .. }
            ));
            assert!(matches!(
                store
                    .add_initial_message_v2(&mk_spk_init(6, spk3), 10, 2_200)
                    .unwrap(),
                AddInitialOutcome::Added { inserted: true, .. }
            ));
            assert_eq!(
                store
                    .add_initial_message_v2(&mk_spk_init(7, spk1), 10, 2_200)
                    .unwrap(),
                AddInitialOutcome::StalePrekey
            );
        }
    }
}
