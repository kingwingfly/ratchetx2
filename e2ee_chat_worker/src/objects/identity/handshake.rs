//! V2 capability manifests, classical and post-quantum prekeys, and the two-phase handshake inbox.

use worker::{Date, Error, Result, SqlStorage, SqlStorageValue};

use super::{Identity, rows::*};
use crate::objects::{
    ClaimedBundleWire, InitialMessageV2Wire, ManifestWire, PqCommitmentWire, PqPrekeyWire,
    PqSnapshotWire, PublishV2Outcome, RefillOutcome, blob, checked_integer, has_table,
};

struct PqInitialBindings {
    version: SqlStorageValue,
    suite: SqlStorageValue,
    last_resort: SqlStorageValue,
    prekey_id: SqlStorageValue,
    ciphertext: SqlStorageValue,
    manifest_digest: SqlStorageValue,
}

impl Identity {
    fn pop_classical_opk_sql(sql: &SqlStorage) -> Result<Option<Vec<u8>>> {
        let prekey = sql
            .exec(
                "SELECT position, prekey FROM one_time_prekeys ORDER BY position LIMIT 1",
                None,
            )?
            .to_array::<PrekeyRow>()?
            .pop();
        if let Some(ref prekey) = prekey {
            sql.exec(
                "DELETE FROM one_time_prekeys WHERE position = ?",
                vec![checked_integer(prekey.position)?],
            )?;
        }
        Ok(prekey.map(|p| p.prekey))
    }

    fn get_manifest_sql(sql: &SqlStorage) -> Result<Option<ManifestWire>> {
        if !has_table(sql, "capability_manifest")? {
            return Ok(None);
        }
        let Some(row) = sql
            .exec(
                "SELECT audience, identity_key, manifest_seq, generation, issued_at, expires_at, \
                 pq_enabled, strict_pq, pq_ratchet_supported, offered_suites, signed_prekey, \
                 pq_last_resort_commitments, signature FROM capability_manifest",
                None,
            )?
            .to_array::<ManifestRow>()?
            .pop()
        else {
            return Ok(None);
        };
        let pq_last_resort: Vec<PqCommitmentWire> =
            postcard::from_bytes(&row.pq_last_resort_commitments)
                .map_err(|e| Error::RustError(e.to_string()))?;
        Ok(Some(ManifestWire {
            audience: row.audience,
            identity_key: row.identity_key,
            manifest_seq: row.manifest_seq,
            generation: row.generation,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            pq_enabled: row.pq_enabled != 0,
            strict_pq: row.strict_pq != 0,
            pq_ratchet_supported: row.pq_ratchet_supported != 0,
            offered_suites: row.offered_suites,
            signed_prekey: row.signed_prekey,
            pq_last_resort,
            signature: row.signature,
        }))
    }

    fn pq_one_time_counts_sql(sql: &SqlStorage) -> Result<Vec<(u8, u64)>> {
        if !has_table(sql, "pq_one_time_prekeys")? {
            return Ok(vec![]);
        }
        let rows: Vec<SuiteCountRow> = sql
            .exec(
                "SELECT suite, count(*) AS count FROM pq_one_time_prekeys GROUP BY suite ORDER BY suite",
                None,
            )?
            .to_array()?;
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
        let ts_val = checked_integer(timestamp)?;
        let seq_val = checked_integer(manifest.manifest_seq)?;
        let gen_val = checked_integer(manifest.generation)?;
        let issued_val = checked_integer(manifest.issued_at)?;
        let expires_val = checked_integer(manifest.expires_at)?;
        let pq_enabled_val = checked_integer(u64::from(manifest.pq_enabled))?;
        let strict_pq_val = checked_integer(u64::from(manifest.strict_pq))?;
        let pq_ratchet_val = checked_integer(u64::from(manifest.pq_ratchet_supported))?;

        // Check duplicate classical OPKs, duplicate PQ last-resort suites, and duplicate PQ IDs.
        let mut seen_opks = std::collections::HashSet::with_capacity(one_time_prekeys.len());
        let mut opk_positions = Vec::with_capacity(one_time_prekeys.len());
        for (pos, opk) in one_time_prekeys.iter().enumerate() {
            if !seen_opks.insert(opk.as_slice()) {
                return Ok(PublishV2Outcome::DuplicatePrekey);
            }
            opk_positions.push(checked_integer(pos as u64)?);
        }
        let mut seen_lr_suites = std::collections::HashSet::with_capacity(pq_last_resort.len());
        let mut seen_pq = std::collections::HashSet::with_capacity(
            pq_last_resort.len() + pq_one_time_prekeys.len(),
        );
        let mut lr_suite_vals = Vec::with_capacity(pq_last_resort.len());
        for lr in pq_last_resort {
            if !seen_lr_suites.insert(lr.suite) || !seen_pq.insert(lr.id.as_slice()) {
                return Ok(PublishV2Outcome::DuplicatePrekey);
            }
            lr_suite_vals.push(checked_integer(lr.suite.into())?);
        }
        let mut pq_opk_suite_vals = Vec::with_capacity(pq_one_time_prekeys.len());
        for opk in pq_one_time_prekeys {
            if !seen_pq.insert(opk.id.as_slice()) {
                return Ok(PublishV2Outcome::DuplicatePrekey);
            }
            pq_opk_suite_vals.push(checked_integer(opk.suite.into())?);
        }

        let commitments_blob = postcard::to_allocvec(&manifest.pq_last_resort)
            .map_err(|e| Error::RustError(e.to_string()))?;

        self.transaction_sync(|sql| {
            let existing: Vec<ManifestSeqRow> = sql
                .exec("SELECT manifest_seq FROM capability_manifest", None)?
                .to_array()?;
            if existing
                .first()
                .is_some_and(|row| row.manifest_seq >= manifest.manifest_seq)
            {
                return Ok(PublishV2Outcome::StaleSequence);
            }

            // Prepare classical SPK signature bundle timestamp before any mutations.
            let next_bundle_ts = if !manifest.strict_pq && signed_prekey_signature.is_some() {
                let prev: Vec<TimestampRow> =
                    sql.exec("SELECT timestamp FROM bundle", None)?.to_array()?;
                let next_ts = prev
                    .first()
                    .map_or(timestamp, |r| r.timestamp.max(timestamp));
                Some(checked_integer(next_ts)?)
            } else {
                None
            };

            // Store or clear classical SPK signature row depending on strict_pq and signature presence.
            if let (Some(sig), Some(next_ts_val)) = (signed_prekey_signature, next_bundle_ts) {
                sql.exec(
                    "INSERT INTO bundle (only, signed_prekey, signature, timestamp) VALUES (0, ?, ?, ?) \
                     ON CONFLICT (only) DO UPDATE SET signed_prekey = excluded.signed_prekey, \
                     signature = excluded.signature, timestamp = excluded.timestamp",
                    vec![blob(&manifest.signed_prekey), blob(sig), next_ts_val],
                )?;
            } else {
                sql.exec("DELETE FROM bundle", None)?;
            }

            // Replace classical OPKs.
            sql.exec("DELETE FROM one_time_prekeys", None)?;
            for (pos_val, prekey) in opk_positions.into_iter().zip(one_time_prekeys.iter()) {
                sql.exec(
                    "INSERT INTO one_time_prekeys (position, prekey) VALUES (?, ?)",
                    vec![pos_val, blob(prekey)],
                )?;
            }

            // Replace or clear PQ prekeys depending on affirmative pq_enabled flag.
            sql.exec("DELETE FROM pq_last_resort", None)?;
            sql.exec("DELETE FROM pq_one_time_prekeys", None)?;
            if manifest.pq_enabled {
                for (suite_val, lr) in lr_suite_vals.into_iter().zip(pq_last_resort.iter()) {
                    sql.exec(
                        "INSERT INTO pq_last_resort (suite, prekey_id, encapsulation_key, signature) \
                         VALUES (?, ?, ?, ?)",
                        vec![
                            suite_val,
                            blob(&lr.id),
                            blob(&lr.encapsulation_key),
                            blob(&lr.signature),
                        ],
                    )?;
                }
                for (suite_val, opk) in pq_opk_suite_vals
                    .into_iter()
                    .zip(pq_one_time_prekeys.iter())
                {
                    sql.exec(
                        "INSERT INTO pq_one_time_prekeys (suite, prekey_id, encapsulation_key, signature) \
                         VALUES (?, ?, ?, ?)",
                        vec![
                            suite_val,
                            blob(&opk.id),
                            blob(&opk.encapsulation_key),
                            blob(&opk.signature),
                        ],
                    )?;
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
                vec![
                    manifest.audience.as_str().into(),
                    blob(&manifest.identity_key),
                    seq_val,
                    gen_val,
                    issued_val,
                    expires_val,
                    pq_enabled_val,
                    strict_pq_val,
                    pq_ratchet_val,
                    blob(&manifest.offered_suites),
                    blob(&manifest.signed_prekey),
                    blob(&commitments_blob),
                    blob(&manifest.signature),
                ],
            )?;
            sql.exec(
                "INSERT INTO publish_watermarks (only, last_v1_publish_ts, last_refill_ts) \
                 VALUES (0, ?, 0) \
                 ON CONFLICT (only) DO UPDATE SET \
                 last_v1_publish_ts = max(publish_watermarks.last_v1_publish_ts, excluded.last_v1_publish_ts)",
                vec![ts_val],
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
        let ts_val = checked_integer(timestamp)?;
        if !self.has_tables()? {
            return Ok(RefillOutcome::NotFound);
        }

        self.transaction_sync(|sql| {
            let Some(manifest) = Self::get_manifest_sql(sql)? else {
                return Ok(RefillOutcome::NotFound);
            };
            if manifest.generation != generation {
                return Ok(RefillOutcome::StaleGeneration);
            }
            if !pq_one_time_prekeys.is_empty() && !manifest.pq_enabled {
                return Ok(RefillOutcome::StaleGeneration);
            }

            let wm: Vec<WatermarkRow> = sql
                .exec("SELECT last_refill_ts FROM publish_watermarks", None)?
                .to_array()?;
            if wm
                .first()
                .is_some_and(|row| row.last_refill_ts >= timestamp)
            {
                return Ok(RefillOutcome::StaleTimestamp);
            }
            let existing_opks: Vec<PrekeyRow> = sql
                .exec(
                    "SELECT position, prekey FROM one_time_prekeys ORDER BY position",
                    None,
                )?
                .to_array()?;
            if (existing_opks.len() as u64).saturating_add(one_time_prekeys.len() as u64)
                > max_one_time_prekeys
            {
                return Ok(RefillOutcome::LimitExceeded);
            }
            let mut seen_opks: std::collections::HashSet<Vec<u8>> =
                existing_opks.iter().map(|r| r.prekey.clone()).collect();
            for opk in one_time_prekeys {
                if !seen_opks.insert(opk.clone()) {
                    return Ok(RefillOutcome::DuplicatePrekey);
                }
            }

            let existing_pq_ids: Vec<IdBlobRow> = sql
                .exec("SELECT prekey_id FROM pq_one_time_prekeys", None)?
                .to_array()?;
            if (existing_pq_ids.len() as u64).saturating_add(pq_one_time_prekeys.len() as u64)
                > max_pq_one_time_prekeys
            {
                return Ok(RefillOutcome::LimitExceeded);
            }
            let mut seen_pq_ids: std::collections::HashSet<Vec<u8>> =
                existing_pq_ids.into_iter().map(|r| r.prekey_id).collect();
            let lr_ids: Vec<IdBlobRow> = sql
                .exec("SELECT prekey_id FROM pq_last_resort", None)?
                .to_array()?;
            for lr in lr_ids {
                seen_pq_ids.insert(lr.prekey_id);
            }
            for pq in pq_one_time_prekeys {
                if !manifest.offered_suites.contains(&pq.suite) {
                    return Ok(RefillOutcome::StaleGeneration);
                }
                if !seen_pq_ids.insert(pq.id.clone()) {
                    return Ok(RefillOutcome::DuplicatePrekey);
                }
            }

            // Pre-validate all integer bindings before mutating SQLite.
            let start_pos = existing_opks.last().map_or(0, |r| r.position + 1);
            let mut opk_positions = Vec::with_capacity(one_time_prekeys.len());
            for offset in 0..one_time_prekeys.len() {
                opk_positions.push(checked_integer(start_pos.saturating_add(offset as u64))?);
            }
            let mut pq_suite_vals = Vec::with_capacity(pq_one_time_prekeys.len());
            for pq in pq_one_time_prekeys {
                pq_suite_vals.push(checked_integer(pq.suite.into())?);
            }

            // Record monotonic refill watermark and append OPKs/PQOPKs without rotating SPK.
            sql.exec(
                "INSERT INTO publish_watermarks (only, last_v1_publish_ts, last_refill_ts) \
                 VALUES (0, 0, ?) \
                 ON CONFLICT (only) DO UPDATE SET last_refill_ts = excluded.last_refill_ts",
                vec![ts_val],
            )?;
            for (pos_val, opk) in opk_positions.into_iter().zip(one_time_prekeys.iter()) {
                sql.exec(
                    "INSERT INTO one_time_prekeys (position, prekey) VALUES (?, ?)",
                    vec![pos_val, blob(opk)],
                )?;
            }
            // Append PQOPKs.
            for (suite_val, pq) in pq_suite_vals.into_iter().zip(pq_one_time_prekeys.iter()) {
                sql.exec(
                    "INSERT INTO pq_one_time_prekeys (suite, prekey_id, encapsulation_key, signature) \
                     VALUES (?, ?, ?, ?)",
                    vec![
                        suite_val,
                        blob(&pq.id),
                        blob(&pq.encapsulation_key),
                        blob(&pq.signature),
                    ],
                )?;
            }

            let classical_count = existing_opks.len() as u64 + one_time_prekeys.len() as u64;
            let pq_counts = Self::pq_one_time_counts_sql(sql)?;
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
        Self::get_manifest_sql(&self.sql())
    }

    pub(super) fn claim_bundle(
        &self,
        preferred_suites: &[u8],
    ) -> Result<Option<ClaimedBundleWire>> {
        if !self.has_tables()? {
            return Ok(None);
        }
        self.transaction_sync(|sql| {
            if let Some(manifest) = Self::get_manifest_sql(sql)? {
                let signed_prekey_signature = if manifest.strict_pq {
                    None
                } else {
                    sql.exec("SELECT signed_prekey, signature FROM bundle", None)?
                        .to_array::<BundleRow>()?
                        .pop()
                        .filter(|b| b.signed_prekey == manifest.signed_prekey)
                        .map(|b| b.signature)
                };
                let one_time_prekey = Self::pop_classical_opk_sql(sql)?;

                let (pq_last_resort, pq_one_time_prekey) = if manifest.pq_enabled
                    && !preferred_suites.is_empty()
                    && has_table(sql, "pq_last_resort")?
                {
                    let mut negotiated = None;
                    for &suite in preferred_suites {
                        if !manifest.offered_suites.contains(&suite) {
                            continue;
                        }
                        let lr = sql
                            .exec(
                                "SELECT suite, prekey_id, encapsulation_key, signature \
                                 FROM pq_last_resort WHERE suite = ?",
                                vec![checked_integer(suite.into())?],
                            )?
                            .to_array::<PqLastResortRow>()?
                            .pop();
                        if let Some(lr) = lr {
                            negotiated = Some((suite, lr));
                            break;
                        }
                    }
                    if let Some((suite, lr)) = negotiated {
                        let opk = if has_table(sql, "pq_one_time_prekeys")? {
                            let row = sql
                                .exec(
                                    "SELECT position, suite, prekey_id, encapsulation_key, signature \
                                     FROM pq_one_time_prekeys WHERE suite = ? ORDER BY position LIMIT 1",
                                    vec![checked_integer(suite.into())?],
                                )?
                                .to_array::<PqOneTimeRow>()?
                                .pop();
                            if let Some(ref r) = row {
                                sql.exec(
                                    "DELETE FROM pq_one_time_prekeys WHERE position = ?",
                                    vec![checked_integer(r.position)?],
                                )?;
                            }
                            row.map(|r| PqPrekeyWire {
                                suite: r.suite as u8,
                                id: r.prekey_id,
                                encapsulation_key: r.encapsulation_key,
                                signature: r.signature,
                            })
                        } else {
                            None
                        };
                        (
                            Some(PqPrekeyWire {
                                suite: lr.suite as u8,
                                id: lr.prekey_id,
                                encapsulation_key: lr.encapsulation_key,
                                signature: lr.signature,
                            }),
                            opk,
                        )
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                };

                return Ok(Some(ClaimedBundleWire {
                    signed_prekey: manifest.signed_prekey.clone(),
                    manifest: Some(manifest),
                    signed_prekey_signature,
                    one_time_prekey,
                    pq_last_resort,
                    pq_one_time_prekey,
                }));
            }

            // Preserve read compatibility for pre-existing DOs that still have a classical bundle row.
            let Some(bundle) = sql
                .exec("SELECT signed_prekey, signature FROM bundle", None)?
                .to_array::<BundleRow>()?
                .pop()
            else {
                return Ok(None);
            };
            let one_time_prekey = Self::pop_classical_opk_sql(sql)?;
            Ok(Some(ClaimedBundleWire {
                manifest: None,
                signed_prekey: bundle.signed_prekey,
                signed_prekey_signature: Some(bundle.signature),
                one_time_prekey,
                pq_last_resort: None,
                pq_one_time_prekey: None,
            }))
        })
    }

    pub(super) fn add_initial_message_v2(
        &self,
        message: &InitialMessageV2Wire,
        limit: u64,
    ) -> Result<Option<u64>> {
        let now_val = checked_integer(Date::now().as_millis())?;
        let initial = vec![
            blob(&message.sender),
            blob(&message.ephemeral_key),
            blob(&message.signed_prekey),
            message
                .one_time_prekey
                .as_deref()
                .map_or(SqlStorageValue::Null, blob),
            blob(&message.header),
            blob(&message.content),
            now_val,
        ];
        let pq = if message.version == 1 {
            None
        } else {
            Some(PqInitialBindings {
                version: checked_integer(u64::from(message.version))?,
                suite: checked_integer(u64::from(message.pq_suite.unwrap_or(0)))?,
                last_resort: checked_integer(u64::from(message.pq_last_resort))?,
                prekey_id: blob(message.pq_prekey_id.as_deref().unwrap_or_default()),
                ciphertext: blob(message.pq_ciphertext.as_deref().unwrap_or_default()),
                manifest_digest: message
                    .manifest_digest
                    .as_deref()
                    .map_or(SqlStorageValue::Null, blob),
            })
        };
        self.transaction_sync(|sql| {
            let count: CountRow = sql
                .exec("SELECT count(*) AS count FROM initial_messages", None)?
                .one()?;
            if count.count >= limit {
                return Ok(None);
            }
            let inserted: IdRow = sql
                .exec(
                    "INSERT INTO initial_messages (sender, ephemeral_key, signed_prekey, \
                 one_time_prekey, header, content, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
                 RETURNING id",
                    initial,
                )?
                .one()?;
            let id = checked_integer(inserted.id)?;
            if let Some(pq) = pq {
                sql.exec(
                    "INSERT INTO initial_messages_pq \
                     (initial_message_id, version, pq_suite, pq_last_resort, pq_prekey_id, \
                      pq_ciphertext, manifest_digest) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    vec![
                        id,
                        pq.version,
                        pq.suite,
                        pq.last_resort,
                        pq.prekey_id,
                        pq.ciphertext,
                        pq.manifest_digest,
                    ],
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
        let has_pq_table = has_table(&sql, "initial_messages_pq")?;
        if has_pq_table {
            let rows: Vec<InitialMessageJoinedRow> = sql
                .exec(
                    "SELECT m.id, m.sender, m.ephemeral_key, m.signed_prekey, m.one_time_prekey, \
                     m.header, m.content, p.version, p.pq_suite, p.pq_last_resort, \
                     p.pq_prekey_id, p.pq_ciphertext, p.manifest_digest \
                     FROM initial_messages m \
                     LEFT JOIN initial_messages_pq p ON p.initial_message_id = m.id \
                     ORDER BY m.id LIMIT ?",
                    vec![checked_integer(limit)?],
                )?
                .to_array()?;
            Ok(rows
                .into_iter()
                .map(|r| InitialMessageV2Wire {
                    id: r.id,
                    version: r.version.map_or(1, |v| v as u32),
                    sender: r.sender,
                    ephemeral_key: r.ephemeral_key,
                    signed_prekey: r.signed_prekey,
                    one_time_prekey: r.one_time_prekey,
                    header: r.header,
                    content: r.content,
                    pq_suite: r.pq_suite.map(|s| s as u8),
                    pq_last_resort: r.pq_last_resort.unwrap_or(0) != 0,
                    pq_prekey_id: r.pq_prekey_id,
                    pq_ciphertext: r.pq_ciphertext,
                    manifest_digest: r.manifest_digest,
                })
                .collect())
        } else {
            let rows: Vec<InitialMessageWithIdRow> = sql
                .exec(
                    "SELECT id, sender, ephemeral_key, signed_prekey, one_time_prekey, header, content \
                     FROM initial_messages ORDER BY id LIMIT ?",
                    vec![checked_integer(limit)?],
                )?
                .to_array()?;
            Ok(rows
                .into_iter()
                .map(|r| InitialMessageV2Wire {
                    id: r.id,
                    version: 1,
                    sender: r.sender,
                    ephemeral_key: r.ephemeral_key,
                    signed_prekey: r.signed_prekey,
                    one_time_prekey: r.one_time_prekey,
                    header: r.header,
                    content: r.content,
                    pq_suite: None,
                    pq_last_resort: false,
                    pq_prekey_id: None,
                    pq_ciphertext: None,
                    manifest_digest: None,
                })
                .collect())
        }
    }

    pub(super) fn ack_initial_messages(&self, ids: &[u64]) -> Result<u64> {
        let mut id_vals = Vec::with_capacity(ids.len());
        for &id in ids {
            id_vals.push(checked_integer(id)?);
        }
        if !self.has_tables()? || id_vals.is_empty() {
            return Ok(0);
        }
        self.transaction_sync(|sql| {
            let has_pq_table = has_table(sql, "initial_messages_pq")?;
            let mut deleted = 0u64;
            for id_val in id_vals {
                if has_pq_table {
                    sql.exec(
                        "DELETE FROM initial_messages_pq WHERE initial_message_id = ?",
                        vec![id_val.clone()],
                    )?;
                }
                let res = sql.exec("DELETE FROM initial_messages WHERE id = ?", vec![id_val])?;
                deleted = deleted.saturating_add(res.rows_written() as u64);
            }
            Self::cleanup_orphan_pq_initials_sql(sql)?;
            Ok(deleted)
        })
    }

    fn pq_one_time_counts(&self) -> Result<Vec<(u8, u64)>> {
        Self::pq_one_time_counts_sql(&self.sql())
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
        let manifest = self.get_manifest()?;
        let classical: CountRow = sql
            .exec("SELECT count(*) AS count FROM one_time_prekeys", None)?
            .one()?;
        let pq_last_resort_suites = if has_table(&sql, "pq_last_resort")? {
            let rows: Vec<SuiteRow> = sql
                .exec("SELECT suite FROM pq_last_resort ORDER BY suite", None)?
                .to_array()?;
            rows.into_iter().map(|r| r.suite as u8).collect()
        } else {
            vec![]
        };
        let pq_one_time_counts = self.pq_one_time_counts()?;
        let pending: CountRow = sql
            .exec("SELECT count(*) AS count FROM initial_messages", None)?
            .one()?;
        Ok(PqSnapshotWire {
            manifest,
            classical_one_time_count: classical.count,
            pq_last_resort_suites,
            pq_one_time_counts,
            pending_initial_messages: pending.count,
        })
    }
}
