//! The object of an attachment: how many chunks it has, the hashes of its two tokens, and which
//! chunks were put, while its chunks are R2 objects named `v2/attachments/<id>/<index>`. An alarm
//! deletes it, chunks first, once `FILE_RETENTION_DAYS` old, as deleting it does.

use serde::Deserialize;
use storage::StoredAttachment;
use worker::{
    Date, DurableObject, Env, Error, Method, Request, Response, Result, State, console_error,
    durable_object,
};

use super::{
    AttachmentCall, RETRY_ALARM, alarm_at, answer_rpc, decode, has_table, rpc,
    sql::{Blob, SqlExec, WorkerSql, params},
};

/// How long attachments are kept, unless the `FILE_RETENTION_DAYS` variable says: longer than
/// messages, as recipients may download them again, e.g. on a new device.
pub const DEFAULT_FILE_RETENTION_DAYS: u64 = 90;

/// Its table, a single row while it is kept.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS attachment (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    id BLOB NOT NULL,
    chunks INTEGER NOT NULL,
    -- SHA-256 of its upload token, and of its delete token.
    token_hash BLOB NOT NULL,
    delete_hash BLOB NOT NULL,
    -- The chunks put so far, chunk i as bit i: one put and gone from R2 since, as the bucket's
    -- lifecycle rules deleted it, expired, rather than is still to come.
    uploaded INTEGER NOT NULL DEFAULT 0,
    -- Being deleted: gone for every call, while its chunks go, see `AttachmentV2::delete`.
    deleting INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
";

/// SQL-backed core of [`AttachmentV2`], parameterized over [`SqlExec`] and timestamps so native
/// SQLite tests can drive every query, constraint, bitmask, expiry, and deletion transition.
pub(crate) struct AttachmentStore<'a, S: SqlExec> {
    sql: &'a S,
    retention_ms: u64,
}

impl<'a, S: SqlExec> AttachmentStore<'a, S> {
    pub(crate) fn new(sql: &'a S, retention_ms: u64) -> Self {
        Self { sql, retention_ms }
    }

    fn expiry_cutoff(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.retention_ms)
    }

    /// Load the stored attachment row. When `only_live` is `true`, hides rows being deleted or
    /// already past `FILE_RETENTION_DAYS` even if the expiry alarm has not run yet.
    fn load_row(&self, only_live: bool, now_ms: u64) -> Result<Option<AttachmentDbRow>> {
        if !has_table(self.sql, "attachment")? {
            return Ok(None);
        }
        if only_live {
            self.sql.query_opt(
                "SELECT id, chunks, token_hash, delete_hash, uploaded FROM attachment \
                 WHERE deleting = 0 AND created_at >= ?",
                params![self.expiry_cutoff(now_ms)]?,
            )
        } else {
            self.sql.query_opt(
                "SELECT id, chunks, token_hash, delete_hash, uploaded FROM attachment",
                vec![],
            )
        }
    }

    /// Ensures the `attachment` table exists and reports whether the single slot (`only = 0`) is
    /// still unoccupied so the caller can arm the expiry alarm before inserting.
    pub(crate) fn prepare_add(&self) -> Result<bool> {
        self.sql.exec_batch(SCHEMA)?;
        let kept: CountRow = self
            .sql
            .query_one("SELECT count(*) AS count FROM attachment", vec![])?;
        Ok(kept.count == 0)
    }

    /// Inserts the single attachment row (`only = 0`) using `ON CONFLICT (only) DO NOTHING`.
    pub(crate) fn insert_row(&self, attachment: &StoredAttachment, now_ms: u64) -> Result<bool> {
        let inserted: Option<OnlyRow> = self.sql.query_opt(
            "INSERT INTO attachment (only, id, chunks, token_hash, delete_hash, created_at) \
             VALUES (0, ?, ?, ?, ?, ?) ON CONFLICT (only) DO NOTHING RETURNING only",
            params![
                attachment.id.as_slice(),
                attachment.chunks,
                attachment.token_hash.as_slice(),
                attachment.delete_hash.as_slice(),
                now_ms
            ]?,
        )?;
        Ok(inserted.is_some())
    }

    /// The attachment, unless gone, being deleted, or expired.
    pub(crate) fn get(&self, now_ms: u64) -> Result<Option<StoredAttachment>> {
        self.load_row(true, now_ms)?
            .map(StoredAttachment::try_from)
            .transpose()
    }

    /// Note chunk `index` as put, in one statement, which also tells whether the attachment is
    /// still kept and unexpired: if it is gone, expired, or being deleted, the Worker deletes the
    /// chunk, as deleting the attachment may have missed it.
    pub(crate) fn note(&self, index: u32, now_ms: u64) -> Result<bool> {
        if !has_table(self.sql, "attachment")? {
            return Ok(false);
        }
        let updated: Option<OnlyRow> = self.sql.query_opt(
            "UPDATE attachment SET uploaded = uploaded | ? \
             WHERE deleting = 0 AND created_at >= ? RETURNING only",
            params![storage::uploaded_bit(index), self.expiry_cutoff(now_ms)]?,
        )?;
        Ok(updated.is_some())
    }

    /// Marks the attachment row as `deleting = 1` (if any row exists, including expired or
    /// previously-marked rows awaiting R2 retry) and returns the stored row for chunk deletion.
    fn begin_delete(&self) -> Result<Option<AttachmentDbRow>> {
        let Some(attachment) = self.load_row(false, 0)? else {
            return Ok(None);
        };
        self.sql
            .exec("UPDATE attachment SET deleting = 1", vec![])?;
        Ok(Some(attachment))
    }
}

#[durable_object]
pub struct AttachmentV2 {
    state: State,
    env: Env,
}

impl DurableObject for AttachmentV2 {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut request: Request) -> Result<Response> {
        if request.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        let call = match decode(&mut request).await {
            Ok(call) => call,
            Err(_) => return Response::error("malformed internal request", 400),
        };
        match call {
            AttachmentCall::Add(req) => {
                answer_rpc::<rpc::AddAttachment>(self.add(&req.attachment).await)
            }
            AttachmentCall::Get(_) => answer_rpc::<rpc::GetAttachment>(self.get()),
            AttachmentCall::Note(req) => answer_rpc::<rpc::NoteChunk>(self.note(req.index)),
            AttachmentCall::Delete(_) => answer_rpc::<rpc::DeleteAttachment>(self.delete().await),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        self.delete().await?;
        Response::empty()
    }
}

impl AttachmentV2 {
    fn retention(&self) -> u64 {
        crate::millis(crate::period(
            &self.env,
            "FILE_RETENTION_DAYS",
            DEFAULT_FILE_RETENTION_DAYS,
        ))
    }

    fn with_store<T>(
        &self,
        f: impl FnOnce(AttachmentStore<'_, WorkerSql<'_>>) -> Result<T>,
    ) -> Result<T> {
        let sql = self.state.storage().sql();
        let worker_sql = WorkerSql(&self.state, &sql);
        f(AttachmentStore::new(&worker_sql, self.retention()))
    }

    /// Keep the attachment, unless kept already, and set its alarm: first, so that failing to
    /// set it keeps nothing, rather than an attachment that never expires. Its table is created
    /// here, and only here, see `has_table`.
    async fn add(&self, attachment: &StoredAttachment) -> Result<bool> {
        if !self.with_store(|store| store.prepare_add())? {
            return Ok(false);
        }
        let now = Date::now().as_millis();
        let at = now.saturating_add(self.retention());
        self.state.storage().set_alarm(alarm_at(at)).await?;
        self.with_store(|store| store.insert_row(attachment, Date::now().as_millis()))
    }

    /// The attachment, unless gone, being deleted, or expired.
    fn get(&self) -> Result<Option<StoredAttachment>> {
        self.with_store(|store| store.get(Date::now().as_millis()))
    }

    /// Note chunk `index` as put, in one statement, which also tells whether the attachment is
    /// still kept and unexpired: if it is gone, expired, or being deleted, the Worker deletes the
    /// chunk, as deleting the attachment may have missed it.
    fn note(&self, index: u32) -> Result<bool> {
        self.with_store(|store| store.note(index, Date::now().as_millis()))
    }

    /// Delete the attachment: gone for every call at once, then its chunks, then its row, so
    /// that a chunk put meanwhile, which finds it gone, is deleted by the Worker, and a failure
    /// leaves the row, rather than chunks no row names. If R2 fails, the alarm tries again
    /// later; the attachment is gone meanwhile.
    async fn delete(&self) -> Result<()> {
        let Some(attachment) = self.with_store(|store| store.begin_delete())? else {
            return Ok(());
        };
        let objects = (0..attachment.chunks)
            .map(|index| crate::store::chunk_object(&attachment.id, index))
            .collect();
        let storage = self.state.storage();
        let deleted = match self.env.bucket(crate::BUCKET) {
            Ok(bucket) => crate::store::delete_objects(&bucket, objects).await,
            Err(e) => Err(e),
        };
        if let Err(e) = deleted {
            console_error!("cannot delete an attachment's chunks: {e}");
            let at = Date::now().as_millis().saturating_add(RETRY_ALARM);
            return storage.set_alarm(alarm_at(at)).await;
        }
        storage.delete_all().await?;
        if let Err(e) = storage.delete_alarm().await {
            console_error!("cannot delete attachment alarm after deleting storage: {e}");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct CountRow {
    count: u64,
}

#[derive(Deserialize)]
struct OnlyRow {
    #[allow(dead_code)]
    only: i64,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct AttachmentDbRow {
    id: Blob,
    chunks: u32,
    token_hash: Blob,
    delete_hash: Blob,
    /// A bitmask, which SQLite keeps as a signed integer.
    uploaded: i64,
}

fn fixed_blob<const N: usize>(blob: Blob, name: &str) -> Result<[u8; N]> {
    blob.into_vec()
        .try_into()
        .map_err(|_| Error::RustError(format!("corrupt stored attachment {name} length")))
}

impl TryFrom<AttachmentDbRow> for StoredAttachment {
    type Error = Error;

    fn try_from(row: AttachmentDbRow) -> Result<Self> {
        Ok(Self {
            id: fixed_blob(row.id, "id")?,
            chunks: row.chunks,
            token_hash: fixed_blob(row.token_hash, "token_hash")?,
            delete_hash: fixed_blob(row.delete_hash, "delete_hash")?,
            uploaded: row.uploaded as u64,
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::objects::sql::TestSql;

    const RETENTION_MS: u64 = 10_000;

    fn sample_attachment(id_byte: u8, chunks: u32) -> StoredAttachment {
        StoredAttachment {
            id: [id_byte; 16],
            chunks,
            token_hash: [id_byte.wrapping_add(1); 32],
            delete_hash: [id_byte.wrapping_add(2); 32],
            uploaded: 0,
        }
    }

    #[test]
    fn reads_and_notes_leave_unallocated_storage_untouched() {
        let sql = TestSql::in_memory();
        let store = AttachmentStore::new(&sql, RETENTION_MS);

        assert!(store.get(1_000).unwrap().is_none());
        assert!(!store.note(0, 1_000).unwrap());
        assert!(store.load_row(false, 1_000).unwrap().is_none());
        assert!(store.begin_delete().unwrap().is_none());
        assert!(!has_table(&sql, "attachment").unwrap());
    }

    #[test]
    fn single_row_constraint_and_on_conflict_do_nothing() {
        let sql = TestSql::in_memory();
        let store = AttachmentStore::new(&sql, RETENTION_MS);
        let first = sample_attachment(0x11, 4);
        let second = sample_attachment(0x22, 9);

        assert!(store.prepare_add().unwrap());
        assert!(store.insert_row(&first, 5_000).unwrap());
        // `prepare_add` sees the existing row before setting an alarm.
        assert!(!store.prepare_add().unwrap());
        // Direct concurrent `insert_row` hits `ON CONFLICT (only) DO NOTHING` without overwriting.
        assert!(!store.insert_row(&second, 6_000).unwrap());
        // CHECK (only = 0) rejects any second slot.
        let check_err = sql.exec(
            "INSERT INTO attachment (only, id, chunks, token_hash, delete_hash, created_at) \
             VALUES (1, ?, 1, ?, ?, 5000)",
            params![
                second.id.as_slice(),
                second.token_hash.as_slice(),
                second.delete_hash.as_slice()
            ]
            .unwrap(),
        );
        assert!(check_err.is_err());

        let row = store.get(5_000).unwrap().expect("stored attachment");
        assert_eq!(row, first);
    }

    #[test]
    fn note_updates_uploaded_bitmask_across_chunks() {
        let sql = TestSql::in_memory();
        let store = AttachmentStore::new(&sql, RETENTION_MS);
        let att = sample_attachment(0x33, 60);
        assert!(store.prepare_add().unwrap());
        assert!(store.insert_row(&att, 1_000).unwrap());

        assert!(store.note(0, 1_500).unwrap());
        assert!(store.note(3, 1_500).unwrap());
        assert!(store.note(storage::UPLOADED_NOTED - 1, 1_500).unwrap());
        // Re-noting the same bit is idempotent.
        assert!(store.note(3, 1_600).unwrap());
        // Chunks at or above UPLOADED_NOTED still return true for live rows without corrupting bits.
        assert!(store.note(storage::UPLOADED_NOTED, 1_600).unwrap());

        let row = store.get(1_600).unwrap().unwrap();
        let expected =
            storage::uploaded_bit(0) | storage::uploaded_bit(3) | storage::uploaded_bit(52);
        assert_eq!(row.uploaded, expected);
    }

    #[test]
    fn load_row_live_vs_all_handles_expiry_and_deleting_retry_lifecycle() {
        let sql = TestSql::in_memory();
        let store = AttachmentStore::new(&sql, RETENTION_MS);
        let att = sample_attachment(0x44, 3);
        assert!(store.prepare_add().unwrap());
        assert!(store.insert_row(&att, 10_000).unwrap());

        // Exactly at retention boundary (created_at == now - retention): still live.
        assert!(
            store
                .load_row(true, 10_000 + RETENTION_MS)
                .unwrap()
                .is_some()
        );
        assert!(store.note(0, 10_000 + RETENTION_MS).unwrap());

        // 1 ms past retention: hidden from `load_row(true)` / `get` / `note`,
        // but still visible to `load_row(false)` for alarm R2 cleanup.
        let expired_now = 10_000 + RETENTION_MS + 1;
        assert!(store.load_row(true, expired_now).unwrap().is_none());
        assert!(store.get(expired_now).unwrap().is_none());
        assert!(!store.note(1, expired_now).unwrap());
        let raw_expired = store
            .load_row(false, expired_now)
            .unwrap()
            .expect("expired row retained for cleanup");
        assert_eq!(raw_expired.id.as_ref(), &att.id);
        assert_eq!(raw_expired.uploaded as u64, storage::uploaded_bit(0));

        // Transition to `deleting = 1` (e.g. while R2 deletion is in flight or retrying).
        let started = store
            .begin_delete()
            .unwrap()
            .expect("row returned for R2 delete");
        assert_eq!(started.chunks, 3);

        // Even at an unexpired timestamp, `deleting = 1` hides the row from `load_row(true)` /
        // `get` / `note` immediately.
        assert!(store.load_row(true, 10_000).unwrap().is_none());
        assert!(store.get(10_000).unwrap().is_none());
        assert!(!store.note(2, 10_000).unwrap());

        // `load_row(false)` and subsequent `begin_delete()` retries still see the row until wipe.
        let retry = store
            .load_row(false, 10_000)
            .unwrap()
            .expect("deleting row retained for R2 retry");
        assert_eq!(retry.id.as_ref(), &att.id);
        assert!(store.begin_delete().unwrap().is_some());

        // After storage wipe (simulated `delete_all`), row is gone for all callers.
        sql.exec("DROP TABLE attachment", vec![]).unwrap();
        assert!(store.load_row(false, 10_000).unwrap().is_none());
        assert!(store.begin_delete().unwrap().is_none());
    }
}
