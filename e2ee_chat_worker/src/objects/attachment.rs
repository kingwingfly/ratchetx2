//! The object of an attachment: how many chunks it has, the hashes of its two tokens, and which
//! chunks were put, while its chunks are R2 objects named `attachments/<id>/<index>`. An alarm
//! deletes it, chunks first, once `FILE_RETENTION_DAYS` old, as deleting it does.

use serde::Deserialize;
use worker::{
    Date, DurableObject, Env, Method, Request, Response, Result, SqlStorage, State, console_error,
    durable_object,
};

use super::{
    AttachmentCall, AttachmentRow, RETRY_ALARM, alarm_at, answer_rpc, decode, has_table, rpc,
    sql::{Blob, exec, params, query_one, query_opt},
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
    -- Being deleted: gone for every call, while its chunks go, see `Attachment::delete`.
    deleting INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
";

#[durable_object]
pub struct Attachment {
    state: State,
    env: Env,
}

impl DurableObject for Attachment {
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
            AttachmentCall::Add(req) => answer_rpc::<rpc::AddAttachment>(
                self.add(&req.id, req.chunks, &req.token_hash, &req.delete_hash)
                    .await,
            ),
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

impl Attachment {
    fn sql(&self) -> SqlStorage {
        self.state.storage().sql()
    }

    fn retention(&self) -> u64 {
        crate::millis(crate::period(
            &self.env,
            "FILE_RETENTION_DAYS",
            DEFAULT_FILE_RETENTION_DAYS,
        ))
    }

    fn expiry_cutoff(&self) -> u64 {
        Date::now().as_millis().saturating_sub(self.retention())
    }

    /// Load the stored attachment row. When `only_live` is `true`, hides rows being deleted or
    /// already past `FILE_RETENTION_DAYS` even if the expiry alarm has not run yet.
    fn load_row(&self, only_live: bool) -> Result<Option<AttachmentDbRow>> {
        let sql = self.sql();
        if !has_table(&sql, "attachment")? {
            return Ok(None);
        }
        if only_live {
            query_opt(
                &sql,
                "SELECT id, chunks, token_hash, delete_hash, uploaded FROM attachment \
                 WHERE deleting = 0 AND created_at >= ?",
                params![self.expiry_cutoff()]?,
            )
        } else {
            query_opt(
                &sql,
                "SELECT id, chunks, token_hash, delete_hash, uploaded FROM attachment",
                vec![],
            )
        }
    }

    /// Keep the attachment, unless kept already, and set its alarm: first, so that failing to
    /// set it keeps nothing, rather than an attachment that never expires. Its table is created
    /// here, and only here, see `has_table`.
    async fn add(
        &self,
        id: &[u8],
        chunks: u32,
        token_hash: &[u8],
        delete_hash: &[u8],
    ) -> Result<bool> {
        let sql = self.sql();
        sql.exec(SCHEMA, None)?;
        let kept: CountRow = query_one(&sql, "SELECT count(*) AS count FROM attachment", vec![])?;
        if kept.count > 0 {
            return Ok(false);
        }
        let now = Date::now().as_millis();
        let at = now.saturating_add(self.retention());
        self.state.storage().set_alarm(alarm_at(at)).await?;
        let inserted: Option<OnlyRow> = query_opt(
            &self.sql(),
            "INSERT INTO attachment (only, id, chunks, token_hash, delete_hash, created_at) \
             VALUES (0, ?, ?, ?, ?, ?) ON CONFLICT (only) DO NOTHING RETURNING only",
            params![id, chunks, token_hash, delete_hash, Date::now().as_millis()]?,
        )?;
        Ok(inserted.is_some())
    }

    /// The attachment, unless gone, being deleted, or expired.
    fn get(&self) -> Result<Option<AttachmentRow>> {
        Ok(self.load_row(true)?.map(AttachmentRow::from))
    }

    /// Note chunk `index` as put, in one statement, which also tells whether the attachment is
    /// still kept and unexpired: if it is gone, expired, or being deleted, the Worker deletes the
    /// chunk, as deleting the attachment may have missed it.
    fn note(&self, index: u32) -> Result<bool> {
        let sql = self.sql();
        if !has_table(&sql, "attachment")? {
            return Ok(false);
        }
        let updated: Option<OnlyRow> = query_opt(
            &sql,
            "UPDATE attachment SET uploaded = uploaded | ? \
             WHERE deleting = 0 AND created_at >= ? RETURNING only",
            params![storage::uploaded_bit(index), self.expiry_cutoff()]?,
        )?;
        Ok(updated.is_some())
    }

    /// Delete the attachment: gone for every call at once, then its chunks, then its row, so
    /// that a chunk put meanwhile, which finds it gone, is deleted by the Worker, and a failure
    /// leaves the row, rather than chunks no row names. If R2 fails, the alarm tries again
    /// later; the attachment is gone meanwhile.
    async fn delete(&self) -> Result<()> {
        let Some(attachment) = self.load_row(false)? else {
            return Ok(());
        };
        exec(&self.sql(), "UPDATE attachment SET deleting = 1", vec![])?;
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

#[derive(Deserialize)]
struct AttachmentDbRow {
    id: Blob,
    chunks: u32,
    token_hash: Blob,
    delete_hash: Blob,
    /// A bitmask, which SQLite keeps as a signed integer.
    uploaded: i64,
}

impl From<AttachmentDbRow> for AttachmentRow {
    fn from(row: AttachmentDbRow) -> Self {
        Self {
            id: row.id.into_vec(),
            chunks: row.chunks,
            token_hash: row.token_hash.into_vec(),
            delete_hash: row.delete_hash.into_vec(),
            uploaded: row.uploaded as u64,
        }
    }
}
