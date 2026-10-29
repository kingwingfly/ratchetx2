//! The object of an attachment: how many chunks it has, the hashes of its two tokens, and which
//! chunks were put, while its chunks are R2 objects named `attachments/<id>/<index>`. An alarm
//! deletes it, chunks first, once `FILE_RETENTION_DAYS` old, as deleting it does.

use serde::Deserialize;
use worker::{
    Date, DurableObject, Env, Method, Request, Response, Result, SqlStorage, State, console_error,
    durable_object,
};

use super::{
    AttachmentCall, AttachmentRow, RETRY_ALARM, alarm_at, answer, blob, decode, has_table, integer,
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
        let call = decode(&mut request).await?;
        match call {
            AttachmentCall::Add {
                id,
                chunks,
                token_hash,
                delete_hash,
            } => answer(self.add(&id, chunks, &token_hash, &delete_hash).await),
            AttachmentCall::Get => answer(self.get()),
            AttachmentCall::Note { index } => answer(self.note(index)),
            AttachmentCall::Delete => answer(self.delete().await),
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
        let kept: CountRow = sql
            .exec("SELECT count(*) AS count FROM attachment", None)?
            .one()?;
        if kept.count > 0 {
            return Ok(false);
        }
        let retention = crate::period(
            &self.env,
            "FILE_RETENTION_DAYS",
            DEFAULT_FILE_RETENTION_DAYS,
        );
        let at = Date::now()
            .as_millis()
            .saturating_add(crate::millis(retention));
        self.state.storage().set_alarm(alarm_at(at)).await?;
        let added = self.sql().exec(
            "INSERT INTO attachment (only, id, chunks, token_hash, delete_hash, created_at) \
             VALUES (0, ?, ?, ?, ?, ?) ON CONFLICT (only) DO NOTHING",
            vec![
                blob(id),
                integer(chunks.into()),
                blob(token_hash),
                blob(delete_hash),
                integer(Date::now().as_millis()),
            ],
        )?;
        Ok(added.rows_written() > 0)
    }

    /// The attachment, unless gone, or being deleted.
    fn get(&self) -> Result<Option<AttachmentRow>> {
        let sql = self.sql();
        if !has_table(&sql, "attachment")? {
            return Ok(None);
        }
        let rows: Vec<Row> = sql
            .exec(
                "SELECT id, chunks, token_hash, delete_hash, uploaded FROM attachment \
                 WHERE deleting = 0",
                None,
            )?
            .to_array()?;
        Ok(rows.into_iter().next().map(|row| AttachmentRow {
            id: row.id,
            chunks: row.chunks,
            token_hash: row.token_hash,
            delete_hash: row.delete_hash,
            uploaded: row.uploaded as u64,
        }))
    }

    /// Note chunk `index` as put, in one statement, which also tells whether the attachment is
    /// still kept: if it is gone, or being deleted, e.g. deleted while the chunk was on its way,
    /// the Worker deletes the chunk, as deleting the attachment may have missed it.
    fn note(&self, index: u32) -> Result<bool> {
        let sql = self.sql();
        if !has_table(&sql, "attachment")? {
            return Ok(false);
        }
        let noted = sql.exec(
            "UPDATE attachment SET uploaded = uploaded | ? WHERE deleting = 0",
            vec![integer(storage::uploaded_bit(index))],
        )?;
        Ok(noted.rows_written() > 0)
    }

    /// Delete the attachment: gone for every call at once, then its chunks, then its row, so
    /// that a chunk put meanwhile, which finds it gone, is deleted by the Worker, and a failure
    /// leaves the row, rather than chunks no row names. If R2 fails, the alarm tries again
    /// later; the attachment is gone meanwhile.
    async fn delete(&self) -> Result<()> {
        let sql = self.sql();
        if !has_table(&sql, "attachment")? {
            return Ok(());
        }
        let rows: Vec<Row> = sql
            .exec(
                "SELECT id, chunks, token_hash, delete_hash, uploaded FROM attachment",
                None,
            )?
            .to_array()?;
        let Some(attachment) = rows.into_iter().next() else {
            return Ok(());
        };
        sql.exec("UPDATE attachment SET deleting = 1", None)?;
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
        storage.delete_alarm().await?;
        storage.delete_all().await
    }
}

#[derive(Deserialize)]
struct CountRow {
    count: u64,
}

#[derive(Deserialize)]
struct Row {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    chunks: u32,
    #[serde(with = "serde_bytes")]
    token_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    delete_hash: Vec<u8>,
    /// A bitmask, which SQLite keeps as a signed integer.
    uploaded: i64,
}
