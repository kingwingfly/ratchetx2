//! The object of an attachment: who uploaded it, how many chunks it has, its upload token's
//! hash, and which chunks were put, while its chunks are R2 objects named
//! `attachments/<id>/<index>`. An alarm deletes it, chunks first, once `FILE_RETENTION_DAYS` old,
//! as cancelling its upload does.

use serde::Deserialize;
use worker::{
    Date, DurableObject, Env, Method, Request, Response, Result, ScheduledTime, SqlStorage, State,
    durable_object, js_sys,
};

use super::{AttachmentCall, AttachmentRow, answer, blob, decode, integer};

/// How long attachments are kept, unless the `FILE_RETENTION_DAYS` variable says: longer than
/// messages, as recipients may download them again, e.g. on a new device.
pub const DEFAULT_FILE_RETENTION_DAYS: u64 = 90;

/// Its table, a single row while it is kept.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS attachment (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    id BLOB NOT NULL,
    uploader BLOB NOT NULL,
    chunks INTEGER NOT NULL,
    token_hash BLOB NOT NULL,
    -- The chunks put so far, chunk i as bit i: one put and gone from R2 since, as the bucket's
    -- lifecycle rules deleted it, expired, rather than is still to come.
    uploaded INTEGER NOT NULL DEFAULT 0,
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
        // Created on each call, as deleting the attachment deletes its table.
        self.sql().exec(SCHEMA, None)?;
        match call {
            AttachmentCall::Add {
                id,
                uploader,
                chunks,
                token_hash,
            } => {
                let added = self.add(&id, &uploader, chunks, &token_hash);
                if matches!(added, Ok(true)) {
                    let retention = crate::period(
                        &self.env,
                        "FILE_RETENTION_DAYS",
                        DEFAULT_FILE_RETENTION_DAYS,
                    );
                    let at = Date::now()
                        .as_millis()
                        .saturating_add(crate::millis(retention));
                    self.state
                        .storage()
                        .set_alarm(ScheduledTime::new(js_sys::Date::new(&(at as f64).into())))
                        .await?;
                }
                answer(added)
            }
            AttachmentCall::Get => answer(self.get()),
            AttachmentCall::Note { index } => answer(self.note(index)),
            AttachmentCall::Delete => answer(self.delete().await),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        self.sql().exec(SCHEMA, None)?;
        self.delete().await?;
        Response::empty()
    }
}

impl Attachment {
    fn sql(&self) -> SqlStorage {
        self.state.storage().sql()
    }

    fn add(&self, id: &[u8], uploader: &[u8], chunks: u32, token_hash: &[u8]) -> Result<bool> {
        let added = self.sql().exec(
            "INSERT INTO attachment (only, id, uploader, chunks, token_hash, created_at) \
             VALUES (0, ?, ?, ?, ?, ?) ON CONFLICT (only) DO NOTHING",
            vec![
                blob(id),
                blob(uploader),
                integer(chunks.into()),
                blob(token_hash),
                integer(Date::now().as_millis()),
            ],
        )?;
        Ok(added.rows_written() > 0)
    }

    fn get(&self) -> Result<Option<AttachmentRow>> {
        let rows: Vec<Row> = self
            .sql()
            .exec(
                "SELECT id, uploader, chunks, token_hash, uploaded FROM attachment",
                None,
            )?
            .to_array()?;
        Ok(rows.into_iter().next().map(|row| AttachmentRow {
            id: row.id,
            uploader: row.uploader,
            chunks: row.chunks,
            token_hash: row.token_hash,
            uploaded: row.uploaded as u64,
        }))
    }

    /// Note chunk `index` as put, in one statement, which also tells whether the attachment is
    /// still kept: if it was deleted meanwhile, e.g. cancelled while the chunk was on its way,
    /// the Worker deletes the chunk, as no row names it for deleting.
    fn note(&self, index: u32) -> Result<bool> {
        let noted = self.sql().exec(
            "UPDATE attachment SET uploaded = uploaded | ?",
            vec![integer(storage::uploaded_bit(index))],
        )?;
        Ok(noted.rows_written() > 0)
    }

    /// Delete the attachment: its chunks first, so that a failure leaves the row, which the next
    /// alarm or cancel deletes, rather than chunks no row names. A chunk put meanwhile finds the
    /// row gone, and is deleted by the Worker.
    async fn delete(&self) -> Result<()> {
        let Some(attachment) = self.get()? else {
            return Ok(());
        };
        let objects = (0..attachment.chunks)
            .map(|index| crate::store::chunk_object(&attachment.id, index))
            .collect();
        crate::store::delete_objects(&self.env.bucket(crate::BUCKET)?, objects).await?;
        let storage = self.state.storage();
        storage.delete_alarm().await?;
        storage.delete_all().await
    }
}

#[derive(Deserialize)]
struct Row {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    uploader: Vec<u8>,
    chunks: u32,
    #[serde(with = "serde_bytes")]
    token_hash: Vec<u8>,
    /// A bitmask, which SQLite keeps as a signed integer.
    uploaded: i64,
}
