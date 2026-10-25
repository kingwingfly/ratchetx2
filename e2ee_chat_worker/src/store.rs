//! The handshake, mailbox and attachment stores over D1, with large message contents and
//! attachments' chunks in R2.
//!
//! The tables are in `migrations/`. Every method is one D1 statement or one batch, which D1 runs
//! as a transaction, so each is atomic as the storage traits require. Where a batch depends on a
//! condition, such as a newer timestamp, every statement checks it against the rows as they were,
//! before the statement that changes them, which comes last.

use futures_util::future::try_join_all;
use serde::Deserialize;
use storage::{
    AttachmentId, Bundle, Bytes, Error, ErrorKind, LocalAttachmentStore, LocalHandshakeStore,
    LocalMailboxStore, PublicKey, Result, StoredAttachment, StoredInitialMessage, StoredMessage,
};
use worker::{
    Bucket, D1Database, D1PreparedStatement, D1Result, Date, Env, console_error,
    js_sys::Uint8Array, wasm_bindgen::JsValue,
};

/// Contents larger than this go to R2; smaller ones stay in their D1 row.
pub const INLINE_CONTENT_MAX: usize = 64 << 10;

/// JavaScript's largest exact integer, as D1 takes integers as JavaScript numbers.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The stores over the D1 database `DB` and the R2 bucket `BUCKET`.
pub struct Store {
    db: D1Database,
    bucket: Bucket,
    /// Most bytes, headers and contents, one read returns, unless its first message alone is
    /// larger.
    max_read_size: usize,
}

impl Store {
    /// The stores over `env`'s bindings, whose reads return at most `max_read_size` bytes,
    /// unless the first message alone is larger.
    pub fn new(env: &Env, max_read_size: usize) -> worker::Result<Self> {
        Ok(Self {
            db: env.d1("DB")?,
            bucket: env.bucket("BUCKET")?,
            max_read_size,
        })
    }

    fn prepare(&self, query: &str, values: &[JsValue]) -> Result<D1PreparedStatement> {
        self.db.prepare(query).bind(values).map_err(unavailable)
    }

    async fn batch(&self, statements: Vec<D1PreparedStatement>) -> Result<Vec<D1Result>> {
        self.db.batch(statements).await.map_err(unavailable)
    }

    /// Delete the messages, initial messages and attachments created before `before`, and their
    /// R2 objects. Returns how many messages and attachments were deleted.
    pub async fn expire(&self, before: u64) -> Result<(usize, usize)> {
        let messages = self.expire_messages(before).await?;
        let attachments = self.expire_attachments(before).await?;
        Ok((messages, attachments))
    }

    /// Delete the attachments created before `before`, in pages, their chunks first, so that a
    /// failure leaves rows, which the next run picks up, rather than chunks no row names.
    async fn expire_attachments(&self, before: u64) -> Result<usize> {
        const PAGE: &str =
            "SELECT id FROM attachments WHERE created_at < ?1 ORDER BY created_at, id LIMIT 100";
        let before = integer(before);
        let mut deleted = 0;
        loop {
            let rows: Vec<AttachmentRow> = rows(
                &self
                    .prepare(
                        &format!(
                            "SELECT id, uploader, chunks, token_hash FROM attachments \
                             WHERE id IN ({PAGE})"
                        ),
                        std::slice::from_ref(&before),
                    )?
                    .all()
                    .await
                    .map_err(unavailable)?,
            )?;
            let attachments = rows
                .iter()
                .map(AttachmentRow::stored)
                .collect::<Result<Vec<_>>>()?;
            self.delete_chunks(&attachments).await?;
            self.prepare(
                &format!("DELETE FROM attachments WHERE id IN ({PAGE})"),
                std::slice::from_ref(&before),
            )?
            .run()
            .await
            .map_err(unavailable)?;
            deleted += rows.len();
            if rows.len() < 100 {
                return Ok(deleted);
            }
        }
    }

    /// Delete the messages and initial messages created before `before`, and the messages' R2
    /// objects. Returns how many messages were deleted.
    async fn expire_messages(&self, before: u64) -> Result<usize> {
        let before = integer(before);
        self.prepare(
            "DELETE FROM initial_messages WHERE created_at < ?1",
            std::slice::from_ref(&before),
        )?
        .run()
        .await
        .map_err(unavailable)?;
        // In pages, so each statement and R2 call stays small. The R2 objects go first: a row
        // whose object is gone reads as empty content and goes in the next run, while an object
        // whose row is gone would stay forever. The order makes both statements pick the same
        // rows.
        const PAGE: &str = "SELECT sender, recipient, sequence FROM messages WHERE created_at < ?1 \
                            ORDER BY created_at, sender, recipient, sequence LIMIT 1000";
        let mut deleted = 0;
        loop {
            let rows: Vec<ObjectRow> = rows(
                &self
                    .prepare(
                        &format!(
                            "SELECT object FROM messages \
                             WHERE (sender, recipient, sequence) IN ({PAGE})"
                        ),
                        std::slice::from_ref(&before),
                    )?
                    .all()
                    .await
                    .map_err(unavailable)?,
            )?;
            let objects: Vec<_> = rows
                .iter()
                .filter_map(|row| row.object.as_deref())
                .collect();
            if !objects.is_empty() {
                self.bucket
                    .delete_multiple(objects)
                    .await
                    .map_err(unavailable)?;
            }
            self.prepare(
                &format!("DELETE FROM messages WHERE (sender, recipient, sequence) IN ({PAGE})"),
                std::slice::from_ref(&before),
            )?
            .run()
            .await
            .map_err(unavailable)?;
            deleted += rows.len();
            if rows.len() < 1000 {
                return Ok(deleted);
            }
        }
    }
}

impl LocalHandshakeStore for Store {
    async fn publish(&self, bundle: Bundle, one_time_prekeys: Vec<PublicKey>) -> Result<bool> {
        let identity_key = blob(&bundle.identity_key);
        let timestamp = integer(bundle.timestamp);
        // The prekeys as a JSON array of hex strings, inserted by one statement.
        let one_time_prekeys: Vec<String> = one_time_prekeys.iter().map(|key| hex(key)).collect();
        let one_time_prekeys = json_array(&one_time_prekeys);
        // Only if the stored bundle, if any, is older.
        const OLDER: &str =
            "NOT EXISTS (SELECT 1 FROM bundles WHERE identity_key = ?1 AND timestamp >= ?2)";
        let results = self
            .batch(vec![
                self.prepare(
                    &format!("DELETE FROM one_time_prekeys WHERE identity_key = ?1 AND {OLDER}"),
                    &[identity_key.clone(), timestamp.clone()],
                )?,
                self.prepare(
                    &format!(
                        "INSERT INTO one_time_prekeys (identity_key, position, prekey) \
                         SELECT ?1, key, unhex(value) FROM json_each(?3) WHERE {OLDER}"
                    ),
                    &[
                        identity_key.clone(),
                        timestamp.clone(),
                        one_time_prekeys.into(),
                    ],
                )?,
                self.prepare(
                    "INSERT INTO bundles \
                     (identity_key, signed_prekey, signed_prekey_signature, timestamp) \
                     VALUES (?1, ?2, ?3, ?4) \
                     ON CONFLICT (identity_key) DO UPDATE SET \
                     signed_prekey = excluded.signed_prekey, \
                     signed_prekey_signature = excluded.signed_prekey_signature, \
                     timestamp = excluded.timestamp \
                     WHERE excluded.timestamp > bundles.timestamp",
                    &[
                        identity_key,
                        blob(&bundle.signed_prekey),
                        blob(&bundle.signed_prekey_signature),
                        timestamp,
                    ],
                )?,
            ])
            .await?;
        Ok(changes(&results[2])? > 0)
    }

    async fn take_bundle(
        &self,
        identity_key: &PublicKey,
    ) -> Result<Option<(Bundle, Option<PublicKey>)>> {
        let key = blob(identity_key);
        let results = self
            .batch(vec![
                self.prepare(
                    "DELETE FROM one_time_prekeys WHERE identity_key = ?1 AND position = \
                     (SELECT min(position) FROM one_time_prekeys WHERE identity_key = ?1) \
                     RETURNING prekey",
                    std::slice::from_ref(&key),
                )?,
                self.prepare(
                    "SELECT signed_prekey, signed_prekey_signature, timestamp FROM bundles \
                     WHERE identity_key = ?1",
                    &[key],
                )?,
            ])
            .await?;
        let Some(bundle) = rows::<BundleRow>(&results[1])?.pop() else {
            return Ok(None);
        };
        let one_time_prekey = rows::<PrekeyRow>(&results[0])?
            .pop()
            .map(|row| fixed(&row.prekey))
            .transpose()?;
        let bundle = Bundle {
            identity_key: *identity_key,
            signed_prekey: fixed(&bundle.signed_prekey)?,
            signed_prekey_signature: fixed(&bundle.signed_prekey_signature)?,
            timestamp: bundle.timestamp,
        };
        Ok(Some((bundle, one_time_prekey)))
    }

    async fn add_initial_message(
        &self,
        initial_message: StoredInitialMessage,
        limit: usize,
    ) -> Result<bool> {
        let result = self
            .prepare(
                "INSERT INTO initial_messages \
                 (recipient, sender, ephemeral_key, signed_prekey, one_time_prekey, header, \
                 content, created_at) \
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 \
                 WHERE (SELECT count(*) FROM initial_messages WHERE recipient = ?1) < ?9",
                &[
                    blob(&initial_message.recipient),
                    blob(&initial_message.sender),
                    blob(&initial_message.ephemeral_key),
                    blob(&initial_message.signed_prekey),
                    initial_message
                        .one_time_prekey
                        .as_ref()
                        .map_or(JsValue::NULL, |key| blob(key)),
                    blob(&initial_message.header),
                    blob(&initial_message.content),
                    integer(Date::now().as_millis()),
                    integer(limit as u64),
                ],
            )?
            .run()
            .await
            .map_err(unavailable)?;
        Ok(changes(&result)? > 0)
    }

    async fn take_initial_messages(
        &self,
        recipient: &PublicKey,
        timestamp: u64,
    ) -> Result<Option<Vec<StoredInitialMessage>>> {
        let values = [blob(recipient), integer(timestamp)];
        let results = self
            .batch(vec![
                self.prepare(
                    "DELETE FROM initial_messages WHERE recipient = ?1 AND NOT EXISTS \
                     (SELECT 1 FROM inboxes WHERE recipient = ?1 AND last_take >= ?2) \
                     RETURNING id, sender, ephemeral_key, signed_prekey, one_time_prekey, header, \
                     content",
                    &values,
                )?,
                self.prepare(
                    "INSERT INTO inboxes (recipient, last_take) VALUES (?1, ?2) \
                     ON CONFLICT (recipient) DO UPDATE SET last_take = excluded.last_take \
                     WHERE excluded.last_take > inboxes.last_take",
                    &values,
                )?,
            ])
            .await?;
        if changes(&results[1])? == 0 {
            return Ok(None);
        }
        let mut rows = rows::<InitialMessageRow>(&results[0])?;
        rows.sort_by_key(|row| row.id);
        rows.into_iter()
            .map(|row| {
                Ok(StoredInitialMessage {
                    sender: fixed(&row.sender)?,
                    recipient: *recipient,
                    ephemeral_key: fixed(&row.ephemeral_key)?,
                    signed_prekey: fixed(&row.signed_prekey)?,
                    one_time_prekey: row.one_time_prekey.as_deref().map(fixed).transpose()?,
                    header: Bytes::from(row.header),
                    content: Bytes::from(row.content),
                })
            })
            .collect::<Result<_>>()
            .map(Some)
    }
}

impl LocalMailboxStore for Store {
    async fn append(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
    ) -> Result<u64> {
        let object = (content.len() > INLINE_CONTENT_MAX).then(|| {
            format!(
                "messages/{}/{}/{}",
                hex(sender),
                hex(recipient),
                random_id()
            )
        });
        let queue = [blob(sender), blob(recipient)];
        let statements = vec![
            self.prepare(
                "INSERT INTO queues (sender, recipient, last_sequence) VALUES (?1, ?2, 1) \
                 ON CONFLICT (sender, recipient) DO UPDATE SET last_sequence = last_sequence + 1",
                &queue,
            )?,
            self.prepare(
                "INSERT INTO messages \
                 (sender, recipient, sequence, header, content, object, size, created_at) \
                 SELECT ?1, ?2, last_sequence, ?3, ?4, ?5, ?6, ?7 FROM queues \
                 WHERE sender = ?1 AND recipient = ?2 RETURNING sequence",
                &[
                    queue[0].clone(),
                    queue[1].clone(),
                    blob(&header),
                    match object {
                        Some(_) => JsValue::NULL,
                        None => blob(&content),
                    },
                    object.as_deref().map_or(JsValue::NULL, JsValue::from_str),
                    integer(content.len() as u64),
                    integer(Date::now().as_millis()),
                ],
            )?,
        ];
        if let Some(object) = &object {
            self.bucket
                .put(object, content.to_vec())
                .execute()
                .await
                .map_err(unavailable)?;
        }
        let results = match self.batch(statements).await {
            Ok(results) => results,
            Err(error) => {
                if let Some(object) = object
                    && let Err(e) = self.bucket.delete(object).await
                {
                    console_error!("cannot delete the object of a message not appended: {e}");
                }
                return Err(error);
            }
        };
        let row = rows::<SequenceRow>(&results[1])?
            .pop()
            .ok_or_else(|| Error::new(ErrorKind::Corrupt, "no sequence number returned"))?;
        Ok(row.sequence)
    }

    async fn read(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
    ) -> Result<Vec<StoredMessage>> {
        // Only the messages that fit in the size, headers included as the mailbox counts them,
        // leave D1, so a page fits in the Worker's memory: their bytes are summed from the
        // lengths, without reading the blobs; the first message always comes, so that fetching
        // progresses.
        let rows: Vec<MessageRow> = rows(
            &self
                .prepare(
                    "WITH page AS ( \
                         SELECT sequence, size + length(header) AS bytes FROM messages \
                         WHERE sender = ?1 AND recipient = ?2 AND sequence > ?3 \
                         ORDER BY sequence LIMIT ?4 \
                     ), sums AS ( \
                         SELECT sequence, sum(bytes) OVER (ORDER BY sequence) AS total FROM page \
                     ) \
                     SELECT m.sequence, m.header, m.content, m.object FROM sums \
                     JOIN messages AS m \
                     ON m.sender = ?1 AND m.recipient = ?2 AND m.sequence = sums.sequence \
                     WHERE sums.total <= ?5 OR sums.sequence = (SELECT min(sequence) FROM page) \
                     ORDER BY m.sequence",
                    &[
                        blob(sender),
                        blob(recipient),
                        integer(after),
                        integer(limit.into()),
                        integer(self.max_read_size as u64),
                    ],
                )?
                .all()
                .await
                .map_err(unavailable)?,
        )?;
        try_join_all(rows.into_iter().map(|row| async move {
            let content = match (row.content, &row.object) {
                (Some(content), _) => Bytes::from(content),
                (None, Some(object)) => self.object(object).await?,
                (None, None) => return Err(Error::new(ErrorKind::Corrupt, "no content")),
            };
            Ok(StoredMessage {
                sender: *sender,
                recipient: *recipient,
                sequence: row.sequence,
                header: Bytes::from(row.header),
                content,
            })
        }))
        .await
    }
}

impl LocalAttachmentStore for Store {
    async fn add_attachment(&self, attachment: StoredAttachment) -> Result<bool> {
        let result = self
            .prepare(
                "INSERT INTO attachments (id, uploader, chunks, token_hash, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (id) DO NOTHING",
                &[
                    blob(&attachment.id),
                    blob(&attachment.uploader),
                    integer(attachment.chunks.into()),
                    blob(&attachment.token_hash),
                    integer(Date::now().as_millis()),
                ],
            )?
            .run()
            .await
            .map_err(unavailable)?;
        Ok(changes(&result)? > 0)
    }

    async fn attachment(&self, id: &AttachmentId) -> Result<Option<StoredAttachment>> {
        let result = self
            .prepare(
                "SELECT id, uploader, chunks, token_hash FROM attachments WHERE id = ?1",
                &[blob(id)],
            )?
            .all()
            .await
            .map_err(unavailable)?;
        rows::<AttachmentRow>(&result)?
            .first()
            .map(AttachmentRow::stored)
            .transpose()
    }

    /// The row is looked at again once the chunk is in R2: if the attachment was deleted
    /// meanwhile, e.g. cancelled while the chunk was on its way, the chunk goes too, as no row
    /// would name it for expiry to delete.
    async fn put_chunk(&self, id: &AttachmentId, index: u32, data: Bytes) -> Result<()> {
        let object = chunk_object(id, index);
        self.bucket
            .put(&object, data.to_vec())
            .execute()
            .await
            .map_err(unavailable)?;
        if self.attachment(id).await?.is_none() {
            self.bucket.delete(&object).await.map_err(unavailable)?;
            return Err(Error::new(ErrorKind::Other, "the attachment was deleted"));
        }
        Ok(())
    }

    /// The chunks go first, so that a failure leaves the row, which expires, rather than chunks
    /// no row names; and again once the row is gone, as a chunk put meanwhile, which found the
    /// row still there, would stay.
    async fn delete_attachment(&self, id: &AttachmentId) -> Result<()> {
        let Some(attachment) = self.attachment(id).await? else {
            return Ok(());
        };
        let attachment = std::slice::from_ref(&attachment);
        self.delete_chunks(attachment).await?;
        self.prepare("DELETE FROM attachments WHERE id = ?1", &[blob(id)])?
            .run()
            .await
            .map_err(unavailable)?;
        self.delete_chunks(attachment).await
    }

    async fn chunk(&self, id: &AttachmentId, index: u32) -> Result<Option<Bytes>> {
        let Some(object) = self
            .bucket
            .get(chunk_object(id, index))
            .execute()
            .await
            .map_err(unavailable)?
        else {
            return Ok(None);
        };
        let body = object
            .body()
            .ok_or_else(|| Error::new(ErrorKind::Corrupt, "an R2 object without a body"))?;
        Ok(Some(Bytes::from(body.bytes().await.map_err(unavailable)?)))
    }
}

impl Store {
    /// Delete the R2 objects of the chunks of `attachments`, 1000 at once, as R2 takes them.
    async fn delete_chunks(&self, attachments: &[StoredAttachment]) -> Result<()> {
        let objects: Vec<_> = attachments
            .iter()
            .flat_map(|attachment| {
                (0..attachment.chunks).map(|index| chunk_object(&attachment.id, index))
            })
            .collect();
        for objects in objects.chunks(1000) {
            self.bucket
                .delete_multiple(objects.to_vec())
                .await
                .map_err(unavailable)?;
        }
        Ok(())
    }
}

/// The R2 object of chunk `index` of the attachment `id`.
fn chunk_object(id: &[u8], index: u32) -> String {
    format!("attachments/{}/{index}", hex(id))
}

impl Store {
    /// The content in R2 under `object`. A missing object reads as empty content, which fails to
    /// decrypt, so that it cannot block the messages after it.
    async fn object(&self, object: &str) -> Result<Bytes> {
        let Some(object) = self
            .bucket
            .get(object)
            .execute()
            .await
            .map_err(unavailable)?
        else {
            console_error!("the R2 object {object} of a message is missing");
            return Ok(Bytes::new());
        };
        let body = object
            .body()
            .ok_or_else(|| Error::new(ErrorKind::Corrupt, "an R2 object without a body"))?;
        Ok(Bytes::from(body.bytes().await.map_err(unavailable)?))
    }
}

#[derive(Deserialize)]
struct BundleRow {
    #[serde(with = "serde_bytes")]
    signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signed_prekey_signature: Vec<u8>,
    timestamp: u64,
}

#[derive(Deserialize)]
struct PrekeyRow {
    #[serde(with = "serde_bytes")]
    prekey: Vec<u8>,
}

#[derive(Deserialize)]
struct InitialMessageRow {
    id: u64,
    #[serde(with = "serde_bytes")]
    sender: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ephemeral_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    one_time_prekey: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    content: Vec<u8>,
}

#[derive(Deserialize)]
struct SequenceRow {
    sequence: u64,
}

#[derive(Deserialize)]
struct MessageRow {
    sequence: u64,
    #[serde(with = "serde_bytes")]
    header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    content: Option<Vec<u8>>,
    object: Option<String>,
}

#[derive(Deserialize)]
struct AttachmentRow {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    uploader: Vec<u8>,
    chunks: u32,
    #[serde(with = "serde_bytes")]
    token_hash: Vec<u8>,
}

impl AttachmentRow {
    fn stored(&self) -> Result<StoredAttachment> {
        Ok(StoredAttachment {
            id: fixed(&self.id)?,
            uploader: fixed(&self.uploader)?,
            chunks: self.chunks,
            token_hash: fixed(&self.token_hash)?,
        })
    }
}

#[derive(Deserialize)]
struct ObjectRow {
    object: Option<String>,
}

/// Bind bytes as a BLOB.
fn blob(bytes: &[u8]) -> JsValue {
    Uint8Array::from(bytes).buffer().into()
}

/// Bind an integer, as a JavaScript number. Beyond 2^53, where a number is no longer exact, the
/// integer is clamped: only absurd timestamps get there, which compare as equal and so as stale.
fn integer(value: u64) -> JsValue {
    JsValue::from_f64(value.min(MAX_SAFE_INTEGER) as f64)
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A JSON array of hex strings, which need no escaping.
fn json_array(strings: &[String]) -> String {
    let quoted: Vec<_> = strings
        .iter()
        .map(|string| format!("\"{string}\""))
        .collect();
    format!("[{}]", quoted.join(","))
}

/// A random name, for an R2 object.
fn random_id() -> String {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).expect("crypto.getRandomValues is available in Workers");
    hex(&bytes)
}

/// The rows of a result.
fn rows<T: for<'de> Deserialize<'de>>(result: &D1Result) -> Result<Vec<T>> {
    result.results().map_err(|e| {
        console_error!("unexpected rows: {e}");
        Error::new(ErrorKind::Corrupt, e.to_string())
    })
}

/// How many rows a statement changed.
fn changes(result: &D1Result) -> Result<usize> {
    let meta = result.meta().map_err(unavailable)?;
    Ok(meta.and_then(|meta| meta.changes).unwrap_or(0))
}

/// A stored key or signature of `N` bytes.
fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| {
        let error = format!("a stored key of {} bytes, not {N}", bytes.len());
        console_error!("{error}");
        Error::new(ErrorKind::Corrupt, error)
    })
}

/// A failed D1 or R2 call, logged, since clients only learn that the storage failed.
fn unavailable(error: worker::Error) -> Error {
    console_error!("storage failed: {error}");
    Error::new(ErrorKind::Unavailable, error.to_string())
}
