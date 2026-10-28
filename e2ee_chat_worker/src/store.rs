//! The handshake, mailbox and attachment stores over the Worker's Durable Objects, with large
//! message contents and attachments' chunks in R2.
//!
//! Each store method is one call of one object, which serves it whole, so it is atomic, as the
//! storage traits require: an identity's object for its keys, its inbox and the queues of
//! messages to it, and an attachment's object for it. What goes to R2 goes from here, around
//! those calls: a large content before its message is appended, and the objects of delivered
//! messages before they are deleted, so that a failure leaves rows, which expire, rather than
//! objects no row names.

use futures_util::future::try_join_all;
use serde::de::DeserializeOwned;
use storage::{
    AttachmentId, Bundle, Bytes, Error, ErrorKind, LocalAttachmentStore, LocalHandshakeStore,
    LocalMailboxStore, PublicKey, Result, StoredAttachment, StoredInitialMessage, StoredMessage,
};
use worker::{Bucket, Conditional, Env, console_error};

use crate::objects::{
    self, AttachmentCall, AttachmentRow, Content, IdentityCall, InitialMessage, StoredRow,
    TakenBundle,
};

/// Contents larger than this go to R2; smaller ones stay in their object's row.
pub const INLINE_CONTENT_MAX: usize = 64 << 10;

/// The stores over `env`'s objects and its R2 bucket.
#[derive(Clone)]
pub struct Store {
    env: Env,
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
            env: env.clone(),
            bucket: env.bucket(crate::BUCKET)?,
            max_read_size,
        })
    }

    /// Make `call` of the object of `identity_key`.
    async fn identity<T: DeserializeOwned>(
        &self,
        identity_key: &[u8],
        call: &IdentityCall,
    ) -> Result<T> {
        let stub = objects::identity(&self.env, identity_key).map_err(unavailable)?;
        objects::call(&stub, call).await.map_err(unavailable)
    }

    /// Make `call` of the object of the attachment `id`.
    async fn attachment_call<T: DeserializeOwned>(
        &self,
        id: &AttachmentId,
        call: &AttachmentCall,
    ) -> Result<T> {
        let stub = objects::attachment(&self.env, id).map_err(unavailable)?;
        objects::call(&stub, call).await.map_err(unavailable)
    }

    /// The content in R2 under `object`; none if it expired, as the bucket's lifecycle rules
    /// deleted it before its message was read, which the recipient goes past.
    async fn object(&self, object: &str) -> Result<Option<Bytes>> {
        let Some(object) = self
            .bucket
            .get(object)
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

impl LocalHandshakeStore for Store {
    async fn publish(&self, bundle: Bundle, one_time_prekeys: Vec<PublicKey>) -> Result<bool> {
        let call = IdentityCall::Publish {
            signed_prekey: bundle.signed_prekey.to_vec(),
            signature: bundle.signed_prekey_signature.to_vec(),
            timestamp: bundle.timestamp,
            one_time_prekeys: one_time_prekeys.iter().map(|key| key.to_vec()).collect(),
        };
        self.identity(&bundle.identity_key, &call).await
    }

    async fn take_bundle(
        &self,
        identity_key: &PublicKey,
    ) -> Result<Option<(Bundle, Option<PublicKey>)>> {
        let taken: Option<TakenBundle> = self
            .identity(identity_key, &IdentityCall::TakeBundle)
            .await?;
        let Some(taken) = taken else {
            return Ok(None);
        };
        let bundle = Bundle {
            identity_key: *identity_key,
            signed_prekey: fixed(&taken.signed_prekey)?,
            signed_prekey_signature: fixed(&taken.signature)?,
            timestamp: taken.timestamp,
        };
        let one_time_prekey = taken.one_time_prekey.as_deref().map(fixed).transpose()?;
        Ok(Some((bundle, one_time_prekey)))
    }

    async fn add_initial_message(
        &self,
        initial_message: StoredInitialMessage,
        limit: usize,
    ) -> Result<bool> {
        let call = IdentityCall::AddInitialMessage {
            message: InitialMessage {
                sender: initial_message.sender.to_vec(),
                ephemeral_key: initial_message.ephemeral_key.to_vec(),
                signed_prekey: initial_message.signed_prekey.to_vec(),
                one_time_prekey: initial_message.one_time_prekey.map(|key| key.to_vec()),
                header: initial_message.header.to_vec(),
                content: initial_message.content.to_vec(),
            },
            limit: limit as u64,
        };
        self.identity(&initial_message.recipient, &call).await
    }

    async fn take_initial_messages(
        &self,
        recipient: &PublicKey,
        timestamp: u64,
    ) -> Result<Option<Vec<StoredInitialMessage>>> {
        let taken: Option<Vec<InitialMessage>> = self
            .identity(recipient, &IdentityCall::TakeInitialMessages { timestamp })
            .await?;
        let Some(taken) = taken else {
            return Ok(None);
        };
        taken
            .into_iter()
            .map(|message| {
                Ok(StoredInitialMessage {
                    sender: fixed(&message.sender)?,
                    recipient: *recipient,
                    ephemeral_key: fixed(&message.ephemeral_key)?,
                    signed_prekey: fixed(&message.signed_prekey)?,
                    one_time_prekey: message.one_time_prekey.as_deref().map(fixed).transpose()?,
                    header: Bytes::from(message.header),
                    content: Bytes::from(message.content),
                })
            })
            .collect::<Result<_>>()
            .map(Some)
    }
}

impl LocalMailboxStore for Store {
    /// A content too large for its row goes to R2 first, and goes again if the message is not
    /// appended.
    async fn append(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        delivery_hash: Option<[u8; 32]>,
    ) -> Result<u64> {
        let size = content.len() as u64;
        let content = if content.len() > INLINE_CONTENT_MAX {
            let object = format!(
                "messages/{}/{}/{}",
                hex(sender),
                hex(recipient),
                random_id()
            );
            self.bucket
                .put(&object, content.to_vec())
                .execute()
                .await
                .map_err(unavailable)?;
            Content::Object(object)
        } else {
            Content::Inline(content.to_vec())
        };
        let call = IdentityCall::Append {
            sender: sender.to_vec(),
            header: header.to_vec(),
            content: content.clone(),
            size,
            initial_message: initial_message.map(|bytes| bytes.to_vec()),
            delivery_hash: delivery_hash.map(Vec::from),
        };
        let appended = self.identity(recipient, &call).await;
        if appended.is_err()
            && let Content::Object(object) = content
            && let Err(e) = self.bucket.delete(object).await
        {
            console_error!("cannot delete the object of a message not appended: {e}");
        }
        appended
    }

    async fn read(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
    ) -> Result<Vec<StoredMessage>> {
        let call = IdentityCall::Read {
            sender: sender.to_vec(),
            after,
            limit,
            max_size: self.max_read_size as u64,
        };
        let rows: Vec<StoredRow> = self.identity(recipient, &call).await?;
        try_join_all(rows.into_iter().map(|row| async move {
            let content = match row.content {
                Content::Inline(content) => Some(Bytes::from(content)),
                Content::Object(object) => self.object(&object).await?,
            };
            Ok(StoredMessage {
                sender: *sender,
                recipient: *recipient,
                sequence: row.sequence,
                header: Bytes::from(row.header),
                content,
                initial_message: row.initial_message.map(Bytes::from),
            })
        }))
        .await
    }

    /// Their R2 objects go first. If R2 fails, it is logged, and only the messages without
    /// objects go: the others expire, rather than leave objects no row names, and the fetch this
    /// is part of still reads.
    async fn delete_delivered(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        hashes: &[[u8; 32]],
    ) -> Result<()> {
        if hashes.is_empty() {
            return Ok(());
        }
        let hashes: Vec<Vec<u8>> = hashes.iter().map(|hash| hash.to_vec()).collect();
        let call = IdentityCall::DeliveredObjects {
            sender: sender.to_vec(),
            hashes: hashes.clone(),
        };
        let objects: Vec<String> = self.identity(recipient, &call).await?;
        let inline_only = match delete_objects(&self.bucket, objects).await {
            Ok(()) => false,
            Err(e) => {
                console_error!("cannot delete the objects of delivered messages: {e}");
                true
            }
        };
        let call = IdentityCall::DeleteDelivered {
            sender: sender.to_vec(),
            hashes,
            inline_only,
        };
        self.identity(recipient, &call).await
    }
}

impl LocalAttachmentStore for Store {
    async fn add_attachment(&self, attachment: StoredAttachment) -> Result<bool> {
        let call = AttachmentCall::Add {
            id: attachment.id.to_vec(),
            chunks: attachment.chunks,
            token_hash: attachment.token_hash.to_vec(),
            delete_hash: attachment.delete_hash.to_vec(),
        };
        self.attachment_call(&attachment.id, &call).await
    }

    async fn attachment(&self, id: &AttachmentId) -> Result<Option<StoredAttachment>> {
        let row: Option<AttachmentRow> = self.attachment_call(id, &AttachmentCall::Get).await?;
        row.map(|row| {
            Ok(StoredAttachment {
                id: fixed(&row.id)?,
                chunks: row.chunks,
                token_hash: fixed(&row.token_hash)?,
                delete_hash: fixed(&row.delete_hash)?,
                uploaded: row.uploaded,
            })
        })
        .transpose()
    }

    /// A chunk in R2 already stays, as a chunk is uploaded once: R2 puts it only if there is
    /// none, in one step, so that of two puts at once, the second changes nothing. The object
    /// notes it once it is in R2, which also tells whether the attachment was deleted meanwhile,
    /// e.g. cancelled while the chunk was on its way: then the chunk goes too, as nothing would
    /// name it for deleting.
    async fn put_chunk(&self, id: &AttachmentId, index: u32, data: Bytes) -> Result<()> {
        let object = chunk_object(id, index);
        let absent = Conditional {
            etag_does_not_match: Some("*".to_string()),
            ..Conditional::default()
        };
        // None if one was there already, which stays.
        self.bucket
            .put(&object, data.to_vec())
            .only_if(absent)
            .execute()
            .await
            .map_err(unavailable)?;
        let noted: bool = self
            .attachment_call(id, &AttachmentCall::Note { index })
            .await?;
        if !noted {
            self.bucket.delete(&object).await.map_err(unavailable)?;
            return Err(Error::new(ErrorKind::Other, "the attachment was deleted"));
        }
        Ok(())
    }

    async fn chunk(&self, id: &AttachmentId, index: u32) -> Result<Option<Bytes>> {
        self.object(&chunk_object(id, index)).await
    }

    async fn delete_attachment(&self, id: &AttachmentId) -> Result<()> {
        self.attachment_call(id, &AttachmentCall::Delete).await
    }
}

/// The R2 object of chunk `index` of the attachment `id`.
pub(crate) fn chunk_object(id: &[u8], index: u32) -> String {
    format!("attachments/{}/{index}", hex(id))
}

/// Delete the R2 `objects`, 1000 at once, as R2 takes them.
pub(crate) async fn delete_objects(bucket: &Bucket, objects: Vec<String>) -> worker::Result<()> {
    for objects in objects.chunks(1000) {
        bucket.delete_multiple(objects.to_vec()).await?;
    }
    Ok(())
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A random name, for an R2 object.
fn random_id() -> String {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).expect("crypto.getRandomValues is available in Workers");
    hex(&bytes)
}

/// A stored key or signature of `N` bytes.
fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| {
        let error = format!("a stored key of {} bytes, not {N}", bytes.len());
        console_error!("{error}");
        Error::new(ErrorKind::Corrupt, error)
    })
}

/// A failed object or R2 call, logged, since clients only learn that the storage failed.
fn unavailable(error: worker::Error) -> Error {
    console_error!("storage failed: {error}");
    Error::new(ErrorKind::Unavailable, error.to_string())
}
