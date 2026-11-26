//! The v2 handshake, unified sealed-sender-lite mailbox, and attachment stores over the Worker's
//! Durable Objects, with R2 used exclusively for attachment chunks (`v2/attachments/{hex}/{idx}`).
//!
//! `IdentityV2` has zero R2 dependency: all `PushV2` envelopes (capped at 64 KiB) live inline in
//! the recipient's Durable Object SQLite database. Each store method is one typed call of one
//! object, served atomically.

use storage::{
    AttachmentId, Bytes, ClaimOutcome, ClaimedPqBundle, Error, ErrorKind, LocalAttachmentStore,
    LocalIdempotentMailboxStore, LocalPqHandshakeStore, MAX_SAFE_INTEGER, MailboxPage,
    PqStorageSnapshot, PublicKey, PublishV2Record, PublishV2Status, RefillPrekeysRecord,
    RefillStatus, RegisterWriteTokenRecord, Result, RevokeWriteTokenRecord, StoredAttachment,
    StoredCapabilityManifest, StoredInitialMessageV2, WriteTokenHash,
};
use worker::{Bucket, Conditional, Env, console_error};

use crate::objects::{
    self, AckMessagesOutcome, AddInitialOutcome, AppendOutcome, AttachmentRpc, IdentityRpc,
    ReadMailboxOutcome, RefillOutcome, RegisterWriteTokenOutcome, RevokeWriteTokenOutcome, rpc,
};

/// The stores over `env`'s objects and its R2 bucket (attachments only).
#[derive(Clone)]
pub struct Store {
    env: Env,
    bucket: Bucket,
    /// Most bytes one mailbox read returns, unless its first message alone is larger.
    max_read_size: usize,
}

impl Store {
    /// The stores over `env`'s bindings, whose mailbox reads return at most `max_read_size` bytes,
    /// unless the first message alone is larger.
    pub fn new(env: &Env, max_read_size: usize) -> worker::Result<Self> {
        Ok(Self {
            env: env.clone(),
            bucket: env.bucket(crate::BUCKET)?,
            max_read_size,
        })
    }

    /// Make typed `call` of the `IdentityV2` object of `identity_key`.
    async fn identity<R: IdentityRpc>(&self, identity_key: &[u8], call: R) -> Result<R::Reply> {
        let stub = objects::identity(&self.env, identity_key).map_err(unavailable)?;
        objects::call(&stub, call).await.map_err(unavailable)
    }

    /// Make typed `call` of the `AttachmentV2` object of `id`.
    async fn attachment_call<R: AttachmentRpc>(
        &self,
        id: &AttachmentId,
        call: R,
    ) -> Result<R::Reply> {
        let stub = objects::attachment(&self.env, id).map_err(unavailable)?;
        objects::call(&stub, call).await.map_err(unavailable)
    }

    /// Read an attachment chunk from R2 under `object`; `None` if not uploaded or expired.
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

fn check_safe(value: u64) -> Result<()> {
    if value > MAX_SAFE_INTEGER {
        return Err(ErrorKind::InvalidArgument.into());
    }
    Ok(())
}

fn check_positive_safe(value: u64) -> Result<()> {
    if value == 0 || value > MAX_SAFE_INTEGER {
        return Err(ErrorKind::InvalidArgument.into());
    }
    Ok(())
}

impl LocalPqHandshakeStore for Store {
    async fn publish_v2(&self, record: PublishV2Record) -> Result<PublishV2Status> {
        check_safe(record.timestamp)?;
        check_safe(record.manifest.manifest_seq)?;
        check_safe(record.manifest.generation)?;
        check_safe(record.manifest.issued_at)?;
        check_safe(record.manifest.expires_at)?;
        let identity_key = record.manifest.identity_key;
        self.identity(&identity_key, rpc::PublishV2 { record })
            .await
    }

    async fn refill_prekeys(&self, record: RefillPrekeysRecord) -> Result<RefillStatus> {
        check_safe(record.generation)?;
        check_safe(record.timestamp)?;
        let identity_key = record.identity_key;
        let outcome = self
            .identity(&identity_key, rpc::RefillPrekeys { record })
            .await?;
        match outcome {
            RefillOutcome::Stored {
                classical_count,
                pq_counts,
            } => Ok(RefillStatus::Stored {
                classical_count: classical_count as usize,
                pq_counts: pq_counts
                    .into_iter()
                    .map(|(suite, count)| (suite, count as usize))
                    .collect(),
            }),
            RefillOutcome::NotFound => Ok(RefillStatus::NotFound),
            RefillOutcome::StaleGeneration => Ok(RefillStatus::StaleGeneration),
            RefillOutcome::StaleTimestamp => Ok(RefillStatus::StaleTimestamp),
            RefillOutcome::DuplicatePrekey => Ok(RefillStatus::DuplicatePrekey),
            RefillOutcome::LimitExceeded => Ok(RefillStatus::LimitExceeded),
            RefillOutcome::SuiteNotOffered => Err(Error::new(
                ErrorKind::InvalidArgument,
                "PQ suite not offered by current manifest",
            )),
        }
    }

    async fn get_manifest(
        &self,
        identity_key: &PublicKey,
    ) -> Result<Option<StoredCapabilityManifest>> {
        self.identity(identity_key, rpc::GetManifest).await
    }

    async fn claim_bundle(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
    ) -> Result<Option<ClaimedPqBundle>> {
        match self
            .claim_bundle_checked(identity_key, preferred_suites, false)
            .await?
        {
            ClaimOutcome::Claimed(bundle) => Ok(Some(*bundle)),
            ClaimOutcome::NotFound | ClaimOutcome::PqDisabledForPqManifest => Ok(None),
        }
    }

    async fn claim_bundle_checked(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
        reject_pq_on_manifest: bool,
    ) -> Result<ClaimOutcome> {
        self.identity(
            identity_key,
            rpc::ClaimBundleChecked {
                preferred_suites: preferred_suites.to_vec(),
                reject_pq_on_manifest,
            },
        )
        .await
    }

    async fn add_initial_message_v2(
        &self,
        initial_message: StoredInitialMessageV2,
        limit: usize,
    ) -> Result<Option<u64>> {
        let recipient = initial_message.recipient;
        match self
            .identity(
                &recipient,
                rpc::AddInitialMessageV2 {
                    message: initial_message,
                    limit: limit as u64,
                },
            )
            .await?
        {
            AddInitialOutcome::Added { id, .. } => Ok(Some(id)),
            AddInitialOutcome::LimitExceeded => Ok(None),
            AddInitialOutcome::NotFound => Err(ErrorKind::NotFound.into()),
            AddInitialOutcome::PayloadMismatch => Err(ErrorKind::InvalidArgument.into()),
            AddInitialOutcome::SequenceOverflow => Err(ErrorKind::LimitExceeded.into()),
        }
    }

    async fn list_initial_messages(
        &self,
        recipient: &PublicKey,
        after_id: u64,
        limit: usize,
    ) -> Result<Vec<StoredInitialMessageV2>> {
        check_safe(after_id)?;
        self.identity(
            recipient,
            rpc::ListInitialMessages {
                recipient: *recipient,
                after_id,
                limit: limit as u64,
            },
        )
        .await
    }

    async fn ack_initial_messages(&self, recipient: &PublicKey, ids: &[u64]) -> Result<usize> {
        for &id in ids {
            check_safe(id)?;
        }
        let deleted = self
            .identity(recipient, rpc::AckInitialMessages { ids: ids.to_vec() })
            .await?;
        Ok(deleted as usize)
    }

    async fn pq_snapshot(&self, identity_key: &PublicKey) -> Result<PqStorageSnapshot> {
        self.identity(identity_key, rpc::PqSnapshot).await
    }
}

impl LocalIdempotentMailboxStore for Store {
    async fn append_idempotent(
        &self,
        recipient: &PublicKey,
        token_hash: &WriteTokenHash,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        client_message_id: Option<[u8; 16]>,
    ) -> Result<u64> {
        match self
            .identity(
                recipient,
                rpc::AppendIdempotent {
                    token_hash: *token_hash,
                    header,
                    content,
                    initial_message,
                    client_message_id,
                },
            )
            .await?
        {
            AppendOutcome::Appended(seq) | AppendOutcome::Deduplicated(seq) => Ok(seq),
            AppendOutcome::WriteTokenRejected => Err(ErrorKind::WriteTokenRejected.into()),
            AppendOutcome::LimitExceeded => Err(ErrorKind::LimitExceeded.into()),
        }
    }

    async fn read_mailbox(
        &self,
        recipient: &PublicKey,
        after_sequence: u64,
        limit: u32,
        max_size: usize,
        ack_up_to_sequence: u64,
    ) -> Result<MailboxPage> {
        check_safe(after_sequence)?;
        check_safe(ack_up_to_sequence)?;
        let capped_size = max_size.min(self.max_read_size) as u64;
        match self
            .identity(
                recipient,
                rpc::ReadMailbox {
                    after_sequence,
                    limit,
                    max_size: capped_size,
                    ack_up_to_sequence,
                },
            )
            .await?
        {
            ReadMailboxOutcome::Page(page) => Ok(page),
            ReadMailboxOutcome::InvalidAckSequence => Err(ErrorKind::InvalidArgument.into()),
        }
    }

    async fn ack_messages(&self, recipient: &PublicKey, up_to_sequence: u64) -> Result<u64> {
        check_positive_safe(up_to_sequence)?;
        match self
            .identity(recipient, rpc::AckMessages { up_to_sequence })
            .await?
        {
            AckMessagesOutcome::Acked(deleted) => Ok(deleted),
            AckMessagesOutcome::InvalidSequence => Err(ErrorKind::InvalidArgument.into()),
        }
    }

    async fn register_write_token(&self, record: RegisterWriteTokenRecord) -> Result<()> {
        check_positive_safe(record.grant_version)?;
        let recipient = record.recipient;
        match self
            .identity(&recipient, rpc::RegisterWriteToken { record })
            .await?
        {
            RegisterWriteTokenOutcome::Registered => Ok(()),
            RegisterWriteTokenOutcome::NotFound => Err(ErrorKind::NotFound.into()),
            RegisterWriteTokenOutcome::StaleVersion => Err(ErrorKind::StaleVersion.into()),
            RegisterWriteTokenOutcome::InvalidArgument => Err(ErrorKind::InvalidArgument.into()),
            RegisterWriteTokenOutcome::LimitExceeded => Err(ErrorKind::LimitExceeded.into()),
        }
    }

    async fn revoke_write_token(&self, record: RevokeWriteTokenRecord) -> Result<u32> {
        check_positive_safe(record.min_grant_version)?;
        let recipient = record.recipient;
        match self
            .identity(&recipient, rpc::RevokeWriteToken { record })
            .await?
        {
            RevokeWriteTokenOutcome::Revoked(revoked) => Ok(revoked),
            RevokeWriteTokenOutcome::NotFound => Err(ErrorKind::NotFound.into()),
            RevokeWriteTokenOutcome::InvalidArgument => Err(ErrorKind::InvalidArgument.into()),
        }
    }
}

impl LocalAttachmentStore for Store {
    async fn add_attachment(&self, attachment: StoredAttachment) -> Result<bool> {
        let id = attachment.id;
        self.attachment_call(&id, rpc::AddAttachment { attachment })
            .await
    }

    async fn attachment(&self, id: &AttachmentId) -> Result<Option<StoredAttachment>> {
        self.attachment_call(id, rpc::GetAttachment).await
    }

    async fn put_chunk(&self, id: &AttachmentId, index: u32, data: Bytes) -> Result<()> {
        let object = chunk_object(id, index);
        let absent = Conditional {
            etag_does_not_match: Some("*".to_string()),
            ..Conditional::default()
        };
        // `Vec::from(data)` reuses the allocation zero-copy when `data` is uniquely owned, and
        // `PutOptionsBuilder::execute` copies into a JS `Uint8Array` and drops the Rust `Vec`
        // BEFORE awaiting the R2 put promise.
        self.bucket
            .put(&object, Vec::from(data))
            .only_if(absent)
            .execute()
            .await
            .map_err(unavailable)?;
        let noted = self.attachment_call(id, rpc::NoteChunk { index }).await?;
        if !noted {
            self.bucket.delete(&object).await.map_err(unavailable)?;
            return Err(Error::new(
                ErrorKind::NotFound,
                "the attachment was deleted",
            ));
        }
        Ok(())
    }

    async fn chunk(&self, id: &AttachmentId, index: u32) -> Result<Option<Bytes>> {
        self.object(&chunk_object(id, index)).await
    }

    async fn delete_attachment(&self, id: &AttachmentId) -> Result<()> {
        self.attachment_call(id, rpc::DeleteAttachment).await
    }
}

/// The opaque R2 object key of chunk `index` of attachment `id` (zero identity keys in R2).
pub(crate) fn chunk_object(id: &[u8], index: u32) -> String {
    format!("v2/attachments/{}/{index}", hex(id))
}

/// Delete the R2 `objects`, 1000 at once, as R2 takes them.
pub(crate) async fn delete_objects(bucket: &Bucket, objects: Vec<String>) -> worker::Result<()> {
    for objects in objects.chunks(1000) {
        bucket.delete_multiple(objects.to_vec()).await?;
    }
    Ok(())
}

/// Pre-sized lowercase hex encoder with zero intermediate allocations.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn decode_hex_fixed<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    if pairs.len() != N || !remainder.is_empty() {
        return None;
    }
    let mut out = [0; N];
    for (byte, &[hi, lo]) in out.iter_mut().zip(pairs) {
        let hi = char::from(hi).to_digit(16)?;
        let lo = char::from(lo).to_digit(16)?;
        *byte = (hi << 4 | lo) as u8;
    }
    Some(out)
}

/// A failed object or R2 call, logged internally while returning a generic message to clients.
fn unavailable(error: worker::Error) -> Error {
    console_error!("storage failed: {error}");
    Error::new(ErrorKind::Unavailable, "storage temporarily unavailable")
}

#[cfg(test)]
mod tests {
    use super::{chunk_object, decode_hex_fixed, hex};

    #[test]
    fn chunk_object_uses_opaque_v2_attachments_prefix() {
        let id = [0xab; 16];
        assert_eq!(
            chunk_object(&id, 7),
            "v2/attachments/abababababababababababababababab/7"
        );
    }

    #[test]
    fn hex_encodes_all_byte_values_and_round_trips() {
        assert_eq!(hex(&[]), "");
        let all_bytes: [u8; 256] = std::array::from_fn(|i| i as u8);
        let encoded = hex(&all_bytes);
        assert_eq!(encoded.len(), 512);
        assert!(
            encoded
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        );
        assert_eq!(decode_hex_fixed::<256>(&encoded), Some(all_bytes));

        let key = std::array::from_fn(|i| i as u8);
        assert_eq!(decode_hex_fixed::<32>(&hex(&key)), Some(key));
        assert_eq!(decode_hex_fixed::<64>(&"aB".repeat(64)), Some([0xab; 64]));
    }

    #[test]
    fn fixed_hex_rejects_wrong_lengths_and_invalid_digits() {
        for len in [0, 63, 65, 128] {
            assert!(decode_hex_fixed::<32>(&"0".repeat(len)).is_none());
        }
        for pair in ["+1", "zz", "é"] {
            assert!(decode_hex_fixed::<32>(&pair.repeat(32)).is_none());
        }
    }
}
