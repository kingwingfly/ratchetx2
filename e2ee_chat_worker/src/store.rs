//! The handshake, mailbox and attachment stores over the Worker's Durable Objects, with large
//! message contents and attachments' chunks in R2.
//!
//! Each store method is one call of one object, which serves it whole, so it is atomic, as the
//! storage traits require. Large contents go to R2 before the DO append call; on an ambiguous DO
//! RPC error the R2 object is intentionally NOT deleted (relying on R2 lifecycle/GC) so a committed
//! message row can never be left pointing at a deleted blob. Only a definitive pre-commit
//! rejection (`AppendOutcome::LimitExceeded`) deletes the staged R2 object.

use futures_util::future::try_join_all;
use serde::de::DeserializeOwned;
#[cfg(feature = "pq")]
use storage::{
    ClaimedPqBundle, LocalIdempotentMailboxStore, LocalPqHandshakeStore, PqLastResortCommitment,
    PqStorageSnapshot, PublishV2Record, PublishV2Status, RefillPrekeysRecord, RefillStatus,
    StoredCapabilityManifest, StoredInitialMessageV2, StoredPqPrekey,
};
use storage::{
    AttachmentId, Bundle, Bytes, Error, ErrorKind, LocalAttachmentStore, LocalHandshakeStore,
    LocalMailboxStore, MAX_SAFE_INTEGER, PublicKey, Result, StoredAttachment, StoredInitialMessage,
    StoredMessage,
};
use worker::{Bucket, Conditional, Env, console_error};

#[cfg(feature = "pq")]
use crate::objects::{
    ClaimedBundleWire, InitialMessageV2Wire, ManifestWire, PqCommitmentWire, PqPrekeyWire,
    PqSnapshotWire, PublishV2Outcome, RefillOutcome,
};
use crate::objects::{
    self, AppendOutcome, AttachmentCall, AttachmentRow, Content, IdentityCall, InitialMessage,
    StoredRow, TakenBundle,
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

    async fn stage_content(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        content: Bytes,
    ) -> Result<(Content, u64)> {
        let size = content.len() as u64;
        if content.len() > INLINE_CONTENT_MAX {
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
            Ok((Content::Object(object), size))
        } else {
            Ok((Content::Inline(content.to_vec()), size))
        }
    }

    async fn finish_append(
        &self,
        outcome: Result<AppendOutcome>,
        staged: &Content,
    ) -> Result<u64> {
        match outcome {
            Ok(AppendOutcome::Appended(seq)) => Ok(seq),
            #[cfg(feature = "pq")]
            Ok(AppendOutcome::Deduplicated(seq)) => {
                // Retry hit existing dedup row; newly staged R2 object is not referenced.
                if let Content::Object(object) = staged
                    && let Err(e) = self.bucket.delete(object).await
                {
                    console_error!("cannot delete unused duplicate R2 object: {e}");
                }
                Ok(seq)
            }
            Ok(AppendOutcome::LimitExceeded) => {
                // Definitive pre-commit rejection: safe to clean up the staged R2 object.
                if let Content::Object(object) = staged
                    && let Err(e) = self.bucket.delete(object).await
                {
                    console_error!("cannot delete R2 object after definitive rejection: {e}");
                }
                Err(ErrorKind::LimitExceeded.into())
            }
            // Ambiguous DO RPC failure: DO NOT delete the R2 object, because the DO may have
            // committed the row before the response failed. R2 lifecycle rules GC true orphans.
            Err(e) => Err(e),
        }
    }
}

fn check_safe(value: u64) -> Result<()> {
    if value > MAX_SAFE_INTEGER {
        return Err(ErrorKind::InvalidArgument.into());
    }
    Ok(())
}

impl LocalHandshakeStore for Store {
    async fn publish(&self, bundle: Bundle, one_time_prekeys: Vec<PublicKey>) -> Result<bool> {
        check_safe(bundle.timestamp)?;
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
        check_safe(timestamp)?;
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

#[cfg(feature = "pq")]
fn manifest_to_wire(manifest: &StoredCapabilityManifest) -> ManifestWire {
    ManifestWire {
        audience: manifest.audience.clone(),
        identity_key: manifest.identity_key.to_vec(),
        manifest_seq: manifest.manifest_seq,
        generation: manifest.generation,
        issued_at: manifest.issued_at,
        expires_at: manifest.expires_at,
        pq_enabled: manifest.pq_enabled,
        strict_pq: manifest.strict_pq,
        pq_ratchet_supported: manifest.pq_ratchet_supported,
        offered_suites: manifest.offered_suites.clone(),
        signed_prekey: manifest.signed_prekey.to_vec(),
        pq_last_resort: manifest
            .pq_last_resort
            .iter()
            .map(|c| PqCommitmentWire {
                suite: c.suite,
                prekey_id: c.prekey_id.to_vec(),
            })
            .collect(),
        signature: manifest.signature.to_vec(),
    }
}

#[cfg(feature = "pq")]
fn manifest_from_wire(wire: ManifestWire) -> Result<StoredCapabilityManifest> {
    let pq_last_resort = wire
        .pq_last_resort
        .into_iter()
        .map(|c| {
            Ok(PqLastResortCommitment {
                suite: c.suite,
                prekey_id: fixed(&c.prekey_id)?,
            })
        })
        .collect::<Result<_>>()?;
    Ok(StoredCapabilityManifest {
        audience: wire.audience,
        identity_key: fixed(&wire.identity_key)?,
        manifest_seq: wire.manifest_seq,
        generation: wire.generation,
        issued_at: wire.issued_at,
        expires_at: wire.expires_at,
        pq_enabled: wire.pq_enabled,
        strict_pq: wire.strict_pq,
        pq_ratchet_supported: wire.pq_ratchet_supported,
        offered_suites: wire.offered_suites,
        signed_prekey: fixed(&wire.signed_prekey)?,
        pq_last_resort,
        signature: fixed(&wire.signature)?,
    })
}

#[cfg(feature = "pq")]
fn pq_prekey_to_wire(key: &StoredPqPrekey) -> PqPrekeyWire {
    PqPrekeyWire {
        suite: key.suite,
        id: key.id.to_vec(),
        encapsulation_key: key.encapsulation_key.to_vec(),
        signature: key.signature.to_vec(),
    }
}

#[cfg(feature = "pq")]
fn pq_prekey_from_wire(wire: PqPrekeyWire) -> Result<StoredPqPrekey> {
    Ok(StoredPqPrekey {
        suite: wire.suite,
        id: fixed(&wire.id)?,
        encapsulation_key: Bytes::from(wire.encapsulation_key),
        signature: fixed(&wire.signature)?,
    })
}

#[cfg(feature = "pq")]
impl LocalPqHandshakeStore for Store {
    async fn publish_v2(&self, record: PublishV2Record) -> Result<PublishV2Status> {
        check_safe(record.timestamp)?;
        check_safe(record.manifest.manifest_seq)?;
        check_safe(record.manifest.generation)?;
        check_safe(record.manifest.issued_at)?;
        check_safe(record.manifest.expires_at)?;
        let call = IdentityCall::PublishV2 {
            manifest: manifest_to_wire(&record.manifest),
            signed_prekey_signature: record.signed_prekey_signature.map(|s| s.to_vec()),
            one_time_prekeys: record.one_time_prekeys.iter().map(|k| k.to_vec()).collect(),
            pq_last_resort: record.pq_last_resort.iter().map(pq_prekey_to_wire).collect(),
            pq_one_time_prekeys: record
                .pq_one_time_prekeys
                .iter()
                .map(pq_prekey_to_wire)
                .collect(),
            timestamp: record.timestamp,
        };
        let outcome: PublishV2Outcome = self.identity(&record.manifest.identity_key, &call).await?;
        Ok(match outcome {
            PublishV2Outcome::Stored => PublishV2Status::Stored,
            PublishV2Outcome::StaleSequence => PublishV2Status::StaleSequence,
            PublishV2Outcome::DuplicatePrekey => PublishV2Status::DuplicatePrekey,
        })
    }

    async fn refill_prekeys(&self, record: RefillPrekeysRecord) -> Result<RefillStatus> {
        check_safe(record.generation)?;
        let call = IdentityCall::RefillPrekeys {
            generation: record.generation,
            one_time_prekeys: record.one_time_prekeys.iter().map(|k| k.to_vec()).collect(),
            pq_one_time_prekeys: record
                .pq_one_time_prekeys
                .iter()
                .map(pq_prekey_to_wire)
                .collect(),
            max_one_time_prekeys: record.max_one_time_prekeys as u64,
            max_pq_one_time_prekeys: record.max_pq_one_time_prekeys as u64,
        };
        let outcome: RefillOutcome = self.identity(&record.identity_key, &call).await?;
        Ok(match outcome {
            RefillOutcome::Stored {
                classical_count,
                pq_counts,
            } => RefillStatus::Stored {
                classical_count: classical_count as usize,
                pq_counts: pq_counts
                    .into_iter()
                    .map(|(suite, count)| (suite, count as usize))
                    .collect(),
            },
            RefillOutcome::NotFound => RefillStatus::NotFound,
            RefillOutcome::StaleGeneration => RefillStatus::StaleGeneration,
            RefillOutcome::DuplicatePrekey => RefillStatus::DuplicatePrekey,
            RefillOutcome::LimitExceeded => RefillStatus::LimitExceeded,
        })
    }

    async fn get_manifest(
        &self,
        identity_key: &PublicKey,
    ) -> Result<Option<StoredCapabilityManifest>> {
        let wire: Option<ManifestWire> = self
            .identity(identity_key, &IdentityCall::GetManifest)
            .await?;
        wire.map(manifest_from_wire).transpose()
    }

    async fn claim_bundle(
        &self,
        identity_key: &PublicKey,
        preferred_suites: &[u8],
    ) -> Result<Option<ClaimedPqBundle>> {
        let wire: Option<ClaimedBundleWire> = self
            .identity(
                identity_key,
                &IdentityCall::ClaimBundle {
                    preferred_suites: preferred_suites.to_vec(),
                },
            )
            .await?;
        let Some(wire) = wire else {
            return Ok(None);
        };
        Ok(Some(ClaimedPqBundle {
            identity_key: *identity_key,
            manifest: wire.manifest.map(manifest_from_wire).transpose()?,
            signed_prekey: fixed(&wire.signed_prekey)?,
            signed_prekey_signature: wire
                .signed_prekey_signature
                .as_deref()
                .map(fixed)
                .transpose()?,
            one_time_prekey: wire.one_time_prekey.as_deref().map(fixed).transpose()?,
            pq_last_resort: wire.pq_last_resort.map(pq_prekey_from_wire).transpose()?,
            pq_one_time_prekey: wire
                .pq_one_time_prekey
                .map(pq_prekey_from_wire)
                .transpose()?,
        }))
    }

    async fn add_initial_message_v2(
        &self,
        initial_message: StoredInitialMessageV2,
        limit: usize,
    ) -> Result<Option<u64>> {
        let call = IdentityCall::AddInitialMessageV2 {
            message: InitialMessageV2Wire {
                id: 0,
                version: initial_message.version,
                sender: initial_message.sender.to_vec(),
                ephemeral_key: initial_message.ephemeral_key.to_vec(),
                signed_prekey: initial_message.signed_prekey.to_vec(),
                one_time_prekey: initial_message.one_time_prekey.map(|k| k.to_vec()),
                header: initial_message.header.to_vec(),
                content: initial_message.content.to_vec(),
                pq_suite: initial_message.pq_suite,
                pq_last_resort: initial_message.pq_last_resort,
                pq_prekey_id: initial_message.pq_prekey_id.map(|id| id.to_vec()),
                pq_ciphertext: initial_message.pq_ciphertext.map(|ct| ct.to_vec()),
                manifest_digest: initial_message.manifest_digest.map(|d| d.to_vec()),
            },
            limit: limit as u64,
        };
        self.identity(&initial_message.recipient, &call).await
    }

    async fn list_initial_messages(
        &self,
        recipient: &PublicKey,
        limit: usize,
    ) -> Result<Vec<StoredInitialMessageV2>> {
        let wires: Vec<InitialMessageV2Wire> = self
            .identity(
                recipient,
                &IdentityCall::ListInitialMessages {
                    limit: limit as u64,
                },
            )
            .await?;
        wires
            .into_iter()
            .map(|w| {
                Ok(StoredInitialMessageV2 {
                    id: w.id,
                    version: w.version,
                    sender: fixed(&w.sender)?,
                    recipient: *recipient,
                    ephemeral_key: fixed(&w.ephemeral_key)?,
                    signed_prekey: fixed(&w.signed_prekey)?,
                    one_time_prekey: w.one_time_prekey.as_deref().map(fixed).transpose()?,
                    header: Bytes::from(w.header),
                    content: Bytes::from(w.content),
                    pq_suite: w.pq_suite,
                    pq_last_resort: w.pq_last_resort,
                    pq_prekey_id: w.pq_prekey_id.as_deref().map(fixed).transpose()?,
                    pq_ciphertext: w.pq_ciphertext.map(Bytes::from),
                    manifest_digest: w.manifest_digest.as_deref().map(fixed).transpose()?,
                })
            })
            .collect()
    }

    async fn ack_initial_messages(&self, recipient: &PublicKey, ids: &[u64]) -> Result<usize> {
        for &id in ids {
            check_safe(id)?;
        }
        let deleted: u64 = self
            .identity(
                recipient,
                &IdentityCall::AckInitialMessages { ids: ids.to_vec() },
            )
            .await?;
        Ok(deleted as usize)
    }

    async fn pq_snapshot(&self, identity_key: &PublicKey) -> Result<PqStorageSnapshot> {
        let wire: PqSnapshotWire = self
            .identity(identity_key, &IdentityCall::PqSnapshot)
            .await?;
        Ok(PqStorageSnapshot {
            manifest: wire.manifest.map(manifest_from_wire).transpose()?,
            classical_one_time_count: wire.classical_one_time_count as usize,
            pq_last_resort_suites: wire.pq_last_resort_suites,
            pq_one_time_counts: wire
                .pq_one_time_counts
                .into_iter()
                .map(|(s, c)| (s, c as usize))
                .collect(),
            pending_initial_messages: wire.pending_initial_messages as usize,
        })
    }
}

impl LocalMailboxStore for Store {
    /// Stages large content in R2 before appending to the DO. Only deletes the R2 object on a
    /// definitive pre-commit rejection (`AppendOutcome::LimitExceeded`), never on an ambiguous DO
    /// RPC failure.
    async fn append(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        delivery_hash: Option<[u8; 32]>,
    ) -> Result<u64> {
        let (staged, size) = self.stage_content(sender, recipient, content).await?;
        let call = IdentityCall::Append {
            sender: sender.to_vec(),
            header: header.to_vec(),
            content: staged.clone(),
            size,
            initial_message: initial_message.map(|bytes| bytes.to_vec()),
            delivery_hash: delivery_hash.map(Vec::from),
        };
        let outcome = self.identity(recipient, &call).await;
        self.finish_append(outcome, &staged).await
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
        let objects = match delete_objects(&self.bucket, objects.clone()).await {
            Ok(()) => objects,
            Err(e) => {
                console_error!("cannot delete the objects of delivered messages: {e}");
                vec![]
            }
        };
        let call = IdentityCall::DeleteDelivered {
            sender: sender.to_vec(),
            hashes,
            objects,
        };
        self.identity(recipient, &call).await
    }
}

#[cfg(feature = "pq")]
impl LocalIdempotentMailboxStore for Store {
    async fn append_idempotent(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        delivery_hash: Option<[u8; 32]>,
        client_message_id: Option<[u8; 16]>,
    ) -> Result<u64> {
        let (staged, size) = self.stage_content(sender, recipient, content).await?;
        let call = IdentityCall::AppendIdempotent {
            sender: sender.to_vec(),
            header: header.to_vec(),
            content: staged.clone(),
            size,
            initial_message: initial_message.map(|bytes| bytes.to_vec()),
            delivery_hash: delivery_hash.map(Vec::from),
            client_message_id: client_message_id.map(Vec::from),
        };
        let outcome = self.identity(recipient, &call).await;
        self.finish_append(outcome, &staged).await
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

    async fn put_chunk(&self, id: &AttachmentId, index: u32, data: Bytes) -> Result<()> {
        let object = chunk_object(id, index);
        let absent = Conditional {
            etag_does_not_match: Some("*".to_string()),
            ..Conditional::default()
        };
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
