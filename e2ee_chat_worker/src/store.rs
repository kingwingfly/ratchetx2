//! The v2 handshake, idempotent mailbox, and attachment stores over the Worker's Durable Objects,
//! with large message contents and attachments' chunks in R2.
//!
//! Each store method is one typed call of one object, which serves it whole, so it is atomic, as
//! the storage traits require. Large contents go to R2 before the DO append call; on an ambiguous
//! DO RPC error the R2 object is intentionally NOT deleted (relying on R2 lifecycle/GC) so a
//! committed message row can never be left pointing at a deleted blob. Only a definitive
//! pre-commit rejection (`AppendOutcome::LimitExceeded`) deletes the staged R2 object.

use futures_util::{StreamExt, TryStreamExt, stream};
use storage::{
    AttachmentId, Bytes, ClaimOutcome, ClaimedPqBundle, Error, ErrorKind, LocalAttachmentStore,
    LocalIdempotentMailboxStore, LocalPqHandshakeStore, MAX_SAFE_INTEGER, PqLastResortCommitment,
    PqStorageSnapshot, PublicKey, PublishV2Record, PublishV2Status, RefillPrekeysRecord,
    RefillStatus, Result, StoredAttachment, StoredCapabilityManifest, StoredInitialMessageV2,
    StoredMessage, StoredPqPrekey,
};
use worker::{Bucket, Conditional, Env, console_error};

use crate::objects::{
    self, AppendOutcome, AttachmentRpc, ClaimBundleOutcome, ClaimedBundleWire, Content,
    IdentityRpc, InitialMessageV2Wire, ManifestWire, PqCommitmentWire, PqPrekeyWire,
    PublishV2Outcome, RefillOutcome, rpc,
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

    /// Make typed `call` of the object of `identity_key`.
    async fn identity<R: IdentityRpc>(&self, identity_key: &[u8], call: R) -> Result<R::Reply> {
        let stub = objects::identity(&self.env, identity_key).map_err(unavailable)?;
        objects::call(&stub, call).await.map_err(unavailable)
    }

    /// Make typed `call` of the object of `identity_key`, returning `Ok(None)` if an older
    /// Durable Object rejected the newly introduced wire tag during a rolling deploy.
    async fn identity_or_unsupported<R: IdentityRpc>(
        &self,
        identity_key: &[u8],
        call: R,
    ) -> Result<Option<R::Reply>> {
        let stub = objects::identity(&self.env, identity_key).map_err(unavailable)?;
        match objects::call_raw(&stub, call).await {
            Ok(reply) => Ok(Some(reply)),
            Err(err) if err.is_unsupported_call() => Ok(None),
            Err(err) => Err(unavailable(err.into_worker_error())),
        }
    }

    /// Make typed `call` of the object of the attachment `id`.
    async fn attachment_call<R: AttachmentRpc>(
        &self,
        id: &AttachmentId,
        call: R,
    ) -> Result<R::Reply> {
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
                random_id()?
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

    async fn finish_append(&self, outcome: Result<AppendOutcome>, staged: &Content) -> Result<u64> {
        match outcome {
            Ok(AppendOutcome::Appended(seq)) => Ok(seq),
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

    async fn read_with_cap(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
        max_size: usize,
    ) -> Result<Vec<StoredMessage>> {
        let rows = self
            .identity(
                recipient,
                rpc::Read {
                    sender: sender.to_vec(),
                    after,
                    limit,
                    max_size: max_size as u64,
                },
            )
            .await?;
        stream::iter(rows.into_iter().map(|row| async move {
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
        .buffered(6)
        .try_collect()
        .await
    }
}

fn check_safe(value: u64) -> Result<()> {
    if value > MAX_SAFE_INTEGER {
        return Err(ErrorKind::InvalidArgument.into());
    }
    Ok(())
}

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

fn pq_prekey_to_wire(key: &StoredPqPrekey) -> PqPrekeyWire {
    PqPrekeyWire {
        suite: key.suite,
        id: key.id.to_vec(),
        encapsulation_key: key.encapsulation_key.to_vec(),
        signature: key.signature.to_vec(),
    }
}

fn pq_prekey_from_wire(wire: PqPrekeyWire) -> Result<StoredPqPrekey> {
    Ok(StoredPqPrekey {
        suite: wire.suite,
        id: fixed(&wire.id)?,
        encapsulation_key: Bytes::from(wire.encapsulation_key),
        signature: fixed(&wire.signature)?,
    })
}

fn claimed_bundle_from_wire(
    identity_key: &PublicKey,
    wire: ClaimedBundleWire,
) -> Result<ClaimedPqBundle> {
    Ok(ClaimedPqBundle {
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
    })
}

impl LocalPqHandshakeStore for Store {
    async fn publish_v2(&self, record: PublishV2Record) -> Result<PublishV2Status> {
        check_safe(record.timestamp)?;
        check_safe(record.manifest.manifest_seq)?;
        check_safe(record.manifest.generation)?;
        check_safe(record.manifest.issued_at)?;
        check_safe(record.manifest.expires_at)?;
        let outcome = self
            .identity(
                &record.manifest.identity_key,
                rpc::PublishV2 {
                    manifest: manifest_to_wire(&record.manifest),
                    signed_prekey_signature: record.signed_prekey_signature.map(|s| s.to_vec()),
                    one_time_prekeys: record.one_time_prekeys.iter().map(|k| k.to_vec()).collect(),
                    pq_last_resort: record
                        .pq_last_resort
                        .iter()
                        .map(pq_prekey_to_wire)
                        .collect(),
                    pq_one_time_prekeys: record
                        .pq_one_time_prekeys
                        .iter()
                        .map(pq_prekey_to_wire)
                        .collect(),
                    timestamp: record.timestamp,
                },
            )
            .await?;
        Ok(match outcome {
            PublishV2Outcome::Stored => PublishV2Status::Stored,
            PublishV2Outcome::StaleSequence => PublishV2Status::StaleSequence,
            PublishV2Outcome::DuplicatePrekey => PublishV2Status::DuplicatePrekey,
        })
    }

    async fn refill_prekeys(&self, record: RefillPrekeysRecord) -> Result<RefillStatus> {
        check_safe(record.generation)?;
        check_safe(record.timestamp)?;
        let outcome = self
            .identity(
                &record.identity_key,
                rpc::RefillPrekeys {
                    generation: record.generation,
                    one_time_prekeys: record.one_time_prekeys.iter().map(|k| k.to_vec()).collect(),
                    pq_one_time_prekeys: record
                        .pq_one_time_prekeys
                        .iter()
                        .map(pq_prekey_to_wire)
                        .collect(),
                    max_one_time_prekeys: record.max_one_time_prekeys as u64,
                    max_pq_one_time_prekeys: record.max_pq_one_time_prekeys as u64,
                    timestamp: record.timestamp,
                },
            )
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
        let wire = self.identity(identity_key, rpc::GetManifest).await?;
        wire.map(manifest_from_wire).transpose()
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
        if let Some(outcome) = self
            .identity_or_unsupported(
                identity_key,
                rpc::ClaimBundleChecked {
                    preferred_suites: preferred_suites.to_vec(),
                    reject_pq_on_manifest,
                },
            )
            .await?
        {
            return match outcome {
                ClaimBundleOutcome::NotFound => Ok(ClaimOutcome::NotFound),
                ClaimBundleOutcome::PqDisabledForPqManifest => {
                    Ok(ClaimOutcome::PqDisabledForPqManifest)
                }
                ClaimBundleOutcome::Claimed(wire) => Ok(ClaimOutcome::Claimed(Box::new(
                    claimed_bundle_from_wire(identity_key, *wire)?,
                ))),
            };
        }
        // Rolling-deploy fallback for older DO instances that do not recognize tag 17 yet:
        // pre-check `get_manifest` when `reject_pq_on_manifest` is set, then call tag 11.
        if reject_pq_on_manifest
            && self
                .get_manifest(identity_key)
                .await?
                .is_some_and(|manifest| manifest.pq_enabled)
        {
            return Ok(ClaimOutcome::PqDisabledForPqManifest);
        }
        let wire = self
            .identity(
                identity_key,
                rpc::ClaimBundle {
                    preferred_suites: preferred_suites.to_vec(),
                },
            )
            .await?;
        let Some(wire) = wire else {
            return Ok(ClaimOutcome::NotFound);
        };
        let claimed = claimed_bundle_from_wire(identity_key, wire)?;
        if reject_pq_on_manifest && claimed.manifest.as_ref().is_some_and(|m| m.pq_enabled) {
            return Ok(ClaimOutcome::PqDisabledForPqManifest);
        }
        Ok(ClaimOutcome::Claimed(Box::new(claimed)))
    }

    async fn add_initial_message_v2(
        &self,
        initial_message: StoredInitialMessageV2,
        limit: usize,
    ) -> Result<Option<u64>> {
        self.identity(
            &initial_message.recipient,
            rpc::AddInitialMessageV2 {
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
            },
        )
        .await
    }

    async fn list_initial_messages(
        &self,
        recipient: &PublicKey,
        limit: usize,
    ) -> Result<Vec<StoredInitialMessageV2>> {
        let wires = self
            .identity(
                recipient,
                rpc::ListInitialMessages {
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
        let deleted = self
            .identity(recipient, rpc::AckInitialMessages { ids: ids.to_vec() })
            .await?;
        Ok(deleted as usize)
    }

    async fn pq_snapshot(&self, identity_key: &PublicKey) -> Result<PqStorageSnapshot> {
        let wire = self.identity(identity_key, rpc::PqSnapshot).await?;
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
        let outcome = self
            .identity(
                recipient,
                rpc::AppendIdempotent {
                    sender: sender.to_vec(),
                    header: header.to_vec(),
                    content: staged.clone(),
                    size,
                    initial_message: initial_message.map(|bytes| bytes.to_vec()),
                    delivery_hash: delivery_hash.map(Vec::from),
                    client_message_id: client_message_id.map(Vec::from),
                },
            )
            .await;
        self.finish_append(outcome, &staged).await
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
        if self
            .identity_or_unsupported(
                recipient,
                rpc::DeleteDeliveredAtomic {
                    sender: sender.to_vec(),
                    hashes: hashes.clone(),
                },
            )
            .await?
            .is_some()
        {
            return Ok(());
        }
        // Rolling-deploy fallback for older DO instances that do not recognize tag 18 yet:
        // call tags 6 + 7, propagating any R2 deletion failure BEFORE SQL deletion so client
        // receipts are never silently dropped.
        let objects = self
            .identity(
                recipient,
                rpc::DeliveredObjects {
                    sender: sender.to_vec(),
                    hashes: hashes.clone(),
                },
            )
            .await?;
        if !objects.is_empty() {
            delete_objects(&self.bucket, objects.clone())
                .await
                .map_err(unavailable)?;
        }
        self.identity(
            recipient,
            rpc::DeleteDelivered {
                sender: sender.to_vec(),
                hashes,
                objects,
            },
        )
        .await
    }

    async fn read(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
    ) -> Result<Vec<StoredMessage>> {
        self.read_with_cap(sender, recipient, after, limit, self.max_read_size)
            .await
    }

    async fn read_bounded(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
        max_size: usize,
    ) -> Result<Vec<StoredMessage>> {
        self.read_with_cap(
            sender,
            recipient,
            after,
            limit,
            max_size.min(self.max_read_size),
        )
        .await
    }
}

impl LocalAttachmentStore for Store {
    async fn add_attachment(&self, attachment: StoredAttachment) -> Result<bool> {
        self.attachment_call(
            &attachment.id,
            rpc::AddAttachment {
                id: attachment.id.to_vec(),
                chunks: attachment.chunks,
                token_hash: attachment.token_hash.to_vec(),
                delete_hash: attachment.delete_hash.to_vec(),
            },
        )
        .await
    }

    async fn attachment(&self, id: &AttachmentId) -> Result<Option<StoredAttachment>> {
        let row = self.attachment_call(id, rpc::GetAttachment).await?;
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
        let noted = self.attachment_call(id, rpc::NoteChunk { index }).await?;
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
        self.attachment_call(id, rpc::DeleteAttachment).await
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

/// A random 128-bit hex identifier for an R2 object.
fn random_id() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|e| {
        console_error!("RNG failed generating R2 object ID: {e}");
        Error::new(ErrorKind::Unavailable, "storage temporarily unavailable")
    })?;
    Ok(hex(&bytes))
}

/// A stored key or signature of `N` bytes.
fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| {
        console_error!(
            "corrupt stored key length: {} bytes, expected {N}",
            bytes.len()
        );
        Error::new(ErrorKind::Corrupt, "corrupt stored record")
    })
}

/// A failed object or R2 call, logged internally while returning a generic message to clients.
fn unavailable(error: worker::Error) -> Error {
    console_error!("storage failed: {error}");
    Error::new(ErrorKind::Unavailable, "storage temporarily unavailable")
}

#[cfg(test)]
mod tests {
    use super::{decode_hex_fixed, hex};

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
