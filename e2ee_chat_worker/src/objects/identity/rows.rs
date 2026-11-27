//! Rows returned by canonical `SCHEMA_V5` identity SQLite queries.

use serde::Deserialize;
use storage::{Bytes, PublicKey, StoredInitialMessageV2, StoredMessage, StoredPqPrekey};
use worker::{Error, Result};

use crate::objects::sql::Blob;

pub(super) fn fixed_blob<const N: usize>(blob: Blob, name: &str) -> Result<[u8; N]> {
    blob.into_vec()
        .try_into()
        .map_err(|_| Error::RustError(format!("corrupt stored {name} length")))
}

#[derive(Deserialize)]
pub(super) struct SchemaVersionRow {
    pub(super) schema_version: u64,
}

#[derive(Deserialize)]
pub(super) struct WatermarkRow {
    pub(super) last_refill_ts: u64,
}

#[derive(Deserialize)]
pub(super) struct PrekeyRow {
    pub(super) position: u64,
    pub(super) prekey: Blob,
}

#[derive(Deserialize)]
pub(super) struct CountRow {
    pub(super) count: u64,
}

#[derive(Deserialize)]
pub(super) struct RecipientStatsRow {
    pub(super) last_sequence: u64,
    pub(super) total_bytes: u64,
    pub(super) authorized_peer_count: u64,
}

#[derive(Deserialize)]
pub(super) struct LastSequenceRow {
    pub(super) last_sequence: u64,
}

#[derive(Deserialize)]
pub(super) struct PeerGrantRow {
    pub(super) max_version: u64,
    pub(super) revoked_below_version: u64,
    pub(super) active_token_hash: Option<Blob>,
    pub(super) message_count: u64,
    pub(super) total_bytes: u64,
}

#[derive(Deserialize)]
pub(super) struct WriteTokenRow {
    pub(super) peer_slot_id: Blob,
}

#[derive(Deserialize)]
pub(super) struct WriteTokenAuthRow {
    pub(super) token_hash: Blob,
    pub(super) peer_slot_id: Blob,
    pub(super) grant_version: u64,
}

#[derive(Deserialize)]
pub(super) struct TokenHashRow {
    pub(super) token_hash: Blob,
}

#[derive(Deserialize)]
pub(super) struct DedupRow {
    pub(super) sequence: u64,
    pub(super) expires_at: u64,
}

#[derive(Deserialize)]
pub(super) struct TokenCountRow {
    pub(super) token_hash: Blob,
    pub(super) count: u64,
}

#[derive(Deserialize)]
pub(super) struct DeletedPeerBytesRow {
    pub(super) peer_slot_id: Blob,
    pub(super) bytes: u64,
}

#[derive(Deserialize)]
pub(super) struct MessageMetaRow {
    pub(super) sequence: u64,
    pub(super) bytes: u64,
}

#[derive(Deserialize)]
pub(super) struct SequenceRow {
    #[allow(dead_code)]
    pub(super) sequence: u64,
}

#[derive(Deserialize)]
pub(super) struct MessageRow {
    pub(super) sequence: u64,
    pub(super) token_hash: Blob,
    pub(super) header: Blob,
    pub(super) content: Blob,
    pub(super) initial_message: Option<Blob>,
}

impl TryFrom<MessageRow> for StoredMessage {
    type Error = Error;

    fn try_from(row: MessageRow) -> Result<Self> {
        Ok(Self {
            sequence: row.sequence,
            token_hash: fixed_blob(row.token_hash, "token_hash")?,
            header: Bytes::from(row.header.into_vec()),
            content: Bytes::from(row.content.into_vec()),
            initial_message: row.initial_message.map(|b| Bytes::from(b.into_vec())),
        })
    }
}

#[derive(Deserialize)]
pub(super) struct OldestRow {
    pub(super) oldest: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct ManifestSeqRow {
    pub(super) manifest_seq: u64,
}

#[derive(Deserialize)]
pub(super) struct ManifestRow {
    pub(super) audience: String,
    pub(super) identity_key: Blob,
    pub(super) manifest_seq: u64,
    pub(super) generation: u64,
    pub(super) issued_at: u64,
    pub(super) expires_at: u64,
    pub(super) pq_enabled: u64,
    pub(super) strict_pq: u64,
    pub(super) pq_ratchet_supported: u64,
    pub(super) offered_suites: Blob,
    pub(super) signed_prekey: Blob,
    pub(super) signed_prekey_signature: Option<Blob>,
    pub(super) pq_last_resort_commitments: Blob,
    pub(super) signature: Blob,
}

#[derive(Deserialize)]
pub(super) struct IdBlobRow {
    pub(super) prekey_id: Blob,
}

#[derive(Deserialize)]
pub(super) struct PqLastResortRow {
    pub(super) suite: u64,
    pub(super) prekey_id: Blob,
    pub(super) encapsulation_key: Blob,
    pub(super) signature: Blob,
}

impl TryFrom<PqLastResortRow> for StoredPqPrekey {
    type Error = Error;

    fn try_from(row: PqLastResortRow) -> Result<Self> {
        Ok(Self {
            suite: row.suite as u8,
            id: fixed_blob(row.prekey_id, "prekey_id")?,
            encapsulation_key: Bytes::from(row.encapsulation_key.into_vec()),
            signature: fixed_blob(row.signature, "pq signature")?,
        })
    }
}

#[derive(Deserialize)]
pub(super) struct PqOneTimeRow {
    pub(super) position: u64,
    pub(super) suite: u64,
    pub(super) prekey_id: Blob,
    pub(super) encapsulation_key: Blob,
    pub(super) signature: Blob,
}

impl TryFrom<PqOneTimeRow> for StoredPqPrekey {
    type Error = Error;

    fn try_from(row: PqOneTimeRow) -> Result<Self> {
        Ok(Self {
            suite: row.suite as u8,
            id: fixed_blob(row.prekey_id, "prekey_id")?,
            encapsulation_key: Bytes::from(row.encapsulation_key.into_vec()),
            signature: fixed_blob(row.signature, "pq signature")?,
        })
    }
}

#[derive(Deserialize)]
pub(super) struct OpkBudgetRow {
    pub(super) window_start: u64,
    pub(super) claims: u64,
}

#[derive(Deserialize)]
pub(super) struct IdRow {
    pub(super) id: u64,
}

#[derive(Deserialize)]
pub(super) struct InitialPayloadRow {
    pub(super) id: u64,
    pub(super) payload_hash: Blob,
}

#[derive(Deserialize)]
pub(super) struct InitialMessageRow {
    pub(super) id: u64,
    pub(super) version: u64,
    pub(super) sender: Blob,
    pub(super) ephemeral_key: Blob,
    pub(super) signed_prekey: Blob,
    pub(super) one_time_prekey: Option<Blob>,
    pub(super) header: Blob,
    pub(super) content: Blob,
    pub(super) pq_suite: Option<u64>,
    pub(super) pq_last_resort: u64,
    pub(super) pq_prekey_id: Option<Blob>,
    pub(super) pq_ciphertext: Option<Blob>,
    pub(super) manifest_digest: Option<Blob>,
}

impl InitialMessageRow {
    pub(super) fn into_stored(self, recipient: PublicKey) -> Result<StoredInitialMessageV2> {
        Ok(StoredInitialMessageV2 {
            id: self.id,
            version: self.version as u32,
            sender: fixed_blob(self.sender, "sender")?,
            recipient,
            ephemeral_key: fixed_blob(self.ephemeral_key, "ephemeral_key")?,
            signed_prekey: fixed_blob(self.signed_prekey, "signed_prekey")?,
            one_time_prekey: self
                .one_time_prekey
                .map(|b| fixed_blob(b, "one_time_prekey"))
                .transpose()?,
            header: Bytes::from(self.header.into_vec()),
            content: Bytes::from(self.content.into_vec()),
            pq_suite: self.pq_suite.map(|s| s as u8),
            pq_last_resort: self.pq_last_resort != 0,
            pq_prekey_id: self
                .pq_prekey_id
                .map(|b| fixed_blob(b, "pq_prekey_id"))
                .transpose()?,
            pq_ciphertext: self.pq_ciphertext.map(|b| Bytes::from(b.into_vec())),
            manifest_digest: self
                .manifest_digest
                .map(|b| fixed_blob(b, "manifest_digest"))
                .transpose()?,
        })
    }
}

#[derive(Deserialize)]
pub(super) struct SuiteCountRow {
    pub(super) suite: u64,
    pub(super) count: u64,
}

#[derive(Deserialize)]
pub(super) struct SuiteRow {
    pub(super) suite: u64,
}
