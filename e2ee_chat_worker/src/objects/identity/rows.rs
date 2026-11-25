//! Rows returned by the identity SQLite queries.

use serde::Deserialize;

use crate::objects::{InitialMessageV2Wire, PqPrekeyWire, sql::Blob};

#[derive(Deserialize)]
pub(super) struct TableInfoRow {
    pub(super) name: String,
}

#[derive(Deserialize)]
pub(super) struct SchemaVersionRow {
    pub(super) schema_version: u64,
}

#[derive(Deserialize)]
pub(super) struct TimestampRow {
    pub(super) timestamp: u64,
}

#[derive(Deserialize)]
pub(super) struct WatermarkRow {
    pub(super) last_refill_ts: u64,
}

#[derive(Deserialize)]
pub(super) struct BundleRow {
    pub(super) signed_prekey: Blob,
    pub(super) signature: Blob,
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
pub(super) struct QueueStateRow {
    pub(super) last_sequence: u64,
    pub(super) message_count: u64,
    pub(super) total_bytes: u64,
}

#[derive(Deserialize)]
pub(super) struct RecipientStatsRow {
    pub(super) queue_count: u64,
    pub(super) total_bytes: u64,
    pub(super) sequence_floor: u64,
}

#[derive(Deserialize)]
pub(super) struct DedupRow {
    pub(super) sequence: u64,
    pub(super) expires_at: u64,
}

#[derive(Deserialize)]
pub(super) struct SenderCountRow {
    pub(super) sender: Blob,
    pub(super) count: u64,
}

#[derive(Deserialize)]
pub(super) struct DeletedMessageRow {
    pub(super) bytes: u64,
    pub(super) object: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DeletedSenderBytesRow {
    pub(super) sender: Blob,
    pub(super) bytes: u64,
}

#[derive(Deserialize)]
pub(super) struct PendingObjectRow {
    pub(super) object: String,
}

#[derive(Deserialize)]
pub(super) struct MessageMetaRow {
    pub(super) sequence: u64,
    pub(super) header_len: u64,
    pub(super) size: u64,
    pub(super) init_len: u64,
    pub(super) is_object: u64,
}

#[derive(Deserialize)]
pub(super) struct MessageRow {
    pub(super) sequence: u64,
    pub(super) header: Blob,
    pub(super) content: Option<Blob>,
    pub(super) object: Option<String>,
    pub(super) initial_message: Option<Blob>,
}

#[derive(Deserialize)]
pub(super) struct ObjectRow {
    pub(super) object: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ExpiredObjectRow {
    pub(super) sender: Blob,
    pub(super) sequence: u64,
    pub(super) object: String,
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

impl From<PqLastResortRow> for PqPrekeyWire {
    fn from(row: PqLastResortRow) -> Self {
        Self {
            suite: row.suite as u8,
            id: row.prekey_id.into_vec(),
            encapsulation_key: row.encapsulation_key.into_vec(),
            signature: row.signature.into_vec(),
        }
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

impl From<PqOneTimeRow> for PqPrekeyWire {
    fn from(row: PqOneTimeRow) -> Self {
        Self {
            suite: row.suite as u8,
            id: row.prekey_id.into_vec(),
            encapsulation_key: row.encapsulation_key.into_vec(),
            signature: row.signature.into_vec(),
        }
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
pub(super) struct InitialMessageWithIdRow {
    pub(super) id: u64,
    pub(super) sender: Blob,
    pub(super) ephemeral_key: Blob,
    pub(super) signed_prekey: Blob,
    pub(super) one_time_prekey: Option<Blob>,
    pub(super) header: Blob,
    pub(super) content: Blob,
}

impl From<InitialMessageWithIdRow> for InitialMessageV2Wire {
    fn from(row: InitialMessageWithIdRow) -> Self {
        Self {
            id: row.id,
            version: 1,
            sender: row.sender.into_vec(),
            ephemeral_key: row.ephemeral_key.into_vec(),
            signed_prekey: row.signed_prekey.into_vec(),
            one_time_prekey: row.one_time_prekey.map(Blob::into_vec),
            header: row.header.into_vec(),
            content: row.content.into_vec(),
            pq_suite: None,
            pq_last_resort: false,
            pq_prekey_id: None,
            pq_ciphertext: None,
            manifest_digest: None,
        }
    }
}

#[derive(Deserialize)]
pub(super) struct InitialMessageJoinedRow {
    pub(super) id: u64,
    pub(super) sender: Blob,
    pub(super) ephemeral_key: Blob,
    pub(super) signed_prekey: Blob,
    pub(super) one_time_prekey: Option<Blob>,
    pub(super) header: Blob,
    pub(super) content: Blob,
    pub(super) version: Option<u64>,
    pub(super) pq_suite: Option<u64>,
    pub(super) pq_last_resort: Option<u64>,
    pub(super) pq_prekey_id: Option<Blob>,
    pub(super) pq_ciphertext: Option<Blob>,
    pub(super) manifest_digest: Option<Blob>,
}

impl From<InitialMessageJoinedRow> for InitialMessageV2Wire {
    fn from(row: InitialMessageJoinedRow) -> Self {
        Self {
            id: row.id,
            version: row.version.map_or(1, |v| v as u32),
            sender: row.sender.into_vec(),
            ephemeral_key: row.ephemeral_key.into_vec(),
            signed_prekey: row.signed_prekey.into_vec(),
            one_time_prekey: row.one_time_prekey.map(Blob::into_vec),
            header: row.header.into_vec(),
            content: row.content.into_vec(),
            pq_suite: row.pq_suite.map(|s| s as u8),
            pq_last_resort: row.pq_last_resort.unwrap_or(0) != 0,
            pq_prekey_id: row.pq_prekey_id.map(Blob::into_vec),
            pq_ciphertext: row.pq_ciphertext.map(Blob::into_vec),
            manifest_digest: row.manifest_digest.map(Blob::into_vec),
        }
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
