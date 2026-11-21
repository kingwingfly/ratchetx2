//! Rows returned by the identity SQLite queries.

use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct TableInfoRow {
    pub(super) name: String,
}

#[derive(Deserialize)]
pub(super) struct TimestampRow {
    pub(super) timestamp: u64,
}

#[derive(Deserialize)]
pub(super) struct WatermarkRow {
    pub(super) last_v1_publish_ts: u64,
    #[cfg_attr(not(feature = "pq"), allow(dead_code))]
    pub(super) last_refill_ts: u64,
}

#[derive(Deserialize)]
pub(super) struct BundleRow {
    #[serde(with = "serde_bytes")]
    pub(super) signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) signature: Vec<u8>,
    pub(super) timestamp: u64,
}

#[derive(Deserialize)]
pub(super) struct PrekeyRow {
    pub(super) position: u64,
    #[serde(with = "serde_bytes")]
    pub(super) prekey: Vec<u8>,
}

#[derive(Deserialize)]
pub(super) struct CountRow {
    pub(super) count: u64,
}

#[derive(Deserialize)]
pub(super) struct QueueUsageRow {
    pub(super) count: u64,
    pub(super) total_bytes: u64,
}

#[derive(Deserialize)]
pub(super) struct LastTakeRow {
    pub(super) last_take: u64,
}

#[derive(Deserialize)]
pub(super) struct InitialMessageRow {
    #[serde(with = "serde_bytes")]
    pub(super) sender: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) ephemeral_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) one_time_prekey: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub(super) header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) content: Vec<u8>,
}

#[derive(Deserialize)]
pub(super) struct SequenceRow {
    pub(super) sequence: u64,
}

#[derive(Deserialize)]
pub(super) struct MessageMetaRow {
    pub(super) sequence: u64,
    pub(super) header_len: u64,
    pub(super) size: u64,
    pub(super) init_len: u64,
}

#[derive(Deserialize)]
pub(super) struct MessageRow {
    pub(super) sequence: u64,
    #[serde(with = "serde_bytes")]
    pub(super) header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) content: Option<Vec<u8>>,
    pub(super) object: Option<String>,
    #[allow(dead_code)]
    pub(super) size: u64,
    #[serde(with = "serde_bytes")]
    pub(super) initial_message: Option<Vec<u8>>,
}

#[derive(Deserialize)]
pub(super) struct ObjectRow {
    pub(super) object: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ExpiredObjectRow {
    #[serde(with = "serde_bytes")]
    pub(super) sender: Vec<u8>,
    pub(super) sequence: u64,
    pub(super) object: String,
}

#[derive(Deserialize)]
pub(super) struct OldestRow {
    pub(super) oldest: Option<u64>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
pub(super) struct ManifestSeqRow {
    pub(super) manifest_seq: u64,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
pub(super) struct ManifestRow {
    pub(super) audience: String,
    #[serde(with = "serde_bytes")]
    pub(super) identity_key: Vec<u8>,
    pub(super) manifest_seq: u64,
    pub(super) generation: u64,
    pub(super) issued_at: u64,
    pub(super) expires_at: u64,
    pub(super) pq_enabled: u64,
    pub(super) strict_pq: u64,
    pub(super) pq_ratchet_supported: u64,
    #[serde(with = "serde_bytes")]
    pub(super) offered_suites: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) pq_last_resort_commitments: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) signature: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
pub(super) struct IdBlobRow {
    #[serde(with = "serde_bytes")]
    pub(super) prekey_id: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
pub(super) struct PqLastResortRow {
    pub(super) suite: u64,
    #[serde(with = "serde_bytes")]
    pub(super) prekey_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) encapsulation_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) signature: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
pub(super) struct PqOneTimeRow {
    pub(super) position: u64,
    pub(super) suite: u64,
    #[serde(with = "serde_bytes")]
    pub(super) prekey_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) encapsulation_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) signature: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
pub(super) struct IdRow {
    pub(super) id: u64,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
pub(super) struct InitialMessageWithIdRow {
    pub(super) id: u64,
    #[serde(with = "serde_bytes")]
    pub(super) sender: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) ephemeral_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) one_time_prekey: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub(super) header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) content: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
pub(super) struct InitialMessageJoinedRow {
    pub(super) id: u64,
    #[serde(with = "serde_bytes")]
    pub(super) sender: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) ephemeral_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) one_time_prekey: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub(super) header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(super) content: Vec<u8>,
    pub(super) version: Option<u64>,
    pub(super) pq_suite: Option<u64>,
    pub(super) pq_last_resort: Option<u64>,
    #[serde(with = "serde_bytes")]
    pub(super) pq_prekey_id: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub(super) pq_ciphertext: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub(super) manifest_digest: Option<Vec<u8>>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
pub(super) struct SuiteCountRow {
    pub(super) suite: u64,
    pub(super) count: u64,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
pub(super) struct SuiteRow {
    pub(super) suite: u64,
}
