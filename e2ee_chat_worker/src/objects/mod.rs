//! The Durable Objects that keep the server's state: an [`Identity`] per identity key, and an
//! [`Attachment`] per attachment, each with its own SQLite database. Each call the Worker makes
//! to one, encoded with postcard, is served whole before the next, so that it is atomic, as the
//! storage traits require; and as each identity's data is its own object's, the server grows
//! with its users rather than through one database.

mod attachment;
mod identity;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use storage::MAX_SAFE_INTEGER;
use worker::{
    Env, Error, Method, ObjectNamespace, Request, RequestInit, Response, Result, ScheduledTime,
    SqlStorage, SqlStorageValue, Stub,
    js_sys::{self, Uint8Array},
};

pub use attachment::{Attachment, DEFAULT_FILE_RETENTION_DAYS};
pub use identity::{
    HEADER_PENDING_IDENTITY, HEADER_SUBSCRIBE_SIG, HEADER_SUBSCRIBE_TS, Identity,
};

/// The binding of the identities' namespace.
const IDENTITIES: &str = "IDENTITIES";
/// The binding of the attachments' namespace.
const ATTACHMENTS: &str = "ATTACHMENTS";
/// The latest an alarm may be set for, in milliseconds since the Unix epoch: 2189-01-01, as the
/// runtime refuses alarms after 2189.
const LATEST: u64 = 6_911_049_600_000;
/// How long, in milliseconds, after an alarm that failed, e.g. as R2 could not be reached, the
/// next tries again: the runtime retries one only for a few minutes, and nothing else would set
/// it again.
const RETRY_ALARM: u64 = 60 * 60 * 1000;

/// The object of `identity_key`.
pub fn identity(env: &Env, identity_key: &[u8]) -> Result<Stub> {
    stub(&env.durable_object(IDENTITIES)?, identity_key)
}

/// The object of the attachment `id`.
pub fn attachment(env: &Env, id: &[u8]) -> Result<Stub> {
    stub(&env.durable_object(ATTACHMENTS)?, id)
}

fn stub(namespace: &ObjectNamespace, key: &[u8]) -> Result<Stub> {
    namespace.id_from_name(&crate::hex(key))?.get_stub()
}

/// Outcome of an [`IdentityCall::Append`] or [`IdentityCall::AppendIdempotent`], distinguishing
/// a definitive pre-commit rejection (safe to delete a staged R2 blob) from an ambiguous RPC error
/// (must NOT delete the R2 blob).
#[derive(Debug, Serialize, Deserialize)]
pub enum AppendOutcome {
    /// A new message row was committed at this sequence number.
    Appended(u64),
    /// Deduplicated against a previously committed `client_message_id` (newly staged blob unused).
    #[cfg(feature = "pq")]
    Deduplicated(u64),
    /// Rejected before commit because the per-queue row or byte quota would be exceeded.
    LimitExceeded,
}

/// What the Worker asks of an [`Identity`], about its identity's keys, inbox and the queues of
/// messages to it.
#[derive(Debug, Serialize, Deserialize)]
pub enum IdentityCall {
    /// Store the legacy v1 bundle, and replace classical one-time prekeys, if `timestamp` is newer
    /// than the stored v1 bundle's. Does NOT overwrite or clear v2 manifests or PQ prekeys.
    Publish {
        signed_prekey: Vec<u8>,
        signature: Vec<u8>,
        timestamp: u64,
        one_time_prekeys: Vec<Vec<u8>>,
    },
    /// The legacy v1 bundle, with a classical one-time prekey, which goes. Never pops PQOPKs.
    TakeBundle,
    /// Add a classical v1 initial message to the inbox, unless it holds `limit`.
    AddInitialMessage { message: InitialMessage, limit: u64 },
    /// Take classical v1 initial messages only, if `timestamp` is newer than the last take's.
    /// Does not allocate tables for unknown identities and never drains v2 PQ initial messages.
    TakeInitialMessages { timestamp: u64 },
    /// Append a message to the queue from `sender`. Answers [`AppendOutcome`].
    Append {
        sender: Vec<u8>,
        header: Vec<u8>,
        content: Content,
        /// The content's length, wherever it is.
        size: u64,
        initial_message: Option<Vec<u8>>,
        delivery_hash: Option<Vec<u8>>,
    },
    /// The messages of the queue from `sender` after `after`, at most `limit`, and at most
    /// `max_size` bytes (header + initial_message + content) but for the first.
    Read {
        sender: Vec<u8>,
        after: u64,
        limit: u32,
        max_size: u64,
    },
    /// The R2 objects of the messages from `sender` whose delivery hashes are among `hashes`.
    DeliveredObjects {
        sender: Vec<u8>,
        hashes: Vec<Vec<u8>>,
    },
    /// Delete the messages from `sender` whose delivery hashes are among `hashes`: those without
    /// R2 objects, and those whose objects are among `objects`, which went.
    DeleteDelivered {
        sender: Vec<u8>,
        hashes: Vec<Vec<u8>>,
        objects: Vec<String>,
    },
    /// Atomically publish a signed v2 CapabilityManifest and classical + PQ prekeys.
    #[cfg(feature = "pq")]
    PublishV2 {
        manifest: ManifestWire,
        signed_prekey_signature: Option<Vec<u8>>,
        one_time_prekeys: Vec<Vec<u8>>,
        pq_last_resort: Vec<PqPrekeyWire>,
        pq_one_time_prekeys: Vec<PqPrekeyWire>,
        timestamp: u64,
    },
    /// Append classical OPKs and/or signed PQOPKs to the current generation without rotating SPK.
    #[cfg(feature = "pq")]
    RefillPrekeys {
        generation: u64,
        one_time_prekeys: Vec<Vec<u8>>,
        pq_one_time_prekeys: Vec<PqPrekeyWire>,
        max_one_time_prekeys: u64,
        max_pq_one_time_prekeys: u64,
        timestamp: u64,
    },
    /// Non-consuming read of the stored CapabilityManifest.
    #[cfg(feature = "pq")]
    GetManifest,
    /// Atomically claim a bundle with preferred PQ suites (or classical v1 fallback).
    #[cfg(feature = "pq")]
    ClaimBundle { preferred_suites: Vec<u8> },
    /// Insert a v1 or v2 initial message into the inbox, returning `Option<u64>` assigned ID.
    #[cfg(feature = "pq")]
    AddInitialMessageV2 {
        message: InitialMessageV2Wire,
        limit: u64,
    },
    /// Non-destructively list up to `limit` pending initial messages (both v1 and v2).
    #[cfg(feature = "pq")]
    ListInitialMessages { limit: u64 },
    /// Delete only the specified initial message IDs, returning count deleted.
    #[cfg(feature = "pq")]
    AckInitialMessages { ids: Vec<u64> },
    /// Diagnostic snapshot of v2 PQ storage state.
    #[cfg(feature = "pq")]
    PqSnapshot,
    /// Idempotent append sharing the same queue as [`IdentityCall::Append`].
    #[cfg(feature = "pq")]
    AppendIdempotent {
        sender: Vec<u8>,
        header: Vec<u8>,
        content: Content,
        size: u64,
        initial_message: Option<Vec<u8>>,
        delivery_hash: Option<Vec<u8>>,
        client_message_id: Option<Vec<u8>>,
    },
}

/// A message's content: in its row, or in R2 under a name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Content {
    Inline(Vec<u8>),
    Object(String),
}

/// A bundle as kept, with a one-time prekey taken from it, if any was left.
#[derive(Debug, Serialize, Deserialize)]
pub struct TakenBundle {
    pub signed_prekey: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub one_time_prekey: Option<Vec<u8>>,
}

/// An initial message, as kept in its recipient's inbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialMessage {
    pub sender: Vec<u8>,
    pub ephemeral_key: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub one_time_prekey: Option<Vec<u8>>,
    pub header: Vec<u8>,
    pub content: Vec<u8>,
}

/// A message of a queue, as kept.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredRow {
    pub sequence: u64,
    pub header: Vec<u8>,
    pub content: Content,
    pub initial_message: Option<Vec<u8>>,
}

#[cfg(feature = "pq")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqCommitmentWire {
    pub suite: u8,
    pub prekey_id: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestWire {
    pub audience: String,
    pub identity_key: Vec<u8>,
    pub manifest_seq: u64,
    pub generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub pq_enabled: bool,
    pub strict_pq: bool,
    pub pq_ratchet_supported: bool,
    pub offered_suites: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub pq_last_resort: Vec<PqCommitmentWire>,
    pub signature: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqPrekeyWire {
    pub suite: u8,
    pub id: Vec<u8>,
    pub encapsulation_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Debug, Serialize, Deserialize)]
pub enum PublishV2Outcome {
    Stored,
    StaleSequence,
    DuplicatePrekey,
}

#[cfg(feature = "pq")]
#[derive(Debug, Serialize, Deserialize)]
pub enum RefillOutcome {
    Stored {
        classical_count: u64,
        pq_counts: Vec<(u8, u64)>,
    },
    NotFound,
    StaleGeneration,
    StaleTimestamp,
    DuplicatePrekey,
    LimitExceeded,
}

#[cfg(feature = "pq")]
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimedBundleWire {
    pub manifest: Option<ManifestWire>,
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_signature: Option<Vec<u8>>,
    pub one_time_prekey: Option<Vec<u8>>,
    pub pq_last_resort: Option<PqPrekeyWire>,
    pub pq_one_time_prekey: Option<PqPrekeyWire>,
}

#[cfg(feature = "pq")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialMessageV2Wire {
    pub id: u64,
    pub version: u32,
    pub sender: Vec<u8>,
    pub ephemeral_key: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub one_time_prekey: Option<Vec<u8>>,
    pub header: Vec<u8>,
    pub content: Vec<u8>,
    pub pq_suite: Option<u8>,
    pub pq_last_resort: bool,
    pub pq_prekey_id: Option<Vec<u8>>,
    pub pq_ciphertext: Option<Vec<u8>>,
    pub manifest_digest: Option<Vec<u8>>,
}

#[cfg(feature = "pq")]
#[derive(Debug, Serialize, Deserialize)]
pub struct PqSnapshotWire {
    pub manifest: Option<ManifestWire>,
    pub classical_one_time_count: u64,
    pub pq_last_resort_suites: Vec<u8>,
    pub pq_one_time_counts: Vec<(u8, u64)>,
    pub pending_initial_messages: u64,
}

/// What the Worker asks of an [`Attachment`].
#[derive(Debug, Serialize, Deserialize)]
pub enum AttachmentCall {
    /// Keep the attachment `id`, unless kept already, until it expires. Answers whether it did.
    Add {
        id: Vec<u8>,
        chunks: u32,
        token_hash: Vec<u8>,
        delete_hash: Vec<u8>,
    },
    /// The attachment, if kept. Answers an `Option<AttachmentRow>`.
    Get,
    /// Note that chunk `index` is in R2. Answers whether the attachment is still kept.
    Note { index: u32 },
    /// Delete the attachment and its chunks. Answers `()`.
    Delete,
}

/// An attachment, as kept.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttachmentRow {
    pub id: Vec<u8>,
    pub chunks: u32,
    pub token_hash: Vec<u8>,
    pub delete_hash: Vec<u8>,
    /// The chunks put, chunk `i` as bit `i`; see `storage::StoredAttachment::uploaded`.
    pub uploaded: u64,
}

/// Make `call` of the object `stub`, and decode its answer.
pub async fn call<T: DeserializeOwned>(stub: &Stub, call: &impl Serialize) -> Result<T> {
    let body = postcard::to_allocvec(call).map_err(|e| Error::RustError(e.to_string()))?;
    let request = Request::new_with_init(
        "https://object/call",
        RequestInit::new()
            .with_method(Method::Post)
            .with_body(Some(Uint8Array::from(body.as_slice()).into())),
    )?;
    let mut response = stub.fetch_with_request(request).await?;
    let answer = response.bytes().await?;
    if response.status_code() != 200 {
        return Err(Error::RustError(
            String::from_utf8_lossy(&answer).into_owned(),
        ));
    }
    postcard::from_bytes(&answer).map_err(|e| Error::RustError(e.to_string()))
}

/// The call that `request`, to an object, carries.
async fn decode<T: DeserializeOwned>(request: &mut Request) -> Result<T> {
    let body = request.bytes().await?;
    postcard::from_bytes(&body).map_err(|e| Error::RustError(e.to_string()))
}

/// The response that answers a call with `answer`, or the error that failed it.
fn answer<T: Serialize>(answer: Result<T>) -> Result<Response> {
    match answer.and_then(|answer| {
        postcard::to_allocvec(&answer).map_err(|e| Error::RustError(e.to_string()))
    }) {
        Ok(body) => Response::from_bytes(body),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// Bind an integer, rejecting any value above [`MAX_SAFE_INTEGER`] (`2^53 - 1`) instead of
/// silently clamping it.
pub(super) fn checked_integer(value: u64) -> Result<SqlStorageValue> {
    if value > MAX_SAFE_INTEGER {
        return Err(Error::RustError("integer exceeds MAX_SAFE_INTEGER".into()));
    }
    Ok(SqlStorageValue::Integer(value as i64))
}

/// Bind bytes as a BLOB.
fn blob(bytes: &[u8]) -> SqlStorageValue {
    SqlStorageValue::Blob(bytes.to_vec())
}

/// An alarm at `at`, in milliseconds since the Unix epoch, or as late as one may be: a retention
/// of more days than that keeps everything, rather than fails what it would keep.
fn alarm_at(at: u64) -> ScheduledTime {
    ScheduledTime::new(js_sys::Date::new(&(at.min(LATEST) as f64).into()))
}

/// Whether the object's table `name` is there. Only what keeps something creates its object's
/// tables, so that a read of an object nothing was kept in, or whose data was deleted, e.g. a
/// download of an attachment gone, which anyone may try, leaves no storage behind.
fn has_table(sql: &SqlStorage, name: &str) -> Result<bool> {
    let found: TablesRow = sql
        .exec(
            "SELECT count(*) AS tables FROM sqlite_master WHERE type = 'table' AND name = ?",
            vec![name.into()],
        )?
        .one()?;
    Ok(found.tables > 0)
}

#[derive(Deserialize)]
struct TablesRow {
    tables: u64,
}
