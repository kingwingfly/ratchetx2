//! The Durable Objects that keep the server's state: an [`Identity`] per identity key, and an
//! [`Attachment`] per attachment, each with its own SQLite database. Each call the Worker makes
//! to one, encoded with postcard, is served whole before the next, so that it is atomic, as the
//! storage traits require; and as each identity's data is its own object's, the server grows
//! with its users rather than through one database.

mod attachment;
mod identity;
pub(super) mod sql;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use worker::{
    Env, Error, Method, ObjectNamespace, Request, RequestInit, Response, Result, ScheduledTime,
    Stub, console_error,
    js_sys::{self, Uint8Array},
};

pub use attachment::{Attachment, DEFAULT_FILE_RETENTION_DAYS};
pub use identity::{
    HEADER_DEPLOYMENT_AUTH, HEADER_PENDING_IDENTITY, HEADER_SESSION_EXPIRES,
    HEADER_SUBSCRIBE_AUDIENCE, HEADER_SUBSCRIBE_SIG, HEADER_SUBSCRIBE_TS, Identity,
};
use sql::{SqlExec, params};

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

/// Typed Durable Object RPC binding each request type to its exact reply type so postcard
/// deserialization can never silently decode the wrong reply schema.
pub trait RpcCall: Sized {
    type Reply: Serialize + DeserializeOwned;

    fn encode(self) -> Result<Vec<u8>>;
}

/// Marker for RPCs routed to an [`Identity`] Durable Object.
pub trait IdentityRpc: RpcCall {}

/// Marker for RPCs routed to an [`Attachment`] Durable Object.
pub trait AttachmentRpc: RpcCall {}

/// Outcome of an [`IdentityCall::AppendIdempotent`], distinguishing a definitive pre-commit
/// rejection (safe to delete a staged R2 blob) from an ambiguous RPC error (must NOT delete the
/// R2 blob).
#[derive(Debug, Serialize, Deserialize)]
pub enum AppendOutcome {
    /// A new message row was committed at this sequence number.
    Appended(u64),
    /// Deduplicated against a previously committed `client_message_id` (newly staged blob unused).
    Deduplicated(u64),
    /// Rejected before commit because per-queue or per-recipient row/byte quotas would be exceeded.
    LimitExceeded,
}

/// Typed request payloads for [`IdentityCall`] and [`AttachmentCall`].
///
/// Using newtype enum variants in [`IdentityCall`] and [`AttachmentCall`] keeps postcard wire
/// encoding byte-for-byte identical to flat struct variants while statically associating each RPC
/// with its exact reply type via [`RpcCall`].
pub mod rpc {
    use serde::{Deserialize, Serialize};

    use super::{
        AppendOutcome, AttachmentCall, AttachmentRow, AttachmentRpc, ClaimBundleOutcome,
        ClaimedBundleWire, Content, IdentityCall, IdentityRpc, InitialMessageV2Wire, ManifestWire,
        PqPrekeyWire, PqSnapshotWire, PublishV2Outcome, RefillOutcome, RpcCall, StoredRow,
    };
    use worker::{Error, Result};

    fn encode_wire(value: &impl Serialize) -> Result<Vec<u8>> {
        postcard::to_allocvec(value).map_err(|e| Error::RustError(e.to_string()))
    }

    macro_rules! impl_identity_rpc {
        ($req:ident => $variant:ident, Reply = $reply:ty) => {
            impl RpcCall for $req {
                type Reply = $reply;

                fn encode(self) -> Result<Vec<u8>> {
                    encode_wire(&IdentityCall::$variant(self))
                }
            }

            impl IdentityRpc for $req {}
        };
    }

    macro_rules! impl_attachment_rpc {
        ($req:ident => $variant:ident, Reply = $reply:ty) => {
            impl RpcCall for $req {
                type Reply = $reply;

                fn encode(self) -> Result<Vec<u8>> {
                    encode_wire(&AttachmentCall::$variant(self))
                }
            }

            impl AttachmentRpc for $req {}
        };
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Read {
        pub sender: Vec<u8>,
        pub after: u64,
        pub limit: u32,
        pub max_size: u64,
    }
    impl_identity_rpc!(Read => Read, Reply = Vec<StoredRow>);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DeliveredObjects {
        pub sender: Vec<u8>,
        pub hashes: Vec<Vec<u8>>,
    }
    impl_identity_rpc!(DeliveredObjects => DeliveredObjects, Reply = Vec<String>);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DeleteDelivered {
        pub sender: Vec<u8>,
        pub hashes: Vec<Vec<u8>>,
        pub objects: Vec<String>,
    }
    impl_identity_rpc!(DeleteDelivered => DeleteDelivered, Reply = ());

    #[derive(Debug, Serialize, Deserialize)]
    pub struct PublishV2 {
        pub manifest: ManifestWire,
        pub signed_prekey_signature: Option<Vec<u8>>,
        pub one_time_prekeys: Vec<Vec<u8>>,
        pub pq_last_resort: Vec<PqPrekeyWire>,
        pub pq_one_time_prekeys: Vec<PqPrekeyWire>,
        pub timestamp: u64,
    }
    impl_identity_rpc!(PublishV2 => PublishV2, Reply = PublishV2Outcome);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct RefillPrekeys {
        pub generation: u64,
        pub one_time_prekeys: Vec<Vec<u8>>,
        pub pq_one_time_prekeys: Vec<PqPrekeyWire>,
        pub max_one_time_prekeys: u64,
        pub max_pq_one_time_prekeys: u64,
        pub timestamp: u64,
    }
    impl_identity_rpc!(RefillPrekeys => RefillPrekeys, Reply = RefillOutcome);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetManifest;
    impl_identity_rpc!(GetManifest => GetManifest, Reply = Option<ManifestWire>);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ClaimBundle {
        pub preferred_suites: Vec<u8>,
    }
    impl_identity_rpc!(ClaimBundle => ClaimBundle, Reply = Option<ClaimedBundleWire>);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct AddInitialMessageV2 {
        pub message: InitialMessageV2Wire,
        pub limit: u64,
    }
    impl_identity_rpc!(AddInitialMessageV2 => AddInitialMessageV2, Reply = Option<u64>);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ListInitialMessages {
        pub limit: u64,
    }
    impl_identity_rpc!(ListInitialMessages => ListInitialMessages, Reply = Vec<InitialMessageV2Wire>);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct AckInitialMessages {
        pub ids: Vec<u64>,
    }
    impl_identity_rpc!(AckInitialMessages => AckInitialMessages, Reply = u64);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct PqSnapshot;
    impl_identity_rpc!(PqSnapshot => PqSnapshot, Reply = PqSnapshotWire);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct AppendIdempotent {
        pub sender: Vec<u8>,
        pub header: Vec<u8>,
        pub content: Content,
        /// The content's length, wherever it is.
        pub size: u64,
        pub initial_message: Option<Vec<u8>>,
        pub delivery_hash: Option<Vec<u8>>,
        pub client_message_id: Option<Vec<u8>>,
    }
    impl_identity_rpc!(AppendIdempotent => AppendIdempotent, Reply = AppendOutcome);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ClaimBundleChecked {
        pub preferred_suites: Vec<u8>,
        pub reject_pq_on_manifest: bool,
    }
    impl_identity_rpc!(ClaimBundleChecked => ClaimBundleChecked, Reply = ClaimBundleOutcome);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DeleteDeliveredAtomic {
        pub sender: Vec<u8>,
        pub hashes: Vec<Vec<u8>>,
    }
    impl_identity_rpc!(DeleteDeliveredAtomic => DeleteDeliveredAtomic, Reply = ());

    #[derive(Debug, Serialize, Deserialize)]
    pub struct AddAttachment {
        pub id: Vec<u8>,
        pub chunks: u32,
        pub token_hash: Vec<u8>,
        pub delete_hash: Vec<u8>,
    }
    impl_attachment_rpc!(AddAttachment => Add, Reply = bool);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetAttachment;
    impl_attachment_rpc!(GetAttachment => Get, Reply = Option<AttachmentRow>);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct NoteChunk {
        pub index: u32,
    }
    impl_attachment_rpc!(NoteChunk => Note, Reply = bool);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DeleteAttachment;
    impl_attachment_rpc!(DeleteAttachment => Delete, Reply = ());
}

/// What the Worker asks of an [`Identity`], about its identity's keys, inbox and the queues of
/// messages to it.
///
/// The five retired legacy v1 slots at tags `0..=4` are intentionally reserved so every surviving
/// variant keeps its exact original postcard wire tag index (`5..=16`) during rolling deploys
/// between older and newer Worker / Durable Object versions. New calls append at `17+`.
#[derive(Debug, Serialize, Deserialize)]
pub enum IdentityCall {
    /// Retired legacy v1 `Publish` slot (tag `0`), preserved for rolling-deploy wire compatibility.
    #[allow(dead_code)]
    RetiredPublishV1,
    /// Retired legacy v1 `TakeBundle` slot (tag `1`), preserved for rolling-deploy wire compatibility.
    #[allow(dead_code)]
    RetiredTakeBundleV1,
    /// Retired legacy v1 `AddInitialMessage` slot (tag `2`), preserved for rolling-deploy wire compatibility.
    #[allow(dead_code)]
    RetiredAddInitialMessageV1,
    /// Retired legacy v1 `TakeInitialMessages` slot (tag `3`), preserved for rolling-deploy wire compatibility.
    #[allow(dead_code)]
    RetiredTakeInitialMessagesV1,
    /// Retired legacy v1 `Append` slot (tag `4`), preserved for rolling-deploy wire compatibility.
    #[allow(dead_code)]
    RetiredAppendV1,
    /// Tag `5`: read queue messages after `after`, bounded by `limit` and `max_size`.
    Read(rpc::Read),
    /// Tag `6`: legacy rolling-deploy helper returning R2 object keys for delivered hashes.
    DeliveredObjects(rpc::DeliveredObjects),
    /// Tag `7`: legacy rolling-deploy helper deleting delivered rows after Worker R2 deletion.
    DeleteDelivered(rpc::DeleteDelivered),
    /// Tag `8`: atomically publish a signed v2 CapabilityManifest and classical + PQ prekeys.
    PublishV2(rpc::PublishV2),
    /// Tag `9`: append classical OPKs and/or signed PQOPKs to the current generation.
    RefillPrekeys(rpc::RefillPrekeys),
    /// Tag `10`: non-consuming read of the stored CapabilityManifest.
    GetManifest(rpc::GetManifest),
    /// Tag `11`: legacy rolling-deploy bundle claim without `reject_pq_on_manifest`.
    ClaimBundle(rpc::ClaimBundle),
    /// Tag `12`: insert a v1 or v2 initial message into the inbox.
    AddInitialMessageV2(rpc::AddInitialMessageV2),
    /// Tag `13`: non-destructively list up to `limit` pending initial messages.
    ListInitialMessages(rpc::ListInitialMessages),
    /// Tag `14`: delete specified initial message IDs, returning count deleted.
    AckInitialMessages(rpc::AckInitialMessages),
    /// Tag `15`: diagnostic snapshot of v2 PQ storage state.
    PqSnapshot(rpc::PqSnapshot),
    /// Tag `16`: idempotent append to the queue from `sender`.
    AppendIdempotent(rpc::AppendIdempotent),
    /// Tag `17`: atomically validate policy and claim a bundle.
    ClaimBundleChecked(rpc::ClaimBundleChecked),
    /// Tag `18`: atomically delete delivered queue rows and durably enqueue R2 object deletes.
    DeleteDeliveredAtomic(rpc::DeleteDeliveredAtomic),
}

/// A message's content: in its row, or in R2 under a name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Content {
    Inline(Vec<u8>),
    Object(String),
}

/// A message of a queue, as kept.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredRow {
    pub sequence: u64,
    pub header: Vec<u8>,
    pub content: Content,
    pub initial_message: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqCommitmentWire {
    pub suite: u8,
    pub prekey_id: Vec<u8>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqPrekeyWire {
    pub suite: u8,
    pub id: Vec<u8>,
    pub encapsulation_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PublishV2Outcome {
    Stored,
    StaleSequence,
    DuplicatePrekey,
}

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
    /// PQ prekeys were supplied for a non-PQ manifest or an unoffered suite.
    SuiteNotOffered,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ClaimBundleOutcome {
    NotFound,
    PqDisabledForPqManifest,
    Claimed(Box<ClaimedBundleWire>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimedBundleWire {
    pub manifest: Option<ManifestWire>,
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_signature: Option<Vec<u8>>,
    pub one_time_prekey: Option<Vec<u8>>,
    pub pq_last_resort: Option<PqPrekeyWire>,
    pub pq_one_time_prekey: Option<PqPrekeyWire>,
}

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
    /// Tag `0`: keep the attachment `id`, unless kept already, until it expires.
    Add(rpc::AddAttachment),
    /// Tag `1`: the attachment, if kept and not expired.
    Get(rpc::GetAttachment),
    /// Tag `2`: note that chunk `index` is in R2.
    Note(rpc::NoteChunk),
    /// Tag `3`: delete the attachment and its chunks.
    Delete(rpc::DeleteAttachment),
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

/// Error returned by [`call_raw`], preserving the DO HTTP status and response body so callers
/// can detect rolling-deploy wire-tag mismatches against older Durable Object instances.
pub enum RpcError {
    Status { status: u16, body: String },
    Other(Error),
}

impl RpcError {
    /// Whether this error indicates an older Durable Object failed to decode a newly added
    /// [`IdentityCall`] enum variant (rolling deploy before the DO restarts).
    ///
    /// Current DOs return HTTP 400 on decode errors and HTTP 500 with `"internal storage error"`
    /// on handler failures; older DOs propagate postcard decode errors from `fetch()` as HTTP 500
    /// with a postcard error body (not `"internal storage error"`).
    pub fn is_unsupported_call(&self) -> bool {
        match self {
            Self::Status { status: 400, .. } => true,
            Self::Status { status: 500, body } => body.trim() != "internal storage error",
            _ => false,
        }
    }

    pub fn into_worker_error(self) -> Error {
        match self {
            Self::Status { status, body } => {
                console_error!("durable object RPC returned HTTP {status}: {body}");
                Error::RustError("durable object call failed".into())
            }
            Self::Other(error) => error,
        }
    }
}

/// Make typed `call` of the object `stub`, preserving non-200 HTTP status for fallback handling.
pub async fn call_raw<R: RpcCall>(stub: &Stub, call: R) -> std::result::Result<R::Reply, RpcError> {
    let body = call.encode().map_err(RpcError::Other)?;
    let request = Request::new_with_init(
        "https://object/call",
        RequestInit::new()
            .with_method(Method::Post)
            .with_body(Some(Uint8Array::from(body.as_slice()).into())),
    )
    .map_err(RpcError::Other)?;
    let mut response = stub
        .fetch_with_request(request)
        .await
        .map_err(RpcError::Other)?;
    let answer = response.bytes().await.map_err(RpcError::Other)?;
    let status = response.status_code();
    if status != 200 {
        return Err(RpcError::Status {
            status,
            body: String::from_utf8_lossy(&answer).into_owned(),
        });
    }
    postcard::from_bytes(&answer).map_err(|e| {
        console_error!("failed to decode durable object RPC reply: {e}");
        RpcError::Other(Error::RustError("invalid durable object reply".into()))
    })
}

/// Make typed `call` of the object `stub`, and decode its statically paired reply type.
pub async fn call<R: RpcCall>(stub: &Stub, call: R) -> Result<R::Reply> {
    call_raw(stub, call)
        .await
        .map_err(RpcError::into_worker_error)
}

/// The call that `request`, to an object, carries.
async fn decode<T: DeserializeOwned>(request: &mut Request) -> Result<T> {
    let body = request.bytes().await?;
    postcard::from_bytes(&body).map_err(|e| {
        console_error!("failed to decode durable object RPC request: {e}");
        Error::RustError("invalid internal request".into())
    })
}

/// The response that answers a typed [`RpcCall`] with `answer`, logging internal errors without
/// returning raw SQL/R2/DO error strings in the HTTP body.
fn answer_rpc<R: RpcCall>(value: Result<R::Reply>) -> Result<Response> {
    answer(value)
}

fn answer<T: Serialize>(answer: Result<T>) -> Result<Response> {
    match answer.and_then(|answer| {
        postcard::to_allocvec(&answer).map_err(|e| Error::RustError(e.to_string()))
    }) {
        Ok(body) => Response::from_bytes(body),
        Err(e) => {
            console_error!("durable object handler failed: {e}");
            Response::error("internal storage error", 500)
        }
    }
}

/// An alarm at `at`, in milliseconds since the Unix epoch, or as late as one may be: a retention
/// of more days than that keeps everything, rather than fails what it would keep.
fn alarm_at(at: u64) -> ScheduledTime {
    ScheduledTime::new(js_sys::Date::new(&(at.min(LATEST) as f64).into()))
}

/// Whether the object's table `name` is there. Only what keeps something creates its object's
/// tables, so that a read of an object nothing was kept in, or whose data was deleted, e.g. a
/// download of an attachment gone, which anyone may try, leaves no storage behind.
fn has_table<S: SqlExec + ?Sized>(sql: &S, name: &str) -> Result<bool> {
    let found: TablesRow = sql.query_one(
        "SELECT count(*) AS tables FROM sqlite_master WHERE type = 'table' AND name = ?",
        params![name]?,
    )?;
    Ok(found.tables > 0)
}

#[derive(Deserialize)]
struct TablesRow {
    tables: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag_byte(value: &impl Serialize) -> u8 {
        let bytes = postcard::to_allocvec(value).expect("postcard encode");
        assert!(!bytes.is_empty());
        bytes[0]
    }

    fn dummy_manifest() -> ManifestWire {
        ManifestWire {
            audience: "relay.example".into(),
            identity_key: vec![1; 32],
            manifest_seq: 1,
            generation: 1,
            issued_at: 1,
            expires_at: 2,
            pq_enabled: false,
            strict_pq: false,
            pq_ratchet_supported: false,
            offered_suites: vec![],
            signed_prekey: vec![2; 32],
            pq_last_resort: vec![],
            signature: vec![3; 64],
        }
    }

    fn dummy_initial() -> InitialMessageV2Wire {
        InitialMessageV2Wire {
            id: 0,
            version: 1,
            sender: vec![1; 32],
            ephemeral_key: vec![2; 32],
            signed_prekey: vec![3; 32],
            one_time_prekey: None,
            header: vec![],
            content: vec![],
            pq_suite: None,
            pq_last_resort: false,
            pq_prekey_id: None,
            pq_ciphertext: None,
            manifest_digest: None,
        }
    }

    #[test]
    fn identity_call_postcard_tags_match_legacy_v1_wire_indices() {
        let rpc_tags: &[(Vec<u8>, u8)] = &[
            (
                rpc::Read {
                    sender: vec![1; 32],
                    after: 0,
                    limit: 10,
                    max_size: 1024,
                }
                .encode()
                .unwrap(),
                5,
            ),
            (
                rpc::DeliveredObjects {
                    sender: vec![1; 32],
                    hashes: vec![],
                }
                .encode()
                .unwrap(),
                6,
            ),
            (
                rpc::DeleteDelivered {
                    sender: vec![1; 32],
                    hashes: vec![],
                    objects: vec![],
                }
                .encode()
                .unwrap(),
                7,
            ),
            (
                rpc::PublishV2 {
                    manifest: dummy_manifest(),
                    signed_prekey_signature: None,
                    one_time_prekeys: vec![],
                    pq_last_resort: vec![],
                    pq_one_time_prekeys: vec![],
                    timestamp: 1,
                }
                .encode()
                .unwrap(),
                8,
            ),
            (
                rpc::RefillPrekeys {
                    generation: 1,
                    one_time_prekeys: vec![],
                    pq_one_time_prekeys: vec![],
                    max_one_time_prekeys: 100,
                    max_pq_one_time_prekeys: 100,
                    timestamp: 1,
                }
                .encode()
                .unwrap(),
                9,
            ),
            (rpc::GetManifest.encode().unwrap(), 10),
            (
                rpc::ClaimBundle {
                    preferred_suites: vec![1],
                }
                .encode()
                .unwrap(),
                11,
            ),
            (
                rpc::AddInitialMessageV2 {
                    message: dummy_initial(),
                    limit: 10,
                }
                .encode()
                .unwrap(),
                12,
            ),
            (rpc::ListInitialMessages { limit: 10 }.encode().unwrap(), 13),
            (
                rpc::AckInitialMessages { ids: vec![1] }.encode().unwrap(),
                14,
            ),
            (rpc::PqSnapshot.encode().unwrap(), 15),
            (
                rpc::AppendIdempotent {
                    sender: vec![1; 32],
                    header: vec![],
                    content: Content::Inline(vec![]),
                    size: 0,
                    initial_message: None,
                    delivery_hash: None,
                    client_message_id: None,
                }
                .encode()
                .unwrap(),
                16,
            ),
            (
                rpc::ClaimBundleChecked {
                    preferred_suites: vec![1],
                    reject_pq_on_manifest: true,
                }
                .encode()
                .unwrap(),
                17,
            ),
            (
                rpc::DeleteDeliveredAtomic {
                    sender: vec![1; 32],
                    hashes: vec![],
                }
                .encode()
                .unwrap(),
                18,
            ),
        ];

        for (encoded, expected_tag) in rpc_tags {
            assert_eq!(encoded[0], *expected_tag);
            let decoded: IdentityCall = postcard::from_bytes(encoded).expect("decode IdentityCall");
            assert_eq!(tag_byte(&decoded), *expected_tag);
        }
        // Unit RPC variants must stay single-byte (identical to legacy unit enum variants).
        assert_eq!(rpc::GetManifest.encode().unwrap(), vec![10]);
        assert_eq!(rpc::PqSnapshot.encode().unwrap(), vec![15]);

        // Retired legacy v1 payloads from an older Worker (tag byte + legacy fields) decode cleanly
        // into the corresponding retired variants so the DO answers 501 instead of misdispatching.
        for (wire, expected_discriminant) in [
            (vec![0, 0xaa, 0xbb, 0xcc], 0u8),
            (vec![1], 1u8),
            (vec![2, 0xde, 0xad], 2u8),
            (vec![3, 0x01, 0x02], 3u8),
            (vec![4, 0xff, 0x00, 0x11], 4u8),
        ] {
            let decoded: IdentityCall = postcard::from_bytes(&wire).expect("decode retired slot");
            assert_eq!(tag_byte(&decoded), expected_discriminant);
        }

        // Verify AppendOutcome, RefillOutcome, ClaimBundleOutcome, and AttachmentCall tags.
        assert_eq!(tag_byte(&AppendOutcome::Appended(1)), 0);
        assert_eq!(tag_byte(&AppendOutcome::Deduplicated(1)), 1);
        assert_eq!(tag_byte(&AppendOutcome::LimitExceeded), 2);

        assert_eq!(
            tag_byte(&RefillOutcome::Stored {
                classical_count: 0,
                pq_counts: vec![],
            }),
            0
        );
        assert_eq!(tag_byte(&RefillOutcome::NotFound), 1);
        assert_eq!(tag_byte(&RefillOutcome::StaleGeneration), 2);
        assert_eq!(tag_byte(&RefillOutcome::StaleTimestamp), 3);
        assert_eq!(tag_byte(&RefillOutcome::DuplicatePrekey), 4);
        assert_eq!(tag_byte(&RefillOutcome::LimitExceeded), 5);
        assert_eq!(tag_byte(&RefillOutcome::SuiteNotOffered), 6);

        assert_eq!(tag_byte(&ClaimBundleOutcome::NotFound), 0);
        assert_eq!(tag_byte(&ClaimBundleOutcome::PqDisabledForPqManifest), 1);

        assert_eq!(
            rpc::AddAttachment {
                id: vec![],
                chunks: 1,
                token_hash: vec![],
                delete_hash: vec![],
            }
            .encode()
            .unwrap()[0],
            0
        );
        assert_eq!(rpc::GetAttachment.encode().unwrap(), vec![1]);
        assert_eq!(rpc::NoteChunk { index: 0 }.encode().unwrap()[0], 2);
        assert_eq!(rpc::DeleteAttachment.encode().unwrap(), vec![3]);
    }

    #[test]
    fn rpc_error_classifies_rolling_deploy_unsupported_calls() {
        assert!(
            RpcError::Status {
                status: 400,
                body: "malformed internal request".into(),
            }
            .is_unsupported_call()
        );
        assert!(
            RpcError::Status {
                status: 500,
                body: "Found an unknown enum variant".into(),
            }
            .is_unsupported_call()
        );
        assert!(
            !RpcError::Status {
                status: 500,
                body: "internal storage error".into(),
            }
            .is_unsupported_call()
        );
        assert!(
            !RpcError::Status {
                status: 503,
                body: "overloaded".into(),
            }
            .is_unsupported_call()
        );
        assert!(!RpcError::Other(Error::RustError("network".into())).is_unsupported_call());
    }
}
