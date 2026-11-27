//! The Durable Objects that keep the server's state: an [`IdentityV2`] per identity key, and an
//! [`AttachmentV2`] per attachment, each with its own SQLite database. Each call the Worker makes
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

pub use attachment::{AttachmentV2, DEFAULT_FILE_RETENTION_DAYS};
pub use identity::{
    HEADER_DEPLOYMENT_AUTH, HEADER_SESSION_EXPIRES, HEADER_VERIFIED_AUDIENCE,
    HEADER_VERIFIED_IDENTITY, HEADER_VERIFIED_NONCE, HEADER_VERIFIED_TS, IdentityV2,
    WS_SUBPROTOCOL_V2,
};
use sql::{SqlExec, params};

/// The binding of the identities' namespace.
const IDENTITIES: &str = "IDENTITIES";
/// The binding of the attachments' namespace.
const ATTACHMENTS: &str = "ATTACHMENTS";
/// The latest an alarm may be set for, in milliseconds since the Unix epoch: 2189-01-01, as the
/// runtime refuses alarms after 2189.
const LATEST: u64 = 6_911_049_600_000;
/// How long, in milliseconds, after an alarm that failed (e.g. R2 unreachable during attachment
/// cleanup), the next tries again: the runtime retries one only for a few minutes, and nothing
/// else would set it again.
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

/// Marker for RPCs routed to an [`IdentityV2`] Durable Object.
pub trait IdentityRpc: RpcCall {}

/// Marker for RPCs routed to an [`AttachmentV2`] Durable Object.
pub trait AttachmentRpc: RpcCall {}

/// Outcome of an [`IdentityCall::AddInitialMessageV2`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddInitialOutcome {
    /// Stored or matched idempotently at `id` (`inserted == true` only for a brand-new row).
    Added { id: u64, inserted: bool },
    /// Inbox reached its configured unexpired message cap.
    LimitExceeded,
    /// Recipient has no published capability manifest (no DO tables allocated).
    NotFound,
    /// The initial message's `signed_prekey` is no longer in the recipient's retained generations.
    StalePrekey,
    /// Existing unexpired row for `(sender, ephemeral_key)` had a different payload.
    PayloadMismatch,
    /// Monotonic inbox ID exceeded `MAX_SAFE_INTEGER`.
    SequenceOverflow,
}

/// Outcome of an [`IdentityCall::RefillPrekeys`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Outcome of an [`IdentityCall::AppendIdempotent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppendOutcome {
    /// A new message row was committed at this unified sequence number.
    Appended(u64),
    /// Deduplicated against a previously committed `(token_hash, client_message_id)`.
    Deduplicated(u64),
    /// The write token hash is unknown or revoked (checked before deduplication).
    WriteTokenRejected,
    /// Rejected before commit because per-peer or per-recipient backlog quotas are temporarily full.
    MailboxFull,
    /// Rejected before commit because a permanent mailbox bound (e.g. sequence ceiling) was hit.
    LimitExceeded,
}

/// Outcome of an [`IdentityCall::ReadMailbox`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadMailboxOutcome {
    /// A bounded page of messages in ascending unified sequence order.
    Page(storage::MailboxPage),
    /// The piggybacked `ack_up_to_sequence` exceeded `recipient_stats.last_sequence`.
    InvalidAckSequence,
}

/// Outcome of an [`IdentityCall::AckMessages`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckMessagesOutcome {
    /// Deleted this many rows (`<= up_to_sequence`).
    Acked(u64),
    /// `up_to_sequence` was `0`, exceeded `MAX_SAFE_INTEGER`, or exceeded `last_sequence`.
    InvalidSequence,
}

/// Outcome of an [`IdentityCall::RegisterWriteToken`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisterWriteTokenOutcome {
    Registered,
    NotFound,
    StaleVersion,
    StaleTimestamp,
    InvalidArgument,
    LimitExceeded,
}

/// Outcome of an [`IdentityCall::RevokeWriteToken`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevokeWriteTokenOutcome {
    Revoked(u32),
    NotFound,
    InvalidArgument,
}

/// Typed request payloads for [`IdentityCall`] and [`AttachmentCall`].
///
/// Using newtype enum variants in [`IdentityCall`] and [`AttachmentCall`] keeps postcard wire
/// encoding compact while statically associating each RPC with its exact reply type via
/// [`RpcCall`].
pub mod rpc {
    use serde::{Deserialize, Serialize};
    use storage::{
        Bytes, ClaimOutcome, PqStorageSnapshot, PublicKey, PublishV2Record, PublishV2Status,
        RefillPrekeysRecord, RegisterWriteTokenRecord, RevokeWriteTokenRecord, StoredAttachment,
        StoredCapabilityManifest, StoredInitialMessageV2, WriteTokenHash,
    };
    use worker::{Error, Result};

    use super::{
        AckMessagesOutcome, AddInitialOutcome, AppendOutcome, AttachmentCall, AttachmentRpc,
        IdentityCall, IdentityRpc, ReadMailboxOutcome, RefillOutcome, RegisterWriteTokenOutcome,
        RevokeWriteTokenOutcome, RpcCall,
    };

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
    pub struct PublishV2 {
        pub record: PublishV2Record,
    }
    impl_identity_rpc!(PublishV2 => PublishV2, Reply = PublishV2Status);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct RefillPrekeys {
        pub record: RefillPrekeysRecord,
    }
    impl_identity_rpc!(RefillPrekeys => RefillPrekeys, Reply = RefillOutcome);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetManifest;
    impl_identity_rpc!(GetManifest => GetManifest, Reply = Option<StoredCapabilityManifest>);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ClaimBundleChecked {
        pub preferred_suites: Vec<u8>,
        pub reject_pq_on_manifest: bool,
    }
    impl_identity_rpc!(ClaimBundleChecked => ClaimBundleChecked, Reply = ClaimOutcome);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct AddInitialMessageV2 {
        pub message: StoredInitialMessageV2,
        pub limit: u64,
    }
    impl_identity_rpc!(AddInitialMessageV2 => AddInitialMessageV2, Reply = AddInitialOutcome);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ListInitialMessages {
        pub recipient: PublicKey,
        pub after_id: u64,
        pub limit: u64,
    }
    impl_identity_rpc!(ListInitialMessages => ListInitialMessages, Reply = Vec<StoredInitialMessageV2>);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct AckInitialMessages {
        pub ids: Vec<u64>,
    }
    impl_identity_rpc!(AckInitialMessages => AckInitialMessages, Reply = u64);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct PqSnapshot;
    impl_identity_rpc!(PqSnapshot => PqSnapshot, Reply = PqStorageSnapshot);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct AppendIdempotent {
        pub token_hash: WriteTokenHash,
        pub header: Bytes,
        pub content: Bytes,
        pub initial_message: Option<Bytes>,
        pub client_message_id: Option<[u8; 16]>,
    }
    impl_identity_rpc!(AppendIdempotent => AppendIdempotent, Reply = AppendOutcome);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ReadMailbox {
        pub after_sequence: u64,
        pub limit: u32,
        pub max_size: u64,
        pub ack_up_to_sequence: u64,
    }
    impl_identity_rpc!(ReadMailbox => ReadMailbox, Reply = ReadMailboxOutcome);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct AckMessages {
        pub up_to_sequence: u64,
    }
    impl_identity_rpc!(AckMessages => AckMessages, Reply = AckMessagesOutcome);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct RegisterWriteToken {
        pub record: RegisterWriteTokenRecord,
    }
    impl_identity_rpc!(RegisterWriteToken => RegisterWriteToken, Reply = RegisterWriteTokenOutcome);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct RevokeWriteToken {
        pub record: RevokeWriteTokenRecord,
    }
    impl_identity_rpc!(RevokeWriteToken => RevokeWriteToken, Reply = RevokeWriteTokenOutcome);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct AddAttachment {
        pub attachment: StoredAttachment,
    }
    impl_attachment_rpc!(AddAttachment => Add, Reply = bool);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetAttachment;
    impl_attachment_rpc!(GetAttachment => Get, Reply = Option<StoredAttachment>);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct NoteChunk {
        pub index: u32,
    }
    impl_attachment_rpc!(NoteChunk => Note, Reply = bool);

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DeleteAttachment;
    impl_attachment_rpc!(DeleteAttachment => Delete, Reply = ());
}

/// What the Worker asks of an [`IdentityV2`], about its identity's manifest, prekeys, inbox,
/// write-token grants, and unified sealed-sender-lite mailbox queue.
///
/// Compacted cleanly from tag `0` on the fresh `IdentityV2` Durable Object class.
#[derive(Debug, Serialize, Deserialize)]
pub enum IdentityCall {
    /// Tag `0`: atomically publish a signed v2 CapabilityManifest and classical + PQ prekeys.
    PublishV2(rpc::PublishV2),
    /// Tag `1`: append classical OPKs and/or signed PQOPKs to the current generation.
    RefillPrekeys(rpc::RefillPrekeys),
    /// Tag `2`: non-consuming read of the stored CapabilityManifest.
    GetManifest(rpc::GetManifest),
    /// Tag `3`: atomically validate policy and claim a bundle.
    ClaimBundleChecked(rpc::ClaimBundleChecked),
    /// Tag `4`: idempotently insert a v1 or v2 initial message into the inbox.
    AddInitialMessageV2(rpc::AddInitialMessageV2),
    /// Tag `5`: non-destructively list up to `limit` pending initial messages with `id > after_id`.
    ListInitialMessages(rpc::ListInitialMessages),
    /// Tag `6`: delete specified initial message IDs, returning count deleted.
    AckInitialMessages(rpc::AckInitialMessages),
    /// Tag `7`: diagnostic snapshot of v2 PQ storage state.
    PqSnapshot(rpc::PqSnapshot),
    /// Tag `8`: auth-before-dedup idempotent append to the recipient's unified mailbox.
    AppendIdempotent(rpc::AppendIdempotent),
    /// Tag `9`: read unified mailbox page after `after_sequence` with optional prefix ACK.
    ReadMailbox(rpc::ReadMailbox),
    /// Tag `10`: explicitly delete all messages with `sequence <= up_to_sequence`.
    AckMessages(rpc::AckMessages),
    /// Tag `11`: register a recipient-versioned write-token hash for a peer slot.
    RegisterWriteToken(rpc::RegisterWriteToken),
    /// Tag `12`: revoke one or all write tokens for a peer slot and raise the version floor.
    RevokeWriteToken(rpc::RevokeWriteToken),
}

/// What the Worker asks of an [`AttachmentV2`].
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

/// Make typed `call` of the object `stub`, and decode its statically paired reply type.
pub async fn call<R: RpcCall>(stub: &Stub, call: R) -> Result<R::Reply> {
    let body = call.encode()?;
    let request = Request::new_with_init(
        "https://object/call",
        RequestInit::new()
            .with_method(Method::Post)
            .with_body(Some(Uint8Array::from(body.as_slice()).into())),
    )?;
    let mut response = stub.fetch_with_request(request).await?;
    let answer = response.bytes().await?;
    let status = response.status_code();
    if status != 200 {
        let detail = String::from_utf8_lossy(&answer);
        console_error!("durable object RPC returned HTTP {status}: {detail}");
        return Err(Error::RustError("durable object call failed".into()));
    }
    postcard::from_bytes(&answer).map_err(|e| {
        console_error!("failed to decode durable object RPC reply: {e}");
        Error::RustError("invalid durable object reply".into())
    })
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
    use storage::{
        Bytes, PublishV2Record, RefillPrekeysRecord, RegisterWriteTokenRecord,
        RevokeWriteTokenRecord, StoredAttachment, StoredCapabilityManifest, StoredInitialMessageV2,
    };

    use super::*;

    fn tag_byte(value: &impl Serialize) -> u8 {
        let bytes = postcard::to_allocvec(value).expect("postcard encode");
        assert!(!bytes.is_empty());
        bytes[0]
    }

    fn dummy_manifest() -> StoredCapabilityManifest {
        StoredCapabilityManifest {
            audience: "relay.example".into(),
            identity_key: [1; 32],
            manifest_seq: 1,
            generation: 1,
            issued_at: 1,
            expires_at: 2,
            pq_enabled: false,
            strict_pq: false,
            pq_ratchet_supported: false,
            offered_suites: vec![],
            signed_prekey: [2; 32],
            pq_last_resort: vec![],
            signature: [3; 64],
        }
    }

    fn dummy_initial() -> StoredInitialMessageV2 {
        StoredInitialMessageV2 {
            id: 0,
            version: 1,
            sender: [1; 32],
            recipient: [9; 32],
            ephemeral_key: [2; 32],
            signed_prekey: [3; 32],
            one_time_prekey: None,
            header: Bytes::new(),
            content: Bytes::new(),
            pq_suite: None,
            pq_last_resort: false,
            pq_prekey_id: None,
            pq_ciphertext: None,
            manifest_digest: None,
        }
    }

    #[test]
    fn identity_call_and_attachment_call_postcard_tags_are_compacted_from_zero() {
        let rpc_tags: &[(Vec<u8>, u8)] = &[
            (
                rpc::PublishV2 {
                    record: PublishV2Record {
                        manifest: dummy_manifest(),
                        signed_prekey_signature: None,
                        one_time_prekeys: vec![],
                        pq_last_resort: vec![],
                        pq_one_time_prekeys: vec![],
                        timestamp: 1,
                    },
                }
                .encode()
                .unwrap(),
                0,
            ),
            (
                rpc::RefillPrekeys {
                    record: RefillPrekeysRecord {
                        identity_key: [1; 32],
                        generation: 1,
                        one_time_prekeys: vec![],
                        pq_one_time_prekeys: vec![],
                        max_one_time_prekeys: 100,
                        max_pq_one_time_prekeys: 100,
                        timestamp: 1,
                    },
                }
                .encode()
                .unwrap(),
                1,
            ),
            (rpc::GetManifest.encode().unwrap(), 2),
            (
                rpc::ClaimBundleChecked {
                    preferred_suites: vec![1],
                    reject_pq_on_manifest: true,
                }
                .encode()
                .unwrap(),
                3,
            ),
            (
                rpc::AddInitialMessageV2 {
                    message: dummy_initial(),
                    limit: 10,
                }
                .encode()
                .unwrap(),
                4,
            ),
            (
                rpc::ListInitialMessages {
                    recipient: [9; 32],
                    after_id: 0,
                    limit: 10,
                }
                .encode()
                .unwrap(),
                5,
            ),
            (
                rpc::AckInitialMessages { ids: vec![1] }.encode().unwrap(),
                6,
            ),
            (rpc::PqSnapshot.encode().unwrap(), 7),
            (
                rpc::AppendIdempotent {
                    token_hash: [4; 32],
                    header: Bytes::new(),
                    content: Bytes::new(),
                    initial_message: None,
                    client_message_id: None,
                }
                .encode()
                .unwrap(),
                8,
            ),
            (
                rpc::ReadMailbox {
                    after_sequence: 0,
                    limit: 10,
                    max_size: 1024,
                    ack_up_to_sequence: 0,
                }
                .encode()
                .unwrap(),
                9,
            ),
            (rpc::AckMessages { up_to_sequence: 1 }.encode().unwrap(), 10),
            (
                rpc::RegisterWriteToken {
                    record: RegisterWriteTokenRecord {
                        recipient: [1; 32],
                        peer_slot_id: [2; 32],
                        token_hash: [3; 32],
                        grant_version: 1,
                        pin_active: true,
                        timestamp: 0,
                    },
                }
                .encode()
                .unwrap(),
                11,
            ),
            (
                rpc::RevokeWriteToken {
                    record: RevokeWriteTokenRecord {
                        recipient: [1; 32],
                        peer_slot_id: [2; 32],
                        token_hash: None,
                        min_grant_version: 1,
                    },
                }
                .encode()
                .unwrap(),
                12,
            ),
        ];

        for (encoded, expected_tag) in rpc_tags {
            assert_eq!(encoded[0], *expected_tag);
            let decoded: IdentityCall = postcard::from_bytes(encoded).expect("decode IdentityCall");
            assert_eq!(tag_byte(&decoded), *expected_tag);
        }
        assert_eq!(rpc::GetManifest.encode().unwrap(), vec![2]);
        assert_eq!(rpc::PqSnapshot.encode().unwrap(), vec![7]);

        assert_eq!(
            rpc::AddAttachment {
                attachment: StoredAttachment {
                    id: [1; 16],
                    chunks: 1,
                    token_hash: [2; 32],
                    delete_hash: [3; 32],
                    uploaded: 0,
                },
            }
            .encode()
            .unwrap()[0],
            0
        );
        assert_eq!(rpc::GetAttachment.encode().unwrap(), vec![1]);
        assert_eq!(rpc::NoteChunk { index: 0 }.encode().unwrap()[0], 2);
        assert_eq!(rpc::DeleteAttachment.encode().unwrap(), vec![3]);
    }
}
