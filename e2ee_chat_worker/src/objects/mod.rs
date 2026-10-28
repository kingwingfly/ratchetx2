//! The Durable Objects that keep the server's state: an [`Identity`] per identity key, and an
//! [`Attachment`] per attachment, each with its own SQLite database. Each call the Worker makes
//! to one, encoded with postcard, is served whole before the next, so that it is atomic, as the
//! storage traits require; and as each identity's data is its own object's, the server grows
//! with its users rather than through one database.

mod attachment;
mod identity;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use worker::{
    Env, Error, Method, ObjectNamespace, Request, RequestInit, Response, Result, SqlStorageValue,
    Stub, js_sys::Uint8Array,
};

pub use attachment::{Attachment, DEFAULT_FILE_RETENTION_DAYS};
pub use identity::Identity;

/// The binding of the identities' namespace.
const IDENTITIES: &str = "IDENTITIES";
/// The binding of the attachments' namespace.
const ATTACHMENTS: &str = "ATTACHMENTS";
/// JavaScript's largest exact integer, as SQLite's integers cross into JavaScript as numbers.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

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

/// What the Worker asks of an [`Identity`], about its identity's keys, inbox and the queues of
/// messages to it.
#[derive(Debug, Serialize, Deserialize)]
pub enum IdentityCall {
    /// Store the bundle, and replace the one-time prekeys, if `timestamp` is newer than the
    /// stored bundle's. Answers whether it did.
    Publish {
        signed_prekey: Vec<u8>,
        signature: Vec<u8>,
        timestamp: u64,
        one_time_prekeys: Vec<Vec<u8>>,
    },
    /// The bundle, with a one-time prekey, which goes. Answers an `Option<TakenBundle>`.
    TakeBundle,
    /// Add an initial message to the inbox, unless it holds `limit`. Answers whether it did.
    AddInitialMessage { message: InitialMessage, limit: u64 },
    /// Take the inbox, if `timestamp` is newer than the last take's. Answers an
    /// `Option<Vec<InitialMessage>>`.
    TakeInitialMessages { timestamp: u64 },
    /// Append a message to the queue from `sender`. Answers its sequence number.
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
    /// `max_size` bytes but for the first. Answers a `Vec<StoredRow>`.
    Read {
        sender: Vec<u8>,
        after: u64,
        limit: u32,
        max_size: u64,
    },
    /// The R2 objects of the messages from `sender` whose delivery hashes are among `hashes`.
    /// Answers a `Vec<String>`.
    DeliveredObjects {
        sender: Vec<u8>,
        hashes: Vec<Vec<u8>>,
    },
    /// Delete the messages from `sender` whose delivery hashes are among `hashes`; only those
    /// without R2 objects if `inline_only`. Answers `()`.
    DeleteDelivered {
        sender: Vec<u8>,
        hashes: Vec<Vec<u8>>,
        inline_only: bool,
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

/// Bind an integer, which SQLite keeps exactly, but JavaScript only up to 2^53: beyond, it is
/// clamped, as only absurd timestamps get there.
fn integer(value: u64) -> SqlStorageValue {
    SqlStorageValue::Integer(value.min(MAX_SAFE_INTEGER) as i64)
}

/// Bind bytes as a BLOB.
fn blob(bytes: &[u8]) -> SqlStorageValue {
    SqlStorageValue::Blob(bytes.to_vec())
}
