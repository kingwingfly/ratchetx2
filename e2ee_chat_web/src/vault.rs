//! The vault: everything the client keeps, in IndexedDB, encrypted with a key derived from the
//! passphrase.
//!
//! The database `e2ee-chat` has one object store of records by name:
//! - `vault`: the [`VaultHeader`], in the clear: the salt and the parameters of the KDF.
//! - `state`: the [`AppState`]: the identity, the prekeys, the contacts and their sessions.
//! - `history/<peer in hex>/<index>`: one [`HistoryEntry`] of a chat, without the bytes of its
//!   file, if any, which are in `file/<peer in hex>/<index>`, a [`FileRecord`], read when shown.
//! - `outbox/<peer in hex>/<index>`: a message of a chat, the history entry `index`, waiting to
//!   be pushed: an [`OutgoingRecord`]. The state only lists them, so that saving it stays small.
//! - `attachment/<peer in hex>/<id in hex>/<index>`: a chunk of an attachment in a chat, as the
//!   server has it: encrypted under the attachment's key, which only the history holds.
//! - `upload/<peer in hex>/<id in hex>`: a [`PendingUpload`], an attachment this client uploads
//!   or uploaded, with its upload token, which can delete it from the server.
//!
//! But for the header and the chunks, each record is `nonce ‖ AES-256-GCM(key, record)`, with the
//! record's name as associated data so that one record cannot pass for another. The key is
//! Argon2id of the passphrase.

use std::fmt;

use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit,
    aead::{Aead, Payload, array::typenum::Unsigned},
};
use argon2::{Algorithm, Argon2, Params, Version};
use idb::{Database, DatabaseEvent, Factory, KeyRange, ObjectStoreParams, TransactionMode};
use js_sys::Uint8Array;
use prost::Message;
use session::{PublicKey, Sealed, protocol::mailbox::PushRequest};
use wasm_bindgen::JsValue;
use zeroize::Zeroizing;

use crate::{
    content::{Content, Events, Kind},
    preview::{self, Sort},
    state::Delivery,
    util::{from_hex, hex},
};

const DATABASE: &str = "e2ee-chat";
const STORE: &str = "records";
const HEADER: &str = "vault";
const STATE: &str = "state";

/// AES-GCM nonce length.
const NONCE_LEN: usize = <Aes256Gcm as AeadCore>::NonceSize::USIZE;

/// The KDF's salt and parameters, in the clear.
#[derive(Clone, PartialEq, prost::Message)]
pub struct VaultHeader {
    #[prost(bytes = "vec", tag = "1")]
    pub salt: Vec<u8>,
    /// Argon2id's memory, in KiB.
    #[prost(uint32, tag = "2")]
    pub memory: u32,
    #[prost(uint32, tag = "3")]
    pub iterations: u32,
    #[prost(uint32, tag = "4")]
    pub parallelism: u32,
}

impl VaultHeader {
    /// A new random salt, and OWASP's recommended Argon2id parameters.
    fn new() -> Self {
        let mut salt = vec![0; 16];
        getrandom::fill(&mut salt).expect("crypto.getRandomValues");
        Self {
            salt,
            memory: 19 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }

    fn derive_key(&self, passphrase: &str) -> Result<Zeroizing<[u8; 32]>> {
        let params = Params::new(self.memory, self.iterations, self.parallelism, Some(32))
            .map_err(|e| Error::Corrupt(e.to_string()))?;
        let mut key = Zeroizing::new([0; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), &self.salt, key.as_mut_slice())
            .map_err(|e| Error::Corrupt(e.to_string()))?;
        Ok(key)
    }
}

/// Everything but the chats' histories.
#[derive(Clone, PartialEq, prost::Message)]
pub struct AppState {
    #[prost(message, optional, tag = "1")]
    pub client: Option<session::proto::ClientState>,
    /// The server's address; empty for the page's own.
    #[prost(string, tag = "2")]
    pub server: String,
    /// The name this client goes by, which its greetings carry.
    #[prost(string, tag = "3")]
    pub name: String,
    #[prost(message, repeated, tag = "4")]
    pub contacts: Vec<ContactState>,
    /// When the prekeys were last published; 0 if never.
    #[prost(uint64, tag = "5")]
    pub published_at: u64,
    /// One-time prekeys used since then.
    #[prost(uint32, tag = "6")]
    pub used_one_time_prekeys: u32,
    /// The messages telling peers that this client deleted their chats, to push.
    #[prost(message, repeated, tag = "7")]
    pub farewells: Vec<Farewell>,
}

/// A peer, and the session with it.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ContactState {
    #[prost(bytes = "vec", tag = "1")]
    pub peer: Vec<u8>,
    #[prost(string, tag = "2")]
    pub name: String,
    /// The peer started the session, and it is not accepted yet.
    #[prost(bool, tag = "3")]
    pub request: bool,
    #[prost(message, optional, tag = "4")]
    pub session: Option<session::proto::SessionState>,
    /// Messages not pushed yet, in order.
    #[prost(message, repeated, tag = "5")]
    pub outbox: Vec<Outgoing>,
    #[prost(uint32, tag = "7")]
    pub unread: u32,
    /// Number of entries in the history.
    #[prost(uint64, tag = "8")]
    pub history_len: u64,
    /// When the last message was sent or received.
    #[prost(uint64, tag = "9")]
    pub last_activity: u64,
    /// The name the peer gave in its greeting.
    #[prost(string, tag = "10")]
    pub hello_name: String,
    /// The chat's Lamport clock: the highest place of its messages, both ways, so far.
    #[prost(uint64, tag = "11")]
    pub clock: u64,
    /// The place of the peer's last message, which the next one goes after.
    #[prost(uint64, tag = "12")]
    pub peer_last: u64,
    /// The highest place of this client's messages that the peer says it read, which the peer's
    /// next message goes after.
    #[prost(uint64, tag = "13")]
    pub read_by_peer: u64,
    /// This client's messages pushed whose last event has not come, oldest first.
    #[prost(message, repeated, tag = "14")]
    pub awaiting: Vec<Awaiting>,
    /// The clocks of the peer's messages that came while the chat was not on screen, which are
    /// read once it is.
    #[prost(uint64, repeated, tag = "15")]
    pub unseen: Vec<u64>,
    /// What to tell the peer it did with its messages, once it can be.
    #[prost(message, optional, tag = "16")]
    pub events: Option<Events>,
}

/// A message this client pushed, waiting for the peer to read it, or to download its attachment.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Awaiting {
    /// Its place, which events name it by.
    #[prost(uint64, tag = "1")]
    pub place: u64,
    /// Its entry in the history.
    #[prost(uint64, tag = "2")]
    pub history_index: u64,
    /// Whether the peer read it already, its attachment waiting to be downloaded.
    #[prost(bool, tag = "3")]
    pub read: bool,
    /// Whether it is an attachment, which waits for both.
    #[prost(bool, tag = "4")]
    pub attachment: bool,
}

/// An attachment being uploaded, kept so that the upload can go on after the page goes, with
/// the file chosen again: from `uploaded`, once the file still has the hash it had. Once done, it
/// stays, so that its upload token can delete it from the server.
///
/// One whose upload has not started, as the server keeps files only for those signed in to it,
/// has no token yet, and is kept under an ID of this client's: its message waits in the chat, at
/// `history_index`, for the upload to start, which then keeps it under the server's ID.
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct PendingUpload {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub token: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub key: Vec<u8>,
    #[prost(string, tag = "4")]
    pub name: String,
    #[prost(string, tag = "5")]
    pub mime: String,
    #[prost(uint64, tag = "6")]
    pub size: u64,
    /// Chunks the server has, which the upload goes on after.
    #[prost(uint32, tag = "7")]
    pub uploaded: u32,
    /// Chunks that may have been encrypted, and so may be on their way: the file must still
    /// begin with them, as another plaintext under the same key and nonce would give the key
    /// away.
    #[prost(uint32, tag = "8")]
    pub encrypted: u32,
    /// SHA-256 of the file's first `encrypted` chunks. It never leaves the vault: it would let
    /// the server check a guess of the file.
    #[prost(bytes = "vec", tag = "9")]
    pub prefix_hash: Vec<u8>,
    /// The attachment was sent to the chat, which downloads it as it is uploaded.
    #[prost(bool, tag = "10")]
    pub announced: bool,
    /// The upload is done.
    #[prost(bool, tag = "11")]
    pub done: bool,
    /// The history entry of its message, while its upload has not started.
    #[prost(uint64, tag = "12")]
    pub history_index: u64,
    /// When the server deletes it, in milliseconds since the Unix epoch, as it said as the
    /// upload started; 0 if it did not.
    #[prost(uint64, tag = "13")]
    pub expires: u64,
}

impl PendingUpload {
    /// Whether its upload started, so that the server has it, under its ID.
    pub fn started(&self) -> bool {
        !self.token.is_empty()
    }

    /// Whether it is done and the server deleted it by `now`, the server's time, so that its
    /// token is no use, and it need not be kept.
    pub fn expired(&self, now: u64) -> bool {
        self.done && self.expires != 0 && self.expires <= now
    }
}

impl fmt::Debug for PendingUpload {
    /// Shows no key, token or hash.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingUpload")
            .field("name", &self.name)
            .field("size", &self.size)
            .field("uploaded", &self.uploaded)
            .finish_non_exhaustive()
    }
}

/// A message not pushed yet, whose [`OutgoingRecord`] is kept apart.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Outgoing {
    /// Its entry in the history.
    #[prost(uint64, tag = "2")]
    pub history_index: u64,
    /// Whether it is encrypted, as it goes next; otherwise it waits for the ones before it to
    /// go, or for a session to send on.
    #[prost(bool, tag = "4")]
    pub sealed: bool,
    /// Its place, given as it was encrypted.
    #[prost(uint64, tag = "5")]
    pub clock: u64,
    /// It is an attachment whose upload has not started, as the server keeps files only for
    /// those signed in to it: it waits, and the ones after it with it, until it starts and the
    /// message has the attachment.
    #[prost(bool, tag = "6")]
    pub awaits_upload: bool,
}

/// What a message not pushed yet is: its content, encrypted just before it goes, once its place
/// in the chat is known.
#[derive(Clone, PartialEq, prost::Message)]
pub struct OutgoingRecord {
    /// The message, once encrypted.
    #[prost(message, optional, tag = "1")]
    pub message: Option<party::EncryptedMessage>,
    /// Its content, until it is encrypted.
    #[prost(bytes = "vec", tag = "3")]
    pub content: Vec<u8>,
    /// SHA-256 of its delivery token, once encrypted, under the key of the session it was
    /// encrypted on, see `session::Sealed`.
    #[prost(bytes = "vec", tag = "4")]
    pub delivery_hash: Vec<u8>,
}

impl OutgoingRecord {
    /// The record of `sealed`, encrypted.
    pub fn sealed(sealed: Sealed) -> Self {
        Self {
            message: Some(sealed.message),
            content: vec![],
            delivery_hash: sealed.delivery_hash.map(Vec::from).unwrap_or_default(),
        }
    }

    /// The message to push, once encrypted.
    pub fn to_push(&self) -> Sealed {
        Sealed {
            message: self.message.clone().unwrap_or_default(),
            delivery_hash: self.delivery_hash.as_slice().try_into().ok(),
        }
    }
}

/// The bytes of a file in the history.
#[derive(Clone, PartialEq, prost::Message)]
pub struct FileRecord {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

/// The name of the [`OutgoingRecord`] of the history entry `index` of the chat with `peer`.
pub fn outbox_key(peer: &PublicKey, index: u64) -> String {
    format!("outbox/{}/{index:020}", hex(peer))
}

/// The name of the [`FileRecord`] of the history entry `index` of the chat with `peer`.
fn file_key(peer: &PublicKey, index: u64) -> String {
    format!("file/{}/{index:020}", hex(peer))
}

/// A message telling a peer that this client deleted the chat, not pushed yet: its push, made
/// while the chat's session was there.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Farewell {
    #[prost(message, optional, tag = "1")]
    pub push: Option<PushRequest>,
}

/// A message sent or received.
#[derive(Clone, PartialEq, prost::Message)]
pub struct HistoryEntry {
    #[prost(bool, tag = "1")]
    pub outgoing: bool,
    /// When it was sent or received.
    #[prost(uint64, tag = "2")]
    pub at: u64,
    /// Its content, with the clock its sender gave it.
    #[prost(message, optional, tag = "3")]
    pub content: Option<Content>,
    /// How far it got, if it is this client's.
    #[prost(enumeration = "Delivery", tag = "4")]
    pub delivery: i32,
    /// Its place in the chat, which it shows by: its clock, unless the peer gave one that would
    /// put it before the peer's earlier messages; 0 for this client's until it is pushed.
    #[prost(uint64, tag = "5")]
    pub place: u64,
    /// The size of its file, if its content is one, whose bytes are in a record of their own.
    #[prost(uint64, tag = "6")]
    pub file: u64,
    /// The MIME type of its file, if it is an image, a video or audio, by its first bytes:
    /// the chat shows it in place. Empty otherwise.
    #[prost(string, tag = "7")]
    pub media: String,
    /// The sort of its file, by its content, which the chat's file browser groups it by.
    #[prost(enumeration = "Sort", tag = "8")]
    pub sort: i32,
}

impl HistoryEntry {
    /// The entry without the bytes of its file, if any, which it notes, and the bytes. One read
    /// back from the history has none, and notes its file already.
    fn without_file(&self) -> (Self, Option<Vec<u8>>) {
        let mut entry = self.clone();
        let data = match entry
            .content
            .as_mut()
            .and_then(|content| content.kind.as_mut())
        {
            // Typed as the chat shows it when it comes, e.g. a BMP of the TUI client's.
            Some(Kind::File(file)) if !file.data.is_empty() => {
                entry.media = preview::media_mime(&file.name, &file.mime, &file.data)
                    .unwrap_or_default()
                    .to_string();
                entry.sort = preview::sort(&file.name, &file.mime, &file.data).into();
                std::mem::take(&mut file.data)
            }
            Some(Kind::Image(data)) if !data.is_empty() => {
                entry.media = preview::media_mime("image", "", data)
                    .unwrap_or_default()
                    .to_string();
                entry.sort = preview::sort("image", "", data).into();
                std::mem::take(data)
            }
            _ => return (entry, None),
        };
        entry.file = data.len() as u64;
        (entry, Some(data))
    }
}

/// The name of a history entry's record.
pub fn history_key(peer: &PublicKey, index: u64) -> String {
    // Zero-padded to u64::MAX's digits, so that the names sort by index.
    format!("history/{}/{index:020}", hex(peer))
}

/// Every name that starts with `prefix`, which ends with `/`: `0` sorts right after `/`.
fn prefix_range(prefix: &str) -> Result<KeyRange> {
    Ok(KeyRange::bound(
        &prefix.into(),
        &format!("{}0", prefix.trim_end_matches('/')).into(),
        None,
        Some(true),
    )?)
}

/// The name of the upload `id`, in the chat with `peer`.
fn upload_key(peer: &PublicKey, id: &[u8]) -> String {
    format!("upload/{}/{}", hex(peer), hex(id))
}

/// The name of chunk `index` of the attachment `id`, in the chat with `peer`.
fn chunk_key(peer: &PublicKey, id: &[u8], index: u32) -> String {
    // Zero-padded to u32::MAX's digits, so that the names sort by index.
    format!("attachment/{}/{}/{index:010}", hex(peer), hex(id))
}

/// The history entries of the chat with `peer`, from index `first` to `last`.
fn history_range(peer: &PublicKey, first: u64, last: u64) -> Result<KeyRange> {
    Ok(KeyRange::bound(
        &history_key(peer, first).into(),
        &history_key(peer, last).into(),
        None,
        None,
    )?)
}

#[derive(Debug)]
pub enum Error {
    /// IndexedDB failed, e.g. it is not available in a private window.
    Storage(String),
    /// The passphrase does not open the vault.
    WrongPassphrase,
    /// A record does not decode.
    Corrupt(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "the browser's storage failed: {e}"),
            Self::WrongPassphrase => write!(f, "wrong passphrase"),
            Self::Corrupt(e) => write!(f, "the vault is corrupt: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<idb::Error> for Error {
    fn from(error: idb::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// The open vault.
pub struct Vault {
    database: Database,
    key: Zeroizing<[u8; 32]>,
}

impl Vault {
    /// Whether this browser has a vault.
    pub async fn exists() -> Result<bool> {
        Ok(get(&open().await?, HEADER).await?.is_some())
    }

    /// A new vault holding `state`, under `passphrase`, replacing any other.
    pub async fn create(passphrase: &str, state: &AppState) -> Result<Self> {
        let database = open().await?;
        let header = VaultHeader::new();
        let key = header.derive_key(passphrase)?;
        let vault = Self { database, key };
        let transaction = vault
            .database
            .transaction(&[STORE], TransactionMode::ReadWrite)?;
        let store = transaction.object_store(STORE)?;
        store.clear()?;
        store.put(&bytes(&header.encode_to_vec()), Some(&HEADER.into()))?;
        store.put(&bytes(&vault.seal(STATE, state)), Some(&STATE.into()))?;
        commit(transaction).await?;
        Ok(vault)
    }

    /// Open the vault with `passphrase`.
    pub async fn unlock(passphrase: &str) -> Result<(Self, AppState)> {
        let database = open().await?;
        let header = get(&database, HEADER)
            .await?
            .ok_or_else(|| Error::Corrupt("no vault".into()))?;
        let header =
            VaultHeader::decode(header.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))?;
        let vault = Self {
            database,
            key: header.derive_key(passphrase)?,
        };
        let state = get(&vault.database, STATE)
            .await?
            .ok_or_else(|| Error::Corrupt("no state".into()))?;
        let state = vault.open(STATE, &state).ok_or(Error::WrongPassphrase)?;
        let state =
            AppState::decode(state.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))?;
        Ok((vault, state))
    }

    /// Save `state`, `entries`, each file of theirs in a record of its own, and `outgoing`,
    /// the records of messages waiting to be pushed, or none for one that went, together, or
    /// none of them.
    pub async fn save<'a>(
        &self,
        state: &AppState,
        entries: impl IntoIterator<Item = &'a (String, HistoryEntry)>,
        outgoing: &[(String, Option<OutgoingRecord>)],
    ) -> Result<()> {
        let transaction = self
            .database
            .transaction(&[STORE], TransactionMode::ReadWrite)?;
        let store = transaction.object_store(STORE)?;
        store.put(&bytes(&self.seal(STATE, state)), Some(&STATE.into()))?;
        self.put_entries(&store, entries)?;
        for (key, record) in outgoing {
            match record {
                Some(record) => {
                    store.put(&bytes(&self.seal(key, record)), Some(&key.as_str().into()))?;
                }
                None => {
                    store.delete(JsValue::from_str(key))?;
                }
            }
        }
        commit(transaction).await
    }

    /// Put `entries` in `store`, each file of theirs in a record of its own.
    fn put_entries<'a>(
        &self,
        store: &idb::ObjectStore,
        entries: impl IntoIterator<Item = &'a (String, HistoryEntry)>,
    ) -> Result<()> {
        for (key, entry) in entries {
            let (entry, data) = entry.without_file();
            if let Some(data) = data {
                let name = key.replacen("history/", "file/", 1);
                let record = FileRecord { data };
                store.put(
                    &bytes(&self.seal(&name, &record)),
                    Some(&name.as_str().into()),
                )?;
            }
            store.put(&bytes(&self.seal(key, &entry)), Some(&key.as_str().into()))?;
        }
        Ok(())
    }

    /// The bytes of the file of the history entry `index` of the chat with `peer`.
    pub async fn file(&self, peer: &PublicKey, index: u64) -> Result<Vec<u8>> {
        let name = file_key(peer, index);
        let sealed = get(&self.database, &name)
            .await?
            .ok_or_else(|| Error::Corrupt(format!("{name} is missing")))?;
        let record = self
            .open(&name, &sealed)
            .ok_or_else(|| Error::Corrupt(format!("{name} does not decrypt")))?;
        FileRecord::decode(record.as_slice())
            .map(|record| record.data)
            .map_err(|e| Error::Corrupt(e.to_string()))
    }

    /// The content of the history entry `index` of the chat with `peer`, `entry` as read from
    /// the history, with its file, if any.
    pub async fn content(
        &self,
        peer: &PublicKey,
        index: u64,
        entry: &HistoryEntry,
    ) -> Result<Option<Kind>> {
        let mut kind = entry
            .content
            .as_ref()
            .and_then(|content| content.kind.clone());
        if entry.file > 0 {
            let data = self.file(peer, index).await?;
            match kind.as_mut() {
                Some(Kind::File(file)) => file.data = data,
                Some(Kind::Image(image)) => *image = data,
                _ => {}
            }
        }
        Ok(kind)
    }

    /// The history entry `index` of the chat with `peer`, without its file, if any.
    pub async fn entry(&self, peer: &PublicKey, index: u64) -> Result<Option<HistoryEntry>> {
        let name = history_key(peer, index);
        let Some(sealed) = get(&self.database, &name).await? else {
            return Ok(None);
        };
        let entry = self
            .open(&name, &sealed)
            .ok_or_else(|| Error::Corrupt(format!("{name} does not decrypt")))?;
        HistoryEntry::decode(entry.as_slice())
            .map(Some)
            .map_err(|e| Error::Corrupt(e.to_string()))
    }

    /// The record of the message waiting to be pushed that is the history entry `index` of the
    /// chat with `peer`.
    pub async fn outgoing(&self, peer: &PublicKey, index: u64) -> Result<OutgoingRecord> {
        let name = outbox_key(peer, index);
        let sealed = get(&self.database, &name)
            .await?
            .ok_or_else(|| Error::Corrupt(format!("{name} is missing")))?;
        let record = self
            .open(&name, &sealed)
            .ok_or_else(|| Error::Corrupt(format!("{name} does not decrypt")))?;
        OutgoingRecord::decode(record.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))
    }

    /// The history of the chat with `peer`, oldest first, at most the last `limit` entries.
    pub async fn history(
        &self,
        peer: &PublicKey,
        history_len: u64,
        limit: u64,
    ) -> Result<Vec<(u64, HistoryEntry)>> {
        let Some(last) = history_len.checked_sub(1) else {
            return Ok(vec![]);
        };
        // Up to the last entry, so that records left beyond it, e.g. of a deleted chat with the
        // same peer, do not show.
        let range = history_range(peer, history_len.saturating_sub(limit), last)?;
        let transaction = self
            .database
            .transaction(&[STORE], TransactionMode::ReadOnly)?;
        let store = transaction.object_store(STORE)?;
        let keys = store
            .get_all_keys(Some(range.clone().into()), None)?
            .await?;
        let values = store.get_all(Some(range.into()), None)?.await?;
        keys.into_iter()
            .zip(values)
            .map(|(key, value)| {
                let key = key.as_string().unwrap_or_default();
                // From the record's name rather than its position, which a missing entry shifts.
                let index = key
                    .rsplit('/')
                    .next()
                    .and_then(|index| index.parse().ok())
                    .ok_or_else(|| Error::Corrupt(format!("{key} is not a history entry")))?;
                let entry = self
                    .open(&key, &Uint8Array::new(&value).to_vec())
                    .ok_or_else(|| Error::Corrupt(format!("{key} does not decrypt")))?;
                let entry = HistoryEntry::decode(entry.as_slice())
                    .map_err(|e| Error::Corrupt(e.to_string()))?;
                Ok((index, entry))
            })
            .collect()
    }

    /// Keep chunk `index` of the attachment `id`, in the chat with `peer`, as the server has it.
    pub async fn put_chunk(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
        chunk: &[u8],
    ) -> Result<()> {
        let transaction = self
            .database
            .transaction(&[STORE], TransactionMode::ReadWrite)?;
        transaction
            .object_store(STORE)?
            .put(&bytes(chunk), Some(&chunk_key(peer, id, index).into()))?;
        commit(transaction).await
    }

    /// Chunk `index` of the attachment `id`, in the chat with `peer`, if kept.
    pub async fn chunk(&self, peer: &PublicKey, id: &[u8], index: u32) -> Result<Option<Vec<u8>>> {
        get(&self.database, &chunk_key(peer, id, index)).await
    }

    /// How many chunks of the attachment `id`, in the chat with `peer`, are kept.
    pub async fn chunks_kept(&self, peer: &PublicKey, id: &[u8]) -> Result<u32> {
        let range = prefix_range(&format!("attachment/{}/{}/", hex(peer), hex(id)))?;
        let transaction = self
            .database
            .transaction(&[STORE], TransactionMode::ReadOnly)?;
        let count = transaction
            .object_store(STORE)?
            .count(Some(range.into()))?
            .await?;
        Ok(count)
    }

    /// Keep `upload`, in the chat with `peer`, replacing what was kept of it.
    pub async fn save_upload(&self, peer: &PublicKey, upload: &PendingUpload) -> Result<()> {
        let name = upload_key(peer, &upload.id);
        let transaction = self
            .database
            .transaction(&[STORE], TransactionMode::ReadWrite)?;
        transaction.object_store(STORE)?.put(
            &bytes(&self.seal(&name, upload)),
            Some(&name.as_str().into()),
        )?;
        commit(transaction).await
    }

    /// Forget the upload `id`, in the chat with `peer`, once cancelled, or its attachment
    /// deleted from the server.
    pub async fn forget_upload(&self, peer: &PublicKey, id: &[u8]) -> Result<()> {
        let transaction = self
            .database
            .transaction(&[STORE], TransactionMode::ReadWrite)?;
        transaction
            .object_store(STORE)?
            .delete(JsValue::from_str(&upload_key(peer, id)))?;
        commit(transaction).await
    }

    /// The upload `id`, in the chat with `peer`, if kept.
    pub async fn upload(&self, peer: &PublicKey, id: &[u8]) -> Result<Option<PendingUpload>> {
        let name = upload_key(peer, id);
        let Some(sealed) = get(&self.database, &name).await? else {
            return Ok(None);
        };
        let upload = self
            .open(&name, &sealed)
            .ok_or_else(|| Error::Corrupt(format!("{name} does not decrypt")))?;
        PendingUpload::decode(upload.as_slice())
            .map(Some)
            .map_err(|e| Error::Corrupt(e.to_string()))
    }

    /// The uploads kept, done or not, with the peers of their chats: those of the chat with
    /// `peer` only, if given.
    pub async fn uploads(
        &self,
        peer: Option<&PublicKey>,
    ) -> Result<Vec<(PublicKey, PendingUpload)>> {
        let range = match peer {
            Some(peer) => prefix_range(&format!("upload/{}/", hex(peer)))?,
            None => prefix_range("upload/")?,
        };
        let transaction = self
            .database
            .transaction(&[STORE], TransactionMode::ReadOnly)?;
        let store = transaction.object_store(STORE)?;
        let keys = store
            .get_all_keys(Some(range.clone().into()), None)?
            .await?;
        let values = store.get_all(Some(range.into()), None)?.await?;
        keys.into_iter()
            .zip(values)
            .map(|(key, value)| {
                let key = key.as_string().unwrap_or_default();
                let corrupt = || Error::Corrupt(format!("{key} is not an upload"));
                let peer = key
                    .split('/')
                    .nth(1)
                    .and_then(from_hex)
                    .and_then(|peer| PublicKey::try_from(peer).ok())
                    .ok_or_else(corrupt)?;
                let upload = self
                    .open(&key, &Uint8Array::new(&value).to_vec())
                    .ok_or_else(corrupt)?;
                let upload = PendingUpload::decode(upload.as_slice())
                    .map_err(|e| Error::Corrupt(e.to_string()))?;
                Ok((peer, upload))
            })
            .collect()
    }

    /// Save `state`, without the history, files, outbox, attachments and uploads of the chat
    /// with `peer`, and `entries` of other chats with it.
    pub async fn forget<'a>(
        &self,
        state: &AppState,
        peer: &PublicKey,
        entries: impl IntoIterator<Item = &'a (String, HistoryEntry)>,
    ) -> Result<()> {
        let transaction = self
            .database
            .transaction(&[STORE], TransactionMode::ReadWrite)?;
        let store = transaction.object_store(STORE)?;
        store.delete(history_range(peer, 0, u64::MAX)?)?;
        for prefix in ["file", "outbox", "attachment", "upload"] {
            store.delete(prefix_range(&format!("{prefix}/{}/", hex(peer)))?)?;
        }
        store.put(&bytes(&self.seal(STATE, state)), Some(&STATE.into()))?;
        self.put_entries(&store, entries)?;
        commit(transaction).await
    }

    /// Delete the vault for good.
    pub async fn destroy() -> Result<()> {
        let transaction = open()
            .await?
            .transaction(&[STORE], TransactionMode::ReadWrite)?;
        transaction.object_store(STORE)?.clear()?;
        commit(transaction).await
    }

    /// `record`, encrypted under the name `name`. Its plaintext, which holds keys, is zeroized.
    fn seal(&self, name: &str, record: &impl Message) -> Vec<u8> {
        let plaintext = Zeroizing::new(record.encode_to_vec());
        let mut nonce = [0; NONCE_LEN];
        getrandom::fill(&mut nonce).expect("crypto.getRandomValues");
        let mut sealed = nonce.to_vec();
        sealed.extend(
            Aes256Gcm::new(&(*self.key).into())
                .encrypt(
                    &nonce.into(),
                    Payload {
                        msg: &plaintext,
                        aad: name.as_bytes(),
                    },
                )
                .expect("AES-GCM encrypts any record that fits in memory"),
        );
        sealed
    }

    /// The plaintext of the record `name`, zeroized once dropped; `None` if it does not decrypt.
    fn open(&self, name: &str, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let (nonce, ciphertext) = sealed.split_at_checked(NONCE_LEN)?;
        Aes256Gcm::new(&(*self.key).into())
            .decrypt(
                &<[u8; NONCE_LEN]>::try_from(nonce).ok()?.into(),
                Payload {
                    msg: ciphertext,
                    aad: name.as_bytes(),
                },
            )
            .ok()
            .map(Zeroizing::new)
    }
}

async fn open() -> Result<Database> {
    let mut request = Factory::new()?.open(DATABASE, Some(1))?;
    request.on_upgrade_needed(|event| {
        if let Ok(database) = event.database()
            && !database.store_names().iter().any(|name| name == STORE)
        {
            let _ = database.create_object_store(STORE, ObjectStoreParams::new());
        }
    });
    Ok(request.await?)
}

async fn get(database: &Database, name: &str) -> Result<Option<Vec<u8>>> {
    let transaction = database.transaction(&[STORE], TransactionMode::ReadOnly)?;
    let value = transaction
        .object_store(STORE)?
        .get(JsValue::from_str(name))?
        .await?;
    Ok(value.map(|value| Uint8Array::new(&value).to_vec()))
}

/// Wait for the requests of `transaction`, which fails as a whole if one does.
async fn commit(transaction: idb::Transaction) -> Result<()> {
    if transaction.await?.is_committed() {
        Ok(())
    } else {
        Err(Error::Storage("the transaction was aborted".into()))
    }
}

fn bytes(bytes: &[u8]) -> JsValue {
    Uint8Array::from(bytes).into()
}
