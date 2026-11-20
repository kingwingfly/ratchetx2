//! The vault: everything the client keeps, in IndexedDB (schema v2), encrypted with a key derived
//! from the passphrase.
//!
//! The database `e2ee-chat` (IndexedDB version 2) has one object store of records by name:
//! - `vault`: the [`VaultHeader`], in the clear: the salt, Argon2id parameters, schema version,
//!   and monotonic CAS revision.
//! - `state`: the [`AppState`]: the identity, the prekeys, the contacts and their sessions.
//!   In v2, its AES-256-GCM AAD is `b"state/v2\0" || encoded(VaultHeader)` so any tampering with
//!   header parameters, version, or revision fails decryption.
//! - `history/<peer in hex>/<index>`: one [`HistoryEntry`] of a chat, without the bytes of its
//!   file, if any, which are in `file/<peer in hex>/<index>`, a [`FileRecord`], read when shown.
//! - `outbox/<peer in hex>/<index>`: a message of a chat, the history entry `index`, waiting to
//!   be pushed: an [`OutgoingRecord`]. The state only lists them, so that saving it stays small.
//! - `attachment/<peer in hex>/<id in hex>/<index>`: a chunk of an attachment in a chat, as the
//!   server has it: encrypted under the attachment's key, which only the history holds.
//! - `upload/<peer in hex>/<id in hex>`: a [`PendingUpload`], an attachment this client uploads,
//!   with its upload token, forgotten once the upload is done.
//!
//! Every `ReadWrite` transaction enforces monotonic `revision` compare-and-swap (CAS) against the
//! persisted `VaultHeader` inside the transaction so concurrent tabs cannot fork ratchets.

use std::{cell::RefCell, fmt};

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
/// IndexedDB schema version 2 fence: older v1 clients fail closed with `VersionError` instead of
/// stripping unknown prost PQ fields or offering to wipe via `create()`.
const DATABASE_VERSION: u32 = 2;
const STORE: &str = "records";
const HEADER: &str = "vault";
const STATE: &str = "state";

/// Legacy v1 vault schema version (v1 headers omitted field 5, so protobuf decodes `0`).
pub const VAULT_VERSION_V1: u32 = 1;
/// Hardened v2 vault schema version (header-bound `STATE` AAD + monotonic CAS revision).
pub const VAULT_VERSION_V2: u32 = 2;

/// Prefix for v2 `STATE` associated data: `b"state/v2\0" || header_bytes`.
const STATE_V2_AAD_PREFIX: &[u8] = b"state/v2\0";

/// Allowed Argon2id parameter bounds (enforced on untrusted headers BEFORE key derivation).
pub const ARGON2_MEMORY_MIN: u32 = 16 * 1024;
pub const ARGON2_MEMORY_MAX: u32 = 256 * 1024;
/// Default Argon2id memory for NEW vaults: 64 MiB.
pub const ARGON2_DEFAULT_MEMORY: u32 = 64 * 1024;
pub const ARGON2_ITERATIONS_MIN: u32 = 1;
pub const ARGON2_ITERATIONS_MAX: u32 = 10;
pub const ARGON2_DEFAULT_ITERATIONS: u32 = 2;
pub const ARGON2_PARALLELISM_MIN: u32 = 1;
pub const ARGON2_PARALLELISM_MAX: u32 = 4;
pub const ARGON2_DEFAULT_PARALLELISM: u32 = 1;
pub const ARGON2_SALT_MIN: usize = 16;
pub const ARGON2_SALT_MAX: usize = 64;

/// Pending outbound classical approval state stored in [`ContactState::classical_approval_needed`].
pub const CLASSICAL_APPROVAL_NONE: u32 = 0;
pub const CLASSICAL_APPROVAL_LEGACY: u32 = 1;
pub const CLASSICAL_APPROVAL_SIGNED_OFF: u32 = 2;

/// Per-contact security alert state stored in [`ContactState::security_alert`].
pub const SECURITY_ALERT_NONE: u32 = 0;
pub const SECURITY_ALERT_DOWNGRADE: u32 = 1;
pub const SECURITY_ALERT_MANIFEST_EXPIRED: u32 = 2;
pub const SECURITY_ALERT_PQ_REQUIRED: u32 = 3;

/// AES-GCM nonce length.
const NONCE_LEN: usize = <Aes256Gcm as AeadCore>::NonceSize::USIZE;

/// Build the v2 `STATE` associated data binding `header_bytes`: `b"state/v2\0" || header_bytes`.
pub fn state_v2_aad(header_bytes: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(STATE_V2_AAD_PREFIX.len() + header_bytes.len());
    aad.extend_from_slice(STATE_V2_AAD_PREFIX);
    aad.extend_from_slice(header_bytes);
    aad
}

/// The KDF's salt, parameters, schema version, and monotonic CAS revision, in the clear.
/// Bound into `STATE` AAD in v2 vaults so tampering is detected upon unlock.
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
    /// Schema version: `0` or `1` for legacy v1 vaults, `2` for hardened v2 vaults.
    #[prost(uint32, tag = "5")]
    pub version: u32,
    /// Monotonic state revision enforced with compare-and-swap inside every RW transaction.
    #[prost(uint64, tag = "6")]
    pub revision: u64,
}

impl VaultHeader {
    /// A new v2 header with a random 16-byte salt and hardened Argon2id parameters (64 MiB).
    fn new() -> Self {
        let mut salt = vec![0; 16];
        getrandom::fill(&mut salt).expect("crypto.getRandomValues");
        Self {
            salt,
            memory: ARGON2_DEFAULT_MEMORY,
            iterations: ARGON2_DEFAULT_ITERATIONS,
            parallelism: ARGON2_DEFAULT_PARALLELISM,
            version: VAULT_VERSION_V2,
            revision: 1,
        }
    }

    /// Whether this header represents a legacy v1 vault awaiting atomic v1 -> v2 upgrade.
    pub fn is_legacy_v1(&self) -> bool {
        self.version == 0 || self.version == VAULT_VERSION_V1
    }

    /// Validate untrusted header version, salt length, and Argon2id parameters BEFORE deriving
    /// any key (prevents DoS via huge memory/iterations or downgrade via tiny parameters).
    pub fn validate(&self) -> Result<()> {
        match self.version {
            0 | VAULT_VERSION_V1 => {}
            VAULT_VERSION_V2 => {
                if self.revision == 0 {
                    return Err(Error::Corrupt(
                        "v2 vault header has invalid revision 0".into(),
                    ));
                }
            }
            v => {
                return Err(Error::Corrupt(format!("unsupported vault version {v}")));
            }
        }
        if !(ARGON2_SALT_MIN..=ARGON2_SALT_MAX).contains(&self.salt.len()) {
            return Err(Error::Corrupt(format!(
                "invalid vault salt length {}",
                self.salt.len()
            )));
        }
        if !(ARGON2_MEMORY_MIN..=ARGON2_MEMORY_MAX).contains(&self.memory) {
            return Err(Error::Corrupt(format!(
                "Argon2 memory {} KiB outside allowed range [{}..={}]",
                self.memory, ARGON2_MEMORY_MIN, ARGON2_MEMORY_MAX
            )));
        }
        if !(ARGON2_ITERATIONS_MIN..=ARGON2_ITERATIONS_MAX).contains(&self.iterations) {
            return Err(Error::Corrupt(format!(
                "Argon2 iterations {} outside allowed range [{}..={}]",
                self.iterations, ARGON2_ITERATIONS_MIN, ARGON2_ITERATIONS_MAX
            )));
        }
        if !(ARGON2_PARALLELISM_MIN..=ARGON2_PARALLELISM_MAX).contains(&self.parallelism) {
            return Err(Error::Corrupt(format!(
                "Argon2 parallelism {} outside allowed range [{}..={}]",
                self.parallelism, ARGON2_PARALLELISM_MIN, ARGON2_PARALLELISM_MAX
            )));
        }
        Ok(())
    }

    /// Derive the 32-byte vault key from `passphrase` after validating parameters.
    pub fn derive_key(&self, passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        self.validate()?;
        let params = Params::new(self.memory, self.iterations, self.parallelism, Some(32))
            .map_err(|e| Error::Corrupt(e.to_string()))?;
        let mut key = Zeroizing::new([0; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase, &self.salt, key.as_mut_slice())
            .map_err(|e| Error::Corrupt(e.to_string()))?;
        Ok(key)
    }
}

/// Encrypt `plaintext` under `key` with associated data `aad`.
pub fn seal_bytes(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("crypto.getRandomValues");
    let mut sealed = nonce.to_vec();
    sealed.extend(
        Aes256Gcm::new(key.into())
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("AES-GCM encrypts any record that fits in memory"),
    );
    sealed
}

/// Decrypt `sealed` under `key` with associated data `aad`; zeroized on drop.
pub fn open_bytes(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (nonce, ciphertext) = sealed.split_at_checked(NONCE_LEN)?;
    Aes256Gcm::new(key.into())
        .decrypt(
            &<[u8; NONCE_LEN]>::try_from(nonce).ok()?.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
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
    /// When the signed prekey was last published/rotated; 0 if never.
    #[prost(uint64, tag = "5")]
    pub published_at: u64,
    /// Classical one-time prekeys used since last publish or refill.
    #[prost(uint32, tag = "6")]
    pub used_one_time_prekeys: u32,
    /// The messages telling peers that this client deleted their chats, to push.
    #[prost(message, repeated, tag = "7")]
    pub farewells: Vec<Farewell>,
    /// Post-quantum one-time prekeys used since last publish or refill.
    #[prost(uint32, tag = "8")]
    pub used_pq_one_time_prekeys: u32,
    /// Whether a full manifest/prekey publish is pending (e.g. after toggling PQ config).
    #[prost(bool, tag = "9")]
    pub needs_publish: bool,
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
    /// Events encrypted for the peer whose push has not gone yet: it goes again as it is, as
    /// encrypting them again would use up another key of the ratchet, of which the peer skips
    /// only so many.
    #[prost(message, optional, tag = "17")]
    pub sealed_events: Option<SealedEvents>,
    /// Whether an inbound classical initial message is held in quarantine pending explicit approval.
    #[prost(bool, tag = "18")]
    pub quarantined: bool,
    /// Whether the peer was already PQ-pinned when the quarantined classical session arrived.
    #[prost(bool, tag = "19")]
    pub quarantined_was_pq_pinned: bool,
    /// Quarantined inbound classical session for an existing contact (held apart so the active
    /// session is never overwritten before approval).
    #[prost(message, optional, tag = "20")]
    pub quarantined_session: Option<session::proto::SessionState>,
    /// Held decrypted first message bytes of the quarantined session (not shown or applied until approved).
    #[prost(bytes = "vec", tag = "21")]
    pub quarantined_first_message: Vec<u8>,
    /// Pending outbound classical fallback prompt (`CLASSICAL_APPROVAL_*`).
    #[prost(uint32, tag = "22")]
    pub classical_approval_needed: u32,
    /// Active security alert (`SECURITY_ALERT_*`).
    #[prost(uint32, tag = "23")]
    pub security_alert: u32,
    /// Whether this contact's primary (active) session itself is an unapproved quarantined
    /// classical session. Cleared only by explicit classical approval or verified PQ upgrade.
    #[prost(bool, tag = "24")]
    pub quarantined_primary: bool,
}

/// Events encrypted for the peer, waiting to be pushed, see [`ContactState::sealed_events`].
#[derive(Clone, PartialEq, prost::Message)]
pub struct SealedEvents {
    /// The message, encrypted.
    #[prost(message, optional, tag = "1")]
    pub record: Option<OutgoingRecord>,
    /// The ID of the session it was encrypted on: if another is active by the time it goes, it
    /// is encrypted again on that one, as the peer may never have had this one.
    #[prost(bytes = "vec", tag = "2")]
    pub session: Vec<u8>,
    /// What it tells, which [`ContactState::events`] forgets once it went.
    #[prost(message, optional, tag = "3")]
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
/// is forgotten, with its upload token, which is no use then: deleting the attachment from the
/// server takes its delete token, which either peer derives from its key.
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
    /// The history entry of its message, while its upload has not started.
    #[prost(uint64, tag = "12")]
    pub history_index: u64,
    /// When the server deletes it, in milliseconds since the Unix epoch, as it said as the
    /// upload started, which its message tells the peer; 0 if it did not.
    #[prost(uint64, tag = "13")]
    pub expires: u64,
}

impl PendingUpload {
    /// Whether its upload started, so that the server has it, under its ID.
    pub fn started(&self) -> bool {
        !self.token.is_empty()
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
    /// Optional deterministic 16-byte `client_message_id` for v2 idempotent `PushV2`.
    #[prost(bytes = "vec", tag = "2")]
    pub client_message_id: Vec<u8>,
    /// Encoded `protocol::mailbox_v2::PushV2Request` preserving v2/PQXDH carried initial messages.
    #[prost(bytes = "vec", tag = "3")]
    pub push_v2: Vec<u8>,
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
    /// Whether its attachment, if its content is one, is gone from the server, as this client
    /// deleted it, or found it gone when deleting it: the chat's file browser no longer offers to.
    #[prost(bool, tag = "9")]
    pub gone: bool,
    /// Whether this entry represents a message whose skipped ratchet key was evicted before arrival.
    #[prost(bool, tag = "10")]
    pub evicted: bool,
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
    /// A record does not decode or failed parameter validation.
    Corrupt(String),
    /// The vault revision changed underneath this tab (concurrent writer detected via CAS).
    Conflict { expected: u64, actual: u64 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "the browser's storage failed: {e}"),
            Self::WrongPassphrase => write!(f, "wrong passphrase"),
            Self::Corrupt(e) => write!(f, "the vault is corrupt: {e}"),
            Self::Conflict { expected, actual } => write!(
                f,
                "the vault was modified elsewhere (expected revision {expected}, found {actual}); reload this page"
            ),
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
    header: RefCell<VaultHeader>,
}

impl Vault {
    /// Whether this browser has a vault.
    pub async fn exists() -> Result<bool> {
        Ok(get(&open().await?, HEADER).await?.is_some())
    }

    /// A new v2 vault holding `state`, under `passphrase`, replacing any other.
    pub async fn create(passphrase: &[u8], state: &AppState) -> Result<Self> {
        let database = open().await?;
        let header = VaultHeader::new();
        let key = header.derive_key(passphrase)?;
        let header_bytes = header.encode_to_vec();
        let vault = Self {
            database,
            key,
            header: RefCell::new(header),
        };
        let sealed_state = vault.seal_with_aad(&state_v2_aad(&header_bytes), state);
        let transaction = vault
            .database
            .transaction(&[STORE], TransactionMode::ReadWrite)?;
        let store = transaction.object_store(STORE)?;
        let write_res: Result<()> = (|| {
            store.clear()?;
            store.put(&bytes(&sealed_state), Some(&STATE.into()))?;
            store.put(&bytes(&header_bytes), Some(&HEADER.into()))?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = transaction.abort();
            return Err(e);
        }
        commit(transaction).await?;
        Ok(vault)
    }

    /// Open the vault with `passphrase`, seamlessly upgrading legacy v1 vaults to v2 atomically
    /// in a single IndexedDB RW transaction.
    pub async fn unlock(passphrase: &[u8]) -> Result<(Self, AppState)> {
        let database = open().await?;
        let header_bytes = get(&database, HEADER)
            .await?
            .ok_or_else(|| Error::Corrupt("no vault".into()))?;
        let header = VaultHeader::decode(header_bytes.as_slice())
            .map_err(|e| Error::Corrupt(e.to_string()))?;
        // Validate version, salt, and Argon2 parameters BEFORE deriving key.
        header.validate()?;
        let key = header.derive_key(passphrase)?;
        let sealed_state = get(&database, STATE)
            .await?
            .ok_or_else(|| Error::Corrupt("no state".into()))?;

        if header.is_legacy_v1() {
            // Unlock legacy v1 vault with `"state"` AAD, then atomically re-seal as v2.
            let plain =
                open_bytes(&key, STATE.as_bytes(), &sealed_state).ok_or(Error::WrongPassphrase)?;
            let state =
                AppState::decode(plain.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))?;

            let mut v2_header = header;
            v2_header.version = VAULT_VERSION_V2;
            v2_header.revision = 1;
            let v2_header_bytes = v2_header.encode_to_vec();
            let v2_sealed_state =
                seal_bytes(&key, &state_v2_aad(&v2_header_bytes), plain.as_slice());

            let transaction = database.transaction(&[STORE], TransactionMode::ReadWrite)?;
            let store = transaction.object_store(STORE)?;
            // CAS check inside the upgrade transaction: ensure HEADER wasn't changed concurrently.
            let current = match store.get(JsValue::from_str(HEADER))?.await? {
                Some(v) => Uint8Array::new(&v).to_vec(),
                None => {
                    let _ = transaction.abort();
                    return Err(Error::Corrupt("no vault".into()));
                }
            };
            if current != header_bytes {
                let actual = VaultHeader::decode(current.as_slice())
                    .map(|h| h.revision)
                    .unwrap_or(0);
                let _ = transaction.abort();
                return Err(Error::Conflict {
                    expected: 0,
                    actual,
                });
            }
            let write_res: Result<()> = (|| {
                store.put(&bytes(&v2_sealed_state), Some(&STATE.into()))?;
                store.put(&bytes(&v2_header_bytes), Some(&HEADER.into()))?;
                Ok(())
            })();
            if let Err(e) = write_res {
                let _ = transaction.abort();
                return Err(e);
            }
            commit(transaction).await?;

            let vault = Self {
                database,
                key,
                header: RefCell::new(v2_header),
            };
            Ok((vault, state))
        } else {
            let plain = open_bytes(&key, &state_v2_aad(&header_bytes), &sealed_state)
                .ok_or(Error::WrongPassphrase)?;
            let state =
                AppState::decode(plain.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))?;
            let vault = Self {
                database,
                key,
                header: RefCell::new(header),
            };
            Ok((vault, state))
        }
    }

    /// Open an IndexedDB RW transaction and enforce monotonic CAS revision BEFORE any writes.
    async fn begin_checked_rw_tx(
        &self,
    ) -> Result<(idb::Transaction, idb::ObjectStore, VaultHeader)> {
        let transaction = self
            .database
            .transaction(&[STORE], TransactionMode::ReadWrite)?;
        let store = transaction.object_store(STORE)?;
        let expected = self.header.borrow().revision;
        let current = match store.get(JsValue::from_str(HEADER))?.await? {
            Some(v) => Uint8Array::new(&v).to_vec(),
            None => {
                let _ = transaction.abort();
                return Err(Error::Corrupt("vault header missing".into()));
            }
        };
        let decoded = match VaultHeader::decode(current.as_slice()) {
            Ok(decoded) => decoded,
            Err(e) => {
                let _ = transaction.abort();
                return Err(Error::Corrupt(e.to_string()));
            }
        };
        if decoded.version != VAULT_VERSION_V2 || decoded.revision != expected {
            let _ = transaction.abort();
            return Err(Error::Conflict {
                expected,
                actual: decoded.revision,
            });
        }
        Ok((transaction, store, decoded))
    }

    /// Save `state`, `entries`, each file of theirs in a record of its own, and `outgoing`,
    /// the records of messages waiting to be pushed, or none for one that went, together, or
    /// none of them, enforcing monotonic `revision` CAS inside the transaction.
    pub async fn save<'a>(
        &self,
        state: &AppState,
        entries: impl IntoIterator<Item = &'a (String, HistoryEntry)>,
        outgoing: &[(String, Option<OutgoingRecord>)],
    ) -> Result<()> {
        let (transaction, store, mut next_header) = self.begin_checked_rw_tx().await?;
        let Some(next_revision) = next_header.revision.checked_add(1) else {
            let _ = transaction.abort();
            return Err(Error::Corrupt("vault revision overflow".into()));
        };
        next_header.revision = next_revision;
        let next_header_bytes = next_header.encode_to_vec();
        let sealed_state = self.seal_with_aad(&state_v2_aad(&next_header_bytes), state);
        let write_res: Result<()> = (|| {
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
            store.put(&bytes(&sealed_state), Some(&STATE.into()))?;
            store.put(&bytes(&next_header_bytes), Some(&HEADER.into()))?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = transaction.abort();
            return Err(e);
        }
        commit(transaction).await?;
        *self.header.borrow_mut() = next_header;
        Ok(())
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
        let (transaction, store, _) = self.begin_checked_rw_tx().await?;
        if let Err(e) = store.put(&bytes(chunk), Some(&chunk_key(peer, id, index).into())) {
            let _ = transaction.abort();
            return Err(e.into());
        }
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
        let (transaction, store, _) = self.begin_checked_rw_tx().await?;
        if let Err(e) = store.put(&bytes(&self.seal(&name, upload)), Some(&name.as_str().into())) {
            let _ = transaction.abort();
            return Err(e.into());
        }
        commit(transaction).await
    }

    /// Forget the upload `id`, in the chat with `peer`, once cancelled, or its attachment
    /// deleted from the server.
    pub async fn forget_upload(&self, peer: &PublicKey, id: &[u8]) -> Result<()> {
        let (transaction, store, _) = self.begin_checked_rw_tx().await?;
        if let Err(e) = store.delete(JsValue::from_str(&upload_key(peer, id))) {
            let _ = transaction.abort();
            return Err(e.into());
        }
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

    /// The uploads kept, those not done, with the peers of their chats: those of the chat with
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
    /// with `peer`, and `entries` of other chats with it, enforcing monotonic `revision` CAS.
    pub async fn forget<'a>(
        &self,
        state: &AppState,
        peer: &PublicKey,
        entries: impl IntoIterator<Item = &'a (String, HistoryEntry)>,
    ) -> Result<()> {
        let (transaction, store, mut next_header) = self.begin_checked_rw_tx().await?;
        let Some(next_revision) = next_header.revision.checked_add(1) else {
            let _ = transaction.abort();
            return Err(Error::Corrupt("vault revision overflow".into()));
        };
        next_header.revision = next_revision;
        let next_header_bytes = next_header.encode_to_vec();
        let sealed_state = self.seal_with_aad(&state_v2_aad(&next_header_bytes), state);
        let write_res: Result<()> = (|| {
            store.delete(history_range(peer, 0, u64::MAX)?)?;
            for prefix in ["file", "outbox", "attachment", "upload"] {
                store.delete(prefix_range(&format!("{prefix}/{}/", hex(peer)))?)?;
            }
            self.put_entries(&store, entries)?;
            store.put(&bytes(&sealed_state), Some(&STATE.into()))?;
            store.put(&bytes(&next_header_bytes), Some(&HEADER.into()))?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = transaction.abort();
            return Err(e);
        }
        commit(transaction).await?;
        *self.header.borrow_mut() = next_header;
        Ok(())
    }

    /// Delete the vault for good.
    pub async fn destroy() -> Result<()> {
        let transaction = open()
            .await?
            .transaction(&[STORE], TransactionMode::ReadWrite)?;
        transaction.object_store(STORE)?.clear()?;
        commit(transaction).await
    }

    /// `record`, encrypted under explicit `aad`. Its plaintext, which holds keys, is zeroized.
    fn seal_with_aad(&self, aad: &[u8], record: &impl Message) -> Vec<u8> {
        let plaintext = Zeroizing::new(record.encode_to_vec());
        seal_bytes(&self.key, aad, &plaintext)
    }

    /// `record`, encrypted under the name `name`. Its plaintext, which holds keys, is zeroized.
    fn seal(&self, name: &str, record: &impl Message) -> Vec<u8> {
        self.seal_with_aad(name.as_bytes(), record)
    }

    /// The plaintext of the record `name`, zeroized once dropped; `None` if it does not decrypt.
    fn open(&self, name: &str, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        open_bytes(&self.key, name.as_bytes(), sealed)
    }
}

async fn open() -> Result<Database> {
    let mut request = Factory::new()?.open(DATABASE, Some(DATABASE_VERSION))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_header_argon2_parameter_bounds_and_defaults() {
        let new_header = VaultHeader::new();
        assert_eq!(new_header.version, VAULT_VERSION_V2);
        assert_eq!(new_header.revision, 1);
        assert_eq!(new_header.memory, ARGON2_DEFAULT_MEMORY);
        assert_eq!(new_header.memory, 64 * 1024);
        assert!(new_header.validate().is_ok());

        // Legacy v1 vault header (19 MiB, version = 0, revision = 0) validates cleanly.
        let legacy_v1 = VaultHeader {
            salt: vec![0x42; 16],
            memory: 19 * 1024,
            iterations: 2,
            parallelism: 1,
            version: 0,
            revision: 0,
        };
        assert!(legacy_v1.is_legacy_v1());
        assert!(legacy_v1.validate().is_ok());

        // Reject out-of-range Argon2 parameters BEFORE running KDF.
        for bad in [
            VaultHeader {
                memory: ARGON2_MEMORY_MIN - 1,
                ..new_header.clone()
            },
            VaultHeader {
                memory: ARGON2_MEMORY_MAX + 1,
                ..new_header.clone()
            },
            VaultHeader {
                iterations: 0,
                ..new_header.clone()
            },
            VaultHeader {
                iterations: ARGON2_ITERATIONS_MAX + 1,
                ..new_header.clone()
            },
            VaultHeader {
                parallelism: 0,
                ..new_header.clone()
            },
            VaultHeader {
                parallelism: ARGON2_PARALLELISM_MAX + 1,
                ..new_header.clone()
            },
            VaultHeader {
                salt: vec![0u8; 8],
                ..new_header.clone()
            },
            VaultHeader {
                version: 3,
                ..new_header.clone()
            },
            VaultHeader {
                version: VAULT_VERSION_V2,
                revision: 0,
                ..new_header.clone()
            },
        ] {
            assert!(
                matches!(bad.validate(), Err(Error::Corrupt(_))),
                "expected Corrupt for {bad:?}"
            );
            assert!(matches!(bad.derive_key(b"passphrase"), Err(Error::Corrupt(_))));
        }
    }

    #[test]
    fn vault_v1_to_v2_header_bound_aad_detects_tampering() {
        let legacy_header = VaultHeader {
            salt: vec![0x11; 16],
            memory: ARGON2_MEMORY_MIN,
            iterations: 1,
            parallelism: 1,
            version: 0,
            revision: 0,
        };
        let key = legacy_header.derive_key(b"correct horse battery staple").unwrap();

        let state = AppState {
            name: "Alice".to_string(),
            server: "https://chat.example.com".to_string(),
            ..AppState::default()
        };
        let plain = state.encode_to_vec();

        // Legacy v1 STATE sealed under `"state"` AAD opens cleanly.
        let v1_sealed = seal_bytes(&key, STATE.as_bytes(), &plain);
        let opened_v1 = open_bytes(&key, STATE.as_bytes(), &v1_sealed).unwrap();
        assert_eq!(opened_v1.as_slice(), plain.as_slice());

        // Upgrade to v2: bind encoded v2 VaultHeader bytes into STATE AAD.
        let mut v2_header = legacy_header;
        v2_header.version = VAULT_VERSION_V2;
        v2_header.revision = 1;
        let v2_header_bytes = v2_header.encode_to_vec();
        let v2_aad = state_v2_aad(&v2_header_bytes);
        assert!(v2_aad.starts_with(b"state/v2\0"));
        let v2_sealed = seal_bytes(&key, &v2_aad, &opened_v1);

        // Opens with matching v2 header bytes, fails with legacy `"state"` AAD.
        assert!(open_bytes(&key, STATE.as_bytes(), &v2_sealed).is_none());
        let opened_v2 = open_bytes(&key, &v2_aad, &v2_sealed).unwrap();
        assert_eq!(AppState::decode(opened_v2.as_slice()).unwrap(), state);

        // Any tampering with VaultHeader (e.g. revision rollback or memory change) fails AAD check!
        let mut tampered_rev = v2_header.clone();
        tampered_rev.revision = 2;
        assert!(
            open_bytes(&key, &state_v2_aad(&tampered_rev.encode_to_vec()), &v2_sealed).is_none()
        );

        let mut tampered_mem = v2_header;
        tampered_mem.memory = ARGON2_DEFAULT_MEMORY;
        assert!(
            open_bytes(&key, &state_v2_aad(&tampered_mem.encode_to_vec()), &v2_sealed).is_none()
        );
    }
}
