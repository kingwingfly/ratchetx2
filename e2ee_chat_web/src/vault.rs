//! The vault: everything the client keeps, in IndexedDB (schema v2), encrypted with a key derived
//! from the passphrase.
//!
//! The database `e2ee-chat` (IndexedDB version 2) has one object store of records by name:
//! - `vault`: the [`VaultHeader`], in the clear: the salt, Argon2id parameters, schema version,
//!   and monotonic CAS revision.
//! - `state`: the [`AppState`]: the identity, the prekeys, the contacts and their sessions, plus
//!   authenticated checkpoints for `upload/*`, per-revision tags for `outbox/*`, a vault-instance
//!   `record_epoch`, and the SHA-256 digest of `deferred_initials`.
//!   In v2, its AES-256-GCM AAD is `b"state/v2\0" || encoded(VaultHeader)` so any tampering with
//!   header parameters, version, or revision fails decryption.
//! - `deferred_initials`: optional [`DeferredInitialsRecord`] holding encrypted inbox initials
//!   retained for a build with their suite (or restored contact), encrypted under AAD
//!   `b"deferred_initials"` and committed atomically in the same CAS transaction as `state`. Its
//!   SHA-256 digest is bound into `AppState` so swapping an old sidecar against a newer `STATE`
//!   fails unlock while remaining tolerant of older bundles that do not populate tag 16.
//! - `history/<peer in hex>/<index>`: one [`HistoryEntry`] of a chat, without the bytes of its
//!   file, if any, which are in `file/<peer in hex>/<index>`, a [`FileRecord`], read when shown.
//! - `outbox/<peer in hex>/<index>`: a message of a chat, the history entry `index`, waiting to
//!   be pushed: an [`OutgoingRecord`], bound via AAD to its commit revision in `STATE`.
//! - `attachment/<peer in hex>/<id in hex>/<index>`: a chunk of an attachment in a chat, as the
//!   server has it: encrypted under the attachment's key, which only the history holds.
//! - `upload/<peer in hex>/<id in hex>`: a [`PendingUpload`], an attachment this client uploads,
//!   with its upload token and checkpoint bound into `STATE`, forgotten once the upload is done.
//!
//! Every `ReadWrite` transaction enforces monotonic `revision` compare-and-swap (CAS) against the
//! persisted `VaultHeader` inside the transaction and updates a monotonic `localStorage` rollback
//! anchor (`migrated_v2`, `max_revision`, `salt_hash`) so neither concurrent tabs nor offline
//! storage rollback / v1 replay can rewind Double Ratchet or prekey state.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    fmt,
};

use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit,
    aead::{Aead, Payload, array::typenum::Unsigned},
};
use argon2::{Algorithm, Argon2, Params, Version};
use idb::{Database, DatabaseEvent, Factory, KeyRange, ObjectStoreParams, TransactionMode};
use js_sys::Uint8Array;
use prost::Message;
use session::{PublicKey, Sealed, protocol::mailbox::PushRequest};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    content::{Content, Events, Kind},
    preview::{self, Sort},
    state::{Delivery, LastMessage, LastMessageKind},
    util::{from_hex, hex},
};

const DATABASE: &str = "e2ee-chat";
/// IndexedDB schema version 2 fence: older v1 clients fail closed with `VersionError` instead of
/// stripping unknown prost PQ fields or offering to wipe via `create()`.
const DATABASE_VERSION: u32 = 2;
const STORE: &str = "records";
const HEADER: &str = "vault";
const STATE: &str = "state";
const DEFERRED_INITIALS: &str = "deferred_initials";
/// `localStorage` key storing the monotonic v2 rollback / v1-downgrade anchor.
const ROLLBACK_ANCHOR_KEY: &str = "e2ee-chat.vault.anchor.v1";

/// Legacy v1 vault schema version (v1 headers omitted field 5, so protobuf decodes `0`).
pub const VAULT_VERSION_V1: u32 = 1;
/// Hardened v2 vault schema version (header-bound `STATE` AAD + monotonic CAS revision).
pub const VAULT_VERSION_V2: u32 = 2;

/// Prefix for v2 `STATE` associated data: `b"state/v2\0" || header_bytes`.
const STATE_V2_AAD_PREFIX: &[u8] = b"state/v2\0";
/// Domain prefix for the `DEFERRED_INITIALS` digest stored in `AppState`.
const DEFERRED_DIGEST_PREFIX: &[u8] = b"deferred_initials/v1\0";

/// Allowed Argon2id parameter bounds (enforced on untrusted headers BEFORE key derivation).
pub const ARGON2_MEMORY_MIN: u32 = 16 * 1024;
pub const ARGON2_MEMORY_MAX: u32 = 256 * 1024;
/// Default Argon2id memory for NEW and upgraded vaults: 64 MiB.
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

/// Initial-greeting delivery state stored in [`ContactState::greeting_delivery`].
pub const GREETING_DELIVERY_LEGACY_UNKNOWN: u32 = 0;
pub const GREETING_DELIVERY_UNSENT: u32 = 1;
pub const GREETING_DELIVERY_UNCERTAIN: u32 = 2;
pub const GREETING_DELIVERY_CONFIRMED: u32 = 3;

/// Explicit upload lifecycle state stored in [`PendingUpload::upload_state`].
#[allow(dead_code)] // Legacy sentinel (`0` from older prost messages).
pub const UPLOAD_STATE_LEGACY: u32 = 0;
/// Waiting for server sign-in under a client-generated placeholder ID.
pub const UPLOAD_STATE_WAITING: u32 = 1;
/// Started on the server, awaiting chat announcement.
pub const UPLOAD_STATE_STARTED: u32 = 2;
/// Started on the server and durably announced in chat history/outbox.
pub const UPLOAD_STATE_ANNOUNCED: u32 = 3;

/// AES-GCM nonce length.
const NONCE_LEN: usize = <Aes256Gcm as AeadCore>::NonceSize::USIZE;

/// Build the v2 `STATE` associated data binding `header_bytes`: `b"state/v2\0" || header_bytes`.
pub fn state_v2_aad(header_bytes: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(STATE_V2_AAD_PREFIX.len() + header_bytes.len());
    aad.extend_from_slice(STATE_V2_AAD_PREFIX);
    aad.extend_from_slice(header_bytes);
    aad
}

/// Build per-record associated data binding `name` and vault instance `epoch`.
/// When `epoch == 0` (legacy pre-epoch records), returns `name.as_bytes()` for backwards
/// compatibility.
pub fn record_aad(name: &str, epoch: u64) -> Vec<u8> {
    if epoch == 0 {
        return name.as_bytes().to_vec();
    }
    let mut aad = Vec::with_capacity(name.len() + 15);
    aad.extend_from_slice(name.as_bytes());
    aad.extend_from_slice(b"\0epoch/");
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// Build per-revision associated data for `outbox/*` records so an attacker with storage write
/// access cannot substitute an older `OutgoingRecord` next to a newer `STATE`.
pub fn outbox_aad(name: &str, epoch: u64, revision: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(name.len() + 27);
    aad.extend_from_slice(name.as_bytes());
    aad.extend_from_slice(b"\0epoch/");
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(b"/rev/");
    aad.extend_from_slice(&revision.to_be_bytes());
    aad
}

/// SHA-256 digest of a [`DeferredInitialsRecord`] bound into `AppState`.
pub fn deferred_initials_digest(record: &DeferredInitialsRecord) -> Vec<u8> {
    let encoded = Zeroizing::new(record.encode_to_vec());
    let mut hasher = Sha256::new();
    hasher.update(DEFERRED_DIGEST_PREFIX);
    hasher.update(encoded.as_slice());
    hasher.finalize().to_vec()
}

/// Verify `record` against the expected digest stored in `AppState` (when populated by a build
/// supporting tag 16).
pub fn verify_deferred_initials_digest(
    expected: &[u8],
    record: &DeferredInitialsRecord,
) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }
    let actual = deferred_initials_digest(record);
    if expected != actual.as_slice() {
        return Err(Error::Corrupt(
            "deferred_initials record does not match authenticated state digest".into(),
        ));
    }
    Ok(())
}

/// Monotonic rollback & v1-downgrade anchor persisted outside IndexedDB in `localStorage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackAnchor {
    pub migrated_v2: bool,
    pub max_revision: u64,
    /// Hex-encoded SHA-256 of the v2 vault's `VaultHeader.salt`.
    pub salt_hash: String,
}

impl RollbackAnchor {
    pub fn for_v2_header(header: &VaultHeader) -> Self {
        Self {
            migrated_v2: true,
            max_revision: header.revision,
            salt_hash: salt_fingerprint(&header.salt),
        }
    }

    #[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
    pub fn encode(&self) -> String {
        format!(
            "v1:{}:{}:{}",
            u8::from(self.migrated_v2),
            self.max_revision,
            self.salt_hash
        )
    }

    #[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
    pub fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.trim().split(':');
        if parts.next()? != "v1" {
            return None;
        }
        let migrated_v2 = match parts.next()? {
            "1" => true,
            "0" => false,
            _ => return None,
        };
        let max_revision: u64 = parts.next()?.parse().ok()?;
        let salt_hash = parts.next()?.to_string();
        if parts.next().is_some() {
            return None;
        }
        if !salt_hash.is_empty()
            && (salt_hash.len() != 64 || !salt_hash.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return None;
        }
        Some(Self {
            migrated_v2,
            max_revision,
            salt_hash,
        })
    }
}

fn salt_fingerprint(salt: &[u8]) -> String {
    hex(&Sha256::digest(salt))
}

/// Reject legacy v1 replay or v2 revision/salt rollback against an external [`RollbackAnchor`].
pub fn check_unlock_against_anchor(
    anchor: Option<&RollbackAnchor>,
    header: &VaultHeader,
) -> Result<()> {
    let Some(anchor) = anchor else {
        return Ok(());
    };
    if anchor.migrated_v2 && header.is_legacy_v1() {
        return Err(Error::Corrupt(
            "legacy v1 vault replay rejected after v2 migration".into(),
        ));
    }
    if header.version == VAULT_VERSION_V2 {
        let current_salt = salt_fingerprint(&header.salt);
        if anchor.migrated_v2 && !anchor.salt_hash.is_empty() && anchor.salt_hash != current_salt {
            return Err(Error::Corrupt(
                "vault rollback or replacement detected (header salt does not match anchor)".into(),
            ));
        }
        if header.revision < anchor.max_revision {
            return Err(Error::Corrupt(format!(
                "vault rollback detected (revision {} is behind anchor {})",
                header.revision, anchor.max_revision
            )));
        }
    }
    Ok(())
}

/// Advance an existing anchor monotonically for a committed v2 header.
fn advance_anchor(existing: Option<&RollbackAnchor>, header: &VaultHeader) -> RollbackAnchor {
    let current_salt = salt_fingerprint(&header.salt);
    let prev_rev = existing
        .filter(|a| a.salt_hash == current_salt)
        .map_or(0, |a| a.max_revision);
    RollbackAnchor {
        migrated_v2: true,
        max_revision: prev_rev.max(header.revision),
        salt_hash: current_salt,
    }
}

fn read_rollback_anchor() -> Option<RollbackAnchor> {
    #[cfg(target_arch = "wasm32")]
    {
        let storage = web_sys::window()?.local_storage().ok()??;
        let raw = storage.get_item(ROLLBACK_ANCHOR_KEY).ok()??;
        RollbackAnchor::parse(&raw)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = ROLLBACK_ANCHOR_KEY;
        None
    }
}

fn write_rollback_anchor(anchor: &RollbackAnchor) {
    #[cfg(target_arch = "wasm32")]
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item(ROLLBACK_ANCHOR_KEY, &anchor.encode());
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = anchor;
    }
}

fn clear_rollback_anchor() {
    #[cfg(target_arch = "wasm32")]
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.remove_item(ROLLBACK_ANCHOR_KEY);
    }
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

fn verify_checked_header(expected: &VaultHeader, raw: &[u8]) -> Result<VaultHeader> {
    let decoded = VaultHeader::decode(raw).map_err(|e| Error::Corrupt(e.to_string()))?;
    if decoded.version != VAULT_VERSION_V2 || decoded.revision != expected.revision {
        return Err(Error::Conflict {
            expected: expected.revision,
            actual: decoded.revision,
        });
    }
    if expected.version != VAULT_VERSION_V2
        || decoded != *expected
        || raw != expected.encode_to_vec()
    {
        return Err(Error::Corrupt(
            "vault header was modified unexpectedly".into(),
        ));
    }
    Ok(expected.clone())
}

#[cfg(test)]
fn reseal_state_for_next_revision(
    key: &[u8; 32],
    current: &VaultHeader,
    sealed_state: &[u8],
) -> Result<(VaultHeader, Vec<u8>, Vec<u8>)> {
    let plain = open_bytes(key, &state_v2_aad(&current.encode_to_vec()), sealed_state)
        .ok_or_else(|| Error::Corrupt("vault state failed authentication".into()))?;
    let next = current.next_revision()?;
    let header = next.encode_to_vec();
    let sealed = try_seal_bytes(key, &state_v2_aad(&header), plain.as_slice())?;
    Ok((next, header, sealed))
}

impl VaultHeader {
    fn next_revision(&self) -> Result<Self> {
        let revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| Error::Corrupt("vault revision overflow".into()))?;
        Ok(Self {
            revision,
            ..self.clone()
        })
    }

    /// A new v2 header with a random 16-byte salt and hardened Argon2id parameters (64 MiB),
    /// returning an error instead of panicking if browser CSPRNG fails.
    pub fn try_new() -> Result<Self> {
        let mut salt = vec![0; 16];
        getrandom::fill(&mut salt)
            .map_err(|e| Error::Storage(format!("random salt generation failed: {e}")))?;
        Ok(Self {
            salt,
            memory: ARGON2_DEFAULT_MEMORY,
            iterations: ARGON2_DEFAULT_ITERATIONS,
            parallelism: ARGON2_DEFAULT_PARALLELISM,
            version: VAULT_VERSION_V2,
            revision: 1,
        })
    }

    #[cfg(test)]
    fn new() -> Self {
        Self::try_new().expect("crypto.getRandomValues")
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

/// Fallibly encrypt `plaintext` under `key` with associated data `aad` (never panics on RNG error).
pub fn try_seal_bytes(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| Error::Storage(format!("random nonce generation failed: {e}")))?;
    let ciphertext = Aes256Gcm::new(key.into())
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Corrupt("AES-GCM encryption failed".into()))?;
    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Encrypt `plaintext` under `key` with associated data `aad`.
#[cfg(test)]
pub fn seal_bytes(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    try_seal_bytes(key, aad, plaintext).expect("AES-GCM sealing in tests")
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
    /// Locally processed v2 inbox IDs awaiting acknowledgement after durable persistence.
    #[prost(uint64, repeated, tag = "10")]
    pub pending_inbox_acks: Vec<u64>,
    /// Preferences to restore if the relay refuses a pending settings change.
    #[prost(message, optional, tag = "11")]
    pub pending_pq_rollback: Option<PendingPqRollback>,
    /// Legacy migration field for deferred inbox initials; always left empty on writes because
    /// deferred initials are stored in the separate [`DEFERRED_INITIALS`] record.
    #[prost(message, repeated, tag = "12")]
    pub deferred_initials: Vec<session::protocol::handshake_v2::InitialMessageV2>,
    /// Monotonic floor for newly started chat `Hello.session_seq` values so recreating a deleted
    /// chat never reuses `session_seq = 1` against a peer who kept the old history.
    #[prost(uint64, tag = "13")]
    pub next_session_seq: u64,
    /// Authenticated per-upload watermarks and hashes bound inside `STATE`, detecting partial
    /// rollback of standalone `upload/<peer>/<id>` records.
    #[prost(message, repeated, tag = "14")]
    pub upload_checkpoints: Vec<UploadCheckpoint>,
    /// Vault-instance epoch bound into per-record AAD for records written by this build.
    #[prost(uint64, tag = "15")]
    pub record_epoch: u64,
    /// SHA-256 digest of the committed `DEFERRED_INITIALS` record (empty only in legacy vaults).
    #[prost(bytes = "vec", tag = "16")]
    pub deferred_initials_digest: Vec<u8>,
    /// Per-outbox-record commit revisions bound into `outbox/*` AADs.
    #[prost(message, repeated, tag = "17")]
    pub outbox_revisions: Vec<OutboxRevision>,
}

impl AppState {
    /// Wipe secret key material and sensitive buffers held in this protobuf copy.
    pub fn zeroize_secrets(&mut self) {
        // `session::proto::ClientState` derives `ZeroizeOnDrop`.
        drop(self.client.take());
        for contact in &mut self.contacts {
            contact.zeroize_secrets();
        }
        for cp in &mut self.upload_checkpoints {
            cp.prefix_hash.zeroize();
            cp.sealed_chunk_hash.zeroize();
        }
        self.deferred_initials_digest.zeroize();
    }
}

/// Compact upload watermark authenticated inside `STATE` so partial rollback of an
/// `upload/<peer>/<id>` record cannot supply stale `encrypted` / `prefix_hash` values on resume.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct UploadCheckpoint {
    #[prost(bytes = "vec", tag = "1")]
    pub peer: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub id: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub uploaded: u32,
    #[prost(uint32, tag = "4")]
    pub encrypted: u32,
    #[prost(bytes = "vec", tag = "5")]
    pub prefix_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub sealed_chunk_hash: Vec<u8>,
    #[prost(uint32, tag = "7")]
    pub upload_state: u32,
}

impl UploadCheckpoint {
    fn from_upload(peer: &PublicKey, upload: &PendingUpload) -> Self {
        Self {
            peer: peer.to_vec(),
            id: upload.id.clone(),
            uploaded: upload.uploaded,
            encrypted: upload.encrypted,
            prefix_hash: upload.prefix_hash.clone(),
            sealed_chunk_hash: upload.sealed_chunk_hash.clone(),
            upload_state: upload.upload_state,
        }
    }

    fn matches(&self, peer: &PublicKey, upload: &PendingUpload) -> bool {
        self.peer.as_slice() == peer.as_slice()
            && self.id == upload.id
            && self.uploaded == upload.uploaded
            && self.encrypted == upload.encrypted
            && self.prefix_hash == upload.prefix_hash
            && self.sealed_chunk_hash == upload.sealed_chunk_hash
            && self.upload_state == upload.upload_state
    }
}

/// Authenticated revision binding for an active `outbox/<peer>/<index>` record.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct OutboxRevision {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(uint64, tag = "2")]
    pub revision: u64,
}

/// One encrypted inbox initial retained until a build with its suite (or restored contact) can
/// decrypt it, together with when it was first deferred (Unix ms, `0` if unknown).
#[derive(Clone, PartialEq, prost::Message)]
pub struct DeferredInitial {
    #[prost(message, optional, tag = "1")]
    pub initial: Option<session::protocol::handshake_v2::InitialMessageV2>,
    #[prost(uint64, tag = "2")]
    pub deferred_at: u64,
}

/// Earliest timestamp (Unix ms) at which a carried initial referencing `signed_prekey` was
/// retained, bounding signed-prekey preservation across rotations without changing `ContactState`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct CarriedDeferredTimestamp {
    #[prost(bytes = "vec", tag = "1")]
    pub signed_prekey: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub deferred_at: u64,
}

/// Separate encrypted sidecar record committed atomically with `STATE` so rolling back to an
/// older bundle that rewrites `STATE` cannot strip already-acknowledged greetings.
#[derive(Clone, PartialEq, prost::Message)]
pub struct DeferredInitialsRecord {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<DeferredInitial>,
    #[prost(message, repeated, tag = "2")]
    pub carried_timestamps: Vec<CarriedDeferredTimestamp>,
}

impl DeferredInitialsRecord {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.carried_timestamps.is_empty()
    }
}

/// Fallibly seal a [`DeferredInitialsRecord`] under `key` with the `deferred_initials` record AAD.
pub fn try_seal_deferred_initials(
    key: &[u8; 32],
    record: &DeferredInitialsRecord,
) -> Result<Vec<u8>> {
    let plaintext = Zeroizing::new(record.encode_to_vec());
    try_seal_bytes(key, DEFERRED_INITIALS.as_bytes(), &plaintext)
}

/// Seal a [`DeferredInitialsRecord`] under `key` with the `deferred_initials` record AAD.
#[cfg(test)]
pub fn seal_deferred_initials(key: &[u8; 32], record: &DeferredInitialsRecord) -> Vec<u8> {
    try_seal_deferred_initials(key, record).expect("deferred_initials sealing in tests")
}

/// Open a sealed [`DeferredInitialsRecord`] under `key` with the `deferred_initials` record AAD.
pub fn open_deferred_initials(key: &[u8; 32], sealed: &[u8]) -> Result<DeferredInitialsRecord> {
    let plain = open_bytes(key, DEFERRED_INITIALS.as_bytes(), sealed)
        .ok_or_else(|| Error::Corrupt("deferred_initials does not decrypt".into()))?;
    DeferredInitialsRecord::decode(plain.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PendingPqRollback {
    #[prost(bool, tag = "1")]
    pub pq_enabled: bool,
    #[prost(uint32, tag = "2")]
    pub preferred_suite: u32,
    #[prost(bool, tag = "3")]
    pub pq_ratchet_enabled: bool,
    #[prost(bool, tag = "4")]
    pub strict_pq: bool,
    #[prost(bool, tag = "5")]
    pub previous_needs_publish: bool,
}

impl PendingPqRollback {
    pub fn from_config(config: &session::PqConfig, previous_needs_publish: bool) -> Self {
        Self {
            pq_enabled: config.pq_enabled,
            preferred_suite: u32::from(config.preferred_suite.as_u8()),
            pq_ratchet_enabled: config.pq_ratchet_enabled,
            strict_pq: config.strict_pq,
            previous_needs_publish,
        }
    }

    pub fn config(&self) -> session::PqConfig {
        session::PqConfig {
            pq_enabled: self.pq_enabled,
            preferred_suite: u8::try_from(self.preferred_suite)
                .ok()
                .and_then(session::PqSuite::from_u8)
                .unwrap_or_else(session::PqConfig::default_suite),
            pq_ratchet_enabled: self.pq_ratchet_enabled,
            strict_pq: self.strict_pq,
        }
    }
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
    /// Events encrypted for the peer whose push has not gone yet.
    #[prost(message, optional, tag = "17")]
    pub sealed_events: Option<SealedEvents>,
    /// Whether an inbound classical initial message is held in quarantine pending explicit approval.
    #[prost(bool, tag = "18")]
    pub quarantined: bool,
    /// Whether the peer was already PQ-pinned when the quarantined classical session arrived.
    #[prost(bool, tag = "19")]
    pub quarantined_was_pq_pinned: bool,
    /// Quarantined inbound classical session for an existing contact.
    #[prost(message, optional, tag = "20")]
    pub quarantined_session: Option<session::proto::SessionState>,
    /// Held decrypted first message bytes of the quarantined session.
    #[prost(bytes = "vec", tag = "21")]
    pub quarantined_first_message: Vec<u8>,
    /// Pending outbound classical fallback prompt (`CLASSICAL_APPROVAL_*`).
    #[prost(uint32, tag = "22")]
    pub classical_approval_needed: u32,
    /// Active security alert (`SECURITY_ALERT_*`).
    #[prost(uint32, tag = "23")]
    pub security_alert: u32,
    /// Whether this contact's primary (active) session itself is an unapproved quarantined
    /// classical session.
    #[prost(bool, tag = "24")]
    pub quarantined_primary: bool,
    /// A replacement session took over before the sealed outbox could be rebuilt from history.
    #[prost(bool, tag = "25")]
    pub needs_requeue_sealed: bool,
    /// Carried initial messages persisted atomically with the mailbox cursor until durably joined.
    #[prost(bytes = "vec", repeated, tag = "26")]
    pub pending_carried_initials: Vec<Vec<u8>>,
    /// Delivery status of the initial greeting (`GREETING_DELIVERY_*`).
    #[prost(uint32, tag = "27")]
    pub greeting_delivery: u32,
    /// Coalesced half-open history index ranges `[start, end)` already acknowledged on screen.
    #[prost(message, repeated, tag = "28")]
    pub acked_ranges: Vec<IndexRange>,
    /// Durable fallback farewells from a previously established session.
    #[prost(message, repeated, tag = "29")]
    pub fallback_farewells: Vec<Farewell>,
    /// Structured single-line preview of the most recent message in this chat.
    #[prost(message, optional, tag = "30")]
    pub last_message: Option<LastMessageRecord>,
}

/// Persisted structured preview of the most recent message in a chat.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct LastMessageRecord {
    #[prost(enumeration = "LastMessageKind", tag = "1")]
    pub kind: i32,
    #[prost(bool, tag = "2")]
    pub outgoing: bool,
    /// Sanitized single-line text, filename, or shared contact label.
    #[prost(string, tag = "3")]
    pub text: String,
}

impl LastMessageRecord {
    pub fn to_view(&self) -> Option<LastMessage> {
        if self.kind == i32::from(LastMessageKind::None) {
            return None;
        }
        let kind = LastMessageKind::try_from(self.kind).unwrap_or(LastMessageKind::Unknown);
        Some(LastMessage {
            kind,
            outgoing: self.outgoing,
            text: self.text.clone(),
        })
    }

    pub fn zeroize_secrets(&mut self) {
        self.text.zeroize();
        self.kind = 0;
        self.outgoing = false;
    }
}

impl ContactState {
    pub fn zeroize_secrets(&mut self) {
        // `session::proto::SessionState` derives `ZeroizeOnDrop`.
        drop(self.session.take());
        drop(self.quarantined_session.take());
        self.quarantined_first_message.zeroize();
        if let Some(mut last) = self.last_message.take() {
            last.zeroize_secrets();
        }
        for buf in &mut self.pending_carried_initials {
            buf.zeroize();
        }
        if let Some(sealed) = &mut self.sealed_events
            && let Some(rec) = &mut sealed.record
        {
            rec.zeroize_secrets();
        }
    }
}

/// Coalesced half-open history index range `[start, end)` already acknowledged on screen.
#[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
pub struct IndexRange {
    #[prost(uint64, tag = "1")]
    pub start: u64,
    #[prost(uint64, tag = "2")]
    pub end: u64,
}

/// Events encrypted for the peer, waiting to be pushed, see [`ContactState::sealed_events`].
#[derive(Clone, PartialEq, prost::Message)]
pub struct SealedEvents {
    /// The message, encrypted.
    #[prost(message, optional, tag = "1")]
    pub record: Option<OutgoingRecord>,
    /// The ID of the session it was encrypted on.
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
/// the file chosen again: from `uploaded`, once the file still has the hash it had.
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
    /// Chunks that may have been encrypted, and so may be on their way.
    #[prost(uint32, tag = "8")]
    pub encrypted: u32,
    /// SHA-256 of the file's first `encrypted` chunks.
    #[prost(bytes = "vec", tag = "9")]
    pub prefix_hash: Vec<u8>,
    /// The attachment was sent to the chat, which downloads it as it is uploaded.
    #[prost(bool, tag = "10")]
    pub announced: bool,
    /// The history entry of its message, while its upload has not started.
    #[prost(uint64, tag = "12")]
    pub history_index: u64,
    /// When the server deletes it, in milliseconds since the Unix epoch; 0 if it did not say.
    #[prost(uint64, tag = "13")]
    pub expires: u64,
    /// Explicit upload lifecycle state (`UPLOAD_STATE_*`).
    #[prost(uint32, tag = "14")]
    pub upload_state: u32,
    /// SHA-256 of chunk `uploaded` persisted before encrypting it (`encrypted == uploaded + 1`),
    /// passed to `Upload::resume_with_digests` so resumed uploads verify exact plaintext identity.
    #[prost(bytes = "vec", tag = "15")]
    pub sealed_chunk_hash: Vec<u8>,
}

impl PendingUpload {
    /// Whether its upload started, so that the server has it, under its ID.
    pub fn started(&self) -> bool {
        match self.upload_state {
            UPLOAD_STATE_WAITING => false,
            UPLOAD_STATE_STARTED | UPLOAD_STATE_ANNOUNCED => !self.token.is_empty(),
            _ => !self.token.is_empty(),
        }
    }

    /// Whether the server-assigned attachment pointer has been durably announced in chat history.
    pub fn is_announced(&self) -> bool {
        match self.upload_state {
            UPLOAD_STATE_WAITING | UPLOAD_STATE_STARTED => false,
            UPLOAD_STATE_ANNOUNCED => true,
            _ => self.announced && !self.token.is_empty(),
        }
    }

    fn clear_secrets(&mut self) {
        self.token.zeroize();
        self.key.zeroize();
        self.prefix_hash.zeroize();
        self.sealed_chunk_hash.zeroize();
    }
}

impl Drop for PendingUpload {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}

impl zeroize::ZeroizeOnDrop for PendingUpload {}

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
    /// Whether it is encrypted, as it goes next.
    #[prost(bool, tag = "4")]
    pub sealed: bool,
    /// Its place, given as it was encrypted.
    #[prost(uint64, tag = "5")]
    pub clock: u64,
    /// It is an attachment whose upload has not started.
    #[prost(bool, tag = "6")]
    pub awaits_upload: bool,
}

/// What a message not pushed yet is: its content, encrypted just before it goes.
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

    /// Wipe plaintext content and delivery hash buffers.
    pub fn zeroize_secrets(&mut self) {
        self.content.zeroize();
        self.delivery_hash.zeroize();
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

/// A message telling a peer that this client deleted the chat, not pushed yet.
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

impl Farewell {
    /// Recipient identity key of this farewell.
    pub fn recipient(&self) -> Option<Vec<u8>> {
        if !self.push_v2.is_empty()
            && let Ok(v2) =
                session::protocol::mailbox_v2::PushV2Request::decode(self.push_v2.as_slice())
        {
            return Some(v2.recipient.to_vec());
        }
        self.push.as_ref().map(|p| p.recipient.to_vec())
    }
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
    /// Its place in the chat.
    #[prost(uint64, tag = "5")]
    pub place: u64,
    /// The size of its file, if its content is one, whose bytes are in a record of their own.
    #[prost(uint64, tag = "6")]
    pub file: u64,
    /// The MIME type of its file, if it is an image, a video or audio, by its first bytes.
    #[prost(string, tag = "7")]
    pub media: String,
    /// The sort of its file, by its content, which the chat's file browser groups it by.
    #[prost(enumeration = "Sort", tag = "8")]
    pub sort: i32,
    /// Whether its attachment, if its content is one, is gone from the server.
    #[prost(bool, tag = "9")]
    pub gone: bool,
    /// Whether this entry represents a message whose skipped ratchet key was evicted before arrival.
    #[prost(bool, tag = "10")]
    pub evicted: bool,
}

impl HistoryEntry {
    /// The entry without the bytes of its file, if any, which it notes, and the bytes.
    pub(crate) fn without_file(&self) -> (Self, Option<Zeroizing<Vec<u8>>>) {
        let mut entry = self.clone();
        let data = match entry
            .content
            .as_mut()
            .and_then(|content| content.kind.as_mut())
        {
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
        (entry, Some(Zeroizing::new(data)))
    }

    /// Wipe attachment key and embedded file plaintext bytes from this copy.
    pub fn zeroize_secrets(&mut self) {
        if let Some(kind) = self.content.as_mut().and_then(|c| c.kind.as_mut()) {
            match kind {
                Kind::Attachment(pointer) => pointer.zeroize(),
                Kind::File(file) => file.data.zeroize(),
                Kind::Image(data) => data.zeroize(),
                Kind::Text(text) => text.zeroize(),
                _ => {}
            }
        }
    }
}

/// The name of a history entry's record.
pub fn history_key(peer: &PublicKey, index: u64) -> String {
    format!("history/{}/{index:020}", hex(peer))
}

/// Compute the inclusive `[first, last]` history index bounds for `(history_len, limit)`.
/// Returns `None` when `history_len == 0` or `limit == 0` so `KeyRange::bound` is never called
/// with `lower > upper`.
fn history_bounds(history_len: u64, limit: u64) -> Option<(u64, u64)> {
    if limit == 0 {
        return None;
    }
    let last = history_len.checked_sub(1)?;
    let first = history_len.saturating_sub(limit);
    Some((first, last))
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

fn parse_upload_peer(key: &str) -> Option<PublicKey> {
    key.split('/')
        .nth(1)
        .and_then(from_hex)
        .and_then(|peer| PublicKey::try_from(peer).ok())
}

fn upsert_upload_checkpoint(
    checkpoints: &mut Vec<UploadCheckpoint>,
    peer: &PublicKey,
    upload: &PendingUpload,
) {
    let cp = UploadCheckpoint::from_upload(peer, upload);
    if let Some(existing) = checkpoints
        .iter_mut()
        .find(|c| c.peer.as_slice() == peer.as_slice() && c.id == upload.id)
    {
        *existing = cp;
    } else {
        checkpoints.push(cp);
    }
}

fn remove_upload_checkpoint(checkpoints: &mut Vec<UploadCheckpoint>, peer: &PublicKey, id: &[u8]) {
    checkpoints.retain(|c| !(c.peer.as_slice() == peer.as_slice() && c.id.as_slice() == id));
}

fn verify_upload_checkpoint(
    checkpoints: &[UploadCheckpoint],
    enforced: bool,
    peer: &PublicKey,
    upload: &PendingUpload,
) -> bool {
    match checkpoints
        .iter()
        .find(|c| c.peer.as_slice() == peer.as_slice() && c.id == upload.id)
    {
        Some(cp) => cp.matches(peer, upload),
        None => !enforced,
    }
}

/// Decode a batch of `(key, sealed_bytes)` upload records, skipping individual corrupt or
/// checkpoint-mismatched records so one damaged upload never breaks `uploads()` or `delete()`.
fn decode_uploads_tolerant(
    key: &[u8; 32],
    record_epoch: u64,
    checkpoints: &[UploadCheckpoint],
    records: impl IntoIterator<Item = (String, Vec<u8>)>,
) -> Vec<(PublicKey, PendingUpload)> {
    let enforced = record_epoch > 0;
    let mut out = Vec::new();
    for (name, sealed) in records {
        let Some(peer) = parse_upload_peer(&name) else {
            continue;
        };
        let Some(plain) = open_record_bytes(key, &name, record_epoch, &sealed) else {
            continue;
        };
        let Ok(upload) = PendingUpload::decode(plain.as_slice()) else {
            continue;
        };
        if !verify_upload_checkpoint(checkpoints, enforced, &peer, &upload) {
            continue;
        }
        out.push((peer, upload));
    }
    out
}

fn open_record_bytes(
    key: &[u8; 32],
    name: &str,
    record_epoch: u64,
    sealed: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let aad = record_aad(name, record_epoch);
    open_bytes(key, &aad, sealed)
}

/// Re-encrypted record set produced during an atomic v1 -> v2 KDF upgrade.
struct UpgradedV1Records {
    updated: Vec<(String, Vec<u8>)>,
    deleted: Vec<String>,
    deferred: DeferredInitialsRecord,
    checkpoints: Vec<UploadCheckpoint>,
    outbox_revs: BTreeMap<String, u64>,
}

/// Re-encrypt all non-header, non-state, non-attachment vault records during an atomic v1 -> v2
/// KDF upgrade (`old_key` -> `new_key`, binding `record_epoch = 1` and `outbox_revisions` /
/// `upload_checkpoints`).
fn upgrade_v1_records(
    old_key: &[u8; 32],
    new_key: &[u8; 32],
    record_epoch: u64,
    v2_revision: u64,
    records: Vec<(String, Vec<u8>)>,
) -> Result<UpgradedV1Records> {
    let mut updated = Vec::new();
    let mut deleted = Vec::new();
    let mut deferred = DeferredInitialsRecord::default();
    let mut checkpoints = Vec::new();
    let mut outbox_revs = BTreeMap::new();

    for (name, sealed) in records {
        if name == HEADER || name == STATE || name.starts_with("attachment/") {
            continue;
        }
        if name == DEFERRED_INITIALS {
            deferred = open_deferred_initials(old_key, &sealed)?;
            if !deferred.is_empty() {
                updated.push((name, try_seal_deferred_initials(new_key, &deferred)?));
            } else {
                deleted.push(name);
            }
            continue;
        }
        if name.starts_with("upload/") {
            let Some(peer) = parse_upload_peer(&name) else {
                deleted.push(name);
                continue;
            };
            let Some(plain) = open_bytes(old_key, name.as_bytes(), &sealed) else {
                deleted.push(name);
                continue;
            };
            let Ok(upload) = PendingUpload::decode(plain.as_slice()) else {
                deleted.push(name);
                continue;
            };
            upsert_upload_checkpoint(&mut checkpoints, &peer, &upload);
            let resealed = try_seal_bytes(new_key, &record_aad(&name, record_epoch), &plain)?;
            updated.push((name, resealed));
            continue;
        }
        if name.starts_with("outbox/") {
            let plain = open_bytes(old_key, name.as_bytes(), &sealed)
                .ok_or_else(|| Error::Corrupt(format!("{name} does not decrypt during upgrade")))?;
            let resealed = try_seal_bytes(
                new_key,
                &outbox_aad(&name, record_epoch, v2_revision),
                &plain,
            )?;
            outbox_revs.insert(name.clone(), v2_revision);
            updated.push((name, resealed));
            continue;
        }
        if name.starts_with("history/") || name.starts_with("file/") {
            let plain = open_bytes(old_key, name.as_bytes(), &sealed)
                .ok_or_else(|| Error::Corrupt(format!("{name} does not decrypt during upgrade")))?;
            let resealed = try_seal_bytes(new_key, &record_aad(&name, record_epoch), &plain)?;
            updated.push((name, resealed));
        }
    }
    Ok(UpgradedV1Records {
        updated,
        deleted,
        deferred,
        checkpoints,
        outbox_revs,
    })
}

#[derive(Debug)]
pub enum Error {
    /// IndexedDB failed, e.g. it is not available in a private window.
    Storage(String),
    /// The passphrase does not open the vault.
    WrongPassphrase,
    /// A record does not decode, failed parameter validation, or failed rollback/integrity check.
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
    /// Vault-instance epoch bound into per-record AADs (`0` only for pre-epoch legacy v2 vaults).
    record_epoch: u64,
    /// Authoritative upload checkpoints persisted inside `STATE`.
    upload_checkpoints: RefCell<Vec<UploadCheckpoint>>,
    /// Authoritative per-outbox-record revisions persisted inside `STATE`.
    outbox_revisions: RefCell<BTreeMap<String, u64>>,
}

/// Fail closed before opening or mutating any IndexedDB transaction once `pagehide` has released
/// this tab's exclusive Web Lock (or if the lock is not held).
fn ensure_vault_lock_owned() -> Result<()> {
    if !crate::glue::owns_lock() {
        return Err(Error::Storage("page is closing; tab lock released".into()));
    }
    Ok(())
}

fn outbox_revisions_to_proto(map: &BTreeMap<String, u64>) -> Vec<OutboxRevision> {
    map.iter()
        .map(|(key, &revision)| OutboxRevision {
            key: key.clone(),
            revision,
        })
        .collect()
}

fn outbox_revisions_from_proto(list: &[OutboxRevision]) -> BTreeMap<String, u64> {
    list.iter()
        .map(|entry| (entry.key.clone(), entry.revision))
        .collect()
}

impl Vault {
    /// Whether this browser has a vault.
    pub async fn exists() -> Result<bool> {
        Ok(get(&open().await?, HEADER).await?.is_some())
    }

    /// A new v2 vault holding `state`, under `passphrase`, replacing any other.
    pub async fn create(passphrase: &[u8], state: &AppState) -> Result<Self> {
        ensure_vault_lock_owned()?;
        let database = open().await?;
        let header = VaultHeader::try_new()?;
        let key = header.derive_key(passphrase)?;
        let header_bytes = header.encode_to_vec();
        let record_epoch = 1u64;
        let mut state_to_save = state.clone();
        state_to_save.record_epoch = record_epoch;
        state_to_save.upload_checkpoints.clear();
        state_to_save.outbox_revisions.clear();
        state_to_save.deferred_initials_digest =
            deferred_initials_digest(&DeferredInitialsRecord::default());
        let vault = Self {
            database,
            key,
            header: RefCell::new(header.clone()),
            record_epoch,
            upload_checkpoints: RefCell::new(Vec::new()),
            outbox_revisions: RefCell::new(BTreeMap::new()),
        };
        let sealed_state = vault.seal_with_aad(&state_v2_aad(&header_bytes), &state_to_save)?;
        state_to_save.zeroize_secrets();
        ensure_vault_lock_owned()?;
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
        write_rollback_anchor(&RollbackAnchor::for_v2_header(&header));
        Ok(vault)
    }

    /// Open the vault with `passphrase`, enforcing lock ownership, single-transaction snapshot
    /// reads, rollback-anchor verification, and atomic v1 -> v2 KDF + record upgrade.
    pub async fn unlock(passphrase: &[u8]) -> Result<(Self, AppState, DeferredInitialsRecord)> {
        ensure_vault_lock_owned()?;
        let database = open().await?;
        ensure_vault_lock_owned()?;
        // Read HEADER, STATE, and DEFERRED_INITIALS in one consistent ReadOnly snapshot.
        let (header_bytes, sealed_state, sealed_deferred) = {
            let tx = database.transaction(&[STORE], TransactionMode::ReadOnly)?;
            let store = tx.object_store(STORE)?;
            let header = store
                .get(JsValue::from_str(HEADER))?
                .await?
                .map(|v| Uint8Array::new(&v).to_vec())
                .ok_or_else(|| Error::Corrupt("no vault".into()))?;
            let state = store
                .get(JsValue::from_str(STATE))?
                .await?
                .map(|v| Uint8Array::new(&v).to_vec())
                .ok_or_else(|| Error::Corrupt("no state".into()))?;
            let deferred = store
                .get(JsValue::from_str(DEFERRED_INITIALS))?
                .await?
                .map(|v| Uint8Array::new(&v).to_vec());
            (header, state, deferred)
        };
        let header = VaultHeader::decode(header_bytes.as_slice())
            .map_err(|e| Error::Corrupt(e.to_string()))?;
        // Validate version, salt, Argon2 parameters, and rollback anchor BEFORE deriving key.
        header.validate()?;
        let anchor = read_rollback_anchor();
        check_unlock_against_anchor(anchor.as_ref(), &header)?;
        let key = header.derive_key(passphrase)?;

        if header.is_legacy_v1() {
            // Unlock legacy v1 vault with `"state"` AAD, then atomically re-key with default
            // 64 MiB Argon2id params + fresh salt and re-encrypt all vault records in one RW tx.
            let plain =
                open_bytes(&key, STATE.as_bytes(), &sealed_state).ok_or(Error::WrongPassphrase)?;
            let mut state =
                AppState::decode(plain.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))?;

            let v2_header = VaultHeader::try_new()?;
            let new_key = v2_header.derive_key(passphrase)?;
            let v2_header_bytes = v2_header.encode_to_vec();
            let record_epoch = 1u64;

            ensure_vault_lock_owned()?;
            let transaction = database.transaction(&[STORE], TransactionMode::ReadWrite)?;
            let store = transaction.object_store(STORE)?;
            let current = match store.get(JsValue::from_str(HEADER))?.await? {
                Some(v) => Uint8Array::new(&v).to_vec(),
                None => {
                    let _ = transaction.abort();
                    return Err(Error::Corrupt("no vault".into()));
                }
            };
            if let Err(e) = ensure_vault_lock_owned() {
                let _ = transaction.abort();
                return Err(e);
            }
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
            let keys = store.get_all_keys(None, None)?.await?;
            let values = store.get_all(None, None)?.await?;
            let all_records: Vec<(String, Vec<u8>)> = keys
                .into_iter()
                .zip(values)
                .map(|(k, v)| {
                    (
                        k.as_string().unwrap_or_default(),
                        Uint8Array::new(&v).to_vec(),
                    )
                })
                .collect();
            let UpgradedV1Records {
                updated,
                deleted,
                deferred,
                checkpoints,
                outbox_revs,
            } = match upgrade_v1_records(
                &key,
                &new_key,
                record_epoch,
                v2_header.revision,
                all_records,
            ) {
                Ok(res) => res,
                Err(e) => {
                    let _ = transaction.abort();
                    return Err(e);
                }
            };
            state.record_epoch = record_epoch;
            state.upload_checkpoints = checkpoints.clone();
            state.outbox_revisions = outbox_revisions_to_proto(&outbox_revs);
            state.deferred_initials_digest = deferred_initials_digest(&deferred);
            let encoded_state = Zeroizing::new(state.encode_to_vec());
            let v2_sealed_state =
                match try_seal_bytes(&new_key, &state_v2_aad(&v2_header_bytes), &encoded_state) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = transaction.abort();
                        return Err(e);
                    }
                };
            let write_res: Result<()> = (|| {
                for (name, sealed) in &updated {
                    store.put(&bytes(sealed), Some(&name.as_str().into()))?;
                }
                for name in &deleted {
                    store.delete(JsValue::from_str(name))?;
                }
                store.put(&bytes(&v2_sealed_state), Some(&STATE.into()))?;
                store.put(&bytes(&v2_header_bytes), Some(&HEADER.into()))?;
                Ok(())
            })();
            if let Err(e) = write_res {
                let _ = transaction.abort();
                return Err(e);
            }
            commit(transaction).await?;
            write_rollback_anchor(&RollbackAnchor::for_v2_header(&v2_header));

            let vault = Self {
                database,
                key: new_key,
                header: RefCell::new(v2_header),
                record_epoch,
                upload_checkpoints: RefCell::new(checkpoints),
                outbox_revisions: RefCell::new(outbox_revs),
            };
            Ok((vault, state, deferred))
        } else {
            let plain = open_bytes(&key, &state_v2_aad(&header_bytes), &sealed_state)
                .ok_or(Error::WrongPassphrase)?;
            let state =
                AppState::decode(plain.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))?;
            let deferred = match sealed_deferred {
                Some(sealed) => open_deferred_initials(&key, &sealed)?,
                None => DeferredInitialsRecord::default(),
            };
            verify_deferred_initials_digest(&state.deferred_initials_digest, &deferred)?;
            let next_anchor = advance_anchor(anchor.as_ref(), &header);
            write_rollback_anchor(&next_anchor);
            let record_epoch = state.record_epoch;
            let checkpoints = state.upload_checkpoints.clone();
            let outbox_revs = outbox_revisions_from_proto(&state.outbox_revisions);
            let vault = Self {
                database,
                key,
                header: RefCell::new(header),
                record_epoch,
                upload_checkpoints: RefCell::new(checkpoints),
                outbox_revisions: RefCell::new(outbox_revs),
            };
            Ok((vault, state, deferred))
        }
    }

    /// Open an IndexedDB RW transaction and enforce lock ownership plus monotonic CAS revision
    /// BEFORE any writes.
    async fn begin_checked_rw_tx(
        &self,
    ) -> Result<(idb::Transaction, idb::ObjectStore, VaultHeader)> {
        ensure_vault_lock_owned()?;
        let transaction = self
            .database
            .transaction(&[STORE], TransactionMode::ReadWrite)?;
        let store = transaction.object_store(STORE)?;
        let current = match store.get(JsValue::from_str(HEADER))?.await? {
            Some(v) => Uint8Array::new(&v).to_vec(),
            None => {
                let _ = transaction.abort();
                return Err(Error::Corrupt("vault header missing".into()));
            }
        };
        if let Err(e) = ensure_vault_lock_owned() {
            let _ = transaction.abort();
            return Err(e);
        }
        match verify_checked_header(&self.header.borrow(), &current) {
            Ok(trusted) => Ok((transaction, store, trusted)),
            Err(e) => {
                let _ = transaction.abort();
                Err(e)
            }
        }
    }

    fn prepare_state_for_commit(
        &self,
        state: &AppState,
        deferred: &DeferredInitialsRecord,
        checkpoints: &[UploadCheckpoint],
        outbox_revs: &BTreeMap<String, u64>,
        next_header_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        let mut stamped = state.clone();
        stamped.record_epoch = self.record_epoch;
        stamped.upload_checkpoints = checkpoints.to_vec();
        stamped.outbox_revisions = outbox_revisions_to_proto(outbox_revs);
        stamped.deferred_initials_digest = deferred_initials_digest(deferred);
        let sealed = self.seal_with_aad(&state_v2_aad(next_header_bytes), &stamped);
        stamped.zeroize_secrets();
        sealed
    }

    fn commit_header_and_anchor(&self, next_header: VaultHeader) {
        let anchor = read_rollback_anchor();
        let next_anchor = advance_anchor(anchor.as_ref(), &next_header);
        write_rollback_anchor(&next_anchor);
        *self.header.borrow_mut() = next_header;
    }

    /// Save `state`, `deferred`, `entries`, each file of theirs in a record of its own, and
    /// `outgoing`, the records of messages waiting to be pushed, or none for one that went,
    /// together, or none of them, enforcing monotonic `revision` CAS inside the transaction.
    pub async fn save<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredInitialsRecord,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> Result<()> {
        let (transaction, store, trusted) = self.begin_checked_rw_tx().await?;
        let next_header = trusted.next_revision()?;
        let next_header_bytes = next_header.encode_to_vec();
        let outgoing_vec: Vec<(String, Option<&OutgoingRecord>)> = outgoing
            .into_iter()
            .map(|(peer, index, record)| (outbox_key(peer, *index), record.as_ref()))
            .collect();
        let mut next_outbox_revs = self.outbox_revisions.borrow().clone();
        for (key, record) in &outgoing_vec {
            if record.is_some() {
                next_outbox_revs.insert(key.clone(), next_header.revision);
            } else {
                next_outbox_revs.remove(key);
            }
        }
        let checkpoints = self.upload_checkpoints.borrow().clone();
        let sealed_state = match self.prepare_state_for_commit(
            state,
            deferred,
            &checkpoints,
            &next_outbox_revs,
            &next_header_bytes,
        ) {
            Ok(s) => s,
            Err(e) => {
                let _ = transaction.abort();
                return Err(e);
            }
        };
        let write_res: Result<()> = (|| {
            self.put_entries(&store, entries)?;
            self.put_outgoing(&store, &outgoing_vec, next_header.revision)?;
            self.put_deferred_initials(&store, deferred)?;
            store.put(&bytes(&sealed_state), Some(&STATE.into()))?;
            store.put(&bytes(&next_header_bytes), Some(&HEADER.into()))?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = transaction.abort();
            return Err(e);
        }
        commit(transaction).await?;
        *self.outbox_revisions.borrow_mut() = next_outbox_revs;
        self.commit_header_and_anchor(next_header);
        Ok(())
    }

    /// Put or delete the separate encrypted [`DEFERRED_INITIALS`] record in `store`.
    fn put_deferred_initials(
        &self,
        store: &idb::ObjectStore,
        deferred: &DeferredInitialsRecord,
    ) -> Result<()> {
        if deferred.is_empty() {
            store.delete(JsValue::from_str(DEFERRED_INITIALS))?;
        } else {
            let sealed = try_seal_deferred_initials(&self.key, deferred)?;
            store.put(&bytes(&sealed), Some(&DEFERRED_INITIALS.into()))?;
        }
        Ok(())
    }

    /// Put or delete `outgoing` records in `store`, binding each to `revision`.
    fn put_outgoing(
        &self,
        store: &idb::ObjectStore,
        outgoing: &[(String, Option<&OutgoingRecord>)],
        revision: u64,
    ) -> Result<()> {
        for (key, record) in outgoing {
            match record {
                Some(record) => {
                    let aad = outbox_aad(key, self.record_epoch, revision);
                    let sealed = self.seal_with_aad(&aad, *record)?;
                    store.put(&bytes(&sealed), Some(&key.as_str().into()))?;
                }
                None => {
                    store.delete(JsValue::from_str(key))?;
                }
            }
        }
        Ok(())
    }

    /// Put `entries` in `store`, each file of theirs in a record of its own.
    fn put_entries<'a>(
        &self,
        store: &idb::ObjectStore,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
    ) -> Result<()> {
        for (peer, index, entry) in entries {
            let key = history_key(peer, *index);
            let (mut entry, data) = entry.without_file();
            if let Some(data) = data {
                let name = file_key(peer, *index);
                let mut record = FileRecord {
                    data: data.to_vec(),
                };
                let sealed = self.seal_record(&name, &record)?;
                record.data.zeroize();
                store.put(&bytes(&sealed), Some(&name.as_str().into()))?;
            }
            let sealed_entry = self.seal_record(&key, &entry)?;
            entry.zeroize_secrets();
            store.put(&bytes(&sealed_entry), Some(&key.as_str().into()))?;
        }
        Ok(())
    }

    /// The bytes of the file of the history entry `index` of the chat with `peer`.
    pub async fn file(&self, peer: &PublicKey, index: u64) -> Result<Vec<u8>> {
        let name = file_key(peer, index);
        self.file_data(&name)
            .await?
            .ok_or_else(|| Error::Corrupt(format!("{name} is missing")))
    }

    async fn file_data(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let Some(sealed) = get(&self.database, name).await? else {
            return Ok(None);
        };
        let record = self
            .open_record(name, &sealed)
            .ok_or_else(|| Error::Corrupt(format!("{name} does not decrypt")))?;
        FileRecord::decode(record.as_slice())
            .map(|record| Some(record.data))
            .map_err(|e| Error::Corrupt(e.to_string()))
    }

    /// The content of the history entry `index` of the chat with `peer`.
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
            let Some(data) = self.file_data(&file_key(peer, index)).await? else {
                return Ok(None);
            };
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
            .open_record(&name, &sealed)
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
        let expected_rev = self.outbox_revisions.borrow().get(&name).copied();
        let record = match expected_rev {
            Some(rev) => open_bytes(
                &self.key,
                &outbox_aad(&name, self.record_epoch, rev),
                &sealed,
            ),
            None if self.record_epoch == 0 => open_bytes(&self.key, name.as_bytes(), &sealed),
            None => None,
        }
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
        let Some((first, last)) = history_bounds(history_len, limit) else {
            return Ok(vec![]);
        };
        let range = history_range(peer, first, last)?;
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
                let index = key
                    .rsplit('/')
                    .next()
                    .and_then(|index| index.parse().ok())
                    .ok_or_else(|| Error::Corrupt(format!("{key} is not a history entry")))?;
                let entry = self
                    .open_record(&key, &Uint8Array::new(&value).to_vec())
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

    /// Keep `upload` in the chat with `peer`, replacing any previous copy, and bind its
    /// checkpoint into `STATE` in the same transaction.
    pub async fn save_upload(&self, peer: &PublicKey, upload: &PendingUpload) -> Result<()> {
        let name = upload_key(peer, &upload.id);
        let sealed = self.seal_record(&name, upload)?;
        self.write_upload(peer, &upload.id, &name, Some((upload, &sealed)))
            .await
    }

    /// Atomically promote a waiting sign-in upload (`old_id`) into a server-started `new_upload`
    /// together with the updated `state`, `deferred`, `entries`, and `outgoing` in a single
    /// IndexedDB RW transaction (preventing orphaned uploads or stale placeholder pointers on crash).
    #[allow(clippy::too_many_arguments)]
    pub async fn promote_upload<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredInitialsRecord,
        peer: &PublicKey,
        old_id: &[u8],
        new_upload: &PendingUpload,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> Result<()> {
        let (transaction, store, trusted) = self.begin_checked_rw_tx().await?;
        let next_header = trusted.next_revision()?;
        let next_header_bytes = next_header.encode_to_vec();
        let outgoing_vec: Vec<(String, Option<&OutgoingRecord>)> = outgoing
            .into_iter()
            .map(|(p, index, record)| (outbox_key(p, *index), record.as_ref()))
            .collect();
        let mut next_outbox_revs = self.outbox_revisions.borrow().clone();
        for (key, record) in &outgoing_vec {
            if record.is_some() {
                next_outbox_revs.insert(key.clone(), next_header.revision);
            } else {
                next_outbox_revs.remove(key);
            }
        }
        let mut next_checkpoints = self.upload_checkpoints.borrow().clone();
        remove_upload_checkpoint(&mut next_checkpoints, peer, old_id);
        upsert_upload_checkpoint(&mut next_checkpoints, peer, new_upload);

        let sealed_state = match self.prepare_state_for_commit(
            state,
            deferred,
            &next_checkpoints,
            &next_outbox_revs,
            &next_header_bytes,
        ) {
            Ok(s) => s,
            Err(e) => {
                let _ = transaction.abort();
                return Err(e);
            }
        };
        let new_name = upload_key(peer, &new_upload.id);
        let sealed_upload = match self.seal_record(&new_name, new_upload) {
            Ok(s) => s,
            Err(e) => {
                let _ = transaction.abort();
                return Err(e);
            }
        };
        let old_name = upload_key(peer, old_id);
        let write_res: Result<()> = (|| {
            store.put(&bytes(&sealed_upload), Some(&new_name.as_str().into()))?;
            if old_name != new_name {
                store.delete(JsValue::from_str(&old_name))?;
            }
            self.put_entries(&store, entries)?;
            self.put_outgoing(&store, &outgoing_vec, next_header.revision)?;
            self.put_deferred_initials(&store, deferred)?;
            store.put(&bytes(&sealed_state), Some(&STATE.into()))?;
            store.put(&bytes(&next_header_bytes), Some(&HEADER.into()))?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = transaction.abort();
            return Err(e);
        }
        commit(transaction).await?;
        *self.upload_checkpoints.borrow_mut() = next_checkpoints;
        *self.outbox_revisions.borrow_mut() = next_outbox_revs;
        self.commit_header_and_anchor(next_header);
        Ok(())
    }

    /// Forget the upload once cancelled or deleted from the server, removing its checkpoint from
    /// `STATE` in the same transaction.
    pub async fn forget_upload(&self, peer: &PublicKey, id: &[u8]) -> Result<()> {
        let name = upload_key(peer, id);
        self.write_upload(peer, id, &name, None).await
    }

    /// Advance the revision, update `AppState.upload_checkpoints`, and rebind `STATE` to the new
    /// header in the same transaction as the upload record mutation.
    async fn write_upload(
        &self,
        peer: &PublicKey,
        id: &[u8],
        name: &str,
        upload: Option<(&PendingUpload, &[u8])>,
    ) -> Result<()> {
        let (transaction, store, trusted) = self.begin_checked_rw_tx().await?;
        let write = async {
            let state_raw = store
                .get(JsValue::from_str(STATE))?
                .await?
                .ok_or_else(|| Error::Corrupt("no state".into()))?;
            ensure_vault_lock_owned()?;
            let state_bytes = Uint8Array::new(&state_raw).to_vec();
            let plain = open_bytes(
                &self.key,
                &state_v2_aad(&trusted.encode_to_vec()),
                &state_bytes,
            )
            .ok_or_else(|| Error::Corrupt("vault state failed authentication".into()))?;
            let mut app_state =
                AppState::decode(plain.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))?;

            let mut next_checkpoints = self.upload_checkpoints.borrow().clone();
            match upload {
                Some((pending, _)) => {
                    upsert_upload_checkpoint(&mut next_checkpoints, peer, pending)
                }
                None => remove_upload_checkpoint(&mut next_checkpoints, peer, id),
            }
            app_state.record_epoch = self.record_epoch;
            app_state.upload_checkpoints = next_checkpoints.clone();

            let next = trusted.next_revision()?;
            let header = next.encode_to_vec();
            let sealed = self.seal_with_aad(&state_v2_aad(&header), &app_state);
            app_state.zeroize_secrets();
            let sealed = sealed?;

            let name = JsValue::from_str(name);
            match upload {
                Some((_, sealed_upload)) => {
                    store.put(&bytes(sealed_upload), Some(&name))?;
                }
                None => {
                    store.delete(name)?;
                }
            }
            store.put(&bytes(&sealed), Some(&STATE.into()))?;
            store.put(&bytes(&header), Some(&HEADER.into()))?;
            Ok((next, next_checkpoints))
        }
        .await;
        let (next, next_checkpoints) = match write {
            Ok(res) => res,
            Err(e) => {
                let _ = transaction.abort();
                return Err(e);
            }
        };
        commit(transaction).await?;
        *self.upload_checkpoints.borrow_mut() = next_checkpoints;
        self.commit_header_and_anchor(next);
        Ok(())
    }

    /// The upload `id`, in the chat with `peer`, if kept and matching its `STATE` checkpoint.
    pub async fn upload(&self, peer: &PublicKey, id: &[u8]) -> Result<Option<PendingUpload>> {
        let name = upload_key(peer, id);
        let Some(sealed) = get(&self.database, &name).await? else {
            return Ok(None);
        };
        let upload = self
            .open_record(&name, &sealed)
            .ok_or_else(|| Error::Corrupt(format!("{name} does not decrypt")))?;
        let upload =
            PendingUpload::decode(upload.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))?;
        let enforced = self.record_epoch > 0;
        if !verify_upload_checkpoint(&self.upload_checkpoints.borrow(), enforced, peer, &upload) {
            return Err(Error::Corrupt(format!(
                "{name} does not match authenticated upload checkpoint"
            )));
        }
        Ok(Some(upload))
    }

    /// The uploads kept, those not done, with the peers of their chats: those of the chat with
    /// `peer` only, if given. Tolerates individual corrupt or stale upload records so one damaged
    /// entry cannot block vault unlock or chat deletion.
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
        let raw_records = keys.into_iter().zip(values).map(|(k, v)| {
            (
                k.as_string().unwrap_or_default(),
                Uint8Array::new(&v).to_vec(),
            )
        });
        Ok(decode_uploads_tolerant(
            &self.key,
            self.record_epoch,
            &self.upload_checkpoints.borrow(),
            raw_records,
        ))
    }

    /// Save `state` and `deferred`, without the history, files, outbox, attachments and uploads
    /// of the chat with `peer`, and `entries` / `outgoing` of other chats with it, enforcing
    /// monotonic `revision` CAS.
    pub async fn forget<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredInitialsRecord,
        peer: &PublicKey,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> Result<()> {
        let (transaction, store, trusted) = self.begin_checked_rw_tx().await?;
        let next_header = trusted.next_revision()?;
        let next_header_bytes = next_header.encode_to_vec();
        let outgoing_vec: Vec<(String, Option<&OutgoingRecord>)> = outgoing
            .into_iter()
            .map(|(p, index, record)| (outbox_key(p, *index), record.as_ref()))
            .collect();
        let peer_outbox_prefix = format!("outbox/{}/", hex(peer));
        let mut next_outbox_revs = self.outbox_revisions.borrow().clone();
        next_outbox_revs.retain(|k, _| !k.starts_with(&peer_outbox_prefix));
        for (key, record) in &outgoing_vec {
            if record.is_some() {
                next_outbox_revs.insert(key.clone(), next_header.revision);
            } else {
                next_outbox_revs.remove(key);
            }
        }
        let mut next_checkpoints = self.upload_checkpoints.borrow().clone();
        next_checkpoints.retain(|cp| cp.peer.as_slice() != peer.as_slice());

        let sealed_state = match self.prepare_state_for_commit(
            state,
            deferred,
            &next_checkpoints,
            &next_outbox_revs,
            &next_header_bytes,
        ) {
            Ok(s) => s,
            Err(e) => {
                let _ = transaction.abort();
                return Err(e);
            }
        };
        let write_res: Result<()> = (|| {
            store.delete(history_range(peer, 0, u64::MAX)?)?;
            for prefix in ["file", "outbox", "attachment", "upload"] {
                store.delete(prefix_range(&format!("{prefix}/{}/", hex(peer)))?)?;
            }
            self.put_entries(&store, entries)?;
            self.put_outgoing(&store, &outgoing_vec, next_header.revision)?;
            self.put_deferred_initials(&store, deferred)?;
            store.put(&bytes(&sealed_state), Some(&STATE.into()))?;
            store.put(&bytes(&next_header_bytes), Some(&HEADER.into()))?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = transaction.abort();
            return Err(e);
        }
        commit(transaction).await?;
        *self.upload_checkpoints.borrow_mut() = next_checkpoints;
        *self.outbox_revisions.borrow_mut() = next_outbox_revs;
        self.commit_header_and_anchor(next_header);
        Ok(())
    }

    /// Delete the vault for good and clear its external rollback anchor.
    pub async fn destroy() -> Result<()> {
        ensure_vault_lock_owned()?;
        let database = open().await?;
        ensure_vault_lock_owned()?;
        let transaction = database.transaction(&[STORE], TransactionMode::ReadWrite)?;
        transaction.object_store(STORE)?.clear()?;
        commit(transaction).await?;
        clear_rollback_anchor();
        Ok(())
    }

    /// `record`, encrypted under explicit `aad`. Its plaintext, which holds keys, is zeroized.
    fn seal_with_aad(&self, aad: &[u8], record: &impl Message) -> Result<Vec<u8>> {
        let plaintext = Zeroizing::new(record.encode_to_vec());
        try_seal_bytes(&self.key, aad, &plaintext)
    }

    /// `record`, encrypted under `record_aad(name, self.record_epoch)`.
    fn seal_record(&self, name: &str, record: &impl Message) -> Result<Vec<u8>> {
        self.seal_with_aad(&record_aad(name, self.record_epoch), record)
    }

    /// The plaintext of the record `name`, zeroized once dropped; `None` if it does not decrypt.
    fn open_record(&self, name: &str, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        open_record_bytes(&self.key, name, self.record_epoch, sealed)
    }
}

/// Pure helper verifying an upload's persisted `sealed_chunk_hash` map for `Upload::resume_with_digests`.
#[allow(dead_code)] // Available to tests and cross-module verification.
pub fn upload_resume_digests(upload: &PendingUpload) -> HashMap<u32, [u8; 32]> {
    let mut digests = HashMap::new();
    if upload.encrypted > upload.uploaded
        && let Ok(hash) = <[u8; 32]>::try_from(upload.sealed_chunk_hash.as_slice())
    {
        digests.insert(upload.uploaded, hash);
    }
    digests
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
            assert!(matches!(
                bad.derive_key(b"passphrase"),
                Err(Error::Corrupt(_))
            ));
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
        let key = legacy_header
            .derive_key(b"correct horse battery staple")
            .unwrap();

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
            open_bytes(
                &key,
                &state_v2_aad(&tampered_rev.encode_to_vec()),
                &v2_sealed
            )
            .is_none()
        );

        let mut tampered_mem = v2_header;
        tampered_mem.memory = ARGON2_DEFAULT_MEMORY;
        assert!(
            open_bytes(
                &key,
                &state_v2_aad(&tampered_mem.encode_to_vec()),
                &v2_sealed
            )
            .is_none()
        );
    }

    #[test]
    fn checked_header_requires_the_authenticated_encoding() {
        let trusted = VaultHeader::new();
        assert_eq!(
            verify_checked_header(&trusted, &trusted.encode_to_vec()).unwrap(),
            trusted
        );
        for field in 0..6 {
            let mut changed = trusted.clone();
            match field {
                0 => changed.salt[0] ^= 1,
                1 => changed.memory += 1,
                2 => changed.iterations += 1,
                3 => changed.parallelism += 1,
                4 => changed.revision += 1,
                _ => changed.version = 1,
            }
            let error = verify_checked_header(&trusted, &changed.encode_to_vec()).unwrap_err();
            if field < 4 {
                assert!(matches!(error, Error::Corrupt(_)));
            } else {
                assert!(matches!(error, Error::Conflict { .. }));
            }
        }
        let mut extra = trusted.encode_to_vec();
        extra.extend([0x38, 1]);
        assert!(matches!(
            verify_checked_header(&trusted, &extra),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn upload_revisions_authenticate_state_at_each_commit() {
        let key = [42; 32];
        let mut current = VaultHeader::new();
        let mut sealed = seal_bytes(&key, &state_v2_aad(&current.encode_to_vec()), b"state");
        for _ in 0..2 {
            let (next, header, updated) =
                reseal_state_for_next_revision(&key, &current, &sealed).unwrap();
            assert_eq!(next.revision, current.revision + 1);
            assert_eq!(next.encode_to_vec(), header);
            assert_eq!(
                &**open_bytes(&key, &state_v2_aad(&header), &updated).unwrap(),
                b"state"
            );
            assert!(open_bytes(&key, &state_v2_aad(&current.encode_to_vec()), &updated).is_none());
            current = next;
            sealed = updated;
        }
        sealed[0] ^= 1;
        assert!(matches!(
            reseal_state_for_next_revision(&key, &current, &sealed),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn pending_upload_wipes_both_secrets() {
        fn requires_wipe_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let mut upload = PendingUpload::default();
        upload.token.extend([1; 16]);
        upload.key.extend([2; 32]);
        upload.prefix_hash.extend([3; 32]);
        upload.sealed_chunk_hash.extend([4; 32]);
        requires_wipe_on_drop(&upload);
        upload.clear_secrets();
        assert!(upload.token.is_empty() && upload.key.is_empty());
        assert!(upload.prefix_hash.is_empty() && upload.sealed_chunk_hash.is_empty());
    }

    #[test]
    fn deferred_initials_separate_record_survives_older_state_overwrite() {
        let key = [0x5Au8; 32];
        let header_v1 = VaultHeader::new();
        let state_v1 = AppState {
            name: "Alice".to_string(),
            pending_inbox_acks: vec![42],
            ..AppState::default()
        };
        assert!(state_v1.deferred_initials.is_empty());
        let deferred = DeferredInitialsRecord {
            entries: vec![DeferredInitial {
                initial: Some(session::protocol::handshake_v2::InitialMessageV2 {
                    version: 2,
                    identity_key: vec![0x11; 32].into(),
                    ephemeral_key: vec![0x22; 32].into(),
                    signed_prekey: vec![0x33; 32].into(),
                    pq_suite: 1,
                    pq_last_resort: true,
                    pq_prekey_id: vec![0x44; 32].into(),
                    pq_ciphertext: vec![0x55; 1568].into(),
                    ..Default::default()
                }),
                deferred_at: 1_700_000_000_000,
            }],
            carried_timestamps: vec![CarriedDeferredTimestamp {
                signed_prekey: vec![0x33; 32],
                deferred_at: 1_700_000_000_123,
            }],
        };

        let sealed_state_1 = seal_bytes(
            &key,
            &state_v2_aad(&header_v1.encode_to_vec()),
            &state_v1.encode_to_vec(),
        );
        let sealed_deferred = seal_deferred_initials(&key, &deferred);

        // Simulate rolling back to an older `dev` bundle that unlocks `STATE`, advances
        // `VaultHeader.revision`, and overwrites `STATE` without knowing about `DEFERRED_INITIALS`.
        let (header_v2, header_v2_bytes, sealed_state_2) =
            reseal_state_for_next_revision(&key, &header_v1, &sealed_state_1).unwrap();
        assert_eq!(header_v2.revision, header_v1.revision + 1);
        assert!(open_bytes(&key, &state_v2_aad(&header_v2_bytes), &sealed_state_2).is_some());

        // The separate `DEFERRED_INITIALS` record still decrypts cleanly after the `STATE` overwrite!
        let restored = open_deferred_initials(&key, &sealed_deferred).unwrap();
        assert_eq!(restored, deferred);

        // Wrong key or wrong AAD fails authentication.
        let wrong_key = [0xA5u8; 32];
        assert!(matches!(
            open_deferred_initials(&wrong_key, &sealed_deferred),
            Err(Error::Corrupt(_))
        ));
        assert!(open_bytes(&key, STATE.as_bytes(), &sealed_deferred).is_none());
    }

    #[test]
    fn rollback_anchor_rejects_v1_replay_and_v2_revision_or_salt_rollback() {
        let mut h = VaultHeader::new();
        h.revision = 5;
        let anchor = RollbackAnchor::for_v2_header(&h);
        assert_eq!(
            RollbackAnchor::parse(&anchor.encode()),
            Some(anchor.clone())
        );

        // Same or higher revision with matching salt succeeds.
        assert!(check_unlock_against_anchor(Some(&anchor), &h).is_ok());
        let mut newer = h.clone();
        newer.revision = 6;
        assert!(check_unlock_against_anchor(Some(&anchor), &newer).is_ok());

        // Lower revision with same salt is rejected.
        let mut older = h.clone();
        older.revision = 4;
        assert!(matches!(
            check_unlock_against_anchor(Some(&anchor), &older),
            Err(Error::Corrupt(_))
        ));

        // Legacy v1 replay is rejected once `migrated_v2` is set.
        let v1 = VaultHeader {
            salt: vec![0x22; 16],
            memory: ARGON2_MEMORY_MIN,
            iterations: 1,
            parallelism: 1,
            version: 0,
            revision: 0,
        };
        assert!(matches!(
            check_unlock_against_anchor(Some(&anchor), &v1),
            Err(Error::Corrupt(_))
        ));

        // Different salt on v2 is rejected as possible vault replacement/rollback.
        let mut swapped_salt = h.clone();
        swapped_salt.salt[0] ^= 0xFF;
        swapped_salt.revision = 10;
        assert!(matches!(
            check_unlock_against_anchor(Some(&anchor), &swapped_salt),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn per_record_aad_and_deferred_digest_detect_record_swaps() {
        let key = [0x33u8; 32];
        let peer = [0x11u8; 32];
        let out_name = outbox_key(&peer, 7);

        // Outbox record bound to revision 5 cannot be replayed at revision 6 or legacy AAD.
        let sealed_rev5 = try_seal_bytes(&key, &outbox_aad(&out_name, 1, 5), b"msg-v5").unwrap();
        assert!(open_bytes(&key, &outbox_aad(&out_name, 1, 5), &sealed_rev5).is_some());
        assert!(open_bytes(&key, &outbox_aad(&out_name, 1, 6), &sealed_rev5).is_none());
        assert!(open_bytes(&key, out_name.as_bytes(), &sealed_rev5).is_none());

        // Deferred initials digest detects swapping an old non-empty record when state expects empty.
        let empty = DeferredInitialsRecord::default();
        let non_empty = DeferredInitialsRecord {
            entries: vec![DeferredInitial {
                initial: None,
                deferred_at: 123,
            }],
            carried_timestamps: vec![],
        };
        let empty_digest = deferred_initials_digest(&empty);
        assert_eq!(empty_digest.len(), 32);
        assert!(verify_deferred_initials_digest(&empty_digest, &empty).is_ok());
        assert!(matches!(
            verify_deferred_initials_digest(&empty_digest, &non_empty),
            Err(Error::Corrupt(_))
        ));
        // Empty expected digest remains backwards-compatible with legacy bundles.
        assert!(verify_deferred_initials_digest(&[], &non_empty).is_ok());
    }

    #[test]
    fn v1_to_v2_upgrade_rekeys_all_records_and_populates_checkpoints() {
        let old_key = [0x12u8; 32];
        let new_key = [0x34u8; 32];
        let peer = [0xABu8; 32];
        let hist_k = history_key(&peer, 0);
        let out_k = outbox_key(&peer, 1);
        let up_id = [0x77u8; 16];
        let up_k = upload_key(&peer, &up_id);
        let upload = PendingUpload {
            id: up_id.to_vec(),
            token: vec![1; 16],
            key: vec![2; 32],
            name: "photo.jpg".into(),
            mime: "image/jpeg".into(),
            size: 100,
            uploaded: 0,
            encrypted: 1,
            prefix_hash: vec![9; 32],
            announced: true,
            history_index: 0,
            expires: 0,
            upload_state: UPLOAD_STATE_ANNOUNCED,
            sealed_chunk_hash: vec![8; 32],
        };
        let records = vec![
            (
                hist_k.clone(),
                seal_bytes(&old_key, hist_k.as_bytes(), b"hist"),
            ),
            (
                out_k.clone(),
                seal_bytes(&old_key, out_k.as_bytes(), b"out"),
            ),
            (
                up_k.clone(),
                seal_bytes(&old_key, up_k.as_bytes(), &upload.encode_to_vec()),
            ),
            ("attachment/aa/bb/0000000000".into(), b"raw-chunk".to_vec()),
        ];

        let UpgradedV1Records {
            updated,
            deleted,
            deferred,
            checkpoints,
            outbox_revs,
        } = upgrade_v1_records(&old_key, &new_key, 1, 1, records).unwrap();
        assert!(deleted.is_empty());
        assert!(deferred.is_empty());
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(outbox_revs.get(&out_k), Some(&1));

        let by_name: HashMap<String, Vec<u8>> = updated.into_iter().collect();
        // Attachments are left untouched.
        assert!(!by_name.contains_key("attachment/aa/bb/0000000000"));
        // History and upload decrypt under `new_key` with epoch 1 AAD, not `old_key`.
        assert_eq!(
            &**open_record_bytes(&new_key, &hist_k, 1, &by_name[&hist_k]).unwrap(),
            b"hist"
        );
        assert!(open_bytes(&old_key, hist_k.as_bytes(), &by_name[&hist_k]).is_none());
        assert_eq!(
            &**open_bytes(&new_key, &outbox_aad(&out_k, 1, 1), &by_name[&out_k]).unwrap(),
            b"out"
        );
        // Valid upload passes checkpoint verification; rolled-back upload is rejected.
        let decoded = decode_uploads_tolerant(
            &new_key,
            1,
            &checkpoints,
            vec![(up_k.clone(), by_name[&up_k].clone())],
        );
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].1.name, "photo.jpg");
    }

    #[test]
    fn history_bounds_guards_zero_limit_and_empty_history() {
        assert_eq!(history_bounds(0, 0), None);
        assert_eq!(history_bounds(0, 50), None);
        assert_eq!(history_bounds(10, 0), None);
        assert_eq!(history_bounds(10, 1), Some((9, 9)));
        assert_eq!(history_bounds(10, 5), Some((5, 9)));
        assert_eq!(history_bounds(10, 500), Some((0, 9)));
    }

    #[test]
    fn decode_uploads_tolerant_skips_corrupt_and_stale_records() {
        let key = [0x55u8; 32];
        let peer = [0x22u8; 32];
        let good_id = [0x01u8; 16];
        let stale_id = [0x02u8; 16];
        let bad_id = [0x03u8; 16];

        let mut good = PendingUpload::default();
        good.id = good_id.to_vec();
        good.name = "good.bin".into();
        good.uploaded = 2;
        good.encrypted = 2;
        good.prefix_hash = vec![1; 32];
        good.upload_state = UPLOAD_STATE_ANNOUNCED;

        let mut stale_old = PendingUpload::default();
        stale_old.id = stale_id.to_vec();
        stale_old.name = "stale.bin".into();
        stale_old.uploaded = 0;
        stale_old.encrypted = 1;
        stale_old.prefix_hash = vec![2; 32];
        stale_old.upload_state = UPLOAD_STATE_ANNOUNCED;

        let mut stale_expected = stale_old.clone();
        stale_expected.uploaded = 1;
        stale_expected.encrypted = 2;

        let mut checkpoints = Vec::new();
        upsert_upload_checkpoint(&mut checkpoints, &peer, &good);
        upsert_upload_checkpoint(&mut checkpoints, &peer, &stale_expected);

        let good_k = upload_key(&peer, &good_id);
        let stale_k = upload_key(&peer, &stale_id);
        let bad_k = upload_key(&peer, &bad_id);
        let records = vec![
            (
                good_k.clone(),
                try_seal_bytes(&key, &record_aad(&good_k, 1), &good.encode_to_vec()).unwrap(),
            ),
            (
                stale_k.clone(),
                try_seal_bytes(&key, &record_aad(&stale_k, 1), &stale_old.encode_to_vec()).unwrap(),
            ),
            (bad_k, b"corrupt-ciphertext".to_vec()),
        ];

        let listed = decode_uploads_tolerant(&key, 1, &checkpoints, records);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, peer);
        assert_eq!(listed[0].1.id, good_id);
    }
}
