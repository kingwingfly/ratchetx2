//! The vault: everything the client keeps, in IndexedDB (schema v3), encrypted with
//! XChaCha20-Poly1305 under HKDF-SHA256 subkeys derived from a random 32-byte `root_key` wrapped
//! by the passphrase-derived Argon2id KEK.
//!
//! The database `e2ee-chat` (IndexedDB version 3) has one object store of records:
//! - `vault`: the [`VaultHeader`] (v3), in the clear: Argon2id parameters & salt, schema version
//!   (`3`), monotonic CAS `revision`, static 16-byte `vault_id`, and 72-byte `wrapped_root_key`.
//! - `state`: the [`AppState`], encrypted under `state_key` with AAD
//!   `b"state/v3\0" || encoded(VaultHeader)`, holding identity, prekeys, contacts, upload
//!   checkpoints (with commit revisions), structured outbox revisions, compact `peer_storage`
//!   indices, pending write-token revokes, random non-zero `record_epoch`, and the SHA-256 digest
//!   of the deferred sidecar.
//! - All other IndexedDB keys are flat 64-hex opaque `HMAC-SHA256(idb_mac_key, len_prefixed(domain, parts...))`
//!   tags with zero cleartext prefixes, peer keys, or counters leaked in IDB metadata:
//!   - `("deferred",)` — [`DeferredRecord`] (deferred initials, carried timestamps, and buffered
//!     `DeferredEnvelope`s), encrypted under `record_key` with AAD `b"deferred/v3\0" || epoch_be`
//!     and bound via SHA-256 digest in `STATE`.
//!   - `("history", peer, index_be)` — [`HistoryEntry`] under `record_key` with static AAD.
//!   - `("file", peer, index_be)` — [`FileRecord`] under `record_key` with static AAD.
//!   - `("outbox", peer, index_be)` — [`OutgoingRecord`] under `record_key` with revision-bound AAD.
//!   - `("upload", peer, id)` — [`PendingUpload`] under `record_key` with revision-bound AAD.
//!   - `("chunk", peer, id, index_be)` — server-side encrypted attachment chunk tracked via bitmap
//!     in `AppState.peer_storage`.
//!
//! Every `ReadWrite` transaction enforces monotonic `revision` compare-and-swap (CAS) against the
//! persisted `VaultHeader` inside the transaction and updates the external `localStorage` rollback
//! anchor (`e2ee-chat.vault.anchor.v3`, format `v3:{max_revision}:{vault_id_hex}`).

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, HashMap},
    fmt,
};

use bytes::Bytes;
use chacha20poly1305::{
    AeadCore, KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload, array::typenum::Unsigned},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use idb::{Database, DatabaseEvent, Factory, ObjectStoreParams, TransactionMode};
use js_sys::Uint8Array;
use prost::Message;
use session::{PublicKey, Sealed, protocol::mailbox_v2::PushV2Request};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    content::{Content, Events, Kind},
    kdf_worker::{KdfCancelToken, KdfError, derive_kek_async},
    preview::{self, Sort},
    state::{Delivery, LastMessage, LastMessageKind},
    util::hex,
};

type HmacSha256 = Hmac<Sha256>;

const DATABASE: &str = "e2ee-chat";
/// IndexedDB schema version 3 fence.
const DATABASE_VERSION: u32 = 3;
const STORE: &str = "records";
const HEADER: &str = "vault";
const STATE: &str = "state";
/// `localStorage` key storing the monotonic v3 rollback anchor (`v3:{max_revision}:{vault_id_hex}`).
const ROLLBACK_ANCHOR_KEY: &str = "e2ee-chat.vault.anchor.v3";
/// Legacy v1/v2 `localStorage` anchor key cleared on [`Vault::destroy`].
const LEGACY_ROLLBACK_ANCHOR_KEY: &str = "e2ee-chat.vault.anchor.v1";

/// Vault v3 schema version (XChaCha20-Poly1305, KEK-wrapped root key, HKDF subkeys, opaque HMAC keys).
pub const VAULT_VERSION_V3: u32 = 3;

const VAULT_ID_LEN: usize = 16;
const NONCE_LEN: usize = <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE;
const TAG_LEN: usize = <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE;
/// 24B nonce || 32B root key ciphertext || 16B Poly1305 tag.
const WRAPPED_ROOT_KEY_LEN: usize = NONCE_LEN + 32 + TAG_LEN;

/// Domain prefix for the static KEK root-key wrap AAD (deliberately omits `revision`).
const ROOT_KEY_WRAP_AAD_PREFIX: &[u8] = b"root-key/v3\0";
/// Prefix for v3 `STATE` associated data: `b"state/v3\0" || header_bytes`.
const STATE_V3_AAD_PREFIX: &[u8] = b"state/v3\0";
/// Prefix for `history` per-record AAD.
const HISTORY_V3_AAD_PREFIX: &[u8] = b"history/v3\0";
/// Prefix for `file` per-record AAD.
const FILE_V3_AAD_PREFIX: &[u8] = b"file/v3\0";
/// Prefix for `outbox` per-record AAD.
const OUTBOX_V3_AAD_PREFIX: &[u8] = b"outbox/v3\0";
/// Prefix for `upload` per-record AAD.
const UPLOAD_V3_AAD_PREFIX: &[u8] = b"upload/v3\0";
/// Prefix for `deferred` per-record AAD and SHA-256 digest.
const DEFERRED_V3_PREFIX: &[u8] = b"deferred/v3\0";
/// Prefix for authenticated SHA-256 digest binding outbox/awaiting entries to history/file content.
const CONTENT_KIND_DIGEST_PREFIX: &[u8] = b"outbox-content/v3\0";

/// HKDF-SHA256 info strings for the three Vault v3 subkeys.
const HKDF_INFO_STATE: &[u8] = b"ratchetx2/vault/v3/state";
const HKDF_INFO_RECORD: &[u8] = b"ratchetx2/vault/v3/record";
const HKDF_INFO_IDB_KEY: &[u8] = b"ratchetx2/vault/v3/idb-key";

/// Maximum chunk bitmap byte length accepted (supports >500k chunks; `MAX_FILE_SIZE` is ~1024 chunks).
const MAX_CHUNK_BITMAP_BYTES: usize = 65_536;

/// Allowed Argon2id parameter bounds (enforced on untrusted headers BEFORE key derivation).
pub const ARGON2_MEMORY_MIN: u32 = 16 * 1024;
pub const ARGON2_MEMORY_MAX: u32 = 256 * 1024;
/// Default Argon2id memory for new vaults: 64 MiB.
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
pub const CLASSICAL_APPROVAL_SIGNED_OFF: u32 = 2;

/// Per-contact security alert state stored in [`ContactState::security_alert`].
pub const SECURITY_ALERT_NONE: u32 = 0;
pub const SECURITY_ALERT_DOWNGRADE: u32 = 1;
pub const SECURITY_ALERT_MANIFEST_EXPIRED: u32 = 2;
pub const SECURITY_ALERT_PQ_REQUIRED: u32 = 3;

/// Initial-greeting delivery state stored in [`ContactState::greeting_delivery`].
pub const GREETING_DELIVERY_UNSENT: u32 = 1;
pub const GREETING_DELIVERY_UNCERTAIN: u32 = 2;
pub const GREETING_DELIVERY_CONFIRMED: u32 = 3;

/// Explicit upload lifecycle state stored in [`PendingUpload::upload_state`].
/// Waiting for server sign-in under a client-generated placeholder ID.
pub const UPLOAD_STATE_WAITING: u32 = 1;
/// Started on the server, awaiting chat announcement.
pub const UPLOAD_STATE_STARTED: u32 = 2;
/// Started on the server and durably announced in chat history/outbox.
pub const UPLOAD_STATE_ANNOUNCED: u32 = 3;

/// Three HKDF-SHA256 subkeys derived from `(vault_id, root_key)` (96 bytes in RAM, zeroized on drop).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKeys {
    pub state_key: [u8; 32],
    pub record_key: [u8; 32],
    pub idb_mac_key: [u8; 32],
}

impl VaultKeys {
    /// Derive `(state_key, record_key, idb_mac_key)` via HKDF-SHA256 salted by static `vault_id`.
    pub fn derive(vault_id: &[u8], root_key: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(vault_id), root_key.as_slice());
        let mut state_key = [0u8; 32];
        let mut record_key = [0u8; 32];
        let mut idb_mac_key = [0u8; 32];
        hk.expand(HKDF_INFO_STATE, &mut state_key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        hk.expand(HKDF_INFO_RECORD, &mut record_key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        hk.expand(HKDF_INFO_IDB_KEY, &mut idb_mac_key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self {
            state_key,
            record_key,
            idb_mac_key,
        }
    }
}

/// Compute a flat 64-hex opaque IndexedDB key via length-prefixed `HMAC-SHA256(idb_mac_key, ...)`.
pub fn opaque_idb_key(idb_mac_key: &[u8; 32], domain: &[u8], parts: &[&[u8]]) -> String {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(idb_mac_key)
        .expect("HMAC-SHA256 accepts any 32-byte key");
    mac.update(&(domain.len() as u32).to_be_bytes());
    mac.update(domain);
    for part in parts {
        mac.update(&(part.len() as u32).to_be_bytes());
        mac.update(part);
    }
    hex(&mac.finalize().into_bytes())
}

pub fn opaque_deferred_key(idb_mac_key: &[u8; 32]) -> String {
    opaque_idb_key(idb_mac_key, b"deferred", &[])
}

pub fn opaque_history_key(idb_mac_key: &[u8; 32], peer: &PublicKey, index: u64) -> String {
    opaque_idb_key(idb_mac_key, b"history", &[peer, &index.to_be_bytes()])
}

pub fn opaque_file_key(idb_mac_key: &[u8; 32], peer: &PublicKey, index: u64) -> String {
    opaque_idb_key(idb_mac_key, b"file", &[peer, &index.to_be_bytes()])
}

pub fn opaque_outbox_key(idb_mac_key: &[u8; 32], peer: &PublicKey, index: u64) -> String {
    opaque_idb_key(idb_mac_key, b"outbox", &[peer, &index.to_be_bytes()])
}

pub fn opaque_upload_key(idb_mac_key: &[u8; 32], peer: &PublicKey, id: &[u8]) -> String {
    opaque_idb_key(idb_mac_key, b"upload", &[peer, id])
}

pub fn opaque_chunk_key(idb_mac_key: &[u8; 32], peer: &PublicKey, id: &[u8], index: u32) -> String {
    opaque_idb_key(idb_mac_key, b"chunk", &[peer, id, &index.to_be_bytes()])
}

/// Static KEK wrap AAD for `VaultHeader.wrapped_root_key` (deliberately omits `revision` so
/// normal CAS revision increments never require re-wrapping the root key or retaining the KEK).
pub fn root_key_wrap_aad(header: &VaultHeader) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        ROOT_KEY_WRAP_AAD_PREFIX.len() + header.vault_id.len() + 20 + header.salt.len(),
    );
    aad.extend_from_slice(ROOT_KEY_WRAP_AAD_PREFIX);
    aad.extend_from_slice(&header.vault_id);
    aad.extend_from_slice(&header.version.to_be_bytes());
    aad.extend_from_slice(&header.memory.to_be_bytes());
    aad.extend_from_slice(&header.iterations.to_be_bytes());
    aad.extend_from_slice(&header.parallelism.to_be_bytes());
    aad.extend_from_slice(&(header.salt.len() as u32).to_be_bytes());
    aad.extend_from_slice(&header.salt);
    aad
}

/// Build the v3 `STATE` associated data binding `header_bytes`: `b"state/v3\0" || header_bytes`.
pub fn state_v3_aad(header_bytes: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(STATE_V3_AAD_PREFIX.len() + header_bytes.len());
    aad.extend_from_slice(STATE_V3_AAD_PREFIX);
    aad.extend_from_slice(header_bytes);
    aad
}

/// Static per-record AAD for `history` records:
/// `b"history/v3\0" || peer || index_be || epoch_be || conversation_gen_be`.
pub fn history_aad(peer: &PublicKey, index: u64, epoch: u64, conversation_gen: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HISTORY_V3_AAD_PREFIX.len() + 32 + 24);
    aad.extend_from_slice(HISTORY_V3_AAD_PREFIX);
    aad.extend_from_slice(peer);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&conversation_gen.to_be_bytes());
    aad
}

/// Static per-record AAD for `file` records:
/// `b"file/v3\0" || peer || index_be || epoch_be || conversation_gen_be`.
pub fn file_aad(peer: &PublicKey, index: u64, epoch: u64, conversation_gen: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FILE_V3_AAD_PREFIX.len() + 32 + 24);
    aad.extend_from_slice(FILE_V3_AAD_PREFIX);
    aad.extend_from_slice(peer);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&conversation_gen.to_be_bytes());
    aad
}

/// SHA-256 digest binding an [`Outgoing`] or [`Awaiting`] entry inside authenticated `STATE`
/// to the exact serialized [`Kind`] bytes stored in its `history`/`file` records.
pub fn content_kind_digest(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(CONTENT_KIND_DIGEST_PREFIX);
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

/// Revision-bound AAD for `outbox` records: `b"outbox/v3\0" || peer || index_be || epoch_be || rev_be`.
pub fn outbox_aad(peer: &PublicKey, index: u64, epoch: u64, revision: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(OUTBOX_V3_AAD_PREFIX.len() + 32 + 24);
    aad.extend_from_slice(OUTBOX_V3_AAD_PREFIX);
    aad.extend_from_slice(peer);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&revision.to_be_bytes());
    aad
}

/// Revision-bound AAD for `upload` records: `b"upload/v3\0" || peer || id || epoch_be || rev_be`.
pub fn upload_aad(peer: &PublicKey, id: &[u8], epoch: u64, revision: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(UPLOAD_V3_AAD_PREFIX.len() + 32 + id.len() + 16);
    aad.extend_from_slice(UPLOAD_V3_AAD_PREFIX);
    aad.extend_from_slice(peer);
    aad.extend_from_slice(id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&revision.to_be_bytes());
    aad
}

/// Per-record AAD for the `deferred` sidecar: `b"deferred/v3\0" || epoch_be`.
pub fn deferred_aad(epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DEFERRED_V3_PREFIX.len() + 8);
    aad.extend_from_slice(DEFERRED_V3_PREFIX);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// SHA-256 digest of a [`DeferredRecord`] bound into `AppState`.
pub fn deferred_record_digest(record: &DeferredRecord) -> Vec<u8> {
    let encoded = Zeroizing::new(record.encode_to_vec());
    let mut hasher = Sha256::new();
    hasher.update(DEFERRED_V3_PREFIX);
    hasher.update(encoded.as_slice());
    hasher.finalize().to_vec()
}

/// Strictly verify `record` against the 32-byte SHA-256 digest stored in `AppState`.
pub fn verify_deferred_record_digest(expected: &[u8], record: &DeferredRecord) -> Result<()> {
    if expected.len() != 32 {
        return Err(Error::Corrupt(
            "missing or invalid deferred record digest in vault state".into(),
        ));
    }
    let actual = deferred_record_digest(record);
    if expected != actual.as_slice() {
        return Err(Error::Corrupt(
            "deferred record does not match authenticated state digest".into(),
        ));
    }
    Ok(())
}

/// Monotonic v3 rollback anchor persisted outside IndexedDB in `localStorage`.
/// Keyed by static `vault_id_hex` (32 lowercase hex chars) so future passphrase/salt rotation
/// does not false-positive as a vault swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackAnchor {
    pub max_revision: u64,
    /// 32-char lowercase hex encoding of `VaultHeader.vault_id`.
    pub vault_id_hex: String,
}

impl RollbackAnchor {
    pub fn for_v3_header(header: &VaultHeader) -> Self {
        Self {
            max_revision: header.revision,
            vault_id_hex: hex(&header.vault_id),
        }
    }

    #[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
    pub fn encode(&self) -> String {
        format!("v3:{}:{}", self.max_revision, self.vault_id_hex)
    }

    #[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
    pub fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.trim().split(':');
        if parts.next()? != "v3" {
            return None;
        }
        let max_revision: u64 = parts.next()?.parse().ok()?;
        let vault_id_hex = parts.next()?.to_ascii_lowercase();
        if parts.next().is_some() {
            return None;
        }
        if vault_id_hex.len() != VAULT_ID_LEN * 2
            || !vault_id_hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        Some(Self {
            max_revision,
            vault_id_hex,
        })
    }
}

/// Reject revision rollback or vault replacement against an external [`RollbackAnchor`].
pub fn check_unlock_against_anchor(
    anchor: Option<&RollbackAnchor>,
    header: &VaultHeader,
) -> Result<()> {
    let Some(anchor) = anchor else {
        return Ok(());
    };
    let current_id = hex(&header.vault_id);
    if anchor.vault_id_hex != current_id {
        return Err(Error::Corrupt(
            "vault rollback or replacement detected (vault_id does not match anchor)".into(),
        ));
    }
    if header.revision < anchor.max_revision {
        return Err(Error::Corrupt(format!(
            "vault rollback detected (revision {} is behind anchor {})",
            header.revision, anchor.max_revision
        )));
    }
    Ok(())
}

/// Advance an existing anchor monotonically for a committed v3 header.
fn advance_anchor(existing: Option<&RollbackAnchor>, header: &VaultHeader) -> RollbackAnchor {
    let current_id = hex(&header.vault_id);
    let prev_rev = existing
        .filter(|a| a.vault_id_hex == current_id)
        .map_or(0, |a| a.max_revision);
    RollbackAnchor {
        max_revision: prev_rev.max(header.revision),
        vault_id_hex: current_id,
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

/// Whether `localStorage` currently retains any non-empty v3 or legacy v1/v2 rollback anchor
/// entry (valid or tampered), indicating a vault previously existed in this browser.
fn has_rollback_anchor_entry() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) else {
            return false;
        };
        [ROLLBACK_ANCHOR_KEY, LEGACY_ROLLBACK_ANCHOR_KEY]
            .into_iter()
            .any(|key| {
                storage
                    .get_item(key)
                    .ok()
                    .flatten()
                    .is_some_and(|raw| !raw.trim().is_empty())
            })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (ROLLBACK_ANCHOR_KEY, LEGACY_ROLLBACK_ANCHOR_KEY);
        false
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
        let _ = storage.remove_item(LEGACY_ROLLBACK_ANCHOR_KEY);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (ROLLBACK_ANCHOR_KEY, LEGACY_ROLLBACK_ANCHOR_KEY);
    }
}

/// The v3 vault header stored in the clear under key `"vault"`.
/// Bound into `STATE` AAD (`state/v3\0 || encoded(VaultHeader)`) so tampering fails unlock.
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
    /// Schema version (must equal [`VAULT_VERSION_V3`]).
    #[prost(uint32, tag = "5")]
    pub version: u32,
    /// Monotonic state revision enforced with compare-and-swap inside every RW transaction.
    #[prost(uint64, tag = "6")]
    pub revision: u64,
    /// Static random 16-byte vault identifier (salts HKDF subkeys & rollback anchor).
    #[prost(bytes = "vec", tag = "7")]
    pub vault_id: Vec<u8>,
    /// XChaCha20-Poly1305 wrapped 32-byte random root key (72B: 24B nonce || 32B ct || 16B tag).
    #[prost(bytes = "vec", tag = "8")]
    pub wrapped_root_key: Vec<u8>,
}

fn verify_checked_header(expected: &VaultHeader, raw: &[u8]) -> Result<VaultHeader> {
    let decoded = VaultHeader::decode(raw).map_err(|e| Error::Corrupt(e.to_string()))?;
    if decoded.version != VAULT_VERSION_V3 || decoded.revision != expected.revision {
        return Err(Error::Conflict {
            expected: expected.revision,
            actual: decoded.revision,
        });
    }
    if expected.version != VAULT_VERSION_V3
        || decoded != *expected
        || raw != expected.encode_to_vec()
    {
        return Err(Error::Corrupt(
            "vault header was modified unexpectedly".into(),
        ));
    }
    Ok(expected.clone())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn reseal_state_for_next_revision(
    state_key: &[u8; 32],
    current: &VaultHeader,
    sealed_state: &[u8],
) -> Result<(VaultHeader, Vec<u8>, Vec<u8>)> {
    let plain = open_bytes(
        state_key,
        &state_v3_aad(&current.encode_to_vec()),
        sealed_state,
    )
    .ok_or_else(|| Error::Corrupt("vault state failed authentication".into()))?;
    let next = current.next_revision()?;
    let header = next.encode_to_vec();
    let sealed = try_seal_bytes(state_key, &state_v3_aad(&header), plain.as_slice())?;
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

    /// Create a fresh v3 header with random salt, random 16B `vault_id`, and a random 32B
    /// `root_key` wrapped under the Argon2id KEK derived via the ephemeral `vault_kdf` worker (on
    /// `wasm32`) or `e2ee_chat_kdf` (on host). Immediately drops both `kek` and `root_key`.
    pub async fn create_with_passphrase_async(
        passphrase: &[u8],
        cancel: &KdfCancelToken,
    ) -> Result<(Self, VaultKeys)> {
        Self::create_with_params_async(
            passphrase,
            ARGON2_DEFAULT_MEMORY,
            ARGON2_DEFAULT_ITERATIONS,
            ARGON2_DEFAULT_PARALLELISM,
            cancel,
        )
        .await
    }

    async fn create_with_params_async(
        passphrase: &[u8],
        memory: u32,
        iterations: u32,
        parallelism: u32,
        cancel: &KdfCancelToken,
    ) -> Result<(Self, VaultKeys)> {
        let mut salt = vec![0u8; 16];
        getrandom::fill(&mut salt)
            .map_err(|e| Error::Storage(format!("random salt generation failed: {e}")))?;
        let mut vault_id = vec![0u8; VAULT_ID_LEN];
        getrandom::fill(&mut vault_id)
            .map_err(|e| Error::Storage(format!("random vault_id generation failed: {e}")))?;
        let mut root_key = Zeroizing::new([0u8; 32]);
        getrandom::fill(root_key.as_mut_slice())
            .map_err(|e| Error::Storage(format!("random root key generation failed: {e}")))?;

        let mut header = Self {
            salt,
            memory,
            iterations,
            parallelism,
            version: VAULT_VERSION_V3,
            revision: 1,
            vault_id,
            wrapped_root_key: vec![0u8; WRAPPED_ROOT_KEY_LEN],
        };
        header.validate()?;
        let kek = derive_kek_async(
            passphrase,
            &header.salt,
            header.memory,
            header.iterations,
            header.parallelism,
            cancel,
        )
        .await?;
        let wrap_aad = root_key_wrap_aad(&header);
        header.wrapped_root_key = try_seal_bytes(&kek, &wrap_aad, root_key.as_slice())?;
        drop(kek);
        header.validate()?;
        let keys = VaultKeys::derive(&header.vault_id, &root_key);
        drop(root_key);
        Ok((header, keys))
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    fn create_with_params(
        passphrase: &[u8],
        memory: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<(Self, VaultKeys)> {
        let mut salt = vec![0u8; 16];
        getrandom::fill(&mut salt)
            .map_err(|e| Error::Storage(format!("random salt generation failed: {e}")))?;
        let mut vault_id = vec![0u8; VAULT_ID_LEN];
        getrandom::fill(&mut vault_id)
            .map_err(|e| Error::Storage(format!("random vault_id generation failed: {e}")))?;
        let mut root_key = Zeroizing::new([0u8; 32]);
        getrandom::fill(root_key.as_mut_slice())
            .map_err(|e| Error::Storage(format!("random root key generation failed: {e}")))?;

        let mut header = Self {
            salt,
            memory,
            iterations,
            parallelism,
            version: VAULT_VERSION_V3,
            revision: 1,
            vault_id,
            wrapped_root_key: vec![0u8; WRAPPED_ROOT_KEY_LEN],
        };
        header.validate()?;
        let kek = header.derive_kek(passphrase)?;
        let wrap_aad = root_key_wrap_aad(&header);
        header.wrapped_root_key = try_seal_bytes(&kek, &wrap_aad, root_key.as_slice())?;
        drop(kek);
        header.validate()?;
        let keys = VaultKeys::derive(&header.vault_id, &root_key);
        drop(root_key);
        Ok((header, keys))
    }

    /// Validate untrusted header version, revision, salt length, Argon2id bounds, `vault_id`
    /// length, and `wrapped_root_key` length BEFORE running Argon2id KDF.
    pub fn validate(&self) -> Result<()> {
        if self.version != VAULT_VERSION_V3 {
            return Err(Error::IncompatibleVersion(self.version));
        }
        if self.revision == 0 {
            return Err(Error::Corrupt(
                "v3 vault header has invalid revision 0".into(),
            ));
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
        if self.vault_id.len() != VAULT_ID_LEN {
            return Err(Error::Corrupt(format!(
                "invalid vault_id length {}",
                self.vault_id.len()
            )));
        }
        if self.wrapped_root_key.len() != WRAPPED_ROOT_KEY_LEN {
            return Err(Error::Corrupt(format!(
                "invalid wrapped_root_key length {}",
                self.wrapped_root_key.len()
            )));
        }
        Ok(())
    }

    /// Derive the temporary 32-byte Argon2id KEK synchronously on host targets.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn derive_kek(&self, passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        self.validate()?;
        e2ee_chat_kdf::derive_kek(
            passphrase,
            &self.salt,
            self.memory,
            self.iterations,
            self.parallelism,
        )
        .map_err(Error::Corrupt)
    }

    /// Unwrap `wrapped_root_key` with `kek`, drop `kek` and `root_key`, and return the three
    /// HKDF-SHA256 subkeys.
    fn unwrap_keys_with_kek(&self, kek: Zeroizing<[u8; 32]>) -> Result<VaultKeys> {
        let wrap_aad = root_key_wrap_aad(self);
        let unwrapped =
            open_bytes(&kek, &wrap_aad, &self.wrapped_root_key).ok_or(Error::WrongPassphrase)?;
        drop(kek);
        let mut root_key = Zeroizing::new([0u8; 32]);
        if unwrapped.len() != 32 {
            return Err(Error::Corrupt(
                "unwrapped root key has unexpected length".into(),
            ));
        }
        root_key.copy_from_slice(unwrapped.as_slice());
        drop(unwrapped);
        let keys = VaultKeys::derive(&self.vault_id, &root_key);
        drop(root_key);
        Ok(keys)
    }

    /// Unwrap `wrapped_root_key` asynchronously via the ephemeral `vault_kdf` worker (on `wasm32`)
    /// or `e2ee_chat_kdf` (on host), validating header bounds BEFORE spawning the worker.
    pub async fn unwrap_keys_async(
        &self,
        passphrase: &[u8],
        cancel: &KdfCancelToken,
    ) -> Result<VaultKeys> {
        self.validate()?;
        let kek = derive_kek_async(
            passphrase,
            &self.salt,
            self.memory,
            self.iterations,
            self.parallelism,
            cancel,
        )
        .await?;
        self.unwrap_keys_with_kek(kek)
    }

    /// Synchronous host-only unwrap for unit tests.
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn unwrap_keys(&self, passphrase: &[u8]) -> Result<VaultKeys> {
        let kek = self.derive_kek(passphrase)?;
        self.unwrap_keys_with_kek(kek)
    }
}

/// Fallibly encrypt `plaintext` under `key` with XChaCha20-Poly1305 and associated data `aad`.
pub fn try_seal_bytes(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| Error::Storage(format!("random nonce generation failed: {e}")))?;
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Corrupt("XChaCha20-Poly1305 encryption failed".into()))?;
    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Encrypt `plaintext` under `key` with XChaCha20-Poly1305 and associated data `aad`.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub fn seal_bytes(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    try_seal_bytes(key, aad, plaintext).expect("XChaCha20-Poly1305 sealing in tests")
}

/// Decrypt `sealed` under `key` with XChaCha20-Poly1305 and associated data `aad`; zeroized on drop.
pub fn open_bytes(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (nonce, ciphertext) = sealed.split_at_checked(NONCE_LEN)?;
    XChaCha20Poly1305::new(key.into())
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

fn generate_record_epoch() -> Result<u64> {
    let mut buf = [0u8; 8];
    loop {
        getrandom::fill(&mut buf)
            .map_err(|e| Error::Storage(format!("random epoch generation failed: {e}")))?;
        let epoch = u64::from_be_bytes(buf);
        if epoch != 0 {
            return Ok(epoch);
        }
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
    // Tag 12 reserved (removed legacy inline deferred_initials).
    /// Monotonic floor for newly started chat `Hello.session_seq` values so recreating a deleted
    /// chat never reuses `session_seq = 1` against a peer who kept the old history.
    #[prost(uint64, tag = "13")]
    pub next_session_seq: u64,
    /// Authenticated per-upload watermarks, hashes, and commit revisions bound inside `STATE`.
    #[prost(message, repeated, tag = "14")]
    pub upload_checkpoints: Vec<UploadCheckpoint>,
    /// Random non-zero vault-instance epoch bound into per-record AADs.
    #[prost(uint64, tag = "15")]
    pub record_epoch: u64,
    /// SHA-256 digest of the committed `DeferredRecord` sidecar.
    #[prost(bytes = "vec", tag = "16")]
    pub deferred_initials_digest: Vec<u8>,
    /// Structured per-outbox-record commit revisions bound into `outbox` AADs.
    #[prost(message, repeated, tag = "17")]
    pub outbox_revisions: Vec<OutboxRevision>,
    /// Compact per-peer storage indices (history length, file indices, kept chunk bitmaps)
    /// authenticated inside `STATE`, replacing all IndexedDB prefix scans.
    #[prost(message, repeated, tag = "18")]
    pub peer_storage: Vec<PeerStorageIndex>,
    /// Durable pending write-token revocations staged on chat deletion and flushed on sync.
    #[prost(message, repeated, tag = "19")]
    pub pending_revokes: Vec<PendingRevoke>,
    /// Vault-wide monotonic conversation generation allocator (starts at 1). Allocated when
    /// creating a new chat so forgotten peers need zero residual entries in `peer_storage`.
    #[prost(uint64, tag = "20")]
    pub next_conversation_gen: u64,
    /// Durable flag indicating an empty-OPK greeting on `current_signed_prekey` requested a
    /// bounded classical refill probe (`R12-P2-4`, `R13-P2-4`).
    #[prost(bool, tag = "21")]
    pub classical_fallback_probe_pending: bool,
    /// Durable Unix ms deadline before which classical empty-OPK greetings skip probing (`R13-P2-4`).
    #[prost(uint64, tag = "22")]
    pub classical_fallback_probe_cooldown_until: u64,
    /// Durable PQ suite IDs (`PqSuite::as_u8()`) with pending last-resort fallback refill probes
    /// (`R13-P2-4`).
    #[prost(uint32, repeated, tag = "23")]
    pub pq_fallback_probe_pending: Vec<u32>,
    /// Durable per-suite Unix ms probe cooldown deadlines after stocked relay responses (`R13-P2-4`).
    #[prost(message, repeated, tag = "24")]
    pub pq_fallback_probe_cooldowns: Vec<PqSuiteCooldown>,
}

/// Persisted per-suite fallback OPK probe cooldown deadline (`R13-P2-4`).
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct PqSuiteCooldown {
    #[prost(uint32, tag = "1")]
    pub suite: u32,
    #[prost(uint64, tag = "2")]
    pub until: u64,
}

impl AppState {
    /// Wipe secret key material and sensitive buffers held in this protobuf copy.
    pub fn zeroize_secrets(&mut self) {
        // `session::proto::ClientState` derives `ZeroizeOnDrop`.
        drop(self.client.take());
        for contact in &mut self.contacts {
            contact.zeroize_secrets();
        }
        // `Farewell` implements `Drop` + `ZeroizeOnDrop`.
        self.farewells.clear();
        for cp in &mut self.upload_checkpoints {
            cp.prefix_hash.zeroize();
            cp.sealed_chunk_hash.zeroize();
        }
        self.deferred_initials_digest.zeroize();
    }
}

/// Compact upload watermark and commit revision authenticated inside `STATE`.
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
    #[prost(uint64, tag = "8")]
    pub revision: u64,
    #[prost(uint64, tag = "9")]
    pub history_index: u64,
}

impl UploadCheckpoint {
    fn from_upload(peer: &PublicKey, upload: &PendingUpload, revision: u64) -> Self {
        Self {
            peer: peer.to_vec(),
            id: upload.id.clone(),
            uploaded: upload.uploaded,
            encrypted: upload.encrypted,
            prefix_hash: upload.prefix_hash.clone(),
            sealed_chunk_hash: upload.sealed_chunk_hash.clone(),
            upload_state: upload.upload_state,
            revision,
            history_index: upload.history_index,
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
            && self.history_index == upload.history_index
    }
}

/// Structured authenticated revision binding for an active outbox record `(peer, index)`.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct OutboxRevision {
    #[prost(bytes = "vec", tag = "1")]
    pub peer: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub index: u64,
    #[prost(uint64, tag = "3")]
    pub revision: u64,
}

/// Compact per-peer storage index authenticated inside `STATE`.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct PeerStorageIndex {
    #[prost(bytes = "vec", tag = "1")]
    pub peer: Vec<u8>,
    /// Exclusive upper bound on history indices written for `peer`.
    #[prost(uint64, tag = "2")]
    pub max_history_len: u64,
    /// Sorted deduplicated history indices that have a separate `file` record.
    #[prost(uint64, repeated, tag = "3")]
    pub file_indices: Vec<u64>,
    /// Kept attachment chunk bitmaps for `peer`.
    #[prost(message, repeated, tag = "4")]
    pub kept_chunks: Vec<AttachmentChunks>,
    /// Monotonic conversation generation incremented on [`Vault::forget`] so deleted history and
    /// file ciphertexts cannot be spliced into a future chat with the same `peer`.
    #[prost(uint64, tag = "5")]
    pub conversation_gen: u64,
}

/// Bitmap tracking which chunk indices of attachment `id` are cached locally in IndexedDB.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct AttachmentChunks {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    /// Bit `i` (byte `i / 8`, mask `1 << (i % 8)`) is set iff chunk `i` is kept in IndexedDB.
    #[prost(bytes = "vec", tag = "2")]
    pub chunks_bitmap: Vec<u8>,
}

impl AttachmentChunks {
    pub fn has_bit(&self, index: u32) -> bool {
        let byte_idx = (index / 8) as usize;
        let mask = 1u8 << (index % 8);
        self.chunks_bitmap
            .get(byte_idx)
            .is_some_and(|b| b & mask != 0)
    }

    /// Set bit `index`, returning `true` if newly set or `false` if already set.
    pub fn set_bit(&mut self, index: u32) -> Result<bool> {
        let byte_idx = (index / 8) as usize;
        if byte_idx >= MAX_CHUNK_BITMAP_BYTES {
            return Err(Error::Corrupt(format!(
                "attachment chunk index {index} exceeds bitmap bound"
            )));
        }
        let mask = 1u8 << (index % 8);
        if self.chunks_bitmap.len() <= byte_idx {
            self.chunks_bitmap.resize(byte_idx + 1, 0);
        }
        let prev = self.chunks_bitmap[byte_idx];
        self.chunks_bitmap[byte_idx] |= mask;
        Ok((prev & mask) == 0)
    }

    pub fn count(&self) -> u32 {
        self.chunks_bitmap.iter().map(|b| b.count_ones()).sum()
    }

    pub fn indices(&self) -> impl Iterator<Item = u32> + '_ {
        self.chunks_bitmap
            .iter()
            .enumerate()
            .flat_map(|(byte_idx, &byte)| {
                (0u32..8).filter_map(move |bit| {
                    ((byte & (1u8 << bit)) != 0).then_some((byte_idx as u32) * 8 + bit)
                })
            })
    }
}

/// Pending mailbox write-token revocation staged on chat deletion and flushed on sync.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct PendingRevoke {
    #[prost(bytes = "vec", tag = "1")]
    pub peer_slot_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub min_grant_version: u64,
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

/// Raw mailbox envelope buffered locally for a stalled/quarantined/rekeying/isolated peer so the
/// server mailbox cursor advances immediately for all active peers (cross-peer stall isolation).
#[derive(Clone, PartialEq, prost::Message)]
pub struct DeferredEnvelope {
    #[prost(bytes = "vec", tag = "1")]
    pub peer: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(message, optional, tag = "3")]
    pub message: Option<party::EncryptedMessage>,
    #[prost(message, optional, tag = "4")]
    pub initial_message: Option<session::protocol::handshake_v2::InitialMessageV2>,
    #[prost(uint64, tag = "5")]
    pub deferred_at: u64,
    /// Buffered while the peer was isolated on a reduced-PQ build; uses the dedicated isolated
    /// spool budget and is exempt from the 30-day replay window so already-ACKed envelopes survive
    /// until a capable build unlocks and replays them.
    #[prost(bool, tag = "6")]
    pub pq_isolated: bool,
}

/// Separate encrypted sidecar record committed atomically with `STATE` under opaque key `("deferred",)`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct DeferredRecord {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<DeferredInitial>,
    #[prost(message, repeated, tag = "2")]
    pub carried_timestamps: Vec<CarriedDeferredTimestamp>,
    #[prost(message, repeated, tag = "3")]
    pub envelopes: Vec<DeferredEnvelope>,
}

impl DeferredRecord {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.carried_timestamps.is_empty() && self.envelopes.is_empty()
    }
}

/// Fallibly seal a [`DeferredRecord`] under `record_key` with `deferred_aad(epoch)`.
pub fn try_seal_deferred(
    record_key: &[u8; 32],
    epoch: u64,
    record: &DeferredRecord,
) -> Result<Vec<u8>> {
    let plaintext = Zeroizing::new(record.encode_to_vec());
    try_seal_bytes(record_key, &deferred_aad(epoch), &plaintext)
}

/// Open a sealed [`DeferredRecord`] under `record_key` with `deferred_aad(epoch)`.
pub fn open_deferred(record_key: &[u8; 32], epoch: u64, sealed: &[u8]) -> Result<DeferredRecord> {
    let plain = open_bytes(record_key, &deferred_aad(epoch), sealed)
        .ok_or_else(|| Error::Corrupt("deferred sidecar does not decrypt".into()))?;
    DeferredRecord::decode(plain.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))
}

/// Saved per-contact security/approval flags cleared during a pending `PqConfig` edit so a
/// definitive server refusal restores them even across a page reload.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct PendingPqContactFlag {
    #[prost(bytes = "vec", tag = "1")]
    pub peer: Vec<u8>,
    #[prost(uint32, optional, tag = "2")]
    pub prev_security_alert: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub prev_classical_approval: Option<u32>,
    /// Conversation generation of `peer` when the flag was cleared, preventing rollback from
    /// re-attaching a deleted chat's alerts to a newly recreated conversation.
    #[prost(uint64, tag = "4")]
    pub conversation_gen: u64,
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
    #[prost(message, repeated, tag = "6")]
    pub contact_flags: Vec<PendingPqContactFlag>,
}

impl PendingPqRollback {
    pub fn from_config(config: &session::PqConfig, previous_needs_publish: bool) -> Self {
        Self {
            pq_enabled: config.pq_enabled,
            preferred_suite: u32::from(config.preferred_suite.as_u8()),
            pq_ratchet_enabled: config.pq_ratchet_enabled,
            strict_pq: config.strict_pq,
            previous_needs_publish,
            contact_flags: Vec::new(),
        }
    }

    pub fn record_contact_flag(
        &mut self,
        peer: &[u8],
        conversation_gen: u64,
        prev_alert: Option<u32>,
        prev_approval: Option<u32>,
    ) {
        self.contact_flags
            .retain(|f| f.peer.as_slice() != peer || f.conversation_gen == conversation_gen);
        if let Some(existing) = self
            .contact_flags
            .iter_mut()
            .find(|f| f.peer.as_slice() == peer && f.conversation_gen == conversation_gen)
        {
            if let Some(a) = prev_alert {
                existing.prev_security_alert.get_or_insert(a);
            }
            if let Some(p) = prev_approval {
                existing.prev_classical_approval.get_or_insert(p);
            }
        } else {
            self.contact_flags.push(PendingPqContactFlag {
                peer: peer.to_vec(),
                prev_security_alert: prev_alert,
                prev_classical_approval: prev_approval,
                conversation_gen,
            });
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
    /// Durable flag set when an outbound chat/rekey hits `WriteTokenRejected` while
    /// `!is_known_by_peer()`, keeping the awaiting-acceptance notice stable across reloads and
    /// manual syncs until the peer accepts or a push succeeds.
    #[prost(bool, tag = "31")]
    pub awaiting_peer_acceptance: bool,
    /// Monotonic conversation generation assigned when this contact was created, matching its
    /// `PeerStorageIndex.conversation_gen` and distinguishing recreated conversations with the
    /// same peer across concurrent async flows.
    #[prost(uint64, tag = "32")]
    pub conversation_gen: u64,
    /// Number of mailbox envelopes dropped after overflowing the dedicated isolated-peer spool
    /// while this contact was unsupported on a reduced-PQ build.
    #[prost(uint32, tag = "33")]
    pub evicted_while_isolated: u32,
    /// Provisional outbound contact created by `start_chat` before final submission confirmation;
    /// gated out of background greeting retries, background grant flushes, and inbound
    /// auto-approval so even total storage failure during cancellation never grants approval or
    /// transmits a cancelled chat's greeting after reload.
    #[prost(bool, tag = "34")]
    pub provisional: bool,
    /// Peer signed `CapabilityManifest.generation` targeted by the current active greeting
    /// (`0` if unknown), used to restrict `CONFIRMED` SPK-eviction probes until the peer has
    /// rotated at least twice (`manifest.generation >= greeting_target_generation + 2`).
    #[prost(uint64, tag = "35")]
    pub greeting_target_generation: u64,
    /// Local wall-clock Unix ms when the current active greeting was first transmitted or
    /// confirmed (`0` while `UNSENT`), bounding `UNCERTAIN` and `CONFIRMED` SPK-eviction reclaim
    /// strictly within the server's delivery-tombstone TTL window.
    #[prost(uint64, tag = "36")]
    pub greeting_sent_at: u64,
    /// Set once a post-2-rotation `CONFIRMED` greeting probe succeeded (`Added { inserted: false }`),
    /// proving the server retained a live row or ACK tombstone so no further probes are needed.
    #[prost(bool, tag = "37")]
    pub greeting_delivery_verified: bool,
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
        self.fallback_farewells.clear();
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
    /// SHA-256 digest of the serialized [`Kind`] bytes in history/file records, verified before
    /// reconstructing an outbox resend on peer chat deletion.
    #[prost(bytes = "vec", tag = "5")]
    pub content_digest: Vec<u8>,
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
        matches!(
            self.upload_state,
            UPLOAD_STATE_STARTED | UPLOAD_STATE_ANNOUNCED
        ) && !self.token.is_empty()
    }

    /// Whether the server-assigned attachment pointer has been durably announced in chat history.
    pub fn is_announced(&self) -> bool {
        self.upload_state == UPLOAD_STATE_ANNOUNCED && !self.token.is_empty()
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

impl ZeroizeOnDrop for PendingUpload {}

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
    /// SHA-256 digest of the serialized [`Kind`] bytes in history/file records, verified before
    /// reconstructing a missing/corrupt or requeued [`OutgoingRecord`].
    #[prost(bytes = "vec", tag = "7")]
    pub content_digest: Vec<u8>,
    /// Persisted before transmitting `PushV2` so a reload or lost response after a concurrent
    /// rekey reconciles the exact same `client_message_id` idempotently instead of unsealing and
    /// duplicating delivery; cleared only on definitive relay non-delivery.
    #[prost(bool, tag = "8")]
    pub dispatched: bool,
    /// Authenticated 16-byte attachment ID when this outbox entry announces an attachment pointer,
    /// allowing `Engine::flush` and orphan-upload recovery to identify unuploaded 0-chunk
    /// attachments even if the separate `HistoryEntry` record is missing (`R14-P2-2`, `R14-P2-3`).
    #[prost(bytes = "vec", tag = "9")]
    pub attachment_id: Vec<u8>,
}

/// What a message not pushed yet is: its content, encrypted just before it goes.
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct OutgoingRecord {
    /// The message, once encrypted.
    #[prost(message, optional, tag = "1")]
    pub message: Option<party::EncryptedMessage>,
    /// Its content, until it is encrypted.
    #[prost(bytes = "vec", tag = "3")]
    pub content: Vec<u8>,
    /// Raw 32-byte mailbox write token for this sealed message (`PushV2Request.write_token`).
    #[prost(bytes = "vec", tag = "4")]
    pub write_token: Vec<u8>,
    /// Optional encoded `InitialMessageV2` carried alongside this sealed message.
    #[prost(bytes = "vec", tag = "5")]
    pub carried_initial: Vec<u8>,
    /// Session ID that produced `message`, `write_token`, and `carried_initial`.
    #[prost(bytes = "vec", tag = "6")]
    pub session_id: Vec<u8>,
}

impl OutgoingRecord {
    /// Build an unsealed [`OutgoingRecord`] carrying plaintext `content` bytes waiting to be
    /// encrypted once its position in the chat is fixed.
    pub fn unsealed(content: Vec<u8>) -> Self {
        Self {
            message: None,
            content,
            write_token: Vec::new(),
            carried_initial: Vec::new(),
            session_id: Vec::new(),
        }
    }

    /// Build a sealed [`OutgoingRecord`] bound to `session_id`.
    pub fn sealed(sealed: Sealed, session_id: &[u8]) -> Self {
        Self {
            message: Some(sealed.message.clone()),
            content: vec![],
            write_token: sealed.write_token.to_vec(),
            carried_initial: sealed
                .initial_message
                .as_ref()
                .map(|bytes| bytes.to_vec())
                .unwrap_or_default(),
            session_id: session_id.to_vec(),
        }
    }

    /// Reconstruct a [`Sealed`] payload if this record has a valid message and 32-byte `write_token`.
    pub fn to_sealed(&self) -> Option<Sealed> {
        let message = self.message.clone()?;
        let write_token: [u8; 32] = self.write_token.as_slice().try_into().ok()?;
        let initial_message = (!self.carried_initial.is_empty())
            .then(|| Bytes::copy_from_slice(&self.carried_initial));
        Some(Sealed {
            message,
            write_token: Zeroizing::new(write_token),
            initial_message,
        })
    }

    /// Build a wire [`PushV2Request`] for `recipient` if this record holds a valid sealed message
    /// and 32-byte `write_token`.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub fn to_push_v2_request(&self, recipient: &PublicKey) -> Option<PushV2Request> {
        let message = self.message.clone()?;
        let write_token: [u8; 32] = self.write_token.as_slice().try_into().ok()?;
        let initial_message = if self.carried_initial.is_empty() {
            None
        } else {
            Some(session::protocol::mailbox_v2::decode_carried_initial(
                &self.carried_initial,
            )?)
        };
        let client_message_id = Bytes::copy_from_slice(&Sealed::client_message_id_for(&message));
        Some(PushV2Request {
            recipient: Bytes::copy_from_slice(recipient),
            message: Some(message),
            initial_message,
            client_message_id,
            write_token: Bytes::copy_from_slice(&write_token),
        })
    }

    /// Wipe plaintext content, write token, carried initial, and session binding.
    pub fn zeroize_secrets(&mut self) {
        self.content.zeroize();
        self.write_token.zeroize();
        self.carried_initial.zeroize();
        self.session_id.zeroize();
    }
}

impl Drop for OutgoingRecord {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

impl ZeroizeOnDrop for OutgoingRecord {}

impl fmt::Debug for OutgoingRecord {
    /// Shows no plaintext content, write token, or ciphertext bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingRecord")
            .field("has_message", &self.message.is_some())
            .field("content_len", &self.content.len())
            .field("has_write_token", &(self.write_token.len() == 32))
            .field("has_carried_initial", &!self.carried_initial.is_empty())
            .field("session_id_len", &self.session_id.len())
            .finish()
    }
}

/// The bytes of a file in the history.
#[derive(Clone, PartialEq, prost::Message)]
pub struct FileRecord {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

/// A message telling a peer that this client deleted the chat, not pushed yet.
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct Farewell {
    /// Encoded `protocol::mailbox_v2::PushV2Request` preserving v2/PQXDH carried initial messages
    /// and the 32-byte `write_token`.
    #[prost(bytes = "vec", tag = "3")]
    pub push_v2: Vec<u8>,
}

impl Farewell {
    /// Recipient identity key of this farewell.
    pub fn recipient(&self) -> Option<Vec<u8>> {
        if self.push_v2.is_empty() {
            return None;
        }
        PushV2Request::decode(self.push_v2.as_slice())
            .ok()
            .map(|v2| v2.recipient.to_vec())
    }
}

impl Drop for Farewell {
    fn drop(&mut self) {
        self.push_v2.zeroize();
    }
}

impl ZeroizeOnDrop for Farewell {}

impl fmt::Debug for Farewell {
    /// Shows no encoded `PushV2Request` / `write_token` bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Farewell")
            .field("push_v2_len", &self.push_v2.len())
            .finish()
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

/// Compute the inclusive `[first, last]` history index bounds for `(history_len, limit)`.
fn history_bounds(history_len: u64, limit: u64) -> Option<(u64, u64)> {
    if limit == 0 {
        return None;
    }
    let last = history_len.checked_sub(1)?;
    let first = history_len.saturating_sub(limit);
    Some((first, last))
}

fn upsert_upload_checkpoint(
    checkpoints: &mut Vec<UploadCheckpoint>,
    peer: &PublicKey,
    upload: &PendingUpload,
    revision: u64,
) {
    let cp = UploadCheckpoint::from_upload(peer, upload, revision);
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

fn find_upload_checkpoint<'a>(
    checkpoints: &'a [UploadCheckpoint],
    peer: &PublicKey,
    id: &[u8],
) -> Option<&'a UploadCheckpoint> {
    checkpoints
        .iter()
        .find(|c| c.peer.as_slice() == peer.as_slice() && c.id.as_slice() == id)
}

fn decode_upload_with_checkpoint(
    record_key: &[u8; 32],
    record_epoch: u64,
    cp: &UploadCheckpoint,
    peer: &PublicKey,
    sealed: &[u8],
) -> Option<PendingUpload> {
    let aad = upload_aad(peer, &cp.id, record_epoch, cp.revision);
    let plain = open_bytes(record_key, &aad, sealed)?;
    let upload = PendingUpload::decode(plain.as_slice()).ok()?;
    cp.matches(peer, &upload).then_some(upload)
}

/// Pre-KDF inspection result for the browser vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultPresence {
    /// No vault exists in IndexedDB.
    None,
    /// A compatible v3 vault exists and can be unlocked with a passphrase.
    Compatible,
    /// A vault with an incompatible schema version exists (detected pre-KDF) and requires reset.
    IncompatibleVersion(u32),
}

#[derive(Debug)]
pub enum Error {
    /// IndexedDB failed, e.g. it is not available in a private window.
    Storage(String),
    /// The passphrase does not open the vault.
    WrongPassphrase,
    /// Key derivation was explicitly cancelled by the user or aborted on `pagehide`.
    Cancelled,
    /// The ephemeral `vault_kdf` worker failed or timed out.
    Kdf(String),
    /// Existing vault has an unsupported/legacy schema version (detected pre-KDF).
    IncompatibleVersion(u32),
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
            Self::Cancelled => write!(f, "key derivation was cancelled"),
            Self::Kdf(e) => f.write_str(e),
            Self::IncompatibleVersion(v) => write!(
                f,
                "incompatible vault format version {v} (expected v{VAULT_VERSION_V3})"
            ),
            Self::Corrupt(e) => write!(f, "the vault is corrupt: {e}"),
            Self::Conflict { expected, actual } => write!(
                f,
                "the vault was modified elsewhere (expected revision {expected}, found {actual}); reload this page"
            ),
        }
    }
}

impl From<KdfError> for Error {
    fn from(error: KdfError) -> Self {
        match error {
            KdfError::Cancelled => Self::Cancelled,
            KdfError::InvalidParams(msg) => Self::Corrupt(msg),
            KdfError::Timeout => Self::Kdf(error.to_string()),
            KdfError::Worker(msg) => Self::Kdf(msg),
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

/// The open v3 vault.
pub struct Vault {
    database: Database,
    keys: VaultKeys,
    header: RefCell<VaultHeader>,
    /// Random non-zero vault-instance epoch bound into per-record AADs.
    record_epoch: u64,
    /// Monotonic `glue::lock_generation()` captured when this vault was created/opened.
    lock_generation: u64,
    /// Authoritative upload checkpoints persisted inside `STATE`.
    upload_checkpoints: RefCell<Vec<UploadCheckpoint>>,
    /// Authoritative per-outbox-record revisions persisted inside `STATE`.
    outbox_revisions: RefCell<BTreeMap<(PublicKey, u64), u64>>,
    /// Authoritative compact per-peer storage indices persisted inside `STATE`.
    peer_storage: RefCell<BTreeMap<PublicKey, PeerStorageIndex>>,
    /// Vault-wide monotonic conversation generation allocator persisted in `AppState`.
    next_conversation_gen: Cell<u64>,
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.database.close();
    }
}

/// Fail closed before opening or committing any IndexedDB transaction once `pagehide` has released
/// this tab's exclusive Web Lock or bumped `glue::lock_generation()`.
fn ensure_vault_lock_owned(expected_generation: u64) -> Result<()> {
    if !crate::glue::owns_lock()
        || crate::glue::lock_released()
        || crate::glue::lock_generation() != expected_generation
    {
        return Err(Error::Storage("page is closing; tab lock released".into()));
    }
    Ok(())
}

fn outbox_revisions_to_proto(map: &BTreeMap<(PublicKey, u64), u64>) -> Vec<OutboxRevision> {
    map.iter()
        .map(|((peer, index), &revision)| OutboxRevision {
            peer: peer.to_vec(),
            index: *index,
            revision,
        })
        .collect()
}

fn outbox_revisions_from_proto(list: &[OutboxRevision]) -> BTreeMap<(PublicKey, u64), u64> {
    let mut map = BTreeMap::new();
    for entry in list {
        if let Ok(peer) = PublicKey::try_from(entry.peer.as_slice()) {
            map.insert((peer, entry.index), entry.revision);
        }
    }
    map
}

fn peer_storage_to_proto(map: &BTreeMap<PublicKey, PeerStorageIndex>) -> Vec<PeerStorageIndex> {
    map.values().cloned().collect()
}

fn peer_storage_from_proto(list: &[PeerStorageIndex]) -> BTreeMap<PublicKey, PeerStorageIndex> {
    let mut map = BTreeMap::new();
    for item in list {
        if let Ok(peer) = PublicKey::try_from(item.peer.as_slice()) {
            map.insert(peer, item.clone());
        }
    }
    map
}

fn peer_conversation_gen(storage: &BTreeMap<PublicKey, PeerStorageIndex>, peer: &PublicKey) -> u64 {
    storage.get(peer).map_or(0, |ps| ps.conversation_gen)
}

fn allocate_peer_conversation_gen(
    next_gen: &mut u64,
    contacts: &[ContactState],
    peer: &PublicKey,
) -> u64 {
    if let Some(conv_gen) = contacts
        .iter()
        .find(|c| c.peer.as_slice() == peer.as_slice())
        .map(|c| c.conversation_gen)
        .filter(|&g| g > 0)
    {
        *next_gen = (*next_gen).max(conv_gen.saturating_add(1));
        conv_gen
    } else {
        let conv_gen = (*next_gen).max(1);
        *next_gen = conv_gen.saturating_add(1);
        conv_gen
    }
}

fn record_peer_entry(
    storage: &mut BTreeMap<PublicKey, PeerStorageIndex>,
    next_gen: &mut u64,
    contacts: &[ContactState],
    peer: PublicKey,
    index: u64,
    has_file: bool,
) {
    let ps = storage.entry(peer).or_insert_with(|| PeerStorageIndex {
        peer: peer.to_vec(),
        max_history_len: 0,
        file_indices: Vec::new(),
        kept_chunks: Vec::new(),
        conversation_gen: allocate_peer_conversation_gen(next_gen, contacts, &peer),
    });
    ps.max_history_len = ps.max_history_len.max(index.saturating_add(1));
    if has_file && let Err(pos) = ps.file_indices.binary_search(&index) {
        ps.file_indices.insert(pos, index);
    }
}

fn set_peer_chunk_bit(
    storage: &mut BTreeMap<PublicKey, PeerStorageIndex>,
    next_gen: &mut u64,
    contacts: &[ContactState],
    peer: PublicKey,
    id: &[u8],
    index: u32,
) -> Result<bool> {
    let ps = storage.entry(peer).or_insert_with(|| PeerStorageIndex {
        peer: peer.to_vec(),
        max_history_len: 0,
        file_indices: Vec::new(),
        kept_chunks: Vec::new(),
        conversation_gen: allocate_peer_conversation_gen(next_gen, contacts, &peer),
    });
    if let Some(existing) = ps.kept_chunks.iter_mut().find(|a| a.id.as_slice() == id) {
        existing.set_bit(index)
    } else {
        let mut chunks = AttachmentChunks {
            id: id.to_vec(),
            chunks_bitmap: Vec::new(),
        };
        let added = chunks.set_bit(index)?;
        ps.kept_chunks.push(chunks);
        Ok(added)
    }
}

type PreparedEntry = (PublicKey, u64, HistoryEntry, Option<Zeroizing<Vec<u8>>>);

impl Vault {
    /// Inspect the stored vault header pre-KDF to distinguish absent, compatible (v3),
    /// incompatible/legacy, and partially restored/corrupt vaults.
    pub async fn inspect() -> Result<VaultPresence> {
        let database = open().await?;
        let close = scopeguard::guard(&database, |db| db.close());
        let (raw, count) = {
            let tx = database.transaction(&[STORE], TransactionMode::ReadOnly)?;
            let store = tx.object_store(STORE)?;
            let header = store
                .get(JsValue::from_str(HEADER))?
                .await?
                .map(|v| Uint8Array::new(&v).to_vec());
            let count = if header.is_none() {
                store.count(None)?.await?
            } else {
                0
            };
            (header, count)
        };
        drop(close);
        let Some(raw) = raw else {
            if count > 0 {
                return Err(Error::Corrupt(
                    "vault header is missing while encrypted vault records remain; reset the vault explicitly to start over".into(),
                ));
            }
            if has_rollback_anchor_entry() {
                return Err(Error::Corrupt(
                    "vault header is missing while a rollback anchor remains in browser storage; reset the vault explicitly to start over".into(),
                ));
            }
            return Ok(VaultPresence::None);
        };
        let header =
            VaultHeader::decode(raw.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))?;
        if header.version != VAULT_VERSION_V3 {
            return Ok(VaultPresence::IncompatibleVersion(header.version));
        }
        Ok(VaultPresence::Compatible)
    }

    fn ensure_lock_owned(&self) -> Result<()> {
        ensure_vault_lock_owned(self.lock_generation)
    }

    /// Create a new v3 vault holding `state` under `passphrase` in an empty store.
    ///
    /// Refuses to overwrite existing records or a surviving rollback anchor (use
    /// [`Vault::destroy`] for explicit reset) and aborts if cancelled before commit.
    pub async fn create(
        passphrase: &[u8],
        state: &AppState,
        cancel: &KdfCancelToken,
    ) -> Result<Self> {
        let lock_generation = crate::glue::lock_generation();
        ensure_vault_lock_owned(lock_generation)?;
        let (header, keys) = VaultHeader::create_with_passphrase_async(passphrase, cancel).await?;
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        ensure_vault_lock_owned(lock_generation)?;
        let database = open().await?;
        let close_on_err = scopeguard::guard(&database, |db| db.close());
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        ensure_vault_lock_owned(lock_generation)?;
        let header_bytes = header.encode_to_vec();
        let record_epoch = generate_record_epoch()?;
        let next_gen = state.next_conversation_gen.max(1);
        let mut state_to_save = state.clone();
        state_to_save.record_epoch = record_epoch;
        state_to_save.next_conversation_gen = next_gen;
        state_to_save.upload_checkpoints.clear();
        state_to_save.outbox_revisions.clear();
        state_to_save.peer_storage.clear();
        state_to_save.deferred_initials_digest = deferred_record_digest(&DeferredRecord::default());
        scopeguard::ScopeGuard::into_inner(close_on_err);
        let vault = Self {
            database,
            keys,
            header: RefCell::new(header.clone()),
            record_epoch,
            lock_generation,
            upload_checkpoints: RefCell::new(Vec::new()),
            outbox_revisions: RefCell::new(BTreeMap::new()),
            peer_storage: RefCell::new(BTreeMap::new()),
            next_conversation_gen: Cell::new(next_gen),
        };
        let sealed_state = vault.seal_state(&state_v3_aad(&header_bytes), &state_to_save)?;
        state_to_save.zeroize_secrets();
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        vault.ensure_lock_owned()?;
        let transaction = vault
            .database
            .transaction(&[STORE], TransactionMode::ReadWrite)?;
        let store = transaction.object_store(STORE)?;
        let existing_count = match store.count(None)?.await {
            Ok(count) => count,
            Err(e) => {
                let _ = transaction.abort();
                return Err(e.into());
            }
        };
        if existing_count > 0 || has_rollback_anchor_entry() {
            let _ = transaction.abort();
            return Err(Error::Corrupt(
                "refusing to overwrite an existing or partial vault without explicit reset".into(),
            ));
        }
        if cancel.is_cancelled() {
            let _ = transaction.abort();
            return Err(Error::Cancelled);
        }
        if let Err(e) = vault.ensure_lock_owned() {
            let _ = transaction.abort();
            return Err(e);
        }
        let write_res: Result<()> = (|| {
            store.put(&bytes(&sealed_state), Some(&STATE.into()))?;
            store.put(&bytes(&header_bytes), Some(&HEADER.into()))?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = transaction.abort();
            return Err(e);
        }
        commit(transaction).await?;
        vault.ensure_lock_owned()?;
        write_rollback_anchor(&RollbackAnchor::for_v3_header(&header));
        Ok(vault)
    }

    /// Open the v3 vault with `passphrase`, enforcing pre-KDF header/version/anchor validation,
    /// ephemeral worker KDF + KEK unwrapping, HKDF subkey derivation, and strict deferred sidecar
    /// digest verification.
    pub async fn unlock(
        passphrase: &[u8],
        cancel: &KdfCancelToken,
    ) -> Result<(Self, AppState, DeferredRecord)> {
        let lock_generation = crate::glue::lock_generation();
        ensure_vault_lock_owned(lock_generation)?;
        let database = open().await?;
        let close_on_err = scopeguard::guard(&database, |db| db.close());
        ensure_vault_lock_owned(lock_generation)?;
        // Read HEADER and STATE in one consistent ReadOnly snapshot.
        let (header_bytes, sealed_state) = {
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
            (header, state)
        };
        ensure_vault_lock_owned(lock_generation)?;
        let header = VaultHeader::decode(header_bytes.as_slice())
            .map_err(|e| Error::Corrupt(e.to_string()))?;
        // Validate version, revision, salt, Argon2 bounds, vault_id, wrapped_root_key, and
        // rollback anchor BEFORE deriving the Argon2id KEK.
        header.validate()?;
        let anchor = read_rollback_anchor();
        check_unlock_against_anchor(anchor.as_ref(), &header)?;

        let keys = header.unwrap_keys_async(passphrase, cancel).await?;
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        ensure_vault_lock_owned(lock_generation)?;
        let plain = open_bytes(&keys.state_key, &state_v3_aad(&header_bytes), &sealed_state)
            .ok_or_else(|| Error::Corrupt("vault state failed authentication".into()))?;
        let mut state =
            AppState::decode(plain.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))?;
        if state.record_epoch == 0 {
            return Err(Error::Corrupt("vault state missing record_epoch".into()));
        }

        let deferred_key = opaque_deferred_key(&keys.idb_mac_key);
        let sealed_deferred = get(&database, &deferred_key).await?;
        ensure_vault_lock_owned(lock_generation)?;
        let deferred = match sealed_deferred {
            Some(sealed) => open_deferred(&keys.record_key, state.record_epoch, &sealed)?,
            None => DeferredRecord::default(),
        };
        verify_deferred_record_digest(&state.deferred_initials_digest, &deferred)?;

        ensure_vault_lock_owned(lock_generation)?;
        let next_anchor = advance_anchor(anchor.as_ref(), &header);
        write_rollback_anchor(&next_anchor);
        let record_epoch = state.record_epoch;
        let checkpoints = state.upload_checkpoints.clone();
        let outbox_revs = outbox_revisions_from_proto(&state.outbox_revisions);
        let peer_storage = peer_storage_from_proto(&state.peer_storage);
        let max_existing_gen = peer_storage
            .values()
            .map(|ps| ps.conversation_gen)
            .chain(state.contacts.iter().map(|c| c.conversation_gen))
            .max()
            .unwrap_or(0);
        let next_conversation_gen = state
            .next_conversation_gen
            .max(max_existing_gen.saturating_add(1))
            .max(1);
        state.next_conversation_gen = next_conversation_gen;
        scopeguard::ScopeGuard::into_inner(close_on_err);
        let vault = Self {
            database,
            keys,
            header: RefCell::new(header),
            record_epoch,
            lock_generation,
            upload_checkpoints: RefCell::new(checkpoints),
            outbox_revisions: RefCell::new(outbox_revs),
            peer_storage: RefCell::new(peer_storage),
            next_conversation_gen: Cell::new(next_conversation_gen),
        };
        Ok((vault, state, deferred))
    }

    /// Open an IndexedDB RW transaction and enforce lock ownership, generation match, plus
    /// monotonic CAS revision BEFORE any writes.
    async fn begin_checked_rw_tx(
        &self,
    ) -> Result<(idb::Transaction, idb::ObjectStore, VaultHeader)> {
        self.ensure_lock_owned()?;
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
        if let Err(e) = self.ensure_lock_owned() {
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

    #[allow(clippy::too_many_arguments)]
    fn prepare_state_for_commit(
        &self,
        state: &AppState,
        deferred: &DeferredRecord,
        checkpoints: &[UploadCheckpoint],
        outbox_revs: &BTreeMap<(PublicKey, u64), u64>,
        peer_storage: &BTreeMap<PublicKey, PeerStorageIndex>,
        next_conversation_gen: u64,
        next_header_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        let mut stamped = state.clone();
        stamped.record_epoch = self.record_epoch;
        stamped.next_conversation_gen = stamped.next_conversation_gen.max(next_conversation_gen);
        stamped.upload_checkpoints = checkpoints.to_vec();
        stamped.outbox_revisions = outbox_revisions_to_proto(outbox_revs);
        stamped.peer_storage = peer_storage_to_proto(peer_storage);
        stamped.deferred_initials_digest = deferred_record_digest(deferred);
        let sealed = self.seal_state(&state_v3_aad(next_header_bytes), &stamped);
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
        deferred: &DeferredRecord,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> Result<()> {
        let (transaction, store, trusted) = self.begin_checked_rw_tx().await?;
        let next_header = trusted.next_revision()?;
        let next_header_bytes = next_header.encode_to_vec();
        let outgoing_vec: Vec<(PublicKey, u64, Option<&OutgoingRecord>)> = outgoing
            .into_iter()
            .map(|(peer, index, record)| (*peer, *index, record.as_ref()))
            .collect();
        let mut next_outbox_revs = self.outbox_revisions.borrow().clone();
        for &(peer, index, record) in &outgoing_vec {
            if record.is_some() {
                next_outbox_revs.insert((peer, index), next_header.revision);
            } else {
                next_outbox_revs.remove(&(peer, index));
            }
        }
        let prepared_entries: Vec<PreparedEntry> = entries
            .into_iter()
            .map(|(peer, index, entry)| {
                let (stripped, file_data) = entry.without_file();
                (*peer, *index, stripped, file_data)
            })
            .collect();
        let mut next_peer_storage = self.peer_storage.borrow().clone();
        let mut next_gen = self
            .next_conversation_gen
            .get()
            .max(state.next_conversation_gen)
            .max(1);
        for (peer, index, _, file_data) in &prepared_entries {
            record_peer_entry(
                &mut next_peer_storage,
                &mut next_gen,
                &state.contacts,
                *peer,
                *index,
                file_data.is_some(),
            );
        }
        let checkpoints = self.upload_checkpoints.borrow().clone();
        let sealed_state = match self.prepare_state_for_commit(
            state,
            deferred,
            &checkpoints,
            &next_outbox_revs,
            &next_peer_storage,
            next_gen,
            &next_header_bytes,
        ) {
            Ok(s) => s,
            Err(e) => {
                let _ = transaction.abort();
                return Err(e);
            }
        };
        let write_res: Result<()> = (|| {
            self.put_prepared_entries(&store, prepared_entries, &next_peer_storage)?;
            self.put_outgoing(&store, &outgoing_vec, next_header.revision)?;
            self.put_deferred(&store, deferred)?;
            store.put(&bytes(&sealed_state), Some(&STATE.into()))?;
            store.put(&bytes(&next_header_bytes), Some(&HEADER.into()))?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = transaction.abort();
            return Err(e);
        }
        commit(transaction).await?;
        self.ensure_lock_owned()?;
        *self.outbox_revisions.borrow_mut() = next_outbox_revs;
        *self.peer_storage.borrow_mut() = next_peer_storage;
        self.next_conversation_gen.set(next_gen);
        self.commit_header_and_anchor(next_header);
        Ok(())
    }

    /// Put or delete the separate encrypted [`DeferredRecord`] under its opaque HMAC key.
    fn put_deferred(&self, store: &idb::ObjectStore, deferred: &DeferredRecord) -> Result<()> {
        let key = opaque_deferred_key(&self.keys.idb_mac_key);
        if deferred.is_empty() {
            store.delete(JsValue::from_str(&key))?;
        } else {
            let sealed = try_seal_deferred(&self.keys.record_key, self.record_epoch, deferred)?;
            store.put(&bytes(&sealed), Some(&key.as_str().into()))?;
        }
        Ok(())
    }

    /// Put or delete `outgoing` records in `store`, binding each to `revision`.
    fn put_outgoing(
        &self,
        store: &idb::ObjectStore,
        outgoing: &[(PublicKey, u64, Option<&OutgoingRecord>)],
        revision: u64,
    ) -> Result<()> {
        for &(peer, index, record) in outgoing {
            let key = opaque_outbox_key(&self.keys.idb_mac_key, &peer, index);
            match record {
                Some(record) => {
                    let aad = outbox_aad(&peer, index, self.record_epoch, revision);
                    let sealed = self.seal_record(&aad, record)?;
                    store.put(&bytes(&sealed), Some(&key.as_str().into()))?;
                }
                None => {
                    store.delete(JsValue::from_str(&key))?;
                }
            }
        }
        Ok(())
    }

    /// Put pre-stripped `entries` and optional separate `FileRecord`s into `store` under opaque keys.
    fn put_prepared_entries(
        &self,
        store: &idb::ObjectStore,
        entries: Vec<PreparedEntry>,
        peer_storage: &BTreeMap<PublicKey, PeerStorageIndex>,
    ) -> Result<()> {
        for (peer, index, mut entry, data) in entries {
            let conversation_gen = peer_conversation_gen(peer_storage, &peer);
            if let Some(data) = data {
                let fkey = opaque_file_key(&self.keys.idb_mac_key, &peer, index);
                let mut record = FileRecord {
                    data: data.to_vec(),
                };
                let sealed = self.seal_record(
                    &file_aad(&peer, index, self.record_epoch, conversation_gen),
                    &record,
                )?;
                record.data.zeroize();
                store.put(&bytes(&sealed), Some(&fkey.as_str().into()))?;
            }
            let hkey = opaque_history_key(&self.keys.idb_mac_key, &peer, index);
            let sealed_entry = self.seal_record(
                &history_aad(&peer, index, self.record_epoch, conversation_gen),
                &entry,
            )?;
            entry.zeroize_secrets();
            store.put(&bytes(&sealed_entry), Some(&hkey.as_str().into()))?;
        }
        Ok(())
    }

    /// The bytes of the file of the history entry `index` of the chat with `peer`.
    pub async fn file(&self, peer: &PublicKey, index: u64) -> Result<Vec<u8>> {
        self.file_data(peer, index)
            .await?
            .ok_or_else(|| Error::Corrupt(format!("file record {index} is missing")))
    }

    async fn file_data(&self, peer: &PublicKey, index: u64) -> Result<Option<Vec<u8>>> {
        self.ensure_lock_owned()?;
        let conversation_gen = peer_conversation_gen(&self.peer_storage.borrow(), peer);
        let key = opaque_file_key(&self.keys.idb_mac_key, peer, index);
        let Some(sealed) = get(&self.database, &key).await? else {
            return Ok(None);
        };
        self.ensure_lock_owned()?;
        let record = open_bytes(
            &self.keys.record_key,
            &file_aad(peer, index, self.record_epoch, conversation_gen),
            &sealed,
        )
        .ok_or_else(|| Error::Corrupt(format!("file record {index} does not decrypt")))?;
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
            let Some(data) = self.file_data(peer, index).await? else {
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
        self.ensure_lock_owned()?;
        let conversation_gen = peer_conversation_gen(&self.peer_storage.borrow(), peer);
        let key = opaque_history_key(&self.keys.idb_mac_key, peer, index);
        let Some(sealed) = get(&self.database, &key).await? else {
            return Ok(None);
        };
        self.ensure_lock_owned()?;
        let entry = open_bytes(
            &self.keys.record_key,
            &history_aad(peer, index, self.record_epoch, conversation_gen),
            &sealed,
        )
        .ok_or_else(|| Error::Corrupt(format!("history entry {index} does not decrypt")))?;
        HistoryEntry::decode(entry.as_slice())
            .map(Some)
            .map_err(|e| Error::Corrupt(e.to_string()))
    }

    /// The record of the message waiting to be pushed that is the history entry `index` of the
    /// chat with `peer`.
    pub async fn outgoing(&self, peer: &PublicKey, index: u64) -> Result<OutgoingRecord> {
        self.ensure_lock_owned()?;
        let key = opaque_outbox_key(&self.keys.idb_mac_key, peer, index);
        let sealed = get(&self.database, &key)
            .await?
            .ok_or_else(|| Error::Corrupt(format!("outbox record {index} is missing")))?;
        self.ensure_lock_owned()?;
        let expected_rev = self
            .outbox_revisions
            .borrow()
            .get(&(*peer, index))
            .copied()
            .ok_or_else(|| Error::Corrupt(format!("outbox record {index} missing revision")))?;
        let record = open_bytes(
            &self.keys.record_key,
            &outbox_aad(peer, index, self.record_epoch, expected_rev),
            &sealed,
        )
        .ok_or_else(|| Error::Corrupt(format!("outbox record {index} does not decrypt")))?;
        OutgoingRecord::decode(record.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))
    }

    /// The history of the chat with `peer`, oldest first, at most the last `limit` entries,
    /// pipelined as point gets inside a single `ReadOnly` transaction.
    pub async fn history(
        &self,
        peer: &PublicKey,
        history_len: u64,
        limit: u64,
    ) -> Result<Vec<(u64, HistoryEntry)>> {
        self.ensure_lock_owned()?;
        let Some((first, last)) = history_bounds(history_len, limit) else {
            return Ok(vec![]);
        };
        let conversation_gen = peer_conversation_gen(&self.peer_storage.borrow(), peer);
        let transaction = self
            .database
            .transaction(&[STORE], TransactionMode::ReadOnly)?;
        let store = transaction.object_store(STORE)?;
        let mut requests = Vec::with_capacity((last - first + 1) as usize);
        for index in first..=last {
            let key = opaque_history_key(&self.keys.idb_mac_key, peer, index);
            requests.push((index, store.get(JsValue::from_str(&key))?));
        }
        let mut entries = Vec::with_capacity(requests.len());
        for (index, req) in requests {
            let Some(value) = req.await? else {
                continue;
            };
            self.ensure_lock_owned()?;
            let sealed = Uint8Array::new(&value).to_vec();
            let plain = open_bytes(
                &self.keys.record_key,
                &history_aad(peer, index, self.record_epoch, conversation_gen),
                &sealed,
            )
            .ok_or_else(|| Error::Corrupt(format!("history entry {index} does not decrypt")))?;
            let entry = HistoryEntry::decode(plain.as_slice())
                .map_err(|e| Error::Corrupt(e.to_string()))?;
            entries.push((index, entry));
        }
        Ok(entries)
    }

    /// Keep chunk `index` of the attachment `id`, in the chat with `peer`, as the server has it.
    /// Short-circuits `STATE` rewrite when chunk `index` is already recorded in `peer_storage`.
    pub async fn put_chunk(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
        chunk: &[u8],
    ) -> Result<()> {
        let key = opaque_chunk_key(&self.keys.idb_mac_key, peer, id, index);
        let already_tracked = self
            .peer_storage
            .borrow()
            .get(peer)
            .and_then(|ps| ps.kept_chunks.iter().find(|a| a.id.as_slice() == id))
            .is_some_and(|a| a.has_bit(index));

        if already_tracked {
            let (transaction, store, _) = self.begin_checked_rw_tx().await?;
            if let Err(e) = store.put(&bytes(chunk), Some(&key.as_str().into())) {
                let _ = transaction.abort();
                return Err(e.into());
            }
            return commit(transaction).await;
        }

        let (transaction, store, trusted) = self.begin_checked_rw_tx().await?;
        let write = async {
            let state_raw = store
                .get(JsValue::from_str(STATE))?
                .await?
                .ok_or_else(|| Error::Corrupt("no state".into()))?;
            self.ensure_lock_owned()?;
            let state_bytes = Uint8Array::new(&state_raw).to_vec();
            let plain = open_bytes(
                &self.keys.state_key,
                &state_v3_aad(&trusted.encode_to_vec()),
                &state_bytes,
            )
            .ok_or_else(|| Error::Corrupt("vault state failed authentication".into()))?;
            let mut app_state =
                AppState::decode(plain.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))?;

            let mut next_peer_storage = self.peer_storage.borrow().clone();
            let mut next_gen = self
                .next_conversation_gen
                .get()
                .max(app_state.next_conversation_gen)
                .max(1);
            set_peer_chunk_bit(
                &mut next_peer_storage,
                &mut next_gen,
                &app_state.contacts,
                *peer,
                id,
                index,
            )?;
            app_state.record_epoch = self.record_epoch;
            app_state.next_conversation_gen = app_state.next_conversation_gen.max(next_gen);
            app_state.upload_checkpoints = self.upload_checkpoints.borrow().clone();
            app_state.outbox_revisions = outbox_revisions_to_proto(&self.outbox_revisions.borrow());
            app_state.peer_storage = peer_storage_to_proto(&next_peer_storage);

            let next = trusted.next_revision()?;
            let header = next.encode_to_vec();
            let sealed = self.seal_state(&state_v3_aad(&header), &app_state);
            app_state.zeroize_secrets();
            let sealed = sealed?;

            store.put(&bytes(chunk), Some(&key.as_str().into()))?;
            store.put(&bytes(&sealed), Some(&STATE.into()))?;
            store.put(&bytes(&header), Some(&HEADER.into()))?;
            Ok((next, next_peer_storage, next_gen))
        }
        .await;
        let (next, next_peer_storage, next_gen) = match write {
            Ok(res) => res,
            Err(e) => {
                let _ = transaction.abort();
                return Err(e);
            }
        };
        commit(transaction).await?;
        self.ensure_lock_owned()?;
        *self.peer_storage.borrow_mut() = next_peer_storage;
        self.next_conversation_gen.set(next_gen);
        self.commit_header_and_anchor(next);
        Ok(())
    }

    /// Chunk `index` of the attachment `id`, in the chat with `peer`, if kept.
    pub async fn chunk(&self, peer: &PublicKey, id: &[u8], index: u32) -> Result<Option<Vec<u8>>> {
        self.ensure_lock_owned()?;
        let key = opaque_chunk_key(&self.keys.idb_mac_key, peer, id, index);
        let chunk = get(&self.database, &key).await?;
        self.ensure_lock_owned()?;
        Ok(chunk)
    }

    /// How many chunks of the attachment `id`, in the chat with `peer`, are kept (O(1) bitmap count).
    pub async fn chunks_kept(&self, peer: &PublicKey, id: &[u8]) -> Result<u32> {
        Ok(self
            .peer_storage
            .borrow()
            .get(peer)
            .and_then(|ps| ps.kept_chunks.iter().find(|a| a.id.as_slice() == id))
            .map_or(0, AttachmentChunks::count))
    }

    /// Keep `upload` in the chat with `peer`, replacing any previous copy, and bind its
    /// checkpoint and commit revision into `STATE` in the same transaction.
    pub async fn save_upload(&self, peer: &PublicKey, upload: &PendingUpload) -> Result<()> {
        self.write_upload(peer, &upload.id, Some(upload)).await
    }

    /// Atomically promote a waiting sign-in upload (`old_id`) into a server-started `new_upload`
    /// (or delete `old_id` when `new_upload` is `None`) together with the updated `state`,
    /// `deferred`, `entries`, and `outgoing` in a single IndexedDB RW transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn promote_upload<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredRecord,
        peer: &PublicKey,
        old_id: &[u8],
        new_upload: Option<&PendingUpload>,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> Result<()> {
        let (transaction, store, trusted) = self.begin_checked_rw_tx().await?;
        let next_header = trusted.next_revision()?;
        let next_header_bytes = next_header.encode_to_vec();
        let outgoing_vec: Vec<(PublicKey, u64, Option<&OutgoingRecord>)> = outgoing
            .into_iter()
            .map(|(p, index, record)| (*p, *index, record.as_ref()))
            .collect();
        let mut next_outbox_revs = self.outbox_revisions.borrow().clone();
        for &(p, index, record) in &outgoing_vec {
            if record.is_some() {
                next_outbox_revs.insert((p, index), next_header.revision);
            } else {
                next_outbox_revs.remove(&(p, index));
            }
        }
        let prepared_entries: Vec<PreparedEntry> = entries
            .into_iter()
            .map(|(p, index, entry)| {
                let (stripped, file_data) = entry.without_file();
                (*p, *index, stripped, file_data)
            })
            .collect();
        let mut next_peer_storage = self.peer_storage.borrow().clone();
        let mut next_gen = self
            .next_conversation_gen
            .get()
            .max(state.next_conversation_gen)
            .max(1);
        for (p, index, _, file_data) in &prepared_entries {
            record_peer_entry(
                &mut next_peer_storage,
                &mut next_gen,
                &state.contacts,
                *p,
                *index,
                file_data.is_some(),
            );
        }
        let mut next_checkpoints = self.upload_checkpoints.borrow().clone();
        remove_upload_checkpoint(&mut next_checkpoints, peer, old_id);
        if let Some(new_upload) = new_upload {
            upsert_upload_checkpoint(
                &mut next_checkpoints,
                peer,
                new_upload,
                next_header.revision,
            );
        }

        let sealed_state = match self.prepare_state_for_commit(
            state,
            deferred,
            &next_checkpoints,
            &next_outbox_revs,
            &next_peer_storage,
            next_gen,
            &next_header_bytes,
        ) {
            Ok(s) => s,
            Err(e) => {
                let _ = transaction.abort();
                return Err(e);
            }
        };
        let sealed_upload = match new_upload {
            Some(new_upload) => match self.seal_record(
                &upload_aad(
                    peer,
                    &new_upload.id,
                    self.record_epoch,
                    next_header.revision,
                ),
                new_upload,
            ) {
                Ok(s) => Some((
                    opaque_upload_key(&self.keys.idb_mac_key, peer, &new_upload.id),
                    s,
                )),
                Err(e) => {
                    let _ = transaction.abort();
                    return Err(e);
                }
            },
            None => None,
        };
        let old_key = opaque_upload_key(&self.keys.idb_mac_key, peer, old_id);
        let write_res: Result<()> = (|| {
            match sealed_upload {
                Some((ref new_key, ref sealed)) => {
                    store.put(&bytes(sealed), Some(&new_key.as_str().into()))?;
                    if old_key != *new_key {
                        store.delete(JsValue::from_str(&old_key))?;
                    }
                }
                None => {
                    store.delete(JsValue::from_str(&old_key))?;
                }
            }
            self.put_prepared_entries(&store, prepared_entries, &next_peer_storage)?;
            self.put_outgoing(&store, &outgoing_vec, next_header.revision)?;
            self.put_deferred(&store, deferred)?;
            store.put(&bytes(&sealed_state), Some(&STATE.into()))?;
            store.put(&bytes(&next_header_bytes), Some(&HEADER.into()))?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = transaction.abort();
            return Err(e);
        }
        commit(transaction).await?;
        self.ensure_lock_owned()?;
        *self.upload_checkpoints.borrow_mut() = next_checkpoints;
        *self.outbox_revisions.borrow_mut() = next_outbox_revs;
        *self.peer_storage.borrow_mut() = next_peer_storage;
        self.next_conversation_gen.set(next_gen);
        self.commit_header_and_anchor(next_header);
        Ok(())
    }

    /// Forget the upload once cancelled or deleted from the server, removing its checkpoint from
    /// `STATE` in the same transaction.
    pub async fn forget_upload(&self, peer: &PublicKey, id: &[u8]) -> Result<()> {
        self.write_upload(peer, id, None).await
    }

    /// Advance the revision, seal `upload` under `next.revision` (if `Some`), update
    /// `AppState.upload_checkpoints`, and rebind `STATE` to the new header in one atomic RW tx.
    async fn write_upload(
        &self,
        peer: &PublicKey,
        id: &[u8],
        upload: Option<&PendingUpload>,
    ) -> Result<()> {
        let key = opaque_upload_key(&self.keys.idb_mac_key, peer, id);
        let (transaction, store, trusted) = self.begin_checked_rw_tx().await?;
        let write = async {
            let state_raw = store
                .get(JsValue::from_str(STATE))?
                .await?
                .ok_or_else(|| Error::Corrupt("no state".into()))?;
            self.ensure_lock_owned()?;
            let state_bytes = Uint8Array::new(&state_raw).to_vec();
            let plain = open_bytes(
                &self.keys.state_key,
                &state_v3_aad(&trusted.encode_to_vec()),
                &state_bytes,
            )
            .ok_or_else(|| Error::Corrupt("vault state failed authentication".into()))?;
            let mut app_state =
                AppState::decode(plain.as_slice()).map_err(|e| Error::Corrupt(e.to_string()))?;

            let next = trusted.next_revision()?;
            let mut next_checkpoints = self.upload_checkpoints.borrow().clone();
            let sealed_upload = match upload {
                Some(pending) => {
                    upsert_upload_checkpoint(&mut next_checkpoints, peer, pending, next.revision);
                    Some(self.seal_record(
                        &upload_aad(peer, &pending.id, self.record_epoch, next.revision),
                        pending,
                    )?)
                }
                None => {
                    remove_upload_checkpoint(&mut next_checkpoints, peer, id);
                    None
                }
            };
            app_state.record_epoch = self.record_epoch;
            app_state.next_conversation_gen = app_state
                .next_conversation_gen
                .max(self.next_conversation_gen.get());
            app_state.upload_checkpoints = next_checkpoints.clone();
            app_state.outbox_revisions = outbox_revisions_to_proto(&self.outbox_revisions.borrow());
            app_state.peer_storage = peer_storage_to_proto(&self.peer_storage.borrow());

            let header = next.encode_to_vec();
            let sealed_state = self.seal_state(&state_v3_aad(&header), &app_state);
            app_state.zeroize_secrets();
            let sealed_state = sealed_state?;

            let key_js = JsValue::from_str(&key);
            match sealed_upload {
                Some(sealed_upload) => {
                    store.put(&bytes(&sealed_upload), Some(&key_js))?;
                }
                None => {
                    store.delete(key_js)?;
                }
            }
            store.put(&bytes(&sealed_state), Some(&STATE.into()))?;
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
        self.ensure_lock_owned()?;
        *self.upload_checkpoints.borrow_mut() = next_checkpoints;
        self.commit_header_and_anchor(next);
        Ok(())
    }

    /// The upload `id`, in the chat with `peer`, if kept and matching its `STATE` checkpoint.
    pub async fn upload(&self, peer: &PublicKey, id: &[u8]) -> Result<Option<PendingUpload>> {
        self.ensure_lock_owned()?;
        let key = opaque_upload_key(&self.keys.idb_mac_key, peer, id);
        let Some(sealed) = get(&self.database, &key).await? else {
            return Ok(None);
        };
        self.ensure_lock_owned()?;
        let checkpoints = self.upload_checkpoints.borrow();
        let cp = find_upload_checkpoint(&checkpoints, peer, id).ok_or_else(|| {
            Error::Corrupt("upload record missing authenticated upload checkpoint".into())
        })?;
        let upload = decode_upload_with_checkpoint(
            &self.keys.record_key,
            self.record_epoch,
            cp,
            peer,
            &sealed,
        )
        .ok_or_else(|| {
            Error::Corrupt("upload record failed decryption or checkpoint check".into())
        })?;
        Ok(Some(upload))
    }

    /// IDs of started uploads (`UPLOAD_STATE_STARTED | UPLOAD_STATE_ANNOUNCED`) for `peer` whose
    /// authenticated checkpoint still records `uploaded == 0`, even if the separate upload record
    /// is missing or failed authentication (`R13-P2-1`, `R13-P1-3`).
    pub fn unuploaded_started_upload_ids(&self, peer: &PublicKey) -> Vec<[u8; 16]> {
        self.upload_checkpoints
            .borrow()
            .iter()
            .filter_map(|cp| {
                if cp.peer.as_slice() == peer.as_slice()
                    && cp.uploaded == 0
                    && matches!(
                        cp.upload_state,
                        UPLOAD_STATE_STARTED | UPLOAD_STATE_ANNOUNCED
                    )
                {
                    <[u8; 16]>::try_from(cp.id.as_slice()).ok()
                } else {
                    None
                }
            })
            .collect()
    }

    /// Snapshot of all authenticated upload checkpoints tracked by the vault header (optionally
    /// filtered to `peer`), enabling orphan-checkpoint recovery on unlock and cancel when a
    /// separate `PendingUpload` record is missing or failed authentication (`R14-P2-3`).
    pub fn tracked_upload_checkpoints(&self, peer: Option<&PublicKey>) -> Vec<UploadCheckpoint> {
        self.upload_checkpoints
            .borrow()
            .iter()
            .filter(|cp| peer.is_none_or(|p| cp.peer.as_slice() == p.as_slice()))
            .cloned()
            .collect()
    }

    /// The uploads kept, those not done, with the peers of their chats: those of the chat with
    /// `peer` only, if given. Point-gets each tracked checkpoint without prefix scanning,
    /// tolerating individual corrupt records.
    pub async fn uploads(
        &self,
        peer: Option<&PublicKey>,
    ) -> Result<Vec<(PublicKey, PendingUpload)>> {
        self.ensure_lock_owned()?;
        let matching: Vec<(PublicKey, UploadCheckpoint)> = self
            .upload_checkpoints
            .borrow()
            .iter()
            .filter_map(|cp| {
                let p = PublicKey::try_from(cp.peer.as_slice()).ok()?;
                if peer.is_none_or(|wanted| wanted == &p) {
                    Some((p, cp.clone()))
                } else {
                    None
                }
            })
            .collect();
        if matching.is_empty() {
            return Ok(Vec::new());
        }
        let transaction = self
            .database
            .transaction(&[STORE], TransactionMode::ReadOnly)?;
        let store = transaction.object_store(STORE)?;
        let mut requests = Vec::with_capacity(matching.len());
        for (p, cp) in matching {
            let key = opaque_upload_key(&self.keys.idb_mac_key, &p, &cp.id);
            requests.push((p, cp, store.get(JsValue::from_str(&key))?));
        }
        let mut out = Vec::with_capacity(requests.len());
        for (p, cp, req) in requests {
            let Some(val) = req.await? else {
                continue;
            };
            self.ensure_lock_owned()?;
            let sealed = Uint8Array::new(&val).to_vec();
            if let Some(upload) = decode_upload_with_checkpoint(
                &self.keys.record_key,
                self.record_epoch,
                &cp,
                &p,
                &sealed,
            ) {
                out.push((p, upload));
            }
        }
        Ok(out)
    }

    /// Save `state` and `deferred`, point-deleting all history, files, outbox, kept chunks, and
    /// uploads tracked for `peer`, plus `entries` / `outgoing` of other chats, enforcing monotonic
    /// `revision` CAS.
    pub async fn forget<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredRecord,
        peer: &PublicKey,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> Result<()> {
        let (transaction, store, trusted) = self.begin_checked_rw_tx().await?;
        let next_header = trusted.next_revision()?;
        let next_header_bytes = next_header.encode_to_vec();
        let outgoing_vec: Vec<(PublicKey, u64, Option<&OutgoingRecord>)> = outgoing
            .into_iter()
            .map(|(p, index, record)| (*p, *index, record.as_ref()))
            .collect();

        // Collect all opaque keys to delete for `peer` from authenticated STATE indices, advance
        // the vault-wide monotonic `next_conversation_gen` so deleted history/file ciphertexts
        // can never decrypt if spliced into a recreated conversation, and completely remove
        // `peer` from `peer_storage` so zero deleted peer identities remain persisted in `STATE`.
        let mut keys_to_delete: Vec<String> = Vec::new();
        let mut next_peer_storage = self.peer_storage.borrow().clone();
        let mut next_gen = self
            .next_conversation_gen
            .get()
            .max(state.next_conversation_gen)
            .max(1);
        if let Some(old_ps) = next_peer_storage.remove(peer) {
            for idx in 0..old_ps.max_history_len {
                keys_to_delete.push(opaque_history_key(&self.keys.idb_mac_key, peer, idx));
            }
            for idx in old_ps.file_indices {
                keys_to_delete.push(opaque_file_key(&self.keys.idb_mac_key, peer, idx));
            }
            for ac in old_ps.kept_chunks {
                for chunk_idx in ac.indices() {
                    keys_to_delete.push(opaque_chunk_key(
                        &self.keys.idb_mac_key,
                        peer,
                        &ac.id,
                        chunk_idx,
                    ));
                }
            }
            next_gen = next_gen.max(old_ps.conversation_gen.saturating_add(1));
        }
        let mut next_outbox_revs = self.outbox_revisions.borrow().clone();
        next_outbox_revs.retain(|&(p, idx), _| {
            if p == *peer {
                keys_to_delete.push(opaque_outbox_key(&self.keys.idb_mac_key, peer, idx));
                false
            } else {
                true
            }
        });
        for &(p, index, record) in &outgoing_vec {
            if record.is_some() {
                next_outbox_revs.insert((p, index), next_header.revision);
            } else {
                next_outbox_revs.remove(&(p, index));
            }
        }
        let mut next_checkpoints = self.upload_checkpoints.borrow().clone();
        next_checkpoints.retain(|cp| {
            if cp.peer.as_slice() == peer.as_slice() {
                keys_to_delete.push(opaque_upload_key(&self.keys.idb_mac_key, peer, &cp.id));
                false
            } else {
                true
            }
        });

        let prepared_entries: Vec<PreparedEntry> = entries
            .into_iter()
            .map(|(p, index, entry)| {
                let (stripped, file_data) = entry.without_file();
                (*p, *index, stripped, file_data)
            })
            .collect();
        for (p, index, _, file_data) in &prepared_entries {
            record_peer_entry(
                &mut next_peer_storage,
                &mut next_gen,
                &state.contacts,
                *p,
                *index,
                file_data.is_some(),
            );
        }

        let sealed_state = match self.prepare_state_for_commit(
            state,
            deferred,
            &next_checkpoints,
            &next_outbox_revs,
            &next_peer_storage,
            next_gen,
            &next_header_bytes,
        ) {
            Ok(s) => s,
            Err(e) => {
                let _ = transaction.abort();
                return Err(e);
            }
        };
        let write_res: Result<()> = (|| {
            for key in &keys_to_delete {
                store.delete(JsValue::from_str(key))?;
            }
            self.put_prepared_entries(&store, prepared_entries, &next_peer_storage)?;
            self.put_outgoing(&store, &outgoing_vec, next_header.revision)?;
            self.put_deferred(&store, deferred)?;
            store.put(&bytes(&sealed_state), Some(&STATE.into()))?;
            store.put(&bytes(&next_header_bytes), Some(&HEADER.into()))?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = transaction.abort();
            return Err(e);
        }
        commit(transaction).await?;
        self.ensure_lock_owned()?;
        *self.upload_checkpoints.borrow_mut() = next_checkpoints;
        *self.outbox_revisions.borrow_mut() = next_outbox_revs;
        *self.peer_storage.borrow_mut() = next_peer_storage;
        self.next_conversation_gen.set(next_gen);
        self.commit_header_and_anchor(next_header);
        Ok(())
    }

    /// Delete the vault for good and clear both v1 and v3 external rollback anchors.
    pub async fn destroy() -> Result<()> {
        let lock_generation = crate::glue::lock_generation();
        ensure_vault_lock_owned(lock_generation)?;
        let database = open().await?;
        let result: Result<()> = async {
            ensure_vault_lock_owned(lock_generation)?;
            let transaction = database.transaction(&[STORE], TransactionMode::ReadWrite)?;
            transaction.object_store(STORE)?.clear()?;
            commit(transaction).await?;
            Ok(())
        }
        .await;
        database.close();
        result?;
        ensure_vault_lock_owned(lock_generation)?;
        clear_rollback_anchor();
        Ok(())
    }

    /// Seal `AppState` under `state_key` with `aad`, zeroizing the encoded plaintext buffer.
    fn seal_state(&self, aad: &[u8], record: &impl Message) -> Result<Vec<u8>> {
        let plaintext = Zeroizing::new(record.encode_to_vec());
        try_seal_bytes(&self.keys.state_key, aad, &plaintext)
    }

    /// Seal a non-state record under `record_key` with `aad`, zeroizing the encoded plaintext buffer.
    fn seal_record(&self, aad: &[u8], record: &impl Message) -> Result<Vec<u8>> {
        let plaintext = Zeroizing::new(record.encode_to_vec());
        try_seal_bytes(&self.keys.record_key, aad, &plaintext)
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn argon2_bounds_match_kdf_crate() {
        assert_eq!(ARGON2_MEMORY_MIN, e2ee_chat_kdf::ARGON2_MEMORY_MIN);
        assert_eq!(ARGON2_MEMORY_MAX, e2ee_chat_kdf::ARGON2_MEMORY_MAX);
        assert_eq!(ARGON2_DEFAULT_MEMORY, e2ee_chat_kdf::ARGON2_DEFAULT_MEMORY);
        assert_eq!(ARGON2_ITERATIONS_MIN, e2ee_chat_kdf::ARGON2_ITERATIONS_MIN);
        assert_eq!(ARGON2_ITERATIONS_MAX, e2ee_chat_kdf::ARGON2_ITERATIONS_MAX);
        assert_eq!(
            ARGON2_DEFAULT_ITERATIONS,
            e2ee_chat_kdf::ARGON2_DEFAULT_ITERATIONS
        );
        assert_eq!(
            ARGON2_PARALLELISM_MIN,
            e2ee_chat_kdf::ARGON2_PARALLELISM_MIN
        );
        assert_eq!(
            ARGON2_PARALLELISM_MAX,
            e2ee_chat_kdf::ARGON2_PARALLELISM_MAX
        );
        assert_eq!(
            ARGON2_DEFAULT_PARALLELISM,
            e2ee_chat_kdf::ARGON2_DEFAULT_PARALLELISM
        );
        assert_eq!(ARGON2_SALT_MIN, e2ee_chat_kdf::ARGON2_SALT_MIN);
        assert_eq!(ARGON2_SALT_MAX, e2ee_chat_kdf::ARGON2_SALT_MAX);
    }

    fn test_header_and_keys(passphrase: &[u8]) -> (VaultHeader, VaultKeys) {
        VaultHeader::create_with_params(passphrase, ARGON2_MEMORY_MIN, 1, 1)
            .expect("create v3 test header")
    }

    #[test]
    fn vault_header_v3_bounds_and_pre_kdf_incompatible_version() {
        let (header, keys) = test_header_and_keys(b"test-passphrase");
        assert_eq!(header.version, VAULT_VERSION_V3);
        assert_eq!(header.revision, 1);
        assert_eq!(header.vault_id.len(), VAULT_ID_LEN);
        assert_eq!(header.wrapped_root_key.len(), WRAPPED_ROOT_KEY_LEN);
        assert!(header.validate().is_ok());

        // Correct passphrase unwraps identical subkeys; wrong passphrase fails cleanly.
        let unwrapped = header.unwrap_keys(b"test-passphrase").unwrap();
        assert_eq!(unwrapped.state_key, keys.state_key);
        assert_eq!(unwrapped.record_key, keys.record_key);
        assert_eq!(unwrapped.idb_mac_key, keys.idb_mac_key);
        assert!(matches!(
            header.unwrap_keys(b"wrong-passphrase"),
            Err(Error::WrongPassphrase)
        ));

        // Legacy/future versions return IncompatibleVersion PRE-KDF even with absurd Argon2 memory.
        for bad_ver in [0u32, 1, 2, 4, 99] {
            let incompat = VaultHeader {
                version: bad_ver,
                memory: u32::MAX,
                ..header.clone()
            };
            assert!(matches!(
                incompat.validate(),
                Err(Error::IncompatibleVersion(v)) if v == bad_ver
            ));
            assert!(matches!(
                incompat.unwrap_keys(b"any"),
                Err(Error::IncompatibleVersion(v)) if v == bad_ver
            ));
        }

        // Out-of-range KDF params, revision 0, bad vault_id/wrapped_root_key fail with Corrupt pre-KDF.
        for bad in [
            VaultHeader {
                memory: ARGON2_MEMORY_MIN - 1,
                ..header.clone()
            },
            VaultHeader {
                memory: ARGON2_MEMORY_MAX + 1,
                ..header.clone()
            },
            VaultHeader {
                iterations: 0,
                ..header.clone()
            },
            VaultHeader {
                iterations: ARGON2_ITERATIONS_MAX + 1,
                ..header.clone()
            },
            VaultHeader {
                parallelism: 0,
                ..header.clone()
            },
            VaultHeader {
                parallelism: ARGON2_PARALLELISM_MAX + 1,
                ..header.clone()
            },
            VaultHeader {
                salt: vec![0u8; 8],
                ..header.clone()
            },
            VaultHeader {
                revision: 0,
                ..header.clone()
            },
            VaultHeader {
                vault_id: vec![0u8; 15],
                ..header.clone()
            },
            VaultHeader {
                wrapped_root_key: vec![0u8; 71],
                ..header.clone()
            },
        ] {
            assert!(
                matches!(bad.validate(), Err(Error::Corrupt(_))),
                "expected Corrupt for {bad:?}"
            );
            assert!(matches!(bad.unwrap_keys(b"pass"), Err(Error::Corrupt(_))));
        }
    }

    #[test]
    fn kek_wrap_survives_revision_bumps_and_salt_rotation_preserves_subkeys_and_anchor() {
        let (header, keys) = test_header_and_keys(b"old-passphrase");
        // Bumping revision keeps wrapped_root_key valid because root_key_wrap_aad omits revision.
        let bumped = VaultHeader {
            revision: 42,
            ..header.clone()
        };
        let unwrapped_bumped = bumped.unwrap_keys(b"old-passphrase").unwrap();
        assert_eq!(unwrapped_bumped.state_key, keys.state_key);
        assert_eq!(unwrapped_bumped.record_key, keys.record_key);
        assert_eq!(unwrapped_bumped.idb_mac_key, keys.idb_mac_key);

        // Tampering KDF params or vault_id invalidates KEK wrap AAD.
        let mut tampered_id = header.clone();
        tampered_id.vault_id[0] ^= 0xFF;
        assert!(matches!(
            tampered_id.unwrap_keys(b"old-passphrase"),
            Err(Error::WrongPassphrase)
        ));
        let mut tampered_mem = header.clone();
        tampered_mem.memory = ARGON2_MEMORY_MIN + 1;
        assert!(matches!(
            tampered_mem.unwrap_keys(b"old-passphrase"),
            Err(Error::WrongPassphrase)
        ));

        // Simulate passphrase + salt rotation keeping static vault_id and root_key:
        // VaultKeys remain identical and RollbackAnchor still accepts the rotated header!
        let old_kek = header.derive_kek(b"old-passphrase").unwrap();
        let root_key_bytes = open_bytes(
            &old_kek,
            &root_key_wrap_aad(&header),
            &header.wrapped_root_key,
        )
        .unwrap();
        let mut rotated = header.clone();
        rotated.salt = vec![0x99; 16];
        rotated.revision = 2;
        let new_kek = rotated.derive_kek(b"new-passphrase").unwrap();
        rotated.wrapped_root_key = try_seal_bytes(
            &new_kek,
            &root_key_wrap_aad(&rotated),
            root_key_bytes.as_slice(),
        )
        .unwrap();

        let rotated_keys = rotated.unwrap_keys(b"new-passphrase").unwrap();
        assert_eq!(rotated_keys.state_key, keys.state_key);
        assert_eq!(rotated_keys.record_key, keys.record_key);
        assert_eq!(rotated_keys.idb_mac_key, keys.idb_mac_key);

        let anchor = RollbackAnchor::for_v3_header(&header);
        assert!(check_unlock_against_anchor(Some(&anchor), &rotated).is_ok());
    }

    #[test]
    fn state_v3_aad_and_checked_header_detect_tampering() {
        let (header, keys) = test_header_and_keys(b"passphrase");
        let state = AppState {
            name: "Alice".to_string(),
            server: "https://chat.example.com".to_string(),
            record_epoch: 7,
            ..AppState::default()
        };
        let header_bytes = header.encode_to_vec();
        let aad = state_v3_aad(&header_bytes);
        assert!(aad.starts_with(b"state/v3\0"));
        let sealed = seal_bytes(&keys.state_key, &aad, &state.encode_to_vec());

        // Opens with exact header; fails on any header mutation or wrong subkey.
        let opened = open_bytes(&keys.state_key, &aad, &sealed).unwrap();
        assert_eq!(AppState::decode(opened.as_slice()).unwrap(), state);
        assert!(open_bytes(&keys.record_key, &aad, &sealed).is_none());

        let mut rev_changed = header.clone();
        rev_changed.revision = 2;
        assert!(
            open_bytes(
                &keys.state_key,
                &state_v3_aad(&rev_changed.encode_to_vec()),
                &sealed
            )
            .is_none()
        );

        assert_eq!(
            verify_checked_header(&header, &header.encode_to_vec()).unwrap(),
            header
        );
        for field in 0..8 {
            let mut changed = header.clone();
            match field {
                0 => changed.salt[0] ^= 1,
                1 => changed.memory += 1,
                2 => changed.iterations += 1,
                3 => changed.parallelism += 1,
                4 => changed.vault_id[0] ^= 1,
                5 => changed.wrapped_root_key[0] ^= 1,
                6 => changed.revision += 1,
                _ => changed.version = 2,
            }
            let error = verify_checked_header(&header, &changed.encode_to_vec()).unwrap_err();
            if field < 6 {
                assert!(matches!(error, Error::Corrupt(_)));
            } else {
                assert!(matches!(error, Error::Conflict { .. }));
            }
        }
    }

    #[test]
    fn upload_revisions_authenticate_state_at_each_commit() {
        let (mut current, keys) = test_header_and_keys(b"passphrase");
        let mut sealed = seal_bytes(
            &keys.state_key,
            &state_v3_aad(&current.encode_to_vec()),
            b"state",
        );
        for _ in 0..2 {
            let (next, header, updated) =
                reseal_state_for_next_revision(&keys.state_key, &current, &sealed).unwrap();
            assert_eq!(next.revision, current.revision + 1);
            assert_eq!(next.encode_to_vec(), header);
            assert_eq!(
                &**open_bytes(&keys.state_key, &state_v3_aad(&header), &updated).unwrap(),
                b"state"
            );
            assert!(
                open_bytes(
                    &keys.state_key,
                    &state_v3_aad(&current.encode_to_vec()),
                    &updated
                )
                .is_none()
            );
            current = next;
            sealed = updated;
        }
        sealed[0] ^= 1;
        assert!(matches!(
            reseal_state_for_next_revision(&keys.state_key, &current, &sealed),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn sensitive_records_implement_zeroize_on_drop_and_redacted_debug() {
        fn requires_wipe_on_drop<T: ZeroizeOnDrop>(_: &T) {}
        let mut upload = PendingUpload::default();
        upload.token.extend([1; 16]);
        upload.key.extend([2; 32]);
        upload.prefix_hash.extend([3; 32]);
        upload.sealed_chunk_hash.extend([4; 32]);
        requires_wipe_on_drop(&upload);
        upload.clear_secrets();
        assert!(upload.token.is_empty() && upload.key.is_empty());

        let outgoing = OutgoingRecord {
            message: None,
            content: b"super-secret-plaintext".to_vec(),
            write_token: vec![0xAA; 32],
            carried_initial: vec![0xBB; 16],
            session_id: vec![0xCC; 16],
        };
        requires_wipe_on_drop(&outgoing);
        let dbg = format!("{outgoing:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(!dbg.contains("170")); // 0xAA
        assert!(outgoing.to_sealed().is_none());
        assert!(outgoing.to_push_v2_request(&[0x55; 32]).is_none());

        let sealed_rec = OutgoingRecord {
            message: Some(party::EncryptedMessage {
                header: Bytes::from_static(b"hdr"),
                content: Bytes::from_static(b"ct"),
            }),
            content: vec![],
            write_token: vec![0xAA; 32],
            carried_initial: vec![],
            session_id: vec![0xCC; 16],
        };
        let req = sealed_rec
            .to_push_v2_request(&[0x55; 32])
            .expect("valid sealed OutgoingRecord builds PushV2Request");
        assert_eq!(req.recipient.as_ref(), &[0x55; 32]);
        assert_eq!(req.write_token.as_ref(), &[0xAA; 32]);
        assert_eq!(req.client_message_id.len(), 16);
        assert!(sealed_rec.to_sealed().is_some());

        let farewell = Farewell {
            push_v2: vec![0xDD; 48],
        };
        requires_wipe_on_drop(&farewell);
        let fdbg = format!("{farewell:?}");
        assert!(!fdbg.contains("221")); // 0xDD
    }

    #[test]
    fn rollback_anchor_v3_rejects_stale_revision_and_vault_id_swap() {
        let (mut h, _) = test_header_and_keys(b"passphrase");
        h.revision = 5;
        let anchor = RollbackAnchor::for_v3_header(&h);
        let encoded = anchor.encode();
        assert!(encoded.starts_with("v3:5:"));
        assert_eq!(RollbackAnchor::parse(&encoded), Some(anchor.clone()));
        assert_eq!(RollbackAnchor::parse("v1:1:5:00"), None);

        assert!(check_unlock_against_anchor(Some(&anchor), &h).is_ok());
        let mut newer = h.clone();
        newer.revision = 6;
        assert!(check_unlock_against_anchor(Some(&anchor), &newer).is_ok());

        let mut older = h.clone();
        older.revision = 4;
        assert!(matches!(
            check_unlock_against_anchor(Some(&anchor), &older),
            Err(Error::Corrupt(_))
        ));

        let mut swapped_id = h.clone();
        swapped_id.vault_id[0] ^= 0xFF;
        swapped_id.revision = 10;
        assert!(matches!(
            check_unlock_against_anchor(Some(&anchor), &swapped_id),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn opaque_keys_and_per_record_aads_isolate_domains_and_revisions() {
        let (_, keys) = test_header_and_keys(b"passphrase");
        let peer = [0x11u8; 32];
        let id = [0x22u8; 16];
        let all_keys = [
            opaque_deferred_key(&keys.idb_mac_key),
            opaque_history_key(&keys.idb_mac_key, &peer, 0),
            opaque_file_key(&keys.idb_mac_key, &peer, 0),
            opaque_outbox_key(&keys.idb_mac_key, &peer, 0),
            opaque_upload_key(&keys.idb_mac_key, &peer, &id),
            opaque_chunk_key(&keys.idb_mac_key, &peer, &id, 0),
        ];
        for k in &all_keys {
            assert_eq!(k.len(), 64);
            assert!(k.bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(!k.contains('/'));
            assert!(!k.contains(&hex(&peer)));
        }
        let unique: std::collections::HashSet<&String> = all_keys.iter().collect();
        assert_eq!(unique.len(), all_keys.len());

        // Revision-bound outbox and upload AADs detect rollback.
        let sealed_out =
            try_seal_bytes(&keys.record_key, &outbox_aad(&peer, 7, 9, 5), b"msg-v5").unwrap();
        assert!(open_bytes(&keys.record_key, &outbox_aad(&peer, 7, 9, 5), &sealed_out).is_some());
        assert!(open_bytes(&keys.record_key, &outbox_aad(&peer, 7, 9, 6), &sealed_out).is_none());
        assert!(open_bytes(&keys.record_key, &outbox_aad(&peer, 7, 10, 5), &sealed_out).is_none());

        // History and file AADs bind conversation_gen so deleted-chat ciphertexts cannot splice
        // into a future chat with the same peer.
        let sealed_hist =
            try_seal_bytes(&keys.record_key, &history_aad(&peer, 0, 9, 0), b"old-msg").unwrap();
        assert!(open_bytes(&keys.record_key, &history_aad(&peer, 0, 9, 0), &sealed_hist).is_some());
        assert!(open_bytes(&keys.record_key, &history_aad(&peer, 0, 9, 1), &sealed_hist).is_none());
        let sealed_file =
            try_seal_bytes(&keys.record_key, &file_aad(&peer, 0, 9, 0), b"old-file").unwrap();
        assert!(open_bytes(&keys.record_key, &file_aad(&peer, 0, 9, 0), &sealed_file).is_some());
        assert!(open_bytes(&keys.record_key, &file_aad(&peer, 0, 9, 1), &sealed_file).is_none());

        // Content digest is domain-separated and detects tampering.
        let d1 = content_kind_digest(b"hello");
        let d2 = content_kind_digest(b"tampered");
        assert_eq!(d1.len(), 32);
        assert_ne!(d1, d2);

        let sealed_up =
            try_seal_bytes(&keys.record_key, &upload_aad(&peer, &id, 9, 5), b"up-v5").unwrap();
        assert!(open_bytes(&keys.record_key, &upload_aad(&peer, &id, 9, 5), &sealed_up).is_some());
        assert!(open_bytes(&keys.record_key, &upload_aad(&peer, &id, 9, 6), &sealed_up).is_none());

        // Strict deferred digest rejects empty expected digest and mismatched records.
        let empty = DeferredRecord::default();
        let non_empty = DeferredRecord {
            entries: vec![DeferredInitial {
                initial: None,
                deferred_at: 123,
            }],
            carried_timestamps: vec![],
            envelopes: vec![],
        };
        let empty_digest = deferred_record_digest(&empty);
        assert!(verify_deferred_record_digest(&empty_digest, &empty).is_ok());
        assert!(matches!(
            verify_deferred_record_digest(&empty_digest, &non_empty),
            Err(Error::Corrupt(_))
        ));
        assert!(matches!(
            verify_deferred_record_digest(&[], &empty),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn attachment_chunks_bitmap_tracks_bits_and_counts() {
        let mut chunks = AttachmentChunks {
            id: vec![1; 16],
            chunks_bitmap: Vec::new(),
        };
        assert_eq!(chunks.count(), 0);
        assert!(!chunks.has_bit(0));
        assert!(chunks.set_bit(0).unwrap());
        assert!(!chunks.set_bit(0).unwrap()); // idempotent
        assert!(chunks.set_bit(7).unwrap());
        assert!(chunks.set_bit(8).unwrap());
        assert!(chunks.set_bit(100).unwrap());
        assert_eq!(chunks.count(), 4);
        assert!(chunks.has_bit(100));
        assert!(!chunks.has_bit(99));
        let indices: Vec<u32> = chunks.indices().collect();
        assert_eq!(indices, vec![0, 7, 8, 100]);
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
    fn allocate_peer_conversation_gen_uses_monotonic_counter_without_tombstones() {
        let peer_a = [0x11; 32];
        let peer_b = [0x22; 32];
        let mut next_gen = 1u64;
        // Unknown peer allocates from monotonic vault-wide counter without needing peer_storage tombstones.
        assert_eq!(
            allocate_peer_conversation_gen(&mut next_gen, &[], &peer_a),
            1
        );
        assert_eq!(next_gen, 2);
        // Existing contact with explicit conversation_gen preserves it and advances next_gen past it.
        let contacts = vec![ContactState {
            peer: peer_b.to_vec(),
            conversation_gen: 7,
            ..ContactState::default()
        }];
        assert_eq!(
            allocate_peer_conversation_gen(&mut next_gen, &contacts, &peer_b),
            7
        );
        assert_eq!(next_gen, 8);
        // Recreating previously forgotten peer_a receives fresh gen 8 (never collides with gen 1).
        assert_eq!(
            allocate_peer_conversation_gen(&mut next_gen, &contacts, &peer_a),
            8
        );
        assert_eq!(next_gen, 9);
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::*;

    use super::*;
    use crate::content::File;

    struct LockReleaseGuard {
        previous: bool,
    }

    impl LockReleaseGuard {
        fn released() -> Self {
            let previous = crate::glue::set_lock_released_for_test(true);
            Self { previous }
        }
    }

    impl Drop for LockReleaseGuard {
        fn drop(&mut self) {
            crate::glue::set_lock_released_for_test(self.previous);
        }
    }

    async fn ensure_real_web_lock() {
        if crate::glue::owns_lock() {
            return;
        }
        let status = crate::glue::take_lock("e2ee-chat").await;
        assert_eq!(
            status,
            crate::glue::LockStatus::Acquired,
            "expected real browser Web Lock acquisition"
        );
        assert!(crate::glue::owns_lock());
    }

    fn raw_local_storage_anchor() -> Option<String> {
        web_sys::window()
            .expect("browser window")
            .local_storage()
            .expect("localStorage access")
            .expect("localStorage available")
            .get_item(ROLLBACK_ANCHOR_KEY)
            .expect("localStorage get_item")
    }

    fn set_raw_local_storage(key: &str, value: &str) {
        web_sys::window()
            .expect("browser window")
            .local_storage()
            .expect("localStorage access")
            .expect("localStorage available")
            .set_item(key, value)
            .expect("localStorage set_item");
    }

    fn get_raw_local_storage(key: &str) -> Option<String> {
        web_sys::window()
            .expect("browser window")
            .local_storage()
            .expect("localStorage access")
            .expect("localStorage available")
            .get_item(key)
            .expect("localStorage get_item")
    }

    async fn raw_idb_put(records: &[(&str, &[u8])]) {
        let db = open().await.expect("open IndexedDB");
        let tx = db
            .transaction(&[STORE], TransactionMode::ReadWrite)
            .expect("open RW tx");
        let store = tx.object_store(STORE).expect("open records store");
        for (name, data) in records {
            store
                .put(&bytes(data), Some(&(*name).into()))
                .expect("put raw record");
        }
        commit(tx).await.expect("commit raw IDB writes");
    }

    async fn raw_idb_keys() -> Vec<String> {
        let db = open().await.expect("open IndexedDB");
        let tx = db
            .transaction(&[STORE], TransactionMode::ReadOnly)
            .expect("open RO tx");
        let store = tx.object_store(STORE).expect("open records store");
        store
            .get_all_keys(None, None)
            .expect("get_all_keys request")
            .await
            .expect("get_all_keys await")
            .into_iter()
            .filter_map(|k| k.as_string())
            .collect()
    }

    async fn clean_browser_vault() {
        ensure_real_web_lock().await;
        Vault::destroy().await.expect("Vault::destroy");
        assert_eq!(
            Vault::inspect().await.expect("Vault::inspect"),
            VaultPresence::None
        );
        assert!(raw_local_storage_anchor().is_none());
        assert!(get_raw_local_storage(LEGACY_ROLLBACK_ANCHOR_KEY).is_none());
        assert!(raw_idb_keys().await.is_empty());
    }

    #[wasm_bindgen_test]
    async fn vault_v3_create_save_opaque_keys_chunks_uploads_forget_and_destroy() {
        let _kdf = crate::kdf_worker::install_test_kdf_worker();
        let cancel = KdfCancelToken::new();
        clean_browser_vault().await;

        // Real browser Web Lock exclusivity: a second acquisition attempt while held fails closed.
        let contended = crate::glue::take_lock("e2ee-chat").await;
        assert_eq!(contended, crate::glue::LockStatus::HeldElsewhere);
        assert!(crate::glue::owns_lock());

        // Simulating `pagehide` lock release must fail closed on all vault mutations/unlocks.
        {
            let _released = LockReleaseGuard::released();
            assert!(!crate::glue::owns_lock());
            assert!(matches!(
                Vault::create(b"locked-out", &AppState::default(), &cancel).await,
                Err(Error::Storage(_))
            ));
            assert!(matches!(
                Vault::unlock(b"locked-out", &cancel).await,
                Err(Error::Storage(_))
            ));
            assert!(matches!(Vault::destroy().await, Err(Error::Storage(_))));
        }
        assert!(crate::glue::owns_lock());

        let initial_state = AppState {
            name: "Alice".to_string(),
            server: "https://chat.example.com".to_string(),
            ..AppState::default()
        };
        let vault = Vault::create(b"correct-horse-battery", &initial_state, &cancel)
            .await
            .expect("Vault::create");
        assert_eq!(
            Vault::inspect().await.expect("Vault::inspect"),
            VaultPresence::Compatible
        );

        let created_vault_id_hex = hex(&vault.header.borrow().vault_id);
        let anchor_after_create = RollbackAnchor::parse(
            &raw_local_storage_anchor().expect("v3 rollback anchor written on create"),
        )
        .expect("parse v3 rollback anchor");
        assert_eq!(
            anchor_after_create,
            RollbackAnchor {
                max_revision: 1,
                vault_id_hex: created_vault_id_hex.clone(),
            }
        );

        // Save state, deferred sidecar (including DeferredEnvelope), history (text + file), outbox.
        let peer: PublicKey = [0x42u8; 32];
        let peer_hex = hex(&peer);
        let updated_state = AppState {
            name: "Alice Updated".to_string(),
            server: "https://relay.example.com".to_string(),
            pending_inbox_acks: vec![7, 11],
            pending_revokes: vec![PendingRevoke {
                peer_slot_id: vec![0x99; 32],
                min_grant_version: 5,
            }],
            ..initial_state
        };
        let deferred = DeferredRecord {
            entries: vec![],
            carried_timestamps: vec![CarriedDeferredTimestamp {
                signed_prekey: vec![0x33; 32],
                deferred_at: 1_700_000_000_555,
            }],
            envelopes: vec![DeferredEnvelope {
                peer: peer.to_vec(),
                sequence: 42,
                message: None,
                initial_message: None,
                deferred_at: 1_700_000_000_600,
                pq_isolated: false,
            }],
        };
        let text_entry = HistoryEntry {
            outgoing: true,
            at: 1_700_000_001_000,
            content: Some(Content {
                clock: 1,
                kind: Some(Kind::Text("hello real indexeddb v3".to_string())),
                ..Content::default()
            }),
            delivery: Delivery::Pending.into(),
            place: 1,
            ..HistoryEntry::default()
        };
        let file_bytes = b"encrypted file record payload".to_vec();
        let file_entry = HistoryEntry {
            outgoing: false,
            at: 1_700_000_002_000,
            content: Some(Content {
                clock: 2,
                kind: Some(Kind::File(File {
                    name: "note.txt".to_string(),
                    mime: "text/plain".to_string(),
                    data: file_bytes.clone(),
                })),
                ..Content::default()
            }),
            delivery: Delivery::Received.into(),
            place: 2,
            ..HistoryEntry::default()
        };
        let entries = [(peer, 0u64, text_entry), (peer, 1u64, file_entry)];
        let outgoing_rec = OutgoingRecord {
            message: None,
            content: b"pending outbox bytes".to_vec(),
            write_token: vec![0xAB; 32],
            carried_initial: vec![],
            session_id: vec![0xCD; 16],
        };
        let outgoing = [(peer, 0u64, Some(outgoing_rec.clone()))];
        vault
            .save(&updated_state, &deferred, &entries, &outgoing)
            .await
            .expect("vault.save");

        // Save an upload and chunks (verifying chunk bitmap + short-circuit on duplicate chunk).
        let upload_id = [0x77u8; 16];
        let upload = PendingUpload {
            id: upload_id.to_vec(),
            token: vec![1; 16],
            key: vec![2; 32],
            name: "clip.bin".into(),
            mime: "application/octet-stream".into(),
            size: 32,
            uploaded: 1,
            encrypted: 1,
            prefix_hash: vec![3; 32],
            announced: true,
            history_index: 0,
            expires: 0,
            upload_state: UPLOAD_STATE_ANNOUNCED,
            sealed_chunk_hash: vec![],
        };
        vault
            .save_upload(&peer, &upload)
            .await
            .expect("vault.save_upload");
        let rev_before_chunk = vault.header.borrow().revision;
        vault
            .put_chunk(&peer, &upload_id, 0, b"chunk-0-ciphertext")
            .await
            .expect("put_chunk 0");
        assert_eq!(vault.header.borrow().revision, rev_before_chunk + 1);
        assert_eq!(vault.chunks_kept(&peer, &upload_id).await.unwrap(), 1);
        // Re-writing the same chunk index short-circuits STATE rewrite (revision unchanged!).
        vault
            .put_chunk(&peer, &upload_id, 0, b"chunk-0-ciphertext-repaired")
            .await
            .expect("put_chunk 0 repair");
        assert_eq!(vault.header.borrow().revision, rev_before_chunk + 1);
        assert_eq!(
            vault.chunk(&peer, &upload_id, 0).await.unwrap().as_deref(),
            Some(b"chunk-0-ciphertext-repaired".as_slice())
        );

        // Verify raw IndexedDB keys contain ONLY "vault", "state", and 64-hex opaque keys!
        let keys = raw_idb_keys().await;
        assert!(keys.len() >= 8);
        for k in &keys {
            if k == HEADER || k == STATE {
                continue;
            }
            assert_eq!(k.len(), 64, "expected 64-hex opaque IDB key, got {k:?}");
            assert!(
                k.bytes().all(|b| b.is_ascii_hexdigit()),
                "non-hex IDB key {k:?}"
            );
            assert!(!k.contains(&peer_hex), "peer hex leaked in key {k:?}");
            for forbidden in [
                "history/",
                "file/",
                "outbox/",
                "upload/",
                "attachment/",
                "deferred_initials",
            ] {
                assert!(
                    !k.contains(forbidden),
                    "forbidden cleartext prefix {forbidden} in key {k:?}"
                );
            }
        }
        drop(vault);

        // Wrong passphrase fails cleanly without disturbing stored records.
        assert!(matches!(
            Vault::unlock(b"wrong-passphrase", &cancel).await,
            Err(Error::WrongPassphrase)
        ));

        // Reopen with correct passphrase and verify every record round-trips.
        let (reopened, restored_state, restored_deferred) =
            Vault::unlock(b"correct-horse-battery", &cancel)
                .await
                .expect("Vault::unlock");
        assert_eq!(restored_state.name, "Alice Updated");
        assert_eq!(restored_state.pending_revokes.len(), 1);
        assert_ne!(restored_state.record_epoch, 0);
        assert_eq!(restored_deferred, deferred);
        let history = reopened.history(&peer, 2, 10).await.unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(reopened.file(&peer, 1).await.unwrap(), file_bytes);
        assert_eq!(reopened.outgoing(&peer, 0).await.unwrap(), outgoing_rec);
        assert_eq!(
            reopened
                .upload(&peer, &upload_id)
                .await
                .unwrap()
                .unwrap()
                .name,
            "clip.bin"
        );
        assert_eq!(reopened.uploads(Some(&peer)).await.unwrap().len(), 1);
        assert_eq!(reopened.chunks_kept(&peer, &upload_id).await.unwrap(), 1);

        // Capture raw ciphertext of history[0] and file[1] before forget to verify splicing into
        // a recreated conversation fails authentication due to bumped `conversation_gen`.
        let old_hist_key = opaque_history_key(&reopened.keys.idb_mac_key, &peer, 0);
        let old_file_key = opaque_file_key(&reopened.keys.idb_mac_key, &peer, 1);
        let old_hist_raw = get(&reopened.database, &old_hist_key)
            .await
            .unwrap()
            .expect("old history[0] raw bytes");
        let old_file_raw = get(&reopened.database, &old_file_key)
            .await
            .unwrap()
            .expect("old file[1] raw bytes");

        // Forget peer: leaves ZERO orphan keys for peer in IndexedDB and bumps conversation_gen!
        let empty_deferred = DeferredRecord::default();
        reopened
            .forget(&restored_state, &empty_deferred, &peer, &[], &[])
            .await
            .expect("vault.forget");
        let keys_after_forget = raw_idb_keys().await;
        assert_eq!(
            keys_after_forget.len(),
            2,
            "expected only vault & state after forget, got {keys_after_forget:?}"
        );
        assert!(keys_after_forget.contains(&HEADER.to_string()));
        assert!(keys_after_forget.contains(&STATE.to_string()));
        assert!(
            !reopened.peer_storage.borrow().contains_key(&peer),
            "Vault::forget must leave zero residual peer_storage tombstone for forgotten peer"
        );
        assert!(
            reopened.next_conversation_gen.get() >= 2,
            "Vault::forget must advance vault-wide next_conversation_gen"
        );
        assert_eq!(reopened.chunks_kept(&peer, &upload_id).await.unwrap(), 0);
        assert!(reopened.uploads(None).await.unwrap().is_empty());

        // Splicing deleted history[0] / file[1] ciphertexts back under the same opaque keys MUST
        // fail decryption after `forget` bumped `conversation_gen`.
        raw_idb_put(&[
            (&old_hist_key, &old_hist_raw),
            (&old_file_key, &old_file_raw),
        ])
        .await;
        assert!(matches!(
            reopened.entry(&peer, 0).await,
            Err(Error::Corrupt(_))
        ));
        assert!(matches!(
            reopened.file(&peer, 1).await,
            Err(Error::Corrupt(_))
        ));

        // Bumping lock_generation (as pagehide does before releasing Web Lock) aborts reads & writes
        // on an already-opened Vault handle even while `owns_lock()` is still true!
        crate::glue::bump_lock_generation_for_test();
        assert!(matches!(
            reopened
                .save(&restored_state, &empty_deferred, &[], &[])
                .await,
            Err(Error::Storage(_))
        ));
        assert!(matches!(
            reopened.entry(&peer, 0).await,
            Err(Error::Storage(_))
        ));

        // Destroy clears BOTH v1 and v3 rollback anchors.
        set_raw_local_storage(LEGACY_ROLLBACK_ANCHOR_KEY, "v1:1:1:00");
        drop(reopened);
        clean_browser_vault().await;
    }

    #[wasm_bindgen_test]
    async fn vault_v3_rejects_incompatible_version_pre_kdf_and_rollback_anchor() {
        let _kdf = crate::kdf_worker::install_test_kdf_worker();
        let cancel = KdfCancelToken::new();
        clean_browser_vault().await;

        // Legacy v2 header with absurd Argon2 memory fails pre-KDF with IncompatibleVersion(2).
        let legacy_v2 = VaultHeader {
            salt: vec![0x11; 16],
            memory: u32::MAX,
            iterations: ARGON2_DEFAULT_ITERATIONS,
            parallelism: ARGON2_DEFAULT_PARALLELISM,
            version: 2,
            revision: 1,
            vault_id: vec![],
            wrapped_root_key: vec![],
        };
        raw_idb_put(&[
            (HEADER, &legacy_v2.encode_to_vec()),
            (STATE, b"unauthenticated-placeholder"),
        ])
        .await;
        assert_eq!(
            Vault::inspect().await.expect("inspect v2"),
            VaultPresence::IncompatibleVersion(2)
        );
        assert!(matches!(
            Vault::unlock(b"any", &cancel).await,
            Err(Error::IncompatibleVersion(2))
        ));

        // Create a real v3 vault, advance revision to 2, then tamper anchor to test rejection.
        clean_browser_vault().await;
        let vault = Vault::create(b"passphrase-rollback", &AppState::default(), &cancel)
            .await
            .expect("create");
        let vault_id_hex = hex(&vault.header.borrow().vault_id);
        drop(vault);

        set_raw_local_storage(ROLLBACK_ANCHOR_KEY, &format!("v3:9:{vault_id_hex}"));
        assert!(matches!(
            Vault::unlock(b"passphrase-rollback", &cancel).await,
            Err(Error::Corrupt(msg)) if msg.contains("behind anchor 9")
        ));

        set_raw_local_storage(ROLLBACK_ANCHOR_KEY, &format!("v3:1:{}", "ff".repeat(16)));
        assert!(matches!(
            Vault::unlock(b"passphrase-rollback", &cancel).await,
            Err(Error::Corrupt(msg)) if msg.contains("vault_id does not match")
        ));

        // Partial vault with missing HEADER + surviving STATE/anchor must report Corrupt (NOT None)
        // and Vault::create must refuse to overwrite without explicit Vault::destroy().
        let db = open().await.expect("open idb");
        let tx = db
            .transaction(&[STORE], TransactionMode::ReadWrite)
            .expect("rw tx");
        tx.object_store(STORE)
            .expect("store")
            .delete(JsValue::from_str(HEADER))
            .expect("delete header");
        commit(tx).await.expect("commit header delete");
        db.close();
        assert!(matches!(Vault::inspect().await, Err(Error::Corrupt(_))));
        assert!(matches!(
            Vault::create(b"new-pass", &AppState::default(), &cancel).await,
            Err(Error::Corrupt(_))
        ));

        clean_browser_vault().await;
    }
}
