#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

use std::error::Error as StdError;

pub use bytes::Bytes;

#[cfg(feature = "memory")]
pub mod memory;
pub mod pq;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(feature = "memory")]
pub use memory::MemoryStore;
pub use pq::*;

/// JavaScript's largest exact integer (`2^53 - 1`), which SQLite-backed stores (e.g. Cloudflare
/// Durable Objects) enforce on timestamps, sequences, and IDs to avoid precision loss or clamping.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
/// Maximum messages queued per peer slot in a recipient's mailbox.
pub const MAX_QUEUE_MESSAGES: usize = 2000;
/// Maximum total bytes (headers, contents, and carried initial messages) per peer slot in a
/// recipient's mailbox: 64 MiB.
pub const MAX_QUEUE_BYTES: u64 = 64 << 20;
/// Maximum total queued bytes across all peers for a single recipient: 256 MiB.
pub const MAX_RECIPIENT_BYTES: u64 = 256 << 20;
/// Maximum distinct authorized peers (with at least one live write token) per recipient.
pub const MAX_AUTHORIZED_PEERS: usize = 4096;
/// Maximum concurrent write-token grants per peer slot (preserving the pinned active token).
pub const MAX_GRANTS_PER_PEER: usize = 4;

/// An X25519 or XEdDSA public key.
pub type PublicKey = [u8; 32];
/// An XEdDSA signature.
pub type Signature = [u8; 64];
/// Opaque 32-byte client-derived per-peer slot identifier (keeps relay blind to `peer_pk`).
pub type PeerSlotId = [u8; 32];
/// SHA-256 of a 32-byte deniable write-capability token.
pub type WriteTokenHash = [u8; 32];

// Check the storage wire widths against the crypto crate without requiring a random source
// in a standalone storage backend.
#[cfg(all(test, not(all(target_family = "wasm", target_os = "unknown"))))]
const _: (PublicKey, Signature) = (
    [0; xeddsa::PUBLIC_KEY_LENGTH],
    [0; xeddsa::SIGNATURE_LENGTH],
);

/// Serde adapter for `Option<[u8; 64]>` backed by `serde_big_array::BigArray`.
#[cfg(feature = "serde")]
pub(crate) mod opt_signature {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_big_array::BigArray;

    use crate::Signature;

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    struct Sig(#[serde(with = "BigArray")] Signature);

    pub fn serialize<S: Serializer>(
        value: &Option<Signature>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.map(Sig).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Signature>, D::Error> {
        Option::<Sig>::deserialize(deserializer).map(|opt| opt.map(|Sig(sig)| sig))
    }
}

/// The random ID of an attachment, which whoever may download it knows.
pub type AttachmentId = [u8; 16];

/// An attachment: a file uploaded in encrypted chunks, which its recipients download.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StoredAttachment {
    /// Its random ID.
    pub id: AttachmentId,
    /// Number of chunks.
    pub chunks: u32,
    /// SHA-256 of the upload token, which only the uploader knows and which writing a chunk
    /// takes.
    pub token_hash: [u8; 32],
    /// SHA-256 of the delete token, which the peers derive from the attachment's key.
    pub delete_hash: [u8; 32],
    /// The chunks put so far, chunk `i` as bit `i`, for the first [`UPLOADED_NOTED`]. One noted
    /// here that is not stored was put, and expired since, e.g. as the storage's lifecycle rules
    /// deleted it.
    pub uploaded: u64,
}

/// How many of an attachment's chunks [`StoredAttachment::uploaded`] notes: as many bits as a
/// JavaScript number holds exactly, as some stores take integers as those.
pub const UPLOADED_NOTED: u32 = 53;

impl StoredAttachment {
    /// Whether chunk `index` was put, as far as [`uploaded`](Self::uploaded) notes.
    pub fn was_uploaded(&self, index: u32) -> bool {
        self.uploaded & uploaded_bit(index) != 0
    }

    /// Whether every chunk (`0..self.chunks`) has been noted in [`uploaded`](Self::uploaded).
    ///
    /// Returns `false` when `chunks == 0` or `chunks > UPLOADED_NOTED` (where the bitmask cannot
    /// prove completeness for chunks at or above [`UPLOADED_NOTED`]).
    pub fn is_complete(&self) -> bool {
        if self.chunks == 0 || self.chunks > UPLOADED_NOTED {
            return false;
        }
        let all_chunks_mask = (1u64 << self.chunks) - 1;
        (self.uploaded & all_chunks_mask) == all_chunks_mask
    }
}

/// The bit of chunk `index` in [`StoredAttachment::uploaded`]; none from chunk
/// [`UPLOADED_NOTED`] on.
pub fn uploaded_bit(index: u32) -> u64 {
    if index < UPLOADED_NOTED {
        1 << index
    } else {
        0
    }
}

/// A message in a recipient's unified sealed-sender-lite mailbox queue.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StoredMessage {
    /// Position in the recipient's unified queue, starting at 1.
    pub sequence: u64,
    /// SHA-256 of the write token that authorized this message (for O(1) client peer dispatch).
    pub token_hash: WriteTokenHash,
    /// The encrypted header.
    pub header: Bytes,
    /// The encrypted content (always stored inline under the 64 KiB envelope cap).
    pub content: Bytes,
    /// The initial message, encoded, of the session the message is on, which its sender sends
    /// with it while the recipient has not answered that session.
    pub initial_message: Option<Bytes>,
}

/// A bounded page of messages read from a recipient's unified mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MailboxPage {
    /// Messages in ascending unified sequence order.
    pub messages: Vec<StoredMessage>,
    /// Whether additional messages remain after the last returned message.
    pub has_more: bool,
}

/// Storage for the attachment server. Every method is atomic.
#[trait_variant::make(AttachmentStore: Send)]
pub trait LocalAttachmentStore {
    /// Add `attachment`, with no chunks yet, none uploaded, unless its ID is taken. Returns
    /// whether it was added.
    async fn add_attachment(&self, attachment: StoredAttachment) -> Result<bool>;
    /// The attachment `id`, if any.
    async fn attachment(&self, id: &AttachmentId) -> Result<Option<StoredAttachment>>;
    /// Store chunk `index` of the attachment `id`, which was added, unless it is stored already,
    /// as a chunk is uploaded once, and note it in the attachment's
    /// [`uploaded`](StoredAttachment::uploaded).
    async fn put_chunk(&self, id: &AttachmentId, index: u32, data: Bytes) -> Result<()>;
    /// Chunk `index` of the attachment `id`, if stored.
    async fn chunk(&self, id: &AttachmentId, index: u32) -> Result<Option<Bytes>>;
    /// Delete the attachment `id` and its chunks, if any.
    async fn delete_attachment(&self, id: &AttachmentId) -> Result<()>;
    /// Atomically delete the attachment `id` and its chunks only if it is still incomplete
    /// (`!StoredAttachment::is_complete`).
    ///
    /// Returns `true` if a stored incomplete attachment was deleted, and `false` if the
    /// attachment was absent or already complete and therefore preserved.
    async fn delete_attachment_if_incomplete(&self, id: &AttachmentId) -> Result<bool>;
}

/// The error type of this crate.
#[derive(Debug, thiserror::Error)]
#[error("{kind}")]
pub struct Error {
    kind: ErrorKind,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl Error {
    /// New an error of `kind`, caused by `source`.
    pub fn new(kind: ErrorKind, source: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    /// The kind of this error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self { kind, source: None }
    }
}

/// The kinds of [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The backend cannot be reached.
    #[error("storage unavailable")]
    Unavailable,
    /// Stored data is malformed.
    #[error("corrupt stored data")]
    Corrupt,
    /// A per-peer, per-recipient, or per-inbox quota was exceeded.
    #[error("storage limit exceeded")]
    LimitExceeded,
    /// A recipient's mailbox backlog quota is temporarily full; callers should retry later.
    #[error("mailbox queue full")]
    MailboxFull,
    /// An argument violates storage bounds (e.g. an integer exceeding [`MAX_SAFE_INTEGER`],
    /// an ACK sequence beyond the high-water mark, a cross-peer `token_hash` collision, or a
    /// mismatched idempotent initial payload).
    #[error("invalid storage argument")]
    InvalidArgument,
    /// The referenced record (e.g. an identity or attachment) does not exist.
    #[error("not found")]
    NotFound,
    /// The supplied write token hash is unknown or has been revoked.
    #[error("write token rejected")]
    WriteTokenRejected,
    /// A write-token registration's `grant_version` does not exceed the peer's revoked version
    /// floor.
    #[error("stale grant version")]
    StaleVersion,
    /// A signed storage operation's timestamp fell outside the freshness window at commit time.
    #[error("stale timestamp")]
    StaleTimestamp,
    /// Any other error; see its [`source`](std::error::Error::source).
    #[error("storage error")]
    Other,
}

/// Result type with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    fn roundtrip<T>(value: &T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + core::fmt::Debug,
    {
        let bin = postcard::to_allocvec(value).expect("postcard serialize");
        let decoded_bin: T = postcard::from_bytes(&bin).expect("postcard deserialize");
        assert_eq!(&decoded_bin, value);

        let json = serde_json::to_string(value).expect("json serialize");
        let decoded_json: T = serde_json::from_str(&json).expect("json deserialize");
        assert_eq!(&decoded_json, value);
    }

    #[test]
    fn all_storage_records_roundtrip_postcard_and_json() {
        let attachment = StoredAttachment {
            id: [0x11; 16],
            chunks: 3,
            token_hash: [0x22; 32],
            delete_hash: [0x33; 32],
            uploaded: 0b101,
        };
        roundtrip(&attachment);

        let msg = StoredMessage {
            sequence: 7,
            token_hash: [0x44; 32],
            header: Bytes::from_static(b"hdr"),
            content: Bytes::from_static(b"body"),
            initial_message: Some(Bytes::from_static(b"init")),
        };
        roundtrip(&msg);
        roundtrip(&MailboxPage {
            messages: vec![msg],
            has_more: true,
        });

        let commitment = PqLastResortCommitment {
            suite: 1,
            prekey_id: [0x55; 32],
        };
        roundtrip(&commitment);

        let manifest = StoredCapabilityManifest {
            audience: "relay.example".to_string(),
            identity_key: [0x01; 32],
            manifest_seq: 2,
            generation: 1,
            issued_at: 1_000,
            expires_at: 2_000,
            pq_enabled: true,
            strict_pq: false,
            pq_ratchet_supported: true,
            offered_suites: vec![1, 2],
            signed_prekey: [0x02; 32],
            pq_last_resort: vec![commitment],
            signature: [0xAB; 64],
        };
        roundtrip(&manifest);

        let prekey = StoredPqPrekey {
            suite: 1,
            id: [0x66; 32],
            encapsulation_key: Bytes::from(vec![0x77; 16]),
            signature: [0xCD; 64],
        };
        roundtrip(&prekey);

        for sig in [Some([0xEF; 64]), None] {
            roundtrip(&PublishV2Record {
                manifest: manifest.clone(),
                signed_prekey_signature: sig,
                one_time_prekeys: vec![[0x03; 32]],
                pq_last_resort: vec![prekey.clone()],
                pq_one_time_prekeys: vec![prekey.clone()],
                timestamp: 1_234,
            });
            let claimed = ClaimedPqBundle {
                identity_key: [0x01; 32],
                manifest: Some(manifest.clone()),
                signed_prekey: [0x02; 32],
                signed_prekey_signature: sig,
                one_time_prekey: Some([0x04; 32]),
                pq_last_resort: Some(prekey.clone()),
                pq_one_time_prekey: None,
            };
            roundtrip(&claimed);
            roundtrip(&ClaimOutcome::Claimed(Box::new(claimed)));
        }
        roundtrip(&PublishV2Status::Stored);
        roundtrip(&PublishV2Status::StaleSequence);
        roundtrip(&PublishV2Status::DuplicatePrekey);
        roundtrip(&ClaimOutcome::NotFound);
        roundtrip(&ClaimOutcome::PqDisabledForPqManifest);

        roundtrip(&RefillPrekeysRecord {
            identity_key: [0x01; 32],
            generation: 1,
            one_time_prekeys: vec![[0x05; 32]],
            pq_one_time_prekeys: vec![prekey],
            max_one_time_prekeys: 100,
            max_pq_one_time_prekeys: 100,
            timestamp: 1_500,
        });
        roundtrip(&RefillStatus::Stored {
            classical_count: 2,
            pq_counts: vec![(1, 3), (2, 1)],
        });
        roundtrip(&RefillStatus::StaleTimestamp);

        roundtrip(&StoredInitialMessageV2 {
            id: 9,
            version: 2,
            sender: [0x10; 32],
            recipient: [0x20; 32],
            ephemeral_key: [0x30; 32],
            signed_prekey: [0x40; 32],
            one_time_prekey: Some([0x50; 32]),
            header: Bytes::from_static(b"ih"),
            content: Bytes::from_static(b"ic"),
            pq_suite: Some(2),
            pq_last_resort: true,
            pq_prekey_id: Some([0x60; 32]),
            pq_ciphertext: Some(Bytes::from_static(b"ct")),
            manifest_digest: Some([0x70; 32]),
        });

        roundtrip(&PqStorageSnapshot {
            manifest: Some(manifest),
            classical_one_time_count: 5,
            pq_last_resort_suites: vec![1, 2],
            pq_one_time_counts: vec![(1, 4)],
            pending_initial_messages: 2,
        });

        roundtrip(&RegisterWriteTokenRecord {
            recipient: [0x01; 32],
            peer_slot_id: [0x02; 32],
            token_hash: [0x03; 32],
            grant_version: 42,
            pin_active: true,
            timestamp: 1_700_000_000_000,
        });
        roundtrip(&RevokeWriteTokenRecord {
            recipient: [0x01; 32],
            peer_slot_id: [0x02; 32],
            token_hash: Some([0x03; 32]),
            min_grant_version: 42,
        });
        roundtrip(&RevokeWriteTokenRecord {
            recipient: [0x01; 32],
            peer_slot_id: [0x02; 32],
            token_hash: None,
            min_grant_version: 43,
        });
    }
}
