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
#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(feature = "memory")]
pub use memory::MemoryStore;

/// An X25519 or XEdDSA public key.
pub type PublicKey = [u8; xeddsa::PUBLIC_KEY_LENGTH];
/// An XEdDSA signature.
pub type Signature = [u8; xeddsa::SIGNATURE_LENGTH];

/// A published prekey bundle, without its one-time prekeys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// The owner's identity key.
    pub identity_key: PublicKey,
    /// The current signed prekey.
    pub signed_prekey: PublicKey,
    /// The identity key's signature of `signed_prekey`.
    pub signed_prekey_signature: Signature,
    /// When it was published, in milliseconds since the Unix epoch.
    pub timestamp: u64,
}

/// An initial message waiting in its recipient's inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredInitialMessage {
    /// The sender's identity key.
    pub sender: PublicKey,
    /// The recipient's identity key.
    pub recipient: PublicKey,
    /// The sender's ephemeral key.
    pub ephemeral_key: PublicKey,
    /// The recipient's signed prekey it uses.
    pub signed_prekey: PublicKey,
    /// The recipient's one-time prekey it uses, if any.
    pub one_time_prekey: Option<PublicKey>,
    /// The encrypted header of the session's first message, which comes with it.
    pub header: Bytes,
    /// The encrypted content of the session's first message.
    pub content: Bytes,
}

/// The random ID of an attachment, which whoever may download it knows.
pub type AttachmentId = [u8; 16];

/// An attachment: a file uploaded in encrypted chunks, which its recipients download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAttachment {
    /// Its random ID.
    pub id: AttachmentId,
    /// The identity key that started the upload.
    pub uploader: PublicKey,
    /// Number of chunks.
    pub chunks: u32,
    /// SHA-256 of the upload token, which only the uploader knows and which writing a chunk
    /// takes.
    pub token_hash: [u8; 32],
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

/// A message in the queue from `sender` to `recipient`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    /// The sender's identity key.
    pub sender: PublicKey,
    /// The recipient's identity key.
    pub recipient: PublicKey,
    /// Position in the queue, starting at 1.
    pub sequence: u64,
    /// The encrypted header.
    pub header: Bytes,
    /// The encrypted content; none if it expired before it was read, e.g. as the storage's
    /// lifecycle rules deleted it.
    pub content: Option<Bytes>,
    /// The initial message, encoded, of the session the message is on, which its sender sends
    /// with it while the recipient has not answered that session.
    pub initial_message: Option<Bytes>,
}

/// Storage for the handshake server. Every method is atomic.
#[trait_variant::make(HandshakeStore: Send)]
pub trait LocalHandshakeStore {
    /// Store `bundle` and replace its owner's one-time prekeys with `one_time_prekeys`, if
    /// `bundle.timestamp` is greater than the stored bundle's. Returns whether it was stored.
    async fn publish(&self, bundle: Bundle, one_time_prekeys: Vec<PublicKey>) -> Result<bool>;
    /// The bundle of `identity_key`, with one of its one-time prekeys, which is removed.
    async fn take_bundle(
        &self,
        identity_key: &PublicKey,
    ) -> Result<Option<(Bundle, Option<PublicKey>)>>;
    /// Add `initial_message` to its recipient's inbox, unless the inbox already holds `limit`.
    /// Returns whether it was added.
    async fn add_initial_message(
        &self,
        initial_message: StoredInitialMessage,
        limit: usize,
    ) -> Result<bool>;
    /// Take every initial message to `recipient`, if `timestamp` is greater than the previous
    /// take's. Returns `None` otherwise.
    async fn take_initial_messages(
        &self,
        recipient: &PublicKey,
        timestamp: u64,
    ) -> Result<Option<Vec<StoredInitialMessage>>>;
}

/// Storage for the mailbox server. Every method is atomic.
#[trait_variant::make(MailboxStore: Send)]
pub trait LocalMailboxStore {
    /// Append a message to the queue from `sender` to `recipient`, with the initial message of
    /// its session if any, and SHA-256 of its delivery token if any; returns its sequence number,
    /// which goes on from the queue's last, even once its messages are deleted.
    async fn append(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        delivery_hash: Option<[u8; 32]>,
    ) -> Result<u64>;
    /// Delete the messages of the queue from `sender` to `recipient` whose delivery tokens'
    /// SHA-256 are among `hashes`, as their recipient has them.
    async fn delete_delivered(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        hashes: &[[u8; 32]],
    ) -> Result<()>;
    /// The messages of the queue from `sender` to `recipient` after sequence number `after`,
    /// in order, at most `limit`.
    async fn read(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
    ) -> Result<Vec<StoredMessage>>;
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
    /// Any other error; see its [`source`](std::error::Error::source).
    #[error("storage error")]
    Other,
}

/// Result type with [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
