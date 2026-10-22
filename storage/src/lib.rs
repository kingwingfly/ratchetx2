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
pub struct Introduction {
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
    /// The encrypted content.
    pub content: Bytes,
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
    /// Add `introduction` to its recipient's inbox, unless the inbox already holds `limit`.
    /// Returns whether it was added.
    async fn add_introduction(&self, introduction: Introduction, limit: usize) -> Result<bool>;
    /// Take every introduction to `recipient`, if `timestamp` is greater than the previous
    /// take's. Returns `None` otherwise.
    async fn take_introductions(
        &self,
        recipient: &PublicKey,
        timestamp: u64,
    ) -> Result<Option<Vec<Introduction>>>;
}

/// Storage for the mailbox server. Every method is atomic.
#[trait_variant::make(MailboxStore: Send)]
pub trait LocalMailboxStore {
    /// Append a message to the queue from `sender` to `recipient`; returns its sequence number.
    async fn append(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
    ) -> Result<u64>;
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
