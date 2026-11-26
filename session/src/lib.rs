#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod attachment;
mod clock;
pub mod error;
pub mod pq;
#[cfg(feature = "prost")]
pub mod proto;
mod safety;

use core::mem;

use bon::Builder;
use bytes::Bytes;
pub use clock::{DEFAULT_MAX_TRUSTED_DRIFT_MS, ServerClock};
pub use error::{Error, ErrorKind, Result};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use party::{EncryptedMessage, Party};
pub use pq::*;
use prost::Message as _;
pub use protocol;
use protocol::{
    attachment::{LocalAttachments, StartUploadRequest},
    content::{Content, Hello, Kind as ContentKind},
    handshake::{
        self, FetchBundleRequest, PublishRequest, SendInitialMessageRequest,
        TakeInitialMessagesRequest,
    },
    mailbox::{DELIVERY_TOKEN_LENGTH, Envelope, FetchRequest, MAX_DELIVERED, PushRequest},
    notify::SubscribeRequest,
};
#[allow(deprecated)]
use protocol::{handshake::LocalHandshake, mailbox::LocalMailbox};
use ratchetx2::{DhPrivateKey, Ratchet, SharedKeys};
pub use safety::safety_number;
use sha2::{Digest, Sha256};
use x3dh::{LocalPrekeys, PrekeyBundle};
pub use x3dh::{PqSuite, PublicKey};
use xeddsa::XEdDSAPrivateKey;
#[cfg(any(feature = "prost", feature = "serde"))]
use xeddsa::XEdDSAPublicKey;
use zeroize::Zeroizing;

/// Upper bound on queued delivery tokens in session state.
const MAX_STORED_DELIVERED: usize = 4096;

/// Request at most the default mailbox fetch limit per page.
const MAX_RECEIVE_PAGE: u32 = 100;

/// Maximum number of recent locally signed `CapabilityManifest` digests retained in `ClientState`.
pub(crate) const MAX_RECENT_MANIFEST_DIGESTS: usize = 16;

/// Maximum consecutive all-expired mailbox pages fetched within one [`Session::receive`] (or v2
/// receive) call before returning control to the caller.
pub(crate) const MAX_EXPIRED_PAGES: usize = 8;

/// Maximum carried initial messages accumulated across expired envelopes or a stalled page.
pub(crate) const MAX_CARRIED_INITIALS: usize = 64;

/// Merge incoming delivery tokens into `existing`, deduplicating and retaining at most the
/// [`MAX_STORED_DELIVERED`] most recent unique tokens in chronological order.
fn merge_delivered(
    existing: &mut Vec<[u8; DELIVERY_TOKEN_LENGTH]>,
    incoming: Vec<[u8; DELIVERY_TOKEN_LENGTH]>,
) {
    if incoming.is_empty() && existing.len() <= MAX_STORED_DELIVERED {
        return;
    }
    let cap = existing
        .len()
        .saturating_add(incoming.len())
        .min(MAX_STORED_DELIVERED);
    let mut seen = std::collections::BTreeSet::new();
    let mut merged = Vec::with_capacity(cap);
    for token in incoming
        .into_iter()
        .rev()
        .chain(existing.iter().copied().rev())
    {
        if seen.insert(token) {
            merged.push(token);
            if merged.len() == MAX_STORED_DELIVERED {
                break;
            }
        }
    }
    merged.reverse();
    *existing = merged;
}

/// An initial message from a peer who wants to start a session, with the session's first
/// message; accept it with [`Client::accept`].
#[derive(Debug, Clone, PartialEq)]
pub struct InitialMessage {
    /// X3DH's part: the identity key it claims to come from, the ephemeral key, and the prekeys
    /// it uses.
    pub x3dh: x3dh::InitialMessage,
    /// The session's first message, which only the owner of that identity key can have
    /// encrypted.
    pub first_message: EncryptedMessage,
}

impl TryFrom<&handshake::InitialMessage> for InitialMessage {
    type Error = Error;

    /// Fails with [`ErrorKind::InvalidInitialMessage`] if it is malformed, or has no first
    /// message.
    fn try_from(message: &handshake::InitialMessage) -> Result<Self> {
        let malformed = || Error::from(ErrorKind::InvalidInitialMessage);
        Ok(Self {
            x3dh: x3dh::InitialMessage::try_from(message).map_err(|_| malformed())?,
            first_message: message.first_message.clone().ok_or_else(malformed)?,
        })
    }
}

/// The wire versions share sequence and ciphertext semantics, with different carried initials.
trait MailboxEnvelope {
    type Initial: PartialEq;
    fn sequence(&self) -> u64;
    fn into_parts(self) -> (Option<EncryptedMessage>, Option<Self::Initial>);
}

impl MailboxEnvelope for Envelope {
    type Initial = InitialMessage;

    fn sequence(&self) -> u64 {
        self.sequence
    }

    fn into_parts(self) -> (Option<EncryptedMessage>, Option<InitialMessage>) {
        (
            self.message,
            self.initial_message
                .as_ref()
                .and_then(|im| InitialMessage::try_from(im).ok()),
        )
    }
}

/// Return false if this envelope must be fetched again to surface a new initial.
fn carry_initial<I: PartialEq>(carried: &mut Vec<I>, initial: Option<I>) -> bool {
    if let Some(initial) = initial
        && !carried.contains(&initial)
    {
        if carried.len() == MAX_CARRIED_INITIALS {
            return false;
        }
        carried.push(initial);
    }
    true
}

/// A message received, see [`Session::receive`].
///
/// Its `Debug` implementation redacts decrypted `content` plaintext bytes.
pub struct Received {
    /// Its content, or why there is none.
    pub content: Result<Vec<u8>>,
    /// Whether it decrypted on an earlier session [kept](Session::keep), rather than the active
    /// one: the peer sent it before the session that replaced it, e.g. before deleting the chat
    /// and starting it again.
    pub earlier: bool,
    /// The initial message of its session, which its sender sends with each message while this
    /// client has not answered that session. For the message receiving [stalled](ErrorKind::Stalled)
    /// at, those that came with the rest of its page too, any of which may be the session it,
    /// or one after it, is on: accepting them with [`Client::accept`] may let them decrypt.
    pub initial_messages: Vec<InitialMessage>,
}

impl core::fmt::Debug for Received {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut s = f.debug_struct("Received");
        match &self.content {
            Ok(bytes) => s.field("content_len", &bytes.len()),
            Err(err) => s.field("error", &err.kind()),
        };
        s.field("earlier", &self.earlier)
            .field("initial_messages", &self.initial_messages.len())
            .finish()
    }
}

impl Received {
    /// Whether this entry represents a message whose skipped key was evicted before arrival
    /// (permanently lost, with its delivery token queued for server acknowledgement).
    pub fn is_evicted(&self) -> bool {
        self.content
            .as_ref()
            .is_err_and(|e| e.kind() == ErrorKind::EvictedMessage)
    }
}

/// A prepared classical prekey publish request from [`Client::prepare_publish`] or
/// [`Client::prepare_extend_keys`].
///
/// Persist [`Client::state`] BEFORE calling [`Client::transmit_publish`], then call
/// [`Client::commit_publish`] on success or [`Client::rollback_publish_on_refusal`] on
/// [`ErrorKind::SignInRequired`].
#[derive(Debug, Clone)]
pub struct PreparedPublish {
    /// The signed v1 publish request to transmit.
    pub request: PublishRequest,
    extended: bool,
    was_publishing: bool,
    prev_last_timestamp: u64,
    signed_prekey: PublicKey,
    one_time_prekeys: Vec<PublicKey>,
}

/// A prepared classical session initiation from [`Client::prepare_initiate`].
///
/// Persist [`session.state()`](Session::state) BEFORE calling [`Client::send_prepared_initiate`].
#[derive(Debug)]
pub struct PreparedInitiate<M> {
    /// The newly established classical session.
    pub session: Session<M>,
    /// The signed-out v1 initial message request to transmit after persisting `session`.
    pub request: SendInitialMessageRequest,
}

/// Extract a [`Hello`] greeting from decrypted or outgoing content bytes, if present.
pub(crate) fn extract_hello(content: &[u8]) -> Option<Hello> {
    match Content::decode(content).ok()?.kind {
        Some(ContentKind::Hello(hello)) => Some(hello),
        _ => None,
    }
}

/// Read a greeting only after authentication, before confirming the claimed prekeys.
fn checked_initial_hello(content: &[u8]) -> Result<Option<Hello>> {
    let hello = extract_hello(content);
    if hello
        .as_ref()
        .is_some_and(|h| h.session_seq > protocol::MAX_SAFE_INTEGER)
    {
        return Err(ErrorKind::InvalidInitialMessage.into());
    }
    Ok(hello)
}

/// Number of earlier sessions with its peer that a [`Session`] keeps, only to decrypt the
/// messages sent on them; see [`Session::keep`].
pub const KEPT_SESSIONS: usize = 3;

/// How many times the peers may turn between one sending on its session and the other's
/// message decrypting only on an earlier one, before the session is retired; see
/// [`Session::keep`].
pub const MAX_DIRECTION_CHANGES: u32 = 5;

/// An identity on a handshake server: publishes prekeys, starts and accepts sessions.
///
/// [`Client::new`] gives it a new random identity key, and [`Client::builder`] can set one:
/// `Client::builder(handshake).identity(identity).build()`. [`Client::restore`] brings back a
/// client from its saved [`state`](Client::state).
#[derive(Debug, Builder)]
pub struct Client<H> {
    #[builder(start_fn)]
    handshake: H,
    /// The identity key; a new random one unless set.
    #[builder(
        name = identity,
        with = |identity: XEdDSAPrivateKey| ClientState::new(identity),
        default = ClientState::new(XEdDSAPrivateKey::generate()),
    )]
    state: ClientState,
    #[builder(skip = state.identity.compute_public_key().to_bytes())]
    identity_key: PublicKey,
    /// The server's clock, which signs the requests whose time it checks.
    #[builder(default)]
    clock: ServerClock,
}

/// What a [`Client`] keeps besides its transport: the identity key, the prekeys and the last
/// request's timestamp.
///
/// Save it to [`restore`](Client::restore) the client later: with `prost` convert it to a
/// `proto::ClientState` (portable versioned persistence), or serialize it with `serde`. It holds
/// private keys, so keep it secret.
#[derive(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "RawClientState")
)]
pub struct ClientState {
    pub(crate) identity: XEdDSAPrivateKey,
    pub(crate) prekeys: LocalPrekeys,
    pub(crate) last_timestamp: u64,
    /// Whether the last publish of the prekeys may have failed, though the server may have
    /// them, its reply being lost, see [`Client::publish_keys`].
    pub(crate) publishing: bool,
    /// User post-quantum preferences (PQ enabled by default when compiled).
    pub(crate) pq_config: PqConfig,
    /// Strictly increasing `CapabilityManifest.manifest_seq` published via v2.
    pub(crate) manifest_seq: u64,
    /// Prekey generation counter published via v2.
    pub(crate) prekey_generation: u64,
    /// SHA-256 digests of recent `CapabilityManifest`s signed by this client (bounded by
    /// `MAX_RECENT_MANIFEST_DIGESTS`).
    pub(crate) recent_manifest_digests: Vec<[u8; 32]>,
}

impl ClientState {
    fn new(identity: XEdDSAPrivateKey) -> Self {
        Self {
            identity,
            prekeys: LocalPrekeys::new(),
            last_timestamp: 0,
            publishing: false,
            pq_config: PqConfig::default(),
            manifest_seq: 0,
            prekey_generation: 0,
            recent_manifest_digests: vec![],
        }
    }

    /// Record a freshly signed manifest digest, retaining at most `MAX_RECENT_MANIFEST_DIGESTS`
    /// while preferring to keep any digests listed in `preserve` (e.g. deferred unsupported-suite
    /// initials waiting for replay) and NEVER evicting the newly pushed digest. Returns the
    /// evicted `(index, digest)` so a refused publish can restore FIFO order.
    pub(crate) fn record_manifest_digest_preserving(
        &mut self,
        digest: [u8; 32],
        preserve: &[[u8; 32]],
    ) -> Option<(usize, [u8; 32])> {
        if let Some(pos) = self
            .recent_manifest_digests
            .iter()
            .position(|d| *d == digest)
        {
            self.recent_manifest_digests.remove(pos);
        }
        self.recent_manifest_digests.push(digest);
        let mut evicted = None;
        while self.recent_manifest_digests.len() > MAX_RECENT_MANIFEST_DIGESTS {
            // Only consider entries strictly older than the newly appended `last()` slot.
            let candidate_end = self.recent_manifest_digests.len() - 1;
            let evict_idx = self.recent_manifest_digests[..candidate_end]
                .iter()
                .position(|d| !preserve.contains(d))
                .unwrap_or(0);
            evicted = Some((evict_idx, self.recent_manifest_digests.remove(evict_idx)));
        }
        evicted
    }

    /// Pop a previously appended manifest digest and restore any digest it evicted at its original
    /// FIFO position.
    pub(crate) fn rollback_manifest_digest(
        &mut self,
        added: [u8; 32],
        evicted: Option<(usize, [u8; 32])>,
    ) {
        if self.recent_manifest_digests.last() == Some(&added) {
            self.recent_manifest_digests.pop();
        }
        if let Some((pos, restored)) = evicted
            && self.recent_manifest_digests.len() < MAX_RECENT_MANIFEST_DIGESTS
            && !self.recent_manifest_digests.contains(&restored)
        {
            let idx = pos.min(self.recent_manifest_digests.len());
            self.recent_manifest_digests.insert(idx, restored);
        }
    }

    /// This client's post-quantum configuration.
    pub fn pq_config(&self) -> &PqConfig {
        &self.pq_config
    }

    #[cfg(any(feature = "prost", feature = "serde"))]
    fn validate(&self) -> Result<()> {
        if self.last_timestamp > protocol::MAX_SAFE_INTEGER
            || self.manifest_seq > protocol::MAX_SAFE_INTEGER
            || self.prekey_generation > protocol::MAX_SAFE_INTEGER
            || self.recent_manifest_digests.len() > MAX_RECENT_MANIFEST_DIGESTS
            || (self.manifest_seq > 0 && self.recent_manifest_digests.is_empty())
        {
            return Err(ErrorKind::MalformedState.into());
        }
        self.pq_config.validate()?;
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_bounded_vec<'de, D, T, const MAX: usize>(
    deserializer: D,
) -> core::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct BoundedVecVisitor<T, const MAX: usize>(core::marker::PhantomData<T>);

    impl<'de, T, const MAX: usize> serde::de::Visitor<'de> for BoundedVecVisitor<T, MAX>
    where
        T: serde::Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "a sequence of at most {MAX} items")
        }

        fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            if let Some(hint) = seq.size_hint()
                && hint > MAX
            {
                return Err(serde::de::Error::custom(format!(
                    "sequence exceeds maximum length {MAX}"
                )));
            }
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX));
            while let Some(item) = seq.next_element()? {
                if out.len() >= MAX {
                    return Err(serde::de::Error::custom(format!(
                        "sequence exceeds maximum length {MAX}"
                    )));
                }
                out.push(item);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor::<T, MAX>(core::marker::PhantomData))
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(rename = "ClientState")]
struct RawClientState {
    identity: XEdDSAPrivateKey,
    prekeys: LocalPrekeys,
    last_timestamp: u64,
    publishing: bool,
    #[serde(default)]
    pq_config: PqConfig,
    #[serde(default)]
    manifest_seq: u64,
    #[serde(default)]
    prekey_generation: u64,
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_vec::<_, _, MAX_RECENT_MANIFEST_DIGESTS>"
    )]
    recent_manifest_digests: Vec<[u8; 32]>,
}

#[cfg(feature = "serde")]
impl TryFrom<RawClientState> for ClientState {
    type Error = Error;

    fn try_from(raw: RawClientState) -> Result<Self> {
        let state = Self {
            identity: raw.identity,
            prekeys: raw.prekeys,
            last_timestamp: raw.last_timestamp,
            publishing: raw.publishing,
            pq_config: raw.pq_config,
            manifest_seq: raw.manifest_seq,
            prekey_generation: raw.prekey_generation,
            recent_manifest_digests: raw.recent_manifest_digests,
        };
        state.validate()?;
        Ok(state)
    }
}

#[cfg(feature = "prost")]
impl From<&ClientState> for proto::ClientState {
    fn from(state: &ClientState) -> Self {
        Self {
            identity: state.identity.to_bytes().to_vec(),
            prekeys: Some((&state.prekeys).into()),
            last_timestamp: state.last_timestamp,
            publishing: state.publishing,
            pq_disabled: !state.pq_config.pq_enabled,
            preferred_pq_suite: u32::from(state.pq_config.preferred_suite.as_u8()),
            pq_ratchet_disabled: !state.pq_config.pq_ratchet_enabled,
            strict_pq: state.pq_config.strict_pq,
            manifest_seq: state.manifest_seq,
            prekey_generation: state.prekey_generation,
            recent_manifest_digests: state
                .recent_manifest_digests
                .iter()
                .map(|d| d.to_vec())
                .collect(),
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&proto::ClientState> for ClientState {
    type Error = Error;

    fn try_from(state: &proto::ClientState) -> Result<Self> {
        let identity_bytes = Zeroizing::new(
            <[u8; xeddsa::PRIVATE_KEY_LENGTH]>::try_from(state.identity.as_slice())
                .map_err(|_| Error::from(ErrorKind::MalformedState))?,
        );
        let identity =
            XEdDSAPrivateKey::from_bytes(*identity_bytes).ok_or(ErrorKind::MalformedState)?;
        let preferred_suite = match state.preferred_pq_suite {
            0 => PqConfig::default_suite(),
            v => u8::try_from(v)
                .ok()
                .and_then(PqSuite::from_u8)
                .ok_or(ErrorKind::MalformedState)?,
        };
        let has_pq = cfg!(any(feature = "ml-kem-1024", feature = "ml-kem-768"));
        if state.strict_pq && (state.pq_disabled || !has_pq) {
            return Err(ErrorKind::MalformedState.into());
        }
        if state.recent_manifest_digests.len() > MAX_RECENT_MANIFEST_DIGESTS {
            return Err(ErrorKind::MalformedState.into());
        }
        let recent_manifest_digests = state
            .recent_manifest_digests
            .iter()
            .map(|d| {
                <[u8; 32]>::try_from(d.as_slice())
                    .map_err(|_| Error::from(ErrorKind::MalformedState))
            })
            .collect::<Result<Vec<_>>>()?;
        let pq_config = PqConfig {
            pq_enabled: has_pq && !state.pq_disabled,
            preferred_suite,
            pq_ratchet_enabled: has_pq && !state.pq_ratchet_disabled,
            strict_pq: state.strict_pq,
        };
        let restored = Self {
            identity,
            prekeys: state
                .prekeys
                .as_ref()
                .map(LocalPrekeys::try_from)
                .transpose()?
                .unwrap_or_default(),
            last_timestamp: state.last_timestamp,
            publishing: state.publishing,
            pq_config,
            manifest_seq: state.manifest_seq,
            prekey_generation: state.prekey_generation,
            recent_manifest_digests,
        };
        restored.validate()?;
        Ok(restored)
    }
}

impl<H> Client<H> {
    /// A client with a new random identity key.
    pub fn new(handshake: H) -> Self {
        Self::builder(handshake).build()
    }

    /// This client's public identity key, which peers use to reach it.
    pub fn identity_key(&self) -> PublicKey {
        self.identity_key
    }

    /// A client over `handshake`, from the `state` of an earlier one.
    pub fn restore(handshake: H, state: ClientState) -> Self {
        let identity_key = state.identity.compute_public_key().to_bytes();
        Self {
            handshake,
            state,
            identity_key,
            clock: ServerClock::default(),
        }
    }

    /// What to save to [`restore`](Client::restore) this client later. Its prekeys change when
    /// publishing and accepting, so save it after those.
    pub fn state(&self) -> &ClientState {
        &self.state
    }

    /// This client, signing the requests whose time the server checks with `clock`, which the
    /// transport keeps to the server's time, e.g. from the `Date` of its responses.
    pub fn with_clock(mut self, clock: ServerClock) -> Self {
        self.clock = clock;
        self
    }

    /// The server's clock, as this client sees it, which signs the requests whose time the
    /// server checks.
    pub fn clock(&self) -> &ServerClock {
        &self.clock
    }

    /// Current post-quantum security configuration.
    pub fn pq_config(&self) -> &PqConfig {
        &self.state.pq_config
    }

    /// Update this client's post-quantum configuration, validating suite support and `strict_pq`
    /// invariants.
    pub fn set_pq_config(&mut self, config: PqConfig) -> Result<()> {
        if config.pq_enabled && !PqConfig::is_compiled_suite(config.preferred_suite) {
            return Err(ErrorKind::UnsupportedSuite.into());
        }
        config.validate()?;
        self.state.pq_config = config;
        Ok(())
    }

    /// Builder-style helper setting this client's post-quantum configuration.
    pub fn with_pq_config(mut self, config: PqConfig) -> Result<Self> {
        self.set_pq_config(config)?;
        Ok(self)
    }

    /// Monotonic `CapabilityManifest.manifest_seq` last prepared/published by this client.
    pub fn manifest_seq(&self) -> u64 {
        self.state.manifest_seq
    }

    /// Prekey generation number last prepared/published via v2 by this client.
    pub fn prekey_generation(&self) -> u64 {
        self.state.prekey_generation
    }

    /// Latest local signed prekey, if any generation has been generated.
    pub fn current_signed_prekey(&self) -> Option<PublicKey> {
        self.state.prekeys.current_signed_prekey()
    }

    /// The signed prekey of the oldest retained generation that the next rotating publish would
    /// evict, if the local prekey store is already at capacity.
    pub fn oldest_evictable_signed_prekey(&self) -> Option<PublicKey> {
        self.state.prekeys.oldest_evictable_signed_prekey()
    }

    /// Number of unused classical one-time prekeys in the latest local generation.
    pub fn current_one_time_count(&self) -> usize {
        self.state.prekeys.current_one_time_count()
    }

    /// Number of unused post-quantum one-time prekeys for `suite` in the latest local generation.
    pub fn current_pq_one_time_count(&self, suite: PqSuite) -> usize {
        self.state.prekeys.current_pq_one_time_count(suite)
    }

    /// Build a [`Hello`] greeting reflecting this client's current [`PqConfig`] and `session_seq`.
    pub fn make_hello(&self, name: impl Into<String>, session_seq: u64) -> Hello {
        let offered = self.state.pq_config.offered_suites();
        let pq_capable = self.state.pq_config.pq_enabled && !offered.is_empty();
        Hello {
            name: name.into(),
            pq_capable,
            max_version: if pq_capable { x3dh::PQXDH_VERSION } else { 1 },
            session_seq,
            offered_suites: offered.into_iter().map(|s| u32::from(s.as_u8())).collect(),
            pq_ratchet_capable: pq_capable && self.state.pq_config.pq_ratchet_enabled,
        }
    }

    /// Prepare a classical v1 prekey publish request without sending it over the network yet.
    ///
    /// Persist [`Client::state`] BEFORE calling [`Client::transmit_publish`], then call
    /// [`Client::commit_publish`] on success or [`Client::rollback_publish_on_refusal`] on
    /// [`ErrorKind::SignInRequired`].
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub fn prepare_publish(&mut self, one_time_count: usize) -> Result<PreparedPublish> {
        let was_publishing = self.state.publishing;
        let prev_last_timestamp = self.state.last_timestamp;
        let extended = was_publishing;
        let timestamp = self.next_timestamp()?;
        let published = if extended {
            self.state
                .prekeys
                .extend(&self.state.identity, one_time_count)
        } else {
            self.state
                .prekeys
                .generate(&self.state.identity, one_time_count)
        };
        self.state.publishing = true;
        let request = PublishRequest::sign(&self.state.identity, &published, timestamp)?;
        Ok(PreparedPublish {
            request,
            extended,
            was_publishing,
            prev_last_timestamp,
            signed_prekey: published.signed_prekey,
            one_time_prekeys: published.one_time_prekeys,
        })
    }

    /// Prepare a classical v1 publish that replenishes `one_time_count` one-time prekeys on the
    /// current generation WITHOUT rotating the signed prekey (generates a generation if none
    /// exists yet).
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub fn prepare_extend_keys(&mut self, one_time_count: usize) -> Result<PreparedPublish> {
        let was_publishing = self.state.publishing;
        let prev_last_timestamp = self.state.last_timestamp;
        let had_gen = self.state.prekeys.generation_count() > 0;
        let timestamp = self.next_timestamp()?;
        let published = self
            .state
            .prekeys
            .extend(&self.state.identity, one_time_count);
        self.state.publishing = true;
        let request = PublishRequest::sign(&self.state.identity, &published, timestamp)?;
        Ok(PreparedPublish {
            request,
            extended: had_gen,
            was_publishing,
            prev_last_timestamp,
            signed_prekey: published.signed_prekey,
            one_time_prekeys: published.one_time_prekeys,
        })
    }

    /// Mark a prepared classical publish as confirmed by the server.
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub fn commit_publish(&mut self, _prepared: PreparedPublish) {
        self.state.publishing = false;
    }

    /// Retract newly added one-time prekeys from a prepared classical publish that was refused
    /// before storage (e.g. [`ErrorKind::SignInRequired`], [`ErrorKind::LimitExceeded`], or
    /// [`ErrorKind::Protocol`]).
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub fn rollback_publish_on_refusal(&mut self, prepared: PreparedPublish) {
        if prepared.extended {
            self.state
                .prekeys
                .retract(&prepared.signed_prekey, &prepared.one_time_prekeys);
            self.state.publishing = prepared.was_publishing;
        }
        if self.state.last_timestamp == prepared.request.timestamp {
            self.state.last_timestamp = prepared.prev_last_timestamp;
        }
    }

    /// Start uploading an attachment of `size` bytes: a new key, and the service's ID and upload
    /// token for it. Then [encrypt](attachment::Upload::try_encrypt) and
    /// [put](attachment::Upload::put) each chunk, and send the ID and key to the recipients in a
    /// message. The upload token may be kept after, to [cancel](attachment::Upload::cancel) it
    /// later, deleting the attachment.
    ///
    /// Fails with [`ErrorKind::LimitExceeded`] if the service takes no attachment that large.
    pub async fn start_upload(
        &self,
        attachments: &impl LocalAttachments,
        size: u64,
    ) -> Result<attachment::Upload> {
        let chunks = u32::try_from(attachment::chunk_count(size))
            .map_err(|_| Error::from(ErrorKind::LimitExceeded))?;
        let key = attachment::try_generate_key()?;
        let response = attachments
            .start_upload(StartUploadRequest {
                chunks,
                delete_hash: Bytes::copy_from_slice(&attachment::delete_hash(&key)),
            })
            .await?;
        Ok(attachment::Upload::new(
            protocol::fixed(&response.id)?,
            Zeroizing::new(protocol::fixed(&response.upload_token)?),
            key,
            chunks,
            (response.expires != 0).then_some(response.expires),
        ))
    }

    /// A legacy non-audience-bound subscription to this client's notifications, signed by its
    /// identity key; see `protocol::notify`. It is good for a few minutes of the server's
    /// [clock](Self::clock).
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    #[allow(deprecated)]
    pub fn subscription(&self) -> SubscribeRequest {
        // Within a few minutes of the server's clock, not by the strictly increasing timestamp,
        // which may have run ahead of it.
        SubscribeRequest::sign(
            &self.state.identity,
            self.clock.now().min(protocol::MAX_SAFE_INTEGER),
        )
    }

    /// Sign a notification subscription for a configured relay URL or host using its clock.
    /// Use [`Self::subscription_for_canonical_audience`] with a previously parsed audience.
    pub fn subscription_for_audience(&self, audience: &str) -> Result<SubscribeRequest> {
        self.subscription_for_canonical_audience(&protocol::NormalizedAudience::parse(audience)?)
    }

    /// Sign a notification subscription for an already normalized relay audience.
    pub fn subscription_for_canonical_audience(
        &self,
        audience: &protocol::NormalizedAudience,
    ) -> Result<SubscribeRequest> {
        Ok(SubscribeRequest::sign_for_canonical_audience(
            &self.state.identity,
            audience,
            self.clock.now(),
        )?)
    }

    /// Milliseconds since the Unix epoch by the server's [clock](Self::clock), bounded by
    /// `protocol::MAX_SAFE_INTEGER` without advancing `last_timestamp`.
    pub(crate) fn current_timestamp(&self) -> Result<u64> {
        let now = self.clock.now();
        if now > protocol::MAX_SAFE_INTEGER {
            return Err(ErrorKind::Protocol.into());
        }
        Ok(now)
    }

    /// Milliseconds since the Unix epoch from [`ServerClock::trusted_clock_pair`], failing closed
    /// with [`ErrorKind::ClockSkew`] if the local clock is invalid or disagrees with the server
    /// clock beyond its trusted drift threshold. Respects monotonicity against `last_timestamp`
    /// (unless `last_timestamp` lies more than [`protocol::MAX_CLOCK_SKEW`] ahead) without
    /// mutating `last_timestamp` during prepare.
    pub(crate) fn trusted_timestamp(&self) -> Result<u64> {
        let (_local, server) = self.clock.trusted_clock_pair()?;
        let ts = if self.state.last_timestamp.saturating_add(1)
            > server.saturating_add(protocol::MAX_CLOCK_SKEW)
        {
            server
        } else {
            server.max(self.state.last_timestamp.saturating_add(1))
        };
        if ts > protocol::MAX_SAFE_INTEGER {
            return Err(ErrorKind::Protocol.into());
        }
        Ok(ts)
    }

    /// Milliseconds since the Unix epoch by the server's [clock](Self::clock), strictly
    /// increasing (unless a stale persisted `last_timestamp` lies more than
    /// [`protocol::MAX_CLOCK_SKEW`] ahead of the current clock) and bounded by
    /// `protocol::MAX_SAFE_INTEGER`.
    pub(crate) fn next_timestamp(&mut self) -> Result<u64> {
        let now = self.clock.now();
        let next = if self.state.last_timestamp.saturating_add(1)
            > now.saturating_add(protocol::MAX_CLOCK_SKEW)
        {
            now
        } else {
            now.max(self.state.last_timestamp.saturating_add(1))
        };
        if next > protocol::MAX_SAFE_INTEGER {
            return Err(ErrorKind::Protocol.into());
        }
        self.state.last_timestamp = next;
        Ok(next)
    }
}

#[allow(deprecated)]
impl<H: LocalHandshake> Client<H> {
    /// Transmit a prepared classical publish request (after persisting [`Client::state`]).
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub async fn transmit_publish(&self, prepared: &PreparedPublish) -> Result<()> {
        self.handshake.publish(prepared.request.clone()).await?;
        Ok(())
    }

    /// Generate and publish a signed prekey and `one_time_count` one-time prekeys, replacing
    /// the published ones.
    ///
    /// Only the last [`x3dh::KEPT_GENERATIONS`] generations of prekeys are kept, so take the
    /// initial messages waiting before publishing again; later, the ones using deleted prekeys
    /// cannot be accepted. If publishing fails, the server may still have the prekeys, its reply
    /// being lost: the next publish sends the same signed prekey again, with new one-time
    /// prekeys, rather than a new generation, which would delete the private keys of prekeys
    /// the server hands out. One refused for want of a sign-in, which the server keeps none of,
    /// forgets the one-time prekeys it added to them, so that publishing again while signed out
    /// does not add up keys. Save the state after this, failed or not.
    ///
    /// For persist-before-transmit flows, use [`Client::prepare_publish`], persist
    /// [`Client::state`], then call [`Client::transmit_publish`] and [`Client::commit_publish`].
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub async fn publish_keys(&mut self, one_time_count: usize) -> Result<()> {
        let prepared = self.prepare_publish(one_time_count)?;
        match self.transmit_publish(&prepared).await {
            Ok(()) => {
                self.commit_publish(prepared);
                Ok(())
            }
            Err(e) if e.is_server_refusal() && e.kind() == ErrorKind::SignInRequired => {
                self.rollback_publish_on_refusal(prepared);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Replenish `one_time_count` classical one-time prekeys on the current generation without
    /// rotating the signed prekey (generates a generation if none exists yet).
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub async fn extend_keys(&mut self, one_time_count: usize) -> Result<()> {
        let prepared = self.prepare_extend_keys(one_time_count)?;
        match self.transmit_publish(&prepared).await {
            Ok(()) => {
                self.commit_publish(prepared);
                Ok(())
            }
            Err(e)
                if e.is_server_refusal()
                    && matches!(
                        e.kind(),
                        ErrorKind::SignInRequired | ErrorKind::LimitExceeded | ErrorKind::Protocol
                    ) =>
            {
                self.rollback_publish_on_refusal(prepared);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Prepare starting a classical session with `peer` without sending the initial message yet,
    /// so the caller can persist [`PreparedInitiate::session`] BEFORE calling
    /// [`Client::send_prepared_initiate`].
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub async fn prepare_initiate<M>(
        &mut self,
        peer: &PublicKey,
        content: &[u8],
        mailbox: M,
    ) -> Result<PreparedInitiate<M>> {
        if self.state.pq_config.strict_pq {
            return Err(ErrorKind::PqRequired.into());
        }
        let response = self
            .handshake
            .fetch_bundle(FetchBundleRequest {
                identity_key: Bytes::copy_from_slice(peer),
            })
            .await?;
        let bundle = PrekeyBundle::try_from(&response)?;
        let (message, agreement) = bundle.initiate(&self.state.identity, peer)?;
        let ratchet = Ratchet::alice(
            &SharedKeys::from_secret(&agreement.secret_key),
            &bundle.signed_prekey,
        )?;
        let mut party = Party::new(ratchet, agreement.associated_data);
        let first_message = party.encrypt(content)?;
        let initial_message = handshake::InitialMessage {
            first_message: Some(first_message),
            ..handshake::InitialMessage::from(&message)
        };
        let request = SendInitialMessageRequest {
            recipient: Bytes::copy_from_slice(peer),
            message: Some(initial_message.clone()),
        };
        let mut session = Session::new(
            mailbox,
            Active {
                party,
                id: message.ephemeral_key,
                known_by_peer: false,
                initial_message: initial_message.encode_to_vec(),
                delivery_key: DeliveryKey::derive(agreement.secret_key.as_slice()),
                security: SessionSecurity::classical(),
                peer_session_seq: 0,
            },
            self.identity_key,
            *peer,
        );
        if let Some(hello) = extract_hello(content)
            && hello.session_seq > 0
        {
            session.state.next_session_seq = hello
                .session_seq
                .saturating_add(1)
                .min(protocol::MAX_SAFE_INTEGER);
        }
        Ok(PreparedInitiate { session, request })
    }

    /// Transmit a prepared classical initial message request (after persisting `session.state()`).
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub async fn send_prepared_initiate(&self, request: &SendInitialMessageRequest) -> Result<()> {
        self.handshake.send_initial_message(request.clone()).await?;
        Ok(())
    }

    /// Start a session with `peer`, whose first message is `content`: fetch the peer's prekeys,
    /// run X3DH, and leave the initial message, with the first message, in the peer's inbox.
    ///
    /// The first message shows the peer that the initial message is this client's, and lets the
    /// peer write back at once. It can be empty.
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub async fn initiate<M>(
        &mut self,
        peer: &PublicKey,
        content: &[u8],
        mailbox: M,
    ) -> Result<Session<M>> {
        let prepared = self.prepare_initiate(peer, content, mailbox).await?;
        self.send_prepared_initiate(&prepared.request).await?;
        Ok(prepared.session)
    }

    /// Prepare starting a new classical session with `session`'s peer and merge it into `session`
    /// via [`Session::keep`], returning the `SendInitialMessageRequest` to transmit AFTER
    /// persisting `session.state()`.
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub async fn prepare_start_again<M: Clone>(
        &mut self,
        session: &mut Session<M>,
        content: &[u8],
    ) -> Result<SendInitialMessageRequest> {
        if session.state.me != self.identity_key {
            return Err(ErrorKind::UnexpectedPeer.into());
        }
        if self.state.pq_config.strict_pq {
            return Err(ErrorKind::PqRequired.into());
        }
        let local_pq_enabled =
            self.state.pq_config.pq_enabled && !self.state.pq_config.offered_suites().is_empty();
        if local_pq_enabled
            && session.state.peer_pq.pq_pinned
            && !session.state.peer_pq.allow_classical_exception
        {
            return Err(ErrorKind::DowngradeDetected.into());
        }
        let prepared = self
            .prepare_initiate(&session.state.peer, content, session.mailbox.clone())
            .await?;
        let older = mem::replace(session, prepared.session);
        session.keep(older)?;
        Ok(prepared.request)
    }

    /// Start a new session with `session`'s peer, whose first message is `content`, and keep
    /// `session`, the chat so far, with it, see [`Session::keep`]: as when it has none to send
    /// on ([`Session::needs_new_session`]).
    ///
    /// Fails with [`ErrorKind::UnexpectedPeer`] if `session` is another identity's, before
    /// anything is sent or changed.
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub async fn start_again<M: Clone>(
        &mut self,
        session: &mut Session<M>,
        content: &[u8],
    ) -> Result<()> {
        let request = self.prepare_start_again(session, content).await?;
        self.send_prepared_initiate(&request).await
    }

    /// Take the initial messages waiting in this client's inbox.
    ///
    /// The server deletes them, so keep the ones to accept later. Malformed ones, which could
    /// never be accepted, are left out.
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub async fn take_initial_messages(&mut self) -> Result<Vec<InitialMessage>> {
        let timestamp = self.next_timestamp()?;
        let request = TakeInitialMessagesRequest::sign(&self.state.identity, timestamp);
        let response = self.handshake.take_initial_messages(request).await?;
        // The server has deleted them already, so one malformed message must not fail the
        // call and lose the others with it.
        Ok(response
            .messages
            .iter()
            .filter_map(|message| InitialMessage::try_from(message).ok())
            .collect())
    }

    /// Accept `initial_message` from `peer`, starting the session `peer` asked for. Returns the
    /// session and the content of its first message.
    ///
    /// Anyone can send an initial message claiming to be from `peer`, but only `peer` can have
    /// encrypted its first message, which must decrypt. Fails with
    /// [`ErrorKind::InvalidInitialMessage`] if it does not, or if the initial message was accepted
    /// already, and with [`ErrorKind::UnexpectedPeer`] if it is not from `peer`; failing, it
    /// uses up nothing.
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub fn accept<M>(
        &mut self,
        peer: &PublicKey,
        initial_message: &InitialMessage,
        mailbox: M,
    ) -> Result<(Session<M>, Vec<u8>)> {
        let (agreement, signed_prekey) =
            self.state
                .prekeys
                .accept(&self.state.identity, peer, &initial_message.x3dh)?;
        let spk_bytes = Zeroizing::new(signed_prekey.to_bytes());
        let ratchet = Ratchet::bob(
            &SharedKeys::from_secret(&agreement.secret_key),
            DhPrivateKey::from(*spk_bytes),
        );
        let mut party = Party::new(ratchet, agreement.associated_data);
        let content = party
            .decrypt(&initial_message.first_message)
            .map_err(|e| Error::new(ErrorKind::InvalidInitialMessage, e))?;
        // Enforce strict-PQ policy AFTER authenticating the sender and BEFORE confirming prekeys.
        if self.state.pq_config.strict_pq {
            return Err(ErrorKind::PqRequired.into());
        }
        let peer_session_seq = checked_initial_hello(&content)?.map_or(0, |h| h.session_seq);
        self.state.prekeys.confirm(&initial_message.x3dh)?;
        let active = Active {
            party,
            id: initial_message.x3dh.ephemeral_key,
            known_by_peer: true,
            initial_message: vec![],
            delivery_key: DeliveryKey::derive(agreement.secret_key.as_slice()),
            security: SessionSecurity::classical(),
            peer_session_seq,
        };
        let mut session = Session::new(mailbox, active, self.identity_key, *peer);
        session.state.peer_pq.peer_session_seq = peer_session_seq;
        Ok((session, content))
    }
}

/// Milliseconds since the Unix epoch, by this device's clock.
fn now() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(protocol::MAX_SAFE_INTEGER)
        })
}

/// A message encrypted for the peer by [`Session::encrypt`], to [push](Session::push) now or
/// later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The message.
    pub message: EncryptedMessage,
    /// SHA-256 of its delivery token, under the key of the session it was encrypted on, which
    /// the token the peer gives back once it has the message matches, so that the server deletes
    /// it; none for one that only expires.
    pub delivery_hash: Option<[u8; 32]>,
}

impl Sealed {
    /// Deterministic 16-byte client idempotency identifier derived from an encrypted message
    /// (`SHA-256("session.v2/client-message-id\0" || len(header) || header || len(content) || content)[..16]`),
    /// stable across retries and restarts without leaking plaintext or keys.
    pub fn client_message_id_for(message: &EncryptedMessage) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(b"session.v2/client-message-id\0");
        hasher.update((message.header.len() as u64).to_be_bytes());
        hasher.update(&message.header);
        hasher.update((message.content.len() as u64).to_be_bytes());
        hasher.update(&message.content);
        let digest = hasher.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        id
    }

    /// Deterministic 16-byte client idempotency identifier derived from this sealed ciphertext
    /// via [`Sealed::client_message_id_for`].
    pub fn client_message_id(&self) -> [u8; 16] {
        Self::client_message_id_for(&self.message)
    }
}

/// A session with one peer: encrypts with a [`Party`] and exchanges messages through a mailbox.
///
/// It may hold earlier sessions with the peer too, which only decrypt, see [`Session::keep`].
///
/// [`Session::restore`] brings back a session from its saved [`state`](Session::state).
#[derive(Debug)]
pub struct Session<M> {
    pub(crate) mailbox: M,
    pub(crate) state: SessionState,
}

/// What a [`Session`] keeps besides its transport: the double ratchets, both identity keys and
/// the position in the peer's queue.
///
/// Save it to [`restore`](Session::restore) the session later: with `prost` convert it to a
/// `proto::SessionState` (portable versioned persistence), or serialize it with `serde`. It holds
/// the session's keys, so keep it secret; its `Debug` shows none of them, nor the delivery tokens.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "RawSessionState")
)]
pub struct SessionState {
    /// The session messages are sent on; none once retired, until a new one starts.
    pub(crate) active: Option<Active>,
    /// Earlier sessions with the peer, latest first, which only decrypt, see [`Session::keep`].
    pub(crate) others: Vec<Earlier>,
    pub(crate) me: PublicKey,
    pub(crate) peer: PublicKey,
    /// Sequence number of the last fetched message.
    pub(crate) cursor: u64,
    /// What was done last, and how many times the peers turned between sending on the active
    /// session and receiving on an earlier one, see [`Session::keep`].
    pub(crate) last: LastAction,
    pub(crate) direction_changes: u32,
    /// The last sequence number of the page in which receiving stopped at a message that did not
    /// decrypt, and up to which messages that do not decrypt are skipped, see
    /// [`Session::receive`].
    pub(crate) stalled_through: u64,
    pub(crate) skip_through: u64,
    /// The delivery tokens of the messages received and not told to the server yet, which the
    /// next fetch tells it, see [`Session::receive`].
    pub(crate) delivered: Vec<[u8; DELIVERY_TOKEN_LENGTH]>,
    /// Per-peer post-quantum pinning, downgrade-detection, and `peer_session_seq` state.
    pub(crate) peer_pq: PeerPqState,
    /// Next outgoing monotonic `Hello.session_seq` for this peer (`0` treated as `1`).
    pub(crate) next_session_seq: u64,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.delivered);
    }
}

impl core::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionState")
            .field("active", &self.active)
            .field("others", &self.others)
            .field("me", &self.me)
            .field("peer", &self.peer)
            .field("cursor", &self.cursor)
            .field("last", &self.last)
            .field("direction_changes", &self.direction_changes)
            .field("stalled_through", &self.stalled_through)
            .field("skip_through", &self.skip_through)
            .field("delivered", &self.delivered.len())
            .field("peer_pq", &self.peer_pq)
            .field("next_session_seq", &self.next_session_seq)
            .finish()
    }
}

/// The session a [`SessionState`] sends on.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct Active {
    pub(crate) party: Party,
    /// The session's ID, which both peers have: the X3DH ephemeral key of the one who started
    /// it.
    pub(crate) id: PublicKey,
    /// Whether the peer is known to have it: it started it, or a message on it decrypted.
    pub(crate) known_by_peer: bool,
    /// The initial message, encoded, that started it, which this client did: each message
    /// goes with it until the peer is known to have the session, in case the one in its inbox
    /// was lost. Empty once known.
    pub(crate) initial_message: Vec<u8>,
    pub(crate) delivery_key: DeliveryKey,
    /// Negotiated cryptographic security metadata of this active session.
    #[cfg_attr(feature = "serde", serde(default))]
    pub(crate) security: SessionSecurity,
    /// Peer's `Hello.session_seq` that created this session (`0` if locally initiated or legacy).
    #[cfg_attr(feature = "serde", serde(default))]
    pub(crate) peer_session_seq: u64,
}

/// An earlier session of a [`SessionState`], which only decrypts.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct Earlier {
    pub(crate) party: Party,
    pub(crate) delivery_key: DeliveryKey,
}

impl From<Active> for Earlier {
    fn from(active: Active) -> Self {
        Self {
            party: active.party,
            delivery_key: active.delivery_key,
        }
    }
}

/// A session's delivery key, from X3DH's shared secret, which both peers have. A message's
/// delivery token is HMAC-SHA256 of its encrypted header under it, truncated: only the two peers
/// can compute it, so the recipient, giving it back to the server once it has the message,
/// proves that it does, and the server, which has its SHA-256 from the push, deletes the
/// message. Its `Debug` shows nothing of it.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct DeliveryKey(pub(crate) [u8; 32]);

impl DeliveryKey {
    /// The delivery key of a session whose X3DH shared secret is `secret`.
    pub(crate) fn derive(secret: &[u8]) -> Self {
        let mut key = [0; 32];
        Hkdf::<Sha256>::new(None, secret)
            .expand(b"session.v1/delivery", &mut key)
            .expect("32 bytes are a valid HKDF-SHA256 output length");
        Self(key)
    }

    /// The delivery token of `message`, a message of this session.
    pub(crate) fn token(&self, message: &EncryptedMessage) -> [u8; DELIVERY_TOKEN_LENGTH] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes any key");
        mac.update(&message.header);
        let tag = mac.finalize().into_bytes();
        let mut token = [0; DELIVERY_TOKEN_LENGTH];
        token.copy_from_slice(&tag[..DELIVERY_TOKEN_LENGTH]);
        token
    }
}

impl core::fmt::Debug for DeliveryKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DeliveryKey(..)")
    }
}

/// What was done last on a [`SessionState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum LastAction {
    None,
    Sent,
    ReceivedActive,
    ReceivedEarlier,
}

/// Verify that a `Party`'s associated data binds the exact `(me, peer)` identity pair with length
/// matching classical X3DH (64 bytes) or PQXDH (96 bytes).
#[cfg(any(feature = "prost", feature = "serde"))]
fn check_party_identity_ad(
    ad: &[u8],
    me: &PublicKey,
    peer: &PublicKey,
    expected_pq: Option<bool>,
) -> Result<()> {
    let classical_len = 2 * xeddsa::PUBLIC_KEY_LENGTH;
    let pq_len = x3dh::PQXDH_ASSOCIATED_DATA_LENGTH;
    match expected_pq {
        Some(true) if ad.len() != pq_len => return Err(ErrorKind::MalformedState.into()),
        Some(false) if ad.len() != classical_len => {
            return Err(ErrorKind::MalformedState.into());
        }
        None if ad.len() != classical_len && ad.len() != pq_len => {
            return Err(ErrorKind::MalformedState.into());
        }
        _ => {}
    }
    let (first, second) = (&ad[..32], &ad[32..64]);
    if !((first == me && second == peer) || (first == peer && second == me)) {
        return Err(ErrorKind::MalformedState.into());
    }
    Ok(())
}

#[cfg(any(feature = "prost", feature = "serde"))]
struct ActiveStateView<'a> {
    id: &'a PublicKey,
    peer_session_seq: u64,
    security: SessionSecurity,
    party: &'a Party,
}

#[cfg(any(feature = "prost", feature = "serde"))]
fn validate_session_state<'a>(
    me: &PublicKey,
    peer: &PublicKey,
    counters: [u64; 6],
    pinned_manifest_digest: Option<[u8; 32]>,
    delivered: usize,
    earlier: impl ExactSizeIterator<Item = &'a [u8]>,
    active: Option<ActiveStateView<'a>>,
) -> Result<()> {
    let pinned_manifest_seq = counters[4];
    if [me, peer]
        .into_iter()
        .any(|key| !xeddsa::is_canonical_public_key(key) || XEdDSAPublicKey::new(key).is_err())
        || earlier.len() > KEPT_SESSIONS
        || delivered > MAX_STORED_DELIVERED
        || counters
            .into_iter()
            .any(|seq| seq > protocol::MAX_SAFE_INTEGER)
        || (pinned_manifest_seq == 0 && pinned_manifest_digest.is_some())
    {
        return Err(ErrorKind::MalformedState.into());
    }
    for ad in earlier {
        check_party_identity_ad(ad, me, peer, None)?;
    }
    if let Some(active) = active {
        let security = active.security;
        if !xeddsa::is_canonical_public_key(active.id)
            || *active.id == [0; 32]
            || active.peer_session_seq > protocol::MAX_SAFE_INTEGER
            || security.is_pq != security.suite.is_some()
            || (!security.is_pq && security.pq_ratchet)
        {
            return Err(ErrorKind::MalformedState.into());
        }
        check_party_identity_ad(
            active.party.associated_data(),
            me,
            peer,
            Some(security.is_pq),
        )?;
        if security.pq_ratchet != active.party.is_pq_ratchet_active() {
            return Err(ErrorKind::MalformedState.into());
        }
        if let Some(suite_id) = active.party.pq_suite_id()
            && security.suite.map(PqSuite::as_u8) != Some(suite_id)
        {
            return Err(ErrorKind::MalformedState.into());
        }
    }
    Ok(())
}

impl SessionState {
    /// The peer's identity key.
    pub fn peer(&self) -> &PublicKey {
        &self.peer
    }

    /// Per-peer post-quantum pinning, downgrade-detection, and anti-rollback state.
    pub fn peer_pq_state(&self) -> &PeerPqState {
        &self.peer_pq
    }

    /// Cryptographic security level of the active session, if any.
    pub fn security(&self) -> Option<SessionSecurity> {
        self.active.as_ref().map(|active| active.security)
    }

    /// Validate canonical keys, bounded collections, integer bounds, AD identity-pair bindings,
    /// and PQ metadata invariants.
    #[cfg(any(feature = "prost", feature = "serde"))]
    fn validate(&self) -> Result<()> {
        validate_session_state(
            &self.me,
            &self.peer,
            [
                self.cursor,
                self.stalled_through,
                self.skip_through,
                self.next_session_seq,
                self.peer_pq.pinned_manifest_seq,
                self.peer_pq.peer_session_seq,
            ],
            self.peer_pq.pinned_manifest_digest,
            self.delivered.len(),
            self.others.iter().map(|e| e.party.associated_data()),
            self.active.as_ref().map(|a| ActiveStateView {
                id: &a.id,
                peer_session_seq: a.peer_session_seq,
                security: a.security,
                party: &a.party,
            }),
        )
    }

    /// Keep `earlier`, an earlier session, only to decrypt, dropping the oldest beyond
    /// [`KEPT_SESSIONS`].
    fn archive(&mut self, earlier: Earlier) {
        self.others.insert(0, earlier);
        self.others.truncate(KEPT_SESSIONS);
    }

    /// A message decrypted on an earlier session. If the peers keep turning between this client
    /// sending on the active session and the peer's messages decrypting only on earlier ones,
    /// neither uses the other's: the active session is retired, and the next message goes on a
    /// new one.
    fn received_earlier(&mut self) {
        if self.last == LastAction::Sent {
            self.direction_changes = self.direction_changes.saturating_add(1);
        }
        self.last = LastAction::ReceivedEarlier;
        if self.direction_changes > MAX_DIRECTION_CHANGES {
            if let Some(active) = self.active.take() {
                self.archive(active.into());
            }
            self.direction_changes = 0;
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(rename = "SessionState")]
struct RawSessionState {
    active: Option<Active>,
    #[serde(deserialize_with = "deserialize_bounded_vec::<_, _, KEPT_SESSIONS>")]
    others: Vec<Earlier>,
    me: PublicKey,
    peer: PublicKey,
    cursor: u64,
    last: LastAction,
    direction_changes: u32,
    stalled_through: u64,
    skip_through: u64,
    #[serde(deserialize_with = "deserialize_bounded_vec::<_, _, MAX_STORED_DELIVERED>")]
    delivered: Vec<[u8; DELIVERY_TOKEN_LENGTH]>,
    #[serde(default)]
    peer_pq: PeerPqState,
    #[serde(default)]
    next_session_seq: u64,
}

#[cfg(feature = "serde")]
impl TryFrom<RawSessionState> for SessionState {
    type Error = Error;

    fn try_from(raw: RawSessionState) -> Result<Self> {
        let state = Self {
            active: raw.active,
            others: raw.others,
            me: raw.me,
            peer: raw.peer,
            cursor: raw.cursor,
            last: raw.last,
            direction_changes: raw.direction_changes,
            stalled_through: raw.stalled_through,
            skip_through: raw.skip_through,
            delivered: raw.delivered,
            peer_pq: raw.peer_pq,
            next_session_seq: raw.next_session_seq,
        };
        state.validate()?;
        Ok(state)
    }
}

#[cfg(feature = "prost")]
impl From<&PeerPqState> for proto::PeerPqState {
    fn from(state: &PeerPqState) -> Self {
        Self {
            pq_pinned: state.pq_pinned,
            pinned_manifest_seq: state.pinned_manifest_seq,
            allow_classical_exception: state.allow_classical_exception,
            downgrade_detected: state.downgrade_detected,
            peer_pq_capable: state.peer_pq_capable,
            peer_session_seq: state.peer_session_seq,
            pinned_manifest_digest: state
                .pinned_manifest_digest
                .map_or_else(Vec::new, |d| d.to_vec()),
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&proto::PeerPqState> for PeerPqState {
    type Error = Error;

    fn try_from(state: &proto::PeerPqState) -> Result<Self> {
        let pinned_manifest_digest = if state.pinned_manifest_digest.is_empty() {
            None
        } else {
            Some(
                <[u8; 32]>::try_from(state.pinned_manifest_digest.as_slice())
                    .map_err(|_| Error::from(ErrorKind::MalformedState))?,
            )
        };
        if state.pinned_manifest_seq > protocol::MAX_SAFE_INTEGER
            || state.peer_session_seq > protocol::MAX_SAFE_INTEGER
            || (state.pinned_manifest_seq == 0 && pinned_manifest_digest.is_some())
        {
            return Err(ErrorKind::MalformedState.into());
        }
        Ok(Self {
            pq_pinned: state.pq_pinned,
            pinned_manifest_seq: state.pinned_manifest_seq,
            pinned_manifest_digest,
            allow_classical_exception: state.allow_classical_exception,
            downgrade_detected: state.downgrade_detected,
            peer_pq_capable: state.peer_pq_capable,
            peer_session_seq: state.peer_session_seq,
        })
    }
}

#[cfg(feature = "prost")]
impl From<&SessionSecurity> for proto::SessionSecurity {
    fn from(security: &SessionSecurity) -> Self {
        Self {
            is_pq: security.is_pq,
            suite: security.suite.map_or(0, |s| u32::from(s.as_u8())),
            pq_ratchet: security.pq_ratchet,
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&proto::SessionSecurity> for SessionSecurity {
    type Error = Error;

    fn try_from(security: &proto::SessionSecurity) -> Result<Self> {
        let suite = match security.suite {
            0 => None,
            v => Some(
                u8::try_from(v)
                    .ok()
                    .and_then(PqSuite::from_u8)
                    .ok_or(ErrorKind::MalformedState)?,
            ),
        };
        if security.is_pq {
            if suite.is_none() {
                return Err(ErrorKind::MalformedState.into());
            }
        } else if suite.is_some() || security.pq_ratchet {
            return Err(ErrorKind::MalformedState.into());
        }
        Ok(Self {
            is_pq: security.is_pq,
            suite,
            pq_ratchet: security.pq_ratchet,
        })
    }
}

#[cfg(feature = "prost")]
impl From<&SessionState> for proto::SessionState {
    fn from(state: &SessionState) -> Self {
        Self {
            party: state.active.as_ref().map(|active| (&active.party).into()),
            id: state
                .active
                .as_ref()
                .map(|active| active.id.to_vec())
                .unwrap_or_default(),
            known_by_peer: state
                .active
                .as_ref()
                .is_some_and(|active| active.known_by_peer),
            initial_message: state
                .active
                .as_ref()
                .map(|active| active.initial_message.clone())
                .unwrap_or_default(),
            delivery_key: state
                .active
                .as_ref()
                .map(|active| active.delivery_key.0.to_vec())
                .unwrap_or_default(),
            others: state
                .others
                .iter()
                .map(|earlier| proto::EarlierSession {
                    party: Some((&earlier.party).into()),
                    delivery_key: earlier.delivery_key.0.to_vec(),
                })
                .collect(),
            delivered: state.delivered.iter().map(|token| token.to_vec()).collect(),
            me: state.me.to_vec(),
            peer: state.peer.to_vec(),
            cursor: state.cursor,
            last: match state.last {
                LastAction::None => proto::LastAction::Unspecified,
                LastAction::Sent => proto::LastAction::Sent,
                LastAction::ReceivedActive => proto::LastAction::ReceivedActive,
                LastAction::ReceivedEarlier => proto::LastAction::ReceivedEarlier,
            }
            .into(),
            direction_changes: state.direction_changes,
            stalled_through: state.stalled_through,
            skip_through: state.skip_through,
            peer_pq: Some((&state.peer_pq).into()),
            next_session_seq: state.next_session_seq,
            active_security: state
                .active
                .as_ref()
                .map(|active| (&active.security).into()),
            active_peer_session_seq: state
                .active
                .as_ref()
                .map_or(0, |active| active.peer_session_seq),
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&proto::SessionState> for SessionState {
    type Error = Error;

    fn try_from(state: &proto::SessionState) -> Result<Self> {
        /// An identity or ephemeral key field, which must be 32 bytes.
        fn key(bytes: &[u8]) -> Result<PublicKey> {
            bytes
                .try_into()
                .map_err(|_| ErrorKind::MalformedState.into())
        }

        /// A delivery key, which must be 32 bytes.
        fn delivery_key(bytes: &[u8]) -> Result<DeliveryKey> {
            bytes
                .try_into()
                .map(DeliveryKey)
                .map_err(|_| ErrorKind::MalformedState.into())
        }

        if state.others.len() > KEPT_SESSIONS || state.delivered.len() > MAX_STORED_DELIVERED {
            return Err(ErrorKind::MalformedState.into());
        }

        let me = key(&state.me)?;
        let peer = key(&state.peer)?;

        let active = match &state.party {
            Some(proto_party) => {
                let security = match &state.active_security {
                    Some(sec) => SessionSecurity::try_from(sec)?,
                    None => SessionSecurity::classical(),
                };
                check_party_identity_ad(
                    &proto_party.associated_data,
                    &me,
                    &peer,
                    Some(security.is_pq),
                )?;
                Some(Active {
                    party: Party::try_from(proto_party)?,
                    id: key(&state.id)?,
                    known_by_peer: state.known_by_peer,
                    initial_message: state.initial_message.clone(),
                    delivery_key: delivery_key(&state.delivery_key)?,
                    security,
                    peer_session_seq: state.active_peer_session_seq,
                })
            }
            None => {
                if !state.id.is_empty()
                    || !state.delivery_key.is_empty()
                    || state.known_by_peer
                    || !state.initial_message.is_empty()
                    || state.active_peer_session_seq != 0
                    || state
                        .active_security
                        .as_ref()
                        .is_some_and(|s| s.is_pq || s.suite != 0 || s.pq_ratchet)
                {
                    return Err(ErrorKind::MalformedState.into());
                }
                None
            }
        };
        let last = match proto::LastAction::try_from(state.last) {
            Ok(proto::LastAction::Unspecified) => LastAction::None,
            Ok(proto::LastAction::Sent) => LastAction::Sent,
            Ok(proto::LastAction::ReceivedActive) => LastAction::ReceivedActive,
            Ok(proto::LastAction::ReceivedEarlier) => LastAction::ReceivedEarlier,
            Err(_) => return Err(ErrorKind::MalformedState.into()),
        };
        let peer_pq = state
            .peer_pq
            .as_ref()
            .map(PeerPqState::try_from)
            .transpose()?
            .unwrap_or_default();
        let restored = Self {
            active,
            others: state
                .others
                .iter()
                .map(|earlier| {
                    let proto_party = earlier.party.as_ref().ok_or(ErrorKind::MalformedState)?;
                    check_party_identity_ad(&proto_party.associated_data, &me, &peer, None)?;
                    Ok(Earlier {
                        party: Party::try_from(proto_party)?,
                        delivery_key: delivery_key(&earlier.delivery_key)?,
                    })
                })
                .collect::<Result<_>>()?,
            delivered: state
                .delivered
                .iter()
                .map(|token| {
                    token
                        .as_slice()
                        .try_into()
                        .map_err(|_| ErrorKind::MalformedState.into())
                })
                .collect::<Result<_>>()?,
            me,
            peer,
            cursor: state.cursor,
            last,
            direction_changes: state.direction_changes,
            stalled_through: state.stalled_through,
            skip_through: state.skip_through,
            peer_pq,
            next_session_seq: state.next_session_seq,
        };
        restored.validate()?;
        Ok(restored)
    }
}

impl<M> Session<M> {
    /// A session that begins a chat, sending on `active`.
    pub(crate) fn new(mailbox: M, active: Active, me: PublicKey, peer: PublicKey) -> Self {
        let last = if active.known_by_peer {
            // Its first message was received.
            LastAction::ReceivedActive
        } else {
            LastAction::None
        };
        Self::restore(
            mailbox,
            SessionState {
                active: Some(active),
                others: vec![],
                me,
                peer,
                cursor: 0,
                last,
                direction_changes: 0,
                stalled_through: 0,
                skip_through: 0,
                delivered: vec![],
                peer_pq: PeerPqState::default(),
                next_session_seq: 0,
            },
        )
    }

    /// A session over `mailbox`, from the `state` of an earlier one.
    pub fn restore(mailbox: M, state: SessionState) -> Self {
        Self { mailbox, state }
    }

    /// What to save to [`restore`](Session::restore) this session later. It changes with every
    /// message encrypted or received, so save it after each, before showing what was received,
    /// and before receiving again: the next fetch tells the server to delete what was received.
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// The peer's identity key.
    pub fn peer(&self) -> &PublicKey {
        &self.state.peer
    }

    /// This client's identity key.
    pub fn me(&self) -> &PublicKey {
        &self.state.me
    }

    /// Whether this session has none to send on, as the peers kept missing each other (see
    /// [`Session::keep`]) or it was [retired](Session::retire): start a new one with
    /// [`Client::start_again`] before sending.
    pub fn needs_new_session(&self) -> bool {
        self.state.active.is_none()
    }

    /// The ID of the session messages are sent on, if any, which both peers have: the X3DH
    /// ephemeral key of the one who started it. A message [encrypted](Session::encrypt) to push
    /// later can be told from one of a session that is no longer the active one, e.g. to encrypt
    /// it again on the new one.
    pub fn active_id(&self) -> Option<&PublicKey> {
        self.state.active.as_ref().map(|active| &active.id)
    }

    /// Cryptographic security level of the active session, if any.
    pub fn security(&self) -> Option<SessionSecurity> {
        self.state.security()
    }

    /// Per-peer post-quantum pinning, downgrade-detection, and anti-rollback state.
    pub fn peer_pq_state(&self) -> &PeerPqState {
        &self.state.peer_pq
    }

    /// Mutable reference to this session's per-peer post-quantum state (e.g. to approve a
    /// classical exception or inspect/clear downgrade flags).
    pub fn peer_pq_state_mut(&mut self) -> &mut PeerPqState {
        &mut self.state.peer_pq
    }

    /// Pin this peer as post-quantum capable (e.g. when opening a `#chat=...&pq=1` invite link).
    pub fn pin_peer_pq(&mut self) {
        self.state.peer_pq.pin_peer_pq();
    }

    /// Next outgoing monotonic `Hello.session_seq` for this peer (`>= 1`), without advancing it.
    pub fn next_session_seq(&self) -> u64 {
        self.state.next_session_seq.max(1)
    }

    /// Allocate and advance the next outgoing `Hello.session_seq`, saturating at
    /// [`protocol::MAX_SAFE_INTEGER`].
    pub fn allocate_session_seq(&mut self) -> u64 {
        let seq = self.next_session_seq();
        self.state.next_session_seq = seq.saturating_add(1).min(protocol::MAX_SAFE_INTEGER);
        seq
    }

    /// Highest `Hello.session_seq` observed from this peer (`0` until peer sends a positive one).
    pub fn peer_session_seq(&self) -> u64 {
        self.state.peer_pq.peer_session_seq
    }

    /// `Hello.session_seq` carried by the active peer-initiated session (`0` if none or unset).
    pub fn active_peer_session_seq(&self) -> u64 {
        self.state
            .active
            .as_ref()
            .map_or(0, |active| active.peer_session_seq)
    }

    /// Build a [`Hello`] greeting for starting a new session with this peer, automatically
    /// allocating the next monotonic outgoing `session_seq`.
    pub fn make_hello(&mut self, name: impl Into<String>, pq_config: &PqConfig) -> Hello {
        let seq = self.allocate_session_seq();
        let offered = pq_config.offered_suites();
        let pq_capable = pq_config.pq_enabled && !offered.is_empty();
        Hello {
            name: name.into(),
            pq_capable,
            max_version: if pq_capable { x3dh::PQXDH_VERSION } else { 1 },
            session_seq: seq,
            offered_suites: offered.into_iter().map(|s| u32::from(s.as_u8())).collect(),
            pq_ratchet_capable: pq_capable && pq_config.pq_ratchet_enabled,
        }
    }

    /// Validate a peer's decrypted [`Hello`] against this session's [`PeerPqState`] and active
    /// [`SessionSecurity`].
    ///
    /// When called immediately after [`Client::accept`] or `Client::accept_initial_v2` with the
    /// active peer-initiated session's own greeting (`hello.session_seq > 0` matching
    /// `active.peer_session_seq == peer_session_seq`), does not falsely flag
    /// `stale_session_seq = true` while still enforcing downgrade detection and rejecting `0` or
    /// any strictly smaller `session_seq`.
    pub fn check_peer_hello(&mut self, hello: &Hello, local_pq_enabled: bool) -> HelloCheck {
        let is_own_initial_hello = (1..=protocol::MAX_SAFE_INTEGER).contains(&hello.session_seq)
            && self.state.peer_pq.peer_session_seq == hello.session_seq
            && self.state.active.as_ref().is_some_and(|active| {
                active.known_by_peer && active.peer_session_seq == hello.session_seq
            });
        // When no active session exists (e.g. a late Hello decrypted on an earlier retired
        // session), still enforce session_seq monotonicity and PQ pinning without flagging a
        // false-positive downgrade against a nonexistent classical active session.
        let effective_security = self.security().unwrap_or(SessionSecurity {
            is_pq: true,
            suite: None,
            pq_ratchet: false,
        });
        pq::check_peer_hello_with_allow_same(
            &mut self.state.peer_pq,
            effective_security,
            hello,
            local_pq_enabled,
            is_own_initial_hello,
        )
    }

    /// Go on past the messages that receiving stopped at, as they did not decrypt, once the
    /// initial messages waiting are taken and accepted: those of that page that still do not
    /// decrypt never will, and are skipped, see [`Session::receive`].
    pub fn skip_stalled(&mut self) {
        self.state.skip_through = self.state.skip_through.max(self.state.stalled_through);
    }

    /// Retire the active session, e.g. as the peer deleted the chat, so it no longer has it:
    /// messages on it still decrypt, but none go on it; the next goes on a new one, see
    /// [`Session::needs_new_session`].
    pub fn retire(&mut self) {
        if let Some(active) = self.state.active.take() {
            self.state.archive(active.into());
        }
        self.state.last = LastAction::None;
        self.state.direction_changes = 0;
    }

    /// Discard the active session without archiving it into earlier decryption sessions (e.g. when
    /// replacing an unapproved quarantined classical session so rejected follow-ups never decrypt).
    pub fn discard_active(&mut self) {
        self.state.active = None;
        self.state.last = LastAction::None;
        self.state.direction_changes = 0;
    }

    /// Keep `older`, the chat with the same peer so far, with this session, which the peer or
    /// this client has just started. The last [`KEPT_SESSIONS`] earlier sessions are kept, only
    /// to decrypt, such as the messages the peer sent on `older` before starting this one; and
    /// they go on from the later of the two positions in the peer's queue.
    ///
    /// Of the sessions, one is active: messages are sent on it, so each peer answers the other
    /// on it and its ratchet keeps stepping, as Signal's session management (Tahini) does. An
    /// earlier session never becomes active again, as whoever stole its keys could otherwise
    /// make this client send on it again, where they read everything, though the ratchet has
    /// since locked them out of the active one. A session this client starts becomes active.
    /// One the peer starts does too, unless the active one is this client's and the peer has
    /// not answered it: then both started one at once, and the one whose ID, the X3DH ephemeral
    /// key of who started it, is higher wins, on both sides. If the peers still miss each
    /// other, e.g. as an initial message was lost or a chat deleted, the peer's messages
    /// decrypt only on earlier sessions while this client sends on the active one; after
    /// [`MAX_DIRECTION_CHANGES`] turns between the two, the active session is retired, and the
    /// next message goes on a new one, see [`Session::needs_new_session`].
    pub fn keep(&mut self, older: Session<M>) -> Result<()> {
        if older.state.me != self.state.me || older.state.peer != self.state.peer {
            return Err(ErrorKind::UnexpectedPeer.into());
        }
        let new = mem::replace(&mut self.state, older.state);
        self.merge_incoming_state(new, true).map(|_| ())
    }

    /// Merge an incoming newly accepted or locally initiated session `incoming` into `self`
    /// without swapping first.
    ///
    /// Returns `Ok(true)` if `incoming` became the active session, `Ok(false)` if `incoming` was
    /// archived as an earlier session (e.g. lost a crossed-start tie-break), or
    /// `Err(ErrorKind::StaleSession)` / `Err(ErrorKind::DowngradeDetected)` if rejected (leaving
    /// `self`'s active session intact).
    pub fn accept_replacement(&mut self, incoming: Session<M>) -> Result<bool> {
        self.accept_replacement_with_policy(incoming, true)
    }

    /// Merge a replacement using the current local PQ setting. Disabling PQ permits a
    /// classical replacement for this call without granting a persistent classical exception.
    pub fn accept_replacement_with_policy(
        &mut self,
        incoming: Session<M>,
        local_pq_enabled: bool,
    ) -> Result<bool> {
        if incoming.state.me != self.state.me || incoming.state.peer != self.state.peer {
            return Err(ErrorKind::UnexpectedPeer.into());
        }
        self.merge_incoming_state(incoming.state, local_pq_enabled)
    }

    /// Core session-replacement logic enforcing monotonic `peer_session_seq` anti-rollback,
    /// crossed-start tie-breaking, and PQ-pin downgrade defense.
    fn merge_incoming_state(
        &mut self,
        mut new: SessionState,
        local_pq_enabled: bool,
    ) -> Result<bool> {
        if new.peer_pq.peer_session_seq > protocol::MAX_SAFE_INTEGER
            || new
                .active
                .as_ref()
                .is_some_and(|a| a.peer_session_seq > protocol::MAX_SAFE_INTEGER)
        {
            return Err(ErrorKind::InvalidInitialMessage.into());
        }
        let state = &mut self.state;
        if new.peer_pq.pinned_manifest_seq == state.peer_pq.pinned_manifest_seq
            && let (Some(existing_digest), Some(incoming_digest)) = (
                state.peer_pq.pinned_manifest_digest,
                new.peer_pq.pinned_manifest_digest,
            )
            && existing_digest != incoming_digest
        {
            return Err(ErrorKind::DowngradeDetected.into());
        }
        if let Some(active) = &new.active {
            let started_here = !active.known_by_peer;
            if !started_here {
                // Enforce monotonic peer_session_seq once the peer has ever sent a positive one.
                // `session_seq == 0` is tolerated ONLY while high_water == 0 (legacy TUI compat).
                let high_water = state.peer_pq.peer_session_seq;
                let incoming_seq = active.peer_session_seq;
                if high_water > 0 && (incoming_seq == 0 || incoming_seq <= high_water) {
                    return Err(ErrorKind::StaleSession.into());
                }
                // Defense-in-depth: never let an unapproved classical peer-initiated session
                // silently overwrite a PQ-pinned session.
                if !active.security.is_pq
                    && local_pq_enabled
                    && state.peer_pq.pq_pinned
                    && !state.peer_pq.allow_classical_exception
                {
                    return Err(ErrorKind::DowngradeDetected.into());
                }
            }
        }

        state.cursor = state.cursor.max(new.cursor);
        state.stalled_through = state.stalled_through.max(new.stalled_through);
        state.skip_through = state.skip_through.max(new.skip_through);
        state.next_session_seq = state.next_session_seq.max(new.next_session_seq);
        merge_delivered(&mut state.delivered, mem::take(&mut new.delivered));
        for earlier in mem::take(&mut new.others).into_iter().rev() {
            state.archive(earlier);
        }

        // Merge per-peer PQ metadata monotonically while tracking `peer_pq_capable` according to
        // manifest sequence order so accepting a newer signed PQ-OFF manifest is not clobbered.
        let was_pq_pinned = state.peer_pq.pq_pinned;
        let was_pq_capable = state.peer_pq.peer_pq_capable;
        state.peer_pq.pq_pinned |= new.peer_pq.pq_pinned;
        if new.peer_pq.pinned_manifest_seq > state.peer_pq.pinned_manifest_seq {
            state.peer_pq.pinned_manifest_seq = new.peer_pq.pinned_manifest_seq;
            state.peer_pq.pinned_manifest_digest = new.peer_pq.pinned_manifest_digest;
            state.peer_pq.peer_pq_capable = new.peer_pq.peer_pq_capable;
        } else if new.peer_pq.pinned_manifest_seq == state.peer_pq.pinned_manifest_seq {
            if state.peer_pq.pinned_manifest_digest.is_none() {
                state.peer_pq.pinned_manifest_digest = new.peer_pq.pinned_manifest_digest;
            }
            state.peer_pq.peer_pq_capable |= new.peer_pq.peer_pq_capable;
        }
        if ((!was_pq_pinned && new.peer_pq.pq_pinned)
            || (!was_pq_capable && new.peer_pq.peer_pq_capable))
            && !new.peer_pq.allow_classical_exception
        {
            state.peer_pq.allow_classical_exception = false;
        }
        state.peer_pq.downgrade_detected |= new.peer_pq.downgrade_detected;
        state.peer_pq.peer_session_seq = state
            .peer_pq
            .peer_session_seq
            .max(new.peer_pq.peer_session_seq);

        if let Some(active) = new.active.take() {
            // One this client started is not known by the peer yet.
            let started_here = !active.known_by_peer;
            if active.security.is_pq {
                state.peer_pq.peer_pq_capable = true;
                state.peer_pq.allow_classical_exception = false;
                state.peer_pq.downgrade_detected = false;
            } else if started_here {
                state.peer_pq.allow_classical_exception |= new.peer_pq.allow_classical_exception;
                if state.peer_pq.allow_classical_exception && !state.peer_pq.peer_pq_capable {
                    state.peer_pq.downgrade_detected = false;
                }
            } else if state.peer_pq.allow_classical_exception
                && !state.peer_pq.peer_pq_capable
                && !new.peer_pq.downgrade_detected
            {
                state.peer_pq.downgrade_detected = false;
            }
            if !started_here && active.peer_session_seq > state.peer_pq.peer_session_seq {
                state.peer_pq.peer_session_seq = active.peer_session_seq;
            }
            let takes_over = started_here
                || state.active.as_ref().is_none_or(|current| {
                    current.known_by_peer
                        || match (active.security.is_pq, current.security.is_pq) {
                            (true, false) => true,
                            (false, true) => false,
                            _ => active.id > current.id,
                        }
                });
            if takes_over {
                if let Some(current) = state.active.replace(active) {
                    state.archive(current.into());
                }
                state.last = if started_here {
                    LastAction::None
                } else {
                    LastAction::ReceivedActive
                };
                state.direction_changes = 0;
                return Ok(true);
            } else {
                // Its first message decrypted, on what is now an earlier session.
                state.archive(active.into());
                state.received_earlier();
                if state.active.as_ref().is_some_and(|a| a.security.is_pq) {
                    state.peer_pq.downgrade_detected = false;
                    state.peer_pq.allow_classical_exception = false;
                }
                return Ok(false);
            }
        }
        Ok(false)
    }

    /// Decrypt `message` with the active party, or else with an earlier one, which only counts
    /// towards retiring the active one, see [`Session::keep`]; and tell which, and the message's
    /// delivery token.
    pub(crate) fn decrypt(
        &mut self,
        message: &EncryptedMessage,
    ) -> Result<(Vec<u8>, bool, [u8; DELIVERY_TOKEN_LENGTH])> {
        let state = &mut self.state;
        let mut error = None;
        // A message a session received already is told apart, as a duplicate: one pushed again,
        // e.g. as the reply to its push was lost, which the server deletes too, though it may
        // have deleted the first already, as the peer gives its token.
        let mut duplicate = None;
        // A message whose skipped key was evicted is also authenticated to a known session:
        // acknowledge its delivery token so the server deletes it, and surface it distinctly as
        // `ErrorKind::EvictedMessage` instead of stalling or hiding it as a duplicate.
        let mut evicted = None;
        if let Some(active) = &mut state.active {
            match active.party.decrypt(message) {
                Ok(content) => {
                    active.known_by_peer = true;
                    active.initial_message = vec![];
                    state.last = LastAction::ReceivedActive;
                    return Ok((content, false, active.delivery_key.token(message)));
                }
                Err(e) if e.kind() == party::error::ErrorKind::DuplicateMessage => {
                    state.delivered.push(active.delivery_key.token(message));
                    duplicate = Some(e);
                }
                Err(e) if e.kind() == party::error::ErrorKind::EvictedMessage => {
                    state.delivered.push(active.delivery_key.token(message));
                    evicted = Some(e);
                }
                Err(e) => error = Some(e),
            }
        }
        for earlier in &mut state.others {
            if duplicate.is_some() || evicted.is_some() {
                break;
            }
            match earlier.party.decrypt(message) {
                Ok(content) => {
                    let token = earlier.delivery_key.token(message);
                    state.received_earlier();
                    return Ok((content, true, token));
                }
                Err(e) if e.kind() == party::error::ErrorKind::DuplicateMessage => {
                    state.delivered.push(earlier.delivery_key.token(message));
                    duplicate = Some(e);
                }
                Err(e) if e.kind() == party::error::ErrorKind::EvictedMessage => {
                    state.delivered.push(earlier.delivery_key.token(message));
                    evicted = Some(e);
                }
                Err(_) => {}
            }
        }
        match duplicate.or(evicted).or(error) {
            Some(error) => Err(error.into()),
            None => Err(ErrorKind::Undecryptable.into()),
        }
    }
    /// Encrypt `content` for the peer, on the active session, with SHA-256 of the message's
    /// delivery token under that session's key, so that it is deleted once the peer has it,
    /// though it is pushed after another session became active.
    ///
    /// Fails with [`ErrorKind::NoSession`] if it has none, see [`Session::needs_new_session`].
    pub fn encrypt(&mut self, content: &[u8]) -> Result<Sealed> {
        let state = &mut self.state;
        let active = state.active.as_mut().ok_or(ErrorKind::NoSession)?;
        let message = active.party.encrypt(content)?;
        let delivery_hash = Sha256::digest(active.delivery_key.token(&message)).into();
        if state.last == LastAction::ReceivedEarlier {
            state.direction_changes = state.direction_changes.saturating_add(1);
        }
        state.last = LastAction::Sent;
        Ok(Sealed {
            message,
            delivery_hash: Some(delivery_hash),
        })
    }

    pub(crate) async fn receive_pages<E: MailboxEnvelope, R>(
        &mut self,
        fetch: impl AsyncFn(&M, FetchRequest) -> Result<Vec<E>>,
        entry: impl Fn(Result<Vec<u8>>, bool, Vec<E::Initial>) -> R,
    ) -> Result<Vec<R>> {
        let mut expired_pages = 0;
        // An all-expired page can lead to another fetch in this call. Stage its progress
        // until the last page validates, so a bad continuation also leaves the state intact.
        let mut cursor = self.state.cursor;
        let mut acknowledged = 0;
        let received = 'pages: loop {
            let after = cursor;
            let delivered = &self.state.delivered[acknowledged..];
            let told = delivered.len().min(MAX_DELIVERED);
            let request = FetchRequest {
                sender: Bytes::copy_from_slice(&self.state.peer),
                recipient: Bytes::copy_from_slice(&self.state.me),
                after: cursor,
                limit: MAX_RECEIVE_PAGE,
                delivered: delivered[..told]
                    .iter()
                    .map(|token| Bytes::copy_from_slice(token))
                    .collect(),
            };
            let page = fetch(&self.mailbox, request).await?;
            let after_drain = delivered.len().saturating_sub(told);
            let receipts_fit = after_drain
                .checked_add(page.len())
                .is_some_and(|n| n <= MAX_STORED_DELIVERED || n < delivered.len());
            if page.len() > MAX_RECEIVE_PAGE as usize || !receipts_fit {
                return Err(ErrorKind::Protocol.into());
            }
            let mut prev = cursor;
            for envelope in &page {
                let seq = envelope.sequence();
                if seq <= prev || seq > protocol::MAX_SAFE_INTEGER {
                    return Err(ErrorKind::Protocol.into());
                }
                prev = seq;
            }
            acknowledged += told;

            let mut received = Vec::with_capacity(page.len());
            let mut carried = Vec::new();
            let mut envelopes = page.into_iter();
            while let Some(envelope) = envelopes.next() {
                let sequence = envelope.sequence();
                let (message, initial) = envelope.into_parts();
                let Some(message) = message else {
                    if !carry_initial(&mut carried, initial) {
                        break;
                    }
                    cursor = sequence;
                    continue;
                };

                // A page with a message always returns a result. Free the acknowledged
                // capacity before decrypting, which can itself enqueue a receipt.
                if acknowledged != 0 {
                    self.state.delivered.drain(..mem::take(&mut acknowledged));
                }
                let decrypted = self.decrypt(&message);
                if sequence > self.state.skip_through
                    && decrypted.as_ref().is_err_and(|e| {
                        !matches!(
                            e.kind(),
                            ErrorKind::DuplicateMessage | ErrorKind::EvictedMessage
                        )
                    })
                {
                    if !carry_initial(&mut carried, initial) {
                        break;
                    }
                    // Only offer to skip envelopes whose carried initials were surfaced.
                    self.state.stalled_through = sequence;
                    for next in envelopes {
                        let next_sequence = next.sequence();
                        if !carry_initial(&mut carried, next.into_parts().1) {
                            break;
                        }
                        self.state.stalled_through = next_sequence;
                    }
                    received.push(entry(Err(ErrorKind::Stalled.into()), false, carried));
                    break 'pages received;
                }

                cursor = sequence;
                let earlier = decrypted.as_ref().is_ok_and(|(_, earlier, _)| *earlier);
                // decrypt() already queues the tokens of duplicate and evicted messages.
                if let Ok((_, _, token)) = &decrypted {
                    self.state.delivered.push(*token);
                }
                received.push(entry(
                    decrypted.map(|(content, ..)| content),
                    earlier,
                    initial.into_iter().collect(),
                ));
            }
            if !carried.is_empty() {
                received.push(entry(Err(ErrorKind::Expired.into()), false, carried));
            }
            if !received.is_empty() || cursor == after {
                break received;
            }
            expired_pages += 1;
            if expired_pages == MAX_EXPIRED_PAGES {
                break received;
            }
        };
        self.state.cursor = cursor;
        self.state.delivered.drain(..acknowledged);
        Ok(received)
    }
}

#[allow(deprecated)]
impl<M: LocalMailbox> Session<M> {
    /// Encrypt `content` and push it to the peer.
    ///
    /// If pushing fails the message is lost; to retry instead, use [`Session::encrypt`] and
    /// [`Session::push`].
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub async fn send(&mut self, content: &[u8]) -> Result<()> {
        let message = self.encrypt(content)?;
        self.push(message).await
    }

    /// Push a message encrypted for the peer; it can be pushed again if this fails. While the
    /// peer is not known to have the active session, the initial message that started it goes
    /// with it, in case the one in the peer's inbox was lost.
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub async fn push(&mut self, sealed: Sealed) -> Result<()> {
        self.mailbox.push(self.push_request(sealed)).await?;
        Ok(())
    }

    /// The request [`push`](Session::push) makes for `sealed`, to push later, e.g. once this
    /// session is gone, as when telling the peer that the chat was deleted.
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub fn push_request(&self, sealed: Sealed) -> PushRequest {
        let initial_message = self
            .state
            .active
            .as_ref()
            .filter(|active| !active.initial_message.is_empty())
            .and_then(|active| {
                handshake::InitialMessage::decode(active.initial_message.as_slice()).ok()
            });
        PushRequest {
            sender: Bytes::copy_from_slice(&self.state.me),
            recipient: Bytes::copy_from_slice(&self.state.peer),
            message: Some(sealed.message),
            initial_message,
            delivery_hash: sealed
                .delivery_hash
                .map_or_else(Bytes::new, |hash| Bytes::copy_from_slice(&hash)),
        }
    }

    /// Fetch the next page of the peer's messages and decrypt them: one result per message, in
    /// order. Returns an empty page once there are no new messages.
    ///
    /// A message is tried on the earlier sessions [kept](Session::keep) too. One that does not
    /// decrypt may be on a session whose initial message is waiting, as it reached the server
    /// first, but came after the initial messages were last taken: receiving stops there, the
    /// page ending with an [`ErrorKind::Stalled`] error, and leaves it for later. Take and accept
    /// the initial messages, then [`skip_stalled`](Session::skip_stalled) and receive again: what
    /// of that page still does not decrypt never will, and is skipped, so that it cannot block
    /// the messages after it. A message whose content expired on the server before it was
    /// fetched is gone past, as one lost: carried initial messages are returned at the end of the page with
    /// [`ErrorKind::Expired`]. Empty expired pages are skipped up to a bounded number per call.
    ///
    /// The fetch tells the server which messages the last receive got, with their delivery
    /// tokens, so that it deletes them: save the [state](Session::state) after each receive,
    /// before the next, as the messages are on the server until then.
    ///
    /// Cancel-safe: if the future is dropped, no message is consumed, but those whose contents
    /// expired.
    #[deprecated(
        note = "legacy v1 protocol is deprecated; use v2 methods; see git tag archive/legacy-v1"
    )]
    pub async fn receive(&mut self) -> Result<Vec<Received>> {
        self.receive_pages(
            async |mailbox, request| Ok(mailbox.fetch(request).await?.messages),
            |content, earlier, initial_messages| Received {
                content,
                earlier,
                initial_messages,
            },
        )
        .await
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod test {
    use core::cell::Cell;
    use protocol::{
        attachment::AttachmentServer,
        handshake::{
            FetchBundleResponse, HandshakeServer, PublishResponse, SendInitialMessageResponse,
            TakeInitialMessagesResponse,
        },
        mailbox::{FetchResponse, MailboxLimits, MailboxServer, PushResponse},
    };

    use storage::MemoryStore;

    use super::*;

    /// Lets several clients share one in-process handshake server.
    #[derive(Debug)]
    struct InProcessHandshake<'a>(&'a HandshakeServer<MemoryStore>);

    impl LocalHandshake for InProcessHandshake<'_> {
        async fn publish(&self, request: PublishRequest) -> protocol::Result<PublishResponse> {
            self.0.publish(request).await
        }

        async fn fetch_bundle(
            &self,
            request: FetchBundleRequest,
        ) -> protocol::Result<FetchBundleResponse> {
            self.0.fetch_bundle(request).await
        }

        async fn send_initial_message(
            &self,
            request: SendInitialMessageRequest,
        ) -> protocol::Result<SendInitialMessageResponse> {
            self.0.send_initial_message(request).await
        }

        async fn take_initial_messages(
            &self,
            request: TakeInitialMessagesRequest,
        ) -> protocol::Result<TakeInitialMessagesResponse> {
            self.0.take_initial_messages(request).await
        }
    }

    /// Lets several sessions share one in-process mailbox server.
    #[derive(Debug, Clone)]
    struct InProcessMailbox<'a>(&'a MailboxServer<MemoryStore>);

    impl LocalMailbox for InProcessMailbox<'_> {
        async fn push(&self, request: PushRequest) -> protocol::Result<PushResponse> {
            self.0.push(request).await
        }

        async fn fetch(&self, request: FetchRequest) -> protocol::Result<FetchResponse> {
            self.0.fetch(request).await
        }
    }

    /// A mailbox whose message `expired`, a sequence number, comes without its content, as the
    /// server's storage deleted it.
    struct Expiring<'a>(&'a MailboxServer<MemoryStore>, u64);

    impl LocalMailbox for Expiring<'_> {
        async fn push(&self, request: PushRequest) -> protocol::Result<PushResponse> {
            self.0.push(request).await
        }

        async fn fetch(&self, request: FetchRequest) -> protocol::Result<FetchResponse> {
            let mut response = self.0.fetch(request).await?;
            for envelope in &mut response.messages {
                if envelope.sequence == self.1 {
                    envelope.message = None;
                }
            }
            Ok(response)
        }
    }

    #[tokio::test]
    async fn a_message_expired_on_the_server_is_gone_past() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (_alice, mut alice_session, _bob, bob_session) = talking(&handshake, &mailbox).await;
        for content in [b"a", b"b", b"c"] {
            alice_session.send(content).await.unwrap();
        }
        // "b", the second of Alice's queue after her greeting, which went with her initial
        // message, comes without its content.
        let mut bob_session = Session::restore(Expiring(&mailbox, 2), bob_session.state);
        assert_eq!(contents(bob_session.receive().await.unwrap()), [b"a", b"c"]);
        assert!(bob_session.receive().await.unwrap().is_empty());
    }

    #[derive(Default)]
    struct ScriptedMailbox {
        page: Vec<Envelope>,
        ignore_cursor: bool,
        fail_after: Option<u64>,
        fetches: Cell<usize>,
    }

    impl ScriptedMailbox {
        fn page_after(&self, after: u64) -> protocol::Result<Vec<Envelope>> {
            self.fetches.set(self.fetches.get() + 1);
            if self.fail_after == Some(after) {
                return Err(protocol::ErrorKind::Connect.into());
            }
            Ok(self
                .page
                .iter()
                .filter(|e| self.ignore_cursor || e.sequence > after)
                .cloned()
                .collect())
        }
    }

    impl LocalMailbox for ScriptedMailbox {
        async fn fetch(&self, req: FetchRequest) -> protocol::Result<FetchResponse> {
            assert_eq!(req.limit, 100);
            Ok(FetchResponse {
                messages: self.page_after(req.after)?,
            })
        }

        async fn push(&self, _: PushRequest) -> protocol::Result<PushResponse> {
            unreachable!()
        }
    }

    impl protocol::mailbox_v2::LocalMailboxV2 for ScriptedMailbox {
        async fn fetch_signed(
            &self,
            req: protocol::mailbox_v2::FetchSignedRequest,
        ) -> protocol::Result<protocol::mailbox_v2::FetchSignedResponse> {
            assert_eq!(req.limit, 100);
            Ok(protocol::mailbox_v2::FetchSignedResponse {
                messages: self
                    .page_after(req.after)?
                    .into_iter()
                    .map(|e| protocol::mailbox_v2::EnvelopeV2 {
                        sequence: e.sequence,
                        message: e.message,
                        initial_message: e.initial_message.as_ref().map(Into::into),
                    })
                    .collect(),
            })
        }

        async fn push_v2(
            &self,
            _: protocol::mailbox_v2::PushV2Request,
        ) -> protocol::Result<protocol::mailbox_v2::PushV2Response> {
            unreachable!()
        }
    }

    #[derive(Clone, Copy)]
    enum MailboxVersion {
        V1,
        V2,
    }

    impl MailboxVersion {
        const ALL: &[Self] = &[Self::V1, Self::V2];

        async fn receive(
            self,
            session: &mut Session<ScriptedMailbox>,
            client: &Client<()>,
        ) -> Result<Vec<Received>> {
            match self {
                Self::V1 => session.receive().await,
                Self::V2 => Ok(session
                    .receive_v2(client, "relay.example")
                    .await?
                    .into_iter()
                    .map(|r| Received {
                        content: r.content,
                        earlier: r.earlier,
                        initial_messages: r
                            .initial_messages
                            .into_iter()
                            .map(|im| {
                                let InitialMessageKind::Classical(m) = im.kind else {
                                    panic!("expected classical fixture")
                                };
                                m
                            })
                            .collect(),
                    })
                    .collect()),
            }
        }
    }

    async fn scripted_mailbox() -> (Client<()>, Session<ScriptedMailbox>, EncryptedMessage) {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (_, mut sender, bob, session) = talking(&handshake, &mailbox).await;
        let message = sender.encrypt(b"message").unwrap().message;
        (
            Client::restore((), bob.state),
            Session::restore(ScriptedMailbox::default(), session.state),
            message,
        )
    }

    fn expired_page() -> Vec<Envelope> {
        (1u8..=100)
            .map(|id| Envelope {
                sequence: u64::from(id),
                message: None,
                initial_message: (id <= 70).then(|| handshake::InitialMessage {
                    identity_key: Bytes::from_static(&[1; 32]),
                    ephemeral_key: Bytes::from(vec![id; 32]),
                    signed_prekey: Bytes::from_static(&[3; 32]),
                    one_time_prekey: None,
                    first_message: Some(EncryptedMessage::default()),
                }),
            })
            .collect()
    }

    fn carried_ids(result: &Received, kind: ErrorKind) -> Vec<u8> {
        assert_eq!(result.content.as_ref().unwrap_err().kind(), kind);
        result
            .initial_messages
            .iter()
            .map(|im| im.x3dh.ephemeral_key[0])
            .collect()
    }

    #[tokio::test]
    async fn invalid_pages_preserve_receipts_cursor_and_ratchet() {
        for version in MailboxVersion::ALL {
            let (bob, mut session, message) = scripted_mailbox().await;
            session.state.cursor = 5;
            session.state.stalled_through = 7;
            session.mailbox.ignore_cursor = true;
            let token = [5; DELIVERY_TOKEN_LENGTH];
            // Oversized pages (> MAX_RECEIVE_PAGE) and non-monotonic or out-of-range sequences
            // must be rejected without mutating cursor, stall markers, or queued receipts.
            for (sequences, receipt_count) in [
                ((6..=106).collect::<Vec<_>>(), MAX_STORED_DELIVERED),
                (vec![5], 1),
                (vec![4], 1),
                (vec![6, 6], 1),
                (vec![7, 6], 1),
                (vec![6, protocol::MAX_SAFE_INTEGER + 1], 1),
            ] {
                session.mailbox.page = sequences
                    .into_iter()
                    .map(|sequence| Envelope {
                        sequence,
                        message: None,
                        initial_message: None,
                    })
                    .collect();
                // Even an authentic message at the front must remain decryptable on retry.
                if session.mailbox.page[0].sequence > session.state.cursor {
                    session.mailbox.page[0].message = Some(message.clone());
                }
                let receipts = vec![token; receipt_count];
                session.state.delivered.clone_from(&receipts);
                assert_eq!(
                    version
                        .receive(&mut session, &bob)
                        .await
                        .unwrap_err()
                        .kind(),
                    ErrorKind::Protocol
                );
                assert_eq!(
                    (session.state.cursor, session.state.stalled_through),
                    (5, 7)
                );
                assert_eq!(session.state.delivered, receipts);
            }
            session.state.delivered = vec![token; MAX_STORED_DELIVERED];
            session.mailbox.page = vec![Envelope {
                sequence: 6,
                message: Some(message),
                initial_message: None,
            }];
            assert_eq!(
                contents(version.receive(&mut session, &bob).await.unwrap()),
                [b"message"]
            );
            assert_eq!(
                session.state.delivered.len(),
                MAX_STORED_DELIVERED - MAX_DELIVERED + 1
            );
        }
    }

    #[tokio::test]
    async fn merging_two_large_delivered_queues_deduplicates_caps_and_drains() {
        let token = |n: u32| {
            let mut out = [0u8; DELIVERY_TOKEN_LENGTH];
            out[..4].copy_from_slice(&n.to_be_bytes());
            out
        };

        // 1. Merging two disjoint 3,000-receipt sessions via `Session::keep` caps `delivered` to
        //    `MAX_STORED_DELIVERED` (4,096), retaining the most recent tokens in order.
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;
        let mut newer = alice
            .initiate(&bob.identity_key(), b"again", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        let initial = bob.take_initial_messages().await.unwrap();
        let (mut bob_newer, _) = bob
            .accept(
                &alice.identity_key(),
                &initial[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();

        bob_session.state.delivered = (0u32..3000).map(token).collect();
        bob_newer.state.delivered = (3000u32..6000).map(token).collect();
        bob_newer.keep(bob_session).unwrap();

        let expected_start = 6000u32 - MAX_STORED_DELIVERED as u32;
        assert_eq!(bob_newer.state.delivered.len(), MAX_STORED_DELIVERED);
        assert_eq!(bob_newer.state.delivered[0], token(expected_start));
        assert_eq!(*bob_newer.state.delivered.last().unwrap(), token(5999));
        // Receiving on the merged session succeeds immediately and drains `MAX_DELIVERED`.
        newer.send(b"after-merge").await.unwrap();
        assert_eq!(
            contents(bob_newer.receive().await.unwrap()),
            [b"after-merge"]
        );
        assert_eq!(
            bob_newer.state.delivered.len(),
            MAX_STORED_DELIVERED - MAX_DELIVERED + 1
        );
        let _ = &mut alice_session;

        // 2. Overlapping receipts are deduplicated before capping so unique tokens are preserved.
        let mut existing: Vec<_> = (0u32..3000).map(token).collect();
        let incoming: Vec<_> = (1500u32..4500).map(token).collect();
        merge_delivered(&mut existing, incoming);
        assert_eq!(existing.len(), MAX_STORED_DELIVERED);
        assert_eq!(existing[0], token(4500 - MAX_STORED_DELIVERED as u32));
        assert_eq!(*existing.last().unwrap(), token(4499));
    }

    #[tokio::test]
    async fn over_capacity_delivered_queue_drains_without_wedging_receive() {
        for version in MailboxVersion::ALL {
            let (bob, mut session, message) = scripted_mailbox().await;
            let token = [9u8; DELIVERY_TOKEN_LENGTH];
            // Even if pre-existing `delivered` is far above `MAX_STORED_DELIVERED + MAX_DELIVERED`,
            // receiving MUST drain `MAX_DELIVERED` per batch instead of wedging permanently.
            let initial_len = MAX_STORED_DELIVERED + MAX_DELIVERED + 500;
            session.state.delivered = vec![token; initial_len];
            session.mailbox.page = vec![Envelope {
                sequence: 1,
                message: Some(message),
                initial_message: None,
            }];
            assert_eq!(
                contents(version.receive(&mut session, &bob).await.unwrap()),
                [b"message"]
            );
            assert_eq!(
                session.state.delivered.len(),
                initial_len - MAX_DELIVERED + 1
            );

            // Subsequent empty fetches continue draining cleanly back below `MAX_STORED_DELIVERED`.
            session.mailbox.page.clear();
            while session.state.delivered.len() > MAX_STORED_DELIVERED {
                let before = session.state.delivered.len();
                assert!(
                    version
                        .receive(&mut session, &bob)
                        .await
                        .unwrap()
                        .is_empty()
                );
                assert_eq!(session.state.delivered.len(), before - MAX_DELIVERED);
            }
            assert!(session.state.delivered.len() <= MAX_STORED_DELIVERED);
        }
    }

    #[tokio::test]
    async fn a_bad_continuation_preserves_progress_from_before_the_fetch() {
        for version in MailboxVersion::ALL {
            let (bob, mut session, _) = scripted_mailbox().await;
            let receipts = vec![[7; DELIVERY_TOKEN_LENGTH]; MAX_DELIVERED + 1];
            session.state.delivered.clone_from(&receipts);
            session.mailbox.page = vec![Envelope {
                sequence: 1,
                ..Default::default()
            }];
            session.mailbox.ignore_cursor = true;
            assert_eq!(
                version
                    .receive(&mut session, &bob)
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::Protocol
            );
            assert_eq!(session.mailbox.fetches.get(), 2);
            assert_eq!(session.state.cursor, 0);
            assert_eq!(session.state.delivered, receipts);
        }
    }

    #[tokio::test]
    async fn expired_initial_is_returned_before_a_later_fetch_error() {
        for version in MailboxVersion::ALL {
            let (bob, mut session, _) = scripted_mailbox().await;
            session.mailbox.page = expired_page();
            session.mailbox.page.truncate(1);
            session.mailbox.fail_after = Some(1);
            let received = version.receive(&mut session, &bob).await.unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(carried_ids(&received[0], ErrorKind::Expired), [1]);
            assert_eq!(session.mailbox.fetches.get(), 1);
            assert_eq!(
                version
                    .receive(&mut session, &bob)
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::Server
            );
            assert_eq!(session.mailbox.fetches.get(), 2);
        }
    }

    #[tokio::test]
    async fn expired_and_stalled_carried_initials_resume_at_the_first_one_that_did_not_fit() {
        for version in MailboxVersion::ALL {
            for first_stall in [None, Some(1), Some(65)] {
                let (bob, mut session, _) = scripted_mailbox().await;
                session.mailbox.page = expired_page();
                if let Some(sequence) = first_stall {
                    for env in &mut session.mailbox.page {
                        if env.sequence >= sequence {
                            env.message = Some(EncryptedMessage::default());
                        }
                    }
                }
                let received = version.receive(&mut session, &bob).await.unwrap();
                assert_eq!(received.len(), 1);
                let stalled = first_stall == Some(1);
                let kind = if stalled {
                    ErrorKind::Stalled
                } else {
                    ErrorKind::Expired
                };
                assert_eq!(
                    carried_ids(&received[0], kind),
                    (1..=64).collect::<Vec<_>>()
                );
                assert_eq!(
                    (session.state.cursor, session.state.stalled_through),
                    if stalled { (0, 64) } else { (64, 0) }
                );
                session.skip_stalled();
                let next = version.receive(&mut session, &bob).await.unwrap();
                let kind = if first_stall.is_some() {
                    ErrorKind::Stalled
                } else {
                    ErrorKind::Expired
                };
                assert_eq!(
                    carried_ids(next.last().unwrap(), kind),
                    (65..=70).collect::<Vec<_>>()
                );
                if first_stall.is_some() {
                    assert_eq!(
                        (session.state.cursor, session.state.stalled_through),
                        (64, 100)
                    );
                } else {
                    assert_eq!(session.state.cursor, 100);
                }
            }
        }
    }

    /// A mailbox that answers every fetch with the same expired message, as a faulty server may.
    struct Repeating(Cell<usize>);

    impl LocalMailbox for Repeating {
        async fn push(&self, _request: PushRequest) -> protocol::Result<PushResponse> {
            Ok(PushResponse::default())
        }

        async fn fetch(&self, _request: FetchRequest) -> protocol::Result<FetchResponse> {
            self.0.set(self.0.get() + 1);
            Ok(FetchResponse {
                messages: vec![Envelope::default()],
            })
        }
    }

    #[tokio::test]
    async fn sequence_limits_survive_allocation_and_replacement() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, _, mut bob, mut session) = talking(&handshake, &mailbox).await;
        session.state.next_session_seq = protocol::MAX_SAFE_INTEGER - 1;
        for expected in [
            protocol::MAX_SAFE_INTEGER - 1,
            protocol::MAX_SAFE_INTEGER,
            protocol::MAX_SAFE_INTEGER,
        ] {
            assert_eq!(session.allocate_session_seq(), expected);
            assert_eq!(session.next_session_seq(), protocol::MAX_SAFE_INTEGER);
        }
        let id = *session.active_id().unwrap();
        for invalid_active in [true, false] {
            alice
                .initiate(&bob.identity_key(), b"next", ())
                .await
                .unwrap();
            let inbox = bob.take_initial_messages().await.unwrap();
            let (mut incoming, _) = bob
                .accept(&alice.identity_key(), &inbox[0], InProcessMailbox(&mailbox))
                .unwrap();
            if invalid_active {
                incoming.state.active.as_mut().unwrap().peer_session_seq =
                    protocol::MAX_SAFE_INTEGER + 1;
            } else {
                incoming.state.peer_pq.peer_session_seq = protocol::MAX_SAFE_INTEGER + 1;
            }
            assert_eq!(
                session.accept_replacement(incoming).unwrap_err().kind(),
                ErrorKind::InvalidInitialMessage
            );
            assert_eq!(session.active_id(), Some(&id));
            assert_eq!(session.peer_session_seq(), 0);
        }
    }

    #[tokio::test]
    async fn a_repeated_expired_sequence_is_refused_after_one_fetch() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (_alice, _alice_session, _bob, bob_session) = talking(&handshake, &mailbox).await;
        let mut bob_session = Session::restore(Repeating(Cell::new(0)), bob_session.state);
        assert_eq!(
            bob_session.receive().await.unwrap_err().kind(),
            ErrorKind::Protocol
        );
        assert_eq!(bob_session.mailbox.0.get(), 1);
    }

    #[tokio::test]
    async fn a_page_of_expired_messages_is_not_the_end() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        // A message a page, so that the first page holds only the one expired.
        let limits = MailboxLimits {
            max_fetch: 1,
            ..MailboxLimits::default()
        };
        let mailbox = MailboxServer::builder(MemoryStore::default())
            .limits(limits)
            .build();
        let (_alice, mut alice_session, _bob, bob_session) = talking(&handshake, &mailbox).await;
        for content in [b"a", b"b"] {
            alice_session.send(content).await.unwrap();
        }
        let mut bob_session = Session::restore(Expiring(&mailbox, 1), bob_session.state);
        assert_eq!(contents(bob_session.receive().await.unwrap()), [b"b"]);
        assert!(bob_session.receive().await.unwrap().is_empty());
    }

    /// The messages on the server from `sender` to `recipient`.
    async fn queued(
        mailbox: &MailboxServer<MemoryStore>,
        sender: &PublicKey,
        recipient: &PublicKey,
    ) -> usize {
        let request = FetchRequest {
            sender: Bytes::copy_from_slice(sender),
            recipient: Bytes::copy_from_slice(recipient),
            after: 0,
            limit: 0,
            delivered: vec![],
        };
        mailbox.fetch(request).await.unwrap().messages.len()
    }

    #[tokio::test]
    async fn delivered_messages_leave_the_server() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (alice, mut alice_session, bob, mut bob_session) = talking(&handshake, &mailbox).await;
        let (alice, bob) = (alice.identity_key(), bob.identity_key());
        // Alice received Bob's "hello", and has not fetched since: it is still there.
        assert_eq!(queued(&mailbox, &bob, &alice).await, 1);
        assert!(alice_session.receive().await.unwrap().is_empty());
        assert_eq!(queued(&mailbox, &bob, &alice).await, 0);

        for content in [b"a", b"b"] {
            alice_session.send(content).await.unwrap();
        }
        assert_eq!(contents(bob_session.receive().await.unwrap()), [b"a", b"b"]);
        // Until Bob fetches again, having saved what he received, they stay; through a saved
        // state too.
        assert_eq!(queued(&mailbox, &alice, &bob).await, 2);
        #[cfg(feature = "prost")]
        let mut bob_session = Session::restore(
            InProcessMailbox(&mailbox),
            restored::<SessionState, proto::SessionState>(&bob_session.state),
        );
        assert!(bob_session.receive().await.unwrap().is_empty());
        assert_eq!(queued(&mailbox, &alice, &bob).await, 0);

        // One that decrypts only on an earlier session goes too.
        alice_session.send(b"late").await.unwrap();
        bob_session.retire();
        assert_eq!(contents(bob_session.receive().await.unwrap()), [b"late"]);
        assert!(bob_session.receive().await.unwrap().is_empty());
        assert_eq!(queued(&mailbox, &alice, &bob).await, 0);
    }

    #[tokio::test]
    async fn a_message_pushed_after_the_session_changed_goes_once_delivered() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, bob_session) =
            talking(&handshake, &mailbox).await;
        let (alice_key, bob_key) = (alice.identity_key(), bob.identity_key());
        // Alice encrypts while offline; meanwhile Bob starts the chat again, and Alice takes his
        // session, which becomes the one she sends on, before her message goes.
        let waiting = alice_session.encrypt(b"waiting").unwrap();
        alice.publish_keys(3).await.unwrap();
        let mut bob_session = {
            let mut again = bob
                .initiate(&alice_key, b"again", InProcessMailbox(&mailbox))
                .await
                .unwrap();
            again.keep(bob_session).unwrap();
            again
        };
        let first = accept_keeping(&mut alice, &bob_key, &mut alice_session, &mailbox).await;
        assert_eq!(first, b"again");
        alice_session.push(waiting).await.unwrap();
        // Bob reads it on the earlier session; its token, under that session's key, deletes it.
        assert_eq!(contents(receive_all(&mut bob_session).await), [b"waiting"]);
        assert_eq!(queued(&mailbox, &alice_key, &bob_key).await, 1);
        assert!(bob_session.receive().await.unwrap().is_empty());
        assert_eq!(queued(&mailbox, &alice_key, &bob_key).await, 0);
    }

    #[tokio::test]
    async fn a_copy_pushed_after_the_first_was_delivered_goes_too() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (alice, mut alice_session, bob, mut bob_session) = talking(&handshake, &mailbox).await;
        let (alice, bob) = (alice.identity_key(), bob.identity_key());
        let sealed = alice_session.encrypt(b"twice").unwrap();
        alice_session.push(sealed.clone()).await.unwrap();
        assert_eq!(contents(bob_session.receive().await.unwrap()), [b"twice"]);
        assert!(bob_session.receive().await.unwrap().is_empty());
        assert_eq!(queued(&mailbox, &alice, &bob).await, 0);
        // Pushed again, as the reply to the first push was lost, after Bob had it: a duplicate,
        // which goes too.
        alice_session.push(sealed).await.unwrap();
        let received = bob_session.receive().await.unwrap();
        assert_eq!(
            received[0].content.as_ref().unwrap_err().kind(),
            ErrorKind::DuplicateMessage
        );
        assert!(bob_session.receive().await.unwrap().is_empty());
        assert_eq!(queued(&mailbox, &alice, &bob).await, 0);
    }

    /// `state` saved as a protobuf message, and read back.
    #[cfg(feature = "prost")]
    fn restored<T, P>(state: &T) -> T
    where
        P: prost::Message + Default + for<'a> From<&'a T>,
        T: for<'a> TryFrom<&'a P, Error = Error>,
    {
        let saved = P::from(state).encode_to_vec();
        T::try_from(&P::decode(saved.as_slice()).unwrap()).unwrap()
    }

    fn contents(received: Vec<Received>) -> Vec<Vec<u8>> {
        received
            .into_iter()
            .map(|received| received.content.unwrap())
            .collect()
    }

    /// Receive as a client does once it has taken the initial messages: past what receiving
    /// stalls at, which then never decrypts.
    async fn receive_all<M: LocalMailbox>(session: &mut Session<M>) -> Vec<Received> {
        let mut received = session.receive().await.unwrap();
        if let Some(Received {
            content: Err(e), ..
        }) = received.last()
            && e.kind() == ErrorKind::Stalled
        {
            received.pop();
            session.skip_stalled();
            received.extend(session.receive().await.unwrap());
        }
        received
    }

    #[tokio::test]
    async fn alice_and_bob_talk() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let mut alice = Client::new(InProcessHandshake(&handshake));
        let mut bob = Client::new(InProcessHandshake(&handshake));

        bob.publish_keys(1).await.unwrap();
        let mut alice_session = alice
            .initiate(&bob.identity_key(), b"hi", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        alice_session.send(b"bob").await.unwrap();

        let initial_messages = bob.take_initial_messages().await.unwrap();
        assert_eq!(initial_messages.len(), 1);
        let (mut bob_session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"hi");

        assert_eq!(
            contents(receive_all(&mut bob_session).await),
            [b"bob".to_vec()]
        );
        assert!(receive_all(&mut bob_session).await.is_empty());

        bob_session.send(b"hello").await.unwrap();
        assert_eq!(
            contents(receive_all(&mut alice_session).await),
            [b"hello".to_vec()]
        );

        // A message encrypted but pushed later still arrives, after the ones pushed before it.
        let late = alice_session.encrypt(b"late").unwrap();
        alice_session.send(b"early").await.unwrap();
        alice_session.push(late).await.unwrap();
        assert_eq!(
            contents(receive_all(&mut bob_session).await),
            [b"early".to_vec(), b"late".to_vec()]
        );
    }

    /// Alice and Bob, who talked already: she started with "hi" and he replied "hello".
    async fn talking<'a>(
        handshake: &'a HandshakeServer<MemoryStore>,
        mailbox: &'a MailboxServer<MemoryStore>,
    ) -> (
        Client<InProcessHandshake<'a>>,
        Session<InProcessMailbox<'a>>,
        Client<InProcessHandshake<'a>>,
        Session<InProcessMailbox<'a>>,
    ) {
        let mut alice = Client::new(InProcessHandshake(handshake));
        let mut bob = Client::new(InProcessHandshake(handshake));
        bob.publish_keys(3).await.unwrap();
        let mut alice_session = alice
            .initiate(&bob.identity_key(), b"hi", InProcessMailbox(mailbox))
            .await
            .unwrap();
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (mut bob_session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(mailbox),
            )
            .unwrap();
        assert_eq!(first, b"hi");
        bob_session.send(b"hello").await.unwrap();
        assert_eq!(contents(receive_all(&mut alice_session).await), [b"hello"]);
        (alice, alice_session, bob, bob_session)
    }

    #[tokio::test]
    async fn forged_initial_messages_are_refused() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, _alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Alice starts again, then Mallory sends Bob more initial messages claiming to be hers
        // than he keeps sessions.
        let mut alice_again = alice
            .initiate(&bob.identity_key(), b"again", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        let mut mallory = Client::new(InProcessHandshake(&handshake));
        for _ in 0..=KEPT_SESSIONS {
            mallory
                .initiate(&bob.identity_key(), b"it is me", InProcessMailbox(&mailbox))
                .await
                .unwrap();
        }
        let mut initial_messages = bob.take_initial_messages().await.unwrap();
        for initial_message in &mut initial_messages[1..] {
            initial_message.x3dh.identity_key = alice.identity_key();
        }

        // Each tried twice: only Alice's is accepted, once, and the others fail both times, as
        // they use up nothing.
        let mut accepted = vec![];
        for initial_message in &initial_messages {
            for _ in 0..2 {
                match bob.accept(
                    &alice.identity_key(),
                    initial_message,
                    InProcessMailbox(&mailbox),
                ) {
                    Ok(session) => accepted.push(session),
                    Err(e) => assert_eq!(e.kind(), ErrorKind::InvalidInitialMessage),
                }
            }
        }
        assert_eq!(accepted.len(), 1);
        let (session, first) = accepted.pop().unwrap();
        assert_eq!(first, b"again");
        let older = mem::replace(&mut bob_session, session);
        bob_session.keep(older).unwrap();

        alice_again.send(b"on the new one").await.unwrap();
        assert_eq!(
            contents(receive_all(&mut bob_session).await),
            [b"on the new one"]
        );
        bob_session.send(b"me too").await.unwrap();
        let received = receive_all(&mut alice_again).await;
        // Her new session reads her queue from the start, where his reply to the old one is.
        assert!(received[0].content.is_err());
        assert_eq!(received[1].content.as_ref().unwrap(), b"me too");
    }

    #[tokio::test]
    async fn a_new_session_takes_over_at_once() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Alice sends on her session, then starts again before Bob receives.
        alice_session.send(b"old").await.unwrap();
        let mut alice_again = alice
            .initiate(&bob.identity_key(), b"new", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"new");
        let older = mem::replace(&mut bob_session, session);
        bob_session.keep(older).unwrap();
        // Kept sessions are saved with the session.
        #[cfg(feature = "prost")]
        let mut bob_session = Session::restore(
            InProcessMailbox(&mailbox),
            restored::<_, proto::SessionState>(bob_session.state()),
        );

        // Her earlier message still decrypts, but does not bring the old session back.
        assert_eq!(contents(receive_all(&mut bob_session).await), [b"old"]);
        bob_session.send(b"on the new one").await.unwrap();
        let received = receive_all(&mut alice_again).await;
        assert!(received[0].content.is_err());
        assert_eq!(received[1].content.as_ref().unwrap(), b"on the new one");
        assert!(receive_all(&mut alice_session).await[0].content.is_err());
    }

    /// Whether `a` and `b` send on one session.
    fn on_one_session<M>(a: &Session<M>, b: &Session<M>) -> bool {
        matches!(
            (&a.state.active, &b.state.active),
            (Some(a), Some(b)) if a.id == b.id
        )
    }

    /// Accept the initial message `client` has from `peer`, keeping `session`, the chat so far.
    async fn accept_keeping<'a>(
        client: &mut Client<InProcessHandshake<'a>>,
        peer: &PublicKey,
        session: &mut Session<InProcessMailbox<'a>>,
        mailbox: &'a MailboxServer<MemoryStore>,
    ) -> Vec<u8> {
        let initial_messages = client.take_initial_messages().await.unwrap();
        let (accepted, first) = client
            .accept(peer, &initial_messages[0], InProcessMailbox(mailbox))
            .unwrap();
        let older = mem::replace(session, accepted);
        session.keep(older).unwrap();
        first
    }

    #[tokio::test]
    async fn a_session_the_peer_never_gets_is_retired_for_a_new_one() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Bob starts again, but Alice loses his initial message, and writes on the old session.
        alice.publish_keys(1).await.unwrap();
        bob.start_again(&mut bob_session, b"lost").await.unwrap();
        assert_eq!(alice.take_initial_messages().await.unwrap().len(), 1);

        // Bob reads her on the old session, which never becomes active again, and she cannot
        // read him on the new one; after a few turns, he retires it.
        let mut turns = 0;
        loop {
            alice_session.send(b"still here").await.unwrap();
            assert_eq!(
                contents(receive_all(&mut bob_session).await),
                [b"still here"]
            );
            if bob_session.needs_new_session() {
                break;
            }
            bob_session.send(b"lost too").await.unwrap();
            assert!(receive_all(&mut alice_session).await[0].content.is_err());
            turns += 1;
        }
        assert!(turns <= MAX_DIRECTION_CHANGES);
        assert_eq!(
            bob_session.encrypt(b"no").unwrap_err().kind(),
            ErrorKind::NoSession
        );

        // He starts a new one, which Alice gets this time, and they talk on it.
        bob.start_again(&mut bob_session, b"again").await.unwrap();
        let first = accept_keeping(
            &mut alice,
            &bob.identity_key(),
            &mut alice_session,
            &mailbox,
        )
        .await;
        assert_eq!(first, b"again");
        assert!(on_one_session(&alice_session, &bob_session));
        bob_session.send(b"hello again").await.unwrap();
        assert_eq!(
            contents(receive_all(&mut alice_session).await),
            [b"hello again"]
        );
        alice_session.send(b"hi").await.unwrap();
        assert_eq!(contents(receive_all(&mut bob_session).await), [b"hi"]);
    }

    #[tokio::test]
    async fn sessions_started_at_once_end_as_one() {
        // Each accepts the other's; or one answers the other's before the other accepts its
        // own, which a client does before it receives.
        for answered_first in [false, true] {
            let handshake = HandshakeServer::new(MemoryStore::default());
            let mailbox = MailboxServer::new(MemoryStore::default());
            let mut alice = Client::new(InProcessHandshake(&handshake));
            let mut bob = Client::new(InProcessHandshake(&handshake));
            alice.publish_keys(1).await.unwrap();
            bob.publish_keys(1).await.unwrap();
            let mut alice_session = alice
                .initiate(&bob.identity_key(), b"hi bob", InProcessMailbox(&mailbox))
                .await
                .unwrap();
            let mut bob_session = bob
                .initiate(
                    &alice.identity_key(),
                    b"hi alice",
                    InProcessMailbox(&mailbox),
                )
                .await
                .unwrap();

            let first =
                accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mailbox).await;
            assert_eq!(first, b"hi bob");
            if answered_first {
                bob_session.send(b"b0").await.unwrap();
            }
            let first = accept_keeping(
                &mut alice,
                &bob.identity_key(),
                &mut alice_session,
                &mailbox,
            )
            .await;
            assert_eq!(first, b"hi alice");
            if answered_first {
                assert_eq!(contents(receive_all(&mut alice_session).await), [b"b0"]);
            }

            // The session with the higher ID won on both sides, and whatever each sends, at once
            // or in turn, arrives.
            assert!(on_one_session(&alice_session, &bob_session));
            alice_session.send(b"a1").await.unwrap();
            bob_session.send(b"b1").await.unwrap();
            assert_eq!(contents(receive_all(&mut alice_session).await), [b"b1"]);
            assert_eq!(contents(receive_all(&mut bob_session).await), [b"a1"]);
            alice_session.send(b"a2").await.unwrap();
            assert_eq!(contents(receive_all(&mut bob_session).await), [b"a2"]);
            bob_session.send(b"b2").await.unwrap();
            assert_eq!(contents(receive_all(&mut alice_session).await), [b"b2"]);
            assert!(on_one_session(&alice_session, &bob_session));
        }
    }

    #[tokio::test]
    async fn a_chat_deleted_while_a_session_waits_ends_on_one() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let mut alice = Client::new(InProcessHandshake(&handshake));
        let mut bob = Client::new(InProcessHandshake(&handshake));
        alice.publish_keys(1).await.unwrap();
        bob.publish_keys(2).await.unwrap();
        let (alice_key, bob_key) = (alice.identity_key(), bob.identity_key());

        // Both start at once, but Bob deletes his chat before he takes Alice's initial message,
        // which then begins his chat again; Alice accepts the one he deleted.
        let mut alice_session = alice
            .initiate(&bob_key, b"hi bob", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        let deleted = bob
            .initiate(&alice_key, b"hi alice", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        drop(deleted);
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (mut bob_session, first) = bob
            .accept(&alice_key, &initial_messages[0], InProcessMailbox(&mailbox))
            .unwrap();
        assert_eq!(first, b"hi bob");
        let first = accept_keeping(&mut alice, &bob_key, &mut alice_session, &mailbox).await;
        assert_eq!(first, b"hi alice");

        // If Bob's won, what Alice sends on it is lost, while what Bob sends decrypts on hers,
        // until she retires his and starts a new one.
        let mut lost = 0;
        while !on_one_session(&alice_session, &bob_session) {
            assert!(lost <= MAX_DIRECTION_CHANGES, "they never settle");
            if alice_session.needs_new_session() {
                alice
                    .start_again(&mut alice_session, b"again")
                    .await
                    .unwrap();
                let first = accept_keeping(&mut bob, &alice_key, &mut bob_session, &mailbox).await;
                assert_eq!(first, b"again");
                continue;
            }
            alice_session.send(b"from alice").await.unwrap();
            assert!(receive_all(&mut bob_session).await[0].content.is_err());
            lost += 1;
            bob_session.send(b"from bob").await.unwrap();
            assert_eq!(
                contents(receive_all(&mut alice_session).await),
                [b"from bob"]
            );
        }
        alice_session.send(b"on one").await.unwrap();
        assert_eq!(contents(receive_all(&mut bob_session).await), [b"on one"]);
        bob_session.send(b"at last").await.unwrap();
        assert_eq!(
            contents(receive_all(&mut alice_session).await),
            [b"at last"]
        );
    }

    #[tokio::test]
    async fn a_late_message_from_before_a_chat_was_deleted_changes_nothing() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut deleted, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Alice sends on her session, deletes the chat and starts again; Bob takes the new
        // session before the message sent on the old one.
        deleted.send(b"late").await.unwrap();
        drop(deleted);
        let mut alice_session = alice
            .initiate(&bob.identity_key(), b"again", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        let first =
            accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mailbox).await;
        assert_eq!(first, b"again");
        assert_eq!(contents(receive_all(&mut bob_session).await), [b"late"]);
        bob_session.send(b"on the new one").await.unwrap();
        // The new session reads the queue from its start, where the reply to the old one is.
        let received = receive_all(&mut alice_session).await;
        assert!(received[0].content.is_err());
        assert_eq!(received[1].content.as_ref().unwrap(), b"on the new one");
        assert!(on_one_session(&alice_session, &bob_session));
    }

    #[tokio::test]
    async fn a_chat_the_peer_deleted_starts_again_from_a_retired_session() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, bob_session) =
            talking(&handshake, &mailbox).await;
        alice.publish_keys(1).await.unwrap();

        // Bob deletes the chat, as he tells Alice, who retires her session: what came on it still
        // decrypts, but she sends nothing on it.
        drop(bob_session);
        alice_session.retire();
        assert!(alice_session.needs_new_session());
        assert_eq!(
            alice_session.encrypt(b"no").unwrap_err().kind(),
            ErrorKind::NoSession
        );

        // Her next message goes on a new session, which comes to Bob as a new chat.
        alice
            .start_again(&mut alice_session, b"again")
            .await
            .unwrap();
        alice_session.send(b"still there?").await.unwrap();
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (mut bob_session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"again");
        // His new chat reads Alice's queue from its start, where her first message is.
        let received = receive_all(&mut bob_session).await;
        assert_eq!(
            received.last().unwrap().content.as_ref().unwrap(),
            b"still there?"
        );
        bob_session.send(b"yes").await.unwrap();
        assert_eq!(contents(receive_all(&mut alice_session).await), [b"yes"]);
        assert!(on_one_session(&alice_session, &bob_session));
    }

    #[tokio::test]
    async fn a_message_on_a_session_not_taken_yet_waits_for_it() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Alice starts again and writes on the new session, which Bob receives before he takes
        // its initial message: receiving stops there, however often, and loses nothing.
        alice
            .start_again(&mut alice_session, b"once more")
            .await
            .unwrap();
        alice_session.send(b"new").await.unwrap();
        for _ in 0..2 {
            let received = bob_session.receive().await.unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(
                received[0].content.as_ref().unwrap_err().kind(),
                ErrorKind::Stalled
            );
        }
        let first =
            accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mailbox).await;
        assert_eq!(first, b"once more");
        bob_session.skip_stalled();
        assert_eq!(contents(bob_session.receive().await.unwrap()), [b"new"]);

        // What anyone pushes that never decrypts stops receiving once, then is skipped.
        alice_session
            .push(Sealed {
                message: EncryptedMessage::default(),
                delivery_hash: None,
            })
            .await
            .unwrap();
        alice_session.send(b"after").await.unwrap();
        let received = bob_session.receive().await.unwrap();
        assert_eq!(
            received[0].content.as_ref().unwrap_err().kind(),
            ErrorKind::Stalled
        );
        bob_session.skip_stalled();
        let received = bob_session.receive().await.unwrap();
        assert!(received[0].content.is_err());
        assert_eq!(received[1].content.as_ref().unwrap(), b"after");
    }

    #[tokio::test]
    async fn a_lost_initial_message_comes_with_the_messages_after_it() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Alice starts again, and Bob loses her initial message.
        alice
            .start_again(&mut alice_session, b"once more")
            .await
            .unwrap();
        assert_eq!(bob.take_initial_messages().await.unwrap().len(), 1);
        alice_session.send(b"new").await.unwrap();

        // Her message carries it: accepted from there, it decrypts, and the next ones go
        // without it, once Bob answers.
        let received = bob_session.receive().await.unwrap();
        let stalled = received.last().unwrap();
        assert_eq!(
            stalled.content.as_ref().unwrap_err().kind(),
            ErrorKind::Stalled
        );
        let initial_message = stalled.initial_messages[0].clone();
        let (session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_message,
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"once more");
        let older = mem::replace(&mut bob_session, session);
        bob_session.keep(older).unwrap();
        bob_session.skip_stalled();
        assert_eq!(contents(bob_session.receive().await.unwrap()), [b"new"]);
        bob_session.send(b"got it").await.unwrap();
        assert_eq!(contents(receive_all(&mut alice_session).await), [b"got it"]);
        alice_session.send(b"plain").await.unwrap();
        let received = bob_session.receive().await.unwrap();
        assert!(received[0].initial_messages.is_empty());
    }

    #[tokio::test]
    async fn a_lost_initial_message_behind_junk_is_offered_too() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Junk, which never decrypts, then Alice starts again, and Bob loses her initial
        // message.
        alice_session
            .push(Sealed {
                message: EncryptedMessage::default(),
                delivery_hash: None,
            })
            .await
            .unwrap();
        alice
            .start_again(&mut alice_session, b"once more")
            .await
            .unwrap();
        assert_eq!(bob.take_initial_messages().await.unwrap().len(), 1);
        alice_session.send(b"new").await.unwrap();

        // Receiving stops at the junk, offering the initial message that came after it, so
        // that skipping the page does not skip her message.
        let received = bob_session.receive().await.unwrap();
        let stalled = received.last().unwrap();
        assert_eq!(
            stalled.content.as_ref().unwrap_err().kind(),
            ErrorKind::Stalled
        );
        assert_eq!(stalled.initial_messages.len(), 1);
        let (session, _) = bob
            .accept(
                &alice.identity_key(),
                &stalled.initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        let older = mem::replace(&mut bob_session, session);
        bob_session.keep(older).unwrap();
        bob_session.skip_stalled();
        let received = bob_session.receive().await.unwrap();
        assert!(received[0].content.is_err());
        assert_eq!(received[1].content.as_ref().unwrap(), b"new");
    }

    #[tokio::test]
    async fn a_message_on_an_earlier_session_shows_so() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Sent before Alice started again, which Bob took first.
        alice_session.send(b"old").await.unwrap();
        alice
            .start_again(&mut alice_session, b"again")
            .await
            .unwrap();
        accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mailbox).await;
        alice_session.send(b"new").await.unwrap();
        let received = receive_all(&mut bob_session).await;
        let earlier: Vec<_> = received
            .iter()
            .map(|received| (received.content.as_deref().unwrap(), received.earlier))
            .collect();
        assert_eq!(earlier, [(&b"old"[..], true), (&b"new"[..], false)]);
    }

    /// Publishes, then fails once, as if the server's reply were lost.
    #[derive(Debug)]
    struct LosingReply<'a>(&'a HandshakeServer<MemoryStore>, Cell<bool>);

    impl LocalHandshake for LosingReply<'_> {
        async fn publish(&self, request: PublishRequest) -> protocol::Result<PublishResponse> {
            let response = self.0.publish(request).await?;
            if self.1.replace(false) {
                return Err(protocol::ErrorKind::Connect.into());
            }
            Ok(response)
        }

        async fn fetch_bundle(
            &self,
            request: FetchBundleRequest,
        ) -> protocol::Result<FetchBundleResponse> {
            self.0.fetch_bundle(request).await
        }

        async fn send_initial_message(
            &self,
            request: SendInitialMessageRequest,
        ) -> protocol::Result<SendInitialMessageResponse> {
            self.0.send_initial_message(request).await
        }

        async fn take_initial_messages(
            &self,
            request: TakeInitialMessagesRequest,
        ) -> protocol::Result<TakeInitialMessagesResponse> {
            self.0.take_initial_messages(request).await
        }
    }

    /// Refuses publishing while `.1`, as a server does a client not signed in to it.
    #[derive(Debug)]
    struct SignedOut<'a>(&'a HandshakeServer<MemoryStore>, Cell<bool>);

    impl LocalHandshake for SignedOut<'_> {
        async fn publish(&self, request: PublishRequest) -> protocol::Result<PublishResponse> {
            if self.1.get() {
                return Err(protocol::ErrorKind::SignInRequired.into());
            }
            self.0.publish(request).await
        }

        async fn fetch_bundle(
            &self,
            request: FetchBundleRequest,
        ) -> protocol::Result<FetchBundleResponse> {
            self.0.fetch_bundle(request).await
        }

        async fn send_initial_message(
            &self,
            request: SendInitialMessageRequest,
        ) -> protocol::Result<SendInitialMessageResponse> {
            self.0.send_initial_message(request).await
        }

        async fn take_initial_messages(
            &self,
            request: TakeInitialMessagesRequest,
        ) -> protocol::Result<TakeInitialMessagesResponse> {
            self.0.take_initial_messages(request).await
        }
    }

    #[tokio::test]
    async fn publishing_refused_for_the_sign_in_adds_up_no_keys() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let mut alice = Client::new(InProcessHandshake(&handshake));
        let mut bob = Client::new(SignedOut(&handshake, Cell::new(true)));
        // The one-time prekeys Bob keeps, as his state shows them.
        let one_time = |bob: &Client<SignedOut<'_>>| {
            let state = format!("{:?}", bob.state());
            let count = state.split("one_time: ").nth(1).unwrap();
            count[..count.find(|c: char| !c.is_ascii_digit()).unwrap()].to_string()
        };
        let error = bob.publish_keys(2).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SignInRequired);
        let kept = one_time(&bob);
        for _ in 0..5 {
            bob.publish_keys(2).await.unwrap_err();
        }
        assert_eq!(one_time(&bob), kept);

        // Signed in, it publishes, and Alice can start a chat with him.
        bob.handshake.1.set(false);
        bob.publish_keys(2).await.unwrap();
        let _alice_session = alice
            .initiate(&bob.identity_key(), b"hi", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (_bob_session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"hi");
    }

    #[tokio::test]
    async fn prekeys_published_without_a_reply_stay_usable() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let mut alice = Client::new(InProcessHandshake(&handshake));
        let mut bob = Client::new(LosingReply(&handshake, Cell::new(true)));

        // The server has Bob's prekeys, but he never heard so; Alice uses them meanwhile.
        assert!(bob.publish_keys(1).await.is_err());
        let mut alice_session = alice
            .initiate(&bob.identity_key(), b"hi", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        // Bob publishes again, and many times more, before he takes her initial message: it
        // still is accepted, as publishing again did not start a new generation.
        bob.publish_keys(1).await.unwrap();
        bob.publish_keys(1).await.unwrap();
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (_bob_session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"hi");
        alice_session.send(b"there").await.unwrap();
    }

    #[tokio::test]
    async fn the_active_session_has_an_id_both_peers_share() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, _bob, bob_session) = talking(&handshake, &mailbox).await;
        let first = *alice_session.active_id().unwrap();
        assert_eq!(bob_session.active_id(), Some(&first));
        // Retired, there is none; started again, another.
        alice_session.retire();
        assert_eq!(alice_session.active_id(), None);
        alice
            .start_again(&mut alice_session, b"again")
            .await
            .unwrap();
        let second = *alice_session.active_id().unwrap();
        assert_ne!(second, first);
    }

    #[tokio::test]
    async fn a_message_of_an_earlier_session_pushed_twice_is_a_duplicate() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut earlier, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Alice pushes a message twice, as a push whose answer was lost goes again, and starts
        // a new session, which Bob takes before the message.
        let message = earlier.encrypt(b"twice").unwrap();
        earlier.push(message.clone()).await.unwrap();
        earlier.push(message).await.unwrap();
        alice
            .initiate(&bob.identity_key(), b"again", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mailbox).await;
        let received = receive_all(&mut bob_session).await;
        assert_eq!(received[0].content.as_ref().unwrap(), b"twice");
        assert_eq!(
            received[1].content.as_ref().unwrap_err().kind(),
            ErrorKind::DuplicateMessage
        );
    }

    #[tokio::test]
    async fn a_stolen_earlier_session_is_never_sent_on_again() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut stolen, mut bob, mut bob_session) = talking(&handshake, &mailbox).await;
        alice.publish_keys(KEPT_SESSIONS + 1).await.unwrap();
        let (alice_key, bob_key) = (alice.identity_key(), bob.identity_key());

        // Someone copied Alice's session, and she started a new one, which Bob accepted.
        let mut alice_session = alice
            .initiate(&bob_key, b"new", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        accept_keeping(&mut bob, &alice_key, &mut bob_session, &mailbox).await;
        // Bob's reply to the copied session, from before.
        assert!(receive_all(&mut alice_session).await[0].content.is_err());

        // The thief writes on the copied session as Alice, and Bob decrypts it while he keeps
        // it; but he never sends on it, so the thief reads nothing more. Missing Alice, he
        // retires sessions and starts new ones, which only Alice can accept, until the copied
        // one drops out.
        for _ in 0..4 * MAX_DIRECTION_CHANGES {
            stolen.send(b"it is me").await.unwrap();
            receive_all(&mut bob_session).await;
            if bob_session.needs_new_session() {
                bob.start_again(&mut bob_session, b"again").await.unwrap();
                accept_keeping(&mut alice, &bob_key, &mut alice_session, &mailbox).await;
            }
            bob_session.send(b"for alice").await.unwrap();
            assert!(
                receive_all(&mut stolen)
                    .await
                    .iter()
                    .all(|received| received.content.is_err())
            );
            assert_eq!(
                contents(receive_all(&mut alice_session).await),
                [b"for alice"]
            );
        }
        stolen.send(b"still me").await.unwrap();
        assert!(receive_all(&mut bob_session).await[0].content.is_err());
    }

    #[tokio::test]
    async fn only_sessions_with_the_peer_are_kept() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (_alice, _alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;
        let mut carol = Client::new(InProcessHandshake(&handshake));
        let carol_session = carol
            .initiate(&bob.identity_key(), b"hi", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        assert_eq!(
            bob_session.keep(carol_session).unwrap_err().kind(),
            ErrorKind::UnexpectedPeer
        );
        // And Bob's own, with Carol, is not Alice's either.
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (session, _) = bob
            .accept(
                &carol.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(
            bob_session.keep(session).unwrap_err().kind(),
            ErrorKind::UnexpectedPeer
        );
    }

    #[test]
    fn subscriptions_go_by_the_servers_clock() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let alice = Client::new(InProcessHandshake(&handshake));
        // As if this device's clock were ten minutes behind the server's: refused.
        let behind = now() - 10 * 60 * 1000;
        let error = alice.subscription().verify(behind).unwrap_err();
        assert_eq!(error.kind(), protocol::ErrorKind::StaleTimestamp);
        // Once a response told it the server's time, taken.
        alice.clock().observe(behind);
        let key = alice.subscription().verify(behind).unwrap();
        assert_eq!(key, alice.identity_key());
        let bound = alice
            .subscription_for_audience("https://München.example:443/")
            .unwrap();
        assert!(bound.is_audience_bound());
        assert_eq!(
            bound
                .verify_for_audience("xn--mnchen-3ya.example", behind)
                .unwrap(),
            key
        );
        assert!(
            bound
                .verify_for_audience("relay-b.example", behind)
                .is_err()
        );
        assert_eq!(
            alice.subscription_for_audience("").unwrap_err().kind(),
            ErrorKind::Protocol
        );
        for (url, expected) in [
            ("http://relay.example:443", "relay.example:443"),
            ("https://relay.example:80", "relay.example:80"),
        ] {
            let audience = NormalizedAudience::parse(url).unwrap();
            let bound = alice
                .subscription_for_canonical_audience(&audience)
                .unwrap();
            assert_eq!(bound.audience, expected);
            assert_eq!(
                bound
                    .verify_for_canonical_audience(&audience, behind)
                    .unwrap(),
                key
            );
        }
    }

    #[tokio::test]
    async fn attachments_go_in_chunks() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let attachments = AttachmentServer::new(MemoryStore::default());
        let alice = Client::new(InProcessHandshake(&handshake));
        // Two full chunks and a bit.
        let file: Vec<u8> = (0..2 * attachment::CHUNK_SIZE + 10)
            .map(|i| i as u8)
            .collect();
        let upload = alice
            .start_upload(&attachments, file.len() as u64)
            .await
            .unwrap();
        assert_eq!(upload.chunks(), 3);
        for (index, part) in (0..).zip(file.chunks(attachment::CHUNK_SIZE)) {
            let chunk = upload.encrypt(index, part);
            upload.put(&attachments, index, &chunk).await.unwrap();
        }

        // Bob, with the ID and key from a message.
        let mut received = vec![];
        for index in 0..3 {
            let chunk = attachment::download_chunk(&attachments, upload.id(), index)
                .await
                .unwrap()
                .unwrap();
            received.extend(
                attachment::decrypt_chunk(upload.key(), upload.id(), index, index == 2, &chunk)
                    .unwrap(),
            );
        }
        assert_eq!(received, file);

        // Interrupted after its first chunk, an upload goes on from what was kept.
        let interrupted = alice
            .start_upload(&attachments, file.len() as u64)
            .await
            .unwrap();
        let first = interrupted.encrypt(0, &file[..attachment::CHUNK_SIZE]);
        interrupted.put(&attachments, 0, &first).await.unwrap();
        // Bob downloads while it is uploaded: the chunks after it are not there yet.
        let (id, index) = (*interrupted.id(), 1);
        let chunk = attachment::download_chunk(&attachments, &id, index).await;
        assert_eq!(chunk.unwrap(), None);
        let (id, token, chunks) = (
            *interrupted.id(),
            *interrupted.token(),
            interrupted.chunks(),
        );
        let key = attachment::Key::new(*interrupted.key());
        drop(interrupted);
        let resumed = attachment::Upload::resume_from(id, Zeroizing::new(token), key, chunks, 1);
        for (index, part) in
            (1..).zip(file[attachment::CHUNK_SIZE..].chunks(attachment::CHUNK_SIZE))
        {
            let chunk = resumed.encrypt(index, part);
            resumed.put(&attachments, index, &chunk).await.unwrap();
        }
        let mut received = vec![];
        for index in 0..3 {
            let chunk = attachment::download_chunk(&attachments, &id, index)
                .await
                .unwrap()
                .unwrap();
            received.extend(
                attachment::decrypt_chunk(resumed.key(), &id, index, index == 2, &chunk).unwrap(),
            );
        }
        assert_eq!(received, file);

        // Cancelled, it is gone for Bob.
        resumed.cancel(&attachments).await.unwrap();
        let error = attachment::download_chunk(&attachments, &id, 0)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);

        // Bob, who does not want one, deletes it with its key while it is uploaded, which stops
        // the upload; so may Alice, uploaded or not, once she forgot its upload token.
        let unwanted = alice
            .start_upload(&attachments, file.len() as u64)
            .await
            .unwrap();
        let first = unwanted.encrypt(0, &file[..attachment::CHUNK_SIZE]);
        unwanted.put(&attachments, 0, &first).await.unwrap();
        attachment::delete(&attachments, unwanted.id(), unwanted.key())
            .await
            .unwrap();
        let second = unwanted.encrypt(1, &file[attachment::CHUNK_SIZE..][..attachment::CHUNK_SIZE]);
        let error = unwanted.put(&attachments, 1, &second).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        let error = attachment::delete(&attachments, unwanted.id(), unwanted.key())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);

        // More than the service takes.
        let size = 51 * attachment::CHUNK_SIZE as u64;
        let error = alice.start_upload(&attachments, size).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::LimitExceeded);
    }

    #[tokio::test]
    #[cfg(feature = "prost")]
    async fn restored_clients_and_sessions_carry_on() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let mut alice = Client::new(InProcessHandshake(&handshake));
        let mut bob = Client::new(InProcessHandshake(&handshake));
        bob.publish_keys(1).await.unwrap();
        let mut alice_session = alice
            .initiate(&bob.identity_key(), b"hi", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        alice_session.send(b"there").await.unwrap();

        // Bob's identity, prekeys and timestamp survive a restart, and so does Alice's session.
        let mut bob = Client::restore(
            InProcessHandshake(&handshake),
            restored::<_, proto::ClientState>(bob.state()),
        );
        let mut alice_session = Session::restore(
            InProcessMailbox(&mailbox),
            restored::<_, proto::SessionState>(alice_session.state()),
        );
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (bob_session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"hi");
        // So does what was accepted: it cannot be accepted again.
        let mut bob = Client::restore(
            InProcessHandshake(&handshake),
            restored::<_, proto::ClientState>(bob.state()),
        );
        assert_eq!(
            bob.accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap_err()
            .kind(),
            ErrorKind::InvalidInitialMessage
        );

        // The cursor too: what was received is not fetched again.
        let mut bob_session = Session::restore(
            InProcessMailbox(&mailbox),
            restored::<_, proto::SessionState>(bob_session.state()),
        );
        assert_eq!(
            contents(receive_all(&mut bob_session).await),
            [b"there".to_vec()]
        );
        let mut bob_session = Session::restore(
            InProcessMailbox(&mailbox),
            restored::<_, proto::SessionState>(bob_session.state()),
        );
        assert!(receive_all(&mut bob_session).await.is_empty());
        bob_session.send(b"hello").await.unwrap();
        assert_eq!(
            contents(receive_all(&mut alice_session).await),
            [b"hello".to_vec()]
        );
    }

    #[cfg(feature = "serde")]
    #[tokio::test]
    async fn serde_validate_rejects_tampered_party_associated_data() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (alice, alice_session, bob, _bob_session) = talking(&handshake, &mailbox).await;
        let mut carol = Client::new(InProcessHandshake(&handshake));
        let mut carol_session = carol
            .initiate(&bob.identity_key(), b"carol", InProcessMailbox(&mailbox))
            .await
            .unwrap();

        let to_raw = |mut s: SessionState| RawSessionState {
            active: s.active.take(),
            others: std::mem::take(&mut s.others),
            me: s.me,
            peer: s.peer,
            cursor: s.cursor,
            last: s.last,
            direction_changes: s.direction_changes,
            stalled_through: s.stalled_through,
            skip_through: s.skip_through,
            delivered: std::mem::take(&mut s.delivered),
            peer_pq: std::mem::take(&mut s.peer_pq),
            next_session_seq: s.next_session_seq,
        };

        // 1. Valid state passes serde TryFrom<RawSessionState>.
        let valid_state = SessionState::try_from(to_raw(alice_session.state)).unwrap();
        assert_eq!(valid_state.me, alice.identity_key());

        // 2. Active party with mismatched peer identity in AD is rejected.
        let mut wrong_peer_raw = to_raw(valid_state);
        let orig_peer = wrong_peer_raw.peer;
        wrong_peer_raw.peer = carol.identity_key();
        let err = SessionState::try_from(wrong_peer_raw).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MalformedState);

        // 3. Earlier (`others`) party from a different identity pair (Carol->Bob) is rejected.
        let (alice2, alice2_session, _bob2, _bob2_session) = talking(&handshake, &mailbox).await;
        let _ = (alice2, orig_peer);
        let mut bad_others_raw = to_raw(alice2_session.state);
        bad_others_raw
            .others
            .push(Earlier::from(carol_session.state.active.take().unwrap()));
        let err = SessionState::try_from(bad_others_raw).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MalformedState);

        // 4. Active party with wrong AD length (32 bytes) is rejected.
        let (_a3, a3_session, _b3, _b3_session) = talking(&handshake, &mailbox).await;
        let mut bad_len_raw = to_raw(a3_session.state);
        bad_len_raw.active.as_mut().unwrap().party = Party::new(
            Ratchet::bob(
                &SharedKeys::from_secret(&[9u8; 32]),
                DhPrivateKey::from([10u8; 32]),
            ),
            vec![0xBB; 32],
        );
        let err = SessionState::try_from(bad_len_raw).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MalformedState);
    }

    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    #[test]
    fn accept_initial_v2_rejects_foreign_digest_even_with_empty_recent_digests() {
        let suite = PqConfig::default_suite();
        let alice_id = xeddsa::XEdDSAPrivateKey::generate();
        let bob_id = xeddsa::XEdDSAPrivateKey::generate();
        let bob_id_copy = xeddsa::XEdDSAPrivateKey::from_bytes(*bob_id.to_bytes()).unwrap();
        let mut bob = Client::builder(()).identity(bob_id).build();
        let prep = bob.prepare_publish_v2("relay.example", 2, 2).unwrap();
        let lr_wire = prep.request.pq_last_resort[0].clone();
        bob.commit_publish_v2(prep);
        // Force empty recent_manifest_digests (e.g. restored legacy state before manifest tracking):
        // an authenticated PQXDH initial carrying a foreign `Some(digest)` MUST STILL be rejected!
        bob.state.recent_manifest_digests.clear();

        let spk = bob.current_signed_prekey().unwrap();
        let mut spk_sig = [0u8; 64];
        spk_sig.copy_from_slice(&bob_id_copy.sign(spk));
        let mut lr_sig = [0u8; 64];
        lr_sig.copy_from_slice(&lr_wire.signature);
        let pq_bundle = x3dh::PqPrekeyBundle {
            signed_prekey: spk,
            signed_prekey_signature: Some(spk_sig),
            one_time_prekey: None,
            pq_suite: suite,
            pq_prekey: lr_wire.encapsulation_key.to_vec(),
            pq_prekey_signature: lr_sig,
            pq_last_resort: true,
        };
        let foreign_digest = [0xCC; 32];
        let (pq_init, agreement) = pq_bundle
            .initiate_pq(&alice_id, &bob.identity_key(), Some(&foreign_digest))
            .unwrap();
        let ratchet =
            Ratchet::alice(&SharedKeys::from_secret(&agreement.secret_key), &spk).unwrap();
        let mut party = Party::new(ratchet, agreement.associated_data);
        let first_message = party.encrypt(b"foreign").unwrap();
        let msg = InitialMessageV2 {
            id: 1,
            sender: alice_id.compute_public_key().to_bytes(),
            kind: InitialMessageKind::Pq {
                x3dh: pq_init,
                first_message,
                manifest_digest: Some(foreign_digest),
            },
        };
        assert_eq!(
            bob.accept_initial_v2(
                &alice_id.compute_public_key().to_bytes(),
                &PeerPqState::default(),
                &msg,
                (),
            )
            .unwrap_err()
            .kind(),
            ErrorKind::DowngradeDetected
        );
    }
}
