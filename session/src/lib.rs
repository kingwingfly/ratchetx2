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
use std::collections::BTreeMap;

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
    mailbox_v2::{
        CLIENT_MESSAGE_ID_LENGTH, PEER_SLOT_ID_LENGTH, PushV2Request, WRITE_TOKEN_HASH_LENGTH,
        WRITE_TOKEN_LENGTH, decode_carried_initial,
    },
    notify::SubscribeRequest,
};
pub use safety::safety_number;
use sha2::{Digest, Sha256};
use x3dh::LocalPrekeys;
pub use x3dh::{PqSuite, PublicKey};
use xeddsa::XEdDSAPrivateKey;
#[cfg(any(feature = "prost", feature = "serde"))]
use xeddsa::XEdDSAPublicKey;
use zeroize::Zeroizing;

/// Request at most the default mailbox fetch limit per page when `limit == 0`.
pub(crate) const MAX_RECEIVE_PAGE: u32 = 100;

/// Maximum number of rolling non-preserved locally signed `CapabilityManifest` digests retained in
/// `ClientState`.
pub const MAX_RECENT_MANIFEST_DIGESTS: usize = 16;

/// Hard upper bound on `recent_manifest_digests` including digests explicitly preserved for
/// deferred unsupported-suite initial messages (16 rolling + up to 128 deferred-initial pins).
/// Maximum manifest digests retained by a client across scheduled rotations (16 rolling
/// non-preserved slots + up to 128 preserved deferred-initial digests).
pub const MAX_RETAINED_MANIFEST_DIGESTS: usize = 144;
/// Maximum manifest digests stored transiently while a publish is in flight
/// (`MAX_RETAINED_MANIFEST_DIGESTS` + 1 pending digest awaiting relay confirmation) so an
/// in-flight publish never evicts a digest still referenced by delayed PQ greetings before commit.
pub const MAX_STORED_MANIFEST_DIGESTS: usize = MAX_RETAINED_MANIFEST_DIGESTS + 1;

/// Maximum pending write-token registrations retained per session (matches relay per-peer grant
/// cap).
pub const MAX_PENDING_REGISTER_GRANTS: usize = 4;

/// Domain-separation prefix for opaque per-peer mailbox slot IDs (`HMAC-SHA256`).
const PEER_SLOT_DOMAIN: &[u8] = b"session.v2/peer-slot\0";

/// Domain-separation prefix for directional deniable write-capability tokens (`HKDF-SHA256`).
const WRITE_TOKEN_INFO_PREFIX: &[u8] = b"session.v2/write-token\0";

/// Lock-free attachment upload initiation (equivalent to [`Client::start_upload`] without
/// borrowing [`Client`]).
pub async fn start_upload_with(
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

/// Zeroizes the backing buffer of `bytes` in place when uniquely owned; static or shared handles
/// are detached without panicking.
pub(crate) fn zeroize_bytes(bytes: &mut Bytes) {
    let owned = mem::take(bytes);
    if let Ok(mut buf) = owned.try_into_mut() {
        zeroize::Zeroize::zeroize(buf.as_mut());
    }
}

/// Extract a [`Hello`] greeting from decrypted or outgoing content bytes, if present.
pub(crate) fn extract_hello(content: &[u8]) -> Option<Hello> {
    match Content::decode(content).ok()?.kind {
        Some(ContentKind::Hello(hello)) => Some(hello),
        _ => None,
    }
}

/// Read a greeting only after authentication, before confirming the claimed prekeys.
pub(crate) fn checked_initial_hello(content: &[u8]) -> Result<Option<Hello>> {
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

/// A write-token grant staged on a [`Session`] waiting to be registered on the recipient's
/// mailbox server via [`Client::register_write_token_v2`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PendingGrant {
    /// SHA-256 of the peer's deniable write token (`H(t_{peer->me})`).
    pub token_hash: [u8; WRITE_TOKEN_HASH_LENGTH],
    /// Strictly positive monotonic identity-wide grant version (`1..=MAX_SAFE_INTEGER`) allocated
    /// from [`Client::allocate_grant_version`].
    pub grant_version: u64,
    /// Whether to pin this token as the peer's active (never-evicted) grant on the relay.
    pub pin_active: bool,
}

/// Merge `incoming` pending grants into `existing`, deduplicating by `token_hash` (keeping the
/// higher `grant_version`, OR-ing `pin_active` on ties), demoting stale `pin_active` flags on
/// non-active hashes whenever `active_hash` is present, capping at
/// [`MAX_PENDING_REGISTER_GRANTS`] while strictly preserving `active_hash`, and sorting ascending
/// by `(grant_version, token_hash)`.
fn merge_pending_grants(
    existing: &mut Vec<PendingGrant>,
    incoming: Vec<PendingGrant>,
    active_hash: Option<[u8; WRITE_TOKEN_HASH_LENGTH]>,
) {
    let mut merged = Vec::with_capacity(existing.len().saturating_add(incoming.len()));
    for grant in existing.drain(..).chain(incoming) {
        if let Some(prev) = merged
            .iter_mut()
            .find(|g: &&mut PendingGrant| g.token_hash == grant.token_hash)
        {
            if grant.grant_version > prev.grant_version {
                *prev = grant;
            } else if grant.grant_version == prev.grant_version {
                prev.pin_active |= grant.pin_active;
            }
        } else {
            merged.push(grant);
        }
    }
    if let Some(active) = active_hash {
        for grant in &mut merged {
            if grant.token_hash != active {
                grant.pin_active = false;
            }
        }
    }
    while merged.len() > MAX_PENDING_REGISTER_GRANTS {
        if let Some((evict_idx, _)) = merged.iter().enumerate().min_by_key(|(_, g)| {
            (
                active_hash == Some(g.token_hash),
                g.pin_active,
                g.grant_version,
            )
        }) {
            merged.remove(evict_idx);
        } else {
            break;
        }
    }
    merged.sort_unstable_by_key(|g| (g.grant_version, g.token_hash));
    *existing = merged;
}

/// An identity on a v2 handshake server: publishes prekeys and signed capability manifests,
/// starts and accepts sessions, and manages the unified recipient mailbox and write-token grants.
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

/// What a [`Client`] keeps besides its transport: the identity key, prekeys, signed-request
/// timestamp, PQ manifest state, unified mailbox cursor/ACK watermark, and monotonic grant
/// version counter.
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
    /// them, its reply being lost.
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
    /// SHA-256 digests of `CapabilityManifest`s confirmed stored on the relay (bounded by
    /// `MAX_RECENT_MANIFEST_DIGESTS`). Prioritized ahead of unconfirmed staged digests so repeated
    /// failed publish attempts cannot evict the last confirmed relay manifest digest.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            deserialize_with = "deserialize_bounded_vec::<_, _, MAX_RECENT_MANIFEST_DIGESTS>"
        )
    )]
    pub(crate) confirmed_manifest_digests: Vec<[u8; 32]>,
    /// Mapping from retained `CapabilityManifest` digest to the `signed_prekey` it bound, so
    /// every manifest digest for a still-retained (relay-admissible) signed prekey stays protected
    /// against rolling truncation until that signed prekey is evicted (`R9-P2-4`).
    #[cfg_attr(
        feature = "serde",
        serde(default, serialize_with = "serialize_digest_spk_map")
    )]
    pub(crate) manifest_digest_spks: BTreeMap<[u8; 32], PublicKey>,
    /// Unified mailbox high-water sequence number last committed locally.
    pub(crate) mailbox_cursor: u64,
    /// Unified mailbox sequence number committed locally and awaiting server prefix ACK (`0` if none).
    pub(crate) pending_mailbox_ack: u64,
    /// Identity-wide monotonic write-token grant version counter (starts at `1`).
    pub(crate) next_grant_version: u64,
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
            confirmed_manifest_digests: vec![],
            manifest_digest_spks: BTreeMap::new(),
            mailbox_cursor: 0,
            pending_mailbox_ack: 0,
            next_grant_version: 1,
        }
    }

    fn is_digest_for_retained_spk(&self, digest: &[u8; 32]) -> bool {
        self.manifest_digest_spks
            .get(digest)
            .is_some_and(|spk| self.prekeys.contains_signed_prekey(spk))
    }

    /// Record a manifest digest that has been confirmed stored on the relay (either via a
    /// confirmed `PublishV2` commit or a verified `GetManifest` reconciliation), optionally
    /// associating it with the `signed_prekey` bound by that manifest.
    pub(crate) fn record_confirmed_manifest_digest(
        &mut self,
        digest: [u8; 32],
        signed_prekey: Option<PublicKey>,
    ) {
        if let Some(pos) = self
            .confirmed_manifest_digests
            .iter()
            .position(|d| *d == digest)
        {
            self.confirmed_manifest_digests.remove(pos);
        }
        self.confirmed_manifest_digests.push(digest);
        while self.confirmed_manifest_digests.len() > MAX_RECENT_MANIFEST_DIGESTS {
            self.confirmed_manifest_digests.remove(0);
        }
        if let Some(spk) = signed_prekey {
            self.manifest_digest_spks.insert(digest, spk);
        }
        if !self.recent_manifest_digests.contains(&digest) {
            self.recent_manifest_digests.push(digest);
            while self.recent_manifest_digests.len() > MAX_STORED_MANIFEST_DIGESTS {
                let candidate_end = self.recent_manifest_digests.len() - 1;
                let evict_idx = self.recent_manifest_digests[..candidate_end]
                    .iter()
                    .position(|d| {
                        !self.is_digest_for_retained_spk(d)
                            && !self.confirmed_manifest_digests.contains(d)
                    })
                    .or_else(|| {
                        self.recent_manifest_digests[..candidate_end]
                            .iter()
                            .position(|d| !self.confirmed_manifest_digests.contains(d))
                    })
                    .unwrap_or(0);
                let removed = self.recent_manifest_digests.remove(evict_idx);
                self.manifest_digest_spks.remove(&removed);
            }
        }
    }

    /// Whether recording another manifest digest can fit within `MAX_RETAINED_MANIFEST_DIGESTS`
    /// without evicting any digest listed in `preserve`.
    pub fn has_spare_manifest_digest_slot(&self, preserve: &[[u8; 32]]) -> bool {
        let preserved_in_recent = self
            .recent_manifest_digests
            .iter()
            .filter(|d| preserve.contains(d))
            .count();
        preserved_in_recent < MAX_RETAINED_MANIFEST_DIGESTS
    }

    /// Exact capacity check for a `PublishV2` attempt with `(preserve_spks, preserve_digests)`,
    /// accounting for BOTH explicitly preserved digests AND all manifest digests bound to signed
    /// prekeys that will remain retained after this publish commits (`R9-P2-4`).
    ///
    /// Non-retry in-place extends reserve 1 slot (`< MAX_RETAINED_MANIFEST_DIGESTS - 1`) so the
    /// current signed prekey can always rotate to a fresh generation and eventually release older
    /// SPK-bound digests once the previous SPK is evicted.
    pub fn has_spare_manifest_digest_slot_for_publish(
        &self,
        preserve_spks: &[PublicKey],
        preserve_digests: &[[u8; 32]],
    ) -> bool {
        let preserve_oldest = self
            .prekeys
            .oldest_evictable_signed_prekey()
            .is_some_and(|spk| preserve_spks.contains(&spk));
        let extended = (self.publishing || preserve_oldest) && self.prekeys.generation_count() > 0;
        let post_commit_spks = if extended {
            self.prekeys
                .retained_signed_prekeys_after_prune(preserve_spks)
        } else {
            self.prekeys
                .retained_signed_prekeys_after_rotation(preserve_spks)
        };
        let post_commit_pinned = self
            .recent_manifest_digests
            .iter()
            .filter(|d| {
                preserve_digests.contains(d)
                    || self
                        .manifest_digest_spks
                        .get(*d)
                        .is_some_and(|spk| post_commit_spks.contains(spk))
            })
            .count();
        let limit = if extended && !self.publishing {
            MAX_RETAINED_MANIFEST_DIGESTS - 1
        } else {
            MAX_RETAINED_MANIFEST_DIGESTS
        };
        post_commit_pinned < limit
    }

    /// Stage a freshly signed manifest digest WITHOUT evicting any existing rolling digest yet
    /// (allowing up to `MAX_STORED_MANIFEST_DIGESTS` while a publish is in flight). Only trims if
    /// already at the hard `MAX_STORED_MANIFEST_DIGESTS` ceiling, preferring to evict unconfirmed
    /// non-preserved digests outside retained signed prekeys first. Call
    /// [`prune_manifest_digests_preserving`](Self::prune_manifest_digests_preserving) on commit.
    pub(crate) fn stage_manifest_digest(
        &mut self,
        digest: [u8; 32],
        preserve: &[[u8; 32]],
    ) -> Vec<(usize, [u8; 32], Option<PublicKey>)> {
        if let Some(pos) = self
            .recent_manifest_digests
            .iter()
            .position(|d| *d == digest)
        {
            self.recent_manifest_digests.remove(pos);
        }
        self.recent_manifest_digests.push(digest);
        let mut evicted = Vec::new();
        while self.recent_manifest_digests.len() > MAX_STORED_MANIFEST_DIGESTS {
            let candidate_end = self.recent_manifest_digests.len() - 1;
            let evict_idx = self.recent_manifest_digests[..candidate_end]
                .iter()
                .position(|d| {
                    !preserve.contains(d)
                        && !self.is_digest_for_retained_spk(d)
                        && !self.confirmed_manifest_digests.contains(d)
                })
                .or_else(|| {
                    self.recent_manifest_digests[..candidate_end]
                        .iter()
                        .position(|d| !preserve.contains(d) && !self.is_digest_for_retained_spk(d))
                })
                .or_else(|| {
                    self.recent_manifest_digests[..candidate_end]
                        .iter()
                        .position(|d| {
                            !preserve.contains(d) && !self.confirmed_manifest_digests.contains(d)
                        })
                })
                .or_else(|| {
                    self.recent_manifest_digests[..candidate_end]
                        .iter()
                        .position(|d| !preserve.contains(d))
                })
                .unwrap_or(0);
            let removed = self.recent_manifest_digests.remove(evict_idx);
            let removed_spk = self.manifest_digest_spks.remove(&removed);
            evicted.push((evict_idx, removed, removed_spk));
        }
        evicted
    }

    /// Trim `recent_manifest_digests` down to at most `MAX_RECENT_MANIFEST_DIGESTS` non-preserved
    /// digests PLUS explicitly preserved digests (while never evicting confirmed digests bound to
    /// still-retained signed prekeys, up to `MAX_RETAINED_MANIFEST_DIGESTS` total), never evicting
    /// the newest `last()` entry and prioritizing confirmed relay digests ahead of unconfirmed
    /// staged attempts. Called once a publish is confirmed on the relay (AFTER `prekeys.prune_to_kept`).
    pub(crate) fn prune_manifest_digests_preserving(&mut self, preserve: &[[u8; 32]]) {
        loop {
            let candidate_end = self.recent_manifest_digests.len().saturating_sub(1);
            let non_preserved_count = self
                .recent_manifest_digests
                .iter()
                .filter(|d| !preserve.contains(d))
                .count();
            if non_preserved_count <= MAX_RECENT_MANIFEST_DIGESTS {
                break;
            }
            let Some(evict_idx) = self.recent_manifest_digests[..candidate_end]
                .iter()
                .position(|d| {
                    !preserve.contains(d)
                        && !self.is_digest_for_retained_spk(d)
                        && !self.confirmed_manifest_digests.contains(d)
                })
                .or_else(|| {
                    self.recent_manifest_digests[..candidate_end]
                        .iter()
                        .position(|d| !preserve.contains(d) && !self.is_digest_for_retained_spk(d))
                })
            else {
                break;
            };
            let removed = self.recent_manifest_digests.remove(evict_idx);
            self.manifest_digest_spks.remove(&removed);
        }
        while self.recent_manifest_digests.len() > MAX_RETAINED_MANIFEST_DIGESTS {
            let candidate_end = self.recent_manifest_digests.len() - 1;
            let evict_idx = self.recent_manifest_digests[..candidate_end]
                .iter()
                .position(|d| {
                    !preserve.contains(d)
                        && !self.is_digest_for_retained_spk(d)
                        && !self.confirmed_manifest_digests.contains(d)
                })
                .or_else(|| {
                    self.recent_manifest_digests[..candidate_end]
                        .iter()
                        .position(|d| !preserve.contains(d) && !self.is_digest_for_retained_spk(d))
                })
                .or_else(|| {
                    self.recent_manifest_digests[..candidate_end]
                        .iter()
                        .position(|d| {
                            !preserve.contains(d) && !self.confirmed_manifest_digests.contains(d)
                        })
                })
                .or_else(|| {
                    self.recent_manifest_digests[..candidate_end]
                        .iter()
                        .position(|d| !preserve.contains(d))
                })
                .unwrap_or(0);
            let removed = self.recent_manifest_digests.remove(evict_idx);
            self.manifest_digest_spks.remove(&removed);
        }
    }

    /// Pop a previously appended manifest digest and restore any digests it evicted at their
    /// original FIFO positions.
    pub(crate) fn rollback_manifest_digest(
        &mut self,
        added: [u8; 32],
        evicted: &[(usize, [u8; 32], Option<PublicKey>)],
    ) {
        if self.recent_manifest_digests.last() == Some(&added) {
            self.recent_manifest_digests.pop();
            if !self.recent_manifest_digests.contains(&added) {
                self.manifest_digest_spks.remove(&added);
            }
        }
        for &(pos, restored, restored_spk) in evicted.iter().rev() {
            if self.recent_manifest_digests.len() < MAX_STORED_MANIFEST_DIGESTS
                && !self.recent_manifest_digests.contains(&restored)
            {
                let idx = pos.min(self.recent_manifest_digests.len());
                self.recent_manifest_digests.insert(idx, restored);
                if let Some(spk) = restored_spk {
                    self.manifest_digest_spks.insert(restored, spk);
                }
            }
        }
    }

    /// This client's post-quantum configuration.
    pub fn pq_config(&self) -> &PqConfig {
        &self.pq_config
    }

    /// Unified mailbox high-water sequence number last committed locally.
    pub fn mailbox_cursor(&self) -> u64 {
        self.mailbox_cursor
    }

    /// Unified mailbox sequence number committed locally and awaiting server prefix ACK (`0` if
    /// none).
    pub fn pending_mailbox_ack(&self) -> u64 {
        self.pending_mailbox_ack
    }

    /// Next identity-wide monotonic write-token grant version (`>= 1`).
    pub fn next_grant_version(&self) -> u64 {
        self.next_grant_version.max(1)
    }

    /// Opaque 32-byte per-peer slot identifier sent to the mailbox relay so the relay stays blind
    /// to `peer`: `HMAC-SHA256(identity_sk, b"session.v2/peer-slot\0" || peer)`.
    pub fn peer_slot_id(&self, peer: &PublicKey) -> [u8; PEER_SLOT_ID_LENGTH] {
        let sk = self.identity.to_bytes();
        let mut mac = Hmac::<Sha256>::new_from_slice(sk.as_slice()).expect("HMAC takes any key");
        mac.update(PEER_SLOT_DOMAIN);
        mac.update(peer);
        mac.finalize().into_bytes().into()
    }

    #[cfg(any(feature = "prost", feature = "serde"))]
    fn validate(&self) -> Result<()> {
        if self.last_timestamp > protocol::MAX_SAFE_INTEGER
            || self.manifest_seq > protocol::MAX_SAFE_INTEGER
            || self.prekey_generation > protocol::MAX_SAFE_INTEGER
            || self.mailbox_cursor > protocol::MAX_SAFE_INTEGER
            || self.pending_mailbox_ack > protocol::MAX_SAFE_INTEGER
            || self.pending_mailbox_ack > self.mailbox_cursor
            || self.next_grant_version == 0
            || self.next_grant_version > protocol::MAX_SAFE_INTEGER
            || self.recent_manifest_digests.len() > MAX_STORED_MANIFEST_DIGESTS
            || self.confirmed_manifest_digests.len() > MAX_RECENT_MANIFEST_DIGESTS
            || self.manifest_digest_spks.len() > MAX_STORED_MANIFEST_DIGESTS
            || self
                .manifest_digest_spks
                .keys()
                .any(|d| !self.recent_manifest_digests.contains(d))
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
fn serialize_digest_spk_map<S>(
    map: &BTreeMap<[u8; 32], PublicKey>,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq as _;
    let mut seq = serializer.serialize_seq(Some(map.len()))?;
    for (digest, spk) in map {
        seq.serialize_element(&(digest, spk))?;
    }
    seq.end()
}

#[cfg(feature = "serde")]
fn default_grant_version() -> u64 {
    1
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
        deserialize_with = "deserialize_bounded_vec::<_, _, MAX_STORED_MANIFEST_DIGESTS>"
    )]
    recent_manifest_digests: Vec<[u8; 32]>,
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_vec::<_, _, MAX_RECENT_MANIFEST_DIGESTS>"
    )]
    confirmed_manifest_digests: Vec<[u8; 32]>,
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_vec::<_, _, MAX_STORED_MANIFEST_DIGESTS>"
    )]
    manifest_digest_spks: Vec<([u8; 32], PublicKey)>,
    #[serde(default)]
    mailbox_cursor: u64,
    #[serde(default)]
    pending_mailbox_ack: u64,
    #[serde(default = "default_grant_version")]
    next_grant_version: u64,
}

#[cfg(feature = "serde")]
impl TryFrom<RawClientState> for ClientState {
    type Error = Error;

    fn try_from(raw: RawClientState) -> Result<Self> {
        let mut manifest_digest_spks = BTreeMap::new();
        for (digest, spk) in raw.manifest_digest_spks {
            if manifest_digest_spks.insert(digest, spk).is_some() {
                return Err(ErrorKind::MalformedState.into());
            }
        }
        let state = Self {
            identity: raw.identity,
            prekeys: raw.prekeys,
            last_timestamp: raw.last_timestamp,
            publishing: raw.publishing,
            pq_config: raw.pq_config,
            manifest_seq: raw.manifest_seq,
            prekey_generation: raw.prekey_generation,
            recent_manifest_digests: raw.recent_manifest_digests,
            confirmed_manifest_digests: raw.confirmed_manifest_digests,
            manifest_digest_spks,
            mailbox_cursor: raw.mailbox_cursor,
            pending_mailbox_ack: raw.pending_mailbox_ack,
            next_grant_version: raw.next_grant_version.max(1),
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
            confirmed_manifest_digests: state
                .confirmed_manifest_digests
                .iter()
                .map(|d| d.to_vec())
                .collect(),
            manifest_digest_spks: state
                .manifest_digest_spks
                .iter()
                .map(|(digest, spk)| proto::SignedPrekeyManifestDigest {
                    digest: digest.to_vec(),
                    signed_prekey: spk.to_vec(),
                })
                .collect(),
            mailbox_cursor: state.mailbox_cursor,
            pending_mailbox_ack: state.pending_mailbox_ack,
            next_grant_version: state.next_grant_version.max(1),
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
        if state.recent_manifest_digests.len() > MAX_STORED_MANIFEST_DIGESTS
            || state.confirmed_manifest_digests.len() > MAX_RECENT_MANIFEST_DIGESTS
            || state.manifest_digest_spks.len() > MAX_STORED_MANIFEST_DIGESTS
        {
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
        let confirmed_manifest_digests = state
            .confirmed_manifest_digests
            .iter()
            .map(|d| {
                <[u8; 32]>::try_from(d.as_slice())
                    .map_err(|_| Error::from(ErrorKind::MalformedState))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut manifest_digest_spks = BTreeMap::new();
        for entry in &state.manifest_digest_spks {
            let digest = <[u8; 32]>::try_from(entry.digest.as_slice())
                .map_err(|_| Error::from(ErrorKind::MalformedState))?;
            let spk = PublicKey::try_from(entry.signed_prekey.as_slice())
                .map_err(|_| Error::from(ErrorKind::MalformedState))?;
            if manifest_digest_spks.insert(digest, spk).is_some() {
                return Err(ErrorKind::MalformedState.into());
            }
        }
        let pq_config = PqConfig {
            pq_enabled: !state.pq_disabled,
            preferred_suite,
            pq_ratchet_enabled: !state.pq_ratchet_disabled,
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
            confirmed_manifest_digests,
            manifest_digest_spks,
            mailbox_cursor: state.mailbox_cursor,
            pending_mailbox_ack: state.pending_mailbox_ack,
            next_grant_version: state.next_grant_version.max(1),
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

    /// What to save to [`restore`](Client::restore) this client later. Its prekeys, mailbox
    /// cursors, and grant version counter change on publish, accept, receive, and grant
    /// allocation, so save it after those.
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

    /// Whether recording another manifest digest can fit within [`MAX_RETAINED_MANIFEST_DIGESTS`]
    /// without evicting any digest listed in `preserve`.
    pub fn has_spare_manifest_digest_slot(&self, preserve: &[[u8; 32]]) -> bool {
        self.state.has_spare_manifest_digest_slot(preserve)
    }

    /// Exact capacity check for a `PublishV2` attempt preserving `(preserve_spks, preserve_digests)`
    /// as well as every manifest digest bound to signed prekeys that will remain retained after
    /// commit (`R9-P2-4`).
    pub fn has_spare_manifest_digest_slot_for_publish(
        &self,
        preserve_spks: &[PublicKey],
        preserve_digests: &[[u8; 32]],
    ) -> bool {
        self.state
            .has_spare_manifest_digest_slot_for_publish(preserve_spks, preserve_digests)
    }

    /// SHA-256 digests of all locally signed `CapabilityManifest`s currently retained by this
    /// client (both rolling and preserved).
    pub fn recent_manifest_digests(&self) -> &[[u8; 32]] {
        &self.state.recent_manifest_digests
    }

    /// SHA-256 digests of locally signed `CapabilityManifest`s confirmed stored on the relay.
    pub fn confirmed_manifest_digests(&self) -> &[[u8; 32]] {
        &self.state.confirmed_manifest_digests
    }

    /// Prekey generation number last prepared/published via v2 by this client.
    pub fn prekey_generation(&self) -> u64 {
        self.state.prekey_generation
    }

    /// Unified mailbox high-water sequence number last committed locally.
    pub fn mailbox_cursor(&self) -> u64 {
        self.state.mailbox_cursor
    }

    /// Unified mailbox sequence number committed locally and awaiting server prefix ACK (`0` if
    /// none).
    pub fn pending_mailbox_ack(&self) -> u64 {
        self.state.pending_mailbox_ack
    }

    /// Next identity-wide monotonic write-token grant version (`>= 1`), without advancing it.
    pub fn next_grant_version(&self) -> u64 {
        self.state.next_grant_version()
    }

    /// Opaque 32-byte per-peer slot identifier sent to the mailbox relay so the relay stays blind
    /// to `peer`: `HMAC-SHA256(identity_sk, b"session.v2/peer-slot\0" || peer)`.
    pub fn peer_slot_id(&self, peer: &PublicKey) -> [u8; PEER_SLOT_ID_LENGTH] {
        self.state.peer_slot_id(peer)
    }

    /// Allocate and advance the next strictly positive identity-wide monotonic write-token grant
    /// version (`1..MAX_SAFE_INTEGER`), so deleting and recreating a chat always exceeds any
    /// prior `revoked_below_version`.
    pub fn allocate_grant_version(&mut self) -> Result<u64> {
        let version = self.state.next_grant_version.max(1);
        let next = version
            .checked_add(1)
            .filter(|&n| n <= protocol::MAX_SAFE_INTEGER)
            .ok_or(ErrorKind::Protocol)?;
        self.state.next_grant_version = next;
        Ok(version)
    }

    /// Advance the unified mailbox cursor (`mailbox_cursor`) and pending server prefix ACK
    /// watermark (`pending_mailbox_ack`) monotonically after durably processing a fetched page.
    ///
    /// Fails with [`ErrorKind::InvalidArgument`] if either sequence exceeds
    /// [`protocol::MAX_SAFE_INTEGER`] or if `acked_through` exceeds the resulting cursor.
    pub fn commit_mailbox_page(&mut self, last_seq: u64, acked_through: u64) -> Result<()> {
        if last_seq > protocol::MAX_SAFE_INTEGER || acked_through > protocol::MAX_SAFE_INTEGER {
            return Err(ErrorKind::InvalidArgument.into());
        }
        let new_cursor = self.state.mailbox_cursor.max(last_seq);
        if acked_through > new_cursor {
            return Err(ErrorKind::InvalidArgument.into());
        }
        self.state.mailbox_cursor = new_cursor;
        self.state.pending_mailbox_ack = self.state.pending_mailbox_ack.max(acked_through);
        Ok(())
    }

    /// Clear `pending_mailbox_ack` once the server has confirmed deletion up to `acked_up_to`
    /// (e.g. via a piggybacked `FetchSigned.ack_up_to_sequence` on an empty page).
    pub fn clear_pending_mailbox_ack(&mut self, acked_up_to: u64) {
        if self.state.pending_mailbox_ack <= acked_up_to {
            self.state.pending_mailbox_ack = 0;
        }
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

    /// Remaining classical one-time prekey capacity in the latest local generation before hitting
    /// [`x3dh::MAX_ONE_TIME_PER_GENERATION`].
    pub fn remaining_one_time_headroom(&self) -> usize {
        self.state.prekeys.remaining_one_time_headroom()
    }

    /// Remaining total post-quantum one-time prekey capacity in the latest local generation before
    /// hitting [`x3dh::MAX_ONE_TIME_PER_GENERATION`].
    pub fn remaining_pq_one_time_headroom(&self) -> usize {
        self.state.prekeys.remaining_pq_one_time_headroom()
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
        start_upload_with(attachments, size).await
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

/// Milliseconds since the Unix epoch, by this device's clock.
fn now() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(protocol::MAX_SAFE_INTEGER)
        })
}

/// A message encrypted for the peer by [`Session::encrypt`], bound to the sealing session's
/// deniable write token and optional carried initial message so retries and session rotations
/// never cross-wire sessions.
///
/// Its `Debug` implementation redacts `write_token` and ciphertext bytes, and its `Drop`
/// implementation zeroizes `write_token` (and uniquely owned carried initial bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The encrypted Double Ratchet message.
    pub message: EncryptedMessage,
    /// Deniable 32-byte write-capability token captured from the sealing session at encrypt time.
    pub write_token: Zeroizing<[u8; WRITE_TOKEN_LENGTH]>,
    /// Encoded carried [`protocol::handshake_v2::InitialMessageV2`] captured from the sealing
    /// session while `!known_by_peer`, or `None` once the peer is known to have that session.
    pub initial_message: Option<Bytes>,
}

impl Drop for Sealed {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut *self.write_token);
        if let Some(mut carried) = self.initial_message.take() {
            zeroize_bytes(&mut carried);
        }
    }
}

impl zeroize::ZeroizeOnDrop for Sealed {}

impl core::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealed")
            .field("header_len", &self.message.header.len())
            .field("content_len", &self.message.content.len())
            .field("has_initial_message", &self.initial_message.is_some())
            .finish_non_exhaustive()
    }
}

impl Sealed {
    /// Deterministic 16-byte client idempotency identifier derived from an encrypted message
    /// (`SHA-256("session.v2/client-message-id\0" || len(header) || header || len(content) || content)[..16]`),
    /// stable across retries and restarts without leaking plaintext or keys.
    pub fn client_message_id_for(message: &EncryptedMessage) -> [u8; CLIENT_MESSAGE_ID_LENGTH] {
        let mut hasher = Sha256::new();
        hasher.update(b"session.v2/client-message-id\0");
        hasher.update((message.header.len() as u64).to_be_bytes());
        hasher.update(&message.header);
        hasher.update((message.content.len() as u64).to_be_bytes());
        hasher.update(&message.content);
        let digest = hasher.finalize();
        let mut id = [0u8; CLIENT_MESSAGE_ID_LENGTH];
        id.copy_from_slice(&digest[..CLIENT_MESSAGE_ID_LENGTH]);
        id
    }

    /// Deterministic 16-byte client idempotency identifier derived from this sealed ciphertext
    /// via [`Sealed::client_message_id_for`].
    pub fn client_message_id(&self) -> [u8; CLIENT_MESSAGE_ID_LENGTH] {
        Self::client_message_id_for(&self.message)
    }

    /// Build a sealed-sender-lite [`PushV2Request`] strictly from this [`Sealed`] envelope and
    /// `recipient` (no `sender`, no `delivery_hash`), using the deterministic
    /// [`Self::client_message_id`].
    pub fn push_v2_request(&self, recipient: &PublicKey) -> PushV2Request {
        self.push_v2_request_with_id(recipient, Some(self.client_message_id()))
    }

    /// Build a sealed-sender-lite [`PushV2Request`] strictly from this [`Sealed`] envelope and
    /// `recipient` with an explicit optional 16-byte `client_message_id`.
    pub fn push_v2_request_with_id(
        &self,
        recipient: &PublicKey,
        client_message_id: Option<[u8; CLIENT_MESSAGE_ID_LENGTH]>,
    ) -> PushV2Request {
        let initial_message = self
            .initial_message
            .as_deref()
            .and_then(decode_carried_initial);
        PushV2Request {
            recipient: Bytes::copy_from_slice(recipient),
            message: Some(self.message.clone()),
            initial_message,
            client_message_id: client_message_id
                .map_or_else(Bytes::new, |id| Bytes::copy_from_slice(&id)),
            write_token: Bytes::copy_from_slice(self.write_token.as_slice()),
        }
    }
}

/// A message decrypted synchronously by [`Session::decrypt_envelope`].
///
/// Its `Debug` implementation redacts decrypted `content` plaintext bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct DecryptedMessage {
    /// Decrypted plaintext content.
    pub content: Vec<u8>,
    /// Whether the message decrypted on an earlier archived session [kept](Session::keep) rather
    /// than the active one (e.g. sent before a rekey or before deleting the chat and starting
    /// again).
    pub earlier: bool,
}

impl core::fmt::Debug for DecryptedMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecryptedMessage")
            .field("content_len", &self.content.len())
            .field("earlier", &self.earlier)
            .finish()
    }
}

/// A session with one peer: encrypts and decrypts with a [`Party`] and pushes messages through
/// the v2 mailbox.
///
/// It may hold earlier sessions with the peer too, which only decrypt, see [`Session::keep`].
///
/// [`Session::restore`] brings back a session from its saved [`state`](Session::state).
#[derive(Debug)]
pub struct Session<M> {
    pub(crate) mailbox: M,
    pub(crate) state: SessionState,
}

/// What a [`Session`] keeps besides its transport: the double ratchets, both identity keys,
/// write-token routing material, pending grant registrations, and PQ policy state.
///
/// Save it to [`restore`](Session::restore) the session later: with `prost` convert it to a
/// `proto::SessionState` (portable versioned persistence), or serialize it with `serde`. It holds
/// the session's keys, so keep it secret; its `Debug` shows none of them.
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
    /// What was done last, and how many times the peers turned between sending on the active
    /// session and receiving on an earlier one, see [`Session::keep`].
    pub(crate) last: LastAction,
    pub(crate) direction_changes: u32,
    /// Per-peer post-quantum pinning, downgrade-detection, and `peer_session_seq` state.
    pub(crate) peer_pq: PeerPqState,
    /// Next outgoing monotonic `Hello.session_seq` for this peer (`0` treated as `1`).
    pub(crate) next_session_seq: u64,
    /// Pending write-token registrations queued for this peer (at most
    /// [`MAX_PENDING_REGISTER_GRANTS`]).
    pub(crate) pending_register_grants: Vec<PendingGrant>,
}

impl core::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionState")
            .field("active", &self.active)
            .field("others", &self.others)
            .field("me", &self.me)
            .field("peer", &self.peer)
            .field("last", &self.last)
            .field("direction_changes", &self.direction_changes)
            .field("peer_pq", &self.peer_pq)
            .field("next_session_seq", &self.next_session_seq)
            .field(
                "pending_register_grants",
                &self.pending_register_grants.len(),
            )
            .finish()
    }
}

/// The session a [`SessionState`] sends on.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct Active {
    pub(crate) party: Party,
    /// The session's ID, which both peers have: the X3DH/PQXDH ephemeral key of the one who
    /// started it.
    pub(crate) id: PublicKey,
    /// Whether the peer is known to have it: it started it, or a message on it decrypted.
    pub(crate) known_by_peer: bool,
    /// The initial message (`handshake.v2.InitialMessageV2`, encoded) that started it, which this
    /// client did: captured onto each [`Sealed`] message until the peer is known to have the
    /// session, in case the one in its inbox was lost. Empty once known.
    pub(crate) initial_message: Vec<u8>,
    /// Deniable 32-byte write-capability token `t_{me->peer}` authorizing `PushV2` to `peer`.
    pub(crate) send_write_token: WriteToken,
    /// `SHA-256(t_{peer->me})` registered on our relay and matched on fetched envelopes for O(1)
    /// `token_hash -> peer` dispatch.
    pub(crate) inbound_token_hash: [u8; WRITE_TOKEN_HASH_LENGTH],
    /// Negotiated cryptographic security metadata of this active session.
    #[cfg_attr(feature = "serde", serde(default))]
    pub(crate) security: SessionSecurity,
    /// Peer's `Hello.session_seq` that created this session (`0` if locally initiated or unset).
    #[cfg_attr(feature = "serde", serde(default))]
    pub(crate) peer_session_seq: u64,
}

/// An earlier session of a [`SessionState`], which only decrypts.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct Earlier {
    pub(crate) party: Party,
    /// `SHA-256(t_{peer->me})` copied from [`Active`] so earlier sessions also route O(1) in the
    /// unified recipient mailbox.
    pub(crate) inbound_token_hash: [u8; WRITE_TOKEN_HASH_LENGTH],
}

impl From<Active> for Earlier {
    fn from(active: Active) -> Self {
        Self {
            party: active.party,
            inbound_token_hash: active.inbound_token_hash,
        }
    }
}

/// A directional deniable write-capability token derived from X3DH/PQXDH's shared secret `SK`:
/// `HKDF-SHA256(None, SK, b"session.v2/write-token\0" || sender || recipient)`.
///
/// Both peers can derive both directions from `SK` (preserving deniability), while the relay only
/// ever stores `SHA-256(write_token)` under an opaque `peer_slot_id`. Its `Debug` shows nothing
/// of the token bytes.
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct WriteToken(pub(crate) [u8; WRITE_TOKEN_LENGTH]);

impl WriteToken {
    /// Derive the directional write token for messages sent by `sender` to `recipient` under
    /// X3DH/PQXDH shared secret `secret`.
    pub(crate) fn derive(secret: &[u8], sender: &PublicKey, recipient: &PublicKey) -> Self {
        let mut info = [0u8; WRITE_TOKEN_INFO_PREFIX.len() + 64];
        info[..WRITE_TOKEN_INFO_PREFIX.len()].copy_from_slice(WRITE_TOKEN_INFO_PREFIX);
        info[WRITE_TOKEN_INFO_PREFIX.len()..WRITE_TOKEN_INFO_PREFIX.len() + 32]
            .copy_from_slice(sender);
        info[WRITE_TOKEN_INFO_PREFIX.len() + 32..].copy_from_slice(recipient);
        let mut key = [0u8; WRITE_TOKEN_LENGTH];
        Hkdf::<Sha256>::new(None, secret)
            .expand(&info, &mut key)
            .expect("32 bytes are a valid HKDF-SHA256 output length");
        Self(key)
    }

    /// Derive `(send_write_token = t_{me->peer}, inbound_token_hash = SHA-256(t_{peer->me}))`
    /// from X3DH/PQXDH shared secret `secret`.
    pub(crate) fn pair(
        secret: &[u8],
        me: &PublicKey,
        peer: &PublicKey,
    ) -> (Self, [u8; WRITE_TOKEN_HASH_LENGTH]) {
        let send = Self::derive(secret, me, peer);
        let inbound_hash = Self::derive(secret, peer, me).hash();
        (send, inbound_hash)
    }

    /// `SHA-256(self)` as stored on the relay and returned on `EnvelopeV2.token_hash`.
    pub(crate) fn hash(&self) -> [u8; WRITE_TOKEN_HASH_LENGTH] {
        Sha256::digest(self.0).into()
    }

    /// Copy out a zeroizing handle to the 32-byte write token.
    pub(crate) fn as_zeroizing(&self) -> Zeroizing<[u8; WRITE_TOKEN_LENGTH]> {
        Zeroizing::new(self.0)
    }
}

impl core::fmt::Debug for WriteToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WriteToken(..)")
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
    counters: [u64; 3],
    pinned_manifest_digest: Option<[u8; 32]>,
    pending_register_grants: &[PendingGrant],
    earlier: impl ExactSizeIterator<Item = &'a [u8]>,
    active: Option<ActiveStateView<'a>>,
) -> Result<()> {
    let pinned_manifest_seq = counters[1];
    if [me, peer]
        .into_iter()
        .any(|key| !xeddsa::is_canonical_public_key(key) || XEdDSAPublicKey::new(key).is_err())
        || earlier.len() > KEPT_SESSIONS
        || pending_register_grants.len() > MAX_PENDING_REGISTER_GRANTS
        || counters
            .into_iter()
            .any(|seq| seq > protocol::MAX_SAFE_INTEGER)
        || (pinned_manifest_seq == 0 && pinned_manifest_digest.is_some())
    {
        return Err(ErrorKind::MalformedState.into());
    }
    for (idx, grant) in pending_register_grants.iter().enumerate() {
        if grant.grant_version == 0 || grant.grant_version > protocol::MAX_SAFE_INTEGER {
            return Err(ErrorKind::MalformedState.into());
        }
        if pending_register_grants[..idx]
            .iter()
            .any(|prev| prev.token_hash == grant.token_hash)
        {
            return Err(ErrorKind::MalformedState.into());
        }
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

    /// `SHA-256(t_{peer->me})` of the active session, if any.
    pub fn active_inbound_token_hash(&self) -> Option<[u8; WRITE_TOKEN_HASH_LENGTH]> {
        self.active.as_ref().map(|active| active.inbound_token_hash)
    }

    /// All inbound write-token hashes (`SHA-256(t_{peer->me})`) for O(1) mailbox dispatch across
    /// the active session and all kept earlier sessions.
    pub fn inbound_token_hashes(&self) -> impl Iterator<Item = [u8; WRITE_TOKEN_HASH_LENGTH]> + '_ {
        self.active
            .iter()
            .map(|active| active.inbound_token_hash)
            .chain(self.others.iter().map(|earlier| earlier.inbound_token_hash))
    }

    /// Inbound write-token hashes (`SHA-256(t_{peer->me})`) of all kept earlier (archived)
    /// sessions.
    pub fn earlier_inbound_token_hashes(
        &self,
    ) -> impl Iterator<Item = [u8; WRITE_TOKEN_HASH_LENGTH]> + '_ {
        self.others.iter().map(|earlier| earlier.inbound_token_hash)
    }

    /// Queued write-token registrations awaiting relay confirmation.
    pub fn pending_register_grants(&self) -> &[PendingGrant] {
        &self.pending_register_grants
    }

    /// Validate canonical keys, bounded collections, integer bounds, AD identity-pair bindings,
    /// pending grants, and PQ metadata invariants.
    #[cfg(any(feature = "prost", feature = "serde"))]
    fn validate(&self) -> Result<()> {
        validate_session_state(
            &self.me,
            &self.peer,
            [
                self.next_session_seq,
                self.peer_pq.pinned_manifest_seq,
                self.peer_pq.peer_session_seq,
            ],
            self.peer_pq.pinned_manifest_digest,
            &self.pending_register_grants,
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
    last: LastAction,
    direction_changes: u32,
    #[serde(default)]
    peer_pq: PeerPqState,
    #[serde(default)]
    next_session_seq: u64,
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_vec::<_, _, MAX_PENDING_REGISTER_GRANTS>"
    )]
    pending_register_grants: Vec<PendingGrant>,
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
            last: raw.last,
            direction_changes: raw.direction_changes,
            peer_pq: raw.peer_pq,
            next_session_seq: raw.next_session_seq,
            pending_register_grants: raw.pending_register_grants,
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
impl From<&PendingGrant> for proto::PendingGrant {
    fn from(grant: &PendingGrant) -> Self {
        Self {
            token_hash: grant.token_hash.to_vec(),
            grant_version: grant.grant_version,
            pin_active: grant.pin_active,
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&proto::PendingGrant> for PendingGrant {
    type Error = Error;

    fn try_from(grant: &proto::PendingGrant) -> Result<Self> {
        let token_hash: [u8; WRITE_TOKEN_HASH_LENGTH] = grant
            .token_hash
            .as_slice()
            .try_into()
            .map_err(|_| Error::from(ErrorKind::MalformedState))?;
        if grant.grant_version == 0 || grant.grant_version > protocol::MAX_SAFE_INTEGER {
            return Err(ErrorKind::MalformedState.into());
        }
        Ok(Self {
            token_hash,
            grant_version: grant.grant_version,
            pin_active: grant.pin_active,
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
            others: state
                .others
                .iter()
                .map(|earlier| proto::EarlierSession {
                    party: Some((&earlier.party).into()),
                    inbound_token_hash: earlier.inbound_token_hash.to_vec(),
                })
                .collect(),
            me: state.me.to_vec(),
            peer: state.peer.to_vec(),
            last: match state.last {
                LastAction::None => proto::LastAction::Unspecified,
                LastAction::Sent => proto::LastAction::Sent,
                LastAction::ReceivedActive => proto::LastAction::ReceivedActive,
                LastAction::ReceivedEarlier => proto::LastAction::ReceivedEarlier,
            }
            .into(),
            direction_changes: state.direction_changes,
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
            send_write_token: state
                .active
                .as_ref()
                .map(|active| active.send_write_token.0.to_vec())
                .unwrap_or_default(),
            inbound_token_hash: state
                .active
                .as_ref()
                .map(|active| active.inbound_token_hash.to_vec())
                .unwrap_or_default(),
            pending_register_grants: state
                .pending_register_grants
                .iter()
                .map(proto::PendingGrant::from)
                .collect(),
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&proto::SessionState> for SessionState {
    type Error = Error;

    fn try_from(state: &proto::SessionState) -> Result<Self> {
        /// A fixed 32-byte key or hash field.
        fn fixed32(bytes: &[u8]) -> Result<[u8; 32]> {
            bytes
                .try_into()
                .map_err(|_| ErrorKind::MalformedState.into())
        }

        if state.others.len() > KEPT_SESSIONS
            || state.pending_register_grants.len() > MAX_PENDING_REGISTER_GRANTS
        {
            return Err(ErrorKind::MalformedState.into());
        }

        let me = fixed32(&state.me)?;
        let peer = fixed32(&state.peer)?;

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
                    id: fixed32(&state.id)?,
                    known_by_peer: state.known_by_peer,
                    initial_message: state.initial_message.clone(),
                    send_write_token: WriteToken(fixed32(&state.send_write_token)?),
                    inbound_token_hash: fixed32(&state.inbound_token_hash)?,
                    security,
                    peer_session_seq: state.active_peer_session_seq,
                })
            }
            None => {
                if !state.id.is_empty()
                    || !state.send_write_token.is_empty()
                    || !state.inbound_token_hash.is_empty()
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
        let pending_register_grants = state
            .pending_register_grants
            .iter()
            .map(PendingGrant::try_from)
            .collect::<Result<Vec<_>>>()?;
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
                        inbound_token_hash: fixed32(&earlier.inbound_token_hash)?,
                    })
                })
                .collect::<Result<_>>()?,
            me,
            peer,
            last,
            direction_changes: state.direction_changes,
            peer_pq,
            next_session_seq: state.next_session_seq,
            pending_register_grants,
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
                last,
                direction_changes: 0,
                peer_pq: PeerPqState::default(),
                next_session_seq: 0,
                pending_register_grants: vec![],
            },
        )
    }

    /// A session over `mailbox`, from the `state` of an earlier one.
    pub fn restore(mailbox: M, state: SessionState) -> Self {
        Self { mailbox, state }
    }

    /// What to save to [`restore`](Session::restore) this session later. It changes with every
    /// message encrypted or decrypted, so save it after each.
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
    /// [`Client::start_again_v2`] before sending.
    pub fn needs_new_session(&self) -> bool {
        self.state.active.is_none()
    }

    /// The ID of the session messages are sent on, if any, which both peers have: the X3DH/PQXDH
    /// ephemeral key of the one who started it.
    pub fn active_id(&self) -> Option<&PublicKey> {
        self.state.active.as_ref().map(|active| &active.id)
    }

    /// Whether the peer is known to have the active session (the peer initiated it, or a message
    /// decrypted on it).
    pub fn is_known_by_peer(&self) -> bool {
        self.state
            .active
            .as_ref()
            .is_some_and(|active| active.known_by_peer)
    }

    /// Build a wire [`protocol::handshake_v2::SendInitialV2Request`] for the active session's
    /// carried `initial_message`, if any (used to retry an unconfirmed initial greeting).
    pub fn pending_initial_request(&self) -> Option<protocol::handshake_v2::SendInitialV2Request> {
        let raw = &self.state.active.as_ref()?.initial_message;
        if raw.is_empty() {
            return None;
        }
        let wire = decode_carried_initial(raw)?;
        Some(protocol::handshake_v2::SendInitialV2Request {
            recipient: Bytes::copy_from_slice(&self.state.peer),
            message: Some(wire),
        })
    }

    /// `SHA-256(t_{peer->me})` of the active session, if any (the hash to register on our relay
    /// via [`Client::register_write_token_v2`]).
    pub fn active_inbound_token_hash(&self) -> Option<[u8; WRITE_TOKEN_HASH_LENGTH]> {
        self.state.active_inbound_token_hash()
    }

    /// All inbound write-token hashes (`SHA-256(t_{peer->me})`) across the active session and all
    /// kept earlier sessions, for O(1) `EnvelopeV2.token_hash -> peer` dispatch.
    pub fn inbound_token_hashes(&self) -> impl Iterator<Item = [u8; WRITE_TOKEN_HASH_LENGTH]> + '_ {
        self.state.inbound_token_hashes()
    }

    /// Inbound write-token hashes (`SHA-256(t_{peer->me})`) of all kept earlier (archived)
    /// sessions.
    pub fn earlier_inbound_token_hashes(
        &self,
    ) -> impl Iterator<Item = [u8; WRITE_TOKEN_HASH_LENGTH]> + '_ {
        self.state.earlier_inbound_token_hashes()
    }

    /// Queued write-token registrations awaiting relay confirmation.
    pub fn pending_register_grants(&self) -> &[PendingGrant] {
        &self.state.pending_register_grants
    }

    /// Whether the active session's inbound write token still has a pending registration awaiting
    /// relay confirmation.
    pub fn has_pending_active_grant(&self) -> bool {
        self.active_inbound_token_hash().is_some_and(|active_hash| {
            self.state
                .pending_register_grants
                .iter()
                .any(|g| g.token_hash == active_hash)
        })
    }

    /// Stage a write-token grant registration on this session, deduplicating by `token_hash` and
    /// capping at [`MAX_PENDING_REGISTER_GRANTS`] while strictly preserving the active session's
    /// inbound token hash.
    pub fn queue_pending_grant(&mut self, grant: PendingGrant) -> Result<()> {
        if grant.grant_version == 0 || grant.grant_version > protocol::MAX_SAFE_INTEGER {
            return Err(ErrorKind::InvalidArgument.into());
        }
        let active_hash = self.active_inbound_token_hash();
        merge_pending_grants(
            &mut self.state.pending_register_grants,
            vec![grant],
            active_hash,
        );
        Ok(())
    }

    /// Remove any staged pending grant matching `token_hash` with `grant_version <= confirmed_version`
    /// once [`Client::register_write_token_v2`] succeeds. Returns whether an entry was removed.
    pub fn remove_pending_grant(
        &mut self,
        token_hash: &[u8; WRITE_TOKEN_HASH_LENGTH],
        confirmed_version: u64,
    ) -> bool {
        let before = self.state.pending_register_grants.len();
        self.state
            .pending_register_grants
            .retain(|g| !(g.token_hash == *token_hash && g.grant_version <= confirmed_version));
        self.state.pending_register_grants.len() != before
    }

    /// Drop all staged pending write-token registrations on this session.
    pub fn clear_pending_grants(&mut self) {
        self.state.pending_register_grants.clear();
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
    /// When called immediately after [`Client::accept_initial_v2`] with the active peer-initiated
    /// session's own greeting (`hello.session_seq > 0` matching
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
    /// to decrypt, such as the messages the peer sent on `older` before starting this one; any
    /// staged `pending_register_grants` are deduplicated and merged.
    ///
    /// Of the sessions, one is active: messages are sent on it, so each peer answers the other
    /// on it and its ratchet keeps stepping, as Signal's session management (Tahini) does. An
    /// earlier session never becomes active again, as whoever stole its keys could otherwise
    /// make this client send on it again, where they read everything, though the ratchet has
    /// since locked them out of the active one. A session this client starts becomes active.
    /// One the peer starts does too, unless the active one is this client's and the peer has
    /// not answered it: then both started one at once, and the one whose ID, the X3DH/PQXDH
    /// ephemeral key of who started it, is higher wins, on both sides (preferring PQ over
    /// classical). If the peers still miss each other, e.g. as an initial message was lost or a
    /// chat deleted, the peer's messages decrypt only on earlier sessions while this client sends
    /// on the active one; after [`MAX_DIRECTION_CHANGES`] turns between the two, the active
    /// session is retired, and the next message goes on a new one, see
    /// [`Session::needs_new_session`].
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
    /// crossed-start tie-breaking, PQ-pin downgrade defense, and `pending_register_grants` merge.
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
                // `session_seq == 0` is tolerated ONLY while high_water == 0.
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

        state.next_session_seq = state.next_session_seq.max(new.next_session_seq);
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

        let incoming_grants = mem::take(&mut new.pending_register_grants);
        let took_over = if let Some(active) = new.active.take() {
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
                true
            } else {
                // Its first message decrypted, on what is now an earlier session.
                state.archive(active.into());
                state.received_earlier();
                if state.active.as_ref().is_some_and(|a| a.security.is_pq) {
                    state.peer_pq.downgrade_detected = false;
                    state.peer_pq.allow_classical_exception = false;
                }
                false
            }
        } else {
            false
        };

        let active_hash = state.active.as_ref().map(|a| a.inbound_token_hash);
        merge_pending_grants(
            &mut state.pending_register_grants,
            incoming_grants,
            active_hash,
        );
        Ok(took_over)
    }

    /// Synchronously decrypt a fetched `EncryptedMessage` using the active session or any kept
    /// earlier session.
    ///
    /// - On active-session decryption, marks `known_by_peer = true` and clears the active
    ///   session's carried `initial_message`.
    /// - On earlier-session decryption, tracks `direction_changes` and retires `active` after
    ///   [`MAX_DIRECTION_CHANGES`] alternating turns.
    /// - Surfaces [`ErrorKind::DuplicateMessage`], [`ErrorKind::EvictedMessage`], and
    ///   [`ErrorKind::Undecryptable`] distinctly.
    pub fn decrypt_envelope(&mut self, message: &EncryptedMessage) -> Result<DecryptedMessage> {
        let state = &mut self.state;
        let mut error = None;
        let mut duplicate = None;
        let mut evicted = None;
        if let Some(active) = &mut state.active {
            match active.party.decrypt(message) {
                Ok(content) => {
                    active.known_by_peer = true;
                    active.initial_message = vec![];
                    state.last = LastAction::ReceivedActive;
                    return Ok(DecryptedMessage {
                        content,
                        earlier: false,
                    });
                }
                Err(e) if e.kind() == party::error::ErrorKind::DuplicateMessage => {
                    duplicate = Some(e);
                }
                Err(e) if e.kind() == party::error::ErrorKind::EvictedMessage => {
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
                    state.received_earlier();
                    return Ok(DecryptedMessage {
                        content,
                        earlier: true,
                    });
                }
                Err(e) if e.kind() == party::error::ErrorKind::DuplicateMessage => {
                    duplicate = Some(e);
                }
                Err(e) if e.kind() == party::error::ErrorKind::EvictedMessage => {
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

    /// Encrypt `content` for the peer on the active session, capturing both the active session's
    /// deniable `send_write_token` and optional carried `initial_message` at seal time so pushing
    /// after a session rotation or retirement stays bound to the sealing session.
    ///
    /// Fails with [`ErrorKind::NoSession`] if it has none, see [`Session::needs_new_session`].
    pub fn encrypt(&mut self, content: &[u8]) -> Result<Sealed> {
        let state = &mut self.state;
        let active = state.active.as_mut().ok_or(ErrorKind::NoSession)?;
        let message = active.party.encrypt(content)?;
        let write_token = active.send_write_token.as_zeroizing();
        let initial_message = (!active.initial_message.is_empty())
            .then(|| Bytes::copy_from_slice(&active.initial_message));
        if state.last == LastAction::ReceivedEarlier {
            state.direction_changes = state.direction_changes.saturating_add(1);
        }
        state.last = LastAction::Sent;
        Ok(Sealed {
            message,
            write_token,
            initial_message,
        })
    }
}

#[cfg(test)]
mod test {
    use core::cell::Cell;
    use std::sync::Arc;

    use protocol::{
        attachment::AttachmentServer,
        handshake_v2::{
            AckInitialMessagesRequest, AckInitialMessagesResponse, ClaimBundleRequest,
            ClaimBundleResponse, GetManifestRequest, GetManifestResponse, GetServerInfoRequest,
            GetServerInfoResponse, HandshakeV2Server, ListInitialMessagesRequest,
            ListInitialMessagesResponse, LocalHandshakeV2, PublishV2Request, PublishV2Response,
            RefillPrekeysRequest, RefillPrekeysResponse, SendInitialV2Request,
            SendInitialV2Response, ServerInfoConfig,
        },
        mailbox_v2::{
            AckMessagesRequest, AckMessagesResponse, EnvelopeV2, FetchSignedRequest,
            FetchSignedResponse, LocalMailboxV2, MailboxV2Server, PushV2Response,
            RegisterWriteTokenRequest, RegisterWriteTokenResponse, RevokeWriteTokenRequest,
            RevokeWriteTokenResponse,
        },
    };
    #[cfg(feature = "serde")]
    use ratchetx2::DhPrivateKey;
    #[cfg(any(feature = "serde", feature = "ml-kem-1024", feature = "ml-kem-768"))]
    use ratchetx2::{Ratchet, SharedKeys};
    use storage::MemoryStore;

    use super::*;

    const AUDIENCE: &str = "relay.example";

    #[derive(Debug, Clone, Default)]
    struct SharedStore(Arc<MemoryStore>);

    impl storage::LocalPqHandshakeStore for SharedStore {
        async fn publish_v2(
            &self,
            record: storage::PublishV2Record,
        ) -> storage::Result<storage::PublishV2Status> {
            storage::PqHandshakeStore::publish_v2(&*self.0, record).await
        }
        async fn refill_prekeys(
            &self,
            record: storage::RefillPrekeysRecord,
        ) -> storage::Result<storage::RefillStatus> {
            storage::PqHandshakeStore::refill_prekeys(&*self.0, record).await
        }
        async fn get_manifest(
            &self,
            identity_key: &PublicKey,
        ) -> storage::Result<Option<storage::StoredCapabilityManifest>> {
            storage::PqHandshakeStore::get_manifest(&*self.0, identity_key).await
        }
        async fn claim_bundle(
            &self,
            identity_key: &PublicKey,
            preferred_suites: &[u8],
        ) -> storage::Result<Option<storage::ClaimedPqBundle>> {
            storage::PqHandshakeStore::claim_bundle(&*self.0, identity_key, preferred_suites).await
        }
        async fn claim_bundle_checked(
            &self,
            identity_key: &PublicKey,
            preferred_suites: &[u8],
            reject_pq_on_manifest: bool,
        ) -> storage::Result<storage::ClaimOutcome> {
            storage::PqHandshakeStore::claim_bundle_checked(
                &*self.0,
                identity_key,
                preferred_suites,
                reject_pq_on_manifest,
            )
            .await
        }
        async fn add_initial_message_v2(
            &self,
            initial_message: storage::StoredInitialMessageV2,
            limit: usize,
        ) -> storage::Result<Option<u64>> {
            storage::PqHandshakeStore::add_initial_message_v2(&*self.0, initial_message, limit)
                .await
        }
        async fn add_initial_message_v2_checked(
            &self,
            initial_message: storage::StoredInitialMessageV2,
            limit: usize,
            allow_insert: bool,
        ) -> storage::Result<storage::InitialDisposition> {
            storage::PqHandshakeStore::add_initial_message_v2_checked(
                &*self.0,
                initial_message,
                limit,
                allow_insert,
            )
            .await
        }
        async fn list_initial_messages(
            &self,
            recipient: &PublicKey,
            after_id: u64,
            limit: usize,
        ) -> storage::Result<Vec<storage::StoredInitialMessageV2>> {
            storage::PqHandshakeStore::list_initial_messages(&*self.0, recipient, after_id, limit)
                .await
        }
        async fn list_initial_messages_page(
            &self,
            recipient: &PublicKey,
            after_id: u64,
            limit: usize,
        ) -> storage::Result<storage::InitialMessagePage> {
            storage::PqHandshakeStore::list_initial_messages_page(
                &*self.0, recipient, after_id, limit,
            )
            .await
        }
        async fn ack_initial_messages(
            &self,
            recipient: &PublicKey,
            ids: &[u64],
        ) -> storage::Result<usize> {
            storage::PqHandshakeStore::ack_initial_messages(&*self.0, recipient, ids).await
        }
        async fn pq_snapshot(
            &self,
            identity_key: &PublicKey,
        ) -> storage::Result<storage::PqStorageSnapshot> {
            storage::PqHandshakeStore::pq_snapshot(&*self.0, identity_key).await
        }
    }

    impl storage::LocalIdempotentMailboxStore for SharedStore {
        async fn append_idempotent(
            &self,
            recipient: &PublicKey,
            token_hash: &[u8; 32],
            header: Bytes,
            content: Bytes,
            initial_message: Option<Bytes>,
            client_message_id: Option<[u8; 16]>,
        ) -> storage::Result<u64> {
            storage::IdempotentMailboxStore::append_idempotent(
                &*self.0,
                recipient,
                token_hash,
                header,
                content,
                initial_message,
                client_message_id,
            )
            .await
        }
        async fn read_mailbox(
            &self,
            recipient: &PublicKey,
            after_sequence: u64,
            limit: u32,
            max_size: usize,
            ack_up_to_sequence: u64,
        ) -> storage::Result<storage::MailboxPage> {
            storage::IdempotentMailboxStore::read_mailbox(
                &*self.0,
                recipient,
                after_sequence,
                limit,
                max_size,
                ack_up_to_sequence,
            )
            .await
        }
        async fn ack_messages(
            &self,
            recipient: &PublicKey,
            up_to_sequence: u64,
        ) -> storage::Result<u64> {
            storage::IdempotentMailboxStore::ack_messages(&*self.0, recipient, up_to_sequence).await
        }
        async fn register_write_token(
            &self,
            record: storage::RegisterWriteTokenRecord,
        ) -> storage::Result<()> {
            storage::IdempotentMailboxStore::register_write_token(&*self.0, record).await
        }
        async fn revoke_write_token(
            &self,
            record: storage::RevokeWriteTokenRecord,
        ) -> storage::Result<u32> {
            storage::IdempotentMailboxStore::revoke_write_token(&*self.0, record).await
        }
    }

    #[derive(Clone)]
    struct InProcessHandshake(Arc<HandshakeV2Server<SharedStore>>);

    impl InProcessHandshake {
        fn new(store: SharedStore) -> Self {
            Self(Arc::new(HandshakeV2Server::new(
                store,
                ServerInfoConfig::new(AUDIENCE),
            )))
        }
    }

    impl LocalHandshakeV2 for InProcessHandshake {
        async fn get_server_info(
            &self,
            r: GetServerInfoRequest,
        ) -> protocol::Result<GetServerInfoResponse> {
            self.0.get_server_info(r).await
        }
        async fn publish_v2(&self, r: PublishV2Request) -> protocol::Result<PublishV2Response> {
            self.0.publish_v2(r).await
        }
        async fn refill_prekeys(
            &self,
            r: RefillPrekeysRequest,
        ) -> protocol::Result<RefillPrekeysResponse> {
            self.0.refill_prekeys(r).await
        }
        async fn get_manifest(
            &self,
            r: GetManifestRequest,
        ) -> protocol::Result<GetManifestResponse> {
            self.0.get_manifest(r).await
        }
        async fn claim_bundle(
            &self,
            r: ClaimBundleRequest,
        ) -> protocol::Result<ClaimBundleResponse> {
            self.0.claim_bundle(r).await
        }
        async fn send_initial_v2(
            &self,
            r: SendInitialV2Request,
        ) -> protocol::Result<SendInitialV2Response> {
            self.0.send_initial_v2(r).await
        }
        async fn list_initial_messages(
            &self,
            r: ListInitialMessagesRequest,
        ) -> protocol::Result<ListInitialMessagesResponse> {
            self.0.list_initial_messages(r).await
        }
        async fn ack_initial_messages(
            &self,
            r: AckInitialMessagesRequest,
        ) -> protocol::Result<AckInitialMessagesResponse> {
            self.0.ack_initial_messages(r).await
        }
    }

    #[derive(Debug, Clone)]
    struct InProcessMailbox(Arc<MailboxV2Server<SharedStore>>);

    impl InProcessMailbox {
        fn new(store: SharedStore) -> Self {
            Self(Arc::new(MailboxV2Server::new(store, AUDIENCE)))
        }
    }

    impl LocalMailboxV2 for InProcessMailbox {
        async fn push_v2(&self, r: PushV2Request) -> protocol::Result<PushV2Response> {
            self.0.push_v2(r).await
        }
        async fn fetch_signed(
            &self,
            r: FetchSignedRequest,
        ) -> protocol::Result<FetchSignedResponse> {
            self.0.fetch_signed(r).await
        }
        async fn ack_messages(
            &self,
            r: AckMessagesRequest,
        ) -> protocol::Result<AckMessagesResponse> {
            self.0.ack_messages(r).await
        }
        async fn register_write_token(
            &self,
            r: RegisterWriteTokenRequest,
        ) -> protocol::Result<RegisterWriteTokenResponse> {
            self.0.register_write_token(r).await
        }
        async fn revoke_write_token(
            &self,
            r: RevokeWriteTokenRequest,
        ) -> protocol::Result<RevokeWriteTokenResponse> {
            self.0.revoke_write_token(r).await
        }
    }

    /// Register `session`'s active inbound write token on `client`'s mailbox server.
    async fn register_active_grant<H, M>(
        client: &mut Client<H>,
        session: &Session<M>,
        mailbox: &InProcessMailbox,
    ) {
        let token_hash = session.active_inbound_token_hash().unwrap();
        let ver = client.allocate_grant_version().unwrap();
        client
            .register_write_token_v2(mailbox, AUDIENCE, session.peer(), &token_hash, ver, true)
            .await
            .unwrap();
    }

    /// Fetch, decrypt matching envelopes for `session`, commit page, and ACK on server.
    async fn receive_for<H, M>(
        client: &mut Client<H>,
        session: &mut Session<M>,
        mailbox: &InProcessMailbox,
    ) -> Vec<Result<DecryptedMessage>> {
        let page = client
            .fetch_mailbox_v2(mailbox, AUDIENCE, 100)
            .await
            .unwrap();
        let mut results = Vec::new();
        let hashes: Vec<[u8; 32]> = session.inbound_token_hashes().collect();
        for env in &page.messages {
            let hash: [u8; 32] = env.token_hash.as_ref().try_into().unwrap();
            if hashes.contains(&hash) {
                results.push(session.decrypt_envelope(env.message.as_ref().unwrap()));
            }
        }
        if let Some(last) = page.last_sequence() {
            client.commit_mailbox_page(last, last).unwrap();
            client.ack_mailbox_v2(mailbox, AUDIENCE).await.unwrap();
        } else if page.piggybacked_ack > 0 {
            client.clear_pending_mailbox_ack(page.piggybacked_ack);
        }
        results
    }

    fn contents(results: Vec<Result<DecryptedMessage>>) -> Vec<Vec<u8>> {
        results.into_iter().map(|r| r.unwrap().content).collect()
    }

    /// Count messages currently queued in `store` for `recipient`.
    async fn queued(store: &SharedStore, recipient: &PublicKey) -> usize {
        storage::IdempotentMailboxStore::read_mailbox(&*store.0, recipient, 0, 100, 1 << 20, 0)
            .await
            .unwrap()
            .messages
            .len()
    }

    /// Accept the oldest inbox initial for `client` from `peer`, keeping `session`, acking inbox,
    /// and registering the new session's inbound write token on `mailbox`.
    async fn accept_keeping(
        client: &mut Client<InProcessHandshake>,
        peer: &PublicKey,
        session: &mut Session<InProcessMailbox>,
        mailbox: &InProcessMailbox,
    ) -> Vec<u8> {
        let listed = client
            .list_initial_messages_v2(AUDIENCE, 0, 10)
            .await
            .unwrap();
        let msg = listed
            .messages
            .iter()
            .find(|m| m.sender == *peer)
            .expect("initial message from peer");
        let AcceptedInitial::Accepted {
            session: accepted,
            first_message,
            ..
        } = client
            .accept_initial_v2(peer, session.peer_pq_state(), msg, mailbox.clone())
            .unwrap()
        else {
            panic!("expected accepted initial");
        };
        let new_hash = accepted.active_inbound_token_hash().unwrap();
        let took_over = session.accept_replacement(accepted).unwrap();
        let ver = client.allocate_grant_version().unwrap();
        client
            .register_write_token_v2(mailbox, AUDIENCE, peer, &new_hash, ver, took_over)
            .await
            .unwrap();
        client
            .ack_initial_messages_v2(AUDIENCE, vec![msg.id])
            .await
            .unwrap();
        first_message
    }

    /// Alice and Bob, who have published v2 keys, exchanged grants, and talked ("hi" / "hello").
    async fn talking(
        hs: &InProcessHandshake,
        mb: &InProcessMailbox,
    ) -> (
        Client<InProcessHandshake>,
        Session<InProcessMailbox>,
        Client<InProcessHandshake>,
        Session<InProcessMailbox>,
    ) {
        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs.clone());
        alice.publish_v2(AUDIENCE, 5, 5).await.unwrap();
        bob.publish_v2(AUDIENCE, 5, 5).await.unwrap();

        let mut alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"hi",
                mb.clone(),
            )
            .await
            .unwrap();
        register_active_grant(&mut alice, &alice_session, mb).await;

        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let batch = bob.accept_listed_v2(&listed, mb.clone(), |_| PeerPqState::default());
        bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
            .await
            .unwrap();
        let (
            _,
            AcceptedInitial::Accepted {
                session: mut bob_session,
                first_message,
                ..
            },
        ) = batch.outcomes.into_iter().next().unwrap()
        else {
            panic!("expected accepted");
        };
        assert_eq!(first_message, b"hi");
        register_active_grant(&mut bob, &bob_session, mb).await;

        bob_session.send_v2(b"hello").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut alice, &mut alice_session, mb).await),
            [b"hello"]
        );
        (alice, alice_session, bob, bob_session)
    }

    /// Whether `a` and `b` send on one session.
    fn on_one_session<M>(a: &Session<M>, b: &Session<M>) -> bool {
        matches!(
            (&a.state.active, &b.state.active),
            (Some(a), Some(b)) if a.id == b.id
        )
    }

    #[cfg(feature = "prost")]
    fn restored<T, P>(state: &T) -> T
    where
        P: prost::Message + Default + for<'a> From<&'a T>,
        T: for<'a> TryFrom<&'a P, Error = Error>,
    {
        let saved = P::from(state).encode_to_vec();
        T::try_from(&P::decode(saved.as_slice()).unwrap()).unwrap()
    }

    #[test]
    fn write_token_derivation_deniability_and_peer_slot_id_opaqueness() {
        let sk = [0x42u8; 32];
        let alice = Client::new(());
        let bob = Client::new(());
        let carol = Client::new(());
        let (a_pk, b_pk, c_pk) = (
            alice.identity_key(),
            bob.identity_key(),
            carol.identity_key(),
        );

        let (a_send, a_in_hash) = WriteToken::pair(&sk, &a_pk, &b_pk);
        let (b_send, b_in_hash) = WriteToken::pair(&sk, &b_pk, &a_pk);

        // Directional tokens are distinct yet match across peers (and either side can compute both,
        // preserving deniability).
        assert_ne!(a_send.0, b_send.0);
        assert_eq!(a_send.hash(), b_in_hash);
        assert_eq!(b_send.hash(), a_in_hash);
        assert_eq!(format!("{a_send:?}"), "WriteToken(..)");

        // Different shared secrets produce independent tokens.
        let other = WriteToken::derive(&[0x43u8; 32], &a_pk, &b_pk);
        assert_ne!(other.0, a_send.0);

        // `peer_slot_id` is deterministic per `(identity_sk, peer)`, opaque (never equals `peer`),
        // and distinct across peers and across identities.
        let slot_ab = alice.peer_slot_id(&b_pk);
        let slot_ab_again = alice.peer_slot_id(&b_pk);
        let slot_ac = alice.peer_slot_id(&c_pk);
        let slot_ba = bob.peer_slot_id(&a_pk);
        assert_eq!(slot_ab, slot_ab_again);
        assert_ne!(slot_ab, b_pk);
        assert_ne!(slot_ab, slot_ac);
        assert_ne!(slot_ab, slot_ba);
    }

    #[tokio::test]
    async fn sealed_binds_write_token_and_carried_initial_to_sealing_session_and_redacts_debug() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (mut alice, mut alice_session, mut bob, mut bob_session) = talking(&hs, &mb).await;

        // Alice starts session S2 (unconfirmed: `!known_by_peer`, carries S2's initial) and seals
        // a message on S2, then immediately rotates to S3 BEFORE pushing S2's sealed message.
        alice
            .start_again_v2(AUDIENCE, &mut alice_session, b"s2-hello")
            .await
            .unwrap();
        let s2_id = *alice_session.active_id().unwrap();
        let s2_sealed = alice_session.encrypt(b"s2-body").unwrap();
        assert!(s2_sealed.initial_message.is_some());

        // Redacted `Debug` never leaks write_token bytes or header/content ciphertext.
        let dbg = format!("{s2_sealed:?}");
        assert!(dbg.contains("Sealed"));
        assert!(!dbg.contains(&format!("{:?}", &s2_sealed.write_token[..4])));

        // Rotate to S3 and retire!
        alice
            .start_again_v2(AUDIENCE, &mut alice_session, b"s3-hello")
            .await
            .unwrap();
        let s3_id = *alice_session.active_id().unwrap();
        assert_ne!(s2_id, s3_id);
        alice_session.retire();

        // Building `PushV2Request` from `s2_sealed` even after rotating/retiring MUST still bind
        // S2's write_token AND S2's carried initial message (NOT S3's or None)!
        let req = alice_session.push_v2_request(&s2_sealed);
        assert_eq!(req.write_token.as_ref(), s2_sealed.write_token.as_slice());
        assert_eq!(
            req.initial_message.as_ref().unwrap().ephemeral_key.as_ref(),
            &s2_id
        );
        assert_eq!(
            req.client_message_id.as_ref(),
            &s2_sealed.client_message_id()
        );

        // Accept S2 and S3 on Bob and register both grants; S2's grant routes to S2's earlier
        // session even though S3 is active!
        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        assert_eq!(listed.messages.len(), 2);
        let batch =
            bob.accept_listed_v2(&listed, mb.clone(), |_| bob_session.peer_pq_state().clone());
        bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
            .await
            .unwrap();
        for (_, outcome) in batch.outcomes {
            let AcceptedInitial::Accepted { session: s, .. } = outcome else {
                panic!("expected accepted");
            };
            let h = s.active_inbound_token_hash().unwrap();
            let took_over = bob_session.accept_replacement(s).unwrap();
            let ver = bob.allocate_grant_version().unwrap();
            bob.register_write_token_v2(&mb, AUDIENCE, &alice.identity_key(), &h, ver, took_over)
                .await
                .unwrap();
        }
        assert_eq!(bob_session.active_id(), Some(&s3_id));
        // Both S3 (active) and S2 (earlier) inbound token hashes are exposed for O(1) routing.
        let hashes: Vec<[u8; 32]> = bob_session.inbound_token_hashes().collect();
        let s2_hash: [u8; 32] = Sha256::digest(s2_sealed.write_token.as_slice()).into();
        assert!(hashes.contains(&s2_hash));
        assert_ne!(bob_session.active_inbound_token_hash(), Some(s2_hash));

        // Pushing S2's sealed message succeeds and Bob decrypts it on S2 (marked `earlier = true`).
        alice_session.push_v2(&s2_sealed).await.unwrap();
        let rx = receive_for(&mut bob, &mut bob_session, &mb).await;
        assert_eq!(rx.len(), 1);
        let msg = rx[0].as_ref().unwrap();
        assert_eq!(msg.content, b"s2-body");
        assert!(msg.earlier);
    }

    #[tokio::test]
    async fn invalid_mailbox_pages_preserve_cursor_and_pending_ack() {
        #[derive(Default)]
        struct ScriptedMailbox {
            page: Vec<EnvelopeV2>,
            has_more: bool,
        }

        impl LocalMailboxV2 for ScriptedMailbox {
            async fn push_v2(&self, _: PushV2Request) -> protocol::Result<PushV2Response> {
                unreachable!()
            }
            async fn fetch_signed(
                &self,
                req: FetchSignedRequest,
            ) -> protocol::Result<FetchSignedResponse> {
                assert_eq!(req.limit, 100);
                Ok(FetchSignedResponse {
                    messages: self.page.clone(),
                    has_more: self.has_more,
                })
            }
            async fn ack_messages(
                &self,
                _: AckMessagesRequest,
            ) -> protocol::Result<AckMessagesResponse> {
                unreachable!()
            }
            async fn register_write_token(
                &self,
                _: RegisterWriteTokenRequest,
            ) -> protocol::Result<RegisterWriteTokenResponse> {
                unreachable!()
            }
            async fn revoke_write_token(
                &self,
                _: RevokeWriteTokenRequest,
            ) -> protocol::Result<RevokeWriteTokenResponse> {
                unreachable!()
            }
        }

        let mut bob = Client::new(());
        bob.commit_mailbox_page(5, 4).unwrap();
        assert_eq!((bob.mailbox_cursor(), bob.pending_mailbox_ack()), (5, 4));

        let valid_env = |sequence| EnvelopeV2 {
            sequence,
            token_hash: Bytes::from_static(&[0xAA; 32]),
            message: Some(EncryptedMessage::default()),
            initial_message: None,
        };

        let bad_pages = [
            // Oversized page (> requested limit 100).
            (6..=106).map(valid_env).collect::<Vec<_>>(),
            // Non-advancing / regressive / duplicate / unsafe sequence numbers.
            vec![valid_env(5)],
            vec![valid_env(4)],
            vec![valid_env(6), valid_env(6)],
            vec![valid_env(7), valid_env(6)],
            vec![valid_env(6), valid_env(protocol::MAX_SAFE_INTEGER + 1)],
            // Bad token_hash length.
            vec![EnvelopeV2 {
                token_hash: Bytes::from_static(&[0xAA; 31]),
                ..valid_env(6)
            }],
            // Missing inline message (forbidden under 3A).
            vec![EnvelopeV2 {
                message: None,
                ..valid_env(6)
            }],
        ];

        for page in bad_pages {
            let mb = ScriptedMailbox {
                page,
                has_more: false,
            };
            assert_eq!(
                bob.fetch_mailbox_v2(&mb, AUDIENCE, 100)
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::Protocol
            );
            assert_eq!((bob.mailbox_cursor(), bob.pending_mailbox_ack()), (5, 4));
        }

        // Invalid `commit_mailbox_page` arguments fail without mutating state.
        assert_eq!(
            bob.commit_mailbox_page(protocol::MAX_SAFE_INTEGER + 1, 5)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidArgument
        );
        assert_eq!(
            bob.commit_mailbox_page(6, 7).unwrap_err().kind(),
            ErrorKind::InvalidArgument
        );
        assert_eq!((bob.mailbox_cursor(), bob.pending_mailbox_ack()), (5, 4));
    }

    #[tokio::test]
    async fn merging_pending_register_grants_deduplicates_caps_and_preserves_active() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (mut alice, _, mut bob, mut bob_session) = talking(&hs, &mb).await;

        let active_hash = bob_session.active_inbound_token_hash().unwrap();
        let h = |b: u8| [b; 32];

        // Queue active grant with version 1 (lowest!) plus 3 older non-active grants.
        bob_session
            .queue_pending_grant(PendingGrant {
                token_hash: active_hash,
                grant_version: 1,
                pin_active: true,
            })
            .unwrap();
        for (idx, v) in [(1u8, 10u64), (2, 20), (3, 30)] {
            bob_session
                .queue_pending_grant(PendingGrant {
                    token_hash: h(idx),
                    grant_version: v,
                    pin_active: false,
                })
                .unwrap();
        }
        assert_eq!(
            bob_session.pending_register_grants().len(),
            MAX_PENDING_REGISTER_GRANTS
        );

        // Queueing a 5th non-active grant MUST evict lowest non-active (`h(1)`, v=10), preserving
        // the active grant even though its version (1) is smaller!
        bob_session
            .queue_pending_grant(PendingGrant {
                token_hash: h(4),
                grant_version: 40,
                pin_active: false,
            })
            .unwrap();
        let grants = bob_session.pending_register_grants();
        assert_eq!(grants.len(), MAX_PENDING_REGISTER_GRANTS);
        assert!(grants.iter().any(|g| g.token_hash == active_hash));
        assert!(!grants.iter().any(|g| g.token_hash == h(1)));

        // Merging via `Session::keep` deduplicates by `token_hash` (keeping higher version) and
        // preserves the cap.
        alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"again",
                mb.clone(),
            )
            .await
            .unwrap();
        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let AcceptedInitial::Accepted {
            session: mut bob_newer,
            ..
        } = bob
            .accept_initial_v2(
                &alice.identity_key(),
                bob_session.peer_pq_state(),
                &listed.messages[0],
                mb,
            )
            .unwrap()
        else {
            panic!("expected accepted");
        };
        let newer_active_hash = bob_newer.active_inbound_token_hash().unwrap();
        bob_newer
            .queue_pending_grant(PendingGrant {
                token_hash: h(2),
                grant_version: 25, // supersedes v=20 for same h(2)
                pin_active: false,
            })
            .unwrap();
        bob_newer
            .queue_pending_grant(PendingGrant {
                token_hash: newer_active_hash,
                grant_version: 50,
                pin_active: true,
            })
            .unwrap();
        bob_newer.keep(bob_session).unwrap();

        let merged = bob_newer.pending_register_grants();
        assert_eq!(merged.len(), MAX_PENDING_REGISTER_GRANTS);
        assert!(merged.iter().any(|g| g.token_hash == newer_active_hash));
        assert!(
            merged
                .iter()
                .any(|g| g.token_hash == h(2) && g.grant_version == 25)
        );
        // Sorted ascending by grant_version.
        assert!(
            merged
                .windows(2)
                .all(|w| w[0].grant_version <= w[1].grant_version)
        );

        // Removing a confirmed grant removes only matching hash with version <= confirmed.
        assert!(!bob_newer.remove_pending_grant(&h(2), 24));
        assert!(bob_newer.remove_pending_grant(&h(2), 25));
        assert!(
            !bob_newer
                .pending_register_grants()
                .iter()
                .any(|g| g.token_hash == h(2))
        );

        // Invalid grant versions (0 or > MAX_SAFE_INTEGER) are rejected.
        assert_eq!(
            bob_newer
                .queue_pending_grant(PendingGrant {
                    token_hash: h(9),
                    grant_version: 0,
                    pin_active: false,
                })
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidArgument
        );
        assert_eq!(
            bob_newer
                .queue_pending_grant(PendingGrant {
                    token_hash: h(9),
                    grant_version: protocol::MAX_SAFE_INTEGER + 1,
                    pin_active: false,
                })
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidArgument
        );
    }

    #[tokio::test]
    async fn sequence_limits_survive_allocation_and_replacement() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (mut alice, _, mut bob, mut session) = talking(&hs, &mb).await;
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
                .initiate_v2(
                    AUDIENCE,
                    &bob.identity_key(),
                    &PeerPqState::default(),
                    b"next",
                    (),
                )
                .await
                .unwrap();
            let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
            let msg = &listed.messages[0];
            let AcceptedInitial::Accepted {
                session: mut incoming,
                ..
            } = bob
                .accept_initial_v2(
                    &alice.identity_key(),
                    session.peer_pq_state(),
                    msg,
                    mb.clone(),
                )
                .unwrap()
            else {
                panic!("expected accepted");
            };
            bob.ack_initial_messages_v2(AUDIENCE, vec![msg.id])
                .await
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
    async fn delivered_messages_leave_the_server_via_piggyback_and_explicit_ack() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store.clone());
        let (alice, mut alice_session, mut bob, mut bob_session) = talking(&hs, &mb).await;
        let (alice_key, bob_key) = (alice.identity_key(), bob.identity_key());
        assert_eq!(queued(&store, &alice_key).await, 0);

        for content in [b"a", b"b"] {
            alice_session.send_v2(content).await.unwrap();
        }
        let page1 = bob.fetch_mailbox_v2(&mb, AUDIENCE, 100).await.unwrap();
        assert_eq!(page1.messages.len(), 2);
        let mut decrypted = Vec::new();
        for env in &page1.messages {
            decrypted.push(
                bob_session
                    .decrypt_envelope(env.message.as_ref().unwrap())
                    .unwrap()
                    .content,
            );
        }
        assert_eq!(decrypted, [b"a", b"b"]);
        bob.commit_mailbox_page(
            page1.last_sequence().unwrap(),
            page1.last_sequence().unwrap(),
        )
        .unwrap();
        // Messages remain on server until ACKed (even across ClientState restore).
        assert_eq!(queued(&store, &bob_key).await, 2);
        #[cfg(feature = "prost")]
        let mut bob = Client::restore(
            hs.clone(),
            restored::<ClientState, proto::ClientState>(bob.state()),
        );
        assert_eq!(bob.pending_mailbox_ack(), 2);

        // Next `fetch_mailbox_v2` piggybacks `ack_up_to_sequence = 2`!
        alice_session.send_v2(b"c").await.unwrap();
        let page2 = bob.fetch_mailbox_v2(&mb, AUDIENCE, 100).await.unwrap();
        assert_eq!(page2.piggybacked_ack, 2);
        assert_eq!(page2.messages.len(), 1);
        assert_eq!(page2.messages[0].sequence, 3);
        assert_eq!(queued(&store, &bob_key).await, 1);
        assert_eq!(
            bob_session
                .decrypt_envelope(page2.messages[0].message.as_ref().unwrap())
                .unwrap()
                .content,
            b"c"
        );
        bob.commit_mailbox_page(3, 3).unwrap();

        // Explicit `ack_mailbox_v2` deletes seq 3 and clears `pending_mailbox_ack`.
        assert_eq!(bob.ack_mailbox_v2(&mb, AUDIENCE).await.unwrap(), 1);
        assert_eq!(bob.pending_mailbox_ack(), 0);
        assert_eq!(queued(&store, &bob_key).await, 0);
        // No-op when `pending_mailbox_ack == 0`.
        assert_eq!(bob.ack_mailbox_v2(&mb, AUDIENCE).await.unwrap(), 0);

        // One that decrypts only on an earlier session is ACKed too.
        alice_session.send_v2(b"late").await.unwrap();
        bob_session.retire();
        let rx = receive_for(&mut bob, &mut bob_session, &mb).await;
        assert_eq!(rx[0].as_ref().unwrap().content, b"late");
        assert!(rx[0].as_ref().unwrap().earlier);
        assert_eq!(queued(&store, &bob_key).await, 0);
    }

    #[tokio::test]
    async fn duplicate_and_idempotent_push_behave_cleanly() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store.clone());
        let (_alice, mut alice_session, mut bob, mut bob_session) = talking(&hs, &mb).await;

        let sealed = alice_session.encrypt(b"twice").unwrap();
        let seq1 = alice_session.push_v2(&sealed).await.unwrap();
        // Same client_message_id deduplicates idempotently on the server.
        let seq2 = alice_session.push_v2(&sealed).await.unwrap();
        assert_eq!(seq1, seq2);
        assert_eq!(
            contents(receive_for(&mut bob, &mut bob_session, &mb).await),
            [b"twice"]
        );
        assert_eq!(queued(&store, &bob.identity_key()).await, 0);

        // Pushed again with a distinct client_message_id after Bob already received it ->
        // decrypt_envelope returns DuplicateMessage and prefix ACK still removes it.
        let req = alice_session.push_v2_request_with_id(&sealed, Some([0x77; 16]));
        mb.push_v2(req).await.unwrap();
        let rx = receive_for(&mut bob, &mut bob_session, &mb).await;
        assert_eq!(
            rx[0].as_ref().unwrap_err().kind(),
            ErrorKind::DuplicateMessage
        );
        assert_eq!(queued(&store, &bob.identity_key()).await, 0);
    }

    #[tokio::test]
    async fn alice_and_bob_talk() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs);
        alice.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();

        let mut alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"hi",
                mb.clone(),
            )
            .await
            .unwrap();
        register_active_grant(&mut alice, &alice_session, &mb).await;

        // Before Bob approves/registers Alice's write token, PushV2 returns WriteTokenRejected!
        let early_bob = alice_session.encrypt(b"bob").unwrap();
        let err = alice_session.push_v2(&early_bob).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WriteTokenRejected);
        assert!(err.is_server_refusal());

        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        assert_eq!(listed.messages.len(), 1);
        let AcceptedInitial::Accepted {
            session: mut bob_session,
            first_message: first,
            ..
        } = bob
            .accept_initial_v2(
                &alice.identity_key(),
                &PeerPqState::default(),
                &listed.messages[0],
                mb.clone(),
            )
            .unwrap()
        else {
            panic!("expected accepted");
        };
        assert_eq!(first, b"hi");
        bob.ack_initial_messages_v2(AUDIENCE, vec![listed.messages[0].id])
            .await
            .unwrap();
        register_active_grant(&mut bob, &bob_session, &mb).await;

        // Once Bob registers the grant, Alice's retry of `early_bob` succeeds!
        alice_session.push_v2(&early_bob).await.unwrap();
        assert_eq!(
            contents(receive_for(&mut bob, &mut bob_session, &mb).await),
            [b"bob".to_vec()]
        );
        assert!(
            receive_for(&mut bob, &mut bob_session, &mb)
                .await
                .is_empty()
        );

        bob_session.send_v2(b"hello").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut alice, &mut alice_session, &mb).await),
            [b"hello".to_vec()]
        );

        // A message encrypted earlier but pushed later still arrives out of order.
        let late = alice_session.encrypt(b"late").unwrap();
        alice_session.send_v2(b"early").await.unwrap();
        alice_session.push_v2(&late).await.unwrap();
        assert_eq!(
            contents(receive_for(&mut bob, &mut bob_session, &mb).await),
            [b"early".to_vec(), b"late".to_vec()]
        );
    }

    #[tokio::test]
    async fn forged_initial_messages_are_refused() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (mut alice, _alice_session, mut bob, mut bob_session) = talking(&hs, &mb).await;

        let mut alice_again = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"again",
                mb.clone(),
            )
            .await
            .unwrap();
        register_active_grant(&mut alice, &alice_again, &mb).await;

        let mut mallory = Client::new(hs);
        for _ in 0..=KEPT_SESSIONS {
            mallory
                .initiate_v2(
                    AUDIENCE,
                    &bob.identity_key(),
                    &PeerPqState::default(),
                    b"it is me",
                    mb.clone(),
                )
                .await
                .unwrap();
        }
        let mut listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        for msg in &mut listed.messages[1..] {
            msg.sender = alice.identity_key();
            match &mut msg.kind {
                InitialMessageKind::Classical { x3dh, .. } => {
                    x3dh.identity_key = alice.identity_key()
                }
                InitialMessageKind::Pq { x3dh, .. } => x3dh.identity_key = alice.identity_key(),
            }
        }

        let mut accepted = vec![];
        for msg in &listed.messages {
            for _ in 0..2 {
                match bob.accept_initial_v2(
                    &alice.identity_key(),
                    bob_session.peer_pq_state(),
                    msg,
                    mb.clone(),
                ) {
                    Ok(AcceptedInitial::Accepted {
                        session,
                        first_message,
                        ..
                    }) => accepted.push((session, first_message)),
                    Ok(AcceptedInitial::Quarantined { .. }) => panic!("unexpected quarantine"),
                    Err(e) => assert_eq!(e.kind(), ErrorKind::InvalidInitialMessage),
                }
            }
        }
        assert_eq!(accepted.len(), 1);
        let (session, first) = accepted.pop().unwrap();
        assert_eq!(first, b"again");
        let older = mem::replace(&mut bob_session, session);
        bob_session.keep(older).unwrap();
        register_active_grant(&mut bob, &bob_session, &mb).await;

        alice_again.send_v2(b"on the new one").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut bob, &mut bob_session, &mb).await),
            [b"on the new one"]
        );
        bob_session.send_v2(b"me too").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut alice, &mut alice_again, &mb).await),
            [b"me too"]
        );
    }

    #[tokio::test]
    async fn a_new_session_takes_over_at_once() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (mut alice, mut alice_session, mut bob, mut bob_session) = talking(&hs, &mb).await;

        alice_session.send_v2(b"old").await.unwrap();
        let mut alice_again = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"new",
                mb.clone(),
            )
            .await
            .unwrap();
        register_active_grant(&mut alice, &alice_again, &mb).await;

        let first = accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mb).await;
        assert_eq!(first, b"new");
        #[cfg(feature = "prost")]
        let mut bob_session = Session::restore(
            mb.clone(),
            restored::<_, proto::SessionState>(bob_session.state()),
        );

        let rx = receive_for(&mut bob, &mut bob_session, &mb).await;
        assert_eq!(rx[0].as_ref().unwrap().content, b"old");
        assert!(rx[0].as_ref().unwrap().earlier);

        bob_session.send_v2(b"on the new one").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut alice, &mut alice_again, &mb).await),
            [b"on the new one"]
        );
    }

    #[tokio::test]
    async fn a_session_the_peer_never_gets_is_retired_for_a_new_one() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (mut alice, mut alice_session, mut bob, mut bob_session) = talking(&hs, &mb).await;

        bob.start_again_v2(AUDIENCE, &mut bob_session, b"lost")
            .await
            .unwrap();
        let dropped = alice
            .list_initial_messages_v2(AUDIENCE, 0, 10)
            .await
            .unwrap();
        assert_eq!(dropped.messages.len(), 1);
        alice
            .ack_initial_messages_v2(AUDIENCE, vec![dropped.messages[0].id])
            .await
            .unwrap();

        let mut turns = 0;
        loop {
            alice_session.send_v2(b"still here").await.unwrap();
            assert_eq!(
                contents(receive_for(&mut bob, &mut bob_session, &mb).await),
                [b"still here"]
            );
            if bob_session.needs_new_session() {
                break;
            }
            let _ = bob_session.encrypt(b"lost too").unwrap();
            turns += 1;
        }
        assert!(turns <= MAX_DIRECTION_CHANGES);
        assert_eq!(
            bob_session.encrypt(b"no").unwrap_err().kind(),
            ErrorKind::NoSession
        );

        bob.start_again_v2(AUDIENCE, &mut bob_session, b"again")
            .await
            .unwrap();
        register_active_grant(&mut bob, &bob_session, &mb).await;
        let first = accept_keeping(&mut alice, &bob.identity_key(), &mut alice_session, &mb).await;
        assert_eq!(first, b"again");
        assert!(on_one_session(&alice_session, &bob_session));
        bob_session.send_v2(b"hello again").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut alice, &mut alice_session, &mb).await),
            [b"hello again"]
        );
        alice_session.send_v2(b"hi").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut bob, &mut bob_session, &mb).await),
            [b"hi"]
        );
    }

    #[tokio::test]
    async fn sessions_started_at_once_end_as_one() {
        for answered_first in [false, true] {
            let store = SharedStore::default();
            let hs = InProcessHandshake::new(store.clone());
            let mb = InProcessMailbox::new(store);
            let mut alice = Client::new(hs.clone());
            let mut bob = Client::new(hs);
            alice.publish_v2(AUDIENCE, 3, 3).await.unwrap();
            bob.publish_v2(AUDIENCE, 3, 3).await.unwrap();

            let mut alice_session = alice
                .initiate_v2(
                    AUDIENCE,
                    &bob.identity_key(),
                    &PeerPqState::default(),
                    b"hi bob",
                    mb.clone(),
                )
                .await
                .unwrap();
            register_active_grant(&mut alice, &alice_session, &mb).await;

            let mut bob_session = bob
                .initiate_v2(
                    AUDIENCE,
                    &alice.identity_key(),
                    &PeerPqState::default(),
                    b"hi alice",
                    mb.clone(),
                )
                .await
                .unwrap();
            register_active_grant(&mut bob, &bob_session, &mb).await;

            let first =
                accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mb).await;
            assert_eq!(first, b"hi bob");
            let early_b0 = if answered_first {
                let sealed = bob_session.encrypt(b"b0").unwrap();
                match bob_session.push_v2(&sealed).await {
                    Ok(_) => None,
                    Err(e) if e.kind() == ErrorKind::WriteTokenRejected => Some(sealed),
                    Err(e) => panic!("unexpected push_v2 error: {e:?}"),
                }
            } else {
                None
            };
            let first =
                accept_keeping(&mut alice, &bob.identity_key(), &mut alice_session, &mb).await;
            assert_eq!(first, b"hi alice");
            if let Some(sealed) = early_b0 {
                // Bob's session won the tie-break; retry succeeds once Alice registers its grant.
                bob_session.push_v2(&sealed).await.unwrap();
            }
            if answered_first {
                assert_eq!(
                    contents(receive_for(&mut alice, &mut alice_session, &mb).await),
                    [b"b0"]
                );
            }

            assert!(on_one_session(&alice_session, &bob_session));
            alice_session.send_v2(b"a1").await.unwrap();
            bob_session.send_v2(b"b1").await.unwrap();
            assert_eq!(
                contents(receive_for(&mut alice, &mut alice_session, &mb).await),
                [b"b1"]
            );
            assert_eq!(
                contents(receive_for(&mut bob, &mut bob_session, &mb).await),
                [b"a1"]
            );
            alice_session.send_v2(b"a2").await.unwrap();
            assert_eq!(
                contents(receive_for(&mut bob, &mut bob_session, &mb).await),
                [b"a2"]
            );
            bob_session.send_v2(b"b2").await.unwrap();
            assert_eq!(
                contents(receive_for(&mut alice, &mut alice_session, &mb).await),
                [b"b2"]
            );
            assert!(on_one_session(&alice_session, &bob_session));
        }
    }

    #[tokio::test]
    async fn a_chat_deleted_while_a_session_waits_ends_on_one() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs);
        alice.publish_v2(AUDIENCE, 3, 3).await.unwrap();
        bob.publish_v2(AUDIENCE, 3, 3).await.unwrap();
        let (alice_key, bob_key) = (alice.identity_key(), bob.identity_key());

        let mut alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob_key,
                &PeerPqState::default(),
                b"hi bob",
                mb.clone(),
            )
            .await
            .unwrap();
        register_active_grant(&mut alice, &alice_session, &mb).await;

        let deleted = bob
            .initiate_v2(
                AUDIENCE,
                &alice_key,
                &PeerPqState::default(),
                b"hi alice",
                mb.clone(),
            )
            .await
            .unwrap();
        drop(deleted);

        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let AcceptedInitial::Accepted {
            session: mut bob_session,
            first_message,
            ..
        } = bob
            .accept_initial_v2(
                &alice_key,
                &PeerPqState::default(),
                &listed.messages[0],
                mb.clone(),
            )
            .unwrap()
        else {
            panic!("expected accepted");
        };
        assert_eq!(first_message, b"hi bob");
        bob.ack_initial_messages_v2(AUDIENCE, vec![listed.messages[0].id])
            .await
            .unwrap();
        register_active_grant(&mut bob, &bob_session, &mb).await;

        let first = accept_keeping(&mut alice, &bob_key, &mut alice_session, &mb).await;
        assert_eq!(first, b"hi alice");

        let mut lost = 0;
        while !on_one_session(&alice_session, &bob_session) {
            assert!(lost <= MAX_DIRECTION_CHANGES, "they never settle");
            if alice_session.needs_new_session() {
                alice
                    .start_again_v2(AUDIENCE, &mut alice_session, b"again")
                    .await
                    .unwrap();
                register_active_grant(&mut alice, &alice_session, &mb).await;
                let first = accept_keeping(&mut bob, &alice_key, &mut bob_session, &mb).await;
                assert_eq!(first, b"again");
                continue;
            }
            let _ = alice_session.encrypt(b"from alice").unwrap();
            lost += 1;
            bob_session.send_v2(b"from bob").await.unwrap();
            assert_eq!(
                contents(receive_for(&mut alice, &mut alice_session, &mb).await),
                [b"from bob"]
            );
        }
        alice_session.send_v2(b"on one").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut bob, &mut bob_session, &mb).await),
            [b"on one"]
        );
        bob_session.send_v2(b"at last").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut alice, &mut alice_session, &mb).await),
            [b"at last"]
        );
    }

    #[tokio::test]
    async fn a_chat_the_peer_deleted_starts_again_from_a_retired_session_and_exceeds_revocation() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (mut alice, mut alice_session, mut bob, bob_session) = talking(&hs, &mb).await;

        // Bob deletes the chat and revokes Alice's grants using a version allocated from
        // `bob.allocate_grant_version()`.
        let bob_slot = bob.peer_slot_id(&alice.identity_key());
        let revoke_ver = bob.allocate_grant_version().unwrap();
        let revoked = bob
            .revoke_write_token_v2(&mb, AUDIENCE, &bob_slot, None, revoke_ver)
            .await
            .unwrap();
        assert!(revoked >= 1);
        drop(bob_session);

        // Alice's old session now gets WriteTokenRejected.
        assert_eq!(
            alice_session.send_v2(b"revoked").await.unwrap_err().kind(),
            ErrorKind::WriteTokenRejected
        );
        alice_session.retire();
        assert!(alice_session.needs_new_session());
        assert_eq!(
            alice_session.encrypt(b"no").unwrap_err().kind(),
            ErrorKind::NoSession
        );

        // Alice starts again; Bob accepts and registers a fresh grant whose monotonic
        // `allocate_grant_version()` strictly exceeds `revoke_ver`.
        alice
            .start_again_v2(AUDIENCE, &mut alice_session, b"again")
            .await
            .unwrap();
        register_active_grant(&mut alice, &alice_session, &mb).await;

        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let AcceptedInitial::Accepted {
            session: mut bob_session,
            first_message: first,
            ..
        } = bob
            .accept_initial_v2(
                &alice.identity_key(),
                &PeerPqState::default(),
                &listed.messages[0],
                mb.clone(),
            )
            .unwrap()
        else {
            panic!("expected accepted");
        };
        assert_eq!(first, b"again");
        bob.ack_initial_messages_v2(AUDIENCE, vec![listed.messages[0].id])
            .await
            .unwrap();
        let new_ver = bob.allocate_grant_version().unwrap();
        assert!(new_ver > revoke_ver);
        bob.register_write_token_v2(
            &mb,
            AUDIENCE,
            &alice.identity_key(),
            &bob_session.active_inbound_token_hash().unwrap(),
            new_ver,
            true,
        )
        .await
        .unwrap();

        alice_session.send_v2(b"still there?").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut bob, &mut bob_session, &mb).await),
            [b"still there?"]
        );
        bob_session.send_v2(b"yes").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut alice, &mut alice_session, &mb).await),
            [b"yes"]
        );
        assert!(on_one_session(&alice_session, &bob_session));
    }

    #[tokio::test]
    async fn carried_initial_and_local_buffer_replay_never_block_other_peers() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (mut alice, mut alice_session, mut bob, mut bob_session) = talking(&hs, &mb).await;

        // Also establish Carol <-> Bob.
        let mut carol = Client::new(hs.clone());
        carol.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        let mut carol_session = carol
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"hi from carol",
                mb.clone(),
            )
            .await
            .unwrap();
        register_active_grant(&mut carol, &carol_session, &mb).await;
        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let AcceptedInitial::Accepted {
            session: mut bob_carol,
            ..
        } = bob
            .accept_initial_v2(
                &carol.identity_key(),
                &PeerPqState::default(),
                &listed.messages[0],
                mb.clone(),
            )
            .unwrap()
        else {
            panic!("expected carol accepted");
        };
        bob.ack_initial_messages_v2(AUDIENCE, vec![listed.messages[0].id])
            .await
            .unwrap();
        register_active_grant(&mut bob, &bob_carol, &mb).await;

        // Alice starts a new session S2, Bob loses S2's inbox initial, and suppose Bob had already
        // registered S2's token or Alice sends with a carried initial; meanwhile Carol sends a
        // normal message. First test undecryptable envelope from Alice does NOT block Carol!
        let old_alice_token = alice_session.encrypt(b"dummy").unwrap().write_token.clone();
        alice
            .start_again_v2(AUDIENCE, &mut alice_session, b"once more")
            .await
            .unwrap();
        register_active_grant(&mut alice, &alice_session, &mb).await;
        let dropped = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        bob.ack_initial_messages_v2(AUDIENCE, vec![dropped.messages[0].id])
            .await
            .unwrap();

        // Push Alice's S2 message under her already-granted token (carrying S2's initial) followed
        // by Carol's message.
        let mut s2_sealed = alice_session.encrypt(b"new-from-alice").unwrap();
        assert!(s2_sealed.initial_message.is_some());
        s2_sealed.write_token = old_alice_token;
        alice_session.push_v2(&s2_sealed).await.unwrap();
        carol_session.send_v2(b"from-carol").await.unwrap();

        // Bob fetches unified page in one RPC: Alice's envelope fails decrypt locally
        // (`Undecryptable`) and carries S2's initial, while Carol's envelope decrypts immediately!
        let page = bob.fetch_mailbox_v2(&mb, AUDIENCE, 100).await.unwrap();
        assert_eq!(page.messages.len(), 2);
        let alice_env = &page.messages[0];
        let carol_env = &page.messages[1];
        assert_eq!(
            bob_session
                .decrypt_envelope(alice_env.message.as_ref().unwrap())
                .unwrap_err()
                .kind(),
            ErrorKind::Undecryptable
        );
        assert_eq!(
            bob_carol
                .decrypt_envelope(carol_env.message.as_ref().unwrap())
                .unwrap()
                .content,
            b"from-carol"
        );
        // Commit & ACK entire unified page immediately (Carol never stalled!).
        bob.commit_mailbox_page(carol_env.sequence, carol_env.sequence)
            .unwrap();
        bob.ack_mailbox_v2(&mb, AUDIENCE).await.unwrap();

        // Replay buffered `alice_env` locally after accepting its carried initial!
        let carried =
            InitialMessageV2::try_from(alice_env.initial_message.as_ref().unwrap()).unwrap();
        let AcceptedInitial::Accepted {
            session: bob_s2,
            first_message,
            ..
        } = bob
            .accept_initial_v2(
                &alice.identity_key(),
                bob_session.peer_pq_state(),
                &carried,
                mb.clone(),
            )
            .unwrap()
        else {
            panic!("expected carried initial accepted");
        };
        assert_eq!(first_message, b"once more");
        assert!(bob_session.accept_replacement(bob_s2).unwrap());
        register_active_grant(&mut bob, &bob_session, &mb).await;
        assert_eq!(
            bob_session
                .decrypt_envelope(alice_env.message.as_ref().unwrap())
                .unwrap()
                .content,
            b"new-from-alice"
        );

        // Once Bob answers on S2, Alice clears `initial_message` and subsequent `Sealed` carries
        // no initial.
        bob_session.send_v2(b"got it").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut alice, &mut alice_session, &mb).await),
            [b"got it"]
        );
        assert!(alice_session.is_known_by_peer());
        assert!(
            alice_session
                .encrypt(b"plain")
                .unwrap()
                .initial_message
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_message_on_an_earlier_session_shows_so() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (mut alice, mut alice_session, mut bob, mut bob_session) = talking(&hs, &mb).await;

        alice_session.send_v2(b"old").await.unwrap();
        alice
            .start_again_v2(AUDIENCE, &mut alice_session, b"again")
            .await
            .unwrap();
        register_active_grant(&mut alice, &alice_session, &mb).await;
        accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mb).await;
        alice_session.send_v2(b"new").await.unwrap();

        let rx = receive_for(&mut bob, &mut bob_session, &mb).await;
        let earlier: Vec<_> = rx
            .iter()
            .map(|r| {
                let msg = r.as_ref().unwrap();
                (msg.content.as_slice(), msg.earlier)
            })
            .collect();
        assert_eq!(earlier, [(&b"old"[..], true), (&b"new"[..], false)]);
    }

    struct LosingReply(InProcessHandshake, Cell<bool>);

    impl LocalHandshakeV2 for LosingReply {
        async fn get_server_info(
            &self,
            r: GetServerInfoRequest,
        ) -> protocol::Result<GetServerInfoResponse> {
            self.0.get_server_info(r).await
        }
        async fn publish_v2(&self, r: PublishV2Request) -> protocol::Result<PublishV2Response> {
            let response = self.0.publish_v2(r).await?;
            if self.1.replace(false) {
                return Err(protocol::ErrorKind::Connect.into());
            }
            Ok(response)
        }
        async fn refill_prekeys(
            &self,
            r: RefillPrekeysRequest,
        ) -> protocol::Result<RefillPrekeysResponse> {
            self.0.refill_prekeys(r).await
        }
        async fn get_manifest(
            &self,
            r: GetManifestRequest,
        ) -> protocol::Result<GetManifestResponse> {
            self.0.get_manifest(r).await
        }
        async fn claim_bundle(
            &self,
            r: ClaimBundleRequest,
        ) -> protocol::Result<ClaimBundleResponse> {
            self.0.claim_bundle(r).await
        }
        async fn send_initial_v2(
            &self,
            r: SendInitialV2Request,
        ) -> protocol::Result<SendInitialV2Response> {
            self.0.send_initial_v2(r).await
        }
        async fn list_initial_messages(
            &self,
            r: ListInitialMessagesRequest,
        ) -> protocol::Result<ListInitialMessagesResponse> {
            self.0.list_initial_messages(r).await
        }
        async fn ack_initial_messages(
            &self,
            r: AckInitialMessagesRequest,
        ) -> protocol::Result<AckInitialMessagesResponse> {
            self.0.ack_initial_messages(r).await
        }
    }

    struct SignedOut(InProcessHandshake, Cell<bool>);

    impl LocalHandshakeV2 for SignedOut {
        async fn get_server_info(
            &self,
            r: GetServerInfoRequest,
        ) -> protocol::Result<GetServerInfoResponse> {
            self.0.get_server_info(r).await
        }
        async fn publish_v2(&self, r: PublishV2Request) -> protocol::Result<PublishV2Response> {
            if self.1.get() {
                return Err(protocol::ErrorKind::SignInRequired.into());
            }
            self.0.publish_v2(r).await
        }
        async fn refill_prekeys(
            &self,
            r: RefillPrekeysRequest,
        ) -> protocol::Result<RefillPrekeysResponse> {
            self.0.refill_prekeys(r).await
        }
        async fn get_manifest(
            &self,
            r: GetManifestRequest,
        ) -> protocol::Result<GetManifestResponse> {
            self.0.get_manifest(r).await
        }
        async fn claim_bundle(
            &self,
            r: ClaimBundleRequest,
        ) -> protocol::Result<ClaimBundleResponse> {
            self.0.claim_bundle(r).await
        }
        async fn send_initial_v2(
            &self,
            r: SendInitialV2Request,
        ) -> protocol::Result<SendInitialV2Response> {
            self.0.send_initial_v2(r).await
        }
        async fn list_initial_messages(
            &self,
            r: ListInitialMessagesRequest,
        ) -> protocol::Result<ListInitialMessagesResponse> {
            self.0.list_initial_messages(r).await
        }
        async fn ack_initial_messages(
            &self,
            r: AckInitialMessagesRequest,
        ) -> protocol::Result<AckInitialMessagesResponse> {
            self.0.ack_initial_messages(r).await
        }
    }

    #[tokio::test]
    async fn publishing_refused_for_the_sign_in_adds_up_no_keys() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(SignedOut(hs, Cell::new(true)));

        let error = bob.publish_v2(AUDIENCE, 2, 2).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SignInRequired);
        assert_eq!(bob.current_one_time_count(), 0);
        for _ in 0..5 {
            bob.publish_v2(AUDIENCE, 2, 2).await.unwrap_err();
        }
        assert_eq!(bob.current_one_time_count(), 0);

        bob.handshake.1.set(false);
        bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        let _alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"hi",
                mb.clone(),
            )
            .await
            .unwrap();
        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let AcceptedInitial::Accepted { first_message, .. } = bob
            .accept_initial_v2(
                &alice.identity_key(),
                &PeerPqState::default(),
                &listed.messages[0],
                mb,
            )
            .unwrap()
        else {
            panic!("expected accepted");
        };
        assert_eq!(first_message, b"hi");
    }

    #[tokio::test]
    async fn prekeys_published_without_a_reply_stay_usable() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(LosingReply(hs, Cell::new(true)));

        assert!(bob.publish_v2(AUDIENCE, 1, 1).await.is_err());
        let _alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"hi",
                mb.clone(),
            )
            .await
            .unwrap();
        bob.publish_v2(AUDIENCE, 1, 1).await.unwrap();
        bob.publish_v2(AUDIENCE, 1, 1).await.unwrap();
        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let AcceptedInitial::Accepted { first_message, .. } = bob
            .accept_initial_v2(
                &alice.identity_key(),
                &PeerPqState::default(),
                &listed.messages[0],
                mb,
            )
            .unwrap()
        else {
            panic!("expected accepted");
        };
        assert_eq!(first_message, b"hi");
    }

    #[tokio::test]
    async fn the_active_session_has_an_id_both_peers_share() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (mut alice, mut alice_session, _bob, bob_session) = talking(&hs, &mb).await;
        let first = *alice_session.active_id().unwrap();
        assert_eq!(bob_session.active_id(), Some(&first));
        alice_session.retire();
        assert_eq!(alice_session.active_id(), None);
        alice
            .start_again_v2(AUDIENCE, &mut alice_session, b"again")
            .await
            .unwrap();
        let second = *alice_session.active_id().unwrap();
        assert_ne!(second, first);
    }

    #[tokio::test]
    async fn a_stolen_earlier_session_is_never_sent_on_again() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (mut alice, mut stolen, mut bob, mut bob_session) = talking(&hs, &mb).await;
        alice
            .publish_v2(AUDIENCE, KEPT_SESSIONS + 2, KEPT_SESSIONS + 2)
            .await
            .unwrap();
        let (alice_key, bob_key) = (alice.identity_key(), bob.identity_key());

        let mut alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob_key,
                &PeerPqState::default(),
                b"new",
                mb.clone(),
            )
            .await
            .unwrap();
        register_active_grant(&mut alice, &alice_session, &mb).await;
        accept_keeping(&mut bob, &alice_key, &mut bob_session, &mb).await;

        for _ in 0..4 * MAX_DIRECTION_CHANGES {
            match stolen.send_v2(b"it is me").await {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WriteTokenRejected => break,
                Err(e) => panic!("unexpected stolen send error: {e:?}"),
            }
            let _ = receive_for(&mut bob, &mut bob_session, &mb).await;
            if bob_session.needs_new_session() {
                bob.start_again_v2(AUDIENCE, &mut bob_session, b"again")
                    .await
                    .unwrap();
                register_active_grant(&mut bob, &bob_session, &mb).await;
                accept_keeping(&mut alice, &bob_key, &mut alice_session, &mb).await;
            }
            bob_session.send_v2(b"for alice").await.unwrap();
            let page = alice.fetch_mailbox_v2(&mb, AUDIENCE, 100).await.unwrap();
            for env in &page.messages {
                assert!(
                    stolen
                        .decrypt_envelope(env.message.as_ref().unwrap())
                        .is_err()
                );
                assert_eq!(
                    alice_session
                        .decrypt_envelope(env.message.as_ref().unwrap())
                        .unwrap()
                        .content,
                    b"for alice"
                );
            }
            if let Some(last) = page.last_sequence() {
                alice.commit_mailbox_page(last, last).unwrap();
                alice.ack_mailbox_v2(&mb, AUDIENCE).await.unwrap();
            }
        }
        // After enough rotations, stolen's grant or earlier session is evicted.
        if stolen.send_v2(b"still me").await.is_ok() {
            let rx = receive_for(&mut bob, &mut bob_session, &mb).await;
            assert!(rx.is_empty() || rx[0].is_err());
        }
    }

    #[tokio::test]
    async fn only_sessions_with_the_peer_are_kept() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (_alice, _alice_session, mut bob, mut bob_session) = talking(&hs, &mb).await;
        let mut carol = Client::new(hs);
        let carol_session = carol
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"hi",
                mb.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            bob_session.keep(carol_session).unwrap_err().kind(),
            ErrorKind::UnexpectedPeer
        );
        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let AcceptedInitial::Accepted { session, .. } = bob
            .accept_initial_v2(
                &carol.identity_key(),
                &PeerPqState::default(),
                &listed.messages[0],
                mb,
            )
            .unwrap()
        else {
            panic!("expected accepted");
        };
        assert_eq!(
            bob_session.keep(session).unwrap_err().kind(),
            ErrorKind::UnexpectedPeer
        );
    }

    #[test]
    fn subscriptions_go_by_the_servers_clock_and_bind_audience_and_nonce() {
        let alice = Client::new(());
        let behind = now() - 10 * 60 * 1000;
        let stale = alice.subscription_for_audience(AUDIENCE).unwrap();
        assert_eq!(
            stale
                .verify_for_audience(AUDIENCE, behind)
                .unwrap_err()
                .kind(),
            protocol::ErrorKind::StaleTimestamp
        );
        alice.clock().observe(behind);
        let bound1 = alice
            .subscription_for_audience("https://München.example:443/")
            .unwrap();
        let bound2 = alice
            .subscription_for_audience("https://München.example:443/")
            .unwrap();
        assert_eq!(bound1.nonce.len(), protocol::notify::SUBSCRIBE_NONCE_LENGTH);
        assert_ne!(bound1.nonce, bound2.nonce);
        let key = alice.identity_key();
        assert_eq!(
            bound1
                .verify_for_audience("xn--mnchen-3ya.example", behind)
                .unwrap(),
            key
        );
        assert!(
            bound1
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
        let attachments = AttachmentServer::new(MemoryStore::default());
        let alice = Client::new(());
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

        let interrupted = alice
            .start_upload(&attachments, file.len() as u64)
            .await
            .unwrap();
        let first = interrupted.encrypt(0, &file[..attachment::CHUNK_SIZE]);
        interrupted.put(&attachments, 0, &first).await.unwrap();
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

        resumed.cancel(&attachments).await.unwrap();
        let error = attachment::download_chunk(&attachments, &id, 0)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);

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

        let size = 51 * attachment::CHUNK_SIZE as u64;
        let error = alice.start_upload(&attachments, size).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::LimitExceeded);
    }

    #[tokio::test]
    #[cfg(feature = "prost")]
    async fn restored_clients_and_sessions_carry_on() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs.clone());
        alice.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();

        let alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"hi",
                mb.clone(),
            )
            .await
            .unwrap();
        register_active_grant(&mut alice, &alice_session, &mb).await;

        let mut bob = Client::restore(hs.clone(), restored::<_, proto::ClientState>(bob.state()));
        let mut alice_session = Session::restore(
            mb.clone(),
            restored::<_, proto::SessionState>(alice_session.state()),
        );
        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let AcceptedInitial::Accepted {
            session: mut bob_session,
            first_message: first,
            ..
        } = bob
            .accept_initial_v2(
                &alice.identity_key(),
                &PeerPqState::default(),
                &listed.messages[0],
                mb.clone(),
            )
            .unwrap()
        else {
            panic!("expected accepted");
        };
        assert_eq!(first, b"hi");
        let grant_ver = bob.allocate_grant_version().unwrap();
        bob_session
            .queue_pending_grant(PendingGrant {
                token_hash: bob_session.active_inbound_token_hash().unwrap(),
                grant_version: grant_ver,
                pin_active: true,
            })
            .unwrap();

        // Confirmed initial survives restore and cannot be accepted again (and reports `is_replayed`).
        let mut bob = Client::restore(hs.clone(), restored::<_, proto::ClientState>(bob.state()));
        let replay_err = bob
            .accept_initial_v2(
                &alice.identity_key(),
                &PeerPqState::default(),
                &listed.messages[0],
                mb.clone(),
            )
            .unwrap_err();
        assert_eq!(replay_err.kind(), ErrorKind::InvalidInitialMessage);
        assert!(replay_err.is_replayed());

        // Pending grants & inbound_token_hash survive SessionState restore.
        let mut bob_session = Session::restore(
            mb.clone(),
            restored::<_, proto::SessionState>(bob_session.state()),
        );
        assert_eq!(bob_session.pending_register_grants().len(), 1);
        let pg = bob_session.pending_register_grants()[0];
        bob.register_write_token_v2(
            &mb,
            AUDIENCE,
            &alice.identity_key(),
            &pg.token_hash,
            pg.grant_version,
            pg.pin_active,
        )
        .await
        .unwrap();
        assert!(bob_session.remove_pending_grant(&pg.token_hash, pg.grant_version));

        alice_session.send_v2(b"there").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut bob, &mut bob_session, &mb).await),
            [b"there".to_vec()]
        );

        // Unified cursor survives ClientState restore: already-received messages are not re-fetched.
        let mut bob = Client::restore(hs, restored::<_, proto::ClientState>(bob.state()));
        assert_eq!(bob.mailbox_cursor(), 1);
        assert_eq!(bob.next_grant_version(), grant_ver + 1);
        assert!(
            receive_for(&mut bob, &mut bob_session, &mb)
                .await
                .is_empty()
        );

        bob_session.send_v2(b"hello").await.unwrap();
        assert_eq!(
            contents(receive_for(&mut alice, &mut alice_session, &mb).await),
            [b"hello".to_vec()]
        );
    }

    #[cfg(feature = "serde")]
    #[tokio::test]
    async fn serde_validate_rejects_tampered_party_associated_data_and_grants() {
        let store = SharedStore::default();
        let hs = InProcessHandshake::new(store.clone());
        let mb = InProcessMailbox::new(store);
        let (alice, alice_session, bob, _bob_session) = talking(&hs, &mb).await;
        let mut carol = Client::new(hs.clone());
        let mut carol_session = carol
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"carol",
                mb.clone(),
            )
            .await
            .unwrap();

        let to_raw = |mut s: SessionState| RawSessionState {
            active: s.active.take(),
            others: std::mem::take(&mut s.others),
            me: s.me,
            peer: s.peer,
            last: s.last,
            direction_changes: s.direction_changes,
            peer_pq: std::mem::take(&mut s.peer_pq),
            next_session_seq: s.next_session_seq,
            pending_register_grants: std::mem::take(&mut s.pending_register_grants),
        };

        // 1. Valid state passes serde TryFrom<RawSessionState>.
        let valid_state = SessionState::try_from(to_raw(alice_session.state)).unwrap();
        assert_eq!(valid_state.me, alice.identity_key());

        // 2. Active party with mismatched peer identity in AD is rejected.
        let mut wrong_peer_raw = to_raw(valid_state);
        wrong_peer_raw.peer = carol.identity_key();
        let err = SessionState::try_from(wrong_peer_raw).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MalformedState);

        // 3. Earlier (`others`) party from a different identity pair (Carol->Bob) is rejected.
        let (_alice2, alice2_session, _bob2, _bob2_session) = talking(&hs, &mb).await;
        let mut bad_others_raw = to_raw(alice2_session.state);
        bad_others_raw
            .others
            .push(Earlier::from(carol_session.state.active.take().unwrap()));
        let err = SessionState::try_from(bad_others_raw).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MalformedState);

        // 4. Active party with wrong AD length (32 bytes) is rejected.
        let (_a3, a3_session, _b3, _b3_session) = talking(&hs, &mb).await;
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

        // 5. Duplicate or zero-version pending_register_grants are rejected.
        let (_a4, a4_session, _b4, _b4_session) = talking(&hs, &mb).await;
        let mut dup_grant_raw = to_raw(a4_session.state);
        dup_grant_raw.pending_register_grants = vec![
            PendingGrant {
                token_hash: [0x11; 32],
                grant_version: 1,
                pin_active: true,
            },
            PendingGrant {
                token_hash: [0x11; 32],
                grant_version: 2,
                pin_active: false,
            },
        ];
        assert_eq!(
            SessionState::try_from(dup_grant_raw).unwrap_err().kind(),
            ErrorKind::MalformedState
        );
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

    #[cfg(feature = "prost")]
    #[test]
    fn proto_round_trip_preserves_pq_preferences_on_reduced_builds() {
        let client = Client::new(());
        let mut raw = proto::ClientState::from(client.state());
        raw.pq_disabled = false;
        raw.pq_ratchet_disabled = false;
        raw.strict_pq = false;

        let restored = ClientState::try_from(&raw).expect("non-strict PQ state restores cleanly");
        assert!(restored.pq_config.pq_enabled);
        assert!(restored.pq_config.pq_ratchet_enabled);
        let reserialized = proto::ClientState::from(&restored);
        assert!(
            !reserialized.pq_disabled,
            "restoring on a classical-only build must not flip persisted pq_disabled to true"
        );
        assert!(
            !reserialized.pq_ratchet_disabled,
            "restoring on a classical-only build must not flip persisted pq_ratchet_disabled to true"
        );

        #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
        {
            let mut strict_raw = raw;
            strict_raw.strict_pq = true;
            assert_eq!(
                ClientState::try_from(&strict_raw).unwrap_err().kind(),
                ErrorKind::MalformedState
            );
        }
    }

    #[test]
    fn r7_p2_2_ambiguous_failed_publishes_never_evict_confirmed_relay_manifest_digest() {
        let mut client = Client::new(());
        let p1 = client.prepare_publish_v2("relay.example", 2, 2).unwrap();
        let m1 = p1.request.manifest.clone().unwrap();
        let d1 = protocol::handshake_v2::manifest_digest(&m1).unwrap();
        client.commit_publish_v2(p1);
        assert!(client.state.confirmed_manifest_digests.contains(&d1));
        assert!(client.state.recent_manifest_digests.contains(&d1));

        // Simulate 20 consecutive ambiguous publish attempts that fail before reaching the relay
        // (`reconcile_interrupted_publish` observes `m1` on the relay, keeps `publishing = true`,
        // and each attempt stages a distinct unconfirmed manifest digest).
        for _ in 0..20 {
            let prep = client.prepare_publish_v2("relay.example", 1, 1).unwrap();
            drop(prep);
            assert!(!client.reconcile_interrupted_publish(Some(&m1), &[], &[]));
        }
        // 21st attempt succeeds and commits: `prune_manifest_digests_preserving` trims rolling
        // digests to 16, evicting unconfirmed staged attempts FIRST and strictly preserving `d1`!
        let p_ok = client.prepare_publish_v2("relay.example", 1, 1).unwrap();
        let d_ok = protocol::handshake_v2::manifest_digest(p_ok.request.manifest.as_ref().unwrap())
            .unwrap();
        client.commit_publish_v2(p_ok);
        assert!(
            client.state.recent_manifest_digests.contains(&d1),
            "last confirmed relay manifest digest d1 must survive 20+ failed publish attempts"
        );
        assert!(client.state.recent_manifest_digests.contains(&d_ok));
        assert!(client.state.confirmed_manifest_digests.contains(&d1));
        assert!(client.state.confirmed_manifest_digests.contains(&d_ok));
        assert!(client.state.recent_manifest_digests.len() <= MAX_RECENT_MANIFEST_DIGESTS);

        #[cfg(feature = "prost")]
        {
            let wire = proto::ClientState::from(client.state());
            let restored = ClientState::try_from(&wire).unwrap();
            assert_eq!(
                restored.confirmed_manifest_digests,
                client.state.confirmed_manifest_digests
            );
        }
    }

    #[test]
    fn r8_p2_7_has_spare_digest_slot_and_prepare_refuse_unsatisfiable_preserve() {
        let mut client = Client::new(());
        let mut pinned = Vec::new();
        for _ in 0..MAX_RETAINED_MANIFEST_DIGESTS {
            let prep = client
                .prepare_publish_v2_preserving("relay.example", 1, 1, &[], &pinned)
                .unwrap();
            let d =
                protocol::handshake_v2::manifest_digest(prep.request.manifest.as_ref().unwrap())
                    .unwrap();
            pinned.push(d);
            client.commit_publish_v2(prep);
        }
        assert_eq!(
            client.recent_manifest_digests().len(),
            MAX_RETAINED_MANIFEST_DIGESTS
        );
        assert!(
            !client.has_spare_manifest_digest_slot(&pinned),
            "144 preserved digests leave zero spare slots"
        );
        let seq_before = client.manifest_seq();
        let err = client
            .prepare_publish_v2_preserving("relay.example", 1, 1, &[], &pinned)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert_eq!(client.manifest_seq(), seq_before);
        assert!(
            client.recent_manifest_digests().contains(&pinned[0]),
            "unsatisfiable preserve set must fail before mutating state or evicting index 0"
        );

        // Even if an unconfirmed 145th digest is staged alongside 144 preserved digests,
        // `has_spare_manifest_digest_slot` MUST still return false (no off-by-one!).
        client.state.stage_manifest_digest([0xee; 32], &pinned);
        assert_eq!(
            client.recent_manifest_digests().len(),
            MAX_STORED_MANIFEST_DIGESTS
        );
        assert!(
            !client.has_spare_manifest_digest_slot(&pinned),
            "144 preserved + 1 unconfirmed staged (145 total) still has zero spare slots"
        );
        // Dropping 1 pin frees a slot cleanly (`143 < 144`).
        assert!(client.has_spare_manifest_digest_slot(&pinned[1..]));
    }

    #[test]
    fn r9_p2_4_retained_spk_manifest_digests_survive_inplace_publishes_and_rotation() {
        let mut client = Client::new(());
        // Generation 1 (SPK A)
        let pa = client.prepare_publish_v2("relay.example", 2, 2).unwrap();
        let spk_a = pa.classical.signed_prekey;
        client.commit_publish_v2(pa);

        // Generation 2 (SPK B, manifest M0)
        let pb0 = client.prepare_publish_v2("relay.example", 2, 2).unwrap();
        let spk_b = pb0.classical.signed_prekey;
        assert_ne!(spk_a, spk_b);
        let m0 = pb0.request.manifest.clone().unwrap();
        let d0 = protocol::handshake_v2::manifest_digest(&m0).unwrap();
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        let m0_pq_lr = pb0.request.pq_last_resort[0].clone();
        client.commit_publish_v2(pb0);

        // Perform 16 confirmed in-place publishes on SPK B while SPK A is preserved (undrained
        // inbox), producing M1..M16 all bound to SPK B.
        for _ in 0..16 {
            let p_ext = client
                .prepare_publish_v2_preserving("relay.example", 1, 1, &[spk_a], &[])
                .unwrap();
            assert_eq!(p_ext.classical.signed_prekey, spk_b);
            client.commit_publish_v2_preserving(p_ext, &[spk_a], &[]);
        }
        assert!(client.recent_manifest_digests().contains(&d0));

        // Inbox drains (`preserve = &[]`) and next publish rotates from B -> C (M17).
        // Relay still accepts SPK B as `prev_signed_prekey`, so M0 MUST stay retained!
        let pc = client.prepare_publish_v2("relay.example", 2, 2).unwrap();
        let spk_c = pc.classical.signed_prekey;
        assert_ne!(spk_c, spk_b);
        client.commit_publish_v2(pc);
        assert!(
            client.recent_manifest_digests().contains(&d0),
            "R9-P2-4: oldest manifest digest M0 on relay-admissible prev_signed_prekey B must NOT be pruned"
        );

        #[cfg(feature = "prost")]
        {
            let wire = proto::ClientState::from(client.state());
            let restored = ClientState::try_from(&wire).unwrap();
            assert_eq!(
                restored.manifest_digest_spks,
                client.state.manifest_digest_spks
            );
            assert!(restored.recent_manifest_digests.contains(&d0));
        }

        // Delayed PQ greeting referencing M0 on SPK B must be ACCEPTED (not DowngradeDetected!).
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        {
            let alice_id = XEdDSAPrivateKey::generate();
            let suite = PqSuite::from_u8(m0_pq_lr.suite as u8).unwrap();
            let mut lr_sig = [0u8; 64];
            lr_sig.copy_from_slice(&m0_pq_lr.signature);
            let pq_bundle = x3dh::PqPrekeyBundle {
                signed_prekey: spk_b,
                signed_prekey_signature: None,
                one_time_prekey: None,
                pq_suite: suite,
                pq_prekey: m0_pq_lr.encapsulation_key.to_vec(),
                pq_prekey_signature: lr_sig,
                pq_last_resort: true,
            };
            let (pq_init, agreement) = pq_bundle
                .initiate_pq(&alice_id, &client.identity_key(), Some(&d0))
                .unwrap();
            let ratchet =
                Ratchet::alice(&SharedKeys::from_secret(&agreement.secret_key), &spk_b).unwrap();
            let mut party = Party::new(ratchet, agreement.associated_data);
            let first_message = party.encrypt(b"delayed-m0").unwrap();
            let msg = InitialMessageV2 {
                id: 42,
                sender: alice_id.compute_public_key().to_bytes(),
                kind: InitialMessageKind::Pq {
                    x3dh: pq_init,
                    first_message,
                    manifest_digest: Some(d0),
                },
            };
            let res = client.accept_initial_v2(
                &alice_id.compute_public_key().to_bytes(),
                &PeerPqState::default(),
                &msg,
                (),
            );
            assert!(
                res.is_ok(),
                "R9-P2-4: delayed PQ greeting for M0 on prev_signed_prekey B must succeed: {res:?}"
            );
        }

        // Next rotation C -> D evicts SPK B from LocalPrekeys (and relay prev_signed_prekey), so
        // B's digests automatically become eligible for rolling trim back down to 16.
        let pd = client.prepare_publish_v2("relay.example", 2, 2).unwrap();
        client.commit_publish_v2(pd);
        assert!(
            client.recent_manifest_digests().len() <= MAX_RECENT_MANIFEST_DIGESTS,
            "R9-P2-4: once SPK B is evicted, its digests must prune cleanly back to <= 16"
        );
    }
}
