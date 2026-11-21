//! Optional post-quantum (PQXDH + ML-KEM ratchet) configuration, per-peer pinning & downgrade
//! defense, and v2 handshake/mailbox client flows.
//!
//! Configuration and state types ([`PqConfig`], [`PeerPqState`], [`SessionSecurity`],
//! [`HelloCheck`], [`check_peer_hello`], [`expected_audience_from_url`]) are compiled
//! unconditionally with **zero** `ml-kem` dependency. The cryptographic PQXDH / v2 wire methods
//! are compiled only when `ml-kem-1024`, `ml-kem-768`, or `pq` is enabled.

pub use protocol::{NormalizedAudience, normalize_audience};
use x3dh::PqSuite;

use crate::error::{ErrorKind, Result};

/// Default validity lifetime for a signed `CapabilityManifest`: 30 days in milliseconds.
pub const DEFAULT_MANIFEST_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// User post-quantum security preferences, persisted in [`ClientState`](crate::ClientState).
///
/// When at least one post-quantum suite (`ml-kem-1024` or `ml-kem-768`) is compiled in, PQ is
/// enabled by default (`pq_enabled: true`, `pq_ratchet_enabled: true`, `strict_pq: false`), with
/// `preferred_suite` defaulting to [`PqSuite::MlKem1024`] if compiled else [`PqSuite::MlKem768`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct PqConfig {
    /// Whether post-quantum handshakes (PQXDH) are enabled.
    pub pq_enabled: bool,
    /// Preferred ML-KEM suite when negotiating with a PQ-capable peer.
    pub preferred_suite: PqSuite,
    /// Whether continuous post-quantum KEM ratcheting is enabled on PQ sessions.
    pub pq_ratchet_enabled: bool,
    /// Strict / Require-PQ mode: refuse classical fallback and omit raw v1 SPK signatures.
    pub strict_pq: bool,
}

impl PqConfig {
    /// Default compiled [`PqSuite`], preferring [`PqSuite::MlKem1024`] when compiled, else
    /// [`PqSuite::MlKem768`].
    pub const fn default_suite() -> PqSuite {
        if cfg!(feature = "ml-kem-1024") {
            PqSuite::MlKem1024
        } else if cfg!(feature = "ml-kem-768") {
            PqSuite::MlKem768
        } else {
            PqSuite::MlKem1024
        }
    }

    /// All ML-KEM suites compiled into this build, in default preference order.
    pub fn compiled_suites() -> Vec<PqSuite> {
        let mut suites = Vec::with_capacity(2);
        if PqSuite::MlKem1024.is_supported() {
            suites.push(PqSuite::MlKem1024);
        }
        if PqSuite::MlKem768.is_supported() {
            suites.push(PqSuite::MlKem768);
        }
        suites
    }

    /// Compiled suites offered by this client in preference order (`preferred_suite` first).
    /// Returns an empty list if `!self.pq_enabled` or if no PQ suite is compiled in.
    pub fn offered_suites(&self) -> Vec<PqSuite> {
        if !self.pq_enabled {
            return vec![];
        }
        let mut suites = Vec::with_capacity(2);
        if self.preferred_suite.is_supported() {
            suites.push(self.preferred_suite);
        }
        for candidate in [PqSuite::MlKem1024, PqSuite::MlKem768] {
            if candidate.is_supported() && !suites.contains(&candidate) {
                suites.push(candidate);
            }
        }
        suites
    }

    /// Validate that the configuration is internally consistent for this build.
    pub fn validate(&self) -> Result<()> {
        if self.strict_pq && (!self.pq_enabled || self.offered_suites().is_empty()) {
            return Err(ErrorKind::MalformedState.into());
        }
        Ok(())
    }
}

impl Default for PqConfig {
    fn default() -> Self {
        let has_pq = cfg!(any(feature = "ml-kem-1024", feature = "ml-kem-768"));
        Self {
            pq_enabled: has_pq,
            preferred_suite: Self::default_suite(),
            pq_ratchet_enabled: has_pq,
            strict_pq: false,
        }
    }
}

/// Per-peer post-quantum pinning, downgrade-detection, and anti-rollback state.
///
/// Persisted inside [`SessionState`](crate::SessionState) (and `proto::PeerPqState`), and
/// constructible ahead of initiating a session (e.g. when opening a `#chat=...&pq=1` invite link
/// and calling [`PeerPqState::pin_peer_pq`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct PeerPqState {
    /// Whether this peer is pinned as post-quantum capable (from a verified PQ manifest, a PQ
    /// session, or a `#chat=...&pq=1` invite link).
    pub pq_pinned: bool,
    /// Highest verified `CapabilityManifest.manifest_seq` observed for this peer.
    pub pinned_manifest_seq: u64,
    /// Explicit user-approved exception permitting classical fallback with this peer when local
    /// PQ is enabled and the peer lacks PQ or published a signed `OFF` manifest.
    pub allow_classical_exception: bool,
    /// Set if an active downgrade or contradictory in-band `Hello.pq_capable` was detected.
    pub downgrade_detected: bool,
    /// Whether the peer is known to be post-quantum capable.
    pub peer_pq_capable: bool,
    /// Monotonic high-water mark of `Hello.session_seq` accepted from this peer (`0` until the
    /// peer sends a positive sequence number).
    pub peer_session_seq: u64,
}

impl PeerPqState {
    /// Pin this peer as post-quantum capable (e.g. from a `#chat=...&pq=1` invitation link).
    pub fn pin_peer_pq(&mut self) {
        self.pq_pinned = true;
        self.peer_pq_capable = true;
        self.allow_classical_exception = false;
    }

    /// Explicitly approve a classical fallback exception for this peer after prompting the user.
    pub fn approve_classical_exception(&mut self) {
        self.allow_classical_exception = true;
    }

    /// Clear any previously approved classical fallback exception.
    pub fn clear_classical_exception(&mut self) {
        self.allow_classical_exception = false;
    }
}

/// Cryptographic security metadata of a single established session.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct SessionSecurity {
    /// Whether this session used PQXDH (hybrid X25519 + ML-KEM).
    pub is_pq: bool,
    /// Negotiated ML-KEM suite, if `is_pq` is `true`.
    pub suite: Option<PqSuite>,
    /// Whether continuous ML-KEM ratcheting is active on this session's `Party`.
    pub pq_ratchet: bool,
}

impl SessionSecurity {
    /// Classical X3DH + X25519 Double Ratchet.
    pub const fn classical() -> Self {
        Self {
            is_pq: false,
            suite: None,
            pq_ratchet: false,
        }
    }

    /// Post-quantum X3DH with `suite` and optional continuous PQ KEM ratcheting.
    pub const fn pq(suite: PqSuite, pq_ratchet: bool) -> Self {
        Self {
            is_pq: true,
            suite: Some(suite),
            pq_ratchet,
        }
    }
}

/// Outcome of validating a peer's decrypted [`protocol::content::Hello`] against local PQ policy,
/// per-peer state, and the session's [`SessionSecurity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloCheck {
    /// `true` if `!session_security.is_pq && local_pq_enabled && hello.pq_capable`.
    pub downgrade_detected: bool,
    /// `true` when the caller should start a fresh PQ session to recover from a downgrade.
    pub recommend_start_again: bool,
    /// `true` if `hello.session_seq` was stale (`0` or `<= peer_state.peer_session_seq` once
    /// `peer_state.peer_session_seq > 0`) or exceeded [`protocol::MAX_SAFE_INTEGER`].
    pub stale_session_seq: bool,
}

/// Validate a peer's decrypted [`protocol::content::Hello`] against `peer_state`,
/// `session_security`, and `local_pq_enabled`:
///
/// - Enforces strictly increasing `peer_state.peer_session_seq` once a positive sequence number
///   has been observed (`0` is tolerated only while `peer_state.peer_session_seq == 0` for legacy
///   TUI compatibility).
/// - Records `peer_pq_capable = true` and `pq_pinned = true` if `hello.pq_capable` is `true`.
/// - If `!session_security.is_pq && local_pq_enabled && hello.pq_capable`, sets
///   `peer_state.downgrade_detected = true` and recommends starting a new session.
pub fn check_peer_hello(
    peer_state: &mut PeerPqState,
    session_security: SessionSecurity,
    hello: &protocol::content::Hello,
    local_pq_enabled: bool,
) -> HelloCheck {
    if hello.session_seq > protocol::MAX_SAFE_INTEGER {
        return HelloCheck {
            downgrade_detected: false,
            recommend_start_again: false,
            stale_session_seq: true,
        };
    }
    let stale_session_seq = if peer_state.peer_session_seq > 0 {
        hello.session_seq == 0 || hello.session_seq <= peer_state.peer_session_seq
    } else {
        false
    };
    if !stale_session_seq && hello.session_seq > peer_state.peer_session_seq {
        peer_state.peer_session_seq = hello.session_seq;
    }
    if hello.pq_capable {
        peer_state.peer_pq_capable = true;
        peer_state.pq_pinned = true;
    }
    let downgrade_detected = !session_security.is_pq && local_pq_enabled && hello.pq_capable;
    if downgrade_detected {
        peer_state.downgrade_detected = true;
    }
    HelloCheck {
        downgrade_detected,
        recommend_start_again: downgrade_detected,
        stale_session_seq,
    }
}

/// Derive the canonical audience from the locally configured relay URL or hostname.
pub fn expected_audience_from_url(url_or_host: &str) -> Result<String> {
    normalize_audience(url_or_host).map_err(|_| ErrorKind::Protocol.into())
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
mod v2 {
    use core::mem;

    use bytes::Bytes;
    use party::{EncryptedMessage, Party};
    use prost::Message as _;
    use protocol::{
        handshake::{
            self, FetchBundleRequest, LocalHandshake, PublishRequest, SendInitialMessageRequest,
        },
        handshake_v2::{
            self, AckInitialMessagesRequest, CapabilityManifest, ClaimBundleRequest,
            ClaimBundleResponse, GetManifestRequest, GetServerInfoRequest, GetServerInfoResponse,
            ListInitialMessagesRequest, LocalHandshakeV2, PqLastResortCommitment, PqPrekey,
            PublishV2Request, RefillPrekeysRequest, RefillPrekeysResponse, SendInitialV2Request,
            manifest_digest, sign_manifest, verify_manifest, verify_manifest_at,
            verify_wire_pq_prekey,
        },
        mailbox::LocalMailbox,
        mailbox_v2::{
            CLIENT_MESSAGE_ID_LENGTH, EnvelopeV2, FetchSignedRequest, LocalMailboxV2,
            PushV2Request, decode_carried_initial, encode_carried_initial,
        },
    };
    use ratchetx2::{DhPrivateKey, Ratchet, SharedKeys};
    use x3dh::{
        PQXDH_VERSION, PqInitialMessage, PqPrekeyBundle, PqPrekeyId, PqSuite, PrekeyBundle,
        PublicKey, PublishedPrekeys, pq_prekey_id,
    };
    use xeddsa::XEdDSAPublicKey;

    use super::{DEFAULT_MANIFEST_TTL_MS, PeerPqState, SessionSecurity, check_peer_hello};
    use crate::{
        Active, Client, DeliveryKey, InitialMessage, MailboxEnvelope, Sealed, Session,
        checked_initial_hello,
        error::{Error, ErrorKind, Result},
        extract_hello,
    };

    /// Maximum inbox message IDs acknowledged in one `AckInitialMessages` call.
    const MAX_ACK_BATCH: usize = 100;

    fn unimplemented_refusal(error: &protocol::Error) -> bool {
        error.is_server_refusal() && error.kind() == protocol::ErrorKind::Unimplemented
    }

    /// Which transport path succeeded in [`Client::transmit_publish_v2_or_v1_fallback`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PublishV2Outcome {
        /// Published post-quantum + classical prekeys and a PQ-enabled signed manifest via `PublishV2`.
        V2Pq,
        /// Published classical prekeys and a signed PQ-off manifest via `PublishV2` (either
        /// because local PQ is disabled or because the server rejected PQ-ON with `Unimplemented`
        /// under `PQ_ENABLED="false"`).
        V2ClassicalOff,
        /// Fell back to legacy v1 `Handshake::publish` (server does not implement `PublishV2`).
        V1Fallback,
    }

    /// A prepared v2 prekey + [`CapabilityManifest`] publish request.
    ///
    /// Persist [`Client::state`] BEFORE calling [`Client::transmit_publish_v2`] (or
    /// [`Client::transmit_publish_v2_or_v1_fallback`]), then call [`Client::commit_publish_v2`]
    /// on success or [`Client::rollback_publish_v2_on_refusal`] on definitive refusal.
    #[derive(Debug, Clone)]
    pub struct PreparedPublishV2 {
        /// The signed v2 publish request to transmit.
        pub request: PublishV2Request,
        /// Manifest sequence number assigned to this publish.
        pub manifest_seq: u64,
        /// Prekey generation number assigned to this publish.
        pub generation: u64,
        pub(crate) prev_manifest_seq: u64,
        pub(crate) manifest_digest: [u8; 32],
        pub(crate) classical: PublishedPrekeys,
        pub(crate) extended: bool,
        pub(crate) pq_one_time_prekeys: Vec<PqPrekeyId>,
    }

    /// A prepared v2 non-rotating prekey refill request.
    ///
    /// Persist [`Client::state`] BEFORE calling [`Client::transmit_refill_v2`].
    #[derive(Debug, Clone)]
    pub struct PreparedRefillV2 {
        /// The signed v2 refill request to transmit.
        pub request: RefillPrekeysRequest,
        pub(crate) one_time_prekeys: Vec<PublicKey>,
        pub(crate) pq_one_time_prekeys: Vec<PqPrekeyId>,
    }

    /// An outgoing initial message prepared by [`Client::prepare_initiate_v2`], ready to be
    /// transmitted after persisting the newly created [`Session`].
    #[derive(Debug, Clone)]
    pub enum OutgoingInitialMessage {
        /// Legacy v1 `SendInitialMessageRequest` (used only on v1 fallback when the server
        /// returns `Unimplemented` and local `strict_pq` is `false`).
        V1(SendInitialMessageRequest),
        /// Hardened v2 `SendInitialV2Request` (carries either PQXDH v2 or classical v1).
        V2(SendInitialV2Request),
    }

    /// Result of [`Client::prepare_initiate_v2`]: persist [`session`](Self::session) BEFORE
    /// sending [`request`](Self::request) with [`Client::send_prepared_initiate_v2`].
    #[derive(Debug)]
    pub struct PreparedInitiateV2<M> {
        /// The newly established session (with updated [`PeerPqState`] and [`SessionSecurity`]).
        pub session: Session<M>,
        /// The initial message request to transmit after persisting `session.state()`.
        pub request: OutgoingInitialMessage,
        /// Negotiated security metadata for this session.
        pub security: SessionSecurity,
    }

    /// The inner payload of an [`InitialMessageV2`]: either classical X3DH (v1) or PQXDH (v2).
    #[derive(Debug, Clone, PartialEq)]
    pub enum InitialMessageKind {
        /// Classical X3DH (protocol version 1).
        Classical(InitialMessage),
        /// Post-quantum X3DH (protocol version 2).
        Pq {
            /// PQXDH key agreement payload.
            x3dh: PqInitialMessage,
            /// Encrypted first Double Ratchet message authenticating the sender.
            first_message: EncryptedMessage,
            /// Optional 32-byte SHA-256 digest of this client's verified `CapabilityManifest`.
            manifest_digest: Option<[u8; 32]>,
        },
    }

    /// An initial message normalized from v2 `ListInitialMessages` or a v2 carried mailbox
    /// envelope, supporting both classical X3DH (v1) and PQXDH (v2).
    #[derive(Debug, Clone, PartialEq)]
    pub struct InitialMessageV2 {
        /// Stable server-assigned inbox ID (`0` when carried inside a mailbox envelope or taken
        /// via legacy v1 fallback).
        pub id: u64,
        /// Sender's claimed identity key (not authenticated until accepted).
        pub sender: PublicKey,
        /// Classical or post-quantum initial message payload.
        pub kind: InitialMessageKind,
    }

    impl InitialMessageV2 {
        /// Whether this initial message uses PQXDH (version 2).
        pub fn is_pq(&self) -> bool {
            matches!(self.kind, InitialMessageKind::Pq { .. })
        }

        /// The ML-KEM suite if this is a PQXDH initial message, else `None`.
        pub fn pq_suite(&self) -> Option<PqSuite> {
            match &self.kind {
                InitialMessageKind::Pq { x3dh, .. } => Some(x3dh.pq_suite),
                InitialMessageKind::Classical(_) => None,
            }
        }

        /// Whether this initial message references a classical one-time prekey.
        pub fn uses_one_time_prekey(&self) -> bool {
            match &self.kind {
                InitialMessageKind::Classical(m) => m.x3dh.one_time_prekey.is_some(),
                InitialMessageKind::Pq { x3dh, .. } => x3dh.one_time_prekey.is_some(),
            }
        }

        /// Whether this initial message references a one-time PQOPK (as opposed to last-resort).
        pub fn uses_pq_one_time_prekey(&self) -> bool {
            match &self.kind {
                InitialMessageKind::Classical(_) => false,
                InitialMessageKind::Pq { x3dh, .. } => !x3dh.pq_last_resort,
            }
        }

        /// Decode raw carried initial message bytes from shared mailbox storage (handling both
        /// v2 `b"\0IMV2"`-prefixed and legacy v1 payloads via
        /// [`protocol::mailbox_v2::decode_carried_initial`]).
        pub fn decode_carried(bytes: &[u8]) -> Option<Self> {
            let wire = decode_carried_initial(bytes)?;
            Self::try_from(&wire).ok()
        }
    }

    impl TryFrom<&handshake_v2::InitialMessageV2> for InitialMessageV2 {
        type Error = Error;

        fn try_from(wire: &handshake_v2::InitialMessageV2) -> Result<Self> {
            let malformed = || Error::from(ErrorKind::InvalidInitialMessage);
            if wire.id > protocol::MAX_SAFE_INTEGER {
                return Err(malformed());
            }
            let first_message = wire.first_message.clone().ok_or_else(malformed)?;
            match wire.version {
                1 => {
                    let x3dh = x3dh::InitialMessage::try_from(wire).map_err(|_| malformed())?;
                    Ok(Self {
                        id: wire.id,
                        sender: x3dh.identity_key,
                        kind: InitialMessageKind::Classical(InitialMessage {
                            x3dh,
                            first_message,
                        }),
                    })
                }
                PQXDH_VERSION => {
                    let x3dh = PqInitialMessage::try_from(wire).map_err(|_| malformed())?;
                    let manifest_digest = if wire.manifest_digest.is_empty() {
                        None
                    } else {
                        Some(
                            <[u8; 32]>::try_from(wire.manifest_digest.as_ref())
                                .map_err(|_| malformed())?,
                        )
                    };
                    Ok(Self {
                        id: wire.id,
                        sender: x3dh.identity_key,
                        kind: InitialMessageKind::Pq {
                            x3dh,
                            first_message,
                            manifest_digest,
                        },
                    })
                }
                _ => Err(malformed()),
            }
        }
    }

    /// Result of [`Client::list_initial_messages_v2`].
    #[derive(Debug, Clone)]
    pub struct ListedInitialMessages {
        /// Valid pending initial messages (both v1 and v2), oldest first.
        pub messages: Vec<InitialMessageV2>,
        /// Inbox IDs of malformed messages that can never be accepted and should be acknowledged.
        pub malformed_ids: Vec<u64>,
        /// `true` if the server returned `Unimplemented` and the call fell back to destructive
        /// legacy v1 `TakeInitialMessages` (no ack call is needed).
        pub fell_back_to_v1: bool,
    }

    /// Locally processed inbox outcomes and the progress of their server acknowledgement.
    #[derive(Debug)]
    pub struct ListAndAcceptOutcome<M> {
        /// Every initial message accepted or quarantined locally, with its prekeys confirmed.
        pub outcomes: Vec<(PublicKey, AcceptedInitial<M>)>,
        /// Handled IDs whose acknowledgement is still outstanding. Empty on success or v1 fallback.
        pub unacked_ids: Vec<u64>,
        /// Acknowledgement failure. Persist `outcomes` and retry
        /// [`Client::ack_initial_messages_v2`] with `unacked_ids`.
        pub ack_error: Option<Error>,
    }

    /// Outcome of accepting an inbound v1/v2 initial message via [`Client::accept_initial_v2`].
    #[derive(Debug)]
    pub enum AcceptedInitial<M> {
        /// Accepted cleanly under local PQ policy (either PQXDH, or classical when local PQ is
        /// off or peer is unpinned with an approved classical exception).
        Accepted {
            /// Newly established session (merge into existing chat with [`Session::keep`]).
            session: Session<M>,
            /// Decrypted first message payload.
            first_message: Vec<u8>,
            /// Negotiated cryptographic security of this session.
            security: SessionSecurity,
        },
        /// Authenticated classical initial message received while local PQ is enabled and the
        /// peer is either PQ-pinned or has not been granted a classical exception.
        ///
        /// Callers MUST prompt the user to approve the classical exception before displaying
        /// `first_message`, merging `session`, applying `Hello` effects, or replying.
        Quarantined {
            /// Authenticated classical session held pending user approval.
            session: Session<M>,
            /// Decrypted first message payload (do not display or apply until approved).
            first_message: Vec<u8>,
            /// `true` if the peer was already PQ-pinned (`peer_state.pq_pinned`).
            peer_was_pq_pinned: bool,
        },
    }

    impl MailboxEnvelope for EnvelopeV2 {
        type Initial = InitialMessageV2;

        fn sequence(&self) -> u64 {
            self.sequence
        }

        fn into_parts(self) -> (Option<EncryptedMessage>, Option<InitialMessageV2>) {
            (
                self.message,
                self.initial_message
                    .as_ref()
                    .and_then(|im| InitialMessageV2::try_from(im).ok()),
            )
        }
    }

    /// A message received via [`Session::receive_v2`] / [`Session::fetch_v2`].
    #[derive(Debug)]
    pub struct ReceivedV2 {
        /// Decrypted content, or why there is none (`Stalled`, `DuplicateMessage`,
        /// `EvictedMessage`, `Expired`, `Undecryptable`, etc.).
        pub content: Result<Vec<u8>>,
        /// Whether it decrypted on an earlier archived session rather than the active one.
        pub earlier: bool,
        /// Carried initial messages (both v1 classical and v2 PQXDH) attached to this envelope
        /// or carried across expired envelopes (and for `Stalled`, all carried initials from
        /// the rest of the page).
        pub initial_messages: Vec<InitialMessageV2>,
    }

    impl ReceivedV2 {
        /// Whether this entry represents a message whose skipped key was evicted (permanently
        /// lost, delivery token already queued for server ack).
        pub fn is_evicted(&self) -> bool {
            self.content
                .as_ref()
                .is_err_and(|e| e.kind() == ErrorKind::EvictedMessage)
        }
    }

    /// Helper: verify canonical non-zero XEdDSA public key.
    fn check_canonical_identity(key: &PublicKey) -> Result<()> {
        if !xeddsa::is_canonical_public_key(key) {
            return Err(ErrorKind::InvalidKeys.into());
        }
        XEdDSAPublicKey::new(key).map_err(|e| Error::new(ErrorKind::InvalidKeys, e))?;
        Ok(())
    }

    impl<H> Client<H> {
        /// Prepare a v2 prekey + signed [`CapabilityManifest`] publish request without sending
        /// it over the network yet.
        ///
        /// Persist `self.state()` BEFORE transmitting [`PreparedPublishV2::request`] so a crash
        /// mid-request can never leave the server serving prekeys whose private keys were not
        /// persisted.
        ///
        /// - When `pq_config().pq_enabled` is `true`, publishes classical SPK (+ raw v1 SPK
        ///   signature unless `strict_pq == true`), `one_time_count` classical OPKs, signed
        ///   manifest, last-resort PQSPK and `pq_one_time_count` PQOPKs for **each** suite in
        ///   `pq_config().offered_suites()`.
        /// - When `pq_config().pq_enabled` is `false`, publishes a signed `OFF` manifest
        ///   (`manifest_seq + 1`, empty `offered_suites` and empty PQ prekeys) while preserving
        ///   the local PQ generation for in-flight PQ handshakes.
        pub fn prepare_publish_v2(
            &mut self,
            audience: &str,
            one_time_count: usize,
            pq_one_time_count: usize,
        ) -> Result<PreparedPublishV2> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            self.state.pq_config.validate()?;
            let offered = self.state.pq_config.offered_suites();
            let pq_enabled = self.state.pq_config.pq_enabled && !offered.is_empty();
            let strict_pq = self.state.pq_config.strict_pq;
            if strict_pq && !pq_enabled {
                return Err(ErrorKind::PqRequired.into());
            }

            let timestamp = self.next_timestamp()?;
            let prev_manifest_seq = self.state.manifest_seq;
            let manifest_seq = prev_manifest_seq
                .checked_add(1)
                .filter(|&s| s <= protocol::MAX_SAFE_INTEGER)
                .ok_or(ErrorKind::Protocol)?;

            let extended = self.state.publishing;
            let (classical, pq_last_resort_wire, pq_one_time_wire, pq_opk_ids, generation) =
                if pq_enabled {
                    let first_suite = offered[0];
                    let first = if extended {
                        self.state.prekeys.extend_pq(
                            &self.state.identity,
                            first_suite,
                            one_time_count,
                            pq_one_time_count,
                        )?
                    } else {
                        self.state.prekeys.generate_pq(
                            &self.state.identity,
                            first_suite,
                            one_time_count,
                            pq_one_time_count,
                        )?
                    };
                    let generation = if extended {
                        self.state.prekey_generation.max(1)
                    } else {
                        self.state
                            .prekey_generation
                            .checked_add(1)
                            .filter(|&g| g <= protocol::MAX_SAFE_INTEGER)
                            .ok_or(ErrorKind::Protocol)?
                    };
                    let mut lr_wire = vec![PqPrekey::from(&first.pq_last_resort)];
                    let mut opk_wire: Vec<PqPrekey> = first
                        .pq_one_time_prekeys
                        .iter()
                        .map(PqPrekey::from)
                        .collect();
                    let mut pq_opk_ids: Vec<PqPrekeyId> =
                        first.pq_one_time_prekeys.iter().map(|k| k.id).collect();
                    for &extra_suite in &offered[1..] {
                        let extra = self.state.prekeys.extend_pq(
                            &self.state.identity,
                            extra_suite,
                            0,
                            pq_one_time_count,
                        )?;
                        lr_wire.push(PqPrekey::from(&extra.pq_last_resort));
                        pq_opk_ids.extend(extra.pq_one_time_prekeys.iter().map(|k| k.id));
                        opk_wire.extend(extra.pq_one_time_prekeys.iter().map(PqPrekey::from));
                    }
                    (first.classical, lr_wire, opk_wire, pq_opk_ids, generation)
                } else {
                    // PQ toggled OFF: rotate SPK cleanly on non-retry publishes (`KEPT_GENERATIONS
                    // = 2` retains the prior PQ generation so in-flight PQ handshakes still
                    // decrypt while avoiding dead OPK accumulation across repeated publishes).
                    let classical = if extended {
                        self.state
                            .prekeys
                            .extend(&self.state.identity, one_time_count)
                    } else {
                        self.state
                            .prekeys
                            .generate(&self.state.identity, one_time_count)
                    };
                    let generation = if extended {
                        self.state.prekey_generation.max(1)
                    } else {
                        self.state
                            .prekey_generation
                            .checked_add(1)
                            .filter(|&g| g <= protocol::MAX_SAFE_INTEGER)
                            .ok_or(ErrorKind::Protocol)?
                    };
                    (classical, vec![], vec![], vec![], generation)
                };

            let issued_at = timestamp;
            let expires_at = issued_at
                .checked_add(DEFAULT_MANIFEST_TTL_MS)
                .filter(|&t| t <= protocol::MAX_SAFE_INTEGER)
                .ok_or(ErrorKind::Protocol)?;

            let mut manifest = CapabilityManifest {
                audience: audience.to_string(),
                identity_key: Bytes::new(),
                manifest_seq,
                generation,
                issued_at,
                expires_at,
                pq_enabled,
                strict_pq: pq_enabled && strict_pq,
                pq_ratchet_supported: pq_enabled && self.state.pq_config.pq_ratchet_enabled,
                offered_suites: if pq_enabled {
                    offered.iter().map(|s| u32::from(s.as_u8())).collect()
                } else {
                    vec![]
                },
                signed_prekey: Bytes::copy_from_slice(&classical.signed_prekey),
                pq_last_resort: pq_last_resort_wire
                    .iter()
                    .map(|k| PqLastResortCommitment {
                        suite: k.suite,
                        prekey_id: k.prekey_id.clone(),
                    })
                    .collect(),
                signature: Bytes::new(),
            };
            sign_manifest(&self.state.identity, &mut manifest)?;
            let own_digest = manifest_digest(&manifest)?;

            let spk_sig = if pq_enabled && strict_pq {
                None
            } else {
                Some(classical.signed_prekey_signature)
            };
            let request = PublishV2Request::sign(
                &self.state.identity,
                manifest,
                spk_sig,
                &classical.one_time_prekeys,
                pq_last_resort_wire,
                pq_one_time_wire,
                timestamp,
            )?;

            self.state.manifest_seq = manifest_seq;
            self.state.prekey_generation = generation;
            self.state.publishing = true;
            self.state.record_manifest_digest(own_digest);

            Ok(PreparedPublishV2 {
                request,
                manifest_seq,
                generation,
                prev_manifest_seq,
                manifest_digest: own_digest,
                classical,
                extended,
                pq_one_time_prekeys: pq_opk_ids,
            })
        }

        /// Mark a prepared v2 publish as confirmed by the server.
        pub fn commit_publish_v2(&mut self, _prepared: PreparedPublishV2) {
            self.state.publishing = false;
        }

        /// Retract newly added OPKs/PQOPKs and restore manifest sequence from a prepared v2
        /// publish that was definitively refused before storage (e.g. `ErrorKind::SignInRequired`,
        /// `ErrorKind::PqRequired`, or `ErrorKind::LimitExceeded`).
        pub fn rollback_publish_v2_on_refusal(&mut self, prepared: PreparedPublishV2) {
            if prepared.extended {
                self.state.prekeys.retract_pq(
                    &prepared.classical.one_time_prekeys,
                    &prepared.pq_one_time_prekeys,
                );
            }
            self.state.manifest_seq = prepared.prev_manifest_seq;
            if self.state.recent_manifest_digests.last() == Some(&prepared.manifest_digest) {
                self.state.recent_manifest_digests.pop();
            }
        }

        /// Prepare a non-rotating prekey refill request (`HandshakeV2::refill_prekeys`) to
        /// replenish classical OPKs and/or PQOPKs for the current generation without rotating
        /// the signed prekey or last-resort PQSPKs.
        ///
        /// Persist `self.state()` BEFORE calling [`Client::transmit_refill_v2`].
        pub fn prepare_refill_v2(
            &mut self,
            audience: &str,
            one_time_count: usize,
            pq_one_time_count: usize,
        ) -> Result<PreparedRefillV2> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            if self.state.prekey_generation == 0 || self.state.prekeys.generation_count() == 0 {
                return Err(ErrorKind::Protocol.into());
            }
            self.state.pq_config.validate()?;
            let offered = self.state.pq_config.offered_suites();
            let pq_enabled = self.state.pq_config.pq_enabled && !offered.is_empty();
            let timestamp = self.next_timestamp()?;

            let (classical_opks, pq_opk_wire, pq_opk_ids) = if pq_enabled {
                let first = self.state.prekeys.extend_pq(
                    &self.state.identity,
                    offered[0],
                    one_time_count,
                    pq_one_time_count,
                )?;
                let mut pq_wire: Vec<PqPrekey> = first
                    .pq_one_time_prekeys
                    .iter()
                    .map(PqPrekey::from)
                    .collect();
                let mut pq_ids: Vec<PqPrekeyId> =
                    first.pq_one_time_prekeys.iter().map(|k| k.id).collect();
                for &extra_suite in &offered[1..] {
                    let extra = self.state.prekeys.extend_pq(
                        &self.state.identity,
                        extra_suite,
                        0,
                        pq_one_time_count,
                    )?;
                    pq_ids.extend(extra.pq_one_time_prekeys.iter().map(|k| k.id));
                    pq_wire.extend(extra.pq_one_time_prekeys.iter().map(PqPrekey::from));
                }
                (first.classical.one_time_prekeys, pq_wire, pq_ids)
            } else {
                let extended = self
                    .state
                    .prekeys
                    .extend(&self.state.identity, one_time_count);
                (extended.one_time_prekeys, vec![], vec![])
            };

            let request = RefillPrekeysRequest::sign(
                &self.state.identity,
                audience,
                self.state.prekey_generation,
                &classical_opks,
                pq_opk_wire,
                timestamp,
            )?;

            Ok(PreparedRefillV2 {
                request,
                one_time_prekeys: classical_opks,
                pq_one_time_prekeys: pq_opk_ids,
            })
        }

        /// Retract newly added OPKs/PQOPKs from a prepared v2 refill after
        /// [`Error::is_server_refusal`] confirms the relay refused it.
        pub fn rollback_refill_v2_on_refusal(&mut self, prepared: PreparedRefillV2) {
            self.state
                .prekeys
                .retract_pq(&prepared.one_time_prekeys, &prepared.pq_one_time_prekeys);
        }

        /// Accept an inbound v1 or v2 initial message from `peer`, applying local PQ and
        /// inbound classical quarantine policies.
        ///
        /// **Two-phase ack rule**: this method is purely local and has no transient errors — any
        /// `Err` (`InvalidInitialMessage`, `InvalidKeys`, `UnexpectedPeer`, `PqRequired`,
        /// `UnsupportedSuite`, `DowngradeDetected`, `MalformedState`, etc.) is permanent for that
        /// inbox entry. In a manual `list_initial_messages_v2` -> `accept_initial_v2` -> persist
        /// -> `ack_initial_messages_v2` loop, callers MUST acknowledge every processed `msg.id`
        /// (both `Ok` and `Err` outcomes) after persisting state so unaccepted/malformed entries
        /// cannot permanently fill the inbox.
        ///
        /// - **PQXDH (version 2)**: authenticates the sender first via `accept_pq` + `first_message`
        ///   AEAD decryption (supporting both PQ-ratchet and classical-ratchet PQXDH sessions
        ///   symmetrically, returning [`ErrorKind::InvalidInitialMessage`] on any unauthenticated
        ///   forgery). Only after sender authentication succeeds does it check `manifest_digest`
        ///   against this client's recent signed manifests (rejecting unrecognized digests, or
        ///   missing digests when `strict_pq` is enabled, with [`ErrorKind::DowngradeDetected`]
        ///   without confirming prekey consumption), then confirms prekey consumption, pins
        ///   `peer_pq.pq_pinned = true`, and returns [`AcceptedInitial::Accepted`]. Works even
        ///   after local PQ was toggled OFF so in-flight PQ handshakes still decrypt cleanly.
        /// - **Classical (version 1)**:
        ///   - Authenticates via classical X3DH + `first_message` decryption first (rejecting
        ///     unauthenticated forgeries with [`ErrorKind::InvalidInitialMessage`] without
        ///     consuming prekeys).
        ///   - If local `strict_pq` is `true`: rejects the authenticated classical initial with
        ///     [`ErrorKind::PqRequired`] without calling `confirm()` (consuming no prekeys).
        ///   - Otherwise confirms prekey consumption; if local
        ///     `pq_enabled && (peer_state.pq_pinned || !peer_state.allow_classical_exception)`,
        ///     returns [`AcceptedInitial::Quarantined`] so the caller can prompt the user before
        ///     displaying `first_message`, merging the session, or replying.
        ///   - Otherwise returns [`AcceptedInitial::Accepted`] with [`SessionSecurity::classical`].
        pub fn accept_initial_v2<M>(
            &mut self,
            peer: &PublicKey,
            peer_state: &PeerPqState,
            initial_message: &InitialMessageV2,
            mailbox: M,
        ) -> Result<AcceptedInitial<M>> {
            check_canonical_identity(peer)?;
            if initial_message.sender != *peer {
                return Err(ErrorKind::UnexpectedPeer.into());
            }
            let local_pq_enabled = self.state.pq_config.pq_enabled
                && !self.state.pq_config.offered_suites().is_empty();
            let strict_pq = self.state.pq_config.strict_pq;

            match &initial_message.kind {
                InitialMessageKind::Pq {
                    x3dh: pq_init,
                    first_message,
                    manifest_digest: digest,
                } => {
                    if !pq_init.pq_suite.is_supported() {
                        return Err(ErrorKind::UnsupportedSuite.into());
                    }
                    let (agreement, signed_prekey) = self.state.prekeys.accept_pq(
                        &self.state.identity,
                        peer,
                        pq_init,
                        digest.as_ref().map(|d| d.as_slice()),
                    )?;
                    let ratchet = Ratchet::bob(
                        &SharedKeys::from_secret(&agreement.secret_key),
                        DhPrivateKey::from(signed_prekey.to_bytes()),
                    );
                    // Try classical ratchet first: if Alice used Party::new (PQ ratchet off),
                    // classical Party decrypts cleanly; if Alice used Party::new_pq, classical
                    // Party rejects the PQ header with InvalidHeader and we decrypt with
                    // Party::new_pq.
                    let (party, content, pq_ratchet) = {
                        let mut classical_party =
                            Party::new(ratchet.clone(), agreement.associated_data);
                        match classical_party.decrypt(first_message) {
                            Ok(content) => (classical_party, content, false),
                            Err(e) if e.kind() == party::error::ErrorKind::InvalidHeader => {
                                let party_suite = party::PqSuite::from_id(agreement.suite.as_u8())
                                    .ok_or(ErrorKind::UnsupportedSuite)?;
                                let mut pq_party =
                                    Party::new_pq(ratchet, agreement.associated_data, party_suite);
                                let content = pq_party.decrypt(first_message).map_err(|err| {
                                    Error::new(ErrorKind::InvalidInitialMessage, err)
                                })?;
                                (pq_party, content, true)
                            }
                            Err(e) => {
                                return Err(Error::new(ErrorKind::InvalidInitialMessage, e));
                            }
                        }
                    };
                    // Sender is now cryptographically authenticated via PQXDH + AEAD. Enforce
                    // manifest-digest binding BEFORE confirming prekey consumption so unauthenticated
                    // forgeries never surface sender-attributed `DowngradeDetected`.
                    if !self.state.recent_manifest_digests.is_empty() {
                        match digest {
                            Some(d) if !self.state.recent_manifest_digests.contains(d) => {
                                return Err(ErrorKind::DowngradeDetected.into());
                            }
                            None if strict_pq => {
                                return Err(ErrorKind::DowngradeDetected.into());
                            }
                            _ => {}
                        }
                    }
                    let incoming_seq =
                        checked_initial_hello(&content)?.map_or(0, |h| h.session_seq);
                    self.state.prekeys.confirm_pq(pq_init)?;
                    let security = SessionSecurity::pq(agreement.suite, pq_ratchet);
                    let mut updated_peer_pq = peer_state.clone();
                    updated_peer_pq.pq_pinned = true;
                    updated_peer_pq.peer_pq_capable = true;
                    updated_peer_pq.allow_classical_exception = false;
                    updated_peer_pq.downgrade_detected = false;
                    if incoming_seq > updated_peer_pq.peer_session_seq {
                        updated_peer_pq.peer_session_seq = incoming_seq;
                    }
                    let active = Active {
                        party,
                        id: pq_init.ephemeral_key,
                        known_by_peer: true,
                        initial_message: vec![],
                        delivery_key: DeliveryKey::derive(agreement.secret_key.as_slice()),
                        security,
                        peer_session_seq: incoming_seq,
                    };
                    let mut session = Session::new(mailbox, active, self.identity_key, *peer);
                    session.state.peer_pq = updated_peer_pq;
                    Ok(AcceptedInitial::Accepted {
                        session,
                        first_message: content,
                        security,
                    })
                }
                InitialMessageKind::Classical(classical) => {
                    let (agreement, signed_prekey) =
                        self.state
                            .prekeys
                            .accept(&self.state.identity, peer, &classical.x3dh)?;
                    let ratchet = Ratchet::bob(
                        &SharedKeys::from_secret(&agreement.secret_key),
                        DhPrivateKey::from(signed_prekey.to_bytes()),
                    );
                    let mut party = Party::new(ratchet, agreement.associated_data);
                    let content = party
                        .decrypt(&classical.first_message)
                        .map_err(|e| Error::new(ErrorKind::InvalidInitialMessage, e))?;
                    // Sender is now cryptographically authenticated via X3DH + AEAD. Enforce
                    // strict-PQ policy BEFORE calling `confirm()` so unauthenticated forgeries
                    // always return `InvalidInitialMessage` and strict-PQ rejections consume no
                    // prekeys.
                    if strict_pq {
                        return Err(ErrorKind::PqRequired.into());
                    }
                    let hello = checked_initial_hello(&content)?;
                    self.state.prekeys.confirm(&classical.x3dh)?;

                    let security = SessionSecurity::classical();
                    let incoming_seq = hello.as_ref().map_or(0, |h| h.session_seq);
                    let quarantined = local_pq_enabled
                        && (peer_state.pq_pinned || !peer_state.allow_classical_exception);

                    let mut updated_peer_pq = peer_state.clone();
                    if quarantined {
                        if peer_state.pq_pinned || hello.as_ref().is_some_and(|h| h.pq_capable) {
                            updated_peer_pq.downgrade_detected = true;
                        }
                    } else if let Some(ref h) = hello {
                        let _ =
                            check_peer_hello(&mut updated_peer_pq, security, h, local_pq_enabled);
                    }

                    let active = Active {
                        party,
                        id: classical.x3dh.ephemeral_key,
                        known_by_peer: true,
                        initial_message: vec![],
                        delivery_key: DeliveryKey::derive(agreement.secret_key.as_slice()),
                        security,
                        peer_session_seq: incoming_seq,
                    };
                    let mut session = Session::new(mailbox, active, self.identity_key, *peer);
                    session.state.peer_pq = updated_peer_pq;

                    if quarantined {
                        Ok(AcceptedInitial::Quarantined {
                            session,
                            first_message: content,
                            peer_was_pq_pinned: peer_state.pq_pinned,
                        })
                    } else {
                        Ok(AcceptedInitial::Accepted {
                            session,
                            first_message: content,
                            security,
                        })
                    }
                }
            }
        }
    }

    impl<H: LocalHandshakeV2> Client<H> {
        /// Query `GetServerInfo` and verify that the advertised `server_id` matches the locally
        /// configured `expected_audience` (failing with [`ErrorKind::DowngradeDetected`] on
        /// mismatch so the client never blindly trusts server-supplied audience strings).
        pub async fn check_server_info(
            &self,
            expected_audience: &str,
        ) -> Result<GetServerInfoResponse> {
            if expected_audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            let info = self
                .handshake
                .get_server_info(GetServerInfoRequest {})
                .await?;
            if info.server_id != expected_audience {
                return Err(ErrorKind::DowngradeDetected.into());
            }
            Ok(info)
        }

        /// Non-consuming read and verification of `peer`'s signed [`CapabilityManifest`] against
        /// the locally configured `audience` and server clock.
        pub async fn get_peer_manifest(
            &self,
            audience: &str,
            peer: &PublicKey,
        ) -> Result<Option<CapabilityManifest>> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            check_canonical_identity(peer)?;
            let response = self
                .handshake
                .get_manifest(GetManifestRequest {
                    identity_key: Bytes::copy_from_slice(peer),
                })
                .await?;
            if let Some(manifest) = &response.manifest {
                let verified_id = match verify_manifest_at(manifest, audience, self.clock.now()) {
                    Ok(id) => id,
                    Err(e) if e.kind() == protocol::ErrorKind::StaleTimestamp => {
                        return Err(Error::new(ErrorKind::PeerManifestExpired, e));
                    }
                    Err(e) => return Err(Error::new(ErrorKind::DowngradeDetected, e)),
                };
                if verified_id != *peer {
                    return Err(ErrorKind::DowngradeDetected.into());
                }
            }
            Ok(response.manifest)
        }

        /// Transmit a previously prepared v2 publish request (after persisting `self.state()`).
        pub async fn transmit_publish_v2(&self, prepared: &PreparedPublishV2) -> Result<()> {
            self.handshake.publish_v2(prepared.request.clone()).await?;
            Ok(())
        }

        /// Transmit a previously prepared v2 refill request (after persisting `self.state()`).
        pub async fn transmit_refill_v2(
            &self,
            prepared: &PreparedRefillV2,
        ) -> Result<RefillPrekeysResponse> {
            Ok(self
                .handshake
                .refill_prekeys(prepared.request.clone())
                .await?)
        }

        /// Prepare and transmit a non-rotating prekey refill via `HandshakeV2::refill_prekeys`.
        pub async fn refill_prekeys_v2(
            &mut self,
            audience: &str,
            one_time_count: usize,
            pq_one_time_count: usize,
        ) -> Result<RefillPrekeysResponse> {
            let prepared = self.prepare_refill_v2(audience, one_time_count, pq_one_time_count)?;
            match self.transmit_refill_v2(&prepared).await {
                Ok(response) => Ok(response),
                Err(e) if e.is_server_refusal() => {
                    self.rollback_refill_v2_on_refusal(prepared);
                    Err(e)
                }
                Err(e) => Err(e),
            }
        }

        /// Explicitly acknowledge and delete pending inbox initial messages by their stable
        /// server-assigned IDs (call ONLY after persisting accepted sessions locally).
        ///
        /// Include EVERY listed ID whose local `accept_initial_v2` finished — both accepted /
        /// quarantined AND permanently rejected IDs (such as `InvalidKeys`, `InvalidInitialMessage`,
        /// `PqRequired`, `UnsupportedSuite`, `DowngradeDetected`, or `malformed_ids`) — so
        /// invalid entries cannot permanently clog the inbox.
        pub async fn ack_initial_messages_v2(
            &mut self,
            audience: &str,
            ids: Vec<u64>,
        ) -> Result<u32> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            let ids: Vec<u64> = ids.into_iter().filter(|&id| id != 0).collect();
            if ids.is_empty() {
                return Ok(0);
            }
            let mut total = 0u32;
            for chunk in ids.chunks(MAX_ACK_BATCH) {
                total = total.saturating_add(self.ack_initial_chunk(audience, chunk).await?);
            }
            Ok(total)
        }

        async fn ack_initial_chunk(&mut self, audience: &str, ids: &[u64]) -> Result<u32> {
            let timestamp = self.next_timestamp()?;
            let request = AckInitialMessagesRequest::sign(
                &self.state.identity,
                audience,
                ids.to_vec(),
                timestamp,
            )?;
            Ok(self.handshake.ack_initial_messages(request).await?.deleted)
        }
    }

    impl<H: LocalHandshake + LocalHandshakeV2> Client<H> {
        /// Transmit a prepared v2 publish request, falling back gracefully ONLY when the server
        /// returns `Unimplemented` and `strict_pq` is `false`:
        ///
        /// 1. If `prepared` carried a PQ-enabled manifest and the server returned `Unimplemented`
        ///    (e.g. a v2 server rolled back to `PQ_ENABLED="false"`), first publishes a signed
        ///    `PQ-OFF` manifest via `PublishV2` using the exact same classical prekeys so existing
        ///    v2 users are not locked out of `Identity::publish`.
        /// 2. If `PublishV2` still returns `Unimplemented` (true legacy v1-only server), falls
        ///    back to v1 `Handshake::publish` using the exact same classical prekeys.
        pub async fn transmit_publish_v2_or_v1_fallback(
            &mut self,
            prepared: &PreparedPublishV2,
        ) -> Result<PublishV2Outcome> {
            let prepared_pq = prepared
                .request
                .manifest
                .as_ref()
                .is_some_and(|m| m.pq_enabled);
            match self.handshake.publish_v2(prepared.request.clone()).await {
                Ok(_) => Ok(if prepared_pq {
                    PublishV2Outcome::V2Pq
                } else {
                    PublishV2Outcome::V2ClassicalOff
                }),
                Err(e) if unimplemented_refusal(&e) => {
                    if self.state.pq_config.strict_pq {
                        return Err(Error::from_protocol_with_kind(ErrorKind::PqRequired, e));
                    }
                    if prepared_pq && let Some(orig_manifest) = prepared.request.manifest.as_ref() {
                        let timestamp = self.next_timestamp()?;
                        let expires_at = timestamp
                            .checked_add(DEFAULT_MANIFEST_TTL_MS)
                            .filter(|&t| t <= protocol::MAX_SAFE_INTEGER)
                            .ok_or(ErrorKind::Protocol)?;
                        let mut off_manifest = CapabilityManifest {
                            audience: orig_manifest.audience.clone(),
                            identity_key: Bytes::new(),
                            manifest_seq: prepared.manifest_seq,
                            generation: prepared.generation,
                            issued_at: timestamp,
                            expires_at,
                            pq_enabled: false,
                            strict_pq: false,
                            pq_ratchet_supported: false,
                            offered_suites: vec![],
                            signed_prekey: Bytes::copy_from_slice(
                                &prepared.classical.signed_prekey,
                            ),
                            pq_last_resort: vec![],
                            signature: Bytes::new(),
                        };
                        sign_manifest(&self.state.identity, &mut off_manifest)?;
                        let off_req = PublishV2Request::sign(
                            &self.state.identity,
                            off_manifest,
                            Some(prepared.classical.signed_prekey_signature),
                            &prepared.classical.one_time_prekeys,
                            vec![],
                            vec![],
                            timestamp,
                        )?;
                        match self.handshake.publish_v2(off_req).await {
                            Ok(_) => {
                                // PQOPKs were never uploaded under PQ_ENABLED=false; retract them
                                // locally so unused ML-KEM keys do not accumulate.
                                self.state
                                    .prekeys
                                    .retract_pq(&[], &prepared.pq_one_time_prekeys);
                                return Ok(PublishV2Outcome::V2ClassicalOff);
                            }
                            Err(e2) if unimplemented_refusal(&e2) => {
                                // True v1-only server; fall through to v1 Handshake::publish.
                            }
                            Err(e2) => return Err(e2.into()),
                        }
                    }
                    let timestamp = self.next_timestamp()?;
                    let v1_req =
                        PublishRequest::sign(&self.state.identity, &prepared.classical, timestamp)?;
                    self.handshake.publish(v1_req).await?;
                    self.state
                        .prekeys
                        .retract_pq(&[], &prepared.pq_one_time_prekeys);
                    self.state.manifest_seq = prepared.prev_manifest_seq;
                    if self.state.recent_manifest_digests.last() == Some(&prepared.manifest_digest)
                    {
                        self.state.recent_manifest_digests.pop();
                    }
                    Ok(PublishV2Outcome::V1Fallback)
                }
                Err(e) => Err(e.into()),
            }
        }

        /// Generate and publish prekeys + signed [`CapabilityManifest`] via `HandshakeV2`, with
        /// graceful fallback to signed OFF `PublishV2` or v1 `Handshake::publish` ONLY when the
        /// server returns `Unimplemented` and `strict_pq` is `false`.
        ///
        /// For persist-before-transmit flows, use [`Client::prepare_publish_v2`], persist
        /// [`Client::state`], then call [`Client::transmit_publish_v2_or_v1_fallback`] and
        /// [`Client::commit_publish_v2`].
        pub async fn publish_v2(
            &mut self,
            audience: &str,
            one_time_count: usize,
            pq_one_time_count: usize,
        ) -> Result<()> {
            let prepared = self.prepare_publish_v2(audience, one_time_count, pq_one_time_count)?;
            match self.transmit_publish_v2_or_v1_fallback(&prepared).await {
                Ok(_) => {
                    self.commit_publish_v2(prepared);
                    Ok(())
                }
                Err(e)
                    if e.is_server_refusal()
                        && matches!(
                            e.kind(),
                            ErrorKind::SignInRequired
                                | ErrorKind::PqRequired
                                | ErrorKind::LimitExceeded
                                | ErrorKind::Protocol
                        ) =>
                {
                    self.rollback_publish_v2_on_refusal(prepared);
                    Err(e)
                }
                Err(e) => Err(e),
            }
        }

        /// Claim `peer`'s bundle via `HandshakeV2::claim_bundle` (with v1 fallback on
        /// `Unimplemented` when policy allows), verify `peer`'s signed [`CapabilityManifest`]
        /// against `audience` and `peer_state`, negotiate the highest mutually supported suite
        /// (or enforce downgrade / approval policy), and build a [`PreparedInitiateV2`] WITHOUT
        /// sending the initial message yet so callers can persist `session.state()` first.
        pub async fn prepare_initiate_v2<M>(
            &mut self,
            audience: &str,
            peer: &PublicKey,
            peer_state: &PeerPqState,
            content: &[u8],
            mailbox: M,
        ) -> Result<PreparedInitiateV2<M>> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            check_canonical_identity(peer)?;
            self.state.pq_config.validate()?;

            let local_offered = self.state.pq_config.offered_suites();
            let local_pq_enabled = self.state.pq_config.pq_enabled && !local_offered.is_empty();
            let strict_pq = self.state.pq_config.strict_pq;
            if strict_pq && !local_pq_enabled {
                return Err(ErrorKind::PqRequired.into());
            }

            let preferred_suites: Vec<u32> = if local_pq_enabled {
                local_offered.iter().map(|s| u32::from(s.as_u8())).collect()
            } else {
                vec![]
            };

            let claim = self
                .handshake
                .claim_bundle(ClaimBundleRequest {
                    identity_key: Bytes::copy_from_slice(peer),
                    preferred_suites,
                })
                .await;

            let response = match claim {
                Ok(resp) => resp,
                Err(e) if unimplemented_refusal(&e) => {
                    // Legacy v1-only server.
                    if strict_pq {
                        return Err(Error::from_protocol_with_kind(ErrorKind::PqRequired, e));
                    }
                    if local_pq_enabled {
                        if peer_state.pq_pinned {
                            return Err(ErrorKind::DowngradeDetected.into());
                        }
                        if !peer_state.allow_classical_exception {
                            return Err(ErrorKind::ClassicalApprovalRequired {
                                peer_signed_off: false,
                            }
                            .into());
                        }
                    }
                    let v1_resp = self
                        .handshake
                        .fetch_bundle(FetchBundleRequest {
                            identity_key: Bytes::copy_from_slice(peer),
                        })
                        .await?;
                    let bundle = PrekeyBundle::try_from(&v1_resp)?;
                    return self.build_classical_initiate_v2(
                        peer,
                        peer_state.clone(),
                        bundle,
                        content,
                        mailbox,
                        true,
                    );
                }
                Err(e) => return Err(e.into()),
            };

            let mut updated_peer_state = peer_state.clone();

            match &response.manifest {
                Some(manifest) => {
                    // 1. Verify signature, audience binding, structural invariants, identity,
                    //    monotonic manifest_seq, and SPK match BEFORE checking expiry so a
                    //    replayed older expired manifest still hard-fails as DowngradeDetected!
                    let verified_id = verify_manifest(manifest, audience)
                        .map_err(|e| Error::new(ErrorKind::DowngradeDetected, e))?;
                    if verified_id != *peer {
                        return Err(ErrorKind::DowngradeDetected.into());
                    }
                    if manifest.manifest_seq < peer_state.pinned_manifest_seq {
                        return Err(ErrorKind::DowngradeDetected.into());
                    }
                    // 2. Check manifest validity window against server clock (a peer offline past
                    //    DEFAULT_MANIFEST_TTL_MS surfaces PeerManifestExpired rather than a false
                    //    downgrade alarm).
                    verify_manifest_at(manifest, audience, self.clock.now()).map_err(
                        |e| match e.kind() {
                            protocol::ErrorKind::StaleTimestamp => {
                                Error::new(ErrorKind::PeerManifestExpired, e)
                            }
                            _ => Error::new(ErrorKind::DowngradeDetected, e),
                        },
                    )?;
                    let resp_spk: PublicKey = protocol::fixed(&response.signed_prekey)
                        .map_err(|e| Error::new(ErrorKind::DowngradeDetected, e))?;
                    if manifest.signed_prekey.as_ref() != resp_spk.as_slice() {
                        return Err(ErrorKind::DowngradeDetected.into());
                    }

                    if manifest.pq_enabled {
                        updated_peer_state.pq_pinned = true;
                        updated_peer_state.peer_pq_capable = true;
                        updated_peer_state.pinned_manifest_seq =
                            peer_state.pinned_manifest_seq.max(manifest.manifest_seq);

                        if local_pq_enabled {
                            return self.build_pq_initiate_v2(
                                peer,
                                updated_peer_state,
                                manifest,
                                &response,
                                &local_offered,
                                content,
                                mailbox,
                            );
                        }

                        // Local PQ is OFF while peer has PQ ON.
                        if manifest.strict_pq {
                            return Err(ErrorKind::PqRequired.into());
                        }
                        let bundle = classical_bundle_from_claim(&response)?;
                        self.build_classical_initiate_v2(
                            peer,
                            updated_peer_state,
                            bundle,
                            content,
                            mailbox,
                            false,
                        )
                    } else {
                        // Peer published a valid signed OFF manifest.
                        if peer_state.pq_pinned
                            && peer_state.pinned_manifest_seq > 0
                            && manifest.manifest_seq <= peer_state.pinned_manifest_seq
                        {
                            return Err(ErrorKind::DowngradeDetected.into());
                        }
                        updated_peer_state.pinned_manifest_seq =
                            peer_state.pinned_manifest_seq.max(manifest.manifest_seq);
                        updated_peer_state.peer_pq_capable = false;

                        if strict_pq {
                            return Err(ErrorKind::PqRequired.into());
                        }
                        if local_pq_enabled && !peer_state.allow_classical_exception {
                            return Err(ErrorKind::ClassicalApprovalRequired {
                                peer_signed_off: true,
                            }
                            .into());
                        }
                        let bundle = classical_bundle_from_claim(&response)?;
                        self.build_classical_initiate_v2(
                            peer,
                            updated_peer_state,
                            bundle,
                            content,
                            mailbox,
                            false,
                        )
                    }
                }
                None => {
                    // No manifest: legacy v1 user OR server stripped the manifest.
                    if strict_pq {
                        return Err(ErrorKind::PqRequired.into());
                    }
                    if local_pq_enabled {
                        if peer_state.pq_pinned {
                            return Err(ErrorKind::DowngradeDetected.into());
                        }
                        if !peer_state.allow_classical_exception {
                            return Err(ErrorKind::ClassicalApprovalRequired {
                                peer_signed_off: false,
                            }
                            .into());
                        }
                    }
                    let bundle = classical_bundle_from_claim(&response)?;
                    self.build_classical_initiate_v2(
                        peer,
                        updated_peer_state,
                        bundle,
                        content,
                        mailbox,
                        false,
                    )
                }
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn build_pq_initiate_v2<M>(
            &self,
            peer: &PublicKey,
            mut peer_state: PeerPqState,
            manifest: &CapabilityManifest,
            response: &ClaimBundleResponse,
            local_offered: &[PqSuite],
            content: &[u8],
            mailbox: M,
        ) -> Result<PreparedInitiateV2<M>> {
            let peer_offered: Vec<PqSuite> = manifest
                .offered_suites
                .iter()
                .filter_map(|&s| u8::try_from(s).ok().and_then(PqSuite::from_u8))
                .collect();
            let expected_suite = local_offered
                .iter()
                .copied()
                .find(|s| peer_offered.contains(s))
                .ok_or(ErrorKind::UnsupportedSuite)?;

            // Server MUST return a PQ prekey when both sides support a mutual suite.
            if response.pq_last_resort.is_none() && response.pq_one_time_prekey.is_none() {
                return Err(ErrorKind::DowngradeDetected.into());
            }

            let pq_bundle = PqPrekeyBundle::try_from(response)
                .map_err(|e| Error::new(ErrorKind::DowngradeDetected, e))?;

            // Enforce that the server did not downgrade our mutually preferred suite.
            if pq_bundle.pq_suite != expected_suite {
                return Err(ErrorKind::DowngradeDetected.into());
            }

            // Verify commitment to the peer's last-resort PQSPK for the chosen suite.
            let committed_lr_id: [u8; 32] = manifest
                .pq_last_resort
                .iter()
                .find(|c| c.suite == u32::from(expected_suite.as_u8()))
                .ok_or(ErrorKind::DowngradeDetected)
                .and_then(|c| {
                    protocol::fixed(&c.prekey_id).map_err(|_| ErrorKind::DowngradeDetected)
                })?;

            if let Some(lr_wire) = &response.pq_last_resort {
                let (lr_suite, lr_id, _) = verify_wire_pq_prekey(peer, lr_wire, true)
                    .map_err(|e| Error::new(ErrorKind::DowngradeDetected, e))?;
                if lr_suite != expected_suite || lr_id != committed_lr_id {
                    return Err(ErrorKind::DowngradeDetected.into());
                }
            }
            if pq_bundle.pq_last_resort {
                let actual_id = pq_prekey_id(pq_bundle.pq_suite.as_u8(), &pq_bundle.pq_prekey);
                if actual_id != committed_lr_id {
                    return Err(ErrorKind::DowngradeDetected.into());
                }
            }

            let digest = manifest_digest(manifest)?;
            let (pq_initial, agreement) =
                pq_bundle.initiate_pq(&self.state.identity, peer, Some(&digest))?;

            let ratchet = Ratchet::alice(
                &SharedKeys::from_secret(&agreement.secret_key),
                &pq_bundle.signed_prekey,
            )?;
            let pq_ratchet =
                self.state.pq_config.pq_ratchet_enabled && manifest.pq_ratchet_supported;
            let mut party = if pq_ratchet {
                let party_suite = party::PqSuite::from_id(agreement.suite.as_u8())
                    .ok_or(ErrorKind::UnsupportedSuite)?;
                Party::new_pq(ratchet, agreement.associated_data, party_suite)
            } else {
                Party::new(ratchet, agreement.associated_data)
            };
            let first_message = party.encrypt(content)?;

            let mut wire_initial = handshake_v2::InitialMessageV2::from(&pq_initial);
            wire_initial.first_message = Some(first_message);
            wire_initial.manifest_digest = Bytes::copy_from_slice(&digest);
            let carried = encode_carried_initial(&wire_initial)?;

            peer_state.allow_classical_exception = false;
            peer_state.downgrade_detected = false;
            let security = SessionSecurity::pq(agreement.suite, pq_ratchet);
            let mut session = Session::new(
                mailbox,
                Active {
                    party,
                    id: pq_initial.ephemeral_key,
                    known_by_peer: false,
                    initial_message: carried.to_vec(),
                    delivery_key: DeliveryKey::derive(agreement.secret_key.as_slice()),
                    security,
                    peer_session_seq: 0,
                },
                self.identity_key,
                *peer,
            );
            session.state.peer_pq = peer_state;
            if let Some(hello) = extract_hello(content)
                && hello.session_seq > 0
            {
                session.state.next_session_seq = hello
                    .session_seq
                    .saturating_add(1)
                    .min(protocol::MAX_SAFE_INTEGER);
            }

            Ok(PreparedInitiateV2 {
                session,
                request: OutgoingInitialMessage::V2(SendInitialV2Request {
                    recipient: Bytes::copy_from_slice(peer),
                    message: Some(wire_initial),
                }),
                security,
            })
        }

        fn build_classical_initiate_v2<M>(
            &self,
            peer: &PublicKey,
            peer_state: PeerPqState,
            bundle: PrekeyBundle,
            content: &[u8],
            mailbox: M,
            use_v1_rpc: bool,
        ) -> Result<PreparedInitiateV2<M>> {
            let (message, agreement) = bundle.initiate(&self.state.identity, peer)?;
            let ratchet = Ratchet::alice(
                &SharedKeys::from_secret(&agreement.secret_key),
                &bundle.signed_prekey,
            )?;
            let mut party = Party::new(ratchet, agreement.associated_data);
            let first_message = party.encrypt(content)?;
            let v1_initial = handshake::InitialMessage {
                first_message: Some(first_message.clone()),
                ..handshake::InitialMessage::from(&message)
            };
            let request = if use_v1_rpc {
                OutgoingInitialMessage::V1(SendInitialMessageRequest {
                    recipient: Bytes::copy_from_slice(peer),
                    message: Some(v1_initial.clone()),
                })
            } else {
                let mut v2_initial = handshake_v2::InitialMessageV2::from(&message);
                v2_initial.first_message = Some(first_message);
                OutgoingInitialMessage::V2(SendInitialV2Request {
                    recipient: Bytes::copy_from_slice(peer),
                    message: Some(v2_initial),
                })
            };
            let security = SessionSecurity::classical();
            let mut session = Session::new(
                mailbox,
                Active {
                    party,
                    id: message.ephemeral_key,
                    known_by_peer: false,
                    initial_message: v1_initial.encode_to_vec(),
                    delivery_key: DeliveryKey::derive(agreement.secret_key.as_slice()),
                    security,
                    peer_session_seq: 0,
                },
                self.identity_key,
                *peer,
            );
            session.state.peer_pq = peer_state;
            if let Some(hello) = extract_hello(content)
                && hello.session_seq > 0
            {
                session.state.next_session_seq = hello
                    .session_seq
                    .saturating_add(1)
                    .min(protocol::MAX_SAFE_INTEGER);
            }
            Ok(PreparedInitiateV2 {
                session,
                request,
                security,
            })
        }

        /// Transmit an [`OutgoingInitialMessage`] prepared by [`Client::prepare_initiate_v2`] or
        /// [`Client::prepare_start_again_v2`] (after persisting `session.state()`).
        pub async fn send_prepared_initiate_v2(
            &self,
            request: &OutgoingInitialMessage,
        ) -> Result<()> {
            match request {
                OutgoingInitialMessage::V1(req) => {
                    self.handshake.send_initial_message(req.clone()).await?;
                }
                OutgoingInitialMessage::V2(req) => {
                    self.handshake.send_initial_v2(req.clone()).await?;
                }
            }
            Ok(())
        }

        /// Convenience wrapper: [`prepare_initiate_v2`](Self::prepare_initiate_v2) followed by
        /// [`send_prepared_initiate_v2`](Self::send_prepared_initiate_v2).
        pub async fn initiate_v2<M>(
            &mut self,
            audience: &str,
            peer: &PublicKey,
            peer_state: &PeerPqState,
            content: &[u8],
            mailbox: M,
        ) -> Result<Session<M>> {
            let prepared = self
                .prepare_initiate_v2(audience, peer, peer_state, content, mailbox)
                .await?;
            self.send_prepared_initiate_v2(&prepared.request).await?;
            Ok(prepared.session)
        }

        /// Alias for [`Client::initiate_v2`].
        pub async fn start_v2<M>(
            &mut self,
            audience: &str,
            peer: &PublicKey,
            peer_state: &PeerPqState,
            content: &[u8],
            mailbox: M,
        ) -> Result<Session<M>> {
            self.initiate_v2(audience, peer, peer_state, content, mailbox)
                .await
        }

        /// Prepare starting a new v2 session with `session`'s peer and merge it into `session`
        /// via [`Session::keep`], returning the [`OutgoingInitialMessage`] so the caller can
        /// persist `session.state()` BEFORE transmitting.
        pub async fn prepare_start_again_v2<M: Clone>(
            &mut self,
            audience: &str,
            session: &mut Session<M>,
            content: &[u8],
        ) -> Result<OutgoingInitialMessage> {
            if session.state.me != self.identity_key {
                return Err(ErrorKind::UnexpectedPeer.into());
            }
            let peer = session.state.peer;
            let peer_state = session.state.peer_pq.clone();
            let mailbox = session.mailbox.clone();
            let prepared = self
                .prepare_initiate_v2(audience, &peer, &peer_state, content, mailbox)
                .await?;
            let older = mem::replace(session, prepared.session);
            session.keep(older)?;
            Ok(prepared.request)
        }

        /// Convenience wrapper: start a new v2 session with `session`'s peer, merge via
        /// [`Session::keep`], and transmit the initial message.
        pub async fn start_again_v2<M: Clone>(
            &mut self,
            audience: &str,
            session: &mut Session<M>,
            content: &[u8],
        ) -> Result<()> {
            let outgoing = self
                .prepare_start_again_v2(audience, session, content)
                .await?;
            self.send_prepared_initiate_v2(&outgoing).await
        }

        /// Phase 1 of two-phase inbox receive: non-destructively list pending v1 and v2 initial
        /// messages from the server using `HandshakeV2::list_initial_messages`.
        ///
        /// Falls back to destructive v1 `TakeInitialMessages` ONLY when the server returns
        /// `Unimplemented` and `strict_pq` is `false`.
        pub async fn list_initial_messages_v2(
            &mut self,
            audience: &str,
            limit: u32,
        ) -> Result<ListedInitialMessages> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            let timestamp = self.next_timestamp()?;
            let request =
                ListInitialMessagesRequest::sign(&self.state.identity, audience, limit, timestamp)?;
            match self.handshake.list_initial_messages(request).await {
                Ok(response) => {
                    let mut messages = Vec::with_capacity(response.messages.len());
                    let mut malformed_ids = vec![];
                    for wire in &response.messages {
                        if wire.id == 0 || wire.id > protocol::MAX_SAFE_INTEGER {
                            continue;
                        }
                        match InitialMessageV2::try_from(wire) {
                            Ok(msg) => messages.push(msg),
                            Err(_) => malformed_ids.push(wire.id),
                        }
                    }
                    Ok(ListedInitialMessages {
                        messages,
                        malformed_ids,
                        fell_back_to_v1: false,
                    })
                }
                Err(e) if unimplemented_refusal(&e) => {
                    if self.state.pq_config.strict_pq {
                        return Err(Error::from_protocol_with_kind(ErrorKind::PqRequired, e));
                    }
                    let v1_messages = self.take_initial_messages().await?;
                    let messages = v1_messages
                        .into_iter()
                        .map(|m| InitialMessageV2 {
                            id: 0,
                            sender: m.x3dh.identity_key,
                            kind: InitialMessageKind::Classical(m),
                        })
                        .collect();
                    Ok(ListedInitialMessages {
                        messages,
                        malformed_ids: vec![],
                        fell_back_to_v1: true,
                    })
                }
                Err(e) => Err(e.into()),
            }
        }

        /// Convenience two-phase inbox flow: list, accept locally (returning both
        /// [`AcceptedInitial::Accepted`] and [`AcceptedInitial::Quarantined`] outcomes), and
        /// acknowledge handled inbox IDs. An acknowledgement failure returns the local outcomes
        /// in `Ok`. Persist them and retry the IDs in [`ListAndAcceptOutcome::unacked_ids`].
        ///
        /// Callers that must persist accepted state to durable storage BEFORE acknowledging the
        /// server should instead call [`list_initial_messages_v2`](Self::list_initial_messages_v2),
        /// [`accept_initial_v2`](Self::accept_initial_v2), persist, and then
        /// [`ack_initial_messages_v2`](Self::ack_initial_messages_v2).
        pub async fn list_and_accept_v2<M: Clone>(
            &mut self,
            audience: &str,
            limit: u32,
            mailbox: M,
            mut peer_state_for: impl FnMut(&PublicKey) -> PeerPqState,
        ) -> Result<ListAndAcceptOutcome<M>> {
            let listed = self.list_initial_messages_v2(audience, limit).await?;
            let can_ack = |id| id != 0 && id <= protocol::MAX_SAFE_INTEGER;
            let mut ack_ids = listed.malformed_ids;
            ack_ids.retain(|&id| can_ack(id));
            let mut outcomes = Vec::with_capacity(listed.messages.len());
            for msg in &listed.messages {
                if !listed.fell_back_to_v1 && !can_ack(msg.id) {
                    continue;
                }
                let peer_state = peer_state_for(&msg.sender);
                // `accept_initial_v2` is purely local with no transient errors: always acknowledge
                // every processed inbox ID so permanent failures (e.g. canonical low-order sender
                // `InvalidKeys`, `UnsupportedSuite`, `InvalidInitialMessage`, `PqRequired`,
                // `DowngradeDetected`, etc.) cannot permanently DoS the inbox.
                if !listed.fell_back_to_v1 {
                    ack_ids.push(msg.id);
                }
                if let Ok(outcome) =
                    self.accept_initial_v2(&msg.sender, &peer_state, msg, mailbox.clone())
                {
                    outcomes.push((msg.sender, outcome));
                }
            }
            let mut result = ListAndAcceptOutcome {
                outcomes,
                unacked_ids: vec![],
                ack_error: None,
            };
            if !listed.fell_back_to_v1 {
                for (index, chunk) in ack_ids.chunks(MAX_ACK_BATCH).enumerate() {
                    if let Err(error) = self.ack_initial_chunk(audience, chunk).await {
                        result.ack_error = Some(error);
                        result.unacked_ids = ack_ids.split_off(index * MAX_ACK_BATCH);
                        break;
                    }
                }
            }
            Ok(result)
        }
    }

    /// Build a classical `x3dh::PrekeyBundle` from a `ClaimBundleResponse`.
    fn classical_bundle_from_claim(response: &ClaimBundleResponse) -> Result<PrekeyBundle> {
        let signed_prekey: PublicKey = protocol::fixed(&response.signed_prekey)?;
        let sig_bytes = response
            .signed_prekey_signature
            .as_deref()
            .ok_or(ErrorKind::InvalidKeys)?;
        let signed_prekey_signature = protocol::fixed(sig_bytes)?;
        let one_time_prekey = response
            .one_time_prekey
            .as_deref()
            .map(protocol::fixed)
            .transpose()?;
        Ok(PrekeyBundle {
            signed_prekey,
            signed_prekey_signature,
            one_time_prekey,
        })
    }

    impl<M> Session<M> {
        /// Build a `PushV2Request` for `sealed` with a deterministic 16-byte `client_message_id`
        /// (stable across retries and restarts) and carrying either a v1 or v2 initial message
        /// until the peer is known to have the active session.
        pub fn push_v2_request(&self, sealed: Sealed) -> PushV2Request {
            let client_message_id = sealed.client_message_id();
            self.push_v2_request_with_id(sealed, Some(client_message_id))
        }

        /// Build a `PushV2Request` for `sealed` with an explicit optional 16-byte
        /// `client_message_id`.
        pub fn push_v2_request_with_id(
            &self,
            sealed: Sealed,
            client_message_id: Option<[u8; CLIENT_MESSAGE_ID_LENGTH]>,
        ) -> PushV2Request {
            let initial_message = self
                .state
                .active
                .as_ref()
                .filter(|active| !active.initial_message.is_empty())
                .and_then(|active| decode_carried_initial(&active.initial_message));
            PushV2Request {
                sender: Bytes::copy_from_slice(&self.state.me),
                recipient: Bytes::copy_from_slice(&self.state.peer),
                message: Some(sealed.message),
                initial_message,
                delivery_hash: sealed
                    .delivery_hash
                    .map_or_else(Bytes::new, |hash| Bytes::copy_from_slice(&hash)),
                client_message_id: client_message_id
                    .map_or_else(Bytes::new, |id| Bytes::copy_from_slice(&id)),
            }
        }
    }

    impl<M: LocalMailbox + LocalMailboxV2> Session<M> {
        /// Push `sealed` via `MailboxV2::push_v2` (with stable `client_message_id` and v1/v2
        /// carried initial message), falling back cleanly to v1 `Mailbox::push` on
        /// `ErrorKind::Unimplemented`.
        pub async fn push_v2(&mut self, sealed: Sealed) -> Result<u64> {
            let request = self.push_v2_request(sealed.clone());
            match self.mailbox.push_v2(request).await {
                Ok(resp) => Ok(resp.sequence),
                Err(e) if unimplemented_refusal(&e) => {
                    let resp = self.mailbox.push(self.push_request(sealed)).await?;
                    Ok(resp.sequence)
                }
                Err(e) => Err(e.into()),
            }
        }

        /// Encrypt `content` and push via [`Session::push_v2`].
        pub async fn send_v2(&mut self, content: &[u8]) -> Result<u64> {
            let sealed = self.encrypt(content)?;
            self.push_v2(sealed).await
        }

        /// Alias for [`Session::receive_v2`]: fetch and decrypt messages using recipient-signed
        /// `MailboxV2::fetch_signed` bound to `audience`, falling back cleanly to v1
        /// `Mailbox::fetch` on `ErrorKind::Unimplemented` unless `client.pq_config().strict_pq`
        /// is `true`.
        pub async fn fetch_v2<H>(
            &mut self,
            client: &Client<H>,
            audience: &str,
        ) -> Result<Vec<ReceivedV2>> {
            self.receive_v2(client, audience).await
        }

        /// Fetch and decrypt the next page of messages from the peer using recipient-signed
        /// `MailboxV2::fetch_signed` bound to `audience`, falling back cleanly to v1
        /// `Mailbox::fetch` on `ErrorKind::Unimplemented` unless `client.pq_config().strict_pq`
        /// is `true`.
        ///
        /// Surfaces `ErrorKind::EvictedMessage` distinctly while still acknowledging its
        /// delivery token, and never discards trailing carried v1/v2 initial messages across
        /// expired envelopes or page boundaries.
        pub async fn receive_v2<H>(
            &mut self,
            client: &Client<H>,
            audience: &str,
        ) -> Result<Vec<ReceivedV2>> {
            if self.state.me != client.identity_key {
                return Err(ErrorKind::UnexpectedPeer.into());
            }
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            let peer = self.state.peer;
            self.receive_pages(
                async |mailbox, request| {
                    let timestamp = client.clock.now();
                    if timestamp > protocol::MAX_SAFE_INTEGER {
                        return Err(ErrorKind::Protocol.into());
                    }
                    let signed = FetchSignedRequest::sign(
                        &client.state.identity,
                        audience,
                        &peer,
                        request.after,
                        request.limit,
                        0,
                        request.delivered.clone(),
                        timestamp,
                    )?;
                    match mailbox.fetch_signed(signed).await {
                        Ok(response) => Ok(response.messages),
                        Err(e) if unimplemented_refusal(&e) => {
                            if client.state.pq_config.strict_pq {
                                return Err(Error::from_protocol_with_kind(
                                    ErrorKind::PqRequired,
                                    e,
                                ));
                            }
                            Ok(mailbox
                                .fetch(request)
                                .await?
                                .messages
                                .into_iter()
                                .map(|env| EnvelopeV2 {
                                    sequence: env.sequence,
                                    message: env.message,
                                    initial_message: env
                                        .initial_message
                                        .as_ref()
                                        .map(handshake_v2::InitialMessageV2::from),
                                })
                                .collect())
                        }
                        Err(e) => Err(e.into()),
                    }
                },
                |content, earlier, initial_messages| ReceivedV2 {
                    content,
                    earlier,
                    initial_messages,
                },
            )
            .await
        }
    }
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
pub use v2::*;
