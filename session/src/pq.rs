//! Post-quantum (PQXDH + ML-KEM ratchet) configuration, per-peer pinning & downgrade defense,
//! and v2 handshake, unified mailbox, and write-token grant client flows.
//!
//! All configuration, state types, and v2 wire protocol methods (`handshake.v2`, `mailbox.v2`,
//! signed `CapabilityManifest`s, non-rotating prekey refills, cursor-paginated two-phase
//! initial-message delivery, sealed-sender-lite `PushV2`, unified `FetchSigned` + prefix
//! `AckMessages`, and write-token grants) are compiled unconditionally with **zero** `ml-kem`
//! dependency. ML-KEM cryptographic encapsulation/decapsulation is enabled only when
//! `ml-kem-1024`, `ml-kem-768`, or `pq` is selected.

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
pub struct PqConfig {
    /// Whether post-quantum handshakes (PQXDH) are enabled.
    pub pq_enabled: bool,
    /// Preferred ML-KEM suite when negotiating with a PQ-capable peer.
    pub preferred_suite: PqSuite,
    /// Whether continuous post-quantum KEM ratcheting is enabled on PQ sessions.
    pub pq_ratchet_enabled: bool,
    /// Strict / Require-PQ mode: refuse classical fallback and omit raw SPK signatures.
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

    /// Whether `suite` is compiled into this `session` crate build (gated strictly on `session`'s
    /// own ML-KEM features rather than transitive `x3dh` feature unification).
    pub const fn is_compiled_suite(suite: PqSuite) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match suite {
            PqSuite::MlKem1024 => cfg!(feature = "ml-kem-1024"),
            PqSuite::MlKem768 => cfg!(feature = "ml-kem-768"),
        }
    }

    /// All ML-KEM suites compiled into this build, in default preference order.
    pub fn compiled_suites() -> Vec<PqSuite> {
        let mut suites = Vec::with_capacity(2);
        if Self::is_compiled_suite(PqSuite::MlKem1024) {
            suites.push(PqSuite::MlKem1024);
        }
        if Self::is_compiled_suite(PqSuite::MlKem768) {
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
        if Self::is_compiled_suite(self.preferred_suite) {
            suites.push(self.preferred_suite);
        }
        for candidate in [PqSuite::MlKem1024, PqSuite::MlKem768] {
            if Self::is_compiled_suite(candidate) && !suites.contains(&candidate) {
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
pub struct PeerPqState {
    /// Whether this peer is pinned as post-quantum capable (from a verified PQ manifest, a PQ
    /// session, or a `#chat=...&pq=1` invite link).
    pub pq_pinned: bool,
    /// Highest verified `CapabilityManifest.manifest_seq` observed for this peer.
    pub pinned_manifest_seq: u64,
    /// SHA-256 digest of the verified `CapabilityManifest` observed at `pinned_manifest_seq`, if
    /// known (used to reject manifest equivocation at equal `manifest_seq`).
    #[cfg_attr(feature = "serde", serde(default))]
    pub pinned_manifest_digest: Option<[u8; 32]>,
    /// Explicit user-approved exception permitting classical fallback with this peer when local
    /// PQ is enabled and the peer published a signed `OFF` manifest (or relay rolled back PQ).
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
        if self.peer_pq_capable && self.downgrade_detected {
            return;
        }
        self.allow_classical_exception = true;
        if !self.peer_pq_capable {
            self.downgrade_detected = false;
        }
    }

    /// Clear any previously approved classical fallback exception.
    pub fn clear_classical_exception(&mut self) {
        self.allow_classical_exception = false;
    }

    /// Verify a peer's manifest `(seq, digest)` against the highest-seen pinned manifest and pin
    /// it monotonically.
    ///
    /// Rejects any rollback (`seq < self.pinned_manifest_seq`), out-of-range sequence (`0` or
    /// above [`protocol::MAX_SAFE_INTEGER`]), or equivocation at equal sequence number
    /// (`seq == self.pinned_manifest_seq` with a differing pinned digest) with
    /// [`ErrorKind::DowngradeDetected`] without mutating `self`.
    pub fn check_and_pin_manifest(&mut self, seq: u64, digest: [u8; 32]) -> Result<()> {
        if seq == 0 || seq > protocol::MAX_SAFE_INTEGER {
            return Err(ErrorKind::DowngradeDetected.into());
        }
        if seq < self.pinned_manifest_seq {
            return Err(ErrorKind::DowngradeDetected.into());
        }
        if seq == self.pinned_manifest_seq
            && self.pinned_manifest_digest.is_some_and(|d| d != digest)
        {
            return Err(ErrorKind::DowngradeDetected.into());
        }
        self.pinned_manifest_seq = seq;
        self.pinned_manifest_digest = Some(digest);
        Ok(())
    }

    /// Verify and commit a signed `PQ-OFF` manifest `(seq, digest)` monotonically onto `self`,
    /// transitioning `peer_pq_capable = false` when permitted (`R20-P1-4`).
    ///
    /// Rejects with [`ErrorKind::DowngradeDetected`] without mutating `self` if:
    /// - `self` is PQ-capable at `pinned_manifest_seq > 0` and `seq <= pinned_manifest_seq`
    ///   (rollback or same-sequence replay of an older signed `PQ-OFF` manifest);
    /// - [`Self::check_and_pin_manifest`] rejects the sequence or digest.
    ///
    /// When `pinned_manifest_seq == 0` (e.g. an inbound-initiated PQ contact whose manifest has
    /// never been observed yet), a valid signed `PQ-OFF` manifest still transitions
    /// `peer_pq_capable = false` so callers can prompt for explicit user approval (while
    /// invitation-level `#chat=...&pq=1` links enforce strict refusal at the caller layer).
    pub fn commit_signed_pq_off_manifest(&mut self, seq: u64, digest: [u8; 32]) -> Result<()> {
        if self.peer_pq_capable && self.pinned_manifest_seq > 0 && seq <= self.pinned_manifest_seq {
            return Err(ErrorKind::DowngradeDetected.into());
        }
        self.check_and_pin_manifest(seq, digest)?;
        self.peer_pq_capable = false;
        Ok(())
    }
}

/// Cryptographic security metadata of a single established session.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

pub(crate) fn check_peer_hello_with_allow_same(
    peer_state: &mut PeerPqState,
    session_security: SessionSecurity,
    hello: &protocol::content::Hello,
    local_pq_enabled: bool,
    allow_same_seq: bool,
) -> HelloCheck {
    if hello.session_seq > protocol::MAX_SAFE_INTEGER {
        return HelloCheck {
            downgrade_detected: false,
            recommend_start_again: false,
            stale_session_seq: true,
        };
    }
    let stale_session_seq = if peer_state.peer_session_seq > 0 {
        hello.session_seq == 0
            || if allow_same_seq {
                hello.session_seq < peer_state.peer_session_seq
            } else {
                hello.session_seq <= peer_state.peer_session_seq
            }
    } else {
        false
    };
    if stale_session_seq {
        return HelloCheck {
            downgrade_detected: false,
            recommend_start_again: false,
            stale_session_seq: true,
        };
    }
    if hello.session_seq > peer_state.peer_session_seq {
        peer_state.peer_session_seq = hello.session_seq;
    }
    if hello.pq_capable {
        peer_state.peer_pq_capable = true;
        peer_state.pq_pinned = true;
        peer_state.allow_classical_exception = false;
    }
    let downgrade_detected = !session_security.is_pq && local_pq_enabled && hello.pq_capable;
    if downgrade_detected {
        peer_state.downgrade_detected = true;
    }
    HelloCheck {
        downgrade_detected,
        recommend_start_again: downgrade_detected,
        stale_session_seq: false,
    }
}

/// Validate a peer's decrypted [`protocol::content::Hello`] against `peer_state`,
/// `session_security`, and `local_pq_enabled`:
///
/// - Enforces strictly increasing `peer_state.peer_session_seq` once a positive sequence number
///   has been observed (`0` is tolerated only while `peer_state.peer_session_seq == 0`). Stale or
///   out-of-range greetings return early without mutating `peer_state`.
/// - Records `peer_pq_capable = true` and `pq_pinned = true` if `hello.pq_capable` is `true`.
/// - If `!session_security.is_pq && local_pq_enabled && hello.pq_capable`, sets
///   `peer_state.downgrade_detected = true` and recommends starting a new session.
pub fn check_peer_hello(
    peer_state: &mut PeerPqState,
    session_security: SessionSecurity,
    hello: &protocol::content::Hello,
    local_pq_enabled: bool,
) -> HelloCheck {
    check_peer_hello_with_allow_same(peer_state, session_security, hello, local_pq_enabled, false)
}

/// Derive the canonical audience from the locally configured relay URL or hostname.
pub fn expected_audience_from_url(url_or_host: &str) -> Result<String> {
    normalize_audience(url_or_host).map_err(|_| ErrorKind::Protocol.into())
}

mod v2 {
    use core::mem;

    use bytes::Bytes;
    use party::{EncryptedMessage, Party};
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    use protocol::handshake_v2::verify_wire_pq_prekey;
    use protocol::{
        handshake_v2::{
            self, AckInitialMessagesRequest, CapabilityManifest, ClaimBundleRequest,
            ClaimBundleResponse, GetManifestRequest, GetServerInfoRequest, GetServerInfoResponse,
            ListInitialMessagesRequest, ListInitialMessagesResponse, LocalHandshakeV2,
            PqLastResortCommitment, PqPrekey, PublishV2Request, RefillPrekeysRequest,
            RefillPrekeysResponse, SendInitialV2Request, check_manifest_window_bounded,
            manifest_digest, sign_manifest, verify_manifest,
        },
        mailbox_v2::{
            AckMessagesRequest, CLIENT_MESSAGE_ID_LENGTH, EnvelopeV2, FetchSignedRequest,
            FetchSignedResponse, LocalMailboxV2, PEER_SLOT_ID_LENGTH, PushV2Request,
            RegisterWriteTokenRequest, RevokeWriteTokenRequest, WRITE_TOKEN_HASH_LENGTH,
            decode_carried_initial, encode_carried_initial,
        },
    };
    use ratchetx2::{DhPrivateKey, Ratchet, SharedKeys};
    use x3dh::{
        PQXDH_VERSION, PqInitialMessage, PqPrekeyId, PqSuite, PrekeyBundle, PublicKey,
        PublishedPrekeys,
    };
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    use x3dh::{PqPrekeyBundle, pq_prekey_id};
    use xeddsa::XEdDSAPublicKey;
    use zeroize::Zeroizing;

    use super::{
        DEFAULT_MANIFEST_TTL_MS, PeerPqState, PqConfig, SessionSecurity, check_peer_hello,
    };
    use crate::{
        Active, Client, MAX_RECEIVE_PAGE, Sealed, ServerClock, Session, WriteToken,
        checked_initial_hello,
        error::{Error, ErrorKind, Result},
        extract_hello,
    };

    /// Maximum inbox message IDs acknowledged in one `AckInitialMessages` call.
    const MAX_ACK_BATCH: usize = 100;

    fn unimplemented_refusal(error: &protocol::Error) -> bool {
        error.is_connect_error()
            && error.is_server_refusal()
            && error.kind() == protocol::ErrorKind::Unimplemented
    }

    /// Lock-free `GetServerInfo` capability probe verifying `server_id == expected_audience`.
    pub async fn check_server_info_with(
        handshake: &impl LocalHandshakeV2,
        expected_audience: &str,
    ) -> Result<GetServerInfoResponse> {
        if expected_audience.trim().is_empty() {
            return Err(ErrorKind::Protocol.into());
        }
        let info = handshake.get_server_info(GetServerInfoRequest {}).await?;
        if info.server_id != expected_audience {
            return Err(ErrorKind::DowngradeDetected.into());
        }
        Ok(info)
    }

    /// Lock-free transmission of a previously prepared non-rotating prekey refill request
    /// (after persisting [`Client::state`]). Performs zero local state mutation.
    pub async fn transmit_refill_v2_with(
        handshake: &impl LocalHandshakeV2,
        prepared: &PreparedRefillV2,
    ) -> Result<RefillPrekeysResponse> {
        Ok(handshake.refill_prekeys(prepared.request.clone()).await?)
    }

    /// Which v2 manifest outcome resulted from [`Client::transmit_publish_v2`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PublishV2Outcome {
        /// Published post-quantum + classical prekeys and a PQ-enabled signed manifest via `PublishV2`.
        V2Pq,
        /// Published classical prekeys and a signed PQ-off manifest via `PublishV2` (either
        /// because local PQ is disabled / not compiled in, or after transitioning via
        /// [`Client::prepare_publish_v2_classical_off`]).
        V2ClassicalOff,
        /// The server is a v2 relay with runtime `PQ_ENABLED="false"` that refused a PQ-ON publish
        /// while `strict_pq` is `false`. No local state was mutated and no OFF publish was sent;
        /// call [`Client::prepare_publish_v2_classical_off`], persist [`Client::state`], and
        /// transmit the resulting [`PreparedPublishV2`].
        ServerPqDisabled,
    }

    /// Rollback action for prekeys newly minted during a v2 publish preparation.
    #[derive(Debug)]
    pub(crate) enum PrekeyRollback {
        /// A brand-new generation was pushed (possibly evicting the oldest retained generation).
        Rotated {
            signed_prekey: PublicKey,
            evicted: Option<x3dh::EvictedGeneration>,
            #[allow(dead_code)]
            pq_one_time_prekeys: Vec<PqPrekeyId>,
            #[allow(dead_code)]
            pq_last_resort_suites: Vec<PqSuite>,
        },
        /// The current generation was extended in place with fresh OPKs, PQOPKs, and/or new
        /// last-resort PQSPK suites.
        Extended {
            signed_prekey: PublicKey,
            one_time_prekeys: Vec<PublicKey>,
            pq_one_time_prekeys: Vec<PqPrekeyId>,
            new_pq_last_resort_suites: Vec<PqSuite>,
        },
    }

    impl PrekeyRollback {
        fn rollback_on_prepare_error(self, prekeys: &mut x3dh::LocalPrekeys) {
            match self {
                Self::Rotated {
                    signed_prekey,
                    evicted,
                    ..
                } => {
                    prekeys.rollback_generation(&signed_prekey, evicted);
                }
                Self::Extended {
                    signed_prekey,
                    one_time_prekeys,
                    pq_one_time_prekeys,
                    new_pq_last_resort_suites,
                } => {
                    prekeys.retract_pq(
                        &signed_prekey,
                        &one_time_prekeys,
                        &pq_one_time_prekeys,
                        &new_pq_last_resort_suites,
                    );
                }
            }
        }

        /// Retract only the unused PQ prekeys minted by this prepare when a relay falls back to
        /// signed `PQ-OFF` (retaining the classical SPK/OPKs that were uploaded).
        fn retract_unused_pq(&self, prekeys: &mut x3dh::LocalPrekeys) {
            match self {
                Self::Rotated {
                    signed_prekey,
                    pq_one_time_prekeys,
                    pq_last_resort_suites,
                    ..
                } => {
                    prekeys.retract_pq(
                        signed_prekey,
                        &[],
                        pq_one_time_prekeys,
                        pq_last_resort_suites,
                    );
                }
                Self::Extended {
                    signed_prekey,
                    pq_one_time_prekeys,
                    new_pq_last_resort_suites,
                    ..
                } => {
                    prekeys.retract_pq(
                        signed_prekey,
                        &[],
                        pq_one_time_prekeys,
                        new_pq_last_resort_suites,
                    );
                }
            }
        }

        /// Clear PQ rollback tracking after unused PQ prekeys have been retracted locally,
        /// leaving only the classical rollback remainder.
        fn clear_pq(&mut self) {
            match self {
                Self::Rotated {
                    pq_one_time_prekeys,
                    pq_last_resort_suites,
                    ..
                } => {
                    pq_one_time_prekeys.clear();
                    pq_last_resort_suites.clear();
                }
                Self::Extended {
                    pq_one_time_prekeys,
                    new_pq_last_resort_suites,
                    ..
                } => {
                    pq_one_time_prekeys.clear();
                    new_pq_last_resort_suites.clear();
                }
            }
        }
    }

    /// A prepared v2 prekey + [`CapabilityManifest`] publish request.
    ///
    /// Persist [`Client::state`] BEFORE calling [`Client::transmit_publish_v2`], then call
    /// [`Client::commit_publish_v2`] on success or [`Client::rollback_publish_v2_on_refusal`] on
    /// definitive refusal.
    #[derive(Debug)]
    pub struct PreparedPublishV2 {
        /// The signed v2 publish request to transmit.
        pub request: PublishV2Request,
        /// Manifest sequence number assigned to this publish.
        pub manifest_seq: u64,
        /// Prekey generation number assigned to this publish.
        pub generation: u64,
        pub(crate) prev_manifest_seq: u64,
        pub(crate) prev_prekey_generation: u64,
        pub(crate) manifest_digest: [u8; 32],
        pub(crate) evicted_manifest_digest: Vec<crate::EvictedManifestDigest>,
        pub(crate) classical: PublishedPrekeys,
        pub(crate) rollback: PrekeyRollback,
        pub(crate) was_publishing: bool,
        pub(crate) preserve_signed_prekeys: Vec<PublicKey>,
        pub(crate) preserve_manifest_digests: Vec<[u8; 32]>,
    }

    impl PreparedPublishV2 {
        /// Public signed prekey of the oldest generation tentatively evicted from local `x3dh`
        /// storage by this rotating publish, if any.
        ///
        /// Callers releasing locks across `transmit_publish_v2_with` should defer (rather than
        /// ACK-and-drop) inbound greetings targeting this signed prekey until the publish commits
        /// or rolls back, so a refused publish never permanently deletes a valid greeting.
        pub fn evicted_signed_prekey(&self) -> Option<PublicKey> {
            match &self.rollback {
                PrekeyRollback::Rotated {
                    evicted: Some(ev), ..
                } => Some(ev.signed_prekey()),
                _ => None,
            }
        }
    }

    /// A prepared v2 non-rotating prekey refill request.
    ///
    /// Persist [`Client::state`] BEFORE calling [`Client::transmit_refill_v2`], then call
    /// [`Client::commit_refill_v2`] on success or [`Client::rollback_refill_v2_on_refusal`] on
    /// definitive refusal.
    #[derive(Debug, Clone)]
    pub struct PreparedRefillV2 {
        /// The signed v2 refill request to transmit.
        pub request: RefillPrekeysRequest,
        pub(crate) prev_last_timestamp: u64,
        pub(crate) signed_prekey: PublicKey,
        pub(crate) one_time_prekeys: Vec<PublicKey>,
        pub(crate) pq_one_time_prekeys: Vec<PqPrekeyId>,
    }

    /// Verified peer prekey bundle returned by lock-free [`claim_peer_bundle_v2`], ready to be
    /// completed synchronously with [`Client::finish_prepare_initiate_v2`] or
    /// [`Client::finish_prepare_start_again_v2`].
    #[derive(Debug, Clone)]
    pub struct ClaimedPeerBundle {
        peer: PublicKey,
        audience: String,
        manifest: CapabilityManifest,
        manifest_digest: [u8; 32],
        response: ClaimBundleResponse,
        server_pq_disabled_fallback: bool,
    }

    impl ClaimedPeerBundle {
        /// The peer whose bundle was claimed and verified.
        pub fn peer(&self) -> &PublicKey {
            &self.peer
        }

        /// The relay audience verified against the peer's signed manifest.
        pub fn audience(&self) -> &str {
            &self.audience
        }

        /// The peer's verified [`CapabilityManifest`].
        pub fn manifest(&self) -> &CapabilityManifest {
            &self.manifest
        }

        /// Whether this bundle was claimed via explicit classical fallback while the relay had
        /// `PQ_ENABLED="false"`.
        pub fn is_server_pq_disabled_fallback(&self) -> bool {
            self.server_pq_disabled_fallback
        }
    }

    /// Result of [`Client::prepare_initiate_v2`] or [`Client::finish_prepare_initiate_v2`]:
    /// persist [`session`](Self::session) BEFORE sending [`request`](Self::request) with
    /// [`Client::send_prepared_initiate_v2`].
    #[derive(Debug)]
    pub struct PreparedInitiateV2<M> {
        /// The newly established session (with updated [`PeerPqState`] and [`SessionSecurity`]).
        pub session: Session<M>,
        /// The v2 initial message request (carrying either PQXDH v2 or classical v1) to transmit
        /// after persisting `session.state()`.
        pub request: SendInitialV2Request,
        /// Negotiated security metadata for this session.
        pub security: SessionSecurity,
    }

    /// The inner payload of an [`InitialMessageV2`]: either classical X3DH (v1) or PQXDH (v2).
    #[derive(Debug, Clone, PartialEq)]
    pub enum InitialMessageKind {
        /// Classical X3DH (protocol version 1) inside `handshake.v2`.
        Classical {
            /// Classical X3DH key agreement payload.
            x3dh: x3dh::InitialMessage,
            /// Encrypted first Double Ratchet message authenticating the sender.
            first_message: EncryptedMessage,
        },
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
        /// Stable server-assigned inbox ID (`0` when carried inside a mailbox envelope).
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
                InitialMessageKind::Classical { .. } => None,
            }
        }

        /// Classical signed prekey public key referenced by this initial message.
        pub fn signed_prekey(&self) -> PublicKey {
            match &self.kind {
                InitialMessageKind::Classical { x3dh, .. } => x3dh.signed_prekey,
                InitialMessageKind::Pq { x3dh, .. } => x3dh.signed_prekey,
            }
        }

        /// Whether this initial message references a classical one-time prekey.
        pub fn uses_one_time_prekey(&self) -> bool {
            self.one_time_prekey().is_some()
        }

        /// Classical one-time prekey public key referenced by this initial message, if any.
        pub fn one_time_prekey(&self) -> Option<PublicKey> {
            match &self.kind {
                InitialMessageKind::Classical { x3dh, .. } => x3dh.one_time_prekey,
                InitialMessageKind::Pq { x3dh, .. } => x3dh.one_time_prekey,
            }
        }

        /// Whether this initial message references a one-time PQOPK (as opposed to last-resort).
        pub fn uses_pq_one_time_prekey(&self) -> bool {
            self.pq_one_time_prekey_id().is_some()
        }

        /// One-time PQOPK identifier referenced by this initial message, if any (returns `None`
        /// for classical initials or last-resort PQSPK handshakes).
        pub fn pq_one_time_prekey_id(&self) -> Option<PqPrekeyId> {
            match &self.kind {
                InitialMessageKind::Classical { .. } => None,
                InitialMessageKind::Pq { x3dh, .. } if !x3dh.pq_last_resort => {
                    Some(x3dh.pq_prekey_id)
                }
                InitialMessageKind::Pq { .. } => None,
            }
        }

        /// Decode raw carried initial message bytes from mailbox storage via
        /// [`protocol::mailbox_v2::decode_carried_initial`].
        pub fn decode_carried(bytes: &[u8]) -> Option<Self> {
            let wire = decode_carried_initial(bytes)?;
            let mut msg = Self::try_from(&wire).ok()?;
            msg.id = 0;
            Some(msg)
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
                        kind: InitialMessageKind::Classical {
                            x3dh,
                            first_message,
                        },
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
        /// Maximum validated inbox ID (`1..=MAX_SAFE_INTEGER`) examined on this page across all
        /// items (valid, `UnsupportedSuite`, and malformed), for cursor pagination.
        pub next_after_id: Option<u64>,
        /// Whether additional pending initial messages remain on the server after this page.
        pub has_more: bool,
    }

    /// Synchronous batch result from [`Client::accept_listed_v2`].
    ///
    /// Persist [`Client::state`] and every session in `outcomes` durably BEFORE acknowledging
    /// `ack_ids` via [`Client::ack_initial_messages_v2`]. Because processing is synchronous,
    /// cancelling an async task cannot lose locally confirmed sessions before they are returned.
    #[derive(Debug)]
    pub struct AcceptedInboxBatch<M> {
        /// Every initial message accepted or quarantined locally, with its prekeys confirmed.
        pub outcomes: Vec<(PublicKey, AcceptedInitial<M>)>,
        /// Inbox IDs safe to acknowledge after durable persistence: malformed IDs, accepted or
        /// quarantined IDs, post-persist/pre-ack crash-replayed IDs (`replayed_ids`), and
        /// permanent local rejections — excluding `unsupported` IDs.
        pub ack_ids: Vec<u64>,
        /// Inbox IDs whose ephemeral key was already confirmed in local prekey state
        /// (`x3dh::ErrorKind::Replayed`, e.g. on post-persist/pre-ack crash replay); already
        /// queued in `ack_ids`.
        pub replayed_ids: Vec<u64>,
        /// Valid PQXDH initial messages whose suite is not compiled into this build
        /// (`ErrorKind::UnsupportedSuite`); NOT included in `ack_ids` unless durably deferred
        /// first.
        pub unsupported: Vec<InitialMessageV2>,
        /// Permanently rejected inbox items `(id, claimed_sender, error)` (excluding `replayed_ids`
        /// and `unsupported`); already queued in `ack_ids`.
        pub rejected: Vec<(u64, PublicKey, Error)>,
        /// Cursor for fetching the next inbox page (`ListedInitialMessages::next_after_id`).
        pub next_after_id: Option<u64>,
        /// Whether additional inbox pages remain (`ListedInitialMessages::has_more`).
        pub has_more: bool,
    }

    /// Outcome of accepting an inbound v1/v2 initial message via [`Client::accept_initial_v2`].
    ///
    /// Its `Debug` implementation redacts `first_message` plaintext bytes.
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

    impl<M: core::fmt::Debug> core::fmt::Debug for AcceptedInitial<M> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Accepted {
                    session,
                    first_message,
                    security,
                } => f
                    .debug_struct("Accepted")
                    .field("session", session)
                    .field("first_message_len", &first_message.len())
                    .field("security", security)
                    .finish(),
                Self::Quarantined {
                    session,
                    first_message,
                    peer_was_pq_pinned,
                } => f
                    .debug_struct("Quarantined")
                    .field("session", session)
                    .field("first_message_len", &first_message.len())
                    .field("peer_was_pq_pinned", peer_was_pq_pinned)
                    .finish(),
            }
        }
    }

    /// One validated page fetched from the recipient's unified v2 mailbox via
    /// [`Client::fetch_mailbox_v2`].
    #[derive(Debug, Clone)]
    pub struct MailboxPage {
        /// Envelopes in strictly ascending `sequence` order (`> mailbox_cursor`,
        /// `<= MAX_SAFE_INTEGER`), each carrying a 32-byte `token_hash` and an inline encrypted
        /// message.
        pub messages: Vec<EnvelopeV2>,
        /// Whether additional messages remain on the server after the last returned envelope.
        pub has_more: bool,
        /// The `ack_up_to_sequence` watermark piggybacked on the `FetchSigned` request that the
        /// relay applied when returning this page (`0` if none was piggybacked).
        pub piggybacked_ack: u64,
    }

    impl MailboxPage {
        /// Highest sequence number present on this page, if non-empty.
        pub fn last_sequence(&self) -> Option<u64> {
            self.messages.last().map(|env| env.sequence)
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

    /// Lock-free transmission of a previously prepared v2 publish request (after persisting
    /// `Client::state()`).
    ///
    /// Performs zero local state mutation. If `prepared` carried a PQ-enabled manifest and a
    /// v2 server rolled back to runtime `PQ_ENABLED="false"` refuses PQ-ON with confirmed
    /// `Unimplemented`:
    /// - returns `Err(ErrorKind::PqRequired)` when `strict_pq` is `true`, or
    /// - returns `Ok(PublishV2Outcome::ServerPqDisabled)` when `strict_pq` is `false` without
    ///   transmitting an OFF manifest. Callers should then run
    ///   [`Client::prepare_publish_v2_classical_off`], persist [`Client::state`], and transmit
    ///   the resulting classical-OFF [`PreparedPublishV2`].
    pub async fn transmit_publish_v2_with(
        handshake: &impl LocalHandshakeV2,
        prepared: &PreparedPublishV2,
        strict_pq: bool,
    ) -> Result<PublishV2Outcome> {
        let prepared_pq = prepared
            .request
            .manifest
            .as_ref()
            .is_some_and(|m| m.pq_enabled);
        match handshake.publish_v2(prepared.request.clone()).await {
            Ok(_) => Ok(if prepared_pq {
                PublishV2Outcome::V2Pq
            } else {
                PublishV2Outcome::V2ClassicalOff
            }),
            Err(e) if unimplemented_refusal(&e) => {
                if prepared_pq && let Some(orig_manifest) = prepared.request.manifest.as_ref() {
                    match check_server_info_with(handshake, &orig_manifest.audience).await {
                        Ok(info) if !info.pq_enabled => {
                            if strict_pq {
                                return Err(Error::from_protocol_with_kind(
                                    ErrorKind::PqRequired,
                                    e,
                                ));
                            }
                            return Ok(PublishV2Outcome::ServerPqDisabled);
                        }
                        Ok(_) => return Err(e.into()),
                        Err(info_err) if info_err.kind() == ErrorKind::DowngradeDetected => {
                            return Err(info_err);
                        }
                        Err(info_err)
                            if info_err.is_connect_error()
                                && info_err.is_server_refusal()
                                && info_err.kind() == ErrorKind::Unimplemented =>
                        {
                            return Err(e.into());
                        }
                        Err(info_err) => return Err(info_err),
                    }
                }
                Err(e.into())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Lock-free Phase 1 of session initiation: claim `peer`'s bundle via
    /// `HandshakeV2::claim_bundle` (with `GetServerInfo` verification on `PQ_ENABLED="false"`
    /// relay rollback), verify `peer`'s signed [`CapabilityManifest`] against `audience`,
    /// `peer_state`, `pq_config`, and bounded local/server `clock`, and return an opaque
    /// [`ClaimedPeerBundle`] for synchronous completion via [`Client::finish_prepare_initiate_v2`]
    /// or [`Client::finish_prepare_start_again_v2`].
    ///
    /// Rejects any `ClaimBundleResponse` missing a signed manifest (`manifest: None`) with
    /// [`ErrorKind::DowngradeDetected`].
    pub async fn claim_peer_bundle_v2(
        handshake: &impl LocalHandshakeV2,
        audience: &str,
        peer: &PublicKey,
        peer_state: &PeerPqState,
        pq_config: &PqConfig,
        clock: &ServerClock,
    ) -> Result<ClaimedPeerBundle> {
        if audience.trim().is_empty() {
            return Err(ErrorKind::Protocol.into());
        }
        check_canonical_identity(peer)?;
        pq_config.validate()?;

        let local_offered = pq_config.offered_suites();
        let local_pq_enabled = pq_config.pq_enabled && !local_offered.is_empty();
        let strict_pq = pq_config.strict_pq;
        if strict_pq && !local_pq_enabled {
            return Err(ErrorKind::PqRequired.into());
        }

        let preferred_suites: Vec<u32> = if local_pq_enabled {
            local_offered.iter().map(|s| u32::from(s.as_u8())).collect()
        } else {
            vec![]
        };

        let mut server_pq_disabled_fallback = false;
        let response = match handshake
            .claim_bundle(ClaimBundleRequest {
                identity_key: Bytes::copy_from_slice(peer),
                preferred_suites,
            })
            .await
        {
            Ok(resp) => resp,
            Err(e) if unimplemented_refusal(&e) && local_pq_enabled => {
                match check_server_info_with(handshake, audience).await {
                    Ok(info) if !info.pq_enabled => {
                        if strict_pq {
                            return Err(Error::from_protocol_with_kind(ErrorKind::PqRequired, e));
                        }
                        if peer_state.pq_pinned {
                            return Err(ErrorKind::DowngradeDetected.into());
                        }
                        if !peer_state.allow_classical_exception {
                            return Err(Error::server_pq_disabled_approval());
                        }
                        server_pq_disabled_fallback = true;
                        handshake
                            .claim_bundle(ClaimBundleRequest {
                                identity_key: Bytes::copy_from_slice(peer),
                                preferred_suites: vec![],
                            })
                            .await?
                    }
                    Ok(_) => return Err(e.into()),
                    Err(info_err) if info_err.kind() == ErrorKind::DowngradeDetected => {
                        return Err(info_err);
                    }
                    Err(info_err)
                        if info_err.is_connect_error()
                            && info_err.is_server_refusal()
                            && info_err.kind() == ErrorKind::Unimplemented =>
                    {
                        return Err(e.into());
                    }
                    Err(info_err) => return Err(info_err),
                }
            }
            Err(e) => return Err(e.into()),
        };

        let Some(manifest) = response.manifest.clone() else {
            return Err(ErrorKind::DowngradeDetected.into());
        };

        // 1. Verify signature, audience binding, structural invariants, identity, monotonic
        //    manifest_seq + anti-equivocation digest, and SPK match BEFORE checking clock skew or
        //    expiry so a replayed or equivocating manifest always hard-fails as DowngradeDetected.
        let verified_id = verify_manifest(&manifest, audience)
            .map_err(|e| Error::new(ErrorKind::DowngradeDetected, e))?;
        if verified_id != *peer {
            return Err(ErrorKind::DowngradeDetected.into());
        }
        let digest =
            manifest_digest(&manifest).map_err(|e| Error::new(ErrorKind::DowngradeDetected, e))?;
        let mut candidate_peer_state = peer_state.clone();
        candidate_peer_state.check_and_pin_manifest(manifest.manifest_seq, digest)?;
        let resp_spk: PublicKey = protocol::fixed(&response.signed_prekey)
            .map_err(|e| Error::new(ErrorKind::DowngradeDetected, e))?;
        if manifest.signed_prekey.as_ref() != resp_spk.as_slice() {
            return Err(ErrorKind::DowngradeDetected.into());
        }

        // 2. Check manifest validity window against the bounded local + server clock pair.
        let (local_now, server_now) = clock.trusted_clock_pair()?;
        check_manifest_window_bounded(&manifest, local_now, server_now)
            .map_err(|e| Error::new(ErrorKind::PeerManifestExpired, e))?;

        // 3. Enforce policy upfront so callers fail before re-acquiring locks.
        let claimed = ClaimedPeerBundle {
            peer: *peer,
            audience: audience.to_string(),
            manifest,
            manifest_digest: digest,
            response,
            server_pq_disabled_fallback,
        };
        let _ = evaluate_claimed_bundle_policy(&claimed, peer_state, pq_config)?;
        Ok(claimed)
    }

    enum ResolvedBundlePolicy {
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        Pq {
            updated_peer_state: PeerPqState,
            expected_suite: PqSuite,
        },
        Classical {
            updated_peer_state: PeerPqState,
            bundle: PrekeyBundle,
        },
    }

    /// Evaluate policy and prekey consistency for a verified [`ClaimedPeerBundle`] against the
    /// live `peer_state` and `pq_config`.
    fn evaluate_claimed_bundle_policy(
        claimed: &ClaimedPeerBundle,
        peer_state: &PeerPqState,
        pq_config: &PqConfig,
    ) -> Result<ResolvedBundlePolicy> {
        pq_config.validate()?;
        let local_offered = pq_config.offered_suites();
        let local_pq_enabled = pq_config.pq_enabled && !local_offered.is_empty();
        let strict_pq = pq_config.strict_pq;
        if strict_pq && !local_pq_enabled {
            return Err(ErrorKind::PqRequired.into());
        }

        let manifest = &claimed.manifest;
        let mut updated_peer_state = peer_state.clone();
        if manifest.pq_enabled {
            updated_peer_state
                .check_and_pin_manifest(manifest.manifest_seq, claimed.manifest_digest)?;
        } else {
            updated_peer_state
                .commit_signed_pq_off_manifest(manifest.manifest_seq, claimed.manifest_digest)?;
        }

        if claimed.server_pq_disabled_fallback {
            if strict_pq {
                return Err(ErrorKind::PqRequired.into());
            }
            if peer_state.pq_pinned || (local_pq_enabled && peer_state.downgrade_detected) {
                return Err(ErrorKind::DowngradeDetected.into());
            }
            if local_pq_enabled && !peer_state.allow_classical_exception {
                return Err(Error::server_pq_disabled_approval());
            }
        }

        if manifest.pq_enabled {
            if !claimed.server_pq_disabled_fallback {
                updated_peer_state.pq_pinned = true;
                updated_peer_state.allow_classical_exception = false;
            }
            updated_peer_state.peer_pq_capable = true;

            #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
            if local_pq_enabled && !claimed.server_pq_disabled_fallback {
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
                if claimed.response.pq_last_resort.is_none()
                    && claimed.response.pq_one_time_prekey.is_none()
                {
                    return Err(ErrorKind::DowngradeDetected.into());
                }
                return Ok(ResolvedBundlePolicy::Pq {
                    updated_peer_state,
                    expected_suite,
                });
            }

            if manifest.strict_pq {
                return Err(ErrorKind::PqRequired.into());
            }
            let bundle = classical_bundle_from_claim(&claimed.response)?;
            Ok(ResolvedBundlePolicy::Classical {
                updated_peer_state,
                bundle,
            })
        } else {
            // Peer published a valid signed OFF manifest (already verified against rollback and
            // pre-manifest PQ pins via `commit_signed_pq_off_manifest` above).
            if strict_pq {
                return Err(ErrorKind::PqRequired.into());
            }
            if local_pq_enabled && peer_state.downgrade_detected {
                return Err(ErrorKind::DowngradeDetected.into());
            }
            if local_pq_enabled && !peer_state.allow_classical_exception {
                return Err(match updated_peer_state.pinned_manifest_digest {
                    Some(digest) if updated_peer_state.pinned_manifest_seq > 0 => {
                        Error::signed_pq_off_approval(
                            updated_peer_state.pinned_manifest_seq,
                            digest,
                        )
                    }
                    _ => ErrorKind::ClassicalApprovalRequired.into(),
                });
            }
            let bundle = classical_bundle_from_claim(&claimed.response)?;
            Ok(ResolvedBundlePolicy::Classical {
                updated_peer_state,
                bundle,
            })
        }
    }

    impl<H> Client<H> {
        /// Prepare a v2 prekey + signed [`CapabilityManifest`] publish request without sending
        /// it over the network yet.
        ///
        /// Persist `self.state()` BEFORE transmitting [`PreparedPublishV2::request`] so a crash
        /// mid-request can never leave the server serving prekeys whose private keys were not
        /// persisted.
        ///
        /// - When `pq_config().pq_enabled` is `true`, publishes classical SPK (+ raw SPK
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
            self.prepare_publish_v2_preserving(
                audience,
                one_time_count,
                pq_one_time_count,
                &[],
                &[],
            )
        }

        /// Prepare a v2 prekey + signed [`CapabilityManifest`] publish request while preserving
        /// any local prekey generation referenced by `preserve_signed_prekeys` and preferring to
        /// retain any manifest digests listed in `preserve_manifest_digests` (e.g. for deferred
        /// unsupported-suite initials awaiting replay on a capable build).
        ///
        /// When rotating would otherwise evict the oldest kept generation and its signed prekey
        /// appears in `preserve_signed_prekeys`, this extends the current generation in place
        /// instead of rotating it out.
        pub fn prepare_publish_v2_preserving(
            &mut self,
            audience: &str,
            one_time_count: usize,
            pq_one_time_count: usize,
            preserve_signed_prekeys: &[PublicKey],
            preserve_manifest_digests: &[[u8; 32]],
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
            if !self.has_spare_manifest_digest_slot_for_publish(
                preserve_signed_prekeys,
                preserve_manifest_digests,
            ) {
                return Err(ErrorKind::LimitExceeded.into());
            }

            let timestamp = self.trusted_timestamp()?;
            let issued_at = timestamp;
            let expires_at = issued_at
                .checked_add(DEFAULT_MANIFEST_TTL_MS)
                .filter(|&t| t <= protocol::MAX_SAFE_INTEGER)
                .ok_or(ErrorKind::Protocol)?;
            let prev_manifest_seq = self.state.manifest_seq;
            let prev_prekey_generation = self.state.prekey_generation;
            let manifest_seq = prev_manifest_seq
                .checked_add(1)
                .filter(|&s| s <= protocol::MAX_SAFE_INTEGER)
                .ok_or(ErrorKind::Protocol)?;

            let was_publishing = self.state.publishing;
            let preserve_oldest = self
                .state
                .prekeys
                .oldest_evictable_signed_prekey()
                .is_some_and(|spk| preserve_signed_prekeys.contains(&spk));
            let extended =
                (was_publishing || preserve_oldest) && self.state.prekeys.generation_count() > 0;
            // If a prior confirmed publish left an extra generation pinned only because of a
            // deferred initial that has now cleared, prune it before staging a new generation so
            // total stored generations remain <= MAX_STORED_GENERATIONS without evicting `G`.
            if !extended && !was_publishing {
                self.state.prekeys.prune_to_kept(preserve_signed_prekeys);
            }
            let generation = if extended {
                self.state.prekey_generation.max(1)
            } else {
                self.state
                    .prekey_generation
                    .checked_add(1)
                    .filter(|&g| g <= protocol::MAX_SAFE_INTEGER)
                    .ok_or(ErrorKind::Protocol)?
            };
            let (classical, pq_last_resort_wire, pq_one_time_wire, rollback) = {
                #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
                let pq_branch = pq_enabled;
                #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
                let pq_branch = {
                    let _ = pq_one_time_count;
                    false
                };
                if pq_branch {
                    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
                    {
                        let first_suite = offered[0];
                        let mut new_lr_suites = Vec::with_capacity(offered.len());
                        if extended && !self.state.prekeys.has_pq_last_resort(first_suite) {
                            new_lr_suites.push(first_suite);
                        }
                        let (first, evicted) = if extended {
                            (
                                self.state.prekeys.extend_pq(
                                    &self.state.identity,
                                    first_suite,
                                    one_time_count,
                                    pq_one_time_count,
                                )?,
                                None,
                            )
                        } else {
                            new_lr_suites.push(first_suite);
                            self.state.prekeys.generate_pq_pending(
                                &self.state.identity,
                                first_suite,
                                one_time_count,
                                pq_one_time_count,
                            )?
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
                            let minted_lr = !self.state.prekeys.has_pq_last_resort(extra_suite);
                            match self.state.prekeys.extend_pq(
                                &self.state.identity,
                                extra_suite,
                                0,
                                pq_one_time_count,
                            ) {
                                Ok(extra) => {
                                    if minted_lr {
                                        new_lr_suites.push(extra_suite);
                                    }
                                    lr_wire.push(PqPrekey::from(&extra.pq_last_resort));
                                    pq_opk_ids
                                        .extend(extra.pq_one_time_prekeys.iter().map(|k| k.id));
                                    opk_wire.extend(
                                        extra.pq_one_time_prekeys.iter().map(PqPrekey::from),
                                    );
                                }
                                Err(err) => {
                                    let rollback = if extended {
                                        PrekeyRollback::Extended {
                                            signed_prekey: first.classical.signed_prekey,
                                            one_time_prekeys: first.classical.one_time_prekeys,
                                            pq_one_time_prekeys: pq_opk_ids,
                                            new_pq_last_resort_suites: new_lr_suites,
                                        }
                                    } else {
                                        PrekeyRollback::Rotated {
                                            signed_prekey: first.classical.signed_prekey,
                                            evicted,
                                            pq_one_time_prekeys: pq_opk_ids,
                                            pq_last_resort_suites: new_lr_suites,
                                        }
                                    };
                                    rollback.rollback_on_prepare_error(&mut self.state.prekeys);
                                    return Err(err.into());
                                }
                            }
                        }
                        let rollback = if extended {
                            PrekeyRollback::Extended {
                                signed_prekey: first.classical.signed_prekey,
                                one_time_prekeys: first.classical.one_time_prekeys.clone(),
                                pq_one_time_prekeys: pq_opk_ids,
                                new_pq_last_resort_suites: new_lr_suites,
                            }
                        } else {
                            PrekeyRollback::Rotated {
                                signed_prekey: first.classical.signed_prekey,
                                evicted,
                                pq_one_time_prekeys: pq_opk_ids,
                                pq_last_resort_suites: new_lr_suites,
                            }
                        };
                        (first.classical, lr_wire, opk_wire, rollback)
                    }
                    #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
                    unreachable!("pq_branch is false when no ML-KEM suite is compiled in")
                } else {
                    let (classical, evicted) = if extended {
                        (
                            self.state
                                .prekeys
                                .extend(&self.state.identity, one_time_count),
                            None,
                        )
                    } else {
                        self.state
                            .prekeys
                            .generate_pending(&self.state.identity, one_time_count)
                    };
                    let rollback = if extended {
                        PrekeyRollback::Extended {
                            signed_prekey: classical.signed_prekey,
                            one_time_prekeys: classical.one_time_prekeys.clone(),
                            pq_one_time_prekeys: vec![],
                            new_pq_last_resort_suites: vec![],
                        }
                    } else {
                        PrekeyRollback::Rotated {
                            signed_prekey: classical.signed_prekey,
                            evicted,
                            pq_one_time_prekeys: vec![],
                            pq_last_resort_suites: vec![],
                        }
                    };
                    (
                        classical,
                        Vec::<PqPrekey>::new(),
                        Vec::<PqPrekey>::new(),
                        rollback,
                    )
                }
            };

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
            let spk_sig = if pq_enabled && strict_pq {
                None
            } else {
                Some(classical.signed_prekey_signature)
            };
            let signed = (|| -> Result<([u8; 32], PublishV2Request)> {
                sign_manifest(&self.state.identity, &mut manifest)?;
                let own_digest = manifest_digest(&manifest)?;
                let request = PublishV2Request::sign(
                    &self.state.identity,
                    manifest,
                    spk_sig,
                    &classical.one_time_prekeys,
                    pq_last_resort_wire,
                    pq_one_time_wire,
                    timestamp,
                )?;
                Ok((own_digest, request))
            })();
            let (own_digest, request) = match signed {
                Ok(pair) => pair,
                Err(err) => {
                    rollback.rollback_on_prepare_error(&mut self.state.prekeys);
                    return Err(err);
                }
            };

            self.state.manifest_seq = manifest_seq;
            self.state.prekey_generation = generation;
            self.state.publishing = true;
            let evicted_manifest_digest = self.state.stage_manifest_digest(
                own_digest,
                Some(classical.signed_prekey),
                preserve_manifest_digests,
            );

            Ok(PreparedPublishV2 {
                request,
                manifest_seq,
                generation,
                prev_manifest_seq,
                prev_prekey_generation,
                manifest_digest: own_digest,
                evicted_manifest_digest,
                classical,
                rollback,
                was_publishing,
                preserve_signed_prekeys: preserve_signed_prekeys.to_vec(),
                preserve_manifest_digests: preserve_manifest_digests.to_vec(),
            })
        }

        /// Whether a previously prepared publish was persisted without confirmation and awaits
        /// reconciliation against the relay's signed manifest before rotating or refilling.
        pub fn has_unreconciled_publish(&self) -> bool {
            self.state.publishing
        }

        /// Reconcile an interrupted or ambiguous publish against the relay's current verified
        /// `CapabilityManifest` (returned by read-only `GetManifest`).
        ///
        /// Returns `true` when the relay already holds this client's latest `manifest_seq` and
        /// current signed prekey (meaning the interrupted publish landed and is now committed),
        /// or `false` when the relay still holds an older (or absent) manifest.
        ///
        /// When the publish has NOT landed on the relay yet, this NEVER pops the prepared latest
        /// generation, NEVER deletes its manifest digest, and NEVER rewinds `manifest_seq`:
        /// keeping `publishing == true` ensures a delayed in-flight publish from a prior tab
        /// remains decryptable if it arrives late, while the caller's retry reuses the exact same
        /// prepared generation at `manifest_seq + 1` (preventing relay `prev_signed_prekey`
        /// desync and blocking `RefillPrekeys` until confirmed commit).
        pub fn reconcile_interrupted_publish(
            &mut self,
            relay_manifest: Option<&CapabilityManifest>,
            preserve_signed_prekeys: &[PublicKey],
            preserve_manifest_digests: &[[u8; 32]],
        ) -> bool {
            let mut eff_spks = preserve_signed_prekeys.to_vec();
            let mut eff_digests = preserve_manifest_digests.to_vec();
            let Some(m) = relay_manifest else {
                // First-ever publish hasn't landed on the relay (or is still in flight): keep
                // prepared generation, digest, durable `manifest_seq`, and `publishing = true`
                // so the retry reuses the prepared generation at a strictly higher `manifest_seq`.
                return false;
            };
            let relay_spk = <[u8; 32]>::try_from(m.signed_prekey.as_ref()).ok();
            if let Some(spk) = relay_spk
                && !eff_spks.contains(&spk)
            {
                eff_spks.push(spk);
            }
            let relay_digest = manifest_digest(m).ok();
            if let Some(d) = relay_digest {
                // Record the verified relay manifest digest as confirmed so subsequent failed
                // publish attempts can never evict it from the rolling 16-entry window.
                self.state.record_confirmed_manifest_digest(d, relay_spk);
                if !eff_digests.contains(&d) {
                    eff_digests.push(d);
                }
            }
            let landed = relay_spk.is_some()
                && relay_spk == self.state.prekeys.current_signed_prekey()
                && m.manifest_seq >= self.state.manifest_seq;
            if landed {
                self.state.manifest_seq = m.manifest_seq;
                self.state.prekey_generation = m.generation;
                self.state.publishing = false;
                self.state.prekeys.prune_to_kept(&eff_spks);
                self.state.prune_manifest_digests_preserving(&eff_digests);
                true
            } else {
                // Keep the prepared generation, digest, durable `manifest_seq` high-water mark,
                // and `publishing = true` so a delayed in-flight publish cannot lose keys or
                // collide with a reused sequence number; advance only if the relay is ahead.
                if m.manifest_seq > self.state.manifest_seq {
                    self.state.manifest_seq = m.manifest_seq;
                }
                if m.generation >= self.state.prekey_generation {
                    if relay_spk != self.state.prekeys.current_signed_prekey() {
                        self.state.prekey_generation = m
                            .generation
                            .saturating_add(1)
                            .min(protocol::MAX_SAFE_INTEGER);
                    } else {
                        self.state.prekey_generation = m.generation;
                    }
                }
                false
            }
        }

        /// Mark a prepared v2 publish as confirmed by the server, now safely pruning superseded
        /// prekey generations and rolling manifest digests outside the preserved sets.
        pub fn commit_publish_v2_preserving(
            &mut self,
            prepared: PreparedPublishV2,
            preserve_signed_prekeys: &[PublicKey],
            preserve_manifest_digests: &[[u8; 32]],
        ) {
            self.state.publishing = false;
            self.state.record_confirmed_manifest_digest(
                prepared.manifest_digest,
                Some(prepared.classical.signed_prekey),
            );
            self.state.prekeys.prune_to_kept(preserve_signed_prekeys);
            self.state
                .prune_manifest_digests_preserving(preserve_manifest_digests);
        }

        /// Mark a prepared v2 publish as confirmed by the server, preserving any signed prekeys
        /// and manifest digests requested when preparing it.
        pub fn commit_publish_v2(&mut self, prepared: PreparedPublishV2) {
            let preserve_spks = prepared.preserve_signed_prekeys.clone();
            let preserve_digests = prepared.preserve_manifest_digests.clone();
            self.commit_publish_v2_preserving(prepared, &preserve_spks, &preserve_digests);
        }

        /// Transition a prepared PQ-ON publish into a signed classical `PQ-OFF` publish after
        /// [`Client::transmit_publish_v2`] returned [`PublishV2Outcome::ServerPqDisabled`].
        ///
        /// Persist [`Client::state`] AFTER this returns `Ok(off_prepared)` and BEFORE transmitting
        /// with [`Client::transmit_publish_v2`], then call [`Client::commit_publish_v2`] on
        /// success or [`Client::rollback_publish_v2_on_refusal`] on storage failure or definitive
        /// refusal.
        ///
        /// On any error for the active `prepared` (e.g. `strict_pq`, [`ErrorKind::ClockSkew`],
        /// overflow, or signing error), rolls back `prepared` via
        /// [`Client::rollback_publish_v2_on_refusal`] before returning `Err`.
        pub fn prepare_publish_v2_classical_off(
            &mut self,
            mut prepared: PreparedPublishV2,
            preserve_manifest_digests: &[[u8; 32]],
        ) -> Result<PreparedPublishV2> {
            if self.state.manifest_seq != prepared.manifest_seq {
                return Err(ErrorKind::Protocol.into());
            }
            let built = (|| -> Result<(u64, [u8; 32], PublishV2Request)> {
                if self.state.pq_config.strict_pq {
                    return Err(ErrorKind::PqRequired.into());
                }
                let orig_manifest = prepared
                    .request
                    .manifest
                    .as_ref()
                    .ok_or(ErrorKind::Protocol)?;
                if !orig_manifest.pq_enabled {
                    return Err(ErrorKind::Protocol.into());
                }
                let post_commit_spks = self
                    .state
                    .prekeys
                    .retained_signed_prekeys_after_prune(&prepared.preserve_signed_prekeys);
                let preserved_other = self.state.count_hard_pinned_manifest_digests(
                    &post_commit_spks,
                    preserve_manifest_digests,
                    Some(prepared.manifest_digest),
                );
                if preserved_other >= crate::MAX_RETAINED_MANIFEST_DIGESTS {
                    return Err(ErrorKind::LimitExceeded.into());
                }
                let timestamp = self.trusted_timestamp()?;
                let expires_at = timestamp
                    .checked_add(DEFAULT_MANIFEST_TTL_MS)
                    .filter(|&t| t <= protocol::MAX_SAFE_INTEGER)
                    .ok_or(ErrorKind::Protocol)?;
                let off_manifest_seq = self
                    .state
                    .manifest_seq
                    .max(prepared.manifest_seq)
                    .checked_add(1)
                    .filter(|&s| s <= protocol::MAX_SAFE_INTEGER)
                    .ok_or(ErrorKind::Protocol)?;
                let mut off_manifest = CapabilityManifest {
                    audience: orig_manifest.audience.clone(),
                    identity_key: Bytes::new(),
                    manifest_seq: off_manifest_seq,
                    generation: prepared.generation,
                    issued_at: timestamp,
                    expires_at,
                    pq_enabled: false,
                    strict_pq: false,
                    pq_ratchet_supported: false,
                    offered_suites: vec![],
                    signed_prekey: Bytes::copy_from_slice(&prepared.classical.signed_prekey),
                    pq_last_resort: vec![],
                    signature: Bytes::new(),
                };
                sign_manifest(&self.state.identity, &mut off_manifest)?;
                let off_digest = manifest_digest(&off_manifest)?;
                let off_req = PublishV2Request::sign(
                    &self.state.identity,
                    off_manifest,
                    Some(prepared.classical.signed_prekey_signature),
                    &prepared.classical.one_time_prekeys,
                    vec![],
                    vec![],
                    timestamp,
                )?;
                Ok((off_manifest_seq, off_digest, off_req))
            })();
            let (off_manifest_seq, off_digest, off_req) = match built {
                Ok(values) => values,
                Err(err) => {
                    self.rollback_publish_v2_on_refusal(prepared);
                    return Err(err);
                }
            };

            prepared.rollback.retract_unused_pq(&mut self.state.prekeys);
            prepared.rollback.clear_pq();
            self.state.rollback_manifest_digest(
                prepared.manifest_digest,
                &prepared.evicted_manifest_digest,
            );
            let evicted_manifest_digest = self.state.stage_manifest_digest(
                off_digest,
                Some(prepared.classical.signed_prekey),
                preserve_manifest_digests,
            );
            self.state.manifest_seq = off_manifest_seq;
            self.state.publishing = true;

            Ok(PreparedPublishV2 {
                request: off_req,
                manifest_seq: off_manifest_seq,
                generation: prepared.generation,
                prev_manifest_seq: prepared.prev_manifest_seq,
                prev_prekey_generation: prepared.prev_prekey_generation,
                manifest_digest: off_digest,
                evicted_manifest_digest,
                classical: prepared.classical,
                rollback: prepared.rollback,
                was_publishing: prepared.was_publishing,
                preserve_signed_prekeys: prepared.preserve_signed_prekeys,
                preserve_manifest_digests: preserve_manifest_digests.to_vec(),
            })
        }

        /// Retract newly added OPKs/PQOPKs/last-resort PQSPKs (or pop the unpublished generation
        /// and restore any evicted generation) and restore manifest sequence from a prepared v2
        /// publish that was definitively refused before storage (e.g. `ErrorKind::SignInRequired`,
        /// `ErrorKind::PqRequired`, or `ErrorKind::LimitExceeded`).
        pub fn rollback_publish_v2_on_refusal(&mut self, prepared: PreparedPublishV2) {
            match prepared.rollback {
                PrekeyRollback::Extended {
                    signed_prekey,
                    one_time_prekeys,
                    pq_one_time_prekeys,
                    new_pq_last_resort_suites,
                } => {
                    self.state.prekeys.retract_pq(
                        &signed_prekey,
                        &one_time_prekeys,
                        &pq_one_time_prekeys,
                        &new_pq_last_resort_suites,
                    );
                    if self.state.manifest_seq == prepared.manifest_seq {
                        self.state.prekey_generation = prepared.prev_prekey_generation;
                        self.state.publishing = prepared.was_publishing;
                        self.state.manifest_seq = prepared.prev_manifest_seq;
                        self.state.rollback_manifest_digest(
                            prepared.manifest_digest,
                            &prepared.evicted_manifest_digest,
                        );
                    }
                }
                PrekeyRollback::Rotated {
                    signed_prekey,
                    evicted,
                    ..
                } => {
                    if self.state.manifest_seq == prepared.manifest_seq
                        && self
                            .state
                            .prekeys
                            .rollback_generation(&signed_prekey, evicted)
                    {
                        self.state.prekey_generation = prepared.prev_prekey_generation;
                        self.state.publishing = prepared.was_publishing;
                        self.state.manifest_seq = prepared.prev_manifest_seq;
                        self.state.rollback_manifest_digest(
                            prepared.manifest_digest,
                            &prepared.evicted_manifest_digest,
                        );
                    }
                }
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
            let offered = self.state.pq_config.offered_suites();
            let per_suite: Vec<(PqSuite, usize)> = if pq_one_time_count > 0 {
                offered
                    .iter()
                    .copied()
                    .map(|s| (s, pq_one_time_count))
                    .collect()
            } else {
                vec![]
            };
            self.prepare_refill_v2_per_suite(audience, one_time_count, &per_suite)
        }

        /// Prepare a non-rotating prekey refill request with explicit per-suite PQ one-time counts
        /// so skewed demand (e.g. every peer preferring ML-KEM-1024) replenishes depleted suites
        /// without over-filling unused suites.
        ///
        /// Persist `self.state()` BEFORE calling [`Client::transmit_refill_v2`].
        pub fn prepare_refill_v2_per_suite(
            &mut self,
            audience: &str,
            one_time_count: usize,
            pq_counts: &[(PqSuite, usize)],
        ) -> Result<PreparedRefillV2> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            let Some(signed_prekey) = self.state.prekeys.current_signed_prekey() else {
                return Err(ErrorKind::Protocol.into());
            };
            if self.state.prekey_generation == 0 {
                return Err(ErrorKind::Protocol.into());
            }
            self.state.pq_config.validate()?;
            let offered = self.state.pq_config.offered_suites();
            let pq_enabled = self.state.pq_config.pq_enabled && !offered.is_empty();
            let active_pq: Vec<(PqSuite, usize)> = if pq_enabled {
                pq_counts
                    .iter()
                    .copied()
                    .filter(|(suite, count)| *count > 0 && offered.contains(suite))
                    .collect()
            } else {
                vec![]
            };
            let prev_last_timestamp = self.state.last_timestamp;
            let timestamp = self.next_timestamp()?;

            let (classical_opks, pq_opk_wire, pq_opk_ids) = {
                #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
                let pq_branch = !active_pq.is_empty();
                #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
                let pq_branch = {
                    let _ = &active_pq;
                    false
                };
                if pq_branch {
                    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
                    {
                        let (first_suite, first_count) = active_pq[0];
                        let first = match self.state.prekeys.refill_pq_only(
                            &self.state.identity,
                            first_suite,
                            one_time_count,
                            first_count,
                        ) {
                            Ok(first) => first,
                            Err(err) => {
                                self.state.last_timestamp = prev_last_timestamp;
                                return Err(err.into());
                            }
                        };
                        let mut pq_wire: Vec<PqPrekey> = first
                            .pq_one_time_prekeys
                            .iter()
                            .map(PqPrekey::from)
                            .collect();
                        let mut pq_ids: Vec<PqPrekeyId> =
                            first.pq_one_time_prekeys.iter().map(|k| k.id).collect();
                        for &(extra_suite, extra_count) in &active_pq[1..] {
                            match self.state.prekeys.refill_pq_only(
                                &self.state.identity,
                                extra_suite,
                                0,
                                extra_count,
                            ) {
                                Ok(extra) => {
                                    pq_ids.extend(extra.pq_one_time_prekeys.iter().map(|k| k.id));
                                    pq_wire.extend(
                                        extra.pq_one_time_prekeys.iter().map(PqPrekey::from),
                                    );
                                }
                                Err(err) => {
                                    self.state.prekeys.retract_pq(
                                        &signed_prekey,
                                        &first.classical.one_time_prekeys,
                                        &pq_ids,
                                        &[],
                                    );
                                    self.state.last_timestamp = prev_last_timestamp;
                                    return Err(err.into());
                                }
                            }
                        }
                        (first.classical.one_time_prekeys, pq_wire, pq_ids)
                    }
                    #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
                    unreachable!("pq_branch is false when no ML-KEM suite is compiled in")
                } else {
                    let extended = self
                        .state
                        .prekeys
                        .extend(&self.state.identity, one_time_count);
                    (extended.one_time_prekeys, vec![], vec![])
                }
            };

            let request = match RefillPrekeysRequest::sign(
                &self.state.identity,
                audience,
                self.state.prekey_generation,
                &classical_opks,
                pq_opk_wire,
                timestamp,
            ) {
                Ok(request) => request,
                Err(err) => {
                    self.state.prekeys.retract_pq(
                        &signed_prekey,
                        &classical_opks,
                        &pq_opk_ids,
                        &[],
                    );
                    self.state.last_timestamp = prev_last_timestamp;
                    return Err(err.into());
                }
            };

            Ok(PreparedRefillV2 {
                request,
                prev_last_timestamp,
                signed_prekey,
                one_time_prekeys: classical_opks,
                pq_one_time_prekeys: pq_opk_ids,
            })
        }

        /// Mark a prepared v2 refill as confirmed by the server.
        pub fn commit_refill_v2(&mut self, _prepared: PreparedRefillV2) {}

        /// Retract newly added OPKs/PQOPKs from a prepared v2 refill after
        /// [`Error::is_server_refusal`] confirms the relay refused it.
        pub fn rollback_refill_v2_on_refusal(&mut self, prepared: PreparedRefillV2) {
            self.state.prekeys.retract_pq(
                &prepared.signed_prekey,
                &prepared.one_time_prekeys,
                &prepared.pq_one_time_prekeys,
                &[],
            );
            if self.state.last_timestamp == prepared.request.timestamp {
                self.state.last_timestamp = prepared.prev_last_timestamp;
            }
        }

        /// Synchronous Phase 2 of session initiation: validate a [`ClaimedPeerBundle`] from
        /// [`claim_peer_bundle_v2`] against live `self.pq_config()` and `peer_state`, run the
        /// local PQXDH or classical X3DH handshake, and return [`PreparedInitiateV2`] so the
        /// caller can persist `session.state()` BEFORE calling
        /// [`Client::send_prepared_initiate_v2`].
        pub fn finish_prepare_initiate_v2<M>(
            &self,
            claimed: ClaimedPeerBundle,
            peer_state: &PeerPqState,
            content: &[u8],
            mailbox: M,
        ) -> Result<PreparedInitiateV2<M>> {
            // Re-validate the manifest window against the current bounded clock pair immediately
            // before Phase 2 key agreement so a bundle claimed near expiry cannot be used after
            // expiring while awaiting locks.
            let (local_now, server_now) = self.clock.trusted_clock_pair()?;
            check_manifest_window_bounded(&claimed.manifest, local_now, server_now)
                .map_err(|e| Error::new(ErrorKind::PeerManifestExpired, e))?;
            let policy =
                evaluate_claimed_bundle_policy(&claimed, peer_state, &self.state.pq_config)?;
            match policy {
                #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
                ResolvedBundlePolicy::Pq {
                    updated_peer_state,
                    expected_suite,
                } => self.build_pq_initiate_v2(
                    &claimed.peer,
                    updated_peer_state,
                    &claimed.manifest,
                    claimed.manifest_digest,
                    &claimed.response,
                    expected_suite,
                    content,
                    mailbox,
                ),
                ResolvedBundlePolicy::Classical {
                    updated_peer_state,
                    bundle,
                } => self.build_classical_initiate_v2(
                    &claimed.peer,
                    updated_peer_state,
                    bundle,
                    content,
                    mailbox,
                ),
            }
        }

        /// Synchronous Phase 2 of rekeying (`start_again`): complete `claimed` against
        /// `session`'s live [`PeerPqState`] and merge the new session into `session` via
        /// [`Session::keep`], returning [`SendInitialV2Request`] to transmit AFTER persisting
        /// `session.state()`.
        pub fn finish_prepare_start_again_v2<M: Clone>(
            &self,
            claimed: ClaimedPeerBundle,
            session: &mut Session<M>,
            content: &[u8],
        ) -> Result<SendInitialV2Request> {
            if session.state.me != self.identity_key || session.state.peer != claimed.peer {
                return Err(ErrorKind::UnexpectedPeer.into());
            }
            let peer_state = session.state.peer_pq.clone();
            let mailbox = session.mailbox.clone();
            let prepared =
                self.finish_prepare_initiate_v2(claimed, &peer_state, content, mailbox)?;
            let older = mem::replace(session, prepared.session);
            session.keep(older)?;
            Ok(prepared.request)
        }

        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        #[allow(clippy::too_many_arguments)]
        fn build_pq_initiate_v2<M>(
            &self,
            peer: &PublicKey,
            mut peer_state: PeerPqState,
            manifest: &CapabilityManifest,
            digest: [u8; 32],
            response: &ClaimBundleResponse,
            expected_suite: PqSuite,
            content: &[u8],
            mailbox: M,
        ) -> Result<PreparedInitiateV2<M>> {
            if response.pq_last_resort.is_none() && response.pq_one_time_prekey.is_none() {
                return Err(ErrorKind::DowngradeDetected.into());
            }

            let pq_bundle = PqPrekeyBundle::try_from(response)
                .map_err(|e| Error::new(ErrorKind::DowngradeDetected, e))?;

            if pq_bundle.pq_suite != expected_suite {
                return Err(ErrorKind::DowngradeDetected.into());
            }

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
            let (send_write_token, inbound_token_hash) =
                WriteToken::pair(agreement.secret_key.as_slice(), &self.identity_key, peer);
            let mut session = Session::new(
                mailbox,
                Active {
                    party,
                    id: pq_initial.ephemeral_key,
                    known_by_peer: false,
                    initial_message: carried.to_vec(),
                    send_write_token,
                    inbound_token_hash,
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
                request: SendInitialV2Request {
                    recipient: Bytes::copy_from_slice(peer),
                    message: Some(wire_initial),
                },
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
        ) -> Result<PreparedInitiateV2<M>> {
            if self.state.pq_config.strict_pq {
                return Err(ErrorKind::PqRequired.into());
            }
            let (message, agreement) = bundle.initiate(&self.state.identity, peer)?;
            let ratchet = Ratchet::alice(
                &SharedKeys::from_secret(&agreement.secret_key),
                &bundle.signed_prekey,
            )?;
            let mut party = Party::new(ratchet, agreement.associated_data);
            let first_message = party.encrypt(content)?;
            let mut v2_initial = handshake_v2::InitialMessageV2::from(&message);
            v2_initial.first_message = Some(first_message);
            let carried = encode_carried_initial(&v2_initial)?;
            let request = SendInitialV2Request {
                recipient: Bytes::copy_from_slice(peer),
                message: Some(v2_initial),
            };
            let security = SessionSecurity::classical();
            let (send_write_token, inbound_token_hash) =
                WriteToken::pair(agreement.secret_key.as_slice(), &self.identity_key, peer);
            let mut session = Session::new(
                mailbox,
                Active {
                    party,
                    id: message.ephemeral_key,
                    known_by_peer: false,
                    initial_message: carried.to_vec(),
                    send_write_token,
                    inbound_token_hash,
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

        /// Accept an inbound v1 or v2 initial message from `peer`, applying local PQ and
        /// inbound classical quarantine policies.
        ///
        /// **Two-phase ack rule**: this method is purely local — permanent failures
        /// (`InvalidInitialMessage`, `InvalidKeys`, `UnexpectedPeer`, `PqRequired`,
        /// `DowngradeDetected`, `MalformedState`, etc.) should be acknowledged in a
        /// `list_initial_messages_v2` -> `accept_listed_v2` / `accept_initial_v2` -> persist ->
        /// `ack_initial_messages_v2` loop so unaccepted/malformed entries cannot permanently fill
        /// the inbox. For [`ErrorKind::UnsupportedSuite`], acknowledge only after durably storing
        /// the encrypted initial for replay by a capable build.
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
                    if !PqConfig::is_compiled_suite(pq_init.pq_suite) {
                        return Err(ErrorKind::UnsupportedSuite.into());
                    }
                    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
                    {
                        let (agreement, signed_prekey) = self.state.prekeys.accept_pq(
                            &self.state.identity,
                            peer,
                            pq_init,
                            digest.as_ref().map(|d| d.as_slice()),
                        )?;
                        let spk_bytes = Zeroizing::new(signed_prekey.to_bytes());
                        let ratchet = Ratchet::bob(
                            &SharedKeys::from_secret(&agreement.secret_key),
                            DhPrivateKey::from(*spk_bytes),
                        );
                        let (party, content, pq_ratchet) = {
                            let mut classical_party =
                                Party::new(ratchet.clone(), agreement.associated_data);
                            match classical_party.decrypt(first_message) {
                                Ok(content) => (classical_party, content, false),
                                Err(e) if e.kind() == party::error::ErrorKind::InvalidHeader => {
                                    let party_suite =
                                        party::PqSuite::from_id(agreement.suite.as_u8())
                                            .ok_or(ErrorKind::UnsupportedSuite)?;
                                    let mut pq_party = Party::new_pq(
                                        ratchet,
                                        agreement.associated_data,
                                        party_suite,
                                    );
                                    let content =
                                        pq_party.decrypt(first_message).map_err(|err| {
                                            Error::new(ErrorKind::InvalidInitialMessage, err)
                                        })?;
                                    (pq_party, content, true)
                                }
                                Err(e) => {
                                    return Err(Error::new(ErrorKind::InvalidInitialMessage, e));
                                }
                            }
                        };
                        match digest {
                            Some(d) if !self.state.recent_manifest_digests.contains(d) => {
                                return Err(ErrorKind::DowngradeDetected.into());
                            }
                            None if strict_pq => {
                                return Err(ErrorKind::DowngradeDetected.into());
                            }
                            _ => {}
                        }
                        let incoming_seq =
                            checked_initial_hello(&content)?.map_or(0, |h| h.session_seq);
                        if peer_state.peer_session_seq > 0
                            && (incoming_seq == 0 || incoming_seq <= peer_state.peer_session_seq)
                        {
                            return Err(ErrorKind::StaleSession.into());
                        }
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
                        let (send_write_token, inbound_token_hash) = WriteToken::pair(
                            agreement.secret_key.as_slice(),
                            &self.identity_key,
                            peer,
                        );
                        let active = Active {
                            party,
                            id: pq_init.ephemeral_key,
                            known_by_peer: true,
                            initial_message: vec![],
                            send_write_token,
                            inbound_token_hash,
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
                    #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
                    {
                        let _ = (first_message, digest, mailbox);
                        Err(ErrorKind::UnsupportedSuite.into())
                    }
                }
                InitialMessageKind::Classical {
                    x3dh,
                    first_message,
                } => {
                    let (agreement, signed_prekey) =
                        self.state
                            .prekeys
                            .accept(&self.state.identity, peer, x3dh)?;
                    let spk_bytes = Zeroizing::new(signed_prekey.to_bytes());
                    let ratchet = Ratchet::bob(
                        &SharedKeys::from_secret(&agreement.secret_key),
                        DhPrivateKey::from(*spk_bytes),
                    );
                    let mut party = Party::new(ratchet, agreement.associated_data);
                    let content = party
                        .decrypt(first_message)
                        .map_err(|e| Error::new(ErrorKind::InvalidInitialMessage, e))?;
                    if strict_pq {
                        return Err(ErrorKind::PqRequired.into());
                    }
                    let hello = checked_initial_hello(&content)?;
                    let incoming_seq = hello.as_ref().map_or(0, |h| h.session_seq);
                    if peer_state.peer_session_seq > 0
                        && (incoming_seq == 0 || incoming_seq <= peer_state.peer_session_seq)
                    {
                        return Err(ErrorKind::StaleSession.into());
                    }
                    self.state.prekeys.confirm(x3dh)?;

                    let security = SessionSecurity::classical();
                    let hello_claims_pq = hello.as_ref().is_some_and(|h| h.pq_capable);
                    let active_pq_pin = peer_state.pq_pinned
                        && (peer_state.peer_pq_capable || peer_state.pinned_manifest_seq == 0);
                    let quarantined = local_pq_enabled
                        && (active_pq_pin
                            || peer_state.downgrade_detected
                            || hello_claims_pq
                            || !peer_state.allow_classical_exception);

                    let mut updated_peer_pq = peer_state.clone();
                    if quarantined {
                        if hello_claims_pq {
                            updated_peer_pq.pq_pinned = true;
                            updated_peer_pq.peer_pq_capable = true;
                            updated_peer_pq.clear_classical_exception();
                        }
                        updated_peer_pq.downgrade_detected =
                            hello_claims_pq || peer_state.downgrade_detected || active_pq_pin;
                    } else if let Some(ref h) = hello {
                        let _ =
                            check_peer_hello(&mut updated_peer_pq, security, h, local_pq_enabled);
                    }

                    let (send_write_token, inbound_token_hash) =
                        WriteToken::pair(agreement.secret_key.as_slice(), &self.identity_key, peer);
                    let active = Active {
                        party,
                        id: x3dh.ephemeral_key,
                        known_by_peer: true,
                        initial_message: vec![],
                        send_write_token,
                        inbound_token_hash,
                        security,
                        peer_session_seq: incoming_seq,
                    };
                    let mut session = Session::new(mailbox, active, self.identity_key, *peer);
                    session.state.peer_pq = updated_peer_pq;

                    if quarantined {
                        Ok(AcceptedInitial::Quarantined {
                            session,
                            first_message: content,
                            peer_was_pq_pinned: active_pq_pin || hello_claims_pq,
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

        /// Synchronously process one page returned by [`Client::list_initial_messages_v2`].
        ///
        /// - Updates per-peer [`PeerPqState`] across messages within the same batch so a later
        ///   classical initial cannot ride on a stale pre-batch exception after an earlier PQ
        ///   initial pins the peer.
        /// - Idempotent on post-persist/pre-ack crash replay: any message whose ephemeral key is
        ///   already recorded in local prekey `confirmed` state (`Error::is_replayed()`) is placed
        ///   in [`AcceptedInboxBatch::replayed_ids`] and re-queued in [`AcceptedInboxBatch::ack_ids`].
        /// - Leaves [`ErrorKind::UnsupportedSuite`] entries out of `ack_ids` (surfacing them in
        ///   [`AcceptedInboxBatch::unsupported`]) while queueing malformed and permanently
        ///   rejected IDs in `ack_ids`.
        ///
        /// Persist [`Client::state`] and `outcomes` durably BEFORE calling
        /// [`Client::ack_initial_messages_v2`] with `batch.ack_ids`.
        pub fn accept_listed_v2<M: Clone>(
            &mut self,
            listed: &ListedInitialMessages,
            mailbox: M,
            mut peer_state_for: impl FnMut(&PublicKey) -> PeerPqState,
        ) -> AcceptedInboxBatch<M> {
            let can_ack = |id: u64| id != 0 && id <= protocol::MAX_SAFE_INTEGER;
            let mut ack_ids: Vec<u64> = listed
                .malformed_ids
                .iter()
                .copied()
                .filter(|&id| can_ack(id))
                .collect();
            let mut outcomes = Vec::with_capacity(listed.messages.len());
            let mut replayed_ids = Vec::new();
            let mut unsupported = Vec::new();
            let mut rejected = Vec::new();
            let mut peer_states = std::collections::HashMap::<PublicKey, PeerPqState>::new();

            for msg in &listed.messages {
                if !can_ack(msg.id) {
                    continue;
                }
                let peer_state = peer_states
                    .entry(msg.sender)
                    .or_insert_with(|| peer_state_for(&msg.sender))
                    .clone();
                match self.accept_initial_v2(&msg.sender, &peer_state, msg, mailbox.clone()) {
                    Ok(outcome) => {
                        // R20-P1-2: Propagate updated `PeerPqState` on BOTH `Accepted` and
                        // `Quarantined` so a later classical initial in the same batch cannot
                        // ride on a stale pre-batch `allow_classical_exception` after an earlier
                        // `Hello { pq_capable: true }` quarantine pinned the peer.
                        match outcome {
                            AcceptedInitial::Accepted { ref session, .. }
                            | AcceptedInitial::Quarantined { ref session, .. } => {
                                peer_states.insert(msg.sender, session.state.peer_pq.clone());
                            }
                        }
                        ack_ids.push(msg.id);
                        outcomes.push((msg.sender, outcome));
                    }
                    Err(e) if e.kind() == ErrorKind::UnsupportedSuite => {
                        unsupported.push(msg.clone());
                    }
                    Err(e) if e.is_replayed() => {
                        replayed_ids.push(msg.id);
                        ack_ids.push(msg.id);
                    }
                    Err(e) => {
                        ack_ids.push(msg.id);
                        rejected.push((msg.id, msg.sender, e));
                    }
                }
            }

            AcceptedInboxBatch {
                outcomes,
                ack_ids,
                replayed_ids,
                unsupported,
                rejected,
                next_after_id: listed.next_after_id,
                has_more: listed.has_more,
            }
        }

        /// Synchronously sign a unified [`FetchSignedRequest`] using `self.mailbox_cursor()` and
        /// piggybacking `self.pending_mailbox_ack()`.
        pub fn sign_fetch_mailbox_v2(
            &self,
            audience: &str,
            limit: u32,
        ) -> Result<FetchSignedRequest> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            let req_limit = if limit == 0 { MAX_RECEIVE_PAGE } else { limit };
            let timestamp = self.current_timestamp()?;
            Ok(FetchSignedRequest::sign(
                &self.state.identity,
                audience,
                self.state.mailbox_cursor,
                req_limit,
                0,
                self.state.pending_mailbox_ack,
                timestamp,
            )?)
        }

        /// Validate a [`FetchSignedResponse`] against `req_limit`, `self.mailbox_cursor()`, and
        /// the `piggybacked_ack` carried by the corresponding request.
        pub fn validate_mailbox_page(
            &self,
            req_limit: u32,
            piggybacked_ack: u64,
            response: FetchSignedResponse,
        ) -> Result<MailboxPage> {
            let max_items = if req_limit == 0 {
                MAX_RECEIVE_PAGE as usize
            } else {
                req_limit as usize
            };
            if response.messages.len() > max_items {
                return Err(ErrorKind::Protocol.into());
            }
            let mut prev = self.state.mailbox_cursor;
            for env in &response.messages {
                if env.sequence <= prev
                    || env.sequence > protocol::MAX_SAFE_INTEGER
                    || env.token_hash.len() != WRITE_TOKEN_HASH_LENGTH
                    || env.message.is_none()
                {
                    return Err(ErrorKind::Protocol.into());
                }
                prev = env.sequence;
            }
            Ok(MailboxPage {
                messages: response.messages,
                has_more: response.has_more,
                piggybacked_ack,
            })
        }

        /// Fetch the next page from this recipient's unified v2 mailbox, using
        /// `self.mailbox_cursor()` and piggybacking `self.pending_mailbox_ack()`.
        ///
        /// Purely read-only on `self` (cancel-safe): after durably processing/buffering the page,
        /// advance local state via [`Client::commit_mailbox_page`] and acknowledge on the relay
        /// via piggybacked next fetch or [`Client::ack_mailbox_v2`].
        pub async fn fetch_mailbox_v2(
            &self,
            mailbox: &impl LocalMailboxV2,
            audience: &str,
            limit: u32,
        ) -> Result<MailboxPage> {
            let request = self.sign_fetch_mailbox_v2(audience, limit)?;
            let req_limit = request.limit;
            let piggybacked_ack = request.ack_up_to_sequence;
            let response = mailbox.fetch_signed(request).await?;
            self.validate_mailbox_page(req_limit, piggybacked_ack, response)
        }

        /// Synchronously sign an explicit [`AckMessagesRequest`] deleting all unified mailbox
        /// messages with `sequence <= up_to_sequence`.
        pub fn sign_ack_mailbox_v2(
            &self,
            audience: &str,
            up_to_sequence: u64,
        ) -> Result<AckMessagesRequest> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            if up_to_sequence == 0 || up_to_sequence > protocol::MAX_SAFE_INTEGER {
                return Err(ErrorKind::InvalidArgument.into());
            }
            let timestamp = self.current_timestamp()?;
            Ok(AckMessagesRequest::sign(
                &self.state.identity,
                audience,
                up_to_sequence,
                timestamp,
            )?)
        }

        /// Explicitly acknowledge and delete unified mailbox messages up to
        /// `self.pending_mailbox_ack()` via `MailboxV2::ack_messages`.
        ///
        /// No-ops returning `Ok(0)` when `pending_mailbox_ack == 0`. Clears
        /// `pending_mailbox_ack` on success; preserves it on error for retry or piggybacking.
        pub async fn ack_mailbox_v2(
            &mut self,
            mailbox: &impl LocalMailboxV2,
            audience: &str,
        ) -> Result<u64> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            let up_to = self.state.pending_mailbox_ack;
            if up_to == 0 {
                return Ok(0);
            }
            let request = self.sign_ack_mailbox_v2(audience, up_to)?;
            let response = mailbox.ack_messages(request).await?;
            self.clear_pending_mailbox_ack(up_to);
            Ok(response.deleted)
        }

        /// Synchronously sign a [`RegisterWriteTokenRequest`] authorizing `token_hash` under
        /// `self.peer_slot_id(peer)`.
        pub fn sign_register_write_token_v2(
            &self,
            audience: &str,
            peer: &PublicKey,
            token_hash: &[u8; WRITE_TOKEN_HASH_LENGTH],
            grant_version: u64,
            pin_active: bool,
        ) -> Result<RegisterWriteTokenRequest> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            check_canonical_identity(peer)?;
            if grant_version == 0 || grant_version > protocol::MAX_SAFE_INTEGER {
                return Err(ErrorKind::InvalidArgument.into());
            }
            let peer_slot_id = self.peer_slot_id(peer);
            let timestamp = self.current_timestamp()?;
            Ok(RegisterWriteTokenRequest::sign(
                &self.state.identity,
                audience,
                &peer_slot_id,
                token_hash,
                grant_version,
                pin_active,
                timestamp,
            )?)
        }

        /// Register `token_hash` for `peer` (addressed to the relay strictly via opaque
        /// [`Client::peer_slot_id`]) at monotonic `grant_version`, optionally pinning it as the
        /// peer's never-evicted active grant.
        pub async fn register_write_token_v2(
            &self,
            mailbox: &impl LocalMailboxV2,
            audience: &str,
            peer: &PublicKey,
            token_hash: &[u8; WRITE_TOKEN_HASH_LENGTH],
            grant_version: u64,
            pin_active: bool,
        ) -> Result<()> {
            let request = self.sign_register_write_token_v2(
                audience,
                peer,
                token_hash,
                grant_version,
                pin_active,
            )?;
            mailbox.register_write_token(request).await?;
            Ok(())
        }

        /// Synchronously sign a [`RevokeWriteTokenRequest`] revoking one or all write tokens for
        /// `peer_slot_id` and advancing the minimum grant version floor to `min_grant_version`.
        pub fn sign_revoke_write_token_v2(
            &self,
            audience: &str,
            peer_slot_id: &[u8; PEER_SLOT_ID_LENGTH],
            token_hash: Option<&[u8; WRITE_TOKEN_HASH_LENGTH]>,
            min_grant_version: u64,
        ) -> Result<RevokeWriteTokenRequest> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            if min_grant_version == 0 || min_grant_version > protocol::MAX_SAFE_INTEGER {
                return Err(ErrorKind::InvalidArgument.into());
            }
            let timestamp = self.current_timestamp()?;
            Ok(RevokeWriteTokenRequest::sign(
                &self.state.identity,
                audience,
                peer_slot_id,
                token_hash,
                min_grant_version,
                timestamp,
            )?)
        }

        /// Revoke one (`Some(token_hash)`) or all (`None`) write tokens for `peer_slot_id` and
        /// advance `revoked_below_version` to at least `min_grant_version`, returning the number
        /// of revoked grants.
        pub async fn revoke_write_token_v2(
            &self,
            mailbox: &impl LocalMailboxV2,
            audience: &str,
            peer_slot_id: &[u8; PEER_SLOT_ID_LENGTH],
            token_hash: Option<&[u8; WRITE_TOKEN_HASH_LENGTH]>,
            min_grant_version: u64,
        ) -> Result<u32> {
            let request = self.sign_revoke_write_token_v2(
                audience,
                peer_slot_id,
                token_hash,
                min_grant_version,
            )?;
            Ok(mailbox.revoke_write_token(request).await?.revoked)
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
            check_server_info_with(&self.handshake, expected_audience).await
        }

        /// Alias for [`Client::check_server_info`].
        pub async fn fetch_server_info(
            &self,
            expected_audience: &str,
        ) -> Result<GetServerInfoResponse> {
            self.check_server_info(expected_audience).await
        }

        /// Non-consuming read and verification of `peer`'s signed [`CapabilityManifest`] against
        /// the locally configured `audience` and bounded local/server clock pair.
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
                let verified_id = verify_manifest(manifest, audience)
                    .map_err(|e| Error::new(ErrorKind::DowngradeDetected, e))?;
                if verified_id != *peer {
                    return Err(ErrorKind::DowngradeDetected.into());
                }
                let (local_now, server_now) = self.clock.trusted_clock_pair()?;
                check_manifest_window_bounded(manifest, local_now, server_now)
                    .map_err(|e| Error::new(ErrorKind::PeerManifestExpired, e))?;
            }
            Ok(response.manifest)
        }

        /// Non-consuming read and verification of `peer`'s signed [`CapabilityManifest`] against
        /// `audience`, `peer_state` (enforcing monotonic sequence and anti-equivocation digest
        /// pinning before clock/window checks), and the bounded local/server clock pair.
        ///
        /// Updates `peer_state` only after all cryptographic, anti-equivocation, and validity
        /// checks succeed.
        pub async fn get_peer_manifest_for(
            &self,
            audience: &str,
            peer: &PublicKey,
            peer_state: &mut PeerPqState,
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
                let verified_id = verify_manifest(manifest, audience)
                    .map_err(|e| Error::new(ErrorKind::DowngradeDetected, e))?;
                if verified_id != *peer {
                    return Err(ErrorKind::DowngradeDetected.into());
                }
                let digest = manifest_digest(manifest)
                    .map_err(|e| Error::new(ErrorKind::DowngradeDetected, e))?;
                let mut candidate = peer_state.clone();
                // R19-P2-1 + R20-P1-1: Commit the verified capability transition atomically with
                // the manifest sequence and digest (rejecting pre-manifest PQ pins and rolled-back
                // PQ-OFF manifests via `commit_signed_pq_off_manifest`).
                if !manifest.pq_enabled {
                    candidate.commit_signed_pq_off_manifest(manifest.manifest_seq, digest)?;
                } else {
                    candidate.check_and_pin_manifest(manifest.manifest_seq, digest)?;
                    candidate.pq_pinned = true;
                    candidate.peer_pq_capable = true;
                    candidate.clear_classical_exception();
                }
                let (local_now, server_now) = self.clock.trusted_clock_pair()?;
                check_manifest_window_bounded(manifest, local_now, server_now)
                    .map_err(|e| Error::new(ErrorKind::PeerManifestExpired, e))?;
                *peer_state = candidate;
            }
            Ok(response.manifest)
        }

        /// Alias for [`Client::get_peer_manifest`].
        pub async fn fetch_peer_manifest(
            &self,
            audience: &str,
            peer: &PublicKey,
        ) -> Result<Option<CapabilityManifest>> {
            self.get_peer_manifest(audience, peer).await
        }

        /// Transmit a previously prepared v2 publish request (after persisting `self.state()`).
        ///
        /// Performs zero local state mutation. If `prepared` carried a PQ-enabled manifest and a
        /// v2 server rolled back to runtime `PQ_ENABLED="false"` refuses PQ-ON with confirmed
        /// `Unimplemented`:
        /// - returns `Err(ErrorKind::PqRequired)` when `strict_pq` is `true`, or
        /// - returns `Ok(PublishV2Outcome::ServerPqDisabled)` when `strict_pq` is `false` without
        ///   transmitting an OFF manifest. Callers should then run
        ///   [`Client::prepare_publish_v2_classical_off`], persist [`Client::state`], and transmit
        ///   the resulting classical-OFF [`PreparedPublishV2`].
        pub async fn transmit_publish_v2(
            &self,
            prepared: &PreparedPublishV2,
        ) -> Result<PublishV2Outcome> {
            transmit_publish_v2_with(&self.handshake, prepared, self.state.pq_config.strict_pq)
                .await
        }

        /// Generate and publish prekeys + signed [`CapabilityManifest`] via `HandshakeV2`.
        ///
        /// If the server is a v2 relay with runtime `PQ_ENABLED="false"` and `strict_pq` is
        /// `false`, transitions via [`Client::prepare_publish_v2_classical_off`] to publish a
        /// signed `PQ-OFF` manifest on `PublishV2`.
        pub async fn publish_v2(
            &mut self,
            audience: &str,
            one_time_count: usize,
            pq_one_time_count: usize,
        ) -> Result<()> {
            let mut prepared =
                self.prepare_publish_v2(audience, one_time_count, pq_one_time_count)?;
            let outcome = match self.transmit_publish_v2(&prepared).await {
                Ok(PublishV2Outcome::ServerPqDisabled) => {
                    prepared = self.prepare_publish_v2_classical_off(prepared, &[])?;
                    self.transmit_publish_v2(&prepared).await
                }
                other => other,
            };
            match outcome {
                Ok(PublishV2Outcome::V2Pq | PublishV2Outcome::V2ClassicalOff) => {
                    self.commit_publish_v2(prepared);
                    Ok(())
                }
                Ok(PublishV2Outcome::ServerPqDisabled) => {
                    self.rollback_publish_v2_on_refusal(prepared);
                    Err(ErrorKind::Protocol.into())
                }
                Err(e)
                    if e.is_server_refusal()
                        && matches!(
                            e.kind(),
                            ErrorKind::SignInRequired
                                | ErrorKind::PqRequired
                                | ErrorKind::LimitExceeded
                                | ErrorKind::Protocol
                                | ErrorKind::Unimplemented
                        ) =>
                {
                    self.rollback_publish_v2_on_refusal(prepared);
                    Err(e)
                }
                Err(e) => Err(e),
            }
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
                Ok(response) => {
                    self.commit_refill_v2(prepared);
                    Ok(response)
                }
                Err(e) if e.is_server_refusal() => {
                    self.rollback_refill_v2_on_refusal(prepared);
                    Err(e)
                }
                Err(e) => Err(e),
            }
        }

        /// Sign one or more [`AckInitialMessagesRequest`] batches (chunked to `MAX_ACK_BATCH`)
        /// without holding the client across network RPCs.
        pub fn sign_ack_initial_messages_v2(
            &mut self,
            audience: &str,
            ids: &[u64],
        ) -> Result<Vec<AckInitialMessagesRequest>> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            let ids: Vec<u64> = ids.iter().copied().filter(|&id| id != 0).collect();
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let mut requests = Vec::with_capacity(ids.len().div_ceil(MAX_ACK_BATCH));
            for chunk in ids.chunks(MAX_ACK_BATCH) {
                let timestamp = self.current_timestamp()?;
                requests.push(AckInitialMessagesRequest::sign(
                    &self.state.identity,
                    audience,
                    chunk.to_vec(),
                    timestamp,
                )?);
            }
            Ok(requests)
        }

        /// Explicitly acknowledge and delete pending inbox initial messages by their stable
        /// server-assigned IDs (call ONLY after persisting accepted sessions locally).
        pub async fn ack_initial_messages_v2(
            &mut self,
            audience: &str,
            ids: Vec<u64>,
        ) -> Result<u32> {
            let requests = self.sign_ack_initial_messages_v2(audience, &ids)?;
            let mut total = 0u32;
            for request in requests {
                total = total
                    .saturating_add(self.handshake.ack_initial_messages(request).await?.deleted);
            }
            Ok(total)
        }

        /// Claim `peer`'s bundle via [`claim_peer_bundle_v2`] and build a [`PreparedInitiateV2`]
        /// via [`Client::finish_prepare_initiate_v2`] WITHOUT sending the initial message yet so
        /// callers can persist `session.state()` first.
        ///
        /// Callers that must release a mutex across the `ClaimBundle` network RTT should invoke
        /// [`claim_peer_bundle_v2`] and [`Client::finish_prepare_initiate_v2`] directly.
        pub async fn prepare_initiate_v2<M>(
            &mut self,
            audience: &str,
            peer: &PublicKey,
            peer_state: &PeerPqState,
            content: &[u8],
            mailbox: M,
        ) -> Result<PreparedInitiateV2<M>> {
            let claimed = claim_peer_bundle_v2(
                &self.handshake,
                audience,
                peer,
                peer_state,
                &self.state.pq_config,
                &self.clock,
            )
            .await?;
            self.finish_prepare_initiate_v2(claimed, peer_state, content, mailbox)
        }

        /// Transmit a [`SendInitialV2Request`] prepared by [`Client::prepare_initiate_v2`],
        /// [`Client::finish_prepare_initiate_v2`], [`Client::prepare_start_again_v2`], or
        /// [`Client::finish_prepare_start_again_v2`] (after persisting `session.state()`).
        pub async fn send_prepared_initiate_v2(
            &self,
            request: &SendInitialV2Request,
        ) -> Result<()> {
            self.handshake.send_initial_v2(request.clone()).await?;
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
        /// via [`Session::keep`], returning the [`SendInitialV2Request`] so the caller can
        /// persist `session.state()` BEFORE transmitting.
        ///
        /// Callers that must release a mutex across `ClaimBundle` should invoke
        /// [`claim_peer_bundle_v2`] and [`Client::finish_prepare_start_again_v2`] directly.
        pub async fn prepare_start_again_v2<M: Clone>(
            &mut self,
            audience: &str,
            session: &mut Session<M>,
            content: &[u8],
        ) -> Result<SendInitialV2Request> {
            if session.state.me != self.identity_key {
                return Err(ErrorKind::UnexpectedPeer.into());
            }
            let peer = session.state.peer;
            let peer_state = session.state.peer_pq.clone();
            let claimed = claim_peer_bundle_v2(
                &self.handshake,
                audience,
                &peer,
                &peer_state,
                &self.state.pq_config,
                &self.clock,
            )
            .await?;
            self.finish_prepare_start_again_v2(claimed, session, content)
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

        /// Sign a [`ListInitialMessagesRequest`] so callers can dispatch the RPC outside a lock
        /// and decode the response via [`parse_listed_initial_messages`].
        pub fn sign_list_initial_messages_v2(
            &mut self,
            audience: &str,
            after_id: u64,
            limit: u32,
        ) -> Result<ListInitialMessagesRequest> {
            if audience.trim().is_empty() {
                return Err(ErrorKind::Protocol.into());
            }
            let timestamp = self.current_timestamp()?;
            Ok(ListInitialMessagesRequest::sign(
                &self.state.identity,
                audience,
                after_id,
                limit,
                timestamp,
            )?)
        }

        /// Phase 1 of cursor-paginated two-phase inbox receive: non-destructively list pending
        /// v1 and v2 initial messages strictly after `after_id` using
        /// `HandshakeV2::list_initial_messages`.
        ///
        /// Pass `after_id = 0` for the first page, then pass [`ListedInitialMessages::next_after_id`]
        /// on subsequent pages while [`ListedInitialMessages::has_more`] is `true`.
        pub async fn list_initial_messages_v2(
            &mut self,
            audience: &str,
            after_id: u64,
            limit: u32,
        ) -> Result<ListedInitialMessages> {
            let request = self.sign_list_initial_messages_v2(audience, after_id, limit)?;
            let response = self.handshake.list_initial_messages(request).await?;
            Ok(parse_listed_initial_messages(&response))
        }
    }

    /// Decode a wire [`ListInitialMessagesResponse`] into a [`ListedInitialMessages`] page.
    pub fn parse_listed_initial_messages(
        response: &ListInitialMessagesResponse,
    ) -> ListedInitialMessages {
        let mut messages = Vec::with_capacity(response.messages.len());
        let mut malformed_ids = vec![];
        let mut next_after_id: Option<u64> = None;
        for wire in &response.messages {
            if wire.id == 0 || wire.id > protocol::MAX_SAFE_INTEGER {
                continue;
            }
            next_after_id = Some(next_after_id.map_or(wire.id, |prev| prev.max(wire.id)));
            match InitialMessageV2::try_from(wire) {
                Ok(msg) => messages.push(msg),
                Err(_) => malformed_ids.push(wire.id),
            }
        }
        ListedInitialMessages {
            messages,
            malformed_ids,
            next_after_id,
            has_more: response.has_more,
        }
    }

    /// Build a classical `x3dh::PrekeyBundle` from a `ClaimBundleResponse`, preserving
    /// `signed_prekey_signature` verification for intentional classical X3DH inside v2.
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
        /// Build a sealed-sender-lite [`PushV2Request`] strictly from `sealed` and
        /// `self.peer()` (no `sender`, no `delivery_hash`), carrying the sealing session's
        /// `write_token`, optional `initial_message`, and deterministic `client_message_id`.
        pub fn push_v2_request(&self, sealed: &Sealed) -> PushV2Request {
            sealed.push_v2_request(&self.state.peer)
        }

        /// Build a sealed-sender-lite [`PushV2Request`] strictly from `sealed` and
        /// `self.peer()` with an explicit optional 16-byte `client_message_id`.
        pub fn push_v2_request_with_id(
            &self,
            sealed: &Sealed,
            client_message_id: Option<[u8; CLIENT_MESSAGE_ID_LENGTH]>,
        ) -> PushV2Request {
            sealed.push_v2_request_with_id(&self.state.peer, client_message_id)
        }
    }

    impl<M: LocalMailboxV2> Session<M> {
        /// Push `sealed` via `MailboxV2::push_v2` (with stable `client_message_id`, sealing
        /// session `write_token`, and sealing session carried initial message).
        pub async fn push_v2(&self, sealed: &Sealed) -> Result<u64> {
            let request = self.push_v2_request(sealed);
            Ok(self.mailbox.push_v2(request).await?.sequence)
        }

        /// Encrypt `content` and push via [`Session::push_v2`].
        pub async fn send_v2(&mut self, content: &[u8]) -> Result<u64> {
            let sealed = self.encrypt(content)?;
            self.push_v2(&sealed).await
        }
    }
}

pub use v2::*;
