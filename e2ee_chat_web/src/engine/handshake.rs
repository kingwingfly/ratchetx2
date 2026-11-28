//! Initial messages, peer handshakes and prekey publication.

use super::contact::{Contact, DisplayedEntry, FarewellMode, forget_told};
use super::{
    Engine, Inner, InnerGuard, NOT_SIGNED_IN_HERE, ONE_TIME_PREKEYS, PQ_ONE_TIME_PREKEYS,
    ProtocolRpcScope, REFILL_USED, REPUBLISH_AGE, SERVER_MAX_ONE_TIME_PREKEYS,
    SERVER_MAX_PQ_ONE_TIME_PREKEYS, StartChatError, VaultStore, origin, records, same_server,
    should_require_update_for_rpc,
};
use crate::content::{Content, Deleted, Events, Kind, stamp};
use crate::state::{Delivery, MessageView, ServerPqStatus};
use crate::transport::{Connect, Fetch};
use crate::util::{describe, key_from_text, now, short};
use crate::vault::{
    CLASSICAL_APPROVAL_NONE, CarriedDeferredTimestamp, ContactState, DeferredInitial, Farewell,
    GREETING_DELIVERY_CONFIRMED, GREETING_DELIVERY_UNCERTAIN, GREETING_DELIVERY_UNSENT,
    HistoryEntry, IndexRange, OutgoingRecord, PendingRevoke, SECURITY_ALERT_DOWNGRADE,
    SECURITY_ALERT_NONE, SECURITY_ALERT_PQ_REQUIRED, SealedEvents,
};
use leptos::prelude::*;
use prost::Message as _;
use session::protocol::handshake_v2::{
    CapabilityManifest, GetManifestRequest, InitialMessageV2 as WireInitial, LocalHandshakeV2,
    verify_manifest,
};
use session::{
    AcceptedInitial, ErrorKind, InitialMessageKind, InitialMessageV2, ListedInitialMessages,
    PeerPqState, PqSuite, PublicKey, PublishV2Outcome, Session,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) type Incoming = InitialMessageV2;

// A page can include 64 initials from retrying a previous stall and another 64
// surfaced together at its expired or newly stalled tail.
const MAX_PENDING_CARRIED_INITIALS: usize = 2 * 64;
const MAX_DEFERRED_INITIALS: usize = 100;
/// Maximum age (30 days in ms) for which deferred initials preserve their target signed prekey
/// generation and manifest digest across scheduled prekey rotations.
pub(super) const DEFERRED_REPLAY_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Cooldown (1 hour in ms, matching the Worker's hourly OPK claim window) applied after an
/// empty-OPK fallback refill probe proves the relay still had stocked OPKs (`R12-P2-4`).
const OPK_FALLBACK_PROBE_COOLDOWN_MS: u64 = 60 * 60 * 1000;

/// Verified manifest summary extracted from a crossed `ClaimBundle` so
/// `finish_existing_contact_start_chat` can commit monotonic manifest pins and detect equivocation
/// before accepting or blocking the existing contact (`R22-P2-2`, `R22-P2-4`).
#[derive(Clone, Copy)]
pub(super) struct ClaimedManifestInfo {
    pub(super) seq: u64,
    pub(super) digest: [u8; 32],
    pub(super) pq_enabled: bool,
    pub(super) server_pq_disabled_fallback: bool,
}

impl ClaimedManifestInfo {
    fn from_claimed(claimed: &session::ClaimedPeerBundle) -> Self {
        Self {
            seq: claimed.manifest().manifest_seq,
            digest: claimed.manifest_digest(),
            pq_enabled: claimed.manifest().pq_enabled,
            server_pq_disabled_fallback: claimed.is_server_pq_disabled_fallback(),
        }
    }
}

/// Monotonically apply verified New Chat manifest observations (`pending_new_chat_off_pins`
/// and/or a crossed `ClaimBundle`'s verified manifest) onto an existing `contact` BEFORE
/// evaluating Phase-A / Phase-B PQ block policy (`R21-P2-3`, `R22-P2-2`, `R22-P2-4`).
///
/// Returns `(mutated, equivocated)`.
pub(super) fn apply_observed_start_chat_manifests(
    contact: &mut Contact,
    off_pin: Option<(u64, [u8; 32])>,
    claimed: Option<ClaimedManifestInfo>,
) -> (bool, bool) {
    let before_pq = contact.session.peer_pq_state().clone();
    let before_alert = contact.state.security_alert;
    let before_prompt = contact.state.classical_approval_needed;
    let before_q_pinned = contact.state.quarantined_was_pq_pinned;
    let mut equivocated = false;

    if let Some((seq, digest)) = off_pin {
        let cur_seq = contact.session.peer_pq_state().pinned_manifest_seq;
        if seq > cur_seq {
            let _ = contact
                .session
                .peer_pq_state_mut()
                .check_and_pin_manifest(seq, digest);
        } else if seq == cur_seq
            && contact
                .session
                .peer_pq_state()
                .pinned_manifest_digest
                .is_some_and(|d| d != digest)
        {
            contact.record_policy_error(ErrorKind::DowngradeDetected);
            equivocated = true;
        }
    }

    if let Some(info) = claimed {
        let cur_seq = contact.session.peer_pq_state().pinned_manifest_seq;
        if info.seq > cur_seq {
            if info.pq_enabled {
                if contact
                    .session
                    .peer_pq_state_mut()
                    .check_and_pin_manifest(info.seq, info.digest)
                    .is_ok()
                {
                    let ppq = contact.session.peer_pq_state_mut();
                    ppq.peer_pq_capable = true;
                    if !info.server_pq_disabled_fallback {
                        ppq.pq_pinned = true;
                        ppq.clear_classical_exception();
                        contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                        // R23-P2-5: A verified signed PQ-ON manifest directly contradicts a
                        // quarantined classical contact; escalate to a hard downgrade alarm.
                        if contact.state.quarantined {
                            contact.state.quarantined_was_pq_pinned = true;
                            contact.record_policy_error(ErrorKind::DowngradeDetected);
                        }
                    }
                }
            } else if !contact.state.quarantined
                && !contact.session.peer_pq_state().downgrade_detected
                && contact.state.security_alert != SECURITY_ALERT_DOWNGRADE
                && contact.is_classical_session()
            {
                if contact
                    .session
                    .peer_pq_state_mut()
                    .commit_signed_pq_off_manifest(info.seq, info.digest)
                    .is_err()
                {
                    contact.record_policy_error(ErrorKind::DowngradeDetected);
                    equivocated = true;
                }
            } else {
                let _ = contact
                    .session
                    .peer_pq_state_mut()
                    .check_and_pin_manifest(info.seq, info.digest);
            }
        } else if info.seq == cur_seq && cur_seq > 0 {
            if contact
                .session
                .peer_pq_state()
                .pinned_manifest_digest
                .is_some_and(|d| d != info.digest)
            {
                contact.record_policy_error(ErrorKind::DowngradeDetected);
                equivocated = true;
            } else if contact
                .session
                .peer_pq_state()
                .pinned_manifest_digest
                .is_none()
            {
                let _ = contact
                    .session
                    .peer_pq_state_mut()
                    .check_and_pin_manifest(info.seq, info.digest);
            }
            if !equivocated && info.pq_enabled {
                let ppq = contact.session.peer_pq_state_mut();
                ppq.peer_pq_capable = true;
                if !info.server_pq_disabled_fallback {
                    ppq.pq_pinned = true;
                    ppq.clear_classical_exception();
                    contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                    if contact.state.quarantined {
                        contact.state.quarantined_was_pq_pinned = true;
                        contact.record_policy_error(ErrorKind::DowngradeDetected);
                    }
                }
            }
        }
    }

    let mutated = *contact.session.peer_pq_state() != before_pq
        || contact.state.security_alert != before_alert
        || contact.state.classical_approval_needed != before_prompt
        || contact.state.quarantined_was_pq_pinned != before_q_pinned;
    (mutated, equivocated)
}

/// Result of [`Engine::join_carried`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct JoinCarriedOutcome {
    /// If an accepted session's `Hello` triggered an automatic PQ upgrade recommendation, records
    /// the contact's exact `conversation_gen` so queued upgrades never adopt a recreated chat.
    pub(super) recommend_upgrade: Option<u64>,
    /// Whether at least one carried initial for this contact remains deferred on this build.
    pub(super) has_deferred: bool,
    /// Peers whose newly joined sessions staged write-token grants to flush outside `self.inner`.
    pub(super) grant_peers: BTreeSet<PublicKey>,
}

fn initial_payload(kind: &InitialMessageKind) -> WireInitial {
    match kind {
        InitialMessageKind::Classical {
            x3dh,
            first_message,
        } => WireInitial {
            first_message: Some(first_message.clone()),
            ..WireInitial::from(x3dh)
        },
        InitialMessageKind::Pq {
            x3dh,
            first_message,
            manifest_digest,
        } => WireInitial {
            first_message: Some(first_message.clone()),
            manifest_digest: manifest_digest
                .as_ref()
                .map_or_else(bytes::Bytes::new, |digest| {
                    bytes::Bytes::copy_from_slice(digest)
                }),
            ..WireInitial::from(x3dh)
        },
    }
}

fn is_unsupported_carried_bytes(bytes: &[u8]) -> bool {
    Incoming::decode_carried(bytes)
        .and_then(|message| message.pq_suite())
        .is_some_and(|suite| !suite.is_supported())
}

/// Stage a single carried initial into `state.pending_carried_initials`, returning `Ok(true)` if
/// stored (or already present) and `Ok(false)` if either the supported or unsupported queue has
/// reached `MAX_PENDING_CARRIED_INITIALS`.
pub(super) fn stage_carried_initial_one(
    state: &mut ContactState,
    message: &Incoming,
) -> Result<bool, String> {
    let quarantined_id = state
        .quarantined
        .then(|| state.quarantined_session.as_ref().map(|s| s.id.as_slice()))
        .flatten();
    if let Some(q_id) = quarantined_id
        && let InitialMessageKind::Classical { x3dh, .. } = &message.kind
        && x3dh.ephemeral_key.as_slice() == q_id
    {
        return Ok(true);
    }
    let pending = &mut state.pending_carried_initials;
    let bytes =
        session::protocol::mailbox_v2::encode_carried_initial(&initial_payload(&message.kind))
            .map_err(|e| describe(&e))?
            .to_vec();
    if pending.contains(&bytes) {
        return Ok(true);
    }
    let unsupported_count = pending
        .iter()
        .filter(|entry| is_unsupported_carried_bytes(entry))
        .count();
    let supported_count = pending.len() - unsupported_count;
    let is_unsupported = message
        .pq_suite()
        .is_some_and(|suite| !suite.is_supported());
    if is_unsupported {
        if unsupported_count >= MAX_PENDING_CARRIED_INITIALS {
            return Ok(false);
        }
    } else if supported_count >= MAX_PENDING_CARRIED_INITIALS {
        return Ok(false);
    }
    pending.push(bytes);
    Ok(true)
}

#[cfg(test)]
pub(super) fn stage_carried_initials<'a>(
    state: &mut ContactState,
    initials: impl IntoIterator<Item = &'a Incoming>,
) -> Result<(), String> {
    let quarantined_id = state
        .quarantined
        .then(|| state.quarantined_session.as_ref().map(|s| s.id.as_slice()))
        .flatten();
    let pending = &mut state.pending_carried_initials;
    let mut unsupported_count = pending
        .iter()
        .filter(|entry| is_unsupported_carried_bytes(entry))
        .count();
    let mut supported_count = pending.len() - unsupported_count;
    for message in initials {
        if let Some(q_id) = quarantined_id
            && let InitialMessageKind::Classical { x3dh, .. } = &message.kind
            && x3dh.ephemeral_key.as_slice() == q_id
        {
            continue;
        }
        let bytes =
            session::protocol::mailbox_v2::encode_carried_initial(&initial_payload(&message.kind))
                .map_err(|e| describe(&e))?
                .to_vec();
        if !pending.contains(&bytes) {
            if message
                .pq_suite()
                .is_some_and(|suite| !suite.is_supported())
            {
                // Bound retained unsupported entries independently so a full unsupported queue
                // never blocks supported handshakes or causes cursor rollback loops.
                if unsupported_count >= MAX_PENDING_CARRIED_INITIALS {
                    continue;
                }
                pending.push(bytes);
                unsupported_count += 1;
            } else {
                if supported_count >= MAX_PENDING_CARRIED_INITIALS {
                    return Err("Too many pending carried initial messages for this chat.".into());
                }
                pending.push(bytes);
                supported_count += 1;
            }
        }
    }
    Ok(())
}

/// Maximum inbox pages drained per `take_initial_messages` pass.
const MAX_INBOX_PAGES: usize = 10;

/// Validate, normalize (`id = 0`), deduplicate, cap, and timestamp deferred inbox initials
/// restored from disk. Returns `(removed_count, modified)`.
pub(super) fn sanitize_deferred_initials(
    entries: &mut Vec<DeferredInitial>,
    now_ms: u64,
) -> (usize, bool) {
    let mut cleaned = Vec::with_capacity(entries.len().min(MAX_DEFERRED_INITIALS));
    let mut removed = 0usize;
    let mut modified = false;
    for entry in entries.drain(..) {
        let Some(mut wire) = entry.initial else {
            removed += 1;
            modified = true;
            continue;
        };
        if wire.id != 0 {
            wire.id = 0;
            modified = true;
        }
        if Incoming::try_from(&wire).is_err() {
            removed += 1;
            modified = true;
            continue;
        }
        let deferred_at = if entry.deferred_at == 0 {
            if now_ms != 0 {
                modified = true;
            }
            now_ms
        } else {
            entry.deferred_at
        };
        if let Some(existing) = cleaned
            .iter_mut()
            .find(|e: &&mut DeferredInitial| e.initial.as_ref() == Some(&wire))
        {
            if deferred_at != 0 && (existing.deferred_at == 0 || deferred_at < existing.deferred_at)
            {
                existing.deferred_at = deferred_at;
            }
            removed += 1;
            modified = true;
            continue;
        }
        if cleaned.len() >= MAX_DEFERRED_INITIALS {
            removed += 1;
            modified = true;
            continue;
        }
        cleaned.push(DeferredInitial {
            initial: Some(wire),
            deferred_at,
        });
    }
    *entries = cleaned;
    (removed, modified)
}

fn initial_spk_and_digest(initial: &Incoming) -> (PublicKey, Option<[u8; 32]>) {
    match &initial.kind {
        InitialMessageKind::Classical { x3dh, .. } => (x3dh.signed_prekey, None),
        InitialMessageKind::Pq {
            x3dh,
            manifest_digest,
            ..
        } => (x3dh.signed_prekey, *manifest_digest),
    }
}

/// Record earliest retention timestamps for any unsupported-suite carried initials staged in
/// `pending_carried_initials` so prekey preservation stays bounded to [`DEFERRED_REPLAY_WINDOW_MS`].
pub(super) fn record_carried_timestamps(
    timestamps: &mut Vec<CarriedDeferredTimestamp>,
    pending_carried: &[Vec<u8>],
    now_ms: u64,
) {
    for bytes in pending_carried {
        let Some(initial) = Incoming::decode_carried(bytes) else {
            continue;
        };
        if !initial.pq_suite().is_some_and(|s| !s.is_supported()) {
            continue;
        }
        let (spk, _) = initial_spk_and_digest(&initial);
        if !timestamps
            .iter()
            .any(|t| t.signed_prekey.as_slice() == spk.as_slice())
        {
            timestamps.push(CarriedDeferredTimestamp {
                signed_prekey: spk.to_vec(),
                deferred_at: now_ms,
            });
        }
    }
}

/// Prune `carried_deferred_timestamps` entries whose signed prekeys are no longer referenced by
/// any active or isolated contact's `pending_carried_initials`. Returns how many entries were
/// removed.
pub(super) fn prune_carried_timestamps_for_contacts<'a>(
    timestamps: &mut Vec<CarriedDeferredTimestamp>,
    contacts: impl IntoIterator<Item = &'a Contact>,
    isolated_contacts: impl IntoIterator<Item = &'a ContactState>,
) -> usize {
    if timestamps.is_empty() {
        return 0;
    }
    let mut active_spks = std::collections::HashSet::new();
    for state in contacts
        .into_iter()
        .map(|contact| &contact.state)
        .chain(isolated_contacts)
    {
        for bytes in &state.pending_carried_initials {
            if let Some(initial) = Incoming::decode_carried(bytes) {
                active_spks.insert(initial_spk_and_digest(&initial).0);
            }
        }
    }
    let before = timestamps.len();
    timestamps.retain(|entry| {
        PublicKey::try_from(entry.signed_prekey.as_slice())
            .is_ok_and(|spk| active_spks.contains(&spk))
    });
    before - timestamps.len()
}

/// Collect signed prekeys and manifest digests referenced by long-lived deferred initials
/// (unsupported-suite inbox initials, PQ-incompatible isolated contacts, and unsupported-suite
/// carried initials / buffered envelopes) up to [`MAX_DEFERRED_PINNED_DIGESTS`], and optionally
/// also transient supported-suite carried initials / buffered envelopes within the same 128-digest
/// ceiling (`R9-P1-3`).
///
/// SPKs are always collected without capping (there are at most 3 local generations). Distinct
/// digests present in `inner.client.recent_manifest_digests()` are strictly capped at
/// [`MAX_DEFERRED_PINNED_DIGESTS`] (128) with long-lived unsupported/isolated initials prioritized
/// first, so supported-suite mailbox bursts never starve the 16 reserved rolling manifest slots
/// while healthy carried initials remain unstripped in `receive_mailbox`.
fn preserved_deferred_prekeys_inner<V: VaultStore>(
    inner: &Inner<V>,
    now_ms: u64,
    include_supported_transient: bool,
) -> (Vec<PublicKey>, Vec<[u8; 32]>) {
    let recent = inner.client.recent_manifest_digests();
    let mut spks = Vec::new();
    let mut digests = Vec::new();
    let mut pinned_in_recent = 0usize;
    let mut record = |initial: &Incoming| {
        let (spk, digest) = initial_spk_and_digest(initial);
        if !spks.contains(&spk) {
            spks.push(spk);
        }
        if let Some(d) = digest
            && !digests.contains(&d)
        {
            if recent.contains(&d) {
                if pinned_in_recent < MAX_DEFERRED_PINNED_DIGESTS {
                    digests.push(d);
                    pinned_in_recent += 1;
                }
            } else {
                digests.push(d);
            }
        }
    };
    let is_unsupported_suite = |initial: &Incoming| {
        initial
            .pq_suite()
            .is_some_and(|suite| !suite.is_supported())
    };

    // Pass 1: Long-lived unsupported-suite and PQ-incompatible isolated entries.
    for entry in &inner.deferred_initials {
        let Some(wire) = &entry.initial else {
            continue;
        };
        let is_isolated_peer = PublicKey::try_from(wire.identity_key.as_ref())
            .is_ok_and(|peer| inner.is_pq_incompatible_isolated_peer(&peer));
        let within_window = is_isolated_peer
            || entry.deferred_at == 0
            || now_ms.saturating_sub(entry.deferred_at) <= DEFERRED_REPLAY_WINDOW_MS;
        if !within_window {
            continue;
        }
        if let Ok(initial) = Incoming::try_from(wire) {
            record(&initial);
        }
    }
    let me = inner.client.identity_key();
    for iso in &inner.isolated_contacts {
        let is_pq_iso = super::contact::is_pq_incompatible_isolated(iso, &me);
        for bytes in &iso.pending_carried_initials {
            let Some(initial) = Incoming::decode_carried(bytes) else {
                continue;
            };
            let (spk, _) = initial_spk_and_digest(&initial);
            let deferred_at = inner
                .carried_deferred_timestamps
                .iter()
                .find(|t| t.signed_prekey.as_slice() == spk.as_slice())
                .map_or(0, |t| t.deferred_at);
            let within_window = is_pq_iso
                || deferred_at == 0
                || now_ms.saturating_sub(deferred_at) <= DEFERRED_REPLAY_WINDOW_MS;
            if within_window {
                record(&initial);
            }
        }
    }
    let mut transient_supported = Vec::new();
    for contact in &inner.contacts {
        for bytes in &contact.state.pending_carried_initials {
            let Some(initial) = Incoming::decode_carried(bytes) else {
                continue;
            };
            let (spk, _) = initial_spk_and_digest(&initial);
            let deferred_at = inner
                .carried_deferred_timestamps
                .iter()
                .find(|t| t.signed_prekey.as_slice() == spk.as_slice())
                .map_or(0, |t| t.deferred_at);
            let within_window =
                deferred_at == 0 || now_ms.saturating_sub(deferred_at) <= DEFERRED_REPLAY_WINDOW_MS;
            if !within_window {
                continue;
            }
            if is_unsupported_suite(&initial) {
                record(&initial);
            } else if include_supported_transient {
                transient_supported.push(initial);
            }
        }
    }
    for env in &inner.deferred_envelopes {
        let Some(wire) = &env.initial_message else {
            continue;
        };
        let is_isolated = env.pq_isolated
            || inner.isolated_contacts.iter().any(|iso| {
                iso.peer == env.peer && super::contact::is_pq_incompatible_isolated(iso, &me)
            });
        let within_window = is_isolated
            || env.deferred_at == 0
            || now_ms.saturating_sub(env.deferred_at) <= DEFERRED_REPLAY_WINDOW_MS;
        if within_window && let Ok(initial) = Incoming::try_from(wire) {
            if is_isolated || is_unsupported_suite(&initial) {
                record(&initial);
            } else if include_supported_transient {
                transient_supported.push(initial);
            }
        }
    }

    // Pass 2: Transient supported-suite carried initials & buffered envelopes (share the same
    // 128-digest ceiling; any overflow remains protected by the 16 rolling slots + SPK retention).
    for initial in &transient_supported {
        record(initial);
    }
    (spks, digests)
}

/// Collect signed prekeys and manifest digests referenced by deferred inbox initials, carried
/// initials (active or isolated contacts), and buffered `DeferredEnvelope`s so scheduled prekey
/// rotations do not evict prekeys needed to replay them.
pub(super) fn preserved_deferred_prekeys<V: VaultStore>(
    inner: &Inner<V>,
    now_ms: u64,
) -> (Vec<PublicKey>, Vec<[u8; 32]>) {
    preserved_deferred_prekeys_inner(inner, now_ms, true)
}

/// Whether local processing has finished for this initial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InitialOutcome {
    /// Accepted, quarantined, or permanently rejected — safe to acknowledge after local save.
    Ack,
    /// Keep the ciphertext so a build with the required suite can process it.
    DeferUnsupportedSuite,
}

/// Result of attempting to store a deferred unsupported-suite inbox initial locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DeferInboxOutcome {
    /// Stored locally (or already present) and staged for ACK once saved.
    Stored { dirty: bool },
    /// Local `MAX_DEFERRED_INITIALS` cap is full and the message was not already stored; it stays
    /// un-ACKed on the server and suppresses destructive deferred-envelope pruning.
    CapFull,
}

pub(super) struct OpenedInitial {
    pub(super) session: Session<Connect>,
    first_message: Vec<u8>,
    /// A held classical initial and whether the peer was already pinned.
    quarantine: Option<bool>,
}

#[derive(Default)]
pub(super) struct InitialBatch {
    dirty: bool,
    /// Set if any inbox initial was left un-ACKed on the server (e.g. `MAX_DEFERRED_INITIALS`
    /// cap full), preventing premature destructive pruning of buffered `DeferredEnvelope`s.
    pub(super) has_unacked_deferred: bool,
    records: Vec<(PublicKey, u64, HistoryEntry)>,
    /// Newly added entries for the open chat: `(peer, view, displayed_entry)`.
    views: Vec<(PublicKey, MessageView, DisplayedEntry)>,
    requeue: BTreeSet<PublicKey>,
    upgrades: BTreeMap<PublicKey, u64>,
    /// Contacts whose quarantine was lifted by an accepted incoming PQ initial in this batch.
    unquarantined: BTreeSet<PublicKey>,
    /// Already-approved contacts that received a rekey initial and staged a new write-token grant.
    grant_peers: BTreeSet<PublicKey>,
    /// Peers whose session state advanced via an accepted initial in this batch.
    touched_peers: BTreeSet<PublicKey>,
}

fn is_valid_inbox_ack_id(id: u64) -> bool {
    id != 0 && id <= session::protocol::MAX_SAFE_INTEGER
}

/// Zero is reserved for carried initial messages in mailbox envelopes.
pub(super) fn stage_inbox_ack(pending: &mut Vec<u64>, id: u64) -> bool {
    if !is_valid_inbox_ack_id(id) || pending.contains(&id) {
        return false;
    }
    pending.push(id);
    true
}

pub(super) fn prune_invalid_inbox_acks(pending: &mut Vec<u64>) -> usize {
    let before = pending.len();
    let mut seen = std::collections::HashSet::new();
    pending.retain(|&id| is_valid_inbox_ack_id(id) && seen.insert(id));
    before - pending.len()
}

/// Maximum distinct local manifest digests that deferred initial messages may pin, reserving
/// [`session::MAX_RECENT_MANIFEST_DIGESTS`] (16) slots for rolling/mandatory manifest renewals
/// (`R8-P2-7`).
const MAX_DEFERRED_PINNED_DIGESTS: usize =
    session::MAX_RETAINED_MANIFEST_DIGESTS - session::MAX_RECENT_MANIFEST_DIGESTS;

/// Pin the oldest evictable signed prekey AND locally retained manifest digests whenever
/// `inbox_ready_for_eviction == false` during publish preparation so an undrained inbox (`listed = 1`
/// row whose list response was lost or un-ACKed) can never lose either its SPK (`R7-P1-4`) or its
/// manifest digest `M0` (`R8-P0-1`) across repeated publishes.
fn preserve_undrained_inbox_prekeys<V: VaultStore>(
    inner: &Inner<V>,
    inbox_ready_for_eviction: bool,
    preserve_spks: &mut Vec<PublicKey>,
    preserve_digests: &mut Vec<[u8; 32]>,
) {
    if inbox_ready_for_eviction {
        return;
    }
    if let Some(oldest_spk) = inner.client.oldest_evictable_signed_prekey()
        && !preserve_spks.contains(&oldest_spk)
    {
        preserve_spks.push(oldest_spk);
    }
    for &digest in inner.client.recent_manifest_digests() {
        if !preserve_digests.contains(&digest) {
            preserve_digests.push(digest);
        }
    }
}

/// Commit/reconcile variant of [`preserve_undrained_inbox_prekeys`] (`R9-P2-3`): when a publish
/// already landed on the relay with `recent_manifest_digests().len() > MAX_RETAINED_MANIFEST_DIGESTS`
/// (e.g. 145 staged entries: 128 deferred + 16 rolling + 1 landed) and `!inbox_ready_for_eviction`,
/// cap extra undrained-inbox digest pins among `recent[..len - 1]` to
/// `MAX_RETAINED_MANIFEST_DIGESTS - 1` (newest confirmed digests first) so
/// `prune_manifest_digests_preserving` always evicts the oldest unpinned rolling/unconfirmed digest
/// instead of falling back to index `0` (the oldest deferred-pinned digest `D_0`).
#[cfg(test)]
pub(super) fn preserve_undrained_inbox_prekeys_for_commit<V: VaultStore>(
    inner: &Inner<V>,
    inbox_ready_for_eviction: bool,
    preserve_spks: &mut Vec<PublicKey>,
    preserve_digests: &mut Vec<[u8; 32]>,
) {
    preserve_undrained_inbox_prekeys_for_commit_with(
        inner,
        inbox_ready_for_eviction,
        None,
        preserve_spks,
        preserve_digests,
    );
}

pub(super) fn preserve_undrained_inbox_prekeys_for_commit_with<V: VaultStore>(
    inner: &Inner<V>,
    inbox_ready_for_eviction: bool,
    landed: Option<([u8; 32], PublicKey)>,
    preserve_spks: &mut Vec<PublicKey>,
    preserve_digests: &mut Vec<[u8; 32]>,
) {
    if inbox_ready_for_eviction {
        return;
    }
    if let Some(oldest_spk) = inner.client.oldest_evictable_signed_prekey()
        && !preserve_spks.contains(&oldest_spk)
    {
        preserve_spks.push(oldest_spk);
    }
    let recent = inner.client.recent_manifest_digests();
    if recent.len() <= session::MAX_RETAINED_MANIFEST_DIGESTS {
        for &digest in recent {
            if !preserve_digests.contains(&digest) {
                preserve_digests.push(digest);
            }
        }
        return;
    }
    // R14-P2-6 + R15-P2-4: Identify the newly staged/landed manifest digest AND its retained SPK
    // BEFORE commit/reconciliation flips it from unconfirmed to confirmed (using explicit verified
    // manifest metadata when available, or `digest_retained_spk(recent.last())` which ignores the
    // `confirmed` flag), so it counts once against its SPK's 16-entry quota and is never double-
    // counted in `preserve_digests`.
    let landed_digest = landed
        .map(|(d, _)| d)
        .filter(|d| recent.contains(d))
        .or_else(|| recent.last().copied());
    let landed_spk = landed
        .filter(|(_, spk)| inner.client.has_signed_prekey(spk))
        .map(|(_, spk)| spk)
        .or_else(|| landed_digest.and_then(|d| inner.client.digest_retained_spk(&d)));
    let candidates: Vec<[u8; 32]> = recent
        .iter()
        .copied()
        .filter(|d| Some(*d) != landed_digest)
        .collect();
    let max_candidate_pins = session::MAX_RETAINED_MANIFEST_DIGESTS.saturating_sub(1);
    let mut pinned_candidates = candidates
        .iter()
        .filter(|d| preserve_digests.contains(d))
        .count();
    let mut pinned_confirmed_per_spk: BTreeMap<PublicKey, usize> = BTreeMap::new();
    if let Some(spk) = landed_spk {
        *pinned_confirmed_per_spk.entry(spk).or_insert(0) += 1;
    }
    for digest in preserve_digests.iter() {
        if Some(*digest) == landed_digest {
            continue;
        }
        if let Some(spk) = inner.client.confirmed_digest_retained_spk(digest) {
            *pinned_confirmed_per_spk.entry(spk).or_insert(0) += 1;
        }
    }
    let confirmed = inner.client.confirmed_manifest_digests();
    // R10-P2-2 + R13-P2-3 + R14-P2-6:
    // - Tier 0: Guarantee at least 1 newest confirmed digest for EVERY retained SPK first (even
    //   when 128 deferred digests leave only 15 free candidate pin slots).
    // - Tier 1: Fill up to `MAX_RECENT_MANIFEST_DIGESTS` (16) confirmed digests per retained SPK
    //   (inclusive of `recent.last()` and deferred pins).
    // - Tier 2: Surplus confirmed retained-SPK digests.
    // - Tier 3: Confirmed rolling digests.
    // - Tier 4: Unconfirmed retained-SPK digests.
    // - Tier 5: Remaining unconfirmed digests.
    for tier in 0..6u8 {
        for &digest in candidates.iter().rev() {
            if pinned_candidates >= max_candidate_pins {
                return;
            }
            if preserve_digests.contains(&digest) {
                continue;
            }
            let confirmed_spk = inner.client.confirmed_digest_retained_spk(&digest);
            let matches = match tier {
                0 => confirmed_spk.is_some_and(|spk| {
                    pinned_confirmed_per_spk.get(&spk).copied().unwrap_or(0) == 0
                }),
                1 => confirmed_spk.is_some_and(|spk| {
                    pinned_confirmed_per_spk.get(&spk).copied().unwrap_or(0)
                        < session::MAX_RECENT_MANIFEST_DIGESTS
                }),
                2 => confirmed_spk.is_some(),
                3 => confirmed.contains(&digest),
                4 => inner.client.is_unconfirmed_digest_for_retained_spk(&digest),
                _ => true,
            };
            if !matches {
                continue;
            }
            if let Some(spk) = confirmed_spk {
                *pinned_confirmed_per_spk.entry(spk).or_insert(0) += 1;
            }
            preserve_digests.push(digest);
            pinned_candidates += 1;
        }
    }
}

impl<V: VaultStore> Inner<V> {
    /// Whether deferring `message` would stay within [`MAX_DEFERRED_PINNED_DIGESTS`] distinct
    /// locally retained manifest digests pinned by long-lived deferred initials, preserving
    /// rolling/renewal manifest capacity (`R8-P2-7`, `R9-P1-3`).
    pub(super) fn can_pin_deferred_digest(&self, message: &Incoming, now_ms: u64) -> bool {
        let (_, new_digest) = initial_spk_and_digest(message);
        let Some(digest) = new_digest else {
            return true;
        };
        let recent = self.client.recent_manifest_digests();
        if !recent.contains(&digest) {
            return true;
        }
        let (_, existing_digests) = preserved_deferred_prekeys_inner(self, now_ms, false);
        if existing_digests.contains(&digest) {
            return true;
        }
        let pinned_in_recent = recent
            .iter()
            .filter(|d| existing_digests.contains(d))
            .count();
        pinned_in_recent < MAX_DEFERRED_PINNED_DIGESTS
    }

    /// Reserve a local copy deduplicated by payload (ignoring relay-assigned inbox ID) and
    /// include its ack ID in the same vault transaction.
    pub(super) fn defer_inbox_initial(&mut self, message: &Incoming) -> DeferInboxOutcome {
        let wire = WireInitial {
            id: 0,
            ..initial_payload(&message.kind)
        };
        let already_stored = self
            .deferred_initials
            .iter()
            .any(|entry| entry.initial.as_ref() == Some(&wire));
        if !already_stored {
            let now_ms = now();
            if self.deferred_initials.len() >= MAX_DEFERRED_INITIALS
                || !self.can_pin_deferred_digest(message, now_ms)
            {
                return DeferInboxOutcome::CapFull;
            }
            self.deferred_initials.push(DeferredInitial {
                initial: Some(wire),
                deferred_at: now_ms,
            });
        }
        let dirty =
            stage_inbox_ack(&mut self.deferred_acks_after_save, message.id) || !already_stored;
        DeferInboxOutcome::Stored { dirty }
    }

    pub(super) fn check_outgoing_peer(&self, peer: &PublicKey) -> Result<(), StartChatError> {
        if *peer == self.client.identity_key() {
            return Err(StartChatError::Other(
                "You cannot start a chat with your own identity key.".into(),
            ));
        }
        self.check_isolation(peer).map_err(StartChatError::Other)
    }

    pub(super) async fn save_full_publish_success(
        &mut self,
        concurrent_classical_used: u32,
    ) -> crate::vault::Result<()> {
        self.state.published_at = now();
        self.state.used_one_time_prekeys = concurrent_classical_used;
        self.state.needs_publish = false;
        self.state.pending_pq_rollback = None;
        self.save_state().await
    }

    pub(super) fn open_initial(
        &mut self,
        peer: &PublicKey,
        message: &Incoming,
    ) -> session::Result<OpenedInitial> {
        let mailbox = Fetch::client(&self.server);
        let pin = self
            .contact(peer)
            .map(|c| c.session.peer_pq_state().clone())
            .unwrap_or_default();
        let (opened, pq_suite) = match self
            .client
            .accept_initial_v2(peer, &pin, message, mailbox)?
        {
            AcceptedInitial::Accepted {
                session,
                first_message,
                security,
            } => (
                OpenedInitial {
                    session,
                    first_message,
                    quarantine: None,
                },
                security.suite,
            ),
            AcceptedInitial::Quarantined {
                session,
                first_message,
                peer_was_pq_pinned,
            } => (
                OpenedInitial {
                    session,
                    first_message,
                    quarantine: Some(peer_was_pq_pinned),
                },
                None,
            ),
        };
        // R10-P2-5 + R11-P2-5 + R11-P3-1:
        // - Exact OPK/PQOPK key-ID matching absorbs pre-refill relay claims without hiding newer
        //   depletion, and ignores delayed greetings from superseded publications (whose keys are
        //   no longer in the replacement FIFO queue, or whose SPK != current_signed_prekey).
        // - Greetings referencing `current_signed_prekey` that fell back to SPK-only or PQ
        //   last-resort (`one_time_prekey() == None` / `pq_one_time_prekey_id() == None`) prove
        //   that pool hit 0 on the relay (e.g. from abandoned bundle claims) OR the Worker's hourly
        //   32-claim OPK budget throttled the claim (`R11-P2-5`, `R12-P2-4`, `R12-P2-5`). Bump the
        //   local usage counter to trigger a single bounded refill probe (rate-limited by a 1-hour
        //   cooldown if the relay responds with stocked keys) WITHOUT clobbering `last_server_*`,
        //   fabricating a partial multi-suite map after reload, or discarding FIFO queue tracking.
        const MAX_TRACKED_OPK_CLAIMS: usize = 1024;
        let on_current_spk = self.client.current_signed_prekey() == Some(message.signed_prekey());
        let unreconciled = self.client.has_unreconciled_publish();
        if let Some(opk) = message.one_time_prekey() {
            if !self.relay_claimed_classical_opks.remove(&opk) {
                let charge_current_pool = unreconciled
                    || match self.relay_classical_opk_queue.as_ref() {
                        Some(queue) => queue.contains(&opk),
                        None => on_current_spk,
                    };
                if charge_current_pool {
                    self.state.used_one_time_prekeys =
                        self.state.used_one_time_prekeys.saturating_add(1);
                    if self.accepted_classical_since_baseline.len() < MAX_TRACKED_OPK_CLAIMS {
                        self.accepted_classical_since_baseline.insert(opk);
                    }
                }
            }
        } else if on_current_spk
            && !unreconciled
            && now() >= self.classical_fallback_probe_cooldown_until
        {
            self.state.used_one_time_prekeys = self.state.used_one_time_prekeys.max(REFILL_USED);
            self.classical_fallback_probe_pending = true;
        }
        if let Some(pq_id) = message.pq_one_time_prekey_id() {
            let absorbed_pq = if let Some(suite) = pq_suite
                && let Some(claimed) = self.relay_claimed_pq_opks_by_suite.get_mut(&suite)
                && claimed.remove(&pq_id)
            {
                if claimed.is_empty() {
                    self.relay_claimed_pq_opks_by_suite.remove(&suite);
                }
                true
            } else {
                false
            };
            if !absorbed_pq {
                let charge_pq_pool = unreconciled
                    || match (pq_suite, self.relay_pq_opk_queue_by_suite.as_ref()) {
                        (Some(suite), Some(queues)) => match queues.get(&suite) {
                            Some(q) => q.contains(&pq_id),
                            // R12-P2-3: A per-suite queue removed on ambiguous error or untracked
                            // refill means that suite's queue is unknown (not empty); fall back to
                            // `on_current_spk` just like when the outer `Option` is `None`.
                            None => on_current_spk,
                        },
                        _ => on_current_spk,
                    };
                if charge_pq_pool {
                    self.state.used_pq_one_time_prekeys =
                        self.state.used_pq_one_time_prekeys.saturating_add(1);
                    if let Some(suite) = pq_suite {
                        let entry = self.used_pq_by_suite.entry(suite).or_insert(0);
                        *entry = entry.saturating_add(1);
                        let accepted = self.accepted_pq_since_baseline.entry(suite).or_default();
                        if accepted.len() < MAX_TRACKED_OPK_CLAIMS {
                            accepted.insert(pq_id);
                        }
                    }
                }
            }
        } else if on_current_spk
            && !unreconciled
            && let Some(suite) = pq_suite
            && now()
                >= self
                    .pq_fallback_probe_cooldown_until
                    .get(&suite)
                    .copied()
                    .unwrap_or(0)
        {
            let entry = self.used_pq_by_suite.entry(suite).or_insert(0);
            *entry = (*entry).max(REFILL_USED);
            self.state.used_pq_one_time_prekeys =
                self.state.used_pq_one_time_prekeys.max(REFILL_USED);
            self.pq_fallback_probe_pending.insert(suite);
        }
        Ok(opened)
    }

    #[cfg(test)]
    pub(super) async fn ack_persisted_inbox(
        &mut self,
        mut acknowledge: impl AsyncFnMut(
            &mut session::Client<Connect>,
            &str,
            Vec<u64>,
        ) -> Result<(), String>,
    ) -> Result<(), String> {
        if prune_invalid_inbox_acks(&mut self.state.pending_inbox_acks) > 0 {
            self.save_state().await.map_err(|e| describe(&e))?;
        }
        if self.needs_save() {
            return Ok(());
        }
        let before = self.state.pending_inbox_acks.len();
        let result = loop {
            let pending = &mut self.state.pending_inbox_acks;
            let count = pending.len().min(100);
            if count == 0 {
                break Ok(());
            }
            if let Err(e) =
                acknowledge(&mut self.client, &self.audience, pending[..count].to_vec()).await
            {
                break Err(e);
            }
            pending.drain(..count);
        };
        if before != self.state.pending_inbox_acks.len()
            && let Err(e) = self.save_state().await
        {
            let warning = format!(
                "failed to save acknowledged inbox IDs (will retry): {}",
                describe(&e)
            );
            return Err(match result {
                Ok(()) => warning,
                Err(error) => format!("{error}. {warning}"),
            });
        }
        result
    }

    /// Accepted initials consume prekeys. Keep every part of a failed transaction staged until
    /// the next full state save, including a batch consisting only of alerts or inbox IDs.
    pub(super) async fn save_inbox_changes(
        &mut self,
        history: Vec<(PublicKey, u64, HistoryEntry)>,
        outbox: Vec<(PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> Result<(), String> {
        if let Err(e) = self.save_with(&history, &outbox).await {
            self.unsaved.extend(history);
            self.unsaved_outbox.extend(outbox);
            self.unsaved_state = true;
            return Err(describe(&e));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct PublishError {
    pub(super) kind: Option<ErrorKind>,
    definitive_refusal: bool,
    malformed: bool,
    pub(super) message: String,
}

impl PublishError {
    fn locked() -> Self {
        Self {
            kind: None,
            definitive_refusal: false,
            malformed: false,
            message: "locked".into(),
        }
    }

    fn prepare(e: session::Error) -> Self {
        let message = if e.kind() == ErrorKind::ClockSkew {
            super::CLOCK_SKEW_MESSAGE.to_string()
        } else {
            describe(&e)
        };
        Self {
            kind: Some(e.kind()),
            definitive_refusal: false,
            malformed: false,
            message,
        }
    }

    fn storage(e: crate::vault::Error) -> Self {
        Self {
            kind: None,
            definitive_refusal: false,
            malformed: false,
            message: describe(&e),
        }
    }

    pub(super) fn transmitted(e: session::Error) -> Self {
        // Strict v2 fallback maps the server's Unimplemented refusal to a local PqRequired.
        let definitive_refusal = e.is_server_refusal() || e.kind() == ErrorKind::PqRequired;
        let wire_kind = std::error::Error::source(&e)
            .and_then(|source| source.downcast_ref::<session::protocol::Error>())
            .map(session::protocol::Error::kind);
        Self {
            kind: Some(e.kind()),
            definitive_refusal,
            malformed: wire_kind == Some(session::protocol::ErrorKind::Malformed),
            message: describe(&e),
        }
    }

    pub(super) fn rejects_settings(&self) -> bool {
        self.definitive_refusal
            && (self.malformed
                || matches!(
                    self.kind,
                    Some(
                        ErrorKind::PqRequired
                            | ErrorKind::LimitExceeded
                            | ErrorKind::InvalidKeys
                            | ErrorKind::UnsupportedSuite
                    )
                ))
    }

    pub(super) fn needs_sign_in(&self) -> bool {
        self.definitive_refusal && self.kind == Some(ErrorKind::SignInRequired)
    }

    pub(super) fn is_unimplemented(&self) -> bool {
        self.definitive_refusal && self.kind == Some(ErrorKind::Unimplemented)
    }
}

#[derive(PartialEq, Eq)]
enum RefillV2Outcome {
    Handled,
    PqDisabled,
    SuiteMismatchNeedsClassicalOnly,
    MixedLimitExceeded,
    /// A single-pool refill batch larger than 1 key hit `LimitExceeded`; retry once with a 1-key
    /// probe so partially-available shared-cap slots are still used and exact relay counts are
    /// recovered before treating the pool as completely full (`R13-P2-5`).
    RetryProbeSingleKey,
}

#[derive(PartialEq, Eq)]
enum PublishFullOutcome {
    Published,
    Deferred,
}

impl<V: VaultStore> Engine<V> {
    /// Acknowledge persisted v2 inbox IDs without holding `self.inner` across network RPCs.
    async fn ack_pending_inbox_v2(&self, vgen: u64) -> Result<(), String> {
        loop {
            if !self.is_live(vgen) {
                return Ok(());
            }
            let next = {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok(());
                }
                let Some(inner) = guard.as_mut() else {
                    return Ok(());
                };
                if prune_invalid_inbox_acks(&mut inner.state.pending_inbox_acks) > 0 {
                    inner.save_state().await.map_err(|e| describe(&e))?;
                    if !self.is_live(vgen) {
                        return Ok(());
                    }
                }
                if inner.needs_save() || inner.state.pending_inbox_acks.is_empty() {
                    return Ok(());
                }
                let count = inner.state.pending_inbox_acks.len().min(100);
                let ids = inner.state.pending_inbox_acks[..count].to_vec();
                match inner
                    .client
                    .sign_ack_initial_messages_v2(&inner.audience, &ids)
                {
                    Ok(reqs) => (inner.server.clone(), ids, reqs),
                    Err(e) => {
                        if e.kind() == ErrorKind::ClockSkew {
                            self.warn_clock_skew(inner.client.clock().offset_ms());
                        }
                        self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                        return Err(describe(&e));
                    }
                }
            };
            let (server, ids, reqs) = next;
            for req in reqs {
                let res: session::Result<_> = Fetch::client(&server)
                    .ack_initial_messages(req)
                    .await
                    .map_err(session::Error::from);
                if !self.is_live(vgen) {
                    return Ok(());
                }
                if let Err(e) = res {
                    self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                    return Err(describe(&e));
                }
            }
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(());
            }
            let Some(inner) = guard.as_mut() else {
                return Ok(());
            };
            let before = inner.state.pending_inbox_acks.len();
            inner
                .state
                .pending_inbox_acks
                .retain(|id| !ids.contains(id));
            if before != inner.state.pending_inbox_acks.len()
                && let Err(e) = inner.save_state().await
            {
                return Err(format!(
                    "failed to save acknowledged inbox IDs (will retry): {}",
                    describe(&e)
                ));
            }
        }
    }

    pub(super) fn process_inbox_messages(
        &self,
        inner: &mut Inner<impl VaultStore>,
        inbox: ListedInitialMessages,
        batch: &mut InitialBatch,
    ) {
        for message in inbox.messages {
            let (peer, id) = (message.sender, message.id);
            if !is_valid_inbox_ack_id(id) {
                self.ui.log(format!(
                    "Skipped initial message with out-of-range inbox ID {id}."
                ));
                continue;
            }
            if inner.state.pending_inbox_acks.contains(&id)
                || inner.deferred_acks_after_save.contains(&id)
            {
                continue;
            }
            match self.process_initial(inner, &peer, &message, batch) {
                InitialOutcome::Ack => {
                    batch.dirty |= stage_inbox_ack(&mut inner.state.pending_inbox_acks, id);
                }
                InitialOutcome::DeferUnsupportedSuite => {
                    match inner.defer_inbox_initial(&message) {
                        DeferInboxOutcome::Stored { dirty } => batch.dirty |= dirty,
                        DeferInboxOutcome::CapFull => batch.has_unacked_deferred = true,
                    }
                }
            }
        }
        for id in inbox.malformed_ids {
            if !is_valid_inbox_ack_id(id) {
                self.ui.log(format!(
                    "Skipped malformed initial message with out-of-range inbox ID {id}."
                ));
                continue;
            }
            batch.dirty |= stage_inbox_ack(&mut inner.state.pending_inbox_acks, id);
        }
    }

    pub(super) async fn take_initial_messages(&self) -> Result<bool, String> {
        self.take_initial_messages_with_replayed()
            .await
            .map(|(any_progress, _, _)| any_progress)
    }

    /// Drain pending inbox initials and replay any newly unblocked deferred envelopes.
    ///
    /// Returns `(any_progress, replayed_peers, drained_all)` where `drained_all` is `true` only
    /// when server pagination reached `has_more == false` without hitting `MAX_INBOX_PAGES` or
    /// leaving any deferred unsupported-suite initial un-ACKed on the server.
    pub(super) async fn take_initial_messages_with_replayed(
        &self,
    ) -> Result<(bool, BTreeSet<PublicKey>, bool), String> {
        let vgen = self.vault_gen();
        let mut any_progress = false;
        let mut drained_all = false;
        let mut any_unacked_deferred = false;
        let mut pre_final_list_cursor = 0u64;
        let mut after_id = 0u64;
        let mut all_upgrades: BTreeMap<PublicKey, u64> = BTreeMap::new();
        let mut all_grant_peers: BTreeSet<PublicKey> = BTreeSet::new();
        let mut inbox_peers = BTreeSet::new();
        let mut all_replayed = BTreeSet::new();
        // Serialize inbox `list`/`process`/`ack` pagination without holding `self.inner` across
        // network RTTs so concurrent callers cannot race on already-ACKed last-resort-prekey
        // requests and resurrect a deleted chat request.
        let inbox_guard = self.inbox_lock.lock().await;
        if !self.is_live(vgen) {
            return Ok((false, BTreeSet::new(), false));
        }
        for _ in 0..MAX_INBOX_PAGES {
            if !self.is_live(vgen) {
                return Ok((false, BTreeSet::new(), false));
            }
            {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok((false, BTreeSet::new(), false));
                }
                let Some(inner) = guard.as_mut() else {
                    break;
                };
                if inner.needs_save() {
                    inner.save(&[]).await.map_err(|e| describe(&e))?;
                }
                if !self.is_live(vgen) {
                    return Ok((false, BTreeSet::new(), false));
                }
            }
            self.ack_pending_inbox_v2(vgen).await?;
            if !self.is_live(vgen) {
                return Ok((false, BTreeSet::new(), false));
            }
            let (server, list_req, cursor_before_list) = {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok((false, BTreeSet::new(), false));
                }
                let Some(inner) = guard.as_mut() else {
                    break;
                };
                let cursor_now = inner.client.mailbox_cursor();
                match inner
                    .client
                    .sign_list_initial_messages_v2(&inner.audience, after_id, 100)
                {
                    Ok(req) => (inner.server.clone(), req, cursor_now),
                    Err(e) => {
                        if e.kind() == ErrorKind::ClockSkew {
                            self.warn_clock_skew(inner.client.clock().offset_ms());
                        }
                        self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                        return Err(describe(&e));
                    }
                }
            };
            pre_final_list_cursor = cursor_before_list;
            // Mark inbox drain status dirty BEFORE calling `ListInitialMessages`: the relay marks
            // returned rows `listed = 1`, so any concurrent/subsequent publish must not evict
            // `oldest_evictable_signed_prekey` until this drain completes cleanly.
            self.inbox_drained_clean.set(false);
            let raw_inbox: session::Result<_> = Fetch::client(&server)
                .list_initial_messages(list_req)
                .await
                .map_err(session::Error::from);
            if !self.is_live(vgen) {
                return Ok((false, BTreeSet::new(), false));
            }
            let inbox = match raw_inbox {
                Ok(resp) => session::parse_listed_initial_messages(&resp),
                Err(e) => {
                    self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                    return Err(describe(&e));
                }
            };
            let has_more = inbox.has_more;
            let next_after_id = inbox.next_after_id;
            let dirty = {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok((false, BTreeSet::new(), false));
                }
                let Some(inner) = guard.as_mut() else {
                    break;
                };
                let mut batch = InitialBatch::default();
                // Defer read receipts until `save_initial_batch` confirms the chat is still open and
                // visible after persistence.
                self.process_inbox_messages(inner, inbox, &mut batch);
                any_unacked_deferred |= batch.has_unacked_deferred;
                if batch.dirty {
                    any_progress = true;
                    let grant_peers = std::mem::take(&mut batch.grant_peers);
                    let touched_peers = std::mem::take(&mut batch.touched_peers);
                    let upgrades = self.save_initial_batch(inner, batch).await?;
                    if !self.is_live(vgen) {
                        return Ok((false, BTreeSet::new(), false));
                    }
                    all_upgrades.extend(upgrades);
                    all_grant_peers.extend(grant_peers);
                    inbox_peers.extend(touched_peers);
                    true
                } else {
                    false
                }
            };
            if dirty {
                if !self.is_live(vgen) {
                    return Ok((false, BTreeSet::new(), false));
                }
                self.ack_pending_inbox_v2(vgen).await?;
            }
            if !has_more {
                drained_all = !any_unacked_deferred;
                break;
            }
            match next_after_id {
                Some(next) if next > after_id => after_id = next,
                _ => break,
            }
        }
        // Only mark `inbox_drained_clean = true` while still holding `inbox_lock` when every page
        // drained cleanly with zero unacked deferred items AND zero pending inbox ACKs.
        if drained_all && self.is_live(vgen) {
            let guard = self.lock_inner().await;
            if self.is_live(vgen)
                && guard
                    .as_ref()
                    .is_some_and(|inner| inner.state.pending_inbox_acks.is_empty())
            {
                self.inbox_drained_clean.set(true);
            }
        }
        // Release `inbox_lock` BEFORE grant flushes, replay, and automatic PQ upgrades (`R20-P2-10`)
        // so `inbox_lock` never nests with `grant_sync_lock` or `peer_flush_lock` and a slow revoke
        // never stalls publishes or inbox drains.
        drop(inbox_guard);
        for peer in all_grant_peers {
            if !self.is_live(vgen) {
                return Ok((false, BTreeSet::new(), false));
            }
            let _ = self.flush_pending_grants_for_peer(&peer).await;
        }
        // Replay buffered envelopes only AFTER draining inbox pages, scoped strictly to peers
        // whose session state advanced in this pass and bounded to `pre_final_list_cursor` so
        // envelopes concurrently fetched/ACKed after our final `ListInitialMessages` are never
        // dropped before their inbox initial is pulled.
        let drop_up_to = drained_all.then_some(pre_final_list_cursor);
        let mut replay_grants = BTreeSet::new();
        if !inbox_peers.is_empty() && self.is_live(vgen) {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok((false, BTreeSet::new(), false));
            }
            if let Some(inner) = guard.as_mut()
                && !inner.deferred_envelopes.is_empty()
            {
                for peer in inbox_peers {
                    if !self.is_live(vgen) {
                        return Ok((false, BTreeSet::new(), false));
                    }
                    if let Ok((replayed_peers, replay_upgrades, grants)) = self
                        .replay_deferred_envelopes(inner, Some(&peer), drop_up_to, None)
                        .await
                    {
                        for replayed in &replayed_peers {
                            self.clear_approval_backoff(replayed);
                        }
                        all_replayed.extend(replayed_peers);
                        all_upgrades.extend(replay_upgrades);
                        replay_grants.extend(grants);
                    }
                }
            }
        }
        for peer in replay_grants {
            if !self.is_live(vgen) {
                return Ok((false, BTreeSet::new(), false));
            }
            let _ = self.flush_pending_grants_for_peer(&peer).await;
        }
        for (peer, conv_gen) in all_upgrades {
            if !self.is_live(vgen) {
                return Ok((false, BTreeSet::new(), false));
            }
            let _ = self.upgrade_to_pq_auto(peer, conv_gen).await;
        }
        Ok((any_progress, all_replayed, drained_all))
    }

    /// Commit replayed initials with their history and consumed prekeys. Return `(upgrades,
    /// grant_peers)` to execute after releasing `self.inner`, or `None` if the queue made no
    /// progress.
    pub(super) async fn replay_deferred_initials(
        &self,
        inner: &mut Inner<impl VaultStore>,
    ) -> Result<Option<(BTreeMap<PublicKey, u64>, BTreeSet<PublicKey>)>, String> {
        let mut batch = InitialBatch::default();
        let (pruned, modified) = sanitize_deferred_initials(&mut inner.deferred_initials, now());
        if pruned > 0 {
            self.ui.log(format!(
                "Removed {pruned} invalid, duplicate, or excess deferred initial message(s)."
            ));
        }
        if pruned > 0 || modified {
            batch.dirty = true;
        }
        let mut replayable = Vec::new();
        let deferred_entries = std::mem::take(&mut inner.deferred_initials);
        let mut remaining = Vec::with_capacity(deferred_entries.len());
        for entry in deferred_entries {
            let Some(wire) = entry.initial.as_ref() else {
                batch.dirty = true;
                continue;
            };
            match Incoming::try_from(wire) {
                Ok(message) => {
                    let suite_supported = message.pq_suite().is_none_or(PqSuite::is_supported);
                    let contact_blocked = inner.is_pq_incompatible_isolated_peer(&message.sender);
                    if suite_supported && !contact_blocked {
                        replayable.push((entry, Ok(message)));
                    } else {
                        remaining.push(entry);
                    }
                }
                Err(e) => replayable.push((entry, Err(e))),
            }
        }
        inner.deferred_initials = remaining;
        for (entry, decoded) in replayable {
            match decoded {
                Ok(message) => {
                    let peer = message.sender;
                    if self.process_initial(inner, &peer, &message, &mut batch)
                        == InitialOutcome::DeferUnsupportedSuite
                    {
                        inner.deferred_initials.push(entry);
                        continue;
                    }
                }
                Err(e) => self.ui.log(format!(
                    "Discarded an unreadable deferred initial message: {}",
                    describe(&e)
                )),
            }
            batch.dirty = true;
        }
        if batch.dirty {
            let grant_peers = std::mem::take(&mut batch.grant_peers);
            let upgrades = self.save_initial_batch(inner, batch).await?;
            Ok(Some((upgrades, grant_peers)))
        } else {
            Ok(None)
        }
    }

    /// Join the peer's pending carried initials. Each removal commits with its prekeys, session
    /// and history, returning any staged `grant_peers` for lock-free registration outside
    /// `self.inner`.
    pub(super) async fn join_carried(
        &self,
        inner: &mut Inner<impl VaultStore>,
        peer: &PublicKey,
    ) -> Result<JoinCarriedOutcome, String> {
        inner.check_isolation(peer)?;
        let Some(index) = inner.contacts.iter().position(|c| c.peer == *peer) else {
            return Ok(JoinCarriedOutcome::default());
        };
        if inner.contacts[index].is_new_quarantined() {
            return Ok(JoinCarriedOutcome::default());
        }
        // A prior join may have consumed prekeys and staged history after a failed save.
        if inner.needs_save() {
            inner.save(&[]).await.map_err(|e| describe(&e))?;
        }
        let mut recommend_upgrade: Option<u64> = None;
        let mut grant_peers = BTreeSet::new();
        loop {
            let contact = &inner.contacts[index];
            let next = contact.deferred_carried;
            let Some(bytes) = contact.state.pending_carried_initials.get(next) else {
                break;
            };
            let mut batch = InitialBatch::default();
            if let Some(message) = Incoming::decode_carried(bytes) {
                if self.process_initial(inner, peer, &message, &mut batch)
                    == InitialOutcome::DeferUnsupportedSuite
                {
                    inner.contacts[index].deferred_carried += 1;
                    continue;
                }
            } else {
                self.ui.log(format!(
                    "Discarded an unreadable carried initial message for {}.",
                    short(peer)
                ));
            }
            let bytes = inner.contacts[index]
                .state
                .pending_carried_initials
                .remove(next);
            let saved_carried_ts = inner.carried_deferred_timestamps.clone();
            prune_carried_timestamps_for_contacts(
                &mut inner.carried_deferred_timestamps,
                inner.contacts.iter(),
                inner.isolated_contacts.iter(),
            );
            if batch.dirty {
                let staged = std::mem::take(&mut batch.grant_peers);
                if let Some(&conv_gen) = self.save_initial_batch(inner, batch).await?.get(peer) {
                    recommend_upgrade = Some(conv_gen);
                }
                grant_peers.extend(staged);
            } else if let Err(e) = inner.save(&[]).await {
                // Nothing consumed a prekey. Retry the original entry if storage recovers.
                inner.contacts[index]
                    .state
                    .pending_carried_initials
                    .insert(next, bytes);
                inner.carried_deferred_timestamps = saved_carried_ts;
                return Err(describe(&e));
            }
        }
        Ok(JoinCarriedOutcome {
            recommend_upgrade,
            has_deferred: inner.contacts[index].deferred_carried > 0,
            grant_peers,
        })
    }

    pub(super) fn process_initial(
        &self,
        inner: &mut Inner<impl VaultStore>,
        peer: &PublicKey,
        message: &Incoming,
        batch: &mut InitialBatch,
    ) -> InitialOutcome {
        if *peer == inner.client.identity_key() {
            self.ui
                .log("dropped an initial message claiming to be from your own key");
            return InitialOutcome::Ack;
        }
        if inner.is_isolated_peer(peer) {
            if inner.is_pq_incompatible_isolated_peer(peer) {
                self.ui.log(format!(
                    "Deferred initial message from {}: existing contact uses a post-quantum suite unsupported by this build.",
                    short(peer)
                ));
                return InitialOutcome::DeferUnsupportedSuite;
            }
            if let Err(reason) = inner.check_isolation(peer) {
                self.ui.log(reason);
            }
            return InitialOutcome::Ack;
        }
        if message.pq_suite().is_some_and(|s| !s.is_supported()) {
            self.ui.log(format!(
                "Deferred initial message from {}: unsupported post-quantum suite.",
                short(peer)
            ));
            return InitialOutcome::DeferUnsupportedSuite;
        }
        let opened = match inner.open_initial(peer, message) {
            Ok(opened) => opened,
            Err(e) => {
                if e.kind() == ErrorKind::UnsupportedSuite {
                    self.ui.log(format!(
                        "Deferred initial message from {}: {}",
                        short(peer),
                        describe(&e)
                    ));
                    return InitialOutcome::DeferUnsupportedSuite;
                }
                self.ui.log(format!(
                    "dropped an initial message claiming to be from {}: {}",
                    short(peer),
                    describe(&e)
                ));
                // Only authenticated policy failures can set an alert. Preserve healthy PQ chats.
                if let Some(contact) = inner.contact(peer)
                    && !contact.has_healthy_pq_session()
                {
                    batch.dirty |= contact.record_policy_error(e.kind());
                }
                return InitialOutcome::Ack;
            }
        };
        batch.dirty = true; // Accepting also commits prekey consumption, even if the merge is rejected.
        let OpenedInitial {
            session,
            first_message,
            quarantine,
        } = opened;
        let local_pq = inner.local_pq_enabled();
        let incoming_hello_downgrade = quarantine.is_none()
            && local_pq
            && !session.security().is_some_and(|s| s.is_pq)
            && matches!(
                Content::from_bytes(&first_message).kind,
                Some(Kind::Hello(ref hello)) if hello.pq_capable
            );
        let server_now = inner.client.clock().now();
        let existing = inner.contacts.iter().position(|c| c.peer == *peer);
        let contact = match existing {
            Some(index) => {
                let server = inner.server.clone();
                let contact = &mut inner.contacts[index];
                let is_pq = session.security().is_some_and(|security| security.is_pq);
                // R18-P1-1 + R19-P1-4: Never allow an inbound classical session to replace or
                // auto-register write tokens on a peer with an active PQ pin, active downgrade
                // alarm, or an authenticated `Hello` claiming `pq_capable == true`.
                let hard_blocked_downgrade = !is_pq
                    && local_pq
                    && (incoming_hello_downgrade
                        || session.peer_pq_state().downgrade_detected
                        || super::classical_hard_blocked_by_pin_or_downgrade(
                            contact.session.peer_pq_state(),
                        )
                        || contact.state.security_alert == SECURITY_ALERT_DOWNGRADE);
                let effective_quarantine = quarantine.or_else(|| {
                    hard_blocked_downgrade.then_some(
                        incoming_hello_downgrade
                            || (contact.session.peer_pq_state().pq_pinned
                                && (contact.session.peer_pq_state().peer_pq_capable
                                    || contact.session.peer_pq_state().pinned_manifest_seq == 0)),
                    )
                });
                if let Some(pinned) = effective_quarantine {
                    let high_water = contact
                        .session
                        .peer_session_seq()
                        .max(if contact.is_new_quarantined() {
                            contact.session.active_peer_session_seq()
                        } else {
                            0
                        })
                        .max(
                            contact
                                .state
                                .quarantined_session
                                .as_ref()
                                .map_or(0, |s| s.active_peer_session_seq),
                        );
                    let incoming_seq = session.active_peer_session_seq();
                    if high_water > 0 && (incoming_seq == 0 || incoming_seq <= high_water) {
                        self.ui.log(format!(
                            "ignored stale classical session request from {}",
                            short(peer)
                        ));
                        return InitialOutcome::Ack;
                    }
                    let downgrade = pinned
                        || hard_blocked_downgrade
                        || session.peer_pq_state().downgrade_detected;
                    contact.record_quarantined_initial(
                        Some(session.state().into()),
                        first_message,
                        pinned,
                        downgrade,
                        now(),
                    );
                    self.ui.log(format!(
                        "quarantined classical session request from {} pending approval",
                        short(peer)
                    ));
                    return InitialOutcome::Ack;
                }
                let incoming_token_hash = session.active_inbound_token_hash();
                let was_quarantined = contact.state.quarantined;
                // Do not archive an unapproved primary classical session into `others` when
                // replacing a brand-new quarantined contact with an accepted session.
                let discarded_primary: Option<session::proto::SessionState> =
                    if contact.is_new_quarantined() {
                        let saved = contact.session.state().into();
                        contact.session.discard_active();
                        Some(saved)
                    } else {
                        None
                    };
                let auto_register_grant = match contact.replace_session(session, local_pq) {
                    Ok(took_over) => {
                        if is_pq || took_over || was_quarantined {
                            contact.clear_quarantine_and_alerts();
                            if was_quarantined {
                                batch.unquarantined.insert(*peer);
                            }
                        }
                        if took_over && contact.state.needs_requeue_sealed {
                            batch.requeue.insert(*peer);
                        }
                        // Already-approved contacts auto-register write-token grants for rekeys;
                        // unaccepted requests, quarantined contacts, and provisional cancelled
                        // `start_chat` contacts wait for explicit approval.
                        (!contact.state.request
                            && !contact.state.quarantined
                            && !contact.state.provisional)
                            .then_some(took_over)
                    }
                    Err(e) => {
                        if let Some(saved) = discarded_primary
                            && let Ok(restored) = session::SessionState::try_from(&saved)
                        {
                            contact.session =
                                session::Session::restore(Fetch::client(&server), restored);
                        }
                        self.ui.log(format!(
                            "rejected incoming session from {}: {}",
                            short(peer),
                            describe(&e)
                        ));
                        contact.record_policy_error(e.kind());
                        return InitialOutcome::Ack;
                    }
                };
                if let (Some(pin_active), Some(token_hash)) =
                    (auto_register_grant, incoming_token_hash)
                    && inner
                        .stage_write_token_grant(peer, token_hash, pin_active)
                        .is_ok()
                {
                    batch.grant_peers.insert(*peer);
                }
                &mut inner.contacts[index]
            }
            None => {
                let conversation_gen = inner.allocate_conversation_gen();
                let mut contact = Contact {
                    peer: *peer,
                    session,
                    deferred_carried: 0,
                    state: ContactState {
                        peer: peer.to_vec(),
                        request: true,
                        greeting_delivery: GREETING_DELIVERY_CONFIRMED,
                        conversation_gen,
                        ..Default::default()
                    },
                };
                if let Some(pinned) = quarantine {
                    contact.state.quarantined_primary = true;
                    let downgrade = pinned || contact.session.peer_pq_state().downgrade_detected;
                    contact.record_quarantined_initial(
                        None,
                        first_message,
                        pinned,
                        downgrade,
                        now(),
                    );
                    inner.contacts.push(contact);
                    self.ui.log(format!(
                        "quarantined classical chat request from {} pending approval",
                        short(peer)
                    ));
                    return InitialOutcome::Ack;
                }
                self.ui.log(format!("chat request from {}", short(peer)));
                inner.contacts.push(contact);
                inner.contacts.last_mut().expect("just pushed")
            }
        };
        batch.touched_peers.insert(*peer);
        let content = Content::from_bytes(&first_message);
        if let Some(Kind::Hello(ref hello)) = content.kind {
            let check = contact.session.check_peer_hello(hello, local_pq);
            // If an incoming classical initial lost a crossed-start tie-break against a local
            // classical session, `replace_session` already merged its `peer_pq` state (including
            // `downgrade_detected`), while `check_peer_hello` sees the already-advanced sequence.
            let crossed_downgrade = incoming_hello_downgrade && !contact.has_healthy_pq_session();
            if check.downgrade_detected || crossed_downgrade {
                contact.state.security_alert = SECURITY_ALERT_DOWNGRADE;
                if local_pq
                    && (check.recommend_start_again || crossed_downgrade)
                    && !contact.state.request
                    && !contact.state.quarantined
                {
                    batch.upgrades.insert(*peer, contact.state.conversation_gen);
                }
            }
        }
        // Defer read receipts until `save_initial_batch` confirms the chat is open and visible.
        let (index, entry) = match contact.add_received_at(content, false, server_now) {
            Ok(record) => record,
            Err(reason) => {
                self.ui.log(format!(
                    "Skipped initial message history entry for {}. {reason}",
                    short(peer)
                ));
                return InitialOutcome::Ack;
            }
        };
        if self.ui.open.get_untracked() == Some(*peer) {
            let (counts_unread, clock) = entry_read_tracking(&entry);
            batch.views.push((
                *peer,
                contact.message_at(index, entry.clone(), server_now),
                DisplayedEntry {
                    index,
                    counts_unread,
                    clock,
                },
            ));
        }
        batch.records.push((*peer, index, entry));
        InitialOutcome::Ack
    }

    pub(super) async fn save_initial_batch(
        &self,
        inner: &mut Inner<impl VaultStore>,
        mut batch: InitialBatch,
    ) -> Result<BTreeMap<PublicKey, u64>, String> {
        let vgen = self.vault_gen();
        let mut outgoing = vec![];
        let mut changed = vec![];
        let mut requeued_outcomes = vec![];
        for peer in batch.requeue {
            match inner.requeue_sealed(&peer).await {
                Ok(outcome) => {
                    if self.shutting_down.get() || crate::glue::lock_released() {
                        return Ok(BTreeMap::new());
                    }
                    outcome.log_missing(&self.ui, &peer);
                    outgoing.extend(outcome.outbox.clone());
                    batch.records.extend(records(&peer, &outcome.history));
                    changed.push((peer, outcome.history.clone()));
                    requeued_outcomes.push((peer, outcome));
                }
                // replace_session set the durable gate. flush retries before pushing any ciphertext.
                Err(e) => {
                    if self.shutting_down.get() || crate::glue::lock_released() {
                        return Ok(BTreeMap::new());
                    }
                    self.ui.log(format!(
                        "could not requeue pending messages for {} (will retry): {e}",
                        short(&peer)
                    ));
                }
            }
        }
        inner.save_inbox_changes(batch.records, outgoing).await?;
        if self.shutting_down.get() || crate::glue::lock_released() {
            return Ok(BTreeMap::new());
        }
        for (peer, outcome) in &requeued_outcomes {
            self.finalize_requeue_gone(vgen, inner, peer, outcome).await;
            if !self.is_live(vgen) {
                return Ok(BTreeMap::new());
            }
        }
        for (peer, history) in changed {
            self.show_changes(inner, &peer, &history);
        }
        if let Some(open) = self.ui.open.get_untracked() {
            let mut views = Vec::new();
            let mut displayed_entries = Vec::new();
            for (peer, view, displayed) in batch.views {
                if peer == open {
                    views.push(view);
                    displayed_entries.push(displayed);
                }
            }
            let showed_views = !views.is_empty();
            self.show_new(inner, &open, views);
            if batch.unquarantined.contains(&open) {
                if showed_views {
                    self.record_displayed_entries(&open, &displayed_entries);
                }
                if super::is_page_visible()
                    && self.acknowledge_displayed_window(inner, &open)
                    && let Err(e) = inner.save_state().await
                    && !self.shutting_down.get()
                    && !crate::glue::lock_released()
                {
                    self.ui.notify(describe(&e));
                }
            } else if showed_views {
                self.acknowledge_appended_displayed(inner, &open, &displayed_entries)
                    .await;
            }
        }
        if !self.shutting_down.get() && !crate::glue::lock_released() {
            self.refresh_contacts(inner);
        }
        Ok(batch.upgrades)
    }

    /// Execute a full signed-prekey + manifest publish serialized under `self.publish_lock` while
    /// releasing `self.inner` across network RTTs, preserving the structured [`ErrorKind`] so
    /// [`set_pq_config`](Self::set_pq_config) can distinguish definitive server refusals from
    /// transient network/sign-in failures.
    pub(super) async fn publish_full(
        &self,
        vgen: u64,
        now_anyway: bool,
    ) -> Result<(), PublishError> {
        let _publish_guard = self.publish_lock.lock().await;
        self.publish_full_locked(vgen, now_anyway).await
    }

    /// Reconcile an interrupted or ambiguous local publish (`has_unreconciled_publish()`) against
    /// our own signed `CapabilityManifest` stored on the relay before preparing a new rotation.
    ///
    /// Caller MUST hold `self.publish_lock` and `self.inbox_lock` and MUST NOT hold `self.inner`.
    ///
    /// Returns `Ok(true)` when reconciliation alone already satisfied a non-forced publish
    /// (`!now_anyway` and the landed relay manifest matches current `PqConfig` and is fresh), or
    /// `Ok(false)` when Phase 1 should proceed to prepare & transmit a publish.
    async fn reconcile_pending_publish_locked(
        &self,
        vgen: u64,
        now_anyway: bool,
        allow_scheduled_rotation: bool,
    ) -> Result<bool, PublishError> {
        let probe_inputs = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err(PublishError::locked());
            }
            let Some(inner) = guard.as_ref() else {
                return Err(PublishError::locked());
            };
            inner.client.has_unreconciled_publish().then(|| {
                (
                    inner.server.clone(),
                    inner.audience.clone(),
                    inner.client.identity_key(),
                )
            })
        };
        let Some((server, audience, own_id)) = probe_inputs else {
            return Ok(false);
        };
        let resp = Fetch::client(&server)
            .get_manifest(GetManifestRequest {
                identity_key: bytes::Bytes::copy_from_slice(&own_id),
            })
            .await
            .map_err(|e| {
                let err = session::Error::from(e);
                self.check_protocol_error(ProtocolRpcScope::CoreV2, &err);
                PublishError::transmitted(err)
            })?;
        if !self.is_live(vgen) {
            return Err(PublishError::locked());
        }
        let verified_manifest: Option<CapabilityManifest> = match resp.manifest {
            Some(manifest) => {
                let verified_id = verify_manifest(&manifest, &audience)
                    .map_err(|e| PublishError::prepare(session::Error::from(e)))?;
                if verified_id != own_id {
                    return Err(PublishError::prepare(session::Error::from(
                        ErrorKind::InvalidKeys,
                    )));
                }
                Some(manifest)
            }
            None => None,
        };
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Err(PublishError::locked());
        }
        let Some(inner) = guard.as_mut() else {
            return Err(PublishError::locked());
        };
        let prev_seq = inner.client.manifest_seq();
        let prev_gen = inner.client.prekey_generation();
        let (mut preserve_spks, mut preserve_digests) = preserved_deferred_prekeys(inner, now());
        let inbox_ready_for_eviction = allow_scheduled_rotation
            && self.inbox_drained_clean.get()
            && inner.state.pending_inbox_acks.is_empty();
        let landed_meta = verified_manifest.as_ref().and_then(|m| {
            let digest = session::protocol::handshake_v2::manifest_digest(m).ok()?;
            let spk = PublicKey::try_from(m.signed_prekey.as_ref()).ok()?;
            Some((digest, spk))
        });
        preserve_undrained_inbox_prekeys_for_commit_with(
            inner,
            inbox_ready_for_eviction,
            landed_meta,
            &mut preserve_spks,
            &mut preserve_digests,
        );
        if let Some(m) = verified_manifest.as_ref() {
            let mut relay_suites = BTreeSet::new();
            if m.pq_enabled {
                for &raw in &m.offered_suites {
                    if let Some(suite) = u8::try_from(raw).ok().and_then(PqSuite::from_u8) {
                        relay_suites.insert(suite);
                    }
                }
            }
            inner.confirmed_relay_pq_suites = Some(relay_suites);
        }
        let landed = inner.client.reconcile_interrupted_publish(
            verified_manifest.as_ref(),
            &preserve_spks,
            &preserve_digests,
        );
        if landed {
            let m = verified_manifest
                .as_ref()
                .expect("landed requires a verified relay manifest");
            let now_ms = now();
            let effective_now = inner
                .client
                .clock()
                .trusted_clock_pair()
                .map(|(l, s)| l.max(s))
                .unwrap_or_else(|_| now_ms.max(inner.client.clock().now()));
            let manifest_age_ms = effective_now.saturating_sub(m.issued_at);
            let manifest_fresh = m.expires_at > effective_now && manifest_age_ms <= REPUBLISH_AGE;
            // Anchor `published_at` to the landed manifest's signed `issued_at` (never `now()`)
            // and preserve local OPK usage counters so an expired/old reconciled manifest renews
            // immediately and OPK refills are never starved.
            inner.state.published_at = now_ms.saturating_sub(manifest_age_ms).max(1);
            inner.last_server_classical_opks = None;
            inner.last_server_pq_opks_by_suite = None;
            inner.relay_classical_opk_queue = None;
            inner.relay_claimed_classical_opks.clear();
            inner.accepted_classical_since_baseline.clear();
            inner.relay_pq_opk_queue_by_suite = None;
            inner.relay_claimed_pq_opks_by_suite.clear();
            inner.accepted_pq_since_baseline.clear();
            let matches_config =
                manifest_matches_local_config(m, inner.client.pq_config(), &inner.server_pq);
            if matches_config && manifest_fresh {
                self.startup.on_publish_succeeded();
                inner.state.needs_publish = false;
                inner.state.pending_pq_rollback = None;
                inner.deferred_refill_rejected_pq_suites.clear();
                inner.classical_fallback_probe_pending = false;
                inner.classical_fallback_probe_cooldown_until = 0;
                inner.pq_fallback_probe_pending.clear();
                inner.pq_fallback_probe_cooldown_until.clear();
                inner.save_state().await.map_err(PublishError::storage)?;
                if self.is_live(vgen) {
                    self.ui.me.set(Some(inner.me()));
                    self.ui
                        .log("reconciled previously interrupted prekey publication with server");
                }
                return Ok(!now_anyway);
            }
            // R7-P2-4: Persist `needs_publish = true` whenever the landed manifest mismatches
            // local config or is stale/expired so Phase 1 immediately renews it (even when
            // `manifest_age_ms <= REPUBLISH_AGE` or the inbox has undrained items).
            inner.state.needs_publish = true;
            inner.save_state().await.map_err(PublishError::storage)?;
            if !self.is_live(vgen) {
                return Err(PublishError::locked());
            }
            return Ok(false);
        }
        // Publish has NOT landed on the relay (or is still in flight): `reconcile_interrupted_publish`
        // kept `publishing = true`, the prepared generation/digest (and recorded the verified
        // relay manifest digest as confirmed), and the durable `manifest_seq` high-water mark so
        // Phase 1 immediately reuses the prepared generation at `seq + 1`.
        if verified_manifest.is_some()
            || inner.client.manifest_seq() != prev_seq
            || inner.client.prekey_generation() != prev_gen
        {
            inner.save_state().await.map_err(PublishError::storage)?;
            if !self.is_live(vgen) {
                return Err(PublishError::locked());
            }
        }
        Ok(false)
    }

    /// Core lock-free full publish helper. Caller MUST hold `self.publish_lock` and MUST NOT hold
    /// `self.inner`.
    pub(super) async fn publish_full_locked(
        &self,
        vgen: u64,
        now_anyway: bool,
    ) -> Result<(), PublishError> {
        self.publish_full_locked_gated(vgen, now_anyway, true)
            .await
            .map(|_| ())
    }

    async fn publish_full_locked_gated(
        &self,
        vgen: u64,
        now_anyway: bool,
        allow_scheduled_rotation: bool,
    ) -> Result<PublishFullOutcome, PublishError> {
        // Mandatory renewal threshold (25 days < 30-day manifest TTL) so an expired or
        // near-expired manifest always renews in place even when scheduled SPK rotation is
        // deferred by an undrained inbox (`R7-P2-4`).
        const MANIFEST_RENEW_MANDATORY_AGE: u64 = 25 * 24 * 60 * 60 * 1000;

        if !self.is_live(vgen) {
            return Err(PublishError::locked());
        }
        // R7-P1-4: Serialize destructive prekey publication/reconciliation behind `inbox_lock`
        // (preserving acyclic lock DAG `peer_flush_lock -> publish_lock -> inbox_lock -> inner`)
        // so manual or settings-triggered publishes can never prune `G1` while an in-flight
        // `ListInitialMessages` has already marked a `G1` greeting `listed = 1`.
        let _inbox_guard = self.inbox_lock.lock().await;
        if !self.is_live(vgen) {
            return Err(PublishError::locked());
        }
        // Reconcile any interrupted/ambiguous prior publish against our own signed `GetManifest`
        // BEFORE preparing a new rotation so a displaced SPK `G` or rolling manifest digest `D`
        // that the relay still retains is never lost across reloads or transport errors.
        if self
            .reconcile_pending_publish_locked(vgen, now_anyway, allow_scheduled_rotation)
            .await?
        {
            return Ok(PublishFullOutcome::Published);
        }
        // Phase 1 under `self.inner`: re-verify schedule/pause state under `publish_lock`,
        // prepare signed manifest + prekeys (retaining the prior SPKs and digests in `ClientState`
        // until confirmed commit), and persist to IndexedDB BEFORE releasing `self.inner` (H-2).
        let (server, strict_pq, mut prepared, pre_classical_used, pre_pq_used, pre_pq_by_suite) = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err(PublishError::locked());
            }
            let Some(inner) = guard.as_mut() else {
                return Err(PublishError::locked());
            };
            let has_unreconciled = inner.client.has_unreconciled_publish();
            let now_ms = now();
            let manifest_near_expiry = inner.state.published_at > 0
                && now_ms.saturating_sub(inner.state.published_at) >= MANIFEST_RENEW_MANDATORY_AGE;
            if !now_anyway {
                let needs_v2_manifest =
                    inner.client.manifest_seq() == 0 || inner.client.prekey_generation() == 0;
                let full_due = inner.state.published_at == 0
                    || inner.state.needs_publish
                    || needs_v2_manifest
                    || has_unreconciled
                    || manifest_near_expiry
                    || now_ms.saturating_sub(inner.state.published_at) > REPUBLISH_AGE;
                if !full_due || self.startup.is_publish_paused() {
                    return Ok(PublishFullOutcome::Deferred);
                }
            }
            let (mut preserve_spks, mut preserve_digests) =
                preserved_deferred_prekeys(inner, now_ms);
            let is_scheduled_rotation = !now_anyway
                && !inner.state.needs_publish
                && !has_unreconciled
                && !manifest_near_expiry
                && inner.state.published_at > 0
                && inner.client.manifest_seq() > 0
                && inner.client.prekey_generation() > 0;
            let inbox_ready_for_eviction = allow_scheduled_rotation
                && self.inbox_drained_clean.get()
                && inner.state.pending_inbox_acks.is_empty();
            if is_scheduled_rotation && !inbox_ready_for_eviction {
                self.ui.log(
                    "Deferred scheduled prekey rotation until pending inbox initial messages are acknowledged.",
                );
                return Ok(PublishFullOutcome::Deferred);
            }
            // R7-P1-4 + R8-P0-1: When the inbox has not cleanly drained yet, pin BOTH
            // `oldest_evictable_signed_prekey` AND every locally retained manifest digest so
            // repeated publishes can never destroy a key or manifest digest referenced by an
            // unseen `listed = 1` inbox row.
            preserve_undrained_inbox_prekeys(
                inner,
                inbox_ready_for_eviction,
                &mut preserve_spks,
                &mut preserve_digests,
            );
            let has_spare_digest = inner
                .client
                .has_spare_manifest_digest_slot_for_publish(&preserve_spks, &preserve_digests);
            // Never evict a pinned deferred, retained-SPK, or undrained-inbox manifest digest on an
            // automatic publish (including age-based renewal or pending settings change) when a
            // confirmed generation already exists and no digest slot is spare (`R3-P2-6`, `R8-P2-7`,
            // `R9-P2-4`, `R9-P2-5`). Keep `needs_publish` pending and return `Deferred` so
            // non-rotating OPK refills still replenish the confirmed generation.
            if !now_anyway
                && !has_unreconciled
                && inner.state.published_at > 0
                && inner.client.manifest_seq() > 0
                && inner.client.prekey_generation() > 0
                && !has_spare_digest
            {
                self.ui.log(
                    "Deferred prekey publication: all manifest digest slots are pinned by deferred, active-SPK, or pending inbox initial messages.",
                );
                return Ok(PublishFullOutcome::Deferred);
            }
            let pre_classical_used = inner.state.used_one_time_prekeys;
            let pre_pq_used = inner.state.used_pq_one_time_prekeys;
            let pre_pq_by_suite = inner.used_pq_by_suite.clone();
            let prepared = inner
                .client
                .prepare_publish_v2_preserving(
                    &inner.audience,
                    ONE_TIME_PREKEYS,
                    PQ_ONE_TIME_PREKEYS,
                    &preserve_spks,
                    &preserve_digests,
                )
                .map_err(|e| {
                    if e.kind() == ErrorKind::ClockSkew {
                        self.warn_clock_skew(inner.client.clock().offset_ms());
                    }
                    PublishError::prepare(e)
                })?;
            // H-2: Persist new prekeys & manifest state BEFORE transmitting; roll back in-memory
            // prekeys if storage fails so never-transmitted rotations are not committed later.
            if let Err(e) = inner.save(&[]).await {
                inner.client.rollback_publish_v2_on_refusal(prepared);
                return Err(PublishError::storage(e));
            }
            if !self.is_live(vgen) {
                return Err(PublishError::locked());
            }
            (
                inner.server.clone(),
                inner.client.pq_config().strict_pq,
                prepared,
                pre_classical_used,
                pre_pq_used,
                pre_pq_by_suite,
            )
        };

        // Phase 2 outside `self.inner`: transmit signed publish over the network (and handle
        // runtime `PQ_ENABLED="false"` fallback by re-acquiring `self.inner` strictly to prepare
        // and persist the classical-OFF manifest before the second RTT).
        // R24-P1-1: Suppress the global `REFUSED` sign-in hook so a background/stale publish 403
        // cannot hijack an unrelated active `start_chat` or a newly unlocked vault.
        let first_outcome = session::transmit_publish_v2_with(
            &Fetch::client_without_refused_hook(&server),
            &prepared,
            strict_pq,
        )
        .await;
        if !self.is_live(vgen) {
            return Err(PublishError::locked());
        }
        let outcome = match first_outcome {
            Ok(PublishV2Outcome::ServerPqDisabled) => {
                let off_strict_pq = {
                    let mut guard = self.lock_inner().await;
                    if !self.is_live(vgen) {
                        return Err(PublishError::locked());
                    }
                    let Some(inner) = guard.as_mut() else {
                        return Err(PublishError::locked());
                    };
                    // R28-P2-3: `PublishV2` #1 passed Worker sign-in auth before returning
                    // `Unimplemented` -> `ServerPqDisabled`; clear latched origin waits and
                    // non-waiting `ui.held` rows immediately before classical-OFF preparation or
                    // the second transmit (which might fail with `ClockSkew`, IDB, or 5xx).
                    if same_server(&inner.server, &origin()) {
                        self.on_origin_auth_proven_locked(vgen, inner);
                    }
                    let (mut preserve_spks, mut preserve_digests) =
                        preserved_deferred_prekeys(inner, now());
                    let inbox_ready_for_eviction = allow_scheduled_rotation
                        && self.inbox_drained_clean.get()
                        && inner.state.pending_inbox_acks.is_empty();
                    preserve_undrained_inbox_prekeys(
                        inner,
                        inbox_ready_for_eviction,
                        &mut preserve_spks,
                        &mut preserve_digests,
                    );
                    prepared = match inner
                        .client
                        .prepare_publish_v2_classical_off(prepared, &preserve_digests)
                    {
                        Ok(off_prepared) => off_prepared,
                        Err(e) => {
                            if e.kind() == ErrorKind::ClockSkew {
                                self.warn_clock_skew(inner.client.clock().offset_ms());
                            }
                            // `prepare_publish_v2_classical_off` already rolled back `prepared` in
                            // memory; persist the rollback so IndexedDB stays consistent with memory.
                            return self
                                .finish_publish_rollback(
                                    inner,
                                    PublishError::prepare(e),
                                    now_anyway,
                                )
                                .await
                                .map(|()| PublishFullOutcome::Deferred);
                        }
                    };
                    if let Err(e) = inner.save(&[]).await {
                        inner.client.rollback_publish_v2_on_refusal(prepared);
                        inner.state.needs_publish = true;
                        inner.unsaved_state = true;
                        let _ = inner.save_state().await;
                        return Err(PublishError::storage(e));
                    }
                    if !self.is_live(vgen) {
                        return Err(PublishError::locked());
                    }
                    inner.client.pq_config().strict_pq
                };
                let second = session::transmit_publish_v2_with(
                    &Fetch::client_without_refused_hook(&server),
                    &prepared,
                    off_strict_pq,
                )
                .await;
                if !self.is_live(vgen) {
                    return Err(PublishError::locked());
                }
                second
            }
            other => other,
        };

        // Phase 3 under `self.inner`: commit (pruning superseded generations & rolling digests
        // now that the relay has confirmed the new manifest) or roll back on definitive refusal.
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Err(PublishError::locked());
        }
        let Some(inner) = guard.as_mut() else {
            return Err(PublishError::locked());
        };
        match outcome {
            Ok(outcome @ (PublishV2Outcome::V2Pq | PublishV2Outcome::V2ClassicalOff)) => {
                // Record actual published OPK counts (as baseline BEFORE deducting concurrent
                // consumption, which remains in `used_*_one_time_prekeys` / `used_pq_by_suite` so
                // each consumption delta is deducted exactly once — R7-P3-1).
                let published_classical = prepared.request.one_time_prekeys.len() as u32;
                let published_classical_keys: Vec<PublicKey> = prepared
                    .request
                    .one_time_prekeys
                    .iter()
                    .filter_map(|raw| PublicKey::try_from(raw.as_ref()).ok())
                    .collect();
                let published_classical_set: std::collections::HashSet<PublicKey> =
                    published_classical_keys.iter().copied().collect();
                let mut published_pq_by_suite: std::collections::BTreeMap<PqSuite, u32> =
                    std::collections::BTreeMap::new();
                let mut published_pq_queues: std::collections::BTreeMap<
                    PqSuite,
                    std::collections::VecDeque<session::PqPrekeyId>,
                > = std::collections::BTreeMap::new();
                let mut published_pq_sets: std::collections::BTreeMap<
                    PqSuite,
                    std::collections::HashSet<session::PqPrekeyId>,
                > = std::collections::BTreeMap::new();
                if matches!(outcome, PublishV2Outcome::V2Pq) {
                    for suite in inner.client.pq_config().offered_suites() {
                        published_pq_by_suite.insert(suite, 0);
                        published_pq_queues.insert(suite, std::collections::VecDeque::new());
                    }
                    for pk in &prepared.request.pq_one_time_prekeys {
                        if let Some(suite) = u8::try_from(pk.suite).ok().and_then(PqSuite::from_u8)
                        {
                            *published_pq_by_suite.entry(suite).or_insert(0) += 1;
                            if let Ok(id) = session::PqPrekeyId::try_from(pk.prekey_id.as_ref()) {
                                published_pq_queues.entry(suite).or_default().push_back(id);
                                published_pq_sets.entry(suite).or_default().insert(id);
                            }
                        }
                    }
                }
                let (mut preserve_spks, mut preserve_digests) =
                    preserved_deferred_prekeys(inner, now());
                let inbox_ready_for_eviction = allow_scheduled_rotation
                    && self.inbox_drained_clean.get()
                    && inner.state.pending_inbox_acks.is_empty();
                let landed_meta = prepared.request.manifest.as_ref().and_then(|m| {
                    let digest = session::protocol::handshake_v2::manifest_digest(m).ok()?;
                    let spk = PublicKey::try_from(m.signed_prekey.as_ref()).ok()?;
                    Some((digest, spk))
                });
                preserve_undrained_inbox_prekeys_for_commit_with(
                    inner,
                    inbox_ready_for_eviction,
                    landed_meta,
                    &mut preserve_spks,
                    &mut preserve_digests,
                );
                inner.client.commit_publish_v2_preserving(
                    prepared,
                    &preserve_spks,
                    &preserve_digests,
                );
                self.startup.on_publish_succeeded();
                if same_server(&inner.server, &origin()) {
                    self.on_origin_auth_proven_locked(vgen, inner);
                }
                let concurrent_classical = inner
                    .state
                    .used_one_time_prekeys
                    .saturating_sub(pre_classical_used);
                let concurrent_pq = inner
                    .state
                    .used_pq_one_time_prekeys
                    .saturating_sub(pre_pq_used);
                let mut next_used_pq_by_suite = std::collections::BTreeMap::new();
                for (&suite, &after) in &inner.used_pq_by_suite {
                    let delta =
                        after.saturating_sub(pre_pq_by_suite.get(&suite).copied().unwrap_or(0));
                    if delta > 0 {
                        next_used_pq_by_suite.insert(suite, delta);
                    }
                }
                inner.used_pq_by_suite = next_used_pq_by_suite;
                inner.state.used_pq_one_time_prekeys = concurrent_pq;
                inner.last_server_classical_opks = Some(published_classical);
                inner.relay_classical_opk_queue =
                    Some(std::collections::VecDeque::from(published_classical_keys));
                inner.relay_claimed_classical_opks.clear();
                inner
                    .accepted_classical_since_baseline
                    .retain(|k| published_classical_set.contains(k));
                inner.relay_claimed_pq_opks_by_suite.clear();
                inner.accepted_pq_since_baseline.retain(|suite, ids| {
                    if let Some(published) = published_pq_sets.get(suite) {
                        ids.retain(|id| published.contains(id));
                        !ids.is_empty()
                    } else {
                        false
                    }
                });
                inner.deferred_refill_rejected_pq_suites.clear();
                inner.classical_fallback_probe_pending = false;
                inner.classical_fallback_probe_cooldown_until = 0;
                inner.pq_fallback_probe_pending.clear();
                inner.pq_fallback_probe_cooldown_until.clear();
                let log_msg = match outcome {
                    PublishV2Outcome::V2Pq => {
                        inner.confirmed_relay_pq_suites =
                            Some(published_pq_by_suite.keys().copied().collect());
                        inner.last_server_pq_opks_by_suite = Some(published_pq_by_suite);
                        inner.relay_pq_opk_queue_by_suite = Some(published_pq_queues);
                        if inner.server_pq == ServerPqStatus::Disabled {
                            inner.set_server_pq(ServerPqStatus::Unknown);
                        } else {
                            // Bump epoch so any older in-flight `GetServerInfo` returning
                            // `Disabled` cannot overwrite a verified PQ publish (`R7-P3-2`).
                            inner.bump_server_pq_epoch();
                        }
                        "published post-quantum + classical prekeys and signed capability manifest"
                    }
                    PublishV2Outcome::V2ClassicalOff => {
                        inner.confirmed_relay_pq_suites = Some(BTreeSet::new());
                        inner.last_server_pq_opks_by_suite =
                            Some(std::collections::BTreeMap::new());
                        inner.relay_pq_opk_queue_by_suite = Some(std::collections::BTreeMap::new());
                        if inner.local_pq_enabled() {
                            inner.set_server_pq(ServerPqStatus::Disabled);
                            "published classical prekeys and signed PQ-off capability manifest (server PQ disabled)"
                        } else {
                            inner.bump_server_pq_epoch();
                            "published classical prekeys and signed PQ-off capability manifest"
                        }
                    }
                    PublishV2Outcome::ServerPqDisabled => unreachable!(),
                };
                inner
                    .save_full_publish_success(concurrent_classical)
                    .await
                    .map_err(PublishError::storage)?;
                if self.is_live(vgen) {
                    self.ui.me.set(Some(inner.me()));
                    self.ui.log(log_msg);
                }
                Ok(PublishFullOutcome::Published)
            }
            Ok(PublishV2Outcome::ServerPqDisabled) => {
                if same_server(&inner.server, &origin()) {
                    self.on_origin_auth_proven_locked(vgen, inner);
                }
                inner.client.rollback_publish_v2_on_refusal(prepared);
                self.finish_publish_rollback(
                    inner,
                    PublishError::prepare(session::Error::from(ErrorKind::Protocol)),
                    now_anyway,
                )
                .await
                .map(|()| PublishFullOutcome::Deferred)
            }
            Err(e) => {
                // R28-P2-3: `ErrorKind::DowngradeDetected` from `transmit_publish_v2_with` is
                // only produced by `check_server_info_with` strictly after `PublishV2` passed
                // Worker sign-in auth and returned `Unimplemented`.
                if same_server(&inner.server, &origin())
                    && ((e.is_server_refusal() && e.kind() != ErrorKind::SignInRequired)
                        || e.kind() == ErrorKind::DowngradeDetected)
                {
                    self.on_origin_auth_proven_locked(vgen, inner);
                }
                self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                let error = PublishError::transmitted(e);
                if error.definitive_refusal {
                    inner.client.rollback_publish_v2_on_refusal(prepared);
                    self.finish_publish_rollback(inner, error, now_anyway)
                        .await
                        .map(|()| PublishFullOutcome::Deferred)
                } else {
                    Err(error)
                }
            }
        }
    }

    pub(super) async fn finish_publish_rollback(
        &self,
        inner: &mut Inner<impl VaultStore>,
        mut error: PublishError,
        now_anyway: bool,
    ) -> Result<(), PublishError> {
        let live = !self.shutting_down.get() && !crate::glue::lock_released();
        if error.needs_sign_in() {
            self.startup.set_publish_waits_sign_in(true);
            if live && same_server(&inner.server, &origin()) {
                self.ask_sign_in_for(!now_anyway);
            }
        }
        if error.rejects_settings() {
            if error.kind == Some(ErrorKind::PqRequired) {
                inner.set_server_pq(ServerPqStatus::Disabled);
                if live {
                    self.ui.me.set(Some(inner.me()));
                }
            }
            if let Some(rollback) = inner.state.pending_pq_rollback.clone() {
                match inner.client.set_pq_config(rollback.config()) {
                    Ok(()) => {
                        inner.state.needs_publish = rollback.previous_needs_publish;
                        inner.state.pending_pq_rollback = None;
                        for flag in rollback.contact_flags {
                            if let Ok(peer) = PublicKey::try_from(flag.peer.as_slice())
                                && let Some(contact) = inner.contact(&peer)
                                && contact.state.conversation_gen == flag.conversation_gen
                            {
                                if let Some(alert) = flag.prev_security_alert
                                    && contact.state.security_alert == SECURITY_ALERT_NONE
                                {
                                    contact.state.security_alert = alert;
                                }
                                if let Some(approval) = flag.prev_classical_approval
                                    && contact.state.classical_approval_needed
                                        == CLASSICAL_APPROVAL_NONE
                                {
                                    contact.state.classical_approval_needed = approval;
                                }
                            }
                        }
                        if live {
                            self.ui.me.set(Some(inner.me()));
                            self.refresh_contacts(inner);
                            self.ui.log("The server refused the pending post-quantum settings. Restored the previous settings.");
                        }
                    }
                    Err(e) => {
                        inner.state.needs_publish = false;
                        self.startup.set_publish_waits_settings(true);
                        error.message.push_str(&format!(
                            ". Could not restore previous settings: {}. Adjust post-quantum settings in Settings to retry.",
                            describe(&e)
                        ));
                    }
                }
            } else {
                inner.state.needs_publish = false;
                self.startup.set_publish_waits_settings(true);
                let guidance = "The server refused the current post-quantum settings; automatic prekey publishing is paused. Open Settings to adjust post-quantum settings and retry.";
                if live {
                    self.ui.log(format!("{guidance} ({})", error.message));
                    if !now_anyway {
                        self.ui.notify(guidance);
                    }
                }
                error
                    .message
                    .push_str(". Adjust post-quantum settings in Settings or retry manually.");
            }
        }
        if let Err(e) = inner.save_state().await {
            inner.unsaved_state = true;
            // Keep a definitive settings refusal even if saving the prekey rollback also failed.
            if error.rejects_settings() {
                error.message.push_str(&format!(
                    ". Failed to save publish rollback (will retry): {}",
                    describe(&e)
                ));
            } else {
                return Err(PublishError::storage(e));
            }
        } else if error.needs_sign_in() && !now_anyway {
            return Ok(());
        }
        Err(error)
    }

    /// Try one lock-free non-rotating v2 refill. Caller MUST hold `self.publish_lock` and MUST NOT
    /// hold `self.inner`. When `pq_counts` is non-empty and the relay has runtime PQ disabled,
    /// returns `Ok(RefillV2Outcome::PqDisabled)` so the caller can retry with classical OPKs only.
    async fn try_refill_v2_locked(
        &self,
        vgen: u64,
        classical_count: usize,
        pq_counts: &[(PqSuite, usize)],
    ) -> Result<RefillV2Outcome, String> {
        // R8-P2-8: Serialize non-rotating OPK refills behind `inbox_lock` (preserving acyclic
        // `publish_lock -> inbox_lock -> Engine::inner`) so notification-driven inbox accepts
        // cannot overlap `RefillPrekeys` and double-count pre-refill claims already reflected in
        // the relay response.
        let _inbox_guard = self.inbox_lock.lock().await;
        if !self.is_live(vgen) {
            return Ok(RefillV2Outcome::Handled);
        }
        let wants_pq = pq_counts.iter().any(|(_, c)| *c > 0);
        // Phase 1 under `self.inner`: prepare & persist newly generated OPKs before transmitting.
        let (
            server,
            audience,
            prepared,
            pre_classical_used,
            pre_pq_used,
            pre_pq_by_suite,
            pre_accepted_classical,
            pre_accepted_pq,
            added_classical_keys,
            mut added_pq_ids_by_suite,
        ) = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(RefillV2Outcome::Handled);
            }
            let Some(inner) = guard.as_mut() else {
                return Ok(RefillV2Outcome::Handled);
            };
            let pre_classical_used = inner.state.used_one_time_prekeys;
            let pre_pq_used = inner.state.used_pq_one_time_prekeys;
            let pre_pq_by_suite = inner.used_pq_by_suite.clone();
            let pre_accepted_classical = inner.accepted_classical_since_baseline.clone();
            let pre_accepted_pq = inner.accepted_pq_since_baseline.clone();
            let prepared = inner
                .client
                .prepare_refill_v2_per_suite(&inner.audience, classical_count, pq_counts)
                .map_err(|e| describe(&e))?;
            if prepared.request.one_time_prekeys.is_empty()
                && prepared.request.pq_one_time_prekeys.is_empty()
            {
                inner.client.rollback_refill_v2_on_refusal(prepared);
                return Ok(RefillV2Outcome::Handled);
            }
            let added_classical_keys: Vec<PublicKey> = prepared
                .request
                .one_time_prekeys
                .iter()
                .filter_map(|raw| PublicKey::try_from(raw.as_ref()).ok())
                .collect();
            let mut added_pq_ids_by_suite: std::collections::BTreeMap<
                PqSuite,
                Vec<session::PqPrekeyId>,
            > = std::collections::BTreeMap::new();
            for pk in &prepared.request.pq_one_time_prekeys {
                if let Some(suite) = u8::try_from(pk.suite).ok().and_then(PqSuite::from_u8)
                    && let Ok(id) = session::PqPrekeyId::try_from(pk.prekey_id.as_ref())
                {
                    added_pq_ids_by_suite.entry(suite).or_default().push(id);
                }
            }
            if let Err(e) = inner.save(&[]).await {
                inner.client.rollback_refill_v2_on_refusal(prepared);
                return Err(describe(&e));
            }
            if !self.is_live(vgen) {
                return Ok(RefillV2Outcome::Handled);
            }
            (
                inner.server.clone(),
                inner.audience.clone(),
                prepared,
                pre_classical_used,
                pre_pq_used,
                pre_pq_by_suite,
                pre_accepted_classical,
                pre_accepted_pq,
                added_classical_keys,
                added_pq_ids_by_suite,
            )
        };

        // Phase 2 outside `self.inner`: transmit `RefillPrekeys` (and confirm `GetServerInfo` on
        // `Unimplemented` when `wants_pq`) without holding `self.inner`.
        // R24-P1-1: Suppress global `REFUSED` sign-in hook so background/stale refill 403s cannot
        // hijack an active `start_chat` or newly unlocked vault.
        let refill_res = session::transmit_refill_v2_with(
            &Fetch::client_without_refused_hook(&server),
            &prepared,
        )
        .await;
        if !self.is_live(vgen) {
            return Ok(RefillV2Outcome::Handled);
        }
        let server_info_probe = match &refill_res {
            Err(e) if e.is_server_refusal() && e.kind() == ErrorKind::Unimplemented && wants_pq => {
                let res = session::check_server_info_with(&Fetch::client(&server), &audience).await;
                if !self.is_live(vgen) {
                    return Ok(RefillV2Outcome::Handled);
                }
                Some(res)
            }
            _ => None,
        };

        // Phase 3 under `self.inner`: commit or roll back `prepared` and persist state.
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Ok(RefillV2Outcome::Handled);
        }
        let Some(inner) = guard.as_mut() else {
            return Ok(RefillV2Outcome::Handled);
        };
        let sent_classical = !prepared.request.one_time_prekeys.is_empty();
        let sent_pq = !prepared.request.pq_one_time_prekeys.is_empty();
        let response = match refill_res {
            Ok(response) => {
                if same_server(&inner.server, &origin()) {
                    self.on_origin_auth_proven_locked(vgen, inner);
                }
                response
            }
            Err(e) if !e.is_server_refusal() => {
                // R11-P2-3: Ambiguous transport/timeout/5xx failure may have committed the batch on
                // the relay; invalidate FIFO queue tracking for every pool included in this batch
                // so the next refill cannot silently operate on a shifted FIFO key order.
                if sent_classical {
                    inner.relay_classical_opk_queue = None;
                    inner.relay_claimed_classical_opks.clear();
                    inner.accepted_classical_since_baseline.clear();
                }
                if sent_pq {
                    for suite in added_pq_ids_by_suite.keys() {
                        if let Some(pq_queues) = inner.relay_pq_opk_queue_by_suite.as_mut() {
                            pq_queues.remove(suite);
                        }
                        inner.relay_claimed_pq_opks_by_suite.remove(suite);
                        inner.accepted_pq_since_baseline.remove(suite);
                    }
                }
                return Err(describe(&e));
            }
            Err(e) => {
                if same_server(&inner.server, &origin()) && e.kind() != ErrorKind::SignInRequired {
                    self.on_origin_auth_proven_locked(vgen, inner);
                }
                inner.client.rollback_refill_v2_on_refusal(prepared);
                let outcome = match e.kind() {
                    ErrorKind::SignInRequired => {
                        self.startup.set_publish_waits_sign_in(true);
                        if self.is_live(vgen) && same_server(&inner.server, &origin()) {
                            self.ask_sign_in_background();
                        }
                        Ok(RefillV2Outcome::Handled)
                    }
                    ErrorKind::LimitExceeded if sent_classical && sent_pq => {
                        // R8-P2-9: Relay enforces classical and PQ caps independently and rejects
                        // a mixed batch atomically without revealing which pool is full. Do NOT
                        // fabricate full counts for either pool; let the caller retry each pool
                        // separately so the non-full pool replenishes and restores authoritative
                        // relay counts for both pools.
                        Ok(RefillV2Outcome::MixedLimitExceeded)
                    }
                    ErrorKind::LimitExceeded => {
                        let total_sent = if sent_classical {
                            added_classical_keys.len()
                        } else {
                            added_pq_ids_by_suite.values().map(Vec::len).sum()
                        };
                        if total_sent > 1 {
                            // R13-P2-5: A batch > 1 may straddle the relay's 100-key cap while
                            // free slots still exist (e.g. suite A = 0, suite B = 95, 10-key A
                            // batch > 100). Retry once with 1 key before treating the pool as
                            // completely full or installing a fallback probe cooldown.
                            Ok(RefillV2Outcome::RetryProbeSingleKey)
                        } else {
                            let cooldown_until =
                                now().saturating_add(OPK_FALLBACK_PROBE_COOLDOWN_MS);
                            if sent_classical {
                                if std::mem::take(&mut inner.classical_fallback_probe_pending) {
                                    inner.classical_fallback_probe_cooldown_until = cooldown_until;
                                }
                                inner.state.used_one_time_prekeys = 0;
                                inner.relay_classical_opk_queue = None;
                                inner.relay_claimed_classical_opks.clear();
                                inner.accepted_classical_since_baseline.clear();
                                inner.last_server_classical_opks =
                                    Some(SERVER_MAX_ONE_TIME_PREKEYS as u32);
                            }
                            if sent_pq {
                                // R13-P3-1: Shared 100-key PQ cap is confirmed completely full
                                // (0 slots left); drain ALL pending PQ fallback probes into
                                // cooldown so skipped secondary suites cannot dangle.
                                for suite in std::mem::take(&mut inner.pq_fallback_probe_pending) {
                                    inner
                                        .pq_fallback_probe_cooldown_until
                                        .insert(suite, cooldown_until);
                                }
                                inner.state.used_pq_one_time_prekeys = 0;
                                inner.used_pq_by_suite.clear();
                                inner.relay_pq_opk_queue_by_suite = None;
                                inner.relay_claimed_pq_opks_by_suite.clear();
                                inner.accepted_pq_since_baseline.clear();
                                // R8-P2-9 (Gemini P3-1): Distribute the shared 100-key cap across
                                // ALL offered suites instead of assigning 100% to `offered[0]` so
                                // claims on secondary suites (e.g. `MlKem768`) still reduce
                                // `total_est_rem` and trigger future replenishment.
                                let mut full_map = std::collections::BTreeMap::new();
                                let offered = inner.client.pq_config().offered_suites();
                                if !offered.is_empty() {
                                    let n = offered.len() as u32;
                                    let base = (SERVER_MAX_PQ_ONE_TIME_PREKEYS as u32) / n;
                                    let rem = (SERVER_MAX_PQ_ONE_TIME_PREKEYS as u32) % n;
                                    for (idx, &suite) in offered.iter().enumerate() {
                                        let share = base + if idx == 0 { rem } else { 0 };
                                        full_map.insert(suite, share);
                                    }
                                }
                                inner.last_server_pq_opks_by_suite = Some(full_map);
                            }
                            self.ui
                                .log("server one-time prekey pool is already full; skipped refill");
                            Ok(RefillV2Outcome::Handled)
                        }
                    }
                    ErrorKind::Unimplemented if wants_pq => match server_info_probe {
                        Some(Ok(info)) if !info.pq_enabled => {
                            inner.set_server_pq(ServerPqStatus::Disabled);
                            if inner.client.pq_config().strict_pq {
                                Err(describe(&e))
                            } else {
                                Ok(RefillV2Outcome::PqDisabled)
                            }
                        }
                        Some(Ok(_)) => {
                            self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                            Err(describe(&e))
                        }
                        Some(Err(info_err))
                            if should_require_update_for_rpc(
                                ProtocolRpcScope::CoreV2,
                                &info_err,
                            ) =>
                        {
                            self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                            Err(describe(&e))
                        }
                        Some(Err(info_err)) => Err(describe(&info_err)),
                        None => Err(describe(&e)),
                    },
                    ErrorKind::Unimplemented => {
                        self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                        Err(describe(&e))
                    }
                    ErrorKind::Protocol
                        if sent_pq && inner.state.needs_publish && e.is_protocol_malformed() =>
                    {
                        // R10-P2-1 + R11-P3-2 + R12-P2-6: When a settings/suite change is pending
                        // in `needs_publish`, the relay's confirmed manifest may reject a newly
                        // enabled PQ suite with `InvalidArgument` / `Malformed` (`SuiteNotOffered`).
                        // Only cache definitive `Malformed` refusals (never transient
                        // `StaleTimestamp` / `InvalidSignature`) so subsequent syncs skip only
                        // genuinely unoffered suites while multi-suite batches are probed singly.
                        inner.state.needs_publish = true;
                        if added_pq_ids_by_suite.len() == 1
                            && let Some(&suite) = added_pq_ids_by_suite.keys().next()
                        {
                            inner.deferred_refill_rejected_pq_suites.insert(suite);
                        }
                        Ok(RefillV2Outcome::SuiteMismatchNeedsClassicalOnly)
                    }
                    ErrorKind::NotFound | ErrorKind::Protocol => {
                        inner.state.needs_publish = true;
                        Err(describe(&e))
                    }
                    _ => Err(describe(&e)),
                };
                inner.save_state().await.map_err(|e| describe(&e))?;
                if self.is_live(vgen) {
                    self.ui.me.set(Some(inner.me()));
                }
                return outcome;
            }
        };
        inner.client.commit_refill_v2(prepared);
        let mut server_pq_map = std::collections::BTreeMap::new();
        // R11-P2-2: Worker SQL `GROUP BY suite` omits 0-row exhausted suites. Seed `0` for suites
        // confirmed advertised on the relay (or all local offered suites when `!needs_publish`),
        // never overwriting `confirmed_relay_pq_suites` from `RefillPrekeysResponse`.
        if let Some(confirmed_suites) = inner.confirmed_relay_pq_suites.as_ref() {
            for &suite in confirmed_suites {
                server_pq_map.insert(suite, 0);
            }
        } else if !inner.state.needs_publish {
            for suite in inner.client.pq_config().offered_suites() {
                server_pq_map.insert(suite, 0);
            }
        }
        for sc in &response.pq_one_time_counts {
            if let Some(suite) = u8::try_from(sc.suite).ok().and_then(PqSuite::from_u8) {
                server_pq_map.insert(suite, sc.count);
            }
        }
        // R8-P2-8 + R10-P2-5 + R11-P2-4: Reconcile concurrent RTT accepts and delayed pre-refill
        // relay claims using the exact FIFO OPK/PQOPK queue order (`ORDER BY position LIMIT 1`).
        // Popped keys not yet accepted locally are tracked by exact key ID so abandoned pre-refill
        // claims can never hide newer post-refill depletion. When queue state is unknown (e.g.
        // after reload or an ambiguous refill failure), retain `raw_concurrent` conservatively with
        // zero ambiguous carry-forward credits so abandoned pre-refill claims can never erase
        // genuine post-snapshot RTT consumption.
        const MAX_TRACKED_OPK_CLAIMS: usize = 1024;
        let cooldown_until = now().saturating_add(OPK_FALLBACK_PROBE_COOLDOWN_MS);
        let added_classical_len = added_classical_keys.len() as u32;
        if (sent_classical || response.classical_one_time_count > 0)
            && std::mem::take(&mut inner.classical_fallback_probe_pending)
        {
            // R12-P2-4 + R13-P3-1: If the relay's authoritative count shows stocked classical
            // OPKs (`count > added`, including when a PQ-only refill observed `count > 0`), the
            // fallback greeting was throttled by the hourly budget rather than an empty pool;
            // apply a 1-hour probe cooldown and clear the pending flag.
            if response.classical_one_time_count > added_classical_len {
                inner.classical_fallback_probe_cooldown_until = cooldown_until;
            }
        }
        let raw_concurrent_classical = inner
            .state
            .used_one_time_prekeys
            .saturating_sub(pre_classical_used);
        let concurrent_classical = if let Some(queue) = inner.relay_classical_opk_queue.as_mut()
            && queue.len().saturating_add(added_classical_keys.len())
                >= response.classical_one_time_count as usize
        {
            let rtt_accepted: std::collections::HashSet<PublicKey> = inner
                .accepted_classical_since_baseline
                .iter()
                .copied()
                .filter(|k| !pre_accepted_classical.contains(k))
                .collect();
            queue.extend(added_classical_keys);
            let popped_count = queue
                .len()
                .saturating_sub(response.classical_one_time_count as usize);
            for _ in 0..popped_count {
                if let Some(key) = queue.pop_front()
                    && !inner.accepted_classical_since_baseline.contains(&key)
                    && inner.relay_claimed_classical_opks.len() < MAX_TRACKED_OPK_CLAIMS
                {
                    inner.relay_claimed_classical_opks.insert(key);
                }
            }
            let still_in_queue: std::collections::HashSet<PublicKey> = rtt_accepted
                .into_iter()
                .filter(|k| queue.contains(k))
                .collect();
            let count = still_in_queue.len() as u32;
            inner.accepted_classical_since_baseline = still_in_queue;
            count
        } else {
            inner.relay_classical_opk_queue = None;
            inner.relay_claimed_classical_opks.clear();
            inner.accepted_classical_since_baseline.clear();
            raw_concurrent_classical
        };

        let mut all_pq_suites = BTreeSet::new();
        all_pq_suites.extend(server_pq_map.keys().copied());
        all_pq_suites.extend(inner.used_pq_by_suite.keys().copied());
        all_pq_suites.extend(inner.relay_claimed_pq_opks_by_suite.keys().copied());
        if let Some(pq_queues) = inner.relay_pq_opk_queue_by_suite.as_ref() {
            all_pq_suites.extend(pq_queues.keys().copied());
        }
        let mut next_used_pq_by_suite = std::collections::BTreeMap::new();
        let mut any_pq_untracked = false;
        for suite in all_pq_suites {
            let resp_s = server_pq_map.get(&suite).copied().unwrap_or(0);
            let added_ids = added_pq_ids_by_suite.remove(&suite).unwrap_or_default();
            let added_pq_len = added_ids.len() as u32;
            if (added_pq_len > 0 || resp_s > 0) && inner.pq_fallback_probe_pending.remove(&suite) {
                // R12-P2-4 + R13-P3-1: Stocked relay PQOPKs before our probe batch (or observed
                // by a classical-only refill with `resp_s > 0`) indicate hourly budget throttling
                // rather than an empty pool; apply a 1-hour cooldown for this suite.
                if resp_s > added_pq_len {
                    inner
                        .pq_fallback_probe_cooldown_until
                        .insert(suite, cooldown_until);
                }
            }
            if let Some(pq_queues) = inner.relay_pq_opk_queue_by_suite.as_mut()
                && let Some(queue) = pq_queues.get_mut(&suite)
                && queue.len().saturating_add(added_ids.len()) >= resp_s as usize
            {
                let accepted_s = inner
                    .accepted_pq_since_baseline
                    .remove(&suite)
                    .unwrap_or_default();
                let pre_accepted_s = pre_accepted_pq.get(&suite);
                let rtt_accepted_s: std::collections::HashSet<session::PqPrekeyId> = accepted_s
                    .iter()
                    .copied()
                    .filter(|id| !pre_accepted_s.is_some_and(|pre| pre.contains(id)))
                    .collect();
                queue.extend(added_ids);
                let popped_count = queue.len().saturating_sub(resp_s as usize);
                for _ in 0..popped_count {
                    if let Some(id) = queue.pop_front()
                        && !accepted_s.contains(&id)
                    {
                        let claimed = inner
                            .relay_claimed_pq_opks_by_suite
                            .entry(suite)
                            .or_default();
                        if claimed.len() < MAX_TRACKED_OPK_CLAIMS {
                            claimed.insert(id);
                        }
                    }
                }
                let still_in_queue: std::collections::HashSet<session::PqPrekeyId> = rtt_accepted_s
                    .into_iter()
                    .filter(|id| queue.contains(id))
                    .collect();
                let effective_delta = still_in_queue.len() as u32;
                if !still_in_queue.is_empty() {
                    inner
                        .accepted_pq_since_baseline
                        .insert(suite, still_in_queue);
                }
                if effective_delta > 0 {
                    next_used_pq_by_suite.insert(suite, effective_delta);
                }
            } else {
                any_pq_untracked = true;
                if let Some(pq_queues) = inner.relay_pq_opk_queue_by_suite.as_mut() {
                    pq_queues.remove(&suite);
                }
                inner.relay_claimed_pq_opks_by_suite.remove(&suite);
                inner.accepted_pq_since_baseline.remove(&suite);
                let after = inner.used_pq_by_suite.get(&suite).copied().unwrap_or(0);
                let pre_s = pre_pq_by_suite.get(&suite).copied().unwrap_or(0);
                let delta = after.saturating_sub(pre_s);
                if delta > 0 {
                    next_used_pq_by_suite.insert(suite, delta);
                }
            }
        }
        let raw_concurrent_pq = inner
            .state
            .used_pq_one_time_prekeys
            .saturating_sub(pre_pq_used);
        let tracked_concurrent_pq = next_used_pq_by_suite
            .values()
            .copied()
            .fold(0u32, u32::saturating_add);
        let concurrent_pq = if any_pq_untracked {
            raw_concurrent_pq.max(tracked_concurrent_pq)
        } else {
            tracked_concurrent_pq
        };

        // R13-P3-1: Never leave stale pending fallback probes dangling for non-offered suites or
        // suites already proven stocked in `server_pq_map`.
        let offered_now = inner.client.pq_config().offered_suites();
        inner
            .pq_fallback_probe_pending
            .retain(|s| offered_now.contains(s) && server_pq_map.get(s).copied().unwrap_or(0) == 0);
        // Record authoritative relay counts as the single baseline BEFORE deducting concurrent
        // consumption deltas, and reset `used_*` to those reconciled concurrent deltas so each
        // claim is deducted once and never twice (`R7-P3-1`, `R8-P2-8`, `R10-P2-5`), retaining
        // per-suite counts (`R7-P2-5`).
        // R14-P2-4: Preserve the `REFILL_USED` floor for any fallback probe still pending after a
        // partial/single-pool refill so reload does not strand a persisted probe with `used_* == 0`.
        let final_classical_used = if inner.classical_fallback_probe_pending {
            concurrent_classical.max(REFILL_USED)
        } else {
            concurrent_classical
        };
        let mut final_pq_used = concurrent_pq;
        for &suite in &inner.pq_fallback_probe_pending {
            let entry = next_used_pq_by_suite.entry(suite).or_insert(0);
            *entry = (*entry).max(REFILL_USED);
            final_pq_used = final_pq_used.max(REFILL_USED);
        }
        inner.last_server_classical_opks = Some(response.classical_one_time_count);
        inner.last_server_pq_opks_by_suite = Some(server_pq_map);
        inner.state.used_one_time_prekeys = final_classical_used;
        inner.state.used_pq_one_time_prekeys = final_pq_used;
        inner.used_pq_by_suite = next_used_pq_by_suite;
        if sent_pq {
            // R8-P2-10: Mirror `publish_full_locked_gated` — a successful PQ refill proves the
            // relay accepted PQ prekeys, so clear any stale `Disabled` status to `Unknown` (and
            // bump epoch) so subsequent refills and settings saves are not wedged on `Disabled`.
            if inner.server_pq == ServerPqStatus::Disabled {
                inner.set_server_pq(ServerPqStatus::Unknown);
            } else {
                inner.bump_server_pq_epoch();
            }
        }
        inner.save_state().await.map_err(|e| describe(&e))?;
        if self.is_live(vgen) {
            self.ui.me.set(Some(inner.me()));
            self.ui
                .log("replenished one-time prekeys without rotating signed prekey");
        }
        Ok(RefillV2Outcome::Handled)
    }

    /// Compute the headroom-clamped non-rotating OPK/PQOPK refill batch under `inner`, resetting
    /// stale local usage counters when the relay is already confirmed at its 100-key cap.
    async fn plan_refill_batch_locked(
        &self,
        inner: &mut Inner<V>,
    ) -> Result<(usize, Vec<(PqSuite, usize)>), String> {
        if !inner.state.needs_publish && !inner.deferred_refill_rejected_pq_suites.is_empty() {
            inner.deferred_refill_rejected_pq_suites.clear();
        }
        let offered_suites: Vec<PqSuite> = if inner.local_pq_enabled()
            && inner.server_pq != ServerPqStatus::Disabled
        {
            let mut suites: Vec<PqSuite> = inner
                .client
                .pq_config()
                .offered_suites()
                .iter()
                .copied()
                .filter(|&suite| inner.client.has_current_pq_last_resort(suite))
                .collect();
            if inner.state.needs_publish {
                // R10-P2-1 + R11-P2-2 + R11-P3-2: When a settings/suite change is pending in
                // `needs_publish`, restrict PQ refills to suites confirmed advertised on the
                // relay's current manifest (separate from `last_server_pq_opks_by_suite` so
                // exhausted 0-row suites are never dropped) and skip suites already refused by
                // the relay so subsequent syncs do not repeat refused RPCs.
                if inner
                    .state
                    .pending_pq_rollback
                    .as_ref()
                    .is_some_and(|rb| !rb.pq_enabled)
                {
                    suites.clear();
                } else if let Some(confirmed) = inner.confirmed_relay_pq_suites.as_ref() {
                    suites.retain(|suite| confirmed.contains(suite));
                }
                suites.retain(|suite| !inner.deferred_refill_rejected_pq_suites.contains(suite));
            }
            // R13-P3-1: Prioritize suites with pending fallback probes ahead of routine refills so
            // a primary suite cannot starve a secondary suite's probe of the remaining headroom.
            suites.sort_by_key(|suite| !inner.pq_fallback_probe_pending.contains(suite));
            suites
        } else {
            vec![]
        };
        let classical_headroom = inner.client.remaining_one_time_headroom();
        let mut pq_headroom = inner.client.remaining_pq_one_time_headroom();
        let (raw_classical, raw_pq_per_suite) = refill_batch_counts_per_suite(
            inner.state.used_one_time_prekeys,
            inner.state.used_pq_one_time_prekeys,
            &inner.used_pq_by_suite,
            &offered_suites,
            inner.last_server_classical_opks,
            inner.last_server_pq_opks_by_suite.as_ref(),
        );
        let mut classical_count = raw_classical.min(classical_headroom);
        let mut pq_counts = Vec::with_capacity(raw_pq_per_suite.len());
        for &(suite, raw_count) in &raw_pq_per_suite {
            let take = raw_count.min(pq_headroom);
            if take > 0 {
                pq_counts.push((suite, take));
                pq_headroom = pq_headroom.saturating_sub(take);
            }
        }
        // R14-P2-5: Do not silently discard a pending fallback probe solely because a stale
        // full-pool baseline estimates zero relay headroom (e.g. a remote claim consumed another
        // suite's key before its greeting arrived). Issue a bounded 1-key probe to the relay first
        // so either a free slot is used + counts refresh, or `LimitExceeded` proves the cap full
        // and applies the 1-hour cooldown.
        if classical_count == 0 && inner.classical_fallback_probe_pending && classical_headroom > 0
        {
            classical_count = 1;
        }
        if pq_counts.is_empty()
            && pq_headroom > 0
            && let Some(&probe_suite) = offered_suites.iter().find(|suite| {
                inner.pq_fallback_probe_pending.contains(suite)
                    && inner
                        .last_server_pq_opks_by_suite
                        .as_ref()
                        .is_none_or(|m| m.get(suite).copied().unwrap_or(0) == 0)
            })
        {
            pq_counts.push((probe_suite, 1));
        }
        // If server is already at its 100-key cap, reset counters so sync doesn't loop.
        if classical_count == 0 && pq_counts.is_empty() {
            let classical_low = inner.state.used_one_time_prekeys >= REFILL_USED;
            let pq_low = !inner.state.needs_publish
                && !offered_suites.is_empty()
                && inner.state.used_pq_one_time_prekeys >= REFILL_USED;
            let mut cleared = false;
            if classical_low && raw_classical == 0 {
                inner.state.used_one_time_prekeys = 0;
                inner.classical_fallback_probe_pending = false;
                cleared = true;
            }
            if pq_low && raw_pq_per_suite.is_empty() {
                inner.state.used_pq_one_time_prekeys = 0;
                inner.used_pq_by_suite.clear();
                inner.pq_fallback_probe_pending.clear();
                cleared = true;
            }
            if cleared {
                inner.save_state().await.map_err(|e| describe(&e))?;
            }
        }
        Ok((classical_count, pq_counts))
    }

    /// Publish new prekeys (SPK rotation / PQ manifest) if due or requested, or replenish low
    /// OPKs/PQOPKs WITHOUT rotating SPK via non-rotating refill. Always persists newly generated
    /// private keys to IndexedDB BEFORE transmitting over the network (H-2).
    pub async fn publish(&self, now_anyway: bool) -> Result<(), String> {
        self.publish_with_rotation_gate(now_anyway, true).await
    }

    /// Like [`Self::publish`], allowing `sync()` to defer scheduled SPK rotations (while still
    /// running mandatory publishes and non-rotating OPK refills) whenever inbox draining left
    /// unacknowledged items on the relay.
    pub(super) async fn publish_with_rotation_gate(
        &self,
        now_anyway: bool,
        allow_scheduled_rotation: bool,
    ) -> Result<(), String> {
        const MANIFEST_RENEW_MANDATORY_AGE: u64 = 25 * 24 * 60 * 60 * 1000;

        let vgen = self.vault_gen();
        // Serialize BOTH full publishes and non-rotating OPK refills under `publish_lock`
        // (preserving `publish_lock -> inbox_lock -> self.inner`) so overlapping sync/manual/settings
        // publishes never double-rotate SPKs or race `RefillPrekeys` against an in-flight `PublishV2`.
        let _publish_guard = self.publish_lock.lock().await;
        if !self.is_live(vgen) {
            return Ok(());
        }
        let should_try_full = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(());
            }
            let Some(inner) = guard.as_ref() else {
                return Ok(());
            };
            let now_ms = now();
            let needs_v2_manifest =
                inner.client.manifest_seq() == 0 || inner.client.prekey_generation() == 0;
            let manifest_near_expiry = inner.state.published_at > 0
                && now_ms.saturating_sub(inner.state.published_at) >= MANIFEST_RENEW_MANDATORY_AGE;
            let mandatory_full = now_anyway
                || inner.state.published_at == 0
                || inner.state.needs_publish
                || needs_v2_manifest
                || manifest_near_expiry
                || inner.client.has_unreconciled_publish();
            let scheduled_full = allow_scheduled_rotation
                && self.inbox_drained_clean.get()
                && inner.state.pending_inbox_acks.is_empty()
                && now_ms.saturating_sub(inner.state.published_at) > REPUBLISH_AGE;
            mandatory_full || scheduled_full
        };
        if should_try_full {
            if self.startup.is_publish_paused() && !now_anyway {
                return Ok(());
            }
            if now_anyway {
                self.startup.set_publish_waits_settings(false);
            }
            match self
                .publish_full_locked_gated(vgen, now_anyway, allow_scheduled_rotation)
                .await
            {
                Ok(PublishFullOutcome::Published) => return Ok(()),
                Ok(PublishFullOutcome::Deferred) => {
                    // R8-P2-7: When automatic full rotation/renewal is deferred (e.g. undrained
                    // inbox or 144 pinned digests), fall through to non-rotating OPK refill unless
                    // `now_anyway` was requested or an unreconciled publish is still pending.
                    if now_anyway {
                        return Ok(());
                    }
                }
                Err(_) if !self.is_live(vgen) => return Ok(()),
                Err(e) => return Err(e.message),
            }
        }

        // M-5: Non-rotating OPK/PQOPK refill (does NOT rotate SPK!).
        if !self.is_live(vgen) || self.startup.is_publish_paused() {
            return Ok(());
        }
        let refill_plan = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(());
            }
            let Some(inner) = guard.as_mut() else {
                return Ok(());
            };
            if inner.state.published_at == 0
                || inner.client.manifest_seq() == 0
                || inner.client.prekey_generation() == 0
                || inner.client.has_unreconciled_publish()
            {
                return Ok(());
            }
            self.plan_refill_batch_locked(inner).await?
        };
        let (classical_count, pq_counts) = refill_plan;
        if classical_count == 0 && pq_counts.is_empty() {
            return Ok(());
        }
        match self
            .try_refill_v2_locked(vgen, classical_count, &pq_counts)
            .await?
        {
            RefillV2Outcome::Handled => Ok(()),
            RefillV2Outcome::PqDisabled => {
                // A PQ-disabled v2 server can still accept a classical-only v2 refill.
                if classical_count > 0 && !pq_counts.is_empty() && self.is_live(vgen) {
                    let _ = self
                        .try_refill_v2_locked(vgen, classical_count, &[])
                        .await?;
                }
                Ok(())
            }
            RefillV2Outcome::SuiteMismatchNeedsClassicalOnly => {
                // R10-P2-1 + R11-P3-2: A relay whose confirmed manifest predates a deferred local
                // PQ suite change can still accept a classical-only refill, and if multiple PQ
                // suites were attempted, probe each PQ suite singly so valid advertised suites
                // refill while unadvertised suites are recorded in `deferred_refill_rejected_pq_suites`.
                if classical_count > 0 && !pq_counts.is_empty() && self.is_live(vgen) {
                    let _ = self
                        .try_refill_v2_locked(vgen, classical_count, &[])
                        .await?;
                }
                if pq_counts.len() > 1 && self.is_live(vgen) && !self.startup.is_publish_paused() {
                    for &(suite, count) in &pq_counts {
                        if !self.is_live(vgen) || self.startup.is_publish_paused() {
                            break;
                        }
                        let _ = self
                            .try_refill_v2_locked(vgen, 0, &[(suite, count)])
                            .await?;
                    }
                }
                Ok(())
            }
            RefillV2Outcome::RetryProbeSingleKey => {
                // R13-P2-5: Single-pool refill batch (> 1 key) hit `LimitExceeded`; retry ONCE
                // with a 1-key probe to recover exact authoritative relay counts and use any
                // remaining shared-cap headroom before declaring the pool completely full.
                if classical_count > 1 && pq_counts.is_empty() && self.is_live(vgen) {
                    if matches!(
                        self.try_refill_v2_locked(vgen, 1, &[]).await?,
                        RefillV2Outcome::Handled
                    ) && self.is_live(vgen)
                        && !self.startup.is_publish_paused()
                    {
                        let rem_classical = {
                            let mut guard = self.lock_inner().await;
                            match guard.as_mut() {
                                Some(inner) if self.is_live(vgen) => {
                                    self.plan_refill_batch_locked(inner).await?.0
                                }
                                _ => 0,
                            }
                        };
                        if rem_classical > 0 && self.is_live(vgen) {
                            let _ = self.try_refill_v2_locked(vgen, rem_classical, &[]).await?;
                        }
                    }
                } else if classical_count == 0
                    && let Some(&(suite, _)) = pq_counts.first()
                    && self.is_live(vgen)
                    && matches!(
                        self.try_refill_v2_locked(vgen, 0, &[(suite, 1)]).await?,
                        RefillV2Outcome::Handled
                    )
                    && self.is_live(vgen)
                    && !self.startup.is_publish_paused()
                {
                    let rem_pq = {
                        let mut guard = self.lock_inner().await;
                        match guard.as_mut() {
                            Some(inner) if self.is_live(vgen) => {
                                self.plan_refill_batch_locked(inner).await?.1
                            }
                            _ => vec![],
                        }
                    };
                    if !rem_pq.is_empty() && self.is_live(vgen) {
                        let _ = self.try_refill_v2_locked(vgen, 0, &rem_pq).await?;
                    }
                }
                Ok(())
            }
            RefillV2Outcome::MixedLimitExceeded => {
                // R8-P2-9 + R13-P2-5: Retry classical-only first (with 1-key probe fallback on
                // cap-straddling `LimitExceeded`); if it succeeds, it updates authoritative counts
                // for BOTH pools so we recompute the PQ batch before attempting PQ-only.
                if classical_count > 0
                    && self.is_live(vgen)
                    && !self.startup.is_publish_paused()
                    && matches!(
                        self.try_refill_v2_locked(vgen, classical_count, &[])
                            .await?,
                        RefillV2Outcome::RetryProbeSingleKey
                    )
                    && self.is_live(vgen)
                    && !self.startup.is_publish_paused()
                    && matches!(
                        self.try_refill_v2_locked(vgen, 1, &[]).await?,
                        RefillV2Outcome::Handled
                    )
                    && self.is_live(vgen)
                    && !self.startup.is_publish_paused()
                {
                    let rem_classical = {
                        let mut guard = self.lock_inner().await;
                        match guard.as_mut() {
                            Some(inner) if self.is_live(vgen) => {
                                self.plan_refill_batch_locked(inner).await?.0
                            }
                            _ => 0,
                        }
                    };
                    if rem_classical > 0 && self.is_live(vgen) {
                        let _ = self.try_refill_v2_locked(vgen, rem_classical, &[]).await?;
                    }
                }
                if !self.is_live(vgen) || self.startup.is_publish_paused() {
                    return Ok(());
                }
                let retry_pq = {
                    let mut guard = self.lock_inner().await;
                    if !self.is_live(vgen) {
                        return Ok(());
                    }
                    let Some(inner) = guard.as_mut() else {
                        return Ok(());
                    };
                    self.plan_refill_batch_locked(inner).await?.1
                };
                if !retry_pq.is_empty()
                    && self.is_live(vgen)
                    && !self.startup.is_publish_paused()
                    && matches!(
                        self.try_refill_v2_locked(vgen, 0, &retry_pq).await?,
                        RefillV2Outcome::RetryProbeSingleKey
                    )
                    && let Some(&(suite, _)) = retry_pq.first()
                    && self.is_live(vgen)
                    && !self.startup.is_publish_paused()
                    && matches!(
                        self.try_refill_v2_locked(vgen, 0, &[(suite, 1)]).await?,
                        RefillV2Outcome::Handled
                    )
                    && self.is_live(vgen)
                    && !self.startup.is_publish_paused()
                {
                    let rem_pq = {
                        let mut guard = self.lock_inner().await;
                        match guard.as_mut() {
                            Some(inner) if self.is_live(vgen) => {
                                self.plan_refill_batch_locked(inner).await?.1
                            }
                            _ => vec![],
                        }
                    };
                    if !rem_pq.is_empty() && self.is_live(vgen) {
                        let _ = self.try_refill_v2_locked(vgen, 0, &rem_pq).await?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Map a `session::Error` from `claim_peer_bundle_v2` or `finish_prepare_initiate_v2` into
    /// [`StartChatError`], checking `is_live(vgen)` before touching UI signals or cancellation.
    #[allow(clippy::too_many_arguments)]
    fn map_start_chat_session_error(
        &self,
        vgen: u64,
        submission_id: u64,
        peer: &PublicKey,
        pin_pq: bool,
        signs_in_here: bool,
        clock: &session::ServerClock,
        error: session::Error,
    ) -> StartChatError {
        if !self.is_live(vgen) {
            return StartChatError::Cancelled;
        }
        self.check_protocol_error(ProtocolRpcScope::CoreV2, &error);
        if self.is_submission_cancelled(submission_id) {
            return StartChatError::Cancelled;
        }
        match error.kind() {
            ErrorKind::SignInRequired if signs_in_here => StartChatError::SignInRequired,
            ErrorKind::SignInRequired => {
                StartChatError::Other(format!("sign-in required: {NOT_SIGNED_IN_HERE}"))
            }
            ErrorKind::ClassicalApprovalRequired => {
                // R20-P2-2 + R22-P2-3: Always record any verified signed PQ-OFF `(seq, digest)`
                // BEFORE branching on `pin_pq` so an initial `#chat=...&pq=1` attempt still seeds
                // monotonic rollback/equivocation detection across subsequent retries.
                if let Some((seq, digest)) = error.signed_pq_off_manifest()
                    && self
                        .startup
                        .record_new_chat_signed_pq_off(*peer, seq, digest)
                        .is_err()
                {
                    return StartChatError::DowngradeDetected;
                }
                // R20-P1-1: Explicit `#chat=...&pq=1` invitation links promise to refuse classical
                // downgrades; never offer `"Allow classical"` when a `pin_pq` invite encounters a
                // `PQ-OFF` or server-disabled classical fallback.
                if pin_pq {
                    StartChatError::DowngradeDetected
                } else if error.is_server_pq_disabled_approval() {
                    StartChatError::ServerPqDisabledApprovalRequired
                } else {
                    StartChatError::ClassicalApprovalRequired
                }
            }
            ErrorKind::DowngradeDetected => StartChatError::DowngradeDetected,
            ErrorKind::PeerManifestExpired => StartChatError::PeerManifestExpired,
            ErrorKind::PqRequired => StartChatError::PqRequired,
            ErrorKind::ClockSkew => {
                self.warn_clock_skew(clock.offset_ms());
                StartChatError::Other(super::CLOCK_SKEW_MESSAGE.to_string())
            }
            ErrorKind::NotFound => StartChatError::Other(
                "nobody published keys for that key on this server".to_string(),
            ),
            _ => StartChatError::Other(describe(&error)),
        }
    }

    /// Complete [`Engine::start_chat`] when `peer` already exists in `inner.contacts` (either on
    /// entry or because an inbound initial arrived while `ClaimBundle` was suspended). Caller MUST
    /// hold `peer_flush_lock(&peer)` (`peer_guard`, Rank 1) and `Engine::inner` (`guard`, Rank 5).
    /// Releases `guard` across `RegisterWriteToken` and drops `peer_guard` strictly before
    /// `upgrade_to_pq_auto` / `flush`.
    ///
    /// R9-P1-2 + R10-P1-1 + R10-P1-2 + R10-P1-3:
    /// - Marks `(request = true, provisional = true)` durably while `RegisterWriteToken` is in
    ///   flight so reload cleanup (`cleanup_abandoned_provisional_contacts`) revokes any abandoned
    ///   grant and background `flush_pending_grants` skips unaccepted/quarantined requests.
    /// - Loops Phase A if a concurrent inbound rekey introduced a new session token during
    ///   `RegisterWriteToken`, ensuring `Events { accepted: true }` never ships with an
    ///   unregistered write token.
    /// - On cancellation, mid-flight quarantine, or Phase-B `inner.save` failure, restores
    ///   `provisional = false` (if set by Phase A), clears pending grants, and stages a
    ///   `PendingRevoke` before releasing `peer_guard`.
    #[allow(clippy::too_many_arguments)]
    async fn finish_existing_contact_start_chat(
        &self,
        mut guard: InnerGuard<'_, V>,
        peer_guard: impl Drop,
        vgen: u64,
        submission_id: u64,
        peer: PublicKey,
        name: String,
        pin_pq: bool,
        allow_classical: bool,
        claimed_manifest: Option<ClaimedManifestInfo>,
    ) -> Result<PublicKey, StartChatError> {
        let stage_revoke = |inner: &mut Inner<V>| {
            let peer_slot_id = inner.client.peer_slot_id(&peer);
            if let Ok(min_grant_version) = inner.client.allocate_grant_version() {
                if let Some(existing) = inner
                    .state
                    .pending_revokes
                    .iter_mut()
                    .find(|r| r.peer_slot_id.as_slice() == peer_slot_id.as_slice())
                {
                    existing.min_grant_version = existing.min_grant_version.max(min_grant_version);
                } else {
                    inner.state.pending_revokes.push(PendingRevoke {
                        peer_slot_id: peer_slot_id.to_vec(),
                        min_grant_version,
                    });
                }
            }
        };

        let (initial_conv_gen, initial_was_request, initial_was_provisional) = {
            let inner = guard
                .as_ref()
                .ok_or_else(|| StartChatError::Other("locked".into()))?;
            let Some(contact) = inner.contacts.iter().find(|c| c.peer == peer) else {
                self.startup.end_new_chat_submit(submission_id);
                return Err(StartChatError::Cancelled);
            };
            (
                contact.state.conversation_gen,
                contact.state.request,
                contact.state.provisional,
            )
        };

        // Phase A (bounded loop): stage & flush write-token grants while keeping `request = true`
        // and marking `provisional = true` durably on acceptance-in-progress (`R10-P1-1`),
        // repeating if an inbound rekey installs a new session during `RegisterWriteToken`
        // (`R10-P1-3`).
        const MAX_GRANT_PASSES: usize = 4;
        let mut staged_tokens: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut flushed_grants = false;
        let mut marked_provisional_for_accept = false;

        for pass in 0..MAX_GRANT_PASSES {
            let need_flush = {
                let inner = guard
                    .as_mut()
                    .ok_or_else(|| StartChatError::Other("locked".into()))?;
                if self.is_submission_cancelled(submission_id) {
                    self.startup.end_new_chat_submit(submission_id);
                    if (flushed_grants || marked_provisional_for_accept)
                        && let Some(c) = inner.contacts.iter_mut().find(|c| {
                            c.peer == peer && c.state.conversation_gen == initial_conv_gen
                        })
                        && ((initial_was_request && c.state.request)
                            || (initial_was_provisional && c.state.provisional))
                    {
                        if marked_provisional_for_accept {
                            c.state.provisional = false;
                        }
                        c.session.clear_pending_grants();
                        if flushed_grants {
                            stage_revoke(inner);
                        }
                        if inner.save_state().await.is_err() {
                            inner.unsaved_state = true;
                        }
                        if !self.is_live(vgen) {
                            return Err(StartChatError::Cancelled);
                        }
                        self.refresh_contacts(inner);
                        drop(guard);
                        drop(peer_guard);
                        if flushed_grants {
                            self.wake();
                        }
                    }
                    return Err(StartChatError::Cancelled);
                }
                let Some(index) = inner
                    .contacts
                    .iter()
                    .position(|c| c.peer == peer && c.state.conversation_gen == initial_conv_gen)
                else {
                    self.startup.end_new_chat_submit(submission_id);
                    return Err(StartChatError::Cancelled);
                };
                let cur_request = inner.contacts[index].state.request;
                let cur_provisional = inner.contacts[index].state.provisional;
                let cur_quarantined = inner.contacts[index].state.quarantined;
                // R21-P2-3 + R22-P2-2 + R22-P2-4: Monotonically apply verified New Chat manifest
                // observations (`pending_new_chat_off_pins` and any crossed `ClaimBundle` manifest)
                // BEFORE evaluating `pq_block_err` so equivocation or a newer signed PQ-ON pin
                // immediately forces `StartChatError::DowngradeDetected` and prevents Phase-A
                // grant staging.
                let off_pin = self.startup.new_chat_signed_pq_off(&peer);
                let transfer_off_pin = off_pin.is_some();
                let (manifest_dirty, manifest_equivocated) = apply_observed_start_chat_manifests(
                    &mut inner.contacts[index],
                    off_pin,
                    claimed_manifest,
                );
                // R11-P1-2 + R12-P1-1 + R12-P1-2 + R12-P1-3 + R17-P1-2 + R17-P1-3 + R21-P1-3:
                // Never stage grants for or accept/resume an unquarantined classical request OR
                // rolled-back provisional contact when local policy requires PQ, AND never silently
                // open an already-accepted classical chat from an explicit `#chat=...&pq=1`
                // (`pin_pq`) invitation under `strict_pq` or `local_pq`.
                let pq_block_err = if manifest_equivocated {
                    Some(StartChatError::DowngradeDetected)
                } else if !cur_quarantined && inner.contacts[index].is_classical_session() {
                    let strict_pq = inner.client.pq_config().strict_pq;
                    let local_pq = inner.local_pq_enabled();
                    let peer_pq = inner.contacts[index].session.peer_pq_state();
                    if cur_request || cur_provisional {
                        if strict_pq {
                            Some(StartChatError::PqRequired)
                        } else if local_pq {
                            if pin_pq || super::classical_hard_blocked_by_pin_or_downgrade(peer_pq)
                            {
                                Some(StartChatError::DowngradeDetected)
                            } else if !allow_classical && !peer_pq.allow_classical_exception {
                                Some(StartChatError::ExistingClassicalRequestApprovalRequired)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else if pin_pq {
                        if strict_pq {
                            Some(StartChatError::PqRequired)
                        } else if local_pq {
                            Some(StartChatError::DowngradeDetected)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some(block_err) = pq_block_err {
                    let mut dirty = manifest_dirty;
                    let was_unrequested_provisional = cur_provisional && !cur_request;
                    // R13-P2-2 + R20-P1-1 + R21-P1-3: Persist a fresh `pin_pq` invitation pin
                    // (clearing any stale `allow_classical_exception`) under BOTH
                    // `DowngradeDetected` AND `PqRequired`, and flag `downgrade_detected` + alert
                    // whenever `&pq=1` contradicts an existing classical session so later disabling
                    // `strict_pq` or publishing signed PQ-OFF cannot clear it.
                    if pin_pq
                        && matches!(
                            block_err,
                            StartChatError::DowngradeDetected | StartChatError::PqRequired
                        )
                    {
                        let c = &mut inner.contacts[index];
                        c.session.pin_peer_pq();
                        c.session.peer_pq_state_mut().downgrade_detected = true;
                        c.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                        match block_err {
                            StartChatError::DowngradeDetected => {
                                c.record_policy_error(ErrorKind::DowngradeDetected);
                            }
                            StartChatError::PqRequired if !cur_request && !cur_provisional => {
                                c.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                            }
                            _ => {}
                        }
                        dirty = true;
                    }
                    if was_unrequested_provisional {
                        // R17-P1-2: Convert a blocked provisional classical start (e.g. after
                        // `R16-P2-2` rollback) into an explicit unaccepted request and revoke
                        // its provisional relay grant.
                        let c = &mut inner.contacts[index];
                        c.state.provisional = false;
                        c.state.request = true;
                        c.session.clear_pending_grants();
                        c.session.prune_classical_earlier();
                        match block_err {
                            StartChatError::PqRequired => {
                                c.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                            }
                            StartChatError::DowngradeDetected => {
                                c.record_policy_error(ErrorKind::DowngradeDetected);
                            }
                            _ => {}
                        }
                        stage_revoke(inner);
                        dirty = true;
                    } else if flushed_grants || marked_provisional_for_accept {
                        let c = &mut inner.contacts[index];
                        if marked_provisional_for_accept {
                            c.state.provisional = false;
                        }
                        c.session.clear_pending_grants();
                        if flushed_grants {
                            stage_revoke(inner);
                        }
                        dirty = true;
                    }
                    if dirty {
                        if inner.save_state().await.is_err() {
                            inner.unsaved_state = true;
                        } else if transfer_off_pin {
                            self.startup.clear_new_chat_signed_pq_off(&peer);
                        }
                        if !self.is_live(vgen) {
                            return Err(StartChatError::Cancelled);
                        }
                        self.refresh_contacts(inner);
                    } else if transfer_off_pin {
                        self.startup.clear_new_chat_signed_pq_off(&peer);
                    }
                    self.startup.end_new_chat_submit(submission_id);
                    drop(guard);
                    if flushed_grants || was_unrequested_provisional {
                        let _ = self.flush_pending_revoke_for_peer(vgen, &peer).await;
                    }
                    drop(peer_guard);
                    if (flushed_grants || was_unrequested_provisional) && self.is_live(vgen) {
                        self.wake();
                    }
                    return Err(block_err);
                }
                let cur_will_accept = cur_request && !cur_quarantined;
                let cur_will_resume = cur_provisional && !cur_request && !cur_quarantined;
                if !(cur_will_accept || cur_will_resume) {
                    false
                } else {
                    // R13-P1-1: Never stage or register write tokens for archived unapproved
                    // classical earlier sessions when accepting/resuming a PQ contact under
                    // `strict_pq` or without a classical exception while local PQ is enabled.
                    let strict_pq = inner.client.pq_config().strict_pq;
                    let local_pq = inner.local_pq_enabled();
                    let active_is_pq = inner.contacts[index]
                        .session
                        .security()
                        .is_some_and(|s| s.is_pq);
                    let pps = inner.contacts[index].session.peer_pq_state();
                    let allow_earlier_classical = super::allow_earlier_classical_sessions(
                        strict_pq,
                        local_pq,
                        active_is_pq,
                        pps,
                        pin_pq,
                        allow_classical,
                    );
                    let active_token = inner.contacts[index].session.active_inbound_token_hash();
                    let earlier_tokens: Vec<[u8; 32]> = inner.contacts[index]
                        .session
                        .earlier_inbound_token_hashes_for_policy(allow_earlier_classical)
                        .filter(|h| Some(*h) != active_token)
                        .collect();
                    // R17-P1-2: Stage `active_token` on `pass == 0` for `cur_will_resume` even
                    // when `is_known_by_peer() == true` (e.g. a rolled-back crossed-start winner
                    // whose token was suppressed while provisional).
                    let need_active = active_token.filter(|t| !staged_tokens.contains(t));
                    let need_earlier: Vec<[u8; 32]> = earlier_tokens
                        .into_iter()
                        .filter(|t| !staged_tokens.contains(t))
                        .collect();
                    let has_existing_pending = pass == 0
                        && !inner.contacts[index]
                            .session
                            .pending_register_grants()
                            .is_empty();
                    if need_active.is_none() && need_earlier.is_empty() && !has_existing_pending {
                        false
                    } else {
                        let pre_stage_snapshot = inner.contacts[index].snapshot();
                        let prev_marked_provisional = marked_provisional_for_accept;
                        let mut mutated = false;
                        let mut newly_staged = Vec::new();
                        if cur_will_accept && !inner.contacts[index].state.provisional {
                            inner.contacts[index].state.provisional = true;
                            marked_provisional_for_accept = true;
                            mutated = true;
                        }
                        let mut stage_err: Option<String> = None;
                        if let Some(token_hash) = need_active {
                            match inner.stage_write_token_grant(&peer, token_hash, true) {
                                Ok(()) => {
                                    newly_staged.push(token_hash);
                                    mutated = true;
                                }
                                Err(e) => stage_err = Some(e),
                            }
                        }
                        if stage_err.is_none() {
                            for earlier_hash in need_earlier {
                                match inner.stage_write_token_grant(&peer, earlier_hash, false) {
                                    Ok(()) => {
                                        newly_staged.push(earlier_hash);
                                        mutated = true;
                                    }
                                    Err(e) => {
                                        stage_err = Some(e);
                                        break;
                                    }
                                }
                            }
                        }
                        if let Some(e) = stage_err {
                            let _ = inner.roll_back(&peer, pre_stage_snapshot);
                            marked_provisional_for_accept = prev_marked_provisional;
                            if flushed_grants || marked_provisional_for_accept {
                                if let Some(c) = inner.contacts.iter_mut().find(|c| {
                                    c.peer == peer && c.state.conversation_gen == initial_conv_gen
                                }) {
                                    if marked_provisional_for_accept {
                                        c.state.provisional = false;
                                    }
                                    c.session.clear_pending_grants();
                                }
                                if flushed_grants {
                                    stage_revoke(inner);
                                }
                                if inner.save_state().await.is_err() {
                                    inner.unsaved_state = true;
                                }
                                if self.is_live(vgen) {
                                    self.refresh_contacts(inner);
                                }
                                drop(guard);
                                drop(peer_guard);
                                if flushed_grants && self.is_live(vgen) {
                                    self.wake();
                                }
                            }
                            return Err(StartChatError::Other(e));
                        }
                        if mutated {
                            if let Err(e) = inner.save(&[]).await {
                                let _ = inner.roll_back(&peer, pre_stage_snapshot);
                                marked_provisional_for_accept = prev_marked_provisional;
                                if !self.is_live(vgen) {
                                    return Err(StartChatError::Cancelled);
                                }
                                let cancelled = self.is_submission_cancelled(submission_id);
                                if cancelled {
                                    self.startup.end_new_chat_submit(submission_id);
                                }
                                if flushed_grants || marked_provisional_for_accept {
                                    if let Some(c) = inner.contacts.iter_mut().find(|c| {
                                        c.peer == peer
                                            && c.state.conversation_gen == initial_conv_gen
                                    }) {
                                        if marked_provisional_for_accept {
                                            c.state.provisional = false;
                                        }
                                        c.session.clear_pending_grants();
                                    }
                                    if flushed_grants {
                                        stage_revoke(inner);
                                    }
                                    if inner.save_state().await.is_err() {
                                        inner.unsaved_state = true;
                                    }
                                    if !self.is_live(vgen) {
                                        return Err(StartChatError::Cancelled);
                                    }
                                    self.refresh_contacts(inner);
                                    drop(guard);
                                    drop(peer_guard);
                                    if flushed_grants {
                                        self.wake();
                                    }
                                }
                                return if cancelled {
                                    Err(StartChatError::Cancelled)
                                } else {
                                    Err(StartChatError::Other(describe(&e)))
                                };
                            }
                            if !self.is_live(vgen) {
                                return Err(StartChatError::Cancelled);
                            }
                            if self.is_submission_cancelled(submission_id) {
                                self.startup.end_new_chat_submit(submission_id);
                                let _ = inner.roll_back(&peer, pre_stage_snapshot);
                                if flushed_grants || prev_marked_provisional {
                                    if let Some(c) = inner.contacts.iter_mut().find(|c| {
                                        c.peer == peer
                                            && c.state.conversation_gen == initial_conv_gen
                                    }) {
                                        if prev_marked_provisional {
                                            c.state.provisional = false;
                                        }
                                        c.session.clear_pending_grants();
                                    }
                                    if flushed_grants {
                                        stage_revoke(inner);
                                    }
                                }
                                if inner.save_state().await.is_err() {
                                    inner.unsaved_state = true;
                                }
                                if self.is_live(vgen) {
                                    self.refresh_contacts(inner);
                                }
                                drop(guard);
                                drop(peer_guard);
                                if flushed_grants && self.is_live(vgen) {
                                    self.wake();
                                }
                                return Err(StartChatError::Cancelled);
                            }
                        }
                        staged_tokens.extend(newly_staged);
                        inner
                            .contacts
                            .iter()
                            .find(|c| {
                                c.peer == peer && c.state.conversation_gen == initial_conv_gen
                            })
                            .is_some_and(|c| !c.session.pending_register_grants().is_empty())
                    }
                }
            };
            if !need_flush {
                break;
            }
            drop(guard);
            let _ = self.flush_pending_grants_for_peer(&peer).await;
            flushed_grants = true;
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
            guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
        }

        // Phase B (under the exact same `guard` as the final Phase-A check): re-verify
        // cancellation and `conversation_gen`, then commit acceptance / metadata updates (or
        // clean up Phase-A grants if the contact became quarantined mid-flight or `save` fails).
        let (accepted_now, resumed_provisional, phase_b_extra_grants, revoked_in_phase_b) = {
            let inner = guard
                .as_mut()
                .ok_or_else(|| StartChatError::Other("locked".into()))?;
            if self.is_submission_cancelled(submission_id) {
                self.startup.end_new_chat_submit(submission_id);
                if (flushed_grants || marked_provisional_for_accept)
                    && let Some(c) = inner
                        .contacts
                        .iter_mut()
                        .find(|c| c.peer == peer && c.state.conversation_gen == initial_conv_gen)
                    && ((initial_was_request && c.state.request)
                        || (initial_was_provisional && c.state.provisional))
                {
                    if marked_provisional_for_accept {
                        c.state.provisional = false;
                    }
                    c.session.clear_pending_grants();
                    if flushed_grants {
                        stage_revoke(inner);
                    }
                    if inner.save_state().await.is_err() {
                        inner.unsaved_state = true;
                    }
                    if !self.is_live(vgen) {
                        return Err(StartChatError::Cancelled);
                    }
                    self.refresh_contacts(inner);
                    drop(guard);
                    drop(peer_guard);
                    if flushed_grants {
                        self.wake();
                    }
                    return Err(StartChatError::Cancelled);
                }
                return Err(StartChatError::Cancelled);
            }
            let Some(index) = inner
                .contacts
                .iter()
                .position(|c| c.peer == peer && c.state.conversation_gen == initial_conv_gen)
            else {
                self.startup.end_new_chat_submit(submission_id);
                return Err(StartChatError::Cancelled);
            };
            let snapshot = inner.contacts[index].snapshot();
            let was_request = inner.contacts[index].state.request;
            let was_provisional = inner.contacts[index].state.provisional;
            let quarantined = inner.contacts[index].state.quarantined;
            // R21-P2-3 + R22-P2-2 + R22-P2-4: Re-apply observed New Chat manifests BEFORE Phase B's
            // PQ block check so any manifest update that landed while Phase A awaited
            // `RegisterWriteToken` is checked for equivocation before accepting the chat.
            let off_pin_b = self.startup.new_chat_signed_pq_off(&peer);
            let transfer_off_pin = off_pin_b.is_some();
            let (manifest_dirty_b, manifest_equivocated_b) = apply_observed_start_chat_manifests(
                &mut inner.contacts[index],
                off_pin_b,
                claimed_manifest,
            );
            // R11-P1-2 + R12-P1-1 + R12-P1-2 + R12-P1-3 + R17-P1-2 + R17-P1-3 + R21-P1-3: Re-check
            // classical request, provisional-resume, and already-accepted `pin_pq` policy under
            // Phase B's `guard` (in case `strict_pq`, `pq_enabled`, or peer session changed while
            // Phase A awaited `RegisterWriteToken`).
            let phase_b_pq_block = if manifest_equivocated_b {
                Some(StartChatError::DowngradeDetected)
            } else if !quarantined && inner.contacts[index].is_classical_session() {
                let strict_pq = inner.client.pq_config().strict_pq;
                let local_pq = inner.local_pq_enabled();
                let peer_pq = inner.contacts[index].session.peer_pq_state();
                if was_request || was_provisional {
                    if strict_pq {
                        Some(StartChatError::PqRequired)
                    } else if local_pq {
                        if pin_pq || super::classical_hard_blocked_by_pin_or_downgrade(peer_pq) {
                            Some(StartChatError::DowngradeDetected)
                        } else if !allow_classical && !peer_pq.allow_classical_exception {
                            Some(StartChatError::ExistingClassicalRequestApprovalRequired)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else if pin_pq {
                    if strict_pq {
                        Some(StartChatError::PqRequired)
                    } else if local_pq {
                        Some(StartChatError::DowngradeDetected)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(block_err) = phase_b_pq_block {
                let mut dirty = manifest_dirty_b;
                let was_unrequested_provisional = was_provisional && !was_request;
                if pin_pq
                    && matches!(
                        block_err,
                        StartChatError::DowngradeDetected | StartChatError::PqRequired
                    )
                {
                    let c = &mut inner.contacts[index];
                    c.session.pin_peer_pq();
                    c.session.peer_pq_state_mut().downgrade_detected = true;
                    c.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                    match block_err {
                        StartChatError::DowngradeDetected => {
                            c.record_policy_error(ErrorKind::DowngradeDetected);
                        }
                        StartChatError::PqRequired if !was_request && !was_provisional => {
                            c.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                        }
                        _ => {}
                    }
                    dirty = true;
                }
                if was_unrequested_provisional {
                    let c = &mut inner.contacts[index];
                    c.state.provisional = false;
                    c.state.request = true;
                    c.session.clear_pending_grants();
                    c.session.prune_classical_earlier();
                    match block_err {
                        StartChatError::PqRequired => {
                            c.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                        }
                        StartChatError::DowngradeDetected => {
                            c.record_policy_error(ErrorKind::DowngradeDetected);
                        }
                        _ => {}
                    }
                    stage_revoke(inner);
                    dirty = true;
                } else if flushed_grants || marked_provisional_for_accept {
                    let c = &mut inner.contacts[index];
                    if marked_provisional_for_accept {
                        c.state.provisional = false;
                    }
                    c.session.clear_pending_grants();
                    if flushed_grants {
                        stage_revoke(inner);
                    }
                    dirty = true;
                }
                if dirty {
                    if inner.save_state().await.is_err() {
                        inner.unsaved_state = true;
                    } else if transfer_off_pin {
                        self.startup.clear_new_chat_signed_pq_off(&peer);
                    }
                    if !self.is_live(vgen) {
                        return Err(StartChatError::Cancelled);
                    }
                    self.refresh_contacts(inner);
                } else if transfer_off_pin {
                    self.startup.clear_new_chat_signed_pq_off(&peer);
                }
                self.startup.end_new_chat_submit(submission_id);
                drop(guard);
                if flushed_grants || was_unrequested_provisional {
                    let _ = self.flush_pending_revoke_for_peer(vgen, &peer).await;
                }
                drop(peer_guard);
                if (flushed_grants || was_unrequested_provisional) && self.is_live(vgen) {
                    self.wake();
                }
                return Err(block_err);
            }
            let accepted_now = was_request && !quarantined;
            let resumed_provisional = was_provisional && !was_request && !quarantined;
            let mut phase_b_extra_grants = false;
            let mut revoke_staged = false;
            let prev_pending_revokes = inner.state.pending_revokes.clone();
            let strict_pq_b = inner.client.pq_config().strict_pq;
            let local_pq_b = inner.local_pq_enabled();
            let (extra_tokens, revoke_for_pruned) = {
                let contact = &mut inner.contacts[index];
                if pin_pq {
                    contact.session.pin_peer_pq();
                    contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                    if contact.state.quarantined {
                        contact.state.quarantined_was_pq_pinned = true;
                        contact.record_policy_error(ErrorKind::DowngradeDetected);
                    }
                }
                // R20-P1-6: Never stamp `allow_classical_exception = true` onto a PQ session or a
                // PQ-pinned / downgrade-blocked contact (e.g. when an inbound PQ initial arrived
                // while an approved classical New Chat retry was claiming a bundle).
                if allow_classical
                    && !pin_pq
                    && contact.is_classical_session()
                    && !super::classical_hard_blocked_by_pin_or_downgrade(
                        contact.session.peer_pq_state(),
                    )
                {
                    contact
                        .session
                        .peer_pq_state_mut()
                        .approve_classical_exception();
                    contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                }
                // R13-P1-1 + R14-P1-1 + R14-P1-4: Drop archived unapproved classical earlier
                // sessions before accepting or resuming a PQ contact. If any pruned classical
                // token was already registered on the relay during Phase A (`staged_tokens`) or a
                // prior provisional start, revoke the peer slot and restage all retained tokens at
                // strictly higher grant versions.
                let active_is_pq = contact.session.security().is_some_and(|s| s.is_pq);
                let allow_earlier_classical = super::allow_earlier_classical_sessions(
                    strict_pq_b,
                    local_pq_b,
                    active_is_pq,
                    contact.session.peer_pq_state(),
                    pin_pq,
                    false,
                );
                let pruned_classical =
                    if (accepted_now || resumed_provisional) && !allow_earlier_classical {
                        contact.session.prune_classical_earlier()
                    } else {
                        vec![]
                    };
                let revoke_pruned = !pruned_classical.is_empty()
                    && (resumed_provisional
                        || pruned_classical.iter().any(|h| staged_tokens.contains(h)));
                let tokens = if accepted_now {
                    contact.state.request = false;
                    contact.state.provisional = false;
                    contact.state.events.get_or_insert_default().accepted = true;
                    let active = contact.session.active_inbound_token_hash();
                    let earlier: Vec<[u8; 32]> = contact
                        .session
                        .earlier_inbound_token_hashes_for_policy(allow_earlier_classical)
                        .filter(|h| {
                            Some(*h) != active && (revoke_pruned || !staged_tokens.contains(h))
                        })
                        .collect();
                    (
                        active.filter(|t| revoke_pruned || !staged_tokens.contains(t)),
                        earlier,
                    )
                } else if resumed_provisional {
                    contact.state.provisional = false;
                    // R18-P2-2: Reconcile current active and policy-allowed retained tokens
                    // against `staged_tokens` even when `!revoke_pruned` so an inbound rekey
                    // arriving during the final Phase-A pass (suppressed while `provisional`)
                    // never strands the resumed contact without its active relay write token.
                    let active = contact.session.active_inbound_token_hash();
                    let earlier: Vec<[u8; 32]> = contact
                        .session
                        .earlier_inbound_token_hashes_for_policy(allow_earlier_classical)
                        .filter(|h| {
                            Some(*h) != active && (revoke_pruned || !staged_tokens.contains(h))
                        })
                        .collect();
                    (
                        active.filter(|t| revoke_pruned || !staged_tokens.contains(t)),
                        earlier,
                    )
                } else if flushed_grants || marked_provisional_for_accept {
                    // R10-P1-1: Contact became quarantined during Phase A (or is no longer
                    // eligible for acceptance): clear our temporary provisional flag, drop any
                    // pending grants, and revoke any grant registered in Phase A.
                    if marked_provisional_for_accept {
                        contact.state.provisional = false;
                    }
                    contact.session.clear_pending_grants();
                    (None, vec![])
                } else {
                    (None, vec![])
                };
                if !name.is_empty() {
                    contact.state.name = name;
                }
                (tokens, revoke_pruned)
            };
            if revoke_for_pruned {
                stage_revoke(inner);
                revoke_staged = true;
            }
            if accepted_now || resumed_provisional {
                if let Some(token_hash) = extra_tokens.0
                    && inner
                        .stage_write_token_grant(&peer, token_hash, true)
                        .is_ok()
                {
                    phase_b_extra_grants = true;
                }
                for earlier_hash in extra_tokens.1 {
                    if inner
                        .stage_write_token_grant(&peer, earlier_hash, false)
                        .is_ok()
                    {
                        phase_b_extra_grants = true;
                    }
                }
            } else if !resumed_provisional && flushed_grants {
                stage_revoke(inner);
                revoke_staged = true;
            }
            if let Err(e) = inner.save(&[]).await {
                inner.state.pending_revokes = prev_pending_revokes;
                revoke_staged = false;
                let _ = inner.roll_back(&peer, snapshot);
                if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                }
                let cancelled = self.is_submission_cancelled(submission_id);
                if cancelled {
                    self.startup.end_new_chat_submit(submission_id);
                }
                if flushed_grants || marked_provisional_for_accept {
                    if let Some(c) = inner
                        .contacts
                        .iter_mut()
                        .find(|c| c.peer == peer && c.state.conversation_gen == initial_conv_gen)
                    {
                        if marked_provisional_for_accept {
                            c.state.provisional = false;
                        }
                        c.session.clear_pending_grants();
                    }
                    if flushed_grants && !revoke_staged {
                        stage_revoke(inner);
                    }
                    if inner.save_state().await.is_err() {
                        inner.unsaved_state = true;
                    }
                    if !self.is_live(vgen) {
                        return Err(StartChatError::Cancelled);
                    }
                    self.refresh_contacts(inner);
                    drop(guard);
                    drop(peer_guard);
                    if flushed_grants {
                        self.wake();
                    }
                }
                return if cancelled {
                    Err(StartChatError::Cancelled)
                } else {
                    Err(StartChatError::Other(describe(&e)))
                };
            }
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
            if self.is_submission_cancelled(submission_id) {
                self.startup.end_new_chat_submit(submission_id);
                let _ = inner.roll_back(&peer, snapshot);
                if (flushed_grants || marked_provisional_for_accept)
                    && let Some(c) = inner
                        .contacts
                        .iter_mut()
                        .find(|c| c.peer == peer && c.state.conversation_gen == initial_conv_gen)
                {
                    if marked_provisional_for_accept {
                        c.state.provisional = false;
                    }
                    c.session.clear_pending_grants();
                    if flushed_grants && !revoke_staged {
                        stage_revoke(inner);
                    }
                }
                let mut last_err = None;
                for _ in 0..2 {
                    match inner.save_state().await {
                        Ok(()) => {
                            last_err = None;
                            break;
                        }
                        Err(e) => {
                            if !self.is_live(vgen) {
                                return Err(StartChatError::Cancelled);
                            }
                            last_err = Some(e);
                        }
                    }
                }
                if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                }
                if let Some(err) = last_err {
                    inner.unsaved_state = true;
                    let detail = describe(&err);
                    self.ui.log(format!(
                        "cancelled update to {} could not be persisted to storage (will retry): {detail}",
                        short(&peer)
                    ));
                    self.ui.notify(format!(
                        "Cancelled chat update for {} could not be saved ({detail}); reload may restore it until storage recovers.",
                        short(&peer)
                    ));
                }
                self.refresh_contacts(inner);
                drop(guard);
                drop(peer_guard);
                if flushed_grants {
                    self.wake();
                }
                return Err(StartChatError::Cancelled);
            }
            self.startup.clear_new_chat_signed_pq_off(&peer);
            self.startup.end_new_chat_submit(submission_id);
            self.refresh_contacts(inner);
            (
                accepted_now,
                resumed_provisional,
                phase_b_extra_grants,
                revoke_staged,
            )
        };
        drop(guard);
        // R25-P2-3: Mark this submission as already persisted (`greeting_only = true`) across the
        // post-accept grant/replay/flush work so a `403 SignInRequired` from `push_events` opens
        // `Dialog::SignIn` via `on_chat_created_greeting_needs_sign_in(submission_id)` without
        // minting a fresh orphan `pending_new_chat` ID from `active_new_chat`.
        self.startup.set_in_flight_start_chat(submission_id, true);
        let _in_flight = scopeguard::guard((), |()| {
            self.startup.clear_in_flight_start_chat(submission_id);
        });
        if phase_b_extra_grants {
            let _ = self.flush_pending_grants_for_peer(&peer).await;
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
        }
        let replay_upgrades = if accepted_now {
            let (replay_upgrades, replay_grants) = {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                }
                let mut upgrades = BTreeMap::new();
                let mut grants = BTreeSet::new();
                if let Some(inner) = guard.as_mut() {
                    if let Ok((_, up, gp)) = self
                        .replay_deferred_envelopes(inner, Some(&peer), None, None)
                        .await
                    {
                        upgrades = up;
                        grants = gp;
                    }
                    if !self.is_live(vgen) {
                        return Err(StartChatError::Cancelled);
                    }
                    self.refresh_contacts(inner);
                }
                (upgrades, grants)
            };
            for gp in replay_grants {
                if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                }
                let _ = self.flush_pending_grants_for_peer(&gp).await;
            }
            replay_upgrades
        } else {
            BTreeMap::new()
        };
        // R10-P1-2: Release `peer_flush_lock(&peer)` (Rank 1) strictly BEFORE calling
        // `upgrade_to_pq_auto` or `self.flush_with_mode(&peer, ...)` (both of which acquire Rank 1).
        drop(peer_guard);
        if accepted_now {
            for (up_peer, conv_gen) in replay_upgrades {
                if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                }
                let _ = self.upgrade_to_pq_auto(up_peer, conv_gen).await;
            }
            let _ = self
                .flush_with_mode(&peer, self.is_submission_cancelled(submission_id))
                .await;
        }
        if (accepted_now || resumed_provisional || revoked_in_phase_b) && self.is_live(vgen) {
            self.wake();
        }
        // R17-P2-1: Re-verify `initial_conv_gen` before returning `Ok(peer)` so a concurrent
        // `delete_for_gen` (+ replacement inbound request) during post-Phase-B grant/outbox
        // flushes cannot navigate the dialog into a different conversation incarnation.
        if phase_b_extra_grants || accepted_now {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
            let still_same_chat = guard.as_ref().is_some_and(|inner| {
                inner
                    .contacts
                    .iter()
                    .any(|c| c.peer == peer && c.state.conversation_gen == initial_conv_gen)
            });
            drop(guard);
            if !still_same_chat {
                return Err(StartChatError::Cancelled);
            }
        }
        Ok(peer)
    }

    /// Start a chat with `key`, named `name`, greeting the peer; or open the chat if there is one.
    ///
    /// When `pin_pq` is `true` (e.g. from a `#chat=...&pq=1` invitation link), pins the peer as
    /// post-quantum capable BEFORE the first `ClaimBundle` so server stripping hard-fails.
    /// When `allow_classical` is `true`, records an explicit user-approved classical fallback.
    /// Releases `Engine::inner` across `ClaimBundle`, `RegisterWriteToken`, and `SendInitialV2`
    /// network RPCs while always persisting the newly established session to IndexedDB BEFORE
    /// transmitting (H-2).
    pub async fn start_chat(
        &self,
        submission_id: u64,
        key: &str,
        name: String,
        server: Option<&str>,
        pin_pq: bool,
        allow_classical: bool,
    ) -> Result<PublicKey, StartChatError> {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Err(StartChatError::Cancelled);
        }
        let peer = key_from_text(key)
            .ok_or_else(|| StartChatError::Other("that is not an identity key".into()))?;
        let name = name.trim().to_string();
        // R10-P1-2: Serialize ALL `start_chat` lifecycle paths for `peer` (including existing-
        // contact acceptance/resume and new-chat initiation) behind `peer_flush_lock(&peer)`
        // (Rank 1, strictly before `publish_lock`, `grant_sync_lock`, and `Engine::inner`) so a
        // cancelled submission #1 can never race with an immediately resubmitted submission #2.
        let peer_lock = self.queue.peer_flush_lock(&peer);
        let peer_guard = peer_lock.lock().await;
        if !self.is_live(vgen) || self.is_submission_cancelled(submission_id) {
            return Err(StartChatError::Cancelled);
        }
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) || self.is_submission_cancelled(submission_id) {
            return Err(StartChatError::Cancelled);
        }
        // R26-P2-3: Arm `in_flight_start_chat(submission_id, false)` BEFORE branching into
        // `finish_existing_contact_start_chat` so concurrent background 403s during Phase-A
        // `RegisterWriteToken` / Phase B cannot hijack or cancel an active existing-contact start.
        self.startup.set_in_flight_start_chat(submission_id, false);
        let _in_flight = scopeguard::guard((), |()| {
            self.startup.clear_in_flight_start_chat(submission_id);
        });
        {
            let inner = guard
                .as_mut()
                .ok_or_else(|| StartChatError::Other("locked".into()))?;
            // Validate any invitation relay URL BEFORE any contact lookup or mutation so a foreign
            // invitation can never rename, accept, or mutate an existing local contact.
            validate_start_chat_server(server, &inner.server)?;
            inner.check_outgoing_peer(&peer)?;
            if allow_classical
                && super::settings::check_classical_approval(inner.client.pq_config()).is_err()
            {
                return Err(StartChatError::PqRequired);
            }
            if pin_pq && allow_classical && inner.local_pq_enabled() {
                return Err(StartChatError::DowngradeDetected);
            }
            if inner.contacts.iter().any(|c| c.peer == peer) {
                return self
                    .finish_existing_contact_start_chat(
                        guard,
                        peer_guard,
                        vgen,
                        submission_id,
                        peer,
                        name,
                        pin_pq,
                        allow_classical,
                        None,
                    )
                    .await;
            }
        }

        let mut peer_state = PeerPqState::default();
        // R20-P2-2 + R21-P2-3: Always seed any verified signed PQ-OFF `(seq, digest)` observed
        // earlier during New Chat — for BOTH ordinary and `pin_pq` starts — so rollbacks (even to
        // an older signed PQ-ON manifest) and equivocations fail closed.
        if let Some((seq, digest)) = self.startup.new_chat_signed_pq_off(&peer) {
            let _ = peer_state.check_and_pin_manifest(seq, digest);
        }
        if pin_pq {
            // R20-P1-1: A pre-manifest `#chat=...&pq=1` pin refuses classical downgrades; never
            // attach a classical approval exception alongside `pin_pq`.
            peer_state.pin_peer_pq();
        } else if allow_classical {
            peer_state.approve_classical_exception();
        }

        // Phase 1: Lock-free `ClaimBundle` (retrying cleanly if PQ settings change mid-flight).
        const MAX_PQ_CONFIG_RETRIES: usize = 2;
        let (claimed, server_url, clock, signs_in_here, claimed_pq_config) = {
            let mut attempt = 0usize;
            loop {
                let (server_url, audience, pq_config, local_pq_enabled, clock, signs_in_here) = {
                    let inner = guard
                        .as_ref()
                        .ok_or_else(|| StartChatError::Other("locked".into()))?;
                    let server_url = inner.server.clone();
                    let audience = inner.audience.clone();
                    let pq_config = inner.client.pq_config().clone();
                    let local_pq_enabled = inner.local_pq_enabled();
                    let clock = inner.client.clock().clone();
                    let signs_in_here = same_server(&server_url, &origin());
                    (
                        server_url,
                        audience,
                        pq_config,
                        local_pq_enabled,
                        clock,
                        signs_in_here,
                    )
                };
                drop(guard);

                // R24-P1-1: Suppress global `REFUSED` hook on `ClaimBundle`; `SignInRequired`
                // already propagates via `StartChatError::SignInRequired` (gated on `is_live(vgen)`
                // and `!is_submission_cancelled(submission_id)`) without colliding across
                // concurrent `start_chat` submissions.
                let claim_res = session::claim_peer_bundle_v2(
                    &Fetch::client_without_refused_hook(&server_url),
                    &audience,
                    &peer,
                    &peer_state,
                    &pq_config,
                    &clock,
                )
                .await;
                let claimed = match claim_res {
                    Ok(claimed) => claimed,
                    Err(e) => {
                        if signs_in_here
                            && super::outbox::is_post_auth_claim_error(
                                &e,
                                &pq_config,
                                local_pq_enabled,
                            )
                        {
                            self.on_origin_auth_proven_async(vgen).await;
                        }
                        return Err(self.map_start_chat_session_error(
                            vgen,
                            submission_id,
                            &peer,
                            pin_pq,
                            signs_in_here,
                            &clock,
                            e,
                        ));
                    }
                };

                if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                }
                guard = self.lock_inner().await;
                // Check `is_live(vgen)` BEFORE `is_submission_cancelled` / any UI writes per PR 29.2.
                if !self.is_live(vgen) || self.is_submission_cancelled(submission_id) {
                    return Err(StartChatError::Cancelled);
                }
                {
                    let inner = guard
                        .as_mut()
                        .ok_or_else(|| StartChatError::Other("locked".into()))?;
                    if signs_in_here {
                        self.on_origin_auth_proven_locked(vgen, inner);
                    }
                    inner.check_outgoing_peer(&peer)?;
                    if inner.contacts.iter().any(|c| c.peer == peer) {
                        // Peer arrived via an inbound initial while `ClaimBundle` was suspended:
                        // discard the stale bundle cleanly without corrupting the inbound ratchet,
                        // while preserving its verified manifest observation (`R22-P2-4`).
                        let claimed_info = Some(ClaimedManifestInfo::from_claimed(&claimed));
                        drop(claimed);
                        if allow_classical
                            && super::settings::check_classical_approval(inner.client.pq_config())
                                .is_err()
                        {
                            return Err(StartChatError::PqRequired);
                        }
                        return self
                            .finish_existing_contact_start_chat(
                                guard,
                                peer_guard,
                                vgen,
                                submission_id,
                                peer,
                                name,
                                pin_pq,
                                allow_classical,
                                claimed_info,
                            )
                            .await;
                    }
                    if *inner.client.pq_config() != pq_config {
                        // User changed PQ settings mid-flight: discard the stale bundle, re-check
                        // classical approval policy, and re-claim under the updated config.
                        drop(claimed);
                        if allow_classical
                            && super::settings::check_classical_approval(inner.client.pq_config())
                                .is_err()
                        {
                            return Err(StartChatError::PqRequired);
                        }
                        if attempt < MAX_PQ_CONFIG_RETRIES {
                            attempt += 1;
                            continue;
                        }
                        return Err(StartChatError::Other(
                            "Post-quantum settings changed while starting this chat. Try again."
                                .to_string(),
                        ));
                    }
                }
                drop(guard);
                break (claimed, server_url, clock, signs_in_here, pq_config);
            }
        };

        // Run initial `publish_full` (if brand-new vault) BEFORE creating/persisting the new
        // contact or staging its write-token grant (still under `peer_guard`, Rank 1 -> Rank 2),
        // so cancelling during initial publish leaves zero contact and zero grant that a
        // concurrent `sync()` could register on the relay.
        let needs_initial_publish = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) || self.is_submission_cancelled(submission_id) {
                return Err(StartChatError::Cancelled);
            }
            let inner = guard
                .as_ref()
                .ok_or_else(|| StartChatError::Other("locked".into()))?;
            (inner.state.published_at == 0 || inner.client.manifest_seq() == 0)
                && !self.startup.is_publish_paused()
                && !inner.contacts.iter().any(|c| c.peer == peer)
        };
        if needs_initial_publish {
            let _ = self.publish_full(vgen, false).await;
            if !self.is_live(vgen) || self.is_submission_cancelled(submission_id) {
                self.startup.end_new_chat_submit(submission_id);
                return Err(StartChatError::Cancelled);
            }
        }

        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) || self.is_submission_cancelled(submission_id) {
            return Err(StartChatError::Cancelled);
        }
        {
            let inner = guard
                .as_mut()
                .ok_or_else(|| StartChatError::Other("locked".into()))?;
            inner.check_outgoing_peer(&peer)?;
            if inner.contacts.iter().any(|c| c.peer == peer) {
                let claimed_info = Some(ClaimedManifestInfo::from_claimed(&claimed));
                drop(claimed);
                if allow_classical
                    && super::settings::check_classical_approval(inner.client.pq_config()).is_err()
                {
                    return Err(StartChatError::PqRequired);
                }
                return self
                    .finish_existing_contact_start_chat(
                        guard,
                        peer_guard,
                        vgen,
                        submission_id,
                        peer,
                        name,
                        pin_pq,
                        allow_classical,
                        claimed_info,
                    )
                    .await;
            }
            if *inner.client.pq_config() != claimed_pq_config {
                return Err(StartChatError::Other(
                    "Post-quantum settings changed while starting this chat. Try again."
                        .to_string(),
                ));
            }
        }

        // Phase 2: Synchronous handshake completion and H-2 durable persistence under `self.inner`.
        // Persist the new contact with `provisional = true` until final pre-send confirmation so
        // even a total storage failure during cancellation rollback can never leave an approved or
        // retry-eligible chat after reload.
        let (
            created_session_id,
            created_inbound_token_hash,
            created_conv_gen,
            outgoing_request,
            retained_farewells,
        ) = {
            let inner = guard
                .as_mut()
                .ok_or_else(|| StartChatError::Other("locked".into()))?;
            let initial_session_seq = inner.next_new_chat_session_seq();
            let hello = Kind::Hello(
                inner
                    .client
                    .make_hello(inner.state.name.clone(), initial_session_seq),
            );
            // The chat's first message, at its first place.
            let mut greeting = hello.to_bytes();
            stamp(&mut greeting, 1);

            let target_prekey_generation = claimed.manifest().generation;
            let prepared = inner
                .client
                .finish_prepare_initiate_v2(
                    claimed,
                    &peer_state,
                    &greeting,
                    Fetch::client(&inner.server),
                )
                .map_err(|e| {
                    self.map_start_chat_session_error(
                        vgen,
                        submission_id,
                        &peer,
                        pin_pq,
                        signs_in_here,
                        &clock,
                        e,
                    )
                })?;

            let (mut session, outgoing_request) = (prepared.session, prepared.request);
            let created_session_id = session.active_id().copied();
            let created_inbound_token_hash = session.active_inbound_token_hash();
            // Stage write-token registration `H(t_{peer->me})` on Alice's DO before persisting so
            // Bob can reply immediately upon accepting Alice's chat request.
            if let Some(token_hash) = created_inbound_token_hash {
                let grant_version = inner
                    .client
                    .allocate_grant_version()
                    .map_err(|e| StartChatError::Other(describe(&e)))?;
                session
                    .queue_pending_grant(session::PendingGrant {
                        token_hash,
                        grant_version,
                        pin_active: true,
                    })
                    .map_err(|e| StartChatError::Other(describe(&e)))?;
            }

            // Retain any previously queued deletion farewells for `peer` on the recreated contact
            // until the replacement greeting is confirmed delivered: `say_farewells` will not send
            // them prematurely while the recreated chat is active, yet deleting the chat before the
            // replacement greeting succeeds still restores them so the peer learns of the original
            // deletion.
            let saved_farewells = inner.state.farewells.clone();
            let mut retained_farewells = Vec::new();
            inner.state.farewells.retain(|farewell| {
                if farewell.recipient().as_deref() == Some(peer.as_slice()) {
                    retained_farewells.push(farewell.clone());
                    false
                } else {
                    true
                }
            });
            let sent_at = now();
            let entry = HistoryEntry {
                outgoing: true,
                at: sent_at,
                content: Some(Content {
                    clock: 1,
                    kind: Some(hello),
                    events: None,
                }),
                delivery: Delivery::Sent.into(),
                place: 1,
                ..HistoryEntry::default()
            };
            let last_message = Some(super::contact::preview_for_entry(&entry));
            let conversation_gen = inner.allocate_conversation_gen();
            inner.contacts.push(Contact {
                peer,
                session,
                deferred_carried: 0,
                state: ContactState {
                    peer: peer.to_vec(),
                    name,
                    history_len: 1,
                    last_activity: sent_at,
                    last_message,
                    clock: 1,
                    greeting_delivery: GREETING_DELIVERY_UNSENT,
                    acked_ranges: vec![IndexRange { start: 0, end: 1 }],
                    fallback_farewells: retained_farewells.clone(),
                    conversation_gen,
                    provisional: true,
                    greeting_target_generation: target_prekey_generation,
                    greeting_sent_at: 0,
                    greeting_delivery_verified: false,
                    ..ContactState::default()
                },
            });
            let prev_next_session_seq = inner.state.next_session_seq;
            inner.state.next_session_seq = initial_session_seq
                .saturating_add(1)
                .min(session::protocol::MAX_SAFE_INTEGER);
            let record = (peer, 0, entry);
            // H-2: Persist the newly created session BEFORE transmitting the initial message!
            if let Err(e) = inner.save(std::slice::from_ref(&record)).await {
                inner.contacts.pop();
                inner.state.farewells = saved_farewells;
                inner.state.next_session_seq = prev_next_session_seq;
                if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                }
                return Err(StartChatError::Other(describe(&e)));
            }
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
            // Recheck cancellation after IndexedDB persistence: roll back the never-announced
            // contact locally so it neither lingers nor transmits a carried greeting on deletion.
            if self.is_submission_cancelled(submission_id) {
                self.startup.end_new_chat_submit(submission_id);
                self.rollback_cancelled_start_chat(inner, &peer, &retained_farewells, false)
                    .await;
                return Err(StartChatError::Cancelled);
            }

            // The chat is now durably persisted; clear any temporary New Chat signed-OFF pin and
            // mark `in_flight_start_chat` as greeting-only so a 403 transport hook clears
            // auto-start ownership immediately instead of handing a stale reservation to
            // `SignInDialog`.
            self.startup.clear_new_chat_signed_pq_off(&peer);
            self.startup.set_in_flight_start_chat(submission_id, true);
            (
                created_session_id,
                created_inbound_token_hash,
                conversation_gen,
                outgoing_request,
                retained_farewells,
            )
        };
        drop(guard);

        // Phase 3: Lock-free `RegisterWriteToken` and `SendInitialV2` network RPCs (all under
        // `peer_guard`, outside `self.inner`).
        let _ = self.flush_pending_grants_for_peer(&peer).await;
        if !self.is_live(vgen) {
            return Err(StartChatError::Cancelled);
        }
        // Re-verify cancellation, contact existence, matching session, AND confirmed active
        // write-token grant inside a single `self.inner` guard right before transmitting
        // `SendInitialV2`, persisting `provisional = false` + `GREETING_DELIVERY_UNCERTAIN`
        // atomically right before transmission so a late cancel, concurrent delete, inbound
        // session, or failed `RegisterWriteToken` never emits a phantom or unreplyable initial.
        let mut rolled_back_on_cancel = false;
        let mut ready_to_send = true;
        let mut flush_extra_grants = false;
        {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
            let Some(inner) = guard.as_mut() else {
                return Err(StartChatError::Cancelled);
            };
            if self.is_submission_cancelled(submission_id) {
                self.startup.end_new_chat_submit(submission_id);
                if !self
                    .handle_cancelled_start_chat_locked(
                        vgen,
                        inner,
                        &peer,
                        created_conv_gen,
                        created_session_id.as_ref(),
                        &retained_farewells,
                        true,
                    )
                    .await
                {
                    return Err(StartChatError::Cancelled);
                }
                rolled_back_on_cancel = true;
            } else {
                let Some(contact) = inner
                    .contacts
                    .iter()
                    .find(|c| c.peer == peer && c.state.conversation_gen == created_conv_gen)
                else {
                    self.startup.end_new_chat_submit(submission_id);
                    return Err(StartChatError::Cancelled);
                };
                if contact.session.active_id() != created_session_id.as_ref() {
                    let mut flush_winning_grant = false;
                    let mut crossed_winner_blocked_err: Option<StartChatError> = None;
                    let strict_pq_now = inner.client.pq_config().strict_pq;
                    let local_pq_now = inner.local_pq_enabled();
                    let prev_contact = inner.contact(&peer).map(|c| c.snapshot());
                    let prev_pending_revokes = inner.state.pending_revokes.clone();
                    if let Some(c) = inner.contact(&peer)
                        && c.state.provisional
                    {
                        c.state.provisional = false;
                        let active_is_pq = c.session.security().is_some_and(|s| s.is_pq);
                        // R15-P1-3 + R16-P2-1: If a crossed peer classical session won the
                        // tie-break while Phase 2's `RegisterWriteToken` was in flight and
                        // `strict_pq` or local PQ policy now blocks classical sessions, do NOT
                        // authorize the classical winner's write token: convert it to a pending
                        // request, record `SECURITY_ALERT_DOWNGRADE` for PQ-pinned peers, revoke
                        // Phase 2's provisional grant, and return the matching policy error.
                        let winner_blocked_by_pq = !active_is_pq
                            && !c.state.request
                            && !c.state.quarantined
                            && super::classical_policy_blocked(
                                strict_pq_now,
                                local_pq_now,
                                c.session.peer_pq_state(),
                            );
                        if winner_blocked_by_pq {
                            c.state.request = true;
                            c.session.clear_pending_grants();
                            c.session.prune_classical_earlier();
                            let is_downgrade =
                                !strict_pq_now && (pin_pq || c.session.peer_pq_state().pq_pinned);
                            if strict_pq_now {
                                if pin_pq {
                                    c.session.pin_peer_pq();
                                    c.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                                }
                                c.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                            } else if is_downgrade {
                                if pin_pq {
                                    c.session.pin_peer_pq();
                                }
                                c.record_policy_error(ErrorKind::DowngradeDetected);
                            }
                            inner.stage_write_token_revoke(&peer);
                            flush_winning_grant = true;
                            crossed_winner_blocked_err = Some(if strict_pq_now {
                                StartChatError::PqRequired
                            } else if is_downgrade {
                                StartChatError::DowngradeDetected
                            } else {
                                StartChatError::ExistingClassicalRequestApprovalRequired
                            });
                        } else {
                            let can_stage = !c.state.request && !c.state.quarantined;
                            let allow_earlier_classical = super::allow_earlier_classical_sessions(
                                strict_pq_now,
                                local_pq_now,
                                active_is_pq,
                                c.session.peer_pq_state(),
                                pin_pq,
                                allow_classical,
                            );
                            let pruned_classical = if can_stage && !allow_earlier_classical {
                                c.session.prune_classical_earlier()
                            } else {
                                vec![]
                            };
                            let revoke_pruned = can_stage
                                && created_inbound_token_hash
                                    .is_some_and(|h| pruned_classical.contains(&h));
                            let winning_token = can_stage
                                .then(|| c.session.active_inbound_token_hash())
                                .flatten();
                            let archived_tokens: Vec<[u8; 32]> = if can_stage {
                                c.session
                                    .earlier_inbound_token_hashes_for_policy(
                                        allow_earlier_classical,
                                    )
                                    .filter(|h| {
                                        Some(*h) != winning_token
                                            && (revoke_pruned
                                                || Some(*h) != created_inbound_token_hash)
                                    })
                                    .collect()
                            } else {
                                vec![]
                            };
                            if revoke_pruned {
                                inner.stage_write_token_revoke(&peer);
                                flush_winning_grant = true;
                            }
                            if let Some(token_hash) = winning_token
                                && inner
                                    .stage_write_token_grant(&peer, token_hash, true)
                                    .is_ok()
                            {
                                flush_winning_grant = true;
                            }
                            for archived_hash in archived_tokens {
                                if inner
                                    .stage_write_token_grant(&peer, archived_hash, false)
                                    .is_ok()
                                {
                                    flush_winning_grant = true;
                                }
                            }
                        }
                        if let Err(e) = inner.save_state().await {
                            if !self.is_live(vgen) {
                                return Err(StartChatError::Cancelled);
                            }
                            // R16-P2-2 + R17-P2-2: On the allowed-winner acceptance path, require
                            // acceptance and staged grants to commit durably BEFORE issuing
                            // `RegisterWriteToken` or returning `Ok(peer)` so a reload cannot
                            // revert the provisional contact and revoke the registered token. If
                            // New Chat was dismissed while `save_state().await` was pending, run
                            // the cancellation handler immediately after rolling back.
                            if crossed_winner_blocked_err.is_none() {
                                if let Some(snapshot) = prev_contact {
                                    let _ = inner.roll_back(&peer, snapshot);
                                }
                                inner.state.pending_revokes = prev_pending_revokes;
                                self.startup.end_new_chat_submit(submission_id);
                                if self.is_submission_cancelled(submission_id) {
                                    let live = self
                                        .handle_cancelled_start_chat_locked(
                                            vgen,
                                            inner,
                                            &peer,
                                            created_conv_gen,
                                            created_session_id.as_ref(),
                                            &retained_farewells,
                                            true,
                                        )
                                        .await;
                                    drop(guard);
                                    drop(peer_guard);
                                    if live {
                                        self.wake();
                                    }
                                    return Err(StartChatError::Cancelled);
                                }
                                self.refresh_contacts(inner);
                                drop(guard);
                                drop(peer_guard);
                                return Err(StartChatError::Other(describe(&e)));
                            }
                            inner.unsaved_state = true;
                        }
                        if !self.is_live(vgen) {
                            return Err(StartChatError::Cancelled);
                        }
                        // R8-P1-1: Re-check cancellation after `save_state().await` so closing
                        // New Chat during IDB persistence converts the crossed contact to a
                        // request + staged revoke instead of approving it.
                        if self.is_submission_cancelled(submission_id) {
                            self.startup.end_new_chat_submit(submission_id);
                            let live = self
                                .handle_cancelled_start_chat_locked(
                                    vgen,
                                    inner,
                                    &peer,
                                    created_conv_gen,
                                    created_session_id.as_ref(),
                                    &retained_farewells,
                                    true,
                                )
                                .await;
                            drop(guard);
                            if live {
                                self.wake();
                            }
                            return Err(StartChatError::Cancelled);
                        }
                        self.refresh_contacts(inner);
                    }
                    drop(guard);
                    if flush_winning_grant {
                        if crossed_winner_blocked_err.is_some() {
                            let _ = self.flush_pending_revoke_for_peer(vgen, &peer).await;
                        } else {
                            let _ = self.flush_pending_grants_for_peer(&peer).await;
                        }
                        if !self.is_live(vgen) {
                            return Err(StartChatError::Cancelled);
                        }
                        // R8-P1-1: Re-check cancellation after awaiting grant registration so
                        // closing New Chat during that RTT converts the crossed contact to a
                        // request + staged revoke instead of returning `Ok(peer)`.
                        if self.is_submission_cancelled(submission_id) {
                            self.startup.end_new_chat_submit(submission_id);
                            let mut guard = self.lock_inner().await;
                            if !self.is_live(vgen) {
                                return Err(StartChatError::Cancelled);
                            }
                            if let Some(inner) = guard.as_mut() {
                                let _ = self
                                    .handle_cancelled_start_chat_locked(
                                        vgen,
                                        inner,
                                        &peer,
                                        created_conv_gen,
                                        created_session_id.as_ref(),
                                        &retained_farewells,
                                        true,
                                    )
                                    .await;
                            }
                            drop(guard);
                            if self.is_live(vgen) {
                                self.wake();
                            }
                            return Err(StartChatError::Cancelled);
                        }
                        // R16-P2-3 + R17-P2-2: Re-verify cancellation AND `created_conv_gen`
                        // under the acquired guard after awaiting the winning-grant RPC so a
                        // dismissal while waiting for `lock_inner()` or a concurrent
                        // `delete_for_gen` (+ replacement request) cannot return `Ok(peer)`.
                        if crossed_winner_blocked_err.is_none() {
                            let mut guard = self.lock_inner().await;
                            if !self.is_live(vgen) {
                                return Err(StartChatError::Cancelled);
                            }
                            if self.is_submission_cancelled(submission_id) {
                                self.startup.end_new_chat_submit(submission_id);
                                if let Some(inner) = guard.as_mut() {
                                    let _ = self
                                        .handle_cancelled_start_chat_locked(
                                            vgen,
                                            inner,
                                            &peer,
                                            created_conv_gen,
                                            created_session_id.as_ref(),
                                            &retained_farewells,
                                            true,
                                        )
                                        .await;
                                }
                                drop(guard);
                                drop(peer_guard);
                                if self.is_live(vgen) {
                                    self.wake();
                                }
                                return Err(StartChatError::Cancelled);
                            }
                            let still_same_chat = guard.as_ref().is_some_and(|inner| {
                                inner.contacts.iter().any(|c| {
                                    c.peer == peer
                                        && c.state.conversation_gen == created_conv_gen
                                        && !c.state.provisional
                                })
                            });
                            drop(guard);
                            if !still_same_chat {
                                self.startup.end_new_chat_submit(submission_id);
                                drop(peer_guard);
                                return Err(StartChatError::Cancelled);
                            }
                        }
                    }
                    self.startup.end_new_chat_submit(submission_id);
                    drop(peer_guard);
                    self.wake();
                    return match crossed_winner_blocked_err {
                        Some(err) => Err(err),
                        None => Ok(peer),
                    };
                }
                // Even when our local outbound session won a crossed-start tie-break, any peer
                // inbound session that arrived while `provisional == true` was archived into
                // `others` with its grant suppressed; stage non-active grants for policy-allowed
                // archived sessions now that we are finalizing the contact (`R13-P1-1`).
                let strict_pq_now = inner.client.pq_config().strict_pq;
                let local_pq_now = inner.local_pq_enabled();
                let active_is_pq = contact.session.security().is_some_and(|s| s.is_pq);
                let allow_earlier_classical = super::allow_earlier_classical_sessions(
                    strict_pq_now,
                    local_pq_now,
                    active_is_pq,
                    contact.session.peer_pq_state(),
                    pin_pq,
                    allow_classical,
                );
                let classical_policy_blocked = contact.is_classical_session()
                    && super::classical_policy_blocked(
                        strict_pq_now,
                        local_pq_now,
                        contact.session.peer_pq_state(),
                    );
                let archived_crossed_tokens: Vec<[u8; 32]> = if contact.state.provisional
                    && !contact.state.request
                    && !contact.state.quarantined
                {
                    contact
                        .session
                        .earlier_inbound_token_hashes_for_policy(allow_earlier_classical)
                        .filter(|h| Some(*h) != created_inbound_token_hash)
                        .collect()
                } else {
                    vec![]
                };
                if contact.session.has_pending_active_grant() {
                    if let Some(contact) = inner.contact(&peer) {
                        if !allow_earlier_classical {
                            contact.session.prune_classical_earlier();
                        }
                        contact.state.provisional = false;
                        contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                        contact.state.greeting_sent_at = 0;
                        if classical_policy_blocked && strict_pq_now {
                            contact.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                        }
                    }
                    for archived_hash in archived_crossed_tokens {
                        let _ = inner.stage_write_token_grant(&peer, archived_hash, false);
                    }
                    if inner.save_state().await.is_err() {
                        inner.unsaved_state = true;
                    }
                    if !self.is_live(vgen) {
                        return Err(StartChatError::Cancelled);
                    }
                    // R8-P1-1: Re-check cancellation after awaiting IDB save on the pending-grant
                    // exit so a cancelled start is rolled back / converted to a request instead of
                    // waking `sync()` to register the token and transmit the cancelled greeting.
                    if self.is_submission_cancelled(submission_id) {
                        self.startup.end_new_chat_submit(submission_id);
                        let live = self
                            .handle_cancelled_start_chat_locked(
                                vgen,
                                inner,
                                &peer,
                                created_conv_gen,
                                created_session_id.as_ref(),
                                &retained_farewells,
                                true,
                            )
                            .await;
                        drop(guard);
                        if live {
                            self.wake();
                        }
                        return Err(StartChatError::Cancelled);
                    }
                    self.startup.end_new_chat_submit(submission_id);
                    self.ui.log(format!(
                        "saved chat with {}; waiting to confirm write-token registration before sending initial greeting",
                        short(&peer)
                    ));
                    self.refresh_contacts(inner);
                    drop(guard);
                    drop(peer_guard);
                    self.wake();
                    return Ok(peer);
                }
                if let Some(contact) = inner.contact(&peer) {
                    if !allow_earlier_classical {
                        contact.session.prune_classical_earlier();
                    }
                    contact.state.provisional = false;
                    // R9-P2-2 + R13-P1-2: If a crossed classical greeting quarantined (or
                    // converted to request) the contact, OR local PQ policy (`strict_pq` / local
                    // PQ without classical exception) changed during `RegisterWriteToken` #1,
                    // NEVER mark `UNCERTAIN` or transmit `SendInitialV2` for a classical greeting;
                    // keep the greeting `UNSENT` until user review/upgrade completes.
                    if contact.state.request
                        || contact.state.quarantined
                        || classical_policy_blocked
                    {
                        contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                        contact.state.greeting_sent_at = 0;
                        if classical_policy_blocked && strict_pq_now {
                            contact.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                        }
                        ready_to_send = false;
                    } else {
                        contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
                        if contact.state.greeting_sent_at == 0 {
                            contact.state.greeting_sent_at = now();
                        }
                    }
                }
                for archived_hash in archived_crossed_tokens {
                    if inner
                        .stage_write_token_grant(&peer, archived_hash, false)
                        .is_ok()
                    {
                        flush_extra_grants = true;
                    }
                }
                if let Err(e) = inner.save(&[]).await {
                    ready_to_send = false;
                    if let Some(contact) = inner.contact(&peer) {
                        contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                        contact.state.greeting_sent_at = 0;
                    }
                    inner.unsaved_state = true;
                    if !self.is_live(vgen) {
                        return Err(StartChatError::Cancelled);
                    }
                    if !self.is_submission_cancelled(submission_id) {
                        self.startup.end_new_chat_submit(submission_id);
                        self.refresh_contacts(inner);
                        self.ui.log(format!(
                            "saved chat with {}, but could not prepare its initial greeting yet (it will carry on the first message): {}",
                            short(&peer),
                            describe(&e)
                        ));
                    }
                } else if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                } else if self.is_submission_cancelled(submission_id) {
                    self.startup.end_new_chat_submit(submission_id);
                    if !self
                        .handle_cancelled_start_chat_locked(
                            vgen,
                            inner,
                            &peer,
                            created_conv_gen,
                            created_session_id.as_ref(),
                            &retained_farewells,
                            true,
                        )
                        .await
                    {
                        return Err(StartChatError::Cancelled);
                    }
                    rolled_back_on_cancel = true;
                } else if !ready_to_send {
                    self.startup.end_new_chat_submit(submission_id);
                    self.refresh_contacts(inner);
                }
            }
        }
        if rolled_back_on_cancel {
            if self.is_live(vgen) {
                self.wake();
            }
            return Err(StartChatError::Cancelled);
        }
        // R9-P1-4: Skip `flush_extra_grants` when `submission_id` was already cancelled (e.g.
        // during a Phase-3 save failure) so we never register extra write tokens for a cancelled
        // submission before running cancellation rollback.
        if flush_extra_grants && !self.is_submission_cancelled(submission_id) {
            let _ = self.flush_pending_grants_for_peer(&peer).await;
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
        }
        // R7-P1-3 + R8-P1-1 + R8-P2-4 + R9-P1-4 + R9-P2-2 + R17-P2-1: Re-check cancellation after
        // `flush_extra_grants` (or after a failed save) AND revalidate conversation generation /
        // active session / request / quarantine state whenever `flush_extra_grants` awaited a
        // network RPC (including when `!ready_to_send`) so neither a cancelled start nor a
        // deleted/replaced/superseded/quarantined outbound session returns `Ok(peer)` or sends.
        if self.is_submission_cancelled(submission_id) || flush_extra_grants {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
            if self.is_submission_cancelled(submission_id) {
                self.startup.end_new_chat_submit(submission_id);
                if let Some(inner) = guard.as_mut() {
                    let _ = self
                        .handle_cancelled_start_chat_locked(
                            vgen,
                            inner,
                            &peer,
                            created_conv_gen,
                            created_session_id.as_ref(),
                            &retained_farewells,
                            true,
                        )
                        .await;
                }
                drop(guard);
                if self.is_live(vgen) {
                    self.wake();
                }
                return Err(StartChatError::Cancelled);
            }
            if let Some(inner) = guard.as_mut() {
                if !ready_to_send {
                    let still_same_chat = inner
                        .contacts
                        .iter()
                        .any(|c| c.peer == peer && c.state.conversation_gen == created_conv_gen);
                    drop(guard);
                    drop(peer_guard);
                    if !still_same_chat {
                        self.startup.end_new_chat_submit(submission_id);
                        return Err(StartChatError::Cancelled);
                    }
                    self.wake();
                    return Ok(peer);
                }
                let outgoing_is_pq = outgoing_request
                    .message
                    .as_ref()
                    .is_some_and(|m| m.version >= 2);
                let strict_pq_now = inner.client.pq_config().strict_pq;
                let local_pq_now = inner.local_pq_enabled();
                let state_check = inner
                    .contacts
                    .iter()
                    .find(|c| c.peer == peer && c.state.conversation_gen == created_conv_gen)
                    .map(|c| {
                        let policy_blocked = !outgoing_is_pq
                            && super::classical_policy_blocked(
                                strict_pq_now,
                                local_pq_now,
                                c.session.peer_pq_state(),
                            );
                        (
                            c.session.active_id() == created_session_id.as_ref(),
                            !c.state.request && !c.state.quarantined && !policy_blocked,
                            policy_blocked,
                        )
                    });
                match state_check {
                    Some((true, true, _)) => {}
                    None => {
                        self.startup.end_new_chat_submit(submission_id);
                        return Err(StartChatError::Cancelled);
                    }
                    Some((matches_active, _, policy_blocked)) => {
                        // A newer inbound peer session won the tie-break (or quarantined/converted
                        // or PQ-policy-blocked the contact) while `flush_extra_grants` awaited: do
                        // NOT dispatch the superseded/blocked `SendInitialV2`.
                        let mut needs_save = false;
                        if let Some(c) = inner.contact(&peer) {
                            if !matches_active
                                && c.state.greeting_delivery != GREETING_DELIVERY_CONFIRMED
                            {
                                c.state.greeting_delivery = GREETING_DELIVERY_CONFIRMED;
                                c.state.greeting_sent_at = 0;
                                c.state.awaiting_peer_acceptance = false;
                                needs_save = true;
                            } else if matches_active {
                                if c.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN {
                                    c.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                                    c.state.greeting_sent_at = 0;
                                    needs_save = true;
                                }
                                if policy_blocked
                                    && strict_pq_now
                                    && c.state.security_alert != SECURITY_ALERT_PQ_REQUIRED
                                {
                                    c.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                                    needs_save = true;
                                }
                            }
                        }
                        if needs_save {
                            if inner.save_state().await.is_err() {
                                inner.unsaved_state = true;
                            }
                            if !self.is_live(vgen) {
                                return Err(StartChatError::Cancelled);
                            }
                            // R9-P1-4: Re-check cancellation after `save_state().await` so closing
                            // New Chat during persistence converts/rolls back the contact instead
                            // of silently approving it.
                            if self.is_submission_cancelled(submission_id) {
                                self.startup.end_new_chat_submit(submission_id);
                                let live = self
                                    .handle_cancelled_start_chat_locked(
                                        vgen,
                                        inner,
                                        &peer,
                                        created_conv_gen,
                                        created_session_id.as_ref(),
                                        &retained_farewells,
                                        true,
                                    )
                                    .await;
                                drop(guard);
                                if live {
                                    self.wake();
                                }
                                return Err(StartChatError::Cancelled);
                            }
                        }
                        self.startup.end_new_chat_submit(submission_id);
                        self.refresh_contacts(inner);
                        drop(guard);
                        drop(peer_guard);
                        self.wake();
                        return Ok(peer);
                    }
                }
            } else {
                return Err(StartChatError::Cancelled);
            }
        }
        if !ready_to_send {
            drop(peer_guard);
            self.wake();
            return Ok(peer);
        }

        // R18-P2-3: Suppress the global transport-level `REFUSED` sign-in hook on `SendInitialV2`
        // so Phase 4 validates `created_conv_gen` and submission cancellation BEFORE transitioning
        // `ui.dialog` to `Dialog::SignIn` (preventing a 403 for a deleted chat from hijacking UI).
        let send_res: session::Result<()> = Fetch::client_without_refused_hook(&server_url)
            .send_initial_v2(outgoing_request.clone())
            .await
            .map(|_| ())
            .map_err(session::Error::from);
        if !self.is_live(vgen) {
            return Err(StartChatError::Cancelled);
        }

        // Phase 4: Re-acquire `self.inner`, validate `is_live(vgen)`, contact still exists, and
        // `active_id` still matches `created_session_id` before persisting confirmation or
        // rolling back on refusal/cancellation.
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Err(StartChatError::Cancelled);
        }
        let Some(inner) = guard.as_mut() else {
            return Err(StartChatError::Cancelled);
        };
        // R17-P2-1: Pin Phase-4 existence strictly to `created_conv_gen` so a concurrent
        // `delete_for_gen` + fresh inbound request cannot make `start_chat` return `Ok(peer)` or
        // open `SignInDialog` for a deleted chat.
        let contact_exists = inner
            .contacts
            .iter()
            .any(|c| c.peer == peer && c.state.conversation_gen == created_conv_gen);
        let matches_session = inner
            .contacts
            .iter()
            .find(|c| c.peer == peer)
            .is_some_and(|c| {
                c.state.conversation_gen == created_conv_gen
                    && c.session.active_id() == created_session_id.as_ref()
            });
        // R19-P2-5: Only present `Dialog::SignIn` on a same-origin 403 when this exact session's
        // greeting is still pending (not superseded or already confirmed by a crossed inbound
        // session while `SendInitialV2` was in flight).
        let greeting_still_pending = matches_session
            && inner
                .contacts
                .iter()
                .find(|c| c.peer == peer)
                .is_some_and(|c| c.state.greeting_delivery != GREETING_DELIVERY_CONFIRMED);

        if signs_in_here
            && (send_res.is_ok()
                || send_res
                    .as_ref()
                    .is_err_and(|e| e.is_server_refusal() && e.kind() != ErrorKind::SignInRequired))
        {
            self.on_origin_auth_proven_locked(vgen, inner);
        }

        match send_res {
            Err(e) => {
                if !contact_exists {
                    self.startup.end_new_chat_submit(submission_id);
                    return Err(StartChatError::Cancelled);
                }
                // Clear auto-start ownership BEFORE any await (`save_state`) so `SignInDialog`
                // cannot claim this submission's history reservation while IndexedDB persists.
                if e.kind() == ErrorKind::SignInRequired
                    && signs_in_here
                    && greeting_still_pending
                    && !self.is_submission_cancelled(submission_id)
                {
                    // R25-P3-1 + R26-P3-1: Mark peer sign-in wait (and hold any queued outbox head)
                    // before `self.wake()` so `retry_pending_greetings` does not immediately send a
                    // duplicate guaranteed-403 `SendInitialV2`.
                    self.queue.mark_waits_sign_in(peer);
                    self.hold_outbox_head_for_sign_in(inner, &peer);
                    let dialog = self
                        .startup
                        .on_chat_created_greeting_needs_sign_in(submission_id);
                    self.show_dialog_if_changed(dialog);
                } else {
                    self.startup.end_new_chat_submit(submission_id);
                }
                // R8-P1-1: On any definitive `SendInitialV2` refusal of a cancelled submission,
                // roll back a pure start OR convert a crossed contact (even when an inbound
                // session already won the tie-break so `matches_session == false`) keyed strictly
                // to `created_conv_gen`.
                if e.is_server_refusal() && self.is_submission_cancelled(submission_id) {
                    let live = self
                        .handle_cancelled_start_chat_locked(
                            vgen,
                            inner,
                            &peer,
                            created_conv_gen,
                            created_session_id.as_ref(),
                            &retained_farewells,
                            true,
                        )
                        .await;
                    drop(guard);
                    if live {
                        self.wake();
                    }
                    return Err(StartChatError::Cancelled);
                }
                if e.is_server_refusal() && matches_session {
                    // Only revert `UNCERTAIN -> UNSENT`; never downgrade a greeting already
                    // confirmed concurrently on this session.
                    let reverted = inner.contact(&peer).is_some_and(|contact| {
                        if contact.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN {
                            contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                            contact.state.greeting_sent_at = 0;
                            true
                        } else {
                            false
                        }
                    });
                    if reverted {
                        let _ = inner.save_state().await;
                        if !self.is_live(vgen) {
                            return Err(StartChatError::Cancelled);
                        }
                        // R9-P2-1: Re-check cancellation after persisting the refusal rollback so
                        // dismissing New Chat during `save_state().await` rolls back / converts
                        // the contact instead of waking `sync()` to retry the cancelled greeting.
                        if self.is_submission_cancelled(submission_id) {
                            let live = self
                                .handle_cancelled_start_chat_locked(
                                    vgen,
                                    inner,
                                    &peer,
                                    created_conv_gen,
                                    created_session_id.as_ref(),
                                    &retained_farewells,
                                    true,
                                )
                                .await;
                            drop(guard);
                            if live {
                                self.wake();
                            }
                            return Err(StartChatError::Cancelled);
                        }
                    }
                }
                let outgoing_is_pq = outgoing_request
                    .message
                    .as_ref()
                    .is_some_and(|m| m.version >= 2);
                self.check_send_initial_protocol_error(inner, outgoing_is_pq, &e);
                if greeting_still_pending {
                    self.ui.log(format!(
                        "saved chat with {}, but could not send its initial greeting yet (it will carry on the first message): {}",
                        short(&peer),
                        describe(&e)
                    ));
                } else {
                    self.ui.log(format!(
                        "initial greeting RPC to {} failed after the chat session was already confirmed: {}",
                        short(&peer),
                        describe(&e)
                    ));
                }
            }
            Ok(()) => {
                self.startup.end_new_chat_submit(submission_id);
                if !contact_exists {
                    return Err(StartChatError::Cancelled);
                }
                if matches_session {
                    if let Some(contact) = inner.contact(&peer) {
                        contact.mark_greeting_confirmed();
                    }
                    self.queue.record_confirmed_probe_backoff(&peer);
                    let _ = inner.save_state().await;
                    if !self.is_live(vgen) {
                        return Err(StartChatError::Cancelled);
                    }
                }
            }
        }
        if !self.is_live(vgen) {
            return Err(StartChatError::Cancelled);
        }
        self.refresh_contacts(inner);
        drop(guard);
        drop(peer_guard);
        self.wake();
        Ok(peer)
    }

    /// Unified `conversation_gen`-keyed cancellation handler for `start_chat` (`R8-P1-1`): rolls
    /// back a pure unconfirmed outbound start or converts a crossed-start contact into an explicit
    /// unaccepted request with a staged revoke. Returns whether `vgen` is still live afterwards.
    #[allow(clippy::too_many_arguments)]
    async fn handle_cancelled_start_chat_locked(
        &self,
        vgen: u64,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        created_conv_gen: u64,
        created_session_id: Option<&[u8; 32]>,
        retained_farewells: &[Farewell],
        revoke_grant: bool,
    ) -> bool {
        let Some(contact) = inner
            .contacts
            .iter()
            .find(|c| c.peer == *peer && c.state.conversation_gen == created_conv_gen)
        else {
            return self.is_live(vgen);
        };
        let pure_unconfirmed = (contact.state.provisional
            || contact.state.greeting_delivery == GREETING_DELIVERY_UNSENT
            || contact.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN)
            && is_pure_unconfirmed_start(contact, created_session_id);
        if pure_unconfirmed {
            self.rollback_cancelled_start_chat(inner, peer, retained_farewells, revoke_grant)
                .await;
        } else {
            self.convert_crossed_cancelled_start_to_request(inner, peer)
                .await;
        }
        self.is_live(vgen)
    }

    /// Convert a cancelled outbound `start_chat` contact that received an incoming crossed-start
    /// session or quarantined request into an explicit unaccepted request (`request = true,
    /// provisional = false`), revoking any abandoned outbound write-token grant so the peer's
    /// message is preserved for explicit user review.
    pub(super) async fn convert_crossed_cancelled_start_to_request(
        &self,
        inner: &mut Inner<V>,
        peer: &PublicKey,
    ) {
        let peer_slot_id = inner.client.peer_slot_id(peer);
        if let Ok(min_grant_version) = inner.client.allocate_grant_version() {
            if let Some(existing) = inner
                .state
                .pending_revokes
                .iter_mut()
                .find(|r| r.peer_slot_id.as_slice() == peer_slot_id.as_slice())
            {
                existing.min_grant_version = existing.min_grant_version.max(min_grant_version);
            } else {
                inner.state.pending_revokes.push(PendingRevoke {
                    peer_slot_id: peer_slot_id.to_vec(),
                    min_grant_version,
                });
            }
        }
        if let Some(c) = inner.contact(peer) {
            // R7-P1-2: If the active session is still our cancelled, never-transmitted outbound
            // session (`!is_known_by_peer()` — e.g. our outbound session won a crossed-start
            // tie-break over an archived peer session, or a classical request was quarantined
            // during provisional PQ `start_chat`), discard it so later acceptance or classical
            // approval never wedges on the dead outbound session.
            if !c.session.is_known_by_peer() {
                c.session.discard_active();
            }
            c.session.clear_pending_grants();
            c.state.request = true;
            c.state.provisional = false;
            c.state.greeting_delivery = GREETING_DELIVERY_CONFIRMED;
            c.state.greeting_sent_at = 0;
            c.state.awaiting_peer_acceptance = false;
        }
        if inner.save_state().await.is_err() {
            inner.unsaved_state = true;
        }
        if !self.shutting_down.get() && !crate::glue::lock_released() {
            self.refresh_contacts(inner);
        }
    }

    /// Roll back a newly saved but never-transmitted chat after cancellation, restoring only
    /// `retained_farewells` into live `AppState.farewells` so concurrent deletes/deliveries for
    /// other peers are never clobbered. When `revoke_grant` is `true` (because
    /// `RegisterWriteToken` may already have committed on our DO), stages a durable
    /// [`PendingRevoke`] inside the same rollback transaction.
    pub(super) async fn rollback_cancelled_start_chat(
        &self,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        retained_farewells: &[Farewell],
        revoke_grant: bool,
    ) {
        // R26-P2-1: Clear any peer sign-in wait set before this cancelled start rolled back.
        self.queue.clear_peer_sign_in_wait(peer);
        let staged_revoke = if revoke_grant {
            let peer_slot_id = inner.client.peer_slot_id(peer);
            inner
                .client
                .allocate_grant_version()
                .ok()
                .map(|min_grant_version| (peer_slot_id, min_grant_version))
        } else {
            None
        };
        let mut last_err = None;
        for _ in 0..2 {
            if self.shutting_down.get() || crate::glue::lock_released() {
                return;
            }
            let mut state = inner.app_state();
            state.contacts.retain(|contact| contact.peer != *peer);
            if let Some((peer_slot_id, min_grant_version)) = staged_revoke {
                if let Some(existing) = state
                    .pending_revokes
                    .iter_mut()
                    .find(|r| r.peer_slot_id.as_slice() == peer_slot_id.as_slice())
                {
                    existing.min_grant_version = existing.min_grant_version.max(min_grant_version);
                } else {
                    state.pending_revokes.push(PendingRevoke {
                        peer_slot_id: peer_slot_id.to_vec(),
                        min_grant_version,
                    });
                }
            }
            for farewell in retained_farewells {
                if !state
                    .farewells
                    .iter()
                    .any(|existing| existing.push_v2 == farewell.push_v2)
                {
                    state.farewells.push(farewell.clone());
                }
            }
            let deferred = inner.deferred_record();
            match inner.forget_peer(peer, state, deferred).await {
                Ok(()) => {
                    if !self.shutting_down.get() && !crate::glue::lock_released() {
                        self.refresh_contacts(inner);
                    }
                    return;
                }
                Err(e) => last_err = Some(e),
            }
        }
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        // Both `forget_peer` attempts failed: neutralize the lingering contact so neither
        // `retry_pending_greetings`, `flush_pending_grants`, nor a future inbound initial can
        // transmit a cancelled greeting or auto-grant approval privileges without user consent,
        // while retaining any pending revocation / farewells.
        if let Some(contact) = inner.contact(peer) {
            contact.session.discard_active();
            contact.session.clear_pending_grants();
            contact.state.request = true;
            contact.state.provisional = true;
            contact.state.greeting_delivery = GREETING_DELIVERY_CONFIRMED;
            contact.state.awaiting_peer_acceptance = false;
            contact.state.fallback_farewells.clear();
        }
        if let Some((peer_slot_id, min_grant_version)) = staged_revoke {
            if let Some(existing) = inner
                .state
                .pending_revokes
                .iter_mut()
                .find(|r| r.peer_slot_id.as_slice() == peer_slot_id.as_slice())
            {
                existing.min_grant_version = existing.min_grant_version.max(min_grant_version);
            } else {
                inner.state.pending_revokes.push(PendingRevoke {
                    peer_slot_id: peer_slot_id.to_vec(),
                    min_grant_version,
                });
            }
        }
        for farewell in retained_farewells {
            if !inner
                .state
                .farewells
                .iter()
                .any(|existing| existing.push_v2 == farewell.push_v2)
            {
                inner.state.farewells.push(farewell.clone());
            }
        }
        if inner.save_state().await.is_err() {
            inner.unsaved_state = true;
        }
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        self.refresh_contacts(inner);
        if let Some(err) = last_err {
            let detail = describe(&err);
            self.ui.log(format!(
                "cancelled chat with {} could not be removed from storage (greeting was never sent): {detail}",
                short(peer)
            ));
            self.ui.notify(format!(
                "Cancelled chat with {} could not be removed from storage ({detail}); delete it from the chat list.",
                short(peer)
            ));
        }
    }
}

/// Whether a relay's verified [`CapabilityManifest`] already satisfies the user's current local
/// [`session::PqConfig`] and known [`ServerPqStatus`], allowing interrupted-publish reconciliation
/// to complete without an unnecessary extra rotation.
fn manifest_matches_local_config(
    manifest: &CapabilityManifest,
    config: &session::PqConfig,
    server_pq: &ServerPqStatus,
) -> bool {
    let want_pq = config.pq_enabled
        && !config.offered_suites().is_empty()
        && *server_pq != ServerPqStatus::Disabled;
    if manifest.pq_enabled != want_pq {
        return false;
    }
    if !want_pq {
        return !manifest.strict_pq
            && !manifest.pq_ratchet_supported
            && manifest.offered_suites.is_empty();
    }
    let want_suites: Vec<u32> = config
        .offered_suites()
        .iter()
        .map(|s| u32::from(s.as_u8()))
        .collect();
    manifest.strict_pq == config.strict_pq
        && manifest.pq_ratchet_supported == config.pq_ratchet_enabled
        && manifest.offered_suites == want_suites
}

/// Validate an optional invitation `invited_server` against this vault's `local_server`:
/// rejects invalid relay URLs and foreign relays before any contact lookup or mutation.
pub(super) fn validate_start_chat_server(
    invited_server: Option<&str>,
    local_server: &str,
) -> Result<(), StartChatError> {
    let Some(raw) = invited_server.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let canonical = crate::util::validate_relay_url(raw).map_err(|reason| {
        StartChatError::Other(format!("Invalid invitation server address: {reason}."))
    })?;
    if !same_server(&canonical, local_server) {
        return Err(StartChatError::Other(format!(
            "This invitation is for a different server ({canonical}); you cannot start it on this server."
        )));
    }
    Ok(())
}

/// Extract `(counts_unread, readable_clock)` for a newly received `HistoryEntry` so display-time
/// acknowledgment marks only entries that were actually appended to the screen.
pub(super) fn entry_read_tracking(entry: &HistoryEntry) -> (bool, Option<u64>) {
    if entry.outgoing || entry.evicted {
        return (false, None);
    }
    let Some(content) = entry.content.as_ref() else {
        return (false, None);
    };
    let counts_unread = !matches!(content.kind, Some(Kind::Hello(_)));
    let readable_clock = content
        .kind
        .as_ref()
        .is_some_and(Kind::is_readable)
        .then_some(content.clock)
        .filter(|&clock| clock > 0);
    (counts_unread, readable_clock)
}

/// Build a persisted [`Farewell`] for `sealed` on `session`, optionally stripping any carried
/// `initial_message` when greeting delivery was uncertain.
pub(super) fn build_farewell_for_session(
    session: &Session<Connect>,
    sealed: session::Sealed,
    strip_initial: bool,
) -> Farewell {
    let mut v2 = session.push_v2_request(&sealed);
    if strip_initial {
        v2.initial_message = None;
    }
    let allow_classical_initial = v2.initial_message.as_ref().is_some_and(|w| w.version < 2)
        && !super::classical_policy_blocked(false, true, session.peer_pq_state());
    Farewell {
        push_v2: v2.encode_to_vec(),
        allow_classical_initial,
    }
}

/// Encrypt any pending read/download events and a `Deleted` farewell message on `session`
/// according to `mode`.
pub(super) fn encrypt_session_farewells(
    session: &mut Session<Connect>,
    clock: u64,
    sealed_events: Option<SealedEvents>,
    mut events: Option<Events>,
    mode: FarewellMode,
) -> Vec<Farewell> {
    if mode == FarewellMode::Suppress {
        return vec![];
    }
    let strip_initial = mode == FarewellMode::WithoutInitial;
    let mut farewells = vec![];
    let mut deleted = Kind::Deleted(Deleted {}).to_bytes();
    stamp(&mut deleted, clock);
    let active = session.active_id().map(|id| id.to_vec());
    if let Some(sealed) = sealed_events
        && Some(&sealed.session) == active.as_ref()
    {
        if let Some(sealed_msg) = sealed.record.as_ref().and_then(OutgoingRecord::to_sealed) {
            farewells.push(build_farewell_for_session(
                session,
                sealed_msg,
                strip_initial,
            ));
        }
        if let (Some(events), Some(told)) = (&mut events, &sealed.events) {
            forget_told(events, told);
        }
    }
    let events = events.filter(|events| !events.is_empty());
    for content in events
        .map(|events| events.to_bytes())
        .into_iter()
        .chain([deleted])
    {
        if let Ok(message) = session.encrypt(&content) {
            farewells.push(build_farewell_for_session(session, message, strip_initial));
        }
    }
    farewells
}

/// Pure helper: whether `contact` is still an untouched outbound `start_chat` with no concurrent
/// crossed-start acceptance, received history, or quarantined inbound classical request.
fn is_pure_unconfirmed_start(contact: &Contact, created_session_id: Option<&[u8; 32]>) -> bool {
    contact.session.active_id() == created_session_id
        && contact.state.history_len == 1
        && !contact.state.quarantined
        && contact.state.quarantined_session.is_none()
        && contact.state.quarantined_first_message.is_empty()
}

/// Pure helper: compute classical OPK and per-suite PQOPK refill batch counts bounded against the
/// server's cumulative 100-key caps so repeated refills never exceed quota and skewed demand on a
/// preferred suite never starves it to zero (`R7-P2-5`).
///
/// `server_classical_known` and `server_pq_by_suite_known` are the baseline relay counts AS OF the
/// last publish or refill response (BEFORE subtracting `used_classical` / `used_pq_by_suite`), so
/// each consumption delta is deducted exactly once (`R7-P3-1`).
pub(super) fn refill_batch_counts_per_suite(
    used_classical: u32,
    used_pq_total: u32,
    used_pq_by_suite: &std::collections::BTreeMap<PqSuite, u32>,
    offered_suites: &[PqSuite],
    server_classical_known: Option<u32>,
    server_pq_by_suite_known: Option<&std::collections::BTreeMap<PqSuite, u32>>,
) -> (usize, Vec<(PqSuite, usize)>) {
    let classical_low_water = ONE_TIME_PREKEYS.saturating_sub(REFILL_USED as usize);
    let classical_remaining = server_classical_known
        .map(|known| (known as usize).saturating_sub(used_classical as usize));
    let classical_needs_refill = used_classical >= REFILL_USED
        || classical_remaining.is_some_and(|rem| rem <= classical_low_water);
    let classical = if classical_needs_refill {
        let deficit = classical_remaining.map_or(used_classical as usize, |rem| {
            ONE_TIME_PREKEYS.saturating_sub(rem)
        });
        let desired = (used_classical as usize)
            .max(deficit)
            .clamp(1, ONE_TIME_PREKEYS);
        match classical_remaining {
            Some(est_remaining) => {
                let headroom = SERVER_MAX_ONE_TIME_PREKEYS.saturating_sub(est_remaining);
                desired.min(headroom)
            }
            None => desired.min(REFILL_USED as usize),
        }
    } else {
        0
    };

    if offered_suites.is_empty() {
        return (classical, vec![]);
    }
    let suite_low_water = PQ_ONE_TIME_PREKEYS.saturating_sub(REFILL_USED as usize);
    let tracked_used_sum: u32 = used_pq_by_suite
        .values()
        .copied()
        .fold(0u32, u32::saturating_add);
    let unaccounted_used = used_pq_total.saturating_sub(tracked_used_sum);
    let mut pq_batches = Vec::with_capacity(offered_suites.len());

    match server_pq_by_suite_known {
        Some(server_map) => {
            // Compute total estimated remaining PQOPKs across ALL suites present on the relay
            // (including any non-offered suites) to stay strictly under the shared 100-key cap.
            let mut total_est_rem = 0usize;
            for (&suite, &known) in server_map {
                let mut used_s = used_pq_by_suite.get(&suite).copied().unwrap_or(0);
                if suite == offered_suites[0] {
                    used_s = used_s.saturating_add(unaccounted_used);
                }
                total_est_rem =
                    total_est_rem.saturating_add((known as usize).saturating_sub(used_s as usize));
            }
            let mut remaining_headroom =
                SERVER_MAX_PQ_ONE_TIME_PREKEYS.saturating_sub(total_est_rem);
            for (idx, &suite) in offered_suites.iter().enumerate() {
                if remaining_headroom == 0 {
                    break;
                }
                let mut used_s = used_pq_by_suite.get(&suite).copied().unwrap_or(0);
                if idx == 0 {
                    used_s = used_s.saturating_add(unaccounted_used);
                }
                let known = server_map.get(&suite).copied().unwrap_or(0) as usize;
                let est_rem = known.saturating_sub(used_s as usize);
                if used_s >= REFILL_USED || est_rem <= suite_low_water {
                    let deficit = PQ_ONE_TIME_PREKEYS.saturating_sub(est_rem);
                    let desired = (used_s as usize).max(deficit).clamp(1, PQ_ONE_TIME_PREKEYS);
                    let batch = desired.min(remaining_headroom);
                    if batch > 0 {
                        pq_batches.push((suite, batch));
                        remaining_headroom = remaining_headroom.saturating_sub(batch);
                    }
                }
            }
        }
        None => {
            if used_pq_total >= REFILL_USED || used_pq_by_suite.values().any(|&v| v >= REFILL_USED)
            {
                let mut remaining_budget = (REFILL_USED as usize).max(1);
                if tracked_used_sum > 0 {
                    for (idx, &suite) in offered_suites.iter().enumerate() {
                        if remaining_budget == 0 {
                            break;
                        }
                        let mut used_s = used_pq_by_suite.get(&suite).copied().unwrap_or(0);
                        if idx == 0 {
                            used_s = used_s.saturating_add(unaccounted_used);
                        }
                        if used_s > 0 {
                            let batch = (used_s as usize)
                                .min(PQ_ONE_TIME_PREKEYS)
                                .min(remaining_budget);
                            if batch > 0 {
                                pq_batches.push((suite, batch));
                                remaining_budget = remaining_budget.saturating_sub(batch);
                            }
                        }
                    }
                } else {
                    let cap_per_suite = (REFILL_USED as usize / offered_suites.len()).max(1);
                    let per_suite =
                        (used_pq_total as usize / offered_suites.len()).clamp(1, cap_per_suite);
                    for &suite in offered_suites {
                        pq_batches.push((suite, per_suite));
                    }
                }
            }
        }
    }
    (classical, pq_batches)
}

#[cfg(test)]
pub(super) fn refill_batch_counts(
    used_classical: u32,
    used_pq: u32,
    pq_suites_len: usize,
    server_classical_known: Option<u32>,
    server_pq_total_known: Option<u32>,
) -> (usize, usize) {
    let offered: Vec<PqSuite> = match pq_suites_len {
        0 => vec![],
        1 => vec![PqSuite::MlKem1024],
        _ => vec![PqSuite::MlKem1024, PqSuite::MlKem768],
    };
    let server_map = server_pq_total_known.map(|total| {
        let mut m = std::collections::BTreeMap::new();
        if !offered.is_empty() {
            let base = total / offered.len() as u32;
            let rem = total % offered.len() as u32;
            for (i, &suite) in offered.iter().enumerate() {
                m.insert(suite, base + u32::from((i as u32) < rem));
            }
        }
        m
    });
    let empty_used = std::collections::BTreeMap::new();
    let (classical, pq_batches) = refill_batch_counts_per_suite(
        used_classical,
        used_pq,
        &empty_used,
        &offered,
        server_classical_known,
        server_map.as_ref(),
    );
    let per_suite = if pq_suites_len == 0 || pq_batches.is_empty() {
        0
    } else {
        let total: usize = pq_batches.iter().map(|(_, n)| *n).sum();
        (total / pq_suites_len).max(1)
    };
    (classical, per_suite)
}
