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
    SECURITY_ALERT_NONE, SealedEvents,
};
use leptos::prelude::*;
use prost::Message as _;
use session::protocol::handshake_v2::{InitialMessageV2 as WireInitial, LocalHandshakeV2};
use session::{
    AcceptedInitial, ErrorKind, InitialMessageKind, InitialMessageV2, ListedInitialMessages,
    PeerPqState, PqSuite, PublicKey, PublishV2Outcome, Session,
};
use std::collections::BTreeSet;

pub(super) type Incoming = InitialMessageV2;

// A page can include 64 initials from retrying a previous stall and another 64
// surfaced together at its expired or newly stalled tail.
const MAX_PENDING_CARRIED_INITIALS: usize = 2 * 64;
const MAX_DEFERRED_INITIALS: usize = 100;
/// Maximum age (30 days in ms) for which deferred initials preserve their target signed prekey
/// generation and manifest digest across scheduled prekey rotations.
pub(super) const DEFERRED_REPLAY_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Result of [`Engine::join_carried`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct JoinCarriedOutcome {
    /// Whether an accepted session's `Hello` triggered an automatic PQ upgrade recommendation.
    pub(super) recommend_upgrade: bool,
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

/// Collect signed prekeys and manifest digests referenced by deferred inbox initials, carried
/// initials (active or isolated contacts), and buffered `DeferredEnvelope`s so scheduled prekey
/// rotations do not evict prekeys needed to replay them.
pub(super) fn preserved_deferred_prekeys<V>(
    inner: &Inner<V>,
    now_ms: u64,
) -> (Vec<PublicKey>, Vec<[u8; 32]>) {
    let mut spks = Vec::new();
    let mut digests = Vec::new();
    let mut record = |initial: &Incoming| {
        let (spk, digest) = initial_spk_and_digest(initial);
        if !spks.contains(&spk) {
            spks.push(spk);
        }
        if let Some(d) = digest
            && !digests.contains(&d)
        {
            digests.push(d);
        }
    };
    for entry in &inner.deferred_initials {
        let within_window = entry.deferred_at == 0
            || now_ms.saturating_sub(entry.deferred_at) <= DEFERRED_REPLAY_WINDOW_MS;
        if !within_window {
            continue;
        }
        if let Some(wire) = &entry.initial
            && let Ok(initial) = Incoming::try_from(wire)
        {
            record(&initial);
        }
    }
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
            if within_window {
                record(&initial);
            }
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
            record(&initial);
        }
    }
    (spks, digests)
}

/// Whether local processing has finished for this initial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InitialOutcome {
    /// Accepted, quarantined, or permanently rejected — safe to acknowledge after local save.
    Ack,
    /// Keep the ciphertext so a build with the required suite can process it.
    DeferUnsupportedSuite,
}

struct OpenedInitial {
    session: Session<Connect>,
    first_message: Vec<u8>,
    /// A held classical initial and whether the peer was already pinned.
    quarantine: Option<bool>,
}

#[derive(Default)]
pub(super) struct InitialBatch {
    dirty: bool,
    records: Vec<(PublicKey, u64, HistoryEntry)>,
    /// Newly added entries for the open chat: `(peer, view, displayed_entry)`.
    views: Vec<(PublicKey, MessageView, DisplayedEntry)>,
    requeue: BTreeSet<PublicKey>,
    upgrades: BTreeSet<PublicKey>,
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

impl<V: VaultStore> Inner<V> {
    /// Reserve a local copy deduplicated by payload (ignoring relay-assigned inbox ID) and
    /// include its ack ID in the same vault transaction.
    pub(super) fn defer_inbox_initial(&mut self, message: &Incoming) -> bool {
        let wire = WireInitial {
            id: 0,
            ..initial_payload(&message.kind)
        };
        let already_stored = self
            .deferred_initials
            .iter()
            .any(|entry| entry.initial.as_ref() == Some(&wire));
        if !already_stored {
            if self.deferred_initials.len() >= MAX_DEFERRED_INITIALS {
                return false;
            }
            self.deferred_initials.push(DeferredInitial {
                initial: Some(wire),
                deferred_at: now(),
            });
        }
        stage_inbox_ack(&mut self.deferred_acks_after_save, message.id) || !already_stored
    }

    pub(super) fn check_outgoing_peer(&self, peer: &PublicKey) -> Result<(), StartChatError> {
        if *peer == self.client.identity_key() {
            return Err(StartChatError::Other(
                "You cannot start a chat with your own identity key.".into(),
            ));
        }
        self.check_isolation(peer).map_err(StartChatError::Other)
    }

    pub(super) async fn save_full_publish_success(&mut self) -> crate::vault::Result<()> {
        self.state.published_at = now();
        self.state.used_one_time_prekeys = 0;
        self.state.needs_publish = false;
        self.state.pending_pq_rollback = None;
        self.pending_pq_contact_flags.clear();
        self.save_state().await
    }

    fn open_initial(
        &mut self,
        peer: &PublicKey,
        message: &Incoming,
    ) -> session::Result<OpenedInitial> {
        let mailbox = Fetch::client(&self.server);
        let pin = self
            .contact(peer)
            .map(|c| c.session.peer_pq_state().clone())
            .unwrap_or_default();
        let opened = match self
            .client
            .accept_initial_v2(peer, &pin, message, mailbox)?
        {
            AcceptedInitial::Accepted {
                session,
                first_message,
                ..
            } => OpenedInitial {
                session,
                first_message,
                quarantine: None,
            },
            AcceptedInitial::Quarantined {
                session,
                first_message,
                peer_was_pq_pinned,
            } => OpenedInitial {
                session,
                first_message,
                quarantine: Some(peer_was_pq_pinned),
            },
        };
        let classical_used = message.uses_one_time_prekey();
        let pq_used = message.uses_pq_one_time_prekey();
        self.state.used_one_time_prekeys = self
            .state
            .used_one_time_prekeys
            .saturating_add(u32::from(classical_used));
        self.state.used_pq_one_time_prekeys = self
            .state
            .used_pq_one_time_prekeys
            .saturating_add(u32::from(pq_used));
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
                    batch.dirty |= inner.defer_inbox_initial(&message)
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
            .map(|(any_progress, _)| any_progress)
    }

    pub(super) async fn take_initial_messages_with_replayed(
        &self,
    ) -> Result<(bool, BTreeSet<PublicKey>), String> {
        let vgen = self.vault_gen();
        let mut any_progress = false;
        let mut after_id = 0u64;
        let mut all_upgrades = BTreeSet::new();
        let mut inbox_peers = BTreeSet::new();
        let mut all_replayed = BTreeSet::new();
        for _ in 0..MAX_INBOX_PAGES {
            if !self.is_live(vgen) {
                return Ok((false, BTreeSet::new()));
            }
            {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok((false, BTreeSet::new()));
                }
                let Some(inner) = guard.as_mut() else {
                    break;
                };
                if inner.needs_save() {
                    inner.save(&[]).await.map_err(|e| describe(&e))?;
                }
                if !self.is_live(vgen) {
                    return Ok((false, BTreeSet::new()));
                }
            }
            self.ack_pending_inbox_v2(vgen).await?;
            if !self.is_live(vgen) {
                return Ok((false, BTreeSet::new()));
            }
            let (server, list_req) = {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok((false, BTreeSet::new()));
                }
                let Some(inner) = guard.as_mut() else {
                    break;
                };
                match inner
                    .client
                    .sign_list_initial_messages_v2(&inner.audience, after_id, 100)
                {
                    Ok(req) => (inner.server.clone(), req),
                    Err(e) => {
                        if e.kind() == ErrorKind::ClockSkew {
                            self.warn_clock_skew(inner.client.clock().offset_ms());
                        }
                        self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                        return Err(describe(&e));
                    }
                }
            };
            let raw_inbox: session::Result<_> = Fetch::client(&server)
                .list_initial_messages(list_req)
                .await
                .map_err(session::Error::from);
            if !self.is_live(vgen) {
                return Ok((false, BTreeSet::new()));
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
            let (dirty, grant_peers) = {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok((false, BTreeSet::new()));
                }
                let Some(inner) = guard.as_mut() else {
                    break;
                };
                let mut batch = InitialBatch::default();
                // Defer read receipts until `save_initial_batch` confirms the chat is still open and
                // visible after persistence.
                self.process_inbox_messages(inner, inbox, &mut batch);
                if batch.dirty {
                    any_progress = true;
                    let grant_peers = std::mem::take(&mut batch.grant_peers);
                    let touched_peers = std::mem::take(&mut batch.touched_peers);
                    let upgrades = self.save_initial_batch(inner, batch).await?;
                    if !self.is_live(vgen) {
                        return Ok((false, BTreeSet::new()));
                    }
                    all_upgrades.extend(upgrades);
                    inbox_peers.extend(touched_peers);
                    (true, grant_peers)
                } else {
                    (false, BTreeSet::new())
                }
            };
            if dirty {
                for peer in grant_peers {
                    if !self.is_live(vgen) {
                        return Ok((false, BTreeSet::new()));
                    }
                    let _ = self.flush_pending_grants_for_peer(&peer).await;
                }
                if !self.is_live(vgen) {
                    return Ok((false, BTreeSet::new()));
                }
                self.ack_pending_inbox_v2(vgen).await?;
            }
            if !has_more {
                break;
            }
            match next_after_id {
                Some(next) if next > after_id => after_id = next,
                _ => break,
            }
        }
        // Replay buffered envelopes only AFTER draining inbox pages, and scoped strictly to peers
        // whose session state advanced in this pass so unrelated peers (whose carried or
        // later-page initials haven't been joined yet) are never prematurely dropped.
        let mut replay_grants = BTreeSet::new();
        if !inbox_peers.is_empty() && self.is_live(vgen) {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok((false, BTreeSet::new()));
            }
            if let Some(inner) = guard.as_mut()
                && !inner.deferred_envelopes.is_empty()
            {
                for peer in inbox_peers {
                    if !self.is_live(vgen) {
                        return Ok((false, BTreeSet::new()));
                    }
                    if let Ok((replayed_peers, replay_upgrades, grants)) =
                        self.replay_deferred_envelopes(inner, Some(&peer)).await
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
                return Ok((false, BTreeSet::new()));
            }
            let _ = self.flush_pending_grants_for_peer(&peer).await;
        }
        for peer in all_upgrades {
            if !self.is_live(vgen) {
                return Ok((false, BTreeSet::new()));
            }
            let _ = self.upgrade_to_pq(peer).await;
        }
        Ok((any_progress, all_replayed))
    }

    /// Commit replayed initials with their history and consumed prekeys. Return `(upgrades,
    /// grant_peers)` to execute after releasing `self.inner`, or `None` if the queue made no
    /// progress.
    pub(super) async fn replay_deferred_initials(
        &self,
        inner: &mut Inner<impl VaultStore>,
    ) -> Result<Option<(BTreeSet<PublicKey>, BTreeSet<PublicKey>)>, String> {
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
        let mut recommend_upgrade = false;
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
                recommend_upgrade |= self.save_initial_batch(inner, batch).await?.contains(peer);
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
        let existing = inner.contacts.iter().position(|c| c.peer == *peer);
        let contact = match existing {
            Some(index) => {
                let server = inner.server.clone();
                let contact = &mut inner.contacts[index];
                if let Some(pinned) = quarantine {
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
                    let downgrade = pinned || session.peer_pq_state().downgrade_detected;
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
                let is_pq = session.security().is_some_and(|security| security.is_pq);
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
                        // unaccepted requests and quarantined contacts wait for explicit approval.
                        (!contact.state.request && !contact.state.quarantined).then_some(took_over)
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
                    batch.upgrades.insert(*peer);
                }
            }
        }
        // Defer read receipts until `save_initial_batch` confirms the chat is open and visible.
        let (index, entry) = match contact.add_received(content, false) {
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
                contact.message(index, entry.clone()),
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
    ) -> Result<BTreeSet<PublicKey>, String> {
        let mut outgoing = vec![];
        let mut changed = vec![];
        for peer in batch.requeue {
            match inner.requeue_sealed(&peer).await {
                Ok(outcome) => {
                    if self.shutting_down.get() || crate::glue::lock_released() {
                        return Ok(BTreeSet::new());
                    }
                    outcome.log_missing(&self.ui, &peer);
                    outgoing.extend(outcome.outbox);
                    batch.records.extend(records(&peer, &outcome.history));
                    changed.push((peer, outcome.history));
                }
                // replace_session set the durable gate. flush retries before pushing any ciphertext.
                Err(e) => {
                    if self.shutting_down.get() || crate::glue::lock_released() {
                        return Ok(BTreeSet::new());
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
            return Ok(BTreeSet::new());
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

    /// Execute a full signed-prekey + manifest publish under the held `inner` lock, preserving the
    /// structured [`ErrorKind`] so [`set_pq_config`](Self::set_pq_config) can distinguish definitive
    /// server refusals from transient network/sign-in failures.
    pub(super) async fn publish_full(
        &self,
        inner: &mut Inner<V>,
        now_anyway: bool,
    ) -> Result<(), PublishError> {
        let (preserve_spks, preserve_digests) = preserved_deferred_prekeys(inner, now());
        let mut prepared = inner
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
        let outcome = match inner.client.transmit_publish_v2(&prepared).await {
            Ok(PublishV2Outcome::ServerPqDisabled) => {
                // Relay has runtime PQ_ENABLED="false": prepare signed classical PQ-OFF manifest,
                // persist updated manifest_seq / digest / retracted PQ prekeys BEFORE
                // transmitting, and then transmit the classical-OFF publish.
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
                            .finish_publish_rollback(inner, PublishError::prepare(e), now_anyway)
                            .await;
                    }
                };
                if let Err(e) = inner.save(&[]).await {
                    inner.client.rollback_publish_v2_on_refusal(prepared);
                    return Err(PublishError::storage(e));
                }
                inner.client.transmit_publish_v2(&prepared).await
            }
            other => other,
        };
        match outcome {
            Ok(outcome @ (PublishV2Outcome::V2Pq | PublishV2Outcome::V2ClassicalOff)) => {
                inner.client.commit_publish_v2(prepared);
                self.startup.on_publish_succeeded();
                inner.state.used_pq_one_time_prekeys = 0;
                inner.last_server_classical_opks = Some(ONE_TIME_PREKEYS as u32);
                let log_msg = match outcome {
                    PublishV2Outcome::V2Pq => {
                        let suites_len = inner.client.pq_config().offered_suites().len();
                        inner.last_server_pq_opks = Some((PQ_ONE_TIME_PREKEYS * suites_len) as u32);
                        if inner.server_pq == ServerPqStatus::Disabled {
                            inner.server_pq = ServerPqStatus::Unknown;
                        }
                        "published post-quantum + classical prekeys and signed capability manifest"
                    }
                    PublishV2Outcome::V2ClassicalOff => {
                        inner.last_server_pq_opks = Some(0);
                        if inner.local_pq_enabled() {
                            inner.server_pq = ServerPqStatus::Disabled;
                            "published classical prekeys and signed PQ-off capability manifest (server PQ disabled)"
                        } else {
                            "published classical prekeys and signed PQ-off capability manifest"
                        }
                    }
                    PublishV2Outcome::ServerPqDisabled => unreachable!(),
                };
                inner
                    .save_full_publish_success()
                    .await
                    .map_err(PublishError::storage)?;
                if !self.shutting_down.get() && !crate::glue::lock_released() {
                    self.ui.me.set(Some(inner.me()));
                    self.ui.log(log_msg);
                }
                Ok(())
            }
            Ok(PublishV2Outcome::ServerPqDisabled) => {
                inner.client.rollback_publish_v2_on_refusal(prepared);
                self.finish_publish_rollback(
                    inner,
                    PublishError::prepare(session::Error::from(ErrorKind::Protocol)),
                    now_anyway,
                )
                .await
            }
            Err(e) => {
                self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                let error = PublishError::transmitted(e);
                if error.rejects_settings() || error.needs_sign_in() || error.is_unimplemented() {
                    inner.client.rollback_publish_v2_on_refusal(prepared);
                    return self.finish_publish_rollback(inner, error, now_anyway).await;
                }
                Err(error)
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
        }
        if error.rejects_settings() {
            if error.kind == Some(ErrorKind::PqRequired) {
                inner.server_pq = ServerPqStatus::Disabled;
                if live {
                    self.ui.me.set(Some(inner.me()));
                }
            }
            if let Some(rollback) = &inner.state.pending_pq_rollback {
                match inner.client.set_pq_config(rollback.config()) {
                    Ok(()) => {
                        inner.state.needs_publish = rollback.previous_needs_publish;
                        inner.state.pending_pq_rollback = None;
                        let restored_flags = std::mem::take(&mut inner.pending_pq_contact_flags);
                        for (peer, (prev_alert, prev_approval)) in restored_flags {
                            if let Some(contact) = inner.contact(&peer) {
                                if let Some(alert) = prev_alert
                                    && contact.state.security_alert == SECURITY_ALERT_NONE
                                {
                                    contact.state.security_alert = alert;
                                }
                                if let Some(approval) = prev_approval
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

    /// Try one non-rotating v2 refill. When `pq_count > 0` and the relay has runtime PQ disabled,
    /// returns `Ok(RefillV2Outcome::PqDisabled)` so the caller can retry with classical OPKs only.
    async fn try_refill_v2(
        &self,
        inner: &mut Inner<V>,
        classical_count: usize,
        pq_count: usize,
    ) -> Result<RefillV2Outcome, String> {
        let prepared = inner
            .client
            .prepare_refill_v2(&inner.audience, classical_count, pq_count)
            .map_err(|e| describe(&e))?;
        if let Err(e) = inner.save(&[]).await {
            inner.client.rollback_refill_v2_on_refusal(prepared);
            return Err(describe(&e));
        }
        let response = match inner.client.transmit_refill_v2(&prepared).await {
            Ok(response) => response,
            Err(e) if !e.is_server_refusal() => return Err(describe(&e)),
            Err(e) => {
                inner.client.rollback_refill_v2_on_refusal(prepared);
                let outcome = match e.kind() {
                    ErrorKind::SignInRequired => {
                        self.startup.set_publish_waits_sign_in(true);
                        Ok(RefillV2Outcome::Handled)
                    }
                    ErrorKind::LimitExceeded => {
                        if classical_count > 0 {
                            inner.state.used_one_time_prekeys = 0;
                            inner.last_server_classical_opks =
                                Some(SERVER_MAX_ONE_TIME_PREKEYS as u32);
                        }
                        if pq_count > 0 {
                            inner.state.used_pq_one_time_prekeys = 0;
                            inner.last_server_pq_opks = Some(SERVER_MAX_PQ_ONE_TIME_PREKEYS as u32);
                        }
                        self.ui
                            .log("server one-time prekey pool is already full; skipped refill");
                        Ok(RefillV2Outcome::Handled)
                    }
                    ErrorKind::Unimplemented if pq_count > 0 => {
                        // Confirm via `GetServerInfo` that the relay has runtime PQ disabled
                        // before marking `ServerPqStatus::Disabled` (a missing `RefillPrekeys` RPC
                        // or transient error must not downgrade server PQ status).
                        match inner.client.check_server_info(&inner.audience).await {
                            Ok(info) if !info.pq_enabled => {
                                inner.server_pq = ServerPqStatus::Disabled;
                                if inner.client.pq_config().strict_pq {
                                    Err(describe(&e))
                                } else {
                                    Ok(RefillV2Outcome::PqDisabled)
                                }
                            }
                            Ok(_) => {
                                self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                                Err(describe(&e))
                            }
                            Err(info_err)
                                if should_require_update_for_rpc(
                                    ProtocolRpcScope::CoreV2,
                                    &info_err,
                                ) =>
                            {
                                self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                                Err(describe(&e))
                            }
                            Err(info_err) => Err(describe(&info_err)),
                        }
                    }
                    ErrorKind::Unimplemented => {
                        self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                        Err(describe(&e))
                    }
                    ErrorKind::NotFound | ErrorKind::Protocol => {
                        inner.state.needs_publish = true;
                        Err(describe(&e))
                    }
                    _ => Err(describe(&e)),
                };
                inner.save_state().await.map_err(|e| describe(&e))?;
                if !self.shutting_down.get() && !crate::glue::lock_released() {
                    self.ui.me.set(Some(inner.me()));
                }
                return outcome;
            }
        };
        inner.client.commit_refill_v2(prepared);
        inner.last_server_classical_opks = Some(response.classical_one_time_count);
        inner.last_server_pq_opks = Some(
            response
                .pq_one_time_counts
                .iter()
                .fold(0u32, |n, s| n.saturating_add(s.count)),
        );
        if classical_count > 0 {
            inner.state.used_one_time_prekeys = 0;
        }
        if pq_count > 0 {
            inner.state.used_pq_one_time_prekeys = 0;
        }
        inner.save_state().await.map_err(|e| describe(&e))?;
        if !self.shutting_down.get() && !crate::glue::lock_released() {
            self.ui
                .log("replenished one-time prekeys without rotating signed prekey");
        }
        Ok(RefillV2Outcome::Handled)
    }

    /// Publish new prekeys (SPK rotation / PQ manifest) if due or requested, or replenish low
    /// OPKs/PQOPKs WITHOUT rotating SPK via non-rotating refill. Always persists newly generated
    /// private keys to IndexedDB BEFORE transmitting over the network (H-2).
    pub async fn publish(&self, now_anyway: bool) -> Result<(), String> {
        let vgen = self.vault_gen();
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Ok(());
        }
        let Some(inner) = guard.as_mut() else {
            return Ok(());
        };
        let needs_v2_manifest =
            inner.client.manifest_seq() == 0 || inner.client.prekey_generation() == 0;
        let full_due = now_anyway
            || inner.state.published_at == 0
            || inner.state.needs_publish
            || needs_v2_manifest
            || now().saturating_sub(inner.state.published_at) > REPUBLISH_AGE;

        if full_due {
            if self.startup.is_publish_paused() && !now_anyway {
                return Ok(());
            }
            if now_anyway {
                self.startup.set_publish_waits_settings(false);
            }
            return self
                .publish_full(inner, now_anyway)
                .await
                .map_err(|e| e.message);
        }

        // M-5: Non-rotating OPK/PQOPK refill (does NOT rotate SPK!).
        if self.startup.is_publish_paused() {
            return Ok(());
        }
        let classical_low = inner.state.used_one_time_prekeys >= REFILL_USED;
        let pq_suites_len =
            if inner.local_pq_enabled() && inner.server_pq != ServerPqStatus::Disabled {
                inner.client.pq_config().offered_suites().len()
            } else {
                0
            };
        let pq_low = pq_suites_len > 0 && inner.state.used_pq_one_time_prekeys >= REFILL_USED;
        if !classical_low && !pq_low {
            return Ok(());
        }

        let (classical_count, pq_count) = refill_batch_counts(
            inner.state.used_one_time_prekeys,
            inner.state.used_pq_one_time_prekeys,
            pq_suites_len,
            inner.last_server_classical_opks,
            inner.last_server_pq_opks,
        );
        // If server is already at its 100-key cap, reset counters so sync doesn't loop.
        if classical_count == 0 && pq_count == 0 {
            let mut cleared = false;
            if classical_low {
                inner.state.used_one_time_prekeys = 0;
                cleared = true;
            }
            if pq_low {
                inner.state.used_pq_one_time_prekeys = 0;
                cleared = true;
            }
            if cleared {
                inner.save_state().await.map_err(|e| describe(&e))?;
            }
            return Ok(());
        }

        if self.try_refill_v2(inner, classical_count, pq_count).await? == RefillV2Outcome::Handled
            || classical_count == 0
        {
            return Ok(());
        }
        // A PQ-disabled v2 server can still accept a classical-only v2 refill.
        if pq_count > 0 {
            let _ = self.try_refill_v2(inner, classical_count, 0).await?;
        }
        Ok(())
    }

    /// Map a `session::Error` from `claim_peer_bundle_v2` or `finish_prepare_initiate_v2` into
    /// [`StartChatError`], checking `is_live(vgen)` before touching UI signals or cancellation.
    fn map_start_chat_session_error(
        &self,
        vgen: u64,
        submission_id: u64,
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
            ErrorKind::ClassicalApprovalRequired => StartChatError::ClassicalApprovalRequired,
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
    /// entry or because an inbound initial arrived while `ClaimBundle` was suspended). Releases
    /// `guard` across `RegisterWriteToken` and `flush`.
    #[allow(clippy::too_many_arguments)]
    async fn finish_existing_contact_start_chat(
        &self,
        mut guard: InnerGuard<'_, V>,
        vgen: u64,
        submission_id: u64,
        peer: PublicKey,
        name: String,
        pin_pq: bool,
        allow_classical: bool,
    ) -> Result<PublicKey, StartChatError> {
        let accepted_now = {
            let inner = guard
                .as_mut()
                .ok_or_else(|| StartChatError::Other("locked".into()))?;
            let Some(index) = inner.contacts.iter().position(|c| c.peer == peer) else {
                return Err(StartChatError::Cancelled);
            };
            let snapshot = inner.contacts[index].snapshot();
            let was_request = inner.contacts[index].state.request;
            let quarantined = inner.contacts[index].state.quarantined;
            let accepted_now = was_request && !quarantined;
            {
                let contact = &mut inner.contacts[index];
                if pin_pq {
                    contact.session.pin_peer_pq();
                    if contact.state.quarantined {
                        contact.state.quarantined_was_pq_pinned = true;
                        contact.state.security_alert = SECURITY_ALERT_DOWNGRADE;
                        contact.session.peer_pq_state_mut().downgrade_detected = true;
                    }
                }
                if allow_classical {
                    contact
                        .session
                        .peer_pq_state_mut()
                        .approve_classical_exception();
                    contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                }
                if accepted_now {
                    contact.state.request = false;
                    contact.state.events.get_or_insert_default().accepted = true;
                }
                if !name.is_empty() {
                    contact.state.name = name;
                }
            }
            if accepted_now
                && let Some(token_hash) = inner.contacts[index].session.active_inbound_token_hash()
                && let Err(e) = inner.stage_write_token_grant(&peer, token_hash, true)
            {
                let _ = inner.roll_back(&peer, snapshot);
                return Err(StartChatError::Other(e));
            }
            if let Err(e) = inner.save(&[]).await {
                let _ = inner.roll_back(&peer, snapshot);
                if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                }
                return Err(StartChatError::Other(describe(&e)));
            }
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
            if self.is_submission_cancelled(submission_id) {
                let _ = inner.roll_back(&peer, snapshot);
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
                return Err(StartChatError::Cancelled);
            }
            self.refresh_contacts(inner);
            accepted_now
        };
        drop(guard);
        if accepted_now {
            let _ = self.flush_pending_grants_for_peer(&peer).await;
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
            let replay_grants = {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                }
                let mut grants = BTreeSet::new();
                if let Some(inner) = guard.as_mut() {
                    if let Ok((_, _, gp)) = self.replay_deferred_envelopes(inner, Some(&peer)).await
                    {
                        grants = gp;
                    }
                    if !self.is_live(vgen) {
                        return Err(StartChatError::Cancelled);
                    }
                    self.refresh_contacts(inner);
                }
                grants
            };
            for gp in replay_grants {
                if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                }
                let _ = self.flush_pending_grants_for_peer(&gp).await;
            }
            let _ = self.flush(&peer).await;
            if self.is_live(vgen) {
                self.wake();
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
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) || self.is_submission_cancelled(submission_id) {
            return Err(StartChatError::Cancelled);
        }
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
            if inner.contacts.iter().any(|c| c.peer == peer) {
                return self
                    .finish_existing_contact_start_chat(
                        guard,
                        vgen,
                        submission_id,
                        peer,
                        name,
                        pin_pq,
                        allow_classical,
                    )
                    .await;
            }
        }

        self.startup.set_in_flight_start_chat(submission_id, false);
        let _in_flight = scopeguard::guard((), |()| {
            self.startup.clear_in_flight_start_chat(submission_id);
        });

        let mut peer_state = PeerPqState::default();
        if pin_pq {
            peer_state.pin_peer_pq();
        }
        if allow_classical {
            peer_state.approve_classical_exception();
        }

        // Phase 1: Lock-free `ClaimBundle` (retrying cleanly if PQ settings change mid-flight).
        const MAX_PQ_CONFIG_RETRIES: usize = 2;
        let (claimed, server_url, clock, signs_in_here, claimed_pq_config) = {
            let mut attempt = 0usize;
            loop {
                let (server_url, audience, pq_config, clock, signs_in_here) = {
                    let inner = guard
                        .as_ref()
                        .ok_or_else(|| StartChatError::Other("locked".into()))?;
                    let server_url = inner.server.clone();
                    let audience = inner.audience.clone();
                    let pq_config = inner.client.pq_config().clone();
                    let clock = inner.client.clock().clone();
                    let signs_in_here = same_server(&server_url, &origin());
                    (server_url, audience, pq_config, clock, signs_in_here)
                };
                drop(guard);

                let claimed = session::claim_peer_bundle_v2(
                    &Fetch::client(&server_url),
                    &audience,
                    &peer,
                    &peer_state,
                    &pq_config,
                    &clock,
                )
                .await
                .map_err(|e| {
                    self.map_start_chat_session_error(vgen, submission_id, signs_in_here, &clock, e)
                })?;

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
                    inner.check_outgoing_peer(&peer)?;
                    if inner.contacts.iter().any(|c| c.peer == peer) {
                        // Peer arrived via an inbound initial while `ClaimBundle` was suspended:
                        // discard the stale bundle cleanly without corrupting the inbound ratchet!
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
                                vgen,
                                submission_id,
                                peer,
                                name,
                                pin_pq,
                                allow_classical,
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

        // Serialize Phases 2–4 per peer via `peer_flush_lock` (acquired strictly BEFORE
        // `self.inner`) so concurrent `retry_pending_greetings()` or `flush()` cannot send
        // `SendInitialV2` before `RegisterWriteToken` completes or defeat cancellation rollback.
        let peer_lock = self.queue.peer_flush_lock(&peer);
        let peer_guard = peer_lock.lock().await;
        if !self.is_live(vgen) || self.is_submission_cancelled(submission_id) {
            return Err(StartChatError::Cancelled);
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
                drop(claimed);
                drop(peer_guard);
                if allow_classical
                    && super::settings::check_classical_approval(inner.client.pq_config()).is_err()
                {
                    return Err(StartChatError::PqRequired);
                }
                return self
                    .finish_existing_contact_start_chat(
                        guard,
                        vgen,
                        submission_id,
                        peer,
                        name,
                        pin_pq,
                        allow_classical,
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
        let (created_session_id, outgoing_request, retained_farewells, ready_to_send) = {
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

            let prepared = inner
                .client
                .finish_prepare_initiate_v2(
                    claimed,
                    &peer_state,
                    &greeting,
                    Fetch::client(&inner.server),
                )
                .map_err(|e| {
                    self.map_start_chat_session_error(vgen, submission_id, signs_in_here, &clock, e)
                })?;

            let (mut session, outgoing_request) = (prepared.session, prepared.request);
            let created_session_id = session.active_id().copied();
            // Stage write-token registration `H(t_{peer->me})` on Alice's DO before persisting so
            // Bob can reply immediately upon accepting Alice's chat request.
            if let Some(token_hash) = session.active_inbound_token_hash() {
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
            let entry = HistoryEntry {
                outgoing: true,
                at: now(),
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
                    last_activity: now(),
                    last_message,
                    clock: 1,
                    greeting_delivery: GREETING_DELIVERY_UNSENT,
                    acked_ranges: vec![IndexRange { start: 0, end: 1 }],
                    fallback_farewells: retained_farewells.clone(),
                    conversation_gen,
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
                self.rollback_cancelled_start_chat(inner, &peer, &retained_farewells, false, false)
                    .await;
                return Err(StartChatError::Cancelled);
            }

            // Persist `GREETING_DELIVERY_UNCERTAIN` BEFORE transmitting so that a lost response or
            // post-success save failure still notifies an established peer on deletion without
            // carrying an unconfirmed greeting. Do NOT transmit unless this durable marker
            // persists, and recheck cancellation immediately after the final await before issuing
            // the RPC.
            let mut ready_to_send = true;
            if let Some(contact) = inner.contact(&peer) {
                contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
            }
            if let Err(e) = inner.save(&[]).await {
                ready_to_send = false;
                if let Some(contact) = inner.contact(&peer) {
                    contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                }
                if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                }
                self.ui.log(format!(
                    "saved chat with {}, but could not prepare its initial greeting yet (it will carry on the first message): {}",
                    short(&peer),
                    describe(&e)
                ));
            }
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
            if self.is_submission_cancelled(submission_id) {
                self.startup.end_new_chat_submit(submission_id);
                self.rollback_cancelled_start_chat(
                    inner,
                    &peer,
                    &retained_farewells,
                    ready_to_send,
                    false,
                )
                .await;
                return Err(StartChatError::Cancelled);
            }

            // Ensure our own manifest is published first if this brand-new vault hasn't published
            // yet, so `RegisterWriteToken` succeeds on our DO.
            if ready_to_send
                && (inner.state.published_at == 0 || inner.client.manifest_seq() == 0)
                && !self.startup.is_publish_paused()
            {
                let _ = self.publish_full(inner, false).await;
                if !self.is_live(vgen) {
                    return Err(StartChatError::Cancelled);
                }
                if self.is_submission_cancelled(submission_id) {
                    self.startup.end_new_chat_submit(submission_id);
                    self.rollback_cancelled_start_chat(
                        inner,
                        &peer,
                        &retained_farewells,
                        ready_to_send,
                        false,
                    )
                    .await;
                    return Err(StartChatError::Cancelled);
                }
            }

            // The chat is now durably persisted; mark `in_flight_start_chat` as greeting-only so a
            // 403 transport hook clears auto-start ownership immediately instead of handing a stale
            // reservation to `SignInDialog`.
            self.startup.set_in_flight_start_chat(submission_id, true);
            if !ready_to_send {
                self.startup.end_new_chat_submit(submission_id);
                self.refresh_contacts(inner);
            }
            (
                created_session_id,
                outgoing_request,
                retained_farewells,
                ready_to_send,
            )
        };
        drop(guard);

        if !ready_to_send {
            self.wake();
            return Ok(peer);
        }

        // Phase 3: Lock-free `RegisterWriteToken` and `SendInitialV2` network RPCs.
        let _ = self.flush_pending_grants_for_peer(&peer).await;
        if !self.is_live(vgen) {
            return Err(StartChatError::Cancelled);
        }
        // If cancelled while `RegisterWriteToken` was in flight (before `SendInitialV2` left),
        // roll back the never-announced contact cleanly AND stage a `PendingRevoke` so any
        // write-token grant already registered on our DO is revoked cleanly.
        if self.is_submission_cancelled(submission_id) {
            self.startup.end_new_chat_submit(submission_id);
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
            let mut rolled_back = false;
            if let Some(inner) = guard.as_mut()
                && inner
                    .contacts
                    .iter()
                    .find(|c| c.peer == peer)
                    .is_some_and(|c| {
                        c.session.active_id() == created_session_id.as_ref()
                            && c.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN
                            && c.state.history_len == 1
                    })
            {
                self.rollback_cancelled_start_chat(inner, &peer, &retained_farewells, true, true)
                    .await;
                rolled_back = true;
            }
            drop(guard);
            if rolled_back && self.is_live(vgen) {
                self.wake();
            }
            return Err(StartChatError::Cancelled);
        }
        // Re-verify contact existence, matching session, AND confirmed active write-token grant
        // immediately before transmitting `SendInitialV2` so a concurrent delete, inbound session,
        // or failed `RegisterWriteToken` never emits a phantom or unreplyable initial request.
        {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err(StartChatError::Cancelled);
            }
            let Some(inner) = guard.as_mut() else {
                return Err(StartChatError::Cancelled);
            };
            let Some(contact) = inner.contacts.iter().find(|c| c.peer == peer) else {
                self.startup.end_new_chat_submit(submission_id);
                return Err(StartChatError::Cancelled);
            };
            if contact.session.active_id() != created_session_id.as_ref() {
                self.startup.end_new_chat_submit(submission_id);
                return Ok(peer);
            }
            if contact.session.has_pending_active_grant() {
                if let Some(contact) = inner.contact(&peer)
                    && contact.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN
                {
                    contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                    let _ = inner.save_state().await;
                    if !self.is_live(vgen) {
                        return Err(StartChatError::Cancelled);
                    }
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
        }

        let send_res: session::Result<()> = Fetch::client(&server_url)
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
        let contact_exists = inner.contacts.iter().any(|c| c.peer == peer);
        let matches_session = inner
            .contacts
            .iter()
            .find(|c| c.peer == peer)
            .is_some_and(|c| c.session.active_id() == created_session_id.as_ref());

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
                    && !self.is_submission_cancelled(submission_id)
                {
                    let dialog = self
                        .startup
                        .on_chat_created_greeting_needs_sign_in(submission_id);
                    self.show_dialog_if_changed(dialog);
                } else {
                    self.startup.end_new_chat_submit(submission_id);
                }
                if e.is_server_refusal() && matches_session {
                    if self.is_submission_cancelled(submission_id)
                        && inner
                            .contacts
                            .iter()
                            .find(|c| c.peer == peer)
                            .is_some_and(|c| {
                                c.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN
                                    && c.state.history_len == 1
                            })
                    {
                        self.rollback_cancelled_start_chat(
                            inner,
                            &peer,
                            &retained_farewells,
                            true,
                            true,
                        )
                        .await;
                        drop(guard);
                        if self.is_live(vgen) {
                            self.wake();
                        }
                        return Err(StartChatError::Cancelled);
                    }
                    // Only revert `UNCERTAIN -> UNSENT`; never downgrade a greeting already
                    // confirmed concurrently on this session.
                    let reverted = inner.contact(&peer).is_some_and(|contact| {
                        if contact.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN {
                            contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
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
                    }
                }
                let outgoing_is_pq = outgoing_request
                    .message
                    .as_ref()
                    .is_some_and(|m| m.version >= 2);
                self.check_send_initial_protocol_error(inner, outgoing_is_pq, &e);
                self.ui.log(format!(
                    "saved chat with {}, but could not send its initial greeting yet (it will carry on the first message): {}",
                    short(&peer),
                    describe(&e)
                ));
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

    /// Roll back a newly saved but never-transmitted chat after cancellation, restoring only
    /// `retained_farewells` into live `AppState.farewells` so concurrent deletes/deliveries for
    /// other peers are never clobbered. When `revoke_grant` is `true` (because
    /// `RegisterWriteToken` may already have committed on our DO), stages a durable
    /// [`PendingRevoke`] inside the same rollback transaction.
    async fn rollback_cancelled_start_chat(
        &self,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        retained_farewells: &[Farewell],
        uncertain_persisted: bool,
        revoke_grant: bool,
    ) {
        if let Some(contact) = inner.contact(peer) {
            contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
        }
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
        if uncertain_persisted && inner.save_state().await.is_err() {
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
    Farewell {
        push_v2: v2.encode_to_vec(),
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

/// Pure helper: compute classical OPK and per-suite PQOPK refill batch counts bounded against the
/// server's cumulative 100-key caps so repeated refills never exceed quota.
///
/// Returns `(classical_count, pq_per_suite_count)`.
pub(super) fn refill_batch_counts(
    used_classical: u32,
    used_pq: u32,
    pq_suites_len: usize,
    server_classical_known: Option<u32>,
    server_pq_total_known: Option<u32>,
) -> (usize, usize) {
    let classical = if used_classical >= REFILL_USED {
        let desired = (used_classical as usize).clamp(1, ONE_TIME_PREKEYS);
        match server_classical_known {
            Some(known) => {
                let est_remaining = (known as usize).saturating_sub(used_classical as usize);
                let headroom = SERVER_MAX_ONE_TIME_PREKEYS.saturating_sub(est_remaining);
                desired.min(headroom)
            }
            None => desired.min(REFILL_USED as usize),
        }
    } else {
        0
    };
    let pq_per_suite = if pq_suites_len > 0 && used_pq >= REFILL_USED {
        let per_suite_target = (used_pq as usize / pq_suites_len).clamp(1, PQ_ONE_TIME_PREKEYS);
        match server_pq_total_known {
            Some(known) => {
                let est_remaining = (known as usize).saturating_sub(used_pq as usize);
                let headroom = SERVER_MAX_PQ_ONE_TIME_PREKEYS.saturating_sub(est_remaining);
                per_suite_target.min(headroom / pq_suites_len)
            }
            None => {
                let cap_per_suite = (REFILL_USED as usize / pq_suites_len).max(1);
                per_suite_target.min(cap_per_suite)
            }
        }
    } else {
        0
    };
    (classical, pq_per_suite)
}
