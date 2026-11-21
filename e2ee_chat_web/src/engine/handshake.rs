//! Initial messages, peer handshakes and prekey publication.

use super::contact::Contact;
use super::{
    Engine, HistoryStore, Inner, NOT_SIGNED_IN_HERE, ONE_TIME_PREKEYS, PQ_ONE_TIME_PREKEYS,
    REFILL_USED, REPUBLISH_AGE, SERVER_MAX_ONE_TIME_PREKEYS, SERVER_MAX_PQ_ONE_TIME_PREKEYS,
    StartChatError, origin, records, same_server,
};
use crate::content::{Content, Kind, stamp};
use crate::state::{Delivery, MessageView, ServerPqStatus};
use crate::transport::{Connect, Fetch};
use crate::util::{describe, key_from_text, now, short};
use crate::vault::{
    CLASSICAL_APPROVAL_NONE, ContactState, Farewell, HistoryEntry, OutgoingRecord,
    SECURITY_ALERT_DOWNGRADE, history_key,
};
use leptos::prelude::*;
use prost::Message as _;
use session::{
    AcceptedInitial, ErrorKind, InitialMessageKind, InitialMessageV2, PeerPqState, PublicKey,
    PublishV2Outcome, Session,
};

pub(super) type Incoming = InitialMessageV2;

// A page can include 64 initials from retrying a previous stall and another 64
// surfaced together at its expired or newly stalled tail.
const MAX_PENDING_CARRIED_INITIALS: usize = 2 * 64;

fn encode_carried_initial(message: &Incoming) -> session::Result<Vec<u8>> {
    use session::protocol::handshake_v2::InitialMessageV2 as Wire;
    let wire = match &message.kind {
        InitialMessageKind::Classical(m) => Wire {
            first_message: Some(m.first_message.clone()),
            ..Wire::from(&m.x3dh)
        },
        InitialMessageKind::Pq {
            x3dh,
            first_message,
            manifest_digest,
        } => Wire {
            first_message: Some(first_message.clone()),
            manifest_digest: manifest_digest
                .as_ref()
                .map_or_else(bytes::Bytes::new, |digest| {
                    bytes::Bytes::copy_from_slice(digest)
                }),
            ..Wire::from(x3dh)
        },
    };
    Ok(session::protocol::mailbox_v2::encode_carried_initial(&wire)?.to_vec())
}

fn decode_carried_initial(bytes: &[u8]) -> Option<Incoming> {
    InitialMessageV2::decode_carried(bytes)
}

pub(super) fn stage_carried_initials<'a>(
    state: &mut ContactState,
    initials: impl IntoIterator<Item = &'a Incoming>,
) -> Result<(), String> {
    let pending = &mut state.pending_carried_initials;
    for message in initials {
        let bytes = encode_carried_initial(message).map_err(|e| describe(&e))?;
        if !pending.contains(&bytes) {
            if pending.len() >= MAX_PENDING_CARRIED_INITIALS {
                return Err("Too many pending carried initial messages for this chat.".into());
            }
            pending.push(bytes);
        }
    }
    Ok(())
}

struct Inbox {
    messages: Vec<(PublicKey, u64, Incoming)>,
    malformed_ids: Vec<u64>,
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
    records: Vec<(PublicKey, (String, HistoryEntry))>,
    views: Vec<(PublicKey, MessageView)>,
    requeue: std::collections::BTreeSet<PublicKey>,
    upgrades: std::collections::BTreeSet<PublicKey>,
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

impl<V: HistoryStore> Inner<V> {
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
        self.save_state().await
    }

    async fn list_inbox(&mut self) -> session::Result<Inbox> {
        let listed = self
            .client
            .list_initial_messages_v2(&self.audience, 100)
            .await?;
        Ok(Inbox {
            messages: listed
                .messages
                .into_iter()
                .map(|m| (m.sender, m.id, m))
                .collect(),
            malformed_ids: listed.malformed_ids,
        })
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
        history: Vec<(PublicKey, (String, HistoryEntry))>,
        outbox: Vec<(PublicKey, (String, Option<OutgoingRecord>))>,
    ) -> Result<(), String> {
        let (peers, records): (Vec<_>, Vec<_>) = history.into_iter().unzip();
        let (outbox_peers, outgoing): (Vec<_>, Vec<_>) = outbox.into_iter().unzip();
        if let Err(e) = self.save_with(&records, &outgoing).await {
            self.unsaved.extend(peers.into_iter().zip(records));
            self.unsaved_outbox
                .extend(outbox_peers.into_iter().zip(outgoing));
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
        Self {
            kind: Some(e.kind()),
            definitive_refusal: false,
            malformed: false,
            message: describe(&e),
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

impl Engine {
    async fn ack_pending_inbox_v2(&self, inner: &mut Inner) -> Result<(), String> {
        inner
            .ack_persisted_inbox(async |client, audience, ids| {
                client
                    .ack_initial_messages_v2(audience, ids)
                    .await
                    .map(drop)
                    .map_err(|e| {
                        self.check_protocol_error(&e);
                        describe(&e)
                    })
            })
            .await
    }

    pub(super) async fn take_initial_messages(&self) -> Result<bool, String> {
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return Ok(false);
        };
        if inner.needs_save() {
            inner.save(&[]).await.map_err(|e| describe(&e))?;
        }
        self.ack_pending_inbox_v2(inner).await?;
        let inbox = match inner.list_inbox().await {
            Ok(inbox) => inbox,
            Err(e) => {
                self.check_protocol_error(&e);
                return Err(describe(&e));
            }
        };
        let mut batch = InitialBatch::default();
        for (peer, id, message) in inbox.messages {
            if !is_valid_inbox_ack_id(id) {
                self.ui.log(format!(
                    "Skipped initial message with out-of-range inbox ID {id}."
                ));
                continue;
            }
            if !stage_inbox_ack(&mut inner.state.pending_inbox_acks, id) {
                continue;
            }
            batch.dirty = true;
            let read = self.ui.open.get_untracked() == Some(peer) && !document().hidden();
            self.process_initial(inner, &peer, &message, read, &mut batch);
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
        if !batch.dirty {
            return Ok(false);
        }
        let upgrades = std::mem::take(&mut batch.upgrades);
        self.save_initial_batch(inner, batch).await?;
        let ack = self.ack_pending_inbox_v2(inner).await;
        drop(guard);
        for peer in upgrades {
            let _ = self.upgrade_to_pq(peer).await;
        }
        ack?;
        Ok(true)
    }

    /// Drain the peer's durable queue. Each removal commits with its prekeys, session and history.
    pub(super) async fn join_carried(
        &self,
        inner: &mut Inner<impl HistoryStore>,
        peer: &PublicKey,
    ) -> Result<bool, String> {
        inner.check_isolation(peer)?;
        let Some(index) = inner.contacts.iter().position(|c| c.peer == *peer) else {
            return Ok(false);
        };
        if inner.contacts[index].is_new_quarantined() {
            return Ok(false);
        }
        // A prior join may have consumed prekeys and staged history after a failed save.
        if inner.needs_save() {
            inner.save(&[]).await.map_err(|e| describe(&e))?;
        }
        let mut upgrade = false;
        while !inner.contacts[index]
            .state
            .pending_carried_initials
            .is_empty()
        {
            let bytes = inner.contacts[index]
                .state
                .pending_carried_initials
                .remove(0);
            let mut batch = InitialBatch::default();
            if let Some(message) = decode_carried_initial(&bytes) {
                self.process_initial(inner, peer, &message, false, &mut batch);
            } else {
                self.ui.log(format!(
                    "Discarded an unreadable carried initial message for {}.",
                    short(peer)
                ));
            }
            upgrade |= batch.upgrades.contains(peer);
            if batch.dirty {
                self.save_initial_batch(inner, batch).await?;
            } else if let Err(e) = inner.save_state().await {
                // Nothing consumed a prekey. Retry the original entry if storage recovers.
                inner.contacts[index]
                    .state
                    .pending_carried_initials
                    .insert(0, bytes);
                return Err(describe(&e));
            }
        }
        Ok(upgrade)
    }

    pub(super) fn process_initial(
        &self,
        inner: &mut Inner<impl HistoryStore>,
        peer: &PublicKey,
        message: &Incoming,
        read: bool,
        batch: &mut InitialBatch,
    ) {
        if *peer == inner.client.identity_key() {
            self.ui
                .log("dropped an initial message claiming to be from your own key");
            return;
        }
        if let Err(reason) = inner.check_isolation(peer) {
            self.ui.log(reason);
            return;
        }
        let opened = match inner.open_initial(peer, message) {
            Ok(opened) => opened,
            Err(e) => {
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
                return;
            }
        };
        batch.dirty = true; // Accepting also commits prekey consumption, even if the merge is rejected.
        let OpenedInitial {
            session,
            first_message,
            quarantine,
        } = opened;
        let local_pq = inner.local_pq_enabled();
        let existing = inner.contacts.iter().position(|c| c.peer == *peer);
        let contact = match existing {
            Some(index) => {
                let contact = &mut inner.contacts[index];
                if let Some(pinned) = quarantine {
                    contact.record_quarantined_initial(
                        Some(session.state().into()),
                        first_message,
                        pinned,
                        now(),
                    );
                    self.ui.log(format!(
                        "quarantined classical session request from {} pending approval",
                        short(peer)
                    ));
                    return;
                }
                let is_pq = session.security().is_some_and(|security| security.is_pq);
                match contact.replace_session(session, local_pq) {
                    Ok(took_over) => {
                        if is_pq {
                            contact.clear_quarantine_and_alerts();
                        }
                        if took_over && contact.state.needs_requeue_sealed {
                            batch.requeue.insert(*peer);
                        }
                    }
                    Err(e) => {
                        self.ui.log(format!(
                            "rejected incoming session from {}: {}",
                            short(peer),
                            describe(&e)
                        ));
                        contact.record_policy_error(e.kind());
                        return;
                    }
                }
                contact
            }
            None => {
                let mut contact = Contact {
                    peer: *peer,
                    session,
                    state: ContactState {
                        peer: peer.to_vec(),
                        request: true,
                        ..Default::default()
                    },
                };
                if let Some(pinned) = quarantine {
                    contact.state.quarantined_primary = true;
                    contact.record_quarantined_initial(None, first_message, pinned, now());
                    inner.contacts.push(contact);
                    self.ui.log(format!(
                        "quarantined classical chat request from {} pending approval",
                        short(peer)
                    ));
                    return;
                }
                self.ui.log(format!("chat request from {}", short(peer)));
                inner.contacts.push(contact);
                inner.contacts.last_mut().expect("just pushed")
            }
        };
        let content = Content::from_bytes(&first_message);
        if let Some(Kind::Hello(ref hello)) = content.kind {
            let check = contact.session.check_peer_hello(hello, local_pq);
            if check.downgrade_detected {
                contact.state.security_alert = SECURITY_ALERT_DOWNGRADE;
                if check.recommend_start_again
                    && !contact.state.request
                    && !contact.state.quarantined
                {
                    batch.upgrades.insert(*peer);
                }
            }
        }
        let (index, entry) = match contact.add_received(content, read) {
            Ok(record) => record,
            Err(reason) => {
                self.ui.log(format!(
                    "Skipped initial message history entry for {}. {reason}",
                    short(peer)
                ));
                return;
            }
        };
        if self.ui.open.get_untracked() == Some(*peer) {
            batch
                .views
                .push((*peer, contact.message(index, entry.clone())));
        }
        batch
            .records
            .push((*peer, (history_key(peer, index), entry)));
    }

    async fn save_initial_batch(
        &self,
        inner: &mut Inner<impl HistoryStore>,
        mut batch: InitialBatch,
    ) -> Result<(), String> {
        let mut outgoing = vec![];
        let mut changed = vec![];
        for peer in batch.requeue {
            match inner.requeue_sealed(&peer).await {
                Ok(outcome) => {
                    outcome.log_missing(&self.ui, &peer);
                    outgoing.extend(outcome.outbox.into_iter().map(|o| (peer, o)));
                    batch.records.extend(
                        records(&peer, &outcome.history)
                            .into_iter()
                            .map(|r| (peer, r)),
                    );
                    changed.push((peer, outcome.history));
                }
                // replace_session set the durable gate. flush retries before pushing any ciphertext.
                Err(e) => self.ui.log(format!(
                    "could not requeue pending messages for {} (will retry): {e}",
                    short(&peer)
                )),
            }
        }
        inner.save_inbox_changes(batch.records, outgoing).await?;
        for (peer, history) in changed {
            self.show_changes(inner, &peer, &history);
        }
        if let Some(open) = self.ui.open.get_untracked() {
            let views = batch
                .views
                .into_iter()
                .filter_map(|(peer, view)| (peer == open).then_some(view))
                .collect();
            self.show_new(inner, &open, views);
        }
        self.ui.contacts.set(inner.views());
        Ok(())
    }

    /// Execute a full signed-prekey + manifest publish under the held `inner` lock, preserving the
    /// structured [`ErrorKind`] so [`set_pq_config`](Self::set_pq_config) can distinguish definitive
    /// server refusals from transient network/sign-in failures.
    pub(super) async fn publish_full(
        &self,
        inner: &mut Inner,
        now_anyway: bool,
    ) -> Result<(), PublishError> {
        let prepared = inner
            .client
            .prepare_publish_v2(&inner.audience, ONE_TIME_PREKEYS, PQ_ONE_TIME_PREKEYS)
            .map_err(PublishError::prepare)?;
        // H-2: Persist new prekeys & manifest state BEFORE transmitting!
        inner.save_state().await.map_err(PublishError::storage)?;
        match inner.client.transmit_publish_v2(&prepared).await {
            Ok(outcome) => {
                inner.client.commit_publish_v2(prepared);
                self.publish_waits_sign_in.set(false);
                self.publish_waits_settings.set(false);
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
                        if inner.client.pq_config().pq_enabled {
                            inner.server_pq = ServerPqStatus::Disabled;
                            "published classical prekeys and signed PQ-off capability manifest (server PQ disabled)"
                        } else {
                            "published classical prekeys and signed PQ-off capability manifest"
                        }
                    }
                };
                inner
                    .save_full_publish_success()
                    .await
                    .map_err(PublishError::storage)?;
                self.ui.me.set(Some(inner.me()));
                self.ui.log(log_msg);
                Ok(())
            }
            Err(e) => {
                self.check_protocol_error(&e);
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
        inner: &mut Inner<impl HistoryStore>,
        mut error: PublishError,
        now_anyway: bool,
    ) -> Result<(), PublishError> {
        if error.needs_sign_in() {
            self.publish_waits_sign_in.set(true);
        }
        if error.rejects_settings() {
            if error.kind == Some(ErrorKind::PqRequired) {
                inner.server_pq = ServerPqStatus::Disabled;
                self.ui.me.set(Some(inner.me()));
            }
            if let Some(rollback) = &inner.state.pending_pq_rollback {
                match inner.client.set_pq_config(rollback.config()) {
                    Ok(()) => {
                        inner.state.needs_publish = rollback.previous_needs_publish;
                        inner.state.pending_pq_rollback = None;
                        self.ui.me.set(Some(inner.me()));
                        self.ui.log("The server refused the pending post-quantum settings. Restored the previous settings.");
                    }
                    Err(e) => {
                        inner.state.needs_publish = false;
                        self.publish_waits_settings.set(true);
                        error.message.push_str(&format!(
                            ". Could not restore previous settings: {}. Adjust post-quantum settings in Settings to retry.",
                            describe(&e)
                        ));
                    }
                }
            } else {
                inner.state.needs_publish = false;
                self.publish_waits_settings.set(true);
                let guidance = "The server refused the current post-quantum settings; automatic prekey publishing is paused. Open Settings to adjust post-quantum settings and retry.";
                self.ui.log(format!("{guidance} ({})", error.message));
                if !now_anyway {
                    self.ui.notify(guidance);
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
        inner: &mut Inner,
        classical_count: usize,
        pq_count: usize,
    ) -> Result<RefillV2Outcome, String> {
        let prepared = inner
            .client
            .prepare_refill_v2(&inner.audience, classical_count, pq_count)
            .map_err(|e| describe(&e))?;
        inner.save_state().await.map_err(|e| describe(&e))?;
        let response = match inner.client.transmit_refill_v2(&prepared).await {
            Ok(response) => response,
            Err(e) if !e.is_server_refusal() => return Err(describe(&e)),
            Err(e) => {
                inner.client.rollback_refill_v2_on_refusal(prepared);
                let outcome = match e.kind() {
                    ErrorKind::SignInRequired => {
                        self.publish_waits_sign_in.set(true);
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
                        inner.server_pq = ServerPqStatus::Disabled;
                        if inner.client.pq_config().strict_pq {
                            Err(describe(&e))
                        } else {
                            Ok(RefillV2Outcome::PqDisabled)
                        }
                    }
                    ErrorKind::Unimplemented => {
                        self.require_update(describe(&e));
                        Err(describe(&e))
                    }
                    ErrorKind::NotFound | ErrorKind::Protocol => {
                        inner.state.needs_publish = true;
                        Err(describe(&e))
                    }
                    _ => Err(describe(&e)),
                };
                inner.save_state().await.map_err(|e| describe(&e))?;
                self.ui.me.set(Some(inner.me()));
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
        self.ui
            .log("replenished one-time prekeys without rotating signed prekey");
        Ok(RefillV2Outcome::Handled)
    }

    /// Publish new prekeys (SPK rotation / PQ manifest) if due or requested, or replenish low
    /// OPKs/PQOPKs WITHOUT rotating SPK via non-rotating refill. Always persists newly generated
    /// private keys to IndexedDB BEFORE transmitting over the network (H-2).
    pub async fn publish(&self, now_anyway: bool) -> Result<(), String> {
        let mut guard = self.inner.lock().await;
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
            if (self.publish_waits_sign_in.get() || self.publish_waits_settings.get())
                && !now_anyway
            {
                return Ok(());
            }
            if now_anyway {
                self.publish_waits_settings.set(false);
            }
            return self
                .publish_full(inner, now_anyway)
                .await
                .map_err(|e| e.message);
        }

        // M-5: Non-rotating OPK/PQOPK refill (does NOT rotate SPK!).
        if self.publish_waits_sign_in.get() || self.publish_waits_settings.get() {
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

    /// Start a chat with `key`, named `name`, greeting the peer; or open the chat if there is one.
    ///
    /// When `pin_pq` is `true` (e.g. from a `#chat=...&pq=1` invitation link), pins the peer as
    /// post-quantum capable BEFORE the first `ClaimBundle` so server stripping hard-fails.
    /// When `allow_classical` is `true`, records an explicit user-approved classical fallback.
    /// Always persists the newly established session to IndexedDB BEFORE transmitting (H-2).
    pub async fn start_chat(
        &self,
        key: &str,
        name: String,
        pin_pq: bool,
        allow_classical: bool,
    ) -> Result<PublicKey, StartChatError> {
        let peer = key_from_text(key)
            .ok_or_else(|| StartChatError::Other("that is not an identity key".into()))?;
        let name = name.trim().to_string();
        let mut guard = self.inner.lock().await;
        let inner = guard
            .as_mut()
            .ok_or_else(|| StartChatError::Other("locked".into()))?;
        inner.check_outgoing_peer(&peer)?;
        if allow_classical
            && super::settings::check_classical_approval(inner.client.pq_config()).is_err()
        {
            return Err(StartChatError::PqRequired);
        }
        if let Some(contact) = inner.contact(&peer) {
            if pin_pq {
                contact.session.pin_peer_pq();
            }
            if allow_classical {
                contact
                    .session
                    .peer_pq_state_mut()
                    .approve_classical_exception();
                contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
            }
            if !contact.state.quarantined {
                contact.state.request = false;
            }
            if !name.is_empty() {
                contact.state.name = name;
            }
            inner
                .save_state()
                .await
                .map_err(|e| StartChatError::Other(describe(&e)))?;
            self.ui.contacts.set(inner.views());
            return Ok(peer);
        }

        let mut peer_state = PeerPqState::default();
        if pin_pq {
            peer_state.pin_peer_pq();
        }
        if allow_classical {
            peer_state.approve_classical_exception();
        }

        let hello = Kind::Hello(inner.client.make_hello(inner.state.name.clone(), 1));
        // The chat's first message, at its first place.
        let mut greeting = hello.to_bytes();
        stamp(&mut greeting, 1);
        let signs_in_here = same_server(&inner.server, &origin());

        let local_pq = inner.local_pq_enabled();
        let prepared = inner
            .client
            .prepare_initiate_v2(
                &inner.audience,
                &peer,
                &peer_state,
                &greeting,
                Fetch::client(&inner.server),
            )
            .await
            .map_err(|e| {
                if e.kind() == ErrorKind::Unimplemented && !local_pq {
                    self.require_update(describe(&e));
                }
                match e.kind() {
                    ErrorKind::SignInRequired if signs_in_here => StartChatError::SignInRequired,
                    ErrorKind::SignInRequired => {
                        StartChatError::Other(format!("sign-in required: {NOT_SIGNED_IN_HERE}"))
                    }
                    ErrorKind::ClassicalApprovalRequired { peer_signed_off } => {
                        StartChatError::ClassicalApprovalRequired { peer_signed_off }
                    }
                    ErrorKind::DowngradeDetected => StartChatError::DowngradeDetected,
                    ErrorKind::PeerManifestExpired => StartChatError::PeerManifestExpired,
                    ErrorKind::PqRequired => StartChatError::PqRequired,
                    ErrorKind::NotFound => StartChatError::Other(
                        "nobody published keys for that key on this server".to_string(),
                    ),
                    _ => StartChatError::Other(describe(&e)),
                }
            })?;
        let (session, outgoing_request) = (prepared.session, prepared.request);

        // Telling the peer that the chat was deleted here, if that has not gone yet, goes no
        // more: this session replaces the deleted one there anyway.
        let saved_farewells = inner.state.farewells.clone();
        inner.state.farewells.retain(|farewell| {
            farewell
                .recipient()
                .is_none_or(|recipient| recipient != peer.as_slice())
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
        inner.contacts.push(Contact {
            peer,
            session,
            state: ContactState {
                peer: peer.to_vec(),
                name,
                history_len: 1,
                last_activity: now(),
                clock: 1,
                ..ContactState::default()
            },
        });
        let record = (history_key(&peer, 0), entry);
        // H-2: Persist the newly created session BEFORE transmitting the initial message!
        if let Err(e) = inner.save(std::slice::from_ref(&record)).await {
            inner.contacts.pop();
            inner.state.farewells = saved_farewells;
            return Err(StartChatError::Other(describe(&e)));
        }
        // The contact is now durably persisted; no longer treat a greeting 403 as a pending draft.
        self.end_new_chat_submit();

        // Transmit the prepared initial message after durable local persistence.
        if let Err(e) = inner
            .client
            .send_prepared_initiate_v2(&outgoing_request)
            .await
        {
            let outgoing_is_pq = outgoing_request
                .message
                .as_ref()
                .is_some_and(|m| m.version >= 2);
            if e.kind() == ErrorKind::Unimplemented && !outgoing_is_pq {
                self.require_update(describe(&e));
            }
            if e.kind() == ErrorKind::SignInRequired && signs_in_here {
                let dialog = self
                    .sign_in_flow
                    .borrow_mut()
                    .on_chat_created_greeting_needs_sign_in();
                self.ui.dialog.set(Some(dialog));
            }
            self.ui.log(format!(
                "saved chat with {}, but could not send its initial greeting yet (it will carry on the first message): {}",
                short(&peer),
                describe(&e)
            ));
        }
        self.ui.contacts.set(inner.views());
        self.wake();
        Ok(peer)
    }
}

/// Build a persisted [`Farewell`] for `sealed` on `contact`'s active session, preserving any
/// carried v2/PQXDH initial message in `push_v2`.
pub(super) fn build_farewell(contact: &Contact, sealed: session::Sealed) -> Farewell {
    let v2 = contact.session.push_v2_request(sealed);
    let cid = v2.client_message_id.to_vec();
    let v2_bytes = v2.encode_to_vec();
    Farewell {
        push: None,
        client_message_id: cid,
        push_v2: v2_bytes,
    }
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
