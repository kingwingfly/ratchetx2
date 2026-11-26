//! Durable outgoing messages, delivery updates and session replacement recovery.

use super::attachments::ServerDeleteJob;
use super::contact::{forget_told, keep_last};
use super::{
    Engine, Inner, NOT_SIGNED_IN_HERE, ProtocolRpcScope, VaultStore, origin, records, same_server,
    should_require_update_for_rpc,
};
use crate::content::{Content, Events, Kind, stamp};
use crate::state::{Delivery, MessageView, Step, Ui};
use crate::util::{describe, now, short};
use crate::vault::{
    Awaiting, CLASSICAL_APPROVAL_NONE, CLASSICAL_APPROVAL_SIGNED_OFF, ContactState,
    GREETING_DELIVERY_CONFIRMED, GREETING_DELIVERY_UNCERTAIN, HistoryEntry, Outgoing,
    OutgoingRecord, SECURITY_ALERT_DOWNGRADE, SECURITY_ALERT_MANIFEST_EXPIRED, SECURITY_ALERT_NONE,
    SECURITY_ALERT_PQ_REQUIRED, SealedEvents,
};
use bytes::Bytes;
use leptos::prelude::*;
use session::protocol::handshake_v2::SendInitialV2Request;
use session::{ErrorKind, PublicKey};
use std::collections::{BTreeMap, BTreeSet, btree_map};

impl<V: VaultStore> Engine<V> {
    /// Push the messages waiting for `peer`, in order, each encrypted as its turn comes, then
    /// the events to tell the peer. Returns whether any went.
    pub(super) async fn flush(&self, peer: &PublicKey) -> Result<bool, String> {
        if self.waits_sign_in.borrow().contains(peer) || self.is_approval_backed_off(peer) {
            return Ok(false);
        }
        // With messages waiting and no session to send on, the peer may have started one, e.g.
        // having deleted the chat and started it again: taken first, it is sent on, rather than
        // another started, which the peer might set aside. If taking fails, one starts.
        let waits = {
            let guard = self.inner.lock().await;
            guard.as_ref().is_some_and(|inner| {
                inner.contacts.iter().any(|contact| {
                    contact.peer == *peer
                        && contact.session.needs_new_session()
                        && !contact.state.outbox.is_empty()
                })
            })
        };
        if waits {
            let _ = self.take_initial_messages().await;
        }
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return Ok(false);
        };
        // Flush any unsaved requeued outbox records before `seal_next` reads from IndexedDB,
        // ensuring we never encrypt stale empty-content records after an earlier save failure.
        if inner.unsaved_state || inner.unsaved_outbox.iter().any(|(p, _, _)| p == peer) {
            inner.save(&[]).await.map_err(|e| describe(&e))?;
        }
        // Never send or send receipts on a brand-new quarantined classical contact.
        if inner
            .contacts
            .iter()
            .any(|c| c.peer == *peer && c.is_new_quarantined())
        {
            return Ok(false);
        }
        if let Some(outcome) = inner.requeue_before_push(peer).await? {
            outcome.log_missing(&self.ui, peer);
            self.show_changes(inner, peer, &outcome.history);
        }
        let mut changed = false;
        let mut result = Ok(());
        let mut server_deletes: Vec<ServerDeleteJob> = vec![];
        // Completed outbox items (with their original `Outgoing` so M-18 can keep any item whose
        // history entry failed to read from IndexedDB instead of deleting its outbox record).
        // Items stay in `contact.state.outbox` until the atomic `save_with` below commits (or
        // rolls back cleanly on failure), indexed via `pushed_count`.
        let mut completed: Vec<(Outgoing, Step, u64)> = vec![];
        let mut pushed_count = 0usize;
        // Whether this page can sign in to the server, which only its own page can: otherwise a
        // message that takes it never goes, and must not hold up those after it.
        let signs_in_here = same_server(&inner.server, &origin());
        while let Some(contact) = inner.contact(peer)
            && let Some(outgoing) = contact.state.outbox.get(pushed_count).cloned()
        {
            // An attachment whose upload has not started: it, and what was sent after it, wait
            // for it to start.
            if outgoing.awaits_upload {
                break;
            }
            if !outgoing.sealed {
                // Pause sealing if waiting on explicit user action (quarantine / classical approval / alert).
                if contact.session.needs_new_session()
                    && (contact.state.quarantined
                        || contact.state.classical_approval_needed != CLASSICAL_APPROVAL_NONE
                        || contact.state.security_alert != SECURITY_ALERT_NONE)
                {
                    break;
                }
                let needed_new_session = contact.session.needs_new_session();
                // Encrypted now that it goes, so that its place is after what came so far; the
                // ones after it wait their turn.
                match inner.seal_next(peer).await {
                    Ok(SealOutcome::Ready) => {
                        if needed_new_session
                            && inner
                                .contact(peer)
                                .is_some_and(|c| !c.session.needs_new_session())
                        {
                            self.ui.contacts.set(inner.views());
                        }
                    }
                    Ok(SealOutcome::Paused) => {
                        self.ui.contacts.set(inner.views());
                        break;
                    }
                    Ok(SealOutcome::Failed(reason, failed_indices)) => {
                        for idx in &failed_indices {
                            self.release(peer, *idx);
                        }
                        server_deletes.extend(
                            self.prepare_cancel_uploads_for_failed(inner, peer, &failed_indices)
                                .await,
                        );
                        self.ui
                            .notify(format!("messages could not be sent: {reason}"));
                        if self.ui.open.get_untracked() == Some(*peer) {
                            self.show_history(inner, peer).await;
                        }
                        changed = true;
                    }
                    Ok(SealOutcome::CorruptDropped(dropped_index, history)) => {
                        self.release(peer, dropped_index);
                        server_deletes.extend(
                            self.prepare_cancel_uploads_for_failed(inner, peer, &[dropped_index])
                                .await,
                        );
                        self.ui.log(format!(
                            "Dropped corrupt pending message #{dropped_index} for {}: outbox record could not be recovered",
                            short(peer)
                        ));
                        self.show_changes(inner, peer, &history);
                        changed = true;
                    }
                    Ok(SealOutcome::UpdateRequired(reason)) => {
                        self.require_update(reason.clone());
                        result = Err(reason);
                        break;
                    }
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
                continue;
            }
            let record = match inner.vault.outgoing(peer, outgoing.history_index).await {
                Ok(record) => record,
                Err(crate::vault::Error::Corrupt(reason)) => {
                    match inner
                        .recover_corrupt_outbox(peer, outgoing.history_index)
                        .await
                    {
                        Ok(CorruptOutboxRecovery::Rebuilt(_)) => {
                            self.ui.log(format!(
                                "Rebuilt corrupt outbox record #{} for {} ({reason})",
                                outgoing.history_index,
                                short(peer)
                            ));
                            changed = true;
                            continue;
                        }
                        Ok(CorruptOutboxRecovery::Dropped { history }) => {
                            self.release(peer, outgoing.history_index);
                            server_deletes.extend(
                                self.prepare_cancel_uploads_for_failed(
                                    inner,
                                    peer,
                                    &[outgoing.history_index],
                                )
                                .await,
                            );
                            self.ui.log(format!(
                                "Dropped corrupt outbox record #{} for {} ({reason})",
                                outgoing.history_index,
                                short(peer)
                            ));
                            self.show_changes(inner, peer, &history);
                            changed = true;
                            continue;
                        }
                        Err(e) => {
                            result = Err(e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    result = Err(describe(&e));
                    break;
                }
            };
            // If this sealed record belongs to an older session than `active_id`, requeue sealed
            // outbox items on the current active session before transmitting.
            let stale_session = !record.session_id.is_empty()
                && inner.contact(peer).is_some_and(|c| {
                    c.session
                        .active_id()
                        .is_some_and(|id| id.as_slice() != record.session_id.as_slice())
                });
            if stale_session {
                if let Some(contact) = inner.contact(peer) {
                    contact.state.needs_requeue_sealed = true;
                }
                if let Some(outcome) = inner.requeue_before_push(peer).await? {
                    outcome.log_missing(&self.ui, peer);
                    self.show_changes(inner, peer, &outcome.history);
                }
                continue;
            }
            let Some(sealed_msg) = record.to_sealed() else {
                match inner
                    .recover_corrupt_outbox(peer, outgoing.history_index)
                    .await
                {
                    Ok(CorruptOutboxRecovery::Rebuilt(_)) => {
                        self.ui.log(format!(
                            "Rebuilt incomplete sealed outbox record #{} for {}",
                            outgoing.history_index,
                            short(peer)
                        ));
                        changed = true;
                        continue;
                    }
                    Ok(CorruptOutboxRecovery::Dropped { history }) => {
                        self.release(peer, outgoing.history_index);
                        server_deletes.extend(
                            self.prepare_cancel_uploads_for_failed(
                                inner,
                                peer,
                                &[outgoing.history_index],
                            )
                            .await,
                        );
                        self.show_changes(inner, peer, &history);
                        changed = true;
                        continue;
                    }
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
            };
            // Persist `GREETING_DELIVERY_UNCERTAIN` BEFORE transmitting a message that can carry a
            // previously unsent initial greeting so a lost response still notifies an established
            // peer on deletion without carrying the unconfirmed greeting.
            let push_res = match inner
                .transmit_with_greeting_delivery(peer, false, false, async |inner| {
                    let Some(contact) = inner.contact(peer) else {
                        return Err(session::Error::from(ErrorKind::NotFound));
                    };
                    contact.session.push_v2(&sealed_msg).await.map(|_| ())
                })
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            };
            if inner.contact(peer).is_none() {
                break;
            }
            let step = match push_res {
                Ok(()) => {
                    self.clear_approval_backoff(peer);
                    self.release(peer, outgoing.history_index);
                    (Step::Pushed, outgoing.clock)
                }
                Err(e) if e.kind() == ErrorKind::WriteTokenRejected => {
                    let known = inner
                        .contact(peer)
                        .is_some_and(|c| c.session.is_known_by_peer());
                    if known {
                        // Peer previously accepted us and has since revoked/deleted the chat:
                        // retire active session and requeue so the next sync starts fresh.
                        if let Some(contact) = inner.contact(peer) {
                            contact.state.needs_requeue_sealed = true;
                            contact.session.retire();
                        }
                        let _ = inner.save_state().await;
                        self.ui.contacts.set(inner.views());
                        break;
                    }
                    // Peer has not yet accepted our chat request: retry idempotent `SendInitialV2`
                    // at most once if greeting delivery wasn't confirmed, then back off without
                    // dropping the outbox or setting an offline error.
                    let greeting_unconfirmed = inner
                        .contact(peer)
                        .is_some_and(|c| c.state.greeting_delivery != GREETING_DELIVERY_CONFIRMED);
                    if greeting_unconfirmed
                        && !record.carried_initial.is_empty()
                        && let Some(wire_initial) =
                            session::protocol::mailbox_v2::decode_carried_initial(
                                &record.carried_initial,
                            )
                    {
                        let retry_req = SendInitialV2Request {
                            recipient: Bytes::copy_from_slice(peer),
                            message: Some(wire_initial),
                        };
                        if inner
                            .client
                            .send_prepared_initiate_v2(&retry_req)
                            .await
                            .is_ok()
                        {
                            if let Some(contact) = inner.contact(peer) {
                                contact.mark_greeting_confirmed();
                            }
                            let _ = inner.save_state().await;
                        }
                    }
                    let delay_ms = self.record_approval_backoff(peer);
                    let label = inner
                        .contact(peer)
                        .map_or_else(|| short(peer), |c| c.view().label());
                    self.ui.log(format!(
                        "Waiting for {label} to accept your chat request (retrying in {}s)…",
                        delay_ms / 1000
                    ));
                    break;
                }
                // Large enough to cost the server storage, which it keeps only for those signed
                // in to it: it waits, with those after it, until this browser is.
                Err(e) if e.kind() == ErrorKind::SignInRequired && signs_in_here => {
                    self.waits_sign_in.borrow_mut().insert(*peer);
                    self.hold(peer, outgoing.history_index);
                    self.ask_sign_in();
                    break;
                }
                // The same, but this page cannot sign in to the server: it never will go.
                Err(e) if e.kind() == ErrorKind::SignInRequired => {
                    self.release(peer, outgoing.history_index);
                    self.ui
                        .notify(format!("a message could not be sent: {NOT_SIGNED_IN_HERE}"));
                    (Step::Refused, 0)
                }
                // Too large for the server: it never will go.
                Err(e) if e.is_server_refusal() && e.kind() == ErrorKind::LimitExceeded => {
                    self.release(peer, outgoing.history_index);
                    self.ui
                        .notify(format!("a message could not be sent: {}", describe(&e)));
                    (Step::Refused, 0)
                }
                Err(e) => {
                    self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                    result = Err(describe(&e));
                    break;
                }
            };
            completed.push((outgoing, step.0, step.1));
            pushed_count += 1;
            changed = true;
        }
        if !completed.is_empty() {
            let pushed_any = completed.iter().any(|(_, step, _)| *step == Step::Pushed);
            let mut entries = vec![];
            let mut gone = vec![];
            let mut keep_in_outbox = vec![];
            let mut new_awaiting = vec![];
            for (outgoing, step, clock) in completed {
                let index = outgoing.history_index;
                match inner.vault.entry(peer, index).await {
                    Ok(Some(mut entry)) => {
                        entry.set_delivery(entry.delivery().after(step));
                        // Pushed, it has its place, and waits for the peer to read it.
                        if step == Step::Pushed {
                            entry.place = clock;
                            let content = entry.content.get_or_insert_default();
                            content.clock = clock;
                            let attachment = matches!(content.kind, Some(Kind::Attachment(_)));
                            new_awaiting.push(Awaiting {
                                place: clock,
                                history_index: index,
                                read: false,
                                attachment,
                            });
                        }
                        entries.push((index, entry));
                        gone.push((*peer, index, None));
                    }
                    Ok(None) => {
                        gone.push((*peer, index, None));
                    }
                    // M-18: Do NOT delete outbox entries when reading the history entry fails!
                    Err(e) => {
                        result = Err(describe(&e));
                        keep_in_outbox.push(outgoing);
                    }
                }
            }
            if !gone.is_empty() {
                // Take a snapshot after any committed `seal_next` advances and BEFORE mutating
                // `outbox`/`awaiting` so a `save_with` failure rolls back cleanly without
                // stranding history entries as `Pending`.
                let snapshot = inner.contact(peer).map(|c| c.snapshot());
                if let Some(contact) = inner.contact(peer) {
                    let drain_end = pushed_count.min(contact.state.outbox.len());
                    contact.state.outbox.splice(0..drain_end, keep_in_outbox);
                    if pushed_any {
                        contact.mark_greeting_confirmed();
                    }
                    if !new_awaiting.is_empty() {
                        contact.state.awaiting.extend(new_awaiting);
                        keep_last(&mut contact.state.awaiting);
                    }
                }
                if let Err(e) = inner.save_with(&records(peer, &entries), &gone).await {
                    if let Some(snapshot) = snapshot {
                        inner.roll_back(peer, snapshot)?;
                    }
                    return Err(describe(&e));
                }
                self.show_changes(inner, peer, &entries);
                let refused_indices: Vec<u64> = entries
                    .iter()
                    .filter(|(_, entry)| entry.delivery() == Delivery::Failed)
                    .map(|(index, _)| *index)
                    .collect();
                if !refused_indices.is_empty() {
                    server_deletes.extend(
                        self.prepare_cancel_uploads_for_failed(inner, peer, &refused_indices)
                            .await,
                    );
                }
            }
        }
        // Not from a page that cannot sign in to the server, which takes no push from it: each
        // try would use up a key of the ratchet.
        if result.is_ok() && signs_in_here {
            match self.push_events(inner, peer).await {
                Ok(told) => changed |= told,
                Err(e) => result = Err(e),
            }
        }
        drop(guard);
        if !server_deletes.is_empty() {
            self.finish_server_deletes(peer, server_deletes).await;
        }
        result.map(|()| changed)
    }

    /// Tell `peer` what this client did with its messages, all in one message, once what waits
    /// for it went: on the session, never starting one for it, and never in a request or
    /// quarantined chat, whose sender learns nothing until it is accepted/approved. Encrypted and
    /// saved once, then pushed as it is until it goes, so that no key of the ratchet is used twice.
    /// Once pushed, clearing `sealed_events` is persisted immediately to the vault.
    async fn push_events(&self, inner: &mut Inner<V>, peer: &PublicKey) -> Result<bool, String> {
        let Some(contact) = inner.contact(peer) else {
            return Ok(false);
        };
        if contact.state.request
            || contact.state.quarantined
            || !contact.state.outbox.is_empty()
            || contact.session.needs_new_session()
        {
            return Ok(false);
        }
        let active = contact.session.active_id().map(|id| id.to_vec());
        // One encrypted on a session that is no longer the active one, which the peer may never
        // have had: what it tells, still in the events, is encrypted again on the active one.
        if contact
            .state
            .sealed_events
            .as_ref()
            .is_some_and(|sealed| Some(&sealed.session) != active.as_ref())
        {
            contact.state.sealed_events = None;
        }
        let sealed = match contact.state.sealed_events.clone() {
            Some(sealed) => sealed,
            None => {
                let Some(events) = contact
                    .state
                    .events
                    .clone()
                    .filter(|events| !events.is_empty())
                else {
                    return Ok(false);
                };
                inner
                    .with_contact_tx(peer, async |inner| {
                        let contact = inner
                            .contact(peer)
                            .ok_or_else(|| "no such chat".to_string())?;
                        let message = contact
                            .session
                            .encrypt(&events.to_bytes())
                            .map_err(|e| describe(&e))?;
                        let session_id = active.clone().unwrap_or_default();
                        let sealed = SealedEvents {
                            record: Some(OutgoingRecord::sealed(message, &session_id)),
                            session: session_id,
                            events: Some(events),
                        };
                        contact.state.sealed_events = Some(sealed.clone());
                        inner.save(&[]).await.map_err(|e| describe(&e))?;
                        Ok::<_, String>(sealed)
                    })
                    .await?
            }
        };
        let Some(message) = sealed.record.as_ref().and_then(OutgoingRecord::to_sealed) else {
            if let Some(contact) = inner.contact(peer) {
                contact.state.sealed_events = None;
            }
            let _ = inner.save_state().await;
            return Ok(false);
        };
        let push_res = inner
            .transmit_with_greeting_delivery(peer, false, false, async |inner| {
                let contact = inner.contact(peer).ok_or(ErrorKind::NotFound)?;
                contact.session.push_v2(&message).await
            })
            .await?;
        match push_res {
            Ok(_) => {
                self.clear_approval_backoff(peer);
            }
            Err(e) if e.kind() == ErrorKind::WriteTokenRejected => {
                let known = inner
                    .contact(peer)
                    .is_some_and(|c| c.session.is_known_by_peer());
                if known {
                    if let Some(contact) = inner.contact(peer) {
                        contact.state.sealed_events = None;
                        contact.state.needs_requeue_sealed = true;
                        contact.session.retire();
                    }
                    let _ = inner.save_state().await;
                } else {
                    self.record_approval_backoff(peer);
                }
                return Ok(false);
            }
            // The chat waits for the sign-in, as a message refused for it does, rather than
            // tries every round, and goes once signed in.
            Err(e) if e.kind() == ErrorKind::SignInRequired => {
                self.waits_sign_in.borrow_mut().insert(*peer);
                return Ok(false);
            }
            Err(e) => {
                self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                return Err(describe(&e));
            }
        }
        // Those told since it was encrypted stay, to go in the next. Persist immediately after
        // clearing `sealed_events` so reload never re-pushes already-sent events.
        inner
            .with_contact_tx(peer, async |inner| {
                let contact = inner
                    .contact(peer)
                    .ok_or_else(|| "no such chat".to_string())?;
                contact.mark_greeting_confirmed();
                contact.state.sealed_events = None;
                if let (Some(events), Some(told)) = (&mut contact.state.events, &sealed.events) {
                    forget_told(events, told);
                }
                if contact.state.events.as_ref().is_some_and(Events::is_empty) {
                    contact.state.events = None;
                }
                inner.save(&[]).await.map_err(|e| describe(&e))
            })
            .await?;
        Ok(true)
    }

    /// Fail the message at `index`, to `peer`, which never went, as it was cancelled: it leaves
    /// the outbox, so that what was sent after it goes.
    pub(super) async fn fail_waiting(
        &self,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        index: u64,
    ) -> Result<(), String> {
        let changed = inner
            .with_contact_tx(peer, async |inner| {
                let contact = inner
                    .contact(peer)
                    .ok_or_else(|| "no such chat".to_string())?;
                contact
                    .state
                    .outbox
                    .retain(|outgoing| outgoing.history_index != index);
                let mut entries = BTreeMap::new();
                inner
                    .step(peer, &mut entries, [(index, Step::Refused)])
                    .await
                    .map_err(|e| describe(&e))?;
                let changed: Vec<_> = entries.into_iter().collect();
                inner
                    .save_with(&records(peer, &changed), &[(*peer, index, None)])
                    .await
                    .map_err(|e| describe(&e))?;
                Ok::<_, String>(changed)
            })
            .await?;
        self.release(peer, index);
        self.show_changes(inner, peer, &changed);
        Ok(())
    }
}

/// Result of [`Inner::seal_next`].
enum SealOutcome {
    /// Ready to push (or nothing unsealed left).
    Ready,
    /// Paused pending explicit user security decision (classical approval / downgrade / expired manifest).
    Paused,
    /// Permanently failed to start a session (e.g. peer has no keys); outbox entries marked failed.
    Failed(String, Vec<u64>),
    /// Unrecoverable corrupt outbox record was dropped and its history entry marked failed.
    CorruptDropped(u64, Vec<(u64, HistoryEntry)>),
    /// Server rejected the v2 protocol (`ErrorKind::Unimplemented`); prompt the user to refresh.
    UpdateRequired(String),
}

/// Result of [`Inner::recover_corrupt_outbox`].
pub(super) enum CorruptOutboxRecovery {
    /// Rebuilt unsealed content bytes from `history`/`file` and reset the outbox item to unsealed.
    Rebuilt(Vec<u8>),
    /// Original history content was missing or corrupt too: dropped the outbox item and marked its
    /// history entry `Failed` so subsequent sends are unblocked.
    Dropped { history: Vec<(u64, HistoryEntry)> },
}

impl<V: VaultStore> Inner<V> {
    /// Add `content` to the chat with `peer`, to be pushed in its turn, see `flush`: one that
    /// `awaits_upload` waits, with those after it, for its attachment's upload to start. Saved,
    /// or else forgotten; returns how it shows.
    pub(super) async fn add(
        &mut self,
        peer: &PublicKey,
        content: Kind,
        awaits_upload: bool,
    ) -> Result<MessageView, String> {
        if let Kind::Text(ref text) = content
            && text.len() > super::MAX_TEXT_BYTES
        {
            return Err(format!(
                "Message is too long (maximum {} KiB).",
                super::MAX_TEXT_BYTES / 1024
            ));
        }
        let contact = self.contact(peer).ok_or("no such chat")?;
        if contact.state.request {
            return Err("accept the request first".into());
        }
        if contact.state.quarantined {
            return Err("approve classical encryption or upgrade to post-quantum first".into());
        }
        // If saving fails, the message is forgotten: it never left.
        self.with_contact_tx(peer, async |inner| {
            let contact = inner
                .contact(peer)
                .ok_or_else(|| "no such chat".to_string())?;
            let index = contact.next_history_index().map_err(str::to_string)?;
            contact.mark_index_acked(index);
            // Encrypted as it goes, once its place in the chat is known, see `flush`.
            let record = OutgoingRecord::unsealed(content.to_bytes());
            contact.state.last_activity = now();
            contact.state.outbox.push(Outgoing {
                history_index: index,
                sealed: false,
                clock: 0,
                awaits_upload,
            });
            let entry = HistoryEntry {
                outgoing: true,
                at: now(),
                content: Some(Content {
                    kind: Some(content),
                    ..Content::default()
                }),
                delivery: Delivery::Pending.into(),
                ..HistoryEntry::default()
            };
            contact.record_last_message(&entry);
            let view = contact.message(index, entry.clone());
            inner
                .save_with(&[(*peer, index, entry)], &[(*peer, index, Some(record))])
                .await
                .map_err(|e| describe(&e))?;
            Ok(view)
        })
        .await
    }

    /// Encrypt the next message waiting to `peer`, now that it goes, at the next place in the
    /// chat, after what came so far: on the session, or on a new one if there is none to send
    /// on, as the two kept missing each other or the peer deleted the chat. Persists the new
    /// session BEFORE transmitting its initial message (H-2).
    async fn seal_next(&mut self, peer: &PublicKey) -> Result<SealOutcome, String> {
        let Some(index) = self.contacts.iter().position(|c| c.peer == *peer) else {
            return Err("no such chat".into());
        };
        if self.contacts[index].session.needs_new_session() {
            let snapshot = self.contacts[index].snapshot();
            let prev_next_session_seq = self.state.next_session_seq;
            let session_seq = self.next_new_chat_session_seq();
            self.state.next_session_seq = session_seq
                .saturating_add(1)
                .min(session::protocol::MAX_SAFE_INTEGER);
            let greeting =
                Kind::Hello(self.client.make_hello(self.state.name.clone(), session_seq));
            self.contacts[index].state.clock = self.contacts[index].state.clock.saturating_add(1);
            let mut hello = greeting.to_bytes();
            stamp(&mut hello, self.contacts[index].state.clock);

            let prepared = {
                let audience = &self.audience;
                let client = &mut self.client;
                let contact = &mut self.contacts[index];
                client
                    .prepare_start_again_v2(audience, &mut contact.session, &hello)
                    .await
            };
            match prepared {
                Ok(outgoing) => {
                    let token_hash = self.contact(peer).and_then(|contact| {
                        contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                        contact.state.security_alert = SECURITY_ALERT_NONE;
                        contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
                        contact.session.active_inbound_token_hash()
                    });
                    if let Some(token_hash) = token_hash
                        && let Err(e) = self.stage_write_token_grant(peer, token_hash, true)
                    {
                        self.state.next_session_seq = prev_next_session_seq;
                        self.roll_back(peer, snapshot)?;
                        return Err(e);
                    }
                    // H-2: Persist new session, grant, and uncertain delivery marker BEFORE transmitting!
                    if let Err(e) = self.save(&[]).await {
                        self.state.next_session_seq = prev_next_session_seq;
                        self.roll_back(peer, snapshot)?;
                        return Err(describe(&e));
                    }
                    // Register our new inbound write token BEFORE sending the re-initiation.
                    let _ = self.flush_pending_grants_for(peer).await;
                    if let Ok(Err(e)) = self
                        .transmit_with_greeting_delivery(peer, true, true, async |inner| {
                            inner.client.send_prepared_initiate_v2(&outgoing).await
                        })
                        .await
                        && should_require_update_for_rpc(ProtocolRpcScope::CoreV2, &e)
                    {
                        return Ok(SealOutcome::UpdateRequired(describe(&e)));
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::InvalidKeys) => {
                    self.state.next_session_seq = prev_next_session_seq;
                    self.roll_back(peer, snapshot)?;
                    return self
                        .fail_waiting(peer, describe(&e))
                        .await
                        .map(|(reason, failed)| SealOutcome::Failed(reason, failed));
                }
                Err(e) => {
                    let kind = e.kind();
                    self.state.next_session_seq = prev_next_session_seq;
                    self.roll_back(peer, snapshot)?;
                    if should_require_update_for_rpc(ProtocolRpcScope::CoreV2, &e) {
                        return Ok(SealOutcome::UpdateRequired(describe(&e)));
                    }
                    let paused = match kind {
                        ErrorKind::ClassicalApprovalRequired => {
                            if let Some(contact) = self.contact(peer) {
                                if matches!(
                                    contact.state.security_alert,
                                    SECURITY_ALERT_PQ_REQUIRED | SECURITY_ALERT_MANIFEST_EXPIRED
                                ) {
                                    contact.state.security_alert = SECURITY_ALERT_NONE;
                                }
                                contact.state.classical_approval_needed =
                                    CLASSICAL_APPROVAL_SIGNED_OFF;
                            }
                            true
                        }
                        ErrorKind::DowngradeDetected => {
                            if let Some(contact) = self.contact(peer) {
                                contact.session.peer_pq_state_mut().downgrade_detected = true;
                                contact.state.security_alert = SECURITY_ALERT_DOWNGRADE;
                            }
                            true
                        }
                        ErrorKind::PeerManifestExpired => {
                            if let Some(contact) = self.contact(peer) {
                                contact.state.security_alert = SECURITY_ALERT_MANIFEST_EXPIRED;
                            }
                            true
                        }
                        ErrorKind::PqRequired => {
                            if let Some(contact) = self.contact(peer) {
                                contact.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                            }
                            true
                        }
                        _ => false,
                    };
                    if paused {
                        self.save_state().await.map_err(|e| describe(&e))?;
                        return Ok(SealOutcome::Paused);
                    }
                    if kind == ErrorKind::ClockSkew {
                        return Err(super::CLOCK_SKEW_MESSAGE.to_string());
                    }
                    return Err(describe(&e));
                }
            }
        }
        let contact = self.contact(peer).ok_or("no such chat")?;
        let Some(next) = contact
            .state
            .outbox
            .iter()
            .position(|outgoing| !outgoing.sealed)
        else {
            return Ok(SealOutcome::Ready);
        };
        let index = contact.state.outbox[next].history_index;
        let mut content = match self.vault.outgoing(peer, index).await {
            Ok(mut record) => std::mem::take(&mut record.content),
            Err(crate::vault::Error::Corrupt(_)) => {
                match self.recover_corrupt_outbox(peer, index).await? {
                    CorruptOutboxRecovery::Rebuilt(bytes) => bytes,
                    CorruptOutboxRecovery::Dropped { history } => {
                        return Ok(SealOutcome::CorruptDropped(index, history));
                    }
                }
            }
            Err(e) => return Err(describe(&e)),
        };
        self.with_contact_tx(peer, async |inner| {
            let contact = inner
                .contact(peer)
                .ok_or_else(|| "no such chat".to_string())?;
            let Some(next) = contact
                .state
                .outbox
                .iter()
                .position(|outgoing| outgoing.history_index == index && !outgoing.sealed)
            else {
                return Ok(());
            };
            let clock = contact.state.clock.saturating_add(1);
            stamp(&mut content, clock);
            let session_id = contact
                .session
                .active_id()
                .map(|id| id.to_vec())
                .unwrap_or_default();
            let sealed = contact
                .session
                .encrypt(&content)
                .map_err(|e| describe(&e))?;
            contact.state.clock = clock;
            let outgoing = &mut contact.state.outbox[next];
            (outgoing.sealed, outgoing.clock) = (true, clock);
            let record = OutgoingRecord::sealed(sealed, &session_id);
            inner
                .save_with(&[], &[(*peer, index, Some(record))])
                .await
                .map_err(|e| describe(&e))
        })
        .await?;
        Ok(SealOutcome::Ready)
    }

    /// Recover from a missing or corrupt `outbox/<peer>/<index>` record instead of permanently
    /// wedging all subsequent sends to `peer`: rebuild an unsealed outbox record from
    /// `vault.entry` + `vault.content` when intact, otherwise mark the history entry `Failed` and
    /// drop the corrupt outbox item.
    pub(super) async fn recover_corrupt_outbox(
        &mut self,
        peer: &PublicKey,
        index: u64,
    ) -> Result<CorruptOutboxRecovery, String> {
        let entry = match self.vault.entry(peer, index).await {
            Ok(entry) => entry,
            Err(crate::vault::Error::Corrupt(_)) => None,
            Err(e) => return Err(describe(&e)),
        };
        let content = match &entry {
            Some(entry) => match self.vault.content(peer, index, entry).await {
                Ok(content) => content,
                Err(crate::vault::Error::Corrupt(_)) => None,
                Err(e) => return Err(describe(&e)),
            },
            None => None,
        };
        match (entry, content) {
            (Some(_), Some(kind)) => {
                let bytes = kind.to_bytes();
                let rebuilt = OutgoingRecord::unsealed(bytes.clone());
                self.with_contact_tx(peer, async |inner| {
                    let contact = inner
                        .contact(peer)
                        .ok_or_else(|| "no such chat".to_string())?;
                    if let Some(outgoing) = contact
                        .state
                        .outbox
                        .iter_mut()
                        .find(|o| o.history_index == index)
                    {
                        outgoing.sealed = false;
                        outgoing.clock = 0;
                    }
                    inner
                        .save_with(&[], &[(*peer, index, Some(rebuilt))])
                        .await
                        .map_err(|e| describe(&e))
                })
                .await?;
                Ok(CorruptOutboxRecovery::Rebuilt(bytes))
            }
            (entry, _) => {
                let history = match entry {
                    Some(mut entry) => {
                        entry.set_delivery(Delivery::Failed);
                        vec![(index, entry)]
                    }
                    None => vec![],
                };
                self.with_contact_tx(peer, async |inner| {
                    let contact = inner
                        .contact(peer)
                        .ok_or_else(|| "no such chat".to_string())?;
                    contact.state.outbox.retain(|o| o.history_index != index);
                    inner
                        .save_with(&records(peer, &history), &[(*peer, index, None)])
                        .await
                        .map_err(|e| describe(&e))
                })
                .await?;
                Ok(CorruptOutboxRecovery::Dropped { history })
            }
        }
    }
    /// Fail the messages waiting to `peer`, as they cannot go, for `reason`, returning `reason`
    /// together with the failed history indices so callers can release held/upload state.
    pub(super) async fn fail_waiting(
        &mut self,
        peer: &PublicKey,
        reason: String,
    ) -> Result<(String, Vec<u64>), String> {
        let contact = self.contact(peer).ok_or("no such chat")?;
        let waiting: Vec<_> = contact
            .state
            .outbox
            .iter()
            .filter(|outgoing| !outgoing.sealed)
            .map(|outgoing| outgoing.history_index)
            .collect();
        let mut entries = BTreeMap::new();
        let steps = waiting.iter().map(|index| (*index, Step::Refused));
        self.step(peer, &mut entries, steps)
            .await
            .map_err(|e| describe(&e))?;
        let gone: Vec<_> = waiting.iter().map(|index| (*peer, *index, None)).collect();
        let entries: Vec<_> = entries.into_iter().collect();
        self.with_contact_tx(peer, async |inner| {
            let contact = inner
                .contact(peer)
                .ok_or_else(|| "no such chat".to_string())?;
            contact.state.outbox.retain(|outgoing| outgoing.sealed);
            inner
                .save_with(&records(peer, &entries), &gone)
                .await
                .map_err(|e| describe(&e))
        })
        .await?;
        Ok((reason, waiting))
    }

    /// Move the history entries of the chat with `peer` on by `steps`, each read from the vault
    /// into `entries`, unless there already.
    pub(super) async fn step(
        &self,
        peer: &PublicKey,
        entries: &mut BTreeMap<u64, HistoryEntry>,
        steps: impl IntoIterator<Item = (u64, Step)>,
    ) -> crate::vault::Result<()> {
        for (index, step) in steps {
            let entry = match entries.entry(index) {
                btree_map::Entry::Occupied(entry) => entry.into_mut(),
                btree_map::Entry::Vacant(vacant) => match self.vault.entry(peer, index).await? {
                    Some(entry) => vacant.insert(entry),
                    None => continue,
                },
            };
            entry.set_delivery(entry.delivery().after(step));
            // Waiting again, it has no place until it goes.
            if entry.delivery() == Delivery::Pending {
                entry.place = 0;
            }
        }
        Ok(())
    }

    /// Rebuild ciphertext from the retired session, and messages the peer had not read when
    /// they deleted the chat. Delivery changes from this mailbox page take precedence over disk.
    pub(super) async fn requeue(
        &mut self,
        peer: &PublicKey,
        deleted: bool,
        entries: &BTreeMap<u64, HistoryEntry>,
    ) -> Result<RequeueOutcome, String> {
        let contact = self.contact(peer).ok_or("no such chat")?;
        let again = if deleted {
            contact
                .state
                .awaiting
                .iter()
                .filter(|a| !a.read)
                .map(|a| a.history_index)
                .collect()
        } else {
            BTreeSet::new()
        };
        let all_sealed = contact.state.needs_requeue_sealed || contact.session.needs_new_session();
        let outcome = self
            .rebuild_outbox(peer, again, all_sealed, entries)
            .await?;
        if deleted {
            let contact = self.contact(peer).ok_or("no such chat")?;
            contact.state.awaiting.clear();
            contact.state.events = None;
            contact.state.sealed_events = None;
            contact.state.unseen.clear();
        }
        Ok(outcome)
    }

    /// Complete a deferred requeue before flush can read or transmit any sealed record.
    pub(super) async fn requeue_before_push(
        &mut self,
        peer: &PublicKey,
    ) -> Result<Option<RequeueOutcome>, String> {
        let Some(contact) = self.contact(peer) else {
            return Ok(None);
        };
        let retired =
            contact.session.needs_new_session() && contact.state.outbox.iter().any(|o| o.sealed);
        if !contact.state.needs_requeue_sealed && !retired {
            return Ok(None);
        }
        self.with_contact_tx(peer, async |inner| {
            let outcome = inner.requeue_sealed(peer).await?;
            inner
                .save_with(&records(peer, &outcome.history), &outcome.outbox)
                .await
                .map_err(|e| describe(&e))?;
            Ok(Some(outcome))
        })
        .await
    }

    /// Re-encrypt every sealed outbox item after an active session replacement.
    pub(super) async fn requeue_sealed(
        &mut self,
        peer: &PublicKey,
    ) -> Result<RequeueOutcome, String> {
        self.rebuild_outbox(peer, BTreeSet::new(), true, &BTreeMap::new())
            .await
    }

    async fn rebuild_outbox(
        &mut self,
        peer: &PublicKey,
        again: BTreeSet<u64>,
        all_sealed: bool,
        entries: &BTreeMap<u64, HistoryEntry>,
    ) -> Result<RequeueOutcome, String> {
        let contact = self.contact(peer).ok_or("no such chat")?;
        let sealed = contact
            .state
            .outbox
            .iter()
            .filter(|o| all_sealed && o.sealed)
            .map(|o| o.history_index)
            .collect();
        let mut outcome = RequeueOutcome::default();
        for &index in again.union(&sealed) {
            let entry = match entries.get(&index) {
                Some(entry) => Some(entry.clone()),
                None => self
                    .vault
                    .entry(peer, index)
                    .await
                    .map_err(|e| describe(&e))?,
            };
            let content = match &entry {
                Some(entry) => self
                    .vault
                    .content(peer, index, entry)
                    .await
                    .map_err(|e| describe(&e))?,
                None => None,
            };
            outcome.stage(peer, index, entry, content, again.contains(&index));
        }
        // No contact state changes until every fallible history and file read has completed.
        let state = &mut self.contact(peer).ok_or("no such chat")?.state;
        outcome.apply(state, &again, &sealed);
        if all_sealed {
            state.needs_requeue_sealed = false;
        }
        Ok(outcome)
    }
}

#[derive(Default)]
pub(super) struct RequeueOutcome {
    pub(super) outbox: Vec<(PublicKey, u64, Option<OutgoingRecord>)>,
    pub(super) history: Vec<(u64, HistoryEntry)>,
    dropped_missing: BTreeSet<u64>,
}

impl RequeueOutcome {
    fn stage(
        &mut self,
        peer: &PublicKey,
        index: u64,
        entry: Option<HistoryEntry>,
        content: Option<Kind>,
        resend: bool,
    ) {
        let record = match (entry, content) {
            (Some(mut entry), Some(kind)) => {
                if resend {
                    entry.set_delivery(entry.delivery().after(Step::Resent));
                    if entry.delivery() == Delivery::Pending {
                        entry.place = 0;
                    }
                    self.history.push((index, entry));
                }
                Some(OutgoingRecord::unsealed(kind.to_bytes()))
            }
            (entry, _) => {
                if let Some(mut entry) = entry {
                    entry.set_delivery(Delivery::Failed);
                    self.history.push((index, entry));
                }
                self.dropped_missing.insert(index);
                None
            }
        };
        self.outbox.push((*peer, index, record));
    }

    fn apply(&self, state: &mut ContactState, again: &BTreeSet<u64>, sealed: &BTreeSet<u64>) {
        state.outbox.retain_mut(|outgoing| {
            let index = outgoing.history_index;
            if sealed.contains(&index) {
                outgoing.sealed = false;
                outgoing.clock = 0;
            }
            !self.dropped_missing.contains(&index) && !again.contains(&index)
        });
        state.outbox.splice(
            0..0,
            again
                .difference(&self.dropped_missing)
                .map(|&index| Outgoing {
                    history_index: index,
                    ..Default::default()
                }),
        );
    }

    pub(super) fn log_missing(&self, ui: &Ui, peer: &PublicKey) {
        for index in &self.dropped_missing {
            ui.log(format!(
                "Dropped pending message #{index} for {}: original history content missing",
                short(peer)
            ));
        }
    }
}

/// Whether the chat with `peer` has no session to send on.
pub(super) fn needs_new_session<V>(inner: &Inner<V>, peer: &PublicKey) -> bool {
    inner
        .contacts
        .iter()
        .any(|contact| contact.peer == *peer && contact.session.needs_new_session())
}
