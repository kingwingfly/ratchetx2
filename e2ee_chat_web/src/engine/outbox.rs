//! Durable outgoing messages, delivery updates and session replacement recovery.

use super::contact::{forget_told, keep_last};
use super::{
    Engine, HistoryStore, Inner, NOT_SIGNED_IN_HERE, ProtocolRpcScope, origin, records,
    same_server, should_require_update_for_rpc,
};
use crate::content::{Content, Events, Kind, stamp};
use crate::state::{Delivery, MessageView, Step, Ui};
use crate::util::{describe, now, short};
use crate::vault::{
    Awaiting, CLASSICAL_APPROVAL_LEGACY, CLASSICAL_APPROVAL_NONE, CLASSICAL_APPROVAL_SIGNED_OFF,
    ContactState, HistoryEntry, Outgoing, OutgoingRecord, SECURITY_ALERT_DOWNGRADE,
    SECURITY_ALERT_MANIFEST_EXPIRED, SECURITY_ALERT_NONE, SECURITY_ALERT_PQ_REQUIRED, SealedEvents,
    history_key, outbox_key,
};
use leptos::prelude::*;
use session::{ErrorKind, PublicKey};
use std::collections::{BTreeMap, BTreeSet, btree_map};

impl Engine {
    /// Push the messages waiting for `peer`, in order, each encrypted as its turn comes, then
    /// the events to tell the peer. Returns whether any went.
    pub(super) async fn flush(&self, peer: &PublicKey) -> Result<bool, String> {
        if self.waits_sign_in.borrow().contains(peer) {
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
        if inner.unsaved_state || inner.unsaved_outbox.iter().any(|(p, _)| p == peer) {
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
                // Pause sealing if waiting on explicit user action (classical approval / alert).
                if contact.session.needs_new_session()
                    && (contact.state.classical_approval_needed != CLASSICAL_APPROVAL_NONE
                        || contact.state.security_alert != SECURITY_ALERT_NONE)
                {
                    break;
                }
                // Encrypted now that it goes, so that its place is after what came so far; the
                // ones after it wait their turn.
                match inner.seal_next(peer).await {
                    Ok(SealOutcome::Ready) => {}
                    Ok(SealOutcome::Paused) => {
                        self.ui.contacts.set(inner.views());
                        break;
                    }
                    Ok(SealOutcome::Failed(reason)) => {
                        self.ui
                            .notify(format!("messages could not be sent: {reason}"));
                        if self.ui.open.get_untracked() == Some(*peer) {
                            self.show_history(inner, peer).await;
                        }
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
                Err(e) => {
                    result = Err(describe(&e));
                    break;
                }
            };
            let Some(contact) = inner.contact(peer) else {
                break;
            };
            let push_res = contact.session.push_v2(record.to_push()).await.map(|_| ());
            let step = match push_res {
                Ok(()) => {
                    self.release(peer, outgoing.history_index);
                    (Step::Pushed, outgoing.clock)
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
                    self.ui
                        .notify(format!("a message could not be sent: {NOT_SIGNED_IN_HERE}"));
                    (Step::Refused, 0)
                }
                // Too large for the server: it never will go.
                Err(e) if e.is_server_refusal() && e.kind() == ErrorKind::LimitExceeded => {
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
                        gone.push((outbox_key(peer, index), None));
                    }
                    Ok(None) => {
                        gone.push((outbox_key(peer, index), None));
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
        result.map(|()| changed)
    }

    /// Tell `peer` what this client did with its messages, all in one message, once what waits
    /// for it went: on the session, never starting one for it, and never in a request or
    /// quarantined chat, whose sender learns nothing until it is accepted/approved. Encrypted and
    /// saved once, then pushed as it is until it goes, so that no key of the ratchet is used twice.
    /// Once pushed, clearing `sealed_events` is persisted immediately to the vault.
    async fn push_events(&self, inner: &mut Inner, peer: &PublicKey) -> Result<bool, String> {
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
                let snapshot = contact.snapshot();
                let message = contact
                    .session
                    .encrypt(&events.to_bytes())
                    .map_err(|e| describe(&e))?;
                let sealed = SealedEvents {
                    record: Some(OutgoingRecord::sealed(message)),
                    session: active.unwrap_or_default(),
                    events: Some(events),
                };
                contact.state.sealed_events = Some(sealed.clone());
                if let Err(e) = inner.save(&[]).await {
                    inner.roll_back(peer, snapshot)?;
                    return Err(describe(&e));
                }
                sealed
            }
        };
        let contact = inner.contact(peer).ok_or("no such chat")?;
        let message = sealed.record.unwrap_or_default().to_push();
        match contact.session.push_v2(message).await {
            Ok(_) => {}
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
        let snapshot = contact.snapshot();
        contact.state.sealed_events = None;
        if let (Some(events), Some(told)) = (&mut contact.state.events, &sealed.events) {
            forget_told(events, told);
        }
        if contact.state.events.as_ref().is_some_and(Events::is_empty) {
            contact.state.events = None;
        }
        if let Err(e) = inner.save(&[]).await {
            inner.roll_back(peer, snapshot)?;
            return Err(describe(&e));
        }
        Ok(true)
    }

    /// Fail the message at `index`, to `peer`, which never went, as it was cancelled: it leaves
    /// the outbox, so that what was sent after it goes.
    pub(super) async fn fail_waiting(
        &self,
        inner: &mut Inner,
        peer: &PublicKey,
        index: u64,
    ) -> Result<(), String> {
        let contact = inner.contact(peer).ok_or("no such chat")?;
        let snapshot = contact.snapshot();
        contact
            .state
            .outbox
            .retain(|outgoing| outgoing.history_index != index);
        let mut entries = BTreeMap::new();
        let failed = match inner
            .step(peer, &mut entries, [(index, Step::Refused)])
            .await
        {
            Ok(()) => {
                let changed: Vec<_> = entries.into_iter().collect();
                inner
                    .save_with(&records(peer, &changed), &[(outbox_key(peer, index), None)])
                    .await
                    .map(|()| changed)
            }
            Err(e) => Err(e),
        };
        match failed {
            Ok(changed) => {
                self.release(peer, index);
                self.show_changes(inner, peer, &changed);
                Ok(())
            }
            Err(e) => {
                inner.roll_back(peer, snapshot)?;
                Err(describe(&e))
            }
        }
    }
}

/// Result of [`Inner::seal_next`].
enum SealOutcome {
    /// Ready to push (or nothing unsealed left).
    Ready,
    /// Paused pending explicit user security decision (classical approval / downgrade / expired manifest).
    Paused,
    /// Permanently failed to start a session (e.g. peer has no keys); outbox entries marked failed.
    Failed(String),
    /// Server rejected the v2 protocol (`ErrorKind::Unimplemented`); prompt the user to refresh.
    UpdateRequired(String),
}

impl Inner {
    /// Add `content` to the chat with `peer`, to be pushed in its turn, see `flush`: one that
    /// `awaits_upload` waits, with those after it, for its attachment's upload to start. Saved,
    /// or else forgotten; returns how it shows.
    pub(super) async fn add(
        &mut self,
        peer: &PublicKey,
        content: Kind,
        awaits_upload: bool,
    ) -> Result<MessageView, String> {
        let contact = self.contact(peer).ok_or("no such chat")?;
        if contact.state.request {
            return Err("accept the request first".into());
        }
        if contact.state.quarantined {
            return Err("approve classical encryption or upgrade to post-quantum first".into());
        }
        // If saving fails, the message is forgotten: it never left.
        let snapshot = contact.snapshot();
        let index = contact.next_history_index().map_err(str::to_string)?;
        // Encrypted as it goes, once its place in the chat is known, see `flush`.
        let record = OutgoingRecord {
            message: None,
            content: content.to_bytes(),
            delivery_hash: vec![],
        };
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
        let view = contact.message(index, entry.clone());
        let saved = self
            .save_with(
                &[(history_key(peer, index), entry)],
                &[(outbox_key(peer, index), Some(record))],
            )
            .await;
        if let Err(e) = saved {
            self.roll_back(peer, snapshot)?;
            return Err(describe(&e));
        }
        Ok(view)
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
            let pq_cfg = self.client.pq_config().clone();
            let greeting = Kind::Hello(
                self.contacts[index]
                    .session
                    .make_hello(self.state.name.clone(), &pq_cfg),
            );
            self.contacts[index].state.clock = self.contacts[index].state.clock.saturating_add(1);
            let mut hello = greeting.to_bytes();
            stamp(&mut hello, self.contacts[index].state.clock);

            let local_pq = self.local_pq_enabled();
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
                    if let Some(contact) = self.contact(peer) {
                        contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                        contact.state.security_alert = SECURITY_ALERT_NONE;
                    }
                    // H-2: Persist new session BEFORE transmitting!
                    if let Err(e) = self.save(&[]).await {
                        self.roll_back(peer, snapshot)?;
                        return Err(describe(&e));
                    }
                    let _ = self.client.send_prepared_initiate_v2(&outgoing).await;
                }
                Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::InvalidKeys) => {
                    self.roll_back(peer, snapshot)?;
                    return self
                        .fail_waiting(peer, describe(&e))
                        .await
                        .map(SealOutcome::Failed);
                }
                Err(e) => {
                    let kind = e.kind();
                    self.roll_back(peer, snapshot)?;
                    if should_require_update_for_rpc(ProtocolRpcScope::CoreV2, &e) && !local_pq {
                        return Ok(SealOutcome::UpdateRequired(describe(&e)));
                    }
                    let paused = match kind {
                        ErrorKind::ClassicalApprovalRequired { peer_signed_off } => {
                            if let Some(contact) = self.contact(peer) {
                                contact.state.classical_approval_needed = if peer_signed_off {
                                    CLASSICAL_APPROVAL_SIGNED_OFF
                                } else {
                                    CLASSICAL_APPROVAL_LEGACY
                                };
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
        let mut content = self
            .vault
            .outgoing(peer, index)
            .await
            .map_err(|e| describe(&e))?
            .content;
        let contact = self.contact(peer).ok_or("no such chat")?;
        let snapshot = contact.snapshot();
        let clock = contact.state.clock.saturating_add(1);
        stamp(&mut content, clock);
        let sealed = contact
            .session
            .encrypt(&content)
            .map_err(|e| describe(&e))?;
        contact.state.clock = clock;
        let outgoing = &mut contact.state.outbox[next];
        (outgoing.sealed, outgoing.clock) = (true, clock);
        let record = OutgoingRecord::sealed(sealed);
        if let Err(e) = self
            .save_with(&[], &[(outbox_key(peer, index), Some(record))])
            .await
        {
            self.roll_back(peer, snapshot)?;
            return Err(describe(&e));
        }
        Ok(SealOutcome::Ready)
    }
}

impl<V: HistoryStore> Inner<V> {
    /// Fail the messages waiting to `peer`, as they cannot go, for `reason`, which it returns.
    pub(super) async fn fail_waiting(
        &mut self,
        peer: &PublicKey,
        reason: String,
    ) -> Result<String, String> {
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
        let gone: Vec<_> = waiting
            .iter()
            .map(|index| (outbox_key(peer, *index), None))
            .collect();
        let entries: Vec<_> = entries.into_iter().collect();
        let contact = self.contact(peer).ok_or("no such chat")?;
        let snapshot = contact.snapshot();
        contact.state.outbox.retain(|outgoing| outgoing.sealed);
        if let Err(e) = self.save_with(&records(peer, &entries), &gone).await {
            self.roll_back(peer, snapshot)?;
            return Err(describe(&e));
        }
        Ok(reason)
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
        let snapshot = contact.snapshot();
        let outcome = match self.requeue_sealed(peer).await {
            Ok(outcome) => outcome,
            Err(e) => {
                self.roll_back(peer, snapshot)?;
                return Err(e);
            }
        };
        if let Err(e) = self
            .save_with(&records(peer, &outcome.history), &outcome.outbox)
            .await
        {
            self.roll_back(peer, snapshot)?;
            return Err(describe(&e));
        }
        Ok(Some(outcome))
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
    pub(super) outbox: Vec<(String, Option<OutgoingRecord>)>,
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
                Some(OutgoingRecord {
                    content: kind.to_bytes(),
                    ..Default::default()
                })
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
        self.outbox.push((outbox_key(peer, index), record));
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
pub(super) fn needs_new_session(inner: &Inner, peer: &PublicKey) -> bool {
    inner
        .contacts
        .iter()
        .any(|contact| contact.peer == *peer && contact.session.needs_new_session())
}
