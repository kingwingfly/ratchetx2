//! Server notifications, synchronization and incoming mailbox pages.

use super::handshake::{
    Incoming, JoinCarriedOutcome, record_carried_timestamps, stage_carried_initials,
};
use super::outbox::{RequeueOutcome, needs_new_session};
use super::{
    AWAY_CHECK, Engine, HIDDEN_GRACE, HistoryStore, Inner, POLL_AWAY, POLL_FAST, POLL_LIVE,
    POLL_SLOW, POLL_STEP, ProtocolRpcScope, RESUBSCRIBE_MAX, RESUBSCRIBE_MIN, UNFOCUSED_GRACE,
    origin, records, same_server, should_require_update_for_rpc,
};
use crate::content::{Content, Kind};
use crate::notify::{Event, Subscription};
use crate::state::{Link, ServerPqStatus};
use crate::transport::{Connect, Fetch};
use crate::util::{describe, monotonic_now_ms, now, sleep};
use crate::vault::{
    ContactState, Farewell, HistoryEntry, OutgoingRecord, SECURITY_ALERT_DOWNGRADE,
};
use bytes::Bytes;
use futures::future::{Either, select};
use leptos::prelude::*;
use leptos::task::spawn_local;
use prost::Message as _;
use session::protocol::handshake_v2::InitialMessageV2 as WireInitialMessageV2;
use session::protocol::mailbox_v2::{CLIENT_MESSAGE_ID_LENGTH, LocalMailboxV2, PushV2Request};
use session::protocol::notify::{self, Notification};
use session::{Client, ErrorKind, PqSuite, PublicKey, Sealed, Session, proto};
use std::collections::BTreeMap;
use std::rc::Rc;

impl Engine {
    /// Whether the user is here: the page shown and in focus, or hidden for less than
    /// [`HIDDEN_GRACE`], or out of focus for less than [`UNFOCUSED_GRACE`]. Notifications are
    /// for then only, as a WebSocket open is held on the server.
    pub(super) fn present(&self) -> bool {
        let document = document();
        let grace = if document.hidden() {
            Some(HIDDEN_GRACE)
        } else if !document.has_focus().unwrap_or(true) {
            Some(UNFOCUSED_GRACE)
        } else {
            None
        };
        let present = match grace {
            Some(grace) => {
                let now = monotonic_now_ms();
                let since = *self.away_since.get().get_or_insert(now);
                self.away_since.set(Some(since));
                now.saturating_sub(since) < grace
            }
            None => {
                self.away_since.set(None);
                true
            }
        };
        if self.ui.away.get_untracked() == present {
            self.ui.away.set(!present);
        }
        present
    }

    /// Sync until the page goes.
    pub(super) fn run(self: Rc<Self>) {
        spawn_local(async move {
            let mut delay = POLL_FAST;
            loop {
                let asked = self.ui.syncing.get_untracked();
                let active = self.sync().await;
                if asked {
                    self.ui.syncing.set(false);
                }
                delay = if self.ui.live.get_untracked()
                    || self.ui.update_required.with_untracked(Option::is_some)
                {
                    POLL_LIVE
                } else if active {
                    POLL_FAST
                } else {
                    (delay * 3 / 2).min(POLL_SLOW)
                };
                let mut waited = 0;
                let mut was_present = self.present();
                loop {
                    if self.wake.replace(false) {
                        delay = POLL_FAST;
                        break;
                    }
                    let present = self.present();
                    // Back: what came meanwhile, at once.
                    if present && !was_present {
                        delay = POLL_FAST;
                        break;
                    }
                    was_present = present;
                    if waited >= if present { delay } else { delay.max(POLL_AWAY) } {
                        break;
                    }
                    sleep(POLL_STEP).await;
                    waited += POLL_STEP;
                }
            }
        });
    }

    /// Subscribe to this client's notifications while the user is here, until the page goes,
    /// subscribing again whenever the socket closes, and act on each. Away, the socket closes,
    /// which tells the server, and opens again on coming back.
    pub(super) fn listen(self: Rc<Self>) {
        spawn_local(async move {
            let mut retry = RESUBSCRIBE_MIN;
            loop {
                if self.ui.update_required.with_untracked(Option::is_some) {
                    self.ui.live.set(false);
                    return;
                }
                while !self.present() {
                    if self.ui.update_required.with_untracked(Option::is_some) {
                        self.ui.live.set(false);
                        return;
                    }
                    sleep(AWAY_CHECK).await;
                }
                let subscribed = {
                    let mut guard = self.inner.lock().await;
                    let Some(inner) = guard.as_mut() else {
                        return;
                    };
                    inner
                        .client
                        .subscription_for_audience(&inner.server)
                        .map_err(|e| describe(&e))
                        .and_then(|request| Subscription::open(&inner.server, &request))
                };
                let mut left = false;
                match subscribed {
                    Ok(mut subscription) => loop {
                        let next =
                            select(Box::pin(subscription.next()), Box::pin(sleep(AWAY_CHECK)));
                        match next.await {
                            Either::Left((Event::Open, _)) => {
                                self.ui.live.set(true);
                                retry = RESUBSCRIBE_MIN;
                                // What came while it was closed has no notification.
                                self.wake();
                            }
                            Either::Left((Event::Notification(notification), _)) => {
                                self.notified(notification).await
                            }
                            Either::Left((Event::Resync, _)) => self.wake(),
                            Either::Left((Event::UpgradeRequired(reason), _)) => {
                                self.require_update(reason);
                                self.ui.live.set(false);
                                return;
                            }
                            Either::Left((Event::Closed, _)) => break,
                            Either::Right(_)
                                if self.ui.update_required.with_untracked(Option::is_some) =>
                            {
                                self.ui.live.set(false);
                                return;
                            }
                            // Away: dropped, the subscription closes its socket.
                            Either::Right(_) if !self.present() => {
                                left = true;
                                break;
                            }
                            Either::Right(_) => {}
                        }
                    },
                    Err(e) => self
                        .ui
                        .log(format!("cannot subscribe to notifications: {e}")),
                }
                self.ui.live.set(false);
                if self.ui.update_required.with_untracked(Option::is_some) {
                    return;
                }
                if left {
                    retry = RESUBSCRIBE_MIN;
                    continue;
                }
                sleep(retry).await;
                retry = (retry * 2).min(RESUBSCRIBE_MAX);
            }
        });
    }

    /// Fetch what `notification` says arrived; if that fails, sync soon.
    async fn notified(&self, notification: Notification) {
        let fetched = match notification.event {
            Some(notify::Event::MessageFrom(sender)) => {
                match PublicKey::try_from(sender.as_ref()) {
                    // Then what it moved on goes, e.g. events to tell, or messages to send
                    // again, as the peer deleted the chat.
                    Ok(peer) => match self.receive(&peer).await {
                        Ok(_) => self.flush(&peer).await.map(drop),
                        Err(e) => Err(e),
                    },
                    Err(_) => return,
                }
            }
            Some(notify::Event::InitialMessage(_)) => self.take_initial_messages().await.map(drop),
            None => return,
        };
        if fetched.is_err() {
            self.wake();
        }
    }

    /// Sync soon.
    pub fn wake(&self) {
        self.wake.set(true);
    }

    /// Sync now, as asked on the page, showing it until done.
    pub fn sync_now(&self) {
        self.ui.syncing.set(true);
        self.wake();
    }

    /// Query `GetServerInfo` verifying `server_id` against the client's locally derived expected
    /// audience (never blindly trusting server-supplied audience strings).
    pub(super) async fn refresh_server_info(&self, force: bool) {
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return;
        };
        if !force && inner.server_pq != ServerPqStatus::Unknown {
            return;
        }
        let status = match inner.client.check_server_info(&inner.audience).await {
            Ok(info) if info.pq_enabled => {
                let suites = info
                    .supported_suites
                    .iter()
                    .filter_map(|&s| u8::try_from(s).ok().and_then(PqSuite::from_u8))
                    .collect();
                ServerPqStatus::Enabled {
                    suites,
                    pq_ratchet: info.pq_ratchet_supported,
                }
            }
            Ok(_) => ServerPqStatus::Disabled,
            Err(e) if should_require_update_for_rpc(ProtocolRpcScope::CoreV2, &e) => {
                self.require_update(describe(&e));
                return;
            }
            Err(e) if e.kind() == ErrorKind::DowngradeDetected => {
                self.ui.log(format!(
                    "server identity mismatch for {}: possible relay impersonation",
                    inner.audience
                ));
                self.ui.notify(format!(
                    "Server identity mismatch for {} — refusing to trust server PQ metadata.",
                    inner.audience
                ));
                ServerPqStatus::AudienceMismatch
            }
            Err(_) => return,
        };
        if inner.server_pq != status {
            inner.server_pq = status;
            self.ui.me.set(Some(inner.me()));
        }
    }

    /// One round: save what an earlier save failed to, check server PQ info, tell peers of chats
    /// deleted here, take initial messages, publish/refill prekeys when due, receive, and push what
    /// waits. Returns whether anything happened.
    pub(super) async fn sync(&self) -> bool {
        // A step that keeps failing, e.g. a large file timing out over a slow link, a take of
        // initial messages the server refuses, or one chat's queue that cannot be fetched, must
        // not keep the round from the other steps and chats: its error is kept, and the round
        // goes on. Receiving goes before pushing, so that what waits since the user was offline
        // goes on a new session if the peer deleted the chat meanwhile.
        let (mut active, mut failure) = match self.recover_local_changes().await {
            Ok(recovered) => (recovered, None),
            Err(e) => (false, Some(e)),
        };
        self.refresh_server_info(false).await;
        if let Err(e) = self.say_farewells().await {
            failure.get_or_insert(e);
        }
        let reached = match self.take_initial_messages().await {
            Ok(taken) => {
                active |= taken;
                true
            }
            Err(e) => {
                failure.get_or_insert(e);
                false
            }
        };
        // Not while the server does not answer signed requests: each publish that fails keeps
        // its new one-time prekeys, as the server may have them, see `Client::publish_keys`, so
        // retrying every round while offline would grow the state, which each save writes whole.
        if reached && let Err(e) = self.publish(false).await {
            failure.get_or_insert(e);
        }
        for peer in self.peers().await {
            match self.receive(&peer).await {
                Ok(received) => active |= received,
                Err(e) => {
                    failure.get_or_insert(e);
                }
            }
        }
        for peer in self.peers().await {
            match self.flush(&peer).await {
                Ok(pushed) => active |= pushed,
                Err(e) => {
                    failure.get_or_insert(e);
                }
            }
        }
        match failure {
            None => self.ui.link.set(Link::Synced(now())),
            Some(e) => self.ui.link.set(Link::Offline(e)),
        }
        active
    }

    /// Retry failed writes and join the initials left on disk before contacting the relay.
    async fn recover_local_changes(&self) -> Result<bool, String> {
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return Ok(false);
        };
        if inner.needs_save() {
            inner.save(&[]).await.map_err(|e| describe(&e))?;
        }
        let late = std::mem::take(&mut inner.saved_late);
        if std::mem::take(&mut inner.contacts_dirty_late) || !late.is_empty() {
            self.ui.me.set(Some(inner.me()));
            self.ui.contacts.set(inner.views());
            // The open chat shows them in their places.
            if let Some(open) = self.ui.open.get_untracked()
                && late.contains(&open)
            {
                self.show_history(inner, &open).await;
            }
        }
        let open_peer = self
            .ui
            .open
            .get_untracked()
            .filter(|_| !document().hidden());
        let replayed = self.replay_deferred_initials(inner, open_peer).await?;
        let pending: Vec<_> = inner
            .contacts
            .iter()
            .filter(|c| {
                c.deferred_carried < c.state.pending_carried_initials.len()
                    && !c.is_new_quarantined()
            })
            .map(|c| c.peer)
            .collect();
        let recovered = replayed.is_some() || !pending.is_empty();
        let mut upgrades = replayed.unwrap_or_default();
        for peer in pending {
            if self.join_carried(inner, &peer).await?.recommend_upgrade {
                upgrades.insert(peer);
            }
        }
        drop(guard);
        for peer in upgrades {
            let _ = self.upgrade_to_pq(peer).await;
        }
        Ok(recovered)
    }

    /// Push the messages telling peers that their chats were deleted here, see
    /// [`delete`](Self::delete).
    pub(super) async fn say_farewells(&self) -> Result<(), String> {
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return Ok(());
        };
        let signs_in_here = same_server(&inner.server, &origin());
        while let Some(farewell) = inner.state.farewells.first().cloned() {
            let v2_req = farewell_push_v2_request(&farewell);
            let pushed: session::Result<()> = Fetch::client(&inner.server)
                .push_v2(v2_req)
                .await
                .map(|_| ())
                .map_err(session::Error::from);
            match pushed {
                Ok(()) => {}
                // Pushing takes a sign-in: they wait for it, without failing the round.
                Err(e) if e.kind() == ErrorKind::SignInRequired && signs_in_here => return Ok(()),
                // Refused for good, e.g. as the peer's inbox is full, or as this page cannot sign
                // in to the server: it must not hold up the others, nor keep the sync failing.
                Err(e)
                    if e.is_server_refusal()
                        && matches!(
                            e.kind(),
                            ErrorKind::LimitExceeded
                                | ErrorKind::Protocol
                                | ErrorKind::SignInRequired
                        ) =>
                {
                    self.ui.log(format!(
                        "could not tell a deleted chat's peer of it: {}",
                        describe(&e)
                    ));
                }
                Err(e) => {
                    self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                    return Err(describe(&e));
                }
            }
            inner.state.farewells.remove(0);
            inner.save_state().await.map_err(|e| describe(&e))?;
        }
        Ok(())
    }

    pub(super) async fn peers(&self) -> Vec<PublicKey> {
        let inner = self.inner.lock().await;
        inner
            .iter()
            .flat_map(|inner| inner.contacts.iter().map(|contact| contact.peer))
            .collect()
    }

    /// Receive the messages from `peer`, a page at a time. Returns whether any came.
    pub(super) async fn receive(&self, peer: &PublicKey) -> Result<bool, String> {
        let mut received = false;
        let mut recommend_upgrade = false;
        loop {
            let mut guard = self.inner.lock().await;
            let Some(inner) = guard.as_mut() else {
                return Ok(received);
            };
            let open = self.ui.open.get_untracked() == Some(*peer) && !document().hidden();
            let local_pq = inner.local_pq_enabled();
            let Some(index) = inner.contacts.iter().position(|c| c.peer == *peer) else {
                return Ok(received);
            };
            // Never fetch/decrypt or send receipts on a brand-new quarantined classical contact.
            if inner.contacts[index].is_new_quarantined() {
                return Ok(received);
            }
            recommend_upgrade |= self.join_carried(inner, peer).await?.recommend_upgrade;
            let (page, snapshot) = inner
                .fetch_page(index, async |session, client, audience| {
                    let res = session.fetch_v2(client, audience).await;
                    if let Err(ref e) = res {
                        self.check_protocol_error(ProtocolRpcScope::CoreV2, e);
                    }
                    res
                })
                .await?;
            if page.is_empty() {
                inner.persist_empty_page_progress(peer, snapshot).await?;
                break;
            }
            let contact = &mut inner.contacts[index];
            let (mut entries, mut undecryptable, mut evicted) = (vec![], 0usize, 0usize);
            // A stalled page also needs a fresh look at the relay's separate initial-message inbox.
            let mut stalled = false;
            let mut carried_initials = vec![];
            let mut deleted = false;
            // What the peer told of this client's messages, by their history entries.
            let mut steps = vec![];
            for message in page {
                if message.is_evicted() {
                    evicted += 1;
                    match contact.add_evicted() {
                        Ok(entry) => entries.push(entry),
                        Err(reason) => {
                            inner.roll_back(peer, snapshot)?;
                            return Err(reason.into());
                        }
                    }
                    continue;
                }
                let content = match message.content {
                    Ok(content) => content,
                    // At a message that may be on a session whose initial message is waiting,
                    // the page's last.
                    Err(e) if e.kind() == ErrorKind::Stalled => {
                        stalled = true;
                        carried_initials.extend(message.initial_messages);
                        continue;
                    }
                    // Trailing carried initial messages from expired server envelopes.
                    Err(e) if e.kind() == ErrorKind::Expired => {
                        carried_initials.extend(message.initial_messages);
                        continue;
                    }
                    Err(e) if e.kind() == ErrorKind::DuplicateMessage => continue,
                    // Anyone can push to a queue, and an earlier session's messages stay in it.
                    Err(_) => {
                        carried_initials.extend(message.initial_messages);
                        undecryptable += 1;
                        continue;
                    }
                };
                let mut content = Content::from_bytes(&content);
                if let Some(events) = content.events.take() {
                    steps.extend(contact.told(&events));
                    if content.kind.is_none() {
                        continue;
                    }
                }
                if let Some(Kind::Hello(ref hello)) = content.kind {
                    let hc = contact.session.check_peer_hello(hello, local_pq);
                    if hc.downgrade_detected {
                        contact.state.security_alert = SECURITY_ALERT_DOWNGRADE;
                        if hc.recommend_start_again
                            && !contact.state.request
                            && !contact.state.quarantined
                        {
                            recommend_upgrade = true;
                        }
                    }
                }
                // M-14: Only a live-session Delete retires the session and requeues unread
                // messages; an archived earlier-session Delete must NOT requeue the live chat!
                if matches!(content.kind, Some(Kind::Deleted(_))) && !message.earlier {
                    contact.session.retire();
                    deleted = true;
                }
                match contact.add_received(content, open) {
                    Ok(entry) => entries.push(entry),
                    Err(reason) => {
                        inner.roll_back(peer, snapshot)?;
                        return Err(reason.into());
                    }
                }
            }
            if undecryptable > 0 {
                let label = contact.view().label();
                self.ui.log(format!(
                    "skipped {undecryptable} message(s) from {label} that do not decrypt, e.g. \
                     ones of an earlier session"
                ));
            }
            if evicted > 0 {
                let label = contact.view().label();
                self.ui.log(format!(
                    "{evicted} message(s) from {label} arrived too late and their decryption key was evicted"
                ));
            }
            // The entries of this client's messages that the peer's events moved on; then, if
            // the session is retired, as the peer deleted the chat or the two kept missing each
            // other, what was encrypted on it, and what the peer never read if it deleted the
            // chat, waits for a new one.
            let mut changed = BTreeMap::new();
            let moved = match inner.step(peer, &mut changed, steps).await {
                Ok(()) if deleted || needs_new_session(inner, peer) => {
                    inner.requeue(peer, deleted, &changed).await
                }
                Ok(()) => Ok(RequeueOutcome::default()),
                Err(e) => Err(describe(&e)),
            };
            let requeued = match moved {
                Ok(requeued) => requeued,
                Err(e) => {
                    inner.roll_back(peer, snapshot)?;
                    return Err(e);
                }
            };
            changed.extend(requeued.history.iter().cloned());
            let changed: Vec<_> = changed.into_iter().collect();
            let records: Vec<_> = records(peer, &entries)
                .into_iter()
                .chain(records(peer, &changed))
                .collect();
            inner
                .persist_received_page(
                    index,
                    snapshot,
                    &carried_initials,
                    &records,
                    &requeued.outbox,
                )
                .await?;
            requeued.log_missing(&self.ui, peer);
            received |= !entries.is_empty();
            if self.ui.open.get_untracked() == Some(*peer)
                && let Some(contact) = inner.contact(peer)
            {
                let views: Vec<_> = entries
                    .into_iter()
                    .map(|(index, entry)| contact.message(index, entry))
                    .collect();
                self.show_changes(inner, peer, &changed);
                self.show_new(inner, peer, views);
            }
            self.ui.contacts.set(inner.views());
            if stalled {
                // Its initial message, which went first, may have come since they were last
                // taken, or have been lost, and come with the page: once they are taken, and
                // those are accepted, receiving goes on, past what still does not decrypt —
                // UNLESS a deferred unsupported-suite initial exists for this peer, in which case
                // pause right before the first undecryptable envelope so a capable build can
                // decrypt those messages after replaying the greeting.
                drop(guard);
                self.take_initial_messages().await?;
                let mut guard = self.inner.lock().await;
                if let Some(inner) = guard.as_mut() {
                    let join = self.join_carried(inner, peer).await?;
                    recommend_upgrade |= join.recommend_upgrade;
                    let paused = resolve_stalled_peer(inner, peer, join);
                    self.ui.contacts.set(inner.views());
                    if paused {
                        break;
                    }
                }
            } else if !carried_initials.is_empty() {
                recommend_upgrade |= self.join_carried(inner, peer).await?.recommend_upgrade;
            }
        }
        if recommend_upgrade {
            let _ = self.upgrade_to_pq(*peer).await;
        }
        Ok(received)
    }
}

/// Resolve a stalled mailbox page for `peer`: pause without calling `skip_stalled()` if any
/// deferred carried or inbox initial exists for `peer` so a later capable build can decrypt the
/// stalled envelopes after replaying the greeting. Returns `true` when receiving should pause.
pub(super) fn resolve_stalled_peer<V: HistoryStore>(
    inner: &mut Inner<V>,
    peer: &PublicKey,
    join: JoinCarriedOutcome,
) -> bool {
    if join.has_deferred || inner.has_deferred_initial_for(peer) {
        return true;
    }
    if let Some(contact) = inner.contact(peer)
        && !contact.is_new_quarantined()
    {
        contact.session.skip_stalled();
    }
    false
}

/// Build a [`PushV2Request`] for a persisted [`Farewell`], deterministically deriving a 16-byte
/// `client_message_id` from the encrypted message whenever a legacy vaulted farewell has an empty
/// `client_message_id` so retries remain idempotent.
pub(super) fn farewell_push_v2_request(farewell: &Farewell) -> PushV2Request {
    let mut req = if !farewell.push_v2.is_empty()
        && let Ok(decoded) = PushV2Request::decode(farewell.push_v2.as_slice())
    {
        decoded
    } else {
        let push_req = farewell.push.clone().unwrap_or_default();
        PushV2Request {
            sender: push_req.sender,
            recipient: push_req.recipient,
            message: push_req.message,
            initial_message: push_req
                .initial_message
                .as_ref()
                .map(WireInitialMessageV2::from),
            delivery_hash: push_req.delivery_hash,
            client_message_id: Bytes::copy_from_slice(&farewell.client_message_id),
        }
    };
    if req.client_message_id.is_empty() {
        if farewell.client_message_id.len() == CLIENT_MESSAGE_ID_LENGTH {
            req.client_message_id = Bytes::copy_from_slice(&farewell.client_message_id);
        } else if let Some(message) = req.message.as_ref() {
            req.client_message_id = Bytes::copy_from_slice(&Sealed::client_message_id_for(message));
        }
    }
    req
}

impl<V: HistoryStore> Inner<V> {
    /// An empty page can still acknowledge deliveries or advance past expired envelopes.
    pub(super) async fn persist_empty_page_progress(
        &mut self,
        peer: &PublicKey,
        snapshot: (proto::SessionState, ContactState),
    ) -> Result<bool, String> {
        let contact = self.contact(peer).ok_or("no such chat")?;
        if proto::SessionState::from(contact.session.state()) == snapshot.0 {
            return Ok(false);
        }
        if let Err(e) = self.save(&[]).await {
            self.roll_back(peer, snapshot)?;
            return Err(describe(&e));
        }
        Ok(true)
    }

    /// The cursor can advance only with the history, outbox and carried initials from its page.
    pub(super) async fn persist_received_page(
        &mut self,
        index: usize,
        snapshot: (proto::SessionState, ContactState),
        initials: &[Incoming],
        records: &[(String, HistoryEntry)],
        outbox: &[(String, Option<OutgoingRecord>)],
    ) -> Result<(), String> {
        let peer = self.contacts[index].peer;
        let saved_carried_ts = self.carried_deferred_timestamps.clone();
        let staged = stage_carried_initials(&mut self.contacts[index].state, initials);
        let saved = match staged {
            Ok(()) => {
                record_carried_timestamps(
                    &mut self.carried_deferred_timestamps,
                    &self.contacts[index].state.pending_carried_initials,
                    now(),
                );
                let unchanged = records.is_empty()
                    && outbox.is_empty()
                    && !self.needs_save()
                    && proto::SessionState::from(self.contacts[index].session.state())
                        == snapshot.0
                    && self.contacts[index].state == snapshot.1
                    && self.carried_deferred_timestamps == saved_carried_ts;
                if unchanged {
                    Ok(())
                } else {
                    self.save_with(records, outbox)
                        .await
                        .map_err(|e| describe(&e))
                }
            }
            Err(e) => Err(e),
        };
        if saved.is_err() {
            self.carried_deferred_timestamps = saved_carried_ts;
            self.roll_back(&peer, snapshot)?;
        }
        saved
    }

    /// A fetch may consume delivery receipts and advance across expired pages before failing.
    /// Restore the whole snapshot on error. Keep it for the caller until the page is persisted.
    pub(super) async fn fetch_page<T>(
        &mut self,
        index: usize,
        fetch: impl AsyncFnOnce(&mut Session<Connect>, &Client<Connect>, &str) -> session::Result<T>,
    ) -> Result<(T, (proto::SessionState, ContactState)), String> {
        let contact = &mut self.contacts[index];
        let (peer, snapshot) = (contact.peer, contact.snapshot());
        match fetch(&mut contact.session, &self.client, &self.audience).await {
            Ok(page) => Ok((page, snapshot)),
            Err(e) => {
                self.roll_back(&peer, snapshot)?;
                Err(describe(&e))
            }
        }
    }
}
