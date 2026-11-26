//! Server notifications, synchronization, write-token grants/revocations, and unified mailbox
//! receive with cross-peer stall isolation.

use super::contact::Contact;
use super::handshake::{
    DEFERRED_REPLAY_WINDOW_MS, Incoming, record_carried_timestamps, stage_carried_initials,
};
use super::outbox::{RequeueOutcome, needs_new_session};
use super::{
    AWAY_CHECK, Engine, HIDDEN_GRACE, Inner, POLL_AWAY, POLL_FAST, POLL_LIVE, POLL_SLOW, POLL_STEP,
    ProtocolRpcScope, RESUBSCRIBE_MAX, RESUBSCRIBE_MIN, UNFOCUSED_GRACE, VaultStore, origin,
    records, same_server, should_require_update_for_rpc,
};
use crate::content::{Content, Kind};
use crate::notify::{Event, Subscription};
use crate::state::{Link, ServerPqStatus};
use crate::transport::Fetch;
use crate::util::{describe, monotonic_now_ms, now, short, sleep};
use crate::vault::{
    ContactState, DeferredEnvelope, Farewell, HistoryEntry, OutgoingRecord,
    SECURITY_ALERT_DOWNGRADE,
};
use futures_util::future::{Either, select};
use leptos::prelude::*;
use leptos::task::spawn_local;
use prost::Message as _;
use session::protocol::handshake_v2::InitialMessageV2 as WireInitialMessageV2;
use session::protocol::mailbox_v2::{LocalMailboxV2, PushV2Request};
use session::protocol::notify::{self, Notification};
use session::{ClientState, ErrorKind, PqSuite, PublicKey, proto};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

/// Maximum raw mailbox envelopes buffered per peer in `DeferredRecord.envelopes`.
pub(super) const MAX_DEFERRED_ENVELOPES_PER_PEER: usize = 64;
/// Maximum raw mailbox envelopes buffered across all peers in `DeferredRecord.envelopes`.
pub(super) const MAX_TOTAL_DEFERRED_ENVELOPES: usize = 256;
/// Safety bound on unified mailbox pages drained in a single `receive_mailbox` call.
const MAX_MAILBOX_PAGES: usize = 20;

/// Prune expired (`> DEFERRED_REPLAY_WINDOW_MS`), malformed, or unknown-peer `DeferredEnvelope`s
/// on unlock or before replay. Returns how many entries were removed.
pub(super) fn prune_deferred_envelopes(
    envelopes: &mut Vec<DeferredEnvelope>,
    contacts: &[Contact],
    now_ms: u64,
) -> usize {
    let before = envelopes.len();
    let mut seen: BTreeSet<(PublicKey, u64)> = BTreeSet::new();
    let mut per_peer: HashMap<PublicKey, usize> = HashMap::new();
    envelopes.retain(|env| {
        let Ok(peer) = PublicKey::try_from(env.peer.as_slice()) else {
            return false;
        };
        if !contacts.iter().any(|c| c.peer == peer) {
            return false;
        }
        if env.deferred_at != 0
            && now_ms.saturating_sub(env.deferred_at) > DEFERRED_REPLAY_WINDOW_MS
        {
            return false;
        }
        if !seen.insert((peer, env.sequence)) {
            return false;
        }
        let count = per_peer.entry(peer).or_insert(0);
        if *count >= MAX_DEFERRED_ENVELOPES_PER_PEER {
            return false;
        }
        *count += 1;
        true
    });
    if envelopes.len() > MAX_TOTAL_DEFERRED_ENVELOPES {
        envelopes.truncate(MAX_TOTAL_DEFERRED_ENVELOPES);
    }
    before - envelopes.len()
}

/// Buffer one raw mailbox envelope for `peer` into `envelopes`, enforcing per-peer (64) and total
/// (256) caps. Returns `true` if the envelope was stored or already present, or `false` if dropped
/// due to cap overflow (caller must append `contact.add_evicted()` in the same atomic tx!).
pub(super) fn push_deferred_envelope(
    envelopes: &mut Vec<DeferredEnvelope>,
    peer: &PublicKey,
    sequence: u64,
    message: Option<party::EncryptedMessage>,
    initial_message: Option<WireInitialMessageV2>,
    now_ms: u64,
) -> bool {
    if envelopes
        .iter()
        .any(|e| e.peer.as_slice() == peer.as_slice() && e.sequence == sequence)
    {
        return true;
    }
    let peer_count = envelopes
        .iter()
        .filter(|e| e.peer.as_slice() == peer.as_slice())
        .count();
    if peer_count >= MAX_DEFERRED_ENVELOPES_PER_PEER
        || envelopes.len() >= MAX_TOTAL_DEFERRED_ENVELOPES
    {
        return false;
    }
    envelopes.push(DeferredEnvelope {
        peer: peer.to_vec(),
        sequence,
        message,
        initial_message,
        deferred_at: now_ms,
    });
    true
}

impl<V: VaultStore> Inner<V> {
    /// Flush any durably staged `RegisterWriteToken` grants on `peer`'s session to our own DO.
    pub(super) async fn flush_pending_grants_for(
        &mut self,
        peer: &PublicKey,
    ) -> Result<(), session::Error> {
        let grants = match self.contact(peer) {
            Some(c) => c.session.pending_register_grants().to_vec(),
            None => return Ok(()),
        };
        if grants.is_empty() {
            return Ok(());
        }
        let mailbox = Fetch::client(&self.server);
        let mut removed_any = false;
        let mut first_err: Option<session::Error> = None;
        for grant in grants {
            match self
                .client
                .register_write_token_v2(
                    &mailbox,
                    &self.audience,
                    peer,
                    &grant.token_hash,
                    grant.grant_version,
                    grant.pin_active,
                )
                .await
            {
                Ok(()) => {
                    if let Some(contact) = self.contact(peer) {
                        removed_any |= contact
                            .session
                            .remove_pending_grant(&grant.token_hash, grant.grant_version);
                    }
                }
                // Stale/superseded grant version (`grant_version <= revoked_below_version`) or
                // terminal protocol refusal: drop the stale grant so later grants proceed.
                Err(e)
                    if e.is_server_refusal()
                        && matches!(e.kind(), ErrorKind::Protocol | ErrorKind::LimitExceeded) =>
                {
                    if let Some(contact) = self.contact(peer) {
                        removed_any |= contact
                            .session
                            .remove_pending_grant(&grant.token_hash, grant.grant_version);
                    }
                }
                Err(e) => {
                    first_err = Some(e);
                    break;
                }
            }
        }
        if removed_any {
            let _ = self.save_state().await;
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl<V: VaultStore> Engine<V> {
    /// Flush staged `RegisterWriteToken` grants for `peer` while holding `inner` (used by callers
    /// that already hold `self.inner` across a local recovery step or settings flow).
    pub(super) async fn flush_pending_grants_for(
        &self,
        inner: &mut Inner<impl VaultStore>,
        peer: &PublicKey,
    ) -> Result<(), String> {
        match inner.flush_pending_grants_for(peer).await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                Err(describe(&e))
            }
        }
    }

    /// Lock-free flush of staged `RegisterWriteToken` grants for `peer`: signs each request under
    /// `self.inner`, drops `self.inner` across the network RPC, then re-acquires `self.inner`,
    /// validates `is_live(vgen)`, and removes the confirmed grant.
    pub(super) async fn flush_pending_grants_for_peer(
        &self,
        peer: &PublicKey,
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Ok(());
        }
        let mut first_err: Option<String> = None;
        let mut attempted: Vec<([u8; 32], u64)> = Vec::new();
        loop {
            if !self.is_live(vgen) {
                return Ok(());
            }
            let next = {
                let guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok(());
                }
                let Some(inner) = guard.as_ref() else {
                    return Ok(());
                };
                let Some(contact) = inner.contacts.iter().find(|c| c.peer == *peer) else {
                    break;
                };
                let Some(grant) = contact
                    .session
                    .pending_register_grants()
                    .iter()
                    .find(|g| !attempted.contains(&(g.token_hash, g.grant_version)))
                    .copied()
                else {
                    break;
                };
                match inner.client.sign_register_write_token_v2(
                    &inner.audience,
                    peer,
                    &grant.token_hash,
                    grant.grant_version,
                    grant.pin_active,
                ) {
                    Ok(request) => (inner.server.clone(), grant, request),
                    Err(e) => {
                        if e.kind() == ErrorKind::ClockSkew {
                            self.warn_clock_skew(inner.client.clock().offset_ms());
                        }
                        first_err = Some(describe(&e));
                        break;
                    }
                }
            };
            let (server, grant, request) = next;
            attempted.push((grant.token_hash, grant.grant_version));
            let rpc_res: session::Result<()> = Fetch::client(&server)
                .register_write_token(request)
                .await
                .map(|_| ())
                .map_err(session::Error::from);
            if !self.is_live(vgen) {
                return Ok(());
            }
            let remove = match rpc_res {
                Ok(()) => true,
                // Stale/superseded grant version (`grant_version <= revoked_below_version`) or
                // terminal protocol refusal: drop the stale grant so later grants proceed.
                Err(e)
                    if e.is_server_refusal()
                        && matches!(e.kind(), ErrorKind::Protocol | ErrorKind::LimitExceeded) =>
                {
                    true
                }
                Err(e) => {
                    self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                    first_err = Some(describe(&e));
                    break;
                }
            };
            if remove {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok(());
                }
                if let Some(inner) = guard.as_mut()
                    && let Some(contact) = inner.contact(peer)
                    && contact
                        .session
                        .remove_pending_grant(&grant.token_hash, grant.grant_version)
                {
                    let _ = inner.save_state().await;
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Flush staged `RegisterWriteToken` grants across all contacts without holding `self.inner`
    /// across network RPCs.
    pub(super) async fn flush_pending_grants(&self) -> Result<(), String> {
        let vgen = self.vault_gen();
        let peers: Vec<PublicKey> = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(());
            }
            let Some(inner) = guard.as_ref() else {
                return Ok(());
            };
            inner
                .contacts
                .iter()
                .filter(|c| !c.session.pending_register_grants().is_empty())
                .map(|c| c.peer)
                .collect()
        };
        let mut first_err: Option<String> = None;
        for peer in peers {
            if !self.is_live(vgen) {
                return Ok(());
            }
            if let Err(e) = self.flush_pending_grants_for_peer(&peer).await {
                first_err.get_or_insert(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Flush durably staged `RevokeWriteToken` entries from `AppState.pending_revokes` without
    /// holding `self.inner` across network RPCs.
    pub(super) async fn flush_pending_revokes(&self) -> Result<(), String> {
        let vgen = self.vault_gen();
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
                let Some(revoke) = inner.state.pending_revokes.first().cloned() else {
                    return Ok(());
                };
                let Ok(slot_id) = <[u8; 32]>::try_from(revoke.peer_slot_id.as_slice()) else {
                    inner.state.pending_revokes.remove(0);
                    let _ = inner.save_state().await;
                    continue;
                };
                match inner.client.sign_revoke_write_token_v2(
                    &inner.audience,
                    &slot_id,
                    None,
                    revoke.min_grant_version,
                ) {
                    Ok(request) => (inner.server.clone(), revoke, request),
                    Err(e) => {
                        if e.kind() == ErrorKind::ClockSkew {
                            self.warn_clock_skew(inner.client.clock().offset_ms());
                        }
                        return Err(describe(&e));
                    }
                }
            };
            let (server, revoke, request) = next;
            let rpc_res: session::Result<_> = Fetch::client(&server)
                .revoke_write_token(request)
                .await
                .map_err(session::Error::from);
            if !self.is_live(vgen) {
                return Ok(());
            }
            match rpc_res {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => {
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
            // Remove only if the entry still targets the same slot with `min_grant_version`
            // covered by this RPC (if a subsequent delete bumped `min_grant_version`, keep it
            // so the next iteration sends the higher floor).
            if let Some(pos) = inner.state.pending_revokes.iter().position(|r| {
                r.peer_slot_id == revoke.peer_slot_id
                    && r.min_grant_version <= revoke.min_grant_version
            }) {
                inner.state.pending_revokes.remove(pos);
                inner.save_state().await.map_err(|e| describe(&e))?;
            }
        }
    }

    /// Whether the user is here: the page shown and in focus, or hidden for less than
    /// [`HIDDEN_GRACE`], or out of focus for less than [`UNFOCUSED_GRACE`]. Notifications are
    /// for then only, as a WebSocket open is held on the server.
    pub(super) fn present(&self) -> bool {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return false;
        }
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
    pub(super) fn run(self: Rc<Self>, vgen: u64) {
        spawn_local(async move {
            let mut delay = POLL_FAST;
            loop {
                if !self.is_live(vgen) {
                    return;
                }
                let asked = self.ui.syncing.get_untracked();
                let active = self.sync().await;
                if !self.is_live(vgen) {
                    return;
                }
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
                    if !self.is_live(vgen) {
                        return;
                    }
                    if self.queue.take_wake() {
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
    pub(super) fn listen(self: Rc<Self>, vgen: u64) {
        spawn_local(async move {
            let mut retry = RESUBSCRIBE_MIN;
            loop {
                if !self.is_live(vgen) {
                    return;
                }
                if self.ui.update_required.with_untracked(Option::is_some) {
                    self.ui.live.set(false);
                    return;
                }
                while !self.present() {
                    if !self.is_live(vgen) {
                        return;
                    }
                    if self.ui.update_required.with_untracked(Option::is_some) {
                        self.ui.live.set(false);
                        return;
                    }
                    sleep(AWAY_CHECK).await;
                }
                if !self.is_live(vgen) {
                    return;
                }
                let subscribed = {
                    let mut guard = self.lock_inner().await;
                    if !self.is_live(vgen) {
                        return;
                    }
                    let Some(inner) = guard.as_mut() else {
                        return;
                    };
                    inner
                        .client
                        .subscription_for_audience(&inner.audience)
                        .map_err(|e| describe(&e))
                        .and_then(|request| Subscription::open(&inner.server, &request))
                };
                if !self.is_live(vgen) {
                    return;
                }
                let mut left = false;
                match subscribed {
                    Ok(mut subscription) => {
                        *self.ws_close.borrow_mut() = Some(subscription.close_handle());
                        let _clear_ws = scopeguard::guard((), |()| {
                            *self.ws_close.borrow_mut() = None;
                        });
                        if !self.is_live(vgen) {
                            return;
                        }
                        loop {
                            if !self.is_live(vgen) {
                                return;
                            }
                            let next =
                                select(Box::pin(subscription.next()), Box::pin(sleep(AWAY_CHECK)));
                            match next.await {
                                _ if !self.is_live(vgen) => return,
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
                        }
                    }
                    Err(e) if self.is_live(vgen) => self
                        .ui
                        .log(format!("cannot subscribe to notifications: {e}")),
                    Err(_) => return,
                }
                if !self.is_live(vgen) {
                    return;
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
                if !self.is_live(vgen) {
                    return;
                }
                retry = (retry * 2).min(RESUBSCRIBE_MAX);
            }
        });
    }

    /// Fetch what sender-blind `notification` says arrived; if that fails, sync soon.
    async fn notified(&self, notification: Notification) {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return;
        }
        let fetched = match notification.event {
            Some(notify::Event::Message(true)) => match self.receive_mailbox().await {
                Ok(affected_peers) => {
                    for peer in affected_peers {
                        if !self.is_live(vgen) {
                            return;
                        }
                        self.clear_approval_backoff(&peer);
                        let _ = self.flush(&peer).await;
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            },
            Some(notify::Event::InitialMessage(true)) => match self.take_initial_messages().await {
                Ok(true) => {
                    if self.is_live(vgen) {
                        self.wake();
                    }
                    Ok(())
                }
                Ok(false) => Ok(()),
                Err(e) => Err(e),
            },
            _ => return,
        };
        if fetched.is_err() && self.is_live(vgen) {
            self.wake();
        }
    }

    /// Sync soon.
    pub fn wake(&self) {
        if !self.shutting_down.get() && !crate::glue::lock_released() {
            self.queue.request_wake();
        }
    }

    /// Sync now, as asked on the page, clearing per-peer approval backoff and showing it until done.
    pub fn sync_now(&self) {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        self.queue.clear_all_approval_backoffs();
        self.ui.syncing.set(true);
        self.wake();
    }

    /// Query `GetServerInfo` verifying `server_id` against the client's locally derived expected
    /// audience (never blindly trusting server-supplied audience strings).
    pub(super) async fn refresh_server_info(&self, force: bool) {
        let vgen = self.vault_gen();
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return;
        }
        let Some(inner) = guard.as_mut() else {
            return;
        };
        if !force && inner.server_pq != ServerPqStatus::Unknown {
            return;
        }
        let status = match inner.client.check_server_info(&inner.audience).await {
            _ if !self.is_live(vgen) => return,
            Ok(info) if info.pq_enabled => {
                if !inner.client.clock().is_drift_exceeded() {
                    self.startup.clear_clock_skew_warned();
                }
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
            if self.is_live(vgen) {
                self.ui.me.set(Some(inner.me()));
            }
        }
    }

    /// One round: recover unsaved state, refresh server info, push farewells, flush revocations,
    /// take initial messages, publish/refill prekeys, flush write-token grants, receive the
    /// unified mailbox, and flush per-peer outboxes. Returns whether anything happened.
    pub(super) async fn sync(&self) -> bool {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return false;
        }
        let (mut active, mut failure) = match self.recover_local_changes().await {
            Ok(recovered) => (recovered, None),
            Err(e) => (false, Some(e)),
        };
        if !self.is_live(vgen) {
            return false;
        }
        self.refresh_server_info(false).await;
        if !self.is_live(vgen) {
            return false;
        }
        if let Err(e) = self.say_farewells().await {
            failure.get_or_insert(e);
        }
        if !self.is_live(vgen) {
            return false;
        }
        if let Err(e) = self.flush_pending_revokes().await {
            failure.get_or_insert(e);
        }
        if !self.is_live(vgen) {
            return false;
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
        if !self.is_live(vgen) {
            return false;
        }
        if reached && let Err(e) = self.publish(false).await {
            failure.get_or_insert(e);
        }
        if !self.is_live(vgen) {
            return false;
        }
        if let Err(e) = self.flush_pending_grants().await {
            failure.get_or_insert(e);
        }
        if !self.is_live(vgen) {
            return false;
        }
        match self.receive_mailbox().await {
            Ok(affected) => {
                if !affected.is_empty() {
                    active = true;
                    for peer in affected {
                        self.clear_approval_backoff(&peer);
                    }
                }
            }
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
        if !self.is_live(vgen) {
            return false;
        }
        for peer in self.peers().await {
            if !self.is_live(vgen) {
                return false;
            }
            match self.flush(&peer).await {
                Ok(pushed) => active |= pushed,
                Err(e) => {
                    failure.get_or_insert(e);
                }
            }
        }
        if !self.is_live(vgen) {
            return false;
        }
        match failure {
            None => self.ui.link.set(Link::Synced(now())),
            Some(e) => self.ui.link.set(Link::Offline(e)),
        }
        active
    }

    /// Retry failed writes, join initials left on disk, and replay eligible deferred envelopes.
    async fn recover_local_changes(&self) -> Result<bool, String> {
        let vgen = self.vault_gen();
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Ok(false);
        }
        let Some(inner) = guard.as_mut() else {
            return Ok(false);
        };
        if inner.needs_save() {
            inner.save(&[]).await.map_err(|e| describe(&e))?;
        }
        if !self.is_live(vgen) {
            return Ok(false);
        }
        let late = std::mem::take(&mut inner.saved_late);
        if std::mem::take(&mut inner.contacts_dirty_late) || !late.is_empty() {
            self.ui.me.set(Some(inner.me()));
            if let Some(open) = self.ui.open.get_untracked()
                && late.contains(&open)
            {
                self.reconcile_open_chat_read(inner, &open, true).await;
            }
            if !self.is_live(vgen) {
                return Ok(false);
            }
            self.ui.contacts.set(inner.views());
        }
        let replayed = self.replay_deferred_initials(inner).await?;
        if !self.is_live(vgen) {
            return Ok(false);
        }
        let pending: Vec<_> = inner
            .contacts
            .iter()
            .filter(|c| {
                c.deferred_carried < c.state.pending_carried_initials.len()
                    && !c.is_new_quarantined()
            })
            .map(|c| c.peer)
            .collect();
        let mut upgrades = replayed.unwrap_or_default();
        for peer in &pending {
            if !self.is_live(vgen) {
                return Ok(false);
            }
            if self.join_carried(inner, peer).await?.recommend_upgrade {
                upgrades.insert(*peer);
            }
        }
        if !self.is_live(vgen) {
            return Ok(false);
        }
        let (replayed_peers, replay_upgrades) = self.replay_deferred_envelopes(inner, None).await?;
        upgrades.extend(replay_upgrades);
        let recovered = !pending.is_empty() || !replayed_peers.is_empty();
        drop(guard);
        for peer in upgrades {
            if !self.is_live(vgen) {
                return Ok(false);
            }
            let _ = self.upgrade_to_pq(peer).await;
        }
        Ok(recovered)
    }

    /// Push the messages telling peers that their chats were deleted here, see
    /// [`delete`](Self::delete), releasing `self.inner` across each `PushV2` network RPC.
    pub(super) async fn say_farewells(&self) -> Result<(), String> {
        let vgen = self.vault_gen();
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
                let Some(farewell) = inner.state.farewells.first().cloned() else {
                    return Ok(());
                };
                let Some(v2_req) = farewell_push_v2_request(&farewell) else {
                    inner.state.farewells.remove(0);
                    inner.save_state().await.map_err(|e| describe(&e))?;
                    continue;
                };
                let signs_in_here = same_server(&inner.server, &origin());
                (inner.server.clone(), signs_in_here, farewell, v2_req)
            };
            let (server, signs_in_here, farewell, v2_req) = next;
            let pushed: session::Result<()> = Fetch::client(&server)
                .push_v2(v2_req)
                .await
                .map(|_| ())
                .map_err(session::Error::from);
            if !self.is_live(vgen) {
                return Ok(());
            }
            match pushed {
                Ok(()) => {}
                // Pushing takes a sign-in: they wait for it, without failing the round.
                Err(e) if e.kind() == ErrorKind::SignInRequired && signs_in_here => return Ok(()),
                // Refused for good (including WriteTokenRejected when peer already deleted/revoked).
                Err(e)
                    if e.is_server_refusal()
                        && matches!(
                            e.kind(),
                            ErrorKind::WriteTokenRejected
                                | ErrorKind::LimitExceeded
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
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(());
            }
            let Some(inner) = guard.as_mut() else {
                return Ok(());
            };
            if let Some(pos) = inner
                .state
                .farewells
                .iter()
                .position(|f| f.push_v2 == farewell.push_v2)
            {
                inner.state.farewells.remove(pos);
                inner.save_state().await.map_err(|e| describe(&e))?;
            }
        }
    }

    pub(super) async fn peers(&self) -> Vec<PublicKey> {
        let inner = self.lock_inner().await;
        inner
            .iter()
            .flat_map(|inner| inner.contacts.iter().map(|contact| contact.peer))
            .collect()
    }

    /// Drain this identity's unified `mailbox.v2` queue with cross-peer stall isolation:
    /// - Maps every contact's `inbound_token_hashes()` -> `peer` for O(1) dispatch.
    /// - Active peers decrypt immediately; quarantined / deferred-suite / temporarily
    ///   undecryptable envelopes buffer into `DeferredRecord.envelopes` (64/peer, 256 total,
    ///   appending `contact.add_evicted()` on overflow in the same atomic transaction).
    /// - Commits all history, outbox updates, `DeferredRecord`, and `Client::commit_mailbox_page`
    ///   in ONE atomic `vault.save` transaction, then unconditionally advances the server ACK so
    ///   no stalled/quarantined peer ever blocks other peers!
    /// - After draining, joins carried/inbox initials and locally replays buffered envelopes with
    ///   zero server re-fetch.
    pub(super) async fn receive_mailbox(&self) -> Result<Vec<PublicKey>, String> {
        let vgen = self.vault_gen();
        let mut affected_peers: BTreeSet<PublicKey> = BTreeSet::new();
        let mut upgrades: BTreeSet<PublicKey> = BTreeSet::new();
        let mut peers_needing_replay: BTreeSet<PublicKey> = BTreeSet::new();

        for _ in 0..MAX_MAILBOX_PAGES {
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            let Some(inner) = guard.as_mut() else {
                break;
            };
            let local_pq = inner.local_pq_enabled();
            let mut token_map: HashMap<[u8; 32], PublicKey> = HashMap::new();
            for contact in &inner.contacts {
                for th in contact.session.inbound_token_hashes() {
                    token_map.insert(th, contact.peer);
                }
            }

            let mailbox = Fetch::client(&inner.server);
            let page = match inner
                .client
                .fetch_mailbox_v2(&mailbox, &inner.audience, 100)
                .await
            {
                _ if !self.is_live(vgen) => return Ok(Vec::new()),
                Ok(page) => page,
                Err(e) => {
                    self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                    return Err(describe(&e));
                }
            };
            if page.messages.is_empty() {
                if page.piggybacked_ack > 0 {
                    inner.client.clear_pending_mailbox_ack(page.piggybacked_ack);
                    let _ = inner.save_state().await;
                }
                break;
            }

            let last_seq = page.last_sequence().unwrap_or(0);
            let has_more = page.has_more;
            let piggybacked_ack = page.piggybacked_ack;

            // Snapshots for atomic rollback if any step or vault commit fails.
            let client_snapshot = proto::ClientState::from(inner.client.state());
            let saved_envelopes = inner.deferred_envelopes.clone();
            let saved_carried_ts = inner.carried_deferred_timestamps.clone();
            let mut contact_snapshots: HashMap<PublicKey, (proto::SessionState, ContactState)> =
                HashMap::new();

            let mut per_peer_entries: BTreeMap<PublicKey, Vec<(u64, HistoryEntry)>> =
                BTreeMap::new();
            let mut per_peer_steps: BTreeMap<PublicKey, Vec<(u64, crate::state::Step)>> =
                BTreeMap::new();
            let mut per_peer_settled: BTreeMap<PublicKey, Vec<(u64, u64)>> = BTreeMap::new();
            let mut per_peer_carried: BTreeMap<PublicKey, Vec<Incoming>> = BTreeMap::new();
            let mut peer_deleted: BTreeSet<PublicKey> = BTreeSet::new();
            let mut peer_evicted_counts: HashMap<PublicKey, usize> = HashMap::new();
            let now_ms = now();

            let mut process_err: Option<String> = None;
            for env in page.messages {
                let Ok(token_hash) = <[u8; 32]>::try_from(env.token_hash.as_ref()) else {
                    continue;
                };
                let Some(&peer) = token_map.get(&token_hash) else {
                    // Unknown/revoked token hash: drop silently.
                    continue;
                };
                let Some(contact_idx) = inner.contacts.iter().position(|c| c.peer == peer) else {
                    continue;
                };
                contact_snapshots
                    .entry(peer)
                    .or_insert_with(|| inner.contacts[contact_idx].snapshot());

                let peer_has_buffered = inner
                    .deferred_envelopes
                    .iter()
                    .any(|e| e.peer.as_slice() == peer.as_slice());
                let peer_awaiting_user_or_upgrade = inner.contacts[contact_idx].state.quarantined
                    || inner.contacts[contact_idx].is_new_quarantined()
                    || inner.contacts[contact_idx].deferred_carried > 0
                    || inner.has_deferred_initial_for(&peer);
                let peer_blocked = peer_has_buffered || peer_awaiting_user_or_upgrade;

                if peer_blocked {
                    let buffered = push_deferred_envelope(
                        &mut inner.deferred_envelopes,
                        &peer,
                        env.sequence,
                        env.message,
                        env.initial_message,
                        now_ms,
                    );
                    if !buffered {
                        match inner.contacts[contact_idx].add_evicted() {
                            Ok(entry) => {
                                per_peer_entries.entry(peer).or_default().push(entry);
                                *peer_evicted_counts.entry(peer).or_insert(0) += 1;
                            }
                            Err(reason) => {
                                process_err = Some(reason.to_string());
                                break;
                            }
                        }
                    }
                    if !peer_awaiting_user_or_upgrade {
                        peers_needing_replay.insert(peer);
                    }
                    continue;
                }

                // Active peer: stage any carried initial message and attempt immediate decrypt.
                let mut staged_carried_init = false;
                if let Some(ref wire_init) = env.initial_message
                    && let Ok(inc) = Incoming::try_from(wire_init)
                {
                    per_peer_carried.entry(peer).or_default().push(inc);
                    peers_needing_replay.insert(peer);
                    staged_carried_init = true;
                }
                let Some(ref msg) = env.message else {
                    continue;
                };
                match inner.contacts[contact_idx].session.decrypt_envelope(msg) {
                    Ok(decrypted) => {
                        let contact = &mut inner.contacts[contact_idx];
                        let mut content = Content::from_bytes(&decrypted.content);
                        if !decrypted.earlier {
                            contact.mark_greeting_confirmed();
                        }
                        affected_peers.insert(peer);
                        if let Some(events) = content.events.take() {
                            let told = contact.told(&events);
                            per_peer_steps.entry(peer).or_default().extend(told.steps);
                            per_peer_settled
                                .entry(peer)
                                .or_default()
                                .extend(told.settled_outbox);
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
                                    upgrades.insert(peer);
                                }
                            }
                        }
                        if matches!(content.kind, Some(Kind::Deleted(_))) && !decrypted.earlier {
                            contact.session.retire();
                            peer_deleted.insert(peer);
                        }
                        match contact.add_received(content, false) {
                            Ok(entry) => per_peer_entries.entry(peer).or_default().push(entry),
                            Err(reason) => {
                                process_err = Some(reason.to_string());
                                break;
                            }
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::DuplicateMessage => continue,
                    Err(e) if e.kind() == ErrorKind::EvictedMessage => {
                        match inner.contacts[contact_idx].add_evicted() {
                            Ok(entry) => {
                                per_peer_entries.entry(peer).or_default().push(entry);
                                *peer_evicted_counts.entry(peer).or_insert(0) += 1;
                                affected_peers.insert(peer);
                            }
                            Err(reason) => {
                                process_err = Some(reason.to_string());
                                break;
                            }
                        }
                    }
                    Err(_) => {
                        // Buffer temporarily undecryptable envelope (e.g. rekey race) so server
                        // mailbox cursor advances for all peers while we fetch/join initials next.
                        // Omit `initial_message` if it was already captured into `per_peer_carried`
                        // above so `replay_deferred_envelopes` never processes it a second time.
                        let deferred_init = if staged_carried_init {
                            None
                        } else {
                            env.initial_message
                        };
                        let buffered = push_deferred_envelope(
                            &mut inner.deferred_envelopes,
                            &peer,
                            env.sequence,
                            env.message,
                            deferred_init,
                            now_ms,
                        );
                        if !buffered {
                            match inner.contacts[contact_idx].add_evicted() {
                                Ok(entry) => {
                                    per_peer_entries.entry(peer).or_default().push(entry);
                                    *peer_evicted_counts.entry(peer).or_insert(0) += 1;
                                }
                                Err(reason) => {
                                    process_err = Some(reason.to_string());
                                    break;
                                }
                            }
                        }
                        peers_needing_replay.insert(peer);
                    }
                }
            }

            if let Some(err) = process_err {
                rollback_mailbox_page(
                    inner,
                    client_snapshot,
                    contact_snapshots,
                    saved_envelopes,
                    saved_carried_ts,
                )?;
                return Err(err);
            }

            // Stage carried initials, apply delivery steps & requeues across all affected peers.
            let mut all_records: Vec<(PublicKey, u64, HistoryEntry)> = Vec::new();
            let mut all_outbox_updates: Vec<(PublicKey, u64, Option<OutgoingRecord>)> = Vec::new();
            let mut per_peer_changed: BTreeMap<PublicKey, Vec<(u64, HistoryEntry)>> =
                BTreeMap::new();
            let mut requeued_outcomes: Vec<(PublicKey, RequeueOutcome)> = Vec::new();

            let touched_peers: BTreeSet<PublicKey> = contact_snapshots.keys().copied().collect();
            for peer in &touched_peers {
                if let Some(initials) = per_peer_carried.get(peer)
                    && let Some(contact) = inner.contact(peer)
                {
                    if let Err(err) = stage_carried_initials(&mut contact.state, initials) {
                        rollback_mailbox_page(
                            inner,
                            client_snapshot,
                            contact_snapshots,
                            saved_envelopes,
                            saved_carried_ts,
                        )?;
                        return Err(err);
                    }
                    let carried = contact.state.pending_carried_initials.clone();
                    record_carried_timestamps(
                        &mut inner.carried_deferred_timestamps,
                        &carried,
                        now_ms,
                    );
                }

                let steps = per_peer_steps.remove(peer).unwrap_or_default();
                let settled = per_peer_settled.remove(peer).unwrap_or_default();
                let deleted = peer_deleted.contains(peer);
                let mut changed = BTreeMap::new();
                if !steps.is_empty()
                    && let Err(e) = inner.step(peer, &mut changed, steps).await
                {
                    rollback_mailbox_page(
                        inner,
                        client_snapshot,
                        contact_snapshots,
                        saved_envelopes,
                        saved_carried_ts,
                    )?;
                    return Err(describe(&e));
                }
                let mut settled_non_attachments = Vec::new();
                for &(history_index, clock) in &settled {
                    if let Some(entry) = changed.get_mut(&history_index) {
                        if entry.place == 0 {
                            entry.place = clock;
                            entry.content.get_or_insert_default().clock = clock;
                        }
                        let is_attachment = matches!(
                            entry.content.as_ref().and_then(|c| c.kind.as_ref()),
                            Some(Kind::Attachment(_))
                        );
                        if !is_attachment {
                            settled_non_attachments.push(history_index);
                        }
                    }
                    all_outbox_updates.push((*peer, history_index, None));
                }
                if !settled_non_attachments.is_empty()
                    && let Some(contact) = inner.contact(peer)
                {
                    contact
                        .state
                        .awaiting
                        .retain(|a| !settled_non_attachments.contains(&a.history_index));
                }
                if deleted || needs_new_session(inner, peer) {
                    match inner.requeue(peer, deleted, &changed).await {
                        Ok(requeued) => {
                            all_outbox_updates.extend(requeued.outbox.clone());
                            changed.extend(requeued.history.iter().cloned());
                            requeued_outcomes.push((*peer, requeued));
                        }
                        Err(e) => {
                            rollback_mailbox_page(
                                inner,
                                client_snapshot,
                                contact_snapshots,
                                saved_envelopes,
                                saved_carried_ts,
                            )?;
                            return Err(e);
                        }
                    }
                }
                let changed_vec: Vec<_> = changed.into_iter().collect();
                if let Some(entries) = per_peer_entries.get(peer) {
                    all_records.extend(records(peer, entries));
                }
                all_records.extend(records(peer, &changed_vec));
                if !changed_vec.is_empty() {
                    per_peer_changed.insert(*peer, changed_vec);
                }
            }

            if piggybacked_ack > 0 {
                inner.client.clear_pending_mailbox_ack(piggybacked_ack);
            }
            if let Err(e) = inner.client.commit_mailbox_page(last_seq, last_seq) {
                rollback_mailbox_page(
                    inner,
                    client_snapshot,
                    contact_snapshots,
                    saved_envelopes,
                    saved_carried_ts,
                )?;
                return Err(describe(&e));
            }

            if let Err(e) = inner.save_with(&all_records, &all_outbox_updates).await {
                rollback_mailbox_page(
                    inner,
                    client_snapshot,
                    contact_snapshots,
                    saved_envelopes,
                    saved_carried_ts,
                )?;
                return Err(describe(&e));
            }
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }

            // Durable commit succeeded: log evicted counts, update open chat UI & contact views.
            for (peer, evicted_count) in peer_evicted_counts {
                let label = inner
                    .contact(&peer)
                    .map_or_else(|| short(&peer), |c| c.view().label());
                self.ui.log(format!(
                    "{evicted_count} message(s) from {label} could not be decrypted or exceeded the deferred buffer cap"
                ));
            }
            for (peer, outcome) in requeued_outcomes {
                outcome.log_missing(&self.ui, &peer);
            }
            if let Some(open) = self.ui.open.get_untracked() {
                if let Some(changed_vec) = per_peer_changed.get(&open) {
                    self.show_changes(inner, &open, changed_vec);
                }
                if let Some(entries) = per_peer_entries.remove(&open)
                    && !entries.is_empty()
                {
                    let displayed_entries: Vec<_> = entries
                        .iter()
                        .map(|(index, entry)| {
                            let (counts_unread, clock) =
                                super::handshake::entry_read_tracking(entry);
                            super::contact::DisplayedEntry {
                                index: *index,
                                counts_unread,
                                clock,
                            }
                        })
                        .collect();
                    let views: Option<Vec<_>> = inner.contact(&open).map(|contact| {
                        entries
                            .into_iter()
                            .map(|(index, entry)| contact.message(index, entry))
                            .collect()
                    });
                    if let Some(views) = views {
                        self.show_new(inner, &open, views);
                        self.acknowledge_appended_displayed(inner, &open, &displayed_entries)
                            .await;
                    }
                }
            }
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            self.ui.contacts.set(inner.views());

            // Unconditionally ACK server mailbox prefix on the final page (earlier pages piggyback).
            if !has_more {
                if inner.client.pending_mailbox_ack() > 0 {
                    match inner.client.ack_mailbox_v2(&mailbox, &inner.audience).await {
                        _ if !self.is_live(vgen) => return Ok(Vec::new()),
                        Ok(_) => {
                            let _ = inner.save_state().await;
                        }
                        Err(e) => {
                            self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                        }
                    }
                }
                break;
            }
        }

        // If any carried initials or buffered envelopes arrived, pull inbox initials, join carried
        // initials, and locally replay buffered envelopes with zero server re-fetch.
        if !peers_needing_replay.is_empty() {
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            if let Ok((_, replayed_during_inbox)) = self.take_initial_messages_with_replayed().await
            {
                affected_peers.extend(replayed_during_inbox);
            }
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            if let Some(inner) = guard.as_mut() {
                for peer in &peers_needing_replay {
                    if !self.is_live(vgen) {
                        return Ok(Vec::new());
                    }
                    if let Ok(join) = self.join_carried(inner, peer).await
                        && join.recommend_upgrade
                    {
                        upgrades.insert(*peer);
                    }
                }
                if !self.is_live(vgen) {
                    return Ok(Vec::new());
                }
                if let Ok((replayed, replay_upgrades)) =
                    self.replay_deferred_envelopes(inner, None).await
                {
                    affected_peers.extend(replayed);
                    upgrades.extend(replay_upgrades);
                }
            }
        }

        for peer in upgrades {
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            let _ = self.upgrade_to_pq(peer).await;
        }
        Ok(affected_peers.into_iter().collect())
    }

    /// Locally replay buffered `DeferredEnvelope`s (optionally restricted to `only_peer`) for
    /// contacts that are no longer quarantined and have no pending unsupported-suite initials.
    /// Requires zero server re-fetch and commits all replayed messages atomically.
    pub(super) async fn replay_deferred_envelopes(
        &self,
        inner: &mut Inner<V>,
        only_peer: Option<&PublicKey>,
    ) -> Result<(BTreeSet<PublicKey>, BTreeSet<PublicKey>), String> {
        if inner.deferred_envelopes.is_empty() {
            return Ok((BTreeSet::new(), BTreeSet::new()));
        }
        let local_pq = inner.local_pq_enabled();
        let now_ms = now();
        let collect_eligible = |inner: &Inner<V>| -> BTreeSet<PublicKey> {
            let mut eligible = BTreeSet::new();
            for env in &inner.deferred_envelopes {
                let Ok(peer) = PublicKey::try_from(env.peer.as_slice()) else {
                    continue;
                };
                if only_peer.is_some_and(|wanted| wanted != &peer) {
                    continue;
                }
                let Some(contact) = inner.contacts.iter().find(|c| c.peer == peer) else {
                    continue;
                };
                let still_blocked = contact.state.quarantined
                    || contact.is_new_quarantined()
                    || contact.deferred_carried > 0
                    || inner.has_deferred_initial_for(&peer)
                    || inner.is_isolated_peer(&peer);
                if !still_blocked {
                    eligible.insert(peer);
                }
            }
            eligible
        };

        let initial_eligible = collect_eligible(inner);
        if initial_eligible.is_empty() {
            return Ok((BTreeSet::new(), BTreeSet::new()));
        }

        // Phase A (pre-pass): while ALL `DeferredEnvelope`s remain intact in
        // `inner.deferred_envelopes`, extract and join any carried `initial_message` from eligible
        // peers' buffered envelopes (in ascending sequence order). This ensures:
        // 1. `join_carried`'s durable saves never wipe uncommitted `to_replay` envelopes.
        // 2. An out-of-order carried initial on envelope N+1 joins before decrypting envelope N.
        // 3. Any peer quarantined or deferred by `join_carried` is excluded on recomputation below
        //    so its buffered envelopes are preserved rather than dropped.
        let mut upgrades: BTreeSet<PublicKey> = BTreeSet::new();
        let mut carried_indices: Vec<(u64, usize, PublicKey)> = inner
            .deferred_envelopes
            .iter()
            .enumerate()
            .filter_map(|(idx, env)| {
                env.initial_message.as_ref()?;
                if env.deferred_at != 0
                    && now_ms.saturating_sub(env.deferred_at) > DEFERRED_REPLAY_WINDOW_MS
                {
                    return None;
                }
                let peer = PublicKey::try_from(env.peer.as_slice()).ok()?;
                initial_eligible
                    .contains(&peer)
                    .then_some((env.sequence, idx, peer))
            })
            .collect();
        carried_indices.sort_by_key(|&(seq, idx, _)| (seq, idx));

        let mut peers_with_carried: BTreeSet<PublicKey> = BTreeSet::new();
        let phase_a_envelopes = inner.deferred_envelopes.clone();
        let phase_a_carried_ts = inner.carried_deferred_timestamps.clone();
        let mut phase_a_pending: HashMap<PublicKey, Vec<Vec<u8>>> = HashMap::new();
        let mut phase_a_dirty = false;
        for (_, idx, peer) in carried_indices {
            let Some(contact_idx) = inner.contacts.iter().position(|c| c.peer == peer) else {
                continue;
            };
            let decoded = inner.deferred_envelopes[idx]
                .initial_message
                .as_ref()
                .and_then(|wire| Incoming::try_from(wire).ok());
            match decoded {
                Some(inc) => {
                    phase_a_pending.entry(peer).or_insert_with(|| {
                        inner.contacts[contact_idx]
                            .state
                            .pending_carried_initials
                            .clone()
                    });
                    if stage_carried_initials(&mut inner.contacts[contact_idx].state, [&inc])
                        .is_ok()
                    {
                        inner.deferred_envelopes[idx].initial_message = None;
                        peers_with_carried.insert(peer);
                        phase_a_dirty = true;
                    }
                }
                None => {
                    inner.deferred_envelopes[idx].initial_message = None;
                    phase_a_dirty = true;
                }
            }
        }
        if phase_a_dirty {
            for peer in &peers_with_carried {
                if let Some(contact) = inner.contact(peer) {
                    let carried = contact.state.pending_carried_initials.clone();
                    record_carried_timestamps(
                        &mut inner.carried_deferred_timestamps,
                        &carried,
                        now_ms,
                    );
                }
            }
            if let Err(e) = inner.save(&[]).await {
                inner.deferred_envelopes = phase_a_envelopes;
                inner.carried_deferred_timestamps = phase_a_carried_ts;
                for (peer, pending) in phase_a_pending {
                    if let Some(contact) = inner.contact(&peer) {
                        contact.state.pending_carried_initials = pending;
                    }
                }
                return Err(describe(&e));
            }
        }
        // Join carried initials for ALL eligible peers with unjoined `pending_carried_initials` —
        // including entries already staged by `receive_mailbox` (whose `DeferredEnvelope` has
        // `initial_message = None`) — BEFORE Phase B attempts to decrypt buffered envelopes.
        let peers_to_join: BTreeSet<PublicKey> = initial_eligible
            .iter()
            .copied()
            .filter(|peer| {
                peers_with_carried.contains(peer)
                    || inner.contacts.iter().any(|c| {
                        c.peer == *peer
                            && c.deferred_carried < c.state.pending_carried_initials.len()
                    })
            })
            .collect();
        for peer in peers_to_join {
            let outcome = self.join_carried(inner, &peer).await?;
            if outcome.recommend_upgrade {
                upgrades.insert(peer);
            }
        }

        // Recompute eligibility after `join_carried`: exclude any peer that became quarantined or
        // deferred an unsupported suite so its buffered envelopes remain safely preserved.
        let eligible_peers = collect_eligible(inner);
        if eligible_peers.is_empty() {
            return Ok((BTreeSet::new(), upgrades));
        }

        // Phase B (pure in-memory decrypt + single atomic `inner.save_with`): snapshot the clean
        // post-Phase-A state so any vault error rolls back without clobbering committed joins.
        let client_snapshot = proto::ClientState::from(inner.client.state());
        let saved_envelopes = inner.deferred_envelopes.clone();
        let saved_carried_ts = inner.carried_deferred_timestamps.clone();
        let mut contact_snapshots: HashMap<PublicKey, (proto::SessionState, ContactState)> =
            HashMap::new();

        // Partition out eligible envelopes in ascending sequence order.
        let mut to_replay: Vec<DeferredEnvelope> = Vec::new();
        let mut retained: Vec<DeferredEnvelope> = Vec::new();
        for env in std::mem::take(&mut inner.deferred_envelopes) {
            let is_eligible = PublicKey::try_from(env.peer.as_slice())
                .ok()
                .is_some_and(|p| eligible_peers.contains(&p));
            if is_eligible {
                to_replay.push(env);
            } else {
                retained.push(env);
            }
        }
        inner.deferred_envelopes = retained;
        to_replay.sort_by_key(|e| e.sequence);

        let mut replayed_peers: BTreeSet<PublicKey> = BTreeSet::new();
        let mut per_peer_entries: BTreeMap<PublicKey, Vec<(u64, HistoryEntry)>> = BTreeMap::new();
        let mut per_peer_steps: BTreeMap<PublicKey, Vec<(u64, crate::state::Step)>> =
            BTreeMap::new();
        let mut per_peer_settled: BTreeMap<PublicKey, Vec<(u64, u64)>> = BTreeMap::new();
        let mut peer_deleted: BTreeSet<PublicKey> = BTreeSet::new();
        let mut skipped_counts: HashMap<PublicKey, usize> = HashMap::new();

        for env in to_replay {
            let Ok(peer) = PublicKey::try_from(env.peer.as_slice()) else {
                continue;
            };
            if env.deferred_at != 0
                && now_ms.saturating_sub(env.deferred_at) > DEFERRED_REPLAY_WINDOW_MS
            {
                continue;
            }
            let Some(contact_idx) = inner.contacts.iter().position(|c| c.peer == peer) else {
                continue;
            };
            contact_snapshots
                .entry(peer)
                .or_insert_with(|| inner.contacts[contact_idx].snapshot());

            let Some(ref msg) = env.message else {
                continue;
            };
            match inner.contacts[contact_idx].session.decrypt_envelope(msg) {
                Ok(decrypted) => {
                    let contact = &mut inner.contacts[contact_idx];
                    let mut content = Content::from_bytes(&decrypted.content);
                    if !decrypted.earlier {
                        contact.mark_greeting_confirmed();
                    }
                    replayed_peers.insert(peer);
                    if let Some(events) = content.events.take() {
                        let told = contact.told(&events);
                        per_peer_steps.entry(peer).or_default().extend(told.steps);
                        per_peer_settled
                            .entry(peer)
                            .or_default()
                            .extend(told.settled_outbox);
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
                                upgrades.insert(peer);
                            }
                        }
                    }
                    if matches!(content.kind, Some(Kind::Deleted(_))) && !decrypted.earlier {
                        contact.session.retire();
                        peer_deleted.insert(peer);
                    }
                    if let Ok(entry) = contact.add_received(content, false) {
                        per_peer_entries.entry(peer).or_default().push(entry);
                    }
                }
                Err(e) if e.kind() == ErrorKind::DuplicateMessage => {}
                Err(e) if e.kind() == ErrorKind::EvictedMessage => {
                    if let Ok(entry) = inner.contacts[contact_idx].add_evicted() {
                        per_peer_entries.entry(peer).or_default().push(entry);
                        replayed_peers.insert(peer);
                    }
                }
                Err(_) => {
                    // Peer is active, unquarantined, and has no unsupported-suite initials;
                    // drop permanently undecryptable envelope so future messages aren't blocked.
                    *skipped_counts.entry(peer).or_insert(0) += 1;
                }
            }
        }

        let mut all_records: Vec<(PublicKey, u64, HistoryEntry)> = Vec::new();
        let mut all_outbox_updates: Vec<(PublicKey, u64, Option<OutgoingRecord>)> = Vec::new();
        let mut per_peer_changed: BTreeMap<PublicKey, Vec<(u64, HistoryEntry)>> = BTreeMap::new();
        let mut requeued_outcomes: Vec<(PublicKey, RequeueOutcome)> = Vec::new();

        for peer in &eligible_peers {
            let steps = per_peer_steps.remove(peer).unwrap_or_default();
            let settled = per_peer_settled.remove(peer).unwrap_or_default();
            let deleted = peer_deleted.contains(peer);
            let mut changed = BTreeMap::new();
            if !steps.is_empty()
                && let Err(e) = inner.step(peer, &mut changed, steps).await
            {
                rollback_mailbox_page(
                    inner,
                    client_snapshot,
                    contact_snapshots,
                    saved_envelopes,
                    saved_carried_ts,
                )?;
                return Err(describe(&e));
            }
            let mut settled_non_attachments = Vec::new();
            for &(history_index, clock) in &settled {
                if let Some(entry) = changed.get_mut(&history_index) {
                    if entry.place == 0 {
                        entry.place = clock;
                        entry.content.get_or_insert_default().clock = clock;
                    }
                    let is_attachment = matches!(
                        entry.content.as_ref().and_then(|c| c.kind.as_ref()),
                        Some(Kind::Attachment(_))
                    );
                    if !is_attachment {
                        settled_non_attachments.push(history_index);
                    }
                }
                all_outbox_updates.push((*peer, history_index, None));
            }
            if !settled_non_attachments.is_empty()
                && let Some(contact) = inner.contact(peer)
            {
                contact
                    .state
                    .awaiting
                    .retain(|a| !settled_non_attachments.contains(&a.history_index));
            }
            if deleted || needs_new_session(inner, peer) {
                match inner.requeue(peer, deleted, &changed).await {
                    Ok(requeued) => {
                        all_outbox_updates.extend(requeued.outbox.clone());
                        changed.extend(requeued.history.iter().cloned());
                        requeued_outcomes.push((*peer, requeued));
                    }
                    Err(e) => {
                        rollback_mailbox_page(
                            inner,
                            client_snapshot,
                            contact_snapshots,
                            saved_envelopes,
                            saved_carried_ts,
                        )?;
                        return Err(e);
                    }
                }
            }
            let changed_vec: Vec<_> = changed.into_iter().collect();
            if let Some(entries) = per_peer_entries.get(peer) {
                all_records.extend(records(peer, entries));
            }
            all_records.extend(records(peer, &changed_vec));
            if !changed_vec.is_empty() {
                per_peer_changed.insert(*peer, changed_vec);
            }
        }

        if let Err(e) = inner.save_with(&all_records, &all_outbox_updates).await {
            rollback_mailbox_page(
                inner,
                client_snapshot,
                contact_snapshots,
                saved_envelopes,
                saved_carried_ts,
            )?;
            return Err(describe(&e));
        }
        if self.shutting_down.get() || crate::glue::lock_released() {
            return Ok((BTreeSet::new(), BTreeSet::new()));
        }

        for (peer, count) in skipped_counts {
            let label = inner
                .contact(&peer)
                .map_or_else(|| short(&peer), |c| c.view().label());
            self.ui.log(format!(
                "skipped {count} deferred message(s) from {label} that do not decrypt"
            ));
        }
        for (peer, outcome) in requeued_outcomes {
            outcome.log_missing(&self.ui, &peer);
        }
        if let Some(open) = self.ui.open.get_untracked() {
            if let Some(changed_vec) = per_peer_changed.get(&open) {
                self.show_changes(inner, &open, changed_vec);
            }
            if let Some(entries) = per_peer_entries.remove(&open)
                && !entries.is_empty()
            {
                let displayed_entries: Vec<_> = entries
                    .iter()
                    .map(|(index, entry)| {
                        let (counts_unread, clock) = super::handshake::entry_read_tracking(entry);
                        super::contact::DisplayedEntry {
                            index: *index,
                            counts_unread,
                            clock,
                        }
                    })
                    .collect();
                let views: Option<Vec<_>> = inner.contact(&open).map(|contact| {
                    entries
                        .into_iter()
                        .map(|(index, entry)| contact.message(index, entry))
                        .collect()
                });
                if let Some(views) = views {
                    self.show_new(inner, &open, views);
                    self.acknowledge_appended_displayed(inner, &open, &displayed_entries)
                        .await;
                }
            }
        }
        if !self.shutting_down.get() && !crate::glue::lock_released() {
            self.ui.contacts.set(inner.views());
        }
        Ok((replayed_peers, upgrades))
    }
}

fn rollback_mailbox_page<V: VaultStore>(
    inner: &mut Inner<V>,
    client_snapshot: proto::ClientState,
    contact_snapshots: HashMap<PublicKey, (proto::SessionState, ContactState)>,
    saved_envelopes: Vec<DeferredEnvelope>,
    saved_carried_ts: Vec<crate::vault::CarriedDeferredTimestamp>,
) -> Result<(), String> {
    if let Ok(restored_client) = ClientState::try_from(&client_snapshot) {
        let clock = inner.client.clock().clone();
        inner.client = session::Client::restore(Fetch::client(&inner.server), restored_client)
            .with_clock(clock);
    }
    for (peer, snapshot) in contact_snapshots {
        inner.roll_back(&peer, snapshot)?;
    }
    inner.deferred_envelopes = saved_envelopes;
    inner.carried_deferred_timestamps = saved_carried_ts;
    Ok(())
}

/// Decode a persisted [`Farewell`] into a wire [`PushV2Request`], backfilling a deterministic
/// `client_message_id` when empty.
pub(super) fn farewell_push_v2_request(farewell: &Farewell) -> Option<PushV2Request> {
    if farewell.push_v2.is_empty() {
        return None;
    }
    let mut req = PushV2Request::decode(farewell.push_v2.as_slice()).ok()?;
    if req.client_message_id.is_empty()
        && let Some(ref msg) = req.message
    {
        req.client_message_id =
            bytes::Bytes::copy_from_slice(&session::Sealed::client_message_id_for(msg));
    }
    Some(req)
}
