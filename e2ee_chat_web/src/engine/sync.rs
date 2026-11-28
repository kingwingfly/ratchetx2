//! Server notifications, synchronization, write-token grants/revocations, and unified mailbox
//! receive with cross-peer stall isolation.

use super::contact::{Contact, pq_incompatible_isolated_token_hashes};
use super::handshake::{
    DEFERRED_REPLAY_WINDOW_MS, Incoming, record_carried_timestamps, stage_carried_initial_one,
};
use super::outbox::{RekeyOutcome, RequeueOutcome, needs_new_session};
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
    CLASSICAL_APPROVAL_NONE, ContactState, DeferredEnvelope, Farewell, GREETING_DELIVERY_CONFIRMED,
    GREETING_DELIVERY_UNCERTAIN, GREETING_DELIVERY_UNSENT, HistoryEntry, OutgoingRecord,
    SECURITY_ALERT_DOWNGRADE, SECURITY_ALERT_NONE, SECURITY_ALERT_PQ_REQUIRED,
};
use futures_util::future::{Either, select};
use leptos::prelude::*;
use leptos::task::spawn_local;
use prost::Message as _;
use session::protocol::handshake_v2::{
    GetManifestRequest, InitialMessageV2 as WireInitialMessageV2, LocalHandshakeV2,
};
use session::protocol::mailbox_v2::{LocalMailboxV2, PushV2Request};
use session::protocol::notify::{self, Notification};
use session::{ClientState, ErrorKind, PqSuite, PublicKey, proto};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

/// Maximum raw mailbox envelopes buffered per active/quarantined/rekeying peer.
pub(super) const MAX_DEFERRED_ENVELOPES_PER_PEER: usize = 64;
/// Maximum raw mailbox envelopes buffered across all active/quarantined/rekeying peers.
pub(super) const MAX_TOTAL_DEFERRED_ENVELOPES: usize = 256;
/// Maximum raw mailbox envelopes buffered per PQ-incompatible isolated peer (exceeds the relay's
/// 2,000-message queue cap so isolated peers can be drained without stalling healthy contacts).
pub(super) const MAX_ISOLATED_DEFERRED_ENVELOPES_PER_PEER: usize = 2048;
/// Maximum raw mailbox envelopes buffered across all PQ-incompatible isolated peers.
pub(super) const MAX_TOTAL_ISOLATED_DEFERRED_ENVELOPES: usize = 4096;
/// Safety bound on unified mailbox pages drained in a single `receive_mailbox` call.
const MAX_MAILBOX_PAGES: usize = 20;

/// Prune expired (`> DEFERRED_REPLAY_WINDOW_MS`), malformed, or unknown-peer `DeferredEnvelope`s
/// on unlock or before replay, preserving envelopes belonging to PQ-incompatible isolated contacts
/// (and envelopes flagged `pq_isolated` that were ACKed while isolated and await replay after a
/// capable build unlocks) in their own dedicated spool budget without 30-day silent expiry.
/// Any isolated envelope dropped due to cap overflow increments `evicted_while_isolated` on the
/// matching contact so the user is informed. Returns how many entries were removed.
pub(super) fn prune_deferred_envelopes(
    envelopes: &mut Vec<DeferredEnvelope>,
    contacts: &mut [Contact],
    isolated_contacts: &mut [ContactState],
    me: &PublicKey,
    now_ms: u64,
) -> usize {
    let before = envelopes.len();
    let pq_isolated_peers: BTreeSet<PublicKey> = isolated_contacts
        .iter()
        .filter_map(|state| pq_incompatible_isolated_token_hashes(state, me).map(|(p, _)| p))
        .collect();
    let mut seen: BTreeSet<(PublicKey, u64)> = BTreeSet::new();
    let mut active_per_peer: HashMap<PublicKey, usize> = HashMap::new();
    let mut active_total: usize = 0;
    let mut isolated_per_peer: HashMap<PublicKey, usize> = HashMap::new();
    let mut isolated_total: usize = 0;
    envelopes.retain_mut(|env| {
        let Ok(peer) = PublicKey::try_from(env.peer.as_slice()) else {
            return false;
        };
        let peer_is_isolated = pq_isolated_peers.contains(&peer);
        if !contacts.iter().any(|c| c.peer == peer) && !peer_is_isolated {
            return false;
        }
        if peer_is_isolated {
            env.pq_isolated = true;
        }
        let is_isolated = env.pq_isolated;
        if !is_isolated
            && env.deferred_at != 0
            && now_ms.saturating_sub(env.deferred_at) > DEFERRED_REPLAY_WINDOW_MS
        {
            return false;
        }
        if !seen.insert((peer, env.sequence)) {
            return false;
        }
        if is_isolated {
            let count = isolated_per_peer.entry(peer).or_insert(0);
            if *count >= MAX_ISOLATED_DEFERRED_ENVELOPES_PER_PEER
                || isolated_total >= MAX_TOTAL_ISOLATED_DEFERRED_ENVELOPES
            {
                if let Some(iso) = isolated_contacts
                    .iter_mut()
                    .find(|c| c.peer.as_slice() == peer.as_slice())
                {
                    iso.evicted_while_isolated = iso.evicted_while_isolated.saturating_add(1);
                } else if let Some(contact) = contacts.iter_mut().find(|c| c.peer == peer) {
                    contact.state.evicted_while_isolated =
                        contact.state.evicted_while_isolated.saturating_add(1);
                }
                return false;
            }
            *count += 1;
            isolated_total += 1;
        } else {
            let count = active_per_peer.entry(peer).or_insert(0);
            if *count >= MAX_DEFERRED_ENVELOPES_PER_PEER
                || active_total >= MAX_TOTAL_DEFERRED_ENVELOPES
            {
                return false;
            }
            *count += 1;
            active_total += 1;
        }
        true
    });
    before - envelopes.len()
}

/// Buffer one raw mailbox envelope for `peer` into `envelopes`, enforcing separate per-peer and
/// total caps for active (`64`/`256`) vs PQ-isolated (`2048`/`4096`) spools so isolated contacts
/// never steal active-peer budget. Returns `true` if the envelope was stored or already present,
/// or `false` if dropped due to cap overflow (caller must record eviction in the same atomic tx).
pub(super) fn push_deferred_envelope(
    envelopes: &mut Vec<DeferredEnvelope>,
    peer: &PublicKey,
    sequence: u64,
    message: Option<party::EncryptedMessage>,
    initial_message: Option<WireInitialMessageV2>,
    now_ms: u64,
    pq_isolated: bool,
) -> bool {
    if envelopes
        .iter()
        .any(|e| e.peer.as_slice() == peer.as_slice() && e.sequence == sequence)
    {
        return true;
    }
    let (peer_cap, total_cap) = if pq_isolated {
        (
            MAX_ISOLATED_DEFERRED_ENVELOPES_PER_PEER,
            MAX_TOTAL_ISOLATED_DEFERRED_ENVELOPES,
        )
    } else {
        (
            MAX_DEFERRED_ENVELOPES_PER_PEER,
            MAX_TOTAL_DEFERRED_ENVELOPES,
        )
    };
    let peer_count = envelopes
        .iter()
        .filter(|e| e.pq_isolated == pq_isolated && e.peer.as_slice() == peer.as_slice())
        .count();
    let total_count = envelopes
        .iter()
        .filter(|e| e.pq_isolated == pq_isolated)
        .count();
    if peer_count >= peer_cap || total_count >= total_cap {
        return false;
    }
    envelopes.push(DeferredEnvelope {
        peer: peer.to_vec(),
        sequence,
        message,
        initial_message,
        deferred_at: now_ms,
        pq_isolated,
    });
    true
}

impl<V: VaultStore> Engine<V> {
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
                // R7-P2-1 + R8-P2-3: Re-check `pending_revokes` under the SAME `inner` guard that
                // selects EACH grant so a concurrent flusher finishing an earlier RPC can never
                // register a newly staged grant version ahead of a staged `PendingRevoke`, then
                // release `grant_sync_lock` before issuing `RegisterWriteToken`.
                let peer_slot_id = inner.client.peer_slot_id(peer);
                let has_pending_revoke = inner
                    .state
                    .pending_revokes
                    .iter()
                    .any(|r| r.peer_slot_id.as_slice() == peer_slot_id.as_slice());
                if has_pending_revoke {
                    None
                } else {
                    match inner.client.sign_register_write_token_v2(
                        &inner.audience,
                        peer,
                        &grant.token_hash,
                        grant.grant_version,
                        grant.pin_active,
                    ) {
                        Ok(request) => Some((inner.server.clone(), grant, request)),
                        Err(e) => {
                            if e.kind() == ErrorKind::ClockSkew {
                                self.warn_clock_skew(inner.client.clock().offset_ms());
                            }
                            first_err = Some(describe(&e));
                            break;
                        }
                    }
                }
            };
            let Some((server, grant, request)) = next else {
                self.flush_pending_revoke_for_peer(vgen, peer).await?;
                continue;
            };
            attempted.push((grant.token_hash, grant.grant_version));
            let rpc_res: session::Result<()> = Fetch::client(&server)
                .register_write_token(request)
                .await
                .map(|_| ())
                .map_err(session::Error::from);
            if !self.is_live(vgen) {
                return Ok(());
            }
            let (remove, reconcile_active_stale) = match rpc_res {
                Ok(()) => (true, false),
                // Stale/superseded grant version (`grant_version <= revoked_below_version`):
                // drop non-active archived grants cleanly, but if the ACTIVE session's grant hit
                // `StaleVersion`, re-stage it with a freshly allocated higher grant version and
                // keep outbound traffic gated until registration succeeds.
                Err(e) if e.kind() == ErrorKind::StaleVersion => {
                    first_err = Some(describe(&e));
                    (true, true)
                }
                Err(e) if e.kind() == ErrorKind::LimitExceeded => {
                    let msg = format!(
                        "Could not register write token for {}: active server grant limit reached ({})",
                        short(peer),
                        describe(&e)
                    );
                    self.ui.log(msg.clone());
                    self.ui.notify(msg);
                    first_err = Some(describe(&e));
                    break;
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
                let mut active_restaged = false;
                if let Some(inner) = guard.as_mut() {
                    let still_pending = inner
                        .contacts
                        .iter()
                        .find(|c| c.peer == *peer)
                        .is_some_and(|c| {
                            c.session.pending_register_grants().iter().any(|g| {
                                g.token_hash == grant.token_hash
                                    && g.grant_version == grant.grant_version
                            })
                        });
                    let is_active = reconcile_active_stale
                        && still_pending
                        && inner
                            .contacts
                            .iter()
                            .find(|c| c.peer == *peer)
                            .and_then(|c| c.session.active_inbound_token_hash())
                            == Some(grant.token_hash);
                    if is_active {
                        // Re-stage atomically WITHOUT removing the existing pending grant first so
                        // `merge_pending_grants` replaces the lower version on success while any
                        // grant-version allocation failure preserves the pending send gate.
                        if inner
                            .stage_write_token_grant(peer, grant.token_hash, true)
                            .is_ok()
                        {
                            active_restaged = true;
                            let _ = inner.save_state().await;
                        }
                    } else {
                        let removed = inner.contact(peer).is_some_and(|contact| {
                            contact
                                .session
                                .remove_pending_grant(&grant.token_hash, grant.grant_version)
                        });
                        if reconcile_active_stale {
                            // Archived non-active grant or stale concurrent completion whose active
                            // grant was already confirmed/superseded: do not treat as fatal error.
                            first_err = None;
                        }
                        if removed {
                            let _ = inner.save_state().await;
                        }
                    }
                }
                if active_restaged {
                    break;
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
                .filter(|c| {
                    !c.state.provisional
                        && !c.state.request
                        && !c.state.quarantined
                        && !c.session.pending_register_grants().is_empty()
                })
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

    /// Flush any pending `RevokeWriteToken` targeting `peer`'s slot under `self.grant_sync_lock`
    /// (waiting for any in-flight `flush_pending_revokes` call to finish first). Must complete
    /// before sending `RegisterWriteToken` for `peer` so a delayed cancellation revoke never
    /// deletes a freshly re-registered grant.
    pub(super) async fn flush_pending_revoke_for_peer(
        &self,
        vgen: u64,
        peer: &PublicKey,
    ) -> Result<(), String> {
        let _grant_guard = self.grant_sync_lock.lock().await;
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
                let slot_id = inner.client.peer_slot_id(peer);
                let Some(revoke) = inner
                    .state
                    .pending_revokes
                    .iter()
                    .find(|r| r.peer_slot_id.as_slice() == slot_id.as_slice())
                    .cloned()
                else {
                    return Ok(());
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
            if let Some(pos) = inner.state.pending_revokes.iter().position(|r| {
                r.peer_slot_id == revoke.peer_slot_id
                    && r.min_grant_version <= revoke.min_grant_version
            }) {
                inner.state.pending_revokes.remove(pos);
                inner.save_state().await.map_err(|e| describe(&e))?;
            }
        }
    }

    /// Flush durably staged `RevokeWriteToken` entries from `AppState.pending_revokes` without
    /// holding `self.inner` across network RPCs.
    pub(super) async fn flush_pending_revokes(&self) -> Result<(), String> {
        let vgen = self.vault_gen();
        let _grant_guard = self.grant_sync_lock.lock().await;
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
                        let _ = self.flush_background(&peer).await;
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
    /// audience (never blindly trusting server-supplied audience strings), releasing `self.inner`
    /// across the network RPC.
    pub(super) async fn refresh_server_info(&self, force: bool) {
        let vgen = self.vault_gen();
        let (server, audience, probe_epoch) = {
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
            let probe_epoch = inner.bump_server_pq_epoch();
            (inner.server.clone(), inner.audience.clone(), probe_epoch)
        };
        let info_res = session::check_server_info_with(&Fetch::client(&server), &audience).await;
        if !self.is_live(vgen) {
            return;
        }
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return;
        }
        let Some(inner) = guard.as_mut() else {
            return;
        };
        if inner.server_pq_epoch != probe_epoch {
            // A newer `GetServerInfo` probe or authoritative publish/refill outcome already
            // updated server capabilities while this probe was in flight: discard stale reply.
            return;
        }
        let status = match info_res {
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

    /// One round: recover unsaved state, promote waiting uploads after cross-tab sign-in, refresh
    /// server info, push farewells, flush revocations, take initial messages, publish/refill
    /// prekeys, flush write-token grants, receive the unified mailbox, and flush per-peer
    /// outboxes. Returns whether anything happened.
    pub(super) async fn sync(self: &Rc<Self>) -> bool {
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
        // R16-P2-10: If unlock's initial `vault.uploads(None)` failed transiently, retry restoring
        // paused upload cards (including started 0-chunk uploads) and settling orphan checkpoints.
        if self.uploads.restore_needed() {
            if let Err(e) = self.restore_uploads_from_vault().await {
                failure.get_or_insert(e);
            }
            if !self.is_live(vgen) {
                return false;
            }
        }
        // R16-P2-9: Retry any `cancel_upload` whose local vault settlement failed transiently so
        // empty-outbox or stalled peers never remain stranded with no upload card to re-cancel.
        for (cancel_peer, cancel_id) in self.uploads.pending_cancels() {
            if !self.is_live(vgen) {
                return false;
            }
            if let Err(e) = self.cancel_upload(cancel_peer, cancel_id).await {
                failure.get_or_insert(e);
            }
        }
        if !self.is_live(vgen) {
            return false;
        }
        // R20-P2-8 + R21-P2-11: Retry any `HistoryEntry.gone = true` saves that failed transiently
        // after confirmed server deletion so reload + unread requeue never resurrects a deleted
        // pointer, without calling `self.wake()` on persistent write errors so normal polling
        // backoff still applies.
        for (gone_peer, gone_conv_gen, gone_id) in self.uploads.pending_gone() {
            if !self.is_live(vgen) {
                return false;
            }
            if let Err(e) = self
                .note_gone_by_id_for_gen_with_wake(
                    &gone_peer,
                    None,
                    &gone_id,
                    Some(gone_conv_gen),
                    false,
                )
                .await
            {
                failure.get_or_insert(e);
            }
        }
        if !self.is_live(vgen) {
            return false;
        }
        // R28-P2-2: Promote `UPLOAD_STATE_WAITING` uploads once cross-tab sign-in is proven by an
        // authenticated RPC so waiting uploads and messages queued behind them unblock without
        // requiring an explicit in-tab `sign_in()` / `signed_in()` call.
        if self.uploads.start_waiting_needed() {
            active |= self.start_waiting_uploads().await;
            if !self.is_live(vgen) {
                return false;
            }
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
        let inbox_drained_all = match self.take_initial_messages_with_replayed().await {
            Ok((taken, _, drained_all)) => {
                active |= taken;
                drained_all
            }
            Err(e) => {
                failure.get_or_insert(e);
                false
            }
        };
        if !self.is_live(vgen) {
            return false;
        }
        // R8-P2-6: Always run `publish_with_rotation_gate(false, inbox_drained_all)` even when
        // `ListInitialMessages` failed (`inbox_drained_all == false`) so mandatory day-25 manifest
        // renewal / unreconciled publish recovery can still renew in place while scheduled SPK
        // rotation stays deferred and `failure` remains preserved.
        if let Err(e) = self
            .publish_with_rotation_gate(false, inbox_drained_all)
            .await
        {
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
        match self.retry_pending_greetings().await {
            Ok(retried) => active |= retried,
            Err(e) => {
                failure.get_or_insert(e);
            }
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
            match self.flush_background(&peer).await {
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
    pub(super) async fn recover_local_changes(&self) -> Result<bool, String> {
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
            self.refresh_contacts(inner);
        }
        let mut grant_peers: BTreeSet<PublicKey> = BTreeSet::new();
        let mut upgrades: BTreeMap<PublicKey, u64> = BTreeMap::new();
        if let Some((replayed_upgrades, replayed_grants)) =
            self.replay_deferred_initials(inner).await?
        {
            upgrades.extend(replayed_upgrades);
            grant_peers.extend(replayed_grants);
        }
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
        for peer in &pending {
            if !self.is_live(vgen) {
                return Ok(false);
            }
            let join = self.join_carried(inner, peer).await?;
            if let Some(conv_gen) = join.recommend_upgrade {
                upgrades.insert(*peer, conv_gen);
            }
            grant_peers.extend(join.grant_peers);
        }
        if !self.is_live(vgen) {
            return Ok(false);
        }
        // Preserve undecryptable buffered envelopes here because `recover_local_changes` runs
        // BEFORE `take_initial_messages` in `sync()`: a rekeyed ciphertext whose inbox initial has
        // not been fetched yet must survive until the subsequent inbox pull joins it.
        let (replayed_peers, replay_upgrades, replay_grants) = self
            .replay_deferred_envelopes(inner, None, None, None)
            .await?;
        upgrades.extend(replay_upgrades);
        grant_peers.extend(replay_grants);
        let recovered = !pending.is_empty() || !replayed_peers.is_empty();
        drop(guard);
        for peer in grant_peers {
            if !self.is_live(vgen) {
                return Ok(false);
            }
            let _ = self.flush_pending_grants_for_peer(&peer).await;
        }
        for (peer, conv_gen) in upgrades {
            if !self.is_live(vgen) {
                return Ok(false);
            }
            let _ = self.upgrade_to_pq_auto(peer, conv_gen).await;
        }
        Ok(recovered)
    }

    /// Push the messages telling peers that their chats were deleted here, see
    /// [`delete`](Self::delete), releasing `self.inner` across each `PushV2` network RPC.
    pub(super) async fn say_farewells(&self) -> Result<(), String> {
        let vgen = self.vault_gen();
        loop {
            if !self.is_live(vgen) || self.startup.farewells_wait_sign_in() {
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
                let Some(mut v2_req) = farewell_push_v2_request(&farewell) else {
                    inner.state.farewells.remove(0);
                    inner.save_state().await.map_err(|e| describe(&e))?;
                    continue;
                };
                // R15-P2-1 + R16-P2-4: Never transmit a carried classical v1 initial message inside
                // a farewell (including persisted `fallback_farewells`) once `strict_pq` is active,
                // or once ordinary local PQ is enabled without an explicit classical exception
                // recorded on the farewell.
                if v2_req
                    .initial_message
                    .as_ref()
                    .is_some_and(|w| w.version < 2)
                    && (inner.client.pq_config().strict_pq
                        || (inner.local_pq_enabled() && !farewell.allow_classical_initial))
                {
                    v2_req.initial_message = None;
                }
                let signs_in_here = same_server(&inner.server, &origin());
                (inner.server.clone(), signs_in_here, farewell, v2_req)
            };
            let (server, signs_in_here, farewell, v2_req) = next;
            // R24-P1-1: Suppress the global `REFUSED` sign-in hook so a background/stale farewell
            // 403 cannot hijack an unrelated active `start_chat` or a newly unlocked vault.
            let pushed: session::Result<()> = Fetch::client_without_refused_hook(&server)
                .push_v2(v2_req)
                .await
                .map(|_| ())
                .map_err(session::Error::from);
            if !self.is_live(vgen) {
                return Ok(());
            }
            let auth_proven = match pushed {
                Ok(()) => signs_in_here,
                // Pushing takes a sign-in: they wait for it, without failing the round.
                Err(e) if e.kind() == ErrorKind::SignInRequired && signs_in_here => {
                    let still_queued = {
                        let guard = self.lock_inner().await;
                        self.is_live(vgen)
                            && guard.as_ref().is_some_and(|inner| {
                                inner
                                    .state
                                    .farewells
                                    .iter()
                                    .any(|f| f.push_v2 == farewell.push_v2)
                            })
                    };
                    if still_queued && self.is_live(vgen) {
                        self.startup.set_farewells_wait_sign_in(true);
                        self.ask_sign_in_background();
                    }
                    return Ok(());
                }
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
                    signs_in_here && e.kind() != ErrorKind::SignInRequired
                }
                Err(e) => {
                    if signs_in_here
                        && e.is_server_refusal()
                        && e.kind() != ErrorKind::SignInRequired
                    {
                        self.on_origin_auth_proven_async(vgen).await;
                    }
                    self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                    return Err(describe(&e));
                }
            };
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(());
            }
            let Some(inner) = guard.as_mut() else {
                return Ok(());
            };
            if auth_proven {
                self.on_origin_auth_proven_locked(vgen, inner);
            }
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
}

/// Window (28 days, matching the shipped 30-day server inbox retention and strictly shorter than
/// the server's 35-day `acked_initial_messages` delivery-tombstone TTL with a 7-day margin)
/// during which a sender may retry an `UNCERTAIN` greeting or probe a `CONFIRMED` greeting after
/// two peer SPK rotations (`manifest.generation >= target_generation + 2`) and auto-reclaim on
/// `StaleVersion` without risking resurrecting a declined chat request after tombstones expire.
pub(super) const GREETING_AUTO_RECLAIM_WINDOW_MS: u64 = 28 * 24 * 60 * 60 * 1000;

/// Whether a `CONFIRMED` greeting is eligible for a post-2-rotation SPK-eviction probe.
pub(super) fn confirmed_greeting_probe_eligible(state: &ContactState, now_ms: u64) -> bool {
    !state.provisional
        && !state.greeting_delivery_verified
        && state.greeting_target_generation > 0
        && state.greeting_sent_at > 0
        && now_ms.saturating_sub(state.greeting_sent_at) <= GREETING_AUTO_RECLAIM_WINDOW_MS
}

/// Whether an `UNCERTAIN` greeting is still within the server's delivery-tombstone TTL window and
/// therefore safe to retry and auto-reclaim on `StaleVersion`.
pub(super) fn uncertain_greeting_reclaim_eligible(state: &ContactState, now_ms: u64) -> bool {
    !state.provisional
        && state.greeting_sent_at > 0
        && now_ms.saturating_sub(state.greeting_sent_at) <= GREETING_AUTO_RECLAIM_WINDOW_MS
}

/// Verified peer manifest summary returned by [`Engine::probe_confirmed_greeting_spk_rotated`]
/// (`R20-P1-7`) so callers persist the peer's manifest pin monotonically before deciding whether
/// to probe or reclaim a session.
pub(super) struct SpkRotationProbe {
    pub(super) rotated: bool,
    pub(super) manifest_seq: u64,
    pub(super) manifest_digest: [u8; 32],
    pub(super) pq_enabled: bool,
}

impl<V: VaultStore> Engine<V> {
    /// Non-consuming read-only `GetManifest` probe checking whether `peer`'s current signed
    /// manifest has rotated at least two generations past `target_generation` (evicting both
    /// `signed_prekey` and `prev_signed_prekey` on the relay), returning the verified manifest
    /// metadata (`R20-P1-7`) so callers pin PQ upgrades / detect rollbacks before any subsequent
    /// reclaim or `ClaimBundle`.
    pub(super) async fn probe_confirmed_greeting_spk_rotated(
        &self,
        server: &str,
        audience: &str,
        peer: &PublicKey,
        greeting_spk: &[u8],
        target_generation: u64,
        clock: &session::ServerClock,
    ) -> Option<SpkRotationProbe> {
        if target_generation == 0 {
            return None;
        }
        let resp = Fetch::client(server)
            .get_manifest(GetManifestRequest {
                identity_key: bytes::Bytes::copy_from_slice(peer),
            })
            .await
            .ok()?;
        let manifest = resp.manifest?;
        let verified_id =
            session::protocol::handshake_v2::verify_manifest(&manifest, audience).ok()?;
        if verified_id != *peer {
            return None;
        }
        let manifest_digest = session::protocol::handshake_v2::manifest_digest(&manifest).ok()?;
        let (local_now, server_now) = clock.trusted_clock_pair().ok()?;
        session::protocol::handshake_v2::check_manifest_window_bounded(
            &manifest, local_now, server_now,
        )
        .ok()?;
        Some(SpkRotationProbe {
            rotated: manifest.signed_prekey.as_ref() != greeting_spk
                && manifest.generation >= target_generation.saturating_add(2),
            manifest_seq: manifest.manifest_seq,
            manifest_digest,
            pq_enabled: manifest.pq_enabled,
        })
    }

    /// Commit a verified [`SpkRotationProbe`] manifest monotonically onto `peer`'s `PeerPqState`
    /// under `Engine::inner` (`R20-P1-7`), persisting immediately so a newer signed PQ-ON manifest
    /// (or detected rollback/equivocation) is never lost before a `StaleVersion` reclaim.
    /// Returns `false` if the vault generation tore down during `save_state()`.
    pub(super) async fn apply_verified_probe_manifest(
        &self,
        vgen: u64,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        conversation_gen: u64,
        probe: &SpkRotationProbe,
    ) -> bool {
        let Some(contact) = inner
            .contacts
            .iter_mut()
            .find(|c| c.peer == *peer && c.state.conversation_gen == conversation_gen)
        else {
            return self.is_live(vgen);
        };
        let before_pq = contact.session.peer_pq_state().clone();
        let before_alert = contact.state.security_alert;
        let before_prompt = contact.state.classical_approval_needed;
        let before_q_pinned = contact.state.quarantined_was_pq_pinned;
        if probe.pq_enabled {
            // R21-P2-5: An approved `ServerPqDisabled` classical fallback deliberately leaves a
            // PQ-capable peer unpinned with `allow_classical_exception = true` (`pq.rs:1134`).
            // Probing the peer's signed PQ-ON manifest must still pin `(seq, digest)` monotonically
            // against rollback/equivocation without revoking that approved server-disabled
            // fallback.
            let was_server_pq_disabled_fallback = !before_pq.pq_pinned
                && before_pq.peer_pq_capable
                && before_pq.allow_classical_exception
                && contact.is_classical_session();
            let ppq = contact.session.peer_pq_state_mut();
            if ppq
                .check_and_pin_manifest(probe.manifest_seq, probe.manifest_digest)
                .is_ok()
            {
                ppq.peer_pq_capable = true;
                if !was_server_pq_disabled_fallback {
                    ppq.pq_pinned = true;
                    ppq.clear_classical_exception();
                    contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                    // R24-P3-1: Mirror `apply_observed_start_chat_manifests` (`R23-P2-5`): if the
                    // contact became quarantined while `GetManifest` was in flight, escalate the
                    // quarantined classical contact to a downgrade alert.
                    if contact.state.quarantined {
                        contact.state.quarantined_was_pq_pinned = true;
                        contact.record_policy_error(ErrorKind::DowngradeDetected);
                    }
                }
            } else {
                contact.record_policy_error(ErrorKind::DowngradeDetected);
            }
        } else if !contact.state.quarantined
            && !contact.session.peer_pq_state().downgrade_detected
            && contact.state.security_alert != SECURITY_ALERT_DOWNGRADE
        {
            // R21-P2-2: Never clear `peer_pq_capable` via signed PQ-OFF while quarantined or under
            // an active downgrade alarm (matching `settings.rs` and `outbox.rs`).
            if contact
                .session
                .peer_pq_state_mut()
                .commit_signed_pq_off_manifest(probe.manifest_seq, probe.manifest_digest)
                .is_err()
            {
                contact.record_policy_error(ErrorKind::DowngradeDetected);
            }
        } else {
            // R22-P2-6: Pin strictly newer verified signed PQ-OFF manifests monotonically directly
            // onto `contact` (while keeping `peer_pq_capable` and `downgrade_detected` intact) so
            // subsequent probes or upgrades never accept a rollback below `probe.manifest_seq`.
            if contact
                .session
                .peer_pq_state_mut()
                .check_and_pin_manifest(probe.manifest_seq, probe.manifest_digest)
                .is_err()
            {
                contact.record_policy_error(ErrorKind::DowngradeDetected);
            }
        }
        let changed = *contact.session.peer_pq_state() != before_pq
            || contact.state.security_alert != before_alert
            || contact.state.classical_approval_needed != before_prompt
            || contact.state.quarantined_was_pq_pinned != before_q_pinned;
        if changed {
            if inner.save_state().await.is_err() {
                inner.unsaved_state = true;
            }
            if !self.is_live(vgen) {
                return false;
            }
            self.refresh_contacts(inner);
        }
        self.is_live(vgen)
    }

    /// Lock-free retry of unconfirmed initial greetings (`SendInitialV2`) for outbound chats whose
    /// initial request failed before reaching the server (even when their outbox is empty), plus
    /// backoff-throttled post-2-rotation SPK-eviction probes for empty-outbox `CONFIRMED` greetings
    /// that have not yet been verified delivered or answered.
    pub(super) async fn retry_pending_greetings(&self) -> Result<bool, String> {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Ok(false);
        }
        let now_ms = now();
        let candidates: Vec<PublicKey> = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(false);
            }
            let Some(inner) = guard.as_ref() else {
                return Ok(false);
            };
            inner
                .contacts
                .iter()
                .filter(|c| {
                    !c.state.provisional
                        && !c.state.request
                        && !c.state.quarantined
                        && !c.session.is_known_by_peer()
                        && !c.session.has_pending_active_grant()
                        && ((c.state.greeting_delivery != GREETING_DELIVERY_CONFIRMED
                            && ((!c.session.needs_new_session()
                                && (c.state.greeting_delivery == GREETING_DELIVERY_UNSENT
                                    || uncertain_greeting_reclaim_eligible(&c.state, now_ms))
                                && c.session.pending_initial_request().is_some())
                                || (c.session.needs_new_session()
                                    && c.state.classical_approval_needed
                                        == CLASSICAL_APPROVAL_NONE
                                    && c.state.security_alert == SECURITY_ALERT_NONE)))
                            || (c.state.greeting_delivery == GREETING_DELIVERY_CONFIRMED
                                && c.state.outbox.is_empty()
                                && !c.session.needs_new_session()
                                && confirmed_greeting_probe_eligible(&c.state, now_ms)
                                && c.session.pending_initial_request().is_some()))
                })
                .map(|c| c.peer)
                .collect()
        };
        let mut retried_any = false;
        let mut first_err: Option<String> = None;
        for peer in candidates {
            if !self.is_live(vgen) {
                return Ok(false);
            }
            if self.queue.waits_for_sign_in(&peer) {
                continue;
            }
            let peer_lock = self.queue.peer_flush_lock(&peer);
            let _peer_guard = peer_lock.lock().await;
            if !self.is_live(vgen) {
                return Ok(false);
            }
            if self.queue.waits_for_sign_in(&peer) {
                continue;
            }
            enum GreetingRetryAction {
                Skip,
                ReclaimRetired,
                Send {
                    server: String,
                    signs_in_here: bool,
                    conversation_gen: u64,
                    session_id: Option<[u8; 32]>,
                    req: Box<session::protocol::handshake_v2::SendInitialV2Request>,
                    promoted_from_unsent: bool,
                    was_confirmed_probe: bool,
                    target_generation: u64,
                    audience: String,
                    clock: session::ServerClock,
                },
            }
            let action = {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok(false);
                }
                let Some(inner) = guard.as_mut() else {
                    return Ok(false);
                };
                let Some(contact) = inner.contacts.iter().find(|c| c.peer == peer) else {
                    continue;
                };
                if contact.state.provisional
                    || contact.state.request
                    || contact.state.quarantined
                    || contact.session.is_known_by_peer()
                    || contact.session.has_pending_active_grant()
                {
                    GreetingRetryAction::Skip
                } else if contact.state.greeting_delivery == GREETING_DELIVERY_CONFIRMED {
                    if contact.state.outbox.is_empty()
                        && !contact.session.needs_new_session()
                        && confirmed_greeting_probe_eligible(&contact.state, now())
                        && !self.queue.is_confirmed_probe_backed_off(&peer)
                        && let Some(req) = contact.session.pending_initial_request()
                        && (req.message.as_ref().is_some_and(|m| m.version >= 2)
                            || !super::classical_policy_blocked(
                                inner.client.pq_config().strict_pq,
                                inner.local_pq_enabled(),
                                contact.session.peer_pq_state(),
                            ))
                    {
                        GreetingRetryAction::Send {
                            server: inner.server.clone(),
                            signs_in_here: same_server(&inner.server, &origin()),
                            conversation_gen: contact.state.conversation_gen,
                            session_id: contact.session.active_id().copied(),
                            req: Box::new(req),
                            promoted_from_unsent: false,
                            was_confirmed_probe: true,
                            target_generation: contact.state.greeting_target_generation,
                            audience: inner.audience.clone(),
                            clock: inner.client.clock().clone(),
                        }
                    } else {
                        GreetingRetryAction::Skip
                    }
                } else if self.queue.is_approval_backed_off(&peer) {
                    GreetingRetryAction::Skip
                } else if contact.session.needs_new_session() {
                    if contact.state.classical_approval_needed == CLASSICAL_APPROVAL_NONE
                        && contact.state.security_alert == SECURITY_ALERT_NONE
                    {
                        GreetingRetryAction::ReclaimRetired
                    } else {
                        GreetingRetryAction::Skip
                    }
                } else if let Some(req) = contact.session.pending_initial_request() {
                    let conversation_gen = contact.state.conversation_gen;
                    let session_id = contact.session.active_id().copied();
                    let promoted_from_unsent =
                        contact.state.greeting_delivery == GREETING_DELIVERY_UNSENT;
                    let req_is_pq = req.message.as_ref().is_some_and(|m| m.version >= 2);
                    let strict_pq = inner.client.pq_config().strict_pq;
                    let local_pq = inner.local_pq_enabled();
                    let blocked_by_pq_policy = !req_is_pq
                        && super::classical_policy_blocked(
                            strict_pq,
                            local_pq,
                            contact.session.peer_pq_state(),
                        );
                    if blocked_by_pq_policy {
                        // R13-P1-2: Never first transmit or retry a classical greeting once
                        // `strict_pq` (or local PQ without a classical exception) is enabled.
                        if strict_pq && contact.state.security_alert != SECURITY_ALERT_PQ_REQUIRED {
                            if let Some(c) = inner.contact(&peer) {
                                c.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                            }
                            if inner.save_state().await.is_err() {
                                inner.unsaved_state = true;
                            }
                            if !self.is_live(vgen) {
                                return Ok(false);
                            }
                            self.refresh_contacts(inner);
                        }
                        GreetingRetryAction::Skip
                    } else if !promoted_from_unsent
                        && !uncertain_greeting_reclaim_eligible(&contact.state, now())
                    {
                        GreetingRetryAction::Skip
                    } else {
                        if promoted_from_unsent {
                            if let Err(e) = inner
                                .with_contact_tx(&peer, async |inner| {
                                    if let Some(c) = inner.contact(&peer) {
                                        c.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
                                        if c.state.greeting_sent_at == 0 {
                                            c.state.greeting_sent_at = now();
                                        }
                                    }
                                    inner.save(&[]).await.map_err(|e| describe(&e))
                                })
                                .await
                            {
                                first_err.get_or_insert(e);
                                continue;
                            }
                            if !self.is_live(vgen) {
                                return Ok(false);
                            }
                        }
                        GreetingRetryAction::Send {
                            server: inner.server.clone(),
                            signs_in_here: same_server(&inner.server, &origin()),
                            conversation_gen,
                            session_id,
                            req: Box::new(req),
                            promoted_from_unsent,
                            was_confirmed_probe: false,
                            target_generation: 0,
                            audience: inner.audience.clone(),
                            clock: inner.client.clock().clone(),
                        }
                    }
                } else {
                    GreetingRetryAction::Skip
                }
            };
            let (
                server,
                signs_in_here,
                conversation_gen,
                session_id,
                req,
                promoted_from_unsent,
                was_confirmed_probe,
                target_generation,
                audience,
                clock,
            ) = match action {
                GreetingRetryAction::Skip => continue,
                GreetingRetryAction::ReclaimRetired => {
                    let mut server_deletes = Vec::new();
                    match self
                        .ensure_session_for_outbox(vgen, &peer, &mut server_deletes, true)
                        .await
                    {
                        Ok(RekeyOutcome::Aborted) => return Ok(false),
                        Ok(RekeyOutcome::Ready) => {
                            self.clear_approval_backoff(&peer);
                            retried_any = true;
                        }
                        Ok(RekeyOutcome::Failed) => {
                            self.queue.record_approval_backoff(&peer);
                        }
                        Ok(RekeyOutcome::UpdateRequired(reason)) => {
                            self.require_update(reason.clone());
                            first_err.get_or_insert(reason);
                        }
                        Ok(RekeyOutcome::Paused | RekeyOutcome::ContactGone) => {}
                        Err(e) => {
                            self.queue.record_approval_backoff(&peer);
                            first_err.get_or_insert(e);
                        }
                    }
                    if !server_deletes.is_empty() && self.is_live(vgen) {
                        self.finish_server_deletes(&peer, server_deletes).await;
                    }
                    continue;
                }
                GreetingRetryAction::Send {
                    server,
                    signs_in_here,
                    conversation_gen,
                    session_id,
                    req,
                    promoted_from_unsent,
                    was_confirmed_probe,
                    target_generation,
                    audience,
                    clock,
                } => (
                    server,
                    signs_in_here,
                    conversation_gen,
                    session_id,
                    *req,
                    promoted_from_unsent,
                    was_confirmed_probe,
                    target_generation,
                    audience,
                    clock,
                ),
            };
            if was_confirmed_probe {
                let greeting_spk = req
                    .message
                    .as_ref()
                    .map(|m| m.signed_prekey.as_ref())
                    .unwrap_or(&[]);
                let probe = self
                    .probe_confirmed_greeting_spk_rotated(
                        &server,
                        &audience,
                        &peer,
                        greeting_spk,
                        target_generation,
                        &clock,
                    )
                    .await;
                if !self.is_live(vgen) {
                    return Ok(false);
                }
                // R20-P1-7: Commit any verified manifest learned from the SPK-rotation probe
                // BEFORE deciding whether to send `SendInitialV2` or reclaim on `StaleVersion`.
                let still_eligible = {
                    let mut guard = self.lock_inner().await;
                    if !self.is_live(vgen) {
                        return Ok(false);
                    }
                    if let Some(ref probe) = probe
                        && let Some(inner) = guard.as_mut()
                        && !self
                            .apply_verified_probe_manifest(
                                vgen,
                                inner,
                                &peer,
                                conversation_gen,
                                probe,
                            )
                            .await
                    {
                        return Ok(false);
                    }
                    if !probe.is_some_and(|p| p.rotated) {
                        false
                    } else {
                        let outgoing_is_pq_check =
                            req.message.as_ref().is_some_and(|m| m.version >= 2);
                        guard.as_ref().is_some_and(|inner| {
                            let strict_pq = inner.client.pq_config().strict_pq;
                            let local_pq = inner.local_pq_enabled();
                            inner
                                .contacts
                                .iter()
                                .find(|c| c.peer == peer)
                                .is_some_and(|c| {
                                    !c.state.provisional
                                        && !c.state.request
                                        && !c.state.quarantined
                                        && c.state.conversation_gen == conversation_gen
                                        && !c.session.needs_new_session()
                                        && c.session.active_id() == session_id.as_ref()
                                        && !c.session.is_known_by_peer()
                                        && !c.session.has_pending_active_grant()
                                        && (outgoing_is_pq_check
                                            || !super::classical_policy_blocked(
                                                strict_pq,
                                                local_pq,
                                                c.session.peer_pq_state(),
                                            ))
                                        && confirmed_greeting_probe_eligible(&c.state, now())
                                })
                        })
                    }
                };
                if !still_eligible {
                    self.queue.record_confirmed_probe_backoff(&peer);
                    continue;
                }
            }
            let outgoing_is_pq = req.message.as_ref().is_some_and(|m| m.version >= 2);
            // R20-P2-9: Use `client_without_refused_hook` so a stale background greeting 403 for a
            // superseded or replaced chat never fires the global sign-in refusal hook.
            let send_res: session::Result<()> = Fetch::client_without_refused_hook(&server)
                .send_initial_v2(req)
                .await
                .map(|_| ())
                .map_err(session::Error::from);
            if !self.is_live(vgen) {
                return Ok(false);
            }
            let mut reclaim_retired = false;
            {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok(false);
                }
                let Some(inner) = guard.as_mut() else {
                    return Ok(false);
                };
                // Revalidate exact conversation generation, active session, AND that the peer has
                // still never demonstrated knowledge of this session so a late `StaleVersion`
                // after an inbound reply can never retire a now-working session.
                let matches_session =
                    inner
                        .contacts
                        .iter()
                        .find(|c| c.peer == peer)
                        .is_some_and(|c| {
                            c.state.conversation_gen == conversation_gen
                                && !c.session.needs_new_session()
                                && c.session.active_id() == session_id.as_ref()
                                && !c.session.is_known_by_peer()
                        });
                if signs_in_here
                    && (send_res.is_ok()
                        || send_res.as_ref().is_err_and(|e| {
                            e.is_server_refusal() && e.kind() != ErrorKind::SignInRequired
                        }))
                {
                    self.on_origin_auth_proven_locked(vgen, inner);
                }
                match send_res {
                    Ok(()) if matches_session => {
                        if was_confirmed_probe {
                            // Server confirmed our post-2-rotation probe (`Added { inserted: false }`
                            // via live row or `acked_initial_messages` tombstone): mark verified so
                            // we never re-probe this delivered/declined greeting again.
                            if let Some(c) = inner.contact(&peer)
                                && !c.state.greeting_delivery_verified
                            {
                                c.state.greeting_delivery_verified = true;
                                let _ = inner.save_state().await;
                                if !self.is_live(vgen) {
                                    return Ok(false);
                                }
                            }
                            self.queue.record_confirmed_probe_backoff(&peer);
                        } else {
                            self.clear_approval_backoff(&peer);
                            self.queue.record_confirmed_probe_backoff(&peer);
                            if inner
                                .contact(&peer)
                                .is_some_and(Contact::mark_greeting_confirmed)
                            {
                                let _ = inner.save_state().await;
                                if !self.is_live(vgen) {
                                    return Ok(false);
                                }
                            }
                            self.refresh_contacts(inner);
                            retried_any = true;
                        }
                    }
                    Ok(()) => {}
                    Err(e)
                        if e.is_server_refusal()
                            && e.kind() == ErrorKind::StaleVersion
                            && matches_session =>
                    {
                        let allow_reclaim = inner.contact(&peer).is_some_and(|c| {
                            promoted_from_unsent
                                || (was_confirmed_probe
                                    && confirmed_greeting_probe_eligible(&c.state, now()))
                                || (!was_confirmed_probe
                                    && uncertain_greeting_reclaim_eligible(&c.state, now()))
                        });
                        if allow_reclaim {
                            // Recipient retired the signed prekey generation targeted by this
                            // cached greeting while still inside the delivery-tombstone window:
                            // clear `dispatched` on sealed items belonging strictly to this
                            // unreceived session (`R8-P1-3`), retire locally, and immediately claim
                            // a fresh bundle while preserving queued messages.
                            match inner
                                .retire_unreceived_session_on_stale_version(
                                    &peer,
                                    session_id.as_ref().map(|id| id.as_slice()),
                                )
                                .await
                            {
                                Ok(true) => {
                                    if !self.is_live(vgen) {
                                        return Ok(false);
                                    }
                                    self.refresh_contacts(inner);
                                    reclaim_retired = true;
                                }
                                Ok(false) => {
                                    if !self.is_live(vgen) {
                                        return Ok(false);
                                    }
                                }
                                Err(err) => {
                                    if !self.is_live(vgen) {
                                        return Ok(false);
                                    }
                                    first_err.get_or_insert(err);
                                }
                            }
                        } else if was_confirmed_probe {
                            self.queue.record_confirmed_probe_backoff(&peer);
                        } else {
                            self.queue.record_approval_backoff(&peer);
                        }
                    }
                    Err(e) => {
                        if e.is_server_refusal()
                            && promoted_from_unsent
                            && !was_confirmed_probe
                            && matches_session
                        {
                            let reverted = inner.contact(&peer).is_some_and(|c| {
                                if c.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN {
                                    c.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                                    c.state.greeting_sent_at = 0;
                                    true
                                } else {
                                    false
                                }
                            });
                            if reverted {
                                let _ = inner.save_state().await;
                                if !self.is_live(vgen) {
                                    return Ok(false);
                                }
                            }
                        }
                        // R20-P2-9: Gate peer sign-in wait + dialog strictly on `matches_session`
                        // so a late 403 for a superseded/replaced greeting never blocks a healthy
                        // replacement chat.
                        if e.kind() == ErrorKind::SignInRequired && signs_in_here && matches_session
                        {
                            self.queue.mark_waits_sign_in(peer);
                            self.hold_outbox_head_for_sign_in(inner, &peer);
                            self.ask_sign_in_background();
                            self.refresh_contacts(inner);
                        } else if e.kind() == ErrorKind::SignInRequired && signs_in_here {
                            // Superseded/deleted session: do not block the replacement chat.
                        } else if was_confirmed_probe {
                            self.check_send_initial_protocol_error(inner, outgoing_is_pq, &e);
                            self.queue.record_confirmed_probe_backoff(&peer);
                            self.refresh_contacts(inner);
                        } else {
                            self.check_send_initial_protocol_error(inner, outgoing_is_pq, &e);
                            if e.is_server_refusal() {
                                self.queue.record_approval_backoff(&peer);
                            }
                            self.refresh_contacts(inner);
                            first_err.get_or_insert(describe(&e));
                        }
                    }
                }
            }
            if reclaim_retired {
                let mut server_deletes = Vec::new();
                match self
                    .ensure_session_for_outbox(vgen, &peer, &mut server_deletes, true)
                    .await
                {
                    Ok(RekeyOutcome::Aborted) => return Ok(false),
                    Ok(RekeyOutcome::Ready) => {
                        self.clear_approval_backoff(&peer);
                        self.queue.record_confirmed_probe_backoff(&peer);
                        retried_any = true;
                    }
                    Ok(RekeyOutcome::Failed) => {
                        self.queue.record_approval_backoff(&peer);
                    }
                    Ok(RekeyOutcome::UpdateRequired(reason)) => {
                        self.require_update(reason.clone());
                        first_err.get_or_insert(reason);
                    }
                    Ok(RekeyOutcome::Paused | RekeyOutcome::ContactGone) => {}
                    Err(e) => {
                        self.queue.record_approval_backoff(&peer);
                        first_err.get_or_insert(e);
                    }
                }
                if !server_deletes.is_empty() && self.is_live(vgen) {
                    self.finish_server_deletes(&peer, server_deletes).await;
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(retried_any),
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
        let mut upgrades: BTreeMap<PublicKey, u64> = BTreeMap::new();
        let mut peers_needing_replay: BTreeSet<PublicKey> = BTreeSet::new();

        let _mailbox_guard = self.mailbox_lock.lock().await;
        if !self.is_live(vgen) {
            return Ok(Vec::new());
        }

        for _ in 0..MAX_MAILBOX_PAGES {
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            // Phase 1 under `self.inner`: sign `FetchSignedRequest` and release `self.inner`
            // across the network RTT so UI actions and other peers never stall.
            let (server, fetch_req, req_limit, piggybacked_ack, expected_cursor) = {
                let guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok(Vec::new());
                }
                let Some(inner) = guard.as_ref() else {
                    break;
                };
                match inner.client.sign_fetch_mailbox_v2(&inner.audience, 100) {
                    Ok(req) => (
                        inner.server.clone(),
                        req.clone(),
                        req.limit,
                        req.ack_up_to_sequence,
                        inner.client.mailbox_cursor(),
                    ),
                    Err(e) => {
                        if e.kind() == ErrorKind::ClockSkew {
                            self.warn_clock_skew(inner.client.clock().offset_ms());
                        }
                        self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                        return Err(describe(&e));
                    }
                }
            };

            let raw_page: session::Result<_> = Fetch::client(&server)
                .fetch_signed(fetch_req)
                .await
                .map_err(session::Error::from);
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            let response = match raw_page {
                Ok(resp) => resp,
                Err(e) => {
                    self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                    return Err(describe(&e));
                }
            };

            // Phase 2 under `self.inner`: validate cursor, decrypt/defer envelopes, and commit
            // atomically before releasing `self.inner` again for any explicit final ACK.
            let mut explicit_ack: Option<(
                String,
                u64,
                session::protocol::mailbox_v2::AckMessagesRequest,
            )> = None;
            let mut should_break = false;
            {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok(Vec::new());
                }
                let Some(inner) = guard.as_mut() else {
                    break;
                };
                if inner.client.mailbox_cursor() != expected_cursor {
                    continue;
                }
                let page =
                    match inner
                        .client
                        .validate_mailbox_page(req_limit, piggybacked_ack, response)
                    {
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

                let local_pq = inner.local_pq_enabled();
                let me = inner.client.identity_key();
                let mut token_map: HashMap<[u8; 32], PublicKey> = HashMap::new();
                for contact in &inner.contacts {
                    for th in contact.session.inbound_token_hashes() {
                        token_map.insert(th, contact.peer);
                    }
                }
                let mut isolated_token_map: HashMap<[u8; 32], PublicKey> = HashMap::new();
                for iso in &inner.isolated_contacts {
                    if let Some((iso_peer, hashes)) =
                        pq_incompatible_isolated_token_hashes(iso, &me)
                    {
                        for th in hashes {
                            isolated_token_map.entry(th).or_insert(iso_peer);
                        }
                    }
                }

                let last_seq = page.last_sequence().unwrap_or(0);
                let has_more = page.has_more;
                let piggybacked_ack = page.piggybacked_ack;

                // Snapshots for atomic rollback if any step or vault commit fails.
                let client_snapshot = proto::ClientState::from(inner.client.state());
                let saved_envelopes = inner.deferred_envelopes.clone();
                let saved_carried_ts = inner.carried_deferred_timestamps.clone();
                let saved_isolated_contacts = inner.isolated_contacts.clone();
                let mut contact_snapshots: HashMap<PublicKey, (proto::SessionState, ContactState)> =
                    HashMap::new();

                let mut per_peer_entries: BTreeMap<PublicKey, Vec<(u64, HistoryEntry)>> =
                    BTreeMap::new();
                let mut per_peer_steps: BTreeMap<PublicKey, Vec<(u64, crate::state::Step)>> =
                    BTreeMap::new();
                let mut per_peer_settled: BTreeMap<PublicKey, Vec<(u64, u64)>> = BTreeMap::new();
                let mut peers_with_staged_carried: BTreeSet<PublicKey> = BTreeSet::new();
                let mut peer_deleted: BTreeSet<PublicKey> = BTreeSet::new();
                let mut peer_evicted_counts: HashMap<PublicKey, usize> = HashMap::new();
                let mut isolated_evicted_counts: HashMap<PublicKey, usize> = HashMap::new();
                let now_ms = now();

                let mut process_err: Option<String> = None;
                for env in page.messages {
                    let Ok(token_hash) = <[u8; 32]>::try_from(env.token_hash.as_ref()) else {
                        continue;
                    };
                    let Some(&peer) = token_map.get(&token_hash) else {
                        if let Some(&iso_peer) = isolated_token_map.get(&token_hash) {
                            let initial_message = env.initial_message.filter(|wire| {
                                Incoming::try_from(wire)
                                    .is_ok_and(|inc| inner.can_pin_deferred_digest(&inc, now_ms))
                            });
                            let buffered = push_deferred_envelope(
                                &mut inner.deferred_envelopes,
                                &iso_peer,
                                env.sequence,
                                env.message,
                                initial_message,
                                now_ms,
                                true,
                            );
                            if !buffered {
                                // Dedicated isolated spool overflowed: record durable eviction
                                // on the isolated contact and continue so healthy contacts in
                                // this mailbox page still commit and advance.
                                if let Some(iso) = inner
                                    .isolated_contacts
                                    .iter_mut()
                                    .find(|c| c.peer.as_slice() == iso_peer.as_slice())
                                {
                                    iso.evicted_while_isolated =
                                        iso.evicted_while_isolated.saturating_add(1);
                                }
                                *isolated_evicted_counts.entry(iso_peer).or_insert(0) += 1;
                            }
                        }
                        // Unknown/revoked token hash: drop silently.
                        continue;
                    };
                    let Some(contact_idx) = inner.contacts.iter().position(|c| c.peer == peer)
                    else {
                        continue;
                    };
                    contact_snapshots
                        .entry(peer)
                        .or_insert_with(|| inner.contacts[contact_idx].snapshot());

                    let peer_has_buffered = inner
                        .deferred_envelopes
                        .iter()
                        .any(|e| e.peer.as_slice() == peer.as_slice());
                    let peer_awaiting_user_or_upgrade =
                        inner.contacts[contact_idx].state.quarantined
                            || inner.contacts[contact_idx].is_new_quarantined()
                            || inner.contacts[contact_idx].deferred_carried > 0
                            || inner.has_deferred_initial_for(&peer);
                    let peer_blocked = peer_has_buffered || peer_awaiting_user_or_upgrade;

                    if peer_blocked {
                        // R9-P1-3: Only gate unsupported-suite carried initials by
                        // `can_pin_deferred_digest`; NEVER strip a supported-suite carried
                        // initial from a healthy peer's buffered envelope before ACKing.
                        let initial_message = env.initial_message.filter(|wire| {
                            Incoming::try_from(wire).is_ok_and(|inc| {
                                !inc.pq_suite().is_some_and(|suite| !suite.is_supported())
                                    || inner.can_pin_deferred_digest(&inc, now_ms)
                            })
                        });
                        let buffered = push_deferred_envelope(
                            &mut inner.deferred_envelopes,
                            &peer,
                            env.sequence,
                            env.message,
                            initial_message,
                            now_ms,
                            false,
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

                    // Active peer: stage any carried initial message (bounded per peer without
                    // failing unrelated peers on the unified mailbox page) and attempt immediate
                    // decrypt. If staging hits the 128-entry cap, keep `initial_message` attached
                    // to the `DeferredEnvelope` when buffering so Phase B suppresses destructive
                    // drops until staged entries drain.
                    let mut staged_carried_init = false;
                    if let Some(ref wire_init) = env.initial_message
                        && let Ok(inc) = Incoming::try_from(wire_init)
                    {
                        let allow_stage =
                            !inc.pq_suite().is_some_and(|suite| !suite.is_supported())
                                || inner.can_pin_deferred_digest(&inc, now_ms);
                        if allow_stage {
                            match stage_carried_initial_one(
                                &mut inner.contacts[contact_idx].state,
                                &inc,
                            ) {
                                Ok(true) => {
                                    peers_with_staged_carried.insert(peer);
                                    peers_needing_replay.insert(peer);
                                    staged_carried_init = true;
                                }
                                Ok(false) => {
                                    peers_needing_replay.insert(peer);
                                }
                                Err(reason) => {
                                    process_err = Some(reason);
                                    break;
                                }
                            }
                        }
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
                                contact.state.awaiting_peer_acceptance = false;
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
                                        upgrades.insert(peer, contact.state.conversation_gen);
                                    }
                                }
                            }
                            if matches!(content.kind, Some(Kind::Deleted(_))) && !decrypted.earlier
                            {
                                contact.session.retire();
                                peer_deleted.insert(peer);
                            }
                            let server_now = inner.client.clock().now();
                            match inner.contacts[contact_idx]
                                .add_received_at(content, false, server_now)
                            {
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
                                env.initial_message.filter(|wire| {
                                    Incoming::try_from(wire).is_ok_and(|inc| {
                                        !inc.pq_suite().is_some_and(|suite| !suite.is_supported())
                                            || inner.can_pin_deferred_digest(&inc, now_ms)
                                    })
                                })
                            };
                            let buffered = push_deferred_envelope(
                                &mut inner.deferred_envelopes,
                                &peer,
                                env.sequence,
                                env.message,
                                deferred_init,
                                now_ms,
                                false,
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
                        Some(saved_isolated_contacts),
                    )?;
                    return Err(err);
                }

                // Stage carried initials, apply delivery steps & requeues across all affected peers.
                let mut all_records: Vec<(PublicKey, u64, HistoryEntry)> = Vec::new();
                let mut all_outbox_updates: Vec<(PublicKey, u64, Option<OutgoingRecord>)> =
                    Vec::new();
                let mut per_peer_changed: BTreeMap<PublicKey, Vec<(u64, HistoryEntry)>> =
                    BTreeMap::new();
                let mut requeued_outcomes: Vec<(PublicKey, RequeueOutcome)> = Vec::new();
                let mut corrupt_receipt_indices: Vec<(PublicKey, Vec<u64>)> = Vec::new();

                let touched_peers: BTreeSet<PublicKey> =
                    contact_snapshots.keys().copied().collect();
                for peer in &touched_peers {
                    if peers_with_staged_carried.contains(peer)
                        && let Some(contact) = inner.contact(peer)
                    {
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
                    if !steps.is_empty() {
                        match inner.step(peer, &mut changed, steps).await {
                            Ok(skipped) if !skipped.is_empty() => {
                                corrupt_receipt_indices.push((*peer, skipped));
                            }
                            Ok(_) => {}
                            Err(e) => {
                                rollback_mailbox_page(
                                    inner,
                                    client_snapshot,
                                    contact_snapshots,
                                    saved_envelopes,
                                    saved_carried_ts,
                                    Some(saved_isolated_contacts),
                                )?;
                                return Err(describe(&e));
                            }
                        }
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
                        let pending_gone_ids = inner
                            .contact(peer)
                            .map(|c| {
                                self.uploads
                                    .pending_gone_ids_for_peer(peer, c.state.conversation_gen)
                            })
                            .unwrap_or_default();
                        match inner
                            .requeue_excluding_gone(peer, deleted, &changed, &pending_gone_ids)
                            .await
                        {
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
                                    Some(saved_isolated_contacts),
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
                        Some(saved_isolated_contacts),
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
                        Some(saved_isolated_contacts),
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
                if !isolated_evicted_counts.is_empty() {
                    for (peer, evicted_count) in isolated_evicted_counts {
                        self.ui.log(format!(
                            "{evicted_count} message(s) from unsupported contact {} exceeded the isolated offline buffer",
                            short(&peer)
                        ));
                    }
                    self.ui.isolated_contacts.set(inner.isolated_views());
                }
                for (peer, outcome) in requeued_outcomes {
                    outcome.log_missing(&self.ui, &peer);
                    self.finalize_requeue_gone(vgen, inner, &peer, &outcome)
                        .await;
                    if !self.is_live(vgen) {
                        return Ok(Vec::new());
                    }
                }
                for (peer, skipped) in corrupt_receipt_indices {
                    let label = inner
                        .contact(&peer)
                        .map_or_else(|| short(&peer), |c| c.view().label());
                    self.ui.log(format!(
                        "skipped delivery receipt(s) for {} corrupt history entry(ies) in {label}",
                        skipped.len()
                    ));
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
                        let server_now = inner.client.clock().now();
                        let views: Option<Vec<_>> = inner.contact(&open).map(|contact| {
                            entries
                                .into_iter()
                                .map(|(index, entry)| contact.message_at(index, entry, server_now))
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
                self.refresh_contacts(inner);

                // Sign explicit ACK under `self.inner` on the final page, then run the RPC after
                // dropping `guard`.
                if !has_more {
                    should_break = true;
                    let up_to = inner.client.pending_mailbox_ack();
                    if up_to > 0 {
                        match inner.client.sign_ack_mailbox_v2(&inner.audience, up_to) {
                            Ok(ack_req) => {
                                explicit_ack = Some((inner.server.clone(), up_to, ack_req));
                            }
                            Err(e) => {
                                self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                            }
                        }
                    }
                }
            }

            if let Some((ack_server, up_to, ack_req)) = explicit_ack {
                let ack_res: session::Result<_> = Fetch::client(&ack_server)
                    .ack_messages(ack_req)
                    .await
                    .map_err(session::Error::from);
                if !self.is_live(vgen) {
                    return Ok(Vec::new());
                }
                match ack_res {
                    Ok(_) => {
                        let mut guard = self.lock_inner().await;
                        if !self.is_live(vgen) {
                            return Ok(Vec::new());
                        }
                        if let Some(inner) = guard.as_mut() {
                            inner.client.clear_pending_mailbox_ack(up_to);
                            let _ = inner.save_state().await;
                        }
                    }
                    Err(e) => {
                        self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                    }
                }
            }
            if should_break {
                break;
            }
        }
        // Sample the committed mailbox cursor before releasing `_mailbox_guard` so the post-inbox
        // replay pass below only drops undecryptable envelopes up to this watermark (preserving any
        // newer envelopes concurrently fetched/ACKed after `ListInitialMessages` ran).
        let pre_inbox_cursor = if !peers_needing_replay.is_empty() && self.is_live(vgen) {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            guard
                .as_ref()
                .map_or(0, |inner| inner.client.mailbox_cursor())
        } else {
            0
        };
        // Release `mailbox_lock` immediately after finishing `FetchSigned`/`AckMessages` pagination
        // so incoming WebSocket mailbox notifications for other peers never stall behind inbox
        // listing, grant flushes, or multi-RPC PQ upgrades.
        drop(_mailbox_guard);

        // If any carried initials or buffered envelopes arrived, pull inbox initials, join carried
        // initials, and locally replay buffered envelopes with zero server re-fetch.
        let mut grant_peers: BTreeSet<PublicKey> = BTreeSet::new();
        if !peers_needing_replay.is_empty() {
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            let inbox_drained_all = match self.take_initial_messages_with_replayed().await {
                Ok((_, replayed_during_inbox, drained_all)) => {
                    affected_peers.extend(replayed_during_inbox);
                    drained_all
                }
                Err(_) => false,
            };
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
                    if let Ok(join) = self.join_carried(inner, peer).await {
                        if let Some(conv_gen) = join.recommend_upgrade {
                            upgrades.insert(*peer, conv_gen);
                        }
                        grant_peers.extend(join.grant_peers);
                    }
                }
                if !self.is_live(vgen) {
                    return Ok(Vec::new());
                }
                // Only discard undecryptable buffered envelopes when inbox listing drained
                // completely (`!has_more` and no `RetryLater` deferrals), strictly bounded to
                // `pre_inbox_cursor` and `peers_needing_replay` so concurrently buffered newer
                // envelopes or unrelated peers are never discarded prematurely.
                let drop_up_to = inbox_drained_all.then_some(pre_inbox_cursor);
                if let Ok((replayed, replay_upgrades, replay_grants)) = self
                    .replay_deferred_envelopes(inner, None, drop_up_to, Some(&peers_needing_replay))
                    .await
                {
                    affected_peers.extend(replayed);
                    upgrades.extend(replay_upgrades);
                    grant_peers.extend(replay_grants);
                }
            }
        }

        for peer in grant_peers {
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            let _ = self.flush_pending_grants_for_peer(&peer).await;
        }
        for (peer, conv_gen) in upgrades {
            if !self.is_live(vgen) {
                return Ok(Vec::new());
            }
            let _ = self.upgrade_to_pq_auto(peer, conv_gen).await;
        }
        Ok(affected_peers.into_iter().collect())
    }

    /// Locally replay buffered `DeferredEnvelope`s (optionally restricted to `only_peer`) for
    /// contacts that are no longer quarantined and have no pending unsupported-suite initials.
    /// Requires zero server re-fetch and commits all replayed messages atomically, returning
    /// `(replayed_peers, upgrades, grant_peers)` so callers flush grants and run upgrades outside
    /// `self.inner`.
    ///
    /// When `drop_undecryptable_up_to_seq` is `None` (e.g. `ListInitialMessages` failed
    /// transiently, hit `MAX_INBOX_PAGES`, or has not yet run), undecryptable envelopes are
    /// preserved in `inner.deferred_envelopes`. When `Some(max_seq)`, only undecryptable envelopes
    /// with `sequence <= max_seq` (and for a peer in `drop_only_peers` if provided, with no
    /// unstaged carried initials remaining) may be discarded.
    pub(super) async fn replay_deferred_envelopes(
        &self,
        inner: &mut Inner<V>,
        only_peer: Option<&PublicKey>,
        drop_undecryptable_up_to_seq: Option<u64>,
        drop_only_peers: Option<&BTreeSet<PublicKey>>,
    ) -> Result<
        (
            BTreeSet<PublicKey>,
            BTreeMap<PublicKey, u64>,
            BTreeSet<PublicKey>,
        ),
        String,
    > {
        if inner.deferred_envelopes.is_empty() {
            return Ok((BTreeSet::new(), BTreeMap::new(), BTreeSet::new()));
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
            return Ok((BTreeSet::new(), BTreeMap::new(), BTreeSet::new()));
        }

        // Phase A (pre-pass): while ALL `DeferredEnvelope`s remain intact in
        // `inner.deferred_envelopes`, extract and join any carried `initial_message` from eligible
        // peers' buffered envelopes (in ascending sequence order). This ensures:
        // 1. `join_carried`'s durable saves never wipe uncommitted `to_replay` envelopes.
        // 2. An out-of-order carried initial on envelope N+1 joins before decrypting envelope N.
        // 3. Any peer quarantined or deferred by `join_carried` is excluded on recomputation below
        //    so its buffered envelopes are preserved rather than dropped.
        let mut upgrades: BTreeMap<PublicKey, u64> = BTreeMap::new();
        let mut grant_peers: BTreeSet<PublicKey> = BTreeSet::new();
        let mut carried_indices: Vec<(u64, usize, PublicKey)> = inner
            .deferred_envelopes
            .iter()
            .enumerate()
            .filter_map(|(idx, env)| {
                env.initial_message.as_ref()?;
                if !env.pq_isolated
                    && env.deferred_at != 0
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
        let mut staging_capped_peers: BTreeSet<PublicKey> = BTreeSet::new();
        let phase_a_envelopes = inner.deferred_envelopes.clone();
        let phase_a_carried_ts = inner.carried_deferred_timestamps.clone();
        let mut phase_a_pending: HashMap<PublicKey, Vec<Vec<u8>>> = HashMap::new();
        let mut phase_a_dirty = false;
        for (_, idx, peer) in carried_indices {
            if staging_capped_peers.contains(&peer) {
                continue;
            }
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
                    match stage_carried_initial_one(&mut inner.contacts[contact_idx].state, &inc) {
                        Ok(true) => {
                            inner.deferred_envelopes[idx].initial_message = None;
                            peers_with_carried.insert(peer);
                            phase_a_dirty = true;
                        }
                        Ok(false) | Err(_) => {
                            // Pending carried-initial staging hit its 128-entry cap (supported or
                            // unsupported): stop staging more carried initials for this peer in
                            // this pass and retain this and later envelopes (and suppress
                            // destructive drops for earlier envelopes) until staged entries drain.
                            staging_capped_peers.insert(peer);
                        }
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
            if let Some(conv_gen) = outcome.recommend_upgrade {
                upgrades.insert(peer, conv_gen);
            }
            grant_peers.extend(outcome.grant_peers);
        }

        // Recompute eligibility after `join_carried`: exclude any peer that became quarantined or
        // deferred an unsupported suite so its buffered envelopes remain safely preserved.
        let eligible_peers = collect_eligible(inner);
        if eligible_peers.is_empty() {
            return Ok((BTreeSet::new(), upgrades, grant_peers));
        }

        // Phase B (pure in-memory decrypt + single atomic `inner.save_with`): snapshot the clean
        // post-Phase-A state so any vault error rolls back without clobbering committed joins.
        let client_snapshot = proto::ClientState::from(inner.client.state());
        let saved_envelopes = inner.deferred_envelopes.clone();
        let saved_carried_ts = inner.carried_deferred_timestamps.clone();
        let mut contact_snapshots: HashMap<PublicKey, (proto::SessionState, ContactState)> =
            HashMap::new();

        let is_expired_non_isolated = |env: &DeferredEnvelope| -> bool {
            !env.pq_isolated
                && env.deferred_at != 0
                && now_ms.saturating_sub(env.deferred_at) > DEFERRED_REPLAY_WINDOW_MS
        };
        // Any non-expired envelope that still carries an unstaged `initial_message` (e.g. Phase A
        // hit the 128-entry staging cap) MUST stay in `retained`, along with every subsequent
        // envelope for that peer, and suppresses destructive drops for ALL envelopes of that peer
        // (including earlier envelopes `N` that depend on an unstaged carried initial on `N+1`).
        // Expired non-isolated envelopes are excluded so Phase B cleanly discards them instead of
        // permanently blocking newer sequences.
        let mut blocked_from_seq: HashMap<PublicKey, u64> = HashMap::new();
        let mut peers_with_unstaged_carried: BTreeSet<PublicKey> = staging_capped_peers;
        for env in &inner.deferred_envelopes {
            if env.initial_message.is_some()
                && !is_expired_non_isolated(env)
                && let Ok(peer) = PublicKey::try_from(env.peer.as_slice())
            {
                peers_with_unstaged_carried.insert(peer);
                blocked_from_seq
                    .entry(peer)
                    .and_modify(|min_seq| *min_seq = (*min_seq).min(env.sequence))
                    .or_insert(env.sequence);
            }
        }

        // Partition out eligible envelopes in ascending sequence order.
        let mut to_replay: Vec<DeferredEnvelope> = Vec::new();
        let mut retained: Vec<DeferredEnvelope> = Vec::new();
        for env in std::mem::take(&mut inner.deferred_envelopes) {
            let parsed_peer = PublicKey::try_from(env.peer.as_slice()).ok();
            let expired = is_expired_non_isolated(&env);
            let blocked_by_unstaged = !expired
                && parsed_peer.is_some_and(|p| {
                    env.initial_message.is_some()
                        || blocked_from_seq
                            .get(&p)
                            .is_some_and(|&min_seq| env.sequence >= min_seq)
                });
            let is_eligible =
                !blocked_by_unstaged && parsed_peer.is_some_and(|p| eligible_peers.contains(&p));
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
            if !env.pq_isolated
                && env.deferred_at != 0
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
                        contact.state.awaiting_peer_acceptance = false;
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
                                upgrades.insert(peer, contact.state.conversation_gen);
                            }
                        }
                    }
                    if matches!(content.kind, Some(Kind::Deleted(_))) && !decrypted.earlier {
                        contact.session.retire();
                        peer_deleted.insert(peer);
                    }
                    let server_now = inner.client.clock().now();
                    if let Ok(entry) =
                        inner.contacts[contact_idx].add_received_at(content, false, server_now)
                    {
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
                    let allow_drop = drop_undecryptable_up_to_seq
                        .is_some_and(|max_seq| env.sequence <= max_seq)
                        && drop_only_peers.is_none_or(|allowed| allowed.contains(&peer))
                        && !peers_with_unstaged_carried.contains(&peer);
                    if allow_drop {
                        // Peer is active, unquarantined, has no unstaged carried or unsupported
                        // initials, and this envelope preceded a complete inbox drain; drop
                        // permanently undecryptable envelope so future messages aren't blocked.
                        *skipped_counts.entry(peer).or_insert(0) += 1;
                    } else {
                        // Inbox listing was incomplete/concurrently raced or an unstaged carried
                        // initial is still pending: preserve this acknowledged envelope.
                        inner.deferred_envelopes.push(env);
                    }
                }
            }
        }

        let mut all_records: Vec<(PublicKey, u64, HistoryEntry)> = Vec::new();
        let mut all_outbox_updates: Vec<(PublicKey, u64, Option<OutgoingRecord>)> = Vec::new();
        let mut per_peer_changed: BTreeMap<PublicKey, Vec<(u64, HistoryEntry)>> = BTreeMap::new();
        let mut requeued_outcomes: Vec<(PublicKey, RequeueOutcome)> = Vec::new();
        let mut corrupt_receipt_indices: Vec<(PublicKey, Vec<u64>)> = Vec::new();

        for peer in &eligible_peers {
            let steps = per_peer_steps.remove(peer).unwrap_or_default();
            let settled = per_peer_settled.remove(peer).unwrap_or_default();
            let deleted = peer_deleted.contains(peer);
            let mut changed = BTreeMap::new();
            if !steps.is_empty() {
                match inner.step(peer, &mut changed, steps).await {
                    Ok(skipped) if !skipped.is_empty() => {
                        corrupt_receipt_indices.push((*peer, skipped));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        rollback_mailbox_page(
                            inner,
                            client_snapshot,
                            contact_snapshots,
                            saved_envelopes,
                            saved_carried_ts,
                            None,
                        )?;
                        return Err(describe(&e));
                    }
                }
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
                let pending_gone_ids = inner
                    .contact(peer)
                    .map(|c| {
                        self.uploads
                            .pending_gone_ids_for_peer(peer, c.state.conversation_gen)
                    })
                    .unwrap_or_default();
                match inner
                    .requeue_excluding_gone(peer, deleted, &changed, &pending_gone_ids)
                    .await
                {
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
                            None,
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
                None,
            )?;
            return Err(describe(&e));
        }
        if self.shutting_down.get() || crate::glue::lock_released() {
            return Ok((BTreeSet::new(), BTreeMap::new(), BTreeSet::new()));
        }

        for (peer, count) in skipped_counts {
            let label = inner
                .contact(&peer)
                .map_or_else(|| short(&peer), |c| c.view().label());
            self.ui.log(format!(
                "skipped {count} deferred message(s) from {label} that do not decrypt"
            ));
        }
        for (peer, skipped) in corrupt_receipt_indices {
            let label = inner
                .contact(&peer)
                .map_or_else(|| short(&peer), |c| c.view().label());
            self.ui.log(format!(
                "skipped delivery receipt(s) for {} corrupt history entry(ies) in {label}",
                skipped.len()
            ));
        }
        let vgen = self.vault_gen();
        for (peer, outcome) in requeued_outcomes {
            outcome.log_missing(&self.ui, &peer);
            self.finalize_requeue_gone(vgen, inner, &peer, &outcome)
                .await;
            if !self.is_live(vgen) {
                return Ok((BTreeSet::new(), BTreeMap::new(), BTreeSet::new()));
            }
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
                let server_now = inner.client.clock().now();
                let views: Option<Vec<_>> = inner.contact(&open).map(|contact| {
                    entries
                        .into_iter()
                        .map(|(index, entry)| contact.message_at(index, entry, server_now))
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
            self.refresh_contacts(inner);
        }
        Ok((replayed_peers, upgrades, grant_peers))
    }
}

fn rollback_mailbox_page<V: VaultStore>(
    inner: &mut Inner<V>,
    client_snapshot: proto::ClientState,
    contact_snapshots: HashMap<PublicKey, (proto::SessionState, ContactState)>,
    saved_envelopes: Vec<DeferredEnvelope>,
    saved_carried_ts: Vec<crate::vault::CarriedDeferredTimestamp>,
    saved_isolated_contacts: Option<Vec<ContactState>>,
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
    if let Some(saved_isolated) = saved_isolated_contacts {
        inner.isolated_contacts = saved_isolated;
    }
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
