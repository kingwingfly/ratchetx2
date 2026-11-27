//! Durable outgoing messages, delivery updates and session replacement recovery.

use super::attachments::ServerDeleteJob;
use super::contact::{Contact, forget_told, keep_last};
use super::{
    Engine, Inner, NOT_SIGNED_IN_HERE, ProtocolRpcScope, VaultStore, origin, records, same_server,
    should_require_update_for_rpc,
};
use crate::content::{Content, Events, Kind, stamp};
use crate::state::{Delivery, MessageView, Step, Ui};
use crate::transport::Fetch;
use crate::util::{describe, now, short};
use crate::vault::{
    Awaiting, CLASSICAL_APPROVAL_NONE, CLASSICAL_APPROVAL_SIGNED_OFF, ContactState,
    GREETING_DELIVERY_CONFIRMED, GREETING_DELIVERY_UNCERTAIN, GREETING_DELIVERY_UNSENT,
    HistoryEntry, Outgoing, OutgoingRecord, SECURITY_ALERT_DOWNGRADE,
    SECURITY_ALERT_MANIFEST_EXPIRED, SECURITY_ALERT_NONE, SECURITY_ALERT_PQ_REQUIRED, SealedEvents,
};
use bytes::Bytes;
use leptos::prelude::*;
use session::protocol::handshake_v2::{LocalHandshakeV2, SendInitialV2Request};
use session::protocol::mailbox_v2::{LocalMailboxV2, PushV2Request};
use session::{ErrorKind, PublicKey};
use std::collections::{BTreeMap, BTreeSet, btree_map};

/// Wire payload and metadata prepared under `self.inner` before releasing the mutex for `PushV2`.
struct PreparedPush {
    conversation_gen: u64,
    outgoing: Outgoing,
    session_id: Vec<u8>,
    push_req: PushV2Request,
    server: String,
    audience: String,
    retry_initial: Option<SendInitialV2Request>,
    promoted_from_unsent: bool,
}

/// Next action prepared under `self.inner` during [`Engine::flush`] before dropping the lock.
enum NextPush {
    Done,
    FlushPendingGrant,
    NeedsNewSession,
    Push(Box<PreparedPush>),
}

/// Outcome of committing one completed outbox item under `self.inner`.
enum CommitOutcome {
    Committed,
    Aborted,
}

/// Outcome of establishing a replacement session via lock-free `ClaimBundle` +
/// `RegisterWriteToken` + `SendInitialV2`.
pub(super) enum RekeyOutcome {
    /// Active session is now ready (either newly created or an inbound session arrived).
    Ready,
    /// Paused pending explicit user security decision (alert/approval already persisted).
    Paused,
    /// Permanently failed (`NotFound` / `InvalidKeys`): waiting outbox items marked failed.
    Failed,
    /// Contact was deleted or isolated concurrently while rekeying.
    ContactGone,
    /// Server rejected v2 protocol (`Unimplemented`); prompt user to refresh.
    UpdateRequired(String),
    /// `pagehide` / vault teardown fired while rekeying.
    Aborted,
}

/// Result of sealing one unsealed outbox item on an already-active session under `self.inner`.
pub(super) enum LocalSealOutcome {
    Ready,
    CorruptDropped(u64, Vec<(u64, HistoryEntry)>),
}

impl<V: VaultStore> Engine<V> {
    /// Push the messages waiting for `peer`, in order, each encrypted as its turn comes, then
    /// the events to tell the peer. Returns whether any went.
    ///
    /// Serialized per peer via `peer_flush_locks` while releasing `Engine::inner` across every
    /// network RPC (`ClaimBundle`, `RegisterWriteToken`, `SendInitialV2`, `PushV2`, `push_events`)
    /// so UI operations and independent peers' flushes never stall behind slow RTTs.
    pub(super) async fn flush(&self, peer: &PublicKey) -> Result<bool, String> {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Ok(false);
        }
        if self.queue.waits_for_sign_in(peer) || self.queue.is_approval_backed_off(peer) {
            return Ok(false);
        }
        // With messages waiting and no session to send on, the peer may have started one, e.g.
        // having deleted the chat and started it again: taken first, it is sent on, rather than
        // another started, which the peer might set aside. If taking fails, one starts.
        // Run this BEFORE acquiring `peer_flush_lock(peer)` because `take_initial_messages` can
        // invoke `upgrade_to_pq` (which acquires `peer_flush_lock`), preventing both self-deadlock
        // and cross-peer AB-BA deadlocks.
        let waits = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(false);
            }
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
        if !self.is_live(vgen) {
            return Ok(false);
        }
        // RAII `PeerFlushLock` guarantees `_peer_guard` drops first, then the `Rc<Mutex<()>>`, and
        // finally removes the `Weak` entry iff `strong_count() == 0`.
        let peer_lock = self.queue.peer_flush_lock(peer);
        let _peer_guard = peer_lock.lock().await;
        if !self.is_live(vgen) {
            return Ok(false);
        }
        if self.queue.waits_for_sign_in(peer) || self.queue.is_approval_backed_off(peer) {
            return Ok(false);
        }

        let mut changed = false;
        let mut result: Result<(), String> = Ok(());
        let mut server_deletes: Vec<ServerDeleteJob> = vec![];
        let mut signs_in_here = false;
        let mut tried_grant_flush = false;

        loop {
            if !self.is_live(vgen) {
                return Ok(false);
            }
            if self.queue.waits_for_sign_in(peer) || self.queue.is_approval_backed_off(peer) {
                break;
            }

            // Phase 1 under `self.inner`: recover unsaved state / requeue / seal locally and
            // extract the exact `PushV2Request` to transmit outside the mutex.
            let next_push = {
                let mut guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok(false);
                }
                let Some(inner) = guard.as_mut() else {
                    return Ok(false);
                };
                signs_in_here = same_server(&inner.server, &origin());
                // Flush any unsaved requeued outbox records before sealing reads from IndexedDB,
                // ensuring we never encrypt stale empty-content records after a prior save failure.
                if inner.unsaved_state || inner.unsaved_outbox.iter().any(|(p, _, _)| p == peer) {
                    if let Err(e) = inner.save(&[]).await {
                        result = Err(describe(&e));
                        break;
                    }
                    if !self.is_live(vgen) {
                        return Ok(false);
                    }
                }
                // Never send or send receipts on a brand-new quarantined classical contact.
                if inner
                    .contacts
                    .iter()
                    .any(|c| c.peer == *peer && c.is_new_quarantined())
                {
                    return Ok(false);
                }
                // If a previous `PushV2` already succeeded on the relay (`relayed == true`) but
                // `commit_outbox_item` failed transiently on IndexedDB, complete the local commit
                // directly BEFORE `requeue_before_push` or another `PushV2` can run so we never
                // unseal or duplicate an already-delivered message.
                if let Some(relayed) = inner
                    .in_flight_push
                    .get(peer)
                    .copied()
                    .filter(|f| f.relayed)
                {
                    let matched_relayed =
                        inner
                            .contacts
                            .iter()
                            .find(|c| c.peer == *peer)
                            .and_then(|c| {
                                if c.state.conversation_gen != relayed.conversation_gen {
                                    return None;
                                }
                                let head = c.state.outbox.first()?;
                                if head.history_index == relayed.history_index
                                    && head.sealed
                                    && head.clock == relayed.clock
                                {
                                    let confirm_session = !c.session.needs_new_session()
                                        && !c.state.needs_requeue_sealed
                                        && (relayed.session_id.is_none()
                                            || c.session.active_id()
                                                == relayed.session_id.as_ref());
                                    Some((head.clone(), confirm_session))
                                } else {
                                    None
                                }
                            });
                    if let Some((outgoing, confirm_session)) = matched_relayed {
                        match self
                            .commit_outbox_item(
                                vgen,
                                inner,
                                peer,
                                &outgoing,
                                Step::Pushed,
                                outgoing.clock,
                                confirm_session,
                                &mut server_deletes,
                            )
                            .await
                        {
                            Ok(CommitOutcome::Committed) => {
                                inner.in_flight_push.remove(peer);
                                self.clear_approval_backoff(peer);
                                self.release(peer, outgoing.history_index);
                                changed = true;
                            }
                            Ok(CommitOutcome::Aborted) => return Ok(false),
                            Err(e) => {
                                result = Err(e);
                                break;
                            }
                        }
                    } else {
                        inner.in_flight_push.remove(peer);
                    }
                }
                match inner.requeue_before_push(peer).await {
                    Ok(Some(outcome)) => {
                        if !self.is_live(vgen) {
                            return Ok(false);
                        }
                        outcome.log_missing(&self.ui, peer);
                        self.show_changes(inner, peer, &outcome.history);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }

                // Loop locally while sealing/recovering without network RPCs.
                let mut step = NextPush::Done;
                while let Some(contact) = inner.contact(peer)
                    && let Some(outgoing) = contact.state.outbox.first().cloned()
                {
                    if !self.is_live(vgen) {
                        return Ok(false);
                    }
                    // Never transmit `PushV2` while the active session's inbound write-token
                    // registration is still pending confirmation on our DO: otherwise the peer
                    // marks `known_by_peer = true`, hits `WriteTokenRejected`, and retires the
                    // session. Attempt one lock-free grant flush first, then wait if still pending.
                    if contact.session.has_pending_active_grant() {
                        step = if !tried_grant_flush {
                            NextPush::FlushPendingGrant
                        } else {
                            NextPush::Done
                        };
                        break;
                    }
                    // An attachment whose upload has not started: it, and what was sent after it,
                    // wait for it to start.
                    if outgoing.awaits_upload {
                        step = NextPush::Done;
                        break;
                    }
                    if !outgoing.sealed {
                        if contact.session.needs_new_session() {
                            // Pause sealing if waiting on explicit user action (quarantine /
                            // classical approval / security alert).
                            if contact.state.quarantined
                                || contact.state.classical_approval_needed
                                    != CLASSICAL_APPROVAL_NONE
                                || contact.state.security_alert != SECURITY_ALERT_NONE
                            {
                                step = NextPush::Done;
                                break;
                            }
                            step = NextPush::NeedsNewSession;
                            break;
                        }
                        match inner.seal_head_on_active_session(peer).await {
                            _ if !self.is_live(vgen) => return Ok(false),
                            Ok(LocalSealOutcome::Ready) => continue,
                            Ok(LocalSealOutcome::CorruptDropped(dropped_index, history)) => {
                                self.release(peer, dropped_index);
                                server_deletes.extend(
                                    self.prepare_cancel_uploads_for_failed(
                                        inner,
                                        peer,
                                        &[dropped_index],
                                    )
                                    .await,
                                );
                                if !self.is_live(vgen) {
                                    return Ok(false);
                                }
                                self.ui.log(format!(
                                    "Dropped corrupt pending message #{dropped_index} for {}: outbox record could not be recovered",
                                    short(peer)
                                ));
                                self.show_changes(inner, peer, &history);
                                changed = true;
                                continue;
                            }
                            Err(e) => {
                                result = Err(e);
                                step = NextPush::Done;
                                break;
                            }
                        }
                    }

                    let record = match inner.vault.outgoing(peer, outgoing.history_index).await {
                        _ if !self.is_live(vgen) => return Ok(false),
                        Ok(record) => record,
                        Err(crate::vault::Error::Corrupt(reason)) => {
                            match inner
                                .recover_corrupt_outbox(peer, outgoing.history_index)
                                .await
                            {
                                _ if !self.is_live(vgen) => return Ok(false),
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
                                    if !self.is_live(vgen) {
                                        return Ok(false);
                                    }
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
                                    step = NextPush::Done;
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            result = Err(describe(&e));
                            step = NextPush::Done;
                            break;
                        }
                    };

                    // If this sealed record belongs to an older session than `active_id`, requeue
                    // sealed outbox items on the current active session before transmitting.
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
                        match inner.requeue_before_push(peer).await {
                            Ok(Some(outcome)) => {
                                if !self.is_live(vgen) {
                                    return Ok(false);
                                }
                                outcome.log_missing(&self.ui, peer);
                                self.show_changes(inner, peer, &outcome.history);
                            }
                            Ok(None) => {}
                            Err(e) => {
                                result = Err(e);
                                step = NextPush::Done;
                                break;
                            }
                        }
                        continue;
                    }

                    let Some(sealed_msg) = record.to_sealed() else {
                        match inner
                            .recover_corrupt_outbox(peer, outgoing.history_index)
                            .await
                        {
                            _ if !self.is_live(vgen) => return Ok(false),
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
                                if !self.is_live(vgen) {
                                    return Ok(false);
                                }
                                self.show_changes(inner, peer, &history);
                                changed = true;
                                continue;
                            }
                            Err(e) => {
                                result = Err(e);
                                step = NextPush::Done;
                                break;
                            }
                        }
                    };

                    // Persist `GREETING_DELIVERY_UNCERTAIN` BEFORE dropping `guard` and
                    // transmitting a message that can carry a previously unsent initial greeting.
                    let promoted_from_unsent = inner.contacts.iter().any(|c| {
                        c.peer == *peer && c.state.greeting_delivery == GREETING_DELIVERY_UNSENT
                    });
                    if promoted_from_unsent {
                        if let Err(e) = inner
                            .with_contact_tx(peer, async |inner| {
                                if let Some(contact) = inner.contact(peer) {
                                    contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
                                }
                                inner.save(&[]).await.map_err(|e| describe(&e))
                            })
                            .await
                        {
                            result = Err(e);
                            step = NextPush::Done;
                            break;
                        }
                        if !self.is_live(vgen) {
                            return Ok(false);
                        }
                    }

                    let (conversation_gen, session_id) = {
                        let c = inner.contact(peer);
                        let conv_gen = c.as_ref().map_or(0, |c| c.state.conversation_gen);
                        let sid = if !record.session_id.is_empty() {
                            record.session_id.clone()
                        } else {
                            c.and_then(|c| c.session.active_id().map(|id| id.to_vec()))
                                .unwrap_or_default()
                        };
                        (conv_gen, sid)
                    };
                    // Protect this exact in-flight outbox head from concurrent `requeue_sealed`
                    // unsealing while `PushV2` is suspended outside `self.inner` and across local
                    // `commit_outbox_item` persistence.
                    inner.in_flight_push.insert(
                        *peer,
                        super::InFlightPush {
                            conversation_gen,
                            history_index: outgoing.history_index,
                            clock: outgoing.clock,
                            session_id: <[u8; 32]>::try_from(session_id.as_slice()).ok(),
                            relayed: false,
                        },
                    );
                    let push_req = sealed_msg.push_v2_request(peer);
                    let retry_initial = (!record.carried_initial.is_empty())
                        .then(|| {
                            session::protocol::mailbox_v2::decode_carried_initial(
                                &record.carried_initial,
                            )
                            .map(|wire_initial| SendInitialV2Request {
                                recipient: Bytes::copy_from_slice(peer),
                                message: Some(wire_initial),
                            })
                        })
                        .flatten();
                    step = NextPush::Push(Box::new(PreparedPush {
                        conversation_gen,
                        outgoing,
                        session_id,
                        push_req,
                        server: inner.server.clone(),
                        audience: inner.audience.clone(),
                        retry_initial,
                        promoted_from_unsent,
                    }));
                    break;
                }
                step
            };

            if result.is_err() {
                break;
            }

            // Phase 2 outside `self.inner`: run lock-free grant flush, rekey, or `PushV2`.
            match next_push {
                NextPush::Done => break,
                NextPush::FlushPendingGrant => {
                    tried_grant_flush = true;
                    if let Err(e) = self.flush_pending_grants_for_peer(peer).await {
                        result = Err(e);
                        break;
                    }
                    continue;
                }
                NextPush::NeedsNewSession => {
                    match self
                        .ensure_session_for_outbox(vgen, peer, &mut server_deletes)
                        .await
                    {
                        Ok(RekeyOutcome::Aborted) => return Ok(false),
                        Ok(RekeyOutcome::Ready) => continue,
                        Ok(RekeyOutcome::Paused | RekeyOutcome::ContactGone) => break,
                        Ok(RekeyOutcome::Failed) => {
                            changed = true;
                            continue;
                        }
                        Ok(RekeyOutcome::UpdateRequired(reason)) => {
                            self.require_update(reason.clone());
                            result = Err(reason);
                            break;
                        }
                        Err(e) => {
                            result = Err(e);
                            break;
                        }
                    }
                }
                NextPush::Push(prepared) => {
                    let PreparedPush {
                        conversation_gen,
                        outgoing,
                        session_id,
                        push_req,
                        server,
                        audience,
                        retry_initial,
                        promoted_from_unsent,
                    } = *prepared;
                    let push_res: session::Result<()> = Fetch::client(&server)
                        .push_v2(push_req)
                        .await
                        .map(|_| ())
                        .map_err(session::Error::from);
                    if !self.is_live(vgen) {
                        return Ok(false);
                    }

                    // Phase 3: Re-acquire `self.inner` and validate live generation, conversation
                    // incarnation, active session, and head index. Keep `in_flight_push` armed
                    // (marking `relayed = true`) until `commit_outbox_item` persists `Step::Pushed`
                    // so a transient storage error after relay `200 OK` never lets `requeue_sealed`
                    // unseal and duplicate the delivered message.
                    let mut guard = self.lock_inner().await;
                    if !self.is_live(vgen) {
                        return Ok(false);
                    }
                    let Some(inner) = guard.as_mut() else {
                        return Ok(false);
                    };
                    if inner.contact(peer).is_none() {
                        inner.in_flight_push.remove(peer);
                        break;
                    }
                    let same_conversation = inner
                        .contacts
                        .iter()
                        .find(|c| c.peer == *peer)
                        .is_some_and(|c| c.state.conversation_gen == conversation_gen);
                    if !same_conversation {
                        // The chat was deleted and recreated while `PushV2` was suspended: stop
                        // this stale flush cleanly without touching the new conversation.
                        inner.in_flight_push.remove(peer);
                        break;
                    }
                    let session_matches = same_conversation
                        && inner
                            .contacts
                            .iter()
                            .find(|c| c.peer == *peer)
                            .is_some_and(|c| {
                                !c.session.needs_new_session()
                                    && !c.state.needs_requeue_sealed
                                    && (session_id.is_empty()
                                        || c.session.active_id().is_some_and(|id| {
                                            id.as_slice() == session_id.as_slice()
                                        }))
                            });
                    let will_retry_initial = session_matches
                        && matches!(&push_res, Err(e) if e.kind() == ErrorKind::WriteTokenRejected)
                        && retry_initial.is_some()
                        && inner
                            .contacts
                            .iter()
                            .find(|c| c.peer == *peer)
                            .is_some_and(|c| {
                                !c.session.is_known_by_peer()
                                    && !c.session.has_pending_active_grant()
                                    && c.state.greeting_delivery != GREETING_DELIVERY_CONFIRMED
                            });
                    // Only revert `UNCERTAIN -> UNSENT` when NOT about to transmit a `SendInitialV2`
                    // retry, and NEVER downgrade a greeting already confirmed concurrently.
                    if let Err(ref e) = push_res
                        && e.is_server_refusal()
                        && promoted_from_unsent
                        && session_matches
                        && !will_retry_initial
                    {
                        let reverted = inner.contact(peer).is_some_and(|contact| {
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
                                return Ok(false);
                            }
                        }
                    }
                    let head_matches = same_conversation
                        && inner.contact(peer).is_some_and(|c| {
                            c.state.outbox.first().is_some_and(|head| {
                                head.history_index == outgoing.history_index
                                    && head.sealed
                                    && head.clock == outgoing.clock
                            })
                        });
                    if !head_matches {
                        // Head item was already settled (e.g. via peer receipt), requeued, or
                        // cancelled while `PushV2` was suspended: continue with the new head.
                        inner.in_flight_push.remove(peer);
                        continue;
                    }
                    // If `PushV2` already succeeded on the relay, commit `Step::Pushed` even if a
                    // concurrent inbound session rotated `active_id` or set `needs_requeue_sealed`
                    // (otherwise looping to requeue would re-encrypt and duplicate a delivered
                    // message). Only retry/requeue on failure when the session rotated.
                    if push_res.is_err() {
                        inner.in_flight_push.remove(peer);
                        if !session_matches {
                            continue;
                        }
                    }

                    match push_res {
                        Ok(()) => {
                            if let Some(in_flight) = inner.in_flight_push.get_mut(peer) {
                                in_flight.relayed = true;
                            }
                            match self
                                .commit_outbox_item(
                                    vgen,
                                    inner,
                                    peer,
                                    &outgoing,
                                    Step::Pushed,
                                    outgoing.clock,
                                    session_matches,
                                    &mut server_deletes,
                                )
                                .await
                            {
                                Ok(CommitOutcome::Committed) => {
                                    inner.in_flight_push.remove(peer);
                                    self.clear_approval_backoff(peer);
                                    self.release(peer, outgoing.history_index);
                                    changed = true;
                                }
                                Ok(CommitOutcome::Aborted) => return Ok(false),
                                Err(e) => {
                                    // M-18 + R3-P2-5: Outbox entry AND `in_flight_push` (`relayed = true`)
                                    // stay intact when reading/saving failed so the next flush
                                    // retries local commit without unsealing or re-pushing.
                                    result = Err(e);
                                    break;
                                }
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::WriteTokenRejected => {
                            let known = inner
                                .contact(peer)
                                .is_some_and(|c| c.session.is_known_by_peer());
                            if known {
                                // Peer previously accepted us and has since revoked/deleted the
                                // chat: retire active session and requeue so the next sync starts
                                // fresh.
                                if let Some(contact) = inner.contact(peer) {
                                    contact.state.needs_requeue_sealed = true;
                                    contact.session.retire();
                                }
                                let _ = inner.save_state().await;
                                if self.is_live(vgen) {
                                    self.refresh_contacts(inner);
                                }
                                break;
                            }
                            // Peer has not yet accepted our chat request:
                            // - If greeting delivery wasn't confirmed, retry idempotent
                            //   `SendInitialV2` (persisting `GREETING_DELIVERY_UNCERTAIN` first).
                            // - If greeting delivery WAS `CONFIRMED` (e.g. targeting `prev_signed_prekey`
                            //   that the recipient subsequently evicted before reading its inbox),
                            //   probe `GetManifest` first; only if the peer rotated its SPK do we
                            //   probe idempotent `SendInitialV2` so a `StaleVersion` refusal
                            //   reclaims a fresh bundle without re-inserting declined requests.
                            let can_retry_or_probe = inner
                                .contact(peer)
                                .is_some_and(|c| !c.session.has_pending_active_grant());
                            let greeting_unconfirmed = inner.contact(peer).is_some_and(|c| {
                                c.state.greeting_delivery != GREETING_DELIVERY_CONFIRMED
                            });
                            let mut retry_failed = false;
                            let mut retry_retired_spk = false;
                            let mut stale_aborted = false;
                            if can_retry_or_probe && let Some(retry_req) = retry_initial {
                                let mut retry_promoted = promoted_from_unsent;
                                let mut ready_for_retry = true;
                                if greeting_unconfirmed
                                    && inner.contacts.iter().any(|c| {
                                        c.peer == *peer
                                            && c.state.greeting_delivery == GREETING_DELIVERY_UNSENT
                                    })
                                {
                                    match inner
                                        .with_contact_tx(peer, async |inner| {
                                            if let Some(contact) = inner.contact(peer) {
                                                contact.state.greeting_delivery =
                                                    GREETING_DELIVERY_UNCERTAIN;
                                            }
                                            inner.save(&[]).await.map_err(|e| describe(&e))
                                        })
                                        .await
                                    {
                                        Ok(()) => {
                                            retry_promoted = true;
                                        }
                                        Err(save_err) => {
                                            ready_for_retry = false;
                                            retry_failed = true;
                                            result = Err(save_err);
                                        }
                                    }
                                    if !self.is_live(vgen) {
                                        return Ok(false);
                                    }
                                }
                                if ready_for_retry {
                                    let retry_is_pq =
                                        retry_req.message.as_ref().is_some_and(|m| m.version >= 2);
                                    drop(guard);
                                    let should_send_initial = if greeting_unconfirmed {
                                        true
                                    } else {
                                        let greeting_spk = retry_req
                                            .message
                                            .as_ref()
                                            .map(|m| m.signed_prekey.as_ref())
                                            .unwrap_or(&[]);
                                        self.probe_confirmed_greeting_spk_rotated(
                                            &server,
                                            &audience,
                                            peer,
                                            greeting_spk,
                                        )
                                        .await
                                            == Some(true)
                                    };
                                    if !self.is_live(vgen) {
                                        return Ok(false);
                                    }
                                    let retry_res = if should_send_initial {
                                        Some(
                                            Fetch::client(&server)
                                                .send_initial_v2(retry_req)
                                                .await
                                                .map(|_| ())
                                                .map_err(session::Error::from),
                                        )
                                    } else {
                                        None
                                    };
                                    if !self.is_live(vgen) {
                                        return Ok(false);
                                    }
                                    guard = self.lock_inner().await;
                                    if !self.is_live(vgen) {
                                        return Ok(false);
                                    }
                                    let Some(inner) = guard.as_mut() else {
                                        return Ok(false);
                                    };
                                    if inner.contact(peer).is_none() {
                                        break;
                                    }
                                    // Revalidate exact conversation generation, active session, AND
                                    // `!is_known_by_peer()` so neither a recreated conversation nor
                                    // a session that received an inbound reply during the RPC can
                                    // be retired or marked `awaiting_peer_acceptance`.
                                    let still_matches = inner
                                        .contacts
                                        .iter()
                                        .find(|c| c.peer == *peer)
                                        .is_some_and(|c| {
                                            c.state.conversation_gen == conversation_gen
                                                && !c.session.needs_new_session()
                                                && !c.session.is_known_by_peer()
                                                && (session_id.is_empty()
                                                    || c.session.active_id().is_some_and(|id| {
                                                        id.as_slice() == session_id.as_slice()
                                                    }))
                                        });
                                    if !still_matches {
                                        stale_aborted = true;
                                    } else if let Some(retry_res) = retry_res {
                                        match retry_res {
                                            Ok(()) => {
                                                if let Some(contact) = inner.contact(peer) {
                                                    contact.mark_greeting_confirmed();
                                                    contact.state.awaiting_peer_acceptance = true;
                                                }
                                                let _ = inner.save_state().await;
                                                if !self.is_live(vgen) {
                                                    return Ok(false);
                                                }
                                            }
                                            Err(retry_err)
                                                if retry_err.is_server_refusal()
                                                    && retry_err.kind()
                                                        == ErrorKind::StaleVersion =>
                                            {
                                                // Recipient retired the SPK used by this cached
                                                // greeting: retire locally and immediately re-claim
                                                // a fresh bundle on the next loop iteration while
                                                // preserving queued messages.
                                                if let Some(contact) = inner.contact(peer) {
                                                    contact.session.retire();
                                                    contact.state.needs_requeue_sealed = true;
                                                    contact.state.greeting_delivery =
                                                        GREETING_DELIVERY_UNSENT;
                                                }
                                                let _ = inner.save_state().await;
                                                if !self.is_live(vgen) {
                                                    return Ok(false);
                                                }
                                                self.refresh_contacts(inner);
                                                retry_failed = true;
                                                retry_retired_spk = true;
                                            }
                                            Err(retry_err) => {
                                                retry_failed = true;
                                                if retry_err.is_server_refusal()
                                                    && greeting_unconfirmed
                                                    && retry_promoted
                                                {
                                                    // Only revert `UNCERTAIN -> UNSENT`; never
                                                    // downgrade a greeting already confirmed
                                                    // concurrently.
                                                    let reverted = inner.contact(peer).is_some_and(
                                                        |contact| {
                                                            if contact.state.greeting_delivery
                                                                == GREETING_DELIVERY_UNCERTAIN
                                                            {
                                                                contact.state.greeting_delivery =
                                                                    GREETING_DELIVERY_UNSENT;
                                                                true
                                                            } else {
                                                                false
                                                            }
                                                        },
                                                    );
                                                    if reverted {
                                                        let _ = inner.save_state().await;
                                                        if !self.is_live(vgen) {
                                                            return Ok(false);
                                                        }
                                                    }
                                                }
                                                if retry_err.kind() == ErrorKind::SignInRequired
                                                    && signs_in_here
                                                {
                                                    self.queue.mark_waits_sign_in(*peer);
                                                    self.hold(peer, outgoing.history_index);
                                                    self.ask_sign_in();
                                                    self.refresh_contacts(inner);
                                                } else if retry_err.kind()
                                                    == ErrorKind::SignInRequired
                                                {
                                                    self.refresh_contacts(inner);
                                                    result = Err(NOT_SIGNED_IN_HERE.to_string());
                                                } else {
                                                    self.check_send_initial_protocol_error(
                                                        inner,
                                                        retry_is_pq,
                                                        &retry_err,
                                                    );
                                                    self.refresh_contacts(inner);
                                                    result = Err(describe(&retry_err));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if stale_aborted {
                                break;
                            }
                            if retry_retired_spk {
                                continue;
                            }
                            if !retry_failed
                                && let Some(inner) = guard.as_mut()
                                && inner.contact(peer).is_some()
                            {
                                let mark_awaiting = inner.contact(peer).is_some_and(|contact| {
                                    if !contact.state.awaiting_peer_acceptance {
                                        contact.state.awaiting_peer_acceptance = true;
                                        true
                                    } else {
                                        false
                                    }
                                });
                                if mark_awaiting {
                                    let _ = inner.save_state().await;
                                    if !self.is_live(vgen) {
                                        return Ok(false);
                                    }
                                }
                                let delay_ms = self.queue.record_approval_backoff(peer);
                                self.refresh_contacts(inner);
                                let label = inner
                                    .contact(peer)
                                    .map_or_else(|| short(peer), |c| c.view().label());
                                self.ui.log(format!(
                                    "Waiting for {label} to accept your chat request (retrying in {}s)…",
                                    delay_ms / 1000
                                ));
                            }
                            break;
                        }
                        // Large enough to cost the server storage, which it keeps only for those
                        // signed in to it: it waits, with those after it, until this browser is.
                        Err(e) if e.kind() == ErrorKind::SignInRequired && signs_in_here => {
                            self.queue.mark_waits_sign_in(*peer);
                            self.hold(peer, outgoing.history_index);
                            self.ask_sign_in();
                            break;
                        }
                        // The same, but this page cannot sign in to the server: it never will go.
                        Err(e) if e.kind() == ErrorKind::SignInRequired => {
                            self.release(peer, outgoing.history_index);
                            self.ui.notify(format!(
                                "a message could not be sent: {NOT_SIGNED_IN_HERE}"
                            ));
                            match self
                                .commit_outbox_item(
                                    vgen,
                                    inner,
                                    peer,
                                    &outgoing,
                                    Step::Refused,
                                    0,
                                    session_matches,
                                    &mut server_deletes,
                                )
                                .await
                            {
                                Ok(CommitOutcome::Committed) => changed = true,
                                Ok(CommitOutcome::Aborted) => return Ok(false),
                                Err(err) => {
                                    result = Err(err);
                                    break;
                                }
                            }
                        }
                        // Too large for the server: it never will go.
                        Err(e) if e.is_server_refusal() && e.kind() == ErrorKind::LimitExceeded => {
                            self.release(peer, outgoing.history_index);
                            self.ui
                                .notify(format!("a message could not be sent: {}", describe(&e)));
                            match self
                                .commit_outbox_item(
                                    vgen,
                                    inner,
                                    peer,
                                    &outgoing,
                                    Step::Refused,
                                    0,
                                    session_matches,
                                    &mut server_deletes,
                                )
                                .await
                            {
                                Ok(CommitOutcome::Committed) => changed = true,
                                Ok(CommitOutcome::Aborted) => return Ok(false),
                                Err(err) => {
                                    result = Err(err);
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                            result = Err(describe(&e));
                            break;
                        }
                    }
                }
            }
        }

        // Not from a page that cannot sign in to the server, which takes no push from it: each
        // try would use up a key of the ratchet.
        if result.is_ok()
            && signs_in_here
            && self.is_live(vgen)
            && !self.queue.waits_for_sign_in(peer)
            && !self.queue.is_approval_backed_off(peer)
        {
            match self.push_events(vgen, peer).await {
                Ok(told) => changed |= told,
                Err(e) => result = Err(e),
            }
        }
        if !server_deletes.is_empty() && self.is_live(vgen) {
            self.finish_server_deletes(peer, server_deletes).await;
        }
        result.map(|()| changed)
    }

    /// Commit one pushed or permanently refused outbox head entry immediately to the vault,
    /// preserving M-18 outbox retention if reading the history entry fails.
    #[allow(clippy::too_many_arguments)]
    async fn commit_outbox_item(
        &self,
        vgen: u64,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        outgoing: &Outgoing,
        step: Step,
        clock: u64,
        confirm_session: bool,
        server_deletes: &mut Vec<ServerDeleteJob>,
    ) -> Result<CommitOutcome, String> {
        let index = outgoing.history_index;
        let entry_opt = match inner.vault.entry(peer, index).await {
            _ if !self.is_live(vgen) => return Ok(CommitOutcome::Aborted),
            // M-18: Do NOT delete the outbox entry when reading its history entry fails!
            Err(e) => return Err(describe(&e)),
            Ok(entry) => entry,
        };
        let mut entries = vec![];
        let mut new_awaiting = None;
        if let Some(mut entry) = entry_opt {
            entry.set_delivery(entry.delivery().after(step));
            // Pushed, it has its place, and waits for the peer to read it.
            if step == Step::Pushed {
                entry.place = clock;
                let content = entry.content.get_or_insert_default();
                content.clock = clock;
                let attachment = matches!(content.kind, Some(Kind::Attachment(_)));
                new_awaiting = Some(Awaiting {
                    place: clock,
                    history_index: index,
                    read: false,
                    attachment,
                    content_digest: outgoing.content_digest.clone(),
                });
            }
            entries.push((index, entry));
        }
        let snapshot = inner.contact(peer).map(|c| c.snapshot());
        if let Some(contact) = inner.contact(peer) {
            if let Some(pos) = contact
                .state
                .outbox
                .iter()
                .position(|o| o.history_index == index)
            {
                contact.state.outbox.remove(pos);
            }
            if step == Step::Pushed && confirm_session {
                contact.mark_greeting_confirmed();
                contact.state.awaiting_peer_acceptance = false;
            }
            if let Some(awaiting) = new_awaiting {
                contact.state.awaiting.push(awaiting);
                keep_last(&mut contact.state.awaiting);
            }
        }
        if let Err(e) = inner
            .save_with(&records(peer, &entries), &[(*peer, index, None)])
            .await
        {
            if let Some(snapshot) = snapshot {
                inner.roll_back(peer, snapshot)?;
            }
            if !self.is_live(vgen) {
                return Ok(CommitOutcome::Aborted);
            }
            return Err(describe(&e));
        }
        if !self.is_live(vgen) {
            return Ok(CommitOutcome::Aborted);
        }
        self.show_changes(inner, peer, &entries);
        if step == Step::Pushed {
            self.refresh_contacts(inner);
        }
        let refused_indices: Vec<u64> = entries
            .iter()
            .filter(|(_, entry)| entry.delivery() == Delivery::Failed)
            .map(|(idx, _)| *idx)
            .collect();
        if !refused_indices.is_empty() {
            server_deletes.extend(
                self.prepare_cancel_uploads_for_failed(inner, peer, &refused_indices)
                    .await,
            );
            if !self.is_live(vgen) {
                return Ok(CommitOutcome::Aborted);
            }
        }
        Ok(CommitOutcome::Committed)
    }

    /// Map a `session::Error` from `claim_peer_bundle_v2` or `finish_prepare_start_again_v2`
    /// during outbox rekey into [`RekeyOutcome`] while holding `inner` (after rolling back any
    /// in-memory mutations).
    async fn handle_rekey_session_error(
        &self,
        vgen: u64,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        clock: &session::ServerClock,
        error: session::Error,
        server_deletes: &mut Vec<ServerDeleteJob>,
    ) -> Result<RekeyOutcome, String> {
        let kind = error.kind();
        if matches!(kind, ErrorKind::NotFound | ErrorKind::InvalidKeys) {
            let (reason, failed_indices) = inner.fail_waiting(peer, describe(&error)).await?;
            if !self.is_live(vgen) {
                return Ok(RekeyOutcome::Aborted);
            }
            for idx in &failed_indices {
                self.release(peer, *idx);
            }
            server_deletes.extend(
                self.prepare_cancel_uploads_for_failed(inner, peer, &failed_indices)
                    .await,
            );
            if !self.is_live(vgen) {
                return Ok(RekeyOutcome::Aborted);
            }
            if !failed_indices.is_empty() {
                self.ui
                    .notify(format!("messages could not be sent: {reason}"));
            } else {
                self.ui.log(format!(
                    "could not establish a new session with {}: {reason}",
                    short(peer)
                ));
            }
            if self.ui.open.get_untracked() == Some(*peer) {
                self.show_history(inner, peer).await;
            }
            return Ok(RekeyOutcome::Failed);
        }
        if should_require_update_for_rpc(ProtocolRpcScope::CoreV2, &error) {
            return Ok(RekeyOutcome::UpdateRequired(describe(&error)));
        }
        let paused = match kind {
            ErrorKind::ClassicalApprovalRequired => {
                if let Some(contact) = inner.contact(peer) {
                    if matches!(
                        contact.state.security_alert,
                        SECURITY_ALERT_PQ_REQUIRED | SECURITY_ALERT_MANIFEST_EXPIRED
                    ) {
                        contact.state.security_alert = SECURITY_ALERT_NONE;
                    }
                    contact.state.classical_approval_needed = CLASSICAL_APPROVAL_SIGNED_OFF;
                }
                true
            }
            ErrorKind::DowngradeDetected => {
                if let Some(contact) = inner.contact(peer) {
                    contact.session.peer_pq_state_mut().downgrade_detected = true;
                    contact.state.security_alert = SECURITY_ALERT_DOWNGRADE;
                }
                true
            }
            ErrorKind::PeerManifestExpired => {
                if let Some(contact) = inner.contact(peer) {
                    contact.state.security_alert = SECURITY_ALERT_MANIFEST_EXPIRED;
                }
                true
            }
            ErrorKind::PqRequired => {
                if let Some(contact) = inner.contact(peer) {
                    contact.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                }
                true
            }
            _ => false,
        };
        if paused {
            inner.save_state().await.map_err(|e| describe(&e))?;
            if !self.is_live(vgen) {
                return Ok(RekeyOutcome::Aborted);
            }
            self.refresh_contacts(inner);
            return Ok(RekeyOutcome::Paused);
        }
        if kind == ErrorKind::ClockSkew {
            self.warn_clock_skew(clock.offset_ms());
            return Err(super::CLOCK_SKEW_MESSAGE.to_string());
        }
        Err(describe(&error))
    }

    /// Establish a replacement session for `peer` under `peer_flush_locks`, releasing
    /// `Engine::inner` across `ClaimBundle`, `RegisterWriteToken`, and `SendInitialV2`.
    ///
    /// If an inbound session arrives from `peer` while `ClaimBundle` is suspended, the stale
    /// claimed bundle is discarded cleanly without corrupting the inbound ratchet!
    pub(super) async fn ensure_session_for_outbox(
        &self,
        vgen: u64,
        peer: &PublicKey,
        server_deletes: &mut Vec<ServerDeleteJob>,
    ) -> Result<RekeyOutcome, String> {
        const MAX_CONFIG_RETRIES: usize = 2;
        let mut attempt = 0usize;

        let (server, new_session_id, outgoing_req) = loop {
            if !self.is_live(vgen) {
                return Ok(RekeyOutcome::Aborted);
            }
            // Snapshot immutable inputs under `self.inner`, then drop `guard` before `ClaimBundle`.
            let (server, audience, pq_config, clock, peer_pq, expected_conversation_gen) = {
                let guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Ok(RekeyOutcome::Aborted);
                }
                let Some(inner) = guard.as_ref() else {
                    return Ok(RekeyOutcome::Aborted);
                };
                if inner.is_isolated_peer(peer) {
                    return Ok(RekeyOutcome::ContactGone);
                }
                let Some(contact) = inner.contacts.iter().find(|c| c.peer == *peer) else {
                    return Ok(RekeyOutcome::ContactGone);
                };
                if !contact.session.needs_new_session() {
                    return Ok(RekeyOutcome::Ready);
                }
                if contact.state.quarantined
                    || contact.state.classical_approval_needed != CLASSICAL_APPROVAL_NONE
                    || contact.state.security_alert != SECURITY_ALERT_NONE
                {
                    return Ok(RekeyOutcome::Paused);
                }
                (
                    inner.server.clone(),
                    inner.audience.clone(),
                    inner.client.pq_config().clone(),
                    inner.client.clock().clone(),
                    contact.session.peer_pq_state().clone(),
                    contact.state.conversation_gen,
                )
            };

            let claim_res = session::claim_peer_bundle_v2(
                &Fetch::client(&server),
                &audience,
                peer,
                &peer_pq,
                &pq_config,
                &clock,
            )
            .await;
            if !self.is_live(vgen) {
                return Ok(RekeyOutcome::Aborted);
            }

            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(RekeyOutcome::Aborted);
            }
            let Some(inner) = guard.as_mut() else {
                return Ok(RekeyOutcome::Aborted);
            };
            if inner.is_isolated_peer(peer) {
                return Ok(RekeyOutcome::ContactGone);
            }
            let Some(index) = inner.contacts.iter().position(|c| c.peer == *peer) else {
                return Ok(RekeyOutcome::ContactGone);
            };
            if inner.contacts[index].state.conversation_gen != expected_conversation_gen {
                drop(claim_res);
                return Ok(RekeyOutcome::ContactGone);
            }
            if !inner.contacts[index].session.needs_new_session() {
                // An inbound session arrived while `ClaimBundle` was suspended: discard the stale
                // bundle (or claim error) cleanly without corrupting the inbound ratchet!
                drop(claim_res);
                return Ok(RekeyOutcome::Ready);
            }
            if inner.contacts[index].state.quarantined
                || inner.contacts[index].state.classical_approval_needed != CLASSICAL_APPROVAL_NONE
                || inner.contacts[index].state.security_alert != SECURITY_ALERT_NONE
            {
                drop(claim_res);
                return Ok(RekeyOutcome::Paused);
            }
            if *inner.client.pq_config() != pq_config
                || *inner.contacts[index].session.peer_pq_state() != peer_pq
            {
                drop(claim_res);
                if attempt < MAX_CONFIG_RETRIES {
                    attempt += 1;
                    continue;
                }
                return Err(
                    "Post-quantum settings changed while establishing a new session; retrying later."
                        .to_string(),
                );
            }

            let claimed = match claim_res {
                Ok(claimed) => claimed,
                Err(e) => {
                    return self
                        .handle_rekey_session_error(vgen, inner, peer, &clock, e, server_deletes)
                        .await;
                }
            };

            // Synchronous Phase 2: complete handshake, stage grant, persist BEFORE transmitting!
            let snapshot = inner.contacts[index].snapshot();
            let prev_next_session_seq = inner.state.next_session_seq;
            let session_seq = inner.next_new_chat_session_seq();
            inner.state.next_session_seq = session_seq
                .saturating_add(1)
                .min(session::protocol::MAX_SAFE_INTEGER);
            let greeting = Kind::Hello(
                inner
                    .client
                    .make_hello(inner.state.name.clone(), session_seq),
            );
            inner.contacts[index].state.clock = inner.contacts[index].state.clock.saturating_add(1);
            let mut hello = greeting.to_bytes();
            stamp(&mut hello, inner.contacts[index].state.clock);

            let prepared = {
                let client = &inner.client;
                let contact = &mut inner.contacts[index];
                client.finish_prepare_start_again_v2(claimed, &mut contact.session, &hello)
            };
            let outgoing_req = match prepared {
                Ok(req) => req,
                Err(e) => {
                    inner.state.next_session_seq = prev_next_session_seq;
                    inner.roll_back(peer, snapshot)?;
                    return self
                        .handle_rekey_session_error(vgen, inner, peer, &clock, e, server_deletes)
                        .await;
                }
            };

            let (new_session_id, token_hash) = inner
                .contact(peer)
                .map(|contact| {
                    contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                    contact.state.security_alert = SECURITY_ALERT_NONE;
                    contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
                    (
                        contact.session.active_id().copied(),
                        contact.session.active_inbound_token_hash(),
                    )
                })
                .unwrap_or((None, None));
            if let Some(token_hash) = token_hash
                && let Err(e) = inner.stage_write_token_grant(peer, token_hash, true)
            {
                inner.state.next_session_seq = prev_next_session_seq;
                inner.roll_back(peer, snapshot)?;
                return Err(e);
            }
            let requeued = match inner.requeue_sealed(peer).await {
                Ok(requeued) => requeued,
                Err(e) => {
                    inner.state.next_session_seq = prev_next_session_seq;
                    inner.roll_back(peer, snapshot)?;
                    return Err(e);
                }
            };
            // H-2: Persist new session, grant, requeued outbox, and uncertain delivery marker BEFORE transmitting!
            if let Err(e) = inner
                .save_with(&records(peer, &requeued.history), &requeued.outbox)
                .await
            {
                inner.state.next_session_seq = prev_next_session_seq;
                inner.roll_back(peer, snapshot)?;
                if !self.is_live(vgen) {
                    return Ok(RekeyOutcome::Aborted);
                }
                return Err(describe(&e));
            }
            if !self.is_live(vgen) {
                return Ok(RekeyOutcome::Aborted);
            }
            requeued.log_missing(&self.ui, peer);
            self.show_changes(inner, peer, &requeued.history);
            self.refresh_contacts(inner);
            break (server, new_session_id, outgoing_req);
        };

        // Phase 3 outside `self.inner`: register our new inbound write token BEFORE sending the
        // re-initiation `SendInitialV2`.
        let _ = self.flush_pending_grants_for_peer(peer).await;
        if !self.is_live(vgen) {
            return Ok(RekeyOutcome::Aborted);
        }
        // Re-verify contact existence, active session, AND confirmed active write-token grant
        // immediately before transmitting `SendInitialV2` so a concurrent delete, inbound session
        // replacement, or failed `RegisterWriteToken` never emits a phantom or unreplyable initial.
        {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(RekeyOutcome::Aborted);
            }
            let Some(inner) = guard.as_mut() else {
                return Ok(RekeyOutcome::Aborted);
            };
            if inner.is_isolated_peer(peer) {
                return Ok(RekeyOutcome::ContactGone);
            }
            let Some(contact) = inner.contacts.iter().find(|c| c.peer == *peer) else {
                return Ok(RekeyOutcome::ContactGone);
            };
            if contact.session.active_id() != new_session_id.as_ref() {
                return Ok(RekeyOutcome::Ready);
            }
            if contact.session.has_pending_active_grant() {
                if let Some(contact) = inner.contact(peer)
                    && contact.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN
                {
                    contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                    let _ = inner.save_state().await;
                    if !self.is_live(vgen) {
                        return Ok(RekeyOutcome::Aborted);
                    }
                }
                self.refresh_contacts(inner);
                return Ok(RekeyOutcome::Paused);
            }
        }

        let outgoing_is_pq = outgoing_req
            .message
            .as_ref()
            .is_some_and(|m| m.version >= 2);
        let send_res: session::Result<()> = Fetch::client(&server)
            .send_initial_v2(outgoing_req)
            .await
            .map(|_| ())
            .map_err(session::Error::from);
        if !self.is_live(vgen) {
            return Ok(RekeyOutcome::Aborted);
        }

        // Phase 4: Re-acquire `self.inner`, validate `is_live(vgen)`, contact existence, and
        // matching `active_id` before updating `greeting_delivery`.
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Ok(RekeyOutcome::Aborted);
        }
        let Some(inner) = guard.as_mut() else {
            return Ok(RekeyOutcome::Aborted);
        };
        if inner.contact(peer).is_none() {
            return Ok(RekeyOutcome::ContactGone);
        }
        let matches_session = inner
            .contacts
            .iter()
            .find(|c| c.peer == *peer)
            .is_some_and(|c| c.session.active_id() == new_session_id.as_ref());
        match send_res {
            Ok(()) => {
                if matches_session
                    && inner
                        .contact(peer)
                        .is_some_and(Contact::mark_greeting_confirmed)
                {
                    let _ = inner.save_state().await;
                    if !self.is_live(vgen) {
                        return Ok(RekeyOutcome::Aborted);
                    }
                }
            }
            Err(e) => {
                if e.is_server_refusal() && matches_session {
                    // Only revert `UNCERTAIN -> UNSENT`; never downgrade a greeting already
                    // confirmed concurrently on this session.
                    let reverted = inner.contact(peer).is_some_and(|contact| {
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
                            return Ok(RekeyOutcome::Aborted);
                        }
                    }
                }
                if self.check_send_initial_protocol_error(inner, outgoing_is_pq, &e) {
                    return Ok(RekeyOutcome::UpdateRequired(describe(&e)));
                }
                if e.is_server_refusal() {
                    self.queue.record_approval_backoff(peer);
                    self.refresh_contacts(inner);
                    return Ok(RekeyOutcome::Paused);
                }
            }
        }
        Ok(RekeyOutcome::Ready)
    }

    /// Tell `peer` what this client did with its messages, all in one message, once what waits
    /// for it went: on the session, never starting one for it, and never in a request or
    /// quarantined chat, whose sender learns nothing until it is accepted/approved. Encrypted and
    /// saved once under `self.inner`, then pushed outside `self.inner` so slow RTTs never stall
    /// UI or other peers. Once pushed, clearing `sealed_events` is persisted immediately to the
    /// vault after validating `is_live(vgen)`, contact existence, and matching `session_id`.
    async fn push_events(&self, vgen: u64, peer: &PublicKey) -> Result<bool, String> {
        if !self.is_live(vgen) {
            return Ok(false);
        }
        // Phase 1 under `self.inner`: seal & persist `SealedEvents` and extract wire `PushV2Request`.
        let prepared = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(false);
            }
            let Some(inner) = guard.as_mut() else {
                return Ok(false);
            };
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
            // Never transmit events while the active session's inbound write-token registration is
            // still pending confirmation on our DO (nor `Events { accepted: true }` while any
            // grant is pending), otherwise the peer marks `known_by_peer = true` and hits
            // `WriteTokenRejected`.
            let carries_accepted = contact.state.events.as_ref().is_some_and(|e| e.accepted)
                || contact
                    .state
                    .sealed_events
                    .as_ref()
                    .and_then(|s| s.events.as_ref())
                    .is_some_and(|e| e.accepted);
            if contact.session.has_pending_active_grant()
                || (carries_accepted && !contact.session.pending_register_grants().is_empty())
            {
                return Ok(false);
            }
            let active = contact.session.active_id().map(|id| id.to_vec());
            // One encrypted on a session that is no longer the active one, which the peer may
            // never have had: what it tells, still in the events, is encrypted again on the active
            // one.
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
            if !self.is_live(vgen) {
                return Ok(false);
            }
            let Some(message) = sealed.record.as_ref().and_then(OutgoingRecord::to_sealed) else {
                if let Some(contact) = inner.contact(peer) {
                    contact.state.sealed_events = None;
                }
                let _ = inner.save_state().await;
                return Ok(false);
            };
            let promoted_from_unsent = inner
                .contacts
                .iter()
                .any(|c| c.peer == *peer && c.state.greeting_delivery == GREETING_DELIVERY_UNSENT);
            if promoted_from_unsent {
                inner
                    .with_contact_tx(peer, async |inner| {
                        if let Some(contact) = inner.contact(peer) {
                            contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
                        }
                        inner.save(&[]).await.map_err(|e| describe(&e))
                    })
                    .await?;
                if !self.is_live(vgen) {
                    return Ok(false);
                }
            }
            let push_req = message.push_v2_request(peer);
            (inner.server.clone(), sealed, push_req, promoted_from_unsent)
        };
        let (server, sealed, push_req, promoted_from_unsent) = prepared;

        // Phase 2 outside `self.inner`: await `PushV2` RPC.
        let push_res: session::Result<_> = Fetch::client(&server)
            .push_v2(push_req)
            .await
            .map_err(session::Error::from);
        if !self.is_live(vgen) {
            return Ok(false);
        }

        // Phase 3: Re-acquire `self.inner` and validate live generation, contact existence, and
        // matching `sealed_events.session` before mutating or persisting.
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Ok(false);
        }
        let Some(inner) = guard.as_mut() else {
            return Ok(false);
        };
        if inner.contact(peer).is_none() {
            return Ok(false);
        }
        let matches_sealed = inner
            .contacts
            .iter()
            .find(|c| c.peer == *peer)
            .is_some_and(|c| {
                c.state
                    .sealed_events
                    .as_ref()
                    .is_some_and(|s| s.session == sealed.session)
                    && (sealed.session.is_empty()
                        || c.session
                            .active_id()
                            .is_some_and(|id| id.as_slice() == sealed.session.as_slice()))
            });
        if let Err(ref e) = push_res
            && e.is_server_refusal()
            && promoted_from_unsent
            && matches_sealed
        {
            // Only revert `UNCERTAIN -> UNSENT`; never downgrade a greeting already confirmed
            // concurrently on this session.
            let reverted = inner.contact(peer).is_some_and(|contact| {
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
                    return Ok(false);
                }
            }
        }
        match push_res {
            Ok(_) => {
                self.clear_approval_backoff(peer);
            }
            Err(e) if e.kind() == ErrorKind::WriteTokenRejected => {
                if !matches_sealed {
                    return Ok(false);
                }
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
                    if self.is_live(vgen) {
                        self.refresh_contacts(inner);
                    }
                } else {
                    if let Some(contact) = inner.contact(peer)
                        && !contact.state.awaiting_peer_acceptance
                    {
                        contact.state.awaiting_peer_acceptance = true;
                        let _ = inner.save_state().await;
                        if !self.is_live(vgen) {
                            return Ok(false);
                        }
                    }
                    self.queue.record_approval_backoff(peer);
                    self.refresh_contacts(inner);
                }
                return Ok(false);
            }
            // The chat waits for the sign-in, as a message refused for it does, rather than
            // tries every round, and goes once signed in.
            Err(e) if e.kind() == ErrorKind::SignInRequired => {
                self.queue.mark_waits_sign_in(*peer);
                return Ok(false);
            }
            Err(e) => {
                self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                return Err(describe(&e));
            }
        }
        if !matches_sealed {
            return Ok(false);
        }
        // Those told since it was encrypted stay, to go in the next. Persist immediately after
        // clearing `sealed_events` so reload never re-pushes already-sent events.
        inner
            .with_contact_tx(peer, async |inner| {
                let contact = inner
                    .contact(peer)
                    .ok_or_else(|| "no such chat".to_string())?;
                contact.mark_greeting_confirmed();
                contact.state.awaiting_peer_acceptance = false;
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
                let _ = inner
                    .step(peer, &mut entries, [(index, Step::Refused)])
                    .await
                    .map_err(|e| describe(&e))?;
                let changed: Vec<_> = entries.into_iter().collect();
                inner
                    .save_with(&records(peer, &changed), &[(*peer, index, None)])
                    .await
                    .map_err(|e| describe(&e))?;
                if inner
                    .in_flight_push
                    .get(peer)
                    .is_some_and(|f| f.history_index == index)
                {
                    inner.in_flight_push.remove(peer);
                }
                Ok::<_, String>(changed)
            })
            .await?;
        self.release(peer, index);
        self.show_changes(inner, peer, &changed);
        Ok(())
    }
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
            let content_bytes = content.to_bytes();
            let content_digest = crate::vault::content_kind_digest(&content_bytes);
            let record = OutgoingRecord::unsealed(content_bytes);
            contact.state.last_activity = now();
            contact.state.outbox.push(Outgoing {
                history_index: index,
                sealed: false,
                clock: 0,
                awaits_upload,
                content_digest,
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

    /// Encrypt the next unsealed outbox item for `peer` on its already-active session and persist
    /// the sealed [`OutgoingRecord`] to IndexedDB (pure local crypto + storage, zero network RPCs).
    pub(super) async fn seal_head_on_active_session(
        &mut self,
        peer: &PublicKey,
    ) -> Result<LocalSealOutcome, String> {
        let contact = self.contact(peer).ok_or("no such chat")?;
        let Some(next) = contact
            .state
            .outbox
            .iter()
            .position(|outgoing| !outgoing.sealed)
        else {
            return Ok(LocalSealOutcome::Ready);
        };
        let index = contact.state.outbox[next].history_index;
        let mut content = match self.vault.outgoing(peer, index).await {
            Ok(mut record) => std::mem::take(&mut record.content),
            Err(crate::vault::Error::Corrupt(_)) => {
                match self.recover_corrupt_outbox(peer, index).await? {
                    CorruptOutboxRecovery::Rebuilt(bytes) => bytes,
                    CorruptOutboxRecovery::Dropped { history } => {
                        return Ok(LocalSealOutcome::CorruptDropped(index, history));
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
        Ok(LocalSealOutcome::Ready)
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
        let expected_digest = self
            .contact(peer)
            .and_then(|c| c.state.outbox.iter().find(|o| o.history_index == index))
            .map(|o| o.content_digest.clone())
            .unwrap_or_default();
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
        let verified_bytes = match (&entry, content) {
            (Some(_), Some(kind)) => {
                let bytes = kind.to_bytes();
                let digest_ok = expected_digest.len() == 32
                    && crate::vault::content_kind_digest(&bytes) == expected_digest;
                digest_ok.then_some(bytes)
            }
            _ => None,
        };
        match verified_bytes {
            Some(bytes) => {
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
            None => {
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
        let _ = self
            .step(peer, &mut entries, steps)
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
    /// into `entries`, unless there already. Per-entry `vault::Error::Corrupt` is isolated (and
    /// returned in the skipped index list) so one corrupt history record referenced by a receipt
    /// never aborts or rolls back mailbox processing for healthy contacts, while transient storage
    /// errors still propagate.
    pub(super) async fn step(
        &self,
        peer: &PublicKey,
        entries: &mut BTreeMap<u64, HistoryEntry>,
        steps: impl IntoIterator<Item = (u64, Step)>,
    ) -> crate::vault::Result<Vec<u64>> {
        let mut skipped_corrupt = Vec::new();
        for (index, step) in steps {
            let entry = match entries.entry(index) {
                btree_map::Entry::Occupied(entry) => entry.into_mut(),
                btree_map::Entry::Vacant(vacant) => match self.vault.entry(peer, index).await {
                    Ok(Some(entry)) => vacant.insert(entry),
                    Ok(None) => continue,
                    Err(crate::vault::Error::Corrupt(_)) => {
                        skipped_corrupt.push(index);
                        continue;
                    }
                    Err(e) => return Err(e),
                },
            };
            entry.set_delivery(entry.delivery().after(step));
            // Waiting again, it has no place until it goes.
            if entry.delivery() == Delivery::Pending {
                entry.place = 0;
            }
        }
        Ok(skipped_corrupt)
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
        let in_flight = self.in_flight_push.get(peer).copied();
        let contact = self.contact(peer).ok_or("no such chat")?;
        let conversation_gen = contact.state.conversation_gen;
        let mut expected_digests: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for a in &contact.state.awaiting {
            if again.contains(&a.history_index) {
                expected_digests.insert(a.history_index, a.content_digest.clone());
            }
        }
        let mut sealed = BTreeSet::new();
        let mut deferred_in_flight = false;
        for o in &contact.state.outbox {
            if all_sealed && o.sealed {
                // Defer unsealing an outbox head currently in flight in `PushV2` so a successful
                // relay push still commits `Step::Pushed` without re-encrypting a duplicate.
                if !again.contains(&o.history_index)
                    && in_flight.is_some_and(|f| {
                        f.conversation_gen == conversation_gen
                            && f.history_index == o.history_index
                            && f.clock == o.clock
                    })
                {
                    deferred_in_flight = true;
                    continue;
                }
                sealed.insert(o.history_index);
                expected_digests
                    .entry(o.history_index)
                    .or_insert_with(|| o.content_digest.clone());
            }
        }
        let mut outcome = RequeueOutcome::default();
        for &index in again.union(&sealed) {
            let entry = match entries.get(&index) {
                Some(entry) => Some(entry.clone()),
                None => match self.vault.entry(peer, index).await {
                    Ok(entry) => entry,
                    Err(crate::vault::Error::Corrupt(_)) => None,
                    Err(e) => return Err(describe(&e)),
                },
            };
            let content = match &entry {
                Some(entry) => match self.vault.content(peer, index, entry).await {
                    Ok(content) => content,
                    Err(crate::vault::Error::Corrupt(_)) => None,
                    Err(e) => return Err(describe(&e)),
                },
                None => None,
            };
            let expected = expected_digests
                .get(&index)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            outcome.stage(
                peer,
                index,
                entry,
                content,
                expected,
                again.contains(&index),
            );
        }
        // No contact state changes until every fallible history and file read has completed.
        let state = &mut self.contact(peer).ok_or("no such chat")?.state;
        outcome.apply(state, &again, &sealed, &expected_digests);
        if all_sealed {
            state.needs_requeue_sealed = deferred_in_flight;
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
        expected_digest: &[u8],
        resend: bool,
    ) {
        let verified = match (entry, content) {
            (Some(entry), Some(kind)) => {
                let bytes = kind.to_bytes();
                let digest_ok = expected_digest.len() == 32
                    && crate::vault::content_kind_digest(&bytes) == expected_digest;
                if digest_ok {
                    Ok((entry, bytes))
                } else {
                    Err(Some(entry))
                }
            }
            (entry, _) => Err(entry),
        };
        let record = match verified {
            Ok((mut entry, bytes)) => {
                if resend {
                    entry.set_delivery(entry.delivery().after(Step::Resent));
                    if entry.delivery() == Delivery::Pending {
                        entry.place = 0;
                    }
                    self.history.push((index, entry));
                }
                Some(OutgoingRecord::unsealed(bytes))
            }
            Err(entry) => {
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

    fn apply(
        &self,
        state: &mut ContactState,
        again: &BTreeSet<u64>,
        sealed: &BTreeSet<u64>,
        expected_digests: &BTreeMap<u64, Vec<u8>>,
    ) {
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
                    content_digest: expected_digests.get(&index).cloned().unwrap_or_default(),
                    ..Default::default()
                }),
        );
    }

    pub(super) fn log_missing(&self, ui: &Ui, peer: &PublicKey) {
        for index in &self.dropped_missing {
            ui.log(format!(
                "Dropped pending message #{index} for {}: original history content missing or failed integrity check",
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
