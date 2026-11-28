//! Durable outgoing messages, delivery updates and session replacement recovery.

use super::attachments::ServerDeleteJob;
use super::contact::{Contact, forget_told, keep_last};
use super::sync::{confirmed_greeting_probe_eligible, uncertain_greeting_reclaim_eligible};
use super::{
    Engine, Inner, NOT_SIGNED_IN_HERE, ProtocolRpcScope, VaultStore, origin, records, same_server,
    should_require_update_for_rpc,
};
use crate::content::{Content, Events, Kind, stamp};
use crate::state::{Delivery, MessageView, Step, Ui};
use crate::transport::Fetch;
use crate::util::{describe, now, short};
use crate::vault::{
    Awaiting, CLASSICAL_APPROVAL_NONE, CLASSICAL_APPROVAL_SERVER_PQ_DISABLED,
    CLASSICAL_APPROVAL_SIGNED_OFF, ContactState, GREETING_DELIVERY_CONFIRMED,
    GREETING_DELIVERY_UNCERTAIN, GREETING_DELIVERY_UNSENT, HistoryEntry, Outgoing, OutgoingRecord,
    SECURITY_ALERT_DOWNGRADE, SECURITY_ALERT_MANIFEST_EXPIRED, SECURITY_ALERT_NONE,
    SECURITY_ALERT_PQ_REQUIRED, SealedEvents,
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
    known_at_dispatch: bool,
    /// `true` iff this is the very first wire attempt for `outgoing` (`!outgoing.dispatched`
    /// before Phase 1 persisted `dispatched = true`), so any definitive refusal proves no earlier
    /// attempt could have committed on the relay.
    first_dispatch: bool,
}

/// Next action prepared under `self.inner` during [`Engine::flush`] before dropping the lock.
enum NextPush {
    Done,
    FlushPendingGrant,
    NeedsNewSession,
    Push(Box<PreparedPush>),
}

/// Outcome of committing one completed outbox item under `self.inner`.
pub(super) enum CommitOutcome {
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
        self.flush_with_mode(peer, false).await
    }

    /// Background variant of [`Self::flush`] used by periodic `sync()` and WebSocket notification
    /// handlers so `SignInRequired` respects `declined_sign_in` and never hijacks an unrelated
    /// active `start_chat` (`R24-P2-4`).
    pub(super) async fn flush_background(&self, peer: &PublicKey) -> Result<bool, String> {
        self.flush_with_mode(peer, true).await
    }

    pub(super) async fn flush_with_mode(
        &self,
        peer: &PublicKey,
        background: bool,
    ) -> Result<bool, String> {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Ok(false);
        }
        // R25-P1-1: Only background flushes short-circuit on a prior `waits_for_sign_in` flag so
        // explicit interactive sends/accepts/starts still attempt delivery (picking up a sign-in
        // from another tab), mark the head in `ui.held`, and re-open `Dialog::SignIn` on 403.
        if (background && self.queue.waits_for_sign_in(peer))
            || self.queue.is_approval_backed_off(peer)
        {
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
        if (background && self.queue.waits_for_sign_in(peer))
            || self.queue.is_approval_backed_off(peer)
        {
            return Ok(false);
        }

        let mut changed = false;
        let mut result: Result<(), String> = Ok(());
        let mut server_deletes: Vec<ServerDeleteJob> = vec![];
        let mut signs_in_here = false;
        let mut tried_grant_flush = false;
        let mut hit_sign_in_required = false;

        loop {
            if !self.is_live(vgen) {
                return Ok(false);
            }
            if hit_sign_in_required
                || (background && self.queue.waits_for_sign_in(peer))
                || self.queue.is_approval_backed_off(peer)
            {
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
                // Never send or send receipts on an unaccepted request, provisional start, or
                // brand-new quarantined classical contact (`R11-P1-3`).
                if inner.contacts.iter().any(|c| {
                    c.peer == *peer
                        && (c.state.request || c.state.provisional || c.is_new_quarantined())
                }) {
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
                // R16-P2-9: Retry any transiently failed `cancel_upload` settlement for this peer
                // before pushing so a temporary IDB error during Cancel never strands the outbox.
                let mut cancel_retry_err = None;
                for cancel_id in self.uploads.pending_cancels_for_peer(peer) {
                    match self
                        .settle_cancelled_upload_locked(vgen, inner, peer, cancel_id)
                        .await
                    {
                        Ok((jobs, _)) => {
                            self.uploads.remove_pending_cancel(peer, &cancel_id);
                            server_deletes.extend(jobs);
                            changed = true;
                        }
                        Err(e) => {
                            if !self.is_live(vgen) {
                                return Ok(false);
                            }
                            cancel_retry_err = Some(e);
                            break;
                        }
                    }
                }
                if let Some(e) = cancel_retry_err {
                    result = Err(e);
                    break;
                }
                match inner.requeue_before_push(peer).await {
                    Ok(Some(outcome)) => {
                        if !self.is_live(vgen) {
                            return Ok(false);
                        }
                        outcome.log_missing(&self.ui, peer);
                        self.finalize_requeue_gone(vgen, inner, peer, &outcome)
                            .await;
                        if !self.is_live(vgen) {
                            return Ok(false);
                        }
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
                    && let Some(mut outgoing) = contact.state.outbox.first().cloned()
                {
                    if !self.is_live(vgen) {
                        return Ok(false);
                    }
                    if contact.state.request || contact.state.provisional {
                        step = NextPush::Done;
                        break;
                    }
                    // R11-P2-1: If this outbox head is a promoted attachment whose cancel-after-
                    // promote rollback failed transiently, refuse to announce it and complete the
                    // atomic rollback + server delete before flushing any subsequent items.
                    if let Some(cancel_rb) = self
                        .uploads
                        .get_pending_cancel_rollback(peer, outgoing.history_index)
                    {
                        if contact.state.conversation_gen != cancel_rb.conversation_gen {
                            self.uploads
                                .remove_pending_cancel_rollback(peer, outgoing.history_index);
                        } else {
                            let failed_changes =
                                [(outgoing.history_index, cancel_rb.failed_entry.clone())];
                            let rollback_res = inner
                                .with_contact_tx(peer, async |inner| {
                                    let contact = inner
                                        .contact(peer)
                                        .ok_or_else(|| "no such chat".to_string())?;
                                    contact
                                        .state
                                        .outbox
                                        .retain(|o| o.history_index != outgoing.history_index);
                                    inner
                                        .promote_upload_with(
                                            peer,
                                            &cancel_rb.pending.id,
                                            None,
                                            &records(peer, &failed_changes),
                                            &[(*peer, outgoing.history_index, None)],
                                        )
                                        .await
                                        .map_err(|e| describe(&e))
                                })
                                .await;
                            match rollback_res {
                                Ok(()) => {
                                    self.uploads.remove_pending_cancel_rollback(
                                        peer,
                                        outgoing.history_index,
                                    );
                                    if !self.is_live(vgen) {
                                        return Ok(false);
                                    }
                                    self.release(peer, outgoing.history_index);
                                    self.show_changes(inner, peer, &failed_changes);
                                    if let Ok(job) = ServerDeleteJob::for_cancelled_pending(
                                        inner.server.clone(),
                                        &cancel_rb.pending,
                                    ) {
                                        server_deletes.push(job);
                                    }
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
                    // R16-P2-5 + R16-P2-7: If its `UPLOAD_STATE_WAITING` checkpoint exists
                    // (including at `history_index == 0`) and its `PendingUpload` record is
                    // missing or corrupt (e.g. unlock cleanup failed transiently), fail and
                    // unblock the head here once storage recovers.
                    if outgoing.awaits_upload {
                        let waiting_cp = inner
                            .vault
                            .tracked_upload_checkpoints(Some(peer))
                            .into_iter()
                            .find_map(|cp| {
                                let id = <[u8; 16]>::try_from(cp.id.as_slice()).ok()?;
                                (cp.upload_state == crate::vault::UPLOAD_STATE_WAITING
                                    && super::checkpoint_matches_outbox(&cp, &id, &outgoing))
                                .then_some(id)
                            });
                        if let Some(att_id) = waiting_cp
                            && !self.is_cancelled(&att_id)
                        {
                            match inner.vault.upload(peer, &att_id).await {
                                _ if !self.is_live(vgen) => return Ok(false),
                                Ok(Some(_)) => {}
                                Ok(None) | Err(crate::vault::Error::Corrupt(_)) => {
                                    match self
                                        .fail_waiting(inner, peer, outgoing.history_index)
                                        .await
                                    {
                                        Ok(()) => {
                                            if !self.is_live(vgen) {
                                                return Ok(false);
                                            }
                                            let _ = inner.vault.forget_upload(peer, &att_id).await;
                                            if !self.is_live(vgen) {
                                                return Ok(false);
                                            }
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
                            }
                        }
                        step = NextPush::Done;
                        break;
                    }
                    let needs_new_session = contact.session.needs_new_session();
                    let pause_sealing = contact.state.quarantined
                        || contact.state.classical_approval_needed != CLASSICAL_APPROVAL_NONE
                        || contact.state.security_alert != SECURITY_ALERT_NONE;
                    // R12-P1-4 + R13-P2-1 + R13-P1-3 + R14-P2-2 + R14-P2-3 + R16-P1-2 + R16-P2-5 +
                    // R16-P2-6 + R16-P2-7 + R17-P1-4 + R17-P2-3: Guard un-dispatched attachments
                    // tracked by a `STARTED` or `ANNOUNCED` checkpoint — aborting ANY cancelled
                    // attachment regardless of `cp.uploaded`, blocking 0-chunk uploads without a
                    // live file handle (unless already complete on disk), AND settling incomplete
                    // orphaned multi-chunk uploads before publishing an unresumable pointer.
                    let mut first_dispatch_att_id: Option<[u8; 16]> = None;
                    let mut first_dispatch_needs_file = false;
                    if !outgoing.dispatched {
                        first_dispatch_att_id =
                            <[u8; 16]>::try_from(outgoing.attachment_id.as_slice()).ok();
                        let tracked_started: Vec<(crate::vault::UploadCheckpoint, [u8; 16])> =
                            inner
                                .vault
                                .tracked_upload_checkpoints(Some(peer))
                                .into_iter()
                                .filter_map(|cp| {
                                    if matches!(
                                        cp.upload_state,
                                        crate::vault::UPLOAD_STATE_STARTED
                                            | crate::vault::UPLOAD_STATE_ANNOUNCED
                                    ) {
                                        let id = <[u8; 16]>::try_from(cp.id.as_slice()).ok()?;
                                        Some((cp, id))
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                        if !tracked_started.is_empty() {
                            let find_cp = |att_id: [u8; 16]| {
                                tracked_started
                                    .iter()
                                    .find(|(_, id)| *id == att_id)
                                    .cloned()
                            };
                            let mut matched_cp = first_dispatch_att_id.and_then(find_cp);
                            if matched_cp.is_none() {
                                match inner.vault.entry(peer, outgoing.history_index).await {
                                    _ if !self.is_live(vgen) => return Ok(false),
                                    Ok(Some(entry)) => {
                                        if let Some(Kind::Attachment(ptr)) =
                                            entry.content.as_ref().and_then(|c| c.kind.as_ref())
                                            && let Ok(att_id) =
                                                <[u8; 16]>::try_from(ptr.id.as_slice())
                                        {
                                            first_dispatch_att_id = Some(att_id);
                                            matched_cp = find_cp(att_id);
                                        }
                                    }
                                    Ok(None) | Err(crate::vault::Error::Corrupt(_)) => {
                                        // R14-P2-2 + R15-P2-9 + R16-P2-7: Inspect unsealed
                                        // `OutgoingRecord` first; if it proves a non-attachment
                                        // `Kind`, skip checkpoint fallback so an unrelated
                                        // checkpoint can never collide with this head.
                                        let mut proved_non_attachment = false;
                                        if !outgoing.sealed {
                                            match inner
                                                .vault
                                                .outgoing(peer, outgoing.history_index)
                                                .await
                                            {
                                                _ if !self.is_live(vgen) => return Ok(false),
                                                Ok(rec) => match Kind::from_bytes(&rec.content) {
                                                    Some(Kind::Attachment(ptr)) => {
                                                        if let Ok(att_id) =
                                                            <[u8; 16]>::try_from(ptr.id.as_slice())
                                                        {
                                                            first_dispatch_att_id = Some(att_id);
                                                            matched_cp = find_cp(att_id);
                                                        } else {
                                                            proved_non_attachment = true;
                                                        }
                                                    }
                                                    Some(_) => {
                                                        proved_non_attachment = true;
                                                    }
                                                    None => {}
                                                },
                                                Err(crate::vault::Error::Corrupt(_)) => {}
                                                Err(e) => {
                                                    result = Err(describe(&e));
                                                    step = NextPush::Done;
                                                    break;
                                                }
                                            }
                                        }
                                        if matched_cp.is_none() && !proved_non_attachment {
                                            matched_cp = tracked_started
                                                .iter()
                                                .find(|(cp, id)| {
                                                    super::checkpoint_matches_outbox(
                                                        cp, id, &outgoing,
                                                    )
                                                })
                                                .cloned();
                                        }
                                    }
                                    Err(e) => {
                                        result = Err(describe(&e));
                                        step = NextPush::Done;
                                        break;
                                    }
                                }
                            }
                            if let Some((cp, att_id)) = matched_cp {
                                first_dispatch_att_id = Some(att_id);
                                let is_zero_chunk = cp.uploaded == 0;
                                first_dispatch_needs_file = is_zero_chunk;
                                // R17-P1-4: Abort pre-wire dispatch for ANY cancelled attachment
                                // regardless of `cp.uploaded` so waiting `cancel_upload` can fail
                                // it without disclosing the attachment pointer on the wire.
                                if self.is_cancelled(&att_id) {
                                    step = NextPush::Done;
                                    break;
                                }
                                let need_zero_guard =
                                    is_zero_chunk && !self.uploads.has_file(peer, &att_id);
                                let need_upload_check =
                                    need_zero_guard || !self.uploads.is_running(&att_id);
                                if need_upload_check {
                                    match inner.vault.upload(peer, &att_id).await {
                                        _ if !self.is_live(vgen) => return Ok(false),
                                        Ok(Some(pending)) => {
                                            // R17-P2-3 + R19-P2-4: For any started non-running
                                            // `PendingUpload` (1-chunk or multi-chunk, even if the
                                            // local file handle is still cached after a failed
                                            // `forget_upload`), detect durable completion via
                                            // `chunks_kept`, forget the stale upload, and clear
                                            // its paused card/cache.
                                            if pending.has_started_state()
                                                && !self.uploads.is_running(&att_id)
                                            {
                                                let total_chunks =
                                                    session::attachment::chunk_count(pending.size);
                                                let kept = match inner
                                                    .vault
                                                    .chunks_kept(peer, &att_id)
                                                    .await
                                                {
                                                    _ if !self.is_live(vgen) => return Ok(false),
                                                    Ok(n) => u64::from(n),
                                                    Err(e) => {
                                                        result = Err(describe(&e));
                                                        step = NextPush::Done;
                                                        break;
                                                    }
                                                };
                                                if self.uploads.is_server_completed(&att_id)
                                                    || u64::from(pending.uploaded) >= total_chunks
                                                    || kept >= total_chunks
                                                {
                                                    match inner
                                                        .vault
                                                        .forget_upload(peer, &att_id)
                                                        .await
                                                    {
                                                        Ok(()) => {
                                                            if !self.is_live(vgen) {
                                                                return Ok(false);
                                                            }
                                                            // R18-P2-7: Clear any stale paused UI
                                                            // card and cached file handle left by
                                                            // an earlier failed `forget_upload`.
                                                            self.uploads
                                                                .clear_server_completed(&att_id);
                                                            self.remove_attachment_caches(
                                                                peer, &att_id,
                                                            );
                                                            self.ui.uploads.update(|uploads| {
                                                                uploads.retain(|u| u.id != att_id)
                                                            });
                                                            changed = true;
                                                            continue;
                                                        }
                                                        Err(e) => {
                                                            if !self.is_live(vgen) {
                                                                return Ok(false);
                                                            }
                                                            result = Err(describe(&e));
                                                            step = NextPush::Done;
                                                            break;
                                                        }
                                                    }
                                                } else if super::attachments::upload_of(&pending)
                                                    .is_err()
                                                {
                                                    // R24-P2-1: Malformed incomplete `STARTED` /
                                                    // `ANNOUNCED` record (e.g. empty/corrupt upload
                                                    // token) can never resume. Recover any 32-byte
                                                    // delete key onto `server_deletes`, atomically
                                                    // fail the outbox item + forget the upload, and
                                                    // clear caches/UI so flush neither ships a dead
                                                    // partial pointer nor wedges on 0-chunk rows.
                                                    let initial_del_key =
                                                        super::attachments::copy_zeroizing_array::<
                                                            { session::attachment::KEY_LENGTH },
                                                        >(
                                                            &pending.key
                                                        );
                                                    match self
                                                        .fail_unresumable_upload_outbox(
                                                            vgen,
                                                            inner,
                                                            peer,
                                                            outgoing.history_index,
                                                            outgoing.sealed,
                                                            att_id,
                                                            initial_del_key,
                                                            pending.name.clone(),
                                                            &mut server_deletes,
                                                        )
                                                        .await
                                                    {
                                                        Ok(true) => {
                                                            changed = true;
                                                            continue;
                                                        }
                                                        Ok(false) => return Ok(false),
                                                        Err(e) => {
                                                            result = Err(e);
                                                            step = NextPush::Done;
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Ok(None) | Err(crate::vault::Error::Corrupt(_)) => {
                                            // R15-P2-6 + R16-P2-6: Check completion via fallible
                                            // size + `chunks_kept` lookups so transient storage
                                            // errors never fail a completed upload.
                                            let size = match inner
                                                .attachment_size_for_outbox(
                                                    peer,
                                                    outgoing.history_index,
                                                    &att_id,
                                                    outgoing.sealed,
                                                )
                                                .await
                                            {
                                                _ if !self.is_live(vgen) => return Ok(false),
                                                Ok(size) => size,
                                                Err(e) => {
                                                    result = Err(describe(&e));
                                                    step = NextPush::Done;
                                                    break;
                                                }
                                            };
                                            let is_complete = if let Some(size) = size {
                                                let total_chunks =
                                                    session::attachment::chunk_count(size);
                                                let kept = match inner
                                                    .vault
                                                    .chunks_kept(peer, &att_id)
                                                    .await
                                                {
                                                    _ if !self.is_live(vgen) => return Ok(false),
                                                    Ok(n) => u64::from(n),
                                                    Err(e) => {
                                                        result = Err(describe(&e));
                                                        step = NextPush::Done;
                                                        break;
                                                    }
                                                };
                                                u64::from(cp.uploaded) >= total_chunks
                                                    || kept >= total_chunks
                                            } else {
                                                false
                                            };
                                            if is_complete {
                                                // R16-P1-2: Propagate `forget_upload` errors so
                                                // persistent write failures release locks instead
                                                // of busy-looping on this head.
                                                match inner.vault.forget_upload(peer, &att_id).await
                                                {
                                                    Ok(()) => {
                                                        if !self.is_live(vgen) {
                                                            return Ok(false);
                                                        }
                                                        self.remove_attachment_caches(
                                                            peer, &att_id,
                                                        );
                                                        self.ui.uploads.update(|uploads| {
                                                            uploads.retain(|u| u.id != att_id)
                                                        });
                                                        changed = true;
                                                        continue;
                                                    }
                                                    Err(e) => {
                                                        if !self.is_live(vgen) {
                                                            return Ok(false);
                                                        }
                                                        result = Err(describe(&e));
                                                        step = NextPush::Done;
                                                        break;
                                                    }
                                                }
                                            }
                                            // R25-P2-4: Mirror malformed-upload cleanup for
                                            // incomplete orphan checkpoints (`Ok(None)` or
                                            // `Err(Corrupt(_))`): recover `ptr.key` for
                                            // `DeleteCompleted`, atomically fail outbox + forget
                                            // upload, and clear cancellation/caches/UI.
                                            match self
                                                .fail_unresumable_upload_outbox(
                                                    vgen,
                                                    inner,
                                                    peer,
                                                    outgoing.history_index,
                                                    outgoing.sealed,
                                                    att_id,
                                                    None,
                                                    String::new(),
                                                    &mut server_deletes,
                                                )
                                                .await
                                            {
                                                Ok(true) => {
                                                    changed = true;
                                                    continue;
                                                }
                                                Ok(false) => return Ok(false),
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
                                    }
                                }
                                if need_zero_guard {
                                    step = NextPush::Done;
                                    break;
                                }
                            }
                        }
                        // R17-P1-4 + R22-P2-11 + R23-P2-3: Check in-memory cancellation, durable
                        // `ContactState.deleted_attachments` / `HistoryEntry.gone`, AND server-clock
                        // expiry (`ptr.expires <= server_now`) before sealing or pushing any
                        // un-dispatched attachment (even after reload once upload checkpoints are
                        // gone).
                        let server_now = inner.client.clock().now();
                        let mut first_dispatch_entry_gone = false;
                        let mut first_dispatch_att_expired = false;
                        match inner.vault.entry(peer, outgoing.history_index).await {
                            _ if !self.is_live(vgen) => return Ok(false),
                            Ok(Some(entry)) => {
                                first_dispatch_entry_gone = entry.gone;
                                if let Some(Kind::Attachment(ptr)) =
                                    entry.content.as_ref().and_then(|c| c.kind.as_ref())
                                {
                                    if ptr.expires > 0 && ptr.expires <= server_now {
                                        first_dispatch_att_expired = true;
                                    }
                                    if first_dispatch_att_id.is_none()
                                        && let Ok(att_id) = <[u8; 16]>::try_from(ptr.id.as_slice())
                                    {
                                        first_dispatch_att_id = Some(att_id);
                                    }
                                }
                            }
                            Ok(None) | Err(crate::vault::Error::Corrupt(_)) => {
                                if !outgoing.sealed {
                                    match inner.vault.outgoing(peer, outgoing.history_index).await {
                                        _ if !self.is_live(vgen) => return Ok(false),
                                        Ok(rec) => {
                                            if let Some(Kind::Attachment(ptr)) =
                                                Kind::from_bytes(&rec.content)
                                            {
                                                if ptr.expires > 0 && ptr.expires <= server_now {
                                                    first_dispatch_att_expired = true;
                                                }
                                                if first_dispatch_att_id.is_none()
                                                    && let Ok(att_id) =
                                                        <[u8; 16]>::try_from(ptr.id.as_slice())
                                                {
                                                    first_dispatch_att_id = Some(att_id);
                                                }
                                            }
                                        }
                                        Err(crate::vault::Error::Corrupt(_)) => {}
                                        Err(e) => {
                                            result = Err(describe(&e));
                                            step = NextPush::Done;
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                result = Err(describe(&e));
                                step = NextPush::Done;
                                break;
                            }
                        }
                        if first_dispatch_att_id.is_some_and(|id| self.is_cancelled(&id)) {
                            step = NextPush::Done;
                            break;
                        }
                        let durably_deleted = first_dispatch_entry_gone
                            || first_dispatch_att_expired
                            || first_dispatch_att_id.is_some_and(|id| {
                                inner
                                    .contacts
                                    .iter()
                                    .any(|c| c.peer == *peer && c.is_attachment_deleted(&id))
                            });
                        if durably_deleted {
                            match self
                                .settle_gone_undispatched_outbox(
                                    vgen,
                                    inner,
                                    peer,
                                    outgoing.history_index,
                                    first_dispatch_att_id,
                                )
                                .await
                            {
                                Ok(true) => {
                                    changed = true;
                                    continue;
                                }
                                Ok(false) => return Ok(false),
                                Err(e) => {
                                    result = Err(e);
                                    step = NextPush::Done;
                                    break;
                                }
                            }
                        }
                    }
                    if !outgoing.sealed {
                        if needs_new_session {
                            // Pause sealing if waiting on explicit user action (quarantine /
                            // classical approval / security alert).
                            if pause_sealing {
                                step = NextPush::Done;
                                break;
                            }
                            step = NextPush::NeedsNewSession;
                            break;
                        }
                        // R22-P1-1: Never seal a new outbox message onto an active classical
                        // session (including a peer-confirmed classical session) while local PQ
                        // policy blocks classical transmission (e.g. `strict_pq`, live downgrade
                        // alarm, or refused `#chat=...&pq=1` pin).
                        let strict_pq = inner.client.pq_config().strict_pq;
                        let local_pq = inner.local_pq_enabled();
                        let blocked_classical = inner.contacts.iter().any(|c| {
                            c.peer == *peer
                                && c.is_classical_session()
                                && super::classical_policy_blocked(
                                    strict_pq,
                                    local_pq,
                                    c.session.peer_pq_state(),
                                )
                        });
                        if blocked_classical {
                            if strict_pq
                                && let Some(c) = inner.contact(peer)
                                && c.state.security_alert != SECURITY_ALERT_PQ_REQUIRED
                                && c.state.security_alert != SECURITY_ALERT_DOWNGRADE
                            {
                                c.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                                if inner.save_state().await.is_err() {
                                    inner.unsaved_state = true;
                                }
                                if !self.is_live(vgen) {
                                    return Ok(false);
                                }
                                self.refresh_contacts(inner);
                            }
                            step = NextPush::Done;
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
                                Ok(CorruptOutboxRecovery::Dropped {
                                    history,
                                    was_dispatched,
                                }) => {
                                    self.release(peer, outgoing.history_index);
                                    if !was_dispatched {
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
                                    }
                                    self.ui.log(if was_dispatched {
                                        format!(
                                            "Dropped corrupt already-dispatched outbox record #{} for {} (delivery status unknown; preserved attachment and refused to re-encrypt and duplicate: {reason})",
                                            outgoing.history_index,
                                            short(peer)
                                        )
                                    } else {
                                        format!(
                                            "Dropped corrupt outbox record #{} for {} ({reason})",
                                            outgoing.history_index,
                                            short(peer)
                                        )
                                    });
                                    self.show_changes(inner, peer, &history);
                                    // R16-P1-1: Settling a dispatched head unblocks deferred
                                    // `needs_requeue_sealed` before the next item seals/pushes.
                                    if was_dispatched
                                        && inner
                                            .contact(peer)
                                            .is_some_and(|c| c.state.needs_requeue_sealed)
                                    {
                                        match inner.requeue_before_push(peer).await {
                                            Ok(Some(outcome)) => {
                                                if !self.is_live(vgen) {
                                                    return Ok(false);
                                                }
                                                outcome.log_missing(&self.ui, peer);
                                                self.finalize_requeue_gone(
                                                    vgen, inner, peer, &outcome,
                                                )
                                                .await;
                                                if !self.is_live(vgen) {
                                                    return Ok(false);
                                                }
                                                self.show_changes(inner, peer, &outcome.history);
                                            }
                                            Ok(None) => {
                                                if !self.is_live(vgen) {
                                                    return Ok(false);
                                                }
                                            }
                                            Err(e) => {
                                                result = Err(e);
                                                step = NextPush::Done;
                                                break;
                                            }
                                        }
                                    }
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

                    // If this sealed record belongs to an older session than `active_id` and has
                    // NOT been dispatched on the wire yet, requeue sealed outbox items on the
                    // current active session before transmitting. Already-dispatched records must
                    // be reconciled with the relay using their original `client_message_id` first
                    // so a reload or lost response never duplicates a delivered message.
                    let stale_session = !outgoing.dispatched
                        && !record.session_id.is_empty()
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
                                self.finalize_requeue_gone(vgen, inner, peer, &outcome)
                                    .await;
                                if !self.is_live(vgen) {
                                    return Ok(false);
                                }
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
                            Ok(CorruptOutboxRecovery::Dropped {
                                history,
                                was_dispatched,
                            }) => {
                                self.release(peer, outgoing.history_index);
                                if !was_dispatched {
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
                                }
                                if was_dispatched {
                                    self.ui.log(format!(
                                        "Dropped incomplete already-dispatched outbox record #{} for {} (delivery status unknown; preserved attachment and refused to re-encrypt and duplicate)",
                                        outgoing.history_index,
                                        short(peer)
                                    ));
                                }
                                self.show_changes(inner, peer, &history);
                                // R16-P1-1: Settling a dispatched head unblocks deferred
                                // `needs_requeue_sealed` before the next item seals/pushes.
                                if was_dispatched
                                    && inner
                                        .contact(peer)
                                        .is_some_and(|c| c.state.needs_requeue_sealed)
                                {
                                    match inner.requeue_before_push(peer).await {
                                        Ok(Some(outcome)) => {
                                            if !self.is_live(vgen) {
                                                return Ok(false);
                                            }
                                            outcome.log_missing(&self.ui, peer);
                                            self.finalize_requeue_gone(vgen, inner, peer, &outcome)
                                                .await;
                                            if !self.is_live(vgen) {
                                                return Ok(false);
                                            }
                                            self.show_changes(inner, peer, &outcome.history);
                                        }
                                        Ok(None) => {
                                            if !self.is_live(vgen) {
                                                return Ok(false);
                                            }
                                        }
                                        Err(e) => {
                                            result = Err(e);
                                            step = NextPush::Done;
                                            break;
                                        }
                                    }
                                }
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

                    // Persist `Outgoing.dispatched = true` (and `GREETING_DELIVERY_UNCERTAIN` when
                    // promoted from `UNSENT`) BEFORE dropping `guard` and transmitting `PushV2` so
                    // a reload or lost response never lets `requeue_sealed` unseal and duplicate an
                    // already-dispatched message.
                    // R8-P2-2: Only promote `UNSENT -> UNCERTAIN` when this sealed record actually
                    // carries an initial for the CURRENT active session (never when retrying old
                    // ciphertext from a superseded session `S1` while `S2` is still `UNSENT`).
                    let first_dispatch = !outgoing.dispatched;
                    // R13-P1-3 + R17-P1-4 + R22-P2-11: Re-check synchronously right before
                    // persisting `dispatched = true` so a `cancel_upload` or durable deletion
                    // arriving during `vault.outgoing(...)` / sealing (for ANY un-dispatched
                    // attachment) never marks it dispatched or discloses its pointer.
                    if first_dispatch
                        && let Some(att_id) = first_dispatch_att_id
                        && (self.is_cancelled(&att_id)
                            || (first_dispatch_needs_file && !self.uploads.has_file(peer, &att_id))
                            || inner
                                .contacts
                                .iter()
                                .any(|c| c.peer == *peer && c.is_attachment_deleted(&att_id)))
                    {
                        step = NextPush::Done;
                        break;
                    }
                    let promoted_from_unsent = !record.carried_initial.is_empty()
                        && inner.contacts.iter().any(|c| {
                            c.peer == *peer
                                && c.state.greeting_delivery == GREETING_DELIVERY_UNSENT
                                && (record.session_id.is_empty()
                                    || c.session.active_id().is_some_and(|id| {
                                        id.as_slice() == record.session_id.as_slice()
                                    }))
                        });
                    // R13-P1-2 + R14-P1-1 + R14-P1-2 + R22-P1-1: Never transmit a classical
                    // carried initial OR a message on an active classical session (including a
                    // peer-confirmed classical session with empty `carried_initial`) when current
                    // local PQ policy blocks classical sessions.
                    let carries_classical_initial = !record.carried_initial.is_empty()
                        && session::protocol::mailbox_v2::decode_carried_initial(
                            &record.carried_initial,
                        )
                        .is_some_and(|w| w.version < 2);
                    let on_active_classical_session = inner.contacts.iter().any(|c| {
                        c.peer == *peer
                            && c.is_classical_session()
                            && (record.session_id.is_empty()
                                || c.session.active_id().is_some_and(|id| {
                                    id.as_slice() == record.session_id.as_slice()
                                }))
                    });
                    if carries_classical_initial || on_active_classical_session {
                        let strict_pq = inner.client.pq_config().strict_pq;
                        let local_pq = inner.local_pq_enabled();
                        let blocked = inner.contacts.iter().any(|c| {
                            c.peer == *peer
                                && super::classical_policy_blocked(
                                    strict_pq,
                                    local_pq,
                                    c.session.peer_pq_state(),
                                )
                        });
                        if blocked {
                            // R15-P1-2: If this sealed record was ALREADY dispatched on a
                            // superseded classical session before a PQ upgrade, settle it cleanly
                            // via `Step::Unknown` instead of permanently wedging the upgraded PQ
                            // session's subsequent messages behind it.
                            let session_matches = inner.contacts.iter().any(|c| {
                                c.peer == *peer
                                    && if record.session_id.is_empty() {
                                        !c.session.security().is_some_and(|s| s.is_pq)
                                    } else {
                                        c.session.active_id().is_some_and(|id| {
                                            id.as_slice() == record.session_id.as_slice()
                                        })
                                    }
                            });
                            if outgoing.dispatched && !session_matches {
                                match self
                                    .commit_outbox_item(
                                        vgen,
                                        inner,
                                        peer,
                                        &outgoing,
                                        Step::Unknown,
                                        outgoing.clock,
                                        false,
                                        &mut server_deletes,
                                    )
                                    .await
                                {
                                    Ok(CommitOutcome::Committed) => {
                                        self.release(peer, outgoing.history_index);
                                        // R16-P1-1: Settling a superseded dispatched head unblocks
                                        // deferred `needs_requeue_sealed` so the next queued item
                                        // seals/pushes cleanly with `session_matches == true`.
                                        if inner
                                            .contact(peer)
                                            .is_some_and(|c| c.state.needs_requeue_sealed)
                                        {
                                            match inner.requeue_before_push(peer).await {
                                                Ok(Some(outcome)) => {
                                                    if !self.is_live(vgen) {
                                                        return Ok(false);
                                                    }
                                                    outcome.log_missing(&self.ui, peer);
                                                    self.finalize_requeue_gone(
                                                        vgen, inner, peer, &outcome,
                                                    )
                                                    .await;
                                                    if !self.is_live(vgen) {
                                                        return Ok(false);
                                                    }
                                                    self.show_changes(
                                                        inner,
                                                        peer,
                                                        &outcome.history,
                                                    );
                                                }
                                                Ok(None) => {
                                                    if !self.is_live(vgen) {
                                                        return Ok(false);
                                                    }
                                                }
                                                Err(e) => {
                                                    result = Err(e);
                                                    step = NextPush::Done;
                                                    break;
                                                }
                                            }
                                        }
                                        changed = true;
                                        continue;
                                    }
                                    Ok(CommitOutcome::Aborted) => return Ok(false),
                                    Err(e) => {
                                        result = Err(e);
                                        step = NextPush::Done;
                                        break;
                                    }
                                }
                            }
                            if strict_pq
                                && let Some(c) = inner.contact(peer)
                                && c.state.security_alert != SECURITY_ALERT_PQ_REQUIRED
                                && c.state.security_alert != SECURITY_ALERT_DOWNGRADE
                            {
                                c.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                                if inner.save_state().await.is_err() {
                                    inner.unsaved_state = true;
                                }
                                if !self.is_live(vgen) {
                                    return Ok(false);
                                }
                                self.refresh_contacts(inner);
                            }
                            step = NextPush::Done;
                            break;
                        }
                    }
                    if first_dispatch || promoted_from_unsent {
                        let target_index = outgoing.history_index;
                        let target_clock = outgoing.clock;
                        if let Err(e) = inner
                            .with_contact_tx(peer, async |inner| {
                                if let Some(contact) = inner.contact(peer) {
                                    if let Some(head) = contact.state.outbox.first_mut()
                                        && head.history_index == target_index
                                        && head.sealed
                                        && head.clock == target_clock
                                    {
                                        head.dispatched = true;
                                    }
                                    if promoted_from_unsent
                                        && contact.state.greeting_delivery
                                            == GREETING_DELIVERY_UNSENT
                                    {
                                        contact.state.greeting_delivery =
                                            GREETING_DELIVERY_UNCERTAIN;
                                        if contact.state.greeting_sent_at == 0 {
                                            contact.state.greeting_sent_at = now();
                                        }
                                    }
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
                        // R13-P1-3 + R14-P1-5: If `cancel_upload` arrived during the
                        // `dispatched = true` IDB save (still strictly BEFORE `PushV2` has ever
                        // been transmitted on the wire), revert `dispatched = false` directly in
                        // memory (NEVER rolling back to `true` via `with_contact_tx` on transient
                        // IDB failure!) and mark `unsaved_state = true` if persistence fails so
                        // waiting `cancel_upload` always sees `dispatched == false` and settles
                        // `fail_waiting` without ever flushing the cancelled pointer.
                        if first_dispatch
                            && let Some(att_id) = first_dispatch_att_id
                            && (self.is_cancelled(&att_id)
                                || (first_dispatch_needs_file
                                    && !self.uploads.has_file(peer, &att_id)))
                        {
                            if let Some(contact) = inner.contact(peer) {
                                if let Some(head) = contact.state.outbox.first_mut()
                                    && head.history_index == target_index
                                    && head.clock == target_clock
                                {
                                    head.dispatched = false;
                                }
                                if promoted_from_unsent
                                    && contact.state.greeting_delivery
                                        == GREETING_DELIVERY_UNCERTAIN
                                {
                                    contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                                    contact.state.greeting_sent_at = 0;
                                }
                            }
                            if inner.save_state().await.is_err() {
                                inner.unsaved_state = true;
                            }
                            if !self.is_live(vgen) {
                                return Ok(false);
                            }
                            step = NextPush::Done;
                            break;
                        }
                        outgoing.dispatched = true;
                    }

                    let (conversation_gen, session_id, known_at_dispatch) = {
                        let c = inner.contacts.iter().find(|c| c.peer == *peer);
                        let conv_gen = c.map_or(0, |c| c.state.conversation_gen);
                        let sid = if !record.session_id.is_empty() {
                            record.session_id.clone()
                        } else {
                            c.and_then(|c| c.session.active_id().map(|id| id.to_vec()))
                                .unwrap_or_default()
                        };
                        let known = c.is_some_and(|c| c.session.is_known_by_peer());
                        (conv_gen, sid, known)
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
                        known_at_dispatch,
                        first_dispatch,
                    }));
                    break;
                }
                // If the outbox is empty, `Events { accepted: true }` is queued (e.g. user
                // accepted a cancelled crossed-start request whose dead outbound session was
                // discarded), and no active session exists yet, establish a fresh session so the
                // acceptance immediately reaches the peer instead of stalling until the next text.
                if matches!(step, NextPush::Done)
                    && let Some(contact) = inner.contact(peer)
                    && contact.state.outbox.is_empty()
                    && !contact.state.request
                    && !contact.state.quarantined
                    && contact.state.classical_approval_needed == CLASSICAL_APPROVAL_NONE
                    && contact.state.security_alert == SECURITY_ALERT_NONE
                    && contact.session.needs_new_session()
                    && contact.state.events.as_ref().is_some_and(|e| e.accepted)
                {
                    step = NextPush::NeedsNewSession;
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
                        .ensure_session_for_outbox(vgen, peer, &mut server_deletes, background)
                        .await
                    {
                        Ok(RekeyOutcome::Aborted) => return Ok(false),
                        Ok(RekeyOutcome::Ready) => continue,
                        Ok(RekeyOutcome::Paused) => {
                            if self.queue.waits_for_sign_in(peer) {
                                hit_sign_in_required = true;
                            }
                            break;
                        }
                        Ok(RekeyOutcome::ContactGone) => break,
                        Ok(RekeyOutcome::Failed) => {
                            // R8-P1-2: `fail_waiting` already failed every unsealed item in
                            // `outbox` (and is a no-op when `outbox` is empty with
                            // `events.accepted == true`). Record approval backoff and break so an
                            // empty-outbox acceptance rekey never livelocks on `NotFound`/`InvalidKeys`.
                            self.queue.record_approval_backoff(peer);
                            changed = true;
                            break;
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
                        known_at_dispatch,
                        first_dispatch,
                    } = *prepared;
                    let push_res: session::Result<()> = Fetch::client_without_refused_hook(&server)
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
                    // R27-P2-1 + R27-P2-2 + R27-P2-3: Any same-origin `PushV2` response that
                    // passed Worker auth (`Ok` or post-auth server refusal != `SignInRequired`)
                    // proves the origin session cookie is valid, clearing all latched origin
                    // sign-in waits and releasing non-`awaits_upload` `ui.held` rows. On transient
                    // non-403 errors after `head.dispatched = true`, release `outgoing.history_index`
                    // from `ui.held` so it never shows a stale `"waiting for server sign-in"` /
                    // broken `"Cancel it"` button.
                    if signs_in_here
                        && (push_res.is_ok()
                            || push_res.as_ref().is_err_and(|e| {
                                e.is_server_refusal() && e.kind() != ErrorKind::SignInRequired
                            }))
                    {
                        self.on_origin_auth_proven_locked(vgen, inner);
                    } else if push_res
                        .as_ref()
                        .is_err_and(|e| e.kind() != ErrorKind::SignInRequired)
                    {
                        self.release(peer, outgoing.history_index);
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
                                contact.state.greeting_sent_at = 0;
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
                    // message). Only clear `Outgoing.dispatched` on the VERY FIRST wire attempt
                    // (`first_dispatch == true`) after a definitive server refusal, because on a
                    // retry after a lost response/reload (`first_dispatch == false`) even
                    // `WriteTokenRejected`, `SignInRequired`, `LimitExceeded`, or `MailboxFull`
                    // run before dedup and can occur AFTER an earlier attempt committed!
                    if let Err(ref e) = push_res {
                        inner.in_flight_push.remove(peer);
                        let can_clear_dispatched = e.is_server_refusal() && first_dispatch;
                        if can_clear_dispatched {
                            let cleared = inner.contact(peer).is_some_and(|c| {
                                if let Some(head) = c.state.outbox.first_mut()
                                    && head.history_index == outgoing.history_index
                                    && head.sealed
                                    && head.clock == outgoing.clock
                                    && head.dispatched
                                {
                                    head.dispatched = false;
                                    true
                                } else {
                                    false
                                }
                            });
                            if cleared {
                                if let Err(save_err) = inner.save_state().await {
                                    result = Err(describe(&save_err));
                                    break;
                                }
                                if !self.is_live(vgen) {
                                    return Ok(false);
                                }
                            }
                            if !session_matches {
                                continue;
                            }
                        } else if !session_matches
                            && !(e.kind() == ErrorKind::SignInRequired && signs_in_here)
                        {
                            // R7-P1-1: If a previously dispatched head (`!first_dispatch`) hits a
                            // definitive refusal (`WriteTokenRejected`, foreign `SignInRequired`,
                            // or server-refusal `LimitExceeded`) AFTER its session was already
                            // retired or replaced (`!session_matches`), settle this head as
                            // delivery-unknown (`Step::Unknown`, preserving `Awaiting` and
                            // attachments) and continue draining the remaining outbox on the
                            // current/new session without retiring any replacement session!
                            let settle_superseded_head = !first_dispatch
                                && (e.kind() == ErrorKind::WriteTokenRejected
                                    || (e.kind() == ErrorKind::SignInRequired && !signs_in_here)
                                    || (e.is_server_refusal()
                                        && e.kind() == ErrorKind::LimitExceeded));
                            if settle_superseded_head {
                                match self
                                    .commit_outbox_item(
                                        vgen,
                                        inner,
                                        peer,
                                        &outgoing,
                                        Step::Unknown,
                                        outgoing.clock,
                                        false,
                                        &mut server_deletes,
                                    )
                                    .await
                                {
                                    Ok(CommitOutcome::Committed) => {
                                        self.release(peer, outgoing.history_index);
                                        self.ui.log(format!(
                                            "Delivery status unknown for message #{} to {} after session replacement/revocation ({}); advancing outbox without duplicating.",
                                            outgoing.history_index,
                                            short(peer),
                                            describe(e)
                                        ));
                                        changed = true;
                                        continue;
                                    }
                                    Ok(CommitOutcome::Aborted) => return Ok(false),
                                    Err(err) => {
                                        result = Err(err);
                                        break;
                                    }
                                }
                            }
                            self.check_protocol_error(ProtocolRpcScope::CoreV2, e);
                            result = Err(describe(e));
                            break;
                        }
                    }

                    match push_res {
                        Ok(()) => {
                            self.queue.clear_peer_sign_in_wait(peer);
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
                            if known && !known_at_dispatch {
                                // Pre-approval `PushV2` raced with peer acceptance on this exact
                                // session (`is_known_by_peer` flipped true while `PushV2` was in
                                // flight): clear approval backoff and retry on the working session
                                // instead of retiring it.
                                self.clear_approval_backoff(peer);
                                continue;
                            }
                            if known {
                                // Peer previously accepted us BEFORE dispatch and has since
                                // revoked/deleted the chat.
                                if !first_dispatch {
                                    // An earlier dispatch lost its response before the token was
                                    // revoked: settle this head as delivery-unknown (preserving
                                    // attachments and allowing a late receipt to settle history)
                                    // so retiring the session NEVER reseals & duplicates it!
                                    match self
                                        .commit_outbox_item(
                                            vgen,
                                            inner,
                                            peer,
                                            &outgoing,
                                            Step::Unknown,
                                            outgoing.clock,
                                            false,
                                            &mut server_deletes,
                                        )
                                        .await
                                    {
                                        Ok(CommitOutcome::Committed) => {
                                            self.release(peer, outgoing.history_index);
                                            self.ui.log(format!(
                                                "Delivery status unknown for message #{} to {} after write-token revocation; refused to re-encrypt and duplicate.",
                                                outgoing.history_index,
                                                short(peer)
                                            ));
                                            changed = true;
                                        }
                                        Ok(CommitOutcome::Aborted) => return Ok(false),
                                        Err(err) => {
                                            result = Err(err);
                                            break;
                                        }
                                    }
                                }
                                // Retire the revoked session and mark remaining undispatched
                                // sealed outbox items for requeue on the next sync.
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
                            // - If greeting delivery WAS `CONFIRMED` and eligible for a post-2-
                            //   rotation SPK-eviction probe (within the 14-day window, not yet
                            //   delivery-verified, and not backed off), probe signed `GetManifest`
                            //   first; only if `manifest.generation >= target_generation + 2` AND
                            //   revalidation under `self.inner` still holds do we probe idempotent
                            //   `SendInitialV2` (`Ok(())` marks `greeting_delivery_verified = true`
                            //   via live row or 30d ACK tombstone; `StaleVersion` reclaims fresh).
                            let (can_retry_or_probe, greeting_unconfirmed, target_generation) =
                                inner
                                    .contact(peer)
                                    .map(|c| {
                                        let is_unsent =
                                            c.state.greeting_delivery == GREETING_DELIVERY_UNSENT;
                                        let is_uncertain_eligible = c.state.greeting_delivery
                                            == GREETING_DELIVERY_UNCERTAIN
                                            && uncertain_greeting_reclaim_eligible(&c.state, now());
                                        let unconfirmed = is_unsent || is_uncertain_eligible;
                                        let is_confirmed_probe = c.state.greeting_delivery
                                            == GREETING_DELIVERY_CONFIRMED
                                            && confirmed_greeting_probe_eligible(&c.state, now())
                                            && !self.queue.is_confirmed_probe_backed_off(peer);
                                        let eligible = !c.state.provisional
                                            && !c.state.request
                                            && !c.state.quarantined
                                            && !c.session.has_pending_active_grant()
                                            && (unconfirmed || is_confirmed_probe);
                                        (eligible, unconfirmed, c.state.greeting_target_generation)
                                    })
                                    .unwrap_or((false, false, 0));
                            let mut retry_failed = false;
                            let mut retry_retired_spk = false;
                            let mut stale_aborted = false;
                            // R14-P1-2: Enforce current PQ policy before standalone
                            // `SendInitialV2` fallback on `WriteTokenRejected` (matching
                            // `retry_pending_greetings`).
                            let retry_is_blocked_classical =
                                retry_initial.as_ref().is_some_and(|req| {
                                    let req_is_pq =
                                        req.message.as_ref().is_some_and(|m| m.version >= 2);
                                    let strict_pq = inner.client.pq_config().strict_pq;
                                    let local_pq = inner.local_pq_enabled();
                                    !req_is_pq
                                        && inner.contacts.iter().any(|c| {
                                            c.peer == *peer
                                                && super::classical_policy_blocked(
                                                    strict_pq,
                                                    local_pq,
                                                    c.session.peer_pq_state(),
                                                )
                                        })
                                });
                            if can_retry_or_probe && retry_is_blocked_classical {
                                if inner.client.pq_config().strict_pq
                                    && let Some(c) = inner.contact(peer)
                                    && c.state.security_alert != SECURITY_ALERT_PQ_REQUIRED
                                {
                                    c.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                                    if inner.save_state().await.is_err() {
                                        inner.unsaved_state = true;
                                    }
                                    if !self.is_live(vgen) {
                                        return Ok(false);
                                    }
                                    self.refresh_contacts(inner);
                                }
                            } else if can_retry_or_probe && let Some(retry_req) = retry_initial {
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
                                                if contact.state.greeting_sent_at == 0 {
                                                    contact.state.greeting_sent_at = now();
                                                }
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
                                    let probe_clock = inner.client.clock().clone();
                                    drop(guard);
                                    let should_send_initial = if greeting_unconfirmed {
                                        true
                                    } else {
                                        let greeting_spk = retry_req
                                            .message
                                            .as_ref()
                                            .map(|m| m.signed_prekey.as_ref())
                                            .unwrap_or(&[]);
                                        let probe = self
                                            .probe_confirmed_greeting_spk_rotated(
                                                &server,
                                                &audience,
                                                peer,
                                                greeting_spk,
                                                target_generation,
                                                &probe_clock,
                                            )
                                            .await;
                                        if !self.is_live(vgen) {
                                            return Ok(false);
                                        }
                                        // R20-P1-7: Always persist any verified peer manifest pin
                                        // learned during the SPK-rotation probe BEFORE rechecking
                                        // classical policy or retiring/reclaiming the session so a
                                        // newer signed PQ-ON manifest is never discarded.
                                        let mut guard_check = self.lock_inner().await;
                                        if !self.is_live(vgen) {
                                            return Ok(false);
                                        }
                                        if let Some(ref probe) = probe
                                            && let Some(inner) = guard_check.as_mut()
                                            && !self
                                                .apply_verified_probe_manifest(
                                                    vgen,
                                                    inner,
                                                    peer,
                                                    conversation_gen,
                                                    probe,
                                                )
                                                .await
                                        {
                                            return Ok(false);
                                        }
                                        if !probe.is_some_and(|p| p.rotated) {
                                            drop(guard_check);
                                            self.queue.record_confirmed_probe_backoff(peer);
                                            false
                                        } else {
                                            // Revalidate contact incarnation, session identity,
                                            // peer knowledge, and grant state right before
                                            // transmitting `SendInitialV2` so a concurrent delete
                                            // or session swap during `GetManifest` never emits a
                                            // stale greeting.
                                            guard_check.as_ref().is_some_and(|inner| {
                                                let strict_pq = inner.client.pq_config().strict_pq;
                                                let local_pq = inner.local_pq_enabled();
                                                inner
                                                    .contacts
                                                    .iter()
                                                    .find(|c| c.peer == *peer)
                                                    .is_some_and(|c| {
                                                        !c.state.provisional
                                                            && !c.state.request
                                                            && !c.state.quarantined
                                                            && c.state.conversation_gen
                                                                == conversation_gen
                                                            && !c.session.needs_new_session()
                                                            && !c.session.is_known_by_peer()
                                                            && !c.session.has_pending_active_grant()
                                                            && (retry_is_pq
                                                                || !super::classical_policy_blocked(
                                                                    strict_pq,
                                                                    local_pq,
                                                                    c.session.peer_pq_state(),
                                                                ))
                                                            && (session_id.is_empty()
                                                                || c.session
                                                                    .active_id()
                                                                    .is_some_and(|id| {
                                                                        id.as_slice()
                                                                            == session_id.as_slice()
                                                                    }))
                                                            && confirmed_greeting_probe_eligible(
                                                                &c.state,
                                                                now(),
                                                            )
                                                    })
                                            })
                                        }
                                    };
                                    if !self.is_live(vgen) {
                                        return Ok(false);
                                    }
                                    let retry_res = if should_send_initial {
                                        Some(
                                            // R21-P2-12: Suppress global `REFUSED` sign-in hook so
                                            // a late 403 for a superseded/deleted chat never opens
                                            // `Dialog::SignIn` before validating `still_matches`.
                                            Fetch::client_without_refused_hook(&server)
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
                                                if signs_in_here {
                                                    self.on_origin_auth_proven_locked(vgen, inner);
                                                }
                                                if let Some(contact) = inner.contact(peer) {
                                                    contact.mark_greeting_confirmed();
                                                    if !greeting_unconfirmed {
                                                        contact.state.greeting_delivery_verified =
                                                            true;
                                                    }
                                                    contact.state.awaiting_peer_acceptance = true;
                                                }
                                                let _ = inner.save_state().await;
                                                if !self.is_live(vgen) {
                                                    return Ok(false);
                                                }
                                                self.queue.record_confirmed_probe_backoff(peer);
                                            }
                                            Err(retry_err)
                                                if retry_err.is_server_refusal()
                                                    && retry_err.kind()
                                                        == ErrorKind::StaleVersion =>
                                            {
                                                // Recipient retired the SPK used by this cached
                                                // greeting within the delivery-tombstone window:
                                                // Bob never received this session or registered
                                                // its write token, so atomically clear `dispatched`
                                                // on sealed items belonging ONLY to this unreceived
                                                // session (`R8-P1-3`), retire locally, and re-claim
                                                // a fresh bundle while preserving queued messages.
                                                match inner
                                                    .retire_unreceived_session_on_stale_version(
                                                        peer,
                                                        Some(session_id.as_slice()),
                                                    )
                                                    .await
                                                {
                                                    Ok(true) => {
                                                        if !self.is_live(vgen) {
                                                            return Ok(false);
                                                        }
                                                        self.refresh_contacts(inner);
                                                        retry_failed = true;
                                                        retry_retired_spk = true;
                                                    }
                                                    Ok(false) => {
                                                        if !self.is_live(vgen) {
                                                            return Ok(false);
                                                        }
                                                        stale_aborted = true;
                                                    }
                                                    Err(err) => {
                                                        if !self.is_live(vgen) {
                                                            return Ok(false);
                                                        }
                                                        retry_failed = true;
                                                        result = Err(err);
                                                    }
                                                }
                                            }
                                            Err(retry_err) => {
                                                retry_failed = true;
                                                if !greeting_unconfirmed {
                                                    self.queue.record_confirmed_probe_backoff(peer);
                                                }
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
                                                                contact.state.greeting_sent_at = 0;
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
                                                    hit_sign_in_required = true;
                                                    self.hold(peer, outgoing.history_index);
                                                    self.ask_sign_in_for(background);
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
                            hit_sign_in_required = true;
                            self.hold(peer, outgoing.history_index);
                            self.ask_sign_in_for(background);
                            break;
                        }
                        // The same, but this page cannot sign in to the server: it never will go.
                        // If a prior attempt was already dispatched (response lost), settle as
                        // delivery-unknown rather than `Refused` so we never delete an attachment
                        // whose announcement the recipient may already hold!
                        Err(e) if e.kind() == ErrorKind::SignInRequired => {
                            self.release(peer, outgoing.history_index);
                            let (step, commit_clock) = if first_dispatch {
                                self.ui.notify(format!(
                                    "a message could not be sent: {NOT_SIGNED_IN_HERE}"
                                ));
                                (Step::Refused, 0)
                            } else {
                                self.ui.log(format!(
                                    "Delivery status unknown for message #{} to {} ({NOT_SIGNED_IN_HERE}); preserving attachment and awaiting receipt.",
                                    outgoing.history_index,
                                    short(peer)
                                ));
                                (Step::Unknown, outgoing.clock)
                            };
                            match self
                                .commit_outbox_item(
                                    vgen,
                                    inner,
                                    peer,
                                    &outgoing,
                                    step,
                                    commit_clock,
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
                        // Too large for the server: it never will go (unless an earlier attempt
                        // committed before a limit change, in which case settle as unknown).
                        Err(e) if e.is_server_refusal() && e.kind() == ErrorKind::LimitExceeded => {
                            self.release(peer, outgoing.history_index);
                            let (step, commit_clock) = if first_dispatch {
                                self.ui.notify(format!(
                                    "a message could not be sent: {}",
                                    describe(&e)
                                ));
                                (Step::Refused, 0)
                            } else {
                                self.ui.log(format!(
                                    "Delivery status unknown for message #{} to {} ({}); preserving attachment and awaiting receipt.",
                                    outgoing.history_index,
                                    short(peer),
                                    describe(&e)
                                ));
                                (Step::Unknown, outgoing.clock)
                            };
                            match self
                                .commit_outbox_item(
                                    vgen,
                                    inner,
                                    peer,
                                    &outgoing,
                                    step,
                                    commit_clock,
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
            && !hit_sign_in_required
            && !(background && self.queue.waits_for_sign_in(peer))
            && !self.queue.is_approval_backed_off(peer)
        {
            match self.push_events(vgen, peer, background).await {
                Ok(told) => changed |= told,
                Err(e) => result = Err(e),
            }
        }
        if !server_deletes.is_empty() && self.is_live(vgen) {
            self.finish_server_deletes(peer, server_deletes).await;
        }
        result.map(|()| changed)
    }

    /// Record the peer's non-`awaits_upload` outbox head in `ui.held` when signing in is
    /// required (`R25-P1-1`, `R26-P3-1`), so the UI displays `"waiting for server sign-in"` and
    /// `"Cancel it"` consistently across flush, rekey, greeting retry, and PQ upgrade paths.
    pub(super) fn hold_outbox_head_for_sign_in(&self, inner: &Inner<V>, peer: &PublicKey) {
        if let Some(head_idx) = inner
            .contacts
            .iter()
            .find(|c| c.peer == *peer)
            .and_then(|c| c.state.outbox.first())
            .filter(|o| !o.awaits_upload)
            .map(|o| o.history_index)
        {
            self.hold(peer, head_idx);
        }
    }

    /// Release all `ui.held` rows whose outbox entry is not an unstarted `awaits_upload`
    /// placeholder (`R27-P2-1`), so proven sign-in clears `"waiting for server sign-in"` even when
    /// a peer remains queued on approval backoff, rekey, or a transient error.
    pub(super) fn release_non_waiting_held(&self, inner: &Inner<V>) {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        self.ui.held.update(|held| {
            held.retain(|(p, idx)| {
                inner.contacts.iter().any(|c| {
                    c.peer == *p
                        && c.state
                            .outbox
                            .iter()
                            .any(|o| o.history_index == *idx && o.awaits_upload)
                })
            });
        });
    }

    /// Record that an authenticated same-origin RPC passed the relay's sign-in gate while `vgen`
    /// is still live (`R26-P2-1`, `R27-P2-2`, `R27-P2-3`, `R27-P3-1`): clears all latched
    /// origin-wide sign-in wait flags (`publish_waits_sign_in`, `farewells_wait_sign_in`, and all
    /// peers' `waits_for_sign_in`) because `__Host-e2ee-chat` is shared origin-wide.
    pub(super) fn on_origin_auth_proven(&self, vgen: u64) {
        if !self.is_live(vgen) {
            return;
        }
        self.queue.clear_all_sign_in_waits();
        self.startup.set_publish_waits_sign_in(false);
        self.startup.set_farewells_wait_sign_in(false);
    }

    /// Locked variant of [`Self::on_origin_auth_proven`] that also releases non-`awaits_upload`
    /// `ui.held` rows immediately under the held `Engine::inner` guard (`R27-P2-1`).
    pub(super) fn on_origin_auth_proven_locked(&self, vgen: u64, inner: &Inner<V>) {
        if !self.is_live(vgen) {
            return;
        }
        self.on_origin_auth_proven(vgen);
        self.release_non_waiting_held(inner);
    }

    /// Async variant of [`Self::on_origin_auth_proven`] for callers that do not currently hold any
    /// lock (acquiring `Engine::inner` only when `ui.held` is non-empty, preserving Lock DAG).
    pub(super) async fn on_origin_auth_proven_async(&self, vgen: u64) {
        if !self.is_live(vgen) {
            return;
        }
        self.on_origin_auth_proven(vgen);
        if self.ui.held.with_untracked(|held| !held.is_empty()) {
            let guard = self.lock_inner().await;
            if self.is_live(vgen)
                && let Some(inner) = guard.as_ref()
            {
                self.release_non_waiting_held(inner);
            }
        }
    }

    /// Recover any 32-byte attachment delete key + filename from history/outgoing, atomically fail
    /// the outbox item and forget the corrupt/orphaned upload checkpoint, clear caches/UI, and
    /// enqueue `ServerDeleteJob::for_completed` (`R24-P2-1`, `R25-P2-4`, `R26-P2-2`).
    ///
    /// Returns `Ok(true)` when settled, `Ok(false)` when the vault generation became stale, or
    /// `Err(msg)` on transient storage errors.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn fail_unresumable_upload_outbox(
        &self,
        vgen: u64,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        history_index: u64,
        sealed: bool,
        att_id: [u8; 16],
        mut del_key: Option<zeroize::Zeroizing<[u8; session::attachment::KEY_LENGTH]>>,
        mut name: String,
        server_deletes: &mut Vec<ServerDeleteJob>,
    ) -> Result<bool, String> {
        if del_key.is_none() || name.is_empty() {
            match inner.vault.entry(peer, history_index).await {
                _ if !self.is_live(vgen) => return Ok(false),
                Ok(Some(entry)) => {
                    if let Some(Kind::Attachment(ptr)) =
                        entry.content.as_ref().and_then(|c| c.kind.as_ref())
                    {
                        if del_key.is_none() {
                            del_key = super::attachments::copy_zeroizing_array::<
                                { session::attachment::KEY_LENGTH },
                            >(&ptr.key);
                        }
                        if name.is_empty() {
                            name = ptr.name.clone();
                        }
                    }
                }
                Ok(None) | Err(crate::vault::Error::Corrupt(_)) => {}
                Err(e) => return Err(describe(&e)),
            }
        }
        if (del_key.is_none() || name.is_empty()) && !sealed {
            match inner.vault.outgoing(peer, history_index).await {
                _ if !self.is_live(vgen) => return Ok(false),
                Ok(rec) => {
                    if let Some(Kind::Attachment(ptr)) = Kind::from_bytes(&rec.content) {
                        if del_key.is_none() {
                            del_key = super::attachments::copy_zeroizing_array::<
                                { session::attachment::KEY_LENGTH },
                            >(&ptr.key);
                        }
                        if name.is_empty() {
                            name = ptr.name.clone();
                        }
                    }
                }
                Err(crate::vault::Error::Corrupt(_)) => {}
                Err(e) => return Err(describe(&e)),
            }
        }
        self.fail_outbox_and_forget_upload(vgen, inner, peer, history_index, &att_id, false)
            .await?;
        if !self.is_live(vgen) {
            return Ok(false);
        }
        self.uploads.mark_cancelled(att_id);
        self.uploads.clear_server_completed(&att_id);
        self.remove_attachment_caches(peer, &att_id);
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|u| u.id != att_id));
        if let Some(key) = del_key {
            server_deletes.push(ServerDeleteJob::for_completed(
                inner.server.clone(),
                att_id,
                Some(history_index),
                name,
                key,
            ));
        }
        self.refresh_contacts(inner);
        Ok(true)
    }

    /// Commit one pushed or permanently refused outbox head entry immediately to the vault,
    /// preserving M-18 outbox retention if reading the history entry fails transiently while
    /// isolating permanently corrupt history entries so subsequent outbox items never stall.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn commit_outbox_item(
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
            Err(crate::vault::Error::Corrupt(reason)) => {
                self.ui.log(format!(
                    "History entry #{index} for {} is corrupt ({reason}); settling outbox head without updating history",
                    short(peer)
                ));
                None
            }
            // M-18: Do NOT delete the outbox entry when reading its history entry fails transiently!
            Err(e) => return Err(describe(&e)),
            Ok(entry) => entry,
        };
        let mut entries = vec![];
        let mut new_awaiting = None;
        if let Some(mut entry) = entry_opt {
            let was_pending = entry.delivery() == Delivery::Pending;
            entry.set_delivery(entry.delivery().after(step));
            // Pushed (or delivery-unknown after a prior wire dispatch): record its clock and await
            // a peer receipt so history settles if the peer receives/reads it.
            if step == Step::Pushed || (step == Step::Unknown && clock > 0) {
                if entry.place == 0 {
                    entry.place = clock;
                }
                let content = entry.content.get_or_insert_default();
                if content.clock == 0 {
                    content.clock = clock;
                }
                if step == Step::Pushed || was_pending {
                    let attachment = matches!(content.kind, Some(Kind::Attachment(_)));
                    new_awaiting = Some(Awaiting {
                        place: clock,
                        history_index: index,
                        read: false,
                        attachment,
                        content_digest: outgoing.content_digest.clone(),
                    });
                }
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

    /// Atomically settle an un-dispatched outbox item whose attachment is already durably marked
    /// deleted/gone (`R22-P2-11`), removing it from the outbox, marking its history row refused +
    /// gone, deleting its `OutgoingRecord`, and forgetting any surviving upload checkpoint without
    /// transmitting it on the wire. Returns `Ok(true)` if settled, `Ok(false)` if vault locked.
    pub(super) async fn settle_gone_undispatched_outbox(
        &self,
        vgen: u64,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        idx: u64,
        att_id: Option<[u8; 16]>,
    ) -> Result<bool, String> {
        let changed = inner
            .with_contact_tx(peer, async |inner| {
                let mut hist = Vec::new();
                if let Some(contact) = inner.contact(peer) {
                    contact.state.outbox.retain(|o| o.history_index != idx);
                }
                match inner.vault.entry(peer, idx).await {
                    Ok(Some(mut entry)) => {
                        entry.set_delivery(entry.delivery().after(Step::Refused));
                        entry.gone = true;
                        hist.push((idx, entry));
                    }
                    Ok(None) | Err(crate::vault::Error::Corrupt(_)) => {}
                    Err(e) => return Err(describe(&e)),
                }
                if let Some(id) = att_id {
                    inner
                        .promote_upload_with(
                            peer,
                            &id,
                            None,
                            &records(peer, &hist),
                            &[(*peer, idx, None)],
                        )
                        .await
                        .map_err(|e| describe(&e))?;
                } else {
                    inner
                        .save_with(&records(peer, &hist), &[(*peer, idx, None)])
                        .await
                        .map_err(|e| describe(&e))?;
                }
                Ok(hist)
            })
            .await?;
        if !self.is_live(vgen) {
            return Ok(false);
        }
        self.release(peer, idx);
        // R23-P3-1: Mirror the newly persisted `entry.gone = true` into reactive `self.ui.gone`
        // so the open chat immediately hides the delete control without waiting for reload.
        self.ui.gone.update(|gone| {
            gone.insert((*peer, idx));
        });
        if let Some(id) = att_id {
            // R24-P2-2: Mark cancelled so any active multi-chunk `upload_chunks` task stops
            // immediately instead of resurrecting the cleared `UploadView` card, `PendingUpload`,
            // or sign-in dialog.
            self.uploads.mark_cancelled(id);
            self.uploads.clear_server_completed(&id);
            self.remove_attachment_caches(peer, &id);
            self.ui
                .uploads
                .update(|uploads| uploads.retain(|u| u.id != id));
        }
        if !changed.is_empty() {
            self.show_changes(inner, peer, &changed);
        }
        self.refresh_contacts(inner);
        Ok(true)
    }

    /// Map a `session::Error` from `claim_peer_bundle_v2` or `finish_prepare_start_again_v2`
    /// during outbox rekey into [`RekeyOutcome`] while holding `inner` (after rolling back any
    /// in-memory mutations).
    #[allow(clippy::too_many_arguments)]
    async fn handle_rekey_session_error(
        &self,
        vgen: u64,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        clock: &session::ServerClock,
        error: session::Error,
        server_deletes: &mut Vec<ServerDeleteJob>,
        background: bool,
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
        // R22-P2-7 + R25-P1-1: Handle `SignInRequired` ONLY after `ensure_session_for_outbox`
        // verified the live `conversation_gen` so a late 403 for a deleted/replaced chat never
        // opens sign-in, and mark any non-`awaits_upload` outbox head in `ui.held`.
        if kind == ErrorKind::SignInRequired {
            if same_server(&inner.server, &origin()) {
                self.queue.mark_waits_sign_in(*peer);
                self.hold_outbox_head_for_sign_in(inner, peer);
                self.ask_sign_in_for(background);
                self.refresh_contacts(inner);
                return Ok(RekeyOutcome::Paused);
            }
            return Err(describe(&error));
        }
        let paused = match kind {
            ErrorKind::ClassicalApprovalRequired => {
                let server_disabled = error.is_server_pq_disabled_approval();
                if server_disabled {
                    inner.set_server_pq(crate::state::ServerPqStatus::Disabled);
                    if self.is_live(vgen) {
                        self.ui.me.set(Some(inner.me()));
                    }
                }
                if let Some(contact) = inner.contact(peer) {
                    if matches!(
                        contact.state.security_alert,
                        SECURITY_ALERT_PQ_REQUIRED | SECURITY_ALERT_MANIFEST_EXPIRED
                    ) {
                        contact.state.security_alert = SECURITY_ALERT_NONE;
                    }
                    // R19-P1-1 + R20-P1-1 + R20-P1-4: Persist verified signed PQ-OFF manifest pin
                    // via `commit_signed_pq_off_manifest` (enforcing pre-manifest PQ pins and
                    // monotonic rollback rejection) so legitimate signed PQ-OFF peers reach
                    // explicit `"Allow classical"` approval while violations fail closed.
                    let mut downgraded = false;
                    if !server_disabled
                        && !contact.state.quarantined
                        && !contact.session.peer_pq_state().downgrade_detected
                        && contact.state.security_alert != SECURITY_ALERT_DOWNGRADE
                        && let Some((seq, digest)) = error.signed_pq_off_manifest()
                    {
                        let ppq = contact.session.peer_pq_state_mut();
                        if ppq.commit_signed_pq_off_manifest(seq, digest).is_ok() {
                            ppq.clear_classical_exception();
                        } else {
                            contact.record_policy_error(ErrorKind::DowngradeDetected);
                            downgraded = true;
                        }
                    }
                    if !downgraded {
                        contact.state.classical_approval_needed = if server_disabled {
                            CLASSICAL_APPROVAL_SERVER_PQ_DISABLED
                        } else {
                            CLASSICAL_APPROVAL_SIGNED_OFF
                        };
                    }
                }
                true
            }
            ErrorKind::DowngradeDetected => {
                if let Some(contact) = inner.contact(peer) {
                    // R19-P1-2: Route through `record_policy_error` so pre-downgrade classical
                    // exceptions and stale prompts are cleared atomically with the downgrade flag.
                    contact.record_policy_error(ErrorKind::DowngradeDetected);
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
        background: bool,
    ) -> Result<RekeyOutcome, String> {
        const MAX_CONFIG_RETRIES: usize = 2;
        let mut attempt = 0usize;

        let (server, expected_conversation_gen, new_session_id, outgoing_req) = loop {
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

            // R22-P2-7: Suppress the global `REFUSED` sign-in hook so a late 403 for a chat
            // deleted or replaced while `ClaimBundle` was suspended cannot open `Dialog::SignIn`.
            let claim_res = session::claim_peer_bundle_v2(
                &Fetch::client_without_refused_hook(&server),
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
                Ok(claimed) => {
                    // R26-P2-1 + R27-P2-1 + R27-P2-3: Authenticated `ClaimBundle` succeeded; clear
                    // all origin sign-in waits and release non-`awaits_upload` `ui.held` rows.
                    if same_server(&inner.server, &origin()) {
                        self.on_origin_auth_proven_locked(vgen, inner);
                    }
                    claimed
                }
                Err(e) => {
                    if same_server(&inner.server, &origin())
                        && is_post_auth_claim_error(&e, &pq_config, inner.local_pq_enabled())
                    {
                        self.on_origin_auth_proven_locked(vgen, inner);
                    }
                    return self
                        .handle_rekey_session_error(
                            vgen,
                            inner,
                            peer,
                            &clock,
                            e,
                            server_deletes,
                            background,
                        )
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

            let target_prekey_generation = claimed.manifest().generation;
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
                        .handle_rekey_session_error(
                            vgen,
                            inner,
                            peer,
                            &clock,
                            e,
                            server_deletes,
                            background,
                        )
                        .await;
                }
            };

            let (new_session_id, token_hash) = inner
                .contact(peer)
                .map(|contact| {
                    contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                    contact.state.security_alert = SECURITY_ALERT_NONE;
                    contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
                    contact.state.greeting_target_generation = target_prekey_generation;
                    contact.state.greeting_sent_at = now();
                    contact.state.greeting_delivery_verified = false;
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
            self.finalize_requeue_gone(vgen, inner, peer, &requeued)
                .await;
            if !self.is_live(vgen) {
                return Ok(RekeyOutcome::Aborted);
            }
            self.show_changes(inner, peer, &requeued.history);
            self.refresh_contacts(inner);
            break (
                server,
                expected_conversation_gen,
                new_session_id,
                outgoing_req,
            );
        };

        // Phase 3 outside `self.inner`: register our new inbound write token BEFORE sending the
        // re-initiation `SendInitialV2`.
        let _ = self.flush_pending_grants_for_peer(peer).await;
        if !self.is_live(vgen) {
            return Ok(RekeyOutcome::Aborted);
        }
        let outgoing_is_pq = outgoing_req
            .message
            .as_ref()
            .is_some_and(|m| m.version >= 2);
        // Re-verify contact existence, active session, confirmed active write-token grant, AND
        // current PQ policy immediately before transmitting `SendInitialV2` so a concurrent
        // delete, inbound session replacement, failed `RegisterWriteToken`, or mid-flight
        // `strict_pq`/PQ toggle never emits a phantom, unreplyable, or policy-blocked initial.
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
            let strict_pq = inner.client.pq_config().strict_pq;
            let local_pq = inner.local_pq_enabled();
            let Some(contact) = inner.contacts.iter().find(|c| c.peer == *peer) else {
                return Ok(RekeyOutcome::ContactGone);
            };
            if contact.state.conversation_gen != expected_conversation_gen {
                return Ok(RekeyOutcome::ContactGone);
            }
            if contact.session.active_id() != new_session_id.as_ref() {
                return Ok(RekeyOutcome::Ready);
            }
            let blocked_by_pq = !outgoing_is_pq
                && super::classical_policy_blocked(
                    strict_pq,
                    local_pq,
                    contact.session.peer_pq_state(),
                );
            if contact.session.has_pending_active_grant() || blocked_by_pq {
                let mut changed = false;
                if let Some(contact) = inner.contact(peer) {
                    if contact.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN {
                        contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                        contact.state.greeting_sent_at = 0;
                        changed = true;
                    }
                    if blocked_by_pq
                        && strict_pq
                        && contact.state.security_alert != SECURITY_ALERT_PQ_REQUIRED
                    {
                        contact.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                        changed = true;
                    }
                }
                if changed {
                    if inner.save_state().await.is_err() {
                        inner.unsaved_state = true;
                    }
                    if !self.is_live(vgen) {
                        return Ok(RekeyOutcome::Aborted);
                    }
                }
                self.refresh_contacts(inner);
                return Ok(RekeyOutcome::Paused);
            }
        }

        let signs_in_here = same_server(&server, &origin());
        // R21-P2-12: Suppress global `REFUSED` sign-in hook so a late 403 for a superseded or
        // deleted chat cannot open `Dialog::SignIn` or back off a recreated chat before validating
        // `matches_session`.
        let send_res: session::Result<()> = Fetch::client_without_refused_hook(&server)
            .send_initial_v2(outgoing_req)
            .await
            .map(|_| ())
            .map_err(session::Error::from);
        if !self.is_live(vgen) {
            return Ok(RekeyOutcome::Aborted);
        }

        // Phase 4: Re-acquire `self.inner`, validate `is_live(vgen)`, contact existence, exact
        // `conversation_gen`, and matching `active_id` before updating `greeting_delivery` or
        // refusal/backoff state.
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Ok(RekeyOutcome::Aborted);
        }
        let Some(inner) = guard.as_mut() else {
            return Ok(RekeyOutcome::Aborted);
        };
        let Some(contact_cur) = inner.contacts.iter().find(|c| c.peer == *peer) else {
            return Ok(RekeyOutcome::ContactGone);
        };
        if contact_cur.state.conversation_gen != expected_conversation_gen {
            return Ok(RekeyOutcome::ContactGone);
        }
        let matches_session = contact_cur.session.active_id() == new_session_id.as_ref();
        if signs_in_here
            && (send_res.is_ok()
                || send_res
                    .as_ref()
                    .is_err_and(|e| e.is_server_refusal() && e.kind() != ErrorKind::SignInRequired))
        {
            self.on_origin_auth_proven_locked(vgen, inner);
        }
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
            Err(e) if matches_session => {
                if e.is_server_refusal() {
                    // Only revert `UNCERTAIN -> UNSENT`; never downgrade a greeting already
                    // confirmed concurrently on this session.
                    let reverted = inner.contact(peer).is_some_and(|contact| {
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
                            return Ok(RekeyOutcome::Aborted);
                        }
                    }
                }
                if e.kind() == ErrorKind::SignInRequired && signs_in_here {
                    self.queue.mark_waits_sign_in(*peer);
                    self.hold_outbox_head_for_sign_in(inner, peer);
                    self.ask_sign_in_for(background);
                    self.refresh_contacts(inner);
                    return Ok(RekeyOutcome::Paused);
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
            Err(_) => {}
        }
        Ok(RekeyOutcome::Ready)
    }

    /// Tell `peer` what this client did with its messages, all in one message, once what waits
    /// for it went: on the session, never starting one for it, and never in a request or
    /// quarantined chat, whose sender learns nothing until it is accepted/approved. Encrypted and
    /// saved once under `self.inner`, then pushed outside `self.inner` so slow RTTs never stall
    /// UI or other peers. Once pushed, clearing `sealed_events` is persisted immediately to the
    /// vault after validating `is_live(vgen)`, contact existence, and matching `session_id`.
    async fn push_events(
        &self,
        vgen: u64,
        peer: &PublicKey,
        background: bool,
    ) -> Result<bool, String> {
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
            let strict_pq = inner.client.pq_config().strict_pq;
            let local_pq = inner.local_pq_enabled();
            let Some(contact) = inner.contact(peer) else {
                return Ok(false);
            };
            if contact.state.request
                || contact.state.provisional
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
            let expected_conversation_gen = contact.state.conversation_gen;
            // R22-P1-1: Never seal or push events on an active classical session while local PQ
            // policy blocks classical transmission (e.g. `strict_pq`, live downgrade alarm, or a
            // refused `#chat=...&pq=1` pin).
            if contact.is_classical_session()
                && super::classical_policy_blocked(
                    strict_pq,
                    local_pq,
                    contact.session.peer_pq_state(),
                )
            {
                if strict_pq
                    && contact.state.security_alert != SECURITY_ALERT_PQ_REQUIRED
                    && contact.state.security_alert != SECURITY_ALERT_DOWNGRADE
                {
                    contact.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                    if inner.save_state().await.is_err() {
                        inner.unsaved_state = true;
                    }
                    if !self.is_live(vgen) {
                        return Ok(false);
                    }
                    self.refresh_contacts(inner);
                }
                return Ok(false);
            }
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
            // R14-P1-2: Never promote `UNSENT -> UNCERTAIN` or transmit `PushV2` carrying a
            // classical v1 initial message once current local PQ policy blocks classical sessions.
            if message
                .initial_message
                .as_ref()
                .and_then(|raw| session::protocol::mailbox_v2::decode_carried_initial(raw))
                .is_some_and(|w| w.version < 2)
            {
                let strict_pq = inner.client.pq_config().strict_pq;
                let local_pq = inner.local_pq_enabled();
                let blocked = inner.contacts.iter().any(|c| {
                    c.peer == *peer
                        && super::classical_policy_blocked(
                            strict_pq,
                            local_pq,
                            c.session.peer_pq_state(),
                        )
                });
                if blocked {
                    if strict_pq
                        && let Some(c) = inner.contact(peer)
                        && c.state.security_alert != SECURITY_ALERT_PQ_REQUIRED
                    {
                        c.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                        if inner.save_state().await.is_err() {
                            inner.unsaved_state = true;
                        }
                        if !self.is_live(vgen) {
                            return Ok(false);
                        }
                        self.refresh_contacts(inner);
                    }
                    return Ok(false);
                }
            }
            let promoted_from_unsent = inner
                .contacts
                .iter()
                .any(|c| c.peer == *peer && c.state.greeting_delivery == GREETING_DELIVERY_UNSENT);
            if promoted_from_unsent {
                inner
                    .with_contact_tx(peer, async |inner| {
                        if let Some(contact) = inner.contact(peer) {
                            contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
                            if contact.state.greeting_sent_at == 0 {
                                contact.state.greeting_sent_at = now();
                            }
                        }
                        inner.save(&[]).await.map_err(|e| describe(&e))
                    })
                    .await?;
                if !self.is_live(vgen) {
                    return Ok(false);
                }
            }
            let known_at_dispatch = inner
                .contact(peer)
                .is_some_and(|c| c.session.is_known_by_peer());
            let signs_in_here = same_server(&inner.server, &origin());
            let push_req = message.push_v2_request(peer);
            (
                inner.server.clone(),
                expected_conversation_gen,
                signs_in_here,
                sealed,
                push_req,
                promoted_from_unsent,
                known_at_dispatch,
            )
        };
        let (
            server,
            expected_conversation_gen,
            signs_in_here,
            sealed,
            push_req,
            promoted_from_unsent,
            known_at_dispatch,
        ) = prepared;

        // Phase 2 outside `self.inner`: await `PushV2` RPC.
        // R22-P2-7: Suppress the global `REFUSED` sign-in hook so a late 403 for a chat deleted or
        // replaced while `PushV2` was suspended cannot open `Dialog::SignIn` or poison the new
        // chat's sign-in wait state.
        let push_res: session::Result<_> = Fetch::client_without_refused_hook(&server)
            .push_v2(push_req)
            .await
            .map_err(session::Error::from);
        if !self.is_live(vgen) {
            return Ok(false);
        }

        // Phase 3: Re-acquire `self.inner` and validate live generation, contact existence, exact
        // `conversation_gen`, and matching `sealed_events.session` before mutating or persisting.
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
                c.state.conversation_gen == expected_conversation_gen
                    && c.state
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
                    contact.state.greeting_sent_at = 0;
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
        if signs_in_here
            && (push_res.is_ok()
                || push_res
                    .as_ref()
                    .is_err_and(|e| e.is_server_refusal() && e.kind() != ErrorKind::SignInRequired))
        {
            self.on_origin_auth_proven_locked(vgen, inner);
        }
        match push_res {
            Ok(_) => {
                if matches_sealed {
                    self.clear_approval_backoff(peer);
                }
            }
            Err(e) if e.kind() == ErrorKind::WriteTokenRejected => {
                if !matches_sealed {
                    return Ok(false);
                }
                let known = inner
                    .contact(peer)
                    .is_some_and(|c| c.session.is_known_by_peer());
                if known && !known_at_dispatch {
                    // Pre-approval `push_events` raced with peer acceptance on this exact session:
                    // keep `sealed_events` intact, clear approval backoff, and wake sync to retry
                    // on the working session rather than retiring it.
                    self.clear_approval_backoff(peer);
                    self.wake();
                    return Ok(false);
                }
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
                if !matches_sealed {
                    return Ok(false);
                }
                self.queue.mark_waits_sign_in(*peer);
                if signs_in_here {
                    // R27-P3-2: If an upload promoted an outbox item while `push_events` awaited
                    // `PushV2`, mark the non-`awaits_upload` head in `ui.held` alongside setting
                    // `waits_for_sign_in`.
                    self.hold_outbox_head_for_sign_in(inner, peer);
                    self.ask_sign_in_for(background);
                    self.refresh_contacts(inner);
                }
                return Ok(false);
            }
            Err(e) => {
                if !matches_sealed {
                    return Ok(false);
                }
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
    /// Original history content was missing/corrupt or record was already dispatched on the wire:
    /// dropped the outbox item without duplicating (`was_dispatched == true` leaves `Pending` +
    /// `Awaiting` and preserves attachments; `was_dispatched == false` marks `Failed`).
    Dropped {
        history: Vec<(u64, HistoryEntry)>,
        was_dispatched: bool,
    },
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
        if contact.state.provisional {
            return Err("chat is still starting; please wait.".into());
        }
        if contact.state.quarantined {
            return Err("approve classical encryption or upgrade to post-quantum first".into());
        }
        // If saving fails, the message is forgotten: it never left.
        self.with_contact_tx(peer, async |inner| {
            let server_now = inner.client.clock().now();
            let contact = inner
                .contact(peer)
                .ok_or_else(|| "no such chat".to_string())?;
            let index = contact.next_history_index().map_err(str::to_string)?;
            contact.mark_index_acked(index);
            // Encrypted as it goes, once its place in the chat is known, see `flush`.
            let content_bytes = content.to_bytes();
            let content_digest = crate::vault::content_kind_digest(&content_bytes);
            let attachment_id = match &content {
                Kind::Attachment(pointer) => pointer.id.clone(),
                _ => vec![],
            };
            let record = OutgoingRecord::unsealed(content_bytes);
            contact.state.last_activity = now();
            contact.state.outbox.push(Outgoing {
                history_index: index,
                sealed: false,
                clock: 0,
                awaits_upload,
                content_digest,
                dispatched: false,
                attachment_id,
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
            let view = contact.message_at(index, entry.clone(), server_now);
            inner
                .save_with(&[(*peer, index, entry)], &[(*peer, index, Some(record))])
                .await
                .map_err(|e| describe(&e))?;
            Ok(view)
        })
        .await
    }

    /// Atomically persist an unstarted sign-in-waiting upload (`UPLOAD_STATE_WAITING`), its
    /// placeholder `HistoryEntry` (`AttachmentPointer.id == []`), its `OutgoingRecord`, and its
    /// `Outgoing` row bound to `waiting.id` (`R17-P2-7`) in ONE single vault transaction so a
    /// storage failure can never leave two waiting uploads claiming the same `history_index`.
    pub(super) async fn add_waiting_upload(
        &mut self,
        peer: &PublicKey,
        pointer: crate::content::AttachmentPointer,
        waiting: &crate::vault::PendingUpload,
    ) -> Result<MessageView, String> {
        let contact = self.contact(peer).ok_or("no such chat")?;
        if contact.state.request {
            return Err("accept the request first".into());
        }
        if contact.state.provisional {
            return Err("chat is still starting; please wait.".into());
        }
        if contact.state.quarantined {
            return Err("approve classical encryption or upgrade to post-quantum first".into());
        }
        self.with_contact_tx(peer, async |inner| {
            let server_now = inner.client.clock().now();
            let contact = inner
                .contact(peer)
                .ok_or_else(|| "no such chat".to_string())?;
            let index = contact.next_history_index().map_err(str::to_string)?;
            debug_assert_eq!(index, waiting.history_index);
            contact.mark_index_acked(index);
            let content = Kind::Attachment(pointer);
            let content_bytes = content.to_bytes();
            let content_digest = crate::vault::content_kind_digest(&content_bytes);
            let record = OutgoingRecord::unsealed(content_bytes);
            contact.state.last_activity = now();
            contact.state.outbox.push(Outgoing {
                history_index: index,
                sealed: false,
                clock: 0,
                awaits_upload: true,
                content_digest,
                dispatched: false,
                attachment_id: waiting.id.clone(),
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
            let view = contact.message_at(index, entry.clone(), server_now);
            inner
                .promote_upload_with(
                    peer,
                    &waiting.id,
                    Some(waiting),
                    &[(*peer, index, entry)],
                    &[(*peer, index, Some(record))],
                )
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
                    CorruptOutboxRecovery::Dropped { history, .. } => {
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
            (outgoing.sealed, outgoing.clock, outgoing.dispatched) = (true, clock, false);
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
    /// `vault.entry` + `vault.content` when intact AND the record was NEVER dispatched on the wire
    /// (`dispatched == false`), otherwise mark the history entry `Failed` and drop the corrupt
    /// outbox item without re-encrypting (preventing duplicate delivery of an already-dispatched
    /// message whose ciphertext record was damaged).
    pub(super) async fn recover_corrupt_outbox(
        &mut self,
        peer: &PublicKey,
        index: u64,
    ) -> Result<CorruptOutboxRecovery, String> {
        let (expected_digest, was_dispatched, outgoing_clock) = self
            .contact(peer)
            .and_then(|c| c.state.outbox.iter().find(|o| o.history_index == index))
            .map(|o| (o.content_digest.clone(), o.dispatched, o.clock))
            .unwrap_or_default();
        let entry = match self.vault.entry(peer, index).await {
            Ok(entry) => entry,
            Err(crate::vault::Error::Corrupt(_)) => None,
            Err(e) => return Err(describe(&e)),
        };
        let verified_bytes = if was_dispatched {
            // Never rebuild plaintext and re-encrypt under a fresh `client_message_id` when the
            // damaged sealed ciphertext may already have been accepted by the relay.
            None
        } else {
            let content = match &entry {
                Some(entry) => match self.vault.content(peer, index, entry).await {
                    Ok(content) => content,
                    Err(crate::vault::Error::Corrupt(_)) => None,
                    Err(e) => return Err(describe(&e)),
                },
                None => None,
            };
            match (&entry, content) {
                (Some(_), Some(kind)) => {
                    let bytes = kind.to_bytes();
                    let digest_ok = expected_digest.len() == 32
                        && crate::vault::content_kind_digest(&bytes) == expected_digest;
                    digest_ok.then_some(bytes)
                }
                _ => None,
            }
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
                        outgoing.dispatched = false;
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
                let mut new_awaiting = None;
                let history = match entry {
                    Some(mut entry) => {
                        if was_dispatched {
                            // Delivery status is unknown: keep `Delivery::Pending` (never mark
                            // `Failed` or delete attachments) and record `Awaiting` if `clock > 0`
                            // so a late peer receipt can still settle history.
                            let was_pending = entry.delivery() == Delivery::Pending;
                            if outgoing_clock > 0 {
                                if entry.place == 0 {
                                    entry.place = outgoing_clock;
                                }
                                let content = entry.content.get_or_insert_default();
                                if content.clock == 0 {
                                    content.clock = outgoing_clock;
                                }
                                if was_pending {
                                    let attachment =
                                        matches!(content.kind, Some(Kind::Attachment(_)));
                                    new_awaiting = Some(Awaiting {
                                        place: outgoing_clock,
                                        history_index: index,
                                        read: false,
                                        attachment,
                                        content_digest: expected_digest.clone(),
                                    });
                                }
                            }
                        } else {
                            entry.set_delivery(Delivery::Failed);
                        }
                        vec![(index, entry)]
                    }
                    None => vec![],
                };
                self.with_contact_tx(peer, async |inner| {
                    let contact = inner
                        .contact(peer)
                        .ok_or_else(|| "no such chat".to_string())?;
                    contact.state.outbox.retain(|o| o.history_index != index);
                    if let Some(awaiting) = new_awaiting.clone() {
                        contact.state.awaiting.push(awaiting);
                        keep_last(&mut contact.state.awaiting);
                    }
                    inner
                        .save_with(&records(peer, &history), &[(*peer, index, None)])
                        .await
                        .map_err(|e| describe(&e))
                })
                .await?;
                Ok(CorruptOutboxRecovery::Dropped {
                    history,
                    was_dispatched,
                })
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
    #[cfg(test)]
    pub(super) async fn requeue(
        &mut self,
        peer: &PublicKey,
        deleted: bool,
        entries: &BTreeMap<u64, HistoryEntry>,
    ) -> Result<RequeueOutcome, String> {
        self.requeue_excluding_gone(peer, deleted, entries, &std::collections::HashSet::new())
            .await
    }

    /// Variant of [`Inner::requeue`] that also excludes any server-deleted attachment IDs in
    /// `pending_gone_ids` whose local `HistoryEntry.gone = true` save failed transiently
    /// (`R20-P2-8`).
    pub(super) async fn requeue_excluding_gone(
        &mut self,
        peer: &PublicKey,
        deleted: bool,
        entries: &BTreeMap<u64, HistoryEntry>,
        pending_gone_ids: &std::collections::HashSet<[u8; 16]>,
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
            .rebuild_outbox(peer, again, all_sealed, entries, pending_gone_ids)
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

    /// Atomically retire an unreceived (`!is_known_by_peer()`) active session after
    /// `SendInitialV2` returned `StaleVersion` within the delivery-tombstone window (`R8-P1-3`).
    ///
    /// Because `StaleVersion` proves the recipient never received this session's initial or
    /// registered its write token (and `PushV2` enforces auth-before-dedup), any sealed outbox
    /// items belonging strictly to this retired session could never have been accepted by the
    /// relay: clearing `dispatched = false` on those exact items lets `requeue_sealed` re-encrypt
    /// and deliver them on the replacement session instead of dropping them as `Step::Unknown`.
    pub(super) async fn retire_unreceived_session_on_stale_version(
        &mut self,
        peer: &PublicKey,
        expected_session_id: Option<&[u8]>,
    ) -> Result<bool, String> {
        let Some(contact) = self.contact(peer) else {
            return Ok(false);
        };
        if contact.session.needs_new_session() || contact.session.is_known_by_peer() {
            return Ok(false);
        }
        let active_id = contact.session.active_id().copied();
        if let Some(expected) = expected_session_id
            && !expected.is_empty()
            && active_id.as_ref().map(|id| id.as_slice()) != Some(expected)
        {
            return Ok(false);
        }
        let dispatched_candidates: Vec<(u64, u64)> = contact
            .state
            .outbox
            .iter()
            .filter(|o| o.sealed && o.dispatched)
            .map(|o| (o.history_index, o.clock))
            .collect();
        let mut clear_dispatched: Vec<(u64, u64)> = Vec::new();
        if let Some(retired_id) = active_id {
            for (idx, clock) in dispatched_candidates {
                match self.vault.outgoing(peer, idx).await {
                    Ok(rec) if rec.session_id.as_slice() == retired_id.as_slice() => {
                        clear_dispatched.push((idx, clock));
                    }
                    Ok(_) | Err(crate::vault::Error::Corrupt(_)) => {}
                    Err(e) => return Err(describe(&e)),
                }
            }
        }
        self.with_contact_tx(peer, async |inner| {
            let Some(contact) = inner.contact(peer) else {
                return Ok(false);
            };
            for o in &mut contact.state.outbox {
                if o.sealed
                    && o.dispatched
                    && clear_dispatched.contains(&(o.history_index, o.clock))
                {
                    o.dispatched = false;
                }
            }
            contact.session.retire();
            contact.state.needs_requeue_sealed = true;
            contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
            contact.state.greeting_sent_at = 0;
            contact.state.greeting_target_generation = 0;
            contact.state.greeting_delivery_verified = false;
            inner.save_state().await.map_err(|e| describe(&e))?;
            Ok(true)
        })
        .await
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
        self.rebuild_outbox(
            peer,
            BTreeSet::new(),
            true,
            &BTreeMap::new(),
            &std::collections::HashSet::new(),
        )
        .await
    }

    async fn rebuild_outbox(
        &mut self,
        peer: &PublicKey,
        again: BTreeSet<u64>,
        all_sealed: bool,
        entries: &BTreeMap<u64, HistoryEntry>,
        pending_gone_ids: &std::collections::HashSet<[u8; 16]>,
    ) -> Result<RequeueOutcome, String> {
        let in_flight = self.in_flight_push.get(peer).copied();
        let contact = self.contact(peer).ok_or("no such chat")?;
        let conversation_gen = contact.state.conversation_gen;
        // R21-P2-10 + R22-P2-12: Always union durably recorded `deleted_attachments` with
        // `pending_gone_ids` directly inside `rebuild_outbox` so BOTH `requeue_excluding_gone`
        // AND `requeue_sealed` exclude dead attachment pointers even if `HistoryEntry.gone`
        // failed to persist earlier.
        let mut effective_gone = pending_gone_ids.clone();
        for deleted in &contact.state.deleted_attachments {
            if let Ok(id) = <[u8; 16]>::try_from(deleted.id.as_slice()) {
                effective_gone.insert(id);
            }
        }
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
                // Defer unsealing an outbox head that is either in flight in `PushV2` right now
                // OR durably marked `dispatched` (e.g. reload or ambiguous transport error before
                // local commit) so `flush` reconciles the exact `client_message_id` with the relay
                // first and never re-encrypts a delivered message into a duplicate.
                if !again.contains(&o.history_index)
                    && (o.dispatched
                        || in_flight.is_some_and(|f| {
                            f.conversation_gen == conversation_gen
                                && f.history_index == o.history_index
                                && f.clock == o.clock
                        }))
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
        let server_now = self.client.clock().now();
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
                &effective_gone,
                server_now,
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
    pub(super) gone_indices: BTreeSet<u64>,
    pub(super) gone_attachment_ids: Vec<[u8; 16]>,
    attachment_ids: BTreeMap<u64, Vec<u8>>,
}

impl RequeueOutcome {
    #[allow(clippy::too_many_arguments)]
    fn stage(
        &mut self,
        peer: &PublicKey,
        index: u64,
        entry: Option<HistoryEntry>,
        content: Option<Kind>,
        expected_digest: &[u8],
        resend: bool,
        pending_gone_ids: &std::collections::HashSet<[u8; 16]>,
        server_now: u64,
    ) {
        let excluded_gone_att_id = match (&entry, &content) {
            (Some(entry), Some(Kind::Attachment(ptr)))
                if entry.gone
                    || (ptr.expires > 0 && ptr.expires <= server_now)
                    || <[u8; 16]>::try_from(ptr.id.as_slice())
                        .is_ok_and(|id| pending_gone_ids.contains(&id)) =>
            {
                Some(<[u8; 16]>::try_from(ptr.id.as_slice()).ok())
            }
            _ => None,
        };
        let verified = match (entry, content) {
            // R18-P1-3 + R20-P2-8 + R23-P2-3: Exclude attachments durably marked `gone`, queued
            // in `pending_gone` / `deleted_attachments`, OR already expired according to
            // `server_now` so unread/session requeue never resends a dead attachment pointer.
            (Some(entry), Some(kind)) if excluded_gone_att_id.is_none() && !entry.gone => {
                let att_id = match &kind {
                    Kind::Attachment(ptr) if !ptr.id.is_empty() => Some(ptr.id.clone()),
                    _ => None,
                };
                let bytes = kind.to_bytes();
                let digest_ok = expected_digest.len() == 32
                    && crate::vault::content_kind_digest(&bytes) == expected_digest;
                if digest_ok {
                    Ok((entry, bytes, att_id))
                } else {
                    Err((Some(entry), false))
                }
            }
            (entry, _) => Err((entry, excluded_gone_att_id.is_some())),
        };
        let record = match verified {
            Ok((mut entry, bytes, att_id)) => {
                if let Some(id) = att_id {
                    self.attachment_ids.insert(index, id);
                }
                if resend {
                    entry.set_delivery(entry.delivery().after(Step::Resent));
                    if entry.delivery() == Delivery::Pending {
                        entry.place = 0;
                    }
                    self.history.push((index, entry));
                }
                Some(OutgoingRecord::unsealed(bytes))
            }
            Err((entry, is_gone_attachment)) => {
                if let Some(mut entry) = entry {
                    entry.set_delivery(Delivery::Failed);
                    if is_gone_attachment {
                        // R24-P2-5: Heal `entry.gone = true` durably when requeue drops an
                        // expired or `deleted_attachments`-tombstoned attachment so it no longer
                        // depends on an unexpirable tombstone and immediately reflects gone in UI.
                        entry.gone = true;
                    }
                    self.history.push((index, entry));
                }
                if is_gone_attachment {
                    self.gone_indices.insert(index);
                    if let Some(Some(att_id)) = excluded_gone_att_id
                        && !self.gone_attachment_ids.contains(&att_id)
                    {
                        self.gone_attachment_ids.push(att_id);
                    }
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
                outgoing.dispatched = false;
                if outgoing.attachment_id.is_empty()
                    && let Some(id) = self.attachment_ids.get(&index)
                {
                    outgoing.attachment_id = id.clone();
                }
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
                    attachment_id: self.attachment_ids.get(&index).cloned().unwrap_or_default(),
                    ..Default::default()
                }),
        );
    }

    pub(super) fn log_missing(&self, ui: &Ui, peer: &PublicKey) {
        for index in self.dropped_missing.difference(&self.gone_indices) {
            ui.log(format!(
                "Dropped pending message #{index} for {}: original history content missing or failed integrity check",
                short(peer)
            ));
        }
    }
}

impl<V: VaultStore> Engine<V> {
    /// Complete post-commit cleanup for any expired or `deleted_attachments`-tombstoned outbox
    /// attachments dropped during requeue (`R24-P2-5`): release sign-in holds, update reactive
    /// `self.ui.gone`, mark surviving uploads cancelled to stop active chunk loops, clear caches/UI
    /// upload cards, and forget any leftover `PendingUpload` record.
    pub(super) async fn finalize_requeue_gone(
        &self,
        vgen: u64,
        inner: &mut Inner<impl VaultStore>,
        peer: &PublicKey,
        outcome: &RequeueOutcome,
    ) {
        if !self.is_live(vgen)
            || (outcome.gone_indices.is_empty() && outcome.gone_attachment_ids.is_empty())
        {
            return;
        }
        for &idx in &outcome.gone_indices {
            self.release(peer, idx);
        }
        if !outcome.gone_indices.is_empty() {
            self.ui.gone.update(|gone| {
                for &idx in &outcome.gone_indices {
                    gone.insert((*peer, idx));
                }
            });
        }
        for &att_id in &outcome.gone_attachment_ids {
            self.uploads.mark_cancelled(att_id);
            self.uploads.clear_server_completed(&att_id);
            self.remove_attachment_caches(peer, &att_id);
            self.ui
                .uploads
                .update(|uploads| uploads.retain(|u| u.id != att_id));
            if self.is_live(vgen) {
                let _ = inner.vault.forget_upload(peer, &att_id).await;
            }
        }
    }
}

/// Whether a `claim_peer_bundle_v2` error proves the relay's sign-in gate passed (`R27-P2-2`):
/// excludes pre-RPC local `strict_pq && !local_pq_enabled` rejections, then classifies post-claim
/// manifest/policy errors and non-`SignInRequired` server refusals as authenticated.
pub(super) fn is_post_auth_claim_error(
    e: &session::Error,
    pq_config: &session::PqConfig,
    local_pq_enabled: bool,
) -> bool {
    if pq_config.strict_pq && !local_pq_enabled {
        return false;
    }
    matches!(
        e.kind(),
        ErrorKind::ClassicalApprovalRequired
            | ErrorKind::DowngradeDetected
            | ErrorKind::PqRequired
            | ErrorKind::PeerManifestExpired
    ) || (e.is_server_refusal() && e.kind() != ErrorKind::SignInRequired)
}

/// Whether the chat with `peer` has no session to send on.
pub(super) fn needs_new_session<V>(inner: &Inner<V>, peer: &PublicKey) -> bool {
    inner
        .contacts
        .iter()
        .any(|contact| contact.peer == *peer && contact.session.needs_new_session())
}
