//! Encryption settings, classical approvals and post-quantum upgrades.

use super::contact::{Contact, FarewellMode};
use super::handshake::{PublishError, encrypt_session_farewells};
use super::outbox::RequeueOutcome;
use super::{Engine, Inner, PqSaveOutcome, ProtocolRpcScope, VaultStore, records};
use crate::content::{Content, Kind, stamp};
use crate::state::{Delivery, ServerPqStatus};
use crate::transport::Fetch;
use crate::util::{describe, now, short};
use crate::vault::{
    CLASSICAL_APPROVAL_NONE, CLASSICAL_APPROVAL_SIGNED_OFF, ContactState,
    GREETING_DELIVERY_UNCERTAIN, GREETING_DELIVERY_UNSENT, HistoryEntry, PendingPqRollback,
    SECURITY_ALERT_DOWNGRADE, SECURITY_ALERT_MANIFEST_EXPIRED, SECURITY_ALERT_NONE,
    SECURITY_ALERT_PQ_REQUIRED,
};
use leptos::prelude::*;
use session::protocol::handshake_v2::LocalHandshakeV2;
use session::{ErrorKind, PqConfig, PublicKey, Session, SessionState};

impl<V: VaultStore> Engine<V> {
    /// Update local post-quantum security preferences, persist them, and publish a signed
    /// `CapabilityManifest` (ON with PQSPK+PQOPKs, or OFF clearing server PQ prekeys while keeping
    /// local PQ keys for in-flight handshakes).
    ///
    /// Definitive server refusals (such as `PqRequired` on a classical-only server or
    /// `LimitExceeded`) roll back the modified `PqConfig` cleanly so cancelling `Settings` never
    /// leaves rejected preferences persisted. Transient offline / sign-in failures keep the
    /// durable local preference with `needs_publish = true` and report that explicitly.
    pub async fn set_pq_config(&self, config: PqConfig) -> Result<PqSaveOutcome, String> {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_ref().ok_or("locked")?;
            if *inner.client.pq_config() == config
                && !inner.state.needs_publish
                && !self.startup.publish_waits_settings()
            {
                return Ok(PqSaveOutcome::Unchanged);
            }
        }
        // Refresh server capabilities before mutating or persisting `PqConfig` so a concurrent
        // sync or tab close can never observe an unvalidated `strict_pq = true` on a classical-only
        // server.
        self.refresh_server_info(true).await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }

        // Serialize against any in-flight scheduled `publish_full` under `publish_lock` BEFORE
        // mutating `PqConfig` / `pending_pq_rollback`, preserving the lock order
        // `publish_lock -> self.inner` while releasing `self.inner` across the publish RPC.
        let _publish_guard = self.publish_lock.lock().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let changed = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            if *inner.client.pq_config() == config
                && !inner.state.needs_publish
                && !self.startup.publish_waits_settings()
            {
                return Ok(PqSaveOutcome::Unchanged);
            }
            let changed = *inner.client.pq_config() != config;
            inner.save_pq_config(config).await?;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            self.startup.set_publish_waits_settings(false);
            self.ui.me.set(Some(inner.me()));
            self.refresh_contacts(inner);
            changed
        };

        // Publish immediately outside `self.inner` so ON<->OFF transitions and suite changes take
        // effect on the server without stalling UI or mailbox commits.
        let outcome = classify_set_pq_publish_result(self.publish_full_locked(vgen, true).await);
        drop(_publish_guard);
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        if changed && outcome.is_ok() {
            self.wake();
        }
        outcome
    }

    /// Explicitly approve a classical fallback exception for `peer`, releasing any quarantined
    /// inbound classical initial message and/or resuming paused outbound messages.
    pub async fn approve_classical(&self, peer: PublicKey) -> Result<(), String> {
        let vgen = self.vault_gen();
        let should_stage_grant = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            check_classical_approval(inner.client.pq_config())?;
            let local_pq = inner.local_pq_enabled();
            let server = inner.server.clone();
            let contact = inner.contact(&peer).ok_or("no such chat")?;
            let snapshot = contact.snapshot();
            contact
                .session
                .peer_pq_state_mut()
                .approve_classical_exception();
            contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
            if matches!(
                contact.state.security_alert,
                SECURITY_ALERT_PQ_REQUIRED
                    | SECURITY_ALERT_MANIFEST_EXPIRED
                    | SECURITY_ALERT_DOWNGRADE
            ) {
                contact.state.security_alert = SECURITY_ALERT_NONE;
            }
            let mut entries = vec![];
            let mut replaced_session = false;
            let mut should_stage_grant = false;
            if contact.state.quarantined {
                let was_new_quarantined = contact.is_new_quarantined();
                let first_message = std::mem::take(&mut contact.state.quarantined_first_message);
                let held_session = contact.state.quarantined_session.take();
                contact.state.quarantined = false;
                contact.state.quarantined_primary = false;
                contact.state.quarantined_was_pq_pinned = false;
                contact.session.peer_pq_state_mut().downgrade_detected = false;
                if contact.state.security_alert == SECURITY_ALERT_DOWNGRADE {
                    contact.state.security_alert = SECURITY_ALERT_NONE;
                }
                let first_content =
                    (!first_message.is_empty()).then(|| Content::from_bytes(&first_message));
                let mut stale_discarded = false;
                let mut checked_hello_on_incoming = false;
                let mut incoming_hello_pq_capable = false;
                let mut incoming_hello_downgrade = false;
                if let Some(proto_session) = held_session {
                    let restored = match SessionState::try_from(&proto_session) {
                        Ok(restored) => restored,
                        Err(e) => {
                            inner.roll_back(&peer, snapshot)?;
                            return Err(describe(&e));
                        }
                    };
                    let mut incoming = Session::restore(Fetch::client(&server), restored);
                    incoming.peer_pq_state_mut().approve_classical_exception();
                    incoming.peer_pq_state_mut().downgrade_detected = false;
                    // Validate any in-band `Hello` on `incoming` BEFORE `replace_session` so
                    // crossed-start tie-breaks that archive `incoming` still preserve PQ pinning
                    // and downgrade detection instead of misclassifying `hello.session_seq` as stale.
                    if let Some(Content {
                        kind: Some(Kind::Hello(ref hello)),
                        ..
                    }) = first_content
                    {
                        let hc = incoming.check_peer_hello(hello, local_pq);
                        checked_hello_on_incoming = true;
                        incoming_hello_pq_capable = hello.pq_capable;
                        incoming_hello_downgrade = hc.downgrade_detected;
                    }
                    // Do not archive an unapproved primary classical session into `others` when
                    // replacing it with a newer quarantined classical session.
                    let discarded_primary: Option<session::proto::SessionState> =
                        if was_new_quarantined {
                            let saved = contact.session.state().into();
                            contact.session.discard_active();
                            Some(saved)
                        } else {
                            None
                        };
                    replaced_session = match contact.replace_session(incoming, local_pq) {
                        Ok(took_over) => took_over,
                        Err(e) if e.kind() == ErrorKind::StaleSession => {
                            if let Some(saved) = discarded_primary
                                && let Ok(restored_primary) = SessionState::try_from(&saved)
                            {
                                contact.session =
                                    Session::restore(Fetch::client(&server), restored_primary);
                            }
                            stale_discarded = true;
                            self.ui.log(format!(
                                "discarded superseded quarantined classical session from {}",
                                crate::util::short(&peer)
                            ));
                            false
                        }
                        Err(e) => {
                            inner.roll_back(&peer, snapshot)?;
                            return Err(describe(&e));
                        }
                    };
                }
                if contact.has_healthy_pq_session() {
                    contact.session.peer_pq_state_mut().downgrade_detected = false;
                    contact
                        .session
                        .peer_pq_state_mut()
                        .clear_classical_exception();
                }
                if !stale_discarded && let Some(content) = first_content {
                    if checked_hello_on_incoming {
                        if incoming_hello_pq_capable {
                            contact
                                .session
                                .peer_pq_state_mut()
                                .clear_classical_exception();
                        }
                        if incoming_hello_downgrade && !contact.has_healthy_pq_session() {
                            contact.session.peer_pq_state_mut().downgrade_detected = true;
                            contact.state.security_alert = SECURITY_ALERT_DOWNGRADE;
                        }
                    } else if let Some(Kind::Hello(ref hello)) = content.kind {
                        let hc = contact.session.check_peer_hello(hello, local_pq);
                        if hc.downgrade_detected {
                            contact.state.security_alert = SECURITY_ALERT_DOWNGRADE;
                        }
                    }
                    // Record as unread until persisted and confirmed visible on screen.
                    match contact.add_received(content, false) {
                        Ok(entry) => entries.push(entry),
                        Err(reason) => {
                            inner.roll_back(&peer, snapshot)?;
                            return Err(reason.into());
                        }
                    }
                }
                if !stale_discarded && !contact.state.request {
                    should_stage_grant = true;
                    contact.state.events.get_or_insert_default().accepted = true;
                }
            }
            if should_stage_grant
                && let Some(token_hash) = inner
                    .contact(&peer)
                    .and_then(|c| c.session.active_inbound_token_hash())
                && let Err(e) = inner.stage_write_token_grant(&peer, token_hash, true)
            {
                inner.roll_back(&peer, snapshot)?;
                return Err(e);
            }
            let requeued = if replaced_session {
                match inner.requeue_sealed(&peer).await {
                    Ok(requeued) => requeued,
                    Err(e) => {
                        inner.roll_back(&peer, snapshot)?;
                        return Err(e);
                    }
                }
            } else {
                RequeueOutcome::default()
            };
            let mut recs = records(&peer, &entries);
            recs.extend(records(&peer, &requeued.history));
            if let Err(e) = inner.save_with(&recs, &requeued.outbox).await {
                inner.roll_back(&peer, snapshot)?;
                return Err(describe(&e));
            }
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            requeued.log_missing(&self.ui, &peer);
            self.show_changes(inner, &peer, &requeued.history);
            if self.ui.open.get_untracked() == Some(peer) {
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
                let views: Option<Vec<_>> = inner.contact(&peer).map(|contact| {
                    entries
                        .into_iter()
                        .map(|(index, entry)| contact.message(index, entry))
                        .collect()
                });
                if let Some(views) = views {
                    let showed_views = !views.is_empty();
                    self.show_new(inner, &peer, views);
                    if showed_views {
                        self.record_displayed_entries(&peer, &displayed_entries);
                    }
                }
                // Lifting quarantine makes both the newly released message AND any messages
                // already displayed on the prior session while quarantined eligible for read
                // receipts immediately.
                self.reconcile_open_chat_read(inner, &peer, false).await;
            }
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            self.refresh_contacts(inner);
            should_stage_grant
        };
        if should_stage_grant {
            let _ = self.flush_pending_grants_for_peer(&peer).await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
        }
        let replay_grants = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let mut grants = std::collections::BTreeSet::new();
            if let Some(inner) = guard.as_mut() {
                if let Ok((_, _, gp)) = self
                    .replay_deferred_envelopes(inner, Some(&peer), true)
                    .await
                {
                    grants = gp;
                }
                if !self.is_live(vgen) {
                    return Err("locked".into());
                }
                self.refresh_contacts(inner);
            }
            grants
        };
        for gp in replay_grants {
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let _ = self.flush_pending_grants_for_peer(&gp).await;
        }
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let _ = self.flush(&peer).await;
        if self.is_live(vgen) {
            self.wake();
        }
        Ok(())
    }

    /// Initiate a fresh post-quantum session (`claim_peer_bundle_v2` +
    /// `finish_prepare_start_again_v2`) with `peer`, persisting before transmitting (H-2), to
    /// upgrade from a classical session or recover from a downgrade.
    ///
    /// Serialized per peer via `peer_flush_locks` while releasing `self.inner` across all network
    /// RPCs (`ClaimBundle`, `RegisterWriteToken`, `SendInitialV2`).
    pub async fn upgrade_to_pq(&self, peer: PublicKey) -> Result<(), String> {
        self.upgrade_to_pq_inner(peer, None).await
    }

    /// Automatic background PQ upgrade pinned strictly to `expected_conversation_gen` and
    /// requiring the contact to remain an approved, unquarantined chat so deleting a chat and
    /// receiving a fresh inbound request before the queued upgrade executes can NEVER accept the
    /// replacement request.
    pub(super) async fn upgrade_to_pq_auto(
        &self,
        peer: PublicKey,
        expected_conversation_gen: u64,
    ) -> Result<(), String> {
        self.upgrade_to_pq_inner(peer, Some(expected_conversation_gen))
            .await
    }

    async fn upgrade_to_pq_inner(
        &self,
        peer: PublicKey,
        auto_expected_gen: Option<u64>,
    ) -> Result<(), String> {
        const MAX_CONFIG_RETRIES: usize = 2;
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        if PqConfig::compiled_suites().is_empty() {
            return Err("Post-quantum encryption is not compiled into this build.".to_string());
        }
        let peer_lock = self.queue.peer_flush_lock(&peer);
        let _peer_guard = peer_lock.lock().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }

        // Capture the target conversation incarnation ONCE before the `pq_config` retry loop so
        // config retries can never adopt a recreated conversation or auto-accept a fresh request.
        let (expected_conversation_gen, expected_active_id, expected_request, expected_quarantined) = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_ref().ok_or("locked")?;
            let Some(contact) = inner.contacts.iter().find(|c| c.peer == peer) else {
                return Err("no such chat".to_string());
            };
            if let Some(want_gen) = auto_expected_gen
                && (contact.state.conversation_gen != want_gen
                    || contact.state.request
                    || contact.state.quarantined)
            {
                return Err("chat changed while upgrading; please retry.".to_string());
            }
            (
                contact.state.conversation_gen,
                contact.session.active_id().copied(),
                contact.state.request,
                contact.state.quarantined,
            )
        };

        let mut attempt = 0usize;
        let (server, new_session_id, outgoing_req) = loop {
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            // Phase 1 under `self.inner`: re-verify preconditions and snapshot claim inputs
            // without mutating live session state.
            let (server, audience, pq_cfg, clock, peer_pq_for_claim) = {
                let guard = self.lock_inner().await;
                if !self.is_live(vgen) {
                    return Err("locked".into());
                }
                let inner = guard.as_ref().ok_or("locked")?;
                let pq_cfg = inner.client.pq_config().clone();
                if !pq_cfg.pq_enabled || pq_cfg.offered_suites().is_empty() {
                    return Err("Enable post-quantum encryption in Settings first.".to_string());
                }
                if inner.server_pq == ServerPqStatus::Disabled {
                    return Err(describe_upgrade_pq_error(
                        ErrorKind::Unimplemented,
                        &inner.server_pq,
                        String::new(),
                    ));
                }
                let Some(contact) = inner.contacts.iter().find(|c| c.peer == peer) else {
                    return Err("no such chat".to_string());
                };
                if contact.state.conversation_gen != expected_conversation_gen
                    || contact.state.request != expected_request
                    || contact.state.quarantined != expected_quarantined
                {
                    return Err("chat changed while upgrading; please retry.".to_string());
                }
                if contact.session.active_id().copied() != expected_active_id {
                    if contact.has_healthy_pq_session() {
                        return Ok(());
                    }
                    return Err("chat session changed while upgrading; please retry.".to_string());
                }
                // Clear any prior classical exception on the local clone used for bundle claim so
                // `claim_peer_bundle_v2` cannot silently negotiate another classical session.
                let mut peer_pq_for_claim = contact.session.peer_pq_state().clone();
                peer_pq_for_claim.clear_classical_exception();
                (
                    inner.server.clone(),
                    inner.audience.clone(),
                    pq_cfg,
                    inner.client.clock().clone(),
                    peer_pq_for_claim,
                )
            };

            // Phase 2 outside `self.inner`: claim peer bundle over the network.
            let claim_res = session::claim_peer_bundle_v2(
                &Fetch::client(&server),
                &audience,
                &peer,
                &peer_pq_for_claim,
                &pq_cfg,
                &clock,
            )
            .await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }

            // Phase 3 under `self.inner`: re-validate exact conversation incarnation & expected
            // session FIRST (before any `pq_config` retry), then run synchronous Phase-2 key
            // agreement and atomically persist upgraded PQ session + Hello + requeued outbox.
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            let Some(index) = inner.contacts.iter().position(|c| c.peer == peer) else {
                return Err("no such chat".to_string());
            };
            // Revalidate exact conversation generation, approval/quarantine state, and active
            // session BEFORE checking `pq_config` retry or applying either success or error so
            // deleting a chat and receiving a fresh inbound request during `ClaimBundle` can NEVER
            // accept the new request.
            let current = &inner.contacts[index];
            if current.state.conversation_gen != expected_conversation_gen
                || current.state.request != expected_request
                || current.state.quarantined != expected_quarantined
            {
                return Err("chat changed while upgrading; please retry.".to_string());
            }
            if current.session.active_id().copied() != expected_active_id {
                if current.has_healthy_pq_session() {
                    return Ok(());
                }
                return Err("chat session changed while upgrading; please retry.".to_string());
            }
            if *inner.client.pq_config() != pq_cfg {
                drop(claim_res);
                if attempt < MAX_CONFIG_RETRIES {
                    attempt += 1;
                    continue;
                }
                return Err(
                    "Post-quantum settings changed while upgrading; please retry.".to_string(),
                );
            }
            if inner.server_pq == ServerPqStatus::Disabled {
                drop(claim_res);
                return Err(describe_upgrade_pq_error(
                    ErrorKind::Unimplemented,
                    &inner.server_pq,
                    String::new(),
                ));
            }
            let claimed = match claim_res {
                Ok(claimed) => claimed,
                Err(e) => {
                    return Err(self.handle_upgrade_pq_error(vgen, inner, &peer, e).await);
                }
            };

            let snapshot = inner.contacts[index].snapshot();
            let old_farewell_mode = inner.contacts[index].farewell_mode();
            let old_had_session = !inner.contacts[index].session.needs_new_session();
            let old_was_request_or_quarantined =
                inner.contacts[index].state.request || inner.contacts[index].state.quarantined;
            inner.contacts[index]
                .session
                .peer_pq_state_mut()
                .clear_classical_exception();
            let prev_next_session_seq = inner.state.next_session_seq;
            let session_seq = inner.next_new_chat_session_seq();
            inner.state.next_session_seq = session_seq
                .saturating_add(1)
                .min(session::protocol::MAX_SAFE_INTEGER);
            let hello = Kind::Hello(
                inner
                    .client
                    .make_hello(inner.state.name.clone(), session_seq),
            );
            inner.contacts[index].state.clock = inner.contacts[index].state.clock.saturating_add(1);
            let clock_val = inner.contacts[index].state.clock;
            let mut greeting = hello.to_bytes();
            stamp(&mut greeting, clock_val);

            let prepared = {
                let client = &inner.client;
                let contact = &mut inner.contacts[index];
                // Never archive an unapproved quarantined primary classical session into `others`:
                // snapshot rollback still restores it if the PQ upgrade fails.
                if contact.is_new_quarantined() {
                    contact.session.discard_active();
                }
                client.finish_prepare_start_again_v2(claimed, &mut contact.session, &greeting)
            };
            let outgoing_req = match prepared {
                Ok(outgoing) => outgoing,
                Err(e) => {
                    inner.state.next_session_seq = prev_next_session_seq;
                    inner.roll_back(&peer, snapshot)?;
                    return Err(self.handle_upgrade_pq_error(vgen, inner, &peer, e).await);
                }
            };
            // Verify that the new session actually negotiated post-quantum encryption.
            let upgraded_is_pq = inner
                .contact(&peer)
                .is_some_and(|c| c.session.security().is_some_and(|s| s.is_pq));
            if !upgraded_is_pq {
                inner.state.next_session_seq = prev_next_session_seq;
                inner.roll_back(&peer, snapshot)?;
                if self.is_live(vgen) {
                    self.refresh_contacts(inner);
                }
                return Err(
                    "Could not establish a post-quantum session with this peer (peer or server \
                     does not have post-quantum encryption enabled)."
                        .to_string(),
                );
            }
            // Preserve a durable deletion path on the previous established session until the
            // upgraded PQ greeting is confirmed delivered (e.g. if SendInitialV2 is refused and
            // the user deletes the chat before sending another message).
            let old_session_farewells = if old_had_session
                && old_farewell_mode != FarewellMode::Suppress
                && let Ok(restored) = SessionState::try_from(&snapshot.0)
            {
                let mut old_session = Session::restore(Fetch::client(&inner.server), restored);
                encrypt_session_farewells(
                    &mut old_session,
                    snapshot.1.clock.saturating_add(1),
                    snapshot.1.sealed_events.clone(),
                    snapshot.1.events.clone(),
                    old_farewell_mode,
                )
            } else {
                vec![]
            };
            let mut history_records = vec![];
            let mut added_view = None;
            let mut was_quarantined = false;
            if let Some(contact) = inner.contact(&peer) {
                was_quarantined = contact.state.quarantined;
                contact.clear_quarantine_and_alerts();
                // Persist `GREETING_DELIVERY_UNCERTAIN` directly in the single atomic commit below
                // so we transmit immediately after without a redundant second full-state save.
                contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
                contact.state.sealed_events = None;
                if old_was_request_or_quarantined {
                    contact.state.fallback_farewells.clear();
                } else if old_farewell_mode == FarewellMode::Normal {
                    contact.state.fallback_farewells = old_session_farewells;
                } else if !old_session_farewells.is_empty() {
                    contact
                        .state
                        .fallback_farewells
                        .extend(old_session_farewells);
                    const MAX_FALLBACK_FAREWELLS: usize = 4;
                    if contact.state.fallback_farewells.len() > MAX_FALLBACK_FAREWELLS {
                        let drop_count =
                            contact.state.fallback_farewells.len() - MAX_FALLBACK_FAREWELLS;
                        contact.state.fallback_farewells.drain(0..drop_count);
                    }
                }
                if let Some((entry_index, entry)) = finalize_upgrade_to_pq_request_state(
                    &mut contact.state,
                    hello,
                    clock_val,
                    now(),
                ) {
                    contact.mark_index_acked(entry_index);
                    history_records.push((peer, entry_index, entry.clone()));
                    added_view = Some(contact.message(entry_index, entry));
                }
            }
            let new_session_id = inner
                .contact(&peer)
                .and_then(|c| c.session.active_id().copied());
            if let Some(token_hash) = inner
                .contact(&peer)
                .and_then(|c| c.session.active_inbound_token_hash())
                && let Err(e) = inner.stage_write_token_grant(&peer, token_hash, true)
            {
                inner.state.next_session_seq = prev_next_session_seq;
                inner.roll_back(&peer, snapshot)?;
                return Err(e);
            }
            // Requeue any outbox messages sealed on the previous session so they re-encrypt
            // on the new PQ session instead of pushing old-session ciphertexts with the PQ initial.
            let requeued = match inner.requeue_sealed(&peer).await {
                Ok(requeued) => requeued,
                Err(e) => {
                    inner.state.next_session_seq = prev_next_session_seq;
                    inner.roll_back(&peer, snapshot)?;
                    return Err(e);
                }
            };
            // H-2: Persist upgraded PQ session + Hello history + requeued outbox BEFORE transmitting!
            history_records.extend(records(&peer, &requeued.history));
            if let Err(e) = inner.save_with(&history_records, &requeued.outbox).await {
                inner.state.next_session_seq = prev_next_session_seq;
                inner.roll_back(&peer, snapshot)?;
                return Err(describe(&e));
            }
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            requeued.log_missing(&self.ui, &peer);
            self.show_changes(inner, &peer, &requeued.history);
            if let Some(view) = added_view {
                self.show_new(inner, &peer, vec![view]);
            }
            if was_quarantined {
                self.reconcile_open_chat_read(inner, &peer, false).await;
            }
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            self.refresh_contacts(inner);
            break (inner.server.clone(), new_session_id, outgoing_req);
        };

        // Phase 4 outside `self.inner`: register our inbound write token on our DO before
        // transmitting `SendInitialV2` so the peer can reply immediately upon accepting the
        // upgraded PQ session.
        let _ = self.flush_pending_grants_for_peer(&peer).await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        // Re-verify contact existence, matching session, AND confirmed active write-token grant
        // immediately before transmitting `SendInitialV2` so a concurrent delete, inbound session,
        // or failed `RegisterWriteToken` never emits a stale or unreplyable initial.
        let still_active = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let Some(inner) = guard.as_mut() else {
                return Err("locked".into());
            };
            let Some(contact) = inner.contacts.iter().find(|c| c.peer == peer) else {
                return Ok(());
            };
            if contact.session.active_id() != new_session_id.as_ref() {
                false
            } else if contact.session.has_pending_active_grant() {
                if let Some(contact) = inner.contact(&peer)
                    && contact.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN
                {
                    contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                    let _ = inner.save_state().await;
                    if !self.is_live(vgen) {
                        return Err("locked".into());
                    }
                }
                self.ui.log(format!(
                    "upgraded session with {} saved locally; waiting for write-token registration before sending initial greeting",
                    short(&peer)
                ));
                self.refresh_contacts(inner);
                drop(guard);
                if self.is_live(vgen) {
                    self.wake();
                }
                return Ok(());
            } else {
                true
            }
        };
        if !still_active {
            return Ok(());
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
            return Err("locked".into());
        }

        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let Some(inner) = guard.as_mut() else {
            return Err("locked".into());
        };
        let matches_session = inner
            .contacts
            .iter()
            .find(|c| c.peer == peer)
            .is_some_and(|c| c.session.active_id() == new_session_id.as_ref());
        match send_res {
            Ok(()) if matches_session => {
                if inner
                    .contact(&peer)
                    .is_some_and(Contact::mark_greeting_confirmed)
                {
                    let _ = inner.save_state().await;
                    if !self.is_live(vgen) {
                        return Err("locked".into());
                    }
                }
            }
            Ok(()) => {}
            Err(e) => {
                if e.is_server_refusal() && matches_session {
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
                            return Err("locked".into());
                        }
                    }
                }
                self.check_send_initial_protocol_error(inner, outgoing_is_pq, &e);
                self.ui.log(format!(
                    "upgraded session with {} saved locally; initial message will retry automatically: {}",
                    short(&peer),
                    describe(&e)
                ));
            }
        }
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let replay_grants = match self
            .replay_deferred_envelopes(inner, Some(&peer), false)
            .await
        {
            Ok((_, _, gp)) => gp,
            Err(_) => std::collections::BTreeSet::new(),
        };
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        self.refresh_contacts(inner);
        self.ui.log(format!(
            "upgraded chat with {} to post-quantum encryption",
            short(&peer)
        ));
        drop(guard);
        for gp in replay_grants {
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let _ = self.flush_pending_grants_for_peer(&gp).await;
        }
        if self.is_live(vgen) {
            self.wake();
        }
        Ok(())
    }

    async fn handle_upgrade_pq_error(
        &self,
        vgen: u64,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        e: session::Error,
    ) -> String {
        self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
        let kind = e.kind();
        if kind == ErrorKind::ClockSkew {
            self.warn_clock_skew(inner.client.clock().offset_ms());
        }
        let persist_alert = inner
            .contact(peer)
            .is_some_and(|c| c.session.needs_new_session() || c.state.quarantined);
        if persist_alert && let Some(contact) = inner.contact(peer) {
            match kind {
                ErrorKind::DowngradeDetected => {
                    contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                    contact.session.peer_pq_state_mut().downgrade_detected = true;
                    contact.state.security_alert = SECURITY_ALERT_DOWNGRADE;
                }
                ErrorKind::PeerManifestExpired => {
                    contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                    contact.state.security_alert = SECURITY_ALERT_MANIFEST_EXPIRED;
                }
                ErrorKind::PqRequired => {
                    contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                    contact.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                }
                ErrorKind::ClassicalApprovalRequired => {
                    if matches!(
                        contact.state.security_alert,
                        SECURITY_ALERT_PQ_REQUIRED | SECURITY_ALERT_MANIFEST_EXPIRED
                    ) {
                        contact.state.security_alert = SECURITY_ALERT_NONE;
                    }
                    if !contact.state.quarantined {
                        contact.state.classical_approval_needed = CLASSICAL_APPROVAL_SIGNED_OFF;
                    }
                }
                _ => {}
            }
            if let Err(save_err) = inner.save_state().await
                && self.is_live(vgen)
            {
                self.ui.log(format!(
                    "failed to save security alert (will retry): {}",
                    describe(&save_err)
                ));
            }
        }
        if self.is_live(vgen) {
            self.refresh_contacts(inner);
        }
        describe_upgrade_pq_error(kind, &inner.server_pq, describe(&e))
    }

    /// Dismiss the active downgrade/security banner for `peer` without removing `pq_pinned`.
    /// Refuses to clear downgrade alerts while an inbound classical session is still quarantined.
    pub async fn dismiss_downgrade(&self, peer: PublicKey) -> Result<(), String> {
        let mut cleared = false;
        self.change_contact(peer, |contact| {
            if contact.state.quarantined {
                return;
            }
            contact.session.peer_pq_state_mut().downgrade_detected = false;
            contact.state.security_alert = SECURITY_ALERT_NONE;
            cleared = true;
        })
        .await?;
        if cleared {
            self.wake();
        }
        Ok(())
    }

    /// Clear transient security/approval alerts for `peer` and retry PQ session setup / flushing.
    pub async fn retry_pq(&self, peer: PublicKey) -> Result<(), String> {
        let vgen = self.vault_gen();
        let waits_sign_in = self.queue.waits_for_sign_in(&peer);
        let use_flush = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            let pq_ready = inner.local_pq_enabled() && inner.server_pq != ServerPqStatus::Disabled;
            let contact = inner.contact(&peer).ok_or("no such chat")?;
            let use_flush = pq_ready
                && !waits_sign_in
                && !contact.state.quarantined
                && contact.session.needs_new_session()
                && contact
                    .state
                    .outbox
                    .first()
                    .is_some_and(|o| !o.awaits_upload);
            if use_flush {
                inner
                    .with_contact_tx(&peer, async |inner| {
                        let contact = inner
                            .contact(&peer)
                            .ok_or_else(|| "no such chat".to_string())?;
                        contact.state.security_alert = SECURITY_ALERT_NONE;
                        contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                        contact
                            .session
                            .peer_pq_state_mut()
                            .clear_classical_exception();
                        inner.save(&[]).await.map_err(|e| describe(&e))
                    })
                    .await?;
                if !self.is_live(vgen) {
                    return Err("locked".into());
                }
                self.refresh_contacts(inner);
            }
            use_flush
        };
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        if use_flush {
            self.flush(&peer).await.map(drop)
        } else {
            self.upgrade_to_pq(peer).await
        }
    }
}

/// Map the result of `publish_full` during [`Engine::set_pq_config`] to a user-facing
/// [`PqSaveOutcome`] or error, ensuring definitive `Unimplemented` refusals return `Err` instead
/// of `SavedLocallyPendingPublish`.
pub(super) fn classify_set_pq_publish_result(
    res: Result<(), PublishError>,
) -> Result<PqSaveOutcome, String> {
    match res {
        Ok(()) => Ok(PqSaveOutcome::Published),
        Err(error) if error.rejects_settings() => {
            let mut message = error.message;
            if error.kind == Some(ErrorKind::PqRequired) {
                message =
                    format!("Cannot require post-quantum encryption on this server. {message}");
            }
            Err(message)
        }
        Err(error) if error.is_unimplemented() => Err(error.message),
        Err(error) if error.needs_sign_in() => Ok(PqSaveOutcome::SavedLocallyNeedsSignIn),
        Err(error) if error.kind.is_some() => Ok(PqSaveOutcome::SavedLocallyPendingPublish),
        Err(error) => Err(error.message),
    }
}

/// Map `upgrade_to_pq` session errors to plain-English user messages, checking server PQ status
/// first so a classical-only server is never blamed on the peer.
pub(super) fn describe_upgrade_pq_error(
    kind: ErrorKind,
    server_pq: &ServerPqStatus,
    fallback: String,
) -> String {
    if *server_pq == ServerPqStatus::Disabled {
        return "Cannot upgrade to post-quantum encryption: this server does not have \
                post-quantum encryption enabled."
            .to_string();
    }
    match kind {
        ErrorKind::ClassicalApprovalRequired => {
            "Cannot upgrade to post-quantum encryption: this peer has post-quantum encryption \
             turned off."
                .to_string()
        }
        ErrorKind::PeerManifestExpired => {
            "This peer's signed post-quantum capability manifest has expired. Try again after \
             they come online."
                .to_string()
        }
        ErrorKind::PqRequired => {
            "Require post-quantum (strict mode) is enabled, and a post-quantum session could not \
             be established with this peer."
                .to_string()
        }
        ErrorKind::DowngradeDetected => {
            "Downgrade detected: the server did not return valid post-quantum prekeys for this \
             peer."
                .to_string()
        }
        ErrorKind::UnsupportedSuite => {
            "No mutually supported post-quantum encryption suite is available with this peer."
                .to_string()
        }
        ErrorKind::ClockSkew => super::CLOCK_SKEW_MESSAGE.to_string(),
        _ => fallback,
    }
}

/// Pure helper: unlock an inbound request after `upgrade_to_pq` succeeds, and record the outgoing
/// `Hello` greeting in history if `history_len == 0` so the composer unlocks cleanly on a
/// non-empty chat.
pub(super) fn finalize_upgrade_to_pq_request_state(
    state: &mut ContactState,
    hello: Kind,
    clock: u64,
    at: u64,
) -> Option<(u64, HistoryEntry)> {
    state.request = false;
    if state.history_len == 0 {
        let entry = HistoryEntry {
            outgoing: true,
            at,
            content: Some(Content {
                clock,
                kind: Some(hello),
                events: None,
            }),
            delivery: Delivery::Sent.into(),
            place: clock,
            ..HistoryEntry::default()
        };
        state.history_len = 1;
        state.last_activity = at;
        state.last_message = Some(super::contact::preview_for_entry(&entry));
        Some((0, entry))
    } else {
        None
    }
}

pub(super) fn check_classical_approval(config: &PqConfig) -> Result<(), &'static str> {
    if config.strict_pq {
        Err(
            "Cannot allow classical encryption while Require post-quantum (strict mode) is enabled. Disable strict mode in Settings first.",
        )
    } else {
        Ok(())
    }
}

pub(super) fn validate_pq_config_for_server(
    config: &PqConfig,
    server_pq: &ServerPqStatus,
) -> Result<(), String> {
    if !config.pq_enabled {
        return Ok(());
    }
    if config.strict_pq && *server_pq == ServerPqStatus::Disabled {
        return Err("Cannot require post-quantum encryption on a server with post-quantum encryption disabled.".into());
    }
    if let ServerPqStatus::Enabled { suites, .. } = server_pq {
        let unsupported: Vec<_> = config
            .offered_suites()
            .into_iter()
            .filter(|suite| !suites.contains(suite))
            .map(|suite| suite.label())
            .collect();
        if !unsupported.is_empty() {
            return Err(format!(
                "This server does not support the offered encryption suites {}.",
                unsupported.join(", ")
            ));
        }
        if suites.is_empty() {
            return Err("This server has no supported post-quantum encryption suites.".into());
        }
    }
    Ok(())
}

impl<V: VaultStore> Inner<V> {
    pub(super) async fn save_pq_config(&mut self, config: PqConfig) -> Result<(), String> {
        let previous = self.client.pq_config().clone();
        let changed = previous != config;
        let previous_needs_publish = self.state.needs_publish;
        let previous_rollback = self.state.pending_pq_rollback.clone();
        let previous_pending_flags = self.pending_pq_contact_flags.clone();
        validate_pq_config_for_server(&config, &self.server_pq)?;
        let clear_pq_required = previous.strict_pq && !config.strict_pq;
        let clear_classical_approval = previous.pq_enabled && !config.pq_enabled;
        self.client
            .set_pq_config(config)
            .map_err(|e| describe(&e))?;
        let previous_contact_flags: Vec<(usize, u32, u32)> =
            if clear_pq_required || clear_classical_approval {
                self.contacts
                    .iter_mut()
                    .enumerate()
                    .filter_map(|(idx, contact)| {
                        let prev_alert = contact.state.security_alert;
                        let prev_approval = contact.state.classical_approval_needed;
                        let mut modified = false;
                        if clear_pq_required && prev_alert == SECURITY_ALERT_PQ_REQUIRED {
                            contact.state.security_alert = SECURITY_ALERT_NONE;
                            self.pending_pq_contact_flags
                                .entry(contact.peer)
                                .or_default()
                                .0
                                .get_or_insert(prev_alert);
                            modified = true;
                        }
                        if clear_classical_approval && prev_approval != CLASSICAL_APPROVAL_NONE {
                            contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                            self.pending_pq_contact_flags
                                .entry(contact.peer)
                                .or_default()
                                .1
                                .get_or_insert(prev_approval);
                            modified = true;
                        }
                        modified.then_some((idx, prev_alert, prev_approval))
                    })
                    .collect()
            } else {
                Vec::new()
            };
        if changed {
            self.state.pending_pq_rollback.get_or_insert_with(|| {
                PendingPqRollback::from_config(&previous, previous_needs_publish)
            });
        }
        self.state.needs_publish = true;
        if let Err(e) = self.save(&[]).await {
            self.client
                .set_pq_config(previous)
                .map_err(|e| describe(&e))?;
            self.state.needs_publish = previous_needs_publish;
            self.state.pending_pq_rollback = previous_rollback;
            self.pending_pq_contact_flags = previous_pending_flags;
            for (idx, prev_alert, prev_approval) in previous_contact_flags {
                if let Some(contact) = self.contacts.get_mut(idx) {
                    contact.state.security_alert = prev_alert;
                    contact.state.classical_approval_needed = prev_approval;
                }
            }
            return Err(describe(&e));
        }
        Ok(())
    }
}
