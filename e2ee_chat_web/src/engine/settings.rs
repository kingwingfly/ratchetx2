//! Encryption settings, classical approvals and post-quantum upgrades.

use super::contact::FarewellMode;
use super::handshake::{PublishError, encrypt_session_farewells};
use super::outbox::RequeueOutcome;
use super::{Engine, HistoryStore, Inner, PqSaveOutcome, ProtocolRpcScope, records};
use crate::content::{Content, Kind, stamp};
use crate::state::{Delivery, ServerPqStatus};
use crate::transport::Fetch;
use crate::util::{describe, now, short};
use crate::vault::{
    CLASSICAL_APPROVAL_LEGACY, CLASSICAL_APPROVAL_NONE, CLASSICAL_APPROVAL_SIGNED_OFF,
    ContactState, GREETING_DELIVERY_UNCERTAIN, HistoryEntry, PendingPqRollback,
    SECURITY_ALERT_DOWNGRADE, SECURITY_ALERT_MANIFEST_EXPIRED, SECURITY_ALERT_NONE,
    SECURITY_ALERT_PQ_REQUIRED, history_key,
};
use leptos::prelude::*;
use session::{ErrorKind, PqConfig, PublicKey, Session, SessionState};

impl Engine {
    /// Update local post-quantum security preferences, persist them, and publish a signed
    /// `CapabilityManifest` (ON with PQSPK+PQOPKs, or OFF clearing server PQ prekeys while keeping
    /// local PQ keys for in-flight handshakes).
    ///
    /// Definitive server refusals (such as `PqRequired` on a classical-only server or
    /// `LimitExceeded`) roll back the modified `PqConfig` cleanly so cancelling `Settings` never
    /// leaves rejected preferences persisted. Transient offline / sign-in failures keep the
    /// durable local preference with `needs_publish = true` and report that explicitly.
    pub async fn set_pq_config(&self, config: PqConfig) -> Result<PqSaveOutcome, String> {
        {
            let guard = self.inner.lock().await;
            let inner = guard.as_ref().ok_or("locked")?;
            if *inner.client.pq_config() == config
                && !inner.state.needs_publish
                && !self.publish_waits_settings.get()
            {
                return Ok(PqSaveOutcome::Unchanged);
            }
        }
        // Refresh server capabilities before mutating or persisting `PqConfig` so a concurrent
        // sync or tab close can never observe an unvalidated `strict_pq = true` on a classical-only
        // server.
        self.refresh_server_info(true).await;

        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        if *inner.client.pq_config() == config
            && !inner.state.needs_publish
            && !self.publish_waits_settings.get()
        {
            return Ok(PqSaveOutcome::Unchanged);
        }
        let changed = *inner.client.pq_config() != config;
        inner.save_pq_config(config).await?;
        self.publish_waits_settings.set(false);
        self.ui.me.set(Some(inner.me()));
        self.ui.contacts.set(inner.views());

        // Publish immediately so ON<->OFF transitions and suite changes take effect on the server.
        let outcome = classify_set_pq_publish_result(self.publish_full(inner, true).await);
        drop(guard);
        if changed && outcome.is_ok() {
            self.wake();
        }
        outcome
    }

    /// Explicitly approve a classical fallback exception for `peer`, releasing any quarantined
    /// inbound classical initial message and/or resuming paused outbound messages.
    pub async fn approve_classical(&self, peer: PublicKey) -> Result<(), String> {
        {
            let mut guard = self.inner.lock().await;
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
            self.ui.contacts.set(inner.views());
        }
        let _ = self.flush(&peer).await;
        self.wake();
        Ok(())
    }

    /// Initiate a fresh post-quantum session (`prepare_start_again_v2`) with `peer`, persisting
    /// before transmitting (H-2), to upgrade from a classical session or recover from a downgrade.
    pub async fn upgrade_to_pq(&self, peer: PublicKey) -> Result<(), String> {
        if PqConfig::compiled_suites().is_empty() {
            return Err("Post-quantum encryption is not compiled into this build.".to_string());
        }
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
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
        let Some(index) = inner.contacts.iter().position(|c| c.peer == peer) else {
            return Err("no such chat".to_string());
        };
        let snapshot = inner.contacts[index].snapshot();
        let old_farewell_mode = inner.contacts[index].farewell_mode();
        let old_had_session = !inner.contacts[index].session.needs_new_session();
        let old_was_request_or_quarantined =
            inner.contacts[index].state.request || inner.contacts[index].state.quarantined;
        // Clear any prior classical exception before attempting PQ upgrade so
        // `prepare_start_again_v2` cannot silently negotiate another classical session.
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
        let clock = inner.contacts[index].state.clock;
        let mut greeting = hello.to_bytes();
        stamp(&mut greeting, clock);

        let prepared = {
            let audience = &inner.audience;
            let client = &mut inner.client;
            let contact = &mut inner.contacts[index];
            // Never archive an unapproved quarantined primary classical session into `others`:
            // snapshot rollback still restores it if the PQ upgrade fails.
            if contact.is_new_quarantined() {
                contact.session.discard_active();
            }
            client
                .prepare_start_again_v2(audience, &mut contact.session, &greeting)
                .await
        };
        let outgoing = match prepared {
            Ok(outgoing) => outgoing,
            Err(e) => {
                inner.state.next_session_seq = prev_next_session_seq;
                inner.roll_back(&peer, snapshot)?;
                self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                let kind = e.kind();
                let persist_alert = inner
                    .contact(&peer)
                    .is_some_and(|c| c.session.needs_new_session() || c.state.quarantined);
                if persist_alert && let Some(contact) = inner.contact(&peer) {
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
                        ErrorKind::ClassicalApprovalRequired { peer_signed_off } => {
                            if matches!(
                                contact.state.security_alert,
                                SECURITY_ALERT_PQ_REQUIRED | SECURITY_ALERT_MANIFEST_EXPIRED
                            ) {
                                contact.state.security_alert = SECURITY_ALERT_NONE;
                            }
                            if !contact.state.quarantined {
                                contact.state.classical_approval_needed = if peer_signed_off {
                                    CLASSICAL_APPROVAL_SIGNED_OFF
                                } else {
                                    CLASSICAL_APPROVAL_LEGACY
                                };
                            }
                        }
                        _ => {}
                    }
                    if let Err(save_err) = inner.save_state().await {
                        self.ui.log(format!(
                            "failed to save security alert (will retry): {}",
                            describe(&save_err)
                        ));
                    }
                }
                self.ui.contacts.set(inner.views());
                return Err(describe_upgrade_pq_error(
                    kind,
                    &inner.server_pq,
                    describe(&e),
                ));
            }
        };
        // Verify that the new session actually negotiated post-quantum encryption.
        let upgraded_is_pq = inner
            .contact(&peer)
            .is_some_and(|c| c.session.security().is_some_and(|s| s.is_pq));
        if !upgraded_is_pq {
            inner.state.next_session_seq = prev_next_session_seq;
            inner.roll_back(&peer, snapshot)?;
            self.ui.contacts.set(inner.views());
            return Err(
                "Could not establish a post-quantum session with this peer (peer or server \
                 does not have post-quantum encryption enabled)."
                    .to_string(),
            );
        }
        // Preserve a durable deletion path on the previous established session until the
        // upgraded PQ greeting is confirmed delivered (e.g. if SendInitialV2 is refused and the
        // user deletes the chat before sending another message).
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
            // Persist `GREETING_DELIVERY_UNCERTAIN` directly in the single atomic commit below so
            // we transmit immediately after without a redundant second full-state save.
            contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
            contact.state.sealed_events = None;
            if old_was_request_or_quarantined {
                contact.state.fallback_farewells.clear();
            } else if old_farewell_mode == FarewellMode::Normal {
                contact.state.fallback_farewells = old_session_farewells;
            } else if !old_session_farewells.is_empty() {
                // Keep any earlier fallback farewells alongside this uncertain session's farewell.
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
            if let Some((entry_index, entry)) =
                finalize_upgrade_to_pq_request_state(&mut contact.state, hello, clock, now())
            {
                contact.mark_index_acked(entry_index);
                history_records.push((history_key(&peer, entry_index), entry.clone()));
                added_view = Some(contact.message(entry_index, entry));
            }
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
        requeued.log_missing(&self.ui, &peer);
        self.show_changes(inner, &peer, &requeued.history);
        if let Some(view) = added_view {
            self.show_new(inner, &peer, vec![view]);
        }
        if was_quarantined {
            self.reconcile_open_chat_read(inner, &peer, false).await;
        }
        if let Ok(Err(e)) = inner
            .transmit_with_greeting_delivery(&peer, true, true, async |inner| {
                inner.client.send_prepared_initiate_v2(&outgoing).await
            })
            .await
        {
            self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
            self.ui.log(format!(
                "upgraded session with {} saved locally; initial message will carry on next send: {}",
                short(&peer),
                describe(&e)
            ));
        }
        self.ui.contacts.set(inner.views());
        self.ui.log(format!(
            "upgraded chat with {} to post-quantum encryption",
            short(&peer)
        ));
        drop(guard);
        self.wake();
        Ok(())
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
        let waits_sign_in = self.waits_sign_in.borrow().contains(&peer);
        let use_flush = {
            let mut guard = self.inner.lock().await;
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
                self.ui.contacts.set(inner.views());
            }
            use_flush
        };
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
        ErrorKind::ClassicalApprovalRequired {
            peer_signed_off: true,
        } => "Cannot upgrade to post-quantum encryption: this peer has post-quantum encryption \
              turned off."
            .to_string(),
        ErrorKind::ClassicalApprovalRequired {
            peer_signed_off: false,
        } => "Cannot upgrade to post-quantum encryption: this peer has no post-quantum prekeys \
              on the server."
            .to_string(),
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

impl<V: HistoryStore> Inner<V> {
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
