//! Encryption settings, classical approvals and post-quantum upgrades.

use super::outbox::RequeueOutcome;
use super::{Engine, HistoryStore, Inner, PqSaveOutcome, ProtocolRpcScope, records};
use crate::content::{Content, Kind, stamp};
use crate::state::{Delivery, ServerPqStatus};
use crate::transport::Fetch;
use crate::util::{describe, now, short};
use crate::vault::{
    CLASSICAL_APPROVAL_LEGACY, CLASSICAL_APPROVAL_NONE, CLASSICAL_APPROVAL_SIGNED_OFF,
    ContactState, HistoryEntry, PendingPqRollback, SECURITY_ALERT_DOWNGRADE,
    SECURITY_ALERT_MANIFEST_EXPIRED, SECURITY_ALERT_NONE, SECURITY_ALERT_PQ_REQUIRED, history_key,
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
        inner.save_pq_config(config).await?;
        self.publish_waits_settings.set(false);
        self.ui.me.set(Some(inner.me()));

        // Publish immediately so ON<->OFF transitions and suite changes take effect on the server.
        match self.publish_full(inner, true).await {
            Ok(()) => Ok(PqSaveOutcome::Published),
            Err(error) if error.rejects_settings() => {
                let mut message = error.message;
                if error.kind == Some(ErrorKind::PqRequired) {
                    message =
                        format!("Cannot require post-quantum encryption on this server. {message}");
                }
                Err(message)
            }
            Err(error) if error.needs_sign_in() => Ok(PqSaveOutcome::SavedLocallyNeedsSignIn),
            Err(error) if error.kind.is_some() => Ok(PqSaveOutcome::SavedLocallyPendingPublish),
            Err(error) => Err(error.message),
        }
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
            if contact.state.security_alert == SECURITY_ALERT_PQ_REQUIRED {
                contact.state.security_alert = SECURITY_ALERT_NONE;
            }
            let mut entries = vec![];
            let mut replaced_session = false;
            if contact.state.quarantined {
                let first_message = std::mem::take(&mut contact.state.quarantined_first_message);
                let held_session = contact.state.quarantined_session.take();
                contact.state.quarantined = false;
                contact.state.quarantined_primary = false;
                contact.state.quarantined_was_pq_pinned = false;
                contact.session.peer_pq_state_mut().downgrade_detected = false;
                if contact.state.security_alert == SECURITY_ALERT_DOWNGRADE {
                    contact.state.security_alert = SECURITY_ALERT_NONE;
                }
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
                    replaced_session = match contact.replace_session(incoming, local_pq) {
                        Ok(took_over) => took_over,
                        Err(e) => {
                            inner.roll_back(&peer, snapshot)?;
                            return Err(describe(&e));
                        }
                    };
                }
                if !first_message.is_empty() {
                    let content = Content::from_bytes(&first_message);
                    if let Some(Kind::Hello(ref hello)) = content.kind {
                        let hc = contact.session.check_peer_hello(hello, local_pq);
                        if hc.downgrade_detected {
                            contact.state.security_alert = SECURITY_ALERT_DOWNGRADE;
                        }
                    }
                    let open = self.ui.open.get_untracked() == Some(peer)
                        && !document().hidden()
                        && !contact.state.request;
                    match contact.add_received(content, open) {
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
            if self.ui.open.get_untracked() == Some(peer)
                && let Some(contact) = inner.contact(&peer)
            {
                let views: Vec<_> = entries
                    .into_iter()
                    .map(|(index, entry)| contact.message(index, entry))
                    .collect();
                self.show_new(inner, &peer, views);
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
        // Clear any prior classical exception before attempting PQ upgrade so
        // `prepare_start_again_v2` cannot silently negotiate another classical session.
        inner.contacts[index]
            .session
            .peer_pq_state_mut()
            .clear_classical_exception();
        let hello = Kind::Hello(
            inner.contacts[index]
                .session
                .make_hello(inner.state.name.clone(), &pq_cfg),
        );
        inner.contacts[index].state.clock = inner.contacts[index].state.clock.saturating_add(1);
        let clock = inner.contacts[index].state.clock;
        let mut greeting = hello.to_bytes();
        stamp(&mut greeting, clock);

        let prepared = {
            let audience = &inner.audience;
            let client = &mut inner.client;
            let contact = &mut inner.contacts[index];
            client
                .prepare_start_again_v2(audience, &mut contact.session, &greeting)
                .await
        };
        let outgoing = match prepared {
            Ok(outgoing) => outgoing,
            Err(e) => {
                inner.roll_back(&peer, snapshot)?;
                self.check_protocol_error(ProtocolRpcScope::CoreV2, &e);
                let kind = e.kind();
                let persist_alert = inner
                    .contact(&peer)
                    .is_some_and(|c| c.session.needs_new_session() || c.state.quarantined);
                if persist_alert && let Some(contact) = inner.contact(&peer) {
                    match kind {
                        ErrorKind::DowngradeDetected => {
                            contact.session.peer_pq_state_mut().downgrade_detected = true;
                            contact.state.security_alert = SECURITY_ALERT_DOWNGRADE;
                        }
                        ErrorKind::PeerManifestExpired => {
                            contact.state.security_alert = SECURITY_ALERT_MANIFEST_EXPIRED;
                        }
                        ErrorKind::PqRequired => {
                            contact.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
                        }
                        ErrorKind::ClassicalApprovalRequired { peer_signed_off } => {
                            contact.state.classical_approval_needed = if peer_signed_off {
                                CLASSICAL_APPROVAL_SIGNED_OFF
                            } else {
                                CLASSICAL_APPROVAL_LEGACY
                            };
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
            inner.roll_back(&peer, snapshot)?;
            self.ui.contacts.set(inner.views());
            return Err(
                "Could not establish a post-quantum session with this peer (peer or server \
                 does not have post-quantum encryption enabled)."
                    .to_string(),
            );
        }
        let mut history_records = vec![];
        let mut added_view = None;
        if let Some(contact) = inner.contact(&peer) {
            contact.clear_quarantine_and_alerts();
            contact.state.sealed_events = None;
            if let Some((entry_index, entry)) =
                finalize_upgrade_to_pq_request_state(&mut contact.state, hello, clock, now())
            {
                history_records.push((history_key(&peer, entry_index), entry.clone()));
                added_view = Some(contact.message(entry_index, entry));
            }
        }
        // Requeue any outbox messages sealed on the previous session so they re-encrypt
        // on the new PQ session instead of pushing old-session ciphertexts with the PQ initial.
        let requeued = match inner.requeue_sealed(&peer).await {
            Ok(requeued) => requeued,
            Err(e) => {
                inner.roll_back(&peer, snapshot)?;
                return Err(e);
            }
        };
        // H-2: Persist upgraded PQ session + Hello history + requeued outbox BEFORE transmitting!
        history_records.extend(records(&peer, &requeued.history));
        if let Err(e) = inner.save_with(&history_records, &requeued.outbox).await {
            inner.roll_back(&peer, snapshot)?;
            return Err(describe(&e));
        }
        requeued.log_missing(&self.ui, &peer);
        self.show_changes(inner, &peer, &requeued.history);
        if let Some(view) = added_view {
            self.show_new(inner, &peer, vec![view]);
        }
        if let Err(e) = inner.client.send_prepared_initiate_v2(&outgoing).await {
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
    pub async fn dismiss_downgrade(&self, peer: PublicKey) -> Result<(), String> {
        self.change_contact(peer, |contact| {
            contact.session.peer_pq_state_mut().downgrade_detected = false;
            contact.state.security_alert = SECURITY_ALERT_NONE;
        })
        .await
    }

    /// Clear transient security/approval alerts for `peer` and retry PQ session setup / flushing.
    pub async fn retry_pq(&self, peer: PublicKey) -> Result<(), String> {
        let needs_new = {
            let mut guard = self.inner.lock().await;
            let inner = guard.as_mut().ok_or("locked")?;
            let contact = inner.contact(&peer).ok_or("no such chat")?;
            contact.state.security_alert = SECURITY_ALERT_NONE;
            contact.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
            let needs_new = contact.session.needs_new_session();
            inner.save_state().await.map_err(|e| describe(&e))?;
            self.ui.contacts.set(inner.views());
            needs_new
        };
        if needs_new {
            self.flush(&peer).await.map(drop)
        } else {
            self.upgrade_to_pq(peer).await
        }
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
        validate_pq_config_for_server(&config, &self.server_pq)?;
        self.client
            .set_pq_config(config)
            .map_err(|e| describe(&e))?;
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
            return Err(describe(&e));
        }
        Ok(())
    }
}
