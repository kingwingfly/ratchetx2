//! Contact state, message views and delivery receipts.

use super::EVENTS_KEPT;
use crate::content::{Content, Events, Kind};
#[cfg(test)]
use crate::state::message_order_key;
use crate::state::{
    Attachment, Body, ClassicalPrompt, ContactView, Delivery, IsolatedContactView, LastMessageKind,
    LocalFile, MessageView, RemoteFile, SecurityAlert, SecurityView, Step,
};
use crate::transport::{Connect, Fetch};
use crate::util::{describe, now, sanitize_filename, sanitize_preview_text, short};
use crate::vault::{
    Awaiting, CLASSICAL_APPROVAL_NONE, CLASSICAL_APPROVAL_SERVER_PQ_DISABLED,
    CLASSICAL_APPROVAL_SIGNED_OFF, ContactState, GREETING_DELIVERY_CONFIRMED,
    GREETING_DELIVERY_UNCERTAIN, GREETING_DELIVERY_UNSENT, HistoryEntry, IndexRange,
    LastMessageRecord, SECURITY_ALERT_DOWNGRADE, SECURITY_ALERT_MANIFEST_EXPIRED,
    SECURITY_ALERT_NONE, SECURITY_ALERT_PQ_REQUIRED,
};
use crate::{content, preview};
use session::{ErrorKind, PublicKey, Session, SessionState, proto};
use std::collections::HashSet;
use std::sync::Arc;

/// Maximum characters stored for a chat's single-line sidebar preview text.
pub(super) const LAST_MESSAGE_PREVIEW_MAX_CHARS: usize = 120;

fn media_preview_kind(sort: preview::Sort) -> LastMessageKind {
    match sort {
        preview::Sort::Image => LastMessageKind::Image,
        preview::Sort::Video => LastMessageKind::Video,
        preview::Sort::Audio => LastMessageKind::Audio,
        _ => LastMessageKind::File,
    }
}

fn sanitized_file_preview_name(name: &str) -> String {
    if name.trim().is_empty() {
        String::new()
    } else {
        sanitize_preview_text(&sanitize_filename(name), LAST_MESSAGE_PREVIEW_MAX_CHARS)
    }
}

/// Build a bounded, typed single-line chat-list preview for `entry`.
pub(super) fn preview_for_entry(entry: &HistoryEntry) -> LastMessageRecord {
    let make = |kind: LastMessageKind, outgoing: bool, text: String| LastMessageRecord {
        kind: kind.into(),
        outgoing,
        text,
    };
    if entry.evicted {
        return make(LastMessageKind::Evicted, false, String::new());
    }
    match entry.content.as_ref().and_then(|c| c.kind.as_ref()) {
        Some(Kind::Text(text)) => make(
            LastMessageKind::Text,
            entry.outgoing,
            sanitize_preview_text(text, LAST_MESSAGE_PREVIEW_MAX_CHARS),
        ),
        Some(Kind::Image(_)) => make(LastMessageKind::Image, entry.outgoing, String::new()),
        Some(Kind::File(file)) => {
            let sort = if entry.file > 0 {
                if !entry.media.is_empty() {
                    preview::sort(&file.name, &entry.media, &[])
                } else {
                    entry.sort()
                }
            } else {
                preview::sort(&file.name, &file.mime, &file.data)
            };
            make(
                media_preview_kind(sort),
                entry.outgoing,
                sanitized_file_preview_name(&file.name),
            )
        }
        Some(Kind::Attachment(pointer)) => {
            let sort = preview::sort(&pointer.name, &pointer.mime, &[]);
            make(
                media_preview_kind(sort),
                entry.outgoing,
                sanitized_file_preview_name(&pointer.name),
            )
        }
        Some(Kind::Contact(contact)) => match PublicKey::try_from(contact.key.as_slice()) {
            Ok(key) => {
                let clean_name = super::sanitize_shared_name(&contact.name);
                let label = if !clean_name.is_empty() {
                    clean_name
                } else {
                    short(&key)
                };
                make(
                    LastMessageKind::Contact,
                    entry.outgoing,
                    sanitize_preview_text(&label, LAST_MESSAGE_PREVIEW_MAX_CHARS),
                )
            }
            Err(_) => make(LastMessageKind::Unknown, entry.outgoing, String::new()),
        },
        Some(Kind::Hello(_)) => make(LastMessageKind::Hello, entry.outgoing, String::new()),
        Some(Kind::Deleted(_)) => make(LastMessageKind::Deleted, false, String::new()),
        None => make(LastMessageKind::Unknown, entry.outgoing, String::new()),
    }
}

/// Pick the bottom-most message in display order from `entries` and return its sidebar preview.
#[cfg(test)]
pub(super) fn latest_entry_preview(
    entries: &[(u64, HistoryEntry)],
    me: &PublicKey,
    peer: &PublicKey,
) -> Option<LastMessageRecord> {
    let mine_first = me < peer;
    entries
        .iter()
        .max_by_key(|(index, entry)| {
            message_order_key(entry.place, entry.outgoing, mine_first, *index)
        })
        .map(|(_, entry)| preview_for_entry(entry))
}

/// Keep the last [`EVENTS_KEPT`] of `list`.
pub(super) fn keep_last<T>(list: &mut Vec<T>) {
    if list.len() > EVENTS_KEPT {
        list.drain(..list.len() - EVENTS_KEPT);
    }
}

pub(super) struct Contact {
    pub(super) peer: PublicKey,
    pub(super) session: Session<Connect>,
    /// Everything but the session, which is in `session`.
    pub(super) state: ContactState,
    /// Length of the pending carried queue's prefix deferred by this unlocked build.
    pub(super) deferred_carried: usize,
}

/// The place in the chat of the peer's message whose clock is `clock`, as the chat is `state`,
/// see [`content::place`].
pub(super) fn place_of(clock: u64, state: &ContactState) -> u64 {
    content::place(clock, state.peer_last.max(state.read_by_peer), state.clock)
}

/// Pure quarantine helper: whether a contact's primary session itself is unapproved/quarantined.
pub(super) fn contact_state_is_new_quarantined(state: &ContactState) -> bool {
    state.quarantined && state.quarantined_primary
}

/// Pure quarantine helper: record an incoming quarantined classical initial message on an existing
/// contact without clearing `quarantined_primary` (preventing a 2nd classical initial from
/// unblocking `receive()`/`flush()`).
pub(super) fn record_quarantined_initial_state(
    state: &mut ContactState,
    held_session: Option<proto::SessionState>,
    first_message: Vec<u8>,
    peer_was_pq_pinned: bool,
    downgrade_detected: bool,
    at: u64,
) {
    state.quarantined = true;
    state.quarantined_was_pq_pinned |= peer_was_pq_pinned;
    state.quarantined_session = held_session;
    state.quarantined_first_message = first_message;
    state.last_activity = at;
    if peer_was_pq_pinned || downgrade_detected {
        state.security_alert = SECURITY_ALERT_DOWNGRADE;
    }
}

/// Pure helper: accept a chat request only when the contact is NOT quarantined.
pub(super) fn accept_contact_request_state(
    state: &mut ContactState,
    name: &str,
) -> Result<(), String> {
    if state.quarantined {
        return Err(
            "Allow classical encryption or upgrade to PQ before accepting this request."
                .to_string(),
        );
    }
    state.request = false;
    state.provisional = false;
    state.name = name.trim().to_string();
    Ok(())
}

/// How [`Engine::delete`](super::Engine::delete) should notify a peer when deleting a chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FarewellMode {
    /// Suppress farewell completely (unaccepted request, quarantined, or unsent/refused greeting).
    Suppress,
    /// Send a farewell without any carried `initial_message` (greeting transmission was uncertain).
    WithoutInitial,
    /// Send a normal farewell on an established/confirmed session.
    Normal,
}

/// Result of [`Contact::told`]: history delivery steps plus any sealed pending outbox entries
/// settled directly by a peer receipt after a lost push acknowledgement.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct ToldOutcome {
    pub(super) steps: Vec<(u64, Step)>,
    /// `(history_index, clock)` pairs for sealed outbox entries removed after matching a receipt.
    pub(super) settled_outbox: Vec<(u64, u64)>,
}

/// Read-tracking metadata for one history entry currently rendered on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DisplayedEntry {
    pub(super) index: u64,
    pub(super) counts_unread: bool,
    pub(super) clock: Option<u64>,
}

fn acked_ranges_contain(ranges: &[IndexRange], index: u64) -> bool {
    let pos = ranges.partition_point(|r| r.end <= index);
    ranges
        .get(pos)
        .is_some_and(|r| r.start <= index && index < r.end)
}

/// Bound `ranges` to at most [`EVENTS_KEPT`] disjoint intervals by coalescing the oldest gap(s)
/// so alternating acked/unacked entries cannot grow `AppState` unboundedly.
fn cap_acked_ranges(ranges: &mut Vec<IndexRange>) {
    if ranges.len() <= EVENTS_KEPT {
        return;
    }
    let excess = ranges.len() - EVENTS_KEPT;
    let merged_end = ranges[excess].end;
    ranges[0].end = merged_end;
    ranges.drain(1..=excess);
}

fn coalesce_acked_ranges(ranges: &mut Vec<IndexRange>) {
    if ranges.len() <= 1 {
        return;
    }
    ranges.sort_by_key(|r| (r.start, r.end));
    let mut write = 0usize;
    for read in 1..ranges.len() {
        let next = ranges[read];
        if next.start <= ranges[write].end {
            ranges[write].end = ranges[write].end.max(next.end);
        } else {
            write += 1;
            ranges[write] = next;
        }
    }
    ranges.truncate(write + 1);
    cap_acked_ranges(ranges);
}

pub(super) fn insert_acked_range(ranges: &mut Vec<IndexRange>, start: u64, end: u64) {
    if start >= end {
        return;
    }
    if let Some(last) = ranges.last_mut() {
        if start > last.end {
            ranges.push(IndexRange { start, end });
            cap_acked_ranges(ranges);
            return;
        }
        if start >= last.start {
            last.end = last.end.max(end);
            return;
        }
    } else {
        ranges.push(IndexRange { start, end });
        return;
    }
    ranges.push(IndexRange { start, end });
    coalesce_acked_ranges(ranges);
}

fn merge_acked_batch(ranges: &mut Vec<IndexRange>, batch: Vec<IndexRange>) {
    if batch.is_empty() {
        return;
    }
    if ranges.is_empty() {
        *ranges = batch;
        cap_acked_ranges(ranges);
        return;
    }
    // Fast path: the entire sorted batch lies at or after the tail range.
    if let (Some(last), Some(first)) = (ranges.last_mut(), batch.first())
        && first.start >= last.start
    {
        for range in batch {
            if let Some(tail) = ranges.last_mut()
                && range.start <= tail.end
            {
                tail.end = tail.end.max(range.end);
            } else {
                ranges.push(range);
            }
        }
        cap_acked_ranges(ranges);
        return;
    }
    ranges.extend(batch);
    coalesce_acked_ranges(ranges);
}

impl Contact {
    pub(super) fn replace_session(
        &mut self,
        incoming: Session<Connect>,
        local_pq: bool,
    ) -> session::Result<bool> {
        let took_over = self
            .session
            .accept_replacement_with_policy(incoming, local_pq)?;
        if took_over {
            // A peer-initiated session took over as the active session, replacing any unconfirmed
            // local greeting and any superseded fallback farewells on the previous session.
            self.mark_greeting_confirmed();
            self.state.awaiting_peer_acceptance = false;
            self.state.sealed_events = None;
            self.state.needs_requeue_sealed |= self.state.outbox.iter().any(|o| o.sealed);
        }
        Ok(took_over)
    }

    pub(super) fn record_policy_error(&mut self, kind: ErrorKind) -> bool {
        self.state.security_alert = match kind {
            ErrorKind::DowngradeDetected => {
                let peer_pq = self.session.peer_pq_state_mut();
                peer_pq.downgrade_detected = true;
                // R18-P1-1: Clear any prior classical exception or leftover approval prompt so an
                // active downgrade cannot be bypassed by an earlier exception or dismissal.
                peer_pq.clear_classical_exception();
                self.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
                SECURITY_ALERT_DOWNGRADE
            }
            ErrorKind::PqRequired => SECURITY_ALERT_PQ_REQUIRED,
            _ => return false,
        };
        true
    }

    /// Whether this contact already has a healthy active post-quantum session.
    pub(super) fn has_healthy_pq_session(&self) -> bool {
        !self.session.needs_new_session() && self.session.security().is_some_and(|s| s.is_pq)
    }

    /// Whether this contact is a brand-new inbound quarantined classical chat (not yet approved).
    pub(super) fn is_new_quarantined(&self) -> bool {
        contact_state_is_new_quarantined(&self.state)
    }

    /// Record an inbound quarantined classical initial message on an existing contact.
    pub(super) fn record_quarantined_initial(
        &mut self,
        held_session: Option<proto::SessionState>,
        first_message: Vec<u8>,
        peer_was_pq_pinned: bool,
        downgrade_detected: bool,
        at: u64,
    ) {
        record_quarantined_initial_state(
            &mut self.state,
            held_session,
            first_message,
            peer_was_pq_pinned,
            downgrade_detected,
            at,
        );
        if peer_was_pq_pinned {
            // R20-P1-5: Propagate authenticated PQ capability pins (e.g. from `Hello.pq_capable`
            // on an inbound quarantined classical initial) onto the live contact session so
            // subsequent claims and quarantined initials never lose the PQ pin.
            self.session.pin_peer_pq();
        }
        if peer_was_pq_pinned || downgrade_detected {
            let peer_pq = self.session.peer_pq_state_mut();
            peer_pq.downgrade_detected = true;
            // R19-P1-2: Revoke any pre-downgrade classical exception or pending prompt alongside
            // recording a downgrade-triggered quarantine.
            peer_pq.clear_classical_exception();
            self.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
        }
    }

    /// Accept a non-quarantined chat request, refusing while quarantined.
    pub(super) fn accept_request(&mut self, name: &str) -> Result<(), String> {
        accept_contact_request_state(&mut self.state, name)
    }

    /// Whether this contact's active session (or archived earlier session when `active` was
    /// discarded, e.g. after a cancelled crossed start) is classical (non-PQ).
    pub(super) fn is_classical_session(&self) -> bool {
        self.session
            .security()
            .map_or_else(|| self.session.has_classical_earlier(), |s| !s.is_pq)
    }

    /// Clear quarantine state and active security prompts after establishing a verified PQ session.
    pub(super) fn clear_quarantine_and_alerts(&mut self) {
        self.state.quarantined = false;
        self.state.quarantined_primary = false;
        self.state.quarantined_was_pq_pinned = false;
        self.state.quarantined_session = None;
        self.state.quarantined_first_message.clear();
        self.state.classical_approval_needed = CLASSICAL_APPROVAL_NONE;
        self.state.security_alert = SECURITY_ALERT_NONE;
    }

    /// What to go back to with [`super::Inner::roll_back`] if saving a change fails.
    pub(super) fn snapshot(&self) -> (proto::SessionState, ContactState) {
        (self.session.state().into(), self.state.clone())
    }

    pub(super) fn view(&self) -> ContactView {
        self.view_with(false)
    }

    pub(super) fn view_with(&self, approval_backed_off: bool) -> ContactView {
        let peer_pq = self.session.peer_pq_state();
        let active_security = self.session.security();
        let has_active_session = active_security.is_some();
        let pending_peer = !self.state.request
            && !self.state.quarantined
            && has_active_session
            && !self.session.is_known_by_peer()
            && (self.state.awaiting_peer_acceptance
                || (self.state.peer_last == 0 && self.state.awaiting.is_empty())
                || approval_backed_off);
        let greeting_unsent =
            pending_peer && self.state.greeting_delivery == GREETING_DELIVERY_UNSENT;
        let greeting_uncertain =
            pending_peer && self.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN;
        let awaiting_acceptance = pending_peer && !greeting_unsent && !greeting_uncertain;
        let alert = match self.state.security_alert {
            SECURITY_ALERT_DOWNGRADE => SecurityAlert::DowngradeDetected,
            SECURITY_ALERT_MANIFEST_EXPIRED => SecurityAlert::ManifestExpired,
            SECURITY_ALERT_PQ_REQUIRED => SecurityAlert::PqRequired,
            _ if peer_pq.downgrade_detected => SecurityAlert::DowngradeDetected,
            _ => SecurityAlert::None,
        };
        let classical_prompt = if self.state.quarantined {
            ClassicalPrompt::InboundQuarantined {
                peer_was_pq_pinned: self.state.quarantined_was_pq_pinned,
            }
        } else {
            match self.state.classical_approval_needed {
                CLASSICAL_APPROVAL_SIGNED_OFF => ClassicalPrompt::Outbound,
                CLASSICAL_APPROVAL_SERVER_PQ_DISABLED => ClassicalPrompt::ServerPqDisabled,
                _ => ClassicalPrompt::None,
            }
        };
        ContactView {
            peer: self.peer,
            conversation_gen: self.state.conversation_gen,
            name: self.state.name.clone(),
            request: self.state.request,
            greeting_unsent,
            greeting_uncertain,
            awaiting_acceptance,
            hello_name: self.state.hello_name.clone(),
            unread: self.state.unread,
            last_activity: self.state.last_activity,
            last_message: self
                .state
                .last_message
                .as_ref()
                .and_then(LastMessageRecord::to_view),
            security: SecurityView::from_session(active_security.unwrap_or_default()),
            has_active_session,
            has_classical_earlier: self.session.has_classical_earlier(),
            pq_pinned: peer_pq.pq_pinned,
            peer_pq_capable: peer_pq.peer_pq_capable,
            allow_classical_exception: peer_pq.allow_classical_exception,
            downgrade_detected: peer_pq.downgrade_detected,
            classical_hard_blocked: super::classical_hard_blocked_by_pin_or_downgrade(peer_pq)
                || self.state.quarantined_was_pq_pinned
                || self.state.security_alert == SECURITY_ALERT_DOWNGRADE,
            alert,
            classical_prompt,
        }
    }

    pub(super) fn next_history_index(&mut self) -> Result<u64, &'static str> {
        let index = self.state.history_len;
        self.state.history_len = index
            .checked_add(1)
            .filter(|&len| len <= session::protocol::MAX_SAFE_INTEGER)
            .ok_or("This chat has reached its history limit.")?;
        Ok(index)
    }

    /// Update the cached single-line sidebar preview from `entry`.
    pub(super) fn record_last_message(&mut self, entry: &HistoryEntry) {
        self.state.last_message = Some(preview_for_entry(entry));
    }

    /// Record an evicted (undecryptable-aged) message distinctly in history.
    pub(super) fn add_evicted(&mut self) -> Result<(u64, HistoryEntry), &'static str> {
        let index = self.next_history_index()?;
        self.mark_index_acked(index);
        let place = place_of(0, &self.state);
        self.state.clock = self.state.clock.max(place);
        self.state.peer_last = place;
        self.state.last_activity = now();
        let entry = HistoryEntry {
            outgoing: false,
            at: now(),
            content: None,
            place,
            evicted: true,
            ..HistoryEntry::default()
        };
        self.record_last_message(&entry);
        Ok((index, entry))
    }

    /// Add `content`, received, to the history, at its place in the chat, counting it as unread
    /// unless the chat is `open`: then it is read, which the peer is told. Returns the entry and
    /// its index.
    pub(super) fn add_received(
        &mut self,
        content: Content,
        open: bool,
    ) -> Result<(u64, HistoryEntry), &'static str> {
        let index = self.next_history_index()?;
        let place = place_of(content.clock, &self.state);
        self.state.clock = self.state.clock.max(place);
        self.state.peer_last = place;
        match &content.kind {
            Some(Kind::Hello(hello)) => {
                self.state.hello_name = super::sanitize_shared_name(&hello.name);
                self.mark_index_acked(index);
            }
            _ if !open => self.state.unread = self.state.unread.saturating_add(1),
            _ => self.mark_index_acked(index),
        }
        // A message to read, which the peer waits to hear of, by its clock.
        let readable = content.kind.as_ref().is_some_and(Kind::is_readable);
        if readable && content.clock > 0 {
            if open {
                self.tell_read(content.clock);
            } else {
                self.state.unseen.push(content.clock);
                keep_last(&mut self.state.unseen);
            }
        }
        self.state.last_activity = now();
        // R21-P3-3 + R22-P3-4: If this incoming attachment echo arrived after the attachment was
        // already confirmed deleted/missing on the server OR after its server expiry timestamp,
        // mark the new history row `gone = true` immediately so Files and chat views never offer
        // the dead object again.
        let current_ms = now();
        let already_gone = matches!(
            &content.kind,
            Some(Kind::Attachment(ptr))
                if self.is_attachment_deleted(&ptr.id)
                    || (ptr.expires > 0 && ptr.expires <= current_ms)
        );
        let entry = HistoryEntry {
            outgoing: false,
            at: now(),
            content: Some(content),
            place,
            gone: already_gone,
            ..HistoryEntry::default()
        };
        self.record_last_message(&entry);
        Ok((index, entry))
    }

    /// Record attachment `id` as durably deleted/missing on the server (`R21-P2-10`, `R21-P3-3`,
    /// `R22-P3-4`), pruning expired tombstones before enforcing the high-water cap. Returns `true`
    /// if `ContactState.deleted_attachments` changed.
    pub(super) fn record_deleted_attachment(&mut self, id: &[u8; 16], expires: u64) -> bool {
        let current_ms = now();
        let before_len = self.state.deleted_attachments.len();
        self.state
            .deleted_attachments
            .retain(|existing| existing.expires == 0 || existing.expires > current_ms);
        let mut changed = self.state.deleted_attachments.len() != before_len;
        if let Some(existing) = self
            .state
            .deleted_attachments
            .iter_mut()
            .find(|existing| existing.id.as_slice() == id.as_slice())
        {
            if expires > 0 && existing.expires != expires {
                existing.expires = expires;
                changed = true;
            }
            return changed;
        }
        self.state
            .deleted_attachments
            .push(crate::vault::DeletedAttachment {
                id: id.to_vec(),
                expires,
            });
        const MAX_DELETED_ATTACHMENTS: usize = 4096;
        if self.state.deleted_attachments.len() > MAX_DELETED_ATTACHMENTS {
            let excess = self.state.deleted_attachments.len() - MAX_DELETED_ATTACHMENTS;
            self.state.deleted_attachments.drain(..excess);
        }
        true
    }

    /// Whether attachment `id` has already been recorded as deleted/missing on the server.
    pub(super) fn is_attachment_deleted(&self, id: &[u8]) -> bool {
        self.state
            .deleted_attachments
            .iter()
            .any(|existing| existing.id.as_slice() == id)
    }

    /// Tell the peer that its message at `clock` was read.
    fn tell_read(&mut self, clock: u64) {
        let events = self.state.events.get_or_insert_default();
        if !events.read.contains(&clock) {
            events.read.push(clock);
            keep_last(&mut events.read);
        }
    }

    /// Tell the peer that its attachment at `clock` was downloaded, deduplicating repeated
    /// notifications (e.g. concurrent final stream chunks). Returns `true` if queued anew.
    pub(super) fn tell_downloaded(&mut self, clock: u64) -> bool {
        let events = self.state.events.get_or_insert_default();
        if events.downloaded.contains(&clock) {
            return false;
        }
        events.downloaded.push(clock);
        keep_last(&mut events.downloaded);
        true
    }

    /// Record that history entry `index` does not require future unread acknowledgment (outgoing,
    /// greeting, evicted, or already displayed).
    pub(super) fn mark_index_acked(&mut self, index: u64) {
        insert_acked_range(&mut self.state.acked_ranges, index, index.saturating_add(1));
    }

    /// Mark the active session's greeting as confirmed delivered and drop any superseded fallback
    /// farewells from prior/deleted sessions. Returns `true` if contact state changed.
    pub(super) fn mark_greeting_confirmed(&mut self) -> bool {
        let mut changed = self.state.greeting_delivery != GREETING_DELIVERY_CONFIRMED
            || !self.state.fallback_farewells.is_empty();
        self.state.greeting_delivery = GREETING_DELIVERY_CONFIRMED;
        if self.state.greeting_sent_at == 0 {
            self.state.greeting_sent_at = now();
            changed = true;
        }
        self.state.fallback_farewells.clear();
        changed
    }

    /// How deleting this contact should handle farewell transmission.
    pub(super) fn farewell_mode(&self) -> FarewellMode {
        if self.state.request
            || self.state.quarantined
            || self.state.greeting_delivery == GREETING_DELIVERY_UNSENT
        {
            FarewellMode::Suppress
        } else if self.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN {
            FarewellMode::WithoutInitial
        } else {
            FarewellMode::Normal
        }
    }

    /// Idempotently acknowledge `entries` that are actually displayed on screen, keyed by their
    /// history indices in [`ContactState::acked_ranges`].
    ///
    /// - Entries whose indices were already acknowledged are skipped so reopening or reloading the
    ///   same partial page never double-decrements `unread` (even for zero-clock messages).
    /// - Newly acknowledged unread entries decrement `unread` independently of the `EVENTS_KEPT`
    ///   cap on `unseen`, while queuing read receipts strictly for displayed clocks present in
    ///   `unseen`.
    /// - `unread` is never decremented below `unseen.len()`, preventing staged/undisplayed entries
    ///   from losing their unread badge.
    pub(super) fn acknowledge_entries(&mut self, entries: &[DisplayedEntry]) -> bool {
        let had_unread = self.state.unread > 0 || !self.state.unseen.is_empty();
        let mut changed = false;
        let mut acked_unread = 0u32;
        let mut new_ranges: Vec<IndexRange> = Vec::new();
        for entry in entries {
            if acked_ranges_contain(&self.state.acked_ranges, entry.index)
                || acked_ranges_contain(&new_ranges, entry.index)
            {
                continue;
            }
            insert_acked_range(&mut new_ranges, entry.index, entry.index.saturating_add(1));
            if entry.counts_unread {
                acked_unread = acked_unread.saturating_add(1);
            }
            if let Some(clock) = entry.clock
                && let Some(pos) = self.state.unseen.iter().rposition(|&c| c == clock)
            {
                self.state.unseen.remove(pos);
                self.tell_read(clock);
                changed = true;
            }
        }
        let any_newly_acked = !new_ranges.is_empty();
        if any_newly_acked {
            merge_acked_batch(&mut self.state.acked_ranges, new_ranges);
        }
        if had_unread && acked_unread > 0 {
            let min_unread = u32::try_from(self.state.unseen.len()).unwrap_or(u32::MAX);
            let next_unread = self
                .state
                .unread
                .saturating_sub(acked_unread)
                .max(min_unread);
            if next_unread != self.state.unread {
                self.state.unread = next_unread;
                changed = true;
            }
        }
        if self.state.unread > 0
            && self.state.unseen.is_empty()
            && self.state.history_len > 0
            && self.state.acked_ranges.len() == 1
            && self.state.acked_ranges[0].start == 0
            && self.state.acked_ranges[0].end >= self.state.history_len
        {
            self.state.unread = 0;
            changed = true;
        }
        if had_unread && any_newly_acked {
            changed = true;
        }
        changed
    }

    /// Take what the peer told of this client's messages: those it names that wait for it move
    /// on, and are forgotten once they wait for nothing more.
    ///
    /// Caps and deduplicates incoming receipt clocks to [`EVENTS_KEPT`] and matches both
    /// `awaiting` and sealed pending `outbox` entries (in case a push succeeded on the relay but
    /// its reply was lost) in O(N + M) time.
    pub(super) fn told(&mut self, events: &Events) -> ToldOutcome {
        let read_set: HashSet<u64> = events.read.iter().copied().take(EVENTS_KEPT).collect();
        let downloaded_set: HashSet<u64> = events
            .downloaded
            .iter()
            .copied()
            .take(EVENTS_KEPT)
            .collect();
        let mut steps = Vec::new();
        let mut settled_outbox = Vec::new();
        if read_set.is_empty() && downloaded_set.is_empty() {
            return ToldOutcome {
                steps,
                settled_outbox,
            };
        }
        self.state.awaiting.retain_mut(|awaiting| {
            let was_read = read_set.contains(&awaiting.place);
            let was_downloaded = downloaded_set.contains(&awaiting.place);
            if !was_read && !was_downloaded {
                return true;
            }
            // Read, or downloaded, which it opened to: what the peer writes next goes after.
            self.state.read_by_peer = self.state.read_by_peer.max(awaiting.place);
            if was_read {
                steps.push((awaiting.history_index, Step::Read));
                awaiting.read = true;
            }
            if was_downloaded {
                steps.push((awaiting.history_index, Step::Downloaded));
                return false;
            }
            awaiting.attachment
        });
        let mut newly_awaiting = Vec::new();
        self.state.outbox.retain(|outgoing| {
            if !outgoing.sealed || outgoing.clock == 0 {
                return true;
            }
            let was_read = read_set.contains(&outgoing.clock);
            let was_downloaded = downloaded_set.contains(&outgoing.clock);
            if !was_read && !was_downloaded {
                return true;
            }
            self.state.read_by_peer = self.state.read_by_peer.max(outgoing.clock);
            settled_outbox.push((outgoing.history_index, outgoing.clock));
            if was_read {
                steps.push((outgoing.history_index, Step::Read));
            }
            if was_downloaded {
                steps.push((outgoing.history_index, Step::Downloaded));
            } else {
                // Tentatively retain for a subsequent `Downloaded` receipt in case this entry is
                // an attachment; `read = true` ensures peer chat deletion will not requeue it,
                // and `receive()` prunes non-attachments once the history entry is loaded.
                newly_awaiting.push(Awaiting {
                    place: outgoing.clock,
                    history_index: outgoing.history_index,
                    read: true,
                    attachment: true,
                    content_digest: outgoing.content_digest.clone(),
                });
            }
            false
        });
        if !newly_awaiting.is_empty() {
            self.state.awaiting.extend(newly_awaiting);
            keep_last(&mut self.state.awaiting);
        }
        ToldOutcome {
            steps,
            settled_outbox,
        }
    }

    /// History entry `index`, as shown.
    pub(super) fn message(&self, index: u64, mut entry: HistoryEntry) -> MessageView {
        // The clock the peer sent an attachment's message at, to tell it once downloaded.
        let clock = match &entry.content {
            Some(content) if !entry.outgoing => content.clock,
            _ => 0,
        };
        // Moved out, as a file just sent or received comes with its bytes, up to 1 MiB.
        let kind = entry.content.take().and_then(|content| content.kind);
        // A file read from the history comes without its bytes, which a record of their own
        // keeps, as its size notes; one just sent or received, or an empty one, with them.
        let kept_apart = entry.file > 0;
        let file = |name: String, mime: String, data: Vec<u8>| {
            let media = if kept_apart {
                (!entry.media.is_empty()).then(|| entry.media.clone())
            } else {
                preview::media_mime(&name, &mime, &data).map(str::to_string)
            };
            Body::File(LocalFile {
                peer: self.peer,
                index,
                size: if kept_apart {
                    entry.file
                } else {
                    data.len() as u64
                },
                media,
                data: (!kept_apart).then(|| Attachment {
                    name: name.clone(),
                    mime: mime.clone(),
                    data: Arc::new(data),
                }),
                name,
                mime,
            })
        };
        let body = if entry.evicted {
            Body::Evicted
        } else {
            match kind {
                Some(Kind::Text(text)) => Body::Text(text),
                Some(Kind::Image(data)) => {
                    // The TUI client sends any image, e.g. BMP; typed as the history notes it, see
                    // `HistoryEntry::without_file`.
                    let mime = if kept_apart {
                        (!entry.media.is_empty()).then_some(entry.media.as_str())
                    } else {
                        preview::media_mime("image", "", &data)
                    };
                    file(
                        mime.and_then(|mime| mime.strip_prefix("image/"))
                            .map_or_else(
                                || "image".to_string(),
                                |extension| format!("image.{extension}"),
                            ),
                        mime.unwrap_or("application/octet-stream").to_string(),
                        data,
                    )
                }
                Some(Kind::File(content)) => file(content.name, content.mime, content.data),
                Some(Kind::Hello(hello)) => Body::Hello(super::sanitize_shared_name(&hello.name)),
                Some(Kind::Deleted(_)) => Body::Deleted,
                Some(Kind::Attachment(pointer)) => {
                    let gone = entry.gone || self.is_attachment_deleted(&pointer.id);
                    Body::Remote(RemoteFile {
                        peer: self.peer,
                        index,
                        pointer,
                        clock,
                        gone,
                    })
                }
                Some(Kind::Contact(contact)) => match contact.key.try_into() {
                    Ok(key) => Body::Contact(crate::state::SharedContact {
                        key,
                        name: super::sanitize_shared_name(&contact.name),
                        pq_pinned: contact.pq_pinned,
                    }),
                    Err(_) => Body::Unknown,
                },
                None => Body::Unknown,
            }
        };
        MessageView {
            index,
            place: entry.place,
            outgoing: entry.outgoing,
            at: entry.at,
            body,
            delivery: if entry.outgoing {
                entry.delivery()
            } else {
                Delivery::Received
            },
        }
    }
}

/// Forget, of `events`, what `told` told the peer already.
pub(super) fn forget_told(events: &mut Events, told: &Events) {
    events.read.retain(|clock| !told.read.contains(clock));
    events
        .downloaded
        .retain(|clock| !told.downloaded.contains(clock));
    if told.accepted {
        events.accepted = false;
    }
}

fn validate_history(state: &ContactState) -> Result<(), &'static str> {
    if state.history_len > session::protocol::MAX_SAFE_INTEGER {
        return Err("history length exceeds the supported limit");
    }
    if u64::from(state.unread) > state.history_len {
        return Err("unread count exceeds history length");
    }
    if state
        .outbox
        .iter()
        .any(|o| o.history_index >= state.history_len)
    {
        return Err("outbox refers to an entry outside the history");
    }
    if state
        .awaiting
        .iter()
        .any(|a| a.history_index >= state.history_len)
    {
        return Err("delivery receipt refers to an entry outside the history");
    }
    Ok(())
}

fn validate_contact_state(
    state: &ContactState,
    me: &PublicKey,
) -> Result<(PublicKey, SessionState), String> {
    let peer = PublicKey::try_from(state.peer.as_slice())
        .map_err(|_| "malformed identity key".to_string())?;
    validate_history(state)?;
    let raw_session = state.session.as_ref().ok_or("missing session")?;
    let session = SessionState::try_from(raw_session).map_err(|e| describe(&e))?;
    if session.peer() != &peer || raw_session.me != me.as_slice() {
        return Err("session identities do not match the contact and vault".into());
    }
    Ok((peer, session))
}

fn is_unsupported_known_pq_suite(suite: u32) -> bool {
    u8::try_from(suite)
        .ok()
        .and_then(session::PqSuite::from_u8)
        .is_some_and(|s| !s.is_supported())
}

/// Whether an isolated contact record failed restoration specifically because its active or
/// earlier session uses a known ML-KEM suite not compiled into this build (rather than structural
/// corruption). New greetings from such peers must be deferred rather than acknowledged and lost.
pub(super) fn is_pq_incompatible_isolated(state: &ContactState, me: &PublicKey) -> bool {
    if PublicKey::try_from(state.peer.as_slice()).is_err() || validate_history(state).is_err() {
        return false;
    }
    let Some(raw) = state.session.as_ref() else {
        return false;
    };
    if raw.me != me.as_slice() || raw.peer != state.peer {
        return false;
    }
    let active_kem = raw
        .party
        .as_ref()
        .and_then(|p| p.kem_ratchet.as_ref())
        .is_some_and(|k| is_unsupported_known_pq_suite(k.suite));
    let earlier_kem = raw.others.iter().any(|o| {
        o.party
            .as_ref()
            .and_then(|p| p.kem_ratchet.as_ref())
            .is_some_and(|k| is_unsupported_known_pq_suite(k.suite))
    });
    let active_sec = raw
        .active_security
        .as_ref()
        .is_some_and(|s| s.is_pq && is_unsupported_known_pq_suite(s.suite));
    active_kem || earlier_kem || active_sec
}

/// Extract every valid 32-byte inbound write-token hash from a PQ-incompatible isolated contact's
/// raw `SessionState` (`inbound_token_hash`, `others[*].inbound_token_hash`, and
/// `pending_register_grants[*].token_hash`) so unified mailbox receive can defer its envelopes
/// instead of silently discarding and ACKing them.
pub(super) fn pq_incompatible_isolated_token_hashes(
    state: &ContactState,
    me: &PublicKey,
) -> Option<(PublicKey, Vec<[u8; 32]>)> {
    if !is_pq_incompatible_isolated(state, me) {
        return None;
    }
    let peer = PublicKey::try_from(state.peer.as_slice()).ok()?;
    let raw = state.session.as_ref()?;
    let mut hashes = Vec::new();
    if let Ok(h) = <[u8; 32]>::try_from(raw.inbound_token_hash.as_slice()) {
        hashes.push(h);
    }
    for earlier in &raw.others {
        if let Ok(h) = <[u8; 32]>::try_from(earlier.inbound_token_hash.as_slice())
            && !hashes.contains(&h)
        {
            hashes.push(h);
        }
    }
    for grant in &raw.pending_register_grants {
        if let Ok(h) = <[u8; 32]>::try_from(grant.token_hash.as_slice())
            && !hashes.contains(&h)
        {
            hashes.push(h);
        }
    }
    Some((peer, hashes))
}

/// Restore each contact independently. Validate from borrowed fields so every failure retains
/// the original session, including its pinning state. An earlier corrupt record never hides a
/// later healthy valid contact for the same `peer`.
pub(super) fn restore_contacts(
    raw: Vec<ContactState>,
    me: &PublicKey,
    address: &str,
) -> (Vec<Contact>, Vec<ContactState>, Vec<String>) {
    let mut contacts = Vec::new();
    let mut isolated = Vec::new();
    let mut warnings = Vec::new();
    let mut active_peers = HashSet::new();
    for mut state in raw {
        let peer = PublicKey::try_from(state.peer.as_slice());
        let restored: Result<_, String> = (|| {
            let peer = peer.map_err(|_| "malformed identity key".to_string())?;
            if active_peers.contains(&peer) {
                return Err("duplicate identity key".into());
            }
            validate_contact_state(&state, me)
        })();
        match restored {
            Ok((peer, session)) => {
                active_peers.insert(peer);
                state.session = None;
                contacts.push(Contact {
                    peer,
                    session: Session::restore(Fetch::client(address), session),
                    state,
                    deferred_carried: 0,
                });
            }
            Err(reason) => {
                let label = match peer {
                    Ok(peer) => short(&peer),
                    Err(_) if !state.name.is_empty() => state.name.clone(),
                    Err(_) => "unknown".into(),
                };
                warnings.push(format!("Isolated contact {label}: {reason}"));
                isolated.push(state);
            }
        }
    }
    (contacts, isolated, warnings)
}

/// Summarize genuinely isolated corrupt contact records for UI inspection and confirmed deletion.
pub(super) fn isolated_contact_views(
    isolated: &[ContactState],
    me: &PublicKey,
) -> Vec<IsolatedContactView> {
    let mut views: Vec<IsolatedContactView> = Vec::new();
    for state in isolated {
        let peer = PublicKey::try_from(state.peer.as_slice()).ok();
        let pq_pinned = state
            .session
            .as_ref()
            .and_then(|s| s.peer_pq.as_ref())
            .is_some_and(|pq| pq.pq_pinned);
        let mut reason = validate_contact_state(state, me)
            .err()
            .unwrap_or_else(|| "corrupt contact record".to_string());
        if state.evicted_while_isolated > 0 {
            reason.push_str(&format!(
                " ({} message(s) exceeded the local offline buffer while unsupported)",
                state.evicted_while_isolated
            ));
        }
        if let Some(existing) = views.iter_mut().find(|v| v.raw_peer == state.peer) {
            existing.pq_pinned |= pq_pinned;
            existing.records += 1;
            if existing.name.is_empty() && !state.name.trim().is_empty() {
                existing.name = state.name.trim().to_string();
                existing.label = match existing.peer {
                    Some(key) => format!("{} ({})", existing.name, short(&key)),
                    None => format!("{} (invalid key)", existing.name),
                };
            }
            continue;
        }
        let name = state.name.trim().to_string();
        let label = match (name.as_str(), peer) {
            ("", Some(key)) => short(&key),
            (name, Some(key)) => format!("{name} ({})", short(&key)),
            ("", None) => "Corrupt contact (invalid key)".to_string(),
            (name, None) => format!("{name} (invalid key)"),
        };
        views.push(IsolatedContactView {
            raw_peer: state.peer.clone(),
            peer,
            name,
            label,
            reason,
            pq_pinned,
            records: 1,
        });
    }
    views
}

pub(super) fn stored_contacts(active: &[Contact], isolated: &[ContactState]) -> Vec<ContactState> {
    let peers: HashSet<&[u8]> = active.iter().map(|c| c.peer.as_slice()).collect();
    active
        .iter()
        .map(|c| ContactState {
            session: Some(c.session.state().into()),
            ..c.state.clone()
        })
        .chain(
            isolated
                .iter()
                .filter(|c| !peers.contains(c.peer.as_slice()))
                .cloned(),
        )
        .collect()
}
