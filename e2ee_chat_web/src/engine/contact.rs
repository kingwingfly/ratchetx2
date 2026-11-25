//! Contact state, message views and delivery receipts.

use super::EVENTS_KEPT;
use crate::content::{Content, Events, Kind};
use crate::state::{
    Attachment, Body, ClassicalPrompt, ContactView, Delivery, IsolatedContactView, LocalFile,
    MessageView, RemoteFile, SecurityAlert, SecurityView, Step,
};
use crate::transport::{Connect, Fetch};
use crate::util::{describe, now, short};
use crate::vault::{
    CLASSICAL_APPROVAL_LEGACY, CLASSICAL_APPROVAL_NONE, CLASSICAL_APPROVAL_SIGNED_OFF,
    ContactState, GREETING_DELIVERY_CONFIRMED, GREETING_DELIVERY_LEGACY_UNKNOWN,
    GREETING_DELIVERY_UNCERTAIN, GREETING_DELIVERY_UNSENT, HistoryEntry, IndexRange,
    SECURITY_ALERT_DOWNGRADE, SECURITY_ALERT_MANIFEST_EXPIRED, SECURITY_ALERT_NONE,
    SECURITY_ALERT_PQ_REQUIRED,
};
use crate::{content, preview};
use session::{ErrorKind, PublicKey, Session, SessionState, proto};
use std::collections::HashSet;
use std::sync::Arc;

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
}

pub(super) fn insert_acked_range(ranges: &mut Vec<IndexRange>, start: u64, end: u64) {
    if start >= end {
        return;
    }
    if let Some(last) = ranges.last_mut() {
        if start > last.end {
            ranges.push(IndexRange { start, end });
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
            self.state.sealed_events = None;
            self.state.needs_requeue_sealed |= self.state.outbox.iter().any(|o| o.sealed);
        }
        Ok(took_over)
    }

    pub(super) fn record_policy_error(&mut self, kind: ErrorKind) -> bool {
        self.state.security_alert = match kind {
            ErrorKind::DowngradeDetected => {
                self.session.peer_pq_state_mut().downgrade_detected = true;
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
        if peer_was_pq_pinned || downgrade_detected {
            self.session.peer_pq_state_mut().downgrade_detected = true;
        }
    }

    /// Accept a non-quarantined chat request, refusing while quarantined.
    pub(super) fn accept_request(&mut self, name: &str) -> Result<(), String> {
        accept_contact_request_state(&mut self.state, name)
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
        let peer_pq = self.session.peer_pq_state();
        let active_security = self.session.security();
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
                CLASSICAL_APPROVAL_LEGACY => ClassicalPrompt::Outbound {
                    peer_signed_off: false,
                },
                CLASSICAL_APPROVAL_SIGNED_OFF => ClassicalPrompt::Outbound {
                    peer_signed_off: true,
                },
                _ => ClassicalPrompt::None,
            }
        };
        ContactView {
            peer: self.peer,
            name: self.state.name.clone(),
            request: self.state.request,
            hello_name: self.state.hello_name.clone(),
            unread: self.state.unread,
            last_activity: self.state.last_activity,
            security: SecurityView::from_session(active_security.unwrap_or_default()),
            has_active_session: active_security.is_some(),
            pq_pinned: peer_pq.pq_pinned,
            peer_pq_capable: peer_pq.peer_pq_capable,
            allow_classical_exception: peer_pq.allow_classical_exception,
            downgrade_detected: peer_pq.downgrade_detected,
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
                self.state.hello_name = hello.name.clone();
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
        let entry = HistoryEntry {
            outgoing: false,
            at: now(),
            content: Some(content),
            place,
            ..HistoryEntry::default()
        };
        Ok((index, entry))
    }

    /// Tell the peer that its message at `clock` was read.
    fn tell_read(&mut self, clock: u64) {
        let events = self.state.events.get_or_insert_default();
        events.read.push(clock);
        keep_last(&mut events.read);
    }

    /// Record that history entry `index` does not require future unread acknowledgment (outgoing,
    /// greeting, evicted, or already displayed).
    pub(super) fn mark_index_acked(&mut self, index: u64) {
        insert_acked_range(&mut self.state.acked_ranges, index, index.saturating_add(1));
    }

    /// Mark the active session's greeting as confirmed delivered and drop any superseded fallback
    /// farewells from prior/deleted sessions. Returns `true` if contact state changed.
    pub(super) fn mark_greeting_confirmed(&mut self) -> bool {
        let changed = self.state.greeting_delivery != GREETING_DELIVERY_CONFIRMED
            || !self.state.fallback_farewells.is_empty();
        self.state.greeting_delivery = GREETING_DELIVERY_CONFIRMED;
        self.state.fallback_farewells.clear();
        changed
    }

    /// Whether the active local session still carries an unacknowledged initial message.
    pub(super) fn has_carried_initial(&self) -> bool {
        !proto::SessionState::from(self.session.state())
            .initial_message
            .is_empty()
    }

    /// How deleting this contact should handle farewell transmission.
    pub(super) fn farewell_mode(&self) -> FarewellMode {
        if self.state.request
            || self.state.quarantined
            || self.state.greeting_delivery == GREETING_DELIVERY_UNSENT
        {
            FarewellMode::Suppress
        } else if self.state.greeting_delivery == GREETING_DELIVERY_UNCERTAIN
            || (self.state.greeting_delivery == GREETING_DELIVERY_LEGACY_UNKNOWN
                && self.has_carried_initial())
        {
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
    /// on, and are forgotten once they wait for nothing more. Returns their steps, by history
    /// entry.
    pub(super) fn told(&mut self, events: &Events) -> Vec<(u64, Step)> {
        let mut steps = vec![];
        for (clocks, step) in [
            (&events.read, Step::Read),
            (&events.downloaded, Step::Downloaded),
        ] {
            for clock in clocks {
                let Some(at) = self
                    .state
                    .awaiting
                    .iter()
                    .position(|awaiting| awaiting.place == *clock)
                else {
                    continue;
                };
                // Read, or downloaded, which it opened to: what the peer writes next goes after.
                self.state.read_by_peer = self.state.read_by_peer.max(*clock);
                let awaiting = &mut self.state.awaiting[at];
                steps.push((awaiting.history_index, step));
                if step == Step::Read && awaiting.attachment {
                    awaiting.read = true;
                } else {
                    self.state.awaiting.remove(at);
                }
            }
        }
        steps
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
                Some(Kind::Hello(hello)) => Body::Hello(hello.name),
                Some(Kind::Deleted(_)) => Body::Deleted,
                Some(Kind::Attachment(pointer)) => Body::Remote(RemoteFile {
                    peer: self.peer,
                    index,
                    pointer,
                    clock,
                }),
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
    if raw.me != me.as_slice()
        || raw.peer != state.peer
        || raw.cursor > session::protocol::MAX_SAFE_INTEGER
    {
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
        let reason = validate_contact_state(state, me)
            .err()
            .unwrap_or_else(|| "corrupt contact record".to_string());
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
