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
    ContactState, HistoryEntry, SECURITY_ALERT_DOWNGRADE, SECURITY_ALERT_MANIFEST_EXPIRED,
    SECURITY_ALERT_NONE, SECURITY_ALERT_PQ_REQUIRED,
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
#[cfg_attr(
    not(any(feature = "ml-kem-1024", feature = "ml-kem-768", test)),
    allow(dead_code)
)]
pub(super) fn record_quarantined_initial_state(
    state: &mut ContactState,
    held_session: Option<proto::SessionState>,
    first_message: Vec<u8>,
    peer_was_pq_pinned: bool,
    at: u64,
) {
    state.quarantined = true;
    state.quarantined_was_pq_pinned |= peer_was_pq_pinned;
    state.quarantined_session = held_session;
    state.quarantined_first_message = first_message;
    state.last_activity = at;
    if peer_was_pq_pinned {
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
        at: u64,
    ) {
        record_quarantined_initial_state(
            &mut self.state,
            held_session,
            first_message,
            peer_was_pq_pinned,
            at,
        );
        if peer_was_pq_pinned {
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
            Some(Kind::Hello(hello)) => self.state.hello_name = hello.name.clone(),
            _ if !open => self.state.unread = self.state.unread.saturating_add(1),
            _ => {}
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

    /// Count the chat's messages as read, as it is on screen; the peer is told of those it was
    /// not told of. Returns whether that changed anything.
    pub(super) fn read_all(&mut self) -> bool {
        let unseen = std::mem::take(&mut self.state.unseen);
        let changed = self.state.unread > 0 || !unseen.is_empty();
        self.state.unread = 0;
        for clock in unseen {
            self.tell_read(clock);
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
