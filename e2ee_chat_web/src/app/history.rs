//! Browser session-history integration for opening and closing chats.
//!
//! Entering a chat stamps chat-list entries with an opaque session-scoped list token and pushes a
//! single same-URL chat entry with an opaque session-scoped chat token so mobile "go back"
//! gestures (and browser Back) return to the chat list instead of closing or leaving the site,
//! without putting peer identity keys into URLs or persistent history state.

use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    time::Duration,
};

use leptos::{ev, prelude::*, task::spawn_local};
use session::PublicKey;
use wasm_bindgen::JsValue;

use crate::{
    engine::OpenOutcome,
    state::{Dialog, Phase, Ui},
    util::hex,
};

use super::{engine, media::cancel_pending_previews, ui};

/// Prefix for opaque session-scoped chat tokens stored in `window.history.state`.
const STATE_PREFIX: &str = "ratchetx2-chat:";
/// Prefix for opaque session-scoped chat-list tokens stored in `window.history.state`.
const LIST_PREFIX: &str = "ratchetx2-list:";
/// Prefix for opaque session-scoped fragment markers stacked above an active chat/reservation.
const FRAG_PREFIX: &str = "ratchetx2-frag:";

/// Maximum number of session-local chat tokens kept in memory for browser Forward navigation.
pub(super) const MAX_ENTRIES: usize = 64;

/// Time to wait for `popstate` after a programmatic `history.back()` before assuming the browser
/// silently ignored it (e.g. Chromium history rate-limiting) and recovering directly.
const BACK_SETTLE_TIMEOUT: Duration = Duration::from_millis(500);

fn is_any_chat_token(raw: &str) -> bool {
    raw.starts_with(STATE_PREFIX)
}

fn is_any_list_token(raw: &str) -> bool {
    raw.starts_with(LIST_PREFIX)
}

fn parse_any_frag_depth(raw: &str) -> Option<usize> {
    let rest = raw.strip_prefix(FRAG_PREFIX)?;
    let (_session, rest) = rest.split_once(':')?;
    let (_slot_id, depth) = rest.split_once(':')?;
    depth.parse().ok()
}

/// Handle returned by [`ChatHistory::reserve`] during a `NewChat` or `SignIn` submit gesture so
/// completion can commit the reserved entry or honor any newer user navigation (such as Back,
/// Forward, native dialog cancellation, or a newer submission).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reservation {
    /// Ownership of a reserved chat-level history entry pushed during the submit gesture.
    Pushed(u64),
    /// No new entry was pushed (a chat/reusable entry or Back unwind was active, or `pushState`
    /// failed); `nav_epoch` and `res_id` verify no newer navigation or submission superseded it.
    Unpushed { nav_epoch: u64, res_id: u64 },
}

/// Browser History API call to perform for a navigation transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HistoryOp {
    /// Optionally stamp the list entry in place with `tag_list`, then push a new same-URL history
    /// entry with `chat_token`.
    Push {
        tag_list: Option<String>,
        chat_token: String,
    },
    /// Replace the current same-URL chat-level history entry with this opaque chat state token.
    Replace(String),
    /// Best-effort in-place `replaceState` tagging a list or fragment entry with an opaque marker.
    Tag(String),
    /// Step back one entry, identified by `attempt` for timeout recovery if the browser silently
    /// ignores `history.back()`.
    Back(u64),
}

/// UI action to perform alongside a history transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum UiAction {
    None,
    Open(PublicKey),
    Close,
}

/// Combined browser-history and UI transition returned by [`ChatHistory`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Transition {
    pub(super) history: Option<HistoryOp>,
    pub(super) ui: UiAction,
    /// Whether this navigation superseded an active `NewChat` / auto-start `SignIn` submission so
    /// the engine submission should be cancelled and the startup modal dismissed synchronously.
    pub(super) dismiss_startup: bool,
    /// The browser's actual entry *immediately before* `history` is attempted, passed to
    /// [`ChatHistory::on_write_failed`] if `Push`, `Replace`, or `Tag` throws or is ignored.
    pub(super) fallback_active: Option<ActiveEntry>,
}

impl Transition {
    fn noop() -> Self {
        Self {
            history: None,
            ui: UiAction::None,
            dismiss_startup: false,
            fallback_active: None,
        }
    }

    fn ui_only(ui: UiAction) -> Self {
        Self {
            history: None,
            ui,
            dismiss_startup: false,
            fallback_active: None,
        }
    }
}

/// What the current chat-level browser history entry represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EntryKind {
    /// An open chat with `peer`.
    Chat(PublicKey),
    /// Reserved synchronously during a `NewChat` / `SignIn` submit gesture before `peer` is known
    /// (`Some(res_id)` while owned by an in-flight submission; `None` while retained by an open
    /// startup modal awaiting retry or dismissal).
    Reserved(Option<u64>),
    /// The browser cursor is already on a chat-level entry (e.g. after reloading/locking while a
    /// chat or fragment was open, Forward onto a deleted chat, or after a failed/ignored
    /// `history.back()`) while the chat list is shown; the next chat open reuses this slot via
    /// `replaceState` instead of stacking another level.
    Reusable,
}

/// Snapshot of the currently active chat-level browser entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ActiveEntry {
    /// Token ID belonging to this session, or `None` for a pre-reload or fragment entry.
    pub(super) id: Option<u64>,
    /// Stable stack-slot ID preserved across in-place `replaceState` peer switches so Forward
    /// `#fragment` markers remain bound to the surviving peer on this slot.
    pub(super) slot: Option<u64>,
    pub(super) kind: EntryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackGoal {
    /// Return to the chat list and close the UI if the traversal aborts (in-app Back/Close).
    CloseToList,
    /// Return to the chat list without closing UI or advancing `nav_epoch` on settlement (external
    /// deletion, failed open from list, or cancelled reservation).
    UnwindToList,
    /// Step back off manual `#fragment` entries onto the underlying chat entry, then open
    /// `deferred_open` via `replaceState`.
    UnwindFragmentsForOpen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingBack {
    attempt: u64,
    goal: BackGoal,
    /// Bounded number of extra `history.back()` hops permitted while unwinding manual `#fragment`
    /// entries so traversal is guaranteed to terminate.
    remaining_hops: usize,
}

/// Pure state machine synchronizing open chats with a single browser history level above the chat
/// list.
///
/// Peer keys are never placed into URLs or `history.state`; `history.state` holds only opaque
/// per-page-load tokens (`"ratchetx2-list:<session>"`, `"ratchetx2-chat:<session>:<id>"`, and
/// `"ratchetx2-frag:<session>:<chat_id>:<depth>"`) mapped back to a [`PublicKey`] strictly in WASM
/// memory.
#[derive(Debug)]
pub(super) struct ChatHistory {
    session: String,
    list_hash: String,
    /// Whether the current list entry has been stamped with `"ratchetx2-list:<session>"`.
    list_tagged: bool,
    /// Whether any earlier same-document list entry may still lack a list tag (e.g. if we loaded
    /// onto a pre-reload chat token or `replaceState` failed on an earlier list entry).
    untagged_list_entry_exists: bool,
    /// Hashes of list entries whose tagging failed, so navigating back to them is never mistaken
    /// for a `#fragment` above a chat.
    known_untagged_list_hashes: HashSet<String>,
    active: Option<ActiveEntry>,
    /// Number of manual same-document `#fragment` entries currently stacked above `active`.
    fragment_depth: usize,
    pending_back: Option<PendingBack>,
    deferred_open: Option<PublicKey>,
    /// Latest active [`Reservation::Unpushed`] ID, ensuring a newer submission supersedes an older
    /// unpushed submission.
    latest_unpushed_reservation: Option<u64>,
    /// Whether an unpushed startup flow (started from an already-open chat or after a failed push)
    /// is retained by an open `NewChat` / `SignIn` modal so browser Back/Forward still dismisses
    /// the modal and cancels its pending draft.
    retained_unpushed_startup: bool,
    nav_epoch: u64,
    next_id: u64,
    next_reservation: u64,
    next_back_attempt: u64,
    /// Maps session-local chat token IDs (`ratchetx2-chat:<session>:<id>`) to `(slot, depth)`,
    /// preserving extra fragment depth for tokens written during `on_back_aborted` recovery.
    entries: VecDeque<(u64, u64, usize)>,
    /// Maps each stack `slot` (used by both chat tokens and `ratchetx2-frag:<session>:<slot>:<d>`)
    /// to the current surviving peer on that slot.
    slots: VecDeque<(u64, PublicKey)>,
}

impl ChatHistory {
    pub(super) fn new(
        session: String,
        initial_raw_state: Option<&str>,
        initial_hash: String,
    ) -> Self {
        let list_token = format!("{LIST_PREFIX}{session}");
        let list_tagged = initial_raw_state == Some(list_token.as_str());
        let pre_reload_frag_depth = initial_raw_state.and_then(parse_any_frag_depth);
        let starts_on_chat =
            pre_reload_frag_depth.is_some() || initial_raw_state.is_some_and(is_any_chat_token);
        let active = starts_on_chat.then_some(ActiveEntry {
            id: None,
            slot: None,
            kind: EntryKind::Reusable,
        });
        Self {
            session,
            list_hash: initial_hash,
            list_tagged,
            untagged_list_entry_exists: starts_on_chat,
            known_untagged_list_hashes: HashSet::new(),
            active,
            fragment_depth: pre_reload_frag_depth.unwrap_or(0),
            pending_back: None,
            deferred_open: None,
            latest_unpushed_reservation: None,
            retained_unpushed_startup: false,
            nav_epoch: 0,
            next_id: 0,
            next_reservation: 0,
            next_back_attempt: 0,
            entries: VecDeque::new(),
            slots: VecDeque::new(),
        }
    }

    fn list_token(&self) -> String {
        format!("{LIST_PREFIX}{}", self.session)
    }

    fn frag_token(&self, slot_id: Option<u64>, depth: usize) -> String {
        format!(
            "{FRAG_PREFIX}{}:{}:{depth}",
            self.session,
            slot_id.unwrap_or(0)
        )
    }

    fn is_current_list_token(&self, raw: Option<&str>) -> bool {
        raw.is_some_and(|raw| raw.strip_prefix(LIST_PREFIX) == Some(self.session.as_str()))
    }

    fn all_list_entries_tagged(&self) -> bool {
        self.list_tagged && !self.untagged_list_entry_exists
    }

    fn bump_nav_epoch(&mut self) {
        self.nav_epoch = self.nav_epoch.wrapping_add(1);
    }

    fn format_token(&self, id: u64) -> String {
        format!("{STATE_PREFIX}{}:{id}", self.session)
    }

    fn next_token_id(&mut self) -> u64 {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.next_id
    }

    fn next_reservation_id(&mut self) -> u64 {
        self.next_reservation = self.next_reservation.wrapping_add(1).max(1);
        self.next_reservation
    }

    fn bind_slot(&mut self, slot: u64, peer: PublicKey) {
        self.slots.retain(|(slot_id, _)| *slot_id != slot);
        if self.slots.len() >= MAX_ENTRIES {
            self.slots.pop_front();
        }
        self.slots.push_back((slot, peer));
    }

    fn bind_token_slot(&mut self, token_id: u64, slot: u64, depth: usize) {
        if let Some((_, existing_slot, existing_depth)) = self
            .entries
            .iter_mut()
            .find(|(entry_id, _, _)| *entry_id == token_id)
        {
            *existing_slot = slot;
            *existing_depth = depth;
            return;
        }
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back((token_id, slot, depth));
    }

    fn bind_entry(&mut self, token_id: u64, slot: u64, peer: PublicKey, depth: usize) {
        self.bind_token_slot(token_id, slot, depth);
        self.bind_slot(slot, peer);
    }

    fn allocate_chat(&mut self, peer: PublicKey, existing_slot: Option<u64>) -> String {
        let id = self.next_token_id();
        let slot = existing_slot.unwrap_or(id);
        self.bind_entry(id, slot, peer, self.fragment_depth);
        self.active = Some(ActiveEntry {
            id: Some(id),
            slot: Some(slot),
            kind: EntryKind::Chat(peer),
        });
        self.format_token(id)
    }

    fn begin_back(&mut self, goal: BackGoal, remaining_hops: usize) -> u64 {
        self.next_back_attempt = self.next_back_attempt.wrapping_add(1).max(1);
        let attempt = self.next_back_attempt;
        self.pending_back = Some(PendingBack {
            attempt,
            goal,
            remaining_hops,
        });
        attempt
    }

    /// Initiate a programmatic back hop skipping an underlying duplicate chat/fragment entry after
    /// native Back stepped off a fragment-recovered chat token, invalidating any in-flight startup
    /// reservation from before the native Back gesture.
    fn skip_recovered_underlying(
        &mut self,
        remaining_hops: usize,
        dismiss_startup: bool,
    ) -> Transition {
        self.deferred_open = None;
        self.bump_nav_epoch();
        self.latest_unpushed_reservation = None;
        self.retained_unpushed_startup = false;
        let attempt = self.begin_back(BackGoal::CloseToList, remaining_hops);
        Transition {
            history: Some(HistoryOp::Back(attempt)),
            ui: UiAction::None,
            dismiss_startup,
            fallback_active: self.active,
        }
    }

    fn parse_token(&self, raw: Option<&str>) -> Option<u64> {
        let rest = raw?.strip_prefix(STATE_PREFIX)?;
        let (session, id) = rest.split_once(':')?;
        if session != self.session {
            return None;
        }
        id.parse().ok()
    }

    fn parse_frag_token(&self, raw: Option<&str>) -> Option<(Option<u64>, usize)> {
        let rest = raw?.strip_prefix(FRAG_PREFIX)?;
        let (session, rest) = rest.split_once(':')?;
        if session != self.session {
            return None;
        }
        let (slot_id, depth) = rest.split_once(':')?;
        let slot_id: u64 = slot_id.parse().ok()?;
        let depth: usize = depth.parse().ok()?;
        Some(((slot_id != 0).then_some(slot_id), depth))
    }

    fn lookup_token_meta(&self, token_id: u64) -> Option<(u64, usize)> {
        self.entries
            .iter()
            .rev()
            .find_map(|(entry_id, slot, depth)| (*entry_id == token_id).then_some((*slot, *depth)))
    }

    fn lookup_slot_peer(&self, slot: u64) -> Option<PublicKey> {
        self.slots
            .iter()
            .rev()
            .find_map(|(slot_id, peer)| (*slot_id == slot).then_some(*peer))
    }

    fn lookup_token_entry(&self, token_id: u64) -> Option<(u64, PublicKey, usize)> {
        let (slot, depth) = self.lookup_token_meta(token_id)?;
        let peer = self.lookup_slot_peer(slot)?;
        Some((slot, peer, depth))
    }

    fn forget_peer(&mut self, peer: &PublicKey) {
        self.slots.retain(|(_, slot_peer)| slot_peer != peer);
        let live_slots: HashSet<u64> = self.slots.iter().map(|(slot_id, _)| *slot_id).collect();
        self.entries
            .retain(|(_, slot_id, _)| live_slots.contains(slot_id));
    }

    /// Invalidate all cached Forward chat tokens and fragment markers for `peer` once deletion
    /// commits (even if the user already navigated away before the vault write finished).
    pub(super) fn on_peer_deleted(&mut self, peer: PublicKey) {
        self.forget_peer(&peer);
    }

    fn forget_token(&mut self, id: u64) {
        self.entries.retain(|(entry_id, _, _)| *entry_id != id);
    }

    fn forget_slot(&mut self, slot: u64) {
        self.slots.retain(|(slot_id, _)| *slot_id != slot);
        self.entries.retain(|(_, slot_id, _)| *slot_id != slot);
    }

    fn make_push(&mut self, chat_token: String) -> HistoryOp {
        let tag_list = if self.list_tagged {
            None
        } else {
            self.list_tagged = true;
            Some(self.list_token())
        };
        HistoryOp::Push {
            tag_list,
            chat_token,
        }
    }

    fn is_untagged_foreign_fragment(&self, raw_state: Option<&str>, current_hash: &str) -> bool {
        if raw_state.is_some() {
            return false;
        }
        if self.all_list_entries_tagged() {
            // Every list entry visited in this document has been stamped with `LIST_PREFIX`, so
            // any `null`-state same-document `popstate` while on a chat is a new fragment (even
            // `#` with an empty hash).
            true
        } else {
            !current_hash.is_empty()
                && current_hash != self.list_hash
                && !self.known_untagged_list_hashes.contains(current_hash)
        }
    }

    /// Stamp the initial list entry in place so older list entries reached later via the
    /// browser's Back menu remain distinguishable from `#fragments` pushed above a chat.
    pub(super) fn tag_current_list_entry(&mut self) -> Option<HistoryOp> {
        if self.active.is_none() && !self.list_tagged {
            self.list_tagged = true;
            return Some(HistoryOp::Tag(self.list_token()));
        }
        None
    }

    /// Synchronize cursor state when `popstate` fires while the vault is locked (e.g. stepping
    /// back from a pre-reload chat or fragment token onto the list before unlocking) without
    /// opening any chat.
    pub(super) fn on_locked_popstate(&mut self, raw_state: Option<&str>) -> Option<HistoryOp> {
        self.pending_back = None;
        self.deferred_open = None;
        if let Some((slot_id, depth)) = self.parse_frag_token(raw_state) {
            self.active = Some(ActiveEntry {
                id: None,
                slot: slot_id,
                kind: EntryKind::Reusable,
            });
            self.fragment_depth = depth;
            None
        } else if let Some(depth) = raw_state.and_then(parse_any_frag_depth) {
            self.active = Some(ActiveEntry {
                id: None,
                slot: None,
                kind: EntryKind::Reusable,
            });
            self.fragment_depth = depth;
            None
        } else if raw_state.is_some_and(is_any_chat_token) {
            let token_id = self.parse_token(raw_state);
            let meta = token_id.and_then(|id| self.lookup_token_meta(id));
            self.active = Some(ActiveEntry {
                id: token_id,
                slot: meta.map(|(slot, _)| slot),
                kind: EntryKind::Reusable,
            });
            self.fragment_depth = meta.map_or(0, |(_, depth)| depth);
            None
        } else {
            self.active = None;
            self.fragment_depth = 0;
            self.list_tagged = self.is_current_list_token(raw_state);
            if !self.list_tagged {
                self.list_tagged = true;
                Some(HistoryOp::Tag(self.list_token()))
            } else {
                None
            }
        }
    }

    /// Record that stamping a list entry failed or was silently ignored so fallback matching
    /// conservatively treats that hash (and empty hash) as a potential list entry.
    pub(super) fn on_list_tag_failed(&mut self, current_hash: &str) {
        self.list_tagged = false;
        self.untagged_list_entry_exists = true;
        self.known_untagged_list_hashes
            .insert(current_hash.to_string());
    }

    /// Whether `reservation` is still owned by the submission that created it (not cancelled by
    /// browser Back, Forward, native dialog close, or a newer navigation/submission).
    pub(super) fn is_reservation_owned(&self, reservation: Option<Reservation>) -> bool {
        match reservation {
            Some(Reservation::Pushed(res_id)) => {
                self.pending_back.is_none()
                    && matches!(
                        self.active,
                        Some(ActiveEntry {
                            kind: EntryKind::Reserved(Some(active_res)),
                            ..
                        }) if active_res == res_id
                    )
            }
            Some(Reservation::Unpushed { nav_epoch, res_id }) => {
                self.nav_epoch == nav_epoch && self.latest_unpushed_reservation == Some(res_id)
            }
            None => true,
        }
    }

    /// Reserve a chat-level history entry synchronously during a form submit gesture (`NewChat` or
    /// `SignIn` auto-start), transferring ownership of any active or retained reserved slot (even
    /// beneath a manual `#fragment`) so retries keep the gesture-pushed entry and an older
    /// submission can never commit or unwind a newer one.
    pub(super) fn reserve(&mut self, current_hash: &str) -> (Reservation, Option<HistoryOp>) {
        self.retained_unpushed_startup = false;
        if self.pending_back.is_some() {
            let res_id = self.next_reservation_id();
            self.latest_unpushed_reservation = Some(res_id);
            return (
                Reservation::Unpushed {
                    nav_epoch: self.nav_epoch,
                    res_id,
                },
                None,
            );
        }
        // Transfer ownership of an already-reserved (active or retained) slot regardless of
        // `fragment_depth` so retries preserve the gesture-pushed entry and an earlier submission
        // is immediately revoked.
        if let Some(ActiveEntry {
            id: Some(token_id),
            slot,
            kind: EntryKind::Reserved(_),
        }) = self.active
        {
            let res_id = self.next_reservation_id();
            self.latest_unpushed_reservation = None;
            self.active = Some(ActiveEntry {
                id: Some(token_id),
                slot: slot.or(Some(token_id)),
                kind: EntryKind::Reserved(Some(res_id)),
            });
            return (Reservation::Pushed(res_id), None);
        }
        if self.active.is_some() {
            let res_id = self.next_reservation_id();
            self.latest_unpushed_reservation = Some(res_id);
            return (
                Reservation::Unpushed {
                    nav_epoch: self.nav_epoch,
                    res_id,
                },
                None,
            );
        }
        self.list_hash = current_hash.to_string();
        let res_id = self.next_reservation_id();
        self.latest_unpushed_reservation = None;
        let id = self.next_token_id();
        self.active = Some(ActiveEntry {
            id: Some(id),
            slot: Some(id),
            kind: EntryKind::Reserved(Some(res_id)),
        });
        let chat_token = self.format_token(id);
        (
            Reservation::Pushed(res_id),
            Some(self.make_push(chat_token)),
        )
    }

    /// Convert a failed pushed reservation into an unpushed handle so the submission can still
    /// commit unless the user navigates away first.
    pub(super) fn on_reserve_push_failed(
        &mut self,
        op: &HistoryOp,
        current_hash: &str,
    ) -> Reservation {
        self.on_write_failed(op, None, current_hash);
        let res_id = self.next_reservation_id();
        self.latest_unpushed_reservation = Some(res_id);
        Reservation::Unpushed {
            nav_epoch: self.nav_epoch,
            res_id,
        }
    }

    /// Commit a reservation when chat startup succeeds, honoring any Back, Forward, native
    /// dismissal, or newer navigation/submission that happened while startup waited on the relay.
    pub(super) fn commit_reservation(
        &mut self,
        reservation: Option<Reservation>,
        peer: PublicKey,
        current_hash: &str,
    ) -> Transition {
        match reservation {
            Some(Reservation::Pushed(res_id)) => {
                if self.pending_back.is_none()
                    && let Some(ActiveEntry {
                        id: Some(token_id),
                        slot,
                        kind: EntryKind::Reserved(Some(active_res)),
                    }) = self.active
                    && active_res == res_id
                {
                    self.latest_unpushed_reservation = None;
                    self.retained_unpushed_startup = false;
                    self.bump_nav_epoch();
                    if self.fragment_depth > 0 {
                        self.deferred_open = Some(peer);
                        let attempt = self.begin_back(
                            BackGoal::UnwindFragmentsForOpen,
                            self.fragment_depth.saturating_sub(1),
                        );
                        return Transition {
                            history: Some(HistoryOp::Back(attempt)),
                            ui: UiAction::None,
                            dismiss_startup: false,
                            fallback_active: self.active,
                        };
                    }
                    let slot_id = slot.unwrap_or(token_id);
                    self.bind_entry(token_id, slot_id, peer, 0);
                    self.active = Some(ActiveEntry {
                        id: Some(token_id),
                        slot: Some(slot_id),
                        kind: EntryKind::Chat(peer),
                    });
                    return Transition::ui_only(UiAction::Open(peer));
                }
                Transition::noop()
            }
            Some(Reservation::Unpushed { nav_epoch, res_id }) => {
                if self.nav_epoch != nav_epoch || self.latest_unpushed_reservation != Some(res_id) {
                    return Transition::noop();
                }
                self.latest_unpushed_reservation = None;
                self.retained_unpushed_startup = false;
                self.user_open(peer, current_hash)
            }
            None => self.user_open(peer, current_hash),
        }
    }

    /// Release ownership of `reservation` after a retryable failure or `NewChat <-> SignIn`
    /// handoff while retaining a pushed history slot (`EntryKind::Reserved(None)`) or unpushed
    /// startup attachment (`retained_unpushed_startup`) for the still-open startup modal so retries
    /// keep the submit-gesture entry and browser Back still dismisses the modal.
    pub(super) fn retain_reservation(&mut self, reservation: Option<Reservation>) -> bool {
        match reservation {
            Some(Reservation::Pushed(res_id)) => {
                if self.pending_back.is_some() {
                    return false;
                }
                if let Some(ActiveEntry {
                    id,
                    slot,
                    kind: EntryKind::Reserved(Some(active_res)),
                }) = self.active
                    && active_res == res_id
                {
                    self.active = Some(ActiveEntry {
                        id,
                        slot,
                        kind: EntryKind::Reserved(None),
                    });
                    return true;
                }
                false
            }
            Some(Reservation::Unpushed { nav_epoch, res_id }) => {
                if self.nav_epoch == nav_epoch && self.latest_unpushed_reservation == Some(res_id) {
                    self.latest_unpushed_reservation = None;
                    self.retained_unpushed_startup = true;
                    true
                } else {
                    false
                }
            }
            None => true,
        }
    }

    /// Revoke any active submission's ownership while keeping a pushed slot or unpushed startup
    /// attachment retained for a restored startup modal (e.g. dismissing `SignInDialog` back to
    /// `NewChat`).
    pub(super) fn retain_active_reservation(&mut self) {
        if self.latest_unpushed_reservation.take().is_some() {
            self.retained_unpushed_startup = true;
        }
        if self.pending_back.is_none()
            && let Some(ActiveEntry {
                id,
                slot,
                kind: EntryKind::Reserved(Some(_)),
            }) = self.active
        {
            self.active = Some(ActiveEntry {
                id,
                slot,
                kind: EntryKind::Reserved(None),
            });
        }
    }

    /// Release an uncommitted reservation after startup is cancelled or closes without opening a
    /// chat.
    ///
    /// Returns `(still_owned, history_op)` where `still_owned` is `false` if Back, Forward, native
    /// dialog cancellation, or a newer submission already superseded this reservation.
    pub(super) fn cancel_reservation(
        &mut self,
        reservation: Option<Reservation>,
    ) -> (bool, Option<HistoryOp>) {
        match reservation {
            Some(Reservation::Pushed(res_id)) => {
                if self.pending_back.is_some() {
                    return (false, None);
                }
                if matches!(
                    self.active,
                    Some(ActiveEntry {
                        kind: EntryKind::Reserved(Some(active_res)),
                        ..
                    }) if active_res == res_id
                ) {
                    let attempt = self.begin_back(BackGoal::UnwindToList, self.fragment_depth);
                    return (true, Some(HistoryOp::Back(attempt)));
                }
                (false, None)
            }
            Some(Reservation::Unpushed { nav_epoch, res_id }) => {
                if self.nav_epoch == nav_epoch && self.latest_unpushed_reservation == Some(res_id) {
                    self.latest_unpushed_reservation = None;
                    self.retained_unpushed_startup = false;
                    (true, None)
                } else {
                    (false, None)
                }
            }
            None => (true, None),
        }
    }

    /// Unwind an idle retained startup slot (`EntryKind::Reserved(None)`) or clear a retained
    /// unpushed startup attachment once the startup modal closes without committing a chat.
    pub(super) fn cancel_retained_reservation(&mut self) -> Option<HistoryOp> {
        self.retained_unpushed_startup = false;
        if self.pending_back.is_none()
            && matches!(
                self.active,
                Some(ActiveEntry {
                    kind: EntryKind::Reserved(None),
                    ..
                })
            )
        {
            let attempt = self.begin_back(BackGoal::UnwindToList, self.fragment_depth);
            return Some(HistoryOp::Back(attempt));
        }
        None
    }

    /// Revoke any currently active or retained reservation (called synchronously when the user
    /// dismisses `NewChat` or `SignInDialog` natively via Escape or a dialog close request),
    /// unwinding a pushed reserved entry back to the list.
    pub(super) fn cancel_active_reservation(&mut self) -> Option<HistoryOp> {
        self.latest_unpushed_reservation = None;
        self.retained_unpushed_startup = false;
        if self.pending_back.is_none()
            && matches!(
                self.active,
                Some(ActiveEntry {
                    kind: EntryKind::Reserved(_),
                    ..
                })
            )
        {
            let attempt = self.begin_back(BackGoal::UnwindToList, self.fragment_depth);
            return Some(HistoryOp::Back(attempt));
        }
        None
    }

    /// Handle a user-initiated request to open `peer`.
    pub(super) fn user_open(&mut self, peer: PublicKey, current_hash: &str) -> Transition {
        self.bump_nav_epoch();
        self.latest_unpushed_reservation = None;
        self.retained_unpushed_startup = false;
        if self.pending_back.is_some() {
            // A programmatic `history.back()` is already in flight; open `peer` as soon as its
            // `popstate` (or timeout recovery) settles.
            self.deferred_open = Some(peer);
            return Transition::noop();
        }
        if self.fragment_depth > 0 && self.active.is_some() {
            // Unwind manual `#fragment` entries back onto the chat entry before replacing it so
            // switching peers never leaves the old chat underneath the new one.
            self.deferred_open = Some(peer);
            let attempt = self.begin_back(
                BackGoal::UnwindFragmentsForOpen,
                self.fragment_depth.saturating_sub(1),
            );
            return Transition {
                history: Some(HistoryOp::Back(attempt)),
                ui: UiAction::None,
                dismiss_startup: false,
                fallback_active: self.active,
            };
        }
        self.open_peer(peer, current_hash)
    }

    fn open_peer(&mut self, peer: PublicKey, current_hash: &str) -> Transition {
        let fallback_active = self.active;
        if let Some(active) = self.active {
            if active.kind == EntryKind::Chat(peer) {
                return Transition::ui_only(UiAction::Open(peer));
            }
            // Already on a chat-level entry (switching chats, overwriting a reservation, or
            // reusing a leftover pre-reload / deleted / fallback slot): replace in place on the
            // same stack `slot` so one Back gesture returns to the list and any Forward `#fragment`
            // markers stay bound to `peer`.
            let token = self.allocate_chat(peer, active.slot);
            return Transition {
                history: Some(HistoryOp::Replace(token)),
                ui: UiAction::Open(peer),
                dismiss_startup: false,
                fallback_active,
            };
        }
        self.list_hash = current_hash.to_string();
        let token = self.allocate_chat(peer, None);
        let push = self.make_push(token);
        Transition {
            history: Some(push),
            ui: UiAction::Open(peer),
            dismiss_startup: false,
            fallback_active,
        }
    }

    /// Handle a user-initiated request to close the current chat (in-app Back or Close button).
    pub(super) fn user_close(&mut self) -> Transition {
        self.bump_nav_epoch();
        self.latest_unpushed_reservation = None;
        self.retained_unpushed_startup = false;
        self.deferred_open = None;
        if let Some(pending) = &mut self.pending_back {
            if pending.goal == BackGoal::UnwindFragmentsForOpen {
                // Redirect an in-flight fragment unwind (from a peer switch) so it continues past
                // the underlying chat entry all the way back to the chat list.
                pending.goal = BackGoal::CloseToList;
                pending.remaining_hops = pending.remaining_hops.saturating_add(1);
            }
            // Ignore rapid double-taps while a close/unwind traversal is settling so we never step
            // back a second time and leave the site.
            return Transition::noop();
        }
        if matches!(
            self.active,
            Some(ActiveEntry {
                kind: EntryKind::Chat(_),
                ..
            })
        ) {
            let attempt = self.begin_back(BackGoal::CloseToList, self.fragment_depth);
            return Transition {
                history: Some(HistoryOp::Back(attempt)),
                ui: UiAction::None,
                dismiss_startup: false,
                fallback_active: self.active,
            };
        }
        Transition::ui_only(UiAction::Close)
    }

    /// Reconcile after `Engine::open(Some(failed_peer))` returned [`OpenOutcome::Ignored`].
    pub(super) fn on_open_failed(
        &mut self,
        failed_peer: PublicKey,
        actual_open: Option<PublicKey>,
    ) -> Transition {
        if self.pending_back.is_some()
            || !self
                .active
                .is_some_and(|entry| entry.kind == EntryKind::Chat(failed_peer))
        {
            return Transition::noop();
        }
        self.forget_peer(&failed_peer);
        match actual_open {
            None => {
                let attempt = self.begin_back(BackGoal::UnwindToList, self.fragment_depth);
                Transition {
                    history: Some(HistoryOp::Back(attempt)),
                    ui: UiAction::None,
                    dismiss_startup: false,
                    fallback_active: self.active,
                }
            }
            Some(current) if current != failed_peer => {
                if self.fragment_depth > 0 {
                    self.deferred_open = Some(current);
                    let attempt = self.begin_back(
                        BackGoal::UnwindFragmentsForOpen,
                        self.fragment_depth.saturating_sub(1),
                    );
                    return Transition {
                        history: Some(HistoryOp::Back(attempt)),
                        ui: UiAction::None,
                        dismiss_startup: false,
                        fallback_active: self.active,
                    };
                }
                let fallback_active = self.active;
                let existing_slot = fallback_active.and_then(|entry| entry.slot);
                let token = self.allocate_chat(current, existing_slot);
                Transition {
                    history: Some(HistoryOp::Replace(token)),
                    ui: UiAction::None,
                    dismiss_startup: false,
                    fallback_active,
                }
            }
            Some(_) => Transition::noop(),
        }
    }

    /// Reconcile when `ui.open` transitioned from `Some(closed_peer)` to `None` outside browser
    /// history navigation (e.g., deleting the currently open chat).
    pub(super) fn on_ui_closed(&mut self, closed_peer: PublicKey) -> Option<HistoryOp> {
        if self.pending_back.is_some()
            || !self
                .active
                .is_some_and(|entry| entry.kind == EntryKind::Chat(closed_peer))
        {
            return None;
        }
        self.forget_peer(&closed_peer);
        let attempt = self.begin_back(BackGoal::UnwindToList, self.fragment_depth);
        Some(HistoryOp::Back(attempt))
    }

    /// Handle a browser `popstate` event (mobile Back gesture, browser Back/Forward, manual
    /// `#fragment` change, or our own programmatic `history.back()`).
    pub(super) fn on_popstate(
        &mut self,
        raw_state: Option<&str>,
        current_hash: &str,
        startup_dialog_open: bool,
        contact_exists: impl Fn(&PublicKey) -> bool,
    ) -> Transition {
        let pending_back = self.pending_back.take();
        let prev_active = self.active;
        let prev_depth = self.fragment_depth;
        let prev_active_token_depth = prev_active
            .and_then(|entry| entry.id)
            .and_then(|id| self.lookup_token_meta(id))
            .map_or(0, |(_, depth)| depth);
        let prev_active_slot = prev_active.and_then(|entry| entry.slot);
        // Native Back directly off a fragment-recovered chat token (which lives above the
        // underlying chat/fragment entries because `UnwindFragmentsForOpen` timed out).
        let stepping_off_recovered_chat = pending_back.is_none()
            && prev_active_token_depth > 0
            && prev_depth == prev_active_token_depth
            && matches!(
                prev_active,
                Some(ActiveEntry {
                    kind: EntryKind::Chat(_),
                    ..
                })
            );
        let was_reserved = matches!(
            self.active,
            Some(ActiveEntry {
                kind: EntryKind::Reserved(_),
                ..
            })
        );
        let had_unpushed_startup =
            self.latest_unpushed_reservation.is_some() || self.retained_unpushed_startup;
        let has_startup = was_reserved || had_unpushed_startup || startup_dialog_open;

        if let Some(id) = self.parse_token(raw_state) {
            let token_meta = self.lookup_token_meta(id);
            let token_depth = token_meta.map_or(0, |(_, depth)| depth);
            self.fragment_depth = token_depth;

            // Unwinding fragments on the way back to the chat list: we just stepped off the
            // fragment (or a Back-recovered chat token) onto the underlying chat/reserved entry,
            // so step back once more to reach list.
            if let Some(back) = pending_back
                && matches!(back.goal, BackGoal::CloseToList | BackGoal::UnwindToList)
                && back.remaining_hops > 0
            {
                let attempt = self.begin_back(back.goal, back.remaining_hops - 1);
                return Transition {
                    history: Some(HistoryOp::Back(attempt)),
                    ui: UiAction::None,
                    dismiss_startup: false,
                    fallback_active: self.active,
                };
            }

            // Native Back off a fragment-recovered chat token landed on its underlying chat token
            // on the same slot: skip past the duplicate underlying chat back to the list so the
            // first Back gesture closes the chat as expected.
            if stepping_off_recovered_chat
                && token_depth < prev_active_token_depth
                && token_meta.is_some_and(|(slot, _)| Some(slot) == prev_active_slot)
            {
                return self.skip_recovered_underlying(token_depth, has_startup);
            }

            // Unwinding fragments before opening/switching peers: we are now back on the
            // chat/reserved entry, so replace it in place on the same slot with the deferred peer.
            if let Some(back) = pending_back
                && back.goal == BackGoal::UnwindFragmentsForOpen
                && let Some(peer) = self.deferred_open.take()
                && contact_exists(&peer)
            {
                let slot = token_meta.map(|(slot, _)| slot).or(Some(id));
                self.active = Some(ActiveEntry {
                    id: Some(id),
                    slot,
                    kind: EntryKind::Reusable,
                });
                return self.open_peer(peer, current_hash);
            }

            // Returning from a manual `#fragment` back onto a live or retained reservation: keep
            // the reservation intact instead of mistaking its unmapped token for a cancelled chat.
            if matches!(
                self.active,
                Some(ActiveEntry {
                    id: Some(active_id),
                    kind: EntryKind::Reserved(_),
                    ..
                }) if active_id == id
            ) {
                return Transition::noop();
            }

            if let Some((slot, peer, depth)) = self.lookup_token_entry(id)
                && contact_exists(&peer)
            {
                self.fragment_depth = depth;
                self.deferred_open = None;
                let changed = self
                    .active
                    .is_none_or(|entry| entry.kind != EntryKind::Chat(peer));
                self.active = Some(ActiveEntry {
                    id: Some(id),
                    slot: Some(slot),
                    kind: EntryKind::Chat(peer),
                });
                let dismiss_startup = changed && has_startup;
                if changed {
                    self.bump_nav_epoch();
                    self.latest_unpushed_reservation = None;
                    self.retained_unpushed_startup = false;
                }
                return Transition {
                    history: None,
                    ui: UiAction::Open(peer),
                    dismiss_startup,
                    fallback_active: None,
                };
            }

            // Forward navigated onto a deleted, evicted, or cancelled-reservation token of this
            // session: keep the chat list displayed and mark the slot reusable without calling
            // `history.back()`, so any later Forward entries remain reachable.
            self.deferred_open = None;
            let slot = token_meta.map(|(slot, _)| slot).or(Some(id));
            self.active = Some(ActiveEntry {
                id: Some(id),
                slot,
                kind: EntryKind::Reusable,
            });
            let is_programmatic_list_back = pending_back.is_some_and(|back| {
                matches!(back.goal, BackGoal::UnwindToList | BackGoal::CloseToList)
            });
            if !is_programmatic_list_back {
                self.bump_nav_epoch();
                self.latest_unpushed_reservation = None;
                self.retained_unpushed_startup = false;
            }
            return Transition {
                history: None,
                ui: UiAction::Close,
                dismiss_startup: !is_programmatic_list_back && has_startup,
                fallback_active: None,
            };
        }

        // Known fragment marker previously stacked above a chat/reservation slot (including a
        // direct Forward-menu jump from the list straight to the fragment without visiting its
        // intermediate chat entry first).
        if let Some((slot_id, depth)) = self.parse_frag_token(raw_state) {
            self.fragment_depth = depth;
            if let Some(back) = pending_back {
                if back.remaining_hops > 0 {
                    let attempt = self.begin_back(back.goal, back.remaining_hops - 1);
                    return Transition {
                        history: Some(HistoryOp::Back(attempt)),
                        ui: UiAction::None,
                        dismiss_startup: false,
                        fallback_active: self.active,
                    };
                }
                if back.goal == BackGoal::UnwindFragmentsForOpen
                    && let Some(peer) = self.deferred_open.take()
                    && contact_exists(&peer)
                {
                    self.active = Some(ActiveEntry {
                        id: None,
                        slot: slot_id,
                        kind: EntryKind::Reusable,
                    });
                    return self.open_peer(peer, current_hash);
                }
                self.deferred_open = None;
                self.active = Some(ActiveEntry {
                    id: None,
                    slot: slot_id,
                    kind: EntryKind::Reusable,
                });
                return Transition::ui_only(if back.goal == BackGoal::CloseToList {
                    UiAction::Close
                } else {
                    UiAction::None
                });
            }
            if stepping_off_recovered_chat
                && depth < prev_active_token_depth
                && slot_id.is_some()
                && slot_id == prev_active_slot
            {
                return self.skip_recovered_underlying(depth, has_startup);
            }
            if self.active.is_some() {
                return Transition::noop();
            }
            self.deferred_open = None;
            self.bump_nav_epoch();
            self.latest_unpushed_reservation = None;
            self.retained_unpushed_startup = false;
            if let Some(slot) = slot_id
                && let Some(peer) = self.lookup_slot_peer(slot)
                && contact_exists(&peer)
            {
                self.active = Some(ActiveEntry {
                    id: None,
                    slot: Some(slot),
                    kind: EntryKind::Chat(peer),
                });
                return Transition {
                    history: None,
                    ui: UiAction::Open(peer),
                    dismiss_startup: has_startup,
                    fallback_active: None,
                };
            }
            self.active = Some(ActiveEntry {
                id: None,
                slot: slot_id,
                kind: EntryKind::Reusable,
            });
            return Transition {
                history: None,
                ui: UiAction::Close,
                dismiss_startup: has_startup,
                fallback_active: None,
            };
        }

        // Pre-reload fragment marker from an earlier page session: never overwrite it with a list
        // tag. Continue unwinding if a programmatic traversal has hops left; otherwise treat it as
        // a stale chat-level entry preserving its depth.
        if let Some(depth) = raw_state.and_then(parse_any_frag_depth) {
            self.fragment_depth = depth;
            if let Some(back) = pending_back {
                if back.remaining_hops > 0 {
                    let attempt = self.begin_back(back.goal, back.remaining_hops - 1);
                    return Transition {
                        history: Some(HistoryOp::Back(attempt)),
                        ui: UiAction::None,
                        dismiss_startup: false,
                        fallback_active: self.active,
                    };
                }
                if back.goal == BackGoal::UnwindFragmentsForOpen
                    && let Some(peer) = self.deferred_open.take()
                    && contact_exists(&peer)
                {
                    self.active = Some(ActiveEntry {
                        id: None,
                        slot: None,
                        kind: EntryKind::Reusable,
                    });
                    return self.open_peer(peer, current_hash);
                }
            }
            if stepping_off_recovered_chat && depth < prev_active_token_depth {
                return self.skip_recovered_underlying(depth, has_startup);
            }
            self.deferred_open = None;
            self.active = Some(ActiveEntry {
                id: None,
                slot: None,
                kind: EntryKind::Reusable,
            });
            let is_programmatic_list_back = pending_back.is_some_and(|back| {
                matches!(back.goal, BackGoal::UnwindToList | BackGoal::CloseToList)
            });
            let is_programmatic_unwind =
                pending_back.is_some_and(|back| back.goal == BackGoal::UnwindToList);
            if !is_programmatic_list_back {
                self.bump_nav_epoch();
                self.latest_unpushed_reservation = None;
                self.retained_unpushed_startup = false;
            }
            return Transition {
                history: None,
                ui: if is_programmatic_unwind {
                    UiAction::None
                } else {
                    UiAction::Close
                },
                dismiss_startup: !is_programmatic_list_back && has_startup,
                fallback_active: None,
            };
        }

        // Newly pushed `#fragment` (or `#` when all list entries are tagged) above an active
        // chat/reservation entry. Known list entries (`is_any_list_token`) never enter this branch.
        if self.active.is_some()
            && !raw_state.is_some_and(is_any_list_token)
            && self.is_untagged_foreign_fragment(raw_state, current_hash)
        {
            if let Some(back) = pending_back {
                self.fragment_depth = self.fragment_depth.saturating_sub(1);
                if back.remaining_hops > 0 {
                    let attempt = self.begin_back(back.goal, back.remaining_hops - 1);
                    return Transition {
                        history: Some(HistoryOp::Back(attempt)),
                        ui: UiAction::None,
                        dismiss_startup: false,
                        fallback_active: self.active,
                    };
                }
                if back.goal == BackGoal::UnwindFragmentsForOpen
                    && let Some(peer) = self.deferred_open.take()
                    && contact_exists(&peer)
                {
                    self.fragment_depth = self.fragment_depth.max(1);
                    self.active = Some(ActiveEntry {
                        id: None,
                        slot: self.active.and_then(|e| e.slot),
                        kind: EntryKind::Reusable,
                    });
                    return self.open_peer(peer, current_hash);
                }
                self.deferred_open = None;
                self.active = Some(ActiveEntry {
                    id: None,
                    slot: self.active.and_then(|e| e.slot),
                    kind: EntryKind::Reusable,
                });
                return Transition::ui_only(if back.goal == BackGoal::CloseToList {
                    UiAction::Close
                } else {
                    UiAction::None
                });
            } else {
                self.fragment_depth = self.fragment_depth.saturating_add(1);
                let tag = self.frag_token(self.active.and_then(|e| e.slot), self.fragment_depth);
                return Transition {
                    history: Some(HistoryOp::Tag(tag)),
                    ui: UiAction::None,
                    dismiss_startup: false,
                    fallback_active: self.active,
                };
            }
        }

        self.fragment_depth = 0;
        let landed_on_pre_reload_chat = raw_state.is_some_and(is_any_chat_token);
        if landed_on_pre_reload_chat
            && let Some(back) = pending_back
            && matches!(back.goal, BackGoal::CloseToList | BackGoal::UnwindToList)
            && back.remaining_hops > 0
        {
            let attempt = self.begin_back(back.goal, back.remaining_hops - 1);
            return Transition {
                history: Some(HistoryOp::Back(attempt)),
                ui: UiAction::None,
                dismiss_startup: false,
                fallback_active: self.active,
            };
        }
        if landed_on_pre_reload_chat && stepping_off_recovered_chat {
            return self.skip_recovered_underlying(0, has_startup);
        }
        self.active = if landed_on_pre_reload_chat {
            // Landed on a pre-reload chat token from an earlier session: mark reusable so the next
            // open replaces it instead of stacking another level.
            Some(ActiveEntry {
                id: None,
                slot: None,
                kind: EntryKind::Reusable,
            })
        } else {
            None
        };
        // Keep `list_tagged` synchronized with the actual entry we landed on so untagged list
        // entries (such as `#one` typed while on the list) get stamped immediately.
        self.list_tagged = self.is_current_list_token(raw_state);

        // Settlement of a programmatic list-bound `history.back()` (`UnwindToList` or an earlier
        // in-app `CloseToList`) is NOT newer user navigation, so a NewChat/SignIn form or
        // reservation started while that back traversal was settling survives intact.
        let is_programmatic_list_back = pending_back.is_some_and(|back| {
            matches!(back.goal, BackGoal::UnwindToList | BackGoal::CloseToList)
        });
        if !is_programmatic_list_back {
            self.bump_nav_epoch();
            self.latest_unpushed_reservation = None;
            self.retained_unpushed_startup = false;
        }

        if let Some(peer) = self.deferred_open.take()
            && contact_exists(&peer)
        {
            return self.open_peer(peer, current_hash);
        }

        let tag_op = if !landed_on_pre_reload_chat && !self.list_tagged {
            self.list_tagged = true;
            Some(HistoryOp::Tag(self.list_token()))
        } else {
            None
        };

        let dismiss_startup = !is_programmatic_list_back && has_startup;
        let ui = if was_reserved {
            UiAction::None
        } else {
            UiAction::Close
        };

        Transition {
            history: tag_op,
            ui,
            dismiss_startup,
            fallback_active: None,
        }
    }

    /// Roll back or rebind internal state if a synchronous `Push`, `Replace`, or `Tag` threw or
    /// was silently ignored by the browser (verified via `history.state()`).
    pub(super) fn on_write_failed(
        &mut self,
        op: &HistoryOp,
        fallback_active: Option<ActiveEntry>,
        current_hash: &str,
    ) {
        match op {
            HistoryOp::Push { .. } => {
                if let Some(ActiveEntry {
                    id: Some(id),
                    slot,
                    kind: EntryKind::Chat(_),
                }) = self.active
                {
                    self.forget_token(id);
                    if let Some(slot) = slot {
                        self.forget_slot(slot);
                    }
                }
                self.active = fallback_active;
            }
            HistoryOp::Replace(_) => {
                let target_kind = self.active.map(|entry| entry.kind);
                let current_slot = self.active.and_then(|entry| entry.slot);
                if let Some(ActiveEntry { id: Some(id), .. }) = self.active {
                    self.forget_token(id);
                }
                // The browser kept `fallback_active`'s token; rebind that surviving token and its
                // slot to the newly displayed peer so Forward and open-chat deletion stay
                // consistent with UI.
                let surviving_id = fallback_active.and_then(|entry| entry.id);
                let surviving_slot = fallback_active
                    .and_then(|entry| entry.slot)
                    .or(current_slot)
                    .or(surviving_id);
                if let Some(EntryKind::Chat(peer)) = target_kind {
                    if let Some(slot) = surviving_slot {
                        self.bind_slot(slot, peer);
                        if let Some(id) = surviving_id {
                            self.bind_token_slot(id, slot, self.fragment_depth);
                        }
                    } else if let Some(id) = surviving_id {
                        self.bind_entry(id, id, peer, self.fragment_depth);
                    }
                }
                self.active = match (fallback_active, target_kind) {
                    (Some(_), Some(kind)) => Some(ActiveEntry {
                        id: surviving_id,
                        slot: surviving_slot,
                        kind,
                    }),
                    (prev, _) => prev,
                };
            }
            HistoryOp::Tag(token) => {
                if self.is_current_list_token(Some(token.as_str())) {
                    self.on_list_tag_failed(current_hash);
                }
            }
            HistoryOp::Back(_) => {}
        }
    }

    /// Recover when a programmatic `history.back()` threw synchronously or timed out without
    /// firing `popstate` (e.g. Chromium rate-limiting).
    ///
    /// Recognizes surviving chat OR fragment tokens (including pre-reload fragments and untagged
    /// fragments) and preserves `fragment_depth` and `slot` when replacing a fragment entry with a
    /// deferred peer so a subsequent in-app Close steps past the underlying chat entry all the way
    /// back to the list.
    pub(super) fn on_back_aborted(
        &mut self,
        attempt: u64,
        current_raw_state: Option<&str>,
        current_hash: &str,
        contact_exists: impl Fn(&PublicKey) -> bool,
    ) -> Transition {
        let Some(pending) = self.pending_back else {
            return Transition::noop();
        };
        if pending.attempt != attempt {
            return Transition::noop();
        }
        self.pending_back = None;
        if let Some((slot_id, depth)) = self.parse_frag_token(current_raw_state) {
            self.active = Some(ActiveEntry {
                id: None,
                slot: slot_id,
                kind: EntryKind::Reusable,
            });
            // Keep `depth` even when `deferred_open` replaces this fragment entry in place: the
            // underlying chat entry is still beneath it, so the next in-app Close needs `depth`
            // extra hops to reach the list instead of landing on the old chat.
            self.fragment_depth = depth;
        } else if let Some(depth) = current_raw_state.and_then(parse_any_frag_depth) {
            self.active = Some(ActiveEntry {
                id: None,
                slot: None,
                kind: EntryKind::Reusable,
            });
            self.fragment_depth = depth;
        } else if current_raw_state.is_some_and(is_any_chat_token) {
            let token_id = self.parse_token(current_raw_state);
            let meta = token_id.and_then(|id| self.lookup_token_meta(id));
            self.active = Some(ActiveEntry {
                id: token_id,
                slot: meta.map(|(slot, _)| slot),
                kind: EntryKind::Reusable,
            });
            self.fragment_depth = meta.map_or(0, |(_, depth)| depth);
        } else if self.active.is_some()
            && !current_raw_state.is_some_and(is_any_list_token)
            && self.is_untagged_foreign_fragment(current_raw_state, current_hash)
        {
            self.active = Some(ActiveEntry {
                id: None,
                slot: self.active.and_then(|entry| entry.slot),
                kind: EntryKind::Reusable,
            });
            self.fragment_depth = self.fragment_depth.max(1);
        } else {
            self.active = None;
            self.fragment_depth = 0;
            self.list_tagged = self.is_current_list_token(current_raw_state);
        }

        if let Some(peer) = self.deferred_open.take()
            && contact_exists(&peer)
        {
            return self.open_peer(peer, current_hash);
        }

        Transition::ui_only(if pending.goal == BackGoal::CloseToList {
            UiAction::Close
        } else {
            UiAction::None
        })
    }
}

fn random_session_id() -> String {
    let mut bytes = [0u8; 8];
    let _ = getrandom::fill(&mut bytes);
    hex(&bytes)
}

fn current_history_state() -> Option<String> {
    window()
        .history()
        .ok()
        .and_then(|history| history.state().ok())
        .and_then(|value| value.as_string())
}

fn current_location_hash() -> String {
    window().location().hash().unwrap_or_default()
}

thread_local! {
    static CHAT_HISTORY: RefCell<ChatHistory> = RefCell::new(ChatHistory::new(
        random_session_id(),
        current_history_state().as_deref(),
        current_location_hash(),
    ));
}

fn apply_history_op(op: &HistoryOp, current_hash: &str) -> bool {
    let Ok(history) = window().history() else {
        return false;
    };
    match op {
        HistoryOp::Push {
            tag_list,
            chat_token,
        } => {
            if let Some(list_token) = tag_list {
                let tagged = history
                    .replace_state_with_url(&JsValue::from_str(list_token), "", None)
                    .is_ok()
                    && current_history_state().as_deref() == Some(list_token.as_str());
                if !tagged {
                    CHAT_HISTORY.with(|state| state.borrow_mut().on_list_tag_failed(current_hash));
                }
            }
            history
                .push_state_with_url(&JsValue::from_str(chat_token), "", None)
                .is_ok()
                && current_history_state().as_deref() == Some(chat_token.as_str())
        }
        HistoryOp::Replace(token) | HistoryOp::Tag(token) => {
            history
                .replace_state_with_url(&JsValue::from_str(token), "", None)
                .is_ok()
                && current_history_state().as_deref() == Some(token.as_str())
        }
        HistoryOp::Back(_) => history.back().is_ok(),
    }
}

/// Dismiss chat-scoped overlays (file viewer and per-chat dialogs for any peer other than
/// `keep_peer`) and invalidate pending file previews so closing or switching chats never leaves
/// stale modals or late-arriving previews over the new view.
fn close_chat_overlays(ui: Ui, keep_peer: Option<PublicKey>) {
    cancel_pending_previews();
    if ui.viewer.with_untracked(Option::is_some) {
        ui.viewer.set(None);
    }
    if ui.opening.with_untracked(Option::is_some) {
        ui.opening.set(None);
    }
    if ui.streaming.with_untracked(Option::is_some) {
        ui.streaming.set(None);
    }
    let stale_dialog = ui.dialog.with_untracked(|dialog| {
        matches!(
            dialog,
            Some(Dialog::Contact(peer) | Dialog::Files(peer)) if Some(*peer) != keep_peer
        )
    });
    if stale_dialog {
        ui.dialog.set(None);
    }
}

/// Immediately return to the chat list without waiting for the engine mutex.
fn close_chat_immediately(ui: Ui) {
    close_chat_overlays(ui, None);
    engine().close_chat();
}

/// Synchronously cancel any active startup submission (suppressing late 403 sign-in prompts or
/// greetings), mark sign-in prompts declined when backing out of `Dialog::SignIn`, and dismiss a
/// currently displayed `NewChat` / `SignIn` modal.
fn dismiss_startup_dialog(ui: Ui) {
    engine().cancel_active_startup_submission();
    let (startup, was_sign_in) = ui.dialog.with_untracked(|dialog| {
        (
            matches!(dialog, Some(Dialog::NewChat { .. } | Dialog::SignIn)),
            matches!(dialog, Some(Dialog::SignIn)),
        )
    });
    if was_sign_in {
        engine().decline_sign_in_prompts();
    }
    if startup {
        ui.dialog.set(None);
    }
}

/// Apply `op` (if any), verifying synchronous writes against `fallback_active` and scheduling
/// timeout recovery for programmatic `history.back()`. Returns any recovery [`UiAction`] if
/// `history.back()` failed synchronously.
fn execute_history_op(
    op: Option<&HistoryOp>,
    fallback_active: Option<ActiveEntry>,
    current_hash: &str,
    ui: Ui,
) -> Option<UiAction> {
    let op = op?;
    if apply_history_op(op, current_hash) {
        if let HistoryOp::Back(attempt) = *op {
            schedule_back_recovery(attempt, ui);
        }
        return None;
    }
    match op {
        HistoryOp::Push { .. } | HistoryOp::Replace(_) | HistoryOp::Tag(_) => {
            CHAT_HISTORY.with(|history| {
                history
                    .borrow_mut()
                    .on_write_failed(op, fallback_active, current_hash);
            });
            None
        }
        HistoryOp::Back(attempt) => recover_aborted_back(*attempt, ui),
    }
}

fn schedule_back_recovery(attempt: u64, ui: Ui) {
    set_timeout(
        move || {
            if let Some(action) = recover_aborted_back(attempt, ui) {
                execute_ui_action(action, false, ui);
            }
        },
        BACK_SETTLE_TIMEOUT,
    );
}

fn recover_aborted_back(attempt: u64, ui: Ui) -> Option<UiAction> {
    let raw = current_history_state();
    let hash = current_location_hash();
    let transition = CHAT_HISTORY.with(|history| {
        history
            .borrow_mut()
            .on_back_aborted(attempt, raw.as_deref(), &hash, |peer| {
                ui.contact(peer).is_some()
            })
    });
    if let Some(op) = transition.history.as_ref()
        && !matches!(op, HistoryOp::Back(_))
        && !apply_history_op(op, &hash)
    {
        CHAT_HISTORY.with(|history| {
            history
                .borrow_mut()
                .on_write_failed(op, transition.fallback_active, &hash);
        });
    }
    (transition.ui != UiAction::None).then_some(transition.ui)
}

fn execute_ui_action(action: UiAction, dismiss_startup: bool, ui: Ui) {
    if dismiss_startup {
        dismiss_startup_dialog(ui);
    }
    match action {
        UiAction::None => {}
        UiAction::Close => close_chat_immediately(ui),
        UiAction::Open(peer) => {
            // Skip redundant reloads only when `peer` is already displayed AND no conflicting
            // open for another peer is waiting on the engine mutex.
            if !engine().is_settled_on(peer) {
                if ui.open.get_untracked() != Some(peer) {
                    cancel_pending_previews();
                }
                spawn_local(open_and_reconcile(peer));
            }
        }
    }
}

async fn open_and_reconcile(peer: PublicKey) {
    let outcome = engine().open(Some(peer)).await;
    if outcome == OpenOutcome::Ignored {
        let ui = ui();
        let actual_open = ui.open.get_untracked();
        let hash = current_location_hash();
        let transition =
            CHAT_HISTORY.with(|history| history.borrow_mut().on_open_failed(peer, actual_open));
        if let Some(action) = execute_history_op(
            transition.history.as_ref(),
            transition.fallback_active,
            &hash,
            ui,
        ) {
            execute_ui_action(action, false, ui);
        }
    }
}

fn tag_current_list_entry(ui: Ui, hash: &str) {
    let op = CHAT_HISTORY.with(|history| history.borrow_mut().tag_current_list_entry());
    let _ = execute_history_op(op.as_ref(), None, hash, ui);
}

/// Wire up browser `popstate` handling and peer-change / external-close reconciliation (such as
/// deleting the open chat or dismissing stale overlays when switching peers). Call once when
/// mounting [`App`](super::App).
pub(super) fn install(ui: Ui) {
    let initial_hash = current_location_hash();
    tag_current_list_entry(ui, &initial_hash);

    let _ = window_event_listener(ev::popstate, move |event: ev::PopStateEvent| {
        let raw = event.state().as_string();
        let hash = current_location_hash();
        if ui.phase.get_untracked() != Phase::Unlocked {
            let op = CHAT_HISTORY
                .with(|history| history.borrow_mut().on_locked_popstate(raw.as_deref()));
            let _ = execute_history_op(op.as_ref(), None, &hash, ui);
            return;
        }
        let startup_dialog_open = ui.dialog.with_untracked(|dialog| {
            matches!(dialog, Some(Dialog::NewChat { .. } | Dialog::SignIn))
        });
        let transition = CHAT_HISTORY.with(|history| {
            history
                .borrow_mut()
                .on_popstate(raw.as_deref(), &hash, startup_dialog_open, |peer| {
                    ui.contact(peer).is_some()
                })
        });
        let recovery = execute_history_op(
            transition.history.as_ref(),
            transition.fallback_active,
            &hash,
            ui,
        );
        execute_ui_action(
            recovery.unwrap_or(transition.ui),
            transition.dismiss_startup,
            ui,
        );
    });

    Effect::new(move |prev_open: Option<Option<PublicKey>>| {
        let current = ui.open.get();
        if let Some(Some(prev_peer)) = prev_open
            && current != Some(prev_peer)
        {
            // Clear the previous chat's viewer/contact/files overlays on both `Some(A) -> None`
            // and `Some(A) -> Some(B)` transitions.
            close_chat_overlays(ui, current);
            if current.is_none() {
                let hash = current_location_hash();
                let op = CHAT_HISTORY.with(|history| history.borrow_mut().on_ui_closed(prev_peer));
                if let Some(action) = execute_history_op(op.as_ref(), None, &hash, ui) {
                    execute_ui_action(action, false, ui);
                }
            }
        }
        current
    });

    Effect::new(move |prev_startup: Option<bool>| {
        let is_startup = ui
            .dialog
            .with(|dialog| matches!(dialog, Some(Dialog::NewChat { .. } | Dialog::SignIn)));
        if prev_startup == Some(true) && !is_startup {
            // A startup modal closed without committing a chat: unwind any retained
            // (`EntryKind::Reserved(None)`) history slot back to the chat list.
            cancel_retained_reservation();
        }
        is_startup
    });

    Effect::new(move || {
        if let Some((_, peer)) = ui.deleted_peer.get() {
            forget_peer(peer);
        }
    });
}

/// Invalidate all Forward chat tokens and fragment markers for a deleted peer (even if the user
/// already navigated back to the list before deletion committed).
pub(super) fn forget_peer(peer: PublicKey) {
    CHAT_HISTORY.with(|history| history.borrow_mut().on_peer_deleted(peer));
}

/// Reserve a chat-level history entry during a form submit gesture (`NewChat` or `SignIn`
/// auto-start), returning the [`Reservation`] handle to pass to [`commit_reservation`] or
/// [`cancel_reservation`].
pub(super) fn reserve() -> Reservation {
    let hash = current_location_hash();
    let (reservation, op) = CHAT_HISTORY.with(|history| history.borrow_mut().reserve(&hash));
    if let Some(op) = op
        && !apply_history_op(&op, &hash)
    {
        return CHAT_HISTORY
            .with(|history| history.borrow_mut().on_reserve_push_failed(&op, &hash));
    }
    reservation
}

/// Whether `reservation` is still owned by the submission that created it.
pub(super) fn is_reservation_owned(reservation: Option<Reservation>) -> bool {
    CHAT_HISTORY.with(|history| history.borrow().is_reservation_owned(reservation))
}

/// Commit a reserved chat entry to `peer` (honoring any Back, Forward, native dismissal, or newer
/// navigation that happened while startup waited on the relay) and open `peer`.
pub(super) async fn commit_reservation(reservation: Option<Reservation>, peer: PublicKey) {
    let ui = ui();
    let hash = current_location_hash();
    let transition = CHAT_HISTORY.with(|history| {
        history
            .borrow_mut()
            .commit_reservation(reservation, peer, &hash)
    });
    let recovery = execute_history_op(
        transition.history.as_ref(),
        transition.fallback_active,
        &hash,
        ui,
    );
    if transition.dismiss_startup {
        dismiss_startup_dialog(ui);
    }
    match recovery.unwrap_or(transition.ui) {
        UiAction::None => {}
        UiAction::Close => close_chat_immediately(ui),
        UiAction::Open(peer) => {
            if !engine().is_settled_on(peer) {
                if ui.open.get_untracked() != Some(peer) {
                    cancel_pending_previews();
                }
                open_and_reconcile(peer).await;
            }
        }
    }
}

/// Release ownership of a reservation while keeping its gesture-pushed slot retained for a
/// still-open startup modal (`NewChat` retry or `NewChat <-> SignIn` transition).
pub(super) fn retain_reservation(reservation: Option<Reservation>) -> bool {
    CHAT_HISTORY.with(|history| history.borrow_mut().retain_reservation(reservation))
}

/// Revoke any active submission's ownership while keeping a pushed slot retained for a restored
/// startup modal (e.g. dismissing `SignInDialog` back to `NewChat`).
pub(super) fn retain_active_reservation() {
    CHAT_HISTORY.with(|history| history.borrow_mut().retain_active_reservation());
}

/// Unwind an idle retained startup slot (`EntryKind::Reserved(None)`) back to the chat list when
/// the startup modal closes without starting a chat.
pub(super) fn cancel_retained_reservation() {
    let ui = ui();
    let hash = current_location_hash();
    let op = CHAT_HISTORY.with(|history| history.borrow_mut().cancel_retained_reservation());
    if let Some(action) = execute_history_op(op.as_ref(), None, &hash, ui) {
        execute_ui_action(action, false, ui);
    }
}

/// Release an uncommitted reservation after startup is cancelled or closes without opening a chat.
/// Returns whether the reservation was still owned by this submission (rather than superseded by
/// Back, Forward, native dismissal, or a newer submission).
pub(super) fn cancel_reservation(reservation: Option<Reservation>) -> bool {
    let ui = ui();
    let hash = current_location_hash();
    let (still_owned, op) =
        CHAT_HISTORY.with(|history| history.borrow_mut().cancel_reservation(reservation));
    if let Some(action) = execute_history_op(op.as_ref(), None, &hash, ui) {
        execute_ui_action(action, false, ui);
    }
    still_owned
}

/// Revoke any currently active startup reservation (e.g. when a native `<dialog>` is dismissed via
/// Escape or an OS close request rather than `popstate`), unwinding a pushed entry to the list.
pub(super) fn cancel_active_reservation() {
    let ui = ui();
    let hash = current_location_hash();
    let op = CHAT_HISTORY.with(|history| history.borrow_mut().cancel_active_reservation());
    if let Some(action) = execute_history_op(op.as_ref(), None, &hash, ui) {
        execute_ui_action(action, false, ui);
    }
}

/// Navigate to `peer` (or back to the chat list when `None`), synchronizing browser history
/// synchronously inside the caller's user-gesture event handler.
pub(super) fn navigate(peer: Option<PublicKey>) {
    let ui = ui();
    let hash = current_location_hash();
    if peer.is_none() {
        // Synchronously invalidate any in-flight `Engine::open` (e.g. Bob loading while Alice is
        // displayed) so it cannot open and send read receipts before `history.back()` settles.
        engine().cancel_pending_open();
    }
    let transition = CHAT_HISTORY.with(|history| {
        let mut history = history.borrow_mut();
        match peer {
            Some(peer) => history.user_open(peer, &hash),
            None => history.user_close(),
        }
    });
    let recovery = execute_history_op(
        transition.history.as_ref(),
        transition.fallback_active,
        &hash,
        ui,
    );
    if transition.dismiss_startup {
        dismiss_startup_dialog(ui);
    }
    match recovery.unwrap_or(transition.ui) {
        UiAction::None => {}
        UiAction::Close => close_chat_immediately(ui),
        UiAction::Open(peer) => {
            if !engine().is_settled_on(peer) {
                if ui.open.get_untracked() != Some(peer) {
                    cancel_pending_previews();
                }
                spawn_local(open_and_reconcile(peer));
            }
        }
    }
}
