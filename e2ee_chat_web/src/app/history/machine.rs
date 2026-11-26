//! Pure browser-history state machine for opening and closing chats.
//!
//! Zero `web_sys` or DOM calls live in this module: all browser mutations are returned as typed
//! [`HistoryOp`] / [`Transition`] values and applied by the adapter in `super`.

use std::collections::{HashSet, VecDeque};

use session::PublicKey;

/// Prefix for opaque session-scoped chat tokens stored in `window.history.state`.
const STATE_PREFIX: &str = "ratchetx2-chat:";
/// Prefix for opaque session-scoped chat-list tokens stored in `window.history.state`.
const LIST_PREFIX: &str = "ratchetx2-list:";
/// Prefix for opaque session-scoped fragment markers stacked above an active chat/reservation.
const FRAG_PREFIX: &str = "ratchetx2-frag:";

/// Maximum number of session-local chat tokens kept in memory for browser Forward navigation.
pub(super) const MAX_ENTRIES: usize = 64;

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
pub(in crate::app) enum Reservation {
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

/// Ownership state of a pushed startup reservation slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReservationOwner {
    /// Owned by an in-flight `NewChat` / `SignIn` submission (`res_id`).
    Active(u64),
    /// Retained by an open startup modal awaiting retry or dismissal.
    Retained,
}

/// What the current chat-level browser history entry represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChatEntry {
    /// An open chat with `peer`.
    Chat {
        peer: PublicKey,
        /// Token ID belonging to this session, or `None` when landed directly on a fragment marker
        /// or after a failed `replaceState` onto a pre-reload entry.
        token_id: Option<u64>,
        /// Stable stack-slot ID preserved across in-place `replaceState` peer switches so Forward
        /// `#fragment` markers remain bound to the surviving peer on this slot.
        slot: u64,
    },
    /// Reserved synchronously during a `NewChat` / `SignIn` submit gesture before `peer` is known.
    Reserved {
        token_id: u64,
        slot: u64,
        owner: ReservationOwner,
    },
    /// The browser cursor is already on a chat-level entry (e.g. after reloading/locking while a
    /// chat or fragment was open, Forward onto a deleted chat, or after a failed/ignored
    /// `history.back()`) while the chat list is shown; the next chat open reuses this slot via
    /// `replaceState` instead of stacking another level.
    Reusable {
        token_id: Option<u64>,
        slot: Option<u64>,
    },
}

impl ChatEntry {
    fn token_id(self) -> Option<u64> {
        match self {
            Self::Chat { token_id, .. } | Self::Reusable { token_id, .. } => token_id,
            Self::Reserved { token_id, .. } => Some(token_id),
        }
    }

    fn slot(self) -> Option<u64> {
        match self {
            Self::Chat { slot, .. } | Self::Reserved { slot, .. } => Some(slot),
            Self::Reusable { slot, .. } => slot,
        }
    }

    fn is_chat(self, target: PublicKey) -> bool {
        matches!(self, Self::Chat { peer, .. } if peer == target)
    }

    fn is_any_chat(self) -> bool {
        matches!(self, Self::Chat { .. })
    }

    fn is_reserved(self) -> bool {
        matches!(self, Self::Reserved { .. })
    }
}

/// Where the browser history cursor currently sits.
///
/// Encoding list vs. chat-level entry as an enum makes it impossible for a chat-list cursor to
/// carry stacked fragment depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CursorState {
    /// On a chat-list history entry.
    List,
    /// On a chat-level history entry, optionally beneath `fragment_depth` manual same-document
    /// `#fragment` entries stacked above it.
    Entry {
        entry: ChatEntry,
        fragment_depth: usize,
    },
}

impl CursorState {
    fn entry(self) -> Option<ChatEntry> {
        match self {
            Self::List => None,
            Self::Entry { entry, .. } => Some(entry),
        }
    }

    fn fragment_depth(self) -> usize {
        match self {
            Self::List => 0,
            Self::Entry { fragment_depth, .. } => fragment_depth,
        }
    }

    fn set_fragment_depth(&mut self, depth: usize) {
        if let Self::Entry { fragment_depth, .. } = self {
            *fragment_depth = depth;
        }
    }

    fn is_entry(self) -> bool {
        matches!(self, Self::Entry { .. })
    }
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
    pub(super) fallback_active: Option<ChatEntry>,
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

/// Goal of an in-flight programmatic `history.back()` traversal.
///
/// Carrying `deferred_open` / `peer` directly inside each variant makes dangling deferred opens
/// without an in-flight traversal (or fragment-unwind opens without a target peer) unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BackGoal {
    /// Return to the chat list and close the UI if the traversal aborts (in-app Back/Close),
    /// optionally opening `deferred_open` once the traversal settles.
    CloseToList { deferred_open: Option<PublicKey> },
    /// Return to the chat list without closing UI or advancing `nav_epoch` on settlement (external
    /// deletion, failed open from list, or cancelled reservation), optionally opening
    /// `deferred_open` once the traversal settles.
    UnwindToList { deferred_open: Option<PublicKey> },
    /// Step back off manual `#fragment` entries onto the underlying chat entry, then open `peer`
    /// via `replaceState`.
    UnwindFragmentsForOpen { peer: PublicKey },
}

impl BackGoal {
    fn targets_list(self) -> bool {
        matches!(self, Self::CloseToList { .. } | Self::UnwindToList { .. })
    }

    fn closes_ui_on_abort(self) -> bool {
        matches!(self, Self::CloseToList { .. })
    }

    fn deferred_open(self) -> Option<PublicKey> {
        match self {
            Self::CloseToList { deferred_open } | Self::UnwindToList { deferred_open } => {
                deferred_open
            }
            Self::UnwindFragmentsForOpen { peer } => Some(peer),
        }
    }

    fn set_deferred_open(&mut self, peer: PublicKey) {
        match self {
            Self::CloseToList { deferred_open } | Self::UnwindToList { deferred_open } => {
                *deferred_open = Some(peer);
            }
            Self::UnwindFragmentsForOpen { peer: target } => {
                *target = peer;
            }
        }
    }
}

/// Snapshot of an in-flight programmatic `history.back()` traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PendingBack {
    pub(super) attempt: u64,
    pub(super) goal: BackGoal,
    /// Bounded number of extra `history.back()` hops permitted while unwinding manual `#fragment`
    /// entries so traversal is guaranteed to terminate.
    pub(super) remaining_hops: usize,
}

/// Whether a programmatic `history.back()` traversal is currently in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingNavigation {
    Idle,
    Back(PendingBack),
}

impl PendingNavigation {
    fn is_back(self) -> bool {
        matches!(self, Self::Back(_))
    }

    fn take_back(&mut self) -> Option<PendingBack> {
        match std::mem::replace(self, Self::Idle) {
            Self::Idle => None,
            Self::Back(back) => Some(back),
        }
    }
}

/// Tracks a startup flow (`NewChat` / `SignIn`) that did not push its own reserved history entry
/// (because a chat/reusable entry or Back unwind was active, or `pushState` failed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnpushedStartup {
    /// No unpushed startup flow is active or retained.
    None,
    /// Owned by an in-flight submission (`res_id`), ensuring a newer submission supersedes older
    /// ones.
    Active(u64),
    /// Retained by an open `NewChat` / `SignIn` modal so browser Back/Forward still dismisses the
    /// modal and cancels its pending draft.
    Retained,
}

impl UnpushedStartup {
    fn is_active_or_retained(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Tracks whether chat-list entries in this document have been stamped with [`LIST_PREFIX`] so
/// untagged `null`-state `popstate` events can distinguish `#fragments` from older list entries.
#[derive(Debug)]
struct ListTagging {
    list_hash: String,
    /// Whether the current list entry has been stamped with `"ratchetx2-list:<session>"`.
    current_tagged: bool,
    /// Whether any earlier same-document list entry may still lack a list tag (e.g. if we loaded
    /// onto a pre-reload chat token or `replaceState` failed on an earlier list entry).
    earlier_untagged_exists: bool,
    /// Hashes of list entries whose tagging failed, so navigating back to them is never mistaken
    /// for a `#fragment` above a chat.
    failed_hashes: HashSet<String>,
}

impl ListTagging {
    fn new(list_hash: String, current_tagged: bool, earlier_untagged_exists: bool) -> Self {
        Self {
            list_hash,
            current_tagged,
            earlier_untagged_exists,
            failed_hashes: HashSet::new(),
        }
    }

    fn all_list_entries_tagged(&self) -> bool {
        self.current_tagged && !self.earlier_untagged_exists
    }

    fn is_untagged_fragment(&self, current_hash: &str) -> bool {
        if self.all_list_entries_tagged() {
            // Every list entry visited in this document has been stamped with `LIST_PREFIX`, so
            // any `null`-state same-document `popstate` while on a chat is a new fragment (even
            // `#` with an empty hash).
            true
        } else {
            !current_hash.is_empty()
                && current_hash != self.list_hash
                && !self.failed_hashes.contains(current_hash)
        }
    }

    fn record_tag_failed(&mut self, current_hash: &str) {
        self.current_tagged = false;
        self.earlier_untagged_exists = true;
        self.failed_hashes.insert(current_hash.to_string());
    }
}

/// Classification of a raw `window.history.state` string observed on load, `popstate`, or back
/// recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawState {
    SessionChat(u64),
    ForeignChat,
    SessionFragment { slot: Option<u64>, depth: usize },
    ForeignFragment { depth: usize },
    SessionList,
    ForeignList,
    Other,
    Null,
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
    list_tagging: ListTagging,
    cursor: CursorState,
    pending_nav: PendingNavigation,
    unpushed_startup: UnpushedStartup,
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
        let mut history = Self {
            session,
            list_tagging: ListTagging::new(initial_hash, false, false),
            cursor: CursorState::List,
            pending_nav: PendingNavigation::Idle,
            unpushed_startup: UnpushedStartup::None,
            nav_epoch: 0,
            next_id: 0,
            next_reservation: 0,
            next_back_attempt: 0,
            entries: VecDeque::new(),
            slots: VecDeque::new(),
        };
        match history.classify_raw_state(initial_raw_state) {
            RawState::SessionList => {
                history.list_tagging.current_tagged = true;
            }
            RawState::SessionFragment { depth, .. } | RawState::ForeignFragment { depth } => {
                history.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: None,
                        slot: None,
                    },
                    fragment_depth: depth,
                };
                history.list_tagging.earlier_untagged_exists = true;
            }
            RawState::SessionChat(_) | RawState::ForeignChat => {
                history.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: None,
                        slot: None,
                    },
                    fragment_depth: 0,
                };
                history.list_tagging.earlier_untagged_exists = true;
            }
            RawState::ForeignList | RawState::Other | RawState::Null => {}
        }
        history
    }

    #[cfg(test)]
    pub(super) fn cursor_state(&self) -> CursorState {
        self.cursor
    }

    #[cfg(test)]
    pub(super) fn pending_navigation(&self) -> PendingNavigation {
        self.pending_nav
    }

    #[cfg(test)]
    pub(super) fn unpushed_startup_state(&self) -> UnpushedStartup {
        self.unpushed_startup
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

    fn classify_raw_state(&self, raw: Option<&str>) -> RawState {
        let Some(raw) = raw else {
            return RawState::Null;
        };
        if let Some(id) = self.parse_token(Some(raw)) {
            return RawState::SessionChat(id);
        }
        if let Some((slot, depth)) = self.parse_frag_token(Some(raw)) {
            return RawState::SessionFragment { slot, depth };
        }
        if let Some(depth) = parse_any_frag_depth(raw) {
            return RawState::ForeignFragment { depth };
        }
        if is_any_chat_token(raw) {
            return RawState::ForeignChat;
        }
        if is_any_list_token(raw) {
            return if raw.strip_prefix(LIST_PREFIX) == Some(self.session.as_str()) {
                RawState::SessionList
            } else {
                RawState::ForeignList
            };
        }
        RawState::Other
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
        let depth = self.cursor.fragment_depth();
        self.bind_entry(id, slot, peer, depth);
        self.cursor = CursorState::Entry {
            entry: ChatEntry::Chat {
                peer,
                token_id: Some(id),
                slot,
            },
            fragment_depth: depth,
        };
        self.format_token(id)
    }

    fn begin_back(&mut self, goal: BackGoal, remaining_hops: usize) -> u64 {
        self.next_back_attempt = self.next_back_attempt.wrapping_add(1).max(1);
        let attempt = self.next_back_attempt;
        self.pending_nav = PendingNavigation::Back(PendingBack {
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
        self.bump_nav_epoch();
        self.unpushed_startup = UnpushedStartup::None;
        let attempt = self.begin_back(
            BackGoal::CloseToList {
                deferred_open: None,
            },
            remaining_hops,
        );
        Transition {
            history: Some(HistoryOp::Back(attempt)),
            ui: UiAction::None,
            dismiss_startup,
            fallback_active: self.cursor.entry(),
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
        let tag_list = if self.list_tagging.current_tagged {
            None
        } else {
            self.list_tagging.current_tagged = true;
            Some(self.list_token())
        };
        HistoryOp::Push {
            tag_list,
            chat_token,
        }
    }

    /// Stamp the initial list entry in place so older list entries reached later via the
    /// browser's Back menu remain distinguishable from `#fragments` pushed above a chat.
    pub(super) fn tag_current_list_entry(&mut self) -> Option<HistoryOp> {
        if self.cursor == CursorState::List && !self.list_tagging.current_tagged {
            self.list_tagging.current_tagged = true;
            return Some(HistoryOp::Tag(self.list_token()));
        }
        None
    }

    /// Synchronize cursor state when `popstate` fires while the vault is locked (e.g. stepping
    /// back from a pre-reload chat or fragment token onto the list before unlocking) without
    /// opening any chat.
    pub(super) fn on_locked_popstate(&mut self, raw_state: Option<&str>) -> Option<HistoryOp> {
        self.pending_nav = PendingNavigation::Idle;
        match self.classify_raw_state(raw_state) {
            RawState::SessionFragment { slot, depth } => {
                self.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: None,
                        slot,
                    },
                    fragment_depth: depth,
                };
                None
            }
            RawState::ForeignFragment { depth } => {
                self.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: None,
                        slot: None,
                    },
                    fragment_depth: depth,
                };
                None
            }
            RawState::SessionChat(id) => {
                let meta = self.lookup_token_meta(id);
                self.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: Some(id),
                        slot: meta.map(|(slot, _)| slot),
                    },
                    fragment_depth: meta.map_or(0, |(_, depth)| depth),
                };
                None
            }
            RawState::ForeignChat => {
                self.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: None,
                        slot: None,
                    },
                    fragment_depth: 0,
                };
                None
            }
            RawState::SessionList => {
                self.cursor = CursorState::List;
                self.list_tagging.current_tagged = true;
                None
            }
            RawState::ForeignList | RawState::Other | RawState::Null => {
                self.cursor = CursorState::List;
                self.list_tagging.current_tagged = true;
                Some(HistoryOp::Tag(self.list_token()))
            }
        }
    }

    /// Record that stamping a list entry failed or was silently ignored so fallback matching
    /// conservatively treats that hash (and empty hash) as a potential list entry.
    pub(super) fn on_list_tag_failed(&mut self, current_hash: &str) {
        self.list_tagging.record_tag_failed(current_hash);
    }

    /// Whether `reservation` is still owned by the submission that created it (not cancelled by
    /// browser Back, Forward, native dialog close, or a newer navigation/submission).
    pub(super) fn is_reservation_owned(&self, reservation: Option<Reservation>) -> bool {
        match reservation {
            Some(Reservation::Pushed(res_id)) => {
                !self.pending_nav.is_back()
                    && matches!(
                        self.cursor.entry(),
                        Some(ChatEntry::Reserved {
                            owner: ReservationOwner::Active(active_res),
                            ..
                        }) if active_res == res_id
                    )
            }
            Some(Reservation::Unpushed { nav_epoch, res_id }) => {
                self.nav_epoch == nav_epoch
                    && self.unpushed_startup == UnpushedStartup::Active(res_id)
            }
            None => true,
        }
    }

    /// Reserve a chat-level history entry synchronously during a form submit gesture (`NewChat` or
    /// `SignIn` auto-start), transferring ownership of any active or retained reserved slot (even
    /// beneath a manual `#fragment`) so retries keep the gesture-pushed entry and an older
    /// submission can never commit or unwind a newer one.
    pub(super) fn reserve(&mut self, current_hash: &str) -> (Reservation, Option<HistoryOp>) {
        self.unpushed_startup = UnpushedStartup::None;
        if self.pending_nav.is_back() {
            let res_id = self.next_reservation_id();
            self.unpushed_startup = UnpushedStartup::Active(res_id);
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
        if let CursorState::Entry {
            entry: ChatEntry::Reserved { token_id, slot, .. },
            fragment_depth,
        } = self.cursor
        {
            let res_id = self.next_reservation_id();
            self.cursor = CursorState::Entry {
                entry: ChatEntry::Reserved {
                    token_id,
                    slot,
                    owner: ReservationOwner::Active(res_id),
                },
                fragment_depth,
            };
            return (Reservation::Pushed(res_id), None);
        }
        if self.cursor.is_entry() {
            let res_id = self.next_reservation_id();
            self.unpushed_startup = UnpushedStartup::Active(res_id);
            return (
                Reservation::Unpushed {
                    nav_epoch: self.nav_epoch,
                    res_id,
                },
                None,
            );
        }
        self.list_tagging.list_hash = current_hash.to_string();
        let res_id = self.next_reservation_id();
        let id = self.next_token_id();
        self.cursor = CursorState::Entry {
            entry: ChatEntry::Reserved {
                token_id: id,
                slot: id,
                owner: ReservationOwner::Active(res_id),
            },
            fragment_depth: 0,
        };
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
        self.unpushed_startup = UnpushedStartup::Active(res_id);
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
                if !self.pending_nav.is_back()
                    && let CursorState::Entry {
                        entry:
                            ChatEntry::Reserved {
                                token_id,
                                slot,
                                owner: ReservationOwner::Active(active_res),
                            },
                        fragment_depth,
                    } = self.cursor
                    && active_res == res_id
                {
                    self.unpushed_startup = UnpushedStartup::None;
                    self.bump_nav_epoch();
                    if fragment_depth > 0 {
                        let attempt = self.begin_back(
                            BackGoal::UnwindFragmentsForOpen { peer },
                            fragment_depth.saturating_sub(1),
                        );
                        return Transition {
                            history: Some(HistoryOp::Back(attempt)),
                            ui: UiAction::None,
                            dismiss_startup: false,
                            fallback_active: self.cursor.entry(),
                        };
                    }
                    self.bind_entry(token_id, slot, peer, 0);
                    self.cursor = CursorState::Entry {
                        entry: ChatEntry::Chat {
                            peer,
                            token_id: Some(token_id),
                            slot,
                        },
                        fragment_depth: 0,
                    };
                    return Transition::ui_only(UiAction::Open(peer));
                }
                Transition::noop()
            }
            Some(Reservation::Unpushed { nav_epoch, res_id }) => {
                if self.nav_epoch != nav_epoch
                    || self.unpushed_startup != UnpushedStartup::Active(res_id)
                {
                    return Transition::noop();
                }
                self.unpushed_startup = UnpushedStartup::None;
                self.user_open(peer, current_hash)
            }
            None => self.user_open(peer, current_hash),
        }
    }

    /// Release ownership of `reservation` after a retryable failure or `NewChat <-> SignIn`
    /// handoff while retaining a pushed history slot (`ReservationOwner::Retained`) or unpushed
    /// startup attachment (`UnpushedStartup::Retained`) for the still-open startup modal so retries
    /// keep the submit-gesture entry and browser Back still dismisses the modal.
    pub(super) fn retain_reservation(&mut self, reservation: Option<Reservation>) -> bool {
        match reservation {
            Some(Reservation::Pushed(res_id)) => {
                if self.pending_nav.is_back() {
                    return false;
                }
                if let CursorState::Entry {
                    entry:
                        ChatEntry::Reserved {
                            token_id,
                            slot,
                            owner: ReservationOwner::Active(active_res),
                        },
                    fragment_depth,
                } = self.cursor
                    && active_res == res_id
                {
                    self.cursor = CursorState::Entry {
                        entry: ChatEntry::Reserved {
                            token_id,
                            slot,
                            owner: ReservationOwner::Retained,
                        },
                        fragment_depth,
                    };
                    return true;
                }
                false
            }
            Some(Reservation::Unpushed { nav_epoch, res_id }) => {
                if self.nav_epoch == nav_epoch
                    && self.unpushed_startup == UnpushedStartup::Active(res_id)
                {
                    self.unpushed_startup = UnpushedStartup::Retained;
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
        if matches!(self.unpushed_startup, UnpushedStartup::Active(_)) {
            self.unpushed_startup = UnpushedStartup::Retained;
        }
        if !self.pending_nav.is_back()
            && let CursorState::Entry {
                entry:
                    ChatEntry::Reserved {
                        token_id,
                        slot,
                        owner: ReservationOwner::Active(_),
                    },
                fragment_depth,
            } = self.cursor
        {
            self.cursor = CursorState::Entry {
                entry: ChatEntry::Reserved {
                    token_id,
                    slot,
                    owner: ReservationOwner::Retained,
                },
                fragment_depth,
            };
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
                if self.pending_nav.is_back() {
                    return (false, None);
                }
                if let CursorState::Entry {
                    entry:
                        ChatEntry::Reserved {
                            owner: ReservationOwner::Active(active_res),
                            ..
                        },
                    fragment_depth,
                } = self.cursor
                    && active_res == res_id
                {
                    let attempt = self.begin_back(
                        BackGoal::UnwindToList {
                            deferred_open: None,
                        },
                        fragment_depth,
                    );
                    return (true, Some(HistoryOp::Back(attempt)));
                }
                (false, None)
            }
            Some(Reservation::Unpushed { nav_epoch, res_id }) => {
                if self.nav_epoch == nav_epoch
                    && self.unpushed_startup == UnpushedStartup::Active(res_id)
                {
                    self.unpushed_startup = UnpushedStartup::None;
                    (true, None)
                } else {
                    (false, None)
                }
            }
            None => (true, None),
        }
    }

    /// Unwind an idle retained startup slot (`ReservationOwner::Retained`) or clear a retained
    /// unpushed startup attachment once the startup modal closes without committing a chat.
    pub(super) fn cancel_retained_reservation(&mut self) -> Option<HistoryOp> {
        if self.unpushed_startup == UnpushedStartup::Retained {
            self.unpushed_startup = UnpushedStartup::None;
        }
        if !self.pending_nav.is_back()
            && let CursorState::Entry {
                entry:
                    ChatEntry::Reserved {
                        owner: ReservationOwner::Retained,
                        ..
                    },
                fragment_depth,
            } = self.cursor
        {
            let attempt = self.begin_back(
                BackGoal::UnwindToList {
                    deferred_open: None,
                },
                fragment_depth,
            );
            return Some(HistoryOp::Back(attempt));
        }
        None
    }

    /// Revoke any currently active or retained reservation (called synchronously when the user
    /// dismisses `NewChat` or `SignInDialog` natively via Escape or a dialog close request),
    /// unwinding a pushed reserved entry back to the list.
    pub(super) fn cancel_active_reservation(&mut self) -> Option<HistoryOp> {
        self.unpushed_startup = UnpushedStartup::None;
        if !self.pending_nav.is_back()
            && let CursorState::Entry {
                entry: ChatEntry::Reserved { .. },
                fragment_depth,
            } = self.cursor
        {
            let attempt = self.begin_back(
                BackGoal::UnwindToList {
                    deferred_open: None,
                },
                fragment_depth,
            );
            return Some(HistoryOp::Back(attempt));
        }
        None
    }

    /// Handle a user-initiated request to open `peer`.
    pub(super) fn user_open(&mut self, peer: PublicKey, current_hash: &str) -> Transition {
        self.bump_nav_epoch();
        self.unpushed_startup = UnpushedStartup::None;
        if let PendingNavigation::Back(pending) = &mut self.pending_nav {
            // A programmatic `history.back()` is already in flight; open `peer` as soon as its
            // `popstate` (or timeout recovery) settles.
            pending.goal.set_deferred_open(peer);
            return Transition::noop();
        }
        if let CursorState::Entry {
            entry,
            fragment_depth,
        } = self.cursor
            && fragment_depth > 0
        {
            // Unwind manual `#fragment` entries back onto the chat entry before replacing it so
            // switching peers never leaves the old chat underneath the new one.
            let attempt = self.begin_back(
                BackGoal::UnwindFragmentsForOpen { peer },
                fragment_depth.saturating_sub(1),
            );
            return Transition {
                history: Some(HistoryOp::Back(attempt)),
                ui: UiAction::None,
                dismiss_startup: false,
                fallback_active: Some(entry),
            };
        }
        self.open_peer(peer, current_hash)
    }

    fn open_peer(&mut self, peer: PublicKey, current_hash: &str) -> Transition {
        let fallback_active = self.cursor.entry();
        if let Some(active) = fallback_active {
            if active.is_chat(peer) {
                return Transition::ui_only(UiAction::Open(peer));
            }
            // Already on a chat-level entry (switching chats, overwriting a reservation, or
            // reusing a leftover pre-reload / deleted / fallback slot): replace in place on the
            // same stack `slot` so one Back gesture returns to the list and any Forward `#fragment`
            // markers stay bound to `peer`.
            let token = self.allocate_chat(peer, active.slot());
            return Transition {
                history: Some(HistoryOp::Replace(token)),
                ui: UiAction::Open(peer),
                dismiss_startup: false,
                fallback_active,
            };
        }
        self.list_tagging.list_hash = current_hash.to_string();
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
        self.unpushed_startup = UnpushedStartup::None;
        if let PendingNavigation::Back(pending) = &mut self.pending_nav {
            match &mut pending.goal {
                BackGoal::CloseToList { deferred_open }
                | BackGoal::UnwindToList { deferred_open } => {
                    *deferred_open = None;
                }
                BackGoal::UnwindFragmentsForOpen { .. } => {
                    // Redirect an in-flight fragment unwind (from a peer switch) so it continues
                    // past the underlying chat entry all the way back to the chat list.
                    pending.goal = BackGoal::CloseToList {
                        deferred_open: None,
                    };
                    pending.remaining_hops = pending.remaining_hops.saturating_add(1);
                }
            }
            // Ignore rapid double-taps while a close/unwind traversal is settling so we never step
            // back a second time and leave the site.
            return Transition::noop();
        }
        if let CursorState::Entry {
            entry: entry @ ChatEntry::Chat { .. },
            fragment_depth,
        } = self.cursor
        {
            let attempt = self.begin_back(
                BackGoal::CloseToList {
                    deferred_open: None,
                },
                fragment_depth,
            );
            return Transition {
                history: Some(HistoryOp::Back(attempt)),
                ui: UiAction::None,
                dismiss_startup: false,
                fallback_active: Some(entry),
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
        if self.pending_nav.is_back() {
            return Transition::noop();
        }
        let CursorState::Entry {
            entry: active @ ChatEntry::Chat { peer, slot, .. },
            fragment_depth,
        } = self.cursor
        else {
            return Transition::noop();
        };
        if peer != failed_peer {
            return Transition::noop();
        }
        self.forget_peer(&failed_peer);
        match actual_open {
            None => {
                let attempt = self.begin_back(
                    BackGoal::UnwindToList {
                        deferred_open: None,
                    },
                    fragment_depth,
                );
                Transition {
                    history: Some(HistoryOp::Back(attempt)),
                    ui: UiAction::None,
                    dismiss_startup: false,
                    fallback_active: Some(active),
                }
            }
            Some(current) if current != failed_peer => {
                if fragment_depth > 0 {
                    let attempt = self.begin_back(
                        BackGoal::UnwindFragmentsForOpen { peer: current },
                        fragment_depth.saturating_sub(1),
                    );
                    return Transition {
                        history: Some(HistoryOp::Back(attempt)),
                        ui: UiAction::None,
                        dismiss_startup: false,
                        fallback_active: Some(active),
                    };
                }
                let token = self.allocate_chat(current, Some(slot));
                Transition {
                    history: Some(HistoryOp::Replace(token)),
                    ui: UiAction::None,
                    dismiss_startup: false,
                    fallback_active: Some(active),
                }
            }
            Some(_) => Transition::noop(),
        }
    }

    /// Reconcile when `ui.open` transitioned from `Some(closed_peer)` to `None` outside browser
    /// history navigation (e.g., deleting the currently open chat).
    pub(super) fn on_ui_closed(&mut self, closed_peer: PublicKey) -> Option<HistoryOp> {
        if self.pending_nav.is_back() {
            return None;
        }
        let CursorState::Entry {
            entry: ChatEntry::Chat { peer, .. },
            fragment_depth,
        } = self.cursor
        else {
            return None;
        };
        if peer != closed_peer {
            return None;
        }
        self.forget_peer(&closed_peer);
        let attempt = self.begin_back(
            BackGoal::UnwindToList {
                deferred_open: None,
            },
            fragment_depth,
        );
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
        let pending_back = self.pending_nav.take_back();
        let prev_cursor = self.cursor;
        let prev_entry = prev_cursor.entry();
        let prev_depth = prev_cursor.fragment_depth();
        let prev_active_token_depth = prev_entry
            .and_then(ChatEntry::token_id)
            .and_then(|id| self.lookup_token_meta(id))
            .map_or(0, |(_, depth)| depth);
        let prev_active_slot = prev_entry.and_then(ChatEntry::slot);
        // Native Back directly off a fragment-recovered chat token (which lives above the
        // underlying chat/fragment entries because `UnwindFragmentsForOpen` timed out).
        let stepping_off_recovered_chat = pending_back.is_none()
            && prev_active_token_depth > 0
            && prev_depth == prev_active_token_depth
            && prev_entry.is_some_and(ChatEntry::is_any_chat);
        let was_reserved = prev_entry.is_some_and(ChatEntry::is_reserved);
        let has_startup =
            was_reserved || self.unpushed_startup.is_active_or_retained() || startup_dialog_open;

        match self.classify_raw_state(raw_state) {
            RawState::SessionChat(id) => {
                let token_meta = self.lookup_token_meta(id);
                let token_depth = token_meta.map_or(0, |(_, depth)| depth);
                self.cursor.set_fragment_depth(token_depth);

                // Unwinding fragments on the way back to the chat list: we just stepped off the
                // fragment (or a Back-recovered chat token) onto the underlying chat/reserved
                // entry, so step back once more to reach list.
                if let Some(back) = pending_back
                    && back.goal.targets_list()
                    && back.remaining_hops > 0
                {
                    let attempt = self.begin_back(back.goal, back.remaining_hops - 1);
                    return Transition {
                        history: Some(HistoryOp::Back(attempt)),
                        ui: UiAction::None,
                        dismiss_startup: false,
                        fallback_active: self.cursor.entry(),
                    };
                }

                // Native Back off a fragment-recovered chat token landed on its underlying chat
                // token on the same slot: skip past the duplicate underlying chat back to the list
                // so the first Back gesture closes the chat as expected.
                if stepping_off_recovered_chat
                    && token_depth < prev_active_token_depth
                    && token_meta.is_some_and(|(slot, _)| Some(slot) == prev_active_slot)
                {
                    return self.skip_recovered_underlying(token_depth, has_startup);
                }

                // Unwinding fragments before opening/switching peers: we are now back on the
                // chat/reserved entry, so replace it in place on the same slot with the deferred
                // peer.
                if let Some(back) = pending_back
                    && let BackGoal::UnwindFragmentsForOpen { peer } = back.goal
                    && contact_exists(&peer)
                {
                    let slot = token_meta.map(|(slot, _)| slot).or(Some(id));
                    self.cursor = CursorState::Entry {
                        entry: ChatEntry::Reusable {
                            token_id: Some(id),
                            slot,
                        },
                        fragment_depth: token_depth,
                    };
                    return self.open_peer(peer, current_hash);
                }

                // Returning from a manual `#fragment` back onto a live or retained reservation:
                // keep the reservation intact instead of mistaking its unmapped token for a
                // cancelled chat.
                if matches!(
                    self.cursor.entry(),
                    Some(ChatEntry::Reserved { token_id, .. }) if token_id == id
                ) {
                    return Transition::noop();
                }

                if let Some((slot, peer, depth)) = self.lookup_token_entry(id)
                    && contact_exists(&peer)
                {
                    let changed = !self.cursor.entry().is_some_and(|entry| entry.is_chat(peer));
                    self.cursor = CursorState::Entry {
                        entry: ChatEntry::Chat {
                            peer,
                            token_id: Some(id),
                            slot,
                        },
                        fragment_depth: depth,
                    };
                    let dismiss_startup = changed && has_startup;
                    if changed {
                        self.bump_nav_epoch();
                        self.unpushed_startup = UnpushedStartup::None;
                    }
                    return Transition {
                        history: None,
                        ui: UiAction::Open(peer),
                        dismiss_startup,
                        fallback_active: None,
                    };
                }

                // Forward navigated onto a deleted, evicted, or cancelled-reservation token of
                // this session: keep the chat list displayed and mark the slot reusable without
                // calling `history.back()`, so any later Forward entries remain reachable.
                let slot = token_meta.map(|(slot, _)| slot).or(Some(id));
                self.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: Some(id),
                        slot,
                    },
                    fragment_depth: token_depth,
                };
                let is_programmatic_list_back =
                    pending_back.is_some_and(|back| back.goal.targets_list());
                if !is_programmatic_list_back {
                    self.bump_nav_epoch();
                    self.unpushed_startup = UnpushedStartup::None;
                }
                Transition {
                    history: None,
                    ui: UiAction::Close,
                    dismiss_startup: !is_programmatic_list_back && has_startup,
                    fallback_active: None,
                }
            }

            // Known fragment marker previously stacked above a chat/reservation slot (including a
            // direct Forward-menu jump from the list straight to the fragment without visiting its
            // intermediate chat entry first).
            RawState::SessionFragment {
                slot: slot_id,
                depth,
            } => {
                self.cursor.set_fragment_depth(depth);
                if let Some(back) = pending_back {
                    if back.remaining_hops > 0 {
                        let attempt = self.begin_back(back.goal, back.remaining_hops - 1);
                        return Transition {
                            history: Some(HistoryOp::Back(attempt)),
                            ui: UiAction::None,
                            dismiss_startup: false,
                            fallback_active: self.cursor.entry(),
                        };
                    }
                    if let BackGoal::UnwindFragmentsForOpen { peer } = back.goal
                        && contact_exists(&peer)
                    {
                        self.cursor = CursorState::Entry {
                            entry: ChatEntry::Reusable {
                                token_id: None,
                                slot: slot_id,
                            },
                            fragment_depth: depth,
                        };
                        return self.open_peer(peer, current_hash);
                    }
                    self.cursor = CursorState::Entry {
                        entry: ChatEntry::Reusable {
                            token_id: None,
                            slot: slot_id,
                        },
                        fragment_depth: depth,
                    };
                    return Transition::ui_only(if back.goal.closes_ui_on_abort() {
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
                if self.cursor.is_entry() {
                    return Transition::noop();
                }
                self.bump_nav_epoch();
                self.unpushed_startup = UnpushedStartup::None;
                if let Some(slot) = slot_id
                    && let Some(peer) = self.lookup_slot_peer(slot)
                    && contact_exists(&peer)
                {
                    self.cursor = CursorState::Entry {
                        entry: ChatEntry::Chat {
                            peer,
                            token_id: None,
                            slot,
                        },
                        fragment_depth: depth,
                    };
                    return Transition {
                        history: None,
                        ui: UiAction::Open(peer),
                        dismiss_startup: has_startup,
                        fallback_active: None,
                    };
                }
                self.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: None,
                        slot: slot_id,
                    },
                    fragment_depth: depth,
                };
                Transition {
                    history: None,
                    ui: UiAction::Close,
                    dismiss_startup: has_startup,
                    fallback_active: None,
                }
            }

            // Pre-reload fragment marker from an earlier page session: never overwrite it with a
            // list tag. Continue unwinding if a programmatic traversal has hops left; otherwise
            // treat it as a stale chat-level entry preserving its depth.
            RawState::ForeignFragment { depth } => {
                self.cursor.set_fragment_depth(depth);
                if let Some(back) = pending_back {
                    if back.remaining_hops > 0 {
                        let attempt = self.begin_back(back.goal, back.remaining_hops - 1);
                        return Transition {
                            history: Some(HistoryOp::Back(attempt)),
                            ui: UiAction::None,
                            dismiss_startup: false,
                            fallback_active: self.cursor.entry(),
                        };
                    }
                    if let BackGoal::UnwindFragmentsForOpen { peer } = back.goal
                        && contact_exists(&peer)
                    {
                        self.cursor = CursorState::Entry {
                            entry: ChatEntry::Reusable {
                                token_id: None,
                                slot: None,
                            },
                            fragment_depth: depth,
                        };
                        return self.open_peer(peer, current_hash);
                    }
                }
                if stepping_off_recovered_chat && depth < prev_active_token_depth {
                    return self.skip_recovered_underlying(depth, has_startup);
                }
                self.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: None,
                        slot: None,
                    },
                    fragment_depth: depth,
                };
                let is_programmatic_list_back =
                    pending_back.is_some_and(|back| back.goal.targets_list());
                let is_programmatic_unwind = pending_back
                    .is_some_and(|back| matches!(back.goal, BackGoal::UnwindToList { .. }));
                if !is_programmatic_list_back {
                    self.bump_nav_epoch();
                    self.unpushed_startup = UnpushedStartup::None;
                }
                Transition {
                    history: None,
                    ui: if is_programmatic_unwind {
                        UiAction::None
                    } else {
                        UiAction::Close
                    },
                    dismiss_startup: !is_programmatic_list_back && has_startup,
                    fallback_active: None,
                }
            }

            // Newly pushed `#fragment` (or `#` when all list entries are tagged) above an active
            // chat/reservation entry. Known list entries (`SessionList` / `ForeignList`) never
            // enter this branch.
            RawState::Null
                if self.cursor.is_entry()
                    && self.list_tagging.is_untagged_fragment(current_hash) =>
            {
                if let Some(back) = pending_back {
                    let next_depth = prev_depth.saturating_sub(1);
                    self.cursor.set_fragment_depth(next_depth);
                    if back.remaining_hops > 0 {
                        let attempt = self.begin_back(back.goal, back.remaining_hops - 1);
                        return Transition {
                            history: Some(HistoryOp::Back(attempt)),
                            ui: UiAction::None,
                            dismiss_startup: false,
                            fallback_active: self.cursor.entry(),
                        };
                    }
                    if let BackGoal::UnwindFragmentsForOpen { peer } = back.goal
                        && contact_exists(&peer)
                    {
                        self.cursor = CursorState::Entry {
                            entry: ChatEntry::Reusable {
                                token_id: None,
                                slot: prev_active_slot,
                            },
                            fragment_depth: next_depth.max(1),
                        };
                        return self.open_peer(peer, current_hash);
                    }
                    self.cursor = CursorState::Entry {
                        entry: ChatEntry::Reusable {
                            token_id: None,
                            slot: prev_active_slot,
                        },
                        fragment_depth: next_depth,
                    };
                    Transition::ui_only(if back.goal.closes_ui_on_abort() {
                        UiAction::Close
                    } else {
                        UiAction::None
                    })
                } else {
                    let next_depth = prev_depth.saturating_add(1);
                    self.cursor.set_fragment_depth(next_depth);
                    let tag = self.frag_token(prev_active_slot, next_depth);
                    Transition {
                        history: Some(HistoryOp::Tag(tag)),
                        ui: UiAction::None,
                        dismiss_startup: false,
                        fallback_active: self.cursor.entry(),
                    }
                }
            }

            raw @ (RawState::ForeignChat
            | RawState::SessionList
            | RawState::ForeignList
            | RawState::Other
            | RawState::Null) => {
                self.cursor.set_fragment_depth(0);
                let landed_on_pre_reload_chat = raw == RawState::ForeignChat;
                if landed_on_pre_reload_chat
                    && let Some(back) = pending_back
                    && back.goal.targets_list()
                    && back.remaining_hops > 0
                {
                    let attempt = self.begin_back(back.goal, back.remaining_hops - 1);
                    return Transition {
                        history: Some(HistoryOp::Back(attempt)),
                        ui: UiAction::None,
                        dismiss_startup: false,
                        fallback_active: self.cursor.entry(),
                    };
                }
                if landed_on_pre_reload_chat && stepping_off_recovered_chat {
                    return self.skip_recovered_underlying(0, has_startup);
                }
                self.cursor = if landed_on_pre_reload_chat {
                    // Landed on a pre-reload chat token from an earlier session: mark reusable so
                    // the next open replaces it instead of stacking another level.
                    CursorState::Entry {
                        entry: ChatEntry::Reusable {
                            token_id: None,
                            slot: None,
                        },
                        fragment_depth: 0,
                    }
                } else {
                    CursorState::List
                };
                // Keep `current_tagged` synchronized with the actual entry we landed on so
                // untagged list entries (such as `#one` typed while on the list) get stamped
                // immediately.
                self.list_tagging.current_tagged = raw == RawState::SessionList;

                // Settlement of a programmatic list-bound `history.back()` (`UnwindToList` or an
                // earlier in-app `CloseToList`) is NOT newer user navigation, so a NewChat/SignIn
                // form or reservation started while that back traversal was settling survives
                // intact.
                let is_programmatic_list_back =
                    pending_back.is_some_and(|back| back.goal.targets_list());
                if !is_programmatic_list_back {
                    self.bump_nav_epoch();
                    self.unpushed_startup = UnpushedStartup::None;
                }

                if let Some(peer) = pending_back.and_then(|back| back.goal.deferred_open())
                    && contact_exists(&peer)
                {
                    return self.open_peer(peer, current_hash);
                }

                let tag_op = if !landed_on_pre_reload_chat && !self.list_tagging.current_tagged {
                    self.list_tagging.current_tagged = true;
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
        }
    }

    /// Roll back or rebind internal state if a synchronous `Push`, `Replace`, or `Tag` threw or
    /// was silently ignored by the browser (verified via `history.state()`).
    pub(super) fn on_write_failed(
        &mut self,
        op: &HistoryOp,
        fallback_active: Option<ChatEntry>,
        current_hash: &str,
    ) {
        match op {
            HistoryOp::Push { .. } => {
                if let CursorState::Entry {
                    entry: ChatEntry::Chat { token_id, slot, .. },
                    ..
                } = self.cursor
                {
                    if let Some(id) = token_id {
                        self.forget_token(id);
                    }
                    self.forget_slot(slot);
                }
                self.cursor = match fallback_active {
                    Some(entry) => CursorState::Entry {
                        entry,
                        fragment_depth: self.cursor.fragment_depth(),
                    },
                    None => CursorState::List,
                };
            }
            HistoryOp::Replace(_) => {
                let depth = self.cursor.fragment_depth();
                let current_entry = self.cursor.entry();
                if let Some(id) = current_entry.and_then(ChatEntry::token_id) {
                    self.forget_token(id);
                }
                // The browser kept `fallback_active`'s token; rebind that surviving token and its
                // slot to the newly displayed peer so Forward and open-chat deletion stay
                // consistent with UI.
                let surviving_id = fallback_active.and_then(ChatEntry::token_id);
                let surviving_slot = fallback_active
                    .and_then(ChatEntry::slot)
                    .or_else(|| current_entry.and_then(ChatEntry::slot))
                    .or(surviving_id);
                let next_entry = match (fallback_active, current_entry) {
                    (
                        Some(_),
                        Some(ChatEntry::Chat {
                            peer,
                            slot: current_slot,
                            ..
                        }),
                    ) => {
                        let slot = surviving_slot.unwrap_or(current_slot);
                        self.bind_slot(slot, peer);
                        if let Some(id) = surviving_id {
                            self.bind_token_slot(id, slot, depth);
                        }
                        Some(ChatEntry::Chat {
                            peer,
                            token_id: surviving_id,
                            slot,
                        })
                    }
                    (
                        Some(_),
                        Some(ChatEntry::Reserved {
                            token_id,
                            slot,
                            owner,
                        }),
                    ) => Some(ChatEntry::Reserved {
                        token_id: surviving_id.unwrap_or(token_id),
                        slot: surviving_slot.unwrap_or(slot),
                        owner,
                    }),
                    (Some(_), Some(ChatEntry::Reusable { .. })) => Some(ChatEntry::Reusable {
                        token_id: surviving_id,
                        slot: surviving_slot,
                    }),
                    (prev, _) => prev,
                };
                self.cursor = match next_entry {
                    Some(entry) => CursorState::Entry {
                        entry,
                        fragment_depth: depth,
                    },
                    None => CursorState::List,
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
        let PendingNavigation::Back(pending) = self.pending_nav else {
            return Transition::noop();
        };
        if pending.attempt != attempt {
            return Transition::noop();
        }
        self.pending_nav = PendingNavigation::Idle;
        let prev_slot = self.cursor.entry().and_then(ChatEntry::slot);
        let prev_depth = self.cursor.fragment_depth();
        match self.classify_raw_state(current_raw_state) {
            RawState::SessionFragment { slot, depth } => {
                // Keep `depth` even when `deferred_open` replaces this fragment entry in place:
                // the underlying chat entry is still beneath it, so the next in-app Close needs
                // `depth` extra hops to reach the list instead of landing on the old chat.
                self.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: None,
                        slot,
                    },
                    fragment_depth: depth,
                };
            }
            RawState::ForeignFragment { depth } => {
                self.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: None,
                        slot: None,
                    },
                    fragment_depth: depth,
                };
            }
            RawState::SessionChat(id) => {
                let meta = self.lookup_token_meta(id);
                self.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: Some(id),
                        slot: meta.map(|(slot, _)| slot),
                    },
                    fragment_depth: meta.map_or(0, |(_, depth)| depth),
                };
            }
            RawState::ForeignChat => {
                self.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: None,
                        slot: None,
                    },
                    fragment_depth: 0,
                };
            }
            RawState::Null
                if self.cursor.is_entry()
                    && self.list_tagging.is_untagged_fragment(current_hash) =>
            {
                self.cursor = CursorState::Entry {
                    entry: ChatEntry::Reusable {
                        token_id: None,
                        slot: prev_slot,
                    },
                    fragment_depth: prev_depth.max(1),
                };
            }
            raw @ (RawState::SessionList
            | RawState::ForeignList
            | RawState::Other
            | RawState::Null) => {
                self.cursor = CursorState::List;
                self.list_tagging.current_tagged = raw == RawState::SessionList;
            }
        }

        if let Some(peer) = pending.goal.deferred_open()
            && contact_exists(&peer)
        {
            return self.open_peer(peer, current_hash);
        }

        Transition::ui_only(if pending.goal.closes_ui_on_abort() {
            UiAction::Close
        } else {
            UiAction::None
        })
    }
}
