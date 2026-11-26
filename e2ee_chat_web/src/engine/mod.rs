//! The client: the vault, the identity and the sessions, and what the page asks of them.
//!
//! The engine keeps the state; the page only shows the [`Ui`] signals that the engine updates.
//! One lock orders everything that changes the state, so that the sync loop and the page take
//! turns, and every change is saved before it shows.

mod attachments;
mod contact;
mod handshake;
mod outbox;
mod settings;
mod streaming;
mod sync;
#[cfg(test)]
mod tests;

use crate::content::Kind;
use crate::glue::LockStatus;
use crate::kdf_worker::KdfCancelToken;
use crate::notify::CloseHandle;
use crate::state::{
    Body, ContactView, Delivery, Dialog, IsolatedContactView, Link, Me, MessageRow, MessageView,
    PendingNewChat, Phase, ServerPqStatus, SignIn, SignInFlow, SignInSuccessAction, Ui,
    UnavailableReason, UploadState, order, order_rows,
};
use crate::transport::{Connect, Fetch};
use crate::util::{describe, key_to_url, monotonic_now_ms, short, size_u64, sleep};
use crate::vault::{
    AppState, CarriedDeferredTimestamp, ContactState, DeferredEnvelope, DeferredInitial,
    DeferredRecord, GREETING_DELIVERY_UNCERTAIN, GREETING_DELIVERY_UNSENT, HistoryEntry,
    OutgoingRecord, PendingRevoke, PendingUpload, Vault, VaultPresence,
};
use crate::{glue, transport};
use attachments::{ChunkSource, upload_of};
use contact::{
    Contact, DisplayedEntry, FarewellMode, isolated_contact_views, restore_contacts,
    stored_contacts,
};
use futures_channel::oneshot;
use futures_util::future::{Either, select};
use futures_util::lock::Mutex;
use handshake::encrypt_session_farewells;
use leptos::prelude::*;
use leptos::task::spawn_local;
use session::attachment::{CHUNK_SIZE, Upload};
use session::protocol::attachment::DEFAULT_MAX_CHUNKS;
use session::{
    Client, ClientState, ErrorKind, PendingGrant, PqConfig, PublicKey, Session, SessionState,
    attachment, expected_audience_from_url, proto,
};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use streaming::Stream;
use zeroize::Zeroizing;

/// Why an attachment's upload has not started.
const WAITS_SIGN_IN: &str = "waits for you to sign in to the server";
/// Why what takes a sign-in never goes from a page that is not the server's own, which cannot
/// sign in to it.
const NOT_SIGNED_IN_HERE: &str =
    "the server keeps it only for those signed in to it, and only its own page can sign in";
/// Plain-English message surfaced when the local device clock disagrees with the server clock
/// beyond [`session::DEFAULT_MAX_TRUSTED_DRIFT_MS`].
pub(super) const CLOCK_SKEW_MESSAGE: &str = "Your device clock appears to be out of sync with the \
     server by more than 24 hours. Correct your system time and try again.";
/// Classical one-time prekeys in each initial/rotating publish.
const ONE_TIME_PREKEYS: usize = 20;
/// Post-quantum one-time prekeys per suite in each v2 initial/rotating publish.
const PQ_ONE_TIME_PREKEYS: usize = 20;
/// Server-enforced cumulative classical OPK cap (`HandshakeV2Limits::default()`).
const SERVER_MAX_ONE_TIME_PREKEYS: usize = 100;
/// Server-enforced cumulative PQOPK cap summed across all suites (`HandshakeV2Limits::default()`).
const SERVER_MAX_PQ_ONE_TIME_PREKEYS: usize = 100;
/// Replenish one-time prekeys (without rotating SPK) once this many are used...
const REFILL_USED: u32 = 10;
/// ... and rotate the signed prekey once it is this old, in milliseconds.
const REPUBLISH_AGE: u64 = 7 * 24 * 60 * 60 * 1000;
/// Structured error returned by [`Engine::create`] and [`Engine::unlock`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultOpenError {
    /// Key derivation was cancelled explicitly by the user or aborted on `pagehide`.
    Cancelled,
    /// Creation or unlock failed for a user-visible reason.
    Failed(String),
}

/// Structured error returned by [`Engine::start_chat`] so the UI can offer actionable prompts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartChatError {
    /// The server requires sign-in on this page's origin before fetching prekeys / starting a chat.
    SignInRequired,
    ClassicalApprovalRequired,
    DowngradeDetected,
    PeerManifestExpired,
    PqRequired,
    /// The user dismissed or backed out of the startup form before the chat was created.
    Cancelled,
    Other(String),
}
/// Maximum milliseconds to wait for a proactive `/auth` check when unlocking via an invitation link.
const AUTH_CHECK_TIMEOUT: i32 = 1_500;
/// Maximum UTF-8 byte length for an outgoing text message (32 KiB; fits well under the 64 KiB
/// `PushV2` inline envelope cap alongside ratchet/PQ headers and optional carried initial).
pub const MAX_TEXT_BYTES: usize = 32 << 10;
/// Attachments up to this many bytes that are images, videos or audio show in the chat, fetched
/// as they are about to show; larger ones show as files, fetched once opened.
pub const MEDIA_INLINE_MAX: u64 = 8 << 20;
/// The largest file to send: as many chunks as the server takes, unless it says otherwise.
pub const MAX_FILE_SIZE: usize = DEFAULT_MAX_CHUNKS as usize * CHUNK_SIZE;
pub use crate::util::{NAME_MAX, sanitize_shared_name};

/// `name`, trimmed, unless it is longer than [`NAME_MAX`].
fn checked_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.chars().count() > NAME_MAX {
        return Err(format!("A name has at most {NAME_MAX} characters."));
    }
    Ok(name.to_string())
}
/// Milliseconds between asking for a chunk not uploaded yet, doubling up to the second...
const POLL_CHUNK_MIN: i32 = 500;
const POLL_CHUNK_MAX: i32 = 4_000;
/// ... until none came for this long, as the sender may have stopped.
const STALLED: i32 = 60_000;
/// Milliseconds before uploading a chunk again while the server cannot be reached, doubling up
/// to the second.
const RETRY_MIN: i32 = 1_000;
const RETRY_MAX: i32 = 30_000;
/// The history entries shown when a chat opens, without their files, which load when shown;
/// and read at a time to list a chat's files.
const HISTORY_SHOWN: u64 = 500;
/// Milliseconds between syncs: right after something happened, at most while idle, and while
/// the user is away, when the client has no notifications. Workers bill per request, so idle
/// pages back off, and pages left alone all but stop: the Worker and its Durable Objects then scale to
/// nothing.
const POLL_FAST: i32 = 3_000;
const POLL_SLOW: i32 = 30_000;
const POLL_AWAY: i32 = 30 * 60_000;
const POLL_STEP: i32 = 250;
/// The user is away once the page has been hidden this long, or out of focus this long, in
/// milliseconds: a glance at another tab or window keeps the notifications.
const HIDDEN_GRACE: u64 = 30_000;
const UNFOCUSED_GRACE: u64 = 5 * 60_000;
/// Milliseconds between checks of whether the user is away, while subscribed or waiting to.
const AWAY_CHECK: i32 = 1_000;
/// Milliseconds between syncs while notifications come, which only catch what they missed.
const POLL_LIVE: i32 = 300_000;
/// Milliseconds before subscribing again after the socket closed, doubling up to the second.
const RESUBSCRIBE_MIN: i32 = 1_000;
const RESUBSCRIBE_MAX: i32 = 60_000;
/// Decrypted chunks the streams keep, all of them together, as a player asks for one more than
/// once, e.g. as it seeks: beyond, the oldest go, so that however many players show, as in a file
/// browser of videos, they hold little plaintext.
const CHUNKS_DECRYPTED_KEPT: usize = 4;
/// Most clocks a chat keeps in each list of messages waiting for an event, either way: beyond,
/// the oldest are dropped, so that a chat left alone cannot grow the state, which each save
/// writes whole.
const EVENTS_KEPT: usize = 1_000;

pub struct Engine<V = Vault> {
    ui: Ui,
    inner: Mutex<Option<Inner<V>>>,
    /// Monotonic vault lifecycle generation bumped on every create/unlock and synchronously inside
    /// [`Engine::teardown_on_pagehide`] so any in-flight async continuation aborts cleanly without
    /// mutating IndexedDB or repopulating `Ui` signals.
    vault_generation: Cell<u64>,
    /// Set synchronously inside [`Engine::teardown_on_pagehide`]: if `self.inner` was held by an
    /// in-flight async task during `pagehide`, [`InnerGuard::drop`] immediately takes and drops
    /// `Inner` as soon as that task exits the mutex.
    shutting_down: Cell<bool>,
    /// Synchronous close handle for the active notification WebSocket, invoked directly on
    /// `pagehide` without awaiting `self.inner`.
    ws_close: RefCell<Option<CloseHandle>>,
    /// Single-unlock / single-create re-entrancy guard preventing overlapping unlocks or
    /// duplicate sync/notification/service-worker loops.
    unlocking: Cell<bool>,
    /// Sync now, e.g. after sending, as a reply may follow.
    wake: Cell<bool>,
    /// The files of the uploads started or resumed on this page, keyed by `(peer, id, key_hash)`,
    /// which can go on without the files chosen again.
    files: RefCell<HashMap<AttachmentKey, ChunkSource>>,
    /// The uploads going on, or being resumed.
    running: RefCell<HashSet<[u8; 16]>>,
    /// The uploads cancelled, or whose chat was deleted, on this page: those going on stop before
    /// their next chunk, and none is kept in the vault again.
    cancelled: RefCell<HashSet<[u8; 16]>>,
    /// What was sent and has yet to go, in the order it was sent, and whether a task is sending
    /// it.
    sending: RefCell<VecDeque<Sending>>,
    draining: Cell<bool>,
    /// Monotonic timestamp (ms) since the page has been hidden or out of focus, if it is.
    away_since: Cell<Option<u64>>,
    /// The attachments playing as they are fetched, by the tokens of their URLs.
    streams: RefCell<HashMap<String, Stream>>,
    /// The chunks the streams decrypted last, keyed by `(peer, id, key_hash, index)`, oldest
    /// first, shared only across streams with matching peer, attachment ID, and key; zeroized on
    /// eviction/drop.
    decrypted: RefCell<VecDeque<(ChunkOf, DecryptedChunk)>>,
    /// The chunks the streams are fetching, keyed by `(peer, id, key_hash, index)`, with what
    /// waits for each, woken once it is done.
    loading: RefCell<HashMap<ChunkOf, Vec<oneshot::Sender<()>>>>,
    /// The chats whose next message waits for this browser to sign in to the server, which
    /// keeps a message that large only for those who do. It goes once it signs in; until then,
    /// the chat's messages stay in its outbox, in order. An attachment waits so too, by its
    /// message's [`awaits_upload`](crate::vault::Outgoing::awaits_upload).
    waits_sign_in: RefCell<HashSet<PublicKey>>,
    /// Whether this page can sign in to the unlocked vault's server (same origin).
    can_sign_in_here: Cell<bool>,
    /// Coordinates sign-in dialogs with invitation / `NewChat` drafts so signing in or dismissing
    /// never discards a parsed invitation or user edits.
    sign_in_flow: RefCell<SignInFlow>,
    /// Actionable feedback (e.g. classical fallback prompt or error) to display when `NewChat`
    /// reopens after an automatic post-sign-in `start_chat` attempt needs user attention.
    new_chat_feedback: RefCell<Option<StartChatError>>,
    /// Whether publishing the prekeys was refused for the sign-in: it waits for one, rather than
    /// tries every round.
    publish_waits_sign_in: Cell<bool>,
    /// Whether publishing prekeys was definitively refused for the current settings with no
    /// rollback snapshot: background publishing pauses until the user adjusts settings or retries.
    publish_waits_settings: Cell<bool>,
    /// Monotonic generation and target peer (`None` for chat list) for [`Engine::open`],
    /// [`Engine::close_chat`], and open-chat deletion so an older in-flight `open` never
    /// overwrites a newer navigation while deleting peer A never cancels a queued open of peer B.
    open_tracker: Cell<OpenTracker>,
    /// Submission ID of a `start_chat` call currently awaiting network RPCs under `inner`, together
    /// with whether the chat has already been persisted (`greeting_only == true`), used to suppress
    /// late transport 403 sign-in prompts for discarded submissions and prevent greeting-only 403s
    /// from re-attaching an auto-start draft.
    in_flight_start_chat: Cell<Option<(u64, bool)>>,
    /// Startup submission IDs with active async tasks, reference-counted so overlapping `NewChat`
    /// and `SignInDialog` tasks sharing an ID keep cancellation live until the last task finishes.
    live_submissions: RefCell<HashMap<u64, usize>>,
    /// Live startup submission IDs cancelled by browser Back or native dialog dismissal.
    cancelled_submissions: RefCell<HashSet<u64>>,
    /// Exact set of history entries currently rendered on screen for the open chat, so
    /// visibility-return (`mark_read`), `saved_late` recovery, paging earlier history, and lifting
    /// quarantine only acknowledge messages that were actually displayed.
    displayed_history: RefCell<Option<DisplayedHistory>>,
    /// Per-row reactive signals for the currently displayed chat, enabling O(1) delivery and
    /// remote-attachment updates without scanning `ui.messages` per row and disposing cleanly on
    /// chat switches.
    displayed_rows: RefCell<DisplayedRows>,
    /// Monotonic counter tagging `Ui::deleted_peer` notifications.
    deleted_peer_seq: Cell<u64>,
    /// Whether a clock-skew warning has already been surfaced during the current drift episode.
    clock_skew_warned: Cell<bool>,
    /// Per-peer exponential backoff after `WriteTokenRejected` while awaiting peer approval:
    /// maps `peer -> (next_try_monotonic_ms, current_delay_ms)`.
    approval_backoff: RefCell<HashMap<PublicKey, (u64, u64)>>,
    /// Per-peer serialization mutexes for outbox flushes (`ClaimBundle`, `RegisterWriteToken`,
    /// `SendInitialV2`, `PushV2`, `push_events`), stored as `Weak` handles so an in-flight flush's
    /// mutex remains uniquely shared across concurrent delete+recreate cycles and is pruned cleanly
    /// once the last holder drops.
    peer_flush_locks: RefCell<HashMap<PublicKey, std::rc::Weak<Mutex<()>>>>,
}

/// Per-row reactive signal handles owned by the currently rendered chat.
#[derive(Debug, Clone, Copy)]
struct RowSignals {
    place: u64,
    delivery: Option<RwSignal<Delivery>>,
    remote_body: Option<RwSignal<Body>>,
}

impl RowSignals {
    fn from_row(row: &MessageRow) -> Self {
        Self {
            place: row.place,
            delivery: row.delivery_signal,
            remote_body: row.remote_body_signal,
        }
    }

    fn dispose(self) {
        if let Some(signal) = self.delivery {
            signal.dispose();
        }
        if let Some(signal) = self.remote_body {
            signal.dispose();
        }
    }
}

/// Index map of rendered message rows for the active chat.
#[derive(Default)]
struct DisplayedRows {
    peer: Option<PublicKey>,
    rows: HashMap<u64, RowSignals>,
}

/// Tracks what is currently displayed in `ui.messages` for an open chat so read acknowledgments
/// are idempotent by history index and older history pages remain reachable.
#[derive(Debug, Clone)]
struct DisplayedHistory {
    peer: PublicKey,
    /// Whether the latest history window load (`load_history` / `show_history`) succeeded.
    history_loaded: bool,
    /// Oldest history index boundary loaded so far (`0` means the start of history is reached).
    loaded_start: u64,
    /// Displayed entries whose unread/receipt state has not yet been acknowledged on screen.
    pending_entries: Vec<DisplayedEntry>,
}

/// Loaded history page returned by [`Engine::load_history_before`] together with its read-tracking
/// entries.
struct LoadedHistoryPage {
    messages: Vec<MessageView>,
    loaded_start: u64,
    entries: Vec<DisplayedEntry>,
}

/// Tracks the latest requested chat open/close generation and target peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct OpenTracker {
    generation: u64,
    target: Option<PublicKey>,
    /// If the previous target generation was invalidated by deleting that peer (rather than by a
    /// newer navigation), record that generation so its queued `Engine::open` returns
    /// [`OpenOutcome::Ignored`] and reconciles browser history instead of leaving the list on a
    /// deleted chat entry.
    deleted_generation: Option<u64>,
}

impl OpenTracker {
    pub(super) fn begin_open(&mut self, peer: PublicKey) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.target = Some(peer);
        self.deleted_generation = None;
        self.generation
    }

    pub(super) fn close(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.target = None;
        self.deleted_generation = None;
    }

    pub(super) fn is_current(&self, generation: u64) -> bool {
        self.generation == generation
    }

    pub(super) fn was_deleted(&self, generation: u64) -> bool {
        self.deleted_generation == Some(generation)
    }

    pub(super) fn is_settled_on(&self, displayed: Option<PublicKey>, peer: PublicKey) -> bool {
        displayed == Some(peer) && self.target == Some(peer)
    }

    pub(super) fn invalidate_peer(&mut self, peer: PublicKey) {
        if self.target == Some(peer) {
            let invalidated = self.generation;
            self.generation = self.generation.wrapping_add(1);
            self.target = None;
            self.deleted_generation = Some(invalidated);
        }
    }
}

/// Whether the browser tab is currently visible (always `true` in native tests).
#[cfg(target_arch = "wasm32")]
pub(super) fn is_page_visible() -> bool {
    !document().hidden()
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn is_page_visible() -> bool {
    true
}

/// Result of [`Engine::load_history`], distinguishing a missing contact from a vault load failure.
enum LoadedHistory {
    Missing,
    Loaded(LoadedHistoryPage),
    Failed(String),
}

/// Result of [`Engine::open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenOutcome {
    /// The requested chat (or chat list) is now active on screen.
    Opened,
    /// A newer [`Engine::open`] or chat deletion superseded this call before it completed.
    Superseded,
    /// The request could not be opened (vault locked, own identity key, or unknown contact).
    Ignored,
}

/// SHA-256 digest of an attachment key, binding plaintext/file caches without storing raw keys as map keys.
pub(crate) fn attachment_key_hash(key: &[u8]) -> [u8; 32] {
    Sha256::digest(key).into()
}

/// Cache key binding a local file to its exact `(peer, attachment_id, key_hash)`.
pub(crate) type AttachmentKey = (PublicKey, [u8; 16], [u8; 32]);

/// Cache key binding a stream chunk to its exact `(peer, attachment_id, key_hash, chunk_index)`.
pub(crate) type ChunkOf = (PublicKey, [u8; 16], [u8; 32], u32);

/// Shared decrypted stream chunk buffer, zeroized on drop when the last reference clears.
pub type DecryptedChunk = Rc<Zeroizing<Vec<u8>>>;

/// Result of saving post-quantum encryption preferences in [`Engine::set_pq_config`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqSaveOutcome {
    /// Config matched current vault state and no publish was pending.
    Unchanged,
    /// Config was saved locally and updated prekeys/manifest were published to the server.
    Published,
    /// Config was saved locally; publishing updated prekeys requires signing in first.
    SavedLocallyNeedsSignIn,
    /// Config was saved locally; publishing updated prekeys will retry once connected.
    SavedLocallyPendingPublish,
}

/// What was sent, waiting its turn to go: a message, or a file, which is read, or starts
/// uploading, first.
pub enum Sending {
    Content(PublicKey, Kind),
    File(PublicKey, web_sys::File),
}

impl Sending {
    pub(super) fn peer(&self) -> PublicKey {
        match self {
            Self::Content(peer, _) | Self::File(peer, _) => *peer,
        }
    }
}

/// RAII mutex guard over `Engine::inner` that automatically wipes `Inner` on exit if synchronous
/// `pagehide` teardown fired while this guard was held across an `.await`.
pub(super) struct InnerGuard<'a, V> {
    engine: &'a Engine<V>,
    guard: futures_util::lock::MutexGuard<'a, Option<Inner<V>>>,
}

impl<V> std::ops::Deref for InnerGuard<'_, V> {
    type Target = Option<Inner<V>>;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<V> std::ops::DerefMut for InnerGuard<'_, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<V> Drop for InnerGuard<'_, V> {
    fn drop(&mut self) {
        if self.engine.shutting_down.get() {
            let _ = self.guard.take();
        }
    }
}

/// The unlocked client.
pub(super) struct Inner<V = Vault> {
    vault: V,
    /// Monotonic `glue::lock_generation()` captured when this `Inner` was constructed so any
    /// persistence attempt that outlives `pagehide` fails closed even before touching `V`.
    lock_generation: u64,
    /// The server's address.
    server: String,
    /// Canonical expected server audience derived from `server` via `expected_audience_from_url`.
    audience: String,
    /// Server PQ availability discovered via `check_server_info`.
    server_pq: ServerPqStatus,
    /// Last known server-stored classical OPK count (from publish or `RefillPrekeysResponse`).
    last_server_classical_opks: Option<u32>,
    /// Last known server-stored total PQOPK count across all suites.
    last_server_pq_opks: Option<u32>,
    /// What is saved besides the client and the contacts, which are kept below.
    state: AppState,
    /// Encrypted inbox initials retained in the separate `deferred` vault sidecar record.
    deferred_initials: Vec<DeferredInitial>,
    /// Earliest timestamps (Unix ms) at which unsupported carried initials referencing an SPK
    /// were retained, bounding signed-prekey preservation across rotations.
    carried_deferred_timestamps: Vec<CarriedDeferredTimestamp>,
    /// Raw mailbox envelopes buffered for stalled/quarantined/rekeying peers so the unified
    /// mailbox cursor advances immediately for all active peers.
    deferred_envelopes: Vec<DeferredEnvelope>,
    client: Client<Connect>,
    contacts: Vec<Contact>,
    /// Unreadable records retained verbatim until explicitly deleted.
    isolated_contacts: Vec<ContactState>,
    /// History namespaces reserved by unreadable contacts with no healthy active record.
    isolated_peers: HashSet<PublicKey>,
    /// Per-contact `(security_alert, classical_approval_needed)` flags cleared during a pending
    /// `PqConfig` edit so a definitive server refusal restores them alongside `pending_pq_rollback`.
    pending_pq_contact_flags: HashMap<PublicKey, (Option<u32>, Option<u32>)>,
    /// A non-rollbackable state change still needs a successful transaction.
    unsaved_state: bool,
    /// Inbox IDs to commit with their deferred ciphertext before they become eligible for ack.
    deferred_acks_after_save: Vec<u64>,
    /// A later transaction committed that change. Refresh contact and identity views on sync.
    contacts_dirty_late: bool,
    /// History records that a save failed to write after what they record could not be undone:
    /// initial messages, which the server deleted once taken, and the greeting of a chat started.
    /// Each save writes them too, until one succeeds, so that the history has no gap.
    unsaved: Vec<(PublicKey, u64, HistoryEntry)>,
    /// Requeued outbox records that a save failed to write after an accepted replacement session
    /// reset `outbox[*].sealed = false` in memory. Each save writes them before any caller
    /// `outgoing` updates until one succeeds so `seal_next` never reads stale empty-content
    /// sealed outbox records from IndexedDB.
    unsaved_outbox: Vec<(PublicKey, u64, Option<OutgoingRecord>)>,
    /// The chats whose records left unsaved a save wrote, which then show them.
    saved_late: Vec<PublicKey>,
}

/// Which server RPC surface produced a protocol error, controlling whether `Unimplemented`
/// should trip the global `Ui::update_required` banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProtocolRpcScope {
    /// Required core `handshake.v2` / `mailbox.v2` RPCs.
    CoreV2,
    /// Optional `attachment.v1` upload/download/delete RPCs.
    #[cfg_attr(not(test), allow(dead_code))]
    Attachment,
}

/// Whether `error` on an RPC in `scope` should trip the global `Ui::update_required` banner
/// (and slow foreground polling to `POLL_LIVE`).
///
/// The core v2 handler must report a confirmed Connect `Unimplemented` server refusal.
pub(super) fn should_require_update_for_rpc(
    scope: ProtocolRpcScope,
    error: &session::Error,
) -> bool {
    scope == ProtocolRpcScope::CoreV2
        && error.is_server_refusal()
        && error.is_connect_error()
        && error.kind() == ErrorKind::Unimplemented
}

impl Engine<Vault> {
    pub fn new(ui: Ui) -> Rc<Self> {
        Self::empty(ui)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
impl<V: VaultStore> Engine<V> {
    /// Construct an already-unlocked engine backed by `inner` for deterministic native async tests.
    fn with_inner(ui: Ui, inner: Inner<V>) -> Rc<Self> {
        let engine = Self::empty(ui);
        engine.bump_vault_generation();
        engine
            .can_sign_in_here
            .set(same_server(&inner.server, &origin()));
        engine.ui.me.set(Some(inner.me()));
        engine.ui.contacts.set(inner.views());
        engine.ui.isolated_contacts.set(inner.isolated_views());
        engine.ui.phase.set(Phase::Unlocked);
        *engine.inner.try_lock().expect("fresh engine mutex") = Some(inner);
        engine
    }
}

impl<V: VaultStore> Engine<V> {
    fn empty(ui: Ui) -> Rc<Self> {
        let engine = Rc::new(Self {
            ui,
            inner: Mutex::new(None),
            vault_generation: Cell::new(0),
            shutting_down: Cell::new(false),
            ws_close: RefCell::new(None),
            unlocking: Cell::new(false),
            wake: Cell::new(false),
            files: RefCell::default(),
            running: RefCell::default(),
            cancelled: RefCell::default(),
            sending: RefCell::default(),
            draining: Cell::new(false),
            away_since: Cell::new(None),
            streams: RefCell::default(),
            decrypted: RefCell::default(),
            loading: RefCell::default(),
            waits_sign_in: RefCell::default(),
            can_sign_in_here: Cell::new(false),
            sign_in_flow: RefCell::default(),
            new_chat_feedback: RefCell::default(),
            publish_waits_sign_in: Cell::default(),
            publish_waits_settings: Cell::default(),
            open_tracker: Cell::new(OpenTracker::default()),
            in_flight_start_chat: Cell::new(None),
            live_submissions: RefCell::default(),
            cancelled_submissions: RefCell::default(),
            displayed_history: RefCell::default(),
            displayed_rows: RefCell::default(),
            deleted_peer_seq: Cell::new(0),
            clock_skew_warned: Cell::new(false),
            approval_backoff: RefCell::default(),
            peer_flush_locks: RefCell::default(),
        });
        // Register synchronous `pagehide` teardown BEFORE releasing the exclusive Web Lock.
        let weak = Rc::downgrade(&engine);
        glue::on_pagehide(move || {
            if let Some(engine) = weak.upgrade() {
                engine.teardown_on_pagehide();
            }
        });
        // Whatever the server refuses for the sign-in, the user is asked to sign in.
        let weak = Rc::downgrade(&engine);
        transport::on_sign_in_required(move || {
            if let Some(engine) = weak.upgrade() {
                engine.refused_for_sign_in();
            }
        });
        let weak = Rc::downgrade(&engine);
        transport::on_clock_skew(move |offset_ms| {
            if let Some(engine) = weak.upgrade() {
                engine.warn_clock_skew(offset_ms);
            }
        });
        engine
    }

    pub(super) fn bump_vault_generation(&self) -> u64 {
        let next = self.vault_generation.get().wrapping_add(1).max(1);
        self.vault_generation.set(next);
        next
    }

    pub(super) fn vault_gen(&self) -> u64 {
        self.vault_generation.get()
    }

    /// Whether synchronous `pagehide` / manual-lock teardown has started.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.get()
    }

    /// Whether `vgen` still matches the active vault lifecycle generation and `pagehide` has not
    /// revoked this page.
    pub(super) fn is_live(&self, vgen: u64) -> bool {
        !self.shutting_down.get()
            && self.vault_generation.get() == vgen
            && !crate::glue::lock_released()
    }

    /// Acquire `self.inner` through [`InnerGuard`], clearing `Inner` immediately if teardown has
    /// started (and on drop if teardown fires while this guard is held across an `.await`).
    pub(super) async fn lock_inner(&self) -> InnerGuard<'_, V> {
        let mut guard = self.inner.lock().await;
        if self.shutting_down.get() || crate::glue::lock_released() {
            let _ = guard.take();
        }
        InnerGuard {
            engine: self,
            guard,
        }
    }

    /// Synchronously revoke the active vault generation and scrub all sensitive in-memory,
    /// worker, WebSocket, media-port, blob-URL, DOM, and title state. Invoked directly inside
    /// `glue.rs`'s `pagehide` handler BEFORE releasing the exclusive Web Lock (and before manual
    /// vault lock reloads). Idempotent.
    pub fn teardown_on_pagehide(&self) {
        // 1. Bump both Engine and glue generations synchronously before anything else.
        self.shutting_down.set(true);
        self.bump_vault_generation();
        crate::glue::bump_lock_generation();

        // 2. Synchronously cancel and terminate any in-flight KDF worker.
        crate::kdf_worker::cancel_active();

        // 3. Synchronously close the live notification WebSocket without awaiting `self.inner`.
        if let Some(handle) = self.ws_close.borrow_mut().take() {
            handle.close();
        }

        // 4. Synchronously abort and close all active service-worker media ports.
        crate::glue::close_all_media_ports();

        // 5. Synchronously cancel pending previews and revoke all live `blob:` URLs.
        crate::app::cancel_pending_previews();
        crate::app::revoke_all_blob_urls();

        // 6. Synchronously terminate all live preview workers and reject pending calls.
        crate::workers::terminate_all();

        // 7. Clear transient engine caches and invalidate in-flight navigation/submissions.
        self.unlocking.set(false);
        self.wake.set(false);
        self.files.borrow_mut().clear();
        self.running.borrow_mut().clear();
        self.cancelled.borrow_mut().clear();
        self.sending.borrow_mut().clear();
        self.streams.borrow_mut().clear();
        self.decrypted.borrow_mut().clear();
        self.loading.borrow_mut().clear();
        self.waits_sign_in.borrow_mut().clear();
        self.approval_backoff.borrow_mut().clear();
        self.peer_flush_locks.borrow_mut().clear();
        *self.new_chat_feedback.borrow_mut() = None;
        self.cancel_active_startup_submission();
        *self.displayed_history.borrow_mut() = None;
        let mut tracker = self.open_tracker.get();
        tracker.close();
        self.open_tracker.set(tracker);

        // 8. Synchronously clear displayed messages, scrub ALL sensitive `Ui` signals, and reset
        //    `document.title` to generic `"E2EE Chat"` (no unread counts or peer names).
        self.clear_displayed_messages();
        let _ = self.ui.me.try_set(None);
        let _ = self.ui.contacts.try_set(vec![]);
        let _ = self.ui.isolated_contacts.try_set(vec![]);
        let _ = self.ui.open.try_set(None);
        let _ = self.ui.has_older_messages.try_set(false);
        let _ = self.ui.deleted_peer.try_set(None);
        let _ = self.ui.uploads.try_set(vec![]);
        let _ = self.ui.held.try_set(HashSet::new());
        let _ = self.ui.gone.try_set(HashSet::new());
        let _ = self.ui.dialog.try_set(None);
        let _ = self.ui.viewer.try_set(None);
        let _ = self.ui.opening.try_set(None);
        let _ = self.ui.streaming.try_set(None);
        let _ = self.ui.log.try_set(vec![]);
        let _ = self.ui.notice.try_set(None);
        let _ = self.ui.update_required.try_set(None);
        let _ = self.ui.live.try_set(false);
        let _ = self.ui.syncing.try_set(false);
        let _ = self.ui.away.try_set(false);
        let _ = self.ui.link.try_set(Link::Connecting);
        let _ = self.ui.phase.try_set(Phase::Locked);
        #[cfg(target_arch = "wasm32")]
        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            doc.set_title("E2EE Chat");
        }

        // 9. Take and drop `Inner` synchronously if uncontended; if held across an `.await`,
        //    `InnerGuard::drop` takes/drops `Inner` immediately on lock exit while `is_live(vgen)`
        //    and `ensure_vault_lock_owned()` prevent any post-`pagehide` IDB or `Ui` writes.
        if let Some(mut guard) = self.inner.try_lock() {
            let _ = guard.take();
        }
    }

    /// Return the per-peer serialization mutex for `peer`'s outbox flush, upgrading any live
    /// `Weak` entry so concurrent delete+recreate cycles strictly serialize behind an in-flight
    /// flush. Always acquired BEFORE `self.lock_inner()` (never while holding `self.inner`).
    pub(super) fn peer_flush_lock(&self, peer: &PublicKey) -> Rc<Mutex<()>> {
        let mut map = self.peer_flush_locks.borrow_mut();
        if let Some(existing) = map.get(peer).and_then(std::rc::Weak::upgrade) {
            return existing;
        }
        let lock = Rc::new(Mutex::new(()));
        map.insert(*peer, Rc::downgrade(&lock));
        lock
    }

    /// Remove `peer`'s entry from `peer_flush_locks` only once no active or queued flush holds an
    /// `Rc` to that mutex (`strong_count() == 0`).
    pub(super) fn prune_peer_flush_lock(&self, peer: &PublicKey) {
        let mut map = self.peer_flush_locks.borrow_mut();
        if map.get(peer).is_some_and(|weak| weak.strong_count() == 0) {
            map.remove(peer);
        }
    }

    pub(super) fn clear_approval_backoff(&self, peer: &PublicKey) {
        self.approval_backoff.borrow_mut().remove(peer);
    }

    pub(super) fn clear_all_approval_backoffs(&self) {
        self.approval_backoff.borrow_mut().clear();
    }

    pub(super) fn is_approval_backed_off(&self, peer: &PublicKey) -> bool {
        self.approval_backoff
            .borrow()
            .get(peer)
            .is_some_and(|&(next_try, _)| monotonic_now_ms() < next_try)
    }

    /// Record or advance per-peer approval backoff (`15s -> 30s -> 60s -> 5m`).
    pub(super) fn record_approval_backoff(&self, peer: &PublicKey) -> u64 {
        let mut map = self.approval_backoff.borrow_mut();
        let delay = match map.get(peer).map(|&(_, prev)| prev) {
            None => 15_000,
            Some(15_000) => 30_000,
            Some(30_000) => 60_000,
            Some(_) => 300_000,
        };
        map.insert(*peer, (monotonic_now_ms().saturating_add(delay), delay));
        delay
    }

    /// Log and notify the user once per drift episode when the device clock disagrees with the
    /// server beyond [`session::DEFAULT_MAX_TRUSTED_DRIFT_MS`].
    pub(super) fn warn_clock_skew(&self, offset_ms: i64) {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        if !self.clock_skew_warned.replace(true) {
            let hours = offset_ms.unsigned_abs() / (60 * 60 * 1000);
            self.ui.log(format!(
                "device clock drift exceeds trusted limit ({hours}h): {CLOCK_SKEW_MESSAGE}"
            ));
            self.ui.notify(CLOCK_SKEW_MESSAGE);
        }
    }

    /// Surface a persistent upgrade/refresh banner when the server rejects this client's protocol
    /// (e.g. a confirmed `ErrorKind::Unimplemented` server refusal on core v2 RPCs).
    pub(super) fn require_update(&self, reason: impl Into<String>) {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        let message = normalize_update_reason(&reason.into());
        let already_shown = self.ui.update_required.with_untracked(Option::is_some);
        if !already_shown {
            self.ui.log(format!("update required: {message}"));
            self.ui.notify(message.clone());
        }
        self.ui.update_required.set(Some(message));
    }

    /// If `error` is a confirmed `ErrorKind::Unimplemented` server refusal on a core v2
    /// procedure (`handshake.v2` / `mailbox.v2`), prompt the user to refresh/upgrade the page.
    /// Attachment errors (`ProtocolRpcScope::Attachment`) never trigger the global update banner.
    pub(super) fn check_protocol_error(&self, scope: ProtocolRpcScope, error: &session::Error) {
        if should_require_update_for_rpc(scope, error) {
            self.require_update(describe(error));
        }
    }

    /// Send `what` once everything sent before it went: messages go in the order they were
    /// sent, as the ratchet numbers them in the order it encrypts them. Sending each at once
    /// would not keep that order, as a file waits to be read, an attachment for its upload to
    /// start, and each waits for the lock, all of which let what was sent later go first.
    pub fn queue(self: &Rc<Self>, what: Sending) {
        self.sending.borrow_mut().push_back(what);
        if !self.draining.replace(true) {
            let engine = self.clone();
            spawn_local(async move { engine.drain().await });
        }
    }

    /// Send what was sent, a message at a time, until none is left.
    async fn drain(self: Rc<Self>) {
        let vgen = self.vault_gen();
        let _guard = scopeguard::guard((), |()| self.draining.set(false));
        loop {
            if !self.is_live(vgen) {
                break;
            }
            let Some(next) = self.sending.borrow_mut().pop_front() else {
                break;
            };
            let sent = match next {
                Sending::Content(peer, content) => self.send(peer, content).await,
                Sending::File(peer, file) => self.send_file(peer, file).await,
            };
            if !self.is_live(vgen) {
                break;
            }
            if let Err(e) = sent {
                self.ui.notify(e);
            }
        }
    }

    /// Send `file` to `peer`: all files (including 0-byte files) route unconditionally through
    /// the chunked encrypted attachment path (`attachment.v1`) so mailbox envelopes stay bounded.
    async fn send_file(
        self: &Rc<Self>,
        peer: PublicKey,
        file: web_sys::File,
    ) -> Result<(), String> {
        let name = file.name();
        let bytes = file.size() as u64;
        if bytes > MAX_FILE_SIZE as u64 {
            return Err(format!(
                "{name} is {}; files go up to {}.",
                size_u64(bytes),
                size_u64(MAX_FILE_SIZE as u64)
            ));
        }
        self.send_attachment(peer, ChunkSource::File(file)).await
    }

    /// The signals it keeps up to date.
    pub fn ui(&self) -> Ui {
        self.ui
    }

    /// Query `/auth` without side effects.
    async fn check_signed_in(&self) -> Result<Option<SignIn>, String> {
        let server = self.server().await?;
        let (status, answer) = transport::call(&server, "GET", "/auth", None).await?;
        if status != 200 {
            return Err(format!("the server answered {status}"));
        }
        Ok(SignIn::from_json(&answer))
    }

    /// Resume held peers, pending prekey publishing, and waiting uploads after observing a valid
    /// server sign-in (either via [`sign_in`](Self::sign_in) or an external sign-in discovered by
    /// [`signed_in`](Self::signed_in)).
    fn resume_after_sign_in(&self) {
        self.waits_sign_in.borrow_mut().clear();
        self.sign_in_flow.borrow_mut().reset_declined();
        self.publish_waits_sign_in.set(false);
        self.wake();
    }

    /// Who this browser is signed in to the server as, if anyone, which storing files there
    /// takes. If an external sign-in is observed (e.g. on another of the server's pages), resumes
    /// held peers, prekey publishing, and waiting uploads.
    pub async fn signed_in(self: &Rc<Self>) -> Result<Option<SignIn>, String> {
        let vgen = self.vault_gen();
        let signed_in = self.check_signed_in().await?;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        if signed_in.is_some() {
            self.resume_after_sign_in();
            let engine = self.clone();
            spawn_local(async move {
                engine.start_waiting_uploads().await;
            });
        }
        Ok(signed_in)
    }

    /// Sign in to the server with its `password`: what waited for it goes then.
    pub async fn sign_in(self: &Rc<Self>, password: &str) -> Result<SignIn, String> {
        let vgen = self.vault_gen();
        let server = self.server().await?;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        // Its cookie is the server's, which only the server's own page keeps and sends; another
        // origin's calls to it cannot even read its answer.
        if !same_server(&server, &origin()) {
            return Err(
                "This page signs in only to its own server: sign in on the server's own page."
                    .to_string(),
            );
        }
        let (status, _) =
            transport::call(&server, "POST", "/auth/password", Some(password)).await?;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        match status {
            200 => {}
            403 => return Err("Wrong password.".to_string()),
            429 => {
                return Err("Too many sign-in attempts. Wait a minute and try again.".to_string());
            }
            503 => return Err("This server takes no sign-ins: it has no password set.".to_string()),
            status => return Err(format!("The server answered {status}.")),
        }
        // Unless the browser refused the cookie, e.g. as it blocks the server's cookies.
        let signed_in = self.check_signed_in().await?.ok_or(
            "This browser kept no sign-in for the server: it may block the server's cookies.",
        )?;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        self.resume_after_sign_in();
        self.start_waiting_uploads().await;
        if self.is_live(vgen) {
            self.wake();
        }
        Ok(signed_in)
    }

    /// Sign out of the server: files wait for the next sign-in.
    pub async fn sign_out(&self) -> Result<(), String> {
        let server = self.server().await?;
        let (status, _) = transport::call(&server, "POST", "/auth/sign-out", None).await?;
        match status {
            200 => Ok(()),
            status => Err(format!("The server answered {status}.")),
        }
    }

    /// Present `dialog` only if `ui.dialog` does not already hold an equal dialog, avoiding
    /// unmounting and rebuilding an active `SignInDialog` (which would cancel its live submission
    /// and history reservation).
    pub(super) fn show_dialog_if_changed(&self, dialog: Dialog) {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        if self
            .ui
            .dialog
            .with_untracked(|current| current.as_ref() != Some(&dialog))
        {
            self.ui.dialog.set(Some(dialog));
        }
    }

    /// Ask the user to sign in to the server, as what was sent waits for it. If `NewChat` is
    /// currently open, preserves its invitation/draft so it can resume seamlessly after sign-in.
    fn ask_sign_in(&self) {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        let next = self.ui.dialog.with_untracked(|current| {
            self.sign_in_flow.borrow_mut().on_ask_sign_in(
                current.as_ref(),
                self.can_sign_in_here.get(),
                false,
            )
        });
        if let Some(dialog) = next {
            self.show_dialog_if_changed(dialog);
        }
    }

    /// The server refused a call, whichever, as this browser is not signed in to it, which every
    /// write takes: ask, unless the user put it off or cancelled the in-flight startup submission.
    fn refused_for_sign_in(&self) {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        if let Some((id, greeting_only)) = self.in_flight_start_chat.get() {
            if self.is_submission_cancelled(id) {
                return;
            }
            if greeting_only {
                if self.can_sign_in_here.get() {
                    let dialog = self
                        .sign_in_flow
                        .borrow_mut()
                        .on_chat_created_greeting_needs_sign_in(id);
                    self.show_dialog_if_changed(dialog);
                }
                return;
            }
        }
        let next = self.ui.dialog.with_untracked(|current| {
            self.sign_in_flow.borrow_mut().on_ask_sign_in(
                current.as_ref(),
                self.can_sign_in_here.get(),
                true,
            )
        });
        if let Some(dialog) = next {
            self.show_dialog_if_changed(dialog);
        }
    }

    fn mark_submission_cancelled(&self, submission_id: u64) {
        if self.live_submissions.borrow().contains_key(&submission_id) {
            self.cancelled_submissions
                .borrow_mut()
                .insert(submission_id);
        }
    }

    /// Suppress subsequent background sign-in prompts without restoring any cancelled draft
    /// (called when browser Back or an OS close dismisses `Dialog::SignIn`).
    pub fn decline_sign_in_prompts(&self) {
        self.sign_in_flow.borrow_mut().decline_background_prompts();
    }

    /// The user dismissed `SignInDialog` ("Not now" or Escape): suppress background sign-in
    /// prompts, mark any live auto-start submission cancelled, restore any preserved `NewChat` /
    /// invitation draft, and return `true` if a dialog was restored (so a native `<dialog>` cancel
    /// event keeps the modal open).
    pub fn dismiss_sign_in(&self) -> bool {
        let (cancelled_id, restored) = self.sign_in_flow.borrow_mut().on_dismiss_sign_in();
        if let Some(id) = cancelled_id {
            self.mark_submission_cancelled(id);
        }
        match restored {
            Some(restored) => {
                self.ui.dialog.set(Some(restored));
                true
            }
            None => {
                self.close_dialog_if_sign_in();
                false
            }
        }
    }

    /// Record the currently mounted `NewChat` dialog's fields so a background sign-in prompt
    /// preserves any invitation or edits.
    pub fn new_chat_mounted(
        &self,
        key: String,
        name: String,
        server: Option<String>,
        pq_pinned: bool,
    ) {
        self.sign_in_flow
            .borrow_mut()
            .on_new_chat_mounted(key, name, server, pq_pinned);
    }

    /// Update the live `NewChat` draft as the user edits key or name.
    pub fn new_chat_edited(
        &self,
        key: String,
        name: String,
        server: Option<String>,
        pq_pinned: bool,
    ) {
        self.sign_in_flow
            .borrow_mut()
            .on_new_chat_edited(key, name, server, pq_pinned);
    }

    /// Clear the live `NewChat` draft tracker when `NewChat` unmounts.
    pub fn new_chat_unmounted(&self) {
        self.sign_in_flow.borrow_mut().on_new_chat_unmounted();
    }

    /// Mark that `NewChat` has an in-flight `start_chat` submission, returning its unique ID.
    pub fn begin_new_chat_submit(&self, draft: PendingNewChat) -> u64 {
        let id = self.sign_in_flow.borrow_mut().begin_new_chat_submit(draft);
        *self.live_submissions.borrow_mut().entry(id).or_insert(0) += 1;
        id
    }

    /// Register a live `SignInDialog` auto-start task for `submission_id` so dismissal cancels it
    /// without retaining tombstones for idle dialogs.
    pub fn begin_sign_in_auto_start(&self, submission_id: u64) {
        *self
            .live_submissions
            .borrow_mut()
            .entry(submission_id)
            .or_insert(0) += 1;
    }

    /// Decrement the active task count for `submission_id` once its async task finishes, clearing
    /// its cancellation tombstone only once all overlapping tasks sharing `submission_id` end.
    pub fn finish_submission(&self, submission_id: u64) {
        let mut live = self.live_submissions.borrow_mut();
        if let Some(count) = live.get_mut(&submission_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                live.remove(&submission_id);
                self.cancelled_submissions
                    .borrow_mut()
                    .remove(&submission_id);
            }
        } else {
            self.cancelled_submissions
                .borrow_mut()
                .remove(&submission_id);
        }
        self.sign_in_flow
            .borrow_mut()
            .end_new_chat_submit(submission_id);
    }

    /// Mark a specific startup submission cancelled (e.g. on dialog unmount) so late network
    /// responses cannot reopen Sign In, send a greeting, or clobber a newer draft.
    pub fn cancel_startup_submission(&self, submission_id: u64) {
        self.mark_submission_cancelled(submission_id);
        self.sign_in_flow
            .borrow_mut()
            .cancel_submission(submission_id);
    }

    /// Cancel whichever in-flight `NewChat` or auto-start `SignIn` submission is currently active
    /// (called synchronously on browser Back or native dialog cancel/close).
    pub fn cancel_active_startup_submission(&self) {
        let cancelled = self.sign_in_flow.borrow_mut().cancel_active_submissions();
        for id in cancelled {
            self.mark_submission_cancelled(id);
        }
        if let Some((id, _)) = self.in_flight_start_chat.get() {
            self.mark_submission_cancelled(id);
        }
    }

    /// Whether `submission_id` was cancelled by user Back or native dialog dismissal.
    pub fn is_submission_cancelled(&self, submission_id: u64) -> bool {
        self.cancelled_submissions.borrow().contains(&submission_id)
    }

    /// Clear any preserved `pending_new_chat` draft belonging to `submission_id` once `NewChat`
    /// has already succeeded (e.g. if a concurrent background 403 opened `SignInDialog` with this
    /// draft before `start_chat` acquired the engine mutex), without marking `submission_id`
    /// cancelled or closing `SignInDialog`.
    pub fn clear_pending_new_chat(&self, submission_id: u64) {
        self.sign_in_flow
            .borrow_mut()
            .cancel_submission(submission_id);
    }

    /// Preserve a submitted `NewChat` draft (with `auto_start: true`) and immediately present
    /// `SignInDialog` cleanly when `start_chat` hits `SignInRequired`.
    pub fn require_sign_in_for_new_chat(&self, submission_id: u64, draft: PendingNewChat) {
        let dialog = self
            .sign_in_flow
            .borrow_mut()
            .on_start_chat_sign_in_required(submission_id, draft);
        self.show_dialog_if_changed(dialog);
    }

    /// Hint for `SignInDialog` when a `NewChat` / invitation draft is waiting:
    /// `Some((auto_start, has_key))`.
    pub fn pending_new_chat_hint(&self) -> Option<(bool, bool)> {
        self.sign_in_flow.borrow().pending_new_chat_hint()
    }

    /// Submission ID of a pending `auto_start: true` chat waiting behind `SignInDialog`, if any.
    pub fn pending_auto_start_id(&self) -> Option<u64> {
        self.sign_in_flow.borrow().pending_auto_start_id()
    }

    /// Close the dialog only if `NewChat` is still the active dialog (avoiding clobbering
    /// `SignInDialog` if sending the greeting hit `SignInRequired` right after persisting).
    pub fn close_dialog_if_new_chat(&self) {
        if self
            .ui
            .dialog
            .with_untracked(|dialog| matches!(dialog, Some(Dialog::NewChat { .. })))
        {
            self.ui.dialog.set(None);
        }
    }

    /// Close the dialog only if `SignIn` is still the active dialog.
    pub fn close_dialog_if_sign_in(&self) {
        if self
            .ui
            .dialog
            .with_untracked(|dialog| matches!(dialog, Some(Dialog::SignIn)))
        {
            self.ui.dialog.set(None);
        }
    }

    /// Determine what `SignInDialog` should do right after `Engine::sign_in` succeeds.
    pub fn complete_sign_in_flow(&self) -> SignInSuccessAction {
        self.sign_in_flow.borrow_mut().on_sign_in_succeeded()
    }

    /// Complete an automatic post-sign-in `start_chat` attempt scoped strictly to `submission_id`,
    /// closing `SignInDialog` on success or reopening `NewChat` prefilled with `err` when user
    /// attention is required.
    pub fn finish_auto_start_chat(&self, submission_id: u64, err: Option<StartChatError>) {
        let (succeeded, still_needs_sign_in) = match &err {
            None => (true, false),
            Some(StartChatError::SignInRequired) => (false, true),
            Some(_) => (false, false),
        };
        let (close_sign_in, reopened) = self.sign_in_flow.borrow_mut().on_auto_start_finished(
            submission_id,
            succeeded,
            still_needs_sign_in,
        );
        if close_sign_in {
            self.close_dialog_if_sign_in();
        } else if let Some(dialog) = reopened {
            *self.new_chat_feedback.borrow_mut() = err;
            self.ui.dialog.set(Some(dialog));
        }
    }

    /// Take any deferred feedback queued for a newly mounted `NewChat` dialog.
    pub fn take_new_chat_feedback(&self) -> Option<StartChatError> {
        self.new_chat_feedback.borrow_mut().take()
    }

    /// The server's address.
    async fn server(&self) -> Result<String, String> {
        let guard = self.lock_inner().await;
        Ok(guard.as_ref().ok_or("locked")?.server.clone())
    }
}

impl Engine<Vault> {
    /// Find out whether to create or unlock the vault.
    pub async fn start(&self) {
        glue::register_media_worker();
        // Two tabs on one vault would fork the sessions' ratchets. If another tab holds the lock,
        // display `Elsewhere` immediately while waiting ONLY when this tab is visible and focused,
        // so refreshing or locking a foreground tab never hands the vault to a background waiter.
        let mut lock = crate::glue::take_lock("e2ee-chat").await;
        if lock == LockStatus::HeldElsewhere
            && !crate::glue::lock_released()
            && !self.shutting_down.get()
        {
            self.ui.phase.set(Phase::Elsewhere);
            lock = crate::glue::wait_for_lock_when_active("e2ee-chat").await;
        }
        if crate::glue::lock_released() || self.shutting_down.get() {
            return;
        }
        match lock {
            LockStatus::Acquired => {}
            LockStatus::HeldElsewhere => {
                self.ui.phase.set(Phase::Elsewhere);
                return;
            }
            LockStatus::Unavailable {
                insecure_context: true,
            } => {
                self.ui.phase.set(Phase::Unavailable(
                    UnavailableReason::InsecureContext,
                    "This page requires a secure context (HTTPS or localhost) for the Web Locks \
                     API, which prevents concurrent tabs from corrupting your vault."
                        .to_string(),
                ));
                return;
            }
            LockStatus::Unavailable {
                insecure_context: false,
            } => {
                self.ui.phase.set(Phase::Unavailable(
                    UnavailableReason::LocksUnavailable,
                    "This browser does not provide the Web Locks API, so the vault cannot be \
                     opened safely without risking concurrent tab corruption."
                        .to_string(),
                ));
                return;
            }
        }
        if crate::glue::lock_released() || self.shutting_down.get() {
            return;
        }
        match Vault::inspect().await {
            Ok(_) if crate::glue::lock_released() || self.shutting_down.get() => {}
            Ok(VaultPresence::Compatible) => self.ui.phase.set(Phase::Locked),
            Ok(VaultPresence::None) => self.ui.phase.set(Phase::Create),
            Ok(VaultPresence::IncompatibleVersion(version)) => {
                self.ui.phase.set(Phase::IncompatibleVault(version));
            }
            // Offering to create one could replace a vault that is there.
            Err(e) if !crate::glue::lock_released() && !self.shutting_down.get() => {
                self.ui.phase.set(Phase::Unavailable(
                    UnavailableReason::StorageUnavailable,
                    describe(&e),
                ));
            }
            Err(_) => {}
        }
    }

    /// Create a vault with a new identity, under `passphrase`, replacing any other.
    pub async fn create(
        self: &Rc<Self>,
        name: String,
        passphrase: Zeroizing<String>,
        server: String,
        pq_enabled: bool,
        cancel: KdfCancelToken,
    ) -> Result<(), VaultOpenError> {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return Err(VaultOpenError::Cancelled);
        }
        if self.unlocking.replace(true) {
            return Err(VaultOpenError::Failed(
                "The vault is already being opened.".to_string(),
            ));
        }
        let _unlock_guard = scopeguard::guard((), |()| self.unlocking.set(false));
        let vgen = self.bump_vault_generation();
        if self.lock_inner().await.is_some() {
            return Err(VaultOpenError::Failed(
                "The vault is already unlocked.".to_string(),
            ));
        }
        if !self.is_live(vgen) {
            return Err(VaultOpenError::Cancelled);
        }
        let raw_server = server.trim();
        let current_origin = origin();
        let (server, address) = if raw_server.is_empty() {
            let canonical =
                crate::util::validate_relay_url(&current_origin).map_err(VaultOpenError::Failed)?;
            (String::new(), canonical)
        } else {
            let canonical =
                crate::util::validate_relay_url(raw_server).map_err(VaultOpenError::Failed)?;
            // The page's own server is saved as empty, so the vault follows the page.
            let stored = if same_server(&canonical, &current_origin) {
                String::new()
            } else {
                canonical.clone()
            };
            (stored, canonical)
        };
        let audience = expected_audience_from_url(&address).map_err(|_| {
            VaultOpenError::Failed(
                "Enter a valid https:// (or http://localhost) server address.".to_string(),
            )
        })?;
        let mut client =
            Client::new(Fetch::client(&address)).with_clock(transport::clock(&address));
        let mut pq_config = PqConfig::default();
        if !pq_enabled {
            pq_config.pq_enabled = false;
            pq_config.strict_pq = false;
        }
        client
            .set_pq_config(pq_config)
            .map_err(|e| VaultOpenError::Failed(describe(&e)))?;
        let state = AppState {
            client: Some(client.state().into()),
            server,
            name: checked_name(&name).map_err(VaultOpenError::Failed)?,
            ..AppState::default()
        };
        let vault = Vault::create(passphrase.as_bytes(), &state, &cancel)
            .await
            .map_err(|e| match e {
                crate::vault::Error::Cancelled => VaultOpenError::Cancelled,
                other => VaultOpenError::Failed(describe(&other)),
            })?;
        drop(passphrase);
        if !self.is_live(vgen) || cancel.is_cancelled() {
            return Err(VaultOpenError::Cancelled);
        }
        let state = AppState {
            client: None,
            ..state
        };
        self.unlocked(
            vgen,
            Inner::new(
                vault,
                address,
                audience,
                state,
                client,
                vec![],
                vec![],
                DeferredRecord::default(),
            ),
        )
        .await;
        Ok(())
    }

    /// Unlock the vault with `passphrase`.
    pub async fn unlock(
        self: &Rc<Self>,
        passphrase: Zeroizing<String>,
        cancel: KdfCancelToken,
    ) -> Result<(), VaultOpenError> {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return Err(VaultOpenError::Cancelled);
        }
        if self.unlocking.replace(true) {
            return Err(VaultOpenError::Failed(
                "The vault is already being opened.".to_string(),
            ));
        }
        let _unlock_guard = scopeguard::guard((), |()| self.unlocking.set(false));
        let vgen = self.bump_vault_generation();
        if self.lock_inner().await.is_some() {
            return Err(VaultOpenError::Failed(
                "The vault is already unlocked.".to_string(),
            ));
        }
        if !self.is_live(vgen) {
            return Err(VaultOpenError::Cancelled);
        }
        let (vault, mut state, mut deferred) = Vault::unlock(passphrase.as_bytes(), &cancel)
            .await
            .map_err(|e| match e {
                crate::vault::Error::Cancelled => VaultOpenError::Cancelled,
                other => VaultOpenError::Failed(describe(&other)),
            })?;
        drop(passphrase);
        if !self.is_live(vgen) || cancel.is_cancelled() {
            return Err(VaultOpenError::Cancelled);
        }
        let address = address(&state.server);
        let audience = expected_audience_from_url(&address).map_err(|_| {
            VaultOpenError::Failed("the server address saved in the vault is invalid".to_string())
        })?;
        let client = state
            .client
            .take()
            .ok_or_else(|| VaultOpenError::Failed("the vault has no identity".to_string()))?;
        let client = Client::restore(
            Fetch::client(&address),
            ClientState::try_from(&client).map_err(|e| VaultOpenError::Failed(describe(&e)))?,
        )
        .with_clock(transport::clock(&address));
        let (contacts, isolated_contacts, warnings) = restore_contacts(
            std::mem::take(&mut state.contacts),
            &client.identity_key(),
            &address,
        );
        let now_ms = crate::util::now();
        let pruned = handshake::prune_invalid_inbox_acks(&mut state.pending_inbox_acks);
        let (pruned_deferred, modified_deferred) =
            handshake::sanitize_deferred_initials(&mut deferred.entries, now_ms);
        let pruned_carried_ts = handshake::prune_carried_timestamps_for_contacts(
            &mut deferred.carried_timestamps,
            contacts.iter(),
        );
        let pruned_envelopes =
            sync::prune_deferred_envelopes(&mut deferred.envelopes, &contacts, now_ms);
        let mut inner = Inner::new(
            vault,
            address,
            audience,
            state,
            client,
            contacts,
            isolated_contacts,
            deferred,
        );
        if pruned > 0
            || pruned_deferred > 0
            || modified_deferred
            || pruned_carried_ts > 0
            || pruned_envelopes > 0
        {
            inner.unsaved_state = true;
        }
        self.unlocked(vgen, inner).await;
        if !self.is_live(vgen) {
            return Err(VaultOpenError::Cancelled);
        }
        if pruned > 0 {
            self.ui.log(format!(
                "Removed {pruned} invalid or duplicate inbox acknowledgement ID(s) from the vault."
            ));
        }
        if pruned_deferred > 0 {
            self.ui.log(format!(
                "Removed {pruned_deferred} invalid, duplicate, or excess deferred initial message(s) from the vault."
            ));
        }
        let warning_count = warnings.len();
        for warning in warnings {
            self.ui.log(warning);
        }
        let isolated = self.ui.isolated_contacts.with_untracked(Vec::len);
        if isolated > 0 {
            self.ui.notify(format!(
                "Vault unlocked. Isolated {isolated} corrupt contact(s). Review in Settings."
            ));
        } else if warning_count > 0 {
            self.ui.notify(format!(
                "Vault unlocked. Ignored {warning_count} corrupt duplicate contact record(s)."
            ));
        }
        Ok(())
    }

    async fn unlocked(self: &Rc<Self>, vgen: u64, inner: Inner) {
        if !self.is_live(vgen) {
            return;
        }
        let can_sign_in_here = same_server(&inner.server, &origin());
        self.can_sign_in_here.set(can_sign_in_here);
        self.ui.me.set(Some(inner.me()));
        self.ui.contacts.set(inner.views());
        self.ui.isolated_contacts.set(inner.isolated_views());
        // Uploads the page left: their files are gone with it.
        match inner.vault.uploads(None).await {
            Ok(uploads) => {
                for (peer, pending) in uploads {
                    if !self.is_live(vgen) {
                        return;
                    }
                    // Done, but left behind, as forgetting it failed (or tab closed after
                    // keeping the final chunk before `forget_upload` committed).
                    let chunks = attachment::chunk_count(pending.size);
                    if pending.started()
                        && (u64::from(pending.uploaded) >= chunks
                            || u64::from(
                                inner
                                    .vault
                                    .chunks_kept(&peer, &pending.id)
                                    .await
                                    .unwrap_or(0),
                            ) >= chunks)
                    {
                        if !self.is_live(vgen) {
                            return;
                        }
                        let _ = inner.vault.forget_upload(&peer, &pending.id).await;
                        continue;
                    }
                    // Stale unstarted waiting upload whose outbox entry was already promoted to a
                    // real upload (or failed/sent) before `forget_upload` committed.
                    if !pending.started()
                        && !inner.contacts.iter().any(|c| {
                            c.peer == peer
                                && c.state.outbox.iter().any(|o| {
                                    o.history_index == pending.history_index && o.awaits_upload
                                })
                        })
                    {
                        if !self.is_live(vgen) {
                            return;
                        }
                        let _ = inner.vault.forget_upload(&peer, &pending.id).await;
                        continue;
                    }
                    if !self.is_live(vgen) {
                        return;
                    }
                    let reason = if pending.started() {
                        "choose the file again to go on"
                    } else {
                        self.hold(&peer, pending.history_index);
                        "choose the file again, then sign in to the server"
                    };
                    self.show_upload(&peer, &pending, UploadState::Paused(reason.to_string()));
                }
            }
            Err(e) if self.is_live(vgen) => self.ui.notify(describe(&e)),
            Err(_) => return,
        }
        if !self.is_live(vgen) {
            return;
        }
        {
            let mut slot = self.lock_inner().await;
            if !self.is_live(vgen) || slot.is_some() {
                return;
            }
            *slot = Some(inner);
        }
        if let Some(dialog) = invitation() {
            forget_invitation();
            // Proactively check `/auth` (bounded by a short timeout so offline unlock never hangs)
            // so first-time invitees see SignInDialog directly without flashing NewChat or losing
            // the invitation link.
            let signed_in = if can_sign_in_here {
                match select(
                    Box::pin(self.signed_in()),
                    Box::pin(sleep(AUTH_CHECK_TIMEOUT)),
                )
                .await
                {
                    Either::Left((Ok(Some(_)), _)) => Some(true),
                    Either::Left((Ok(None), _)) => Some(false),
                    Either::Left((Err(_), _)) | Either::Right(_) => None,
                }
            } else {
                None
            };
            if !self.is_live(vgen) {
                return;
            }
            let initial = self.sign_in_flow.borrow_mut().on_unlock_with_invitation(
                dialog,
                can_sign_in_here,
                signed_in,
            );
            self.ui.dialog.set(Some(initial));
        }
        if !self.is_live(vgen) {
            return;
        }
        self.ui.phase.set(Phase::Unlocked);
        self.ui.log("vault unlocked");
        self.clone().run(vgen);
        self.clone().listen(vgen);
        let engine = self.clone();
        glue::serve_media(move |request| {
            let engine = engine.clone();
            spawn_local(async move { engine.serve_media(request, vgen).await });
        });
    }
}

impl<V: VaultStore> Engine<V> {
    /// Save `content` for `peer`, then push it, encrypted as its turn comes. What the user sends
    /// goes through [`Engine::queue`], to go in order.
    async fn send(&self, peer: PublicKey, content: Kind) -> Result<(), String> {
        self.send_returning_index(peer, content).await.map(drop)
    }

    async fn send_returning_index(&self, peer: PublicKey, content: Kind) -> Result<u64, String> {
        let vgen = self.vault_gen();
        let index = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            let view = inner.add(&peer, content, false).await?;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let index = view.index;
            self.show_new(inner, &peer, vec![view]);
            self.ui.contacts.set(inner.views());
            index
        };
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        // Saved, so it goes in a later sync if not now.
        if let Err(e) = self.flush(&peer).await
            && self.is_live(vgen)
        {
            self.ui.link.set(Link::Offline(e));
        }
        if self.is_live(vgen) {
            self.wake();
        }
        Ok(index)
    }

    /// Whether `peer` is currently displayed on screen with its history loaded and no conflicting
    /// queued navigation.
    pub fn is_settled_on(&self, peer: PublicKey) -> bool {
        self.open_tracker
            .get()
            .is_settled_on(self.ui.open.get_untracked(), peer)
            && self.is_history_loaded_for(peer)
    }

    /// Invalidate any queued [`Engine::open`] synchronously (e.g. when the user clicks in-app
    /// Close while browser `history.back()` is settling) without clearing `ui.open` prematurely,
    /// so an in-flight history load cannot open and mark a chat read after the user chose to leave.
    pub fn cancel_pending_open(&self) {
        let mut tracker = self.open_tracker.get();
        tracker.close();
        self.open_tracker.set(tracker);
    }

    /// Clear `ui.messages` and dispose every per-row reactive signal owned by the previous chat.
    fn clear_displayed_messages(&self) {
        let _ = self.ui.messages.try_set(vec![]);
        let old = {
            let mut displayed = self.displayed_rows.borrow_mut();
            displayed.peer = None;
            std::mem::take(&mut displayed.rows)
        };
        for signals in old.into_values() {
            signals.dispose();
        }
    }

    /// Replace the displayed message list for `peer`, reusing existing per-row reactive signals
    /// when refreshing the same chat (so `<For>` children stay wired to live signals) and
    /// disposing removed/old signals cleanly.
    fn set_displayed_messages(&self, peer: PublicKey, views: Vec<MessageView>, open_peer: bool) {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        let mut displayed = self.displayed_rows.borrow_mut();
        let same_peer = displayed.peer == Some(peer);
        let mut old_rows = std::mem::take(&mut displayed.rows);
        let mut next_rows = HashMap::with_capacity(views.len());
        let mut rows = Vec::with_capacity(views.len());
        for view in views {
            if same_peer && let Some(existing) = old_rows.remove(&view.index) {
                if let Some(sig) = existing.delivery
                    && sig.get_untracked() != view.delivery
                {
                    sig.set(view.delivery);
                }
                if let Some(sig) = existing.remote_body
                    && sig.with_untracked(|current| *current != view.body)
                {
                    sig.set(view.body.clone());
                }
                let row = MessageRow {
                    index: view.index,
                    place: view.place,
                    outgoing: view.outgoing,
                    at: view.at,
                    body: view.body,
                    delivery: view.delivery,
                    delivery_signal: existing.delivery,
                    remote_body_signal: existing.remote_body,
                };
                next_rows.insert(
                    row.index,
                    RowSignals {
                        place: row.place,
                        delivery: existing.delivery,
                        remote_body: existing.remote_body,
                    },
                );
                rows.push(row);
            } else {
                let row = MessageRow::from_view(view);
                next_rows.insert(row.index, RowSignals::from_row(&row));
                rows.push(row);
            }
        }
        displayed.peer = Some(peer);
        displayed.rows = next_rows;
        drop(displayed);

        self.ui.messages.set(rows);
        if open_peer {
            self.ui.open.set(Some(peer));
        }
        for signals in old_rows.into_values() {
            signals.dispose();
        }
    }

    /// Return to the chat list immediately without waiting for `inner` (which a stalled network
    /// sync or flush may hold), invalidating any in-flight [`Engine::open`] so it cannot reopen
    /// the closed chat or write stale history messages.
    pub fn close_chat(&self) {
        let mut tracker = self.open_tracker.get();
        tracker.close();
        self.open_tracker.set(tracker);
        *self.displayed_history.borrow_mut() = None;
        self.ui.has_older_messages.set(false);
        self.ui.open.set(None);
        self.clear_displayed_messages();
    }

    fn is_history_loaded_for(&self, peer: PublicKey) -> bool {
        self.displayed_history
            .borrow()
            .as_ref()
            .is_some_and(|d| d.peer == peer && d.history_loaded)
    }

    /// Record entries just appended to `ui.messages` for `peer` so later visibility return
    /// (`mark_read`) or quarantine clearance reconciles them idempotently by history index.
    fn record_displayed_entries(&self, peer: &PublicKey, entries: &[DisplayedEntry]) {
        if entries.is_empty() {
            return;
        }
        let mut slot = self.displayed_history.borrow_mut();
        let displayed = match slot.as_mut().filter(|d| d.peer == *peer) {
            Some(d) => d,
            None => slot.insert(DisplayedHistory {
                peer: *peer,
                history_loaded: false,
                loaded_start: 0,
                pending_entries: Vec::new(),
            }),
        };
        displayed.pending_entries.extend_from_slice(entries);
    }

    /// Acknowledge newly appended displayed entries immediately when visible and unquarantined, or
    /// retain them in `displayed_history` so `mark_read` / quarantine clearance reconciles them.
    async fn acknowledge_appended_displayed(
        &self,
        inner: &mut Inner<impl VaultStore>,
        peer: &PublicKey,
        entries: &[DisplayedEntry],
    ) {
        if self.ui.open.get_untracked() != Some(*peer) || entries.is_empty() {
            return;
        }
        let can_ack_now = is_page_visible()
            && inner
                .contacts
                .iter()
                .find(|c| c.peer == *peer)
                .is_some_and(|c| !c.state.quarantined);
        if can_ack_now {
            if inner
                .contact(peer)
                .is_some_and(|contact| contact.acknowledge_entries(entries))
                && let Err(e) = inner.save_state().await
            {
                self.ui.notify(describe(&e));
            }
        } else {
            self.record_displayed_entries(peer, entries);
        }
    }

    /// Acknowledge only the entries currently tracked as displayed on screen for `peer`, returning
    /// `true` if unread count, `acked_ranges`, or pending read receipts changed.
    fn acknowledge_displayed_window(
        &self,
        inner: &mut Inner<impl VaultStore>,
        peer: &PublicKey,
    ) -> bool {
        if self.ui.open.get_untracked() != Some(*peer) || !is_page_visible() {
            return false;
        }
        let Some(contact) = inner.contact(peer) else {
            return false;
        };
        if contact.state.quarantined {
            return false;
        }
        let mut slot = self.displayed_history.borrow_mut();
        let Some(displayed) = slot.as_mut().filter(|d| d.peer == *peer) else {
            return false;
        };
        let entries = std::mem::take(&mut displayed.pending_entries);
        contact.acknowledge_entries(&entries)
    }

    /// Show the chat with `peer`, or the chat list.
    pub async fn open(&self, peer: Option<PublicKey>) -> OpenOutcome {
        let Some(peer) = peer else {
            self.close_chat();
            return OpenOutcome::Opened;
        };
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return OpenOutcome::Ignored;
        }
        let mut tracker = self.open_tracker.get();
        let generation = tracker.begin_open(peer);
        self.open_tracker.set(tracker);
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return OpenOutcome::Ignored;
        }
        let current = self.open_tracker.get();
        if current.was_deleted(generation) {
            return OpenOutcome::Ignored;
        }
        if !current.is_current(generation) {
            return OpenOutcome::Superseded;
        }
        let Some(inner) = guard.as_mut() else {
            return OpenOutcome::Ignored;
        };
        // Self-peer guard: never open a chat with one's own identity key.
        if peer == inner.client.identity_key() {
            return OpenOutcome::Ignored;
        }
        let loaded = match self.load_history(inner, &peer).await {
            LoadedHistory::Missing => return OpenOutcome::Ignored,
            LoadedHistory::Loaded(page) => Some(page),
            LoadedHistory::Failed(e) => {
                if !self.is_live(vgen) {
                    return OpenOutcome::Ignored;
                }
                self.ui.notify(e);
                None
            }
        };
        if !self.is_live(vgen) {
            return OpenOutcome::Ignored;
        }
        let current = self.open_tracker.get();
        if current.was_deleted(generation) {
            return OpenOutcome::Ignored;
        }
        if !current.is_current(generation) {
            return OpenOutcome::Superseded;
        }
        if inner.contact(&peer).is_none() {
            return OpenOutcome::Ignored;
        }
        let (messages, has_older) = match loaded {
            Some(page) => {
                let has_older = page.loaded_start > 0;
                *self.displayed_history.borrow_mut() = Some(DisplayedHistory {
                    peer,
                    history_loaded: true,
                    loaded_start: page.loaded_start,
                    pending_entries: page.entries,
                });
                (page.messages, has_older)
            }
            None => {
                *self.displayed_history.borrow_mut() = Some(DisplayedHistory {
                    peer,
                    history_loaded: false,
                    loaded_start: 0,
                    pending_entries: Vec::new(),
                });
                (vec![], false)
            }
        };
        self.ui.has_older_messages.set(has_older);
        self.set_displayed_messages(peer, messages, true);
        // Do not mark quarantined messages as read, or acknowledge messages if history failed to
        // load or the tab became hidden before display (`visibilitychange` calls `mark_read` on return).
        let read = self.acknowledge_displayed_window(inner, &peer);
        if read && let Err(e) = inner.save_state().await {
            if !self.is_live(vgen) {
                return OpenOutcome::Ignored;
            }
            self.ui.notify(describe(&e));
        }
        if !self.is_live(vgen) {
            return OpenOutcome::Ignored;
        }
        self.ui.contacts.set(inner.views());
        drop(guard);
        // The peer learns what was read.
        if read
            && let Err(e) = self.flush(&peer).await
            && self.is_live(vgen)
        {
            self.ui.link.set(Link::Offline(e));
        }
        if !self.is_live(vgen) {
            return OpenOutcome::Ignored;
        }
        let current = self.open_tracker.get();
        if current.was_deleted(generation) {
            OpenOutcome::Ignored
        } else if !current.is_current(generation) {
            OpenOutcome::Superseded
        } else {
            OpenOutcome::Opened
        }
    }

    /// Load up to `limit` entries immediately before `before` for `peer`, ordered for display,
    /// without touching `ui.messages`.
    async fn load_history_window(
        &self,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        before: u64,
        limit: u64,
    ) -> LoadedHistory {
        if inner.contacts.iter().all(|contact| contact.peer != *peer) {
            return LoadedHistory::Missing;
        }
        let loaded_start = before.saturating_sub(limit);
        let history = inner.vault.history(peer, before, limit).await;
        let Some(contact) = inner.contact(peer) else {
            return LoadedHistory::Missing;
        };
        match history {
            Ok(history) => {
                let mut entries = Vec::with_capacity(history.len());
                let mut messages = Vec::with_capacity(history.len());
                for (index, entry) in history {
                    let (counts_unread, clock) = handshake::entry_read_tracking(&entry);
                    entries.push(DisplayedEntry {
                        index,
                        counts_unread,
                        clock,
                    });
                    messages.push(contact.message(index, entry));
                }
                order(&mut messages, &inner.client.identity_key(), peer);
                LoadedHistory::Loaded(LoadedHistoryPage {
                    messages,
                    loaded_start,
                    entries,
                })
            }
            Err(e) => LoadedHistory::Failed(describe(&e)),
        }
    }

    /// Load the last [`HISTORY_SHOWN`] entries of the history of the chat with `peer`, ordered for
    /// display, without touching `ui.messages`.
    async fn load_history(&self, inner: &mut Inner<V>, peer: &PublicKey) -> LoadedHistory {
        let Some(history_len) = inner
            .contacts
            .iter()
            .find(|contact| contact.peer == *peer)
            .map(|contact| contact.state.history_len)
        else {
            return LoadedHistory::Missing;
        };
        self.load_history_window(inner, peer, history_len, HISTORY_SHOWN)
            .await
    }

    /// Refresh the history of the chat with `peer` if it is still the open chat when the read
    /// completes, preserving any earlier pages the user already loaded (`loaded_start`) instead of
    /// collapsing back to the tail [`HISTORY_SHOWN`] window. Returns `true` only when history
    /// loaded successfully and was applied to the still-open chat.
    async fn show_history(&self, inner: &mut Inner<V>, peer: &PublicKey) -> bool {
        let Some(history_len) = inner
            .contacts
            .iter()
            .find(|contact| contact.peer == *peer)
            .map(|contact| contact.state.history_len)
        else {
            return false;
        };
        let existing_start = self
            .displayed_history
            .borrow()
            .as_ref()
            .filter(|d| d.peer == *peer && d.history_loaded)
            .map(|d| d.loaded_start);
        let limit = match existing_start {
            Some(start) => history_len.saturating_sub(start).max(HISTORY_SHOWN),
            None => HISTORY_SHOWN,
        };
        let vgen = self.vault_gen();
        match self
            .load_history_window(inner, peer, history_len, limit)
            .await
        {
            LoadedHistory::Loaded(page)
                if self.is_live(vgen) && self.ui.open.get_untracked() == Some(*peer) =>
            {
                let has_older = page.loaded_start > 0;
                *self.displayed_history.borrow_mut() = Some(DisplayedHistory {
                    peer: *peer,
                    history_loaded: true,
                    loaded_start: page.loaded_start,
                    pending_entries: page.entries,
                });
                self.ui.has_older_messages.set(has_older);
                self.set_displayed_messages(*peer, page.messages, false);
                true
            }
            LoadedHistory::Failed(e) if self.is_live(vgen) => {
                self.ui.notify(e);
                false
            }
            LoadedHistory::Failed(_) | LoadedHistory::Missing | LoadedHistory::Loaded(_) => false,
        }
    }

    /// Load the preceding page of up to [`HISTORY_SHOWN`] older messages for the currently open
    /// chat so unread messages before the tail page are reachable and acknowledged once displayed.
    /// Returns `Ok(true)` when at least one older row was prepended to `ui.messages`.
    pub async fn load_earlier(&self, peer: PublicKey) -> Result<bool, String> {
        let vgen = self.vault_gen();
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) || self.ui.open.get_untracked() != Some(peer) {
            return Ok(false);
        }
        let Some(inner) = guard.as_mut() else {
            return Err("locked".into());
        };
        let before = match self
            .displayed_history
            .borrow()
            .as_ref()
            .filter(|d| d.peer == peer && d.history_loaded)
        {
            Some(d) if d.loaded_start > 0 => d.loaded_start,
            _ => {
                self.ui.has_older_messages.set(false);
                return Ok(false);
            }
        };
        let page = match self
            .load_history_window(inner, &peer, before, HISTORY_SHOWN)
            .await
        {
            LoadedHistory::Loaded(page) => page,
            LoadedHistory::Missing => return Ok(false),
            LoadedHistory::Failed(e) => return Err(e),
        };
        if !self.is_live(vgen) || self.ui.open.get_untracked() != Some(peer) {
            return Ok(false);
        }
        let still_at_boundary = self
            .displayed_history
            .borrow()
            .as_ref()
            .is_some_and(|d| d.peer == peer && d.history_loaded && d.loaded_start == before);
        if !still_at_boundary {
            return Ok(false);
        }
        let has_older = page.loaded_start > 0;
        let me = inner.client.identity_key();
        let added_rows: Vec<MessageRow> = {
            let mut displayed = self.displayed_rows.borrow_mut();
            if displayed.peer != Some(peer) {
                displayed.peer = Some(peer);
                let old = std::mem::take(&mut displayed.rows);
                for signals in old.into_values() {
                    signals.dispose();
                }
            }
            page.messages
                .into_iter()
                .filter_map(|view| {
                    if displayed.rows.contains_key(&view.index) {
                        None
                    } else {
                        let row = MessageRow::from_view(view);
                        displayed.rows.insert(row.index, RowSignals::from_row(&row));
                        Some(row)
                    }
                })
                .collect()
        };
        let prepended = !added_rows.is_empty();
        if prepended {
            self.ui.messages.update(|messages| {
                messages.extend(added_rows);
                order_rows(messages, &me, &peer);
            });
        }
        if let Some(displayed) = self
            .displayed_history
            .borrow_mut()
            .as_mut()
            .filter(|d| d.peer == peer)
        {
            displayed.loaded_start = page.loaded_start;
            displayed.pending_entries.extend(page.entries);
        }
        self.ui.has_older_messages.set(has_older);
        let read = self.acknowledge_displayed_window(inner, &peer);
        if read && let Err(e) = inner.save_state().await {
            if !self.is_live(vgen) {
                return Ok(false);
            }
            self.ui.notify(describe(&e));
        }
        if !self.is_live(vgen) {
            return Ok(false);
        }
        self.ui.contacts.set(inner.views());
        drop(guard);
        // Schedule receipt delivery asynchronously via the sync loop so local history paging never
        // blocks on a slow or stalled relay.
        if read && self.is_live(vgen) {
            self.wake();
        }
        Ok(prepended)
    }

    /// Reload the currently open chat's history when needed (e.g. after a prior history-load
    /// failure, `saved_late` / staged `unsaved` entries, or `force_reload`), then acknowledge
    /// whatever entries are displayed on a visible, non-quarantined screen and persist state.
    /// Returns `true` if unread/receipt state changed.
    async fn reconcile_open_chat_read(
        &self,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        force_reload: bool,
    ) -> bool {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) || self.ui.open.get_untracked() != Some(*peer) {
            return false;
        }
        if !force_reload && !is_page_visible() {
            return false;
        }
        let needs_reload = force_reload
            || !self.is_history_loaded_for(*peer)
            || inner.saved_late.contains(peer)
            || inner.unsaved.iter().any(|(p, _, _)| p == peer);
        if needs_reload {
            if self.show_history(inner, peer).await {
                inner.saved_late.retain(|saved| saved != peer);
            } else if force_reload
                && self.is_live(vgen)
                && self.ui.open.get_untracked() == Some(*peer)
                && inner.contact(peer).is_some()
            {
                inner.saved_late.push(*peer);
                return false;
            }
        }
        if !self.is_live(vgen) || self.ui.open.get_untracked() != Some(*peer) || !is_page_visible()
        {
            return false;
        }
        if !self.acknowledge_displayed_window(inner, peer) {
            return false;
        }
        if let Err(e) = inner.save_state().await
            && self.is_live(vgen)
        {
            self.ui.notify(describe(&e));
        }
        self.is_live(vgen)
    }

    /// Count the displayed messages of the chat with `peer` as read, e.g. back on the page with
    /// the chat open: if full history is not yet displayed (e.g. after a history-load failure or
    /// pending `saved_late` / staged `unsaved` entries), reload history first and acknowledge only
    /// what is actually displayed.
    pub async fn mark_read(&self, peer: PublicKey) {
        let vgen = self.vault_gen();
        let mut guard = self.lock_inner().await;
        // Re-check after acquiring the mutex: `close_chat` or `pagehide` can clear `ui.open` (or
        // the tab can hide again) while a prior `receive` held `inner`.
        if !self.is_live(vgen) || self.ui.open.get_untracked() != Some(peer) || !is_page_visible() {
            return;
        }
        let Some(inner) = guard.as_mut() else {
            return;
        };
        if !self.reconcile_open_chat_read(inner, &peer, false).await || !self.is_live(vgen) {
            return;
        }
        self.ui.contacts.set(inner.views());
        drop(guard);
        if let Err(e) = self.flush(&peer).await
            && self.is_live(vgen)
        {
            self.ui.link.set(Link::Offline(e));
        }
    }

    /// Accept the request of `peer`, naming the peer `name`, registering the peer's write token
    /// grant, replaying any buffered envelopes, and sending `Events { accepted: true }` to wake
    /// the peer immediately. Refuses while the contact is quarantined pending explicit classical
    /// approval or post-quantum upgrade.
    pub async fn accept(&self, peer: PublicKey, name: String) -> Result<(), String> {
        let vgen = self.vault_gen();
        {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            inner
                .with_contact_tx(&peer, async |inner| {
                    let token_hash = {
                        let contact = inner
                            .contact(&peer)
                            .ok_or_else(|| "no such chat".to_string())?;
                        contact.accept_request(&name)?;
                        contact.state.events.get_or_insert_default().accepted = true;
                        contact.session.active_inbound_token_hash()
                    };
                    if let Some(token_hash) = token_hash {
                        inner.stage_write_token_grant(&peer, token_hash, true)?;
                    }
                    inner.save(&[]).await.map_err(|e| describe(&e))
                })
                .await?;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            self.ui.contacts.set(inner.views());
        }
        // Register write token outside `self.inner` BEFORE pushing `Events { accepted: true }` so
        // the peer's follow-up messages are immediately accepted on our DO without stalling UI.
        let _ = self.flush_pending_grants_for_peer(&peer).await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            if let Some(inner) = guard.as_mut() {
                let _ = self.replay_deferred_envelopes(inner, Some(&peer)).await;
                if !self.is_live(vgen) {
                    return Err("locked".into());
                }
                self.ui.contacts.set(inner.views());
            }
        }
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        // Wake the peer immediately with `Events { accepted: true }` + any read receipts.
        let _ = self.flush(&peer).await;
        if self.is_live(vgen) {
            self.wake();
        }
        Ok(())
    }

    pub async fn rename(&self, peer: PublicKey, name: String) -> Result<(), String> {
        self.change_contact(peer, |contact| contact.state.name = name.trim().to_string())
            .await
    }

    async fn change_contact(
        &self,
        peer: PublicKey,
        change: impl FnOnce(&mut Contact),
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let inner = guard.as_mut().ok_or("locked")?;
        inner
            .with_contact_tx(&peer, async |inner| {
                let contact = inner
                    .contact(&peer)
                    .ok_or_else(|| "no such chat".to_string())?;
                change(contact);
                inner.save(&[]).await.map_err(|e| describe(&e))
            })
            .await?;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        self.ui.contacts.set(inner.views());
        Ok(())
    }

    /// Purge in-flight queued sends and viewer attachment opening state for a deleted `peer`.
    pub(super) fn purge_peer_transient_state(&self, peer: &PublicKey) {
        self.sending
            .borrow_mut()
            .retain(|item| item.peer() != *peer);
        if self
            .ui
            .opening
            .with_untracked(|opening| opening.as_ref().is_some_and(|o| o.peer == *peer))
        {
            self.ui.opening.set(None);
        }
    }

    /// Delete the chat with `peer` and its history. The server knows nothing of it: what it keeps
    /// of the chat goes as it is delivered, or expires; but for its uploads that went up and
    /// have not finished, which it deletes, as they never can now.
    pub async fn delete(&self, peer: PublicKey) -> Result<(), String> {
        self.delete_inner(peer, false).await
    }

    async fn delete_inner(&self, peer: PublicKey, require_isolated: bool) -> Result<(), String> {
        let vgen = self.vault_gen();
        if !crate::glue::owns_lock() || !self.is_live(vgen) {
            return Err("page is closing; tab lock released".into());
        }
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let inner = guard.as_mut().ok_or("locked")?;
        if require_isolated && !inner.is_isolated_peer(&peer) {
            return Err("That contact is no longer isolated.".to_string());
        }
        // Read before anything changes, as the vault forgets them with the chat: cancel any
        // started upload that is still shown, running, or unannounced (leaving already-finished
        // uploads whose vault cleanup raced deletion intact), and mark every vaulted upload ID
        // cancelled so racing tasks cannot resurrect ghost entries.
        let shown: HashSet<Vec<u8>> = self.ui.uploads.with_untracked(|uploads| {
            uploads
                .iter()
                .filter(|upload| upload.peer == peer)
                .map(|upload| upload.id.to_vec())
                .collect()
        });
        let running: HashSet<[u8; 16]> = self.running.borrow().clone();
        let vault_uploads = inner
            .vault
            .uploads(Some(&peer))
            .await
            .map_err(|e| describe(&e))?;
        let mut upload_ids: HashSet<[u8; 16]> = vault_uploads
            .iter()
            .filter_map(|(_, pending)| <[u8; 16]>::try_from(pending.id.as_slice()).ok())
            .collect();
        let unfinished: Vec<(String, Upload)> = vault_uploads
            .into_iter()
            .filter(|(_, pending)| {
                let id_running = <[u8; 16]>::try_from(pending.id.as_slice())
                    .is_ok_and(|id| running.contains(&id));
                pending.started()
                    && (shown.contains(&pending.id) || id_running || !pending.is_announced())
            })
            .filter_map(|(_, pending)| Some((pending.name.clone(), upload_of(&pending).ok()?)))
            .collect();
        // The peer is told, on the session as it is now, so that its next message starts a new
        // one, which comes here as a new chat; see `say_farewells`. If forgetting fails, the
        // session goes back to this, as the farewell never goes.
        let snapshot = inner.contact(&peer).map(|contact| contact.snapshot());
        // Not for a request or quarantined chat, which a stranger may have sent: they learn
        // nothing of it. What was read and not told yet goes first, so that the peer sends again
        // only what was not.
        let mut farewell = vec![];
        if let Some(contact) = inner.contact(&peer)
            && !contact.state.request
            && !contact.state.quarantined
        {
            let mode = contact.farewell_mode();
            if mode != FarewellMode::Normal {
                // Restore any durable fallback farewells from a previously established session (e.g.
                // before an unconfirmed PQ upgrade or recreating a previously deleted chat) so the
                // peer still learns of deletion even when the replacement greeting was unsent or
                // uncertain.
                farewell.extend(contact.state.fallback_farewells.clone());
            }
            if mode != FarewellMode::Suppress {
                contact.state.clock = contact.state.clock.saturating_add(1);
                let clock = contact.state.clock;
                let sealed_events = contact.state.sealed_events.take();
                let events = contact.state.events.take();
                farewell.extend(encrypt_session_farewells(
                    &mut contact.session,
                    clock,
                    sealed_events,
                    events,
                    mode,
                ));
            }
        }
        // Stage a durable write-token revocation before snapshotting `AppState` so `client.next_grant_version`
        // persists above `min_grant_version` and any recreated chat gets a strictly higher grant version.
        let peer_slot_id = inner.client.peer_slot_id(&peer);
        let min_grant_version = inner
            .client
            .allocate_grant_version()
            .map_err(|e| describe(&e))?;
        let mut state = inner.app_state();
        if let Some(existing) = state
            .pending_revokes
            .iter_mut()
            .find(|r| r.peer_slot_id.as_slice() == peer_slot_id.as_slice())
        {
            existing.min_grant_version = existing.min_grant_version.max(min_grant_version);
        } else {
            state.pending_revokes.push(PendingRevoke {
                peer_slot_id: peer_slot_id.to_vec(),
                min_grant_version,
            });
        }
        if let Some(contact) = inner.contact(&peer) {
            state.next_session_seq = state
                .next_session_seq
                .max(contact.session.next_session_seq());
        }
        state.contacts.retain(|contact| contact.peer != peer);
        state.farewells.extend(farewell);
        let deferred = inner.deferred_record_without_peer(&peer);
        let was_isolated = inner.is_isolated_peer(&peer);
        if let Err(e) = inner.forget_peer(&peer, state, deferred).await {
            if let Some(snapshot) = snapshot {
                inner.roll_back(&peer, snapshot)?;
            }
            return Err(describe(&e));
        }
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        self.clear_approval_backoff(&peer);
        self.prune_peer_flush_lock(&peer);
        // Its uploads stop, as cancelled, and keep nothing more: the vault forgot them with the
        // chat, which `may_keep` now tells them is gone.
        upload_ids.extend(self.ui.uploads.with_untracked(|uploads| {
            uploads
                .iter()
                .filter(|upload| upload.peer == peer)
                .map(|upload| upload.id)
                .collect::<Vec<_>>()
        }));
        for id in upload_ids {
            self.cancelled.borrow_mut().insert(id);
            self.remove_attachment_caches(&peer, &id);
        }
        self.purge_peer_transient_state(&peer);
        self.files.borrow_mut().retain(|(p, _, _), _| *p != peer);
        self.decrypted
            .borrow_mut()
            .retain(|((p, _, _, _), _)| *p != peer);
        self.streams
            .borrow_mut()
            .retain(|_, stream| stream.fetching.peer != peer);
        if self
            .ui
            .streaming
            .with_untracked(|streamed| streamed.as_ref().is_some_and(|s| s.remote.peer == peer))
        {
            self.ui.streaming.set(None);
        }
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.peer != peer));
        self.ui.held.update(|held| held.retain(|(p, _)| *p != peer));
        self.ui.gone.update(|gone| gone.retain(|(p, _)| *p != peer));
        // Nor does what waited for a sign-in, which would otherwise hold up a chat started
        // again with the peer, or go to it.
        self.waits_sign_in.borrow_mut().remove(&peer);
        self.wake();
        // Only invalidate a queued open targeting the deleted peer; preserve queued navigation to
        // a different peer started while the vault deletion was committing.
        let mut tracker = self.open_tracker.get();
        tracker.invalidate_peer(peer);
        self.open_tracker.set(tracker);
        if self
            .displayed_history
            .borrow()
            .as_ref()
            .is_some_and(|d| d.peer == peer)
        {
            *self.displayed_history.borrow_mut() = None;
        }
        if self.ui.open.get_untracked() == Some(peer) {
            self.ui.has_older_messages.set(false);
            self.ui.open.set(None);
            self.clear_displayed_messages();
        }
        let seq = self.deleted_peer_seq.get().wrapping_add(1).max(1);
        self.deleted_peer_seq.set(seq);
        self.ui.deleted_peer.set(Some((seq, peer)));
        self.ui.contacts.set(inner.views());
        self.ui.isolated_contacts.set(inner.isolated_views());
        if was_isolated {
            self.ui.log(format!(
                "deleted isolated corrupt contact record for {}",
                short(&peer)
            ));
        }
        // What the server has of the uploads that never can finish now goes, so that the peer
        // does not wait for the rest; with their upload tokens, which name nobody.
        let server = inner.server.clone();
        drop(guard);
        if !unfinished.is_empty() {
            let (ui, attachments) = (self.ui, Fetch::client(&server));
            #[cfg(target_arch = "wasm32")]
            spawn_local(async move {
                for (name, upload) in unfinished {
                    if let Err(e) = upload.cancel(&attachments).await {
                        ui.log(format!(
                            "the server keeps what it has of {name} until it expires: {}",
                            describe(&e)
                        ));
                    }
                }
            });
            #[cfg(not(target_arch = "wasm32"))]
            for (name, upload) in unfinished {
                if let Err(e) = upload.cancel(&attachments).await {
                    ui.log(format!(
                        "the server keeps what it has of {name} until it expires: {}",
                        describe(&e)
                    ));
                }
            }
        }
        Ok(())
    }

    /// Permanently delete an isolated corrupt contact record (and any local history/outbox under
    /// that peer key) after explicit user confirmation. Refuses to delete an active healthy chat.
    pub async fn delete_isolated(&self, raw_peer: Vec<u8>) -> Result<(), String> {
        if let Ok(peer) = PublicKey::try_from(raw_peer.as_slice()) {
            return self.delete_inner(peer, true).await;
        }
        let vgen = self.vault_gen();
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let inner = guard.as_mut().ok_or("locked")?;
        if !inner.delete_isolated_raw(&raw_peer).await? {
            return Err("That isolated contact record was already removed.".to_string());
        }
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        self.ui.isolated_contacts.set(inner.isolated_views());
        self.ui
            .log("deleted isolated contact record with a malformed identity key");
        Ok(())
    }

    /// Go by `name` in the greetings of new chats.
    pub async fn set_name(&self, name: String) -> Result<(), String> {
        let name = checked_name(&name)?;
        let vgen = self.vault_gen();
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let inner = guard.as_mut().ok_or("locked")?;
        let prev_name = std::mem::replace(&mut inner.state.name, name);
        if let Err(e) = inner.save(&[]).await {
            inner.state.name = prev_name;
            return Err(describe(&e));
        }
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        self.ui.me.set(Some(inner.me()));
        Ok(())
    }
}

/// All vault persistence operations used by [`Engine`] and [`Inner`], using typed
/// `(PublicKey, u64, ...)` record keys so underlying storage schemes (v2 string keys, v3 opaque
/// HMAC keys, or native `MemoryVault`) require zero engine signature changes.
pub(crate) trait VaultStore: 'static {
    async fn entry(
        &self,
        peer: &PublicKey,
        index: u64,
    ) -> crate::vault::Result<Option<HistoryEntry>>;
    async fn content(
        &self,
        peer: &PublicKey,
        index: u64,
        entry: &HistoryEntry,
    ) -> crate::vault::Result<Option<Kind>>;
    async fn save<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredRecord,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()>;
    async fn history(
        &self,
        peer: &PublicKey,
        history_len: u64,
        limit: u64,
    ) -> crate::vault::Result<Vec<(u64, HistoryEntry)>>;
    async fn file(&self, peer: &PublicKey, index: u64) -> crate::vault::Result<Vec<u8>>;
    async fn outgoing(&self, peer: &PublicKey, index: u64) -> crate::vault::Result<OutgoingRecord>;
    async fn put_chunk(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
        chunk: &[u8],
    ) -> crate::vault::Result<()>;
    async fn chunk(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
    ) -> crate::vault::Result<Option<Vec<u8>>>;
    async fn chunks_kept(&self, peer: &PublicKey, id: &[u8]) -> crate::vault::Result<u32>;
    async fn save_upload(
        &self,
        peer: &PublicKey,
        upload: &PendingUpload,
    ) -> crate::vault::Result<()>;
    #[allow(clippy::too_many_arguments)]
    async fn promote_upload<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredRecord,
        peer: &PublicKey,
        old_id: &[u8],
        new_upload: &PendingUpload,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()>;
    async fn forget_upload(&self, peer: &PublicKey, id: &[u8]) -> crate::vault::Result<()>;
    async fn upload(
        &self,
        peer: &PublicKey,
        id: &[u8],
    ) -> crate::vault::Result<Option<PendingUpload>>;
    async fn uploads(
        &self,
        peer: Option<&PublicKey>,
    ) -> crate::vault::Result<Vec<(PublicKey, PendingUpload)>>;
    async fn forget<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredRecord,
        peer: &PublicKey,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()>;
}

impl VaultStore for Vault {
    async fn entry(
        &self,
        peer: &PublicKey,
        index: u64,
    ) -> crate::vault::Result<Option<HistoryEntry>> {
        Vault::entry(self, peer, index).await
    }
    async fn content(
        &self,
        peer: &PublicKey,
        index: u64,
        entry: &HistoryEntry,
    ) -> crate::vault::Result<Option<Kind>> {
        Vault::content(self, peer, index, entry).await
    }
    async fn save<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredRecord,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()> {
        Vault::save(self, state, deferred, entries, outgoing).await
    }
    async fn history(
        &self,
        peer: &PublicKey,
        history_len: u64,
        limit: u64,
    ) -> crate::vault::Result<Vec<(u64, HistoryEntry)>> {
        Vault::history(self, peer, history_len, limit).await
    }
    async fn file(&self, peer: &PublicKey, index: u64) -> crate::vault::Result<Vec<u8>> {
        Vault::file(self, peer, index).await
    }
    async fn outgoing(&self, peer: &PublicKey, index: u64) -> crate::vault::Result<OutgoingRecord> {
        Vault::outgoing(self, peer, index).await
    }
    async fn put_chunk(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
        chunk: &[u8],
    ) -> crate::vault::Result<()> {
        Vault::put_chunk(self, peer, id, index, chunk).await
    }
    async fn chunk(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
    ) -> crate::vault::Result<Option<Vec<u8>>> {
        Vault::chunk(self, peer, id, index).await
    }
    async fn chunks_kept(&self, peer: &PublicKey, id: &[u8]) -> crate::vault::Result<u32> {
        Vault::chunks_kept(self, peer, id).await
    }
    async fn save_upload(
        &self,
        peer: &PublicKey,
        upload: &PendingUpload,
    ) -> crate::vault::Result<()> {
        Vault::save_upload(self, peer, upload).await
    }
    #[allow(clippy::too_many_arguments)]
    async fn promote_upload<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredRecord,
        peer: &PublicKey,
        old_id: &[u8],
        new_upload: &PendingUpload,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()> {
        Vault::promote_upload(
            self, state, deferred, peer, old_id, new_upload, entries, outgoing,
        )
        .await
    }
    async fn forget_upload(&self, peer: &PublicKey, id: &[u8]) -> crate::vault::Result<()> {
        Vault::forget_upload(self, peer, id).await
    }
    async fn upload(
        &self,
        peer: &PublicKey,
        id: &[u8],
    ) -> crate::vault::Result<Option<PendingUpload>> {
        Vault::upload(self, peer, id).await
    }
    async fn uploads(
        &self,
        peer: Option<&PublicKey>,
    ) -> crate::vault::Result<Vec<(PublicKey, PendingUpload)>> {
        Vault::uploads(self, peer).await
    }
    async fn forget<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredRecord,
        peer: &PublicKey,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()> {
        Vault::forget(self, state, deferred, peer, entries, outgoing).await
    }
}

impl<V: VaultStore> Inner<V> {
    /// Atomically promote a waiting sign-in upload (`old_id`) into a server-started `new_upload`
    /// together with the updated state, deferred record, history entries, and outbox records in
    /// one vault transaction.
    pub(super) async fn promote_upload_with(
        &mut self,
        peer: &PublicKey,
        old_id: &[u8],
        new_upload: &PendingUpload,
        entries: &[(PublicKey, u64, HistoryEntry)],
        outgoing: &[(PublicKey, u64, Option<OutgoingRecord>)],
    ) -> crate::vault::Result<()> {
        let state = self.app_state();
        let deferred = self.deferred_record();
        if !crate::glue::owns_lock() || crate::glue::lock_generation() != self.lock_generation {
            return Err(crate::vault::Error::Storage(
                "page is closing; tab lock released".into(),
            ));
        }
        self.vault
            .promote_upload(
                &state,
                &deferred,
                peer,
                old_id,
                new_upload,
                self.unsaved.iter().chain(entries),
                self.unsaved_outbox.iter().chain(outgoing),
            )
            .await?;
        self.finish_state_save(state.pending_inbox_acks);
        self.saved_late
            .extend(self.unsaved.drain(..).map(|(peer, _, _)| peer));
        self.unsaved_outbox.clear();
        Ok(())
    }

    /// Persist deletion of `peer` (and any pending records of other chats) via `VaultStore::forget`
    /// and update all in-memory peer/state tracking atomically on success.
    pub(super) async fn forget_peer(
        &mut self,
        peer: &PublicKey,
        state: AppState,
        deferred: DeferredRecord,
    ) -> crate::vault::Result<()> {
        if !crate::glue::owns_lock() || crate::glue::lock_generation() != self.lock_generation {
            return Err(crate::vault::Error::Storage(
                "page is closing; tab lock released".into(),
            ));
        }
        let unsaved = self
            .unsaved
            .iter()
            .filter(|(unsaved, _, _)| unsaved != peer);
        let unsaved_outbox = self
            .unsaved_outbox
            .iter()
            .filter(|(unsaved, _, _)| unsaved != peer);
        self.vault
            .forget(&state, &deferred, peer, unsaved, unsaved_outbox)
            .await?;
        self.state.next_session_seq = state.next_session_seq;
        self.state.farewells = state.farewells;
        self.state.pending_revokes = state.pending_revokes;
        self.contacts.retain(|contact| contact.peer != *peer);
        self.forget_isolated_peer(peer);
        self.pending_pq_contact_flags.remove(peer);
        self.deferred_initials = deferred.entries;
        self.carried_deferred_timestamps = deferred.carried_timestamps;
        self.deferred_envelopes = deferred.envelopes;
        self.finish_state_save(state.pending_inbox_acks);
        self.saved_late.extend(
            self.unsaved
                .drain(..)
                .map(|(unsaved, _, _)| unsaved)
                .filter(|unsaved| unsaved != peer),
        );
        self.unsaved_outbox.clear();
        Ok(())
    }

    /// Locate a history entry carrying attachment `id` (checking `hint_index` first, then scanning
    /// history backwards in `HISTORY_SHOWN` pages).
    pub(super) async fn find_attachment_entry(
        &self,
        peer: &PublicKey,
        hint_index: Option<u64>,
        id: &[u8],
    ) -> crate::vault::Result<Option<(u64, HistoryEntry)>> {
        let matches_id = |entry: &HistoryEntry| {
            matches!(
                entry.content.as_ref().and_then(|content| content.kind.as_ref()),
                Some(Kind::Attachment(pointer)) if pointer.id == id
            )
        };
        if let Some(index) = hint_index
            && let Some(entry) = self.vault.entry(peer, index).await?.filter(matches_id)
        {
            return Ok(Some((index, entry)));
        }
        let mut end = self
            .contacts
            .iter()
            .find(|contact| contact.peer == *peer)
            .map_or(0, |contact| contact.state.history_len);
        while end > 0 {
            let page = self.vault.history(peer, end, HISTORY_SHOWN).await?;
            if let Some(found) = page.into_iter().rev().find(|(_, entry)| matches_id(entry)) {
                return Ok(Some(found));
            }
            end = end.saturating_sub(HISTORY_SHOWN);
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        vault: V,
        server: String,
        audience: String,
        state: AppState,
        client: Client<Connect>,
        contacts: Vec<Contact>,
        mut isolated_contacts: Vec<ContactState>,
        deferred: DeferredRecord,
    ) -> Self {
        let active_peers: HashSet<_> = contacts.iter().map(|c| c.peer).collect();
        isolated_contacts.retain(|c| {
            PublicKey::try_from(c.peer.as_slice())
                .map_or(true, |peer| !active_peers.contains(&peer))
        });
        let isolated_peers: HashSet<_> = isolated_contacts
            .iter()
            .filter_map(|c| PublicKey::try_from(c.peer.as_slice()).ok())
            .collect();
        Self {
            vault,
            lock_generation: crate::glue::lock_generation(),
            server,
            audience,
            state,
            deferred_initials: deferred.entries,
            carried_deferred_timestamps: deferred.carried_timestamps,
            deferred_envelopes: deferred.envelopes,
            client,
            contacts,
            isolated_contacts,
            isolated_peers,
            pending_pq_contact_flags: HashMap::new(),
            server_pq: ServerPqStatus::Unknown,
            last_server_classical_opks: None,
            last_server_pq_opks: None,
            unsaved_state: false,
            deferred_acks_after_save: vec![],
            contacts_dirty_late: false,
            unsaved: vec![],
            unsaved_outbox: vec![],
            saved_late: vec![],
        }
    }

    /// Stage a durable `RegisterWriteToken` grant on `peer`'s session using the next monotonic
    /// identity-wide `grant_version`.
    pub(super) fn stage_write_token_grant(
        &mut self,
        peer: &PublicKey,
        token_hash: [u8; 32],
        pin_active: bool,
    ) -> Result<(), String> {
        let grant_version = self
            .client
            .allocate_grant_version()
            .map_err(|e| describe(&e))?;
        if let Some(contact) = self.contact(peer) {
            contact
                .session
                .queue_pending_grant(PendingGrant {
                    token_hash,
                    grant_version,
                    pin_active,
                })
                .map_err(|e| describe(&e))?;
        }
        Ok(())
    }

    /// Monotonic outgoing `Hello.session_seq` for a newly initiated chat, strictly above any
    /// previously started/deleted chat and floored with the current Unix timestamp in ms so
    /// recreating a deleted chat never collides with a peer's retained `peer_session_seq`.
    pub(super) fn next_new_chat_session_seq(&self) -> u64 {
        let contact_max = self
            .contacts
            .iter()
            .map(|c| c.session.next_session_seq())
            .max()
            .unwrap_or(1);
        self.state
            .next_session_seq
            .max(contact_max)
            .max(crate::util::now().min(session::protocol::MAX_SAFE_INTEGER))
            .clamp(1, session::protocol::MAX_SAFE_INTEGER)
    }

    /// What the vault keeps in `STATE`.
    fn app_state(&self) -> AppState {
        let mut state = AppState {
            client: Some(self.client.state().into()),
            contacts: stored_contacts(&self.contacts, &self.isolated_contacts),
            ..self.state.clone()
        };
        for &id in &self.deferred_acks_after_save {
            handshake::stage_inbox_ack(&mut state.pending_inbox_acks, id);
        }
        state
    }

    fn deferred_record(&self) -> DeferredRecord {
        DeferredRecord {
            entries: self.deferred_initials.clone(),
            carried_timestamps: self.carried_deferred_timestamps.clone(),
            envelopes: self.deferred_envelopes.clone(),
        }
    }

    pub(super) fn deferred_record_without_peer(&self, peer: &PublicKey) -> DeferredRecord {
        let entries = self
            .deferred_initials
            .iter()
            .filter(|entry| {
                entry
                    .initial
                    .as_ref()
                    .is_none_or(|w| w.identity_key.as_ref() != peer.as_slice())
            })
            .cloned()
            .collect();
        let mut carried_timestamps = self.carried_deferred_timestamps.clone();
        handshake::prune_carried_timestamps_for_contacts(
            &mut carried_timestamps,
            self.contacts.iter().filter(|c| c.peer != *peer),
        );
        let envelopes = self
            .deferred_envelopes
            .iter()
            .filter(|env| env.peer.as_slice() != peer.as_slice())
            .cloned()
            .collect();
        DeferredRecord {
            entries,
            carried_timestamps,
            envelopes,
        }
    }

    fn finish_state_save(&mut self, committed_acks: Vec<u64>) {
        self.state.pending_inbox_acks = committed_acks;
        self.deferred_acks_after_save.clear();
        self.contacts_dirty_late |= std::mem::take(&mut self.unsaved_state);
    }

    fn local_pq_enabled(&self) -> bool {
        cfg!(any(feature = "ml-kem-1024", feature = "ml-kem-768"))
            && self.client.pq_config().pq_enabled
            && !self.client.pq_config().offered_suites().is_empty()
    }

    fn needs_save(&self) -> bool {
        self.unsaved_state
            || !self.deferred_acks_after_save.is_empty()
            || !self.unsaved.is_empty()
            || !self.unsaved_outbox.is_empty()
    }

    /// Save a state-only mutation that remains in memory even if storage is unavailable.
    async fn save_state(&mut self) -> crate::vault::Result<()> {
        let result = self.save(&[]).await;
        if result.is_err() {
            self.unsaved_state = true;
        }
        result
    }

    /// Save the state, and `entries` with it, and the records left [unsaved](Self::unsaved).
    async fn save(
        &mut self,
        entries: &[(PublicKey, u64, HistoryEntry)],
    ) -> crate::vault::Result<()> {
        self.save_with(entries, &[]).await
    }

    /// Save as [`save`](Self::save) does, and `outgoing`, the records of messages waiting to be
    /// pushed, or none for one that went.
    async fn save_with(
        &mut self,
        entries: &[(PublicKey, u64, HistoryEntry)],
        outgoing: &[(PublicKey, u64, Option<OutgoingRecord>)],
    ) -> crate::vault::Result<()> {
        let state = self.app_state();
        let deferred = self.deferred_record();
        if !crate::glue::owns_lock() || crate::glue::lock_generation() != self.lock_generation {
            return Err(crate::vault::Error::Storage(
                "page is closing; tab lock released".into(),
            ));
        }
        self.vault
            .save(
                &state,
                &deferred,
                self.unsaved.iter().chain(entries),
                self.unsaved_outbox.iter().chain(outgoing),
            )
            .await?;
        self.finish_state_save(state.pending_inbox_acks);
        self.saved_late
            .extend(self.unsaved.drain(..).map(|(peer, _, _)| peer));
        self.unsaved_outbox.clear();
        Ok(())
    }

    fn contact(&mut self, peer: &PublicKey) -> Option<&mut Contact> {
        self.contacts
            .iter_mut()
            .find(|contact| contact.peer == *peer)
    }

    pub(super) fn is_isolated_peer(&self, peer: &PublicKey) -> bool {
        self.isolated_peers.contains(peer)
    }

    /// Whether `peer` is isolated specifically because its saved session uses a known ML-KEM suite
    /// not compiled into this build (rather than structural corruption).
    pub(super) fn is_pq_incompatible_isolated_peer(&self, peer: &PublicKey) -> bool {
        let me = self.client.identity_key();
        self.is_isolated_peer(peer)
            && self
                .isolated_contacts
                .iter()
                .any(|c| c.peer == peer.as_slice() && contact::is_pq_incompatible_isolated(c, &me))
    }

    /// Whether any deferred inbox initial from `peer` is currently awaiting a capable build.
    pub(super) fn has_deferred_initial_for(&self, peer: &PublicKey) -> bool {
        self.deferred_initials.iter().any(|entry| {
            entry
                .initial
                .as_ref()
                .is_some_and(|w| w.identity_key.as_ref() == peer.as_slice())
        })
    }

    fn check_isolation(&self, peer: &PublicKey) -> Result<(), String> {
        if self.is_isolated_peer(peer) {
            return Err(format!(
                "The contact record for {} is isolated due to corruption. Recover or delete it before starting a new session.",
                crate::util::short(peer)
            ));
        }
        Ok(())
    }

    /// Release the key only after the vault has deleted the peer's records and history.
    fn forget_isolated_peer(&mut self, peer: &PublicKey) {
        self.isolated_contacts.retain(|c| c.peer != peer.as_slice());
        self.isolated_peers.remove(peer);
    }

    /// Remove and persist deletion of an isolated record with a non-32-byte malformed peer key.
    async fn delete_isolated_raw(&mut self, raw_peer: &[u8]) -> Result<bool, String> {
        let saved = self.isolated_contacts.clone();
        self.isolated_contacts.retain(|c| c.peer != raw_peer);
        if self.isolated_contacts.len() == saved.len() {
            return Ok(false);
        }
        if let Err(e) = self.save(&[]).await {
            self.isolated_contacts = saved;
            return Err(describe(&e));
        }
        Ok(true)
    }

    /// Summaries of genuinely isolated corrupt contact records for the UI.
    fn isolated_views(&self) -> Vec<IsolatedContactView> {
        isolated_contact_views(&self.isolated_contacts, &self.client.identity_key())
    }

    /// Snapshot `peer`'s session and contact state, execute `op`, and roll back to the snapshot on
    /// `Err` so failed mutations or storage commits never leave partial state in memory.
    pub(super) async fn with_contact_tx<T>(
        &mut self,
        peer: &PublicKey,
        op: impl AsyncFnOnce(&mut Self) -> Result<T, String>,
    ) -> Result<T, String> {
        let snapshot = self.contact(peer).map(|c| c.snapshot());
        match op(self).await {
            Ok(value) => Ok(value),
            Err(err) => {
                if let Some(snapshot) = snapshot {
                    self.roll_back(peer, snapshot)?;
                }
                Err(err)
            }
        }
    }

    /// Coordinate `GREETING_DELIVERY_{UNSENT,UNCERTAIN,CONFIRMED}` transitions around a network
    /// transmission for `peer`:
    /// - When `!already_uncertain` and `greeting_delivery == GREETING_DELIVERY_UNSENT`, persists
    ///   `GREETING_DELIVERY_UNCERTAIN` before transmitting (rolling back if that save fails).
    /// - On `Ok` with `confirm_on_ok`, marks greeting confirmed and saves state.
    /// - On a definitive server refusal (`e.is_server_refusal()`), reverts to
    ///   `GREETING_DELIVERY_UNSENT` and saves state so deleting the chat suppresses farewells.
    pub(super) async fn transmit_with_greeting_delivery<T>(
        &mut self,
        peer: &PublicKey,
        already_uncertain: bool,
        confirm_on_ok: bool,
        transmit: impl AsyncFnOnce(&mut Self) -> session::Result<T>,
    ) -> Result<session::Result<T>, String> {
        let promoted_from_unsent = !already_uncertain
            && self
                .contacts
                .iter()
                .any(|c| c.peer == *peer && c.state.greeting_delivery == GREETING_DELIVERY_UNSENT);
        if promoted_from_unsent {
            self.with_contact_tx(peer, async |inner| {
                if let Some(contact) = inner.contact(peer) {
                    contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
                }
                inner.save(&[]).await.map_err(|e| describe(&e))
            })
            .await?;
        }
        let result = transmit(self).await;
        match &result {
            Ok(_) if confirm_on_ok => {
                if self
                    .contact(peer)
                    .is_some_and(Contact::mark_greeting_confirmed)
                {
                    let _ = self.save_state().await;
                }
            }
            Err(e) if e.is_server_refusal() && (already_uncertain || promoted_from_unsent) => {
                if let Some(contact) = self.contact(peer) {
                    contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
                }
                let _ = self.save_state().await;
            }
            _ => {}
        }
        Ok(result)
    }

    /// Undo the changes to the contact `peer` since `snapshot`, after saving them failed, so
    /// that what is kept in memory is what the vault has.
    fn roll_back(
        &mut self,
        peer: &PublicKey,
        (session, state): (proto::SessionState, ContactState),
    ) -> Result<(), String> {
        let session = SessionState::try_from(&session).map_err(|e| describe(&e))?;
        let mailbox = Fetch::client(&self.server);
        if let Some(contact) = self.contact(peer) {
            contact.session = Session::restore(mailbox, session);
            contact.state = state;
        }
        Ok(())
    }

    /// The contacts, as shown: requests first, then the latest chats.
    fn views(&self) -> Vec<ContactView> {
        let mut views: Vec<_> = self.contacts.iter().map(Contact::view).collect();
        views.sort_by_key(|view| (!view.request, u64::MAX - view.last_activity));
        views
    }

    fn me(&self) -> Me {
        Me {
            name: self.state.name.clone(),
            key: self.client.identity_key(),
            server: self.server.clone(),
            pq_config: self.client.pq_config().clone(),
            server_pq: self.server_pq.clone(),
        }
    }
}

impl<V: VaultStore> Engine<V> {
    /// Show `views`, new in the chat with `peer`, if it is on screen, in its order.
    fn show_new(&self, inner: &Inner<impl VaultStore>, peer: &PublicKey, views: Vec<MessageView>) {
        if self.shutting_down.get()
            || crate::glue::lock_released()
            || self.ui.open.get_untracked() != Some(*peer)
            || views.is_empty()
        {
            return;
        }
        let me = inner.client.identity_key();
        let added_rows: Vec<MessageRow> = {
            let mut displayed = self.displayed_rows.borrow_mut();
            if displayed.peer != Some(*peer) {
                displayed.peer = Some(*peer);
                let old = std::mem::take(&mut displayed.rows);
                for signals in old.into_values() {
                    signals.dispose();
                }
            }
            views
                .into_iter()
                .filter_map(|view| {
                    if let Some(existing) = displayed.rows.get_mut(&view.index) {
                        if let Some(sig) = existing.delivery
                            && sig.get_untracked() != view.delivery
                        {
                            sig.set(view.delivery);
                        }
                        if let Some(sig) = existing.remote_body
                            && sig.with_untracked(|current| *current != view.body)
                        {
                            sig.set(view.body);
                        }
                        None
                    } else {
                        let row = MessageRow::from_view(view);
                        displayed.rows.insert(row.index, RowSignals::from_row(&row));
                        Some(row)
                    }
                })
                .collect()
        };
        if !added_rows.is_empty() {
            self.ui.messages.update(|messages| {
                messages.extend(added_rows);
                order_rows(messages, &me, peer);
            });
        }
    }

    /// Show the history entries of the chat with `peer` that changed, `entries`, if it is on
    /// screen: how far each got, its place, and updated body (such as held attachments gaining
    /// their real upload pointer once signed in), in the chat's order.
    fn show_changes(
        &self,
        inner: &Inner<impl VaultStore>,
        peer: &PublicKey,
        entries: &[(u64, HistoryEntry)],
    ) {
        if self.shutting_down.get()
            || crate::glue::lock_released()
            || self.ui.open.get_untracked() != Some(*peer)
            || entries.is_empty()
        {
            return;
        }
        let me = inner.client.identity_key();
        let contact = inner.contacts.iter().find(|contact| contact.peer == *peer);
        let mut place_updates: Vec<(u64, u64)> = Vec::new();
        {
            let mut displayed = self.displayed_rows.borrow_mut();
            if displayed.peer != Some(*peer) {
                return;
            }
            for (index, entry) in entries {
                let Some(signals) = displayed.rows.get_mut(index) else {
                    continue;
                };
                if entry.outgoing
                    && let Some(sig) = signals.delivery
                {
                    let next_delivery = entry.delivery();
                    if sig.get_untracked() != next_delivery {
                        sig.set(next_delivery);
                    }
                }
                if let Some(sig) = signals.remote_body
                    && let Some(contact) = contact
                {
                    let updated = contact.message(*index, entry.clone()).body;
                    if sig.with_untracked(|current| *current != updated) {
                        sig.set(updated);
                    }
                }
                if signals.place != entry.place {
                    signals.place = entry.place;
                    place_updates.push((*index, entry.place));
                }
            }
        }
        if !place_updates.is_empty() {
            self.ui.messages.update(|messages| {
                for (index, place) in place_updates {
                    if let Some(message) = messages.iter_mut().find(|m| m.index == index) {
                        message.place = place;
                    }
                }
                order_rows(messages, &me, peer);
            });
        }
    }
}

/// Normalize a protocol-deprecation / `Unimplemented` reason into clear refresh guidance for the UI.
pub(super) fn normalize_update_reason(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("procedure not implemented by server") {
        return "This app version is no longer supported by the server. Refresh the page to load the latest version."
            .to_string();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("refresh") || lower.contains("reload") || lower.contains("upgrade") {
        trimmed.to_string()
    } else {
        format!(
            "This app version is out of date ({trimmed}). Refresh the page to load the latest version."
        )
    }
}

/// The typed records of `entries` of the chat with `peer`.
fn records(
    peer: &PublicKey,
    entries: &[(u64, HistoryEntry)],
) -> Vec<(PublicKey, u64, HistoryEntry)> {
    entries
        .iter()
        .map(|(index, entry)| (*peer, *index, entry.clone()))
        .collect()
}

/// The page's origin, e.g. `https://chat.example.com`.
#[cfg(target_arch = "wasm32")]
pub fn origin() -> String {
    window().location().origin().unwrap_or_default()
}

/// The page's origin in native tests.
#[cfg(not(target_arch = "wasm32"))]
pub fn origin() -> String {
    "http://localhost".to_string()
}

/// The address of `server`, as saved: the page's origin if empty.
fn address(server: &str) -> String {
    if server.is_empty() {
        origin()
    } else {
        server.to_string()
    }
}

/// Whether `a` and `b` resolve to the same HTTP/HTTPS origin (normalizing default ports such as
/// `https://host:443` == `https://host`, scheme/host case, and trailing slashes).
pub fn same_server(a: &str, b: &str) -> bool {
    let (Ok(url_a), Ok(url_b)) = (url::Url::parse(a.trim()), url::Url::parse(b.trim())) else {
        return false;
    };
    let (origin_a, origin_b) = (url_a.origin(), url_b.origin());
    origin_a.is_tuple() && origin_a == origin_b
}

/// RFC 3986 unreserved-preserving percent-encoding set for invitation fragment parameters.
const INVITE_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Whether invitation links for `me` include `&pq=1` (local PQ enabled and server has not disabled
/// post-quantum encryption).
pub fn invitation_pins_pq(me: &Me) -> bool {
    me.pq_config.pq_enabled
        && !me.pq_config.offered_suites().is_empty()
        && me.server_pq != ServerPqStatus::Disabled
}

/// Build an invitation link for `me` relative to `page_origin`, appending `&pq=1` when local PQ
/// is enabled and the server has not disabled post-quantum encryption.
pub fn build_invitation_link(page_origin: &str, me: &Me) -> String {
    let mut link = format!(
        "{}/#chat={}",
        page_origin.trim_end_matches('/'),
        key_to_url(&me.key)
    );
    if !me.name.is_empty() {
        link.push_str(&format!(
            "&name={}",
            percent_encoding::utf8_percent_encode(&me.name, INVITE_ENCODE_SET)
        ));
    }
    if !same_server(&me.server, page_origin) {
        link.push_str(&format!(
            "&server={}",
            percent_encoding::utf8_percent_encode(&me.server, INVITE_ENCODE_SET)
        ));
    }
    if invitation_pins_pq(me) {
        link.push_str("&pq=1");
    }
    link
}

/// Parse a `#chat=<key>&name=<name>&server=<server>&pq=1` fragment into a `Dialog::NewChat`,
/// sanitizing any suggested `name` with [`sanitize_shared_name`].
pub fn parse_invitation_hash(hash: &str) -> Option<Dialog> {
    let mut key = None;
    let mut name = String::new();
    let mut server = None;
    let mut pq_pinned = false;
    for pair in hash.trim_start_matches('#').split('&') {
        match pair.split_once('=') {
            Some(("chat", value)) if !value.is_empty() => key = Some(value.to_string()),
            Some(("name", value)) => {
                if let Ok(decoded) = percent_encoding::percent_decode_str(value).decode_utf8() {
                    name = sanitize_shared_name(&decoded);
                } else {
                    name.clear();
                }
            }
            Some(("server", value)) => {
                server = percent_encoding::percent_decode_str(value)
                    .decode_utf8()
                    .ok()
                    .map(std::borrow::Cow::into_owned);
            }
            Some(("pq", value)) => {
                pq_pinned = value == "1" || value.eq_ignore_ascii_case("true");
            }
            _ => {}
        }
    }
    Some(Dialog::NewChat {
        key: key?,
        name,
        server,
        pq_pinned,
    })
}

/// The invitation link's `#chat=<key>&name=<name>&server=<server>&pq=1` in the page's address, as
/// a dialog to start the chat.
pub fn invitation() -> Option<Dialog> {
    let hash = window().location().hash().ok()?;
    parse_invitation_hash(&hash)
}

/// Remove the invitation from the page's address, once it shows, preserving any existing
/// `history.state` token stamped by session-history management.
fn forget_invitation() {
    let location = window().location();
    if let (Ok(history), Ok(path)) = (window().history(), location.pathname()) {
        let state = history.state().unwrap_or(wasm_bindgen::JsValue::NULL);
        let _ = history.replace_state_with_url(&state, "", Some(&path));
    }
}
