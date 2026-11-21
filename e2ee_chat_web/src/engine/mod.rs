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

use crate::content::{Deleted, Kind, stamp};
use crate::glue::LockStatus;
use crate::state::{
    Body, ContactView, Dialog, IsolatedContactView, Link, Me, MessageView, PendingNewChat, Phase,
    ServerPqStatus, SignIn, SignInFlow, SignInSuccessAction, Ui, UnavailableReason, UploadState,
    order,
};
use crate::transport::{Connect, Fetch};
use crate::util::{describe, js_error, key_to_url, short, size_u64, sleep};
use crate::vault::{
    AppState, CarriedDeferredTimestamp, ContactState, DeferredInitial, DeferredInitialsRecord,
    HistoryEntry, OutgoingRecord, Vault, history_key,
};
use crate::{content, glue, transport};
use attachments::upload_of;
use contact::{Contact, forget_told, isolated_contact_views, restore_contacts, stored_contacts};
use futures::channel::oneshot;
use futures::future::{Either, select};
use futures::lock::Mutex;
use handshake::build_farewell;
use leptos::prelude::*;
use leptos::task::spawn_local;
use session::attachment::{CHUNK_SIZE, Upload};
use session::protocol::attachment::DEFAULT_MAX_CHUNKS;
use session::{
    Client, ClientState, ErrorKind, PqConfig, PublicKey, Session, SessionState, attachment,
    expected_audience_from_url, proto,
};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use streaming::Stream;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

/// Why an attachment's upload has not started.
const WAITS_SIGN_IN: &str = "waits for you to sign in to the server";
/// Why what takes a sign-in never goes from a page that is not the server's own, which cannot
/// sign in to it.
const NOT_SIGNED_IN_HERE: &str =
    "the server keeps it only for those signed in to it, and only its own page can sign in";
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
/// Structured error returned by [`Engine::start_chat`] so the UI can offer actionable prompts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartChatError {
    /// The server requires sign-in on this page's origin before fetching prekeys / starting a chat.
    SignInRequired,
    ClassicalApprovalRequired {
        peer_signed_off: bool,
    },
    DowngradeDetected,
    PeerManifestExpired,
    PqRequired,
    Other(String),
}
/// Maximum milliseconds to wait for a proactive `/auth` check when unlocking via an invitation link.
const AUTH_CHECK_TIMEOUT: i32 = 1_500;
/// Files up to this many bytes go in their message; larger ones go as attachments.
pub const INLINE_FILE_MAX: usize = 1 << 20;
/// Attachments up to this many bytes that are images, videos or audio show in the chat, fetched
/// as they are about to show; larger ones show as files, fetched once opened.
pub const MEDIA_INLINE_MAX: u64 = 8 << 20;
/// The largest file to send: as many chunks as the server takes, unless it says otherwise.
pub const MAX_FILE_SIZE: usize = DEFAULT_MAX_CHUNKS as usize * CHUNK_SIZE;
/// The most characters in this client's name. It goes in the greeting, the first message of each
/// chat it starts, which the server takes up to 4 KiB of; at 4 bytes a character at most, this
/// leaves the greeting far below that.
pub const NAME_MAX: usize = 64;

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

pub struct Engine {
    ui: Ui,
    inner: Mutex<Option<Inner>>,
    /// Sync now, e.g. after sending, as a reply may follow.
    wake: Cell<bool>,
    /// The files of the uploads started or resumed on this page, keyed by `(peer, id, key_hash)`,
    /// which can go on without the files chosen again.
    files: RefCell<HashMap<AttachmentKey, web_sys::File>>,
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
    /// first, shared only across streams with matching peer, attachment ID, and key.
    decrypted: RefCell<VecDeque<(ChunkOf, Rc<Vec<u8>>)>>,
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
}

/// SHA-256 digest of an attachment key, binding plaintext/file caches without storing raw keys as map keys.
pub(crate) fn attachment_key_hash(key: &[u8]) -> [u8; 32] {
    Sha256::digest(key).into()
}

/// Cache key binding a local file to its exact `(peer, attachment_id, key_hash)`.
pub(crate) type AttachmentKey = (PublicKey, [u8; 16], [u8; 32]);

/// Cache key binding a stream chunk to its exact `(peer, attachment_id, key_hash, chunk_index)`.
pub(crate) type ChunkOf = (PublicKey, [u8; 16], [u8; 32], u32);

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

/// The unlocked client.
struct Inner<V = Vault> {
    vault: V,
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
    /// Encrypted inbox initials retained in the separate `deferred_initials` vault record.
    deferred_initials: Vec<DeferredInitial>,
    /// Earliest timestamps (Unix ms) at which unsupported carried initials referencing an SPK
    /// were retained, bounding signed-prekey preservation across rotations.
    carried_deferred_timestamps: Vec<CarriedDeferredTimestamp>,
    client: Client<Connect>,
    contacts: Vec<Contact>,
    /// Unreadable records retained verbatim until explicitly deleted.
    isolated_contacts: Vec<ContactState>,
    /// History namespaces reserved by unreadable contacts with no healthy active record.
    isolated_peers: HashSet<PublicKey>,
    /// A non-rollbackable state change still needs a successful transaction.
    unsaved_state: bool,
    /// Inbox IDs to commit with their deferred ciphertext before they become eligible for ack.
    deferred_acks_after_save: Vec<u64>,
    /// A later transaction committed that change. Refresh contact and identity views on sync.
    contacts_dirty_late: bool,
    /// History records that a save failed to write after what they record could not be undone:
    /// initial messages, which the server deleted once taken, and the greeting of a chat started.
    /// Each save writes them too, until one succeeds, so that the history has no gap.
    unsaved: Vec<(PublicKey, (String, HistoryEntry))>,
    /// Requeued outbox records that a save failed to write after an accepted replacement session
    /// reset `outbox[*].sealed = false` in memory. Each save writes them before any caller
    /// `outgoing` updates until one succeeds so `seal_next` never reads stale empty-content
    /// sealed outbox records from IndexedDB.
    unsaved_outbox: Vec<(PublicKey, (String, Option<OutgoingRecord>))>,
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
/// The core v2 handler must report `Unimplemented`, either directly or in a Connect error body.
/// The transport handles explicit `x-e2ee-deprecated` headers and sync handles WebSocket close
/// code `4010` independently.
pub(super) fn should_require_update_for_rpc(
    scope: ProtocolRpcScope,
    error: &session::Error,
) -> bool {
    scope == ProtocolRpcScope::CoreV2
        && error.is_server_refusal()
        && error.is_connect_error()
        && error.kind() == ErrorKind::Unimplemented
}

impl Engine {
    pub fn new(ui: Ui) -> Rc<Self> {
        let engine = Rc::new(Self {
            ui,
            inner: Mutex::new(None),
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
        });
        // Whatever the server refuses for the sign-in, the user is asked to sign in.
        let weak = Rc::downgrade(&engine);
        transport::on_sign_in_required(move || {
            if let Some(engine) = weak.upgrade() {
                engine.refused_for_sign_in();
            }
        });
        let weak = Rc::downgrade(&engine);
        transport::on_update_required(move |reason| {
            if let Some(engine) = weak.upgrade() {
                engine.require_update(reason);
            }
        });
        engine
    }

    /// Surface a persistent upgrade/refresh banner when the server rejects this client's protocol
    /// (e.g. WebSocket close `4010`, `x-e2ee-deprecated`, or `ErrorKind::Unimplemented`).
    pub(super) fn require_update(&self, reason: impl Into<String>) {
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
        loop {
            let Some(next) = self.sending.borrow_mut().pop_front() else {
                break;
            };
            let sent = match next {
                Sending::Content(peer, content) => self.send(peer, content).await,
                Sending::File(peer, file) => self.send_file(peer, file).await,
            };
            if let Err(e) = sent {
                self.ui.notify(e);
            }
        }
        self.draining.set(false);
    }

    /// Send `file` to `peer`: a small one in its message, a larger one as an attachment.
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
        // An upload shows how far it got above the composer.
        if bytes > INLINE_FILE_MAX as u64 {
            return self.send_attachment(peer, file).await;
        }
        let buffer = JsFuture::from(file.array_buffer())
            .await
            .map_err(|e| format!("Cannot read {name}: {}", js_error(e)))?;
        let data = js_sys::Uint8Array::new(&buffer).to_vec();
        self.send(peer, content::from_file(name, file.type_(), data))
            .await
    }

    /// The signals it keeps up to date.
    pub fn ui(&self) -> Ui {
        self.ui
    }

    /// Who this browser is signed in to the server as, if anyone, which storing files there
    /// takes.
    pub async fn signed_in(&self) -> Result<Option<SignIn>, String> {
        let server = self.server().await?;
        let (status, answer) = transport::call(&server, "GET", "/auth", None).await?;
        if status != 200 {
            return Err(format!("the server answered {status}"));
        }
        let signed_in = SignIn::from_json(&answer);
        // Signed in meanwhile, e.g. on another of the server's pages: publishing goes again.
        if signed_in.is_some() && self.publish_waits_sign_in.replace(false) {
            self.wake();
        }
        Ok(signed_in)
    }

    /// Sign in to the server with its `password`: what waited for it goes then.
    pub async fn sign_in(self: &Rc<Self>, password: &str) -> Result<SignIn, String> {
        let server = self.server().await?;
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
        match status {
            200 => {}
            403 => return Err("Wrong password.".to_string()),
            503 => return Err("This server takes no sign-ins: it has no password set.".to_string()),
            status => return Err(format!("The server answered {status}.")),
        }
        // Unless the browser refused the cookie, e.g. as it blocks the server's cookies.
        let signed_in = self.signed_in().await?.ok_or(
            "This browser kept no sign-in for the server: it may block the server's cookies.",
        )?;
        self.waits_sign_in.borrow_mut().clear();
        self.sign_in_flow.borrow_mut().reset_declined();
        self.publish_waits_sign_in.set(false);
        self.start_waiting_uploads().await;
        self.wake();
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

    /// Ask the user to sign in to the server, as what was sent waits for it. If `NewChat` is
    /// currently open, preserves its invitation/draft so it can resume seamlessly after sign-in.
    fn ask_sign_in(&self) {
        let next = self.ui.dialog.with_untracked(|current| {
            self.sign_in_flow.borrow_mut().on_ask_sign_in(
                current.as_ref(),
                self.can_sign_in_here.get(),
                false,
            )
        });
        if let Some(dialog) = next {
            self.ui.dialog.set(Some(dialog));
        }
    }

    /// The server refused a call, whichever, as this browser is not signed in to it, which every
    /// write takes: ask, unless the user put it off.
    fn refused_for_sign_in(&self) {
        let next = self.ui.dialog.with_untracked(|current| {
            self.sign_in_flow.borrow_mut().on_ask_sign_in(
                current.as_ref(),
                self.can_sign_in_here.get(),
                true,
            )
        });
        if let Some(dialog) = next {
            self.ui.dialog.set(Some(dialog));
        }
    }

    /// The user dismissed `SignInDialog` ("Not now" or Escape): suppress background sign-in
    /// prompts, restore any preserved `NewChat` / invitation draft, and return `true` if a
    /// dialog was restored (so a native `<dialog>` cancel event keeps the modal open).
    pub fn dismiss_sign_in(&self) -> bool {
        match self.sign_in_flow.borrow_mut().on_dismiss_sign_in() {
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
    pub fn new_chat_edited(&self, key: String, name: String) {
        self.sign_in_flow.borrow_mut().on_new_chat_edited(key, name);
    }

    /// Clear the live `NewChat` draft tracker when `NewChat` unmounts.
    pub fn new_chat_unmounted(&self) {
        self.sign_in_flow.borrow_mut().on_new_chat_unmounted();
    }

    /// Mark that `NewChat` has an in-flight `start_chat` submission.
    pub fn begin_new_chat_submit(&self, draft: PendingNewChat) {
        self.sign_in_flow.borrow_mut().begin_new_chat_submit(draft);
    }

    /// Clear the in-flight `NewChat` submission marker.
    pub fn end_new_chat_submit(&self) {
        self.sign_in_flow.borrow_mut().end_new_chat_submit();
    }

    /// Preserve a submitted `NewChat` draft (with `auto_start: true`) and immediately present
    /// `SignInDialog` cleanly when `start_chat` hits `SignInRequired`.
    pub fn require_sign_in_for_new_chat(&self, draft: PendingNewChat) {
        let dialog = self
            .sign_in_flow
            .borrow_mut()
            .on_start_chat_sign_in_required(draft);
        self.ui.dialog.set(Some(dialog));
    }

    /// Hint for `SignInDialog` when a `NewChat` / invitation draft is waiting:
    /// `Some((auto_start, has_key))`.
    pub fn pending_new_chat_hint(&self) -> Option<(bool, bool)> {
        self.sign_in_flow.borrow().pending_new_chat_hint()
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

    /// Complete an automatic post-sign-in `start_chat` attempt, closing `SignInDialog` on success
    /// or reopening `NewChat` prefilled with `err` when user attention is required.
    pub fn finish_auto_start_chat(&self, err: Option<StartChatError>) {
        let (succeeded, still_needs_sign_in) = match &err {
            None => (true, false),
            Some(StartChatError::SignInRequired) => (false, true),
            Some(_) => (false, false),
        };
        let (close_sign_in, reopened) = self
            .sign_in_flow
            .borrow_mut()
            .on_auto_start_finished(succeeded, still_needs_sign_in);
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
        let guard = self.inner.lock().await;
        Ok(guard.as_ref().ok_or("locked")?.server.clone())
    }

    /// Find out whether to create or unlock the vault.
    pub async fn start(&self) {
        glue::register_media_worker();
        // Two tabs on one vault would fork the sessions' ratchets.
        match crate::glue::take_lock("e2ee-chat").await {
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
        match Vault::exists().await {
            Ok(true) => self.ui.phase.set(Phase::Locked),
            Ok(false) => self.ui.phase.set(Phase::Create),
            // Offering to create one could replace a vault that is there.
            Err(e) => self.ui.phase.set(Phase::Unavailable(
                UnavailableReason::StorageUnavailable,
                describe(&e),
            )),
        }
    }

    /// Create a vault with a new identity, under `passphrase`, replacing any other.
    pub async fn create(
        self: &Rc<Self>,
        name: String,
        passphrase: Zeroizing<String>,
        server: String,
        pq_enabled: bool,
    ) -> Result<(), String> {
        let server = server.trim().trim_end_matches('/').to_string();
        // The page's own server is saved as empty, so the vault follows the page.
        let server = if server == origin() {
            String::new()
        } else {
            server
        };
        let address = address(&server);
        let audience = expected_audience_from_url(&address)
            .map_err(|_| "Enter a valid http:// or https:// server address.".to_string())?;
        let mut client =
            Client::new(Fetch::client(&address)).with_clock(transport::clock(&address));
        let mut pq_config = PqConfig::default();
        if !pq_enabled {
            pq_config.pq_enabled = false;
            pq_config.strict_pq = false;
        }
        client.set_pq_config(pq_config).map_err(|e| describe(&e))?;
        let state = AppState {
            client: Some(client.state().into()),
            server,
            name: checked_name(&name)?,
            ..AppState::default()
        };
        let vault = Vault::create(passphrase.as_bytes(), &state)
            .await
            .map_err(|e| describe(&e))?;
        drop(passphrase);
        let state = AppState {
            client: None,
            ..state
        };
        self.unlocked(Inner::new(
            vault,
            address,
            audience,
            state,
            client,
            vec![],
            vec![],
            DeferredInitialsRecord::default(),
        ))
        .await;
        Ok(())
    }

    /// Unlock the vault with `passphrase`.
    pub async fn unlock(self: &Rc<Self>, passphrase: Zeroizing<String>) -> Result<(), String> {
        let (vault, mut state, mut deferred) = Vault::unlock(passphrase.as_bytes())
            .await
            .map_err(|e| describe(&e))?;
        drop(passphrase);
        let address = address(&state.server);
        let audience = expected_audience_from_url(&address)
            .map_err(|_| "the server address saved in the vault is invalid".to_string())?;
        let client = state.client.take().ok_or("the vault has no identity")?;
        let client = Client::restore(
            Fetch::client(&address),
            ClientState::try_from(&client).map_err(|e| describe(&e))?,
        )
        .with_clock(transport::clock(&address));
        let (contacts, isolated_contacts, warnings) = restore_contacts(
            std::mem::take(&mut state.contacts),
            &client.identity_key(),
            &address,
        );
        let pruned = handshake::prune_invalid_inbox_acks(&mut state.pending_inbox_acks);
        let migrated_deferred = handshake::merge_legacy_deferred_initials(
            &mut deferred.entries,
            std::mem::take(&mut state.deferred_initials),
        );
        let (pruned_deferred, modified_deferred) =
            handshake::sanitize_deferred_initials(&mut deferred.entries, crate::util::now());
        let pruned_carried_ts = handshake::prune_carried_timestamps_for_contacts(
            &mut deferred.carried_timestamps,
            contacts.iter(),
        );
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
        if pruned > 0
            || pruned_deferred > 0
            || modified_deferred
            || migrated_deferred
            || pruned_carried_ts > 0
        {
            inner.unsaved_state = true;
        }
        self.unlocked(inner).await;
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

    async fn unlocked(self: &Rc<Self>, inner: Inner) {
        let can_sign_in_here = same_server(&inner.server, &origin());
        self.can_sign_in_here.set(can_sign_in_here);
        self.ui.me.set(Some(inner.me()));
        self.ui.contacts.set(inner.views());
        self.ui.isolated_contacts.set(inner.isolated_views());
        // Uploads the page left: their files are gone with it.
        match inner.vault.uploads(None).await {
            Ok(uploads) => {
                for (peer, pending) in uploads {
                    // Done, but left behind, as forgetting it failed.
                    if pending.started()
                        && u64::from(pending.uploaded) >= attachment::chunk_count(pending.size)
                    {
                        let _ = inner.vault.forget_upload(&peer, &pending.id).await;
                        continue;
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
            Err(e) => self.ui.notify(describe(&e)),
        }
        *self.inner.lock().await = Some(inner);
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
            let initial = self.sign_in_flow.borrow_mut().on_unlock_with_invitation(
                dialog,
                can_sign_in_here,
                signed_in,
            );
            self.ui.dialog.set(Some(initial));
        }
        self.ui.phase.set(Phase::Unlocked);
        self.ui.log("vault unlocked");
        self.clone().run();
        self.clone().listen();
        let engine = self.clone();
        glue::serve_media(move |request| {
            let engine = engine.clone();
            spawn_local(async move { engine.serve_media(request).await });
        });
    }

    /// Save `content` for `peer`, then push it, encrypted as its turn comes. What the user sends
    /// goes through [`Engine::queue`], to go in order.
    async fn send(&self, peer: PublicKey, content: Kind) -> Result<(), String> {
        self.send_returning_index(peer, content).await.map(drop)
    }

    async fn send_returning_index(&self, peer: PublicKey, content: Kind) -> Result<u64, String> {
        let index = {
            let mut guard = self.inner.lock().await;
            let inner = guard.as_mut().ok_or("locked")?;
            let view = inner.add(&peer, content, false).await?;
            let index = view.index;
            self.show_new(inner, &peer, vec![view]);
            self.ui.contacts.set(inner.views());
            index
        };
        // Saved, so it goes in a later sync if not now.
        if let Err(e) = self.flush(&peer).await {
            self.ui.link.set(Link::Offline(e));
        }
        self.wake();
        Ok(index)
    }

    /// Show the chat with `peer`, or the chat list.
    pub async fn open(&self, peer: Option<PublicKey>) {
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return;
        };
        let Some(peer) = peer else {
            self.ui.open.set(None);
            self.ui.messages.set(vec![]);
            return;
        };
        // Self-peer guard: never open a chat with one's own identity key.
        if peer == inner.client.identity_key() {
            return;
        }
        self.show_history(inner, &peer).await;
        let Some(contact) = inner.contact(&peer) else {
            return;
        };
        // Do not mark quarantined messages as read or send receipts before explicit approval.
        let read = if contact.state.quarantined {
            false
        } else {
            contact.read_all()
        };
        self.ui.open.set(Some(peer));
        if read && let Err(e) = inner.save_state().await {
            self.ui.notify(describe(&e));
        }
        self.ui.contacts.set(inner.views());
        drop(guard);
        // The peer learns what was read.
        if read && let Err(e) = self.flush(&peer).await {
            self.ui.link.set(Link::Offline(e));
        }
    }

    /// Show the last [`HISTORY_SHOWN`] entries of the history of the chat with `peer`.
    async fn show_history(&self, inner: &mut Inner, peer: &PublicKey) {
        let Some(contact) = inner.contacts.iter().find(|contact| contact.peer == *peer) else {
            return;
        };
        let history = inner
            .vault
            .history(peer, contact.state.history_len, HISTORY_SHOWN)
            .await;
        let Some(contact) = inner.contact(peer) else {
            return;
        };
        let mut messages: Vec<_> = match history {
            Ok(history) => history
                .into_iter()
                .map(|(index, entry)| contact.message(index, entry))
                .collect(),
            Err(e) => {
                self.ui.notify(describe(&e));
                vec![]
            }
        };
        order(&mut messages, &inner.client.identity_key(), peer);
        self.ui.messages.set(messages);
    }

    /// Count the messages of the chat with `peer` as read, e.g. back on the page with the chat
    /// open: they show already, as [`receive`](Self::receive) adds them to the open chat. The
    /// peer learns it.
    pub async fn mark_read(&self, peer: PublicKey) {
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return;
        };
        let Some(contact) = inner.contact(&peer) else {
            return;
        };
        if contact.state.quarantined || !contact.read_all() {
            return;
        }
        if let Err(e) = inner.save_state().await {
            self.ui.notify(describe(&e));
        }
        self.ui.contacts.set(inner.views());
        drop(guard);
        if let Err(e) = self.flush(&peer).await {
            self.ui.link.set(Link::Offline(e));
        }
    }

    /// Accept the request of `peer`, naming the peer `name`. Refuses while the contact is
    /// quarantined pending explicit classical approval or post-quantum upgrade.
    pub async fn accept(&self, peer: PublicKey, name: String) -> Result<(), String> {
        {
            let mut guard = self.inner.lock().await;
            let inner = guard.as_mut().ok_or("locked")?;
            let contact = inner.contact(&peer).ok_or("no such chat")?;
            contact.accept_request(&name)?;
            inner.save_state().await.map_err(|e| describe(&e))?;
            self.ui.contacts.set(inner.views());
        }
        // The peer learns what was read of the request.
        self.wake();
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
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        change(inner.contact(&peer).ok_or("no such chat")?);
        inner.save_state().await.map_err(|e| describe(&e))?;
        self.ui.contacts.set(inner.views());
        Ok(())
    }

    /// Delete the chat with `peer` and its history. The server knows nothing of it: what it keeps
    /// of the chat goes as it is delivered, or expires; but for its uploads that went up and
    /// have not finished, which it deletes, as they never can now.
    pub async fn delete(&self, peer: PublicKey) -> Result<(), String> {
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        // Read before anything changes, as the vault forgets them with the chat: those still
        // shown, going or paused, as one that just finished leaves the page before the vault.
        let shown: HashSet<Vec<u8>> = self.ui.uploads.with_untracked(|uploads| {
            uploads
                .iter()
                .filter(|upload| upload.peer == peer)
                .map(|upload| upload.id.to_vec())
                .collect()
        });
        let unfinished: Vec<(String, Upload)> = inner
            .vault
            .uploads(Some(&peer))
            .await
            .map_err(|e| describe(&e))?
            .into_iter()
            .filter(|(_, pending)| pending.started() && shown.contains(&pending.id))
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
            let mut deleted = Kind::Deleted(Deleted {}).to_bytes();
            contact.state.clock = contact.state.clock.saturating_add(1);
            stamp(&mut deleted, contact.state.clock);
            let mut events = contact.state.events.take();
            // Events encrypted already on the active session go as they are, before the rest.
            let active = contact.session.active_id().map(|id| id.to_vec());
            if let Some(sealed) = contact.state.sealed_events.take()
                && Some(&sealed.session) == active.as_ref()
            {
                let sealed_msg = sealed.record.unwrap_or_default().to_push();
                farewell.push(build_farewell(contact, sealed_msg));
                if let (Some(events), Some(told)) = (&mut events, &sealed.events) {
                    forget_told(events, told);
                }
            }
            let events = events.filter(|events| !events.is_empty());
            for content in events
                .map(|events| events.to_bytes())
                .into_iter()
                .chain([deleted])
            {
                if let Ok(message) = contact.session.encrypt(&content) {
                    farewell.push(build_farewell(contact, message));
                }
            }
        }
        // Forgotten in the vault first, so that if that fails, the chat stays whole; with the
        // records of other chats left unsaved, as with each save.
        let mut state = inner.app_state();
        state.contacts.retain(|contact| contact.peer != peer);
        state.farewells.extend(farewell.clone());
        let deferred = inner.deferred_record_without_peer(&peer);
        let unsaved = inner
            .unsaved
            .iter()
            .filter(|(unsaved, _)| *unsaved != peer)
            .map(|(_, record)| record);
        let unsaved_outbox = inner
            .unsaved_outbox
            .iter()
            .filter(|(unsaved, _)| *unsaved != peer)
            .map(|(_, record)| record);
        if let Err(e) = inner
            .vault
            .forget(&state, &deferred, &peer, unsaved, unsaved_outbox)
            .await
        {
            if let Some(snapshot) = snapshot {
                inner.roll_back(&peer, snapshot)?;
            }
            return Err(describe(&e));
        }
        // Its uploads stop, as cancelled, and keep nothing more: the vault forgot them with the
        // chat, which `may_keep` now tells them is gone.
        let uploads: Vec<[u8; 16]> = self.ui.uploads.with_untracked(|uploads| {
            uploads
                .iter()
                .filter(|upload| upload.peer == peer)
                .map(|upload| upload.id)
                .collect()
        });
        for id in uploads {
            self.cancelled.borrow_mut().insert(id);
            self.remove_attachment_caches(&peer, &id);
        }
        self.files.borrow_mut().retain(|(p, _, _), _| *p != peer);
        self.decrypted
            .borrow_mut()
            .retain(|((p, _, _, _), _)| *p != peer);
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.peer != peer));
        self.ui.gone.update(|gone| gone.retain(|(p, _)| *p != peer));
        // Nor does what waited for a sign-in, which would otherwise hold up a chat started
        // again with the peer, or go to it.
        self.waits_sign_in.borrow_mut().remove(&peer);
        let was_isolated = inner.is_isolated_peer(&peer);
        inner.contacts.retain(|contact| contact.peer != peer);
        inner.forget_isolated_peer(&peer);
        inner.deferred_initials = deferred.entries;
        inner.carried_deferred_timestamps = deferred.carried_timestamps;
        inner.finish_state_save(state.pending_inbox_acks);
        // The other chats' records left unsaved were saved with it, and show at the next sync.
        inner.saved_late.extend(
            inner
                .unsaved
                .drain(..)
                .map(|(unsaved, _)| unsaved)
                .filter(|unsaved| *unsaved != peer),
        );
        inner.unsaved_outbox.clear();
        inner.state.farewells.extend(farewell);
        self.wake();
        if self.ui.open.get_untracked() == Some(peer) {
            self.ui.open.set(None);
            self.ui.messages.set(vec![]);
        }
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
        if !unfinished.is_empty() {
            let (ui, attachments) = (self.ui, Fetch::client(&inner.server));
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
        }
        Ok(())
    }

    /// Permanently delete an isolated corrupt contact record (and any local history/outbox under
    /// that peer key) after explicit user confirmation. Refuses to delete an active healthy chat.
    pub async fn delete_isolated(&self, raw_peer: Vec<u8>) -> Result<(), String> {
        if let Ok(peer) = PublicKey::try_from(raw_peer.as_slice()) {
            {
                let guard = self.inner.lock().await;
                let inner = guard.as_ref().ok_or("locked")?;
                if !inner.is_isolated_peer(&peer) {
                    return Err("That contact is no longer isolated.".to_string());
                }
            }
            return self.delete(peer).await;
        }
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        if !inner.delete_isolated_raw(&raw_peer).await? {
            return Err("That isolated contact record was already removed.".to_string());
        }
        self.ui.isolated_contacts.set(inner.isolated_views());
        self.ui
            .log("deleted isolated contact record with a malformed identity key");
        Ok(())
    }

    /// Go by `name` in the greetings of new chats.
    pub async fn set_name(&self, name: String) -> Result<(), String> {
        let name = checked_name(&name)?;
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        inner.state.name = name;
        inner.save_state().await.map_err(|e| describe(&e))?;
        self.ui.me.set(Some(inner.me()));
        Ok(())
    }
}

/// The vault operations needed to stage incoming changes and rebuild outgoing messages.
trait HistoryStore {
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
        deferred: &DeferredInitialsRecord,
        entries: impl IntoIterator<Item = &'a (String, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (String, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()>;
}

impl HistoryStore for Vault {
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
        deferred: &DeferredInitialsRecord,
        entries: impl IntoIterator<Item = &'a (String, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (String, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()> {
        Vault::save(self, state, deferred, entries, outgoing).await
    }
}

impl<V: HistoryStore> Inner<V> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        vault: V,
        server: String,
        audience: String,
        mut state: AppState,
        client: Client<Connect>,
        contacts: Vec<Contact>,
        mut isolated_contacts: Vec<ContactState>,
        deferred: DeferredInitialsRecord,
    ) -> Self {
        state.deferred_initials.clear();
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
            server,
            audience,
            state,
            deferred_initials: deferred.entries,
            carried_deferred_timestamps: deferred.carried_timestamps,
            client,
            contacts,
            isolated_contacts,
            isolated_peers,
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

    /// What the vault keeps in `STATE` (never writes tag 12 `deferred_initials`, which live in
    /// the separate `deferred_initials` record).
    fn app_state(&self) -> AppState {
        let mut state = AppState {
            client: Some(self.client.state().into()),
            contacts: stored_contacts(&self.contacts, &self.isolated_contacts),
            deferred_initials: vec![],
            ..self.state.clone()
        };
        for &id in &self.deferred_acks_after_save {
            handshake::stage_inbox_ack(&mut state.pending_inbox_acks, id);
        }
        state
    }

    fn deferred_record(&self) -> DeferredInitialsRecord {
        DeferredInitialsRecord {
            entries: self.deferred_initials.clone(),
            carried_timestamps: self.carried_deferred_timestamps.clone(),
        }
    }

    pub(super) fn deferred_record_without_peer(&self, peer: &PublicKey) -> DeferredInitialsRecord {
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
        DeferredInitialsRecord {
            entries,
            carried_timestamps,
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
    async fn save(&mut self, entries: &[(String, HistoryEntry)]) -> crate::vault::Result<()> {
        self.save_with(entries, &[]).await
    }

    /// Save as [`save`](Self::save) does, and `outgoing`, the records of messages waiting to be
    /// pushed, or none for one that went.
    async fn save_with(
        &mut self,
        entries: &[(String, HistoryEntry)],
        outgoing: &[(String, Option<OutgoingRecord>)],
    ) -> crate::vault::Result<()> {
        let unsaved = self.unsaved.iter().map(|(_, record)| record);
        let unsaved_outbox = self.unsaved_outbox.iter().map(|(_, record)| record);
        let state = self.app_state();
        let deferred = self.deferred_record();
        self.vault
            .save(
                &state,
                &deferred,
                unsaved.chain(entries),
                unsaved_outbox.chain(outgoing),
            )
            .await?;
        self.finish_state_save(state.pending_inbox_acks);
        self.saved_late
            .extend(self.unsaved.drain(..).map(|(peer, _)| peer));
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

impl Engine {
    /// Show `views`, new in the chat with `peer`, if it is on screen, in its order.
    fn show_new(
        &self,
        inner: &Inner<impl HistoryStore>,
        peer: &PublicKey,
        views: Vec<MessageView>,
    ) {
        if self.ui.open.get_untracked() != Some(*peer) || views.is_empty() {
            return;
        }
        let me = inner.client.identity_key();
        self.ui.messages.update(|messages| {
            messages.extend(views);
            order(messages, &me, peer);
        });
    }

    /// Show the history entries of the chat with `peer` that changed, `entries`, if it is on
    /// screen: how far each got, its place, and updated body (such as held attachments gaining
    /// their real upload pointer once signed in), in the chat's order.
    fn show_changes(
        &self,
        inner: &Inner<impl HistoryStore>,
        peer: &PublicKey,
        entries: &[(u64, HistoryEntry)],
    ) {
        if self.ui.open.get_untracked() != Some(*peer) || entries.is_empty() {
            return;
        }
        let me = inner.client.identity_key();
        let contact = inner.contacts.iter().find(|contact| contact.peer == *peer);
        self.ui.messages.update(|messages| {
            for (index, entry) in entries {
                if let Some(message) = messages.iter_mut().find(|message| message.index == *index) {
                    message.place = entry.place;
                    if entry.outgoing {
                        message.delivery = entry.delivery();
                    }
                    if let Some(contact) = contact {
                        let mut updated = contact.message(*index, entry.clone()).body;
                        // Preserve already-loaded inline bytes on `Body::File` when delivery ticks
                        // read back a stripped `HistoryEntry` from IndexedDB.
                        if let (Body::File(existing), Body::File(next)) =
                            (&message.body, &mut updated)
                            && existing.data.is_some()
                            && next.data.is_none()
                        {
                            next.data = existing.data.clone();
                        }
                        if message.body != updated {
                            message.body = updated;
                        }
                    }
                }
            }
            order(messages, &me, peer);
        });
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

/// The records of `entries` of the chat with `peer`.
fn records(peer: &PublicKey, entries: &[(u64, HistoryEntry)]) -> Vec<(String, HistoryEntry)> {
    entries
        .iter()
        .map(|(index, entry)| (history_key(peer, *index), entry.clone()))
        .collect()
}

/// The page's origin, e.g. `https://chat.example.com`.
pub fn origin() -> String {
    window().location().origin().unwrap_or_default()
}

/// The address of `server`, as saved: the page's origin if empty.
fn address(server: &str) -> String {
    if server.is_empty() {
        origin()
    } else {
        server.to_string()
    }
}

/// Whether `a` and `b` are the address of one server.
pub fn same_server(a: &str, b: &str) -> bool {
    a.trim_end_matches('/')
        .eq_ignore_ascii_case(b.trim_end_matches('/'))
}

/// Percent-encode a URI component (RFC 3986 unreserved characters preserved), pure Rust for native tests.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Percent-decode a URI component, pure Rust for native tests.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = *bytes.get(i + 1)? as char;
            let lo = *bytes.get(i + 2)? as char;
            let val = u8::from_str_radix(&format!("{hi}{lo}"), 16).ok()?;
            out.push(val);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
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
        link.push_str(&format!("&name={}", percent_encode(&me.name)));
    }
    if !same_server(&me.server, page_origin) {
        link.push_str(&format!("&server={}", percent_encode(&me.server)));
    }
    if me.pq_config.pq_enabled
        && !me.pq_config.offered_suites().is_empty()
        && me.server_pq != ServerPqStatus::Disabled
    {
        link.push_str("&pq=1");
    }
    link
}

/// Parse a `#chat=<key>&name=<name>&server=<server>&pq=1` fragment into a `Dialog::NewChat`.
pub fn parse_invitation_hash(hash: &str) -> Option<Dialog> {
    let mut key = None;
    let mut name = String::new();
    let mut server = None;
    let mut pq_pinned = false;
    for pair in hash.trim_start_matches('#').split('&') {
        match pair.split_once('=') {
            Some(("chat", value)) if !value.is_empty() => key = Some(value.to_string()),
            Some(("name", value)) => name = percent_decode(value).unwrap_or_default(),
            Some(("server", value)) => server = percent_decode(value),
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

/// Remove the invitation from the page's address, once it shows.
fn forget_invitation() {
    let location = window().location();
    if let (Ok(history), Ok(path)) = (window().history(), location.pathname()) {
        let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&path));
    }
}
