//! What the page shows: plain data in signals, which the engine keeps up to date.

use std::{collections::HashSet, fmt, sync::Arc, time::Duration};

use leptos::prelude::*;
use session::{PqConfig, PqSuite, PublicKey, SessionSecurity};

use crate::{
    content::AttachmentPointer,
    preview::Sort,
    util::{now, short},
};

/// Why the vault cannot be opened on this page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    /// Opened over an insecure origin (plain HTTP, non-localhost) where Web Locks are unavailable.
    InsecureContext,
    /// Browser does not expose the Web Locks API needed to prevent concurrent-tab corruption.
    LocksUnavailable,
    /// Browser storage (IndexedDB) could not be opened.
    StorageUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Loading,
    /// No vault in this browser yet.
    Create,
    Locked,
    Unlocked,
    /// Another tab has the vault open.
    Elsewhere,
    /// Storage or Web Locks failed, so whether a vault is here is unknown; the cause and error.
    Unavailable(UnavailableReason, String),
}

/// How the last sync went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    Connecting,
    Synced(u64),
    Offline(String),
}

/// Server post-quantum capability status discovered via `GetServerInfo` with expected-audience check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(any(feature = "ml-kem-1024", feature = "ml-kem-768")),
    allow(dead_code)
)]
pub enum ServerPqStatus {
    /// Not queried yet (or classical-only build).
    Unknown,
    /// Server verified expected audience and advertises post-quantum routes enabled.
    Enabled {
        suites: Vec<PqSuite>,
        pq_ratchet: bool,
    },
    /// Server explicitly reported `pq_enabled = false` or returned `Unimplemented`.
    Disabled,
    /// Server's `server_id` did not match the client's locally configured expected audience.
    AudienceMismatch,
}

/// This client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Me {
    pub name: String,
    pub key: PublicKey,
    pub server: String,
    pub pq_config: PqConfig,
    pub server_pq: ServerPqStatus,
}

/// Hashable view of an active session's cryptographic security level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SecurityView {
    pub is_pq: bool,
    /// Wire suite ID (`1` = ML-KEM-1024, `2` = ML-KEM-768) when `is_pq` is `true`.
    pub suite: Option<u8>,
    pub pq_ratchet: bool,
}

impl SecurityView {
    pub fn from_session(security: SessionSecurity) -> Self {
        Self {
            is_pq: security.is_pq,
            suite: security.suite.map(PqSuite::as_u8),
            pq_ratchet: security.pq_ratchet,
        }
    }

    pub fn suite_name(self) -> &'static str {
        match self.suite.and_then(PqSuite::from_u8) {
            Some(PqSuite::MlKem1024) => "ML-KEM-1024",
            Some(PqSuite::MlKem768) => "ML-KEM-768",
            None => "Classical",
        }
    }

    /// Short badge label for the chat header (e.g. `PQ · ML-KEM-1024 + Ratchet` or `Classical only`).
    pub fn badge_label(self) -> String {
        if !self.is_pq {
            "Classical only".to_string()
        } else if self.pq_ratchet {
            format!("PQ · {} + Ratchet", self.suite_name())
        } else {
            format!("PQ · {}", self.suite_name())
        }
    }

    /// Detailed description for tooltips and `ContactInfo`.
    pub fn detail_label(self) -> String {
        if !self.is_pq {
            "Classical X3DH + Double Ratchet (not quantum-resistant)".to_string()
        } else if self.pq_ratchet {
            format!("Quantum-resistant · {} + PQ Ratchet", self.suite_name())
        } else {
            format!("Quantum-resistant · {}", self.suite_name())
        }
    }
}

/// Per-contact security alert displayed as an actionable banner / badge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SecurityAlert {
    #[default]
    None,
    DowngradeDetected,
    ManifestExpired,
    PqRequired,
}

/// Actionable classical-fallback approval prompt for a contact.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ClassicalPrompt {
    #[default]
    None,
    /// Outbound initiation or session renewal requires explicit classical approval.
    Outbound { peer_signed_off: bool },
    /// Inbound classical initial message is held in quarantine pending explicit approval.
    InboundQuarantined { peer_was_pq_pinned: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContactView {
    pub peer: PublicKey,
    pub name: String,
    /// The peer started the chat, and it is not accepted yet.
    pub request: bool,
    /// The name the peer gave in its greeting.
    pub hello_name: String,
    pub unread: u32,
    pub last_activity: u64,
    /// Active session cryptographic security level.
    pub security: SecurityView,
    pub has_active_session: bool,
    pub pq_pinned: bool,
    pub peer_pq_capable: bool,
    pub allow_classical_exception: bool,
    pub downgrade_detected: bool,
    pub alert: SecurityAlert,
    pub classical_prompt: ClassicalPrompt,
}

impl ContactView {
    /// The name, or the key's first bytes for a peer without one yet.
    pub fn label(&self) -> String {
        if self.name.is_empty() {
            short(&self.peer)
        } else {
            self.name.clone()
        }
    }

    /// Whether a downgrade alarm is active for this contact.
    pub fn has_downgrade(&self) -> bool {
        self.downgrade_detected || self.alert == SecurityAlert::DowngradeDetected
    }

    /// Whether an inbound classical initial message is held in quarantine.
    pub fn is_quarantined(&self) -> bool {
        matches!(
            self.classical_prompt,
            ClassicalPrompt::InboundQuarantined { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MessageView {
    /// Its entry in the history.
    pub index: u64,
    /// Its place in the chat, its Lamport clock, which both sides show it by; 0 if it has none
    /// yet, as it waits to be pushed.
    pub place: u64,
    pub outgoing: bool,
    pub at: u64,
    pub body: Body,
    pub delivery: Delivery,
}

/// Put `messages`, of the chat between `me` and `peer`, in its order, the same on both sides: by
/// place, then by sender, the one with the lower identity key first. One with no place yet, as
/// it waits to be pushed, goes last, in the order it was sent.
pub fn order(messages: &mut [MessageView], me: &PublicKey, peer: &PublicKey) {
    let mine_first = me < peer;
    messages.sort_by_key(|message| {
        (
            message.place == 0,
            message.place,
            message.outgoing != mine_first,
            message.index,
        )
    });
}

/// How far a message got: one received, or one this client sent, which goes from pending on,
/// one [`Step`] at a time. Kept in the history as a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, prost::Enumeration)]
#[repr(i32)]
pub enum Delivery {
    Received = 0,
    /// Waiting to be pushed: it has no place in the chat yet.
    Pending = 1,
    /// The server has it: one tick.
    Sent = 2,
    /// The peer read it: two ticks.
    Read = 3,
    /// The peer downloaded its attachment whole, having read it.
    Downloaded = 4,
    /// It could not be pushed, e.g. it is too large.
    Failed = 5,
}

/// What happens to a message this client sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The server took it.
    Pushed,
    /// The server refused it for good, or there is no session to send it on.
    Refused,
    /// The peer says it read it, ...
    Read,
    /// ... or downloaded its attachment.
    Downloaded,
    /// The peer deleted the chat without reading it: it goes again, on a new session.
    Resent,
}

impl Delivery {
    /// The delivery after `step`. What the peer tells only moves a message on, so a step told
    /// twice, or late, changes nothing; only the peer deleting the chat unread moves it back,
    /// to go again.
    pub fn after(self, step: Step) -> Self {
        match (self, step) {
            (Self::Pending, Step::Pushed) => Self::Sent,
            (Self::Pending, Step::Refused) => Self::Failed,
            // Pushed already, though its reply was lost.
            (Self::Pending | Self::Sent, Step::Read) => Self::Read,
            (Self::Pending | Self::Sent | Self::Read, Step::Downloaded) => Self::Downloaded,
            (Self::Sent, Step::Resent) => Self::Pending,
            (delivery, _) => delivery,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    Text(String),
    /// A file sent in its message, whose bytes are kept apart, read when shown.
    File(LocalFile),
    /// A file sent as an attachment, which opening fetches unless it is kept here already.
    Remote(RemoteFile),
    /// A greeting, which starts a session; the name the sender goes by.
    Hello(String),
    /// The peer deleted the chat.
    Deleted,
    /// A message arrived too late and its skipped ratchet decryption key was evicted.
    Evicted,
    /// A kind of message this client cannot show.
    Unknown,
}

/// An upload of an attachment to `peer`, as shown in their chat.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UploadView {
    pub peer: PublicKey,
    pub id: [u8; 16],
    pub name: String,
    /// Bytes of the file the server has, or that are on their way, of `size`.
    pub done: u64,
    pub size: u64,
    pub state: UploadState,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UploadState {
    Running,
    /// Verifying the chosen file's hash before resuming so encrypted chunks cannot reuse a nonce.
    Checking,
    /// The server cannot be reached; it goes on once it can.
    Retrying,
    /// Stopped, for this reason; going on may need the file chosen again.
    Paused(String),
}

/// An attachment in the chat with `peer`.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteFile {
    pub peer: PublicKey,
    /// Its entry in the history.
    pub index: u64,
    pub pointer: AttachmentPointer,
    /// The clock of the message the peer sent it in, to tell the peer once it is downloaded;
    /// 0 for this client's own.
    pub clock: u64,
}

/// An attachment being opened: fetched, unless kept here, and decrypted, a chunk at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opening {
    pub id: [u8; 16],
    pub name: String,
    pub size: u64,
    /// How many of its bytes are decrypted.
    pub done: u64,
    /// Whether it waits for its sender to upload the rest.
    pub waiting: bool,
}

/// A file of a chat's history, which [`Engine::file`](crate::engine::Engine::file) reads.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalFile {
    pub peer: PublicKey,
    /// Its entry in the history.
    pub index: u64,
    pub name: String,
    /// The MIME type the sender gave; only a hint.
    pub mime: String,
    pub size: u64,
    /// The MIME type its first bytes show, if it is an image, a video or audio, which shows in
    /// place.
    pub media: Option<String>,
    /// Its bytes, if they are here already, as it was just sent or received.
    pub data: Option<Attachment>,
}

/// A file sent or received.
#[derive(Clone)]
pub struct Attachment {
    pub name: String,
    /// The MIME type the sender gave; only a hint.
    pub mime: String,
    pub data: Arc<Vec<u8>>,
}

impl fmt::Debug for Attachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attachment")
            .field("name", &self.name)
            .field("mime", &self.mime)
            .field("size", &self.data.len())
            .finish()
    }
}

impl PartialEq for Attachment {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.data, &other.data) && self.name == other.name
    }
}

/// The dialogs besides the vault's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dialog {
    /// Start a chat, with the key and name filled in, e.g. from an invitation link, which names
    /// the inviter's server if it is not the page's own and whether PQ was pinned (`&pq=1`).
    NewChat {
        key: String,
        name: String,
        server: Option<String>,
        pq_pinned: bool,
    },
    /// This client's identity key, invitation link, and name.
    Identity,
    /// Post-quantum encryption preferences and server sign-in status.
    Settings,
    /// A contact's name, key, security level, and safety number; for a request, accept or delete it.
    Contact(PublicKey),
    /// The files of the chat with a peer.
    Files(PublicKey),
    /// Sign in to the server, which keeps files only for those who do.
    SignIn,
    /// Recent activity log (reachable on narrow mobile viewports where `Welcome` is hidden).
    Activity,
}

/// A pending "New chat" / invitation draft preserved while the user signs in to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingNewChat {
    pub key: String,
    pub name: String,
    pub server: Option<String>,
    pub pq_pinned: bool,
    pub allow_classical: bool,
    /// `true` when the user already clicked Start in `NewChat` and hit `SignInRequired`
    /// (so signing in automatically resumes starting the chat); `false` when sign-in preempted
    /// an opened invitation before submission (so signing in reopens `NewChat` prefilled).
    pub auto_start: bool,
}

impl PendingNewChat {
    pub fn from_dialog(dialog: &Dialog, allow_classical: bool, auto_start: bool) -> Option<Self> {
        match dialog {
            Dialog::NewChat {
                key,
                name,
                server,
                pq_pinned,
            } => Some(Self {
                key: key.clone(),
                name: name.clone(),
                server: server.clone(),
                pq_pinned: *pq_pinned,
                allow_classical,
                auto_start,
            }),
            _ => None,
        }
    }

    pub fn into_dialog(self) -> Dialog {
        Dialog::NewChat {
            key: self.key,
            name: self.name,
            server: self.server,
            pq_pinned: self.pq_pinned,
        }
    }
}

/// What the UI should do immediately after `Engine::sign_in` succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInSuccessAction {
    /// No pending chat draft; close the sign-in dialog.
    Close,
    /// Proactive sign-in interrupted an invitation before submission: reopen `NewChat` prefilled.
    ReopenNewChat(Dialog),
    /// User submitted `NewChat` before signing in: automatically resume starting the chat.
    AutoStartChat(PendingNewChat),
}

/// Pure state machine coordinating server sign-in prompts with invitation / `NewChat` drafts so
/// signing in or cancelling never loses a parsed invitation link or typed inputs.
#[derive(Debug, Default)]
pub struct SignInFlow {
    /// Whether the user put off signing in, so background sync refusals do not interrupt again
    /// until the user explicitly initiates an action or signs in.
    declined_sign_in: bool,
    /// Live inputs of a currently mounted `NewChat` dialog, kept up to date as the user types.
    active_new_chat: Option<PendingNewChat>,
    /// Draft of an in-flight `NewChat` submission, so concurrent transport `403` hooks preserve
    /// `auto_start: true` and `allow_classical`.
    submitting_new_chat: Option<PendingNewChat>,
    /// Preserved invitation / `NewChat` draft waiting behind `Dialog::SignIn`.
    pending_new_chat: Option<PendingNewChat>,
}

impl SignInFlow {
    /// Decide the initial dialog when the vault unlocks with an invitation link.
    ///
    /// `signed_in` is `Some(false)` when `/auth` confirmed the browser is not signed in,
    /// `Some(true)` when already signed in, and `None` when unknown/unreachable/cross-origin.
    pub fn on_unlock_with_invitation(
        &mut self,
        dialog: Dialog,
        can_sign_in_here: bool,
        signed_in: Option<bool>,
    ) -> Dialog {
        if can_sign_in_here
            && signed_in == Some(false)
            && let Some(pending) = PendingNewChat::from_dialog(&dialog, false, false)
        {
            self.pending_new_chat = Some(pending);
            return Dialog::SignIn;
        }
        dialog
    }

    /// Record a mounted `NewChat` dialog's initial values.
    pub fn on_new_chat_mounted(
        &mut self,
        key: String,
        name: String,
        server: Option<String>,
        pq_pinned: bool,
    ) {
        self.active_new_chat = Some(PendingNewChat {
            key,
            name,
            server,
            pq_pinned,
            allow_classical: false,
            auto_start: false,
        });
    }

    /// Keep the live `NewChat` draft in sync as the user edits inputs.
    pub fn on_new_chat_edited(&mut self, key: String, name: String) {
        if let Some(active) = &mut self.active_new_chat {
            active.key = key;
            active.name = name;
        }
    }

    /// Clear the mounted `NewChat` live draft when the dialog unmounts.
    pub fn on_new_chat_unmounted(&mut self) {
        self.active_new_chat = None;
    }

    /// Mark that the user submitted `NewChat` (`Start` or `Allow classical`).
    pub fn begin_new_chat_submit(&mut self, mut draft: PendingNewChat) {
        draft.auto_start = true;
        self.submitting_new_chat = Some(draft);
    }

    /// Clear the in-flight `NewChat` submission marker.
    pub fn end_new_chat_submit(&mut self) {
        self.submitting_new_chat = None;
    }

    /// Handle a server sign-in prompt (from background sync/transport when `background` is `true`,
    /// or from an explicit user action like sending a message/attachment when `background` is
    /// `false`).
    ///
    /// Returns `Some(Dialog::SignIn)` when the active dialog should switch to `SignIn`.
    pub fn on_ask_sign_in(
        &mut self,
        current_dialog: Option<&Dialog>,
        can_sign_in_here: bool,
        background: bool,
    ) -> Option<Dialog> {
        if !can_sign_in_here {
            return None;
        }
        if background && self.declined_sign_in {
            return None;
        }
        match current_dialog {
            None => Some(Dialog::SignIn),
            Some(Dialog::SignIn) => {
                if let Some(submitting) = self.submitting_new_chat.clone() {
                    self.pending_new_chat = Some(submitting);
                }
                None
            }
            Some(dialog @ Dialog::NewChat { .. }) => {
                let preserved = self
                    .submitting_new_chat
                    .clone()
                    .or_else(|| self.active_new_chat.clone())
                    .or_else(|| PendingNewChat::from_dialog(dialog, false, false));
                if let Some(draft) = preserved {
                    self.pending_new_chat = Some(draft);
                }
                Some(Dialog::SignIn)
            }
            Some(
                Dialog::Identity
                | Dialog::Settings
                | Dialog::Contact(_)
                | Dialog::Files(_)
                | Dialog::Activity,
            ) => None,
        }
    }

    /// Handle `start_chat` returning `SignInRequired` after the user explicitly submitted
    /// `NewChat`: always preserve the draft with `auto_start: true` and present `SignIn`, even if
    /// the user had previously declined sign-in.
    pub fn on_start_chat_sign_in_required(&mut self, mut draft: PendingNewChat) -> Dialog {
        self.submitting_new_chat = None;
        draft.auto_start = true;
        self.pending_new_chat = Some(draft);
        Dialog::SignIn
    }

    /// Clear any pending `NewChat` draft when the chat was already created and persisted, and only
    /// sending its initial greeting hit `SignInRequired`.
    pub fn on_chat_created_greeting_needs_sign_in(&mut self) -> Dialog {
        self.submitting_new_chat = None;
        self.pending_new_chat = None;
        Dialog::SignIn
    }

    /// Clear the declined flag once sign-in succeeds.
    pub fn reset_declined(&mut self) {
        self.declined_sign_in = false;
    }

    /// Decide the next action after sign-in succeeds.
    ///
    /// For `auto_start == true`, keeps `pending_new_chat` in place until `start_chat` finishes so
    /// the invitation cannot be lost if `start_chat` fails or is interrupted.
    pub fn on_sign_in_succeeded(&mut self) -> SignInSuccessAction {
        self.declined_sign_in = false;
        match &self.pending_new_chat {
            None => SignInSuccessAction::Close,
            Some(pending) if pending.auto_start => {
                SignInSuccessAction::AutoStartChat(pending.clone())
            }
            Some(_) => {
                let pending = self.pending_new_chat.take().expect("checked Some");
                SignInSuccessAction::ReopenNewChat(pending.into_dialog())
            }
        }
    }

    /// Complete an `AutoStartChat` attempt after sign-in.
    ///
    /// - `succeeded == true`: clears `pending_new_chat` and returns `(true, None)` if it was still
    ///   pending (so the caller should close `SignInDialog`), or `(false, None)` if it had already
    ///   been cleared (e.g. greeting hit `SignInRequired` after persisting the chat).
    /// - `still_needs_sign_in == true`: preserves `pending_new_chat` and keeps `SignInDialog`.
    /// - Otherwise (e.g. `ClassicalApprovalRequired` or another error): takes `pending_new_chat`
    ///   and returns `(false, Some(Dialog::NewChat { .. }))` to reopen `NewChat` prefilled.
    pub fn on_auto_start_finished(
        &mut self,
        succeeded: bool,
        still_needs_sign_in: bool,
    ) -> (bool, Option<Dialog>) {
        if succeeded {
            let had_pending = self.pending_new_chat.take().is_some();
            return (had_pending, None);
        }
        if still_needs_sign_in {
            return (false, None);
        }
        let reopened = self.pending_new_chat.take().map(PendingNewChat::into_dialog);
        (false, reopened)
    }

    /// Handle cancelling / dismissing `SignInDialog` ("Not now" or Escape).
    ///
    /// Marks sign-in as declined for background syncs and returns `Some(Dialog::NewChat { .. })`
    /// if a preserved invitation/draft should be restored immediately.
    pub fn on_dismiss_sign_in(&mut self) -> Option<Dialog> {
        self.declined_sign_in = true;
        self.pending_new_chat.take().map(PendingNewChat::into_dialog)
    }

    /// Hint metadata for `SignInDialog`: `Some((auto_start, has_key))` when a `NewChat` draft is
    /// waiting behind sign-in.
    pub fn pending_new_chat_hint(&self) -> Option<(bool, bool)> {
        self.pending_new_chat
            .as_ref()
            .map(|pending| (pending.auto_start, !pending.key.trim().is_empty()))
    }
}

/// Who this browser is signed in to its server as, which storing files there takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignIn {
    /// Who: `password`, for the server's password.
    pub subject: String,
    /// When it expires, in milliseconds since the Unix epoch.
    pub expires: u64,
}

impl SignIn {
    /// The sign-in the server's answer `json` names, if any.
    pub fn from_json(json: &str) -> Option<Self> {
        let answer: serde_json::Value = serde_json::from_str(json).ok()?;
        Some(Self {
            subject: answer.get("subject")?.as_str()?.to_string(),
            expires: answer.get("expires")?.as_u64()?,
        })
    }
}

/// A file of a chat, as its file browser lists it.
#[derive(Debug, Clone, PartialEq)]
pub struct FileView {
    /// Its message's entry in the history.
    pub index: u64,
    /// When it was sent or received.
    pub at: u64,
    pub outgoing: bool,
    /// Whether it can be deleted from the server, as an attachment there, sent or received,
    /// which either peer may delete.
    pub deletable: bool,
    /// Whether it is an attachment no longer on the server, as this client deleted it, or it
    /// expired; what is kept here of it still opens.
    pub gone: bool,
    pub name: String,
    pub size: u64,
    pub sort: Sort,
    /// What opens it: a [`Body::File`] or a [`Body::Remote`].
    pub body: Body,
}

#[derive(Debug, Clone, Copy)]
pub struct Ui {
    pub phase: RwSignal<Phase>,
    pub link: RwSignal<Link>,
    /// A sync asked for on the page, until a round that started after it ends.
    pub syncing: RwSignal<bool>,
    /// Notifications come over the server's WebSocket, so the client rarely polls.
    pub live: RwSignal<bool>,
    /// The user is away, so the client neither listens nor polls but rarely.
    pub away: RwSignal<bool>,
    /// The attachments being uploaded, or paused.
    pub uploads: RwSignal<Vec<UploadView>>,
    /// The messages held until this browser signs in to the server, by chat and history entry,
    /// which can be cancelled.
    pub held: RwSignal<HashSet<(PublicKey, u64)>>,
    /// Attachments known to be gone from the server during this session, by chat and history entry,
    /// so open file browsers reflect 404s, cancellations, and deletions immediately.
    pub gone: RwSignal<HashSet<(PublicKey, u64)>>,
    pub me: RwSignal<Option<Me>>,
    pub contacts: RwSignal<Vec<ContactView>>,
    /// The chat on screen, if any.
    pub open: RwSignal<Option<PublicKey>>,
    /// The messages of the chat on screen.
    pub messages: RwSignal<Vec<MessageView>>,
    /// What happened, and when, for the activity list.
    pub log: RwSignal<Vec<(u64, String)>>,
    /// A message for the notice, and its number, so that a newer one is not hidden early.
    pub notice: RwSignal<Option<(u64, String)>>,
    pub dialog: RwSignal<Option<Dialog>>,
    /// The file in the viewer, ...
    pub viewer: RwSignal<Option<Attachment>>,
    /// ... or the attachment it waits for, until it is opened, ...
    pub opening: RwSignal<Option<Opening>>,
    /// ... or the video or audio attachment playing in it as it is fetched.
    pub streaming: RwSignal<Option<Streamed>>,
}

/// A video or audio attachment playing as it is fetched, from the URL of its stream, see
/// [`Engine::stream`](crate::engine::Engine::stream).
#[derive(Debug, Clone, PartialEq)]
pub struct Streamed {
    pub url: String,
    pub remote: RemoteFile,
    pub video: bool,
}

impl Ui {
    pub fn new() -> Self {
        Self {
            phase: RwSignal::new(Phase::Loading),
            link: RwSignal::new(Link::Connecting),
            syncing: RwSignal::new(false),
            live: RwSignal::new(false),
            away: RwSignal::new(false),
            uploads: RwSignal::new(vec![]),
            held: RwSignal::new(HashSet::new()),
            gone: RwSignal::new(HashSet::new()),
            me: RwSignal::new(None),
            contacts: RwSignal::new(vec![]),
            open: RwSignal::new(None),
            messages: RwSignal::new(vec![]),
            log: RwSignal::new(vec![]),
            notice: RwSignal::new(None),
            dialog: RwSignal::new(None),
            viewer: RwSignal::new(None),
            opening: RwSignal::new(None),
            streaming: RwSignal::new(None),
        }
    }

    /// Show `text` in the notice for a few seconds.
    pub fn notify(&self, text: impl Into<String>) {
        let id = now();
        self.notice.set(Some((id, text.into())));
        let notice = self.notice;
        set_timeout(
            move || {
                if notice.with_untracked(|notice| notice.as_ref().is_some_and(|(n, _)| *n == id)) {
                    notice.set(None);
                }
            },
            Duration::from_secs(6),
        );
    }

    /// Add `text` to the activity list.
    pub fn log(&self, text: impl Into<String>) {
        let line = (now(), text.into());
        self.log.update(|log| {
            log.push(line);
            // Recent activity, not a history.
            if log.len() > 100 {
                log.remove(0);
            }
        });
    }

    /// The contact `peer`, as shown.
    pub fn contact(&self, peer: &PublicKey) -> Option<ContactView> {
        self.contacts
            .with(|contacts| contacts.iter().find(|c| c.peer == *peer).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliveries_only_move_on() {
        use Delivery::*;
        let steps = |steps: &[Step]| {
            steps
                .iter()
                .fold(Pending, |delivery, step| delivery.after(*step))
        };
        assert_eq!(steps(&[Step::Pushed]), Sent);
        assert_eq!(steps(&[Step::Pushed, Step::Read]), Read);
        assert_eq!(
            steps(&[Step::Pushed, Step::Read, Step::Downloaded]),
            Downloaded
        );
        // Told late, or twice.
        assert_eq!(
            steps(&[Step::Pushed, Step::Downloaded, Step::Read]),
            Downloaded
        );
        assert_eq!(steps(&[Step::Pushed, Step::Read, Step::Pushed]), Read);
        // Read, though its push seemed to fail.
        assert_eq!(steps(&[Step::Read, Step::Pushed]), Read);
        assert_eq!(steps(&[Step::Refused]), Failed);
        // Unread when the peer deleted the chat, it goes again; read, it stays.
        assert_eq!(steps(&[Step::Pushed, Step::Resent]), Pending);
        assert_eq!(steps(&[Step::Pushed, Step::Read, Step::Resent]), Read);
        assert_eq!(Received.after(Step::Read), Received);
    }

    #[test]
    fn both_sides_show_one_order() {
        let (alice, bob) = ([1; 32], [2; 32]);
        let view = |index, place, outgoing, delivery| MessageView {
            index,
            place,
            outgoing,
            at: 0,
            body: Body::Unknown,
            delivery,
        };
        // Alice's: hers at 1 and 2, written at once with Bob's at 2, and one waiting.
        let mut alice_sees = vec![
            view(0, 1, true, Delivery::Sent),
            view(1, 0, true, Delivery::Pending),
            view(2, 2, true, Delivery::Read),
            view(3, 2, false, Delivery::Received),
            view(4, 3, false, Delivery::Received),
        ];
        order(&mut alice_sees, &alice, &bob);
        let places: Vec<_> = alice_sees.iter().map(|m| (m.place, m.outgoing)).collect();
        assert_eq!(
            places,
            [(1, true), (2, true), (2, false), (3, false), (0, true)]
        );
        // Bob's, which came in another order: at 2, Alice's goes first, as her key is lower.
        let mut bob_sees = vec![
            view(0, 2, true, Delivery::Sent),
            view(1, 1, false, Delivery::Received),
            view(2, 3, true, Delivery::Sent),
            view(3, 2, false, Delivery::Received),
        ];
        order(&mut bob_sees, &bob, &alice);
        let places: Vec<_> = bob_sees.iter().map(|m| (m.place, m.outgoing)).collect();
        assert_eq!(places, [(1, false), (2, false), (2, true), (3, true)]);
    }

    #[test]
    fn pq_config_defaults_match_compiled_features() {
        let cfg = PqConfig::default();
        let compiled = PqConfig::compiled_suites();
        #[cfg(feature = "ml-kem-1024")]
        {
            assert!(cfg.pq_enabled);
            assert!(cfg.pq_ratchet_enabled);
            assert!(!cfg.strict_pq);
            assert_eq!(cfg.preferred_suite, PqSuite::MlKem1024);
            assert!(compiled.contains(&PqSuite::MlKem1024));
        }
        #[cfg(all(feature = "ml-kem-768", not(feature = "ml-kem-1024")))]
        {
            assert!(cfg.pq_enabled);
            assert!(cfg.pq_ratchet_enabled);
            assert!(!cfg.strict_pq);
            assert_eq!(cfg.preferred_suite, PqSuite::MlKem768);
            assert_eq!(compiled, vec![PqSuite::MlKem768]);
        }
        #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
        {
            assert!(!cfg.pq_enabled);
            assert!(!cfg.pq_ratchet_enabled);
            assert!(!cfg.strict_pq);
            assert!(compiled.is_empty());
            assert!(cfg.offered_suites().is_empty());
        }
    }

    #[test]
    fn sign_in_flow_case_a_proactive_unlock_preserves_invitation_across_sign_in_and_cancel() {
        let invite = Dialog::NewChat {
            key: "peer-key-123".to_string(),
            name: "Alice".to_string(),
            server: Some("https://relay.example".to_string()),
            pq_pinned: true,
        };

        // Proactive `/auth` detection on unlock: opens SignIn without losing the invitation.
        let mut flow = SignInFlow::default();
        assert_eq!(
            flow.on_unlock_with_invitation(invite.clone(), true, Some(false)),
            Dialog::SignIn
        );
        assert_eq!(flow.pending_new_chat_hint(), Some((false, true)));

        // Signing in automatically reopens NewChat prefilled with all invitation fields intact.
        assert_eq!(
            flow.on_sign_in_succeeded(),
            SignInSuccessAction::ReopenNewChat(invite.clone())
        );
        assert_eq!(flow.pending_new_chat_hint(), None);

        // A later sign-in with no pending invitation simply closes the dialog.
        assert_eq!(flow.on_sign_in_succeeded(), SignInSuccessAction::Close);

        // Cancelling proactive SignIn restores NewChat intact and silences background prompts.
        let mut flow = SignInFlow::default();
        assert_eq!(
            flow.on_unlock_with_invitation(invite.clone(), true, Some(false)),
            Dialog::SignIn
        );
        assert_eq!(flow.on_dismiss_sign_in(), Some(invite.clone()));
        assert_eq!(flow.pending_new_chat_hint(), None);
        assert_eq!(flow.on_ask_sign_in(Some(&invite), true, true), None);

        // Already signed in or cross-origin opens NewChat directly without prompting SignIn.
        let mut flow = SignInFlow::default();
        assert_eq!(
            flow.on_unlock_with_invitation(invite.clone(), true, Some(true)),
            invite
        );
        assert_eq!(
            flow.on_unlock_with_invitation(invite.clone(), false, Some(false)),
            invite
        );
    }

    #[test]
    fn sign_in_flow_case_a_background_publish_preempts_new_chat_preserving_live_edits() {
        let initial = Dialog::NewChat {
            key: "peer-key-123".to_string(),
            name: "Alice".to_string(),
            server: None,
            pq_pinned: true,
        };
        let mut flow = SignInFlow::default();
        flow.on_new_chat_mounted("peer-key-123".into(), "Alice".into(), None, true);
        // User edits the peer's display name before background `publish()` returns 403.
        flow.on_new_chat_edited("peer-key-123".into(), "Alice Work".into());

        // Background refusal switches cleanly to SignIn while capturing the edited draft.
        assert_eq!(
            flow.on_ask_sign_in(Some(&initial), true, true),
            Some(Dialog::SignIn)
        );
        flow.on_new_chat_unmounted();

        // After signing in, NewChat reopens with the edited name and `pq_pinned: true` intact.
        assert_eq!(
            flow.on_sign_in_succeeded(),
            SignInSuccessAction::ReopenNewChat(Dialog::NewChat {
                key: "peer-key-123".into(),
                name: "Alice Work".into(),
                server: None,
                pq_pinned: true,
            })
        );

        // Other dialogs (Identity, Settings, Contact, Files) are never hijacked by background refusals.
        assert_eq!(flow.on_ask_sign_in(Some(&Dialog::Identity), true, true), None);
        assert_eq!(flow.on_ask_sign_in(Some(&Dialog::Settings), true, true), None);
        // Cross-origin vaults never show SignInDialog.
        assert_eq!(flow.on_ask_sign_in(Some(&initial), false, true), None);
    }

    #[test]
    fn sign_in_flow_case_b_submitting_new_chat_resumes_auto_start_and_handles_cancel_or_error() {
        let draft = PendingNewChat {
            key: "peer-key-456".to_string(),
            name: "Bob".to_string(),
            server: Some("https://chat.example".to_string()),
            pq_pinned: true,
            allow_classical: false,
            auto_start: false,
        };
        let open_dialog = draft.clone().into_dialog();

        // Even after dismissing an earlier proactive sign-in prompt, clicking Start still opens
        // SignInDialog and preserves the draft with `auto_start: true`.
        let mut flow = SignInFlow::default();
        assert_eq!(flow.on_dismiss_sign_in(), None);
        flow.begin_new_chat_submit(draft.clone());

        // If `transport` fires `refused_for_sign_in` concurrently while `start_chat` is in flight,
        // `auto_start: true` is preserved (not downgraded to `false`).
        let mut flow_race = SignInFlow::default();
        flow_race.begin_new_chat_submit(PendingNewChat {
            allow_classical: true,
            ..draft.clone()
        });
        assert_eq!(
            flow_race.on_ask_sign_in(Some(&open_dialog), true, true),
            Some(Dialog::SignIn)
        );
        assert_eq!(flow_race.pending_new_chat_hint(), Some((true, true)));
        assert_eq!(
            flow_race.on_sign_in_succeeded(),
            SignInSuccessAction::AutoStartChat(PendingNewChat {
                allow_classical: true,
                auto_start: true,
                ..draft.clone()
            })
        );

        // Explicit `start_chat` SignInRequired works even when `declined_sign_in == true`.
        assert_eq!(flow.on_start_chat_sign_in_required(draft.clone()), Dialog::SignIn);
        assert_eq!(flow.pending_new_chat_hint(), Some((true, true)));

        // Sign-in succeeds -> triggers AutoStartChat while keeping draft until start_chat ends.
        let expected_auto = PendingNewChat {
            auto_start: true,
            ..draft.clone()
        };
        assert_eq!(
            flow.on_sign_in_succeeded(),
            SignInSuccessAction::AutoStartChat(expected_auto.clone())
        );

        // If start_chat still hits SignInRequired, draft stays intact for another retry.
        assert_eq!(flow.on_auto_start_finished(false, true), (false, None));
        assert_eq!(flow.pending_new_chat_hint(), Some((true, true)));

        // If start_chat needs classical approval (or another error), NewChat reopens prefilled.
        assert_eq!(
            flow.on_auto_start_finished(false, false),
            (false, Some(open_dialog.clone()))
        );
        assert_eq!(flow.pending_new_chat_hint(), None);

        // Successful AutoStartChat closes SignInDialog and clears pending state.
        assert_eq!(flow.on_start_chat_sign_in_required(draft.clone()), Dialog::SignIn);
        assert_eq!(
            flow.on_sign_in_succeeded(),
            SignInSuccessAction::AutoStartChat(expected_auto)
        );
        assert_eq!(flow.on_auto_start_finished(true, false), (true, None));
        assert_eq!(flow.pending_new_chat_hint(), None);

        // Cancelling SignInDialog in Case B restores NewChat with invitation intact.
        assert_eq!(flow.on_start_chat_sign_in_required(draft.clone()), Dialog::SignIn);
        assert_eq!(flow.on_dismiss_sign_in(), Some(open_dialog));
        assert_eq!(flow.pending_new_chat_hint(), None);

        // If chat was already persisted and only sending greeting hit SignInRequired, pending
        // NewChat is cleared so signing in does not re-open NewChat.
        flow.begin_new_chat_submit(draft);
        assert_eq!(flow.on_chat_created_greeting_needs_sign_in(), Dialog::SignIn);
        assert_eq!(flow.pending_new_chat_hint(), None);
        assert_eq!(flow.on_sign_in_succeeded(), SignInSuccessAction::Close);
    }
}
