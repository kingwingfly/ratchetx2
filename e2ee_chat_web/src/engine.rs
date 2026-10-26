//! The client: the vault, the identity and the sessions, and what the page asks of them.
//!
//! The engine keeps the state; the page only shows the [`Ui`] signals that the engine updates.
//! One lock orders everything that changes the state, so that the sync loop and the page take
//! turns, and every change is saved before it shows.

use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet, VecDeque},
    rc::Rc,
    sync::Arc,
};

use futures::{
    future::{Either, select},
    lock::Mutex,
};
use leptos::{prelude::*, task::spawn_local};
use session::{
    Client, ClientState, ErrorKind, PublicKey, Session, SessionState,
    attachment::{self, CHUNK_SIZE, Upload},
    proto,
    protocol::{
        attachment::DEFAULT_MAX_CHUNKS,
        notify::{self, Notification},
    },
};
use sha2::{Digest, Sha256};
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

use crate::{
    content::{self, AttachmentPointer, Content, Hello, Kind, image_type},
    notify::{Event, Subscription},
    state::{
        Attachment, Body, ContactView, Delivery, Dialog, Link, Me, MessageView, Opening, Phase,
        RemoteFile, Ui, UploadState, UploadView,
    },
    transport::{Connect, Fetch},
    util::{describe, js_error, key_from_text, now, short, size, sleep},
    vault::{AppState, ContactState, HistoryEntry, Outgoing, PendingUpload, Vault, history_key},
};

/// One-time prekeys in each publish.
const ONE_TIME_PREKEYS: usize = 20;
/// Publish new prekeys once this many one-time prekeys are used...
const REPUBLISH_USED: u32 = 10;
/// ... or the signed prekey is this old, in milliseconds.
const REPUBLISH_AGE: u64 = 7 * 24 * 60 * 60 * 1000;
/// Files up to this many bytes go in their message; larger ones go as attachments.
pub const INLINE_FILE_MAX: usize = 1 << 20;
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
/// The history entries shown when a chat opens.
// TODO: these come with their files, up to 1 MiB each; load files when shown instead.
const HISTORY_SHOWN: u64 = 500;
/// Milliseconds between syncs: right after something happened, at most while idle, and while
/// the user is away, when the client has no notifications. Workers bill per request, so idle
/// pages back off, and pages left alone all but stop: the Worker and its notifiers then scale to
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

pub struct Engine {
    ui: Ui,
    inner: Mutex<Option<Inner>>,
    /// Sync now, e.g. after sending, as a reply may follow.
    wake: Cell<bool>,
    /// The files of the uploads started or resumed on this page, by attachment ID, which can go
    /// on without the files chosen again.
    files: RefCell<HashMap<[u8; 16], web_sys::File>>,
    /// The uploads going on, or being resumed.
    running: RefCell<HashSet<[u8; 16]>>,
    /// The uploads cancelled, or whose chat was deleted, on this page: those going on stop before
    /// their next chunk, and none is kept in the vault again.
    cancelled: RefCell<HashSet<[u8; 16]>>,
    /// What was sent and has yet to go, in the order it was sent, and whether a task is sending
    /// it.
    sending: RefCell<VecDeque<Sending>>,
    draining: Cell<bool>,
    /// Since when the page has been hidden or out of focus, if it is.
    away_since: Cell<Option<u64>>,
}

/// What was sent, waiting its turn to go: a message, or a file, which is read, or starts
/// uploading, first.
pub enum Sending {
    Content(PublicKey, Kind),
    File(PublicKey, web_sys::File),
}

/// The unlocked client.
struct Inner {
    vault: Vault,
    /// The server's address.
    server: String,
    /// What is saved besides the client and the contacts, which are kept below.
    state: AppState,
    client: Client<Connect>,
    contacts: Vec<Contact>,
    /// History records that a save failed to write after what they record could not be undone:
    /// initial messages, which the server deleted once taken, and the greeting of a chat started.
    /// Each save writes them too, until one succeeds, so that the history has no gap.
    unsaved: Vec<(PublicKey, (String, HistoryEntry))>,
    /// Whether a save wrote such records, whose chats then show.
    saved_late: bool,
}

struct Contact {
    peer: PublicKey,
    session: Session<Connect>,
    /// Everything but the session, which is in `session`.
    state: ContactState,
}

impl Engine {
    pub fn new(ui: Ui) -> Rc<Self> {
        Rc::new(Self {
            ui,
            inner: Mutex::new(None),
            wake: Cell::new(false),
            files: RefCell::default(),
            running: RefCell::default(),
            cancelled: RefCell::default(),
            sending: RefCell::default(),
            draining: Cell::new(false),
            away_since: Cell::new(None),
        })
    }

    /// Whether the user is here: the page shown and in focus, or hidden for less than
    /// [`HIDDEN_GRACE`], or out of focus for less than [`UNFOCUSED_GRACE`]. Notifications are
    /// for then only, as a WebSocket open keeps a notifier on the server.
    fn present(&self) -> bool {
        let document = document();
        let grace = if document.hidden() {
            Some(HIDDEN_GRACE)
        } else if !document.has_focus().unwrap_or(true) {
            Some(UNFOCUSED_GRACE)
        } else {
            None
        };
        let present = match grace {
            Some(grace) => {
                let now = now();
                let since = *self.away_since.get().get_or_insert(now);
                self.away_since.set(Some(since));
                now - since < grace
            }
            None => {
                self.away_since.set(None);
                true
            }
        };
        if self.ui.away.get_untracked() == present {
            self.ui.away.set(!present);
        }
        present
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
        let bytes = file.size() as usize;
        if bytes > MAX_FILE_SIZE {
            return Err(format!(
                "{name} is {}; files go up to {}.",
                size(bytes),
                size(MAX_FILE_SIZE)
            ));
        }
        // An upload shows how far it got above the composer.
        if bytes > INLINE_FILE_MAX {
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

    /// Find out whether to create or unlock the vault.
    pub async fn start(&self) {
        // Two tabs on one vault would fork the sessions' ratchets.
        if !crate::glue::take_lock("e2ee-chat").await {
            self.ui.phase.set(Phase::Elsewhere);
            return;
        }
        match Vault::exists().await {
            Ok(true) => self.ui.phase.set(Phase::Locked),
            Ok(false) => self.ui.phase.set(Phase::Create),
            // Offering to create one could replace a vault that is there.
            Err(e) => self.ui.phase.set(Phase::Unavailable(describe(&e))),
        }
    }

    /// Create a vault with a new identity, under `passphrase`, replacing any other.
    pub async fn create(
        self: &Rc<Self>,
        name: String,
        passphrase: String,
        server: String,
    ) -> Result<(), String> {
        let server = server.trim().trim_end_matches('/').to_string();
        // The page's own server is saved as empty, so the vault follows the page.
        let server = if server == origin() {
            String::new()
        } else {
            server
        };
        let address = address(&server);
        let client = Client::new(Fetch::client(&address));
        let state = AppState {
            client: Some(client.state().into()),
            server,
            name: checked_name(&name)?,
            ..AppState::default()
        };
        let vault = Vault::create(&passphrase, &state)
            .await
            .map_err(|e| describe(&e))?;
        self.unlocked(Inner {
            vault,
            server: address,
            state: AppState {
                client: None,
                ..state
            },
            client,
            contacts: vec![],
            unsaved: vec![],
            saved_late: false,
        })
        .await;
        Ok(())
    }

    /// Unlock the vault with `passphrase`.
    pub async fn unlock(self: &Rc<Self>, passphrase: String) -> Result<(), String> {
        let (vault, mut state) = Vault::unlock(&passphrase).await.map_err(|e| describe(&e))?;
        let address = address(&state.server);
        let client = state.client.take().ok_or("the vault has no identity")?;
        let client = Client::restore(
            Fetch::client(&address),
            ClientState::try_from(&client).map_err(|e| describe(&e))?,
        );
        let contacts = std::mem::take(&mut state.contacts)
            .into_iter()
            .map(|mut contact| {
                let peer: PublicKey = contact
                    .peer
                    .as_slice()
                    .try_into()
                    .map_err(|_| "a contact's key is malformed")?;
                let session = contact.session.take().ok_or("a contact has no session")?;
                let session = SessionState::try_from(&session).map_err(|e| describe(&e))?;
                Ok(Contact {
                    peer,
                    session: Session::restore(Fetch::client(&address), session),
                    state: contact,
                })
            })
            .collect::<Result<_, String>>()?;
        self.unlocked(Inner {
            vault,
            server: address,
            state,
            client,
            contacts,
            unsaved: vec![],
            saved_late: false,
        })
        .await;
        Ok(())
    }

    async fn unlocked(self: &Rc<Self>, inner: Inner) {
        self.ui.me.set(Some(inner.me()));
        self.ui.contacts.set(inner.views());
        // Uploads the page left: their files are gone with it.
        match inner.vault.uploads().await {
            Ok(uploads) => {
                for (peer, pending) in uploads {
                    let reason = "choose the file again to go on".to_string();
                    self.show_upload(&peer, &pending, UploadState::Paused(reason));
                }
            }
            Err(e) => self.ui.notify(describe(&e)),
        }
        *self.inner.lock().await = Some(inner);
        self.ui.phase.set(Phase::Unlocked);
        self.ui.log("vault unlocked");
        if let Some(dialog) = invitation() {
            forget_invitation();
            self.ui.dialog.set(Some(dialog));
        }
        self.clone().run();
        self.clone().listen();
    }

    /// Sync until the page goes.
    fn run(self: Rc<Self>) {
        spawn_local(async move {
            let mut delay = POLL_FAST;
            loop {
                let asked = self.ui.syncing.get_untracked();
                let active = self.sync().await;
                if asked {
                    self.ui.syncing.set(false);
                }
                delay = if self.ui.live.get_untracked() {
                    POLL_LIVE
                } else if active {
                    POLL_FAST
                } else {
                    (delay * 3 / 2).min(POLL_SLOW)
                };
                let mut waited = 0;
                let mut was_present = self.present();
                loop {
                    if self.wake.replace(false) {
                        delay = POLL_FAST;
                        break;
                    }
                    let present = self.present();
                    // Back: what came meanwhile, at once.
                    if present && !was_present {
                        delay = POLL_FAST;
                        break;
                    }
                    was_present = present;
                    if waited >= if present { delay } else { delay.max(POLL_AWAY) } {
                        break;
                    }
                    sleep(POLL_STEP).await;
                    waited += POLL_STEP;
                }
            }
        });
    }

    /// Subscribe to this client's notifications while the user is here, until the page goes,
    /// subscribing again whenever the socket closes, and act on each. Away, the socket closes,
    /// which tells the server, and opens again on coming back.
    fn listen(self: Rc<Self>) {
        spawn_local(async move {
            let mut retry = RESUBSCRIBE_MIN;
            loop {
                while !self.present() {
                    sleep(AWAY_CHECK).await;
                }
                let subscribed = {
                    let mut guard = self.inner.lock().await;
                    let Some(inner) = guard.as_mut() else {
                        return;
                    };
                    Subscription::open(&inner.server, &inner.client.subscription())
                };
                let mut left = false;
                match subscribed {
                    Ok(mut subscription) => loop {
                        let next =
                            select(Box::pin(subscription.next()), Box::pin(sleep(AWAY_CHECK)));
                        match next.await {
                            Either::Left((Event::Open, _)) => {
                                self.ui.live.set(true);
                                retry = RESUBSCRIBE_MIN;
                                // What came while it was closed has no notification.
                                self.wake();
                            }
                            Either::Left((Event::Notification(notification), _)) => {
                                self.notified(notification).await
                            }
                            Either::Left((Event::Closed, _)) => break,
                            // Away: dropped, the subscription closes its socket.
                            Either::Right(_) if !self.present() => {
                                left = true;
                                break;
                            }
                            Either::Right(_) => {}
                        }
                    },
                    Err(e) => self
                        .ui
                        .log(format!("cannot subscribe to notifications: {e}")),
                }
                self.ui.live.set(false);
                if left {
                    retry = RESUBSCRIBE_MIN;
                    continue;
                }
                sleep(retry).await;
                retry = (retry * 2).min(RESUBSCRIBE_MAX);
            }
        });
    }

    /// Fetch what `notification` says arrived; if that fails, sync soon.
    async fn notified(&self, notification: Notification) {
        let fetched = match notification.event {
            Some(notify::Event::MessageFrom(sender)) => {
                match PublicKey::try_from(sender.as_ref()) {
                    Ok(peer) => self.receive(&peer).await.map(drop),
                    Err(_) => return,
                }
            }
            Some(notify::Event::InitialMessage(_)) => self.take_initial_messages().await.map(drop),
            None => return,
        };
        if fetched.is_err() {
            self.wake();
        }
    }

    /// Sync soon.
    pub fn wake(&self) {
        self.wake.set(true);
    }

    /// Sync now, as asked on the page, showing it until done.
    pub fn sync_now(&self) {
        self.ui.syncing.set(true);
        self.wake();
    }

    /// One round: save what an earlier save failed to, push what waits, take initial messages,
    /// publish prekeys when due, and receive. Returns whether anything happened.
    async fn sync(&self) -> bool {
        // A step that keeps failing, e.g. a large file timing out over a slow link, a take of
        // initial messages the server refuses, or one chat's queue that cannot be fetched, must
        // not keep the round from the other steps and chats: its error is kept, and the round
        // goes on.
        let mut failure = None;
        let mut active = false;
        if let Err(e) = self.save_late().await {
            failure.get_or_insert(e);
        }
        for peer in self.peers().await {
            match self.flush(&peer).await {
                Ok(pushed) => active |= pushed,
                Err(e) => {
                    failure.get_or_insert(e);
                }
            }
        }
        match self.take_initial_messages().await {
            Ok(taken) => active |= taken,
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
        if let Err(e) = self.publish(false).await {
            failure.get_or_insert(e);
        }
        for peer in self.peers().await {
            match self.receive(&peer).await {
                Ok(received) => active |= received,
                Err(e) => {
                    failure.get_or_insert(e);
                }
            }
        }
        match failure {
            None => self.ui.link.set(Link::Synced(now())),
            Some(e) => self.ui.link.set(Link::Offline(e)),
        }
        active
    }

    /// Save the history records an earlier save failed to write, see `Inner::unsaved`, unless
    /// another save did, and show their chats.
    async fn save_late(&self) -> Result<(), String> {
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return Ok(());
        };
        if !inner.unsaved.is_empty() {
            inner.save(&[]).await.map_err(|e| describe(&e))?;
        }
        if std::mem::take(&mut inner.saved_late) {
            self.ui.contacts.set(inner.views());
        }
        Ok(())
    }

    async fn peers(&self) -> Vec<PublicKey> {
        let inner = self.inner.lock().await;
        inner
            .iter()
            .flat_map(|inner| inner.contacts.iter().map(|contact| contact.peer))
            .collect()
    }

    /// Push the messages waiting for `peer`, in order. Returns whether any went.
    async fn flush(&self, peer: &PublicKey) -> Result<bool, String> {
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return Ok(false);
        };
        let mut changed = false;
        let mut result = Ok(());
        while let Some(contact) = inner.contact(peer)
            && let Some(outgoing) = contact.state.outbox.first().cloned()
        {
            match contact
                .session
                .push(outgoing.message.unwrap_or_default())
                .await
            {
                Ok(()) => {}
                // Too large for the server: it never will go.
                Err(e) if e.kind() == ErrorKind::LimitExceeded => {
                    contact.state.failed.push(outgoing.history_index);
                    self.ui
                        .notify(format!("a message could not be sent: {}", describe(&e)));
                }
                Err(e) => {
                    result = Err(describe(&e));
                    break;
                }
            }
            contact.state.outbox.remove(0);
            changed = true;
        }
        if changed {
            inner.save(&[]).await.map_err(|e| describe(&e))?;
            self.show_deliveries(inner, peer);
        }
        result.map(|()| changed)
    }

    /// Take the initial messages waiting, and accept each at once, while its prekeys are kept. One
    /// whose first message does not decrypt is not from whom it claims, and is dropped. A new
    /// peer's becomes a request; a known peer's session joins the chat, see `Session::keep`.
    async fn take_initial_messages(&self) -> Result<bool, String> {
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return Ok(false);
        };
        let initial_messages = inner
            .client
            .take_initial_messages()
            .await
            .map_err(|e| describe(&e))?;
        if initial_messages.is_empty() {
            return Ok(false);
        }
        let (mut records, mut views) = (vec![], vec![]);
        let mut peers = vec![];
        for initial_message in &initial_messages {
            let peer = initial_message.x3dh.identity_key;
            let (session, first) =
                match inner
                    .client
                    .accept(&peer, initial_message, Fetch::client(&inner.server))
                {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        self.ui.log(format!(
                            "dropped an initial message claiming to be from {}: {}",
                            short(&peer),
                            describe(&e)
                        ));
                        continue;
                    }
                };
            if initial_message.x3dh.one_time_prekey.is_some() {
                inner.state.used_one_time_prekeys += 1;
            }
            let contact = match inner
                .contacts
                .iter()
                .position(|contact| contact.peer == peer)
            {
                // The peer started again, or both started at once. The old session is kept
                // only to decrypt the messages sent on it, see `Session::keep`.
                Some(index) => {
                    let contact = &mut inner.contacts[index];
                    let older = std::mem::replace(&mut contact.session, session);
                    if let Err(e) = contact.session.keep(older) {
                        self.ui.log(format!(
                            "cannot keep the earlier session with {}: {}",
                            short(&peer),
                            describe(&e)
                        ));
                    }
                    contact
                }
                None => {
                    self.ui.log(format!("chat request from {}", short(&peer)));
                    inner.contacts.push(Contact {
                        peer,
                        session,
                        state: ContactState {
                            peer: peer.to_vec(),
                            request: true,
                            ..ContactState::default()
                        },
                    });
                    inner.contacts.last_mut().expect("just pushed")
                }
            };
            let open = self.ui.open.get_untracked() == Some(peer);
            let (index, entry) = contact.add_received(&first, open && !document().hidden());
            records.push((history_key(&peer, index), entry.clone()));
            peers.push(peer);
            if open {
                views.push(contact.message(index, entry));
            }
        }
        if let Err(e) = inner.save(&records).await {
            // The server deleted them, and their sessions are accepted: they show once saved.
            inner.unsaved.extend(peers.into_iter().zip(records));
            return Err(describe(&e));
        }
        self.ui.messages.update(|messages| messages.extend(views));
        self.ui.contacts.set(inner.views());
        Ok(true)
    }

    /// Publish new prekeys if it is due, or anyway if `now`.
    pub async fn publish(&self, now_anyway: bool) -> Result<(), String> {
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return Ok(());
        };
        let due = now_anyway
            || inner.state.published_at == 0
            || inner.state.used_one_time_prekeys >= REPUBLISH_USED
            || now().saturating_sub(inner.state.published_at) > REPUBLISH_AGE;
        if !due {
            return Ok(());
        }
        // Publishing makes a new generation of prekeys, which deletes older ones; if the server
        // never got it, the client goes back, so the published prekeys stay usable.
        // TODO: if the server stored the bundle and only its reply was lost, going back loses
        // the private keys of the published prekeys, and initial messages fail until the next
        // publish; publish the same bundle again instead, which needs `session` to resend it.
        let before = proto::ClientState::from(inner.client.state());
        if let Err(e) = inner.client.publish_keys(ONE_TIME_PREKEYS).await {
            let before = ClientState::try_from(&before).map_err(|e| describe(&e))?;
            inner.client = Client::restore(Fetch::client(&inner.server), before);
            return Err(describe(&e));
        }
        inner.state.published_at = now();
        inner.state.used_one_time_prekeys = 0;
        inner.save(&[]).await.map_err(|e| describe(&e))?;
        self.ui.log(format!(
            "published a new signed prekey and {ONE_TIME_PREKEYS} one-time prekeys"
        ));
        Ok(())
    }

    /// Receive the messages from `peer`, a page at a time. Returns whether any came.
    async fn receive(&self, peer: &PublicKey) -> Result<bool, String> {
        let mut received = false;
        loop {
            let mut guard = self.inner.lock().await;
            let Some(inner) = guard.as_mut() else {
                return Ok(received);
            };
            let open = self.ui.open.get_untracked() == Some(*peer) && !document().hidden();
            let Some(contact) = inner.contact(peer) else {
                return Ok(received);
            };
            // If saving fails, the contact goes back to this, so the page is fetched again.
            let snapshot = contact.snapshot();
            let page = contact.session.receive().await.map_err(|e| describe(&e))?;
            if page.is_empty() {
                return Ok(received);
            }
            let (mut entries, mut undecryptable) = (vec![], 0);
            for result in page {
                let bytes = match result {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == ErrorKind::DuplicateMessage => continue,
                    // Anyone can push to a queue, and an earlier session's messages stay in it.
                    Err(_) => {
                        undecryptable += 1;
                        continue;
                    }
                };
                entries.push(contact.add_received(&bytes, open));
            }
            if undecryptable > 0 {
                let label = contact.view().label();
                self.ui.log(format!(
                    "skipped {undecryptable} message(s) from {label} that do not decrypt, e.g. \
                     ones of an earlier session"
                ));
            }
            let records: Vec<_> = entries
                .iter()
                .map(|(index, entry)| (history_key(peer, *index), entry.clone()))
                .collect();
            if let Err(e) = inner.save(&records).await {
                inner.roll_back(peer, snapshot)?;
                return Err(describe(&e));
            }
            received |= !entries.is_empty();
            if self.ui.open.get_untracked() == Some(*peer)
                && let Some(contact) = inner.contact(peer)
            {
                let views: Vec<_> = entries
                    .into_iter()
                    .map(|(index, entry)| contact.message(index, entry))
                    .collect();
                self.ui.messages.update(|messages| messages.extend(views));
            }
            self.ui.contacts.set(inner.views());
        }
    }

    /// Encrypt `content` for `peer`, save it, and push it. What the user sends goes through
    /// [`Engine::queue`], to go in order.
    async fn send(&self, peer: PublicKey, content: Kind) -> Result<(), String> {
        {
            let mut guard = self.inner.lock().await;
            let inner = guard.as_mut().ok_or("locked")?;
            let contact = inner.contact(&peer).ok_or("no such chat")?;
            if contact.state.request {
                return Err("accept the request first".into());
            }
            if contact.session.needs_new_session() {
                inner.start_again(&peer).await?;
            }
            let contact = inner.contact(&peer).ok_or("no such chat")?;
            // If saving fails, the message is forgotten, ratchet step and all: it never left.
            let snapshot = contact.snapshot();
            let message = contact
                .session
                .encrypt(&content.to_bytes())
                .map_err(|e| describe(&e))?;
            let index = contact.state.history_len;
            contact.state.history_len += 1;
            contact.state.last_activity = now();
            contact.state.outbox.push(Outgoing {
                message: Some(message),
                history_index: index,
            });
            let entry = HistoryEntry {
                outgoing: true,
                at: now(),
                content: Some(Content {
                    kind: Some(content),
                }),
            };
            let view = contact.message(index, entry.clone());
            if let Err(e) = inner.save(&[(history_key(&peer, index), entry)]).await {
                inner.roll_back(&peer, snapshot)?;
                return Err(describe(&e));
            }
            if self.ui.open.get_untracked() == Some(peer) {
                self.ui.messages.update(|messages| messages.push(view));
            }
            self.ui.contacts.set(inner.views());
        }
        // Saved, so it goes in a later sync if not now.
        if let Err(e) = self.flush(&peer).await {
            self.ui.link.set(Link::Offline(e));
        }
        self.wake();
        Ok(())
    }

    /// Send `peer` an attachment of `file`, then upload it: the peer can download it meanwhile,
    /// and what was sent after it goes without waiting for the upload. Its chunks are kept here
    /// too, so it opens without the server. Each chunk is read as its turn comes, and the upload
    /// is kept in the vault as it goes, so that it can go on after the page goes.
    async fn send_attachment(
        self: &Rc<Self>,
        peer: PublicKey,
        file: web_sys::File,
    ) -> Result<(), String> {
        let size = file.size() as u64;
        let upload = {
            let mut guard = self.inner.lock().await;
            let inner = guard.as_mut().ok_or("locked")?;
            inner
                .client
                .start_upload(&Fetch::client(&inner.server), size)
                .await
                .map_err(|e| describe(&e))?
        };
        let pending = PendingUpload {
            id: upload.id().to_vec(),
            token: upload.token().to_vec(),
            key: upload.key().to_vec(),
            name: file.name(),
            mime: file.type_(),
            size,
            uploaded: 0,
            encrypted: 0,
            prefix_hash: Sha256::digest([]).to_vec(),
            announced: false,
        };
        self.save_upload(&peer, &pending).await?;
        self.files.borrow_mut().insert(*upload.id(), file.clone());
        let pending = self.announce(&peer, pending).await?;
        // A new upload, which nothing else runs.
        self.running.borrow_mut().insert(*upload.id());
        let engine = self.clone();
        spawn_local(async move {
            if let Err(e) = engine.run_upload(peer, pending, file, Sha256::new()).await {
                engine.ui.notify(e);
            }
        });
        Ok(())
    }

    /// Send the attachment of `pending` to `peer`, unless sent already, and keep that it was.
    async fn announce(
        &self,
        peer: &PublicKey,
        mut pending: PendingUpload,
    ) -> Result<PendingUpload, String> {
        if pending.announced {
            return Ok(pending);
        }
        let pointer = AttachmentPointer {
            id: pending.id.clone(),
            key: pending.key.clone(),
            size: pending.size,
            name: pending.name.clone(),
            mime: pending.mime.clone(),
        };
        // Sent first, then kept: going wrong in between sends it twice, not never.
        self.send(*peer, Kind::Attachment(pointer)).await?;
        pending.announced = true;
        self.save_upload(peer, &pending).await?;
        Ok(pending)
    }

    /// Whether the file of the upload `id` is still here, so that it can go on without the file
    /// chosen again.
    pub fn has_file(&self, id: &[u8; 16]) -> bool {
        self.files.borrow().contains_key(id)
    }

    /// Go on with the upload `id`, in the chat with `peer`: with `file`, chosen again, or else
    /// with the file still here. The file must begin as it did, as far as it may have been
    /// encrypted.
    pub async fn resume_upload(
        &self,
        peer: PublicKey,
        id: [u8; 16],
        file: Option<web_sys::File>,
    ) -> Result<(), String> {
        // Running from here on, so that resuming it again meanwhile, e.g. clicked again while
        // the file is checked, neither checks the file twice nor sends the attachment twice.
        if self.cancelled.borrow().contains(&id) || !self.running.borrow_mut().insert(id) {
            return Ok(());
        }
        let resumed = async {
            let pending = {
                let guard = self.inner.lock().await;
                let inner = guard.as_ref().ok_or("locked")?;
                inner
                    .vault
                    .upload(&peer, &id)
                    .await
                    .map_err(|e| describe(&e))?
                    .ok_or("that upload is gone")?
            };
            let file = file
                .or_else(|| self.files.borrow().get(&id).cloned())
                .ok_or("choose the file again")?;
            let hasher = match self.check(&peer, &pending, &file).await {
                Ok(hasher) => hasher,
                Err(e) => {
                    self.show_upload(&peer, &pending, UploadState::Paused(e.clone()));
                    return Err(e);
                }
            };
            // Cancelled while the file was checked: it is not sent.
            if self.cancelled.borrow().contains(&id) {
                return Ok(None);
            }
            self.files.borrow_mut().insert(id, file.clone());
            let pending = self.announce(&peer, pending).await?;
            Ok::<_, String>(Some((pending, file, hasher)))
        }
        .await;
        match resumed {
            Ok(Some((pending, file, hasher))) => self.run_upload(peer, pending, file, hasher).await,
            Ok(None) => {
                self.running.borrow_mut().remove(&id);
                Ok(())
            }
            Err(e) => {
                self.running.borrow_mut().remove(&id);
                Err(e)
            }
        }
    }

    /// Stop the upload `id`, in the chat with `peer`, and forget it. The server deletes what it
    /// has, so the peer finds the attachment gone; if it cannot be reached, what it has expires.
    pub async fn cancel_upload(&self, peer: PublicKey, id: [u8; 16]) -> Result<(), String> {
        // For good, running or not: what is on its way stops, and keeps nothing of it again.
        self.cancelled.borrow_mut().insert(id);
        self.files.borrow_mut().remove(&id);
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != id));
        let guard = self.inner.lock().await;
        let inner = guard.as_ref().ok_or("locked")?;
        let pending = inner
            .vault
            .upload(&peer, &id)
            .await
            .map_err(|e| describe(&e))?;
        if let Some(pending) = &pending
            && let Err(e) = upload_of(pending)?
                .cancel(&Fetch::client(&inner.server))
                .await
        {
            self.ui.log(format!(
                "the server keeps what it has of {} until it expires: {}",
                pending.name,
                describe(&e)
            ));
        }
        inner
            .vault
            .forget_upload(&peer, &id)
            .await
            .map_err(|e| describe(&e))
    }

    /// The hash of `file` as far as `pending` may have encrypted it, once it is what it was then.
    async fn check(
        &self,
        peer: &PublicKey,
        pending: &PendingUpload,
        file: &web_sys::File,
    ) -> Result<Sha256, String> {
        let other = || format!("that is not {}, or it changed", pending.name);
        if file.size() as u64 != pending.size {
            return Err(other());
        }
        self.show_upload(
            peer,
            pending,
            UploadState::Paused("checking the file…".into()),
        );
        let mut hasher = Sha256::new();
        for index in 0..pending.encrypted {
            hasher.update(read_chunk(file, index, pending.size).await?);
        }
        if hasher.clone().finalize().as_slice() != pending.prefix_hash {
            return Err(other());
        }
        Ok(hasher)
    }

    /// Upload the chunks of `pending` from where it is: `hasher` has hashed its first
    /// `encrypted` chunks. While it goes, the upload shows in its chat, and if
    /// it stops, it shows paused, with why. The caller has marked it running, which this ends.
    async fn run_upload(
        &self,
        peer: PublicKey,
        mut pending: PendingUpload,
        file: web_sys::File,
        hasher: Sha256,
    ) -> Result<(), String> {
        let id: [u8; 16] = pending.id.as_slice().try_into().unwrap_or_default();
        let uploaded = match upload_of(&pending) {
            Ok(upload) => {
                self.upload_chunks(&peer, &mut pending, &upload, &file, hasher)
                    .await
            }
            Err(e) => Err(e),
        };
        self.running.borrow_mut().remove(&id);
        // Cancelled, it stays so: what cancelled it forgot it.
        if self.cancelled.borrow().contains(&id) {
            return Ok(());
        }
        if let Err(e) = uploaded {
            self.show_upload(&peer, &pending, UploadState::Paused(e.clone()));
            return Err(e);
        }
        self.files.borrow_mut().remove(&id);
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != id));
        let guard = self.inner.lock().await;
        let inner = guard.as_ref().ok_or("locked")?;
        inner
            .vault
            .forget_upload(&peer, &id)
            .await
            .map_err(|e| describe(&e))
    }

    /// Upload the chunks of `pending` from `uploaded` on, reading each from `file` in its turn,
    /// unless the upload is cancelled.
    async fn upload_chunks(
        &self,
        peer: &PublicKey,
        pending: &mut PendingUpload,
        upload: &Upload,
        file: &web_sys::File,
        mut hasher: Sha256,
    ) -> Result<(), String> {
        let server = {
            let guard = self.inner.lock().await;
            guard.as_ref().ok_or("locked")?.server.clone()
        };
        let attachments = Fetch::client(&server);
        for index in pending.uploaded..upload.chunks() {
            if self.cancelled.borrow().contains(upload.id()) {
                return Ok(());
            }
            self.show_upload(peer, pending, UploadState::Running);
            let plaintext = read_chunk(file, index, pending.size).await?;
            // Kept before the chunk is encrypted: from then on, the file must not change there.
            if index >= pending.encrypted {
                hasher.update(&plaintext);
                pending.encrypted = index + 1;
                pending.prefix_hash = hasher.clone().finalize().to_vec();
            }
            pending.uploaded = index;
            self.save_upload(peer, pending).await?;
            let chunk = upload.encrypt(index, &plaintext);
            self.put_chunk(peer, pending, &attachments, upload, index, &chunk)
                .await?;
            self.keep_chunk(peer, upload.id(), index, &chunk).await?;
            pending.uploaded = index + 1;
        }
        Ok(())
    }

    /// Upload chunk `index` of `upload`, trying again while the server cannot be reached, unless
    /// the upload is cancelled meanwhile.
    async fn put_chunk(
        &self,
        peer: &PublicKey,
        pending: &PendingUpload,
        attachments: &Connect,
        upload: &Upload,
        index: u32,
        chunk: &[u8],
    ) -> Result<(), String> {
        let mut wait = RETRY_MIN;
        loop {
            match upload.put(attachments, index, chunk).await {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == ErrorKind::Server => {
                    self.show_upload(peer, pending, UploadState::Retrying);
                    sleep(wait).await;
                    wait = (wait * 2).min(RETRY_MAX);
                    if self.cancelled.borrow().contains(upload.id()) {
                        return Ok(());
                    }
                }
                Err(e) => return Err(describe(&e)),
            }
        }
    }

    /// Keep `pending`, of the chat with `peer`, in the vault, unless it was cancelled or its chat
    /// deleted meanwhile, which forgot it: it must not come back.
    async fn save_upload(&self, peer: &PublicKey, pending: &PendingUpload) -> Result<(), String> {
        let guard = self.inner.lock().await;
        let inner = guard.as_ref().ok_or("locked")?;
        if !self.may_keep(inner, peer, &pending.id) {
            return Err(format!("the upload of {} was cancelled", pending.name));
        }
        inner
            .vault
            .save_upload(peer, pending)
            .await
            .map_err(|e| describe(&e))
    }

    /// Whether the vault may keep what goes with the attachment `id`, in the chat with `peer`:
    /// its upload was not cancelled, and the chat is still there. Asked under the lock, which
    /// cancelling and deleting take to forget them, so that nothing is kept after.
    fn may_keep(&self, inner: &Inner, peer: &PublicKey, id: &[u8]) -> bool {
        let cancelled =
            <[u8; 16]>::try_from(id).is_ok_and(|id| self.cancelled.borrow().contains(&id));
        !cancelled && inner.contacts.iter().any(|contact| contact.peer == *peer)
    }

    /// Show the upload `pending`, to `peer`, as in `state`.
    fn show_upload(&self, peer: &PublicKey, pending: &PendingUpload, state: UploadState) {
        let view = UploadView {
            peer: *peer,
            id: pending.id.as_slice().try_into().unwrap_or_default(),
            name: pending.name.clone(),
            uploaded: pending.uploaded,
            chunks: attachment::chunk_count(pending.size) as u32,
            state,
        };
        self.ui.uploads.update(|uploads| {
            match uploads.iter_mut().find(|upload| upload.id == view.id) {
                Some(upload) => *upload = view,
                None => uploads.push(view),
            }
        });
    }

    /// Open the attachment `pointer`, in the chat with `peer`, in the viewer, from the chunks
    /// kept here, or else from the server, keeping them from then on. The viewer shows how far
    /// it got meanwhile, and closing it stops it.
    pub async fn open_attachment(
        &self,
        peer: PublicKey,
        pointer: AttachmentPointer,
    ) -> Result<(), String> {
        let Ok(id) = <[u8; 16]>::try_from(pointer.id.as_slice()) else {
            return Err("the attachment is malformed".to_string());
        };
        self.ui.opening.set(Some(Opening {
            id,
            name: pointer.name.clone(),
            size: pointer.size,
            done: 0,
            waiting: false,
        }));
        let opened = self.fetch_attachment(peer, &id, pointer).await;
        // Unless the viewer closed, or went on to another file, meanwhile.
        if !self.opening(&id) {
            return Ok(());
        }
        match opened {
            Ok(Some(attachment)) => {
                self.ui.viewer.set(Some(attachment));
                self.ui.opening.set(None);
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(e) => {
                self.ui.opening.set(None);
                Err(e)
            }
        }
    }

    /// Whether the viewer still waits for the attachment `id`.
    fn opening(&self, id: &[u8; 16]) -> bool {
        self.ui
            .opening
            .with_untracked(|opening| opening.as_ref().is_some_and(|opening| opening.id == *id))
    }

    /// Note how far opening the attachment `id` got.
    fn opened(&self, id: &[u8; 16], done: u64, waiting: bool) {
        self.ui.opening.update(|opening| {
            if let Some(opening) = opening.as_mut().filter(|opening| opening.id == *id) {
                (opening.done, opening.waiting) = (done, waiting);
            }
        });
    }

    /// The file of the attachment `pointer`, whose ID is `id`, in the chat with `peer`; none if
    /// the viewer stopped waiting for it.
    async fn fetch_attachment(
        &self,
        peer: PublicKey,
        id: &[u8; 16],
        pointer: AttachmentPointer,
    ) -> Result<Option<Attachment>, String> {
        let malformed = || "the attachment is malformed".to_string();
        let key = Zeroizing::new(
            <[u8; attachment::KEY_LENGTH]>::try_from(pointer.key.as_slice())
                .map_err(|_| malformed())?,
        );
        if pointer.size > MAX_FILE_SIZE as u64 {
            return Err(format!(
                "{} is {}; files go up to {}.",
                pointer.name,
                size(pointer.size as usize),
                size(MAX_FILE_SIZE)
            ));
        }
        let chunks =
            u32::try_from(attachment::chunk_count(pointer.size)).map_err(|_| malformed())?;
        let server = {
            let guard = self.inner.lock().await;
            guard.as_ref().ok_or("locked")?.server.clone()
        };
        let attachments = Fetch::client(&server);
        // It grows as its chunks decrypt, not to the size the peer claims, which nothing backs
        // until they do.
        let mut data = vec![];
        for index in 0..chunks {
            if !self.opening(id) {
                return Ok(None);
            }
            let (chunk, kept) = match self.kept_chunk(&peer, id, index).await? {
                Some(chunk) => (chunk, true),
                None => match self
                    .await_chunk(&attachments, &pointer.name, id, index)
                    .await?
                {
                    Some(chunk) => (chunk, false),
                    None => return Ok(None),
                },
            };
            let plaintext = attachment::decrypt_chunk(&key, index, index + 1 == chunks, &chunk)
                .map_err(|_| format!("{} does not decrypt", pointer.name))?;
            // Kept only once it decrypts, so that a chunk that does not is fetched again next
            // time rather than kept for good.
            if !kept {
                self.keep_chunk(&peer, id, index, &chunk).await?;
            }
            data.extend(plaintext);
            self.opened(id, data.len() as u64, false);
        }
        if data.len() as u64 != pointer.size {
            return Err(format!("{} is not the size it should be", pointer.name));
        }
        Ok(Some(Attachment {
            name: pointer.name,
            mime: pointer.mime,
            data: Arc::new(data),
        }))
    }

    /// Chunk `index` of the attachment `id`, named `name`, from the server, waiting for it while
    /// it is uploaded, unless no chunk comes for [`STALLED`] milliseconds; none if the viewer
    /// stopped waiting for it meanwhile.
    async fn await_chunk(
        &self,
        attachments: &Connect,
        name: &str,
        id: &[u8; 16],
        index: u32,
    ) -> Result<Option<Vec<u8>>, String> {
        let (mut waited, mut wait) = (0, POLL_CHUNK_MIN);
        loop {
            if !self.opening(id) {
                return Ok(None);
            }
            match attachment::download_chunk(attachments, id, index).await {
                Ok(Some(chunk)) => return Ok(Some(chunk)),
                Ok(None) if waited < STALLED => {
                    self.ui.opening.update(|opening| {
                        if let Some(opening) = opening.as_mut().filter(|opening| opening.id == *id)
                        {
                            opening.waiting = true;
                        }
                    });
                    sleep(wait).await;
                    waited += wait;
                    wait = (wait * 2).min(POLL_CHUNK_MAX);
                }
                Ok(None) => {
                    return Err(format!(
                        "{name} is still being uploaded, but nothing came for a while; open it \
                         again later"
                    ));
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    return Err(format!(
                        "{name} is no longer on the server: its sender cancelled it, or it \
                         expired, as the server keeps attachments for a while only"
                    ));
                }
                Err(e) => return Err(describe(&e)),
            }
        }
    }

    /// Keep chunk `index` of the attachment `id`, in the chat with `peer`, unless its upload was
    /// cancelled or the chat deleted meanwhile.
    async fn keep_chunk(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
        chunk: &[u8],
    ) -> Result<(), String> {
        let guard = self.inner.lock().await;
        let inner = guard.as_ref().ok_or("locked")?;
        if !self.may_keep(inner, peer, id) {
            return Ok(());
        }
        inner
            .vault
            .put_chunk(peer, id, index, chunk)
            .await
            .map_err(|e| describe(&e))
    }

    /// Chunk `index` of the attachment `id`, in the chat with `peer`, if kept.
    async fn kept_chunk(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
    ) -> Result<Option<Vec<u8>>, String> {
        let guard = self.inner.lock().await;
        let inner = guard.as_ref().ok_or("locked")?;
        inner
            .vault
            .chunk(peer, id, index)
            .await
            .map_err(|e| describe(&e))
    }

    /// Start a chat with `key`, named `name`, greeting the peer; or open the chat if there is one.
    pub async fn start_chat(&self, key: &str, name: String) -> Result<PublicKey, String> {
        let peer = key_from_text(key).ok_or("that is not an identity key")?;
        let name = name.trim().to_string();
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        if peer == inner.client.identity_key() {
            return Err("that is your own key".into());
        }
        if let Some(contact) = inner.contact(&peer) {
            contact.state.request = false;
            if !name.is_empty() {
                contact.state.name = name;
            }
            inner.save(&[]).await.map_err(|e| describe(&e))?;
            self.ui.contacts.set(inner.views());
            return Ok(peer);
        }
        // The greeting is the session's first message, which shows the peer that the initial
        // message is this client's, and lets the peer write back.
        let hello = Kind::Hello(Hello {
            name: inner.state.name.clone(),
        });
        let session = inner
            .client
            .initiate(&peer, &hello.to_bytes(), Fetch::client(&inner.server))
            .await
            .map_err(|e| match e.kind() {
                session::ErrorKind::NotFound => {
                    "nobody published keys for that key on this server".to_string()
                }
                _ => describe(&e),
            })?;
        let entry = HistoryEntry {
            outgoing: true,
            at: now(),
            content: Some(Content { kind: Some(hello) }),
        };
        inner.contacts.push(Contact {
            peer,
            session,
            state: ContactState {
                peer: peer.to_vec(),
                name,
                history_len: 1,
                last_activity: now(),
                ..ContactState::default()
            },
        });
        let record = (history_key(&peer, 0), entry);
        if let Err(e) = inner.save(std::slice::from_ref(&record)).await {
            // The peer has the initial message already, so the chat stays: it shows once saved.
            inner.unsaved.push((peer, record));
            return Err(describe(&e));
        }
        self.ui.contacts.set(inner.views());
        self.wake();
        Ok(peer)
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
        let Some(contact) = inner.contacts.iter().find(|contact| contact.peer == peer) else {
            return;
        };
        let history = inner
            .vault
            .history(&peer, contact.state.history_len, HISTORY_SHOWN)
            .await;
        let Some(contact) = inner.contact(&peer) else {
            return;
        };
        let messages = match history {
            Ok(history) => history
                .into_iter()
                .map(|(index, entry)| contact.message(index, entry))
                .collect(),
            Err(e) => {
                self.ui.notify(describe(&e));
                vec![]
            }
        };
        let was_unread = contact.state.unread > 0;
        contact.state.unread = 0;
        self.ui.messages.set(messages);
        self.ui.open.set(Some(peer));
        if was_unread && let Err(e) = inner.save(&[]).await {
            self.ui.notify(describe(&e));
        }
        self.ui.contacts.set(inner.views());
    }

    /// Count the messages of the chat with `peer` as read, e.g. back on the page with the chat
    /// open: they show already, as [`receive`](Self::receive) adds them to the open chat.
    pub async fn mark_read(&self, peer: PublicKey) {
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return;
        };
        let Some(contact) = inner.contact(&peer) else {
            return;
        };
        if contact.state.unread == 0 {
            return;
        }
        contact.state.unread = 0;
        if let Err(e) = inner.save(&[]).await {
            self.ui.notify(describe(&e));
        }
        self.ui.contacts.set(inner.views());
    }

    /// Accept the request of `peer`, naming the peer `name`.
    pub async fn accept(&self, peer: PublicKey, name: String) -> Result<(), String> {
        self.change_contact(peer, |contact| {
            contact.state.request = false;
            contact.state.name = name.trim().to_string();
        })
        .await
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
        inner.save(&[]).await.map_err(|e| describe(&e))?;
        self.ui.contacts.set(inner.views());
        Ok(())
    }

    /// Delete the chat with `peer` and its history.
    pub async fn delete(&self, peer: PublicKey) -> Result<(), String> {
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        // Forgotten in the vault first, so that if that fails, the chat stays whole.
        let mut state = inner.app_state();
        state.contacts.retain(|contact| contact.peer != peer);
        inner
            .vault
            .forget(&state, &peer)
            .await
            .map_err(|e| describe(&e))?;
        // Its uploads stop, as cancelled, and keep nothing more: the vault forgot them with the
        // chat, which `may_keep` now tells them is gone. What the server has expires.
        let uploads: Vec<[u8; 16]> = self.ui.uploads.with_untracked(|uploads| {
            uploads
                .iter()
                .filter(|upload| upload.peer == peer)
                .map(|upload| upload.id)
                .collect()
        });
        for id in uploads {
            self.cancelled.borrow_mut().insert(id);
            self.files.borrow_mut().remove(&id);
        }
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.peer != peer));
        inner.contacts.retain(|contact| contact.peer != peer);
        inner.unsaved.retain(|(unsaved, _)| *unsaved != peer);
        if self.ui.open.get_untracked() == Some(peer) {
            self.ui.open.set(None);
            self.ui.messages.set(vec![]);
        }
        self.ui.contacts.set(inner.views());
        Ok(())
    }

    /// Go by `name` in the greetings of new chats.
    pub async fn set_name(&self, name: String) -> Result<(), String> {
        let name = checked_name(&name)?;
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        inner.state.name = name;
        inner.save(&[]).await.map_err(|e| describe(&e))?;
        self.ui.me.set(Some(inner.me()));
        Ok(())
    }
}

impl Inner {
    /// What the vault keeps.
    fn app_state(&self) -> AppState {
        AppState {
            client: Some(self.client.state().into()),
            contacts: self
                .contacts
                .iter()
                .map(|contact| ContactState {
                    session: Some(contact.session.state().into()),
                    ..contact.state.clone()
                })
                .collect(),
            ..self.state.clone()
        }
    }

    /// Save the state, and `entries` with it, and the records left [unsaved](Self::unsaved).
    // TODO: every save encrypts the whole state, outboxes included, whose messages may be files
    // of up to 1 MiB; keep each waiting message in a record of its own.
    async fn save(&mut self, entries: &[(String, HistoryEntry)]) -> crate::vault::Result<()> {
        if self.unsaved.is_empty() {
            return self.vault.save(&self.app_state(), entries).await;
        }
        let all: Vec<_> = self
            .unsaved
            .iter()
            .map(|(_, record)| record.clone())
            .chain(entries.iter().cloned())
            .collect();
        self.vault.save(&self.app_state(), &all).await?;
        self.unsaved.clear();
        self.saved_late = true;
        Ok(())
    }

    /// Start a new session with `peer`, whose chat has none to send on, as the two kept missing
    /// each other (see `Session::needs_new_session`), greeting the peer in its first message as
    /// a new chat does; and save it.
    async fn start_again(&mut self, peer: &PublicKey) -> Result<(), String> {
        let hello = Kind::Hello(Hello {
            name: self.state.name.clone(),
        });
        let started = self
            .client
            .initiate(peer, &hello.to_bytes(), Fetch::client(&self.server))
            .await
            .map_err(|e| describe(&e))?;
        let contact = self.contact(peer).ok_or("no such chat")?;
        let older = std::mem::replace(&mut contact.session, started);
        contact.session.keep(older).map_err(|e| describe(&e))?;
        self.save(&[]).await.map_err(|e| describe(&e))
    }

    fn contact(&mut self, peer: &PublicKey) -> Option<&mut Contact> {
        self.contacts
            .iter_mut()
            .find(|contact| contact.peer == *peer)
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
        }
    }
}

impl Engine {
    /// Update the delivery of the messages to `peer` on screen.
    fn show_deliveries(&self, inner: &mut Inner, peer: &PublicKey) {
        if self.ui.open.get_untracked() != Some(*peer) {
            return;
        }
        let Some(contact) = inner.contact(peer) else {
            return;
        };
        self.ui.messages.update(|messages| {
            for message in messages.iter_mut().filter(|message| message.outgoing) {
                message.delivery = contact.delivery(message.index);
            }
        });
    }
}

impl Contact {
    /// What to go back to with [`Inner::roll_back`] if saving a change fails.
    fn snapshot(&self) -> (proto::SessionState, ContactState) {
        (self.session.state().into(), self.state.clone())
    }

    fn view(&self) -> ContactView {
        ContactView {
            peer: self.peer,
            name: self.state.name.clone(),
            request: self.state.request,
            hello_name: self.state.hello_name.clone(),
            unread: self.state.unread,
            last_activity: self.state.last_activity,
        }
    }

    /// Add the content `bytes`, received, to the history, counting it as unread unless the chat
    /// is `open`. Returns the entry and its index.
    fn add_received(&mut self, bytes: &[u8], open: bool) -> (u64, HistoryEntry) {
        let content = Kind::from_bytes(bytes);
        match &content {
            Some(Kind::Hello(hello)) => self.state.hello_name = hello.name.clone(),
            _ if !open => self.state.unread += 1,
            _ => {}
        }
        let index = self.state.history_len;
        self.state.history_len += 1;
        self.state.last_activity = now();
        let entry = HistoryEntry {
            outgoing: false,
            at: now(),
            content: Some(Content { kind: content }),
        };
        (index, entry)
    }

    fn delivery(&self, index: u64) -> Delivery {
        if self.state.failed.contains(&index) {
            Delivery::Failed
        } else if self
            .state
            .outbox
            .iter()
            .any(|outgoing| outgoing.history_index == index)
        {
            Delivery::Pending
        } else {
            Delivery::Sent
        }
    }

    /// History entry `index`, as shown.
    fn message(&self, index: u64, entry: HistoryEntry) -> MessageView {
        let body = match entry.content.and_then(|content| content.kind) {
            Some(Kind::Text(text)) => Body::Text(text),
            Some(Kind::Image(data)) => {
                // The TUI client sends any image, e.g. BMP, which only downloads here.
                let mime = image_type(&data);
                Body::File(Attachment {
                    name: mime
                        .and_then(|mime| mime.strip_prefix("image/"))
                        .map_or_else(
                            || "image".to_string(),
                            |extension| format!("image.{extension}"),
                        ),
                    mime: mime.unwrap_or("application/octet-stream").to_string(),
                    data: Arc::new(data),
                })
            }
            Some(Kind::File(file)) => Body::File(Attachment {
                name: file.name,
                mime: file.mime,
                data: Arc::new(file.data),
            }),
            Some(Kind::Hello(hello)) => Body::Hello(hello.name),
            Some(Kind::Attachment(pointer)) => Body::Remote(RemoteFile {
                peer: self.peer,
                pointer,
            }),
            None => Body::Unknown,
        };
        MessageView {
            index,
            outgoing: entry.outgoing,
            at: entry.at,
            body,
            delivery: if entry.outgoing {
                self.delivery(index)
            } else {
                Delivery::Received
            },
        }
    }
}

/// Chunk `index` of `file`, of `size` bytes, as the attachment cuts it.
async fn read_chunk(file: &web_sys::File, index: u32, size: u64) -> Result<Vec<u8>, String> {
    let start = u64::from(index) * CHUNK_SIZE as u64;
    read(file, start, (start + CHUNK_SIZE as u64).min(size)).await
}

/// The upload of `pending`, to go on with.
fn upload_of(pending: &PendingUpload) -> Result<Upload, String> {
    let corrupt = || format!("the upload of {} is corrupt", pending.name);
    let chunks = u32::try_from(attachment::chunk_count(pending.size)).map_err(|_| corrupt())?;
    Ok(Upload::resume(
        pending.id.as_slice().try_into().map_err(|_| corrupt())?,
        pending.token.as_slice().try_into().map_err(|_| corrupt())?,
        Zeroizing::new(pending.key.as_slice().try_into().map_err(|_| corrupt())?),
        chunks,
    ))
}

/// The bytes of `file` from `start` to `end`.
async fn read(file: &web_sys::File, start: u64, end: u64) -> Result<Vec<u8>, String> {
    let failed = |e| format!("cannot read {}: {}", file.name(), js_error(e));
    let part = file
        .slice_with_f64_and_f64(start as f64, end as f64)
        .map_err(failed)?;
    let buffer = JsFuture::from(part.array_buffer()).await.map_err(failed)?;
    Ok(js_sys::Uint8Array::new(&buffer).to_vec())
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

/// The invitation link's `#chat=<key>&name=<name>&server=<server>` in the page's address, as a
/// dialog to start the chat.
pub fn invitation() -> Option<Dialog> {
    let hash = window().location().hash().ok()?;
    let decode = |value: &str| {
        js_sys::decode_uri_component(value)
            .ok()
            .and_then(|value| value.as_string())
    };
    let mut key = None;
    let mut name = String::new();
    let mut server = None;
    for pair in hash.trim_start_matches('#').split('&') {
        match pair.split_once('=') {
            Some(("chat", value)) => key = Some(value.to_string()),
            Some(("name", value)) => name = decode(value).unwrap_or_default(),
            Some(("server", value)) => server = decode(value),
            _ => {}
        }
    }
    Some(Dialog::NewChat {
        key: key?,
        name,
        server,
    })
}

/// Remove the invitation from the page's address, once it shows.
fn forget_invitation() {
    let location = window().location();
    if let (Ok(history), Ok(path)) = (window().history(), location.pathname()) {
        let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&path));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_have_at_most_name_max_characters() {
        assert_eq!(checked_name("  alice \n").as_deref(), Ok("alice"));
        // Characters, not bytes: 64 of four bytes each.
        assert!(checked_name(&"😀".repeat(NAME_MAX)).is_ok());
        assert!(checked_name(&"a".repeat(NAME_MAX + 1)).is_err());
        // The longest greeting is far below the 4 KiB a first message may take.
        let greeting = Kind::Hello(Hello {
            name: "😀".repeat(NAME_MAX),
        });
        assert!(greeting.to_bytes().len() < 512);
    }
}
