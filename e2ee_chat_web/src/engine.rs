//! The client: the vault, the identity and the sessions, and what the page asks of them.
//!
//! The engine keeps the state; the page only shows the [`Ui`] signals that the engine updates.
//! One lock orders everything that changes the state, so that the sync loop and the page take
//! turns, and every change is saved before it shows.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, HashMap, HashSet, VecDeque, btree_map, hash_map},
    rc::Rc,
    sync::Arc,
};

use futures::{
    channel::oneshot,
    future::{Either, select},
    lock::Mutex,
};
use leptos::{prelude::*, task::spawn_local};
use session::{
    Client, ClientState, ErrorKind, InitialMessage, PublicKey, Session, SessionState,
    attachment::{self, CHUNK_SIZE, Upload},
    proto,
    protocol::{
        attachment::DEFAULT_MAX_CHUNKS,
        mailbox::LocalMailbox,
        notify::{self, Notification},
    },
};
use sha2::{Digest, Sha256};
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

use crate::{
    content::{self, AttachmentPointer, Content, Deleted, Events, Hello, Kind, stamp},
    glue::{self, MediaRequest},
    notify::{Event, Subscription},
    preview::{self, Sort},
    state::{
        Attachment, Body, ContactView, Delivery, Dialog, FileView, Link, LocalFile, Me,
        MessageView, Opening, Phase, RemoteFile, SignIn, Step, Ui, UploadState, UploadView, order,
    },
    transport::{self, Connect, Fetch, Progress},
    util::{describe, hex, js_error, key_from_text, now, short, size, sleep},
    vault::{
        AppState, Awaiting, ContactState, Farewell, HistoryEntry, Outgoing, OutgoingRecord,
        PendingUpload, SealedEvents, Vault, history_key, outbox_key,
    },
};

/// Why an attachment's upload has not started.
const WAITS_SIGN_IN: &str = "waits for you to sign in to the server";
/// Why what takes a sign-in never goes from a page that is not the server's own, which cannot
/// sign in to it.
const NOT_SIGNED_IN_HERE: &str =
    "the server keeps it only for those signed in to it, and only its own page can sign in";
/// One-time prekeys in each publish.
const ONE_TIME_PREKEYS: usize = 20;
/// Publish new prekeys once this many one-time prekeys are used...
const REPUBLISH_USED: u32 = 10;
/// ... or the signed prekey is this old, in milliseconds.
const REPUBLISH_AGE: u64 = 7 * 24 * 60 * 60 * 1000;
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

/// Keep the last [`EVENTS_KEPT`] of `list`.
fn keep_last<T>(list: &mut Vec<T>) {
    if list.len() > EVENTS_KEPT {
        list.drain(..list.len() - EVENTS_KEPT);
    }
}

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
    /// The attachments playing as they are fetched, by the tokens of their URLs.
    streams: RefCell<HashMap<String, Stream>>,
    /// The chunks the streams decrypted last, by attachment and index, oldest first, which every
    /// stream of an attachment shares.
    decrypted: RefCell<VecDeque<(ChunkOf, Rc<Vec<u8>>)>>,
    /// The chunks the streams are fetching, by attachment and index, with what waits for each,
    /// woken once it is done: a chunk asked for again meanwhile, as players ask for overlapping
    /// ranges, a preview and the viewer show one file, or the tags of audio are read from its
    /// first, is fetched once.
    loading: RefCell<HashMap<ChunkOf, Vec<oneshot::Sender<()>>>>,
    /// The chats whose next message waits for this browser to sign in to the server, which
    /// keeps a message that large only for those who do. It goes once it signs in; until then,
    /// the chat's messages stay in its outbox, in order. An attachment waits so too, by its
    /// message's [`awaits_upload`](Outgoing::awaits_upload).
    waits_sign_in: RefCell<HashSet<PublicKey>>,
    /// Whether the user put off signing in, so that what the server refuses meanwhile, as it
    /// syncs, does not ask again; what the user sends does.
    declined_sign_in: Cell<bool>,
    /// Whether publishing the prekeys was refused for the sign-in: it waits for one, rather than
    /// tries every round.
    publish_waits_sign_in: Cell<bool>,
}

/// A chunk of an attachment: its ID and the chunk's index.
type ChunkOf = ([u8; 16], u32);

/// An attachment playing as it is fetched, through the service worker, see [`Engine::stream`].
struct Stream {
    fetching: Rc<Fetching>,
    /// Its MIME type, as its first chunk tells once it is here, or as its sender gave it.
    mime: String,
    /// The clock of the peer's message it came in, to tell the peer once it is all here; 0 for
    /// this client's own.
    clock: u64,
}

/// What fetching an attachment's chunks takes, see [`Engine::chunk`].
struct Fetching {
    /// The chat it is in.
    peer: PublicKey,
    id: [u8; 16],
    key: Zeroizing<[u8; attachment::KEY_LENGTH]>,
    name: String,
    size: u64,
    chunks: u32,
    /// How far this client's own upload of it got, if it is unfinished, its file gone with the
    /// page: what the server lacks only comes once the file is chosen again.
    unfinished: Option<u32>,
    attachments: Connect,
}

/// Who waits for an attachment.
#[derive(Clone, Copy)]
enum Waiter<'a> {
    /// The viewer, until it closes or goes on to another file.
    Viewer,
    /// The chat, showing it in place, while this says it does.
    Chat(&'a dyn Fn() -> bool),
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
    /// The chats whose records left unsaved a save wrote, which then show them.
    saved_late: Vec<PublicKey>,
}

struct Contact {
    peer: PublicKey,
    session: Session<Connect>,
    /// Everything but the session, which is in `session`.
    state: ContactState,
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
            declined_sign_in: Cell::default(),
            publish_waits_sign_in: Cell::default(),
        });
        // Whatever the server refuses for the sign-in, the user is asked to sign in.
        let weak = Rc::downgrade(&engine);
        transport::on_sign_in_required(move || {
            if let Some(engine) = weak.upgrade() {
                engine.refused_for_sign_in();
            }
        });
        engine
    }

    /// Whether the user is here: the page shown and in focus, or hidden for less than
    /// [`HIDDEN_GRACE`], or out of focus for less than [`UNFOCUSED_GRACE`]. Notifications are
    /// for then only, as a WebSocket open is held on the server.
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
        self.declined_sign_in.set(false);
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

    /// Ask the user to sign in to the server, as what was sent waits for it, unless a dialog is
    /// open.
    fn ask_sign_in(&self) {
        if self.ui.dialog.with_untracked(Option::is_none) {
            self.ui.dialog.set(Some(Dialog::SignIn));
        }
    }

    /// The server refused a call, whichever, as this browser is not signed in to it, which every
    /// write takes: ask, unless the user put it off.
    fn refused_for_sign_in(&self) {
        if !self.declined_sign_in.get() {
            self.ask_sign_in();
        }
    }

    /// The user put off signing in: what syncing finds refused does not ask again until then.
    pub fn decline_sign_in(&self) {
        self.declined_sign_in.set(true);
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
        let client = Client::new(Fetch::client(&address)).with_clock(transport::clock(&address));
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
            saved_late: vec![],
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
        )
        .with_clock(transport::clock(&address));
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
            saved_late: vec![],
        })
        .await;
        Ok(())
    }

    async fn unlocked(self: &Rc<Self>, inner: Inner) {
        self.ui.me.set(Some(inner.me()));
        self.ui.contacts.set(inner.views());
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
        self.ui.phase.set(Phase::Unlocked);
        self.ui.log("vault unlocked");
        if let Some(dialog) = invitation() {
            forget_invitation();
            self.ui.dialog.set(Some(dialog));
        }
        self.clone().run();
        self.clone().listen();
        let engine = self.clone();
        glue::serve_media(move |request| {
            let engine = engine.clone();
            spawn_local(async move { engine.serve_media(request).await });
        });
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
                    // Then what it moved on goes, e.g. events to tell, or messages to send
                    // again, as the peer deleted the chat.
                    Ok(peer) => match self.receive(&peer).await {
                        Ok(_) => self.flush(&peer).await.map(drop),
                        Err(e) => Err(e),
                    },
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

    /// One round: save what an earlier save failed to, tell peers of chats deleted here, take
    /// initial messages, publish prekeys when due, receive, and push what waits. Returns whether
    /// anything happened.
    async fn sync(&self) -> bool {
        // A step that keeps failing, e.g. a large file timing out over a slow link, a take of
        // initial messages the server refuses, or one chat's queue that cannot be fetched, must
        // not keep the round from the other steps and chats: its error is kept, and the round
        // goes on. Receiving goes before pushing, so that what waits since the user was offline
        // goes on a new session if the peer deleted the chat meanwhile.
        let mut failure = None;
        let mut active = false;
        if let Err(e) = self.save_late().await {
            failure.get_or_insert(e);
        }
        if let Err(e) = self.say_farewells().await {
            failure.get_or_insert(e);
        }
        let reached = match self.take_initial_messages().await {
            Ok(taken) => {
                active |= taken;
                true
            }
            Err(e) => {
                failure.get_or_insert(e);
                false
            }
        };
        // Not while the server does not answer signed requests: each publish that fails keeps
        // its new one-time prekeys, as the server may have them, see `Client::publish_keys`, so
        // retrying every round while offline would grow the state, which each save writes whole.
        if reached && let Err(e) = self.publish(false).await {
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
        for peer in self.peers().await {
            match self.flush(&peer).await {
                Ok(pushed) => active |= pushed,
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
        let late = std::mem::take(&mut inner.saved_late);
        if !late.is_empty() {
            self.ui.contacts.set(inner.views());
            // The open chat shows them in their places.
            if let Some(open) = self.ui.open.get_untracked()
                && late.contains(&open)
            {
                self.show_history(inner, &open).await;
            }
        }
        Ok(())
    }

    /// Push the messages telling peers that their chats were deleted here, see
    /// [`delete`](Self::delete).
    async fn say_farewells(&self) -> Result<(), String> {
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return Ok(());
        };
        let signs_in_here = same_server(&inner.server, &origin());
        while let Some(farewell) = inner.state.farewells.first().cloned() {
            match Fetch::client(&inner.server)
                .push(farewell.push.unwrap_or_default())
                .await
                .map_err(session::Error::from)
            {
                Ok(_) => {}
                // Pushing takes a sign-in: they wait for it, without failing the round.
                Err(e) if e.kind() == ErrorKind::SignInRequired && signs_in_here => return Ok(()),
                // Refused for good, e.g. as the peer's inbox is full, or as this page cannot sign
                // in to the server: it must not hold up the others, nor keep the sync failing.
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::LimitExceeded | ErrorKind::Protocol | ErrorKind::SignInRequired
                    ) =>
                {
                    self.ui.log(format!(
                        "could not tell a deleted chat's peer of it: {}",
                        describe(&e)
                    ));
                }
                Err(e) => return Err(describe(&e)),
            }
            inner.state.farewells.remove(0);
            inner.save(&[]).await.map_err(|e| describe(&e))?;
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

    /// Push the messages waiting for `peer`, in order, each encrypted as its turn comes, then
    /// the events to tell the peer. Returns whether any went.
    async fn flush(&self, peer: &PublicKey) -> Result<bool, String> {
        if self.waits_sign_in.borrow().contains(peer) {
            return Ok(false);
        }
        // With messages waiting and no session to send on, the peer may have started one, e.g.
        // having deleted the chat and started it again: taken first, it is sent on, rather than
        // another started, which the peer might set aside. If taking fails, one starts.
        let waits = {
            let guard = self.inner.lock().await;
            guard.as_ref().is_some_and(|inner| {
                inner.contacts.iter().any(|contact| {
                    contact.peer == *peer
                        && contact.session.needs_new_session()
                        && !contact.state.outbox.is_empty()
                })
            })
        };
        if waits {
            let _ = self.take_initial_messages().await;
        }
        let mut guard = self.inner.lock().await;
        let Some(inner) = guard.as_mut() else {
            return Ok(false);
        };
        // Encrypted on a session retired since, as a push failed, e.g. retired as taking initial
        // messages joined one, which `receive` would only see after a page: put back to go on a
        // new one, as the peer may never have had that one.
        if needs_new_session(inner, peer)
            && let Some(contact) = inner.contact(peer)
            && contact.state.outbox.iter().any(|outgoing| outgoing.sealed)
        {
            let snapshot = contact.snapshot();
            let mut entries = BTreeMap::new();
            let saved = match inner.requeue(peer, false, &mut entries).await {
                Ok(requeued) => inner
                    .save_with(&[], &requeued)
                    .await
                    .map_err(|e| describe(&e)),
                Err(e) => Err(e),
            };
            if let Err(e) = saved {
                inner.roll_back(peer, snapshot)?;
                return Err(e);
            }
        }
        let mut changed = false;
        let mut result = Ok(());
        // What happened to the messages, by their history entries, with their places, and the
        // records gone with them.
        let (mut steps, mut gone) = (vec![], vec![]);
        // Whether this page can sign in to the server, which only its own page can: otherwise a
        // message that takes it never goes, and must not hold up those after it.
        let signs_in_here = same_server(&inner.server, &origin());
        while let Some(contact) = inner.contact(peer)
            && let Some(outgoing) = contact.state.outbox.first().cloned()
        {
            // An attachment whose upload has not started: it, and what was sent after it, wait
            // for it to start.
            if outgoing.awaits_upload {
                break;
            }
            if !outgoing.sealed {
                // Encrypted now that it goes, so that its place is after what came so far; the
                // ones after it wait their turn.
                match inner.seal_next(peer).await {
                    Ok(None) => {}
                    Ok(Some(reason)) => {
                        self.ui
                            .notify(format!("messages could not be sent: {reason}"));
                        if self.ui.open.get_untracked() == Some(*peer) {
                            self.show_history(inner, peer).await;
                        }
                        changed = true;
                    }
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
                continue;
            }
            let record = match inner.vault.outgoing(peer, outgoing.history_index).await {
                Ok(record) => record,
                Err(e) => {
                    result = Err(describe(&e));
                    break;
                }
            };
            let Some(contact) = inner.contact(peer) else {
                break;
            };
            match contact.session.push(record.to_push()).await {
                Ok(()) => {
                    self.release(peer, outgoing.history_index);
                    steps.push((outgoing.history_index, Step::Pushed, outgoing.clock));
                }
                // Large enough to cost the server storage, which it keeps only for those signed
                // in to it: it waits, with those after it, until this browser is.
                Err(e) if e.kind() == ErrorKind::SignInRequired && signs_in_here => {
                    self.waits_sign_in.borrow_mut().insert(*peer);
                    self.hold(peer, outgoing.history_index);
                    self.ask_sign_in();
                    break;
                }
                // The same, but this page cannot sign in to the server: it never will go.
                Err(e) if e.kind() == ErrorKind::SignInRequired => {
                    steps.push((outgoing.history_index, Step::Refused, 0));
                    self.ui
                        .notify(format!("a message could not be sent: {NOT_SIGNED_IN_HERE}"));
                }
                // Too large for the server: it never will go.
                Err(e) if e.kind() == ErrorKind::LimitExceeded => {
                    steps.push((outgoing.history_index, Step::Refused, 0));
                    self.ui
                        .notify(format!("a message could not be sent: {}", describe(&e)));
                }
                Err(e) => {
                    result = Err(describe(&e));
                    break;
                }
            }
            contact.state.outbox.remove(0);
            gone.push((outbox_key(peer, outgoing.history_index), None));
            changed = true;
        }
        if !gone.is_empty() {
            let mut entries = vec![];
            for (index, step, clock) in steps {
                let mut entry = match inner.vault.entry(peer, index).await {
                    Ok(Some(entry)) => entry,
                    Ok(None) => continue,
                    Err(e) => {
                        result = Err(describe(&e));
                        continue;
                    }
                };
                entry.set_delivery(entry.delivery().after(step));
                // Pushed, it has its place, and waits for the peer to read it.
                if step == Step::Pushed {
                    entry.place = clock;
                    let content = entry.content.get_or_insert_default();
                    content.clock = clock;
                    let attachment = matches!(content.kind, Some(Kind::Attachment(_)));
                    if let Some(contact) = inner.contact(peer) {
                        contact.state.awaiting.push(Awaiting {
                            place: clock,
                            history_index: index,
                            read: false,
                            attachment,
                        });
                        keep_last(&mut contact.state.awaiting);
                    }
                }
                entries.push((index, entry));
            }
            inner
                .save_with(&records(peer, &entries), &gone)
                .await
                .map_err(|e| describe(&e))?;
            self.show_changes(inner, peer, &entries);
        }
        // Not from a page that cannot sign in to the server, which takes no push from it: each
        // try would use up a key of the ratchet.
        if result.is_ok() && signs_in_here {
            match self.push_events(inner, peer).await {
                Ok(told) => changed |= told,
                Err(e) => result = Err(e),
            }
        }
        result.map(|()| changed)
    }

    /// Tell `peer` what this client did with its messages, all in one message, once what waits
    /// for it went: on the session, never starting one for it, and never in a request, whose
    /// sender learns nothing until it is accepted. Encrypted and saved once, then pushed as it is
    /// until it goes, so that no key of the ratchet is used twice, nor another on each try, e.g.
    /// while the server cannot be reached: the peer skips only so many. Once it went, what it
    /// told is forgotten, which the next save keeps; if none does, it goes again, which the peer
    /// takes as a duplicate. Returns whether any went.
    async fn push_events(&self, inner: &mut Inner, peer: &PublicKey) -> Result<bool, String> {
        let Some(contact) = inner.contact(peer) else {
            return Ok(false);
        };
        if contact.state.request
            || !contact.state.outbox.is_empty()
            || contact.session.needs_new_session()
        {
            return Ok(false);
        }
        let active = contact.session.active_id().map(|id| id.to_vec());
        // One encrypted on a session that is no longer the active one, which the peer may never
        // have had: what it tells, still in the events, is encrypted again on the active one.
        if contact
            .state
            .sealed_events
            .as_ref()
            .is_some_and(|sealed| Some(&sealed.session) != active.as_ref())
        {
            contact.state.sealed_events = None;
        }
        let sealed = match contact.state.sealed_events.clone() {
            Some(sealed) => sealed,
            None => {
                let Some(events) = contact
                    .state
                    .events
                    .clone()
                    .filter(|events| !events.is_empty())
                else {
                    return Ok(false);
                };
                let snapshot = contact.snapshot();
                let message = contact
                    .session
                    .encrypt(&events.to_bytes())
                    .map_err(|e| describe(&e))?;
                let sealed = SealedEvents {
                    record: Some(OutgoingRecord::sealed(message)),
                    session: active.unwrap_or_default(),
                    events: Some(events),
                };
                contact.state.sealed_events = Some(sealed.clone());
                if let Err(e) = inner.save(&[]).await {
                    inner.roll_back(peer, snapshot)?;
                    return Err(describe(&e));
                }
                sealed
            }
        };
        let contact = inner.contact(peer).ok_or("no such chat")?;
        let message = sealed.record.unwrap_or_default().to_push();
        match contact.session.push(message).await {
            Ok(()) => {}
            // The chat waits for the sign-in, as a message refused for it does, rather than
            // tries every round, and goes once signed in.
            Err(e) if e.kind() == ErrorKind::SignInRequired => {
                self.waits_sign_in.borrow_mut().insert(*peer);
                return Ok(false);
            }
            Err(e) => return Err(describe(&e)),
        }
        // Those told since it was encrypted stay, to go in the next.
        contact.state.sealed_events = None;
        if let (Some(events), Some(told)) = (&mut contact.state.events, &sealed.events) {
            forget_told(events, told);
        }
        if contact.state.events.as_ref().is_some_and(Events::is_empty) {
            contact.state.events = None;
        }
        Ok(true)
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
            let (index, entry) =
                contact.add_received(Content::from_bytes(&first), open && !document().hidden());
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
        if let Some(open) = self.ui.open.get_untracked() {
            self.show_new(inner, &open, views);
        }
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
        if !due || (self.publish_waits_sign_in.get() && !now_anyway) {
            return Ok(());
        }
        // Saved, failed or not: if it failed, the server may still have the prekeys, its reply
        // being lost, and the next publish sends the same signed prekey again, see
        // `Client::publish_keys`.
        if let Err(e) = inner.client.publish_keys(ONE_TIME_PREKEYS).await {
            inner.save(&[]).await.map_err(|e| describe(&e))?;
            // Refused for the sign-in: it waits for one, without failing the round; asked for,
            // it says so.
            if e.kind() == ErrorKind::SignInRequired {
                self.publish_waits_sign_in.set(true);
                if !now_anyway {
                    return Ok(());
                }
            }
            return Err(describe(&e));
        }
        self.publish_waits_sign_in.set(false);
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
            // Where receiving stopped, with the initial messages that came with the rest of the
            // page.
            let mut stalled = None;
            let mut deleted = false;
            // What the peer told of this client's messages, by their history entries.
            let mut steps = vec![];
            for message in page {
                let content = match message.content {
                    Ok(content) => content,
                    // At a message that may be on a session whose initial message is waiting,
                    // the page's last.
                    Err(e) if e.kind() == ErrorKind::Stalled => {
                        stalled = Some(message.initial_messages);
                        continue;
                    }
                    Err(e) if e.kind() == ErrorKind::DuplicateMessage => continue,
                    // Anyone can push to a queue, and an earlier session's messages stay in it.
                    Err(_) => {
                        undecryptable += 1;
                        continue;
                    }
                };
                let mut content = Content::from_bytes(&content);
                if let Some(events) = content.events.take() {
                    steps.extend(contact.told(&events));
                    if content.kind.is_none() {
                        continue;
                    }
                }
                // The peer deleted the chat, and its sessions: the next message goes on a new
                // one. Unless it said so on an earlier session: then it started the chat again
                // since, on the active one, which is the chat now.
                if matches!(content.kind, Some(Kind::Deleted(_))) {
                    if !message.earlier {
                        contact.session.retire();
                    }
                    deleted = true;
                }
                entries.push(contact.add_received(content, open));
            }
            if undecryptable > 0 {
                let label = contact.view().label();
                self.ui.log(format!(
                    "skipped {undecryptable} message(s) from {label} that do not decrypt, e.g. \
                     ones of an earlier session"
                ));
            }
            // The entries of this client's messages that the peer's events moved on; then, if
            // the session is retired, as the peer deleted the chat or the two kept missing each
            // other, what was encrypted on it, and what the peer never read if it deleted the
            // chat, waits for a new one.
            let mut changed = BTreeMap::new();
            let moved = match inner.step(peer, &mut changed, steps).await {
                Ok(()) if deleted || needs_new_session(inner, peer) => {
                    inner.requeue(peer, deleted, &mut changed).await
                }
                Ok(()) => Ok(vec![]),
                Err(e) => Err(describe(&e)),
            };
            let requeued = match moved {
                Ok(requeued) => requeued,
                Err(e) => {
                    inner.roll_back(peer, snapshot)?;
                    return Err(e);
                }
            };
            let changed: Vec<_> = changed.into_iter().collect();
            let records: Vec<_> = records(peer, &entries)
                .into_iter()
                .chain(records(peer, &changed))
                .collect();
            if let Err(e) = inner.save_with(&records, &requeued).await {
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
                self.show_changes(inner, peer, &changed);
                self.show_new(inner, peer, views);
            }
            self.ui.contacts.set(inner.views());
            if let Some(initial_messages) = stalled {
                // Its initial message, which went first, may have come since they were last
                // taken, or have been lost, and come with the page: once they are taken, and
                // those are accepted, receiving goes on, past what still does not decrypt.
                drop(guard);
                self.take_initial_messages().await?;
                let mut guard = self.inner.lock().await;
                if let Some(inner) = guard.as_mut() {
                    for initial_message in &initial_messages {
                        inner.join(peer, initial_message).await?;
                    }
                    if let Some(contact) = inner.contact(peer) {
                        contact.session.skip_stalled();
                    }
                }
            }
        }
    }

    /// Save `content` for `peer`, then push it, encrypted as its turn comes. What the user sends
    /// goes through [`Engine::queue`], to go in order.
    async fn send(&self, peer: PublicKey, content: Kind) -> Result<(), String> {
        {
            let mut guard = self.inner.lock().await;
            let inner = guard.as_mut().ok_or("locked")?;
            let view = inner.add(&peer, content, false).await?;
            self.show_new(inner, &peer, vec![view]);
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
        let (started, signs_in_here) = {
            let mut guard = self.inner.lock().await;
            let inner = guard.as_mut().ok_or("locked")?;
            let started = inner
                .client
                .start_upload(&Fetch::client(&inner.server), size)
                .await;
            (started, same_server(&inner.server, &origin()))
        };
        let upload = match started {
            Ok(upload) => upload,
            // The server keeps attachments only for those signed in to it: its message takes its
            // place in the chat, and waits, with what is sent after it, until this browser is.
            Err(e) if e.kind() == ErrorKind::SignInRequired && signs_in_here => {
                self.wait_for_sign_in(peer, file).await?;
                self.ask_sign_in();
                return Ok(());
            }
            // This page cannot sign in to the server, so the file never would go.
            Err(e) if e.kind() == ErrorKind::SignInRequired => {
                return Err(format!(
                    "{} could not be sent: {NOT_SIGNED_IN_HERE}",
                    file.name()
                ));
            }
            Err(e) => return Err(describe(&e)),
        };
        let pending = PendingUpload {
            id: upload.id().to_vec(),
            token: upload.token().to_vec(),
            key: upload.key().to_vec(),
            expires: upload.expires().unwrap_or_default(),
            name: file.name(),
            mime: file.type_(),
            size,
            uploaded: 0,
            encrypted: 0,
            prefix_hash: Sha256::digest([]).to_vec(),
            announced: false,
            history_index: 0,
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

    /// Keep `file`, to `peer`, until this browser signs in to the server, which takes no
    /// attachment before: its message takes its place in the chat at once, waiting, and what is
    /// sent after it waits for it, see `flush`. Its upload, kept under an ID of this client's,
    /// starts once signed in, see [`start_waiting`](Self::start_waiting); after the page goes,
    /// once the file is chosen again.
    async fn wait_for_sign_in(&self, peer: PublicKey, file: web_sys::File) -> Result<(), String> {
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|e| e.to_string())?;
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        let contact = inner.contact(&peer).ok_or("no such chat")?;
        let waiting = PendingUpload {
            id: id.to_vec(),
            name: file.name(),
            mime: file.type_(),
            size: file.size() as u64,
            announced: true,
            history_index: contact.state.history_len,
            ..PendingUpload::default()
        };
        // Kept first, so that no message waits for an upload that is not kept.
        inner
            .vault
            .save_upload(&peer, &waiting)
            .await
            .map_err(|e| describe(&e))?;
        let pointer = AttachmentPointer {
            id: vec![],
            key: vec![],
            size: waiting.size,
            name: waiting.name.clone(),
            mime: waiting.mime.clone(),
            expires: 0,
        };
        let view = match inner.add(&peer, Kind::Attachment(pointer), true).await {
            Ok(view) => view,
            Err(e) => {
                let _ = inner.vault.forget_upload(&peer, &id).await;
                return Err(e);
            }
        };
        self.show_new(inner, &peer, vec![view]);
        self.ui.contacts.set(inner.views());
        drop(guard);
        self.files.borrow_mut().insert(id, file);
        self.show_upload(
            &peer,
            &waiting,
            UploadState::Paused(WAITS_SIGN_IN.to_string()),
        );
        self.hold(&peer, waiting.history_index);
        Ok(())
    }

    /// Start the uploads that waited for this browser to sign in, whose files are still here.
    async fn start_waiting_uploads(self: &Rc<Self>) {
        let waiting = {
            let guard = self.inner.lock().await;
            let Some(inner) = guard.as_ref() else {
                return;
            };
            match inner.vault.uploads(None).await {
                Ok(uploads) => uploads,
                Err(e) => return self.ui.notify(describe(&e)),
            }
        };
        for (peer, pending) in waiting.into_iter().filter(|(_, p)| !p.started()) {
            let Ok(id) = <[u8; 16]>::try_from(pending.id.as_slice()) else {
                continue;
            };
            let Some(file) = self.files.borrow().get(&id).cloned() else {
                continue;
            };
            if let Err(e) = self.start_waiting(peer, id, file).await {
                self.ui.notify(e);
            }
        }
    }

    /// Start the upload `waiting`, to `peer`, of `file`, which waited for this browser to sign
    /// in: its message, which kept its place in the chat, gets the attachment and goes, with
    /// what waited for it, and the upload runs. Refused again, it waits again.
    async fn start_waiting(
        self: &Rc<Self>,
        peer: PublicKey,
        waiting: [u8; 16],
        file: web_sys::File,
    ) -> Result<(), String> {
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        let Some(kept) = inner
            .vault
            .upload(&peer, &waiting)
            .await
            .map_err(|e| describe(&e))?
            .filter(|pending| !pending.started())
        else {
            return Ok(());
        };
        // Its message still waits for it, unless this record outlived its start, as forgetting
        // it failed: that message has its attachment, and a second upload must not replace it.
        let awaited = inner.contact(&peer).is_some_and(|contact| {
            contact.state.outbox.iter().any(|outgoing| {
                outgoing.history_index == kept.history_index && outgoing.awaits_upload
            })
        });
        if !awaited {
            self.ui
                .uploads
                .update(|uploads| uploads.retain(|upload| upload.id != waiting));
            return inner
                .vault
                .forget_upload(&peer, &waiting)
                .await
                .map_err(|e| describe(&e));
        }
        let started = inner
            .client
            .start_upload(&Fetch::client(&inner.server), kept.size)
            .await;
        let upload = match started {
            Ok(upload) => upload,
            Err(e) if e.kind() == ErrorKind::SignInRequired => {
                drop(guard);
                self.files.borrow_mut().insert(waiting, file);
                self.show_upload(&peer, &kept, UploadState::Paused(WAITS_SIGN_IN.to_string()));
                self.ask_sign_in();
                return Ok(());
            }
            Err(e) => return Err(describe(&e)),
        };
        // Cancelled meanwhile: the server forgets it too, and cancelling fails its message.
        if self.cancelled.borrow().contains(&waiting) {
            let _ = upload.cancel(&Fetch::client(&inner.server)).await;
            return Ok(());
        }
        let pointer = AttachmentPointer {
            id: upload.id().to_vec(),
            key: upload.key().to_vec(),
            size: kept.size,
            name: kept.name.clone(),
            mime: kept.mime.clone(),
            expires: upload.expires().unwrap_or_default(),
        };
        let pending = PendingUpload {
            id: upload.id().to_vec(),
            token: upload.token().to_vec(),
            key: upload.key().to_vec(),
            prefix_hash: Sha256::digest([]).to_vec(),
            history_index: 0,
            expires: upload.expires().unwrap_or_default(),
            ..kept
        };
        // Kept under the server's ID first: if the message is not saved after, the upload is
        // there to cancel, rather than a message with nothing to download.
        inner
            .vault
            .save_upload(&peer, &pending)
            .await
            .map_err(|e| describe(&e))?;
        let mut entry = inner
            .vault
            .entry(&peer, kept.history_index)
            .await
            .map_err(|e| describe(&e))?
            .ok_or("its message is gone")?;
        let content = Kind::Attachment(pointer);
        let record = OutgoingRecord {
            message: None,
            content: content.to_bytes(),
            delivery_hash: vec![],
        };
        entry.content = Some(Content {
            kind: Some(content),
            ..entry.content.unwrap_or_default()
        });
        let contact = inner.contact(&peer).ok_or("no such chat")?;
        let snapshot = contact.snapshot();
        for outgoing in &mut contact.state.outbox {
            if outgoing.history_index == kept.history_index {
                outgoing.awaits_upload = false;
            }
        }
        let changed = [(kept.history_index, entry)];
        let saved = inner
            .save_with(
                &records(&peer, &changed),
                &[(outbox_key(&peer, kept.history_index), Some(record))],
            )
            .await;
        if let Err(e) = saved {
            inner.roll_back(&peer, snapshot)?;
            let _ = inner.vault.forget_upload(&peer, upload.id()).await;
            return Err(describe(&e));
        }
        // Its message has the attachment now: a record left behind is forgotten when found.
        if let Err(e) = inner.vault.forget_upload(&peer, &waiting).await {
            self.ui.log(format!(
                "could not forget the wait of {}: {}",
                pending.name,
                describe(&e)
            ));
        }
        self.show_changes(inner, &peer, &changed);
        // Cancelled while it started, which found nothing left to cancel: it goes no further,
        // and its message fails, as cancelling it before would have done.
        if self.cancelled.borrow().contains(&waiting) {
            let _ = upload.cancel(&Fetch::client(&inner.server)).await;
            let _ = inner.vault.forget_upload(&peer, upload.id()).await;
            self.fail_waiting(inner, &peer, kept.history_index).await?;
            drop(guard);
            if let Err(e) = self.flush(&peer).await {
                self.ui.link.set(Link::Offline(e));
            }
            return Ok(());
        }
        drop(guard);
        // Under the server's ID from now on.
        self.files.borrow_mut().remove(&waiting);
        self.files.borrow_mut().insert(*upload.id(), file.clone());
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != waiting));
        self.running.borrow_mut().remove(&waiting);
        self.running.borrow_mut().insert(*upload.id());
        self.release(&peer, kept.history_index);
        if let Err(e) = self.flush(&peer).await {
            self.ui.link.set(Link::Offline(e));
        }
        self.wake();
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
            expires: pending.expires,
        };
        // Sent first, then kept: going wrong in between sends it twice, not never.
        self.send(*peer, Kind::Attachment(pointer)).await?;
        pending.announced = true;
        self.save_upload(peer, &pending).await?;
        Ok(pending)
    }

    /// The bytes of the file of the history entry `index` of the chat with `peer`, which are
    /// kept apart from it.
    pub async fn file(&self, peer: PublicKey, index: u64) -> Result<Arc<Vec<u8>>, String> {
        let guard = self.inner.lock().await;
        let inner = guard.as_ref().ok_or("locked")?;
        inner
            .vault
            .file(&peer, index)
            .await
            .map(Arc::new)
            .map_err(|e| describe(&e))
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
        self: &Rc<Self>,
        peer: PublicKey,
        id: [u8; 16],
        file: Option<web_sys::File>,
    ) -> Result<(), String> {
        // One that waited for a sign-in starts, its message in its place.
        let waits = {
            let guard = self.inner.lock().await;
            let inner = guard.as_ref().ok_or("locked")?;
            inner
                .vault
                .upload(&peer, &id)
                .await
                .map_err(|e| describe(&e))?
                .is_some_and(|pending| !pending.started())
        };
        if waits {
            let file = file
                .or_else(|| self.files.borrow().get(&id).cloned())
                .ok_or("choose the file again")?;
            return self.start_waiting(peer, id, file).await;
        }
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
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        let pending = inner
            .vault
            .upload(&peer, &id)
            .await
            .map_err(|e| describe(&e))?;
        // One that waited for a sign-in never went: its message fails, and what waited for it
        // goes.
        if let Some(waiting) = pending.as_ref().filter(|pending| !pending.started()) {
            self.fail_waiting(inner, &peer, waiting.history_index)
                .await?;
            inner
                .vault
                .forget_upload(&peer, &id)
                .await
                .map_err(|e| describe(&e))?;
            drop(guard);
            if let Err(e) = self.flush(&peer).await {
                self.ui.link.set(Link::Offline(e));
            }
            return Ok(());
        }
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

    /// Cancel the message at `index`, to `peer`, held until this browser signs in to the server:
    /// it fails, and what waited for it goes, unless it too needs the sign-in. One whose
    /// attachment's upload has not started goes with its upload.
    pub async fn cancel_held(&self, peer: PublicKey, index: u64) -> Result<(), String> {
        let waiting = {
            let guard = self.inner.lock().await;
            let inner = guard.as_ref().ok_or("locked")?;
            let uploads = inner
                .vault
                .uploads(Some(&peer))
                .await
                .map_err(|e| describe(&e))?;
            uploads.into_iter().find_map(|(_, pending)| {
                (!pending.started() && pending.history_index == index)
                    .then(|| <[u8; 16]>::try_from(pending.id.as_slice()).ok())
                    .flatten()
            })
        };
        if let Some(id) = waiting {
            return self.cancel_upload(peer, id).await;
        }
        {
            let mut guard = self.inner.lock().await;
            let inner = guard.as_mut().ok_or("locked")?;
            // Gone meanwhile, e.g. pushed as the sign-in came.
            let waits = inner.contact(&peer).is_some_and(|contact| {
                contact
                    .state
                    .outbox
                    .iter()
                    .any(|outgoing| outgoing.history_index == index)
            });
            if !waits {
                self.release(&peer, index);
                return Ok(());
            }
            self.fail_waiting(inner, &peer, index).await?;
        }
        self.waits_sign_in.borrow_mut().remove(&peer);
        if let Err(e) = self.flush(&peer).await {
            self.ui.link.set(Link::Offline(e));
        }
        self.wake();
        Ok(())
    }

    /// Show the message at `index`, to `peer`, as held until this browser signs in.
    fn hold(&self, peer: &PublicKey, index: u64) {
        self.ui.held.update(|held| {
            held.insert((*peer, index));
        });
    }

    /// Show the message at `index`, to `peer`, as no longer held.
    fn release(&self, peer: &PublicKey, index: u64) {
        if self
            .ui
            .held
            .with_untracked(|held| held.contains(&(*peer, index)))
        {
            self.ui.held.update(|held| {
                held.remove(&(*peer, index));
            });
        }
    }

    /// Fail the message at `index`, to `peer`, which never went, as it was cancelled: it leaves
    /// the outbox, so that what was sent after it goes.
    async fn fail_waiting(
        &self,
        inner: &mut Inner,
        peer: &PublicKey,
        index: u64,
    ) -> Result<(), String> {
        let contact = inner.contact(peer).ok_or("no such chat")?;
        let snapshot = contact.snapshot();
        contact
            .state
            .outbox
            .retain(|outgoing| outgoing.history_index != index);
        let mut entries = BTreeMap::new();
        let failed = match inner
            .step(peer, &mut entries, [(index, Step::Refused)])
            .await
        {
            Ok(()) => {
                let changed: Vec<_> = entries.into_iter().collect();
                inner
                    .save_with(&records(peer, &changed), &[(outbox_key(peer, index), None)])
                    .await
                    .map(|()| changed)
            }
            Err(e) => Err(e),
        };
        match failed {
            Ok(changed) => {
                self.release(peer, index);
                self.show_changes(inner, peer, &changed);
                Ok(())
            }
            Err(e) => {
                inner.roll_back(peer, snapshot)?;
                Err(describe(&e))
            }
        }
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
        match uploaded {
            Ok(true) => {}
            // Deleted from the server, e.g. by the peer, who did not want it: the rest need not
            // go up.
            Ok(false) => {
                self.drop_upload(&peer, id).await?;
                return Err(format!(
                    "{} is no longer on the server, so its upload stopped",
                    pending.name
                ));
            }
            Err(e) => {
                self.show_upload(&peer, &pending, UploadState::Paused(e.clone()));
                return Err(e);
            }
        }
        self.files.borrow_mut().remove(&id);
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != id));
        // Forgotten, with its upload token, which is no use now: deleting it takes its delete
        // token, which its key gives.
        let guard = self.inner.lock().await;
        let inner = guard.as_ref().ok_or("locked")?;
        inner
            .vault
            .forget_upload(&peer, &id)
            .await
            .map_err(|e| describe(&e))
    }

    /// Stop the upload `id`, in the chat with `peer`, if this client uploads it, for good, as
    /// the server no longer has it, and forget it.
    async fn drop_upload(&self, peer: &PublicKey, id: [u8; 16]) -> Result<(), String> {
        let guard = self.inner.lock().await;
        let inner = guard.as_ref().ok_or("locked")?;
        let kept = inner
            .vault
            .upload(peer, &id)
            .await
            .map_err(|e| describe(&e))?
            .is_some();
        if !kept && !self.running.borrow().contains(&id) {
            return Ok(());
        }
        self.cancelled.borrow_mut().insert(id);
        self.files.borrow_mut().remove(&id);
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != id));
        inner
            .vault
            .forget_upload(peer, &id)
            .await
            .map_err(|e| describe(&e))
    }

    /// Delete the attachment `pointer`, of the history entry `index` of the chat with `peer`,
    /// sent or received, from the server, with its delete token, which its key gives: neither
    /// peer can download it any more, though what they downloaded stays. One this client uploads
    /// stops; one the peer uploads stops too, sparing it the rest. The entry notes it, so that
    /// it is not offered again.
    pub async fn delete_attachment(
        &self,
        peer: PublicKey,
        index: u64,
        pointer: &AttachmentPointer,
    ) -> Result<(), String> {
        let not_there = || format!("{} is not on the server", pointer.name);
        let id: [u8; 16] = pointer.id.as_slice().try_into().map_err(|_| not_there())?;
        let key: [u8; 32] = pointer.key.as_slice().try_into().map_err(|_| not_there())?;
        let server = {
            let guard = self.inner.lock().await;
            guard.as_ref().ok_or("locked")?.server.clone()
        };
        match attachment::delete(&Fetch::client(&server), &id, &key).await {
            // Gone already, e.g. expired, or deleted by the peer, as it should be.
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(describe(&e)),
        }
        self.drop_upload(&peer, id).await?;
        self.note_gone(&peer, index, &id).await
    }

    /// Note in the history entry `index` of the chat with `peer` that its attachment `id` is
    /// gone from the server, unless the entry is no longer that attachment's message, as the
    /// chat was deleted, and maybe started again, meanwhile.
    async fn note_gone(&self, peer: &PublicKey, index: u64, id: &[u8; 16]) -> Result<(), String> {
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        let entry = inner
            .vault
            .entry(peer, index)
            .await
            .map_err(|e| describe(&e))?;
        let Some(mut entry) = entry.filter(|entry| {
            matches!(
                entry.content.as_ref().and_then(|content| content.kind.as_ref()),
                Some(Kind::Attachment(pointer)) if pointer.id == id
            )
        }) else {
            return Ok(());
        };
        entry.gone = true;
        inner
            .save(&records(peer, &[(index, entry)]))
            .await
            .map_err(|e| describe(&e))
    }

    /// Upload the chunks of `pending` from `uploaded` on, reading each from `file` in its turn,
    /// unless the upload is cancelled. Returns whether the server still has the attachment: one
    /// deleted meanwhile, e.g. by the peer, is not found.
    async fn upload_chunks(
        &self,
        peer: &PublicKey,
        pending: &mut PendingUpload,
        upload: &Upload,
        file: &web_sys::File,
        mut hasher: Sha256,
    ) -> Result<bool, String> {
        let server = {
            let guard = self.inner.lock().await;
            guard.as_ref().ok_or("locked")?.server.clone()
        };
        // Each chunk shows how far it got as it goes: the bytes before it, and its share of what
        // its request sent.
        let before = Rc::new(Cell::new(0));
        let progress: Progress = {
            let (ui, before, id, size) = (self.ui, before.clone(), *upload.id(), pending.size);
            Rc::new(move |sent, total| {
                let chunk = (size - before.get()).min(CHUNK_SIZE as u64);
                let done = before.get() + chunk * sent / total.max(1);
                ui.uploads.update(|uploads| {
                    if let Some(upload) = uploads.iter_mut().find(|upload| upload.id == id) {
                        upload.done = done;
                    }
                });
            })
        };
        let attachments = Fetch::reporting(&server, progress);
        for index in pending.uploaded..upload.chunks() {
            if self.cancelled.borrow().contains(upload.id()) {
                return Ok(true);
            }
            before.set((u64::from(index) * CHUNK_SIZE as u64).min(pending.size));
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
            if !self
                .put_chunk(peer, pending, &attachments, upload, index, &chunk)
                .await?
            {
                return Ok(false);
            }
            self.keep_chunk(peer, upload.id(), index, &chunk).await?;
            pending.uploaded = index + 1;
        }
        Ok(true)
    }

    /// Upload chunk `index` of `upload`, trying again while the server cannot be reached, unless
    /// the upload is cancelled meanwhile. Returns whether the server still has the attachment.
    async fn put_chunk(
        &self,
        peer: &PublicKey,
        pending: &PendingUpload,
        attachments: &Connect,
        upload: &Upload,
        index: u32,
        chunk: &[u8],
    ) -> Result<bool, String> {
        let mut wait = RETRY_MIN;
        loop {
            match upload.put(attachments, index, chunk).await {
                Ok(()) => return Ok(true),
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
                Err(e) if e.kind() == ErrorKind::Server => {
                    self.show_upload(peer, pending, UploadState::Retrying);
                    sleep(wait).await;
                    wait = (wait * 2).min(RETRY_MAX);
                    if self.cancelled.borrow().contains(upload.id()) {
                        return Ok(true);
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
            done: (u64::from(pending.uploaded) * CHUNK_SIZE as u64).min(pending.size),
            size: pending.size,
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
    /// it got meanwhile, and closing it stops it. Once one of the peer's, sent in its message
    /// at `clock`, is downloaded whole, the peer is told.
    pub async fn open_attachment(
        &self,
        peer: PublicKey,
        pointer: AttachmentPointer,
        clock: u64,
    ) -> Result<(), String> {
        // A message of this client's whose upload waits for it to sign in.
        if pointer.id.is_empty() {
            return Err(format!(
                "{} goes once you sign in to the server.",
                pointer.name
            ));
        }
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
        let opened = self
            .fetch_attachment(peer, &id, pointer, Waiter::Viewer)
            .await;
        let opened = self.told_downloaded(peer, clock, opened).await;
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

    /// The attachment `pointer`, in the chat with `peer`, for the chat to show in place, as small
    /// media, as long as `shows` says it does: from the chunks kept here, or else from the
    /// server, as [`open_attachment`](Self::open_attachment) has it, and the peer is told alike;
    /// none if it stopped showing first.
    pub async fn media(
        &self,
        peer: PublicKey,
        pointer: AttachmentPointer,
        clock: u64,
        shows: &dyn Fn() -> bool,
    ) -> Result<Option<Attachment>, String> {
        let Ok(id) = <[u8; 16]>::try_from(pointer.id.as_slice()) else {
            return Err("the attachment is malformed".to_string());
        };
        let fetched = self
            .fetch_attachment(peer, &id, pointer, Waiter::Chat(shows))
            .await;
        self.told_downloaded(peer, clock, fetched).await
    }

    /// The attachment `fetched`, once the peer is told it is downloaded, if it is the peer's,
    /// sent in its message at `clock`, and came from the server now.
    async fn told_downloaded(
        &self,
        peer: PublicKey,
        clock: u64,
        fetched: Result<Option<(Attachment, bool)>, String>,
    ) -> Result<Option<Attachment>, String> {
        let Some((attachment, from_server)) = fetched? else {
            return Ok(None);
        };
        if from_server
            && clock > 0
            && let Err(e) = self.downloaded(peer, clock).await
        {
            self.ui.link.set(Link::Offline(e));
        }
        Ok(Some(attachment))
    }

    /// Tell `peer` that its attachment, sent in its message at `clock`, is downloaded.
    async fn downloaded(&self, peer: PublicKey, clock: u64) -> Result<(), String> {
        {
            let mut guard = self.inner.lock().await;
            let inner = guard.as_mut().ok_or("locked")?;
            let contact = inner.contact(&peer).ok_or("no such chat")?;
            let events = contact.state.events.get_or_insert_default();
            events.downloaded.push(clock);
            keep_last(&mut events.downloaded);
            inner.save(&[]).await.map_err(|e| describe(&e))?;
        }
        self.flush(&peer).await.map(drop)
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

    /// Whether `waiter` still waits for the attachment `id`.
    fn waits(&self, waiter: Waiter<'_>, id: &[u8; 16]) -> bool {
        match waiter {
            Waiter::Viewer => self.opening(id),
            Waiter::Chat(shows) => shows(),
        }
    }

    /// The file of the attachment `pointer`, whose ID is `id`, in the chat with `peer`, and
    /// whether any of it came from the server, as it was not all downloaded before; none if
    /// `waiter` stopped waiting for it. The viewer shows how far it got.
    async fn fetch_attachment(
        &self,
        peer: PublicKey,
        id: &[u8; 16],
        pointer: AttachmentPointer,
        waiter: Waiter<'_>,
    ) -> Result<Option<(Attachment, bool)>, String> {
        // The sender's own, while on the page that chose it: from its file, as the server may
        // not have it all yet.
        let file = self.files.borrow().get(id).cloned();
        if let Some(file) = file {
            let buffer = JsFuture::from(file.array_buffer())
                .await
                .map_err(|e| format!("Cannot read {}: {}", pointer.name, js_error(e)))?;
            let attachment = Attachment {
                name: pointer.name,
                mime: pointer.mime,
                data: Arc::new(js_sys::Uint8Array::new(&buffer).to_vec()),
            };
            return Ok(Some((attachment, false)));
        }
        let fetching = self.fetching(peer, &pointer).await?;
        // It grows as its chunks decrypt, not to the size the peer claims, which nothing backs
        // until they do.
        let (mut data, mut fetched) = (vec![], false);
        for index in 0..fetching.chunks {
            let Some((plaintext, from_server)) = self.chunk(&fetching, index, waiter).await? else {
                return Ok(None);
            };
            fetched |= from_server;
            data.extend(plaintext);
            if let Waiter::Viewer = waiter {
                self.opened(id, data.len() as u64, false);
            }
        }
        if data.len() as u64 != pointer.size {
            return Err(format!("{} is not the size it should be", pointer.name));
        }
        let attachment = Attachment {
            name: pointer.name,
            mime: pointer.mime,
            data: Arc::new(data),
        };
        Ok(Some((attachment, fetched)))
    }

    /// A URL that plays the attachment `pointer`, in the chat with `peer`, as it is fetched,
    /// through the service worker, see `media-worker.js`: a chunk at a time, as the player asks
    /// for it, so that it plays, and seeks, while it downloads. The peer is told once it is all
    /// here, as when opened, if it is the peer's, sent in its message at `clock`. None if no
    /// service worker controls the page, which then fetches it whole, or if it is malformed. It
    /// plays until [`end_stream`](Self::end_stream).
    pub async fn stream(
        &self,
        peer: PublicKey,
        pointer: &AttachmentPointer,
        clock: u64,
    ) -> Option<String> {
        if !glue::streaming() {
            return None;
        }
        let fetching = self.fetching(peer, pointer).await.ok()?;
        let mut token = [0; 16];
        getrandom::fill(&mut token).ok()?;
        let token = hex(&token);
        let stream = Stream {
            fetching: Rc::new(fetching),
            mime: stream_mime(&pointer.mime),
            clock,
        };
        self.streams.borrow_mut().insert(token.clone(), stream);
        Some(format!("/media/{token}"))
    }

    /// End the stream at `url`, as its player went.
    pub fn end_stream(&self, url: &str) {
        if let Some(token) = url.strip_prefix("/media/") {
            self.streams.borrow_mut().remove(token);
        }
    }

    /// The first chunk of the stream at `url`, e.g. to read the tags of audio from.
    pub async fn stream_head(&self, url: &str) -> Option<Rc<Vec<u8>>> {
        let token = url.strip_prefix("/media/")?;
        self.stream_chunk(token, 0).await.ok().flatten()
    }

    /// Answer the service worker's `request` for a stream's bytes.
    async fn serve_media(&self, request: MediaRequest) {
        match self
            .media_range(&request.token, request.start, request.end)
            .await
        {
            Ok((size, mime, bytes)) => request.reply(Ok((size, &mime, &bytes))),
            Err(status) => request.reply(Err(status)),
        }
    }

    /// The bytes of the stream `token` from `start`, to `end` at most, as far as the chunk they
    /// start in goes, with its size and MIME type; or the HTTP status that says why not.
    async fn media_range(
        &self,
        token: &str,
        start: u64,
        end: Option<u64>,
    ) -> Result<(u64, String, Vec<u8>), u16> {
        const GONE: u16 = 404;
        const OUT_OF_RANGE: u16 = 416;
        let size = self
            .streams
            .borrow()
            .get(token)
            .map(|stream| stream.fetching.size)
            .ok_or(GONE)?;
        if start >= size || end.is_some_and(|end| end < start) {
            return Err(OUT_OF_RANGE);
        }
        let index = u32::try_from(start / CHUNK_SIZE as u64).map_err(|_| OUT_OF_RANGE)?;
        let chunk = match self.stream_chunk(token, index).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return Err(GONE),
            // E.g. its sender cancelled it.
            Err(_) => return Err(502),
        };
        let from = start - u64::from(index) * CHUNK_SIZE as u64;
        let to = end.map_or(u64::MAX, |end| {
            from.saturating_add(end - start).saturating_add(1)
        });
        let bytes = chunk
            .get(from as usize..(to.min(chunk.len() as u64)) as usize)
            .filter(|bytes| !bytes.is_empty())
            .ok_or(OUT_OF_RANGE)?
            .to_vec();
        let mime = self
            .streams
            .borrow()
            .get(token)
            .map(|stream| stream.mime.clone())
            .ok_or(GONE)?;
        Ok((size, mime, bytes))
    }

    /// Chunk `index` of the stream `token`, decrypted: one decrypted lately, or from this
    /// client's own file, while on the page that chose it, or else as [`chunk`](Self::chunk)
    /// has it. Once all its chunks are here, as one came from the server now, the peer is told.
    /// None if the stream ended.
    async fn stream_chunk(&self, token: &str, index: u32) -> Result<Option<Rc<Vec<u8>>>, String> {
        let (fetching, clock) = loop {
            let Some((fetching, clock)) = self
                .streams
                .borrow()
                .get(token)
                .map(|stream| (stream.fetching.clone(), stream.clock))
            else {
                return Ok(None);
            };
            let chunk_of = (fetching.id, index);
            if let Some(chunk) = self.decrypted_chunk(&chunk_of) {
                return Ok(Some(chunk));
            }
            let waiting = match self.loading.borrow_mut().entry(chunk_of) {
                hash_map::Entry::Occupied(mut waiters) => {
                    let (done, waiting) = oneshot::channel();
                    waiters.get_mut().push(done);
                    waiting
                }
                hash_map::Entry::Vacant(vacant) => {
                    vacant.insert(vec![]);
                    break (fetching, clock);
                }
            };
            // Then among those decrypted, unless fetching it failed, or stopped as its stream
            // ended: then fetched here.
            let _ = waiting.await;
        };
        let loaded = self.load_stream_chunk(token, index, &fetching).await;
        // Among those decrypted, if it came: its waiters wake as their senders go.
        self.loading.borrow_mut().remove(&(fetching.id, index));
        let Some((chunk, fetched)) = loaded? else {
            return Ok(None);
        };
        if fetched
            && clock > 0
            && self.all_kept(&fetching).await
            && let Err(e) = self.downloaded(fetching.peer, clock).await
        {
            self.ui.link.set(Link::Offline(e));
        }
        Ok(Some(chunk))
    }

    /// The chunk `chunk_of`, if the streams decrypted it lately, which keeps it longer.
    fn decrypted_chunk(&self, chunk_of: &ChunkOf) -> Option<Rc<Vec<u8>>> {
        let mut decrypted = self.decrypted.borrow_mut();
        let at = decrypted.iter().position(|(of, _)| of == chunk_of)?;
        let kept = decrypted.remove(at)?;
        let chunk = kept.1.clone();
        decrypted.push_back(kept);
        Some(chunk)
    }

    /// Chunk `index` of the stream `token`, which fetches `fetching`, as
    /// [`stream_chunk`](Self::stream_chunk) has it, kept among those decrypted, and whether it
    /// came from the server.
    async fn load_stream_chunk(
        &self,
        token: &str,
        index: u32,
        fetching: &Fetching,
    ) -> Result<Option<(Rc<Vec<u8>>, bool)>, String> {
        let file = self.files.borrow().get(&fetching.id).cloned();
        let (plaintext, fetched) = match file {
            Some(file) => (read_chunk(&file, index, fetching.size).await?, false),
            None => {
                let plays = || self.streams.borrow().contains_key(token);
                match self.chunk(fetching, index, Waiter::Chat(&plays)).await? {
                    Some(chunk) => chunk,
                    None => return Ok(None),
                }
            }
        };
        let chunk = Rc::new(plaintext);
        let mut decrypted = self.decrypted.borrow_mut();
        decrypted.push_back(((fetching.id, index), chunk.clone()));
        if decrypted.len() > CHUNKS_DECRYPTED_KEPT {
            decrypted.pop_front();
        }
        // Served from the page's origin: only ever as video or audio.
        if index == 0
            && let Some(stream) = self.streams.borrow_mut().get_mut(token)
            && let Some(mime) = preview::media_mime(&fetching.name, &stream.mime, &chunk)
                .filter(|mime| mime.starts_with("video/") || mime.starts_with("audio/"))
        {
            stream.mime = mime.to_string();
        }
        Ok(Some((chunk, fetched)))
    }

    /// Whether all the chunks of the attachment `fetching` fetches are kept here.
    async fn all_kept(&self, fetching: &Fetching) -> bool {
        let guard = self.inner.lock().await;
        let Some(inner) = guard.as_ref() else {
            return false;
        };
        inner
            .vault
            .chunks_kept(&fetching.peer, &fetching.id)
            .await
            .is_ok_and(|kept| kept >= fetching.chunks)
    }

    /// What fetching the attachment `pointer`, in the chat with `peer`, takes.
    async fn fetching(
        &self,
        peer: PublicKey,
        pointer: &AttachmentPointer,
    ) -> Result<Fetching, String> {
        let malformed = || "the attachment is malformed".to_string();
        let id = <[u8; 16]>::try_from(pointer.id.as_slice()).map_err(|_| malformed())?;
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
        let guard = self.inner.lock().await;
        let inner = guard.as_ref().ok_or("locked")?;
        let unfinished = inner
            .vault
            .upload(&peer, &id)
            .await
            .map_err(|e| describe(&e))?
            .map(|pending| pending.uploaded);
        Ok(Fetching {
            peer,
            id,
            key,
            name: pointer.name.clone(),
            size: pointer.size,
            chunks,
            unfinished,
            attachments: Fetch::client(&inner.server),
        })
    }

    /// Chunk `index` of the attachment `fetching` fetches, decrypted: kept here, or else fetched
    /// from the server, waiting for it while it is uploaded, and kept from then on; and whether
    /// it came from the server. None if `waiter` stopped waiting for it.
    async fn chunk(
        &self,
        fetching: &Fetching,
        index: u32,
        waiter: Waiter<'_>,
    ) -> Result<Option<(Vec<u8>, bool)>, String> {
        if !self.waits(waiter, &fetching.id) {
            return Ok(None);
        }
        let (chunk, kept) = match self.kept_chunk(&fetching.peer, &fetching.id, index).await? {
            Some(chunk) => (chunk, true),
            None if fetching
                .unfinished
                .is_some_and(|uploaded| index >= uploaded) =>
            {
                return Err(format!(
                    "{} is not all uploaded: choose the file again to go on",
                    fetching.name
                ));
            }
            None => match self
                .await_chunk(
                    &fetching.attachments,
                    &fetching.name,
                    &fetching.id,
                    index,
                    waiter,
                )
                .await?
            {
                Some(chunk) => (chunk, false),
                None => return Ok(None),
            },
        };
        let last = index + 1 == fetching.chunks;
        let plaintext = attachment::decrypt_chunk(&fetching.key, index, last, &chunk)
            .map_err(|_| format!("{} does not decrypt", fetching.name))?;
        // Kept only once it decrypts, so that a chunk that does not is fetched again next time
        // rather than kept for good.
        if !kept {
            self.keep_chunk(&fetching.peer, &fetching.id, index, &chunk)
                .await?;
        }
        Ok(Some((plaintext, !kept)))
    }

    /// Chunk `index` of the attachment `id`, named `name`, from the server, waiting for it while
    /// it is uploaded, unless no chunk comes for [`STALLED`] milliseconds; none if `waiter`
    /// stopped waiting for it meanwhile.
    async fn await_chunk(
        &self,
        attachments: &Connect,
        name: &str,
        id: &[u8; 16],
        index: u32,
        waiter: Waiter<'_>,
    ) -> Result<Option<Vec<u8>>, String> {
        let (mut waited, mut wait) = (0, POLL_CHUNK_MIN);
        loop {
            if !self.waits(waiter, id) {
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
        let hello = inner.greeting();
        // The chat's first message, at its first place.
        let mut greeting = hello.to_bytes();
        stamp(&mut greeting, 1);
        let session = inner
            .client
            .initiate(&peer, &greeting, Fetch::client(&inner.server))
            .await
            .map_err(|e| match e.kind() {
                session::ErrorKind::NotFound => {
                    "nobody published keys for that key on this server".to_string()
                }
                _ => describe(&e),
            })?;
        // Telling the peer that the chat was deleted here, if that has not gone yet, goes no
        // more: this session replaces the deleted one there anyway.
        inner.state.farewells.retain(|farewell| {
            farewell
                .push
                .as_ref()
                .is_none_or(|push| push.recipient != peer.as_slice())
        });
        let entry = HistoryEntry {
            outgoing: true,
            at: now(),
            content: Some(Content {
                clock: 1,
                kind: Some(hello),
                events: None,
            }),
            delivery: Delivery::Sent.into(),
            place: 1,
            ..HistoryEntry::default()
        };
        inner.contacts.push(Contact {
            peer,
            session,
            state: ContactState {
                peer: peer.to_vec(),
                name,
                history_len: 1,
                last_activity: now(),
                clock: 1,
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
        self.show_history(inner, &peer).await;
        let Some(contact) = inner.contact(&peer) else {
            return;
        };
        let read = contact.read_all();
        self.ui.open.set(Some(peer));
        if read && let Err(e) = inner.save(&[]).await {
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

    /// The files of the chat with `peer`, newest first, as its file browser lists them: those its
    /// messages carry, and its attachments. The whole history is read, a page at a time, without
    /// the files' bytes, each page under the lock of its own, so that syncing and sending go on
    /// meanwhile.
    pub async fn files(&self, peer: PublicKey) -> Result<Vec<FileView>, String> {
        let mut files = vec![];
        // The server's time, by which the attachments it deleted already are not offered.
        let now = {
            let guard = self.inner.lock().await;
            guard.as_ref().ok_or("locked")?.client.clock().now()
        };
        let mut end = u64::MAX;
        loop {
            let guard = self.inner.lock().await;
            let inner = guard.as_ref().ok_or("locked")?;
            let contact = inner
                .contacts
                .iter()
                .find(|contact| contact.peer == peer)
                .ok_or("no such chat")?;
            // Not past its end, as the chat may have been deleted and started again meanwhile.
            end = end.min(contact.state.history_len);
            if end == 0 {
                break;
            }
            let page = inner
                .vault
                .history(&peer, end, HISTORY_SHOWN)
                .await
                .map_err(|e| describe(&e))?;
            for (index, entry) in page.into_iter().rev() {
                // Sorted by content as it came, if it came with its bytes; else by its name and
                // type, as an attachment.
                let sort = entry.sort();
                let gone = entry.gone;
                let message = contact.message(index, entry);
                let (name, mime, size) = match &message.body {
                    Body::File(file) => (file.name.clone(), file.mime.clone(), file.size),
                    Body::Remote(remote) => (
                        remote.pointer.name.clone(),
                        remote.pointer.mime.clone(),
                        remote.pointer.size,
                    ),
                    _ => continue,
                };
                let (deletable, gone) = match &message.body {
                    Body::Remote(remote) => {
                        let gone = gone || expired(&remote.pointer, now);
                        (!gone && uploaded(&remote.pointer), gone)
                    }
                    _ => (false, false),
                };
                files.push(FileView {
                    index,
                    at: message.at,
                    outgoing: message.outgoing,
                    deletable,
                    gone,
                    sort: match sort {
                        Sort::Unknown => preview::sort(&name, &mime, &[]),
                        sort => sort,
                    },
                    name,
                    size,
                    body: message.body,
                });
            }
            end = end.saturating_sub(HISTORY_SHOWN);
        }
        Ok(files)
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
        if !contact.read_all() {
            return;
        }
        if let Err(e) = inner.save(&[]).await {
            self.ui.notify(describe(&e));
        }
        self.ui.contacts.set(inner.views());
        drop(guard);
        if let Err(e) = self.flush(&peer).await {
            self.ui.link.set(Link::Offline(e));
        }
    }

    /// Accept the request of `peer`, naming the peer `name`.
    pub async fn accept(&self, peer: PublicKey, name: String) -> Result<(), String> {
        self.change_contact(peer, |contact| {
            contact.state.request = false;
            contact.state.name = name.trim().to_string();
        })
        .await?;
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
        inner.save(&[]).await.map_err(|e| describe(&e))?;
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
        // Not for a request, which a stranger may have sent: they learn nothing of it. What was
        // read and not told yet goes first, so that the peer sends again only what was not.
        let mut farewell = vec![];
        if let Some(contact) = inner.contact(&peer)
            && !contact.state.request
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
                farewell.push(Farewell {
                    push: Some(
                        contact
                            .session
                            .push_request(sealed.record.unwrap_or_default().to_push()),
                    ),
                });
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
                    farewell.push(Farewell {
                        push: Some(contact.session.push_request(message)),
                    });
                }
            }
        }
        // Forgotten in the vault first, so that if that fails, the chat stays whole; with the
        // records of other chats left unsaved, as with each save.
        let mut state = inner.app_state();
        state.contacts.retain(|contact| contact.peer != peer);
        state.farewells.extend(farewell.clone());
        let unsaved = inner
            .unsaved
            .iter()
            .filter(|(unsaved, _)| *unsaved != peer)
            .map(|(_, record)| record);
        if let Err(e) = inner.vault.forget(&state, &peer, unsaved).await {
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
            self.files.borrow_mut().remove(&id);
        }
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.peer != peer));
        // Nor does what waited for a sign-in, which would otherwise hold up a chat started
        // again with the peer, or go to it.
        self.waits_sign_in.borrow_mut().remove(&peer);
        inner.contacts.retain(|contact| contact.peer != peer);
        // The other chats' records left unsaved were saved with it, and show at the next sync.
        inner.saved_late.extend(
            inner
                .unsaved
                .drain(..)
                .map(|(unsaved, _)| unsaved)
                .filter(|unsaved| *unsaved != peer),
        );
        inner.state.farewells.extend(farewell);
        self.wake();
        if self.ui.open.get_untracked() == Some(peer) {
            self.ui.open.set(None);
            self.ui.messages.set(vec![]);
        }
        self.ui.contacts.set(inner.views());
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
    /// Add `content` to the chat with `peer`, to be pushed in its turn, see `flush`: one that
    /// `awaits_upload` waits, with those after it, for its attachment's upload to start. Saved,
    /// or else forgotten; returns how it shows.
    async fn add(
        &mut self,
        peer: &PublicKey,
        content: Kind,
        awaits_upload: bool,
    ) -> Result<MessageView, String> {
        let contact = self.contact(peer).ok_or("no such chat")?;
        if contact.state.request {
            return Err("accept the request first".into());
        }
        // If saving fails, the message is forgotten: it never left.
        let snapshot = contact.snapshot();
        // Encrypted as it goes, once its place in the chat is known, see `flush`.
        let record = OutgoingRecord {
            message: None,
            content: content.to_bytes(),
            delivery_hash: vec![],
        };
        let index = contact.state.history_len;
        contact.state.history_len += 1;
        contact.state.last_activity = now();
        contact.state.outbox.push(Outgoing {
            history_index: index,
            sealed: false,
            clock: 0,
            awaits_upload,
        });
        let entry = HistoryEntry {
            outgoing: true,
            at: now(),
            content: Some(Content {
                kind: Some(content),
                ..Content::default()
            }),
            delivery: Delivery::Pending.into(),
            ..HistoryEntry::default()
        };
        let view = contact.message(index, entry.clone());
        let saved = self
            .save_with(
                &[(history_key(peer, index), entry)],
                &[(outbox_key(peer, index), Some(record))],
            )
            .await;
        if let Err(e) = saved {
            self.roll_back(peer, snapshot)?;
            return Err(describe(&e));
        }
        Ok(view)
    }

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
        self.vault
            .save(&self.app_state(), unsaved.chain(entries), outgoing)
            .await?;
        self.saved_late
            .extend(self.unsaved.drain(..).map(|(peer, _)| peer));
        Ok(())
    }

    /// Encrypt the next message waiting to `peer`, now that it goes, at the next place in the
    /// chat, after what came so far: on the session, or on a new one if there is none to send
    /// on, as the two kept missing each other or the peer deleted the chat. Saved before it
    /// goes, so that no key of the ratchet is used twice. One encrypted while the server cannot
    /// be reached keeps its place, after what had come then. If no session can ever start, as
    /// the peer has no keys on the server, or bad ones, the messages waiting fail for good:
    /// returns why.
    async fn seal_next(&mut self, peer: &PublicKey) -> Result<Option<String>, String> {
        let greeting = self.greeting();
        let contact = self
            .contacts
            .iter_mut()
            .find(|contact| contact.peer == *peer)
            .ok_or("no such chat")?;
        if contact.session.needs_new_session() {
            let snapshot = contact.snapshot();
            contact.state.clock = contact.state.clock.saturating_add(1);
            let mut hello = greeting.to_bytes();
            stamp(&mut hello, contact.state.clock);
            match self.client.start_again(&mut contact.session, &hello).await {
                // Its initial message went: kept at once.
                Ok(()) => self.save(&[]).await.map_err(|e| describe(&e))?,
                Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::InvalidKeys) => {
                    self.roll_back(peer, snapshot)?;
                    return self.fail_waiting(peer, describe(&e)).await.map(Some);
                }
                Err(e) => {
                    self.roll_back(peer, snapshot)?;
                    return Err(describe(&e));
                }
            }
        }
        let contact = self.contact(peer).ok_or("no such chat")?;
        let Some(next) = contact
            .state
            .outbox
            .iter()
            .position(|outgoing| !outgoing.sealed)
        else {
            return Ok(None);
        };
        let index = contact.state.outbox[next].history_index;
        let mut content = self
            .vault
            .outgoing(peer, index)
            .await
            .map_err(|e| describe(&e))?
            .content;
        let contact = self.contact(peer).ok_or("no such chat")?;
        let snapshot = contact.snapshot();
        let clock = contact.state.clock.saturating_add(1);
        stamp(&mut content, clock);
        let sealed = contact
            .session
            .encrypt(&content)
            .map_err(|e| describe(&e))?;
        contact.state.clock = clock;
        let outgoing = &mut contact.state.outbox[next];
        (outgoing.sealed, outgoing.clock) = (true, clock);
        let record = OutgoingRecord::sealed(sealed);
        if let Err(e) = self
            .save_with(&[], &[(outbox_key(peer, index), Some(record))])
            .await
        {
            self.roll_back(peer, snapshot)?;
            return Err(describe(&e));
        }
        Ok(None)
    }

    /// Fail the messages waiting to `peer`, as they cannot go, for `reason`, which it returns.
    async fn fail_waiting(&mut self, peer: &PublicKey, reason: String) -> Result<String, String> {
        let contact = self.contact(peer).ok_or("no such chat")?;
        let waiting: Vec<_> = contact
            .state
            .outbox
            .iter()
            .filter(|outgoing| !outgoing.sealed)
            .map(|outgoing| outgoing.history_index)
            .collect();
        contact.state.outbox.retain(|outgoing| outgoing.sealed);
        let mut entries = BTreeMap::new();
        let steps = waiting.iter().map(|index| (*index, Step::Refused));
        self.step(peer, &mut entries, steps)
            .await
            .map_err(|e| describe(&e))?;
        let gone: Vec<_> = waiting
            .iter()
            .map(|index| (outbox_key(peer, *index), None))
            .collect();
        let entries: Vec<_> = entries.into_iter().collect();
        self.save_with(&records(peer, &entries), &gone)
            .await
            .map_err(|e| describe(&e))?;
        Ok(reason)
    }

    /// Move the history entries of the chat with `peer` on by `steps`, each read from the vault
    /// into `entries`, unless there already.
    async fn step(
        &self,
        peer: &PublicKey,
        entries: &mut BTreeMap<u64, HistoryEntry>,
        steps: impl IntoIterator<Item = (u64, Step)>,
    ) -> crate::vault::Result<()> {
        for (index, step) in steps {
            let entry = match entries.entry(index) {
                btree_map::Entry::Occupied(entry) => entry.into_mut(),
                btree_map::Entry::Vacant(vacant) => match self.vault.entry(peer, index).await? {
                    Some(entry) => vacant.insert(entry),
                    None => continue,
                },
            };
            entry.set_delivery(entry.delivery().after(step));
            // Waiting again, it has no place until it goes.
            if entry.delivery() == Delivery::Pending {
                entry.place = 0;
            }
        }
        Ok(())
    }

    /// Put back to wait to be encrypted again, see [`seal_next`](Self::seal_next), what was
    /// encrypted for `peer` on the session if it was retired since, to go on a new one; and, if
    /// the peer `deleted` the chat, what it never read, as it pushed that already, to go on the
    /// new one, or on the active one if the peer started it again already. Their entries move
    /// on in `entries`. What the peer was to be told of its messages before goes no more then:
    /// it has no chat to tell of. Their contents come from the history. Returns the records to
    /// save with the state.
    async fn requeue(
        &mut self,
        peer: &PublicKey,
        deleted: bool,
        entries: &mut BTreeMap<u64, HistoryEntry>,
    ) -> Result<Vec<(String, Option<OutgoingRecord>)>, String> {
        let contact = self.contact(peer).ok_or("no such chat")?;
        let mut again: Vec<_> = if deleted {
            let unread = contact
                .state
                .awaiting
                .iter()
                .filter(|awaiting| !awaiting.read)
                .map(|awaiting| awaiting.history_index)
                .collect();
            contact.state.awaiting.clear();
            contact.state.events = None;
            contact.state.sealed_events = None;
            contact.state.unseen.clear();
            unread
        } else {
            vec![]
        };
        again.sort_unstable();
        // On the active session, what is encrypted goes as it is.
        let retired = contact.session.needs_new_session();
        let sealed: Vec<_> = contact
            .state
            .outbox
            .iter()
            .filter(|outgoing| retired && outgoing.sealed)
            .map(|outgoing| outgoing.history_index)
            .collect();
        for outgoing in &mut contact.state.outbox {
            if sealed.contains(&outgoing.history_index) {
                (outgoing.sealed, outgoing.clock) = (false, 0);
            }
        }
        // The ones pushed already go first, in the order they went.
        let pushed: Vec<_> = again
            .iter()
            .map(|history_index| Outgoing {
                history_index: *history_index,
                sealed: false,
                clock: 0,
                awaits_upload: false,
            })
            .collect();
        contact.state.outbox.splice(0..0, pushed);
        let steps = again.iter().map(|index| (*index, Step::Resent));
        self.step(peer, entries, steps)
            .await
            .map_err(|e| describe(&e))?;
        let mut records = vec![];
        for index in again.iter().chain(&sealed) {
            let entry = match entries.get(index) {
                Some(entry) => Some(entry.clone()),
                None => self
                    .vault
                    .entry(peer, *index)
                    .await
                    .map_err(|e| describe(&e))?,
            };
            let content = match entry {
                Some(entry) => self
                    .vault
                    .content(peer, *index, &entry)
                    .await
                    .map_err(|e| describe(&e))?,
                None => None,
            };
            let record = OutgoingRecord {
                message: None,
                content: content.map(|kind| kind.to_bytes()).unwrap_or_default(),
                delivery_hash: vec![],
            };
            records.push((outbox_key(peer, *index), Some(record)));
        }
        Ok(records)
    }

    /// Accept `initial_message`, of the peer of the chat with `peer`, which came with one of its
    /// messages rather than through the inbox, where it was lost: its session joins the chat,
    /// see `Session::keep`, and its greeting shows. One accepted already, or not from the peer,
    /// changes nothing.
    async fn join(
        &mut self,
        peer: &PublicKey,
        initial_message: &InitialMessage,
    ) -> Result<(), String> {
        let mailbox = Fetch::client(&self.server);
        let Ok((session, first)) = self.client.accept(peer, initial_message, mailbox) else {
            return Ok(());
        };
        if initial_message.x3dh.one_time_prekey.is_some() {
            self.state.used_one_time_prekeys += 1;
        }
        let contact = self.contact(peer).ok_or("no such chat")?;
        let older = std::mem::replace(&mut contact.session, session);
        contact.session.keep(older).map_err(|e| describe(&e))?;
        let (index, entry) = contact.add_received(Content::from_bytes(&first), false);
        let record = (history_key(peer, index), entry);
        if let Err(e) = self.save(std::slice::from_ref(&record)).await {
            // Accepted, it cannot be again: it shows once saved.
            self.unsaved.push((*peer, record));
            return Err(describe(&e));
        }
        self.saved_late.push(*peer);
        Ok(())
    }

    /// The greeting a session this client starts begins with: its first message, which shows
    /// the peer that the initial message is this client's, and lets the peer write back.
    fn greeting(&self) -> Kind {
        Kind::Hello(Hello {
            name: self.state.name.clone(),
        })
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
    /// Show `views`, new in the chat with `peer`, if it is on screen, in its order.
    fn show_new(&self, inner: &Inner, peer: &PublicKey, views: Vec<MessageView>) {
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
    /// screen: how far each got, and its place, in the chat's order.
    fn show_changes(&self, inner: &Inner, peer: &PublicKey, entries: &[(u64, HistoryEntry)]) {
        if self.ui.open.get_untracked() != Some(*peer) || entries.is_empty() {
            return;
        }
        let me = inner.client.identity_key();
        self.ui.messages.update(|messages| {
            for (index, entry) in entries {
                if let Some(message) = messages.iter_mut().find(|message| message.index == *index) {
                    message.place = entry.place;
                    if entry.outgoing {
                        message.delivery = entry.delivery();
                    }
                }
            }
            order(messages, &me, peer);
        });
    }
}

/// The records of `entries` of the chat with `peer`.
fn records(peer: &PublicKey, entries: &[(u64, HistoryEntry)]) -> Vec<(String, HistoryEntry)> {
    entries
        .iter()
        .map(|(index, entry)| (history_key(peer, *index), entry.clone()))
        .collect()
}

/// Whether the chat with `peer` has no session to send on.
fn needs_new_session(inner: &Inner, peer: &PublicKey) -> bool {
    inner
        .contacts
        .iter()
        .any(|contact| contact.peer == *peer && contact.session.needs_new_session())
}

/// The place in the chat of the peer's message whose clock is `clock`, as the chat is `state`,
/// see [`content::place`].
fn place_of(clock: u64, state: &ContactState) -> u64 {
    content::place(clock, state.peer_last.max(state.read_by_peer), state.clock)
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

    /// Add `content`, received, to the history, at its place in the chat, counting it as unread
    /// unless the chat is `open`: then it is read, which the peer is told. Returns the entry and
    /// its index.
    fn add_received(&mut self, content: Content, open: bool) -> (u64, HistoryEntry) {
        let place = place_of(content.clock, &self.state);
        self.state.clock = self.state.clock.max(place);
        self.state.peer_last = place;
        match &content.kind {
            Some(Kind::Hello(hello)) => self.state.hello_name = hello.name.clone(),
            _ if !open => self.state.unread += 1,
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
        let index = self.state.history_len;
        self.state.history_len += 1;
        self.state.last_activity = now();
        let entry = HistoryEntry {
            outgoing: false,
            at: now(),
            content: Some(content),
            place,
            ..HistoryEntry::default()
        };
        (index, entry)
    }

    /// Tell the peer that its message at `clock` was read.
    fn tell_read(&mut self, clock: u64) {
        let events = self.state.events.get_or_insert_default();
        events.read.push(clock);
        keep_last(&mut events.read);
    }

    /// Count the chat's messages as read, as it is on screen; the peer is told of those it was
    /// not told of. Returns whether that changed anything.
    fn read_all(&mut self) -> bool {
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
    fn told(&mut self, events: &Events) -> Vec<(u64, Step)> {
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
    fn message(&self, index: u64, mut entry: HistoryEntry) -> MessageView {
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
        let body = match kind {
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
                pointer,
                clock,
            }),
            None => Body::Unknown,
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

/// The MIME type a stream is served as until its first bytes tell, from the page's origin: the
/// type its sender gave, if it is a plain video or audio type, else none in particular.
fn stream_mime(mime: &str) -> String {
    let mime = mime.to_lowercase();
    let plain = mime
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/+-.".contains(&byte));
    if plain && (mime.starts_with("video/") || mime.starts_with("audio/")) {
        mime
    } else {
        "application/octet-stream".to_string()
    }
}

/// Chunk `index` of `file`, of `size` bytes, as the attachment cuts it.
async fn read_chunk(file: &web_sys::File, index: u32, size: u64) -> Result<Vec<u8>, String> {
    let start = u64::from(index) * CHUNK_SIZE as u64;
    read(file, start, (start + CHUNK_SIZE as u64).min(size)).await
}

/// Forget, of `events`, what `told` told the peer already.
fn forget_told(events: &mut Events, told: &Events) {
    events.read.retain(|clock| !told.read.contains(clock));
    events
        .downloaded
        .retain(|clock| !told.downloaded.contains(clock));
}

/// Whether the attachment `pointer` went up, rather than waits for a sign-in, so that either
/// peer can delete it from the server while it is there.
fn uploaded(pointer: &AttachmentPointer) -> bool {
    pointer.id.len() == 16 && pointer.key.len() == 32
}

/// Whether the attachment `pointer` expired by `now`, the server's time, as far as its message
/// tells.
fn expired(pointer: &AttachmentPointer, now: u64) -> bool {
    pointer.expires != 0 && pointer.expires <= now
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

    #[test]
    fn a_peer_cannot_place_a_message_before_what_it_saw() {
        let state = ContactState {
            clock: 9,
            peer_last: 5,
            read_by_peer: 7,
            ..ContactState::default()
        };
        // An honest peer's clock is past both.
        assert_eq!(place_of(8, &state), 8);
        // Backdated, it goes after the peer's last message, and the one it read.
        assert_eq!(place_of(2, &state), 8);
        // Without a clock, where it came.
        assert_eq!(place_of(0, &state), 10);
        // Nor far past the chat's highest place, where it would pin the chat's clock.
        assert_eq!(
            place_of(u64::MAX, &state),
            9 + session::protocol::content::MAX_AHEAD
        );
    }
}
