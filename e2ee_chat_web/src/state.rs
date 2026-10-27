//! What the page shows: plain data in signals, which the engine keeps up to date.

use std::{fmt, sync::Arc, time::Duration};

use leptos::prelude::*;
use session::PublicKey;

use crate::{
    content::AttachmentPointer,
    preview::Sort,
    util::{now, short},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Loading,
    /// No vault in this browser yet.
    Create,
    Locked,
    Unlocked,
    /// Another tab has the vault open.
    Elsewhere,
    /// The browser's storage failed, so whether it holds a vault is unknown; the error.
    Unavailable(String),
}

/// How the last sync went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    Connecting,
    Synced(u64),
    Offline(String),
}

/// This client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Me {
    pub name: String,
    pub key: PublicKey,
    pub server: String,
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
    /// The server cannot be reached; it goes on once it can.
    Retrying,
    /// Stopped, for this reason; going on may need the file chosen again.
    Paused(String),
}

/// An attachment in the chat with `peer`.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteFile {
    pub peer: PublicKey,
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
    /// the inviter's server if it is not the page's own.
    NewChat {
        key: String,
        name: String,
        server: Option<String>,
    },
    /// This client's key and name.
    Identity,
    /// A contact's name, key and safety number; for a request, accept or delete it.
    Contact(PublicKey),
    /// The files of the chat with a peer.
    Files(PublicKey),
}

/// A file of a chat, as its file browser lists it.
#[derive(Debug, Clone, PartialEq)]
pub struct FileView {
    /// Its message's entry in the history.
    pub index: u64,
    /// When it was sent or received.
    pub at: u64,
    pub outgoing: bool,
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
}
