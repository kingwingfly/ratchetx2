//! What the page shows: plain data in signals, which the engine keeps up to date.

use std::{fmt, sync::Arc, time::Duration};

use leptos::prelude::*;
use session::PublicKey;

use crate::{
    content::AttachmentPointer,
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
    pub outgoing: bool,
    pub at: u64,
    pub body: Body,
    pub delivery: Delivery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Delivery {
    Received,
    /// Encrypted, and waiting to be pushed.
    Pending,
    Sent,
    /// It could not be pushed, e.g. it is too large.
    Failed,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    Text(String),
    File(Attachment),
    /// A file sent as an attachment, which opening fetches unless it is kept here already.
    Remote(RemoteFile),
    /// A greeting, which starts a session; the name the sender goes by.
    Hello(String),
    /// A kind of message this client cannot show.
    Unknown,
}

/// An upload of an attachment to `peer`, as shown in their chat.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UploadView {
    pub peer: PublicKey,
    pub id: [u8; 16],
    pub name: String,
    /// Chunks the server has, of `chunks`.
    pub uploaded: u32,
    pub chunks: u32,
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
}

#[derive(Debug, Clone, Copy)]
pub struct Ui {
    pub phase: RwSignal<Phase>,
    pub link: RwSignal<Link>,
    /// A sync asked for on the page, until a round that started after it ends.
    pub syncing: RwSignal<bool>,
    /// Notifications come over the server's WebSocket, so the client rarely polls.
    pub live: RwSignal<bool>,
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
    /// What the client is busy with.
    pub busy: RwSignal<Option<String>>,
    pub dialog: RwSignal<Option<Dialog>>,
    /// The file in the viewer.
    pub viewer: RwSignal<Option<Attachment>>,
}

impl Ui {
    pub fn new() -> Self {
        Self {
            phase: RwSignal::new(Phase::Loading),
            link: RwSignal::new(Link::Connecting),
            syncing: RwSignal::new(false),
            live: RwSignal::new(false),
            uploads: RwSignal::new(vec![]),
            me: RwSignal::new(None),
            contacts: RwSignal::new(vec![]),
            open: RwSignal::new(None),
            messages: RwSignal::new(vec![]),
            log: RwSignal::new(vec![]),
            notice: RwSignal::new(None),
            busy: RwSignal::new(None),
            dialog: RwSignal::new(None),
            viewer: RwSignal::new(None),
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
