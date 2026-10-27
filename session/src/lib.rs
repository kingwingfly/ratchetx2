#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod attachment;
pub mod error;
#[cfg(feature = "prost")]
pub mod proto;
mod safety;

use core::mem;

use bon::Builder;
use bytes::Bytes;
pub use error::{Error, ErrorKind, Result};
use party::{EncryptedMessage, Party};
use prost::Message as _;
pub use protocol;
use protocol::{
    attachment::{LocalAttachments, StartUploadRequest},
    handshake::{
        self, FetchBundleRequest, LocalHandshake, PublishRequest, SendInitialMessageRequest,
        TakeInitialMessagesRequest,
    },
    mailbox::{Envelope, FetchRequest, LocalMailbox, PushRequest},
    notify::SubscribeRequest,
};
use ratchetx2::{DhPrivateKey, Ratchet, SharedKeys};
pub use safety::safety_number;
pub use x3dh::PublicKey;
use x3dh::{LocalPrekeys, PrekeyBundle};
use xeddsa::XEdDSAPrivateKey;

/// An initial message from a peer who wants to start a session, with the session's first
/// message; accept it with [`Client::accept`].
#[derive(Debug, Clone, PartialEq)]
pub struct InitialMessage {
    /// X3DH's part: the identity key it claims to come from, the ephemeral key, and the prekeys
    /// it uses.
    pub x3dh: x3dh::InitialMessage,
    /// The session's first message, which only the owner of that identity key can have
    /// encrypted.
    pub first_message: EncryptedMessage,
}

impl TryFrom<&handshake::InitialMessage> for InitialMessage {
    type Error = Error;

    /// Fails with [`ErrorKind::InvalidInitialMessage`] if it is malformed, or has no first
    /// message.
    fn try_from(message: &handshake::InitialMessage) -> Result<Self> {
        let malformed = || Error::from(ErrorKind::InvalidInitialMessage);
        Ok(Self {
            x3dh: x3dh::InitialMessage::try_from(message).map_err(|_| malformed())?,
            first_message: message.first_message.clone().ok_or_else(malformed)?,
        })
    }
}

/// A message received, see [`Session::receive`].
#[derive(Debug)]
pub struct Received {
    /// Its content, or why there is none.
    pub content: Result<Vec<u8>>,
    /// Whether it decrypted on an earlier session [kept](Session::keep), rather than the active
    /// one: the peer sent it before the session that replaced it, e.g. before deleting the chat
    /// and starting it again.
    pub earlier: bool,
    /// The initial message of its session, which its sender sends with each message while this
    /// client has not answered that session. For the message receiving [stalled](ErrorKind::Stalled)
    /// at, those that came with the rest of its page too, any of which may be the session it,
    /// or one after it, is on: accepting them with [`Client::accept`] may let them decrypt.
    pub initial_messages: Vec<InitialMessage>,
}

/// Number of earlier sessions with its peer that a [`Session`] keeps, only to decrypt the
/// messages sent on them; see [`Session::keep`].
pub const KEPT_SESSIONS: usize = 3;

/// How many times the peers may turn between one sending on its session and the other's
/// message decrypting only on an earlier one, before the session is retired; see
/// [`Session::keep`].
pub const MAX_DIRECTION_CHANGES: u32 = 5;

/// An identity on a handshake server: publishes prekeys, starts and accepts sessions.
///
/// [`Client::new`] gives it a new random identity key, and [`Client::builder`] can set one:
/// `Client::builder(handshake).identity(identity).build()`. [`Client::restore`] brings back a
/// client from its saved [`state`](Client::state).
#[derive(Debug, Builder)]
pub struct Client<H> {
    #[builder(start_fn)]
    handshake: H,
    /// The identity key; a new random one unless set.
    #[builder(
        name = identity,
        with = |identity: XEdDSAPrivateKey| ClientState::new(identity),
        default = ClientState::new(XEdDSAPrivateKey::generate()),
    )]
    state: ClientState,
    #[builder(skip = state.identity.compute_public_key().to_bytes())]
    identity_key: PublicKey,
}

/// What a [`Client`] keeps besides its transport: the identity key, the prekeys and the last
/// request's timestamp.
///
/// Save it to [`restore`](Client::restore) the client later: serialize it with the `serde` or
/// `rkyv` feature, or with `prost` convert it to a `proto::ClientState`. It holds private keys,
/// so keep it secret.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct ClientState {
    identity: XEdDSAPrivateKey,
    prekeys: LocalPrekeys,
    last_timestamp: u64,
    /// Whether the last publish of the prekeys may have failed, though the server may have
    /// them, its reply being lost, see [`Client::publish_keys`].
    publishing: bool,
}

impl ClientState {
    fn new(identity: XEdDSAPrivateKey) -> Self {
        Self {
            identity,
            prekeys: LocalPrekeys::new(),
            last_timestamp: 0,
            publishing: false,
        }
    }
}

#[cfg(feature = "prost")]
impl From<&ClientState> for proto::ClientState {
    fn from(state: &ClientState) -> Self {
        Self {
            identity: state.identity.to_bytes().to_vec(),
            prekeys: Some((&state.prekeys).into()),
            last_timestamp: state.last_timestamp,
            publishing: state.publishing,
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&proto::ClientState> for ClientState {
    type Error = Error;

    fn try_from(state: &proto::ClientState) -> Result<Self> {
        let identity = <[u8; xeddsa::PRIVATE_KEY_LENGTH]>::try_from(state.identity.as_slice())
            .ok()
            .and_then(XEdDSAPrivateKey::from_bytes)
            .ok_or(ErrorKind::MalformedState)?;
        Ok(Self {
            identity,
            prekeys: state
                .prekeys
                .as_ref()
                .map(LocalPrekeys::try_from)
                .transpose()?
                .unwrap_or_default(),
            last_timestamp: state.last_timestamp,
            publishing: state.publishing,
        })
    }
}

impl<H> Client<H> {
    /// A client over `handshake`, from the `state` of an earlier one.
    pub fn restore(handshake: H, state: ClientState) -> Self {
        let identity_key = state.identity.compute_public_key().to_bytes();
        Self {
            handshake,
            state,
            identity_key,
        }
    }

    /// What to save to [`restore`](Client::restore) this client later. Its prekeys change when
    /// publishing and accepting, so save it after those.
    pub fn state(&self) -> &ClientState {
        &self.state
    }
}

impl<H: LocalHandshake> Client<H> {
    /// A client with a new random identity key.
    pub fn new(handshake: H) -> Self {
        Self::builder(handshake).build()
    }

    /// This client's public identity key, which peers use to reach it.
    pub fn identity_key(&self) -> PublicKey {
        self.identity_key
    }

    /// Generate and publish a signed prekey and `one_time_count` one-time prekeys, replacing
    /// the published ones.
    ///
    /// Only the last [`x3dh::KEPT_GENERATIONS`] generations of prekeys are kept, so take the
    /// initial messages waiting before publishing again; later, the ones using deleted prekeys
    /// cannot be accepted. If publishing fails, the server may still have the prekeys, its reply
    /// being lost: the next publish sends the same signed prekey again, with new one-time
    /// prekeys, rather than a new generation, which would delete the private keys of prekeys
    /// the server hands out. Save the state after this, failed or not.
    pub async fn publish_keys(&mut self, one_time_count: usize) -> Result<()> {
        let published = if self.state.publishing {
            self.state
                .prekeys
                .extend(&self.state.identity, one_time_count)
        } else {
            self.state
                .prekeys
                .generate(&self.state.identity, one_time_count)
        };
        self.state.publishing = true;
        let timestamp = self.next_timestamp();
        let request = PublishRequest::sign(&self.state.identity, &published, timestamp)?;
        self.handshake.publish(request).await?;
        self.state.publishing = false;
        Ok(())
    }

    /// Start a session with `peer`, whose first message is `content`: fetch the peer's prekeys,
    /// run X3DH, and leave the initial message, with the first message, in the peer's inbox.
    ///
    /// The first message shows the peer that the initial message is this client's, and lets the
    /// peer write back at once. It can be empty.
    pub async fn initiate<M>(
        &mut self,
        peer: &PublicKey,
        content: &[u8],
        mailbox: M,
    ) -> Result<Session<M>> {
        let response = self
            .handshake
            .fetch_bundle(FetchBundleRequest {
                identity_key: Bytes::copy_from_slice(peer),
            })
            .await?;
        let bundle = PrekeyBundle::try_from(&response)?;
        let (message, agreement) = bundle.initiate(&self.state.identity, peer)?;
        let ratchet = Ratchet::alice(
            &SharedKeys::from_secret(&agreement.secret_key),
            &bundle.signed_prekey,
        )?;
        let mut party = Party::new(ratchet, agreement.associated_data);
        let first_message = party.encrypt(content)?;
        let initial_message = handshake::InitialMessage {
            first_message: Some(first_message),
            ..handshake::InitialMessage::from(&message)
        };
        self.handshake
            .send_initial_message(SendInitialMessageRequest {
                recipient: Bytes::copy_from_slice(peer),
                message: Some(initial_message.clone()),
            })
            .await?;
        Ok(Session::new(
            mailbox,
            Active {
                party,
                id: message.ephemeral_key,
                known_by_peer: false,
                initial_message: initial_message.encode_to_vec(),
            },
            self.identity_key,
            *peer,
        ))
    }

    /// Start a new session with `session`'s peer, whose first message is `content`, and keep
    /// `session`, the chat so far, with it, see [`Session::keep`]: as when it has none to send
    /// on ([`Session::needs_new_session`]).
    ///
    /// Fails with [`ErrorKind::UnexpectedPeer`] if `session` is another identity's, before
    /// anything is sent or changed.
    pub async fn start_again<M: Clone>(
        &mut self,
        session: &mut Session<M>,
        content: &[u8],
    ) -> Result<()> {
        // Checked first, as `keep` would only fail once the initial message went and `session`
        // was replaced.
        if session.state.me != self.identity_key {
            return Err(ErrorKind::UnexpectedPeer.into());
        }
        let started = self
            .initiate(&session.state.peer, content, session.mailbox.clone())
            .await?;
        let older = mem::replace(session, started);
        session.keep(older)
    }

    /// Take the initial messages waiting in this client's inbox.
    ///
    /// The server deletes them, so keep the ones to accept later. Malformed ones, which could
    /// never be accepted, are left out.
    pub async fn take_initial_messages(&mut self) -> Result<Vec<InitialMessage>> {
        let timestamp = self.next_timestamp();
        let request = TakeInitialMessagesRequest::sign(&self.state.identity, timestamp);
        let response = self.handshake.take_initial_messages(request).await?;
        // The server has deleted them already, so one malformed message must not fail the
        // call and lose the others with it.
        Ok(response
            .messages
            .iter()
            .filter_map(|message| InitialMessage::try_from(message).ok())
            .collect())
    }

    /// Accept `initial_message` from `peer`, starting the session `peer` asked for. Returns the
    /// session and the content of its first message.
    ///
    /// Anyone can send an initial message claiming to be from `peer`, but only `peer` can have
    /// encrypted its first message, which must decrypt. Fails with
    /// [`ErrorKind::InvalidInitialMessage`] if it does not, or if the initial message was accepted
    /// already, and with [`ErrorKind::UnexpectedPeer`] if it is not from `peer`; failing, it
    /// uses up nothing.
    pub fn accept<M>(
        &mut self,
        peer: &PublicKey,
        initial_message: &InitialMessage,
        mailbox: M,
    ) -> Result<(Session<M>, Vec<u8>)> {
        let (agreement, signed_prekey) =
            self.state
                .prekeys
                .accept(&self.state.identity, peer, &initial_message.x3dh)?;
        let ratchet = Ratchet::bob(
            &SharedKeys::from_secret(&agreement.secret_key),
            DhPrivateKey::from(signed_prekey.to_bytes()),
        );
        let mut party = Party::new(ratchet, agreement.associated_data);
        let content = party
            .decrypt(&initial_message.first_message)
            .map_err(|e| Error::new(ErrorKind::InvalidInitialMessage, e))?;
        self.state.prekeys.confirm(&initial_message.x3dh)?;
        let active = Active {
            party,
            id: initial_message.x3dh.ephemeral_key,
            known_by_peer: true,
            initial_message: vec![],
        };
        Ok((
            Session::new(mailbox, active, self.identity_key, *peer),
            content,
        ))
    }

    /// Start uploading an attachment of `size` bytes: a new key, and the service's ID and upload
    /// token for it. Then [encrypt](attachment::Upload::encrypt) and
    /// [put](attachment::Upload::put) each chunk, and send the ID and key to the recipients in a
    /// message.
    ///
    /// Fails with [`ErrorKind::LimitExceeded`] if the service takes no attachment that large.
    pub async fn start_upload(
        &self,
        attachments: &impl LocalAttachments,
        size: u64,
    ) -> Result<attachment::Upload> {
        let chunks = u32::try_from(attachment::chunk_count(size))
            .map_err(|_| Error::from(ErrorKind::LimitExceeded))?;
        // The server takes it within a few minutes of its clock, so it is signed with this
        // device's, not the strictly increasing timestamp, which may have run ahead of it.
        let request = StartUploadRequest::sign(&self.state.identity, chunks, now());
        let response = attachments.start_upload(request).await?;
        Ok(attachment::Upload {
            id: protocol::fixed(&response.id)?,
            token: protocol::fixed(&response.upload_token)?,
            key: attachment::generate_key(),
            chunks,
        })
    }

    /// A subscription to this client's notifications, signed by its identity key, for a server
    /// that sends them; see `protocol::notify`. It is good for a few minutes.
    pub fn subscription(&self) -> SubscribeRequest {
        // Within a few minutes of the server's clock, like an upload's start.
        SubscribeRequest::sign(&self.state.identity, now())
    }

    /// Milliseconds since the Unix epoch, strictly increasing, as the server requires of
    /// publishing and taking initial messages.
    fn next_timestamp(&mut self) -> u64 {
        self.state.last_timestamp = now().max(self.state.last_timestamp + 1);
        self.state.last_timestamp
    }
}

/// Milliseconds since the Unix epoch, by this device's clock.
fn now() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// A session with one peer: encrypts with a [`Party`] and exchanges messages through a mailbox.
///
/// It may hold earlier sessions with the peer too, which only decrypt, see [`Session::keep`].
///
/// [`Session::restore`] brings back a session from its saved [`state`](Session::state).
#[derive(Debug)]
pub struct Session<M> {
    mailbox: M,
    state: SessionState,
}

/// What a [`Session`] keeps besides its transport: the double ratchets, both identity keys and
/// the position in the peer's queue.
///
/// Save it to [`restore`](Session::restore) the session later: serialize it with the `serde` or
/// `rkyv` feature, or with `prost` convert it to a `proto::SessionState`. It holds the session's
/// keys, so keep it secret.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct SessionState {
    /// The session messages are sent on; none once retired, until a new one starts.
    active: Option<Active>,
    /// The parties of earlier sessions with the peer, latest first, which only decrypt, see
    /// [`Session::keep`].
    others: Vec<Party>,
    me: PublicKey,
    peer: PublicKey,
    /// Sequence number of the last fetched message.
    cursor: u64,
    /// What was done last, and how many times the peers turned between sending on the active
    /// session and receiving on an earlier one, see [`Session::keep`].
    last: LastAction,
    direction_changes: u32,
    /// The last sequence number of the page in which receiving stopped at a message that did not
    /// decrypt, and up to which messages that do not decrypt are skipped, see
    /// [`Session::receive`].
    stalled_through: u64,
    skip_through: u64,
}

/// The session a [`SessionState`] sends on.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
struct Active {
    party: Party,
    /// The session's ID, which both peers have: the X3DH ephemeral key of the one who started
    /// it.
    id: PublicKey,
    /// Whether the peer is known to have it: it started it, or a message on it decrypted.
    known_by_peer: bool,
    /// The initial message, encoded, that started it, which this client did: each message
    /// goes with it until the peer is known to have the session, in case the one in its inbox
    /// was lost. Empty once known.
    initial_message: Vec<u8>,
}

/// What was done last on a [`SessionState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
enum LastAction {
    None,
    Sent,
    ReceivedActive,
    ReceivedEarlier,
}

impl SessionState {
    /// The peer's identity key.
    pub fn peer(&self) -> &PublicKey {
        &self.peer
    }

    /// Keep `party` of an earlier session, only to decrypt, dropping the oldest beyond
    /// [`KEPT_SESSIONS`].
    fn archive(&mut self, party: Party) {
        self.others.insert(0, party);
        self.others.truncate(KEPT_SESSIONS);
    }

    /// A message decrypted on an earlier session. If the peers keep turning between this client
    /// sending on the active session and the peer's messages decrypting only on earlier ones,
    /// neither uses the other's: the active session is retired, and the next message goes on a
    /// new one.
    fn received_earlier(&mut self) {
        if self.last == LastAction::Sent {
            self.direction_changes += 1;
        }
        self.last = LastAction::ReceivedEarlier;
        if self.direction_changes > MAX_DIRECTION_CHANGES {
            if let Some(active) = self.active.take() {
                self.archive(active.party);
            }
            self.direction_changes = 0;
        }
    }
}

#[cfg(feature = "prost")]
impl From<&SessionState> for proto::SessionState {
    fn from(state: &SessionState) -> Self {
        Self {
            party: state.active.as_ref().map(|active| (&active.party).into()),
            id: state
                .active
                .as_ref()
                .map(|active| active.id.to_vec())
                .unwrap_or_default(),
            known_by_peer: state
                .active
                .as_ref()
                .is_some_and(|active| active.known_by_peer),
            initial_message: state
                .active
                .as_ref()
                .map(|active| active.initial_message.clone())
                .unwrap_or_default(),
            others: state.others.iter().map(Into::into).collect(),
            me: state.me.to_vec(),
            peer: state.peer.to_vec(),
            cursor: state.cursor,
            last: match state.last {
                LastAction::None => proto::LastAction::None,
                LastAction::Sent => proto::LastAction::Sent,
                LastAction::ReceivedActive => proto::LastAction::ReceivedActive,
                LastAction::ReceivedEarlier => proto::LastAction::ReceivedEarlier,
            }
            .into(),
            direction_changes: state.direction_changes,
            stalled_through: state.stalled_through,
            skip_through: state.skip_through,
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&proto::SessionState> for SessionState {
    type Error = Error;

    fn try_from(state: &proto::SessionState) -> Result<Self> {
        /// An identity or ephemeral key field, which must be 32 bytes.
        fn key(bytes: &[u8]) -> Result<PublicKey> {
            bytes
                .try_into()
                .map_err(|_| ErrorKind::MalformedState.into())
        }

        let active = match &state.party {
            Some(party) => Some(Active {
                party: Party::try_from(party)?,
                id: key(&state.id)?,
                known_by_peer: state.known_by_peer,
                initial_message: state.initial_message.clone(),
            }),
            None => None,
        };
        let last = match proto::LastAction::try_from(state.last) {
            Ok(proto::LastAction::None) => LastAction::None,
            Ok(proto::LastAction::Sent) => LastAction::Sent,
            Ok(proto::LastAction::ReceivedActive) => LastAction::ReceivedActive,
            Ok(proto::LastAction::ReceivedEarlier) => LastAction::ReceivedEarlier,
            Err(_) => return Err(ErrorKind::MalformedState.into()),
        };
        Ok(Self {
            active,
            others: state
                .others
                .iter()
                .map(Party::try_from)
                .collect::<core::result::Result<_, _>>()?,
            me: key(&state.me)?,
            peer: key(&state.peer)?,
            cursor: state.cursor,
            last,
            direction_changes: state.direction_changes,
            stalled_through: state.stalled_through,
            skip_through: state.skip_through,
        })
    }
}

impl<M> Session<M> {
    /// A session that begins a chat, sending on `active`.
    fn new(mailbox: M, active: Active, me: PublicKey, peer: PublicKey) -> Self {
        let last = if active.known_by_peer {
            // Its first message was received.
            LastAction::ReceivedActive
        } else {
            LastAction::None
        };
        Self::restore(
            mailbox,
            SessionState {
                active: Some(active),
                others: vec![],
                me,
                peer,
                cursor: 0,
                last,
                direction_changes: 0,
                stalled_through: 0,
                skip_through: 0,
            },
        )
    }

    /// A session over `mailbox`, from the `state` of an earlier one.
    pub fn restore(mailbox: M, state: SessionState) -> Self {
        Self { mailbox, state }
    }

    /// What to save to [`restore`](Session::restore) this session later. It changes with every
    /// message encrypted or received, so save it after each, before showing what was received.
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// The peer's identity key.
    pub fn peer(&self) -> &PublicKey {
        &self.state.peer
    }

    /// This client's identity key.
    pub fn me(&self) -> &PublicKey {
        &self.state.me
    }

    /// Whether this session has none to send on, as the peers kept missing each other (see
    /// [`Session::keep`]) or it was [retired](Session::retire): start a new one with
    /// [`Client::start_again`] before sending.
    pub fn needs_new_session(&self) -> bool {
        self.state.active.is_none()
    }

    /// Go on past the messages that receiving stopped at, as they did not decrypt, once the
    /// initial messages waiting are taken and accepted: those of that page that still do not
    /// decrypt never will, and are skipped, see [`Session::receive`].
    pub fn skip_stalled(&mut self) {
        self.state.skip_through = self.state.skip_through.max(self.state.stalled_through);
    }

    /// Retire the active session, e.g. as the peer deleted the chat, so it no longer has it:
    /// messages on it still decrypt, but none go on it; the next goes on a new one, see
    /// [`Session::needs_new_session`].
    pub fn retire(&mut self) {
        if let Some(active) = self.state.active.take() {
            self.state.archive(active.party);
        }
        self.state.last = LastAction::None;
        self.state.direction_changes = 0;
    }

    /// Keep `older`, the chat with the same peer so far, with this session, which the peer or
    /// this client has just started. The last [`KEPT_SESSIONS`] earlier sessions are kept, only
    /// to decrypt, such as the messages the peer sent on `older` before starting this one; and
    /// they go on from the later of the two positions in the peer's queue.
    ///
    /// Of the sessions, one is active: messages are sent on it, so each peer answers the other
    /// on it and its ratchet keeps stepping, as Signal's session management (Tahini) does. An
    /// earlier session never becomes active again, as whoever stole its keys could otherwise
    /// make this client send on it again, where they read everything, though the ratchet has
    /// since locked them out of the active one. A session this client starts becomes active.
    /// One the peer starts does too, unless the active one is this client's and the peer has
    /// not answered it: then both started one at once, and the one whose ID, the X3DH ephemeral
    /// key of who started it, is higher wins, on both sides. If the peers still miss each
    /// other, e.g. as an initial message was lost or a chat deleted, the peer's messages
    /// decrypt only on earlier sessions while this client sends on the active one; after
    /// [`MAX_DIRECTION_CHANGES`] turns between the two, the active session is retired, and the
    /// next message goes on a new one, see [`Session::needs_new_session`].
    pub fn keep(&mut self, older: Session<M>) -> Result<()> {
        if older.state.me != self.state.me || older.state.peer != self.state.peer {
            return Err(ErrorKind::UnexpectedPeer.into());
        }
        let new = mem::replace(&mut self.state, older.state);
        let state = &mut self.state;
        state.cursor = state.cursor.max(new.cursor);
        state.stalled_through = state.stalled_through.max(new.stalled_through);
        state.skip_through = state.skip_through.max(new.skip_through);
        for party in new.others.into_iter().rev() {
            state.archive(party);
        }
        if let Some(active) = new.active {
            // One this client started is not known by the peer yet.
            let started_here = !active.known_by_peer;
            let takes_over = started_here
                || state
                    .active
                    .as_ref()
                    .is_none_or(|current| current.known_by_peer || active.id > current.id);
            if takes_over {
                if let Some(current) = state.active.replace(active) {
                    state.archive(current.party);
                }
                state.last = if started_here {
                    LastAction::None
                } else {
                    LastAction::ReceivedActive
                };
                state.direction_changes = 0;
            } else {
                // Its first message decrypted, on what is now an earlier session.
                state.archive(active.party);
                state.received_earlier();
            }
        }
        Ok(())
    }

    /// Decrypt `message` with the active party, or else with an earlier one, which only counts
    /// towards retiring the active one, see [`Session::keep`]; and tell which.
    fn decrypt(&mut self, message: &EncryptedMessage) -> Result<(Vec<u8>, bool)> {
        let state = &mut self.state;
        let mut error = None;
        if let Some(active) = &mut state.active {
            match active.party.decrypt(message) {
                Ok(content) => {
                    active.known_by_peer = true;
                    active.initial_message = vec![];
                    state.last = LastAction::ReceivedActive;
                    return Ok((content, false));
                }
                Err(e) => error = Some(e),
            }
        }
        // A message an earlier session received already is told apart, as a duplicate.
        let mut duplicate = None;
        for earlier in &mut state.others {
            match earlier.decrypt(message) {
                Ok(content) => {
                    state.received_earlier();
                    return Ok((content, true));
                }
                Err(e) if e.kind() == party::error::ErrorKind::DuplicateMessage => {
                    duplicate = Some(e);
                }
                Err(_) => {}
            }
        }
        match duplicate.or(error) {
            Some(error) => Err(error.into()),
            None => Err(ErrorKind::Undecryptable.into()),
        }
    }
}

impl<M: LocalMailbox> Session<M> {
    /// Encrypt `content` and push it to the peer.
    ///
    /// If pushing fails the message is lost; to retry instead, use [`Session::encrypt`] and
    /// [`Session::push`].
    pub async fn send(&mut self, content: &[u8]) -> Result<()> {
        let message = self.encrypt(content)?;
        self.push(message).await
    }

    /// Encrypt `content` for the peer, on the active session.
    ///
    /// Fails with [`ErrorKind::NoSession`] if it has none, see [`Session::needs_new_session`].
    pub fn encrypt(&mut self, content: &[u8]) -> Result<EncryptedMessage> {
        let state = &mut self.state;
        let active = state.active.as_mut().ok_or(ErrorKind::NoSession)?;
        let message = active.party.encrypt(content)?;
        if state.last == LastAction::ReceivedEarlier {
            state.direction_changes += 1;
        }
        state.last = LastAction::Sent;
        Ok(message)
    }

    /// Push an encrypted message to the peer; it can be pushed again if this fails. While the
    /// peer is not known to have the active session, the initial message that started it goes
    /// with it, in case the one in the peer's inbox was lost.
    pub async fn push(&mut self, message: EncryptedMessage) -> Result<()> {
        let initial_message = self
            .state
            .active
            .as_ref()
            .filter(|active| !active.initial_message.is_empty())
            .and_then(|active| {
                handshake::InitialMessage::decode(active.initial_message.as_slice()).ok()
            });
        self.mailbox
            .push(PushRequest {
                sender: Bytes::copy_from_slice(&self.state.me),
                recipient: Bytes::copy_from_slice(&self.state.peer),
                message: Some(message),
                initial_message,
            })
            .await?;
        Ok(())
    }

    /// Fetch the next page of the peer's messages and decrypt them: one result per message, in
    /// order. Returns an empty page once there are no new messages.
    ///
    /// A message is tried on the earlier sessions [kept](Session::keep) too. One that does not
    /// decrypt may be on a session whose initial message is waiting, as it reached the server
    /// first, but came after the initial messages were last taken: receiving stops there, the
    /// page ending with an [`ErrorKind::Stalled`] error, and leaves it for later. Take and accept
    /// the initial messages, then [`skip_stalled`](Session::skip_stalled) and receive again: what
    /// of that page still does not decrypt never will, and is skipped, so that it cannot block
    /// the messages after it.
    /// Cancel-safe: if the future is dropped, no message is consumed.
    pub async fn receive(&mut self) -> Result<Vec<Received>> {
        let response = self
            .mailbox
            .fetch(FetchRequest {
                sender: Bytes::copy_from_slice(&self.state.peer),
                recipient: Bytes::copy_from_slice(&self.state.me),
                after: self.state.cursor,
                limit: 0,
            })
            .await?;
        let last = response
            .messages
            .last()
            .map_or(0, |envelope| envelope.sequence);
        let attached = |envelope: &Envelope| {
            envelope
                .initial_message
                .as_ref()
                .and_then(|initial_message| InitialMessage::try_from(initial_message).ok())
        };
        let mut received = Vec::with_capacity(response.messages.len());
        let mut envelopes = response.messages.into_iter();
        while let Some(envelope) = envelopes.next() {
            let decrypted = match &envelope.message {
                Some(message) => self.decrypt(message),
                None => Err(ErrorKind::InvalidMessage.into()),
            };
            let mut initial_messages: Vec<_> = attached(&envelope).into_iter().collect();
            let stalls = decrypted
                .as_ref()
                .is_err_and(|e| e.kind() != ErrorKind::DuplicateMessage)
                && envelope.sequence > self.state.skip_through;
            if stalls {
                self.state.stalled_through = last;
                // What still does not decrypt once they are accepted is skipped, the rest of
                // the page with it: so each of its sessions is offered now.
                for initial_message in envelopes
                    .by_ref()
                    .filter_map(|envelope| attached(&envelope))
                {
                    if !initial_messages.contains(&initial_message) {
                        initial_messages.push(initial_message);
                    }
                }
                received.push(Received {
                    content: Err(ErrorKind::Stalled.into()),
                    earlier: false,
                    initial_messages,
                });
                return Ok(received);
            }
            self.state.cursor = self.state.cursor.max(envelope.sequence);
            let earlier = decrypted.as_ref().is_ok_and(|(_, earlier)| *earlier);
            received.push(Received {
                content: decrypted.map(|(content, _)| content),
                earlier,
                initial_messages,
            });
        }
        Ok(received)
    }
}

#[cfg(test)]
mod test {
    use core::cell::Cell;
    use protocol::{
        attachment::AttachmentServer,
        handshake::{
            FetchBundleResponse, HandshakeServer, PublishResponse, SendInitialMessageResponse,
            TakeInitialMessagesResponse,
        },
        mailbox::{FetchResponse, MailboxServer, PushResponse},
    };

    use storage::MemoryStore;

    use super::*;

    /// Lets several clients share one in-process handshake server.
    #[derive(Debug)]
    struct InProcessHandshake<'a>(&'a HandshakeServer<MemoryStore>);

    impl LocalHandshake for InProcessHandshake<'_> {
        async fn publish(&self, request: PublishRequest) -> protocol::Result<PublishResponse> {
            self.0.publish(request).await
        }

        async fn fetch_bundle(
            &self,
            request: FetchBundleRequest,
        ) -> protocol::Result<FetchBundleResponse> {
            self.0.fetch_bundle(request).await
        }

        async fn send_initial_message(
            &self,
            request: SendInitialMessageRequest,
        ) -> protocol::Result<SendInitialMessageResponse> {
            self.0.send_initial_message(request).await
        }

        async fn take_initial_messages(
            &self,
            request: TakeInitialMessagesRequest,
        ) -> protocol::Result<TakeInitialMessagesResponse> {
            self.0.take_initial_messages(request).await
        }
    }

    /// Lets several sessions share one in-process mailbox server.
    #[derive(Debug, Clone)]
    struct InProcessMailbox<'a>(&'a MailboxServer<MemoryStore>);

    impl LocalMailbox for InProcessMailbox<'_> {
        async fn push(&self, request: PushRequest) -> protocol::Result<PushResponse> {
            self.0.push(request).await
        }

        async fn fetch(&self, request: FetchRequest) -> protocol::Result<FetchResponse> {
            self.0.fetch(request).await
        }
    }

    /// `state` saved as a protobuf message, and read back.
    #[cfg(feature = "prost")]
    fn restored<T, P>(state: &T) -> T
    where
        P: prost::Message + Default + for<'a> From<&'a T>,
        T: for<'a> TryFrom<&'a P, Error = Error>,
    {
        let saved = P::from(state).encode_to_vec();
        T::try_from(&P::decode(saved.as_slice()).unwrap()).unwrap()
    }

    fn contents(received: Vec<Received>) -> Vec<Vec<u8>> {
        received
            .into_iter()
            .map(|received| received.content.unwrap())
            .collect()
    }

    /// Receive as a client does once it has taken the initial messages: past what receiving
    /// stalls at, which then never decrypts.
    async fn receive_all<M: LocalMailbox>(session: &mut Session<M>) -> Vec<Received> {
        let mut received = session.receive().await.unwrap();
        if let Some(Received {
            content: Err(e), ..
        }) = received.last()
            && e.kind() == ErrorKind::Stalled
        {
            received.pop();
            session.skip_stalled();
            received.extend(session.receive().await.unwrap());
        }
        received
    }

    #[tokio::test]
    async fn alice_and_bob_talk() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let mut alice = Client::new(InProcessHandshake(&handshake));
        let mut bob = Client::new(InProcessHandshake(&handshake));

        bob.publish_keys(1).await.unwrap();
        let mut alice_session = alice
            .initiate(&bob.identity_key(), b"hi", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        alice_session.send(b"bob").await.unwrap();

        let initial_messages = bob.take_initial_messages().await.unwrap();
        assert_eq!(initial_messages.len(), 1);
        let (mut bob_session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"hi");

        assert_eq!(
            contents(receive_all(&mut bob_session).await),
            [b"bob".to_vec()]
        );
        assert!(receive_all(&mut bob_session).await.is_empty());

        bob_session.send(b"hello").await.unwrap();
        assert_eq!(
            contents(receive_all(&mut alice_session).await),
            [b"hello".to_vec()]
        );

        // A message encrypted but pushed later still arrives, after the ones pushed before it.
        let late = alice_session.encrypt(b"late").unwrap();
        alice_session.send(b"early").await.unwrap();
        alice_session.push(late).await.unwrap();
        assert_eq!(
            contents(receive_all(&mut bob_session).await),
            [b"early".to_vec(), b"late".to_vec()]
        );
    }

    /// Alice and Bob, who talked already: she started with "hi" and he replied "hello".
    async fn talking<'a>(
        handshake: &'a HandshakeServer<MemoryStore>,
        mailbox: &'a MailboxServer<MemoryStore>,
    ) -> (
        Client<InProcessHandshake<'a>>,
        Session<InProcessMailbox<'a>>,
        Client<InProcessHandshake<'a>>,
        Session<InProcessMailbox<'a>>,
    ) {
        let mut alice = Client::new(InProcessHandshake(handshake));
        let mut bob = Client::new(InProcessHandshake(handshake));
        bob.publish_keys(3).await.unwrap();
        let mut alice_session = alice
            .initiate(&bob.identity_key(), b"hi", InProcessMailbox(mailbox))
            .await
            .unwrap();
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (mut bob_session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(mailbox),
            )
            .unwrap();
        assert_eq!(first, b"hi");
        bob_session.send(b"hello").await.unwrap();
        assert_eq!(contents(receive_all(&mut alice_session).await), [b"hello"]);
        (alice, alice_session, bob, bob_session)
    }

    #[tokio::test]
    async fn forged_initial_messages_are_refused() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, _alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Alice starts again, then Mallory sends Bob more initial messages claiming to be hers
        // than he keeps sessions.
        let mut alice_again = alice
            .initiate(&bob.identity_key(), b"again", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        let mut mallory = Client::new(InProcessHandshake(&handshake));
        for _ in 0..=KEPT_SESSIONS {
            mallory
                .initiate(&bob.identity_key(), b"it is me", InProcessMailbox(&mailbox))
                .await
                .unwrap();
        }
        let mut initial_messages = bob.take_initial_messages().await.unwrap();
        for initial_message in &mut initial_messages[1..] {
            initial_message.x3dh.identity_key = alice.identity_key();
        }

        // Each tried twice: only Alice's is accepted, once, and the others fail both times, as
        // they use up nothing.
        let mut accepted = vec![];
        for initial_message in &initial_messages {
            for _ in 0..2 {
                match bob.accept(
                    &alice.identity_key(),
                    initial_message,
                    InProcessMailbox(&mailbox),
                ) {
                    Ok(session) => accepted.push(session),
                    Err(e) => assert_eq!(e.kind(), ErrorKind::InvalidInitialMessage),
                }
            }
        }
        assert_eq!(accepted.len(), 1);
        let (session, first) = accepted.pop().unwrap();
        assert_eq!(first, b"again");
        let older = mem::replace(&mut bob_session, session);
        bob_session.keep(older).unwrap();

        alice_again.send(b"on the new one").await.unwrap();
        assert_eq!(
            contents(receive_all(&mut bob_session).await),
            [b"on the new one"]
        );
        bob_session.send(b"me too").await.unwrap();
        let received = receive_all(&mut alice_again).await;
        // Her new session reads her queue from the start, where his reply to the old one is.
        assert!(received[0].content.is_err());
        assert_eq!(received[1].content.as_ref().unwrap(), b"me too");
    }

    #[tokio::test]
    async fn a_new_session_takes_over_at_once() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Alice sends on her session, then starts again before Bob receives.
        alice_session.send(b"old").await.unwrap();
        let mut alice_again = alice
            .initiate(&bob.identity_key(), b"new", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"new");
        let older = mem::replace(&mut bob_session, session);
        bob_session.keep(older).unwrap();
        // Kept sessions are saved with the session.
        #[cfg(feature = "prost")]
        let mut bob_session = Session::restore(
            InProcessMailbox(&mailbox),
            restored::<_, proto::SessionState>(bob_session.state()),
        );

        // Her earlier message still decrypts, but does not bring the old session back.
        assert_eq!(contents(receive_all(&mut bob_session).await), [b"old"]);
        bob_session.send(b"on the new one").await.unwrap();
        let received = receive_all(&mut alice_again).await;
        assert!(received[0].content.is_err());
        assert_eq!(received[1].content.as_ref().unwrap(), b"on the new one");
        assert!(receive_all(&mut alice_session).await[0].content.is_err());
    }

    /// Whether `a` and `b` send on one session.
    fn on_one_session<M>(a: &Session<M>, b: &Session<M>) -> bool {
        matches!(
            (&a.state.active, &b.state.active),
            (Some(a), Some(b)) if a.id == b.id
        )
    }

    /// Accept the initial message `client` has from `peer`, keeping `session`, the chat so far.
    async fn accept_keeping<'a>(
        client: &mut Client<InProcessHandshake<'a>>,
        peer: &PublicKey,
        session: &mut Session<InProcessMailbox<'a>>,
        mailbox: &'a MailboxServer<MemoryStore>,
    ) -> Vec<u8> {
        let initial_messages = client.take_initial_messages().await.unwrap();
        let (accepted, first) = client
            .accept(peer, &initial_messages[0], InProcessMailbox(mailbox))
            .unwrap();
        let older = mem::replace(session, accepted);
        session.keep(older).unwrap();
        first
    }

    #[tokio::test]
    async fn a_session_the_peer_never_gets_is_retired_for_a_new_one() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Bob starts again, but Alice loses his initial message, and writes on the old session.
        alice.publish_keys(1).await.unwrap();
        bob.start_again(&mut bob_session, b"lost").await.unwrap();
        assert_eq!(alice.take_initial_messages().await.unwrap().len(), 1);

        // Bob reads her on the old session, which never becomes active again, and she cannot
        // read him on the new one; after a few turns, he retires it.
        let mut turns = 0;
        loop {
            alice_session.send(b"still here").await.unwrap();
            assert_eq!(
                contents(receive_all(&mut bob_session).await),
                [b"still here"]
            );
            if bob_session.needs_new_session() {
                break;
            }
            bob_session.send(b"lost too").await.unwrap();
            assert!(receive_all(&mut alice_session).await[0].content.is_err());
            turns += 1;
        }
        assert!(turns <= MAX_DIRECTION_CHANGES);
        assert_eq!(
            bob_session.encrypt(b"no").unwrap_err().kind(),
            ErrorKind::NoSession
        );

        // He starts a new one, which Alice gets this time, and they talk on it.
        bob.start_again(&mut bob_session, b"again").await.unwrap();
        let first = accept_keeping(
            &mut alice,
            &bob.identity_key(),
            &mut alice_session,
            &mailbox,
        )
        .await;
        assert_eq!(first, b"again");
        assert!(on_one_session(&alice_session, &bob_session));
        bob_session.send(b"hello again").await.unwrap();
        assert_eq!(
            contents(receive_all(&mut alice_session).await),
            [b"hello again"]
        );
        alice_session.send(b"hi").await.unwrap();
        assert_eq!(contents(receive_all(&mut bob_session).await), [b"hi"]);
    }

    #[tokio::test]
    async fn sessions_started_at_once_end_as_one() {
        // Each accepts the other's; or one answers the other's before the other accepts its
        // own, which a client does before it receives.
        for answered_first in [false, true] {
            let handshake = HandshakeServer::new(MemoryStore::default());
            let mailbox = MailboxServer::new(MemoryStore::default());
            let mut alice = Client::new(InProcessHandshake(&handshake));
            let mut bob = Client::new(InProcessHandshake(&handshake));
            alice.publish_keys(1).await.unwrap();
            bob.publish_keys(1).await.unwrap();
            let mut alice_session = alice
                .initiate(&bob.identity_key(), b"hi bob", InProcessMailbox(&mailbox))
                .await
                .unwrap();
            let mut bob_session = bob
                .initiate(
                    &alice.identity_key(),
                    b"hi alice",
                    InProcessMailbox(&mailbox),
                )
                .await
                .unwrap();

            let first =
                accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mailbox).await;
            assert_eq!(first, b"hi bob");
            if answered_first {
                bob_session.send(b"b0").await.unwrap();
            }
            let first = accept_keeping(
                &mut alice,
                &bob.identity_key(),
                &mut alice_session,
                &mailbox,
            )
            .await;
            assert_eq!(first, b"hi alice");
            if answered_first {
                assert_eq!(contents(receive_all(&mut alice_session).await), [b"b0"]);
            }

            // The session with the higher ID won on both sides, and whatever each sends, at once
            // or in turn, arrives.
            assert!(on_one_session(&alice_session, &bob_session));
            alice_session.send(b"a1").await.unwrap();
            bob_session.send(b"b1").await.unwrap();
            assert_eq!(contents(receive_all(&mut alice_session).await), [b"b1"]);
            assert_eq!(contents(receive_all(&mut bob_session).await), [b"a1"]);
            alice_session.send(b"a2").await.unwrap();
            assert_eq!(contents(receive_all(&mut bob_session).await), [b"a2"]);
            bob_session.send(b"b2").await.unwrap();
            assert_eq!(contents(receive_all(&mut alice_session).await), [b"b2"]);
            assert!(on_one_session(&alice_session, &bob_session));
        }
    }

    #[tokio::test]
    async fn a_chat_deleted_while_a_session_waits_ends_on_one() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let mut alice = Client::new(InProcessHandshake(&handshake));
        let mut bob = Client::new(InProcessHandshake(&handshake));
        alice.publish_keys(1).await.unwrap();
        bob.publish_keys(2).await.unwrap();
        let (alice_key, bob_key) = (alice.identity_key(), bob.identity_key());

        // Both start at once, but Bob deletes his chat before he takes Alice's initial message,
        // which then begins his chat again; Alice accepts the one he deleted.
        let mut alice_session = alice
            .initiate(&bob_key, b"hi bob", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        let deleted = bob
            .initiate(&alice_key, b"hi alice", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        drop(deleted);
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (mut bob_session, first) = bob
            .accept(&alice_key, &initial_messages[0], InProcessMailbox(&mailbox))
            .unwrap();
        assert_eq!(first, b"hi bob");
        let first = accept_keeping(&mut alice, &bob_key, &mut alice_session, &mailbox).await;
        assert_eq!(first, b"hi alice");

        // If Bob's won, what Alice sends on it is lost, while what Bob sends decrypts on hers,
        // until she retires his and starts a new one.
        let mut lost = 0;
        while !on_one_session(&alice_session, &bob_session) {
            assert!(lost <= MAX_DIRECTION_CHANGES, "they never settle");
            if alice_session.needs_new_session() {
                alice
                    .start_again(&mut alice_session, b"again")
                    .await
                    .unwrap();
                let first = accept_keeping(&mut bob, &alice_key, &mut bob_session, &mailbox).await;
                assert_eq!(first, b"again");
                continue;
            }
            alice_session.send(b"from alice").await.unwrap();
            assert!(receive_all(&mut bob_session).await[0].content.is_err());
            lost += 1;
            bob_session.send(b"from bob").await.unwrap();
            assert_eq!(
                contents(receive_all(&mut alice_session).await),
                [b"from bob"]
            );
        }
        alice_session.send(b"on one").await.unwrap();
        assert_eq!(contents(receive_all(&mut bob_session).await), [b"on one"]);
        bob_session.send(b"at last").await.unwrap();
        assert_eq!(
            contents(receive_all(&mut alice_session).await),
            [b"at last"]
        );
    }

    #[tokio::test]
    async fn a_late_message_from_before_a_chat_was_deleted_changes_nothing() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut deleted, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Alice sends on her session, deletes the chat and starts again; Bob takes the new
        // session before the message sent on the old one.
        deleted.send(b"late").await.unwrap();
        drop(deleted);
        let mut alice_session = alice
            .initiate(&bob.identity_key(), b"again", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        let first =
            accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mailbox).await;
        assert_eq!(first, b"again");
        assert_eq!(contents(receive_all(&mut bob_session).await), [b"late"]);
        bob_session.send(b"on the new one").await.unwrap();
        // The new session reads the queue from its start, where the reply to the old one is.
        let received = receive_all(&mut alice_session).await;
        assert!(received[0].content.is_err());
        assert_eq!(received[1].content.as_ref().unwrap(), b"on the new one");
        assert!(on_one_session(&alice_session, &bob_session));
    }

    #[tokio::test]
    async fn a_chat_the_peer_deleted_starts_again_from_a_retired_session() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, bob_session) =
            talking(&handshake, &mailbox).await;
        alice.publish_keys(1).await.unwrap();

        // Bob deletes the chat, as he tells Alice, who retires her session: what came on it still
        // decrypts, but she sends nothing on it.
        drop(bob_session);
        alice_session.retire();
        assert!(alice_session.needs_new_session());
        assert_eq!(
            alice_session.encrypt(b"no").unwrap_err().kind(),
            ErrorKind::NoSession
        );

        // Her next message goes on a new session, which comes to Bob as a new chat.
        alice
            .start_again(&mut alice_session, b"again")
            .await
            .unwrap();
        alice_session.send(b"still there?").await.unwrap();
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (mut bob_session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"again");
        // His new chat reads Alice's queue from its start, where her first message is.
        let received = receive_all(&mut bob_session).await;
        assert_eq!(
            received.last().unwrap().content.as_ref().unwrap(),
            b"still there?"
        );
        bob_session.send(b"yes").await.unwrap();
        assert_eq!(contents(receive_all(&mut alice_session).await), [b"yes"]);
        assert!(on_one_session(&alice_session, &bob_session));
    }

    #[tokio::test]
    async fn a_message_on_a_session_not_taken_yet_waits_for_it() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Alice starts again and writes on the new session, which Bob receives before he takes
        // its initial message: receiving stops there, however often, and loses nothing.
        alice
            .start_again(&mut alice_session, b"once more")
            .await
            .unwrap();
        alice_session.send(b"new").await.unwrap();
        for _ in 0..2 {
            let received = bob_session.receive().await.unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(
                received[0].content.as_ref().unwrap_err().kind(),
                ErrorKind::Stalled
            );
        }
        let first =
            accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mailbox).await;
        assert_eq!(first, b"once more");
        bob_session.skip_stalled();
        assert_eq!(contents(bob_session.receive().await.unwrap()), [b"new"]);

        // What anyone pushes that never decrypts stops receiving once, then is skipped.
        alice_session
            .push(EncryptedMessage::default())
            .await
            .unwrap();
        alice_session.send(b"after").await.unwrap();
        let received = bob_session.receive().await.unwrap();
        assert_eq!(
            received[0].content.as_ref().unwrap_err().kind(),
            ErrorKind::Stalled
        );
        bob_session.skip_stalled();
        let received = bob_session.receive().await.unwrap();
        assert!(received[0].content.is_err());
        assert_eq!(received[1].content.as_ref().unwrap(), b"after");
    }

    #[tokio::test]
    async fn a_lost_initial_message_comes_with_the_messages_after_it() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Alice starts again, and Bob loses her initial message.
        alice
            .start_again(&mut alice_session, b"once more")
            .await
            .unwrap();
        assert_eq!(bob.take_initial_messages().await.unwrap().len(), 1);
        alice_session.send(b"new").await.unwrap();

        // Her message carries it: accepted from there, it decrypts, and the next ones go
        // without it, once Bob answers.
        let received = bob_session.receive().await.unwrap();
        let stalled = received.last().unwrap();
        assert_eq!(
            stalled.content.as_ref().unwrap_err().kind(),
            ErrorKind::Stalled
        );
        let initial_message = stalled.initial_messages[0].clone();
        let (session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_message,
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"once more");
        let older = mem::replace(&mut bob_session, session);
        bob_session.keep(older).unwrap();
        bob_session.skip_stalled();
        assert_eq!(contents(bob_session.receive().await.unwrap()), [b"new"]);
        bob_session.send(b"got it").await.unwrap();
        assert_eq!(contents(receive_all(&mut alice_session).await), [b"got it"]);
        alice_session.send(b"plain").await.unwrap();
        let received = bob_session.receive().await.unwrap();
        assert!(received[0].initial_messages.is_empty());
    }

    #[tokio::test]
    async fn a_lost_initial_message_behind_junk_is_offered_too() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Junk, which never decrypts, then Alice starts again, and Bob loses her initial
        // message.
        alice_session
            .push(EncryptedMessage::default())
            .await
            .unwrap();
        alice
            .start_again(&mut alice_session, b"once more")
            .await
            .unwrap();
        assert_eq!(bob.take_initial_messages().await.unwrap().len(), 1);
        alice_session.send(b"new").await.unwrap();

        // Receiving stops at the junk, offering the initial message that came after it, so
        // that skipping the page does not skip her message.
        let received = bob_session.receive().await.unwrap();
        let stalled = received.last().unwrap();
        assert_eq!(
            stalled.content.as_ref().unwrap_err().kind(),
            ErrorKind::Stalled
        );
        assert_eq!(stalled.initial_messages.len(), 1);
        let (session, _) = bob
            .accept(
                &alice.identity_key(),
                &stalled.initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        let older = mem::replace(&mut bob_session, session);
        bob_session.keep(older).unwrap();
        bob_session.skip_stalled();
        let received = bob_session.receive().await.unwrap();
        assert!(received[0].content.is_err());
        assert_eq!(received[1].content.as_ref().unwrap(), b"new");
    }

    #[tokio::test]
    async fn a_message_on_an_earlier_session_shows_so() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Sent before Alice started again, which Bob took first.
        alice_session.send(b"old").await.unwrap();
        alice
            .start_again(&mut alice_session, b"again")
            .await
            .unwrap();
        accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mailbox).await;
        alice_session.send(b"new").await.unwrap();
        let received = receive_all(&mut bob_session).await;
        let earlier: Vec<_> = received
            .iter()
            .map(|received| (received.content.as_deref().unwrap(), received.earlier))
            .collect();
        assert_eq!(earlier, [(&b"old"[..], true), (&b"new"[..], false)]);
    }

    /// Publishes, then fails once, as if the server's reply were lost.
    #[derive(Debug)]
    struct LosingReply<'a>(&'a HandshakeServer<MemoryStore>, Cell<bool>);

    impl LocalHandshake for LosingReply<'_> {
        async fn publish(&self, request: PublishRequest) -> protocol::Result<PublishResponse> {
            let response = self.0.publish(request).await?;
            if self.1.replace(false) {
                return Err(protocol::ErrorKind::Connect.into());
            }
            Ok(response)
        }

        async fn fetch_bundle(
            &self,
            request: FetchBundleRequest,
        ) -> protocol::Result<FetchBundleResponse> {
            self.0.fetch_bundle(request).await
        }

        async fn send_initial_message(
            &self,
            request: SendInitialMessageRequest,
        ) -> protocol::Result<SendInitialMessageResponse> {
            self.0.send_initial_message(request).await
        }

        async fn take_initial_messages(
            &self,
            request: TakeInitialMessagesRequest,
        ) -> protocol::Result<TakeInitialMessagesResponse> {
            self.0.take_initial_messages(request).await
        }
    }

    #[tokio::test]
    async fn prekeys_published_without_a_reply_stay_usable() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let mut alice = Client::new(InProcessHandshake(&handshake));
        let mut bob = Client::new(LosingReply(&handshake, Cell::new(true)));

        // The server has Bob's prekeys, but he never heard so; Alice uses them meanwhile.
        assert!(bob.publish_keys(1).await.is_err());
        let mut alice_session = alice
            .initiate(&bob.identity_key(), b"hi", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        // Bob publishes again, and many times more, before he takes her initial message: it
        // still is accepted, as publishing again did not start a new generation.
        bob.publish_keys(1).await.unwrap();
        bob.publish_keys(1).await.unwrap();
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (_bob_session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"hi");
        alice_session.send(b"there").await.unwrap();
    }

    #[tokio::test]
    async fn a_message_of_an_earlier_session_pushed_twice_is_a_duplicate() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut earlier, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Alice pushes a message twice, as a push whose answer was lost goes again, and starts
        // a new session, which Bob takes before the message.
        let message = earlier.encrypt(b"twice").unwrap();
        earlier.push(message.clone()).await.unwrap();
        earlier.push(message).await.unwrap();
        alice
            .initiate(&bob.identity_key(), b"again", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        accept_keeping(&mut bob, &alice.identity_key(), &mut bob_session, &mailbox).await;
        let received = receive_all(&mut bob_session).await;
        assert_eq!(received[0].content.as_ref().unwrap(), b"twice");
        assert_eq!(
            received[1].content.as_ref().unwrap_err().kind(),
            ErrorKind::DuplicateMessage
        );
    }

    #[tokio::test]
    async fn a_stolen_earlier_session_is_never_sent_on_again() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut stolen, mut bob, mut bob_session) = talking(&handshake, &mailbox).await;
        alice.publish_keys(KEPT_SESSIONS + 1).await.unwrap();
        let (alice_key, bob_key) = (alice.identity_key(), bob.identity_key());

        // Someone copied Alice's session, and she started a new one, which Bob accepted.
        let mut alice_session = alice
            .initiate(&bob_key, b"new", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        accept_keeping(&mut bob, &alice_key, &mut bob_session, &mailbox).await;
        // Bob's reply to the copied session, from before.
        assert!(receive_all(&mut alice_session).await[0].content.is_err());

        // The thief writes on the copied session as Alice, and Bob decrypts it while he keeps
        // it; but he never sends on it, so the thief reads nothing more. Missing Alice, he
        // retires sessions and starts new ones, which only Alice can accept, until the copied
        // one drops out.
        for _ in 0..4 * MAX_DIRECTION_CHANGES {
            stolen.send(b"it is me").await.unwrap();
            receive_all(&mut bob_session).await;
            if bob_session.needs_new_session() {
                bob.start_again(&mut bob_session, b"again").await.unwrap();
                accept_keeping(&mut alice, &bob_key, &mut alice_session, &mailbox).await;
            }
            bob_session.send(b"for alice").await.unwrap();
            assert!(
                receive_all(&mut stolen)
                    .await
                    .iter()
                    .all(|received| received.content.is_err())
            );
            assert_eq!(
                contents(receive_all(&mut alice_session).await),
                [b"for alice"]
            );
        }
        stolen.send(b"still me").await.unwrap();
        assert!(receive_all(&mut bob_session).await[0].content.is_err());
    }

    #[tokio::test]
    async fn only_sessions_with_the_peer_are_kept() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (_alice, _alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;
        let mut carol = Client::new(InProcessHandshake(&handshake));
        let carol_session = carol
            .initiate(&bob.identity_key(), b"hi", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        assert_eq!(
            bob_session.keep(carol_session).unwrap_err().kind(),
            ErrorKind::UnexpectedPeer
        );
        // And Bob's own, with Carol, is not Alice's either.
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (session, _) = bob
            .accept(
                &carol.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(
            bob_session.keep(session).unwrap_err().kind(),
            ErrorKind::UnexpectedPeer
        );
    }

    #[tokio::test]
    async fn attachments_go_in_chunks() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let attachments = AttachmentServer::new(MemoryStore::default());
        let alice = Client::new(InProcessHandshake(&handshake));
        // Two full chunks and a bit.
        let file: Vec<u8> = (0..2 * attachment::CHUNK_SIZE + 10)
            .map(|i| i as u8)
            .collect();
        let upload = alice
            .start_upload(&attachments, file.len() as u64)
            .await
            .unwrap();
        assert_eq!(upload.chunks(), 3);
        for (index, part) in (0..).zip(file.chunks(attachment::CHUNK_SIZE)) {
            let chunk = upload.encrypt(index, part);
            upload.put(&attachments, index, &chunk).await.unwrap();
        }

        // Bob, with the ID and key from a message.
        let mut received = vec![];
        for index in 0..3 {
            let chunk = attachment::download_chunk(&attachments, upload.id(), index)
                .await
                .unwrap()
                .unwrap();
            received.extend(
                attachment::decrypt_chunk(upload.key(), index, index == 2, &chunk).unwrap(),
            );
        }
        assert_eq!(received, file);

        // Interrupted after its first chunk, an upload goes on from what was kept.
        let interrupted = alice
            .start_upload(&attachments, file.len() as u64)
            .await
            .unwrap();
        let first = interrupted.encrypt(0, &file[..attachment::CHUNK_SIZE]);
        interrupted.put(&attachments, 0, &first).await.unwrap();
        // Bob downloads while it is uploaded: the chunks after it are not there yet.
        let (id, index) = (*interrupted.id(), 1);
        let chunk = attachment::download_chunk(&attachments, &id, index).await;
        assert_eq!(chunk.unwrap(), None);
        let (id, token, chunks) = (
            *interrupted.id(),
            *interrupted.token(),
            interrupted.chunks(),
        );
        let key = attachment::Key::new(*interrupted.key());
        drop(interrupted);
        let resumed = attachment::Upload::resume(id, token, key, chunks);
        for (index, part) in
            (1..).zip(file[attachment::CHUNK_SIZE..].chunks(attachment::CHUNK_SIZE))
        {
            let chunk = resumed.encrypt(index, part);
            resumed.put(&attachments, index, &chunk).await.unwrap();
        }
        let mut received = vec![];
        for index in 0..3 {
            let chunk = attachment::download_chunk(&attachments, &id, index)
                .await
                .unwrap()
                .unwrap();
            received.extend(
                attachment::decrypt_chunk(resumed.key(), index, index == 2, &chunk).unwrap(),
            );
        }
        assert_eq!(received, file);

        // Cancelled, it is gone for Bob.
        resumed.cancel(&attachments).await.unwrap();
        let error = attachment::download_chunk(&attachments, &id, 0)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);

        // More than the service takes.
        let size = 51 * attachment::CHUNK_SIZE as u64;
        let error = alice.start_upload(&attachments, size).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::LimitExceeded);
    }

    #[tokio::test]
    #[cfg(feature = "prost")]
    async fn restored_clients_and_sessions_carry_on() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let mut alice = Client::new(InProcessHandshake(&handshake));
        let mut bob = Client::new(InProcessHandshake(&handshake));
        bob.publish_keys(1).await.unwrap();
        let mut alice_session = alice
            .initiate(&bob.identity_key(), b"hi", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        alice_session.send(b"there").await.unwrap();

        // Bob's identity, prekeys and timestamp survive a restart, and so does Alice's session.
        let mut bob = Client::restore(
            InProcessHandshake(&handshake),
            restored::<_, proto::ClientState>(bob.state()),
        );
        let mut alice_session = Session::restore(
            InProcessMailbox(&mailbox),
            restored::<_, proto::SessionState>(alice_session.state()),
        );
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (bob_session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"hi");
        // So does what was accepted: it cannot be accepted again.
        let mut bob = Client::restore(
            InProcessHandshake(&handshake),
            restored::<_, proto::ClientState>(bob.state()),
        );
        assert_eq!(
            bob.accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap_err()
            .kind(),
            ErrorKind::InvalidInitialMessage
        );

        // The cursor too: what was received is not fetched again.
        let mut bob_session = Session::restore(
            InProcessMailbox(&mailbox),
            restored::<_, proto::SessionState>(bob_session.state()),
        );
        assert_eq!(
            contents(receive_all(&mut bob_session).await),
            [b"there".to_vec()]
        );
        let mut bob_session = Session::restore(
            InProcessMailbox(&mailbox),
            restored::<_, proto::SessionState>(bob_session.state()),
        );
        assert!(receive_all(&mut bob_session).await.is_empty());
        bob_session.send(b"hello").await.unwrap();
        assert_eq!(
            contents(receive_all(&mut alice_session).await),
            [b"hello".to_vec()]
        );
    }
}
