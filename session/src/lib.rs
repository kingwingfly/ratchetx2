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

use core::{iter, mem};

use bon::Builder;
use bytes::Bytes;
pub use error::{Error, ErrorKind, Result};
use party::{EncryptedMessage, Party};
pub use protocol;
use protocol::{
    attachment::{LocalAttachments, StartUploadRequest},
    handshake::{
        self, FetchBundleRequest, LocalHandshake, PublishRequest, SendInitialMessageRequest,
        TakeInitialMessagesRequest,
    },
    mailbox::{FetchRequest, LocalMailbox, PushRequest},
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

/// Number of earlier sessions with its peer that a [`Session`] keeps, see [`Session::keep`].
pub const KEPT_SESSIONS: usize = 4;

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
}

impl ClientState {
    fn new(identity: XEdDSAPrivateKey) -> Self {
        Self {
            identity,
            prekeys: LocalPrekeys::new(),
            last_timestamp: 0,
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
    /// cannot be accepted.
    pub async fn publish_keys(&mut self, one_time_count: usize) -> Result<()> {
        let published = self
            .state
            .prekeys
            .generate(&self.state.identity, one_time_count);
        let timestamp = self.next_timestamp();
        let request = PublishRequest::sign(&self.state.identity, &published, timestamp)?;
        self.handshake.publish(request).await?;
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
        self.handshake
            .send_initial_message(SendInitialMessageRequest {
                recipient: Bytes::copy_from_slice(peer),
                message: Some(handshake::InitialMessage {
                    first_message: Some(first_message),
                    ..handshake::InitialMessage::from(&message)
                }),
            })
            .await?;
        Ok(Session::new(mailbox, party, self.identity_key, *peer))
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
            .filter_map(|message| {
                Some(InitialMessage {
                    x3dh: x3dh::InitialMessage::try_from(message).ok()?,
                    first_message: message.first_message.clone()?,
                })
            })
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
        Ok((
            Session::new(mailbox, party, self.identity_key, *peer),
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
        &mut self,
        attachments: &impl LocalAttachments,
        size: u64,
    ) -> Result<attachment::Upload> {
        let chunks = u32::try_from(attachment::chunk_count(size))
            .map_err(|_| Error::from(ErrorKind::LimitExceeded))?;
        let timestamp = self.next_timestamp();
        let request = StartUploadRequest::sign(&self.state.identity, chunks, timestamp);
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
    pub fn subscription(&mut self) -> SubscribeRequest {
        let timestamp = self.next_timestamp();
        SubscribeRequest::sign(&self.state.identity, timestamp)
    }

    /// Milliseconds since the Unix epoch, strictly increasing, as the server requires.
    fn next_timestamp(&mut self) -> u64 {
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as u64);
        self.state.last_timestamp = now.max(self.state.last_timestamp + 1);
        self.state.last_timestamp
    }
}

/// A session with one peer: encrypts with a [`Party`] and exchanges messages through a mailbox.
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
    /// The party messages are sent with.
    party: Party,
    /// The parties of earlier sessions with the peer, latest first, see [`Session::keep`].
    others: Vec<Party>,
    me: PublicKey,
    peer: PublicKey,
    /// Sequence number of the last fetched message.
    cursor: u64,
}

impl SessionState {
    /// The peer's identity key.
    pub fn peer(&self) -> &PublicKey {
        &self.peer
    }
}

#[cfg(feature = "prost")]
impl From<&SessionState> for proto::SessionState {
    fn from(state: &SessionState) -> Self {
        Self {
            party: Some((&state.party).into()),
            others: state.others.iter().map(Into::into).collect(),
            me: state.me.to_vec(),
            peer: state.peer.to_vec(),
            cursor: state.cursor,
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&proto::SessionState> for SessionState {
    type Error = Error;

    fn try_from(state: &proto::SessionState) -> Result<Self> {
        /// An identity key field, which must be 32 bytes.
        fn key(bytes: &[u8]) -> Result<PublicKey> {
            bytes
                .try_into()
                .map_err(|_| ErrorKind::MalformedState.into())
        }

        let party = state.party.as_ref().ok_or(ErrorKind::MalformedState)?;
        Ok(Self {
            party: Party::try_from(party)?,
            others: state
                .others
                .iter()
                .map(Party::try_from)
                .collect::<core::result::Result<_, _>>()?,
            me: key(&state.me)?,
            peer: key(&state.peer)?,
            cursor: state.cursor,
        })
    }
}

impl<M> Session<M> {
    fn new(mailbox: M, party: Party, me: PublicKey, peer: PublicKey) -> Self {
        Self::restore(
            mailbox,
            SessionState {
                party,
                others: vec![],
                me,
                peer,
                cursor: 0,
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

    /// Keep `older`, an earlier session with the same peer, behind this one, which the peer or
    /// this client has just started: the messages this session cannot decrypt are tried on it,
    /// such as the ones the peer sent on it before starting this one. Of two sessions the peer
    /// and this client started at once, each keeping the other's, neither loses messages.
    ///
    /// A kept session takes over if a message on it decrypts while nothing has on this one, as
    /// the peer may never have got this one, e.g. if this client started it and its initial
    /// message was lost. Once one has, the peer has this session, so the earlier ones never take
    /// over again. The last [`KEPT_SESSIONS`] are kept, and they go on from the later of the
    /// two positions in the peer's queue.
    pub fn keep(&mut self, older: Session<M>) -> Result<()> {
        if older.state.me != self.state.me || older.state.peer != self.state.peer {
            return Err(ErrorKind::UnexpectedPeer.into());
        }
        self.state.cursor = self.state.cursor.max(older.state.cursor);
        self.state.others.splice(
            0..0,
            iter::once(older.state.party).chain(older.state.others),
        );
        self.state.others.truncate(KEPT_SESSIONS);
        Ok(())
    }

    /// Decrypt `message` with the party, or else with a kept one, which takes over if nothing
    /// has decrypted on the party.
    fn decrypt(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        let error = match self.state.party.decrypt(message) {
            Ok(content) => return Ok(content),
            Err(error) => error,
        };
        for index in 0..self.state.others.len() {
            if let Ok(content) = self.state.others[index].decrypt(message) {
                if !self.state.party.has_received() {
                    let party = self.state.others.remove(index);
                    let previous = mem::replace(&mut self.state.party, party);
                    self.state.others.insert(0, previous);
                }
                return Ok(content);
            }
        }
        Err(error.into())
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

    /// Encrypt `content` for the peer.
    pub fn encrypt(&mut self, content: &[u8]) -> Result<EncryptedMessage> {
        self.state.party.encrypt(content).map_err(Into::into)
    }

    /// Push an encrypted message to the peer; it can be pushed again if this fails.
    pub async fn push(&mut self, message: EncryptedMessage) -> Result<()> {
        self.mailbox
            .push(PushRequest {
                sender: Bytes::copy_from_slice(&self.state.me),
                recipient: Bytes::copy_from_slice(&self.state.peer),
                message: Some(message),
            })
            .await?;
        Ok(())
    }

    /// Fetch the next page of the peer's messages and decrypt them: one result per message, in
    /// order. Returns an empty page once there are no new messages.
    ///
    /// A message is tried on the sessions [kept](Session::keep) too. One that fails to decrypt
    /// is still consumed, so it cannot block the ones after it.
    /// Cancel-safe: if the future is dropped, no message is consumed.
    pub async fn receive(&mut self) -> Result<Vec<Result<Vec<u8>>>> {
        let response = self
            .mailbox
            .fetch(FetchRequest {
                sender: Bytes::copy_from_slice(&self.state.peer),
                recipient: Bytes::copy_from_slice(&self.state.me),
                after: self.state.cursor,
                limit: 0,
            })
            .await?;
        let mut received = Vec::with_capacity(response.messages.len());
        for envelope in response.messages {
            self.state.cursor = self.state.cursor.max(envelope.sequence);
            received.push(match envelope.message {
                Some(message) => self.decrypt(&message),
                None => Err(ErrorKind::InvalidMessage.into()),
            });
        }
        Ok(received)
    }
}

#[cfg(test)]
mod test {
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
    #[derive(Debug)]
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

    fn contents(received: Vec<Result<Vec<u8>>>) -> Vec<Vec<u8>> {
        received
            .into_iter()
            .map(|content| content.unwrap())
            .collect()
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
            contents(bob_session.receive().await.unwrap()),
            [b"bob".to_vec()]
        );
        assert!(bob_session.receive().await.unwrap().is_empty());

        bob_session.send(b"hello").await.unwrap();
        assert_eq!(
            contents(alice_session.receive().await.unwrap()),
            [b"hello".to_vec()]
        );

        // A message encrypted but pushed later still arrives, after the ones pushed before it.
        let late = alice_session.encrypt(b"late").unwrap();
        alice_session.send(b"early").await.unwrap();
        alice_session.push(late).await.unwrap();
        assert_eq!(
            contents(bob_session.receive().await.unwrap()),
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
        assert_eq!(contents(alice_session.receive().await.unwrap()), [b"hello"]);
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
            contents(bob_session.receive().await.unwrap()),
            [b"on the new one"]
        );
        bob_session.send(b"me too").await.unwrap();
        let received = alice_again.receive().await.unwrap();
        // Her new session reads her queue from the start, where his reply to the old one is.
        assert!(received[0].is_err());
        assert_eq!(received[1].as_ref().unwrap(), b"me too");
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
        assert_eq!(contents(bob_session.receive().await.unwrap()), [b"old"]);
        bob_session.send(b"on the new one").await.unwrap();
        let received = alice_again.receive().await.unwrap();
        assert!(received[0].is_err());
        assert_eq!(received[1].as_ref().unwrap(), b"on the new one");
        assert!(alice_session.receive().await.unwrap()[0].is_err());
    }

    #[tokio::test]
    async fn an_earlier_session_takes_over_if_the_new_one_gets_no_answer() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let (mut alice, mut alice_session, mut bob, mut bob_session) =
            talking(&handshake, &mailbox).await;

        // Bob starts again, but Alice never gets his initial message.
        alice.publish_keys(1).await.unwrap();
        let session = bob
            .initiate(&alice.identity_key(), b"new", InProcessMailbox(&mailbox))
            .await
            .unwrap();
        let older = mem::replace(&mut bob_session, session);
        bob_session.keep(older).unwrap();

        // Alice writes on the old session, so Bob goes back to it.
        alice_session.send(b"still here").await.unwrap();
        assert_eq!(
            contents(bob_session.receive().await.unwrap()),
            [b"still here"]
        );
        bob_session.send(b"back on it").await.unwrap();
        assert_eq!(
            contents(alice_session.receive().await.unwrap()),
            [b"back on it"]
        );
    }

    #[tokio::test]
    async fn sessions_started_at_once_lose_nothing() {
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

        // Each takes the other's session, keeping its own.
        let initial_messages = alice.take_initial_messages().await.unwrap();
        let (session, first) = alice
            .accept(
                &bob.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"hi alice");
        let older = mem::replace(&mut alice_session, session);
        alice_session.keep(older).unwrap();
        let initial_messages = bob.take_initial_messages().await.unwrap();
        let (session, first) = bob
            .accept(
                &alice.identity_key(),
                &initial_messages[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(first, b"hi bob");
        let older = mem::replace(&mut bob_session, session);
        bob_session.keep(older).unwrap();

        // Whatever each sends, at once or in turn, arrives.
        alice_session.send(b"a1").await.unwrap();
        bob_session.send(b"b1").await.unwrap();
        assert_eq!(contents(alice_session.receive().await.unwrap()), [b"b1"]);
        assert_eq!(contents(bob_session.receive().await.unwrap()), [b"a1"]);
        alice_session.send(b"a2").await.unwrap();
        assert_eq!(contents(bob_session.receive().await.unwrap()), [b"a2"]);
        bob_session.send(b"b2").await.unwrap();
        assert_eq!(contents(alice_session.receive().await.unwrap()), [b"b2"]);
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
        let mut alice = Client::new(InProcessHandshake(&handshake));
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
            contents(bob_session.receive().await.unwrap()),
            [b"there".to_vec()]
        );
        let mut bob_session = Session::restore(
            InProcessMailbox(&mailbox),
            restored::<_, proto::SessionState>(bob_session.state()),
        );
        assert!(bob_session.receive().await.unwrap().is_empty());
        bob_session.send(b"hello").await.unwrap();
        assert_eq!(
            contents(alice_session.receive().await.unwrap()),
            [b"hello".to_vec()]
        );
    }
}
