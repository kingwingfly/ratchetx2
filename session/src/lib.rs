#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod error;
#[cfg(feature = "prost")]
pub mod proto;

use bon::Builder;
use bytes::Bytes;
pub use error::{Error, ErrorKind, Result};
use party::{EncryptedMessage, Party};
pub use protocol;
use protocol::{
    handshake::{
        FetchBundleRequest, InitialMessage, IntroduceRequest, LocalHandshake, PublishRequest,
        TakeIntroductionsRequest,
    },
    mailbox::{FetchRequest, LocalMailbox, PushRequest},
};
use ratchetx2::{DhPrivateKey, Ratchet, SharedKeys};
pub use x3dh::PublicKey;
use x3dh::{LocalPrekeys, PrekeyBundle};
use xeddsa::XEdDSAPrivateKey;

/// An initial message from a peer who wants to start a session; accept it with
/// [`Client::accept`].
pub type Introduction = x3dh::InitialMessage;

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
    /// introductions waiting before publishing again; later, the ones using deleted prekeys
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

    /// Start a session with `peer`: fetch the peer's prekeys, run X3DH, and leave the initial
    /// message in the peer's inbox.
    pub async fn initiate<M>(&mut self, peer: &PublicKey, mailbox: M) -> Result<Session<M>> {
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
        self.handshake
            .introduce(IntroduceRequest {
                recipient: Bytes::copy_from_slice(peer),
                message: Some(InitialMessage::from(&message)),
            })
            .await?;
        Ok(Session::new(
            mailbox,
            Party::new(ratchet, agreement.associated_data),
            self.identity_key,
            *peer,
        ))
    }

    /// Take the initial messages waiting in this client's inbox.
    ///
    /// The server deletes them, so keep the ones to accept later. Malformed ones, which could
    /// never be accepted, are left out.
    pub async fn take_introductions(&mut self) -> Result<Vec<Introduction>> {
        let timestamp = self.next_timestamp();
        let request = TakeIntroductionsRequest::sign(&self.state.identity, timestamp);
        let response = self.handshake.take_introductions(request).await?;
        // The server has deleted them already, so one malformed message must not fail the
        // call and lose the others with it.
        Ok(response
            .messages
            .iter()
            .filter_map(|message| Introduction::try_from(message).ok())
            .collect())
    }

    /// Accept `introduction` from `peer`, starting the session `peer` asked for.
    ///
    /// Fails with [`ErrorKind::UnexpectedPeer`] if it is not from `peer`, without using it up.
    /// The session can send only after it has received the peer's first message.
    pub fn accept<M>(
        &mut self,
        peer: &PublicKey,
        introduction: &Introduction,
        mailbox: M,
    ) -> Result<Session<M>> {
        let (agreement, signed_prekey) =
            self.state
                .prekeys
                .accept(&self.state.identity, peer, introduction)?;
        let ratchet = Ratchet::bob(
            &SharedKeys::from_secret(&agreement.secret_key),
            DhPrivateKey::from(signed_prekey.to_bytes()),
        );
        Ok(Session::new(
            mailbox,
            Party::new(ratchet, agreement.associated_data),
            self.identity_key,
            *peer,
        ))
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

/// What a [`Session`] keeps besides its transport: the double ratchet, both identity keys and
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
    party: Party,
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
    /// A message that fails to decrypt is still consumed, so it cannot block the ones after it.
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
                Some(message) => self.state.party.decrypt(&message).map_err(Error::from),
                None => Err(ErrorKind::InvalidMessage.into()),
            });
        }
        Ok(received)
    }
}

#[cfg(test)]
mod test {
    use protocol::{
        handshake::{
            FetchBundleResponse, HandshakeServer, IntroduceResponse, PublishResponse,
            TakeIntroductionsResponse,
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

        async fn introduce(
            &self,
            request: IntroduceRequest,
        ) -> protocol::Result<IntroduceResponse> {
            self.0.introduce(request).await
        }

        async fn take_introductions(
            &self,
            request: TakeIntroductionsRequest,
        ) -> protocol::Result<TakeIntroductionsResponse> {
            self.0.take_introductions(request).await
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
            .initiate(&bob.identity_key(), InProcessMailbox(&mailbox))
            .await
            .unwrap();
        alice_session.send(b"hi").await.unwrap();
        alice_session.send(b"bob").await.unwrap();

        let introductions = bob.take_introductions().await.unwrap();
        assert_eq!(introductions.len(), 1);
        let mut bob_session = bob
            .accept(
                &alice.identity_key(),
                &introductions[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();

        assert_eq!(
            contents(bob_session.receive().await.unwrap()),
            [b"hi".to_vec(), b"bob".to_vec()]
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

    #[tokio::test]
    #[cfg(feature = "prost")]
    async fn restored_clients_and_sessions_carry_on() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let mut alice = Client::new(InProcessHandshake(&handshake));
        let mut bob = Client::new(InProcessHandshake(&handshake));
        bob.publish_keys(1).await.unwrap();
        let mut alice_session = alice
            .initiate(&bob.identity_key(), InProcessMailbox(&mailbox))
            .await
            .unwrap();
        alice_session.send(b"hi").await.unwrap();

        // Bob's identity, prekeys and timestamp survive a restart, and so does Alice's session.
        let mut bob = Client::restore(
            InProcessHandshake(&handshake),
            restored::<_, proto::ClientState>(bob.state()),
        );
        let mut alice_session = Session::restore(
            InProcessMailbox(&mailbox),
            restored::<_, proto::SessionState>(alice_session.state()),
        );
        let introductions = bob.take_introductions().await.unwrap();
        let mut bob_session = bob
            .accept(
                &alice.identity_key(),
                &introductions[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();
        assert_eq!(
            contents(bob_session.receive().await.unwrap()),
            [b"hi".to_vec()]
        );

        // The cursor too: what was received is not fetched again.
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
