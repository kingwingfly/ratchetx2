#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod error;

use bon::Builder;
use bytes::Bytes;
use party::{EncryptedMessage, Party};
use protocol::handshake::{
    FetchBundleRequest, InitialMessage, IntroduceRequest, LocalHandshake, PublishRequest,
    TakeIntroductionsRequest,
};
use protocol::mailbox::{FetchRequest, LocalMailbox, PushRequest};
use ratchetx2::{DhPrivateKey, SharedKeys};
use x3dh::{LocalPrekeys, PrekeyBundle};
use xeddsa::XEdDSAPrivateKey;

pub use error::{Error, ErrorKind, Result};
pub use protocol;
pub use x3dh::PublicKey;

/// An initial message from a peer who wants to start a session; accept it with
/// [`Client::accept`].
pub type Introduction = x3dh::InitialMessage;

/// An identity on a handshake server: publishes prekeys, starts and accepts sessions.
///
/// [`Client::new`] gives it a new random identity key, and [`Client::builder`] can set one:
/// `Client::builder(handshake).identity(identity).build()`.
#[derive(Debug, Builder)]
pub struct Client<H> {
    #[builder(start_fn)]
    handshake: H,
    /// The identity key; a new random one unless set.
    #[builder(default = XEdDSAPrivateKey::generate())]
    identity: XEdDSAPrivateKey,
    #[builder(skip = identity.compute_public_key().to_bytes())]
    identity_key: PublicKey,
    #[builder(skip)]
    prekeys: LocalPrekeys,
    #[builder(skip)]
    last_timestamp: u64,
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
        let published = self.prekeys.generate(&self.identity, one_time_count);
        let timestamp = self.next_timestamp();
        let request = PublishRequest::sign(&self.identity, &published, timestamp)?;
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
        let (message, agreement) = x3dh::alice(&self.identity, peer, &bundle)?;
        let ratchet =
            SharedKeys::from_secret(&agreement.secret_key).alice(&bundle.signed_prekey)?;
        self.handshake
            .introduce(IntroduceRequest {
                recipient: Bytes::copy_from_slice(peer),
                message: Some(InitialMessage::from(&message)),
            })
            .await?;
        Ok(Session {
            party: Party::new(ratchet, agreement.associated_data),
            mailbox,
            me: self.identity_key,
            peer: *peer,
            cursor: 0,
        })
    }

    /// Take the initial messages waiting in this client's inbox.
    ///
    /// The server deletes them, so keep the ones to accept later. Malformed ones, which could
    /// never be accepted, are left out.
    pub async fn take_introductions(&mut self) -> Result<Vec<Introduction>> {
        let timestamp = self.next_timestamp();
        let request = TakeIntroductionsRequest::sign(&self.identity, timestamp);
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
            x3dh::bob(&self.identity, &mut self.prekeys, peer, introduction)?;
        let ratchet = SharedKeys::from_secret(&agreement.secret_key)
            .bob(DhPrivateKey::from(signed_prekey.to_bytes()));
        Ok(Session {
            party: Party::new(ratchet, agreement.associated_data),
            mailbox,
            me: self.identity_key,
            peer: *peer,
            cursor: 0,
        })
    }

    /// Milliseconds since the Unix epoch, strictly increasing, as the server requires.
    fn next_timestamp(&mut self) -> u64 {
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as u64);
        self.last_timestamp = now.max(self.last_timestamp + 1);
        self.last_timestamp
    }
}

/// A session with one peer: encrypts with a [`Party`] and exchanges messages through a mailbox.
#[derive(Debug)]
pub struct Session<M> {
    party: Party,
    mailbox: M,
    me: PublicKey,
    peer: PublicKey,
    /// Sequence number of the last fetched message.
    cursor: u64,
}

impl<M: LocalMailbox> Session<M> {
    /// The peer's identity key.
    pub fn peer(&self) -> &PublicKey {
        &self.peer
    }

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
        self.party.encrypt(content).map_err(Into::into)
    }

    /// Push an encrypted message to the peer; it can be pushed again if this fails.
    pub async fn push(&mut self, message: EncryptedMessage) -> Result<()> {
        self.mailbox
            .push(PushRequest {
                sender: Bytes::copy_from_slice(&self.me),
                recipient: Bytes::copy_from_slice(&self.peer),
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
                sender: Bytes::copy_from_slice(&self.peer),
                recipient: Bytes::copy_from_slice(&self.me),
                after: self.cursor,
                limit: 0,
            })
            .await?;
        let mut received = Vec::with_capacity(response.messages.len());
        for envelope in response.messages {
            self.cursor = self.cursor.max(envelope.sequence);
            received.push(match envelope.message {
                Some(message) => self.party.decrypt(&message).map_err(Error::from),
                None => Err(ErrorKind::InvalidMessage.into()),
            });
        }
        Ok(received)
    }
}

#[cfg(test)]
mod test {
    use protocol::handshake::{
        FetchBundleResponse, HandshakeServer, IntroduceResponse, PublishResponse,
        TakeIntroductionsResponse,
    };
    use protocol::mailbox::{FetchResponse, MailboxServer, PushResponse};
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
        assert!(bob.take_introductions().await.unwrap().is_empty());
        let mut bob_session = bob
            .accept(
                &alice.identity_key(),
                &introductions[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap();

        // Bob can send only after receiving Alice's first message.
        let error = bob_session.send(b"too early").await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NoSendingChain);
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

    #[test]
    fn builder_sets_the_identity() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let identity = XEdDSAPrivateKey::generate();
        let identity_key = identity.compute_public_key().to_bytes();
        let client = Client::builder(InProcessHandshake(&handshake))
            .identity(identity)
            .build();
        assert_eq!(client.identity_key(), identity_key);
    }

    #[tokio::test]
    async fn rejections() {
        let handshake = HandshakeServer::new(MemoryStore::default());
        let mailbox = MailboxServer::new(MemoryStore::default());
        let mut alice = Client::new(InProcessHandshake(&handshake));
        let mut bob = Client::new(InProcessHandshake(&handshake));

        let error = alice
            .initiate(&bob.identity_key(), InProcessMailbox(&mailbox))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);

        bob.publish_keys(1).await.unwrap();
        alice
            .initiate(&bob.identity_key(), InProcessMailbox(&mailbox))
            .await
            .unwrap();
        let introductions = bob.take_introductions().await.unwrap();
        // Only from the expected peer, and a wrong guess does not use it up.
        let error = bob
            .accept(&[9; 32], &introductions[0], InProcessMailbox(&mailbox))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedPeer);
        bob.accept(
            &alice.identity_key(),
            &introductions[0],
            InProcessMailbox(&mailbox),
        )
        .unwrap();
        // Its one-time prekey is used up.
        let error = bob
            .accept(
                &alice.identity_key(),
                &introductions[0],
                InProcessMailbox(&mailbox),
            )
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidIntroduction);
    }

    #[tokio::test]
    async fn over_grpc() {
        use protocol::grpc::{GrpcHandshake, GrpcMailbox, TcpIncoming, connect, serve};

        // Bound before serving, so connecting needs no waiting, on a port the OS picks.
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = incoming.local_addr().unwrap();
        tokio::spawn(serve(
            incoming,
            None,
            HandshakeServer::new(MemoryStore::default()),
            MailboxServer::new(MemoryStore::default()),
        ));
        let channel = connect(format!("http://{address}"), None).await.unwrap();
        let mut alice = Client::new(GrpcHandshake::new(channel.clone()));
        let mut bob = Client::new(GrpcHandshake::new(channel.clone()));

        bob.publish_keys(1).await.unwrap();
        let mut alice_session = alice
            .initiate(&bob.identity_key(), GrpcMailbox::new(channel.clone()))
            .await
            .unwrap();
        alice_session.send(b"hi").await.unwrap();
        let introductions = bob.take_introductions().await.unwrap();
        let mut bob_session = bob
            .accept(
                &alice.identity_key(),
                &introductions[0],
                GrpcMailbox::new(channel),
            )
            .unwrap();
        assert_eq!(
            contents(bob_session.receive().await.unwrap()),
            [b"hi".to_vec()]
        );
    }
}
