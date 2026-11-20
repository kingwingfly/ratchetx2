//! End-to-end tests for security hardening (Part 2) and optional PQ support, suite selection,
//! mixed-mode interop, toggle flows, and active downgrade defense (Part 3).

use core::mem;
use std::sync::Arc;
#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use protocol::{
    content::{Hello, Kind as ContentKind},
    handshake::{
        FetchBundleRequest, FetchBundleResponse, HandshakeServer, LocalHandshake, PublishRequest,
        PublishResponse, SendInitialMessageRequest, SendInitialMessageResponse,
        TakeInitialMessagesRequest, TakeInitialMessagesResponse,
    },
    mailbox::{
        FetchRequest, FetchResponse, LocalMailbox, MailboxLimits, MailboxServer, PushRequest,
        PushResponse,
    },
};
use session::{
    Client, ErrorKind, PeerPqState, PublicKey, SessionSecurity, check_peer_hello,
    expected_audience_from_url,
};
#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
use session::{PqConfig, PqSuite};
#[cfg(all(feature = "prost", feature = "ml-kem-1024"))]
use session::Session;
use storage::MemoryStore;

/// Shared `Arc<MemoryStore>` implementing both v1 and (when PQ is enabled) v2 storage traits.
#[derive(Debug, Clone, Default)]
struct SharedStore(Arc<MemoryStore>);

impl storage::LocalHandshakeStore for SharedStore {
    async fn publish(
        &self,
        bundle: storage::Bundle,
        one_time_prekeys: Vec<PublicKey>,
    ) -> storage::Result<bool> {
        storage::HandshakeStore::publish(&*self.0, bundle, one_time_prekeys).await
    }

    async fn take_bundle(
        &self,
        identity_key: &PublicKey,
    ) -> storage::Result<Option<(storage::Bundle, Option<PublicKey>)>> {
        storage::HandshakeStore::take_bundle(&*self.0, identity_key).await
    }

    async fn add_initial_message(
        &self,
        initial_message: storage::StoredInitialMessage,
        limit: usize,
    ) -> storage::Result<bool> {
        storage::HandshakeStore::add_initial_message(&*self.0, initial_message, limit).await
    }

    async fn take_initial_messages(
        &self,
        recipient: &PublicKey,
        timestamp: u64,
    ) -> storage::Result<Option<Vec<storage::StoredInitialMessage>>> {
        storage::HandshakeStore::take_initial_messages(&*self.0, recipient, timestamp).await
    }
}

impl storage::LocalMailboxStore for SharedStore {
    async fn append(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        delivery_hash: Option<[u8; 32]>,
    ) -> storage::Result<u64> {
        storage::MailboxStore::append(
            &*self.0,
            sender,
            recipient,
            header,
            content,
            initial_message,
            delivery_hash,
        )
        .await
    }

    async fn delete_delivered(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        hashes: &[[u8; 32]],
    ) -> storage::Result<()> {
        storage::MailboxStore::delete_delivered(&*self.0, sender, recipient, hashes).await
    }

    async fn read(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
    ) -> storage::Result<Vec<storage::StoredMessage>> {
        storage::MailboxStore::read(&*self.0, sender, recipient, after, limit).await
    }
}

#[derive(Debug, Clone)]
struct V1Handshake(Arc<HandshakeServer<SharedStore>>);

impl LocalHandshake for V1Handshake {
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

#[derive(Debug, Clone)]
struct V1Mailbox(Arc<MailboxServer<SharedStore>>);

impl LocalMailbox for V1Mailbox {
    async fn push(&self, request: PushRequest) -> protocol::Result<PushResponse> {
        self.0.push(request).await
    }

    async fn fetch(&self, request: FetchRequest) -> protocol::Result<FetchResponse> {
        self.0.fetch(request).await
    }
}

/// Wrapper that expires messages at given sequence numbers while keeping their carried initial
/// messages intact.
#[derive(Clone)]
struct ExpiringV1Mailbox {
    inner: Arc<MailboxServer<SharedStore>>,
    expired_seqs: Vec<u64>,
}

impl LocalMailbox for ExpiringV1Mailbox {
    async fn push(&self, request: PushRequest) -> protocol::Result<PushResponse> {
        self.inner.push(request).await
    }

    async fn fetch(&self, request: FetchRequest) -> protocol::Result<FetchResponse> {
        let mut resp = self.inner.fetch(request).await?;
        for env in &mut resp.messages {
            if self.expired_seqs.contains(&env.sequence) {
                env.message = None;
            }
        }
        Ok(resp)
    }
}

fn hello_bytes(name: &str, session_seq: u64, pq_capable: bool) -> Vec<u8> {
    ContentKind::Hello(Hello {
        name: name.into(),
        pq_capable,
        max_version: if pq_capable { 2 } else { 1 },
        session_seq,
        offered_suites: if pq_capable { vec![1, 2] } else { vec![] },
        pq_ratchet_capable: pq_capable,
    })
    .to_bytes()
}

#[test]
fn expected_audience_normalizes_urls_and_rejects_bad_inputs() {
    assert_eq!(
        expected_audience_from_url("https://Chat.Example.COM:443/path?x=1#frag").unwrap(),
        "chat.example.com"
    );
    assert_eq!(
        expected_audience_from_url("https://chat.example.com:8443/").unwrap(),
        "chat.example.com:8443"
    );
    assert_eq!(
        expected_audience_from_url("http://localhost:8787").unwrap(),
        "localhost:8787"
    );
    assert_eq!(
        expected_audience_from_url("http://localhost:80/foo").unwrap(),
        "localhost"
    );
    assert_eq!(
        expected_audience_from_url("relay.example").unwrap(),
        "relay.example"
    );
    assert!(expected_audience_from_url("").is_err());
    assert!(expected_audience_from_url("https://user@evil.example").is_err());
    assert!(expected_audience_from_url("ftp://example.com").is_err());
}

#[tokio::test]
async fn next_timestamp_uses_server_clock_and_enforces_max_safe_integer() {
    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store)));
    let mut alice = Client::new(hs);

    // Simulate device clock being wildly off; observe server's actual time via ServerClock.
    let server_now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    alice.clock().observe(server_now);
    let p1 = alice.prepare_publish(2).unwrap();
    let p2 = alice.prepare_extend_keys(2).unwrap();
    assert!(p2.request.timestamp > p1.request.timestamp);
    assert!(p1.request.timestamp.abs_diff(server_now) < 5_000);

    // Observing a server timestamp beyond MAX_SAFE_INTEGER fails cleanly.
    alice.clock().observe(protocol::MAX_SAFE_INTEGER + 10);
    assert_eq!(
        alice.prepare_publish(1).unwrap_err().kind(),
        ErrorKind::Protocol
    );
}

#[tokio::test]
async fn classical_persist_before_transmit_and_extend_without_rotating_spk() {
    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store.clone())));
    let mb = V1Mailbox(Arc::new(MailboxServer::new(store)));
    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);

    // Bob prepares publish -> persists -> transmits -> commits.
    let prep = bob.prepare_publish(2).unwrap();
    let spk_before = bob.current_signed_prekey().unwrap();
    assert_eq!(bob.current_one_time_count(), 2);
    bob.transmit_publish(&prep).await.unwrap();
    bob.commit_publish(prep);

    // Replenish OPKs without rotating SPK.
    bob.extend_keys(3).await.unwrap();
    assert_eq!(bob.current_signed_prekey().unwrap(), spk_before);
    assert_eq!(bob.current_one_time_count(), 5);

    // Alice prepares initiate -> persists -> transmits.
    let init = alice
        .prepare_initiate(&bob.identity_key(), b"hello", mb.clone())
        .await
        .unwrap();
    let mut alice_session = init.session;
    // Nothing in Bob's inbox yet because Alice hasn't transmitted!
    assert!(bob.take_initial_messages().await.unwrap().is_empty());
    alice.send_prepared_initiate(&init.request).await.unwrap();

    let inbox = bob.take_initial_messages().await.unwrap();
    assert_eq!(inbox.len(), 1);
    let (mut bob_session, first) = bob
        .accept(&alice.identity_key(), &inbox[0], mb.clone())
        .unwrap();
    assert_eq!(first, b"hello");

    alice_session.send(b"ping").await.unwrap();
    let got = bob_session.receive().await.unwrap();
    assert_eq!(got[0].content.as_deref().unwrap(), b"ping");
}

#[tokio::test]
async fn hello_session_seq_anti_rollback_protects_active_session() {
    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store.clone())));
    let mb = V1Mailbox(Arc::new(MailboxServer::new(store)));
    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    bob.publish_keys(10).await.unwrap();

    // 1. Alice starts session #1 (seq=1) and session #2 (seq=2), and a legacy seq=0 initial.
    let s1 = alice
        .initiate(&bob.identity_key(), &hello_bytes("alice", 1, false), mb.clone())
        .await
        .unwrap();
    let mut s2 = alice
        .initiate(&bob.identity_key(), &hello_bytes("alice", 2, false), mb.clone())
        .await
        .unwrap();
    let s0 = alice
        .initiate(&bob.identity_key(), &hello_bytes("alice", 0, false), mb.clone())
        .await
        .unwrap();
    let mut s3 = alice
        .initiate(&bob.identity_key(), &hello_bytes("alice", 3, false), mb.clone())
        .await
        .unwrap();
    drop((s1, s0));

    let inbox = bob.take_initial_messages().await.unwrap();
    assert_eq!(inbox.len(), 4);

    // Suppose Bob receives session #2 FIRST (e.g. server withheld #1 and #0).
    let (mut bob_session, first2) = bob
        .accept(&alice.identity_key(), &inbox[1], mb.clone())
        .unwrap();
    let active_s2 = *bob_session.active_id().unwrap();
    assert_eq!(bob_session.peer_session_seq(), 2);

    // Calling `session.check_peer_hello` right after `Client::accept` with the session's own
    // Hello MUST NOT falsely flag `stale_session_seq = true`!
    let Some(ContentKind::Hello(h2)) = ContentKind::from_bytes(&first2) else {
        panic!("expected Hello");
    };
    let own_check = bob_session.check_peer_hello(&h2, false);
    assert!(!own_check.stale_session_seq);
    assert!(!own_check.downgrade_detected);
    // Checking a strictly older seq (1) or 0 on the same session IS flagged stale.
    assert!(
        bob_session
            .check_peer_hello(
                &Hello {
                    name: "alice".into(),
                    session_seq: 1,
                    ..Hello::default()
                },
                false,
            )
            .stale_session_seq
    );
    assert!(
        bob_session
            .check_peer_hello(&Hello::classical("alice"), false)
            .stale_session_seq
    );

    // Delayed/withheld session #1 (seq=1 <= 2) MUST be rejected and NEVER overwrite active #2!
    let (stale_1, _) = bob
        .accept(&alice.identity_key(), &inbox[0], mb.clone())
        .unwrap();
    assert_eq!(
        bob_session.accept_replacement(stale_1).unwrap_err().kind(),
        ErrorKind::StaleSession
    );
    assert_eq!(bob_session.active_id(), Some(&active_s2));

    // Legacy seq=0 after peer already sent seq > 0 MUST ALSO be rejected even via `keep`!
    let (stale_0, _) = bob
        .accept(&alice.identity_key(), &inbox[2], mb.clone())
        .unwrap();
    let older = mem::replace(&mut bob_session, stale_0);
    let err = bob_session.keep(older).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::StaleSession);
    // Crucial: `bob_session` STILL holds active #2 (not rolled back to #0)!
    assert_eq!(bob_session.active_id(), Some(&active_s2));

    // Active #2 still communicates cleanly.
    s2.send(b"still on 2").await.unwrap();
    let r = bob_session.receive().await.unwrap();
    assert_eq!(r[0].content.as_deref().unwrap(), b"still on 2");

    // Genuinely newer session #3 (seq=3 > 2) IS accepted and replaces active #2!
    let (newer_3, _) = bob
        .accept(&alice.identity_key(), &inbox[3], mb.clone())
        .unwrap();
    assert!(bob_session.accept_replacement(newer_3).unwrap());
    assert_eq!(bob_session.peer_session_seq(), 3);
    assert_eq!(bob_session.active_id(), s3.active_id());
    s3.send(b"on 3").await.unwrap();
    let r = bob_session.receive().await.unwrap();
    assert_eq!(r[0].content.as_deref().unwrap(), b"on 3");

    // In-band check_peer_hello also detects stale seq and downgrade!
    let mut ps = PeerPqState::default();
    let c0 = check_peer_hello(&mut ps, SessionSecurity::classical(), &Hello::classical("a"), false);
    assert!(!c0.stale_session_seq);
    let c1 = check_peer_hello(
        &mut ps,
        SessionSecurity::classical(),
        &Hello {
            name: "a".into(),
            session_seq: 2,
            ..Hello::default()
        },
        false,
    );
    assert!(!c1.stale_session_seq);
    assert_eq!(ps.peer_session_seq, 2);
    let c_zero = check_peer_hello(&mut ps, SessionSecurity::classical(), &Hello::classical("a"), false);
    assert!(c_zero.stale_session_seq);
}

#[tokio::test]
async fn evicted_message_acks_delivery_token_and_surfaces_distinctly() {
    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store.clone())));
    let mailbox_server = Arc::new(MailboxServer::builder(store.clone()).limits(MailboxLimits {
        max_fetch: 50,
        ..MailboxLimits::default()
    }).build());
    let mb = V1Mailbox(mailbox_server.clone());

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    bob.publish_keys(2).await.unwrap();

    let mut alice_session = alice
        .initiate(&bob.identity_key(), b"hi2", mb.clone())
        .await
        .unwrap();
    let inbox = bob.take_initial_messages().await.unwrap();
    let (mut bob_session, _) = bob
        .accept(&alice.identity_key(), &inbox[0], mb.clone())
        .unwrap();

    // Alice encrypts msg-0 (held back), then skips 600 messages and another 600 messages (total
    // 1198 skipped > SKIP_MAX=1024), so Bob evicts msg-0's skipped key before msg-0 arrives!
    let msg0 = alice_session.encrypt(b"msg-0").unwrap();
    for _ in 1..600 {
        let _ = alice_session.encrypt(b"gap").unwrap();
    }
    let msg600 = alice_session.encrypt(b"msg-600").unwrap();
    for _ in 601..1200 {
        let _ = alice_session.encrypt(b"gap").unwrap();
    }
    let msg1200 = alice_session.encrypt(b"msg-1200").unwrap();
    let msg1201 = alice_session.encrypt(b"msg-1201").unwrap();

    // Deliver 600 and 1200 so Bob skips 0..600 then 601..1200 -> 1198 skipped keys > SKIP_MAX(1024),
    // evicting msg 0!
    alice_session.push(msg600).await.unwrap();
    alice_session.push(msg1200).await.unwrap();
    let got = bob_session.receive().await.unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].content.as_deref().unwrap(), b"msg-600");
    assert_eq!(got[1].content.as_deref().unwrap(), b"msg-1200");

    // Now push the evicted msg-0 followed by normal msg-1201!
    alice_session.push(msg0).await.unwrap();
    alice_session.push(msg1201).await.unwrap();

    let got = bob_session.receive().await.unwrap();
    assert_eq!(got.len(), 2, "EvictedMessage must NOT stall the page!");
    assert!(got[0].is_evicted());
    assert_eq!(
        got[0].content.as_ref().unwrap_err().kind(),
        ErrorKind::EvictedMessage
    );
    assert_eq!(got[1].content.as_deref().unwrap(), b"msg-1201");

    // Next fetch MUST send msg-0's delivery token so the server deletes it (0 remaining)!
    assert!(bob_session.receive().await.unwrap().is_empty());
    let queued = mailbox_server
        .fetch(FetchRequest {
            sender: Bytes::copy_from_slice(&alice.identity_key()),
            recipient: Bytes::copy_from_slice(&bob.identity_key()),
            after: 0,
            limit: 100,
            delivered: vec![],
        })
        .await
        .unwrap()
        .messages;
    assert_eq!(
        queued.len(),
        0,
        "evicted message must be deleted from server via delivery token"
    );
}

#[tokio::test]
async fn trailing_carried_initial_message_survives_expired_page_boundary() {
    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store.clone())));
    let mailbox_server = Arc::new(
        MailboxServer::builder(store)
            .limits(MailboxLimits {
                max_fetch: 1,
                ..MailboxLimits::default()
            })
            .build(),
    );
    let mb = V1Mailbox(mailbox_server.clone());

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    bob.publish_keys(5).await.unwrap();

    let mut alice_session = alice
        .initiate(&bob.identity_key(), b"first", mb.clone())
        .await
        .unwrap();
    let inbox = bob.take_initial_messages().await.unwrap();
    let (mut bob_session, _) = bob
        .accept(
            &alice.identity_key(),
            &inbox[0],
            ExpiringV1Mailbox {
                inner: mailbox_server.clone(),
                expired_seqs: vec![1],
            },
        )
        .unwrap();
    bob_session.send(b"ack").await.unwrap();
    assert_eq!(
        alice_session.receive().await.unwrap()[0]
            .content
            .as_deref()
            .unwrap(),
        b"ack"
    );

    // Page 1 is a single expired envelope carrying Alice's new initial message (lost from inbox),
    // and there is NO second message yet! Must surface via `Err(Expired)` with the carried
    // initial message rather than dropping it after advancing cursor.
    alice
        .start_again(&mut alice_session, b"lost-new-session")
        .await
        .unwrap();
    // Simulate Bob losing Alice's inbox initial message.
    assert_eq!(bob.take_initial_messages().await.unwrap().len(), 1);
    alice_session.send(b"expires-1").await.unwrap();

    let received = bob_session.receive().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].content.as_ref().unwrap_err().kind(),
        ErrorKind::Expired
    );
    assert_eq!(received[0].initial_messages.len(), 1);
    let (new_bob, greeting) = bob
        .accept(&alice.identity_key(), &received[0].initial_messages[0], mb)
        .unwrap();
    assert_eq!(greeting, b"lost-new-session");
    drop(new_bob);
}

#[tokio::test]
async fn infinite_expired_pages_relay_terminates_cleanly() {
    use std::sync::atomic::{AtomicU64, Ordering};

    struct InfiniteExpiredMailbox {
        fetches: Arc<AtomicU64>,
    }

    impl LocalMailbox for InfiniteExpiredMailbox {
        async fn push(&self, _: PushRequest) -> protocol::Result<PushResponse> {
            Ok(PushResponse::default())
        }

        async fn fetch(&self, request: FetchRequest) -> protocol::Result<FetchResponse> {
            self.fetches.fetch_add(1, Ordering::Relaxed);
            Ok(FetchResponse {
                messages: vec![protocol::mailbox::Envelope {
                    sequence: request.after + 1,
                    message: None,
                    initial_message: None,
                }],
            })
        }
    }

    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store)));
    let fetches = Arc::new(AtomicU64::new(0));
    let mb = InfiniteExpiredMailbox {
        fetches: fetches.clone(),
    };
    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    bob.publish_keys(1).await.unwrap();
    let mut alice_session = alice
        .initiate(&bob.identity_key(), b"hi", mb)
        .await
        .unwrap();

    // Even with strictly increasing expired sequences, receive() stops cleanly at the page cap.
    let received = alice_session.receive().await.unwrap();
    assert!(received.is_empty());
    assert_eq!(fetches.load(Ordering::Relaxed), 8);
}

#[cfg(feature = "prost")]
#[tokio::test]
async fn state_validation_on_prost_restore_rejects_corruption() {
    use session::proto;

    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store.clone())));
    let mb = V1Mailbox(Arc::new(MailboxServer::new(store)));
    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    bob.publish_keys(2).await.unwrap();
    let alice_session = alice
        .initiate(&bob.identity_key(), b"hi", mb)
        .await
        .unwrap();

    // 1. Valid roundtrip passes.
    let mut proto_client = proto::ClientState::from(alice.state());
    assert!(session::ClientState::try_from(&proto_client).is_ok());

    // 2. Invalid PQ suite ID rejected.
    proto_client.preferred_pq_suite = 99;
    assert_eq!(
        session::ClientState::try_from(&proto_client)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );
    proto_client.preferred_pq_suite = 0;

    // 3. `strict_pq` + `pq_disabled` rejected.
    proto_client.pq_disabled = true;
    proto_client.strict_pq = true;
    assert_eq!(
        session::ClientState::try_from(&proto_client)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    // 4. Legacy ClientState (all PQ fields default false/0) restores with PQ ON when compiled.
    let legacy_client = proto::ClientState {
        identity: proto_client.identity.clone(),
        prekeys: proto_client.prekeys.clone(),
        last_timestamp: 100,
        publishing: false,
        pq_disabled: false,
        preferred_pq_suite: 0,
        pq_ratchet_disabled: false,
        strict_pq: false,
        manifest_seq: 0,
        prekey_generation: 0,
        recent_manifest_digests: vec![],
    };
    let restored_client = session::ClientState::try_from(&legacy_client).unwrap();
    assert_eq!(
        restored_client.pq_config().pq_enabled,
        cfg!(any(feature = "ml-kem-1024", feature = "ml-kem-768"))
    );

    // 5. SessionState validations:
    let base_session = proto::SessionState::from(alice_session.state());
    assert!(session::SessionState::try_from(&base_session).is_ok());

    // 5a. Non-canonical key (high bit set) rejected.
    let mut bad_key = base_session.clone();
    bad_key.me[31] |= 0x80;
    assert_eq!(
        session::SessionState::try_from(&bad_key).unwrap_err().kind(),
        ErrorKind::MalformedState
    );

    // 5b. Swapped identity mismatch vs party.associated_data rejected.
    let mut swapped_peer = base_session.clone();
    let carol = Client::new(V1Handshake(Arc::new(HandshakeServer::new(
        SharedStore::default(),
    ))));
    swapped_peer.peer = carol.identity_key().to_vec();
    assert_eq!(
        session::SessionState::try_from(&swapped_peer)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    // 5c. Exceeding KEPT_SESSIONS in `others` rejected.
    let mut too_many_others = base_session.clone();
    for _ in 0..=session::KEPT_SESSIONS {
        too_many_others.others.push(proto::EarlierSession {
            party: base_session.party.clone(),
            delivery_key: base_session.delivery_key.clone(),
        });
    }
    assert_eq!(
        session::SessionState::try_from(&too_many_others)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    // 5d. Invalid PQ suite ID on `active_security` rejected.
    let mut bad_suite = base_session.clone();
    bad_suite.active_security = Some(proto::SessionSecurity {
        is_pq: true,
        suite: 7,
        pq_ratchet: false,
    });
    assert_eq!(
        session::SessionState::try_from(&bad_suite)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    // 5e. Claiming `is_pq: true` on a classical 64-byte AD session rejected.
    let mut mismatched_pq = base_session;
    mismatched_pq.active_security = Some(proto::SessionSecurity {
        is_pq: true,
        suite: 1,
        pq_ratchet: false,
    });
    assert_eq!(
        session::SessionState::try_from(&mismatched_pq)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
mod pq_e2e {
    use super::*;
    use protocol::{
        handshake_v2::{
            AckInitialMessagesRequest, AckInitialMessagesResponse, ClaimBundleRequest,
            ClaimBundleResponse, GetManifestRequest, GetManifestResponse, GetServerInfoRequest,
            GetServerInfoResponse, HandshakeV2Server, ListInitialMessagesRequest,
            ListInitialMessagesResponse, LocalHandshakeV2, PublishV2Request, PublishV2Response,
            RefillPrekeysRequest, RefillPrekeysResponse, SendInitialV2Request,
            SendInitialV2Response, ServerInfoConfig,
        },
        mailbox_v2::{
            FetchSignedRequest, FetchSignedResponse, LocalMailboxV2, MailboxV2Server,
            PushV2Request, PushV2Response,
        },
    };
    use session::{AcceptedInitial, InitialMessageV2};

    const AUDIENCE: &str = "relay.example";

    impl storage::LocalPqHandshakeStore for SharedStore {
        async fn publish_v2(
            &self,
            record: storage::PublishV2Record,
        ) -> storage::Result<storage::PublishV2Status> {
            storage::PqHandshakeStore::publish_v2(&*self.0, record).await
        }

        async fn refill_prekeys(
            &self,
            record: storage::RefillPrekeysRecord,
        ) -> storage::Result<storage::RefillStatus> {
            storage::PqHandshakeStore::refill_prekeys(&*self.0, record).await
        }

        async fn get_manifest(
            &self,
            identity_key: &PublicKey,
        ) -> storage::Result<Option<storage::StoredCapabilityManifest>> {
            storage::PqHandshakeStore::get_manifest(&*self.0, identity_key).await
        }

        async fn claim_bundle(
            &self,
            identity_key: &PublicKey,
            preferred_suites: &[u8],
        ) -> storage::Result<Option<storage::ClaimedPqBundle>> {
            storage::PqHandshakeStore::claim_bundle(&*self.0, identity_key, preferred_suites).await
        }

        async fn add_initial_message_v2(
            &self,
            initial_message: storage::StoredInitialMessageV2,
            limit: usize,
        ) -> storage::Result<Option<u64>> {
            storage::PqHandshakeStore::add_initial_message_v2(&*self.0, initial_message, limit)
                .await
        }

        async fn list_initial_messages(
            &self,
            recipient: &PublicKey,
            limit: usize,
        ) -> storage::Result<Vec<storage::StoredInitialMessageV2>> {
            storage::PqHandshakeStore::list_initial_messages(&*self.0, recipient, limit).await
        }

        async fn ack_initial_messages(
            &self,
            recipient: &PublicKey,
            ids: &[u64],
        ) -> storage::Result<usize> {
            storage::PqHandshakeStore::ack_initial_messages(&*self.0, recipient, ids).await
        }

        async fn pq_snapshot(
            &self,
            identity_key: &PublicKey,
        ) -> storage::Result<storage::PqStorageSnapshot> {
            storage::PqHandshakeStore::pq_snapshot(&*self.0, identity_key).await
        }
    }

    impl storage::LocalIdempotentMailboxStore for SharedStore {
        async fn append_idempotent(
            &self,
            sender: &PublicKey,
            recipient: &PublicKey,
            header: Bytes,
            content: Bytes,
            initial_message: Option<Bytes>,
            delivery_hash: Option<[u8; 32]>,
            client_message_id: Option<[u8; 16]>,
        ) -> storage::Result<u64> {
            storage::IdempotentMailboxStore::append_idempotent(
                &*self.0,
                sender,
                recipient,
                header,
                content,
                initial_message,
                delivery_hash,
                client_message_id,
            )
            .await
        }
    }

    #[derive(Clone)]
    struct DualHandshake {
        v1: Arc<HandshakeServer<SharedStore>>,
        v2: Arc<HandshakeV2Server<SharedStore>>,
    }

    impl DualHandshake {
        fn new(store: SharedStore, audience: &str) -> Self {
            Self {
                v1: Arc::new(HandshakeServer::new(store.clone())),
                v2: Arc::new(HandshakeV2Server::new(store, ServerInfoConfig::new(audience))),
            }
        }
    }

    impl LocalHandshake for DualHandshake {
        async fn publish(&self, request: PublishRequest) -> protocol::Result<PublishResponse> {
            self.v1.publish(request).await
        }
        async fn fetch_bundle(
            &self,
            request: FetchBundleRequest,
        ) -> protocol::Result<FetchBundleResponse> {
            self.v1.fetch_bundle(request).await
        }
        async fn send_initial_message(
            &self,
            request: SendInitialMessageRequest,
        ) -> protocol::Result<SendInitialMessageResponse> {
            self.v1.send_initial_message(request).await
        }
        async fn take_initial_messages(
            &self,
            request: TakeInitialMessagesRequest,
        ) -> protocol::Result<TakeInitialMessagesResponse> {
            self.v1.take_initial_messages(request).await
        }
    }

    impl LocalHandshakeV2 for DualHandshake {
        async fn get_server_info(
            &self,
            request: GetServerInfoRequest,
        ) -> protocol::Result<GetServerInfoResponse> {
            self.v2.get_server_info(request).await
        }
        async fn publish_v2(
            &self,
            request: PublishV2Request,
        ) -> protocol::Result<PublishV2Response> {
            self.v2.publish_v2(request).await
        }
        async fn refill_prekeys(
            &self,
            request: RefillPrekeysRequest,
        ) -> protocol::Result<RefillPrekeysResponse> {
            self.v2.refill_prekeys(request).await
        }
        async fn get_manifest(
            &self,
            request: GetManifestRequest,
        ) -> protocol::Result<GetManifestResponse> {
            self.v2.get_manifest(request).await
        }
        async fn claim_bundle(
            &self,
            request: ClaimBundleRequest,
        ) -> protocol::Result<ClaimBundleResponse> {
            self.v2.claim_bundle(request).await
        }
        async fn send_initial_v2(
            &self,
            request: SendInitialV2Request,
        ) -> protocol::Result<SendInitialV2Response> {
            self.v2.send_initial_v2(request).await
        }
        async fn list_initial_messages(
            &self,
            request: ListInitialMessagesRequest,
        ) -> protocol::Result<ListInitialMessagesResponse> {
            self.v2.list_initial_messages(request).await
        }
        async fn ack_initial_messages(
            &self,
            request: AckInitialMessagesRequest,
        ) -> protocol::Result<AckInitialMessagesResponse> {
            self.v2.ack_initial_messages(request).await
        }
    }

    #[derive(Debug, Clone)]
    struct DualMailbox {
        v1: Arc<MailboxServer<SharedStore>>,
        v2: Arc<MailboxV2Server<SharedStore>>,
    }

    impl DualMailbox {
        fn new(store: SharedStore, audience: &str) -> Self {
            Self::with_limits(store, audience, MailboxLimits::default())
        }

        fn with_limits(store: SharedStore, audience: &str, limits: MailboxLimits) -> Self {
            Self {
                v1: Arc::new(MailboxServer::builder(store.clone()).limits(limits).build()),
                v2: Arc::new(
                    MailboxV2Server::builder(store)
                        .server_id(audience.to_string())
                        .limits(limits)
                        .build(),
                ),
            }
        }
    }

    impl LocalMailbox for DualMailbox {
        async fn push(&self, request: PushRequest) -> protocol::Result<PushResponse> {
            self.v1.push(request).await
        }
        async fn fetch(&self, request: FetchRequest) -> protocol::Result<FetchResponse> {
            self.v1.fetch(request).await
        }
    }

    impl LocalMailboxV2 for DualMailbox {
        async fn push_v2(&self, request: PushV2Request) -> protocol::Result<PushV2Response> {
            self.v2.push_v2(request).await
        }
        async fn fetch_signed(
            &self,
            request: FetchSignedRequest,
        ) -> protocol::Result<FetchSignedResponse> {
            self.v2.fetch_signed(request).await
        }
    }

    /// A malicious server wrapper that tampers with `claim_bundle` responses to simulate active
    /// downgrade attacks.
    #[derive(Clone)]
    struct AttackingHandshake {
        inner: DualHandshake,
        attack: AttackMode,
    }

    #[derive(Clone)]
    enum AttackMode {
        StripPqPrekeys,
        StripManifest,
        ReplayBundle(Box<ClaimBundleResponse>),
        #[cfg(all(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        DowngradeSuiteTo768,
    }

    impl LocalHandshake for AttackingHandshake {
        async fn publish(&self, request: PublishRequest) -> protocol::Result<PublishResponse> {
            self.inner.publish(request).await
        }
        async fn fetch_bundle(
            &self,
            request: FetchBundleRequest,
        ) -> protocol::Result<FetchBundleResponse> {
            self.inner.fetch_bundle(request).await
        }
        async fn send_initial_message(
            &self,
            request: SendInitialMessageRequest,
        ) -> protocol::Result<SendInitialMessageResponse> {
            self.inner.send_initial_message(request).await
        }
        async fn take_initial_messages(
            &self,
            request: TakeInitialMessagesRequest,
        ) -> protocol::Result<TakeInitialMessagesResponse> {
            self.inner.take_initial_messages(request).await
        }
    }

    impl LocalHandshakeV2 for AttackingHandshake {
        async fn get_server_info(
            &self,
            request: GetServerInfoRequest,
        ) -> protocol::Result<GetServerInfoResponse> {
            self.inner.get_server_info(request).await
        }
        async fn publish_v2(
            &self,
            request: PublishV2Request,
        ) -> protocol::Result<PublishV2Response> {
            self.inner.publish_v2(request).await
        }
        async fn refill_prekeys(
            &self,
            request: RefillPrekeysRequest,
        ) -> protocol::Result<RefillPrekeysResponse> {
            self.inner.refill_prekeys(request).await
        }
        async fn get_manifest(
            &self,
            request: GetManifestRequest,
        ) -> protocol::Result<GetManifestResponse> {
            self.inner.get_manifest(request).await
        }
        async fn claim_bundle(
            &self,
            request: ClaimBundleRequest,
        ) -> protocol::Result<ClaimBundleResponse> {
            match &self.attack {
                AttackMode::StripPqPrekeys => {
                    let mut resp = self.inner.claim_bundle(request).await?;
                    resp.pq_last_resort = None;
                    resp.pq_one_time_prekey = None;
                    Ok(resp)
                }
                AttackMode::StripManifest => {
                    let mut resp = self.inner.claim_bundle(request).await?;
                    resp.manifest = None;
                    resp.pq_last_resort = None;
                    resp.pq_one_time_prekey = None;
                    Ok(resp)
                }
                AttackMode::ReplayBundle(captured) => Ok((**captured).clone()),
                #[cfg(all(feature = "ml-kem-1024", feature = "ml-kem-768"))]
                AttackMode::DowngradeSuiteTo768 => {
                    let mut request = request;
                    request.preferred_suites = vec![u32::from(PqSuite::MlKem768.as_u8())];
                    self.inner.claim_bundle(request).await
                }
            }
        }
        async fn send_initial_v2(
            &self,
            request: SendInitialV2Request,
        ) -> protocol::Result<SendInitialV2Response> {
            self.inner.send_initial_v2(request).await
        }
        async fn list_initial_messages(
            &self,
            request: ListInitialMessagesRequest,
        ) -> protocol::Result<ListInitialMessagesResponse> {
            self.inner.list_initial_messages(request).await
        }
        async fn ack_initial_messages(
            &self,
            request: AckInitialMessagesRequest,
        ) -> protocol::Result<AckInitialMessagesResponse> {
            self.inner.ack_initial_messages(request).await
        }
    }

    /// A legacy v1-only server returning `Unimplemented` for all v2 procedures.
    #[derive(Debug, Clone)]
    struct V1OnlyServer {
        hs: V1Handshake,
        mb: V1Mailbox,
    }

    impl LocalHandshake for V1OnlyServer {
        async fn publish(&self, r: PublishRequest) -> protocol::Result<PublishResponse> {
            self.hs.publish(r).await
        }
        async fn fetch_bundle(
            &self,
            r: FetchBundleRequest,
        ) -> protocol::Result<FetchBundleResponse> {
            self.hs.fetch_bundle(r).await
        }
        async fn send_initial_message(
            &self,
            r: SendInitialMessageRequest,
        ) -> protocol::Result<SendInitialMessageResponse> {
            self.hs.send_initial_message(r).await
        }
        async fn take_initial_messages(
            &self,
            r: TakeInitialMessagesRequest,
        ) -> protocol::Result<TakeInitialMessagesResponse> {
            self.hs.take_initial_messages(r).await
        }
    }

    impl LocalHandshakeV2 for V1OnlyServer {
        async fn get_server_info(
            &self,
            _: GetServerInfoRequest,
        ) -> protocol::Result<GetServerInfoResponse> {
            Err(protocol::ErrorKind::Unimplemented.into())
        }
        async fn publish_v2(&self, _: PublishV2Request) -> protocol::Result<PublishV2Response> {
            Err(protocol::ErrorKind::Unimplemented.into())
        }
        async fn refill_prekeys(
            &self,
            _: RefillPrekeysRequest,
        ) -> protocol::Result<RefillPrekeysResponse> {
            Err(protocol::ErrorKind::Unimplemented.into())
        }
        async fn get_manifest(
            &self,
            _: GetManifestRequest,
        ) -> protocol::Result<GetManifestResponse> {
            Err(protocol::ErrorKind::Unimplemented.into())
        }
        async fn claim_bundle(
            &self,
            _: ClaimBundleRequest,
        ) -> protocol::Result<ClaimBundleResponse> {
            Err(protocol::ErrorKind::Unimplemented.into())
        }
        async fn send_initial_v2(
            &self,
            _: SendInitialV2Request,
        ) -> protocol::Result<SendInitialV2Response> {
            Err(protocol::ErrorKind::Unimplemented.into())
        }
        async fn list_initial_messages(
            &self,
            _: ListInitialMessagesRequest,
        ) -> protocol::Result<ListInitialMessagesResponse> {
            Err(protocol::ErrorKind::Unimplemented.into())
        }
        async fn ack_initial_messages(
            &self,
            _: AckInitialMessagesRequest,
        ) -> protocol::Result<AckInitialMessagesResponse> {
            Err(protocol::ErrorKind::Unimplemented.into())
        }
    }

    impl LocalMailbox for V1OnlyServer {
        async fn push(&self, r: PushRequest) -> protocol::Result<PushResponse> {
            self.mb.push(r).await
        }
        async fn fetch(&self, r: FetchRequest) -> protocol::Result<FetchResponse> {
            self.mb.fetch(r).await
        }
    }

    impl LocalMailboxV2 for V1OnlyServer {
        async fn push_v2(&self, _: PushV2Request) -> protocol::Result<PushV2Response> {
            Err(protocol::ErrorKind::Unimplemented.into())
        }
        async fn fetch_signed(
            &self,
            _: FetchSignedRequest,
        ) -> protocol::Result<FetchSignedResponse> {
            Err(protocol::ErrorKind::Unimplemented.into())
        }
    }

    #[cfg(feature = "ml-kem-1024")]
    #[tokio::test]
    async fn pqxdh_and_pq_ratchet_ml_kem_1024_end_to_end() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store, AUDIENCE);

        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs);
        assert!(alice.pq_config().pq_enabled);
        assert_eq!(alice.pq_config().preferred_suite, PqSuite::MlKem1024);
        assert!(alice.pq_config().pq_ratchet_enabled);
        assert!(!alice.pq_config().strict_pq);

        // Verify expected audience check succeeds on matching server and blocks mismatch.
        let info = alice.check_server_info(AUDIENCE).await.unwrap();
        assert!(info.pq_enabled);
        assert_eq!(
            alice.check_server_info("wrong.example").await.unwrap_err().kind(),
            ErrorKind::DowngradeDetected
        );

        // Bob publishes v2 + refills without rotating SPK.
        bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        let spk1 = bob.current_signed_prekey().unwrap();
        let refill = bob.refill_prekeys_v2(AUDIENCE, 3, 2).await.unwrap();
        assert_eq!(bob.current_signed_prekey().unwrap(), spk1);
        assert_eq!(refill.classical_one_time_count, 5);

        // Alice initiates PQXDH + PQ ratchet with ML-KEM-1024.
        let hello = alice.make_hello("alice", 1);
        let mut alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                &ContentKind::Hello(hello).to_bytes(),
                mb.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            alice_session.security(),
            Some(SessionSecurity::pq(PqSuite::MlKem1024, true))
        );
        assert!(alice_session.peer_pq_state().pq_pinned);
        assert_eq!(alice_session.peer_pq_state().pinned_manifest_seq, 1);

        // Bob runs two-phase list -> accept -> ack.
        let listed = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
        assert_eq!(listed.messages.len(), 1);
        assert!(listed.messages[0].is_pq());
        assert_eq!(listed.messages[0].pq_suite(), Some(PqSuite::MlKem1024));
        assert!(listed.messages[0].uses_pq_one_time_prekey());

        let AcceptedInitial::Accepted {
            mut session,
            first_message,
            security,
        } = bob
            .accept_initial_v2(
                &alice.identity_key(),
                &PeerPqState::default(),
                &listed.messages[0],
                mb.clone(),
            )
            .unwrap()
        else {
            panic!("expected accepted PQ initial message");
        };
        assert_eq!(security, SessionSecurity::pq(PqSuite::MlKem1024, true));
        assert_eq!(session.peer_session_seq(), 1);
        let Some(ContentKind::Hello(h1)) = ContentKind::from_bytes(&first_message) else {
            panic!("expected Hello");
        };
        let hello_check = session.check_peer_hello(&h1, true);
        assert!(!hello_check.stale_session_seq);
        assert!(!hello_check.downgrade_detected);
        assert_eq!(
            bob.ack_initial_messages_v2(AUDIENCE, vec![listed.messages[0].id])
                .await
                .unwrap(),
            1
        );

        // Multiple turns exercising PQ KEM ratcheting + idempotent PushV2 + FetchSigned!
        let sealed = alice_session.encrypt(b"turn-1").unwrap();
        let seq1 = alice_session.push_v2(sealed.clone()).await.unwrap();
        let seq1_retry = alice_session.push_v2(sealed).await.unwrap();
        assert_eq!(seq1, seq1_retry, "PushV2 client_message_id must deduplicate retries");

        let rx = session.receive_v2(&bob, AUDIENCE).await.unwrap();
        assert_eq!(rx.len(), 1);
        assert_eq!(rx[0].content.as_deref().unwrap(), b"turn-1");

        for turn in 0..8 {
            let b_msg = format!("bob-{turn}");
            session.send_v2(b_msg.as_bytes()).await.unwrap();
            let got = alice_session.receive_v2(&alice, AUDIENCE).await.unwrap();
            assert_eq!(got[0].content.as_deref().unwrap(), b_msg.as_bytes());

            let a_msg = format!("alice-{turn}");
            alice_session.send_v2(a_msg.as_bytes()).await.unwrap();
            let got = session.receive_v2(&bob, AUDIENCE).await.unwrap();
            assert_eq!(got[0].content.as_deref().unwrap(), a_msg.as_bytes());
        }

        // Persist and restore both states via prost (when enabled) and verify PQ session survives!
        #[cfg(feature = "prost")]
        {
            let p_alice = session::proto::SessionState::from(alice_session.state());
            let mut restored_alice = Session::restore(
                mb.clone(),
                session::SessionState::try_from(&p_alice).unwrap(),
            );
            assert_eq!(
                restored_alice.security(),
                Some(SessionSecurity::pq(PqSuite::MlKem1024, true))
            );
            restored_alice.send_v2(b"after-restore").await.unwrap();
            let got = session.receive_v2(&bob, AUDIENCE).await.unwrap();
            assert_eq!(got[0].content.as_deref().unwrap(), b"after-restore");
        }
    }

    #[cfg(feature = "ml-kem-768")]
    #[tokio::test]
    async fn pqxdh_and_pq_ratchet_ml_kem_768_and_suite_selection() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store, AUDIENCE);

        let mut alice = Client::new(hs.clone())
            .with_pq_config(PqConfig {
                pq_enabled: true,
                preferred_suite: PqSuite::MlKem768,
                pq_ratchet_enabled: true,
                strict_pq: false,
            })
            .unwrap();
        let mut bob = Client::new(hs);
        bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();

        let mut alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"hi-768",
                mb.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            alice_session.security(),
            Some(SessionSecurity::pq(PqSuite::MlKem768, true))
        );

        let mut outcomes = bob
            .list_and_accept_v2(AUDIENCE, 10, mb.clone(), |_| PeerPqState::default())
            .await
            .unwrap();
        assert_eq!(outcomes.len(), 1);
        let (_, AcceptedInitial::Accepted { mut session, first_message, security }) =
            outcomes.pop().unwrap()
        else {
            panic!("expected accepted ML-KEM-768 session");
        };
        assert_eq!(first_message, b"hi-768");
        assert_eq!(security, SessionSecurity::pq(PqSuite::MlKem768, true));

        session.send_v2(b"reply-768").await.unwrap();
        let got = alice_session.receive_v2(&alice, AUDIENCE).await.unwrap();
        assert_eq!(got[0].content.as_deref().unwrap(), b"reply-768");
    }

    #[tokio::test]
    async fn pq_ratchet_can_be_toggled_off_independently() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store, AUDIENCE);

        let mut alice = Client::new(hs.clone())
            .with_pq_config(PqConfig {
                pq_enabled: true,
                preferred_suite: PqConfig::default_suite(),
                pq_ratchet_enabled: false,
                strict_pq: false,
            })
            .unwrap();
        let mut bob = Client::new(hs);
        bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();

        let mut alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"pq-no-ratchet",
                mb.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            alice_session.security(),
            Some(SessionSecurity::pq(PqConfig::default_suite(), false))
        );

        let mut outcomes = bob
            .list_and_accept_v2(AUDIENCE, 10, mb, |_| PeerPqState::default())
            .await
            .unwrap();
        let (_, AcceptedInitial::Accepted { mut session, first_message, security }) =
            outcomes.pop().unwrap()
        else {
            panic!("expected accepted PQXDH session with classical ratchet");
        };
        assert_eq!(first_message, b"pq-no-ratchet");
        assert_eq!(
            security,
            SessionSecurity::pq(PqConfig::default_suite(), false)
        );

        session.send_v2(b"classical-ratchet-over-pqxdh").await.unwrap();
        let got = alice_session.receive_v2(&alice, AUDIENCE).await.unwrap();
        assert_eq!(
            got[0].content.as_deref().unwrap(),
            b"classical-ratchet-over-pqxdh"
        );
    }

    #[tokio::test]
    async fn mixed_mode_requires_explicit_approval_and_quarantines_inbound_classical() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store, AUDIENCE);

        // Legacy v1 TUI user (no manifest, published via v1).
        let mut tui = Client::new(hs.clone());
        tui.publish_keys(3).await.unwrap();

        // Modern PQ-enabled user.
        let mut alice = Client::new(hs.clone());
        alice.publish_v2(AUDIENCE, 3, 2).await.unwrap();

        // 1. Alice (PQ ON) tries to initiate with legacy TUI peer without exception -> prompts!
        let mut peer_state = PeerPqState::default();
        let err = alice
            .initiate_v2(AUDIENCE, &tui.identity_key(), &peer_state, b"hi", mb.clone())
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::ClassicalApprovalRequired {
                peer_signed_off: false
            }
        );

        // 2. Once user explicitly approves classical exception, classical session succeeds and
        //    legacy TUI peer can take_initial_messages & talk!
        peer_state.approve_classical_exception();
        let mut alice_session = alice
            .initiate_v2(AUDIENCE, &tui.identity_key(), &peer_state, b"hi-tui", mb.clone())
            .await
            .unwrap();
        assert_eq!(alice_session.security(), Some(SessionSecurity::classical()));

        let tui_inbox = tui.take_initial_messages().await.unwrap();
        assert_eq!(tui_inbox.len(), 1);
        let (mut tui_session, first) = tui
            .accept(&alice.identity_key(), &tui_inbox[0], mb.clone())
            .unwrap();
        assert_eq!(first, b"hi-tui");
        tui_session.send(b"from-tui").await.unwrap();
        let got = alice_session.receive_v2(&alice, AUDIENCE).await.unwrap();
        assert_eq!(got[0].content.as_deref().unwrap(), b"from-tui");

        // 3. Inbound classical initial message from a NEW classical peer while Alice has PQ ON
        //    is QUARANTINED (never silently accepted)!
        let mut bob_v1 = Client::new(hs.clone());
        let _bob_sess = bob_v1
            .initiate(&alice.identity_key(), b"classical-hello", mb.clone())
            .await
            .unwrap();

        let listed = alice.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
        assert_eq!(listed.messages.len(), 1);
        assert!(!listed.messages[0].is_pq());

        let outcome = alice
            .accept_initial_v2(
                &bob_v1.identity_key(),
                &PeerPqState::default(),
                &listed.messages[0],
                mb.clone(),
            )
            .unwrap();
        match outcome {
            AcceptedInitial::Quarantined {
                first_message,
                peer_was_pq_pinned,
                ..
            } => {
                assert_eq!(first_message, b"classical-hello");
                assert!(!peer_was_pq_pinned);
            }
            AcceptedInitial::Accepted { .. } => panic!("expected quarantined classical initial"),
        }

        // 4. In strict_pq mode, inbound classical initial message is HARD REJECTED (`PqRequired`)!
        let mut strict_alice = Client::new(hs)
            .with_pq_config(PqConfig {
                pq_enabled: true,
                preferred_suite: PqConfig::default_suite(),
                pq_ratchet_enabled: true,
                strict_pq: true,
            })
            .unwrap();
        strict_alice.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        // Legacy v1 fetch_bundle fails NotFound for strict_pq identity!
        assert_eq!(
            bob_v1
                .initiate(&strict_alice.identity_key(), b"nope", mb.clone())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::NotFound
        );
        // And strict_alice trying to initiate with classical TUI fails PqRequired!
        assert_eq!(
            strict_alice
                .initiate_v2(
                    AUDIENCE,
                    &tui.identity_key(),
                    &PeerPqState {
                        allow_classical_exception: true,
                        ..PeerPqState::default()
                    },
                    b"nope",
                    mb,
                )
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::PqRequired
        );
    }

    #[tokio::test]
    async fn toggle_pq_on_to_off_preserves_in_flight_pq_then_back_on() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store, AUDIENCE);

        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs.clone());
        let mut carol = Client::new(hs);

        // 1. Bob publishes with PQ ON.
        bob.publish_v2(AUDIENCE, 4, 3).await.unwrap();
        let seq_on = bob.manifest_seq();
        assert_eq!(seq_on, 1);

        // 2. Alice initiates a PQ session while Bob's PQ is ON (in-flight!).
        let mut alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"in-flight-pq",
                mb.clone(),
            )
            .await
            .unwrap();
        assert!(alice_session.security().unwrap().is_pq);

        // 3. BEFORE Bob accepts Alice's in-flight PQ message, Bob toggles PQ OFF and publishes
        //    signed OFF manifest (manifest_seq = 2).
        bob.set_pq_config(PqConfig {
            pq_enabled: false,
            preferred_suite: PqConfig::default_suite(),
            pq_ratchet_enabled: false,
            strict_pq: false,
        })
        .unwrap();
        bob.publish_v2(AUDIENCE, 4, 0).await.unwrap();
        assert_eq!(bob.manifest_seq(), 2);

        // Server manifest now shows pq_enabled == false.
        let m = carol
            .get_peer_manifest(AUDIENCE, &bob.identity_key())
            .await
            .unwrap()
            .unwrap();
        assert!(!m.pq_enabled);
        assert_eq!(m.manifest_seq, 2);

        // 4. Bob STILL decrypts Alice's in-flight PQ handshake!
        let mut outcomes = bob
            .list_and_accept_v2(AUDIENCE, 10, mb.clone(), |_| PeerPqState::default())
            .await
            .unwrap();
        assert_eq!(outcomes.len(), 1);
        let (_, AcceptedInitial::Accepted { mut session, first_message, security }) =
            outcomes.pop().unwrap()
        else {
            panic!("in-flight PQ handshake must still be accepted after toggling PQ OFF");
        };
        assert_eq!(first_message, b"in-flight-pq");
        assert!(security.is_pq);
        session.send_v2(b"in-flight-reply").await.unwrap();
        let rx = alice_session.receive_v2(&alice, AUDIENCE).await.unwrap();
        assert_eq!(rx[0].content.as_deref().unwrap(), b"in-flight-reply");

        // 5. Meanwhile Carol (PQ ON, even if previously pinned at seq 1!) sees Bob's newer signed
        //    OFF manifest (seq 2 > 1) -> gets ClassicalApprovalRequired { peer_signed_off: true }!
        let mut carol_peer_state = PeerPqState {
            pq_pinned: true,
            pinned_manifest_seq: 1,
            peer_pq_capable: true,
            ..PeerPqState::default()
        };
        let err = carol
            .initiate_v2(AUDIENCE, &bob.identity_key(), &carol_peer_state, b"hi", mb.clone())
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::ClassicalApprovalRequired {
                peer_signed_off: true
            }
        );
        carol_peer_state.approve_classical_exception();
        let carol_classical = carol
            .initiate_v2(AUDIENCE, &bob.identity_key(), &carol_peer_state, b"ok-classical", mb.clone())
            .await
            .unwrap();
        assert_eq!(carol_classical.security(), Some(SessionSecurity::classical()));

        // 6. Bob toggles PQ BACK ON and re-publishes PQ prekeys (manifest_seq = 3)!
        bob.set_pq_config(PqConfig {
            pq_enabled: true,
            preferred_suite: PqConfig::default_suite(),
            pq_ratchet_enabled: true,
            strict_pq: false,
        })
        .unwrap();
        bob.publish_v2(AUDIENCE, 4, 3).await.unwrap();
        assert_eq!(bob.manifest_seq(), 3);

        // Carol starts a fresh PQ session with Bob!
        let carol_pq = carol
            .initiate_v2(AUDIENCE, &bob.identity_key(), &carol_peer_state, b"back-to-pq", mb)
            .await
            .unwrap();
        assert!(carol_pq.security().unwrap().is_pq);
        assert_eq!(carol_pq.peer_pq_state().pinned_manifest_seq, 3);
    }

    #[tokio::test]
    async fn active_server_downgrade_attacks_are_hard_blocked() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store, AUDIENCE);

        let mut bob = Client::new(hs.clone());
        bob.publish_v2(AUDIENCE, 5, 5).await.unwrap();
        // Capture bundle at manifest_seq = 1 before Bob rotates to manifest_seq = 2.
        let captured_seq1 = hs
            .claim_bundle(ClaimBundleRequest {
                identity_key: Bytes::copy_from_slice(&bob.identity_key()),
                preferred_suites: vec![u32::from(PqConfig::default_suite().as_u8())],
            })
            .await
            .unwrap();
        bob.publish_v2(AUDIENCE, 5, 5).await.unwrap();
        assert_eq!(bob.manifest_seq(), 2);

        let mut pinned = PeerPqState::default();
        pinned.pin_peer_pq();
        pinned.pinned_manifest_seq = 2;

        // Attack 1: Server strips PQ prekeys while returning valid PQ-enabled manifest -> HARD BLOCK.
        let mut alice_strip_pq = Client::new(AttackingHandshake {
            inner: hs.clone(),
            attack: AttackMode::StripPqPrekeys,
        });
        assert_eq!(
            alice_strip_pq
                .initiate_v2(AUDIENCE, &bob.identity_key(), &pinned, b"hi", mb.clone())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::DowngradeDetected
        );

        // Attack 2: Server strips manifest completely for a PQ-pinned peer -> HARD BLOCK.
        let mut alice_strip_manifest = Client::new(AttackingHandshake {
            inner: hs.clone(),
            attack: AttackMode::StripManifest,
        });
        assert_eq!(
            alice_strip_manifest
                .initiate_v2(AUDIENCE, &bob.identity_key(), &pinned, b"hi", mb.clone())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::DowngradeDetected
        );

        // Attack 3: Server replays older manifest_seq (1 < pinned 2) -> HARD BLOCK.
        let mut alice_replay = Client::new(AttackingHandshake {
            inner: hs.clone(),
            attack: AttackMode::ReplayBundle(Box::new(captured_seq1)),
        });
        assert_eq!(
            alice_replay
                .initiate_v2(AUDIENCE, &bob.identity_key(), &pinned, b"hi", mb.clone())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::DowngradeDetected
        );

        // Attack 4: Wrong expected server audience -> HARD BLOCK.
        let mut alice_wrong_aud = Client::new(hs.clone());
        assert_eq!(
            alice_wrong_aud
                .initiate_v2("attacker.example", &bob.identity_key(), &PeerPqState::default(), b"hi", mb.clone())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::DowngradeDetected
        );

        // Attack 5 (when both suites compiled): Server downgrades preferred ML-KEM-1024 to ML-KEM-768 -> HARD BLOCK.
        #[cfg(all(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        {
            let mut alice_suite_downgrade = Client::new(AttackingHandshake {
                inner: hs,
                attack: AttackMode::DowngradeSuiteTo768,
            });
            assert_eq!(
                alice_suite_downgrade
                    .initiate_v2(AUDIENCE, &bob.identity_key(), &PeerPqState::default(), b"hi", mb)
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::DowngradeDetected
            );
        }

        // Attack 6: In-band `Hello.pq_capable == true` received over a classical session while
        // local PQ is ON -> `downgrade_detected = true` and `recommend_start_again = true`!
        let mut state = PeerPqState::default();
        let peer_hello = Hello {
            name: "bob".into(),
            pq_capable: true,
            max_version: 2,
            session_seq: 1,
            offered_suites: vec![1, 2],
            pq_ratchet_capable: true,
        };
        let check = check_peer_hello(&mut state, SessionSecurity::classical(), &peer_hello, true);
        assert!(check.downgrade_detected);
        assert!(check.recommend_start_again);
        assert!(!check.stale_session_seq);
        assert!(state.downgrade_detected);
        assert!(state.pq_pinned);
        assert_eq!(state.peer_session_seq, 1);

        // Stale Hello.session_seq (<= 1 or 0 after 1) is flagged by check_peer_hello too!
        let stale_check = check_peer_hello(
            &mut state,
            SessionSecurity::pq(PqConfig::default_suite(), true),
            &Hello::classical("bob"),
            true,
        );
        assert!(stale_check.stale_session_seq);
        assert_eq!(state.peer_session_seq, 1);
    }

    #[tokio::test]
    async fn two_phase_list_crash_retry_then_ack() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store, AUDIENCE);

        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs);
        bob.publish_v2(AUDIENCE, 3, 3).await.unwrap();

        let _alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"survives-crash",
                mb.clone(),
            )
            .await
            .unwrap();

        // Phase 1: Bob lists, then CRASHES before accepting/persisting/acking!
        let first_list = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
        assert_eq!(first_list.messages.len(), 1);
        let msg_id = first_list.messages[0].id;
        assert!(msg_id > 0);

        // Retry after crash: message is STILL on the server!
        let retry_list = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
        assert_eq!(retry_list.messages.len(), 1);
        assert_eq!(retry_list.messages[0].id, msg_id);

        // Accept + persist + ack.
        let AcceptedInitial::Accepted { first_message, .. } = bob
            .accept_initial_v2(
                &alice.identity_key(),
                &PeerPqState::default(),
                &retry_list.messages[0],
                mb,
            )
            .unwrap()
        else {
            panic!("expected accepted");
        };
        assert_eq!(first_message, b"survives-crash");
        assert_eq!(
            bob.ack_initial_messages_v2(AUDIENCE, vec![msg_id])
                .await
                .unwrap(),
            1
        );

        // Now inbox is empty.
        assert!(
            bob.list_initial_messages_v2(AUDIENCE, 10)
                .await
                .unwrap()
                .messages
                .is_empty()
        );
    }

    #[tokio::test]
    async fn v2_trailing_carried_pq_initial_across_expired_page_and_v1_fallback() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb_inner = DualMailbox::with_limits(
            store,
            AUDIENCE,
            MailboxLimits {
                max_fetch: 1,
                ..MailboxLimits::default()
            },
        );

        /// Expiring wrapper for `DualMailbox` expiring specific sequence numbers.
        #[derive(Clone)]
        struct ExpiringDualMailbox {
            inner: DualMailbox,
            expire_seq: u64,
            fetches: Arc<AtomicUsize>,
        }
        impl LocalMailbox for ExpiringDualMailbox {
            async fn push(&self, r: PushRequest) -> protocol::Result<PushResponse> {
                self.inner.push(r).await
            }
            async fn fetch(&self, r: FetchRequest) -> protocol::Result<FetchResponse> {
                self.inner.fetch(r).await
            }
        }
        impl LocalMailboxV2 for ExpiringDualMailbox {
            async fn push_v2(&self, r: PushV2Request) -> protocol::Result<PushV2Response> {
                self.inner.push_v2(r).await
            }
            async fn fetch_signed(
                &self,
                r: FetchSignedRequest,
            ) -> protocol::Result<FetchSignedResponse> {
                self.fetches.fetch_add(1, Ordering::Relaxed);
                let mut resp = self.inner.fetch_signed(r).await?;
                for env in &mut resp.messages {
                    if env.sequence == self.expire_seq {
                        env.message = None;
                    }
                }
                Ok(resp)
            }
        }

        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs);
        bob.publish_v2(AUDIENCE, 5, 5).await.unwrap();

        let mut alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"s1",
                mb_inner.clone(),
            )
            .await
            .unwrap();
        let mut outcomes = bob
            .list_and_accept_v2(
                AUDIENCE,
                10,
                ExpiringDualMailbox {
                    inner: mb_inner.clone(),
                    expire_seq: 1,
                    fetches: Arc::new(AtomicUsize::new(0)),
                },
                |_| PeerPqState::default(),
            )
            .await
            .unwrap();
        let (_, AcceptedInitial::Accepted { session: mut bob_session, .. }) =
            outcomes.pop().unwrap()
        else {
            panic!("expected accepted");
        };
        bob_session.send_v2(b"ready").await.unwrap();
        assert_eq!(
            alice_session.receive_v2(&alice, AUDIENCE).await.unwrap()[0]
                .content
                .as_deref()
                .unwrap(),
            b"ready"
        );

        // Alice starts a brand-new PQ session (seq 2), Bob drops/loses inbox, Alice pushes msg 1
        // (which expires on server while carrying PQ initial!) and msg 2.
        alice
            .start_again_v2(AUDIENCE, &mut alice_session, b"pq-carried-hello")
            .await
            .unwrap();
        let dropped = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
        bob.ack_initial_messages_v2(AUDIENCE, vec![dropped.messages[0].id])
            .await
            .unwrap();

        alice_session.send_v2(b"expired-msg").await.unwrap();
        alice_session.send_v2(b"after-expired").await.unwrap();

        // Bob fetches page 1 (expired seq 1 carrying PQ initial) -> loops to page 2 (seq 2
        // encrypted on new PQ session -> Stalled!) -> Stalled MUST carry the v2 PQ initial!
        let rx = bob_session.receive_v2(&bob, AUDIENCE).await.unwrap();
        assert_eq!(rx.len(), 1);
        assert_eq!(
            rx[0].content.as_ref().unwrap_err().kind(),
            ErrorKind::Stalled
        );
        assert_eq!(rx[0].initial_messages.len(), 1);
        assert!(rx[0].initial_messages[0].is_pq());

        let AcceptedInitial::Accepted {
            session: new_bob,
            first_message,
            security,
        } = bob
            .accept_initial_v2(
                &alice.identity_key(),
                bob_session.peer_pq_state(),
                &rx[0].initial_messages[0],
                ExpiringDualMailbox {
                    inner: mb_inner.clone(),
                    expire_seq: 999,
                    fetches: Arc::new(AtomicUsize::new(0)),
                },
            )
            .unwrap()
        else {
            panic!("expected accepted carried PQ initial");
        };
        assert_eq!(first_message, b"pq-carried-hello");
        assert!(security.is_pq);
        assert!(bob_session.accept_replacement(new_bob).unwrap());
        bob_session.skip_stalled();
        let rx2 = bob_session.receive_v2(&bob, AUDIENCE).await.unwrap();
        assert_eq!(rx2[0].content.as_deref().unwrap(), b"after-expired");

        // Also test graceful v1 fallback on a v1-only server when !strict_pq!
        let v1_store = SharedStore::default();
        let v1_srv = V1OnlyServer {
            hs: V1Handshake(Arc::new(HandshakeServer::new(v1_store.clone()))),
            mb: V1Mailbox(Arc::new(MailboxServer::new(v1_store))),
        };
        let mut a1 = Client::new(v1_srv.clone());
        let mut b1 = Client::new(v1_srv.clone());
        b1.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        let mut ps = PeerPqState::default();
        assert_eq!(
            a1.initiate_v2(AUDIENCE, &b1.identity_key(), &ps, b"v1", v1_srv.clone())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::ClassicalApprovalRequired {
                peer_signed_off: false
            }
        );
        ps.approve_classical_exception();
        let mut a1_sess = a1
            .initiate_v2(AUDIENCE, &b1.identity_key(), &ps, b"v1-ok", v1_srv.clone())
            .await
            .unwrap();
        a1_sess.send_v2(b"hello-v1").await.unwrap();
        let listed = b1.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
        assert!(listed.fell_back_to_v1);
        assert_eq!(listed.messages.len(), 1);
        // Approve classical on Bob too or check decode_carried works:
        let _ = InitialMessageV2::decode_carried(&[]);
    }

    #[tokio::test]
    async fn pq_crossed_starts_and_pinned_classical_keep_defense() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store, AUDIENCE);

        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs);
        alice.publish_v2(AUDIENCE, 5, 5).await.unwrap();
        bob.publish_v2(AUDIENCE, 5, 5).await.unwrap();

        // Both start PQXDH sessions with session_seq = 1 simultaneously!
        let mut alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                &hello_bytes("alice", 1, true),
                mb.clone(),
            )
            .await
            .unwrap();
        let mut bob_session = bob
            .initiate_v2(
                AUDIENCE,
                &alice.identity_key(),
                &PeerPqState::default(),
                &hello_bytes("bob", 1, true),
                mb.clone(),
            )
            .await
            .unwrap();

        let mut a_in = alice
            .list_and_accept_v2(AUDIENCE, 10, mb.clone(), |_| {
                alice_session.peer_pq_state().clone()
            })
            .await
            .unwrap();
        let mut b_in = bob
            .list_and_accept_v2(AUDIENCE, 10, mb.clone(), |_| {
                bob_session.peer_pq_state().clone()
            })
            .await
            .unwrap();
        let (_, AcceptedInitial::Accepted { session: a_acc, .. }) = a_in.pop().unwrap() else {
            panic!("expected accepted");
        };
        let (_, AcceptedInitial::Accepted { session: b_acc, .. }) = b_in.pop().unwrap() else {
            panic!("expected accepted");
        };

        let _ = alice_session.accept_replacement(a_acc).unwrap();
        let _ = bob_session.accept_replacement(b_acc).unwrap();

        // Both sides converge onto the exact same winning PQ session!
        assert_eq!(alice_session.active_id(), bob_session.active_id());
        assert_eq!(alice_session.peer_session_seq(), 1);
        assert_eq!(bob_session.peer_session_seq(), 1);
        assert!(alice_session.security().unwrap().is_pq);
        assert!(bob_session.security().unwrap().is_pq);

        alice_session.send_v2(b"converged-a").await.unwrap();
        bob_session.send_v2(b"converged-b").await.unwrap();
        assert_eq!(
            bob_session.receive_v2(&bob, AUDIENCE).await.unwrap()[0]
                .content
                .as_deref()
                .unwrap(),
            b"converged-a"
        );
        assert_eq!(
            alice_session.receive_v2(&alice, AUDIENCE).await.unwrap()[0]
                .content
                .as_deref()
                .unwrap(),
            b"converged-b"
        );

        // Defense-in-depth: an unapproved classical peer session cannot overwrite a PQ-pinned
        // session in `Session::keep` / `accept_replacement`.
        let _bob_classical = bob
            .initiate(
                &alice.identity_key(),
                &hello_bytes("bob", 2, false),
                mb.clone(),
            )
            .await
            .unwrap();
        let listed = alice.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
        let AcceptedInitial::Quarantined {
            session: quarantined,
            peer_was_pq_pinned,
            ..
        } = alice
            .accept_initial_v2(
                &bob.identity_key(),
                alice_session.peer_pq_state(),
                &listed.messages[0],
                mb,
            )
            .unwrap()
        else {
            panic!("expected quarantined classical initial for PQ-pinned peer");
        };
        assert!(peer_was_pq_pinned);
        let active_before = *alice_session.active_id().unwrap();
        // Trying to merge without approving classical exception fails closed with DowngradeDetected!
        assert_eq!(
            alice_session
                .accept_replacement(quarantined)
                .unwrap_err()
                .kind(),
            ErrorKind::DowngradeDetected
        );
        assert_eq!(alice_session.active_id(), Some(&active_before));
    }

    #[cfg(feature = "rkyv")]
    #[tokio::test]
    async fn rkyv_roundtrip_preserves_pq_client_and_session_state() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store, AUDIENCE);

        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs);
        bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        let alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"rkyv",
                mb,
            )
            .await
            .unwrap();

        let client_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(bob.state()).unwrap();
        let client_restored: session::ClientState =
            rkyv::from_bytes::<session::ClientState, rkyv::rancor::Error>(&client_bytes).unwrap();
        assert_eq!(client_restored.pq_config(), bob.pq_config());

        let sess_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(alice_session.state()).unwrap();
        let sess_restored: session::SessionState =
            rkyv::from_bytes::<session::SessionState, rkyv::rancor::Error>(&sess_bytes).unwrap();
        assert_eq!(sess_restored.security(), alice_session.security());
        assert_eq!(sess_restored.peer_pq_state(), alice_session.peer_pq_state());
    }

    #[tokio::test]
    async fn permanent_inbox_errors_like_low_order_sender_are_acked_and_cleared() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store, AUDIENCE);

        let mut bob = Client::new(hs.clone());
        bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        let bob_spk = bob.current_signed_prekey().unwrap();

        // Canonical non-zero low-order Curve25519 point (u = 1): passes server's
        // `check_canonical_key`, fails `XEdDSAPublicKey::new` (`InvalidKeys`) locally on Bob!
        let mut low_order_sender = [0u8; 32];
        low_order_sender[0] = 1;
        let mut valid_ephemeral = [0u8; 32];
        valid_ephemeral[0] = 9;
        hs.send_initial_v2(SendInitialV2Request {
            recipient: Bytes::copy_from_slice(&bob.identity_key()),
            message: Some(protocol::handshake_v2::InitialMessageV2 {
                id: 0,
                version: 1,
                identity_key: Bytes::copy_from_slice(&low_order_sender),
                ephemeral_key: Bytes::copy_from_slice(&valid_ephemeral),
                signed_prekey: Bytes::copy_from_slice(&bob_spk),
                one_time_prekey: None,
                first_message: Some(party::EncryptedMessage {
                    header: Bytes::from_static(b"hdr"),
                    content: Bytes::from_static(b"body"),
                }),
                pq_suite: 0,
                pq_last_resort: false,
                pq_prekey_id: Bytes::new(),
                pq_ciphertext: Bytes::new(),
                manifest_digest: Bytes::new(),
            }),
        })
        .await
        .unwrap();

        // Confirm `accept_initial_v2` returns `InvalidKeys` (the exact error that used to go un-acked).
        let listed = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
        assert_eq!(listed.messages.len(), 1);
        assert_eq!(
            bob.accept_initial_v2(
                &low_order_sender,
                &PeerPqState::default(),
                &listed.messages[0],
                mb.clone(),
            )
            .unwrap_err()
            .kind(),
            ErrorKind::InvalidKeys
        );

        // `list_and_accept_v2` MUST ack and clear it so Bob's inbox cannot be permanently DoSed!
        let outcomes = bob
            .list_and_accept_v2(AUDIENCE, 10, mb, |_| PeerPqState::default())
            .await
            .unwrap();
        assert!(outcomes.is_empty());
        assert!(
            bob.list_initial_messages_v2(AUDIENCE, 10)
                .await
                .unwrap()
                .messages
                .is_empty(),
            "permanently rejected low-order sender entry must be acknowledged and removed"
        );
    }

    #[tokio::test]
    async fn expired_manifest_is_distinct_from_downgrade_and_foreign_digest_is_rejected() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store, AUDIENCE);

        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs.clone());
        bob.publish_v2(AUDIENCE, 3, 3).await.unwrap();

        // Advance Alice's ServerClock past DEFAULT_MANIFEST_TTL_MS (31 days): Bob's valid manifest
        // at seq 1 (>= pinned 1) returns `PeerManifestExpired`, NOT a false `DowngradeDetected`!
        let future = alice.clock().now() + session::DEFAULT_MANIFEST_TTL_MS + 60_000;
        alice.clock().observe(future);
        let pinned_seq1 = PeerPqState {
            pq_pinned: true,
            pinned_manifest_seq: 1,
            peer_pq_capable: true,
            ..PeerPqState::default()
        };
        assert_eq!(
            alice
                .initiate_v2(AUDIENCE, &bob.identity_key(), &pinned_seq1, b"hi", mb.clone())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::PeerManifestExpired
        );
        assert_eq!(
            alice
                .get_peer_manifest(AUDIENCE, &bob.identity_key())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::PeerManifestExpired
        );

        // Even when expired, a replayed older manifest (`seq 1 < pinned 2`) MUST STILL return
        // `DowngradeDetected`!
        let pinned_seq2 = PeerPqState {
            pq_pinned: true,
            pinned_manifest_seq: 2,
            peer_pq_capable: true,
            ..PeerPqState::default()
        };
        assert_eq!(
            alice
                .initiate_v2(AUDIENCE, &bob.identity_key(), &pinned_seq2, b"hi", mb.clone())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::DowngradeDetected
        );

        // Reset Alice's clock to current time, initiate normally, then tamper `manifest_digest` to
        // an unrecognized digest -> Bob's `accept_initial_v2` rejects with `DowngradeDetected`!
        let now_ms = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        alice.clock().observe(now_ms);
        let _alice_sess = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"hi-valid",
                mb.clone(),
            )
            .await
            .unwrap();
        let mut listed = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
        let mut tampered = listed.messages.pop().unwrap();
        if let session::InitialMessageKind::Pq {
            manifest_digest, ..
        } = &mut tampered.kind
        {
            *manifest_digest = Some([0xAB; 32]);
        }
        assert_eq!(
            bob.accept_initial_v2(
                &alice.identity_key(),
                &PeerPqState::default(),
                &tampered,
                mb,
            )
            .unwrap_err()
            .kind(),
            ErrorKind::DowngradeDetected
        );
    }

    #[tokio::test]
    async fn v2_infinite_expired_pages_relay_terminates_cleanly() {
        #[derive(Debug, Clone)]
        struct InfiniteExpiredV2Mailbox {
            fetches: Arc<AtomicUsize>,
        }
        impl LocalMailbox for InfiniteExpiredV2Mailbox {
            async fn push(&self, _: PushRequest) -> protocol::Result<PushResponse> {
                Ok(PushResponse::default())
            }
            async fn fetch(&self, _: FetchRequest) -> protocol::Result<FetchResponse> {
                Ok(FetchResponse::default())
            }
        }
        impl LocalMailboxV2 for InfiniteExpiredV2Mailbox {
            async fn push_v2(&self, _: PushV2Request) -> protocol::Result<PushV2Response> {
                Ok(PushV2Response::default())
            }
            async fn fetch_signed(
                &self,
                request: FetchSignedRequest,
            ) -> protocol::Result<FetchSignedResponse> {
                self.fetches.fetch_add(1, Ordering::Relaxed);
                Ok(FetchSignedResponse {
                    messages: vec![protocol::mailbox_v2::EnvelopeV2 {
                        sequence: request.after + 1,
                        message: None,
                        initial_message: None,
                    }],
                })
            }
        }

        let store = SharedStore::default();
        let hs = DualHandshake::new(store, AUDIENCE);
        let fetches = Arc::new(AtomicUsize::new(0));
        let mb = InfiniteExpiredV2Mailbox {
            fetches: fetches.clone(),
        };
        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs);
        bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        let mut alice_session = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"hi",
                mb,
            )
            .await
            .unwrap();

        let received = alice_session.receive_v2(&alice, AUDIENCE).await.unwrap();
        assert!(received.is_empty());
        assert_eq!(fetches.load(Ordering::Relaxed), 8);
    }
}
