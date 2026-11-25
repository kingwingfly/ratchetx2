//! End-to-end tests for classical v1 hardening, sequence anti-rollback, mailbox eviction/expiry,
//! and serialized state restoration.

mod common;

use core::mem;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
#[allow(deprecated)]
use protocol::{
    content::{Hello, Kind as ContentKind},
    handshake::{HandshakeServer, LocalHandshake},
    mailbox::{FetchRequest, LocalMailbox, MailboxLimits, MailboxServer},
};
use session::{
    Client, ErrorKind, PeerPqState, SessionSecurity, check_peer_hello, expected_audience_from_url,
};

use common::{
    ExpiringMailbox, InfiniteExpiredMailbox, LostReply, RpcErrors, SharedStore, V1Handshake,
    V1Mailbox, hello_bytes,
};

#[allow(deprecated)]
async fn check_classical_publish_error(
    handshake: impl LocalHandshake,
    extend: bool,
    expected: ErrorKind,
    refused: bool,
    kept: usize,
) {
    let mut client = Client::new(handshake);
    client.prepare_publish(1).unwrap();
    let result = if extend {
        client.extend_keys(1).await
    } else {
        client.publish_keys(1).await
    };
    let error = result.unwrap_err();
    assert_eq!(error.kind(), expected);
    assert_eq!(error.is_server_refusal(), refused);
    assert_eq!(client.current_one_time_count(), kept);
}

#[allow(deprecated)]
#[tokio::test]
async fn classical_publish_and_extend_check_refusal_provenance() {
    use protocol::{ErrorKind as Kind, connect::ConnectClient};
    for extend in [false, true] {
        for (kind, expected) in [
            (Kind::SignInRequired, ErrorKind::SignInRequired),
            (Kind::LimitExceeded, ErrorKind::LimitExceeded),
            (Kind::Malformed, ErrorKind::Protocol),
        ] {
            let confirmed = RpcErrors::new([("publish", kind.into())]);
            let kept = if extend || kind == Kind::SignInRequired {
                1
            } else {
                2
            };
            check_classical_publish_error(&confirmed, extend, expected, true, kept).await;
            let ambiguous = RpcErrors::new([(
                "publish",
                protocol::Error::ambiguous_response(kind, "lost reply"),
            )]);
            check_classical_publish_error(&ambiguous, extend, expected, false, 2).await;
        }
        for (reply, expected) in [
            (LostReply::CorruptBody, ErrorKind::InvalidResponse),
            (LostReply::Transport, ErrorKind::Server),
        ] {
            check_classical_publish_error(ConnectClient::new(reply), extend, expected, false, 2)
                .await;
        }
    }
}

#[test]
fn expected_audience_from_url_normalizes_and_rejects_bad_inputs() {
    assert_eq!(
        expected_audience_from_url("https://Chat.Example.COM:443/path?x=1#frag").unwrap(),
        "chat.example.com"
    );
    assert_eq!(
        expected_audience_from_url("https://München.example:443/api").unwrap(),
        "xn--mnchen-3ya.example"
    );
    assert_eq!(
        expected_audience_from_url("münchen.example:8443").unwrap(),
        "xn--mnchen-3ya.example:8443"
    );
    for bad in [
        "",
        "   ",
        "https://user:pass@relay.example",
        "https://relay.example:99999",
    ] {
        assert_eq!(
            expected_audience_from_url(bad).unwrap_err().kind(),
            ErrorKind::Protocol,
            "input {bad:?} must fail"
        );
    }
}

#[allow(deprecated)]
#[tokio::test]
async fn expired_envelope_carried_initial_survives_ok_duplicate_and_evicted() {
    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store.clone())));
    let mailbox_server = Arc::new(
        MailboxServer::builder(store)
            .limits(MailboxLimits {
                max_fetch: 50,
                ..MailboxLimits::default()
            })
            .build(),
    );
    let mb = V1Mailbox(mailbox_server.clone());
    let expired_seqs = Arc::new(Mutex::new(Vec::new()));
    let bob_mb = ExpiringMailbox::with_shared(mb.clone(), expired_seqs.clone());

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    bob.publish_keys(10).await.unwrap();

    let mut alice_old = alice
        .initiate(&bob.identity_key(), b"init-0", mb.clone())
        .await
        .unwrap();
    let inbox = bob.take_initial_messages().await.unwrap();
    let (mut bob_session, _) = bob
        .accept(&alice.identity_key(), &inbox[0], bob_mb)
        .unwrap();
    bob_session.send(b"ack-0").await.unwrap();
    assert_eq!(
        alice_old.receive().await.unwrap()[0]
            .content
            .as_deref()
            .unwrap(),
        b"ack-0"
    );

    let evicted_msg = alice_old.encrypt(b"evicted-0").unwrap();
    for _ in 1..600 {
        let _ = alice_old.encrypt(b"gap").unwrap();
    }
    let msg600 = alice_old.encrypt(b"msg-600").unwrap();
    for _ in 601..1200 {
        let _ = alice_old.encrypt(b"gap").unwrap();
    }
    let msg1200 = alice_old.encrypt(b"msg-1200").unwrap();
    let ok_msg = alice_old.encrypt(b"ok-after-expired").unwrap();
    alice_old.push(msg600).await.unwrap();
    alice_old.push(msg1200.clone()).await.unwrap();
    assert_eq!(bob_session.receive().await.unwrap().len(), 2);

    for (case_name, greeting, follow_up) in [
        ("Ok", &b"carried-before-ok"[..], ok_msg),
        ("DuplicateMessage", &b"carried-before-dup"[..], msg1200),
        (
            "EvictedMessage",
            &b"carried-before-evicted"[..],
            evicted_msg,
        ),
    ] {
        let mut alice_new = alice
            .initiate(&bob.identity_key(), greeting, mb.clone())
            .await
            .unwrap();
        assert_eq!(bob.take_initial_messages().await.unwrap().len(), 1);

        let exp_sealed = alice_new.encrypt(b"expires").unwrap();
        let exp_req = alice_new.push_request(exp_sealed);
        let exp_seq = mb.push(exp_req).await.unwrap().sequence;
        expired_seqs.lock().unwrap().push(exp_seq);
        alice_old.push(follow_up).await.unwrap();

        let received = bob_session.receive().await.unwrap();
        assert_eq!(
            received.len(),
            2,
            "{case_name}: expected follow-up + trailing Err(Expired), got {received:?}"
        );
        match case_name {
            "Ok" => assert_eq!(received[0].content.as_deref().unwrap(), b"ok-after-expired"),
            "DuplicateMessage" => assert_eq!(
                received[0].content.as_ref().unwrap_err().kind(),
                ErrorKind::DuplicateMessage
            ),
            "EvictedMessage" => assert!(received[0].is_evicted()),
            _ => unreachable!(),
        }
        assert_eq!(
            received[1].content.as_ref().unwrap_err().kind(),
            ErrorKind::Expired,
            "{case_name}: expired-envelope carried initial must flush via trailing Expired"
        );
        assert_eq!(received[1].initial_messages.len(), 1);
        let (_, accepted_greeting) = bob
            .accept(
                &alice.identity_key(),
                &received[1].initial_messages[0],
                mb.clone(),
            )
            .unwrap();
        assert_eq!(accepted_greeting, greeting);
    }
}

#[allow(deprecated)]
#[tokio::test]
async fn next_timestamp_uses_server_clock_and_enforces_max_safe_integer() {
    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store)));
    let mut alice = Client::new(hs);

    let server_now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    alice.clock().observe(server_now);
    let p1 = alice.prepare_publish(2).unwrap();
    let p2 = alice.prepare_extend_keys(2).unwrap();
    assert!(p2.request.timestamp > p1.request.timestamp);
    assert!(p1.request.timestamp.abs_diff(server_now) < 5_000);

    // Observing an out-of-range server timestamp (> MAX_SAFE_INTEGER) is ignored cleanly rather
    // than poisoning the clock.
    alice.clock().observe(protocol::MAX_SAFE_INTEGER + 10);
    assert!(alice.clock().now().abs_diff(server_now) < 5_000);

    // Observing exact MAX_SAFE_INTEGER lets one publish succeed at MAX_SAFE_INTEGER, and the
    // monotonic increment to MAX_SAFE_INTEGER + 1 fails cleanly with Protocol.
    alice.clock().observe(protocol::MAX_SAFE_INTEGER);
    let at_max = alice.prepare_publish(1).unwrap();
    assert_eq!(at_max.request.timestamp, protocol::MAX_SAFE_INTEGER);
    assert_eq!(
        alice.prepare_publish(1).unwrap_err().kind(),
        ErrorKind::Protocol
    );
}

#[allow(deprecated)]
#[tokio::test]
async fn classical_persist_before_transmit_and_extend_without_rotating_spk() {
    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store.clone())));
    let mb = V1Mailbox(Arc::new(MailboxServer::new(store)));
    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);

    let prep = bob.prepare_publish(2).unwrap();
    let spk_before = bob.current_signed_prekey().unwrap();
    assert_eq!(bob.current_one_time_count(), 2);
    bob.transmit_publish(&prep).await.unwrap();
    bob.commit_publish(prep);

    bob.extend_keys(3).await.unwrap();
    assert_eq!(bob.current_signed_prekey().unwrap(), spk_before);
    assert_eq!(bob.current_one_time_count(), 5);

    let init = alice
        .prepare_initiate(&bob.identity_key(), b"hello", mb.clone())
        .await
        .unwrap();
    let mut alice_session = init.session;
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

#[allow(deprecated)]
#[tokio::test]
async fn classical_initial_and_in_band_hello_reject_unsafe_sequences_without_changing_state() {
    let hs = V1Handshake(Arc::new(HandshakeServer::new(SharedStore::default())));
    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    bob.publish_keys(2).await.unwrap();
    let invalid = protocol::MAX_SAFE_INTEGER + 1;
    alice
        .initiate(
            &bob.identity_key(),
            &hello_bytes("alice", invalid, true),
            (),
        )
        .await
        .unwrap();
    alice
        .initiate(&bob.identity_key(), &hello_bytes("alice", 1, false), ())
        .await
        .unwrap();
    let inbox = bob.take_initial_messages().await.unwrap();
    assert!(inbox[0].x3dh.one_time_prekey.is_some());
    let count = bob.current_one_time_count();
    assert_eq!(
        bob.accept(&alice.identity_key(), &inbox[0], ())
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInitialMessage
    );
    assert_eq!(bob.current_one_time_count(), count);

    let (mut session, _) = bob.accept(&alice.identity_key(), &inbox[1], ()).unwrap();
    let before = session.peer_pq_state().clone();
    let hello = Hello {
        pq_capable: true,
        session_seq: invalid,
        ..Default::default()
    };
    let mut state = before.clone();
    let stale = session::HelloCheck {
        downgrade_detected: false,
        recommend_start_again: false,
        stale_session_seq: true,
    };
    assert_eq!(
        check_peer_hello(&mut state, SessionSecurity::classical(), &hello, true),
        stale
    );
    assert_eq!(state, before);
    assert_eq!(session.check_peer_hello(&hello, true), stale);
    assert_eq!(session.peer_pq_state(), &before);

    #[cfg(feature = "prost")]
    {
        let wire = session::proto::SessionState::from(session.state());
        let restored = session::SessionState::try_from(&wire).unwrap();
        assert_eq!(restored.peer_pq_state(), &before);
    }
    #[cfg(feature = "rkyv")]
    {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(session.state()).unwrap();
        let restored =
            rkyv::from_bytes::<session::SessionState, rkyv::rancor::Error>(&bytes).unwrap();
        assert_eq!(restored.peer_pq_state(), &before);
    }
}

#[allow(deprecated)]
#[tokio::test]
async fn hello_session_seq_anti_rollback_protects_active_session() {
    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store.clone())));
    let mb = V1Mailbox(Arc::new(MailboxServer::new(store)));
    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    bob.publish_keys(10).await.unwrap();

    let s1 = alice
        .initiate(
            &bob.identity_key(),
            &hello_bytes("alice", 1, false),
            mb.clone(),
        )
        .await
        .unwrap();
    let mut s2 = alice
        .initiate(
            &bob.identity_key(),
            &hello_bytes("alice", 2, false),
            mb.clone(),
        )
        .await
        .unwrap();
    let s0 = alice
        .initiate(
            &bob.identity_key(),
            &hello_bytes("alice", 0, false),
            mb.clone(),
        )
        .await
        .unwrap();
    let mut s3 = alice
        .initiate(
            &bob.identity_key(),
            &hello_bytes("alice", 3, false),
            mb.clone(),
        )
        .await
        .unwrap();
    drop((s1, s0));

    let inbox = bob.take_initial_messages().await.unwrap();
    assert_eq!(inbox.len(), 4);

    let (mut bob_session, first2) = bob
        .accept(&alice.identity_key(), &inbox[1], mb.clone())
        .unwrap();
    let active_s2 = *bob_session.active_id().unwrap();
    assert_eq!(bob_session.peer_session_seq(), 2);

    let Some(ContentKind::Hello(h2)) = ContentKind::from_bytes(&first2) else {
        panic!("expected Hello");
    };
    let own_check = bob_session.check_peer_hello(&h2, false);
    assert!(!own_check.stale_session_seq);
    assert!(!own_check.downgrade_detected);
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

    let (stale_1, _) = bob
        .accept(&alice.identity_key(), &inbox[0], mb.clone())
        .unwrap();
    assert_eq!(
        bob_session.accept_replacement(stale_1).unwrap_err().kind(),
        ErrorKind::StaleSession
    );
    assert_eq!(bob_session.active_id(), Some(&active_s2));

    let (stale_0, _) = bob
        .accept(&alice.identity_key(), &inbox[2], mb.clone())
        .unwrap();
    let older = mem::replace(&mut bob_session, stale_0);
    let err = bob_session.keep(older).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::StaleSession);
    assert_eq!(bob_session.active_id(), Some(&active_s2));

    s2.send(b"still on 2").await.unwrap();
    let r = bob_session.receive().await.unwrap();
    assert_eq!(r[0].content.as_deref().unwrap(), b"still on 2");

    let (newer_3, _) = bob
        .accept(&alice.identity_key(), &inbox[3], mb.clone())
        .unwrap();
    assert!(bob_session.accept_replacement(newer_3).unwrap());
    assert_eq!(bob_session.peer_session_seq(), 3);
    assert_eq!(bob_session.active_id(), s3.active_id());
    s3.send(b"on 3").await.unwrap();
    let r = bob_session.receive().await.unwrap();
    assert_eq!(r[0].content.as_deref().unwrap(), b"on 3");

    let mut ps = PeerPqState::default();
    assert!(
        !check_peer_hello(
            &mut ps,
            SessionSecurity::classical(),
            &Hello::classical("a"),
            false,
        )
        .stale_session_seq
    );
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
    assert!(
        check_peer_hello(
            &mut ps,
            SessionSecurity::classical(),
            &Hello::classical("a"),
            false,
        )
        .stale_session_seq
    );
}

#[allow(deprecated)]
#[tokio::test]
async fn evicted_message_acks_delivery_token_and_surfaces_distinctly() {
    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store.clone())));
    let mailbox_server = Arc::new(
        MailboxServer::builder(store)
            .limits(MailboxLimits {
                max_fetch: 50,
                ..MailboxLimits::default()
            })
            .build(),
    );
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

    alice_session.push(msg600).await.unwrap();
    alice_session.push(msg1200).await.unwrap();
    let got = bob_session.receive().await.unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].content.as_deref().unwrap(), b"msg-600");
    assert_eq!(got[1].content.as_deref().unwrap(), b"msg-1200");

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

#[allow(deprecated)]
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
    let mb = V1Mailbox(mailbox_server);

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
            ExpiringMailbox::new(mb.clone(), vec![1]),
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

    alice
        .start_again(&mut alice_session, b"lost-new-session")
        .await
        .unwrap();
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

#[allow(deprecated)]
#[tokio::test]
async fn infinite_expired_pages_relay_terminates_cleanly() {
    let store = SharedStore::default();
    let hs = V1Handshake(Arc::new(HandshakeServer::new(store)));
    let fetches = Arc::new(AtomicUsize::new(0));
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

    let received = alice_session.receive().await.unwrap();
    assert!(received.is_empty());
    assert_eq!(fetches.load(Ordering::Relaxed), 8);
}

#[allow(deprecated)]
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

    let mut proto_client = proto::ClientState::from(alice.state());
    assert!(session::ClientState::try_from(&proto_client).is_ok());

    proto_client.preferred_pq_suite = 99;
    assert_eq!(
        session::ClientState::try_from(&proto_client)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );
    proto_client.preferred_pq_suite = 0;

    proto_client.pq_disabled = true;
    proto_client.strict_pq = true;
    assert_eq!(
        session::ClientState::try_from(&proto_client)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

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

    let base_session = proto::SessionState::from(alice_session.state());
    assert!(session::SessionState::try_from(&base_session).is_ok());

    let mut bad_key = base_session.clone();
    bad_key.me[31] |= 0x80;
    assert_eq!(
        session::SessionState::try_from(&bad_key)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

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
