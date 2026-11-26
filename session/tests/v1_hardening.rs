//! End-to-end tests for audience normalization, server clock bounds, `Hello` `session_seq`
//! anti-rollback, and evicted ratchet message handling over the v2 unified mailbox.

mod common;

use core::mem;

use protocol::content::{Hello, Kind as ContentKind};
use session::{
    AcceptedInitial, Client, ErrorKind, PeerPqState, PqConfig, SessionSecurity, check_peer_hello,
    expected_audience_from_url,
};

use common::{
    AUDIENCE, SharedStore, V2OnlyHandshake, V2OnlyMailbox, hello_bytes, receive_for,
    register_active_grant,
};

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

#[tokio::test]
async fn next_timestamp_uses_server_clock_and_enforces_max_safe_integer() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store, AUDIENCE);
    let mut alice = Client::new(hs)
        .with_clock(session::ServerClock::with_max_drift(u64::MAX))
        .with_pq_config(PqConfig {
            pq_enabled: false,
            ..PqConfig::default()
        })
        .unwrap();

    let server_now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    alice.clock().observe(server_now);
    let p1 = alice.prepare_publish_v2(AUDIENCE, 2, 0).unwrap();
    let p1_ts = p1.request.timestamp;
    alice.commit_publish_v2(p1);
    let r2 = alice.prepare_refill_v2(AUDIENCE, 2, 0).unwrap();
    assert!(r2.request.timestamp > p1_ts);
    assert!(p1_ts.abs_diff(server_now) < 5_000);

    // Observing an out-of-range server timestamp (> MAX_SAFE_INTEGER) is ignored cleanly rather
    // than poisoning the clock.
    alice.clock().observe(protocol::MAX_SAFE_INTEGER + 10);
    assert!(alice.clock().now().abs_diff(server_now) < 5_000);

    // Observing exact MAX_SAFE_INTEGER lets one refill succeed at MAX_SAFE_INTEGER, and the
    // monotonic increment to MAX_SAFE_INTEGER + 1 fails cleanly with Protocol.
    alice.clock().observe(protocol::MAX_SAFE_INTEGER);
    let at_max = alice.prepare_refill_v2(AUDIENCE, 1, 0).unwrap();
    assert_eq!(at_max.request.timestamp, protocol::MAX_SAFE_INTEGER);
    assert_eq!(
        alice.prepare_refill_v2(AUDIENCE, 1, 0).unwrap_err().kind(),
        ErrorKind::Protocol
    );
}

#[tokio::test]
async fn classical_initial_and_in_band_hello_reject_unsafe_sequences_without_changing_state() {
    let hs = V2OnlyHandshake::new(SharedStore::default(), AUDIENCE);
    let off = PqConfig {
        pq_enabled: false,
        ..PqConfig::default()
    };
    let mut alice = Client::new(hs.clone()).with_pq_config(off.clone()).unwrap();
    let mut bob = Client::new(hs).with_pq_config(off).unwrap();
    bob.publish_v2(AUDIENCE, 2, 0).await.unwrap();
    let invalid = protocol::MAX_SAFE_INTEGER + 1;
    alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &hello_bytes("alice", invalid, true),
            (),
        )
        .await
        .unwrap();
    alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &hello_bytes("alice", 1, false),
            (),
        )
        .await
        .unwrap();
    let inbox = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    assert!(inbox.messages[0].uses_one_time_prekey());
    let count = bob.current_one_time_count();
    assert_eq!(
        bob.accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &inbox.messages[0],
            (),
        )
        .unwrap_err()
        .kind(),
        ErrorKind::InvalidInitialMessage
    );
    assert_eq!(bob.current_one_time_count(), count);

    let AcceptedInitial::Accepted { mut session, .. } = bob
        .accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &inbox.messages[1],
            (),
        )
        .unwrap()
    else {
        panic!("expected accepted");
    };
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
}

#[tokio::test]
async fn hello_session_seq_anti_rollback_protects_active_session() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);
    let off = PqConfig {
        pq_enabled: false,
        ..PqConfig::default()
    };
    let mut alice = Client::new(hs.clone()).with_pq_config(off.clone()).unwrap();
    let mut bob = Client::new(hs).with_pq_config(off).unwrap();
    bob.publish_v2(AUDIENCE, 10, 0).await.unwrap();

    let s1 = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &hello_bytes("alice", 1, false),
            mb.clone(),
        )
        .await
        .unwrap();
    let mut s2 = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &hello_bytes("alice", 2, false),
            mb.clone(),
        )
        .await
        .unwrap();
    let s0 = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &hello_bytes("alice", 0, false),
            mb.clone(),
        )
        .await
        .unwrap();
    let mut s3 = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &hello_bytes("alice", 3, false),
            mb.clone(),
        )
        .await
        .unwrap();
    drop((s1, s0));

    let inbox = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    assert_eq!(inbox.messages.len(), 4);

    let AcceptedInitial::Accepted {
        session: mut bob_session,
        first_message: first2,
        ..
    } = bob
        .accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &inbox.messages[1],
            mb.clone(),
        )
        .unwrap()
    else {
        panic!("expected accepted");
    };
    register_active_grant(&mut bob, &bob_session, &mb).await;
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

    let AcceptedInitial::Accepted {
        session: stale_1, ..
    } = bob
        .accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &inbox.messages[0],
            mb.clone(),
        )
        .unwrap()
    else {
        panic!("expected accepted under fresh peer state");
    };
    assert_eq!(
        bob_session.accept_replacement(stale_1).unwrap_err().kind(),
        ErrorKind::StaleSession
    );
    assert_eq!(bob_session.active_id(), Some(&active_s2));

    let AcceptedInitial::Accepted {
        session: stale_0, ..
    } = bob
        .accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &inbox.messages[2],
            mb.clone(),
        )
        .unwrap()
    else {
        panic!("expected accepted under fresh peer state");
    };
    let older = mem::replace(&mut bob_session, stale_0);
    let err = bob_session.keep(older).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::StaleSession);
    assert_eq!(bob_session.active_id(), Some(&active_s2));

    s2.send_v2(b"still on 2").await.unwrap();
    let r = receive_for(&mut bob, &mut bob_session, &mb).await;
    assert_eq!(r[0].as_ref().unwrap().content, b"still on 2");

    let AcceptedInitial::Accepted {
        session: newer_3, ..
    } = bob
        .accept_initial_v2(
            &alice.identity_key(),
            bob_session.peer_pq_state(),
            &inbox.messages[3],
            mb.clone(),
        )
        .unwrap()
    else {
        panic!("expected accepted seq 3");
    };
    assert!(bob_session.accept_replacement(newer_3).unwrap());
    register_active_grant(&mut bob, &bob_session, &mb).await;
    assert_eq!(bob_session.peer_session_seq(), 3);
    assert_eq!(bob_session.active_id(), s3.active_id());
    s3.send_v2(b"on 3").await.unwrap();
    let r = receive_for(&mut bob, &mut bob_session, &mb).await;
    assert_eq!(r[0].as_ref().unwrap().content, b"on 3");

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

#[tokio::test]
async fn evicted_message_surfaces_distinctly_and_clears_unified_mailbox_on_ack() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store.clone(), AUDIENCE);
    let off = PqConfig {
        pq_enabled: false,
        ..PqConfig::default()
    };

    let mut alice = Client::new(hs.clone()).with_pq_config(off.clone()).unwrap();
    let mut bob = Client::new(hs).with_pq_config(off).unwrap();
    bob.publish_v2(AUDIENCE, 2, 0).await.unwrap();

    let mut alice_session = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"hi2",
            mb.clone(),
        )
        .await
        .unwrap();
    let inbox = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let AcceptedInitial::Accepted {
        session: mut bob_session,
        ..
    } = bob
        .accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &inbox.messages[0],
            mb.clone(),
        )
        .unwrap()
    else {
        panic!("expected accepted");
    };
    register_active_grant(&mut bob, &bob_session, &mb).await;

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

    alice_session.push_v2(&msg600).await.unwrap();
    alice_session.push_v2(&msg1200).await.unwrap();
    let got = receive_for(&mut bob, &mut bob_session, &mb).await;
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].as_ref().unwrap().content, b"msg-600");
    assert_eq!(got[1].as_ref().unwrap().content, b"msg-1200");

    alice_session.push_v2(&msg0).await.unwrap();
    alice_session.push_v2(&msg1201).await.unwrap();

    let got = receive_for(&mut bob, &mut bob_session, &mb).await;
    assert_eq!(got.len(), 2, "EvictedMessage must NOT stall decryption!");
    assert_eq!(
        got[0].as_ref().unwrap_err().kind(),
        ErrorKind::EvictedMessage
    );
    assert_eq!(got[1].as_ref().unwrap().content, b"msg-1201");

    // Prefix ACK deleted all 4 envelopes from Bob's unified mailbox.
    let remaining = storage::LocalIdempotentMailboxStore::read_mailbox(
        &store,
        &bob.identity_key(),
        0,
        100,
        1024 * 1024,
        0,
    )
    .await
    .unwrap();
    assert!(remaining.messages.is_empty());
}
