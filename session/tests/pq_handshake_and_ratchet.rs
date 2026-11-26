//! End-to-end tests for universal v2 wire protocol, PQXDH (ML-KEM-1024 / ML-KEM-768), PQ KEM
//! ratcheting, two-phase inbox list/accept/ack, carried initials across expired pages, and crossed
//! starts.

mod common;

use bytes::Bytes;
use protocol::handshake_v2::LocalHandshakeV2;
use session::{
    AcceptedInitial, Client, ErrorKind, PeerPqState, PqConfig, PublishV2Outcome, SessionSecurity,
};

use common::{AUDIENCE, SharedStore, UnimplementedV2Server, V2OnlyHandshake, V2OnlyMailbox};

#[tokio::test]
async fn v2_wire_protocol_works_universally_without_legacy_v1_traits() {
    #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
    {
        let default_cfg = PqConfig::default();
        assert!(!default_cfg.pq_enabled);
        assert!(default_cfg.offered_suites().is_empty());
    }

    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);
    let classical_cfg = PqConfig {
        pq_enabled: false,
        ..PqConfig::default()
    };

    let mut alice = Client::new(hs.clone())
        .with_pq_config(classical_cfg.clone())
        .unwrap();
    let mut bob = Client::new(hs.clone())
        .with_pq_config(classical_cfg.clone())
        .unwrap();
    let mut carol = Client::new(hs).with_pq_config(classical_cfg).unwrap();

    // 1. `fetch_server_info` reports v2 defaults with legacy v1 & unsigned fetch disabled.
    let info = alice.fetch_server_info(AUDIENCE).await.unwrap();
    assert_eq!(info.server_id, AUDIENCE);
    assert!(!info.legacy_v1_enabled);
    assert!(!info.allow_unsigned_fetch);

    // 2. Prepare + retry rollback + transmit + commit publish on v2-only transport.
    let prepared = bob.prepare_publish_v2(AUDIENCE, 2, 0).unwrap();
    assert_eq!(bob.manifest_seq(), 1);
    assert_eq!(bob.current_one_time_count(), 2);
    let rolled = bob.prepare_publish_v2(AUDIENCE, 1, 0).unwrap();
    assert_eq!(bob.manifest_seq(), 2);
    assert_eq!(bob.current_one_time_count(), 3);
    bob.rollback_publish_v2_on_refusal(rolled);
    assert_eq!(bob.manifest_seq(), 1);
    assert_eq!(bob.current_one_time_count(), 2);

    let outcome = bob.transmit_publish_v2(&prepared).await.unwrap();
    assert_eq!(outcome, PublishV2Outcome::V2ClassicalOff);
    bob.commit_publish_v2(prepared);

    alice.publish_v2(AUDIENCE, 2, 0).await.unwrap();
    carol.publish_v2(AUDIENCE, 2, 0).await.unwrap();

    // 3. `fetch_peer_manifest` verifies signed OFF manifest.
    let manifest = alice
        .fetch_peer_manifest(AUDIENCE, &bob.identity_key())
        .await
        .unwrap()
        .expect("bob published a signed OFF manifest");
    assert!(!manifest.pq_enabled);
    assert_eq!(manifest.manifest_seq, 1);

    // 4. `prepare_refill_v2` / rollback / commit + `refill_prekeys_v2`.
    let before_refill = bob.current_one_time_count();
    let rolled_refill = bob.prepare_refill_v2(AUDIENCE, 2, 0).unwrap();
    assert_eq!(bob.current_one_time_count(), before_refill + 2);
    bob.rollback_refill_v2_on_refusal(rolled_refill);
    assert_eq!(bob.current_one_time_count(), before_refill);

    let prepared_refill = bob.prepare_refill_v2(AUDIENCE, 2, 0).unwrap();
    let resp = bob.transmit_refill_v2(&prepared_refill).await.unwrap();
    bob.commit_refill_v2(prepared_refill);
    assert_eq!(resp.classical_one_time_count, (before_refill + 2) as u32);

    let resp2 = bob.refill_prekeys_v2(AUDIENCE, 1, 0).await.unwrap();
    assert_eq!(resp2.classical_one_time_count, (before_refill + 3) as u32);

    // 5. `prepare_initiate_v2` + `send_prepared_initiate_v2` sends classical v1 initial over v2.
    let init = alice
        .prepare_initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"hello-classical-over-v2",
            mb.clone(),
        )
        .await
        .unwrap();
    assert_eq!(init.security, SessionSecurity::classical());
    assert_eq!(init.request.message.as_ref().unwrap().version, 1);
    alice
        .send_prepared_initiate_v2(&init.request)
        .await
        .unwrap();
    let mut alice_session = init.session;

    // 6. Two-phase `list_initial_messages_v2` -> `accept_initial_v2` -> `ack_initial_messages_v2`.
    let listed = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
    assert_eq!(listed.messages.len(), 1);
    assert!(!listed.messages[0].is_pq());
    let AcceptedInitial::Accepted {
        session: mut bob_session,
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
        panic!("expected accepted classical initial over v2");
    };
    assert_eq!(first_message, b"hello-classical-over-v2");
    assert_eq!(security, SessionSecurity::classical());
    bob.ack_initial_messages_v2(AUDIENCE, vec![listed.messages[0].id])
        .await
        .unwrap();
    assert!(
        bob.list_initial_messages_v2(AUDIENCE, 10)
            .await
            .unwrap()
            .messages
            .is_empty()
    );

    // 7. `push_v2` (idempotent retry) + `receive_v2` (`FetchSigned`).
    let sealed = alice_session.encrypt(b"ping-v2").unwrap();
    let seq1 = alice_session.push_v2(sealed.clone()).await.unwrap();
    let seq2 = alice_session.push_v2(sealed).await.unwrap();
    assert_eq!(seq1, seq2, "idempotent push_v2 retry must deduplicate");

    let received = bob_session.receive_v2(&bob, AUDIENCE).await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].content.as_deref().unwrap(), b"ping-v2");

    // 8. `initiate_v2` + `list_and_accept_v2`.
    let _carol_session = carol
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"hi-from-carol",
            mb.clone(),
        )
        .await
        .unwrap();
    let outcome = bob
        .list_and_accept_v2(AUDIENCE, 10, mb, |_| PeerPqState::default())
        .await
        .unwrap();
    assert!(outcome.ack_error.is_none());
    assert!(outcome.unacked_ids.is_empty());
    assert_eq!(outcome.outcomes.len(), 1);
    assert_eq!(outcome.outcomes[0].0, carol.identity_key());

    // 9. Audience-bound notify subscriptions work on v2-only `Client`.
    let now = alice.clock().now();
    let sub = alice.subscription_for_audience(AUDIENCE).unwrap();
    assert!(sub.is_audience_bound());
    assert_eq!(
        sub.verify_for_audience(AUDIENCE, now).unwrap(),
        alice.identity_key()
    );
    let canonical_http =
        protocol::NormalizedAudience::parse("https://Relay.Example:443/api").unwrap();
    let canonical_ws =
        protocol::NormalizedAudience::parse("wss://relay.example/notifications").unwrap();
    let sub_canonical = alice
        .subscription_for_canonical_audience(&canonical_http)
        .unwrap();
    assert!(sub_canonical.is_audience_bound());
    assert_eq!(
        sub_canonical
            .verify_for_canonical_audience(&canonical_ws, now)
            .unwrap(),
        alice.identity_key()
    );
}

#[tokio::test]
async fn v2_never_falls_back_to_v1_on_unimplemented() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store, AUDIENCE);
    let classical_cfg = PqConfig {
        pq_enabled: false,
        ..PqConfig::default()
    };

    let mut peer = Client::new(hs.clone())
        .with_pq_config(classical_cfg.clone())
        .unwrap();
    peer.publish_v2(AUDIENCE, 2, 0).await.unwrap();

    let mut unimpl_client = Client::new(UnimplementedV2Server)
        .with_pq_config(classical_cfg.clone())
        .unwrap();
    for count in [2, 1] {
        assert_eq!(
            unimpl_client
                .publish_v2(AUDIENCE, count, 0)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::Unimplemented
        );
        assert_eq!(unimpl_client.manifest_seq(), 0);
        assert_eq!(unimpl_client.prekey_generation(), 0);
        assert_eq!(unimpl_client.current_one_time_count(), 0);
    }
    assert_eq!(
        unimpl_client
            .prepare_initiate_v2(
                AUDIENCE,
                &peer.identity_key(),
                &PeerPqState::default(),
                b"hi",
                UnimplementedV2Server,
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Unimplemented
    );
    assert_eq!(
        unimpl_client
            .list_initial_messages_v2(AUDIENCE, 10)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Unimplemented
    );

    let mut sender = Client::new(hs).with_pq_config(classical_cfg).unwrap();
    let mut session = sender
        .prepare_initiate_v2(
            AUDIENCE,
            &peer.identity_key(),
            &PeerPqState::default(),
            b"hi",
            UnimplementedV2Server,
        )
        .await
        .unwrap()
        .session;
    assert_eq!(
        session.send_v2(b"msg").await.unwrap_err().kind(),
        ErrorKind::Unimplemented
    );
    assert_eq!(
        session
            .receive_v2(&sender, AUDIENCE)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Unimplemented
    );
}

#[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
#[tokio::test]
async fn classical_only_build_rejects_pq_v2_initial_with_unsupported_suite() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store, AUDIENCE);
    let alice = Client::new(hs.clone());
    let mut bob = Client::new(hs.clone());
    bob.publish_v2(AUDIENCE, 2, 0).await.unwrap();
    let eph = Client::new(()).identity_key();

    let wire = protocol::handshake_v2::InitialMessageV2 {
        id: 7,
        version: 2,
        identity_key: Bytes::copy_from_slice(&alice.identity_key()),
        ephemeral_key: Bytes::copy_from_slice(&eph),
        signed_prekey: Bytes::copy_from_slice(&bob.current_signed_prekey().unwrap()),
        one_time_prekey: None,
        first_message: Some(party::EncryptedMessage::default()),
        pq_suite: 1,
        pq_last_resort: true,
        pq_prekey_id: Bytes::from_static(&[9u8; 32]),
        pq_ciphertext: Bytes::from(vec![0x55; 1568]),
        manifest_digest: Bytes::new(),
    };
    let parsed = session::InitialMessageV2::try_from(&wire).unwrap();
    assert!(parsed.is_pq());
    let err = bob
        .accept_initial_v2(&alice.identity_key(), &PeerPqState::default(), &parsed, ())
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedSuite);

    let queued = hs
        .send_initial_v2(protocol::handshake_v2::SendInitialV2Request {
            recipient: Bytes::copy_from_slice(&bob.identity_key()),
            message: Some(wire),
        })
        .await
        .unwrap();
    assert!(queued.id > 0);
    let outcome = bob
        .list_and_accept_v2(AUDIENCE, 10, (), |_| PeerPqState::default())
        .await
        .unwrap();
    assert!(outcome.outcomes.is_empty());
    assert!(outcome.ack_error.is_none());
    let still_queued = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
    assert_eq!(still_queued.messages.len(), 1);
    assert_eq!(still_queued.messages[0].id, queued.id);
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[allow(deprecated)]
mod pq_flow {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[cfg(feature = "ml-kem-1024")]
    use protocol::content::Kind as ContentKind;
    use protocol::{
        handshake_v2::{
            AckInitialMessagesRequest, AckInitialMessagesResponse, ClaimBundleRequest,
            ClaimBundleResponse, GetManifestRequest, GetManifestResponse, GetServerInfoRequest,
            GetServerInfoResponse, HandshakeV2Limits, HandshakeV2Server,
            ListInitialMessagesRequest, ListInitialMessagesResponse, PublishV2Request,
            PublishV2Response, RefillPrekeysRequest, RefillPrekeysResponse, SendInitialV2Request,
            SendInitialV2Response, ServerInfoConfig,
        },
        mailbox::MailboxLimits,
        mailbox_v2::LocalMailboxV2,
    };
    use session::{InitialMessageV2, PqSuite};

    use common::{
        AttackMode, AttackingHandshake, DualHandshake, DualMailbox, ExpiringMailbox,
        InfiniteExpiredMailbox, InterruptedPost, hello_bytes,
    };

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

        let info = alice.check_server_info(AUDIENCE).await.unwrap();
        assert!(info.pq_enabled);
        assert_eq!(
            alice
                .check_server_info("wrong.example")
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::DowngradeDetected
        );

        bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        let spk1 = bob.current_signed_prekey().unwrap();
        let refill = bob.refill_prekeys_v2(AUDIENCE, 3, 2).await.unwrap();
        assert_eq!(bob.current_signed_prekey().unwrap(), spk1);
        assert_eq!(refill.classical_one_time_count, 5);

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

        let sealed = alice_session.encrypt(b"turn-1").unwrap();
        let seq1 = alice_session.push_v2(sealed.clone()).await.unwrap();
        let seq1_retry = alice_session.push_v2(sealed).await.unwrap();
        assert_eq!(seq1, seq1_retry);

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

        #[cfg(feature = "prost")]
        {
            let p_alice = session::proto::SessionState::from(alice_session.state());
            let mut restored_alice = session::Session::restore(
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
            .unwrap()
            .outcomes;
        let (
            _,
            AcceptedInitial::Accepted {
                mut session,
                first_message,
                security,
            },
        ) = outcomes.pop().unwrap()
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
            .unwrap()
            .outcomes;
        let (
            _,
            AcceptedInitial::Accepted {
                mut session,
                first_message,
                security,
            },
        ) = outcomes.pop().unwrap()
        else {
            panic!("expected accepted PQXDH session with classical ratchet");
        };
        assert_eq!(first_message, b"pq-no-ratchet");
        assert_eq!(
            security,
            SessionSecurity::pq(PqConfig::default_suite(), false)
        );

        session
            .send_v2(b"classical-ratchet-over-pqxdh")
            .await
            .unwrap();
        let got = alice_session.receive_v2(&alice, AUDIENCE).await.unwrap();
        assert_eq!(
            got[0].content.as_deref().unwrap(),
            b"classical-ratchet-over-pqxdh"
        );
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

        let first_list = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
        assert_eq!(first_list.messages.len(), 1);
        let msg_id = first_list.messages[0].id;
        assert!(msg_id > 0);

        let retry_list = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
        assert_eq!(retry_list.messages.len(), 1);
        assert_eq!(retry_list.messages[0].id, msg_id);

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
        assert!(
            bob.list_initial_messages_v2(AUDIENCE, 10)
                .await
                .unwrap()
                .messages
                .is_empty()
        );
    }

    #[tokio::test]
    async fn failed_ack_returns_accepted_sessions_and_only_the_outstanding_ids() {
        use protocol::connect::ConnectClient;
        for (preceding, fail_on) in [(0, 1), (200, 2)] {
            let store = SharedStore::default();
            let limit = 201;
            let hs = DualHandshake {
                v2: Arc::new(
                    HandshakeV2Server::builder(store.clone())
                        .info(ServerInfoConfig::new(AUDIENCE))
                        .limits(HandshakeV2Limits {
                            max_initial_messages: limit,
                            max_list_limit: limit,
                            ..Default::default()
                        })
                        .build(),
                ),
                ..DualHandshake::new(store.clone(), AUDIENCE)
            };
            let mb = DualMailbox::new(store.clone(), AUDIENCE);
            let mut alice = Client::new(hs.clone());
            let mut bob = Client::new(ConnectClient::new(InterruptedPost {
                hs,
                mb: mb.clone(),
                fail_ack_on: Some(fail_on),
                acknowledgements: Default::default(),
                lose_refill_response: false,
            }));
            bob.publish_v2(AUDIENCE, 1, 1).await.unwrap();
            for _ in 0..preceding {
                assert!(
                    storage::LocalHandshakeStore::add_initial_message(
                        &store,
                        storage::StoredInitialMessage {
                            sender: [0; 32],
                            recipient: bob.identity_key(),
                            ephemeral_key: [2; 32],
                            signed_prekey: [3; 32],
                            one_time_prekey: None,
                            header: Bytes::new(),
                            content: Bytes::new(),
                        },
                        limit
                    )
                    .await
                    .unwrap()
                );
            }
            let mut sender = alice
                .initiate_v2(
                    AUDIENCE,
                    &bob.identity_key(),
                    &PeerPqState::default(),
                    b"first",
                    mb.clone(),
                )
                .await
                .unwrap();
            let outcome = bob
                .list_and_accept_v2(AUDIENCE, 0, mb, |_| PeerPqState::default())
                .await
                .unwrap();
            assert!(outcome.ack_error.is_some());
            let first_pending = if fail_on == 1 { 1 } else { 101 };
            assert_eq!(
                outcome.unacked_ids,
                (first_pending..=preceding + 1).collect::<Vec<_>>()
            );
            assert_eq!(outcome.outcomes.len(), 1);
            let (
                peer,
                AcceptedInitial::Accepted {
                    mut session,
                    first_message,
                    ..
                },
            ) = outcome.outcomes.into_iter().next().unwrap()
            else {
                panic!("accepted session was lost");
            };
            assert_eq!(peer, alice.identity_key());
            assert_eq!(first_message, b"first");
            assert_eq!(bob.current_one_time_count(), 0);
            assert_eq!(bob.current_pq_one_time_count(PqConfig::default_suite()), 0);
            sender.send_v2(b"second").await.unwrap();
            assert_eq!(
                session.receive_v2(&bob, AUDIENCE).await.unwrap()[0]
                    .content
                    .as_deref()
                    .unwrap(),
                b"second"
            );
            let pending = bob.list_initial_messages_v2(AUDIENCE, 0).await.unwrap();
            assert_eq!(
                pending.messages.iter().map(|m| m.id).collect::<Vec<_>>(),
                outcome.unacked_ids
            );
            let count = outcome.unacked_ids.len() as u32;
            assert_eq!(
                bob.ack_initial_messages_v2(AUDIENCE, outcome.unacked_ids)
                    .await
                    .unwrap(),
                count
            );
            assert!(
                bob.list_initial_messages_v2(AUDIENCE, 0)
                    .await
                    .unwrap()
                    .messages
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn unreadable_committed_refill_still_decrypts_a_session_using_both_new_keys() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store, AUDIENCE);
        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(protocol::connect::ConnectClient::new(InterruptedPost {
            hs,
            mb: mb.clone(),
            fail_ack_on: None,
            acknowledgements: Default::default(),
            lose_refill_response: true,
        }));
        bob.publish_v2(AUDIENCE, 0, 0).await.unwrap();
        let err = bob.refill_prekeys_v2(AUDIENCE, 1, 1).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidResponse);
        assert!(!err.is_server_refusal());
        alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"refilled",
                mb.clone(),
            )
            .await
            .unwrap();
        let listed = bob.list_initial_messages_v2(AUDIENCE, 1).await.unwrap();
        let init = &listed.messages[0];
        assert!(init.uses_one_time_prekey() && init.uses_pq_one_time_prekey());
        let AcceptedInitial::Accepted { first_message, .. } = bob
            .accept_initial_v2(&alice.identity_key(), &PeerPqState::default(), init, mb)
            .unwrap()
        else {
            panic!("expected a session using the refilled keys");
        };
        assert_eq!(first_message, b"refilled");
    }

    #[tokio::test]
    async fn v2_trailing_carried_pq_initial_across_expired_page() {
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
                ExpiringMailbox::new(mb_inner.clone(), vec![1]),
                |_| PeerPqState::default(),
            )
            .await
            .unwrap()
            .outcomes;
        let (
            _,
            AcceptedInitial::Accepted {
                session: mut bob_session,
                ..
            },
        ) = outcomes.pop().unwrap()
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

        let rx = bob_session.receive_v2(&bob, AUDIENCE).await.unwrap();
        assert_eq!(rx.len(), 1);
        assert_eq!(
            rx[0].content.as_ref().unwrap_err().kind(),
            ErrorKind::Expired
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
                ExpiringMailbox::new(mb_inner, vec![999]),
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
        let _ = InitialMessageV2::decode_carried(&[]);
    }

    #[tokio::test]
    async fn v2_expired_envelope_carried_initial_survives_ok_duplicate_and_evicted() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb_inner = DualMailbox::with_limits(
            store,
            AUDIENCE,
            MailboxLimits {
                max_fetch: 50,
                ..MailboxLimits::default()
            },
        );
        let expired_seqs = Arc::new(Mutex::new(Vec::new()));
        let bob_mb = ExpiringMailbox::with_shared(mb_inner.clone(), expired_seqs.clone());

        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(hs);
        bob.publish_v2(AUDIENCE, 10, 10).await.unwrap();

        let mut alice_old = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"v2-init-0",
                mb_inner.clone(),
            )
            .await
            .unwrap();
        let mut outcomes = bob
            .list_and_accept_v2(AUDIENCE, 10, bob_mb, |_| PeerPqState::default())
            .await
            .unwrap()
            .outcomes;
        let (
            _,
            AcceptedInitial::Accepted {
                session: mut bob_session,
                ..
            },
        ) = outcomes.pop().unwrap()
        else {
            panic!("expected accepted");
        };
        bob_session.send_v2(b"v2-ack-0").await.unwrap();
        assert_eq!(
            alice_old.receive_v2(&alice, AUDIENCE).await.unwrap()[0]
                .content
                .as_deref()
                .unwrap(),
            b"v2-ack-0"
        );

        let evicted_msg = alice_old.encrypt(b"v2-evicted-0").unwrap();
        for _ in 1..600 {
            let _ = alice_old.encrypt(b"gap").unwrap();
        }
        let msg600 = alice_old.encrypt(b"v2-600").unwrap();
        for _ in 601..1200 {
            let _ = alice_old.encrypt(b"gap").unwrap();
        }
        let msg1200 = alice_old.encrypt(b"v2-1200").unwrap();
        let ok_msg = alice_old.encrypt(b"v2-ok-after-expired").unwrap();
        alice_old.push_v2(msg600).await.unwrap();
        alice_old.push_v2(msg1200.clone()).await.unwrap();
        assert_eq!(
            bob_session.receive_v2(&bob, AUDIENCE).await.unwrap().len(),
            2
        );

        for (case_name, greeting, follow_up) in [
            ("Ok", &b"v2-carried-ok"[..], ok_msg),
            ("DuplicateMessage", &b"v2-carried-dup"[..], msg1200),
            ("EvictedMessage", &b"v2-carried-evicted"[..], evicted_msg),
        ] {
            let mut alice_new = alice
                .initiate_v2(
                    AUDIENCE,
                    &bob.identity_key(),
                    &PeerPqState::default(),
                    greeting,
                    mb_inner.clone(),
                )
                .await
                .unwrap();
            let dropped = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
            bob.ack_initial_messages_v2(AUDIENCE, vec![dropped.messages[0].id])
                .await
                .unwrap();

            let exp_seq = alice_new.send_v2(b"expires").await.unwrap();
            expired_seqs.lock().unwrap().push(exp_seq);
            if case_name == "DuplicateMessage" {
                let mut req = alice_old.push_v2_request_with_id(follow_up, Some([0x77; 16]));
                req.client_message_id = Bytes::copy_from_slice(&[0x77; 16]);
                mb_inner.push_v2(req).await.unwrap();
            } else {
                alice_old.push_v2(follow_up).await.unwrap();
            }

            let rx = bob_session.receive_v2(&bob, AUDIENCE).await.unwrap();
            assert_eq!(rx.len(), 2, "{case_name}: unexpected {rx:?}");
            match case_name {
                "Ok" => assert_eq!(rx[0].content.as_deref().unwrap(), b"v2-ok-after-expired"),
                "DuplicateMessage" => assert_eq!(
                    rx[0].content.as_ref().unwrap_err().kind(),
                    ErrorKind::DuplicateMessage
                ),
                "EvictedMessage" => assert!(rx[0].is_evicted()),
                _ => unreachable!(),
            }
            assert_eq!(
                rx[1].content.as_ref().unwrap_err().kind(),
                ErrorKind::Expired
            );
            assert_eq!(rx[1].initial_messages.len(), 1);
            assert!(rx[1].initial_messages[0].is_pq());
            let AcceptedInitial::Accepted { first_message, .. } = bob
                .accept_initial_v2(
                    &alice.identity_key(),
                    &PeerPqState::default(),
                    &rx[1].initial_messages[0],
                    mb_inner.clone(),
                )
                .unwrap()
            else {
                panic!("{case_name}: expected carried PQ initial to accept");
            };
            assert_eq!(first_message, greeting);
        }
    }

    #[tokio::test]
    async fn v2_infinite_expired_pages_relay_terminates_cleanly() {
        let store = SharedStore::default();
        let hs = DualHandshake::new(store, AUDIENCE);
        let fetches = Arc::new(AtomicUsize::new(0));
        let mb = InfiniteExpiredMailbox {
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

    #[tokio::test]
    async fn v2_list_initial_messages_filters_zero_oversized_and_unsafe_ids() {
        // 1. Mixed malformed + oversized IDs from an attacking server omit unsafe IDs before
        //    acceptance and signed ack.
        let store = SharedStore::default();
        let hs = DualHandshake::new(store, AUDIENCE);
        let mut alice = Client::new(hs.clone());
        let mut bob = Client::new(AttackingHandshake {
            inner: hs.clone(),
            attack: AttackMode::MixedInboxIds,
        });
        bob.publish_v2(AUDIENCE, 1, 1).await.unwrap();
        let initial = alice
            .prepare_initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"first",
                (),
            )
            .await
            .unwrap();
        alice
            .send_prepared_initiate_v2(&initial.request)
            .await
            .unwrap();
        let listed = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
        assert_eq!(
            listed.messages.iter().map(|m| m.id).collect::<Vec<_>>(),
            [1]
        );
        assert_eq!(listed.malformed_ids, [2]);
        let mut wire = initial.request.message.unwrap();
        for id in [0, protocol::MAX_SAFE_INTEGER] {
            wire.id = id;
            assert_eq!(InitialMessageV2::try_from(&wire).unwrap().id, id);
        }
        for id in [protocol::MAX_SAFE_INTEGER + 1, u64::MAX] {
            wire.id = id;
            assert_eq!(
                InitialMessageV2::try_from(&wire).unwrap_err().kind(),
                ErrorKind::InvalidInitialMessage
            );
        }
        let outcome = bob
            .list_and_accept_v2(AUDIENCE, 10, (), |_| PeerPqState::default())
            .await
            .unwrap();
        assert!(outcome.ack_error.is_none());
        assert!(outcome.unacked_ids.is_empty());
        assert_eq!(outcome.outcomes.len(), 1);
        assert!(
            bob.list_initial_messages_v2(AUDIENCE, 10)
                .await
                .unwrap()
                .messages
                .is_empty()
        );

        // 2. Scripted inbox with `id == 0` and `id > MAX_SAFE_INTEGER` skips both without
        //    consuming prekeys or acknowledging invalid IDs.
        #[derive(Clone)]
        struct ScriptedListHandshake {
            inner: DualHandshake,
            listed: Arc<Mutex<Vec<protocol::handshake_v2::InitialMessageV2>>>,
            acked: Arc<Mutex<Vec<u64>>>,
        }
        impl LocalHandshakeV2 for ScriptedListHandshake {
            async fn get_server_info(
                &self,
                r: GetServerInfoRequest,
            ) -> protocol::Result<GetServerInfoResponse> {
                self.inner.get_server_info(r).await
            }
            async fn publish_v2(&self, r: PublishV2Request) -> protocol::Result<PublishV2Response> {
                self.inner.publish_v2(r).await
            }
            async fn refill_prekeys(
                &self,
                r: RefillPrekeysRequest,
            ) -> protocol::Result<RefillPrekeysResponse> {
                self.inner.refill_prekeys(r).await
            }
            async fn get_manifest(
                &self,
                r: GetManifestRequest,
            ) -> protocol::Result<GetManifestResponse> {
                self.inner.get_manifest(r).await
            }
            async fn claim_bundle(
                &self,
                r: ClaimBundleRequest,
            ) -> protocol::Result<ClaimBundleResponse> {
                self.inner.claim_bundle(r).await
            }
            async fn send_initial_v2(
                &self,
                r: SendInitialV2Request,
            ) -> protocol::Result<SendInitialV2Response> {
                self.inner.send_initial_v2(r).await
            }
            async fn list_initial_messages(
                &self,
                _: ListInitialMessagesRequest,
            ) -> protocol::Result<ListInitialMessagesResponse> {
                Ok(ListInitialMessagesResponse {
                    messages: self.listed.lock().unwrap().clone(),
                })
            }
            async fn ack_initial_messages(
                &self,
                r: AckInitialMessagesRequest,
            ) -> protocol::Result<AckInitialMessagesResponse> {
                self.acked.lock().unwrap().extend(r.ids.iter().copied());
                Ok(AckInitialMessagesResponse {
                    deleted: r.ids.len() as u32,
                })
            }
        }

        let store2 = SharedStore::default();
        let inner = DualHandshake::new(store2.clone(), AUDIENCE);
        let mb = DualMailbox::new(store2, AUDIENCE);
        let listed_rows = Arc::new(Mutex::new(Vec::new()));
        let acked = Arc::new(Mutex::new(Vec::new()));
        let mut carol = Client::new(inner.clone());
        let mut dave = Client::new(inner.clone());
        let mut erin = Client::new(inner.clone());
        let mut receiver = Client::new(ScriptedListHandshake {
            inner: inner.clone(),
            listed: listed_rows.clone(),
            acked: acked.clone(),
        });
        receiver.publish_v2(AUDIENCE, 4, 4).await.unwrap();

        let mut zero_id = carol
            .prepare_initiate_v2(
                AUDIENCE,
                &receiver.identity_key(),
                &PeerPqState::default(),
                b"zero-id",
                mb.clone(),
            )
            .await
            .unwrap()
            .request
            .message
            .unwrap();
        zero_id.id = 0;
        let mut oversized_id = dave
            .prepare_initiate_v2(
                AUDIENCE,
                &receiver.identity_key(),
                &PeerPqState::default(),
                b"oversized-id",
                mb.clone(),
            )
            .await
            .unwrap()
            .request
            .message
            .unwrap();
        oversized_id.id = protocol::MAX_SAFE_INTEGER + 1;
        let mut valid_id = erin
            .prepare_initiate_v2(
                AUDIENCE,
                &receiver.identity_key(),
                &PeerPqState::default(),
                b"valid-id",
                mb.clone(),
            )
            .await
            .unwrap()
            .request
            .message
            .unwrap();
        valid_id.id = 42;

        *listed_rows.lock().unwrap() = vec![
            zero_id,
            protocol::handshake_v2::InitialMessageV2 {
                id: 0,
                version: 99,
                ..Default::default()
            },
            oversized_id,
            valid_id,
            protocol::handshake_v2::InitialMessageV2 {
                id: 43,
                version: 99,
                ..Default::default()
            },
        ];

        let page = receiver
            .list_initial_messages_v2(AUDIENCE, 10)
            .await
            .unwrap();
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].id, 42);
        assert_eq!(page.malformed_ids, vec![43]);

        let suite = PqConfig::default_suite();
        let classical_before = receiver.current_one_time_count();
        let pq_before = receiver.current_pq_one_time_count(suite);
        let outcome = receiver
            .list_and_accept_v2(AUDIENCE, 10, mb, |_| PeerPqState::default())
            .await
            .unwrap();
        assert_eq!(outcome.outcomes.len(), 1);
        assert_eq!(outcome.outcomes[0].0, erin.identity_key());
        assert_eq!(receiver.current_one_time_count(), classical_before - 1);
        assert_eq!(receiver.current_pq_one_time_count(suite), pq_before - 1);
        assert_eq!(*acked.lock().unwrap(), vec![43, 42]);
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
            .unwrap()
            .outcomes;
        let mut b_in = bob
            .list_and_accept_v2(AUDIENCE, 10, mb.clone(), |_| {
                bob_session.peer_pq_state().clone()
            })
            .await
            .unwrap()
            .outcomes;
        let (_, AcceptedInitial::Accepted { session: a_acc, .. }) = a_in.pop().unwrap() else {
            panic!("expected accepted");
        };
        let (_, AcceptedInitial::Accepted { session: b_acc, .. }) = b_in.pop().unwrap() else {
            panic!("expected accepted");
        };

        let _ = alice_session.accept_replacement(a_acc).unwrap();
        let _ = bob_session.accept_replacement(b_acc).unwrap();

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
        assert_eq!(
            alice_session
                .accept_replacement(quarantined)
                .unwrap_err()
                .kind(),
            ErrorKind::DowngradeDetected
        );
        assert_eq!(alice_session.active_id(), Some(&active_before));
    }

    #[cfg(feature = "prost")]
    #[tokio::test]
    async fn prost_roundtrip_preserves_pq_client_and_session_state() {
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
                b"prost-pq",
                mb,
            )
            .await
            .unwrap();
        assert!(
            alice_session
                .peer_pq_state()
                .pinned_manifest_digest
                .is_some()
        );

        let client_proto = session::proto::ClientState::from(bob.state());
        let client_bytes = prost::Message::encode_to_vec(&client_proto);
        let client_decoded =
            <session::proto::ClientState as prost::Message>::decode(client_bytes.as_slice())
                .unwrap();
        let client_restored = session::ClientState::try_from(&client_decoded).unwrap();
        assert_eq!(client_restored.pq_config(), bob.pq_config());

        let sess_proto = session::proto::SessionState::from(alice_session.state());
        let sess_bytes = prost::Message::encode_to_vec(&sess_proto);
        let sess_decoded =
            <session::proto::SessionState as prost::Message>::decode(sess_bytes.as_slice())
                .unwrap();
        let sess_restored = session::SessionState::try_from(&sess_decoded).unwrap();
        assert_eq!(sess_restored.security(), alice_session.security());
        assert_eq!(sess_restored.peer_pq_state(), alice_session.peer_pq_state());
    }

    #[tokio::test]
    async fn permanent_inbox_errors_like_low_order_sender_are_acked_and_cleared() {
        use storage::LocalPqHandshakeStore as _;

        let store = SharedStore::default();
        let hs = DualHandshake::new(store.clone(), AUDIENCE);
        let mb = DualMailbox::new(store.clone(), AUDIENCE);

        let mut bob = Client::new(hs.clone());
        bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        let bob_spk = bob.current_signed_prekey().unwrap();

        // Low-order Curve25519 point (u = 1) is now rejected at the server boundary (`Malformed`),
        // AND if a malicious/legacy relay still serves one from `list_initial_messages`,
        // `list_and_accept_v2` rejects it with `InvalidKeys` and acknowledges + clears it so
        // Bob's inbox cannot be permanently DoSed.
        let mut low_order_sender = [0u8; 32];
        low_order_sender[0] = 1;
        let valid_ephemeral = Client::new(()).identity_key();
        assert_eq!(
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
            .unwrap_err()
            .kind(),
            protocol::ErrorKind::Malformed
        );

        // Inject directly into storage to simulate a compromised relay returning the row.
        store
            .add_initial_message_v2(
                storage::StoredInitialMessageV2 {
                    id: 0,
                    version: 1,
                    sender: low_order_sender,
                    recipient: bob.identity_key(),
                    ephemeral_key: valid_ephemeral,
                    signed_prekey: bob_spk,
                    one_time_prekey: None,
                    header: Bytes::from_static(b"hdr"),
                    content: Bytes::from_static(b"body"),
                    pq_suite: None,
                    pq_last_resort: false,
                    pq_prekey_id: None,
                    pq_ciphertext: None,
                    manifest_digest: None,
                },
                10,
            )
            .await
            .unwrap()
            .unwrap();

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

        let outcomes = bob
            .list_and_accept_v2(AUDIENCE, 10, mb, |_| PeerPqState::default())
            .await
            .unwrap()
            .outcomes;
        assert!(outcomes.is_empty());
        assert!(
            bob.list_initial_messages_v2(AUDIENCE, 10)
                .await
                .unwrap()
                .messages
                .is_empty()
        );
    }
}
