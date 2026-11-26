//! End-to-end tests for universal v2 wire protocol, PQXDH (ML-KEM-1024 / ML-KEM-768), PQ KEM
//! ratcheting, cursor-paginated two-phase inbox list/accept/ack, unified sealed-sender-lite
//! mailbox & write-token grants, sealing-session `Sealed` binding, and crossed starts.

mod common;

use bytes::Bytes;
use protocol::handshake_v2::LocalHandshakeV2;
use session::{
    AcceptedInitial, Client, ErrorKind, PeerPqState, PqConfig, PublishV2Outcome, SessionSecurity,
};

use common::{
    AUDIENCE, SharedStore, UnimplementedV2Server, V2OnlyHandshake, V2OnlyMailbox, receive_for,
    register_active_grant,
};

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

    // 1. `fetch_server_info` reports v2 server_id.
    let info = alice.fetch_server_info(AUDIENCE).await.unwrap();
    assert_eq!(info.server_id, AUDIENCE);

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
    register_active_grant(&mut alice, &alice_session, &mb).await;

    // 6. Two-phase `list_initial_messages_v2` -> `accept_initial_v2` -> `ack_initial_messages_v2`.
    let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    assert_eq!(listed.messages.len(), 1);
    assert!(!listed.has_more);
    assert_eq!(listed.next_after_id, Some(listed.messages[0].id));
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
        bob.list_initial_messages_v2(AUDIENCE, 0, 10)
            .await
            .unwrap()
            .messages
            .is_empty()
    );

    // 7. Write token rejected before Bob registers grant, then idempotent `push_v2` + unified
    //    `fetch_mailbox_v2` + `decrypt_envelope`.
    let sealed = alice_session.encrypt(b"ping-v2").unwrap();
    let rejected = alice_session.push_v2(&sealed).await.unwrap_err();
    assert_eq!(rejected.kind(), ErrorKind::WriteTokenRejected);
    assert!(rejected.is_server_refusal());

    register_active_grant(&mut bob, &bob_session, &mb).await;
    let seq1 = alice_session.push_v2(&sealed).await.unwrap();
    let seq2 = alice_session.push_v2(&sealed).await.unwrap();
    assert_eq!(seq1, seq2, "idempotent push_v2 retry must deduplicate");

    let received = receive_for(&mut bob, &mut bob_session, &mb).await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].as_ref().unwrap().content, b"ping-v2");

    // 8. `initiate_v2` + `list_initial_messages_v2` + synchronous `accept_listed_v2` + ack.
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
    let page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let batch = bob.accept_listed_v2(&page, mb, |_| PeerPqState::default());
    assert_eq!(batch.outcomes.len(), 1);
    assert_eq!(batch.outcomes[0].0, carol.identity_key());
    assert_eq!(batch.ack_ids.len(), 1);
    assert!(batch.replayed_ids.is_empty());
    assert!(batch.unsupported.is_empty());
    assert!(batch.rejected.is_empty());
    bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
        .await
        .unwrap();

    // 9. Audience-bound notify subscriptions work on v2-only `Client`.
    let now = alice.clock().now();
    let sub = alice.subscription_for_audience(AUDIENCE).unwrap();
    assert_eq!(sub.audience, AUDIENCE);
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
    assert_eq!(sub_canonical.audience, "relay.example");
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
            .list_initial_messages_v2(AUDIENCE, 0, 10)
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
        sender
            .fetch_mailbox_v2(&UnimplementedV2Server, AUDIENCE, 10)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Unimplemented
    );
}

#[tokio::test]
async fn unified_mailbox_multi_peer_routing_pinned_grants_revocation_and_write_token_connect_status()
 {
    use protocol::connect::{ConnectClient, LocalPost, ProcedureV2};

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
    alice.publish_v2(AUDIENCE, 10, 0).await.unwrap();
    bob.publish_v2(AUDIENCE, 10, 0).await.unwrap();
    carol.publish_v2(AUDIENCE, 10, 0).await.unwrap();

    // Establish Alice -> Bob (session S1) and Carol -> Bob.
    let mut alice_s1 = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"a-s1",
            mb.clone(),
        )
        .await
        .unwrap();
    let mut carol_sess = carol
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"c-s1",
            mb.clone(),
        )
        .await
        .unwrap();

    let page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let batch = bob.accept_listed_v2(&page, mb.clone(), |_| PeerPqState::default());
    bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
        .await
        .unwrap();
    let mut bob_alice = None;
    let mut bob_carol = None;
    for (peer, outcome) in batch.outcomes {
        let AcceptedInitial::Accepted { session, .. } = outcome else {
            panic!("expected accepted");
        };
        if peer == alice.identity_key() {
            bob_alice = Some(session);
        } else if peer == carol.identity_key() {
            bob_carol = Some(session);
        }
    }
    let mut bob_alice = bob_alice.unwrap();
    let mut bob_carol = bob_carol.unwrap();

    // Register S1 pinned active for Alice, and Carol's pinned grant for Carol.
    let s1_hash = bob_alice.active_inbound_token_hash().unwrap();
    let s1_ver = bob.allocate_grant_version().unwrap();
    bob.register_write_token_v2(&mb, AUDIENCE, &alice.identity_key(), &s1_hash, s1_ver, true)
        .await
        .unwrap();
    register_active_grant(&mut bob, &bob_carol, &mb).await;

    // Register 4 additional unpinned grants on Carol's slot (total 5 -> oldest unpinned evicted,
    // while Carol's pinned active grant MUST survive!).
    for i in 1u8..=4 {
        let h = [i; 32];
        let v = bob.allocate_grant_version().unwrap();
        bob.register_write_token_v2(&mb, AUDIENCE, &carol.identity_key(), &h, v, false)
            .await
            .unwrap();
    }

    // Alice rotates locally to S2; seal on S1 before rotation to prove earlier session routing &
    // sealing-session binding!
    let sealed_on_s1 = alice_s1.encrypt(b"from-alice-s1").unwrap();
    alice
        .start_again_v2(AUDIENCE, &mut alice_s1, b"a-s2")
        .await
        .unwrap();
    let page2 = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let batch2 = bob.accept_listed_v2(&page2, mb.clone(), |_| PeerPqState::default());
    bob.ack_initial_messages_v2(AUDIENCE, batch2.ack_ids)
        .await
        .unwrap();
    let (
        _,
        AcceptedInitial::Accepted {
            session: bob_s2, ..
        },
    ) = batch2.outcomes.into_iter().next().unwrap()
    else {
        panic!("expected accepted s2");
    };
    assert!(bob_alice.accept_replacement(bob_s2).unwrap());
    // Bob now has BOTH S2 (active) and S1 (earlier) in `inbound_token_hashes()`.
    let all_alice_hashes: Vec<[u8; 32]> = bob_alice.inbound_token_hashes().collect();
    assert_eq!(all_alice_hashes.len(), 2);
    assert!(all_alice_hashes.contains(&s1_hash));
    let s2_hash = bob_alice.active_inbound_token_hash().unwrap();
    assert!(all_alice_hashes.contains(&s2_hash));
    assert_ne!(s1_hash, s2_hash);

    // Register S2 pinned active on Bob's relay (replaces pin on S1; S1 stays valid as unpinned
    // earlier grant while oldest unpinned dummy grant is evicted).
    register_active_grant(&mut bob, &bob_alice, &mb).await;

    // Push S1's pre-rotation Sealed, S2's new message, and Carol's message -> unified mailbox!
    alice_s1.push_v2(&sealed_on_s1).await.unwrap();
    alice_s1.send_v2(b"from-alice-s2").await.unwrap();
    carol_sess.send_v2(b"from-carol").await.unwrap();

    // Single unified `fetch_mailbox_v2` routes O(1) by `token_hash` across Alice's earlier S1,
    // Alice's active S2, and Carol's active session!
    let unified = bob.fetch_mailbox_v2(&mb, AUDIENCE, 100).await.unwrap();
    assert_eq!(unified.messages.len(), 3);
    let mut alice_msgs = Vec::new();
    let mut carol_msgs = Vec::new();
    for env in &unified.messages {
        let th: [u8; 32] = env.token_hash.as_ref().try_into().unwrap();
        let msg = env.message.as_ref().unwrap();
        if bob_alice.inbound_token_hashes().any(|h| h == th) {
            let dec = bob_alice.decrypt_envelope(msg).unwrap();
            alice_msgs.push((dec.content, dec.earlier));
        } else if bob_carol.inbound_token_hashes().any(|h| h == th) {
            let dec = bob_carol.decrypt_envelope(msg).unwrap();
            carol_msgs.push((dec.content, dec.earlier));
        } else {
            panic!("unexpected token_hash");
        }
    }
    assert_eq!(
        alice_msgs,
        vec![
            (b"from-alice-s1".to_vec(), true),
            (b"from-alice-s2".to_vec(), false),
        ]
    );
    assert_eq!(carol_msgs, vec![(b"from-carol".to_vec(), false)]);
    let last_seq = unified.last_sequence().unwrap();
    bob.commit_mailbox_page(last_seq, last_seq).unwrap();
    assert_eq!(bob.ack_mailbox_v2(&mb, AUDIENCE).await.unwrap(), 3);

    // Revoke ALL Alice grants (chat delete) -> Alice's pushes fail with WriteTokenRejected,
    // stale grant_version is rejected, recreated chat with higher grant_version succeeds!
    let revoke_ver = bob.allocate_grant_version().unwrap();
    let alice_slot = bob.peer_slot_id(&alice.identity_key());
    let revoked = bob
        .revoke_write_token_v2(&mb, AUDIENCE, &alice_slot, None, revoke_ver)
        .await
        .unwrap();
    assert!(revoked >= 2);
    let err = alice_s1.send_v2(b"blocked").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WriteTokenRejected);
    assert!(err.is_server_refusal());

    // Registering with version <= revoke_ver is definitively refused (`StaleVersion` -> `Protocol`
    // with `is_server_refusal() == true`), while a fresh monotonic version > revoke_ver succeeds.
    let stale_reg = bob
        .register_write_token_v2(
            &mb,
            AUDIENCE,
            &alice.identity_key(),
            &s2_hash,
            revoke_ver,
            true,
        )
        .await
        .unwrap_err();
    assert_eq!(stale_reg.kind(), ErrorKind::Protocol);
    assert!(stale_reg.is_server_refusal());

    let recreated_ver = bob.allocate_grant_version().unwrap();
    assert!(recreated_ver > revoke_ver);
    bob.register_write_token_v2(
        &mb,
        AUDIENCE,
        &alice.identity_key(),
        &s2_hash,
        recreated_ver,
        true,
    )
    .await
    .unwrap();
    alice_s1.send_v2(b"recreated-ok").await.unwrap();
    let rx = receive_for(&mut bob, &mut bob_alice, &mb).await;
    assert_eq!(rx[0].as_ref().unwrap().content, b"recreated-ok");

    // Verify Connect HTTP 409 mapping: Connect JSON `{"code":"aborted"}` -> WriteTokenRejected
    // (`is_server_refusal() == true`), while bare non-JSON proxy HTTP 409 -> Server (`false`).
    #[derive(Clone, Copy)]
    enum Status409 {
        ConnectAborted,
        BareProxy409,
    }
    impl LocalPost for Status409 {
        async fn post(&self, path: &str, _: Vec<u8>) -> protocol::Result<(u16, Vec<u8>)> {
            assert_eq!(path, ProcedureV2::PushV2.path());
            match self {
                Self::ConnectAborted => {
                    let resp = protocol::connect::error(
                        protocol::ErrorKind::WriteTokenRejected,
                        "write token rejected",
                    );
                    Ok((resp.status, resp.body))
                }
                Self::BareProxy409 => Ok((409, b"<html>Conflict</html>".to_vec())),
            }
        }
    }
    let sealed_probe = alice_s1.encrypt(b"probe").unwrap();
    let s_connect = alice
        .prepare_initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"probe-connect",
            ConnectClient::new(Status409::ConnectAborted),
        )
        .await
        .unwrap()
        .session;
    let err_connect = s_connect.push_v2(&sealed_probe).await.unwrap_err();
    assert_eq!(err_connect.kind(), ErrorKind::WriteTokenRejected);
    assert!(err_connect.is_server_refusal());
    assert!(err_connect.is_connect_error());

    let s_bare = alice
        .prepare_initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"probe-bare",
            ConnectClient::new(Status409::BareProxy409),
        )
        .await
        .unwrap()
        .session;
    let err_bare = s_bare.push_v2(&sealed_probe).await.unwrap_err();
    assert_eq!(err_bare.kind(), ErrorKind::Server);
    assert!(!err_bare.is_server_refusal());
}

#[tokio::test]
async fn inbox_cursor_pagination_drains_multi_page_and_recovers_after_pre_ack_crash() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);
    let classical_cfg = PqConfig {
        pq_enabled: false,
        ..PqConfig::default()
    };

    let mut bob = Client::new(hs.clone())
        .with_pq_config(classical_cfg.clone())
        .unwrap();
    bob.publish_v2(AUDIENCE, 10, 0).await.unwrap();

    // Queue 5 initial messages from 5 distinct senders.
    let mut senders = Vec::new();
    for i in 0..5u8 {
        let mut s = Client::new(hs.clone())
            .with_pq_config(classical_cfg.clone())
            .unwrap();
        let _ = s
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                format!("msg-{i}").as_bytes(),
                mb.clone(),
            )
            .await
            .unwrap();
        senders.push(s.identity_key());
    }

    // Paginate strictly with `limit = 2` using `after_id` / `next_after_id` / `has_more` WITHOUT
    // acking yet, proving cursor pagination advances through every page cleanly.
    let mut after_id = 0u64;
    let mut seen_senders = Vec::new();
    let mut all_ack_ids = Vec::new();
    let mut pages = 0usize;
    loop {
        let page = bob
            .list_initial_messages_v2(AUDIENCE, after_id, 2)
            .await
            .unwrap();
        pages += 1;
        let batch = bob.accept_listed_v2(&page, mb.clone(), |_| PeerPqState::default());
        assert!(batch.replayed_ids.is_empty());
        assert!(batch.unsupported.is_empty());
        assert!(batch.rejected.is_empty());
        for (peer, outcome) in batch.outcomes {
            assert!(matches!(outcome, AcceptedInitial::Accepted { .. }));
            seen_senders.push(peer);
        }
        all_ack_ids.extend(batch.ack_ids);
        if !batch.has_more {
            break;
        }
        after_id = batch.next_after_id.expect("has_more implies next_after_id");
    }
    assert_eq!(pages, 3);
    assert_eq!(seen_senders, senders);
    assert_eq!(all_ack_ids.len(), 5);

    // Simulate post-persist / pre-ack crash: nothing was acked on the server yet, so re-listing
    // from `after_id = 0` yields all 5 messages again. `accept_listed_v2` MUST treat every one as
    // `replayed_ids` (zero double-accepts in `outcomes`, zero errors in `rejected`) and re-queue
    // all 5 IDs in `ack_ids`!
    let replay_page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    assert_eq!(replay_page.messages.len(), 5);
    assert!(!replay_page.has_more);
    let replay_batch = bob.accept_listed_v2(&replay_page, mb, |_| PeerPqState::default());
    assert!(replay_batch.outcomes.is_empty());
    assert!(replay_batch.rejected.is_empty());
    assert!(replay_batch.unsupported.is_empty());
    assert_eq!(replay_batch.replayed_ids, all_ack_ids);
    assert_eq!(replay_batch.ack_ids, all_ack_ids);

    assert_eq!(
        bob.ack_initial_messages_v2(AUDIENCE, replay_batch.ack_ids)
            .await
            .unwrap(),
        5
    );
    assert!(
        bob.list_initial_messages_v2(AUDIENCE, 0, 10)
            .await
            .unwrap()
            .messages
            .is_empty()
    );
}

#[cfg(not(all(feature = "ml-kem-1024", feature = "ml-kem-768")))]
#[tokio::test]
async fn cursor_pagination_advances_past_unsupported_suite_head_of_line_blocking() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let classical_cfg = PqConfig {
        pq_enabled: false,
        ..PqConfig::default()
    };

    let alice_unsupported = Client::new(hs.clone());
    let mut carol = Client::new(hs.clone())
        .with_pq_config(classical_cfg.clone())
        .unwrap();
    let mut bob = Client::new(hs.clone())
        .with_pq_config(classical_cfg)
        .unwrap();
    bob.publish_v2(AUDIENCE, 4, 0).await.unwrap();

    // Pick a valid PqSuite ID that is NOT compiled in this build.
    let (unsupported_suite_id, ct_len) = if cfg!(not(feature = "ml-kem-1024")) {
        (1u32, 1568usize)
    } else {
        (2u32, 1088usize)
    };

    // Enqueue 2 uncompiled-suite PQ initials at the head of Bob's inbox, followed by Carol's valid
    // classical initial.
    for _ in 0..2 {
        let eph = Client::new(()).identity_key();
        let wire = protocol::handshake_v2::InitialMessageV2 {
            id: 0,
            version: 2,
            identity_key: Bytes::copy_from_slice(&alice_unsupported.identity_key()),
            ephemeral_key: Bytes::copy_from_slice(&eph),
            signed_prekey: Bytes::copy_from_slice(&bob.current_signed_prekey().unwrap()),
            one_time_prekey: None,
            first_message: Some(party::EncryptedMessage::default()),
            pq_suite: unsupported_suite_id,
            pq_last_resort: true,
            pq_prekey_id: Bytes::from_static(&[9u8; 32]),
            pq_ciphertext: Bytes::from(vec![0x55; ct_len]),
            manifest_digest: Bytes::new(),
        };
        let queued = hs
            .send_initial_v2(protocol::handshake_v2::SendInitialV2Request {
                recipient: Bytes::copy_from_slice(&bob.identity_key()),
                message: Some(wire),
            })
            .await
            .unwrap();
        assert!(queued.id > 0);
    }

    let _carol_sess = carol
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"behind-unsupported-suite",
            (),
        )
        .await
        .unwrap();

    // Page 1 (`limit = 2`, `after_id = 0`): hits the 2 UnsupportedSuite items, leaves them
    // UNACKED (`ack_ids` empty!), and sets `has_more = true`, `next_after_id = Some(2)`.
    let page1 = bob.list_initial_messages_v2(AUDIENCE, 0, 2).await.unwrap();
    assert_eq!(page1.messages.len(), 2);
    assert!(page1.has_more);
    assert_eq!(page1.next_after_id, Some(2));
    let batch1 = bob.accept_listed_v2(&page1, (), |_| PeerPqState::default());
    assert!(batch1.outcomes.is_empty());
    assert!(batch1.ack_ids.is_empty());
    assert_eq!(batch1.unsupported.len(), 2);

    // Page 2 (`after_id = 2`): advances right past the head-of-line UnsupportedSuite items and
    // accepts Carol's valid message!
    let page2 = bob
        .list_initial_messages_v2(AUDIENCE, batch1.next_after_id.unwrap(), 2)
        .await
        .unwrap();
    assert_eq!(page2.messages.len(), 1);
    assert!(!page2.has_more);
    let batch2 = bob.accept_listed_v2(&page2, (), |_| PeerPqState::default());
    assert_eq!(batch2.outcomes.len(), 1);
    let (peer, AcceptedInitial::Accepted { first_message, .. }) = &batch2.outcomes[0] else {
        panic!("expected carol accepted on page 2");
    };
    assert_eq!(*peer, carol.identity_key());
    assert_eq!(first_message, b"behind-unsupported-suite");
    bob.ack_initial_messages_v2(AUDIENCE, batch2.ack_ids)
        .await
        .unwrap();

    // Unsupported items remain unacked on the server for a future PQ-capable build.
    let remaining = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    assert_eq!(remaining.messages.len(), 2);
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
mod pq_flow {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[cfg(feature = "ml-kem-1024")]
    use protocol::content::Kind as ContentKind;
    use protocol::handshake_v2::{
        AckInitialMessagesRequest, AckInitialMessagesResponse, ClaimBundleRequest,
        ClaimBundleResponse, GetManifestRequest, GetManifestResponse, GetServerInfoRequest,
        GetServerInfoResponse, HandshakeV2Limits, HandshakeV2Server, ListInitialMessagesRequest,
        ListInitialMessagesResponse, PublishV2Request, PublishV2Response, RefillPrekeysRequest,
        RefillPrekeysResponse, SendInitialV2Request, SendInitialV2Response, ServerInfoConfig,
    };
    use session::{InitialMessageV2, PqSuite};

    use common::{AttackMode, AttackingHandshake, InterruptedPost, hello_bytes};

    #[cfg(feature = "ml-kem-1024")]
    #[tokio::test]
    async fn pqxdh_and_pq_ratchet_ml_kem_1024_end_to_end() {
        let store = SharedStore::default();
        let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
        let mb = V2OnlyMailbox::new(store, AUDIENCE);

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

        alice.publish_v2(AUDIENCE, 2, 2).await.unwrap();
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
        register_active_grant(&mut alice, &alice_session, &mb).await;

        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
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
        register_active_grant(&mut bob, &session, &mb).await;

        let sealed = alice_session.encrypt(b"turn-1").unwrap();
        let seq1 = alice_session.push_v2(&sealed).await.unwrap();
        let seq1_retry = alice_session.push_v2(&sealed).await.unwrap();
        assert_eq!(seq1, seq1_retry);

        let rx = receive_for(&mut bob, &mut session, &mb).await;
        assert_eq!(rx.len(), 1);
        assert_eq!(rx[0].as_ref().unwrap().content, b"turn-1");

        for turn in 0..8 {
            let b_msg = format!("bob-{turn}");
            session.send_v2(b_msg.as_bytes()).await.unwrap();
            let got = receive_for(&mut alice, &mut alice_session, &mb).await;
            assert_eq!(got[0].as_ref().unwrap().content, b_msg.as_bytes());

            let a_msg = format!("alice-{turn}");
            alice_session.send_v2(a_msg.as_bytes()).await.unwrap();
            let got = receive_for(&mut bob, &mut session, &mb).await;
            assert_eq!(got[0].as_ref().unwrap().content, a_msg.as_bytes());
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
            let got = receive_for(&mut bob, &mut session, &mb).await;
            assert_eq!(got[0].as_ref().unwrap().content, b"after-restore");
        }
    }

    #[cfg(feature = "ml-kem-768")]
    #[tokio::test]
    async fn pqxdh_and_pq_ratchet_ml_kem_768_and_suite_selection() {
        let store = SharedStore::default();
        let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
        let mb = V2OnlyMailbox::new(store, AUDIENCE);

        let mut alice = Client::new(hs.clone())
            .with_pq_config(PqConfig {
                pq_enabled: true,
                preferred_suite: PqSuite::MlKem768,
                pq_ratchet_enabled: true,
                strict_pq: false,
            })
            .unwrap();
        let mut bob = Client::new(hs);
        alice.publish_v2(AUDIENCE, 2, 2).await.unwrap();
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
        register_active_grant(&mut alice, &alice_session, &mb).await;

        let page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let mut batch = bob.accept_listed_v2(&page, mb.clone(), |_| PeerPqState::default());
        bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
            .await
            .unwrap();
        let (
            _,
            AcceptedInitial::Accepted {
                mut session,
                first_message,
                security,
            },
        ) = batch.outcomes.pop().unwrap()
        else {
            panic!("expected accepted ML-KEM-768 session");
        };
        assert_eq!(first_message, b"hi-768");
        assert_eq!(security, SessionSecurity::pq(PqSuite::MlKem768, true));

        session.send_v2(b"reply-768").await.unwrap();
        let got = receive_for(&mut alice, &mut alice_session, &mb).await;
        assert_eq!(got[0].as_ref().unwrap().content, b"reply-768");
    }

    #[tokio::test]
    async fn pq_ratchet_can_be_toggled_off_independently() {
        let store = SharedStore::default();
        let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
        let mb = V2OnlyMailbox::new(store, AUDIENCE);

        let mut alice = Client::new(hs.clone())
            .with_pq_config(PqConfig {
                pq_enabled: true,
                preferred_suite: PqConfig::default_suite(),
                pq_ratchet_enabled: false,
                strict_pq: false,
            })
            .unwrap();
        let mut bob = Client::new(hs);
        alice.publish_v2(AUDIENCE, 2, 2).await.unwrap();
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
        register_active_grant(&mut alice, &alice_session, &mb).await;

        let page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let mut batch = bob.accept_listed_v2(&page, mb.clone(), |_| PeerPqState::default());
        bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
            .await
            .unwrap();
        let (
            _,
            AcceptedInitial::Accepted {
                mut session,
                first_message,
                security,
            },
        ) = batch.outcomes.pop().unwrap()
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
        let got = receive_for(&mut alice, &mut alice_session, &mb).await;
        assert_eq!(
            got[0].as_ref().unwrap().content,
            b"classical-ratchet-over-pqxdh"
        );
    }

    #[tokio::test]
    async fn two_phase_list_crash_retry_then_ack() {
        let store = SharedStore::default();
        let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
        let mb = V2OnlyMailbox::new(store, AUDIENCE);

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

        let first_list = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        assert_eq!(first_list.messages.len(), 1);
        let msg_id = first_list.messages[0].id;
        assert!(msg_id > 0);

        let retry_list = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
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
            bob.list_initial_messages_v2(AUDIENCE, 0, 10)
                .await
                .unwrap()
                .messages
                .is_empty()
        );
    }

    #[tokio::test]
    async fn failed_ack_preserves_accepted_sessions_and_recovers_idempotently_via_replay() {
        use protocol::connect::ConnectClient;
        for (preceding, fail_on) in [(0u64, 1usize), (200, 2)] {
            let store = SharedStore::default();
            let limit = 201usize;
            let hs = V2OnlyHandshake(Arc::new(
                HandshakeV2Server::builder(store.clone())
                    .info(ServerInfoConfig::new(AUDIENCE))
                    .limits(HandshakeV2Limits {
                        max_initial_messages: limit,
                        max_list_limit: limit,
                        ..Default::default()
                    })
                    .build(),
            ));
            let mb = V2OnlyMailbox::new(store.clone(), AUDIENCE);
            let mut alice = Client::new(hs.clone());
            let mut bob = Client::new(ConnectClient::new(InterruptedPost {
                hs,
                mb: mb.clone(),
                fail_ack_on: Some(fail_on),
                acknowledgements: Default::default(),
                lose_refill_response: false,
            }));
            bob.publish_v2(AUDIENCE, 1, 1).await.unwrap();
            for i in 0..preceding {
                let mut eph = [2u8; 32];
                eph[..8].copy_from_slice(&i.to_le_bytes());
                assert!(
                    storage::LocalPqHandshakeStore::add_initial_message_v2(
                        &store,
                        storage::StoredInitialMessageV2 {
                            id: 0,
                            version: 1,
                            sender: [0; 32],
                            recipient: bob.identity_key(),
                            ephemeral_key: eph,
                            signed_prekey: [3; 32],
                            one_time_prekey: None,
                            header: Bytes::new(),
                            content: Bytes::new(),
                            pq_suite: None,
                            pq_last_resort: false,
                            pq_prekey_id: None,
                            pq_ciphertext: None,
                            manifest_digest: None,
                        },
                        limit,
                    )
                    .await
                    .unwrap()
                    .is_some()
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

            // Synchronous `accept_listed_v2` cannot be cancelled mid-accept and returns all
            // locally confirmed sessions + full `ack_ids` before any network ACK call.
            let page = bob
                .list_initial_messages_v2(AUDIENCE, 0, limit as u32)
                .await
                .unwrap();
            let batch = bob.accept_listed_v2(&page, mb.clone(), |_| PeerPqState::default());
            assert_eq!(batch.outcomes.len(), 1);
            assert_eq!(batch.rejected.len(), preceding as usize);
            assert!(batch.replayed_ids.is_empty());
            assert_eq!(batch.ack_ids, (1..=preceding + 1).collect::<Vec<_>>());
            let (
                peer,
                AcceptedInitial::Accepted {
                    mut session,
                    first_message,
                    ..
                },
            ) = batch.outcomes.into_iter().next().unwrap()
            else {
                panic!("accepted session was lost");
            };
            assert_eq!(peer, alice.identity_key());
            assert_eq!(first_message, b"first");
            assert_eq!(bob.current_one_time_count(), 0);
            assert_eq!(bob.current_pq_one_time_count(PqConfig::default_suite()), 0);
            register_active_grant(&mut bob, &session, &mb).await;

            // Ack fails on chunk `fail_on` (leaving chunk `fail_on..` still unacked on server).
            assert!(
                bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
                    .await
                    .is_err()
            );

            // Session works immediately even while inbox ACK is pending retry.
            sender.send_v2(b"second").await.unwrap();
            assert_eq!(
                receive_for(&mut bob, &mut session, &mb).await[0]
                    .as_ref()
                    .unwrap()
                    .content,
                b"second"
            );

            // Re-list after crash/retry: remaining IDs start at `first_pending`, and Alice's
            // already-confirmed initial is detected as `replayed_ids` and re-queued in `ack_ids`!
            let first_pending = if fail_on == 1 { 1 } else { 101 };
            let expected_remaining: Vec<u64> = (first_pending..=preceding + 1).collect();
            let pending = bob
                .list_initial_messages_v2(AUDIENCE, 0, limit as u32)
                .await
                .unwrap();
            assert_eq!(
                pending.messages.iter().map(|m| m.id).collect::<Vec<_>>(),
                expected_remaining
            );
            let replay_batch = bob.accept_listed_v2(&pending, mb, |_| PeerPqState::default());
            assert!(replay_batch.outcomes.is_empty());
            assert_eq!(replay_batch.replayed_ids, vec![preceding + 1]);
            assert_eq!(replay_batch.ack_ids, expected_remaining);

            let count = replay_batch.ack_ids.len() as u32;
            assert_eq!(
                bob.ack_initial_messages_v2(AUDIENCE, replay_batch.ack_ids)
                    .await
                    .unwrap(),
                count
            );
            assert!(
                bob.list_initial_messages_v2(AUDIENCE, 0, limit as u32)
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
        let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
        let mb = V2OnlyMailbox::new(store, AUDIENCE);
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
        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 1).await.unwrap();
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
    async fn v2_list_initial_messages_filters_zero_oversized_and_unsafe_ids() {
        // 1. Mixed malformed + oversized IDs from an attacking server omit unsafe IDs before
        //    acceptance and signed ack, while tracking `next_after_id` over validated IDs.
        let store = SharedStore::default();
        let hs = V2OnlyHandshake::new(store, AUDIENCE);
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
        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        assert_eq!(
            listed.messages.iter().map(|m| m.id).collect::<Vec<_>>(),
            [1]
        );
        assert_eq!(listed.malformed_ids, [2]);
        assert_eq!(listed.next_after_id, Some(2));
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
        let batch = bob.accept_listed_v2(&listed, (), |_| PeerPqState::default());
        assert_eq!(batch.outcomes.len(), 1);
        assert_eq!(batch.ack_ids, [2, 1]);
        bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
            .await
            .unwrap();
        assert!(
            bob.list_initial_messages_v2(AUDIENCE, 0, 10)
                .await
                .unwrap()
                .messages
                .is_empty()
        );

        // 2. Scripted inbox with `id == 0` and `id > MAX_SAFE_INTEGER` skips both without
        //    consuming prekeys or acknowledging invalid IDs.
        #[derive(Clone)]
        struct ScriptedListHandshake {
            inner: V2OnlyHandshake,
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
                    has_more: false,
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
        let inner = V2OnlyHandshake::new(store2.clone(), AUDIENCE);
        let mb = V2OnlyMailbox::new(store2, AUDIENCE);
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
            .list_initial_messages_v2(AUDIENCE, 0, 10)
            .await
            .unwrap();
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].id, 42);
        assert_eq!(page.malformed_ids, vec![43]);
        assert_eq!(page.next_after_id, Some(43));

        let suite = PqConfig::default_suite();
        let classical_before = receiver.current_one_time_count();
        let pq_before = receiver.current_pq_one_time_count(suite);
        let batch = receiver.accept_listed_v2(&page, mb, |_| PeerPqState::default());
        assert_eq!(batch.outcomes.len(), 1);
        assert_eq!(batch.outcomes[0].0, erin.identity_key());
        assert_eq!(receiver.current_one_time_count(), classical_before - 1);
        assert_eq!(receiver.current_pq_one_time_count(suite), pq_before - 1);
        receiver
            .ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
            .await
            .unwrap();
        assert_eq!(*acked.lock().unwrap(), vec![43, 42]);
    }

    #[tokio::test]
    async fn pq_crossed_starts_and_pinned_classical_keep_defense() {
        let store = SharedStore::default();
        let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
        let mb = V2OnlyMailbox::new(store, AUDIENCE);

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

        let a_page = alice
            .list_initial_messages_v2(AUDIENCE, 0, 10)
            .await
            .unwrap();
        let mut a_batch = alice.accept_listed_v2(&a_page, mb.clone(), |_| {
            alice_session.peer_pq_state().clone()
        });
        alice
            .ack_initial_messages_v2(AUDIENCE, a_batch.ack_ids)
            .await
            .unwrap();

        let b_page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let mut b_batch =
            bob.accept_listed_v2(&b_page, mb.clone(), |_| bob_session.peer_pq_state().clone());
        bob.ack_initial_messages_v2(AUDIENCE, b_batch.ack_ids)
            .await
            .unwrap();

        let (_, AcceptedInitial::Accepted { session: a_acc, .. }) = a_batch.outcomes.pop().unwrap()
        else {
            panic!("expected accepted");
        };
        let (_, AcceptedInitial::Accepted { session: b_acc, .. }) = b_batch.outcomes.pop().unwrap()
        else {
            panic!("expected accepted");
        };

        let _ = alice_session.accept_replacement(a_acc).unwrap();
        let _ = bob_session.accept_replacement(b_acc).unwrap();

        assert_eq!(alice_session.active_id(), bob_session.active_id());
        assert_eq!(alice_session.peer_session_seq(), 1);
        assert_eq!(bob_session.peer_session_seq(), 1);
        assert!(alice_session.security().unwrap().is_pq);
        assert!(bob_session.security().unwrap().is_pq);

        register_active_grant(&mut alice, &alice_session, &mb).await;
        register_active_grant(&mut bob, &bob_session, &mb).await;

        alice_session.send_v2(b"converged-a").await.unwrap();
        bob_session.send_v2(b"converged-b").await.unwrap();
        assert_eq!(
            receive_for(&mut bob, &mut bob_session, &mb).await[0]
                .as_ref()
                .unwrap()
                .content,
            b"converged-a"
        );
        assert_eq!(
            receive_for(&mut alice, &mut alice_session, &mb).await[0]
                .as_ref()
                .unwrap()
                .content,
            b"converged-b"
        );

        // Bob turns PQ off and sends a classical v2 initial -> Alice quarantines it and
        // `accept_replacement` refuses silent downgrade on a PQ-pinned peer!
        bob.set_pq_config(PqConfig {
            pq_enabled: false,
            strict_pq: false,
            ..PqConfig::default()
        })
        .unwrap();
        let _bob_classical = bob
            .initiate_v2(
                AUDIENCE,
                &alice.identity_key(),
                &PeerPqState::default(),
                &hello_bytes("bob", 2, false),
                mb.clone(),
            )
            .await
            .unwrap();
        let listed = alice
            .list_initial_messages_v2(AUDIENCE, 0, 10)
            .await
            .unwrap();
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
        let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
        let mb = V2OnlyMailbox::new(store, AUDIENCE);

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
        assert_eq!(
            sess_restored.active_inbound_token_hash(),
            alice_session.active_inbound_token_hash()
        );
    }

    #[tokio::test]
    async fn permanent_inbox_errors_like_low_order_sender_are_acked_and_cleared() {
        use storage::LocalPqHandshakeStore as _;

        let store = SharedStore::default();
        let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
        let mb = V2OnlyMailbox::new(store.clone(), AUDIENCE);

        let mut bob = Client::new(hs.clone());
        bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();
        let bob_spk = bob.current_signed_prekey().unwrap();

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

        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
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

        let batch = bob.accept_listed_v2(&listed, mb, |_| PeerPqState::default());
        assert!(batch.outcomes.is_empty());
        assert_eq!(batch.rejected.len(), 1);
        assert_eq!(batch.rejected[0].2.kind(), ErrorKind::InvalidKeys);
        assert_eq!(batch.ack_ids, vec![listed.messages[0].id]);
        bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
            .await
            .unwrap();
        assert!(
            bob.list_initial_messages_v2(AUDIENCE, 0, 10)
                .await
                .unwrap()
                .messages
                .is_empty()
        );
    }
}
