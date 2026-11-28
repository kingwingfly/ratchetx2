//! End-to-end tests for PQ policy, mixed-mode quarantine, toggle flows (ON -> OFF -> ON), active
//! downgrade defense, missing-manifest `DowngradeDetected`, signed PQ-OFF classical X3DH
//! `signed_prekey_signature` verification, lock-free `claim_peer_bundle_v2` split, relay
//! `PQ_ENABLED=false` rollback, refusal provenance, and manifest preservation/expiry.

#![cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]

mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use protocol::{
    content::Hello,
    handshake_v2::{ClaimBundleRequest, GetServerInfoResponse, LocalHandshakeV2},
    mailbox_v2::LocalMailboxV2,
};
use session::{
    AcceptedInitial, Client, ErrorKind, InitialMessageV2, PeerPqState, PqConfig, PqSuite,
    SessionSecurity, check_peer_hello, claim_peer_bundle_v2,
};

use common::{
    AUDIENCE, AttackMode, AttackingHandshake, LostReply, RpcErrors, SharedStore,
    ToggleableHandshake, UnimplementedV2Server, V2OnlyHandshake, V2OnlyMailbox, hello_bytes,
    receive_for, register_active_grant,
};

async fn check_publish_v2_error(
    handshake: impl LocalHandshakeV2,
    strict: bool,
    expected: ErrorKind,
    refused: bool,
) {
    let mut client = Client::new(handshake)
        .with_pq_config(PqConfig {
            strict_pq: strict,
            ..Default::default()
        })
        .unwrap();
    client.prepare_publish_v2(AUDIENCE, 1, 1).unwrap();
    let error = client.publish_v2(AUDIENCE, 1, 1).await.unwrap_err();
    assert_eq!(error.kind(), expected);
    assert_eq!(error.is_server_refusal(), refused);
    let kept = if refused { 1 } else { 2 };
    assert_eq!(client.manifest_seq(), kept as u64);
    assert_eq!(client.current_one_time_count(), kept);
    for suite in client.pq_config().offered_suites() {
        assert_eq!(client.current_pq_one_time_count(suite), kept);
    }
}

#[tokio::test]
async fn pq_publish_rolls_back_only_confirmed_refusals() {
    use protocol::{ErrorKind as Kind, connect::ConnectClient};
    for (kind, expected) in [
        (Kind::SignInRequired, ErrorKind::SignInRequired),
        (Kind::LimitExceeded, ErrorKind::LimitExceeded),
        (Kind::Malformed, ErrorKind::Protocol),
        (Kind::InvalidSignature, ErrorKind::Protocol),
        (Kind::StaleTimestamp, ErrorKind::Protocol),
    ] {
        let confirmed = RpcErrors::new([("publish_on", kind.into())]);
        check_publish_v2_error(&confirmed, false, expected, true).await;
        let ambiguous = RpcErrors::new([(
            "publish_on",
            protocol::Error::ambiguous_response(kind, "lost reply"),
        )]);
        check_publish_v2_error(&ambiguous, false, expected, false).await;
    }

    let pq_off_info = GetServerInfoResponse {
        server_id: AUDIENCE.into(),
        pq_enabled: false,
        supported_suites: vec![],
        pq_ratchet_supported: false,
    };
    let strict_pq_off =
        RpcErrors::with_server_info(pq_off_info, [("publish_on", Kind::Unimplemented.into())]);
    check_publish_v2_error(&strict_pq_off, true, ErrorKind::PqRequired, true).await;

    let strict_missing_v2 = RpcErrors::new([
        ("publish_on", Kind::Unimplemented.into()),
        ("get_server_info", Kind::Unimplemented.into()),
    ]);
    check_publish_v2_error(&strict_missing_v2, true, ErrorKind::Unimplemented, true).await;

    for (reply, expected) in [
        (LostReply::CorruptBody, ErrorKind::InvalidResponse),
        (LostReply::Transport, ErrorKind::Server),
    ] {
        check_publish_v2_error(ConnectClient::new(reply), false, expected, false).await;
    }
}

#[tokio::test]
async fn ambiguous_unimplemented_stops_at_the_current_publish_attempt() {
    use protocol::ErrorKind::Unimplemented;
    let ambiguous = || protocol::Error::ambiguous_response(Unimplemented, "lost reply");
    for strict in [false, true] {
        let calls = RpcErrors::new([("publish_on", ambiguous())]);
        check_publish_v2_error(&calls, strict, ErrorKind::Unimplemented, false).await;
        assert!(calls.is_empty());
    }

    let pq_off_info = GetServerInfoResponse {
        server_id: AUDIENCE.into(),
        pq_enabled: false,
        supported_suites: vec![],
        pq_ratchet_supported: false,
    };
    let fallback_ambiguous = RpcErrors::with_server_info(
        pq_off_info.clone(),
        [
            ("publish_on", Unimplemented.into()),
            ("publish_off", ambiguous()),
        ],
    );
    let mut client = Client::new(&fallback_ambiguous);
    client.prepare_publish_v2(AUDIENCE, 1, 1).unwrap();
    let err = client.publish_v2(AUDIENCE, 1, 1).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unimplemented);
    assert!(!err.is_server_refusal());
    assert_eq!(client.manifest_seq(), 3);
    assert_eq!(client.current_one_time_count(), 2);
    for suite in client.pq_config().offered_suites() {
        assert_eq!(client.current_pq_one_time_count(suite), 1);
    }
    assert!(fallback_ambiguous.is_empty());

    let fallback_refused = RpcErrors::with_server_info(
        pq_off_info,
        [
            ("publish_on", Unimplemented.into()),
            ("publish_off", protocol::ErrorKind::SignInRequired.into()),
        ],
    );
    check_publish_v2_error(&fallback_refused, false, ErrorKind::SignInRequired, true).await;
    assert!(fallback_refused.is_empty());
}

#[tokio::test]
async fn v2_handshake_and_mailbox_errors_check_refusal_provenance_without_v1_fallback() {
    use protocol::ErrorKind::Unimplemented;
    let hs = V2OnlyHandshake::new(SharedStore::default(), AUDIENCE);
    let mut peer = Client::new(hs.clone());
    peer.publish_v2(AUDIENCE, 0, 0).await.unwrap();
    for (strict, confirmed) in [(false, false), (false, true), (true, false), (true, true)] {
        let failure = || {
            if confirmed {
                Unimplemented.into()
            } else {
                protocol::Error::ambiguous_response(Unimplemented, "lost reply")
            }
        };
        let calls = if confirmed {
            RpcErrors::new([
                ("claim_bundle", failure()),
                ("get_server_info", failure()),
                ("list_initial_messages", failure()),
                ("push_v2", failure()),
                ("fetch_signed", failure()),
            ])
        } else {
            RpcErrors::new([
                ("claim_bundle", failure()),
                ("list_initial_messages", failure()),
                ("push_v2", failure()),
                ("fetch_signed", failure()),
            ])
        };
        let config = PqConfig {
            strict_pq: strict,
            ..Default::default()
        };
        let mut client = Client::new(&calls).with_pq_config(config.clone()).unwrap();
        let err = client
            .prepare_initiate_v2(
                AUDIENCE,
                &peer.identity_key(),
                &PeerPqState::default(),
                b"first",
                (),
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unimplemented);
        assert_eq!(err.is_server_refusal(), confirmed);

        let err = client
            .list_initial_messages_v2(AUDIENCE, 0, 10)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unimplemented);
        assert_eq!(err.is_server_refusal(), confirmed);

        let mut sender = Client::new(hs.clone()).with_pq_config(config).unwrap();
        let mut chat = sender
            .prepare_initiate_v2(
                AUDIENCE,
                &peer.identity_key(),
                &PeerPqState::default(),
                b"first",
                &calls,
            )
            .await
            .unwrap()
            .session;
        let err = chat.send_v2(b"next").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unimplemented);
        assert_eq!(err.is_server_refusal(), confirmed);

        let err = sender
            .fetch_mailbox_v2(&&calls, AUDIENCE, 10)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unimplemented);
        assert_eq!(err.is_server_refusal(), confirmed);
        assert!(calls.is_empty());
    }
}

#[tokio::test]
async fn only_definitive_connect_refusals_roll_back_refilled_prekeys() {
    use protocol::ErrorKind as Kind;
    use protocol::connect::{ConnectClient, LocalPost, ProcedureV2};

    #[derive(Clone, Copy)]
    enum Reply {
        Http(u16, &'static str),
        Transport(Kind),
    }
    impl LocalPost for Reply {
        async fn post(&self, path: &str, _: Vec<u8>) -> protocol::Result<(u16, Vec<u8>)> {
            assert_eq!(path, ProcedureV2::RefillPrekeys.path());
            match self {
                Self::Http(200, _) => Ok((200, vec![0xff])),
                Self::Http(status, code) => Ok((
                    *status,
                    format!(r#"{{"code":"{code}","message":"failure"}}"#).into_bytes(),
                )),
                Self::Transport(kind) => Err((*kind).into()),
            }
        }
    }
    for (response, expected, refused) in [
        (
            Reply::Http(429, "resource_exhausted"),
            ErrorKind::LimitExceeded,
            true,
        ),
        (
            Reply::Http(403, "permission_denied"),
            ErrorKind::SignInRequired,
            true,
        ),
        (Reply::Http(404, "not_found"), ErrorKind::NotFound, true),
        (
            Reply::Http(501, "unimplemented"),
            ErrorKind::Unimplemented,
            true,
        ),
        (
            Reply::Http(400, "invalid_argument"),
            ErrorKind::Protocol,
            true,
        ),
        (
            Reply::Http(400, "failed_precondition"),
            ErrorKind::Protocol,
            true,
        ),
        (
            Reply::Http(401, "unauthenticated"),
            ErrorKind::Protocol,
            true,
        ),
        (Reply::Http(200, ""), ErrorKind::InvalidResponse, false),
        (
            Reply::Transport(Kind::LimitExceeded),
            ErrorKind::InvalidResponse,
            false,
        ),
        (
            Reply::Transport(Kind::Malformed),
            ErrorKind::InvalidResponse,
            false,
        ),
        (Reply::Http(500, "internal"), ErrorKind::Server, false),
        (Reply::Http(503, "unavailable"), ErrorKind::Server, false),
        (Reply::Transport(Kind::Connect), ErrorKind::Server, false),
    ] {
        let mut bob = Client::new(ConnectClient::new(response));
        let publish = bob.prepare_publish_v2(AUDIENCE, 1, 1).unwrap();
        bob.commit_publish_v2(publish);
        let error = bob.refill_prekeys_v2(AUDIENCE, 1, 1).await.unwrap_err();
        assert_eq!(error.kind(), expected);
        assert_eq!(error.is_server_refusal(), refused);
        let count = if refused { 1 } else { 2 };
        assert_eq!(bob.current_one_time_count(), count);
        assert_eq!(
            bob.current_pq_one_time_count(PqConfig::default_suite()),
            count
        );
    }
    assert!(!session::Error::from(ErrorKind::Protocol).is_server_refusal());
}

#[tokio::test]
async fn unsafe_pq_and_classical_initials_preserve_all_private_prekeys() {
    let hs = V2OnlyHandshake::new(SharedStore::default(), AUDIENCE);
    let mut alice_pq = Client::new(hs.clone());
    let mut alice_cl = Client::new(hs.clone())
        .with_pq_config(PqConfig {
            pq_enabled: false,
            ..PqConfig::default()
        })
        .unwrap();
    let mut bob = Client::new(hs);
    bob.publish_v2(AUDIENCE, 3, 3).await.unwrap();
    let invalid = hello_bytes("alice", protocol::MAX_SAFE_INTEGER + 1, true);
    alice_pq
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &invalid,
            (),
        )
        .await
        .unwrap();
    alice_cl
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &invalid,
            (),
        )
        .await
        .unwrap();
    let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    assert_eq!(listed.messages.len(), 2);
    assert!(listed.messages[0].uses_pq_one_time_prekey());
    assert!(!listed.messages[1].is_pq());
    let suite = listed.messages[0].pq_suite().unwrap();
    let counts = (
        bob.current_one_time_count(),
        bob.current_pq_one_time_count(suite),
    );
    for (sender, initial) in [
        (alice_pq.identity_key(), &listed.messages[0]),
        (alice_cl.identity_key(), &listed.messages[1]),
    ] {
        assert!(initial.uses_one_time_prekey());
        assert_eq!(
            bob.accept_initial_v2(&sender, &PeerPqState::default(), initial, ())
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInitialMessage
        );
        assert_eq!(
            (
                bob.current_one_time_count(),
                bob.current_pq_one_time_count(suite)
            ),
            counts
        );
    }
    let eph = Client::new(()).identity_key();
    let spk = Client::new(()).identity_key();
    let mut wire = protocol::handshake_v2::InitialMessageV2 {
        version: 1,
        identity_key: Bytes::copy_from_slice(&alice_pq.identity_key()),
        ephemeral_key: Bytes::copy_from_slice(&eph),
        signed_prekey: Bytes::copy_from_slice(&spk),
        first_message: Some(party::EncryptedMessage::default()),
        ..Default::default()
    };
    assert!(InitialMessageV2::try_from(&wire).is_ok());
    wire.manifest_digest = Bytes::from_static(&[4; 32]);
    assert_eq!(
        InitialMessageV2::try_from(&wire).unwrap_err().kind(),
        ErrorKind::InvalidInitialMessage
    );
}

#[tokio::test]
async fn toggling_pq_off_for_a_replacement_never_approves_future_classical_sessions() {
    for pinned in [true, false] {
        let hs = V2OnlyHandshake::new(SharedStore::default(), AUDIENCE);
        let mut bob = Client::new(hs.clone());
        let mut alice = Client::new(hs);
        let off = PqConfig {
            pq_enabled: false,
            ..PqConfig::default()
        };
        if !pinned {
            bob.set_pq_config(off.clone()).unwrap();
            alice.set_pq_config(off.clone()).unwrap();
            bob.publish_v2(AUDIENCE, 4, 0).await.unwrap();
        } else {
            bob.publish_v2(AUDIENCE, 4, 2).await.unwrap();
        }
        let peer = alice.identity_key();
        alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                &hello_bytes("alice", 1, pinned),
                (),
            )
            .await
            .unwrap();
        let page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let batch = bob.accept_listed_v2(&page, (), |_| PeerPqState::default());
        bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
            .await
            .unwrap();
        let (
            _,
            AcceptedInitial::Accepted {
                mut session,
                security,
                ..
            },
        ) = batch.outcomes.into_iter().next().unwrap()
        else {
            panic!("expected accepted initial session");
        };
        assert_eq!(security.is_pq, pinned);

        alice.set_pq_config(off.clone()).unwrap();
        alice.publish_v2(AUDIENCE, 2, 0).await.unwrap();
        bob.set_pq_config(off).unwrap();

        alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                &hello_bytes("alice", 2, false),
                (),
            )
            .await
            .unwrap();
        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let initial = &listed.messages[0];
        let AcceptedInitial::Accepted {
            session: incoming, ..
        } = bob
            .accept_initial_v2(&peer, session.peer_pq_state(), initial, ())
            .unwrap()
        else {
            panic!("local PQ is off");
        };
        assert!(!incoming.peer_pq_state().allow_classical_exception);
        assert!(
            session
                .accept_replacement_with_policy(incoming, false)
                .unwrap()
        );
        assert_eq!(session.peer_pq_state().pq_pinned, pinned);
        assert!(!session.peer_pq_state().allow_classical_exception);
        bob.ack_initial_messages_v2(AUDIENCE, vec![initial.id])
            .await
            .unwrap();

        bob.set_pq_config(PqConfig::default()).unwrap();
        alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                &hello_bytes("alice", 3, false),
                (),
            )
            .await
            .unwrap();
        let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
        let AcceptedInitial::Quarantined {
            session: quarantined,
            peer_was_pq_pinned,
            ..
        } = bob
            .accept_initial_v2(&peer, session.peer_pq_state(), &listed.messages[0], ())
            .unwrap()
        else {
            panic!("expected approval prompt");
        };
        assert_eq!(peer_was_pq_pinned, pinned);
        if pinned {
            assert_eq!(
                session
                    .accept_replacement_with_policy(quarantined, true)
                    .unwrap_err()
                    .kind(),
                ErrorKind::DowngradeDetected
            );
        }
        assert_eq!(
            bob.prepare_initiate_v2(AUDIENCE, &peer, session.peer_pq_state(), b"hi", ())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::ClassicalApprovalRequired
        );
    }
}

#[tokio::test]
async fn signed_pq_off_requires_approval_verifies_spk_signature_and_missing_manifest_is_downgrade()
{
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    // Peer publishes signed PQ-OFF manifest via v2 (includes `signed_prekey_signature`).
    let mut classical_peer = Client::new(hs.clone())
        .with_pq_config(PqConfig {
            pq_enabled: false,
            ..PqConfig::default()
        })
        .unwrap();
    classical_peer.publish_v2(AUDIENCE, 4, 0).await.unwrap();

    let mut alice = Client::new(hs.clone());
    alice.publish_v2(AUDIENCE, 3, 2).await.unwrap();

    // 1. Signed PQ-OFF manifest -> unit `ErrorKind::ClassicalApprovalRequired`.
    let mut peer_state = PeerPqState::default();
    let err = alice
        .initiate_v2(
            AUDIENCE,
            &classical_peer.identity_key(),
            &peer_state,
            b"hi",
            mb.clone(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ClassicalApprovalRequired);

    // 2. With explicit approval, classical X3DH succeeds and verifies `signed_prekey_signature`;
    //    stripping OR forging `signed_prekey_signature` fails with `InvalidKeys`!
    peer_state.approve_classical_exception();
    for attack in [AttackMode::StripSpkSignature, AttackMode::ForgeSpkSignature] {
        let mut attacked = Client::new(AttackingHandshake {
            inner: hs.clone(),
            attack,
        });
        assert_eq!(
            attacked
                .prepare_initiate_v2(
                    AUDIENCE,
                    &classical_peer.identity_key(),
                    &peer_state,
                    b"forged-spk-sig",
                    mb.clone(),
                )
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidKeys
        );
    }

    let mut alice_session = alice
        .initiate_v2(
            AUDIENCE,
            &classical_peer.identity_key(),
            &peer_state,
            b"hi-classical-peer",
            mb.clone(),
        )
        .await
        .unwrap();
    assert_eq!(alice_session.security(), Some(SessionSecurity::classical()));
    register_active_grant(&mut alice, &alice_session, &mb).await;

    let listed = classical_peer
        .list_initial_messages_v2(AUDIENCE, 0, 10)
        .await
        .unwrap();
    let AcceptedInitial::Accepted {
        session: mut peer_session,
        first_message,
        ..
    } = classical_peer
        .accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &listed.messages[0],
            mb.clone(),
        )
        .unwrap()
    else {
        panic!("expected classical peer to accept");
    };
    assert_eq!(first_message, b"hi-classical-peer");
    peer_session.send_v2(b"from-classical-peer").await.unwrap();
    let got = receive_for(&mut alice, &mut alice_session, &mb).await;
    assert_eq!(got[0].as_ref().unwrap().content, b"from-classical-peer");

    // 3. Inbound classical initial to PQ-enabled Alice is quarantined!
    let _cl_init = classical_peer
        .initiate_v2(
            AUDIENCE,
            &alice.identity_key(),
            &PeerPqState::default(),
            b"classical-hello",
            mb.clone(),
        )
        .await
        .unwrap();
    let listed = alice
        .list_initial_messages_v2(AUDIENCE, 0, 10)
        .await
        .unwrap();
    match alice
        .accept_initial_v2(
            &classical_peer.identity_key(),
            &PeerPqState::default(),
            &listed.messages[0],
            mb.clone(),
        )
        .unwrap()
    {
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

    // 4. `ClaimBundleResponse { manifest: None }` ALWAYS hard-fails as `DowngradeDetected` — even
    //    for unpinned peers, with `allow_classical_exception = true`, when local PQ is OFF, AND
    //    under `strict_pq = true`!
    let strip_hs = AttackingHandshake {
        inner: hs.clone(),
        attack: AttackMode::StripManifest,
    };
    for (cfg, ps) in [
        (PqConfig::default(), PeerPqState::default()),
        (PqConfig::default(), peer_state.clone()),
        (
            PqConfig {
                pq_enabled: false,
                ..PqConfig::default()
            },
            PeerPqState::default(),
        ),
        (
            PqConfig {
                strict_pq: true,
                ..PqConfig::default()
            },
            PeerPqState::default(),
        ),
    ] {
        let mut c = Client::new(strip_hs.clone()).with_pq_config(cfg).unwrap();
        assert_eq!(
            c.prepare_initiate_v2(
                AUDIENCE,
                &classical_peer.identity_key(),
                &ps,
                b"no-manifest",
                mb.clone(),
            )
            .await
            .unwrap_err()
            .kind(),
            ErrorKind::DowngradeDetected
        );
    }

    // 5. Strict-PQ initiator rejects signed PQ-OFF peer with `PqRequired`, and strict-PQ peer
    //    omits `signed_prekey_signature` so classical-only peer cannot initiate classical X3DH.
    let mut strict_alice = Client::new(hs)
        .with_pq_config(PqConfig {
            pq_enabled: true,
            preferred_suite: PqConfig::default_suite(),
            pq_ratchet_enabled: true,
            strict_pq: true,
        })
        .unwrap();
    strict_alice.publish_v2(AUDIENCE, 2, 2).await.unwrap();
    assert_eq!(
        classical_peer
            .initiate_v2(
                AUDIENCE,
                &strict_alice.identity_key(),
                &PeerPqState::default(),
                b"nope",
                mb.clone(),
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PqRequired
    );
    assert_eq!(
        strict_alice
            .initiate_v2(
                AUDIENCE,
                &classical_peer.identity_key(),
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
async fn lock_free_claim_peer_bundle_and_finish_prepare_recheck_live_state() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs.clone());
    let mut carol = Client::new(hs.clone())
        .with_pq_config(PqConfig {
            pq_enabled: false,
            ..PqConfig::default()
        })
        .unwrap();
    bob.publish_v2(AUDIENCE, 6, 6).await.unwrap();
    carol.publish_v2(AUDIENCE, 6, 0).await.unwrap();

    // 1. Happy path: `claim_peer_bundle_v2` (no lock on Client) -> `finish_prepare_initiate_v2` ->
    //    `send_prepared_initiate_v2` -> `finish_prepare_start_again_v2`.
    let claimed_bob = claim_peer_bundle_v2(
        &hs,
        AUDIENCE,
        &bob.identity_key(),
        &PeerPqState::default(),
        alice.pq_config(),
        alice.clock(),
    )
    .await
    .unwrap();
    assert_eq!(claimed_bob.peer(), &bob.identity_key());
    assert_eq!(claimed_bob.audience(), AUDIENCE);

    let prepared = alice
        .finish_prepare_initiate_v2(
            claimed_bob,
            &PeerPqState::default(),
            b"lock-free-1",
            mb.clone(),
        )
        .unwrap();
    assert!(prepared.security.is_pq);
    alice
        .send_prepared_initiate_v2(&prepared.request)
        .await
        .unwrap();
    let mut alice_bob = prepared.session;

    // Rekey via `claim_peer_bundle_v2` + `finish_prepare_start_again_v2`.
    let claimed_rekey = claim_peer_bundle_v2(
        &hs,
        AUDIENCE,
        &bob.identity_key(),
        alice_bob.peer_pq_state(),
        alice.pq_config(),
        alice.clock(),
    )
    .await
    .unwrap();
    let rekey_req = alice
        .finish_prepare_start_again_v2(claimed_rekey, &mut alice_bob, b"lock-free-rekey")
        .unwrap();
    alice.send_prepared_initiate_v2(&rekey_req).await.unwrap();

    // 2. Concurrent live-state mutations between `claim_peer_bundle_v2` and `finish_prepare_*`:
    //    (a) Peer manifest pin advanced to seq 2 while seq 1 was in flight -> DowngradeDetected.
    let claimed_seq1 = claim_peer_bundle_v2(
        &hs,
        AUDIENCE,
        &bob.identity_key(),
        &PeerPqState::default(),
        alice.pq_config(),
        alice.clock(),
    )
    .await
    .unwrap();
    let newer_pin = PeerPqState {
        pq_pinned: true,
        pinned_manifest_seq: 2,
        peer_pq_capable: true,
        ..PeerPqState::default()
    };
    assert_eq!(
        alice
            .finish_prepare_initiate_v2(claimed_seq1, &newer_pin, b"stale", mb.clone())
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );

    //    (b) Classical exception approved during claim, revoked before finish -> ClassicalApprovalRequired.
    let mut approved = PeerPqState::default();
    approved.approve_classical_exception();
    let claimed_carol = claim_peer_bundle_v2(
        &hs,
        AUDIENCE,
        &carol.identity_key(),
        &approved,
        alice.pq_config(),
        alice.clock(),
    )
    .await
    .unwrap();
    assert_eq!(
        alice
            .finish_prepare_initiate_v2(
                claimed_carol,
                &PeerPqState::default(),
                b"revoked",
                mb.clone()
            )
            .unwrap_err()
            .kind(),
        ErrorKind::ClassicalApprovalRequired
    );

    //    (c) `strict_pq` toggled ON between claim and finish -> PqRequired.
    let claimed_carol2 = claim_peer_bundle_v2(
        &hs,
        AUDIENCE,
        &carol.identity_key(),
        &approved,
        alice.pq_config(),
        alice.clock(),
    )
    .await
    .unwrap();
    alice
        .set_pq_config(PqConfig {
            strict_pq: true,
            ..PqConfig::default()
        })
        .unwrap();
    assert_eq!(
        alice
            .finish_prepare_initiate_v2(claimed_carol2, &approved, b"now-strict", mb)
            .unwrap_err()
            .kind(),
        ErrorKind::PqRequired
    );

    //    (d) `finish_prepare_start_again_v2` rejects mismatched peer.
    alice.set_pq_config(PqConfig::default()).unwrap();
    let claimed_carol3 = claim_peer_bundle_v2(
        &hs,
        AUDIENCE,
        &carol.identity_key(),
        &approved,
        alice.pq_config(),
        alice.clock(),
    )
    .await
    .unwrap();
    assert_eq!(
        alice
            .finish_prepare_start_again_v2(claimed_carol3, &mut alice_bob, b"wrong-peer")
            .unwrap_err()
            .kind(),
        ErrorKind::UnexpectedPeer
    );
}

#[tokio::test]
async fn toggle_pq_on_to_off_preserves_in_flight_pq_then_back_on() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs.clone());
    let mut carol = Client::new(hs);

    alice.publish_v2(AUDIENCE, 2, 2).await.unwrap();
    bob.publish_v2(AUDIENCE, 4, 3).await.unwrap();
    assert_eq!(bob.manifest_seq(), 1);

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
    register_active_grant(&mut alice, &alice_session, &mb).await;

    bob.set_pq_config(PqConfig {
        pq_enabled: false,
        preferred_suite: PqConfig::default_suite(),
        pq_ratchet_enabled: false,
        strict_pq: false,
    })
    .unwrap();
    bob.publish_v2(AUDIENCE, 4, 0).await.unwrap();
    assert_eq!(bob.manifest_seq(), 2);

    let m = carol
        .get_peer_manifest(AUDIENCE, &bob.identity_key())
        .await
        .unwrap()
        .unwrap();
    assert!(!m.pq_enabled);
    assert_eq!(m.manifest_seq, 2);

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
        panic!("in-flight PQ handshake must still be accepted after toggling PQ OFF");
    };
    assert_eq!(first_message, b"in-flight-pq");
    assert!(security.is_pq);
    session.send_v2(b"in-flight-reply").await.unwrap();
    let rx = receive_for(&mut alice, &mut alice_session, &mb).await;
    assert_eq!(rx[0].as_ref().unwrap().content, b"in-flight-reply");

    let mut carol_peer_state = PeerPqState {
        pq_pinned: true,
        pinned_manifest_seq: 1,
        peer_pq_capable: true,
        ..PeerPqState::default()
    };
    assert_eq!(
        carol
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &carol_peer_state,
                b"hi",
                mb.clone(),
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::ClassicalApprovalRequired
    );
    carol_peer_state.approve_classical_exception();
    let carol_classical = carol
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &carol_peer_state,
            b"ok-classical",
            mb.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        carol_classical.security(),
        Some(SessionSecurity::classical())
    );

    bob.set_pq_config(PqConfig {
        pq_enabled: true,
        preferred_suite: PqConfig::default_suite(),
        pq_ratchet_enabled: true,
        strict_pq: false,
    })
    .unwrap();
    bob.publish_v2(AUDIENCE, 4, 3).await.unwrap();
    assert_eq!(bob.manifest_seq(), 3);

    let carol_pq = carol
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &carol_peer_state,
            b"back-to-pq",
            mb,
        )
        .await
        .unwrap();
    assert!(carol_pq.security().unwrap().is_pq);
    assert_eq!(carol_pq.peer_pq_state().pinned_manifest_seq, 3);
}

#[tokio::test]
async fn active_server_downgrade_attacks_are_hard_blocked() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut bob = Client::new(hs.clone());
    bob.publish_v2(AUDIENCE, 5, 5).await.unwrap();
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

    for attack in [
        AttackMode::StripPqPrekeys,
        AttackMode::StripManifest,
        AttackMode::ReplayBundle(Box::new(captured_seq1)),
    ] {
        let mut alice = Client::new(AttackingHandshake {
            inner: hs.clone(),
            attack,
        });
        assert_eq!(
            alice
                .initiate_v2(AUDIENCE, &bob.identity_key(), &pinned, b"hi", mb.clone())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::DowngradeDetected
        );
    }

    let mut alice_wrong_aud = Client::new(hs.clone());
    assert_eq!(
        alice_wrong_aud
            .initiate_v2(
                "attacker.example",
                &bob.identity_key(),
                &PeerPqState::default(),
                b"hi",
                mb.clone()
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );

    #[cfg(all(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    {
        let mut alice_suite_downgrade = Client::new(AttackingHandshake {
            inner: hs,
            attack: AttackMode::DowngradeSuiteTo768,
        });
        assert_eq!(
            alice_suite_downgrade
                .initiate_v2(
                    AUDIENCE,
                    &bob.identity_key(),
                    &PeerPqState::default(),
                    b"hi",
                    mb
                )
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::DowngradeDetected
        );
    }

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
async fn expired_manifest_is_distinct_from_downgrade_and_foreign_digest_is_rejected() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let alice_id = xeddsa::XEdDSAPrivateKey::generate();
    let alice_id_copy = xeddsa::XEdDSAPrivateKey::from_bytes(*alice_id.to_bytes()).unwrap();
    let mut alice = Client::builder(hs.clone())
        .identity(alice_id)
        .clock(session::ServerClock::with_max_drift(u64::MAX))
        .build();
    let mut bob = Client::new(hs.clone());
    bob.publish_v2(AUDIENCE, 3, 3).await.unwrap();

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
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &pinned_seq1,
                b"hi",
                mb.clone()
            )
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

    let pinned_seq2 = PeerPqState {
        pq_pinned: true,
        pinned_manifest_seq: 2,
        peer_pq_capable: true,
        ..PeerPqState::default()
    };
    assert_eq!(
        alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &pinned_seq2,
                b"hi",
                mb.clone()
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );

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
    let mut listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
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
            mb.clone(),
        )
        .unwrap_err()
        .kind(),
        ErrorKind::InvalidInitialMessage
    );

    let claimed = hs
        .claim_bundle(ClaimBundleRequest {
            identity_key: Bytes::copy_from_slice(&bob.identity_key()),
            preferred_suites: vec![u32::from(PqConfig::default_suite().as_u8())],
        })
        .await
        .unwrap();
    let pq_bundle = x3dh::PqPrekeyBundle::try_from(&claimed).unwrap();
    let foreign_digest = [0xAB; 32];
    let (pq_init, agreement) = pq_bundle
        .initiate_pq(&alice_id_copy, &bob.identity_key(), Some(&foreign_digest))
        .unwrap();
    let ratchet = ratchetx2::Ratchet::alice(
        &ratchetx2::SharedKeys::from_secret(&agreement.secret_key),
        &pq_bundle.signed_prekey,
    )
    .unwrap();
    let mut party = party::Party::new(ratchet, agreement.associated_data);
    let first_message = party.encrypt(b"auth-foreign-digest").unwrap();
    let auth_foreign = InitialMessageV2 {
        id: 99,
        sender: alice.identity_key(),
        kind: session::InitialMessageKind::Pq {
            x3dh: pq_init,
            first_message,
            manifest_digest: Some(foreign_digest),
        },
    };
    let opks_before = bob.current_one_time_count();
    let pq_opks_before = bob.current_pq_one_time_count(PqConfig::default_suite());
    assert_eq!(
        bob.accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &auth_foreign,
            mb,
        )
        .unwrap_err()
        .kind(),
        ErrorKind::DowngradeDetected
    );
    assert_eq!(bob.current_one_time_count(), opks_before);
    assert_eq!(
        bob.current_pq_one_time_count(PqConfig::default_suite()),
        pq_opks_before
    );
}

#[tokio::test]
async fn forged_initials_never_trigger_downgrade_or_pq_required_and_strict_pq_rejects_missing_digest()
 {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let alice_id = xeddsa::XEdDSAPrivateKey::generate();
    let alice_id_copy = xeddsa::XEdDSAPrivateKey::from_bytes(*alice_id.to_bytes()).unwrap();
    let bob_id = xeddsa::XEdDSAPrivateKey::generate();
    let bob_id_copy = xeddsa::XEdDSAPrivateKey::from_bytes(*bob_id.to_bytes()).unwrap();
    let alice = Client::builder(hs.clone()).identity(alice_id).build();
    let mut bob = Client::builder(hs.clone()).identity(bob_id).build();
    bob.set_pq_config(PqConfig {
        pq_enabled: true,
        preferred_suite: PqConfig::default_suite(),
        pq_ratchet_enabled: true,
        strict_pq: true,
    })
    .unwrap();
    bob.publish_v2(AUDIENCE, 4, 4).await.unwrap();
    let suite = PqConfig::default_suite();

    let claimed = hs
        .claim_bundle(ClaimBundleRequest {
            identity_key: Bytes::copy_from_slice(&bob.identity_key()),
            preferred_suites: vec![u32::from(suite.as_u8())],
        })
        .await
        .unwrap();
    let pq_bundle = x3dh::PqPrekeyBundle::try_from(&claimed).unwrap();
    let bob_spk = pq_bundle.signed_prekey;

    let (mallory_pq_init, _) = pq_bundle
        .initiate_pq(
            &xeddsa::XEdDSAPrivateKey::generate(),
            &bob.identity_key(),
            Some(&[0xEE; 32]),
        )
        .unwrap();
    let mut forged_pq = mallory_pq_init;
    forged_pq.identity_key = alice.identity_key();
    let mut forged_pq_msg = InitialMessageV2 {
        id: 1,
        sender: alice.identity_key(),
        kind: session::InitialMessageKind::Pq {
            x3dh: forged_pq,
            first_message: party::EncryptedMessage {
                header: Bytes::from_static(b"bad-header"),
                content: Bytes::from_static(b"bad-ciphertext"),
            },
            manifest_digest: Some([0xEE; 32]),
        },
    };
    assert_eq!(
        bob.accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &forged_pq_msg,
            mb.clone(),
        )
        .unwrap_err()
        .kind(),
        ErrorKind::InvalidInitialMessage
    );

    if let session::InitialMessageKind::Pq {
        manifest_digest, ..
    } = &mut forged_pq_msg.kind
    {
        *manifest_digest = None;
    }
    assert_eq!(
        bob.accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &forged_pq_msg,
            mb.clone(),
        )
        .unwrap_err()
        .kind(),
        ErrorKind::InvalidInitialMessage
    );

    let opks_before = bob.current_one_time_count();
    let pq_opks_before = bob.current_pq_one_time_count(suite);
    let mut bob_v1_sig = [0u8; 64];
    bob_v1_sig.copy_from_slice(&bob_id_copy.sign(bob_spk));
    let mut pq_bundle_with_raw_sig = pq_bundle.clone();
    pq_bundle_with_raw_sig.signed_prekey_signature = Some(bob_v1_sig);
    let (alice_none_pq, alice_none_agree) = pq_bundle_with_raw_sig
        .initiate_pq(&alice_id_copy, &bob.identity_key(), None)
        .unwrap();
    let ratchet = ratchetx2::Ratchet::alice(
        &ratchetx2::SharedKeys::from_secret(&alice_none_agree.secret_key),
        &bob_spk,
    )
    .unwrap();
    let mut party = party::Party::new(ratchet, alice_none_agree.associated_data);
    let first_msg = party.encrypt(b"auth-missing-digest").unwrap();
    let auth_none_digest = InitialMessageV2 {
        id: 2,
        sender: alice.identity_key(),
        kind: session::InitialMessageKind::Pq {
            x3dh: alice_none_pq,
            first_message: first_msg,
            manifest_digest: None,
        },
    };
    assert_eq!(
        bob.accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &auth_none_digest,
            mb.clone(),
        )
        .unwrap_err()
        .kind(),
        ErrorKind::DowngradeDetected
    );
    assert_eq!(bob.current_one_time_count(), opks_before);
    assert_eq!(bob.current_pq_one_time_count(suite), pq_opks_before);

    let fake_eph = xeddsa::XEdDSAPrivateKey::generate()
        .compute_public_key()
        .to_bytes();
    let forged_classical = InitialMessageV2 {
        id: 3,
        sender: alice.identity_key(),
        kind: session::InitialMessageKind::Classical {
            x3dh: x3dh::InitialMessage {
                identity_key: alice.identity_key(),
                ephemeral_key: fake_eph,
                signed_prekey: bob_spk,
                one_time_prekey: pq_bundle.one_time_prekey,
            },
            first_message: party::EncryptedMessage {
                header: Bytes::from_static(b"forged-hdr"),
                content: Bytes::from_static(b"forged-body"),
            },
        },
    };
    assert_eq!(
        bob.accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &forged_classical,
            mb.clone(),
        )
        .unwrap_err()
        .kind(),
        ErrorKind::InvalidInitialMessage
    );
    assert_eq!(bob.current_one_time_count(), opks_before);

    let classical_bundle = x3dh::PrekeyBundle {
        signed_prekey: bob_spk,
        signed_prekey_signature: bob_v1_sig,
        one_time_prekey: pq_bundle.one_time_prekey,
    };
    let (alice_classical_x3dh, alice_classical_agree) = classical_bundle
        .initiate(&alice_id_copy, &bob.identity_key())
        .unwrap();
    let c_ratchet = ratchetx2::Ratchet::alice(
        &ratchetx2::SharedKeys::from_secret(&alice_classical_agree.secret_key),
        &bob_spk,
    )
    .unwrap();
    let mut c_party = party::Party::new(c_ratchet, alice_classical_agree.associated_data);
    let c_first = c_party.encrypt(b"auth-classical-in-strict-pq").unwrap();
    let auth_classical = InitialMessageV2 {
        id: 4,
        sender: alice.identity_key(),
        kind: session::InitialMessageKind::Classical {
            x3dh: alice_classical_x3dh,
            first_message: c_first,
        },
    };
    assert_eq!(
        bob.accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &auth_classical,
            mb,
        )
        .unwrap_err()
        .kind(),
        ErrorKind::PqRequired
    );
    assert_eq!(bob.current_one_time_count(), opks_before);
}

#[tokio::test]
async fn pq_off_publish_rotates_spk_and_bounds_opks_while_preserving_in_flight_pq() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);

    bob.publish_v2(AUDIENCE, 5, 4).await.unwrap();
    let spk_gen1 = bob.current_signed_prekey().unwrap();
    assert_eq!(bob.prekey_generation(), 1);
    assert_eq!(bob.current_one_time_count(), 5);

    let _alice_pq = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"in-flight-gen1",
            mb.clone(),
        )
        .await
        .unwrap();

    bob.set_pq_config(PqConfig {
        pq_enabled: false,
        preferred_suite: PqConfig::default_suite(),
        pq_ratchet_enabled: false,
        strict_pq: false,
    })
    .unwrap();
    bob.publish_v2(AUDIENCE, 5, 0).await.unwrap();
    let spk_gen2 = bob.current_signed_prekey().unwrap();
    assert_ne!(spk_gen2, spk_gen1);
    assert_eq!(bob.prekey_generation(), 2);
    assert_eq!(bob.current_one_time_count(), 5);

    let page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let mut batch = bob.accept_listed_v2(&page, mb, |_| PeerPqState::default());
    bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
        .await
        .unwrap();
    let (
        _,
        AcceptedInitial::Accepted {
            first_message,
            security,
            ..
        },
    ) = batch.outcomes.pop().unwrap()
    else {
        panic!("expected in-flight PQ handshake to decrypt across 1st PQ-OFF rotation");
    };
    assert_eq!(first_message, b"in-flight-gen1");
    assert!(security.is_pq);

    bob.publish_v2(AUDIENCE, 5, 0).await.unwrap();
    let spk_gen3 = bob.current_signed_prekey().unwrap();
    assert_ne!(spk_gen3, spk_gen2);
    assert_eq!(bob.prekey_generation(), 3);
    assert_eq!(bob.current_one_time_count(), 5);

    bob.publish_v2(AUDIENCE, 5, 0).await.unwrap();
    let spk_gen4 = bob.current_signed_prekey().unwrap();
    assert_ne!(spk_gen4, spk_gen3);
    assert_eq!(bob.prekey_generation(), 4);
    assert_eq!(bob.current_one_time_count(), 5);
}

#[tokio::test]
async fn pq_disabled_server_rollback_publish_refill_list_and_limit_exceeded_rollback() {
    let store = SharedStore::default();
    let (hs, enabled) = ToggleableHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    let suite = PqConfig::default_suite();

    let prep1 = bob.prepare_publish_v2(AUDIENCE, 5, 5).unwrap();
    assert_eq!(
        bob.transmit_publish_v2(&prep1).await.unwrap(),
        session::PublishV2Outcome::V2Pq
    );
    bob.commit_publish_v2(prep1);

    let _alice_inflight = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"in-flight-before-rollback",
            mb.clone(),
        )
        .await
        .unwrap();

    enabled.store(false, Ordering::Relaxed);

    let prep_off = bob.prepare_publish_v2(AUDIENCE, 5, 5).unwrap();
    assert_eq!(
        bob.transmit_publish_v2(&prep_off).await.unwrap(),
        session::PublishV2Outcome::ServerPqDisabled
    );
    let off_prepared = bob.prepare_publish_v2_classical_off(prep_off, &[]).unwrap();
    assert_eq!(
        bob.transmit_publish_v2(&off_prepared).await.unwrap(),
        session::PublishV2Outcome::V2ClassicalOff
    );
    bob.commit_publish_v2(off_prepared);
    assert_eq!(bob.current_pq_one_time_count(suite), 0);
    assert_eq!(bob.current_one_time_count(), 5);

    let page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let mut batch = bob.accept_listed_v2(&page, mb, |_| PeerPqState::default());
    bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
        .await
        .unwrap();
    let (
        _,
        AcceptedInitial::Accepted {
            first_message,
            security,
            ..
        },
    ) = batch.outcomes.pop().unwrap()
    else {
        panic!("expected in-flight PQ initial to drain during PQ_ENABLED=false");
    };
    assert_eq!(first_message, b"in-flight-before-rollback");
    assert!(security.is_pq);

    let refill_ok = bob.refill_prekeys_v2(AUDIENCE, 5, 0).await.unwrap();
    assert_eq!(refill_ok.classical_one_time_count, 10);
    assert_eq!(bob.current_one_time_count(), 10);

    let opks_before_limit = bob.current_one_time_count();
    let err = bob.refill_prekeys_v2(AUDIENCE, 101, 0).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    assert_eq!(bob.current_one_time_count(), opks_before_limit);

    let mut bob_unimpl = Client::new(UnimplementedV2Server);
    for count in [3, 2] {
        let prep = bob_unimpl
            .prepare_publish_v2(AUDIENCE, count, count)
            .unwrap();
        assert_eq!(bob_unimpl.prekey_generation(), 1);
        assert_eq!(bob_unimpl.current_pq_one_time_count(suite), count);
        let err = bob_unimpl.transmit_publish_v2(&prep).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unimplemented);
        assert!(err.is_server_refusal());
        bob_unimpl.rollback_publish_v2_on_refusal(prep);
        assert_eq!(bob_unimpl.manifest_seq(), 0);
        assert_eq!(bob_unimpl.prekey_generation(), 0);
        assert_eq!(bob_unimpl.current_pq_one_time_count(suite), 0);
    }
}

#[tokio::test]
async fn pq_disabled_rollback_allows_explicitly_approved_classical_chat_and_enforces_pins() {
    use storage::LocalPqHandshakeStore as _;

    let store = SharedStore::default();
    let (hs, enabled) = ToggleableHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store.clone(), AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs.clone());
    let mut carol = Client::new(hs.clone())
        .with_pq_config(PqConfig {
            strict_pq: true,
            ..PqConfig::default()
        })
        .unwrap();

    bob.publish_v2(AUDIENCE, 5, 5).await.unwrap();
    carol.publish_v2(AUDIENCE, 5, 5).await.unwrap();
    enabled.store(false, Ordering::Relaxed);

    let opks_before = store
        .pq_snapshot(&bob.identity_key())
        .await
        .unwrap()
        .classical_one_time_count;
    let err = alice
        .prepare_initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"hi bob",
            mb.clone(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ClassicalApprovalRequired);
    assert_eq!(
        store
            .pq_snapshot(&bob.identity_key())
            .await
            .unwrap()
            .classical_one_time_count,
        opks_before
    );

    let mut strict_alice = Client::new(hs.clone())
        .with_pq_config(PqConfig {
            strict_pq: true,
            ..PqConfig::default()
        })
        .unwrap();
    let mut approved = PeerPqState::default();
    approved.approve_classical_exception();
    assert_eq!(
        strict_alice
            .prepare_initiate_v2(AUDIENCE, &bob.identity_key(), &approved, b"hi", mb.clone())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PqRequired
    );

    let mut pinned = PeerPqState::default();
    pinned.pin_peer_pq();
    pinned.approve_classical_exception();
    assert_eq!(
        alice
            .prepare_initiate_v2(AUDIENCE, &bob.identity_key(), &pinned, b"hi", mb.clone())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );

    assert_eq!(
        alice
            .prepare_initiate_v2(
                AUDIENCE,
                &carol.identity_key(),
                &approved,
                b"hi carol",
                mb.clone(),
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PqRequired
    );

    let prepared = alice
        .prepare_initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &approved,
            b"classical-during-rollback",
            mb.clone(),
        )
        .await
        .unwrap();
    assert!(!prepared.security.is_pq);
    alice
        .send_prepared_initiate_v2(&prepared.request)
        .await
        .unwrap();
    let mut alice_session = prepared.session;

    let page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let batch = bob.accept_listed_v2(&page, mb.clone(), |_| {
        let mut ps = PeerPqState::default();
        ps.approve_classical_exception();
        ps
    });
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
    ) = batch.outcomes.into_iter().next().unwrap()
    else {
        panic!("expected classical session accepted with explicit exception");
    };
    assert!(!security.is_pq);
    assert_eq!(first_message, b"classical-during-rollback");
    register_active_grant(&mut bob, &session, &mb).await;

    alice_session.send_v2(b"follow-up").await.unwrap();
    let msgs = receive_for(&mut bob, &mut session, &mb).await;
    assert_eq!(msgs[0].as_ref().unwrap().content, b"follow-up");

    assert!(!alice_session.peer_pq_state().pq_pinned);
    assert!(alice_session.peer_pq_state().peer_pq_capable);
    assert_eq!(alice_session.peer_pq_state().pinned_manifest_seq, 1);
    let rekey_req = alice
        .prepare_start_again_v2(AUDIENCE, &mut alice_session, b"rekey-during-rollback")
        .await
        .unwrap();
    assert_eq!(rekey_req.message.as_ref().unwrap().version, 1);
    assert!(!alice_session.security().unwrap().is_pq);

    let strip_hs = AttackingHandshake {
        inner: V2OnlyHandshake::new(store.clone(), AUDIENCE),
        attack: AttackMode::StripManifest,
    };
    let mut alice_strip = Client::new(strip_hs);
    assert_eq!(
        alice_strip
            .prepare_initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                alice_session.peer_pq_state(),
                b"stripped",
                mb,
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );

    enabled.store(true, Ordering::Relaxed);
    let upgraded_req = alice
        .prepare_start_again_v2(AUDIENCE, &mut alice_session, b"upgrade-after-recovery")
        .await
        .unwrap();
    assert_eq!(upgraded_req.message.as_ref().unwrap().version, 2);
    assert!(alice_session.security().unwrap().is_pq);
    assert!(alice_session.peer_pq_state().pq_pinned);
    assert!(!alice_session.peer_pq_state().allow_classical_exception);
}

#[tokio::test]
async fn bare_proxy_404_never_downgrades_or_retracts_and_pq_on_unimplemented_surfaces() {
    use prost::Message as _;
    use protocol::connect::{ConnectClient, LocalPost, ProcedureV2};

    #[derive(Clone)]
    struct ProxyAndMismatch {
        calls: Arc<Mutex<Vec<String>>>,
        mode: ProxyMode,
    }
    #[derive(Clone, Copy)]
    enum ProxyMode {
        Bare404,
        ConnectUnimplWithPqOnInfo,
        ConnectUnimplWithTransientInfo502,
    }
    impl LocalPost for ProxyAndMismatch {
        async fn post(&self, path: &str, _: Vec<u8>) -> protocol::Result<(u16, Vec<u8>)> {
            self.calls.lock().unwrap().push(path.to_string());
            match self.mode {
                ProxyMode::Bare404 => Ok((404, b"<html>Not Found</html>".to_vec())),
                ProxyMode::ConnectUnimplWithPqOnInfo => {
                    if path == ProcedureV2::GetServerInfo.path() {
                        let info = GetServerInfoResponse {
                            server_id: AUDIENCE.into(),
                            pq_enabled: true,
                            supported_suites: vec![1, 2],
                            pq_ratchet_supported: true,
                        };
                        Ok((200, info.encode_to_vec()))
                    } else {
                        let err = protocol::connect::error(
                            protocol::ErrorKind::Unimplemented,
                            "procedure missing",
                        );
                        Ok((err.status, err.body))
                    }
                }
                ProxyMode::ConnectUnimplWithTransientInfo502 => {
                    if path == ProcedureV2::GetServerInfo.path() {
                        Ok((502, b"Bad Gateway".to_vec()))
                    } else {
                        let err = protocol::connect::error(
                            protocol::ErrorKind::Unimplemented,
                            "procedure missing",
                        );
                        Ok((err.status, err.body))
                    }
                }
            }
        }
    }

    for strict in [false, true] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let transport = ConnectClient::new(ProxyAndMismatch {
            calls: calls.clone(),
            mode: ProxyMode::Bare404,
        });
        let mut client = Client::new(transport)
            .with_pq_config(PqConfig {
                strict_pq: strict,
                ..PqConfig::default()
            })
            .unwrap();
        let err = client.publish_v2(AUDIENCE, 2, 2).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unimplemented);
        assert!(!err.is_server_refusal());
        assert!(!err.is_connect_error());
        assert_eq!(
            *calls.lock().unwrap(),
            vec![ProcedureV2::PublishV2.path().to_string()]
        );
        assert_eq!(client.current_one_time_count(), 2);

        calls.lock().unwrap().clear();
        let refill_err = client.refill_prekeys_v2(AUDIENCE, 2, 2).await.unwrap_err();
        assert_eq!(refill_err.kind(), ErrorKind::Unimplemented);
        assert!(!refill_err.is_server_refusal());
        assert_eq!(client.current_one_time_count(), 4);

        calls.lock().unwrap().clear();
        let peer = Client::new(()).identity_key();
        let claim_err = client
            .prepare_initiate_v2(AUDIENCE, &peer, &PeerPqState::default(), b"hi", ())
            .await
            .unwrap_err();
        assert_eq!(claim_err.kind(), ErrorKind::Unimplemented);
        assert!(!claim_err.is_server_refusal());
        assert!(!claim_err.is_connect_error());
        assert_eq!(
            *calls.lock().unwrap(),
            vec![ProcedureV2::ClaimBundle.path().to_string()]
        );
    }

    for strict in [false, true] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let transport = ConnectClient::new(ProxyAndMismatch {
            calls: calls.clone(),
            mode: ProxyMode::ConnectUnimplWithPqOnInfo,
        });
        let mut client = Client::new(transport)
            .with_pq_config(PqConfig {
                strict_pq: strict,
                ..PqConfig::default()
            })
            .unwrap();
        let err = client.publish_v2(AUDIENCE, 1, 1).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unimplemented);
        assert!(err.is_connect_error());
        assert!(err.is_server_refusal());
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                ProcedureV2::PublishV2.path().to_string(),
                ProcedureV2::GetServerInfo.path().to_string(),
            ]
        );

        calls.lock().unwrap().clear();
        let peer = Client::new(()).identity_key();
        let claim_err = client
            .prepare_initiate_v2(AUDIENCE, &peer, &PeerPqState::default(), b"hi", ())
            .await
            .unwrap_err();
        assert_eq!(claim_err.kind(), ErrorKind::Unimplemented);
        assert!(claim_err.is_connect_error());
        assert!(claim_err.is_server_refusal());
    }

    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = ConnectClient::new(ProxyAndMismatch {
        calls,
        mode: ProxyMode::ConnectUnimplWithTransientInfo502,
    });
    let mut client = Client::new(transport);
    let err = client.publish_v2(AUDIENCE, 1, 1).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Server);
    assert!(!err.is_server_refusal());
    assert_eq!(client.current_one_time_count(), 1);
}

#[tokio::test]
async fn prepare_publish_v2_preserving_retains_oldest_generation_and_manifest_digest() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);

    let p1 = bob.prepare_publish_v2(AUDIENCE, 2, 2).unwrap();
    let spk1 = bob.current_signed_prekey().unwrap();
    let digest1 =
        protocol::handshake_v2::manifest_digest(p1.request.manifest.as_ref().unwrap()).unwrap();
    bob.transmit_publish_v2(&p1).await.unwrap();
    bob.commit_publish_v2(p1);

    let init = alice
        .prepare_initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"deferred-gen1",
            mb.clone(),
        )
        .await
        .unwrap();
    let deferred_msg = InitialMessageV2::try_from(init.request.message.as_ref().unwrap()).unwrap();

    for _ in 0..5 {
        let prep = bob
            .prepare_publish_v2_preserving(AUDIENCE, 1, 1, &[spk1], &[digest1])
            .unwrap();
        bob.transmit_publish_v2(&prep).await.unwrap();
        bob.commit_publish_v2(prep);
    }
    assert_eq!(bob.oldest_evictable_signed_prekey(), Some(spk1));

    let count_before = bob.current_one_time_count();
    let refused = bob
        .prepare_publish_v2_preserving(AUDIENCE, 3, 2, &[spk1], &[digest1])
        .unwrap();
    bob.rollback_publish_v2_on_refusal(refused);
    assert_eq!(bob.current_one_time_count(), count_before);

    let AcceptedInitial::Accepted { first_message, .. } = bob
        .accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &deferred_msg,
            mb,
        )
        .unwrap()
    else {
        panic!("deferred Gen 1 PQXDH initial must still decrypt after preserved rotations");
    };
    assert_eq!(first_message, b"deferred-gen1");

    let rotated = bob.prepare_publish_v2(AUDIENCE, 1, 1).unwrap();
    bob.commit_publish_v2(rotated);
    assert_ne!(bob.oldest_evictable_signed_prekey(), Some(spk1));
}

#[tokio::test]
async fn signed_pq_off_manifest_allows_repeated_rekeying_and_discard_active() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    alice.publish_v2(AUDIENCE, 4, 4).await.unwrap();
    bob.publish_v2(AUDIENCE, 4, 4).await.unwrap();

    let mut alice_sess = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"pq-hi",
            mb.clone(),
        )
        .await
        .unwrap();
    assert!(alice_sess.peer_pq_state().pq_pinned);
    assert!(alice_sess.peer_pq_state().peer_pq_capable);
    assert_eq!(alice_sess.peer_pq_state().pinned_manifest_seq, 1);

    bob.set_pq_config(PqConfig {
        pq_enabled: false,
        strict_pq: false,
        ..PqConfig::default()
    })
    .unwrap();
    bob.publish_v2(AUDIENCE, 6, 0).await.unwrap();

    alice_sess.peer_pq_state_mut().approve_classical_exception();
    alice
        .start_again_v2(AUDIENCE, &mut alice_sess, b"off-rekey-1")
        .await
        .unwrap();
    assert!(!alice_sess.peer_pq_state().peer_pq_capable);
    assert_eq!(alice_sess.peer_pq_state().pinned_manifest_seq, 2);

    alice
        .start_again_v2(AUDIENCE, &mut alice_sess, b"off-rekey-2")
        .await
        .unwrap();
    assert!(!alice_sess.peer_pq_state().peer_pq_capable);

    let mut bob_discard = bob
        .initiate_v2(
            AUDIENCE,
            &alice.identity_key(),
            &PeerPqState::default(),
            b"c1",
            mb,
        )
        .await
        .unwrap();
    let _ = bob_discard.encrypt(b"c2").unwrap();
    bob_discard.discard_active();
    assert!(bob_discard.needs_new_session());
    #[cfg(feature = "prost")]
    {
        let proto_after: session::proto::SessionState = bob_discard.state().into();
        assert!(proto_after.others.is_empty());
    }
}

#[tokio::test]
async fn fast_clock_does_not_poison_v2_rpcs_and_refused_rotation_rolls_back_generation() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store, AUDIENCE);

    let fast_clock = session::ServerClock::default();
    let now_ms = fast_clock.now();
    fast_clock.observe(now_ms + 2 * 60 * 60 * 1000);
    let mut bob = Client::new(hs).with_clock(fast_clock);
    let fast_prep = bob.prepare_publish_v2(AUDIENCE, 2, 2).unwrap();
    let fast_err = bob.transmit_publish_v2(&fast_prep).await.unwrap_err();
    assert_eq!(fast_err.kind(), ErrorKind::Protocol);
    bob.rollback_publish_v2_on_refusal(fast_prep);
    assert_eq!(bob.prekey_generation(), 0);

    bob.clock().observe(now_ms);
    bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();
    assert_eq!(bob.prekey_generation(), 1);
    let _ = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();

    let spk1 = bob.current_signed_prekey().unwrap();
    bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();
    let spk2 = bob.current_signed_prekey().unwrap();
    assert_eq!(bob.prekey_generation(), 2);
    assert_eq!(bob.oldest_evictable_signed_prekey(), Some(spk1));

    let gen3 = bob.prepare_publish_v2(AUDIENCE, 2, 2).unwrap();
    assert_eq!(bob.prekey_generation(), 3);
    assert_ne!(bob.current_signed_prekey(), Some(spk2));
    // Deferred eviction (R5-P1-1): `spk1` stays retained until `commit_publish_v2` confirms gen3.
    assert_eq!(bob.oldest_evictable_signed_prekey(), Some(spk1));
    bob.rollback_publish_v2_on_refusal(gen3);
    assert_eq!(bob.prekey_generation(), 2);
    assert_eq!(bob.current_signed_prekey(), Some(spk2));
    assert_eq!(bob.oldest_evictable_signed_prekey(), Some(spk1));
    bob.refill_prekeys_v2(AUDIENCE, 1, 1).await.unwrap();
}

#[tokio::test]
async fn merge_rejects_stale_incoming_classical_exception_and_list_batch_updates_peer_state() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    bob.publish_v2(AUDIENCE, 6, 6).await.unwrap();
    alice.publish_v2(AUDIENCE, 6, 6).await.unwrap();

    let _ = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"pq-first",
            mb.clone(),
        )
        .await
        .unwrap();
    alice
        .set_pq_config(PqConfig {
            pq_enabled: false,
            strict_pq: false,
            ..PqConfig::default()
        })
        .unwrap();
    let _ = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"classical-second",
            mb.clone(),
        )
        .await
        .unwrap();

    let mut pre_batch = PeerPqState::default();
    pre_batch.approve_classical_exception();
    let page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let batch = bob.accept_listed_v2(&page, mb.clone(), |_| pre_batch.clone());
    bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
        .await
        .unwrap();
    assert_eq!(batch.outcomes.len(), 2);
    let mut iter = batch.outcomes.into_iter();
    let AcceptedInitial::Accepted {
        session: mut pq_sess,
        ..
    } = iter.next().unwrap().1
    else {
        panic!("first initial must be accepted PQ");
    };
    assert!(matches!(
        iter.next().unwrap().1,
        AcceptedInitial::Quarantined { .. }
    ));
    assert!(pq_sess.peer_pq_state().pq_pinned);
    assert!(!pq_sess.peer_pq_state().allow_classical_exception);

    let _ = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"classical-stale-flag",
            mb.clone(),
        )
        .await
        .unwrap();
    let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let AcceptedInitial::Accepted {
        session: mut stale_classical,
        ..
    } = bob
        .accept_initial_v2(&alice.identity_key(), &pre_batch, &listed.messages[0], mb)
        .unwrap()
    else {
        panic!("accepted under stale pre_batch");
    };
    stale_classical
        .peer_pq_state_mut()
        .approve_classical_exception();
    assert_eq!(
        pq_sess
            .accept_replacement(stale_classical)
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );
}

#[tokio::test]
async fn publish_prepare_error_and_stale_rollback_preserve_state() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store, AUDIENCE);

    let near_max_clock = session::ServerClock::with_max_drift(u64::MAX);
    near_max_clock.observe(protocol::MAX_SAFE_INTEGER - 10);
    let mut bob = Client::new(hs.clone()).with_clock(near_max_clock);
    assert_eq!(
        bob.prepare_publish_v2(AUDIENCE, 2, 2).unwrap_err().kind(),
        ErrorKind::Protocol
    );
    assert!(bob.current_signed_prekey().is_none());
    assert_eq!(bob.prekey_generation(), 0);

    let skewed_clock = session::ServerClock::default();
    skewed_clock.observe(skewed_clock.now() + 25 * 60 * 60 * 1000);
    let mut bob_skewed = Client::new(hs.clone()).with_clock(skewed_clock);
    assert_eq!(
        bob_skewed
            .prepare_publish_v2(AUDIENCE, 2, 2)
            .unwrap_err()
            .kind(),
        ErrorKind::ClockSkew
    );
    assert!(bob_skewed.current_signed_prekey().is_none());
    assert_eq!(bob_skewed.prekey_generation(), 0);
    assert_eq!(bob_skewed.manifest_seq(), 0);

    let mut carol = Client::new(hs);
    carol.publish_v2(AUDIENCE, 2, 2).await.unwrap();
    let stale_prep = carol.prepare_publish_v2(AUDIENCE, 1, 1).unwrap();
    let newer_prep = carol.prepare_publish_v2(AUDIENCE, 1, 1).unwrap();
    let newer_seq = carol.manifest_seq();
    let newer_gen = carol.prekey_generation();
    carol.commit_publish_v2(newer_prep);
    carol.rollback_publish_v2_on_refusal(stale_prep);
    assert_eq!(carol.manifest_seq(), newer_seq);
    assert_eq!(carol.prekey_generation(), newer_gen);
}

#[cfg(feature = "prost")]
#[tokio::test]
async fn far_future_persisted_last_timestamp_recovers_on_refill() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store, AUDIENCE);
    let clock = session::ServerClock::default();
    let now_ms = clock.now();
    clock.observe(now_ms);
    let mut carol = Client::new(hs.clone()).with_clock(clock);
    carol.publish_v2(AUDIENCE, 2, 2).await.unwrap();
    let mut proto_state: session::proto::ClientState = carol.state().into();
    proto_state.last_timestamp = now_ms + protocol::MAX_CLOCK_SKEW + 60_000;
    let restored = session::ClientState::try_from(&proto_state).unwrap();
    let mut carol = Client::restore(hs, restored);
    carol.clock().observe(now_ms);
    carol.refill_prekeys_v2(AUDIENCE, 1, 1).await.unwrap();
}

#[tokio::test]
async fn carried_initial_id_and_sender_validation_and_retired_hello() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut carol = Client::new(hs.clone());
    let bob = Client::new(hs);
    alice.publish_v2(AUDIENCE, 2, 2).await.unwrap();
    carol.publish_v2(AUDIENCE, 2, 2).await.unwrap();

    let mut alice_sess = alice
        .initiate_v2(
            AUDIENCE,
            &carol.identity_key(),
            &PeerPqState::default(),
            b"hello",
            mb.clone(),
        )
        .await
        .unwrap();

    let sealed = alice_sess.encrypt(b"msg").unwrap();
    let mut bad_push = alice_sess.push_v2_request(&sealed);
    let carried = bad_push.initial_message.as_mut().expect("carried initial");
    carried.id = 99;
    let encoded_zeroed = protocol::mailbox_v2::encode_carried_initial(carried).unwrap();
    assert_eq!(
        protocol::mailbox_v2::decode_carried_initial(&encoded_zeroed)
            .unwrap()
            .id,
        0
    );
    assert_eq!(
        InitialMessageV2::decode_carried(&encoded_zeroed)
            .unwrap()
            .id,
        0
    );
    assert_eq!(
        mb.push_v2(bad_push).await.unwrap_err().kind(),
        protocol::ErrorKind::Malformed
    );

    // Without a registered grant on Carol's mailbox, even a well-formed push is refused with
    // `WriteTokenRejected`.
    assert_eq!(
        alice_sess.push_v2(&sealed).await.unwrap_err().kind(),
        ErrorKind::WriteTokenRejected
    );

    // If a carried initial's claimed `identity_key` is swapped to Bob's key, Carol's
    // `accept_initial_v2` rejects it (UnexpectedPeer against Alice, InvalidInitialMessage against
    // Bob because cryptographic DH fails).
    let mut forged_carried_wire = alice_sess
        .push_v2_request(&sealed)
        .initial_message
        .clone()
        .expect("carried initial");
    forged_carried_wire.identity_key = Bytes::copy_from_slice(&bob.identity_key());
    let forged_carried = InitialMessageV2::try_from(&forged_carried_wire).unwrap();
    assert_eq!(
        carol
            .accept_initial_v2(
                &alice.identity_key(),
                &PeerPqState::default(),
                &forged_carried,
                mb.clone(),
            )
            .unwrap_err()
            .kind(),
        ErrorKind::UnexpectedPeer
    );
    assert_eq!(
        carol
            .accept_initial_v2(
                &bob.identity_key(),
                &PeerPqState::default(),
                &forged_carried,
                mb
            )
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInitialMessage
    );

    // Retired session does not raise a false-positive downgrade for a PQ-capable peer.
    let mut retired_sess = alice_sess;
    retired_sess.retire();
    assert!(retired_sess.needs_new_session());
    let late_hello = Hello {
        name: "Carol".into(),
        pq_capable: true,
        max_version: x3dh::PQXDH_VERSION,
        session_seq: 1,
        offered_suites: vec![u32::from(PqSuite::MlKem1024.as_u8())],
        pq_ratchet_capable: true,
    };
    let check = retired_sess.check_peer_hello(&late_hello, true);
    assert!(!check.downgrade_detected);
    assert!(!retired_sess.peer_pq_state().downgrade_detected);
    assert!(retired_sess.peer_pq_state().pq_pinned);
}

#[tokio::test]
async fn crossed_mixed_pq_classical_prefers_pq_and_stale_hello_preserves_state() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut dave = Client::new(hs.clone());
    let mut erin = Client::new(hs);
    dave.publish_v2(AUDIENCE, 4, 4).await.unwrap();
    erin.publish_v2(AUDIENCE, 4, 4).await.unwrap();

    let erin_pq = erin
        .initiate_v2(
            AUDIENCE,
            &dave.identity_key(),
            &PeerPqState::default(),
            b"erin-pq",
            mb.clone(),
        )
        .await
        .unwrap();
    dave.set_pq_config(PqConfig {
        pq_enabled: false,
        preferred_suite: PqConfig::default_suite(),
        pq_ratchet_enabled: false,
        strict_pq: false,
    })
    .unwrap();
    let dave_cl = dave
        .initiate_v2(
            AUDIENCE,
            &erin.identity_key(),
            &PeerPqState::default(),
            b"dave-cl",
            mb.clone(),
        )
        .await
        .unwrap();
    let dave_listed = dave
        .list_initial_messages_v2(AUDIENCE, 0, 10)
        .await
        .unwrap();
    let erin_listed = erin
        .list_initial_messages_v2(AUDIENCE, 0, 10)
        .await
        .unwrap();

    dave.set_pq_config(PqConfig::default()).unwrap();
    let mut dave_sess = dave_cl;
    dave_sess.peer_pq_state_mut().approve_classical_exception();
    let AcceptedInitial::Accepted {
        session: dave_accepted_pq,
        ..
    } = dave
        .accept_initial_v2(
            &erin.identity_key(),
            dave_sess.peer_pq_state(),
            &dave_listed.messages[0],
            mb.clone(),
        )
        .unwrap()
    else {
        panic!("expected Dave to accept Erin's PQ initial");
    };
    assert!(dave_sess.accept_replacement(dave_accepted_pq).unwrap());
    assert!(dave_sess.security().unwrap().is_pq);
    assert!(!dave_sess.peer_pq_state().allow_classical_exception);

    let mut erin_sess = erin_pq;
    let AcceptedInitial::Quarantined {
        session: erin_accepted_cl,
        peer_was_pq_pinned: true,
        ..
    } = erin
        .accept_initial_v2(
            &dave.identity_key(),
            erin_sess.peer_pq_state(),
            &erin_listed.messages[0],
            mb,
        )
        .unwrap()
    else {
        panic!("expected Erin to quarantine Dave's classical initial");
    };
    assert!(
        !erin_sess
            .accept_replacement_with_policy(erin_accepted_cl, false)
            .unwrap()
    );
    assert!(erin_sess.security().unwrap().is_pq);

    let mut peer_state = PeerPqState::default();
    peer_state.approve_classical_exception();
    let hello = Hello {
        name: "Peer".into(),
        pq_capable: true,
        max_version: x3dh::PQXDH_VERSION,
        session_seq: 1,
        offered_suites: vec![u32::from(PqSuite::MlKem1024.as_u8())],
        pq_ratchet_capable: true,
    };
    let hc = check_peer_hello(&mut peer_state, SessionSecurity::classical(), &hello, true);
    assert!(hc.downgrade_detected);
    assert!(peer_state.pq_pinned);
    assert!(!peer_state.allow_classical_exception);

    let mut peer_after_pq_off = PeerPqState {
        pq_pinned: true,
        pinned_manifest_seq: 2,
        pinned_manifest_digest: None,
        peer_pq_capable: false,
        allow_classical_exception: true,
        downgrade_detected: false,
        peer_session_seq: 2,
    };
    let stale_res = check_peer_hello(
        &mut peer_after_pq_off,
        SessionSecurity::classical(),
        &hello,
        true,
    );
    assert!(stale_res.stale_session_seq);
    assert!(!stale_res.downgrade_detected);
    assert!(!peer_after_pq_off.peer_pq_capable);
    assert!(peer_after_pq_off.allow_classical_exception);
    assert_eq!(peer_after_pq_off.peer_session_seq, 2);
}
