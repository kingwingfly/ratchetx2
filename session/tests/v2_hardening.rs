//! Prost state restoration & validation hardening tests covering `ClientState` unified mailbox
//! cursors/grant versions, `SessionState` write tokens, `EarlierSession.inbound_token_hash`,
//! `PendingGrant` bounds/deduplication, and `PeerPqState` manifest digest invariants.

#![cfg(feature = "prost")]

mod common;

use session::{Client, ErrorKind, PeerPqState, PqConfig, proto};

use common::{AUDIENCE, SharedStore, V2OnlyHandshake, V2OnlyMailbox};

#[tokio::test]
async fn state_validation_on_prost_restore_rejects_corruption() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);
    let off = PqConfig {
        pq_enabled: false,
        ..PqConfig::default()
    };
    let mut alice = Client::new(hs.clone()).with_pq_config(off.clone()).unwrap();
    let mut bob = Client::new(hs).with_pq_config(off).unwrap();
    bob.publish_v2(AUDIENCE, 2, 0).await.unwrap();
    let alice_session = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"hi",
            mb,
        )
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
    proto_client.strict_pq = false;

    // Unified mailbox cursor & grant version invariants on ClientState.
    let mut bad_cursor = proto_client.clone();
    bad_cursor.mailbox_cursor = protocol::MAX_SAFE_INTEGER + 1;
    assert_eq!(
        session::ClientState::try_from(&bad_cursor)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    let mut bad_ack = proto_client.clone();
    bad_ack.mailbox_cursor = 5;
    bad_ack.pending_mailbox_ack = 6;
    assert_eq!(
        session::ClientState::try_from(&bad_ack).unwrap_err().kind(),
        ErrorKind::MalformedState
    );

    let mut bad_ver = proto_client.clone();
    bad_ver.next_grant_version = protocol::MAX_SAFE_INTEGER + 1;
    assert_eq!(
        session::ClientState::try_from(&bad_ver).unwrap_err().kind(),
        ErrorKind::MalformedState
    );

    let default_v3_client = proto::ClientState {
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
        mailbox_cursor: 0,
        pending_mailbox_ack: 0,
        next_grant_version: 0,
    };
    let restored_client = session::ClientState::try_from(&default_v3_client).unwrap();
    assert_eq!(restored_client.next_grant_version(), 1);
    assert!(restored_client.pq_config().pq_enabled);
    assert_eq!(
        !restored_client.pq_config().offered_suites().is_empty(),
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
    let carol = Client::new(());
    swapped_peer.peer = carol.identity_key().to_vec();
    assert_eq!(
        session::SessionState::try_from(&swapped_peer)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    // Active write-token / inbound_token_hash validation.
    let mut bad_send_token = base_session.clone();
    bad_send_token.send_write_token = vec![1; 16];
    assert_eq!(
        session::SessionState::try_from(&bad_send_token)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    let mut bad_inbound_hash = base_session.clone();
    bad_inbound_hash.inbound_token_hash = vec![2; 16];
    assert_eq!(
        session::SessionState::try_from(&bad_inbound_hash)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    // Retired session with stray send_write_token or inbound_token_hash is rejected.
    let mut stray_retired = base_session.clone();
    stray_retired.party = None;
    stray_retired.id.clear();
    stray_retired.known_by_peer = false;
    stray_retired.initial_message.clear();
    stray_retired.active_security = None;
    stray_retired.active_peer_session_seq = 0;
    assert_eq!(
        session::SessionState::try_from(&stray_retired)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );
    stray_retired.send_write_token.clear();
    assert_eq!(
        session::SessionState::try_from(&stray_retired)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );
    stray_retired.inbound_token_hash.clear();
    assert!(session::SessionState::try_from(&stray_retired).is_ok());

    // EarlierSession bounds and inbound_token_hash length validation.
    let mut bad_earlier_hash = base_session.clone();
    bad_earlier_hash.others.push(proto::EarlierSession {
        party: base_session.party.clone(),
        inbound_token_hash: vec![3; 12],
    });
    assert_eq!(
        session::SessionState::try_from(&bad_earlier_hash)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    let mut too_many_others = base_session.clone();
    for _ in 0..=session::KEPT_SESSIONS {
        too_many_others.others.push(proto::EarlierSession {
            party: base_session.party.clone(),
            inbound_token_hash: base_session.inbound_token_hash.clone(),
        });
    }
    assert_eq!(
        session::SessionState::try_from(&too_many_others)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    // PendingGrant validation: zero version, bad hash length, duplicate hash, and cap > 4.
    let mut zero_ver_grant = base_session.clone();
    zero_ver_grant
        .pending_register_grants
        .push(proto::PendingGrant {
            token_hash: vec![0x11; 32],
            grant_version: 0,
            pin_active: true,
        });
    assert_eq!(
        session::SessionState::try_from(&zero_ver_grant)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    let mut dup_grant = base_session.clone();
    dup_grant.pending_register_grants = vec![
        proto::PendingGrant {
            token_hash: vec![0x22; 32],
            grant_version: 1,
            pin_active: false,
        },
        proto::PendingGrant {
            token_hash: vec![0x22; 32],
            grant_version: 2,
            pin_active: true,
        },
    ];
    assert_eq!(
        session::SessionState::try_from(&dup_grant)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    let mut too_many_grants = base_session.clone();
    for i in 0..=(session::MAX_PENDING_REGISTER_GRANTS as u8) {
        too_many_grants
            .pending_register_grants
            .push(proto::PendingGrant {
                token_hash: vec![i + 1; 32],
                grant_version: u64::from(i) + 1,
                pin_active: false,
            });
    }
    assert_eq!(
        session::SessionState::try_from(&too_many_grants)
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

    let mut mismatched_pq = base_session.clone();
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

    let mut bad_digest_len = base_session.clone();
    bad_digest_len.peer_pq = Some(proto::PeerPqState {
        pinned_manifest_seq: 1,
        pinned_manifest_digest: vec![0xAA; 16],
        ..proto::PeerPqState::default()
    });
    assert_eq!(
        session::SessionState::try_from(&bad_digest_len)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    let mut digest_without_seq = base_session.clone();
    digest_without_seq.peer_pq = Some(proto::PeerPqState {
        pinned_manifest_seq: 0,
        pinned_manifest_digest: vec![0xBB; 32],
        ..proto::PeerPqState::default()
    });
    assert_eq!(
        session::SessionState::try_from(&digest_without_seq)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );

    let mut valid_digest = base_session;
    valid_digest.peer_pq = Some(proto::PeerPqState {
        pinned_manifest_seq: 3,
        pinned_manifest_digest: vec![0xCC; 32],
        ..proto::PeerPqState::default()
    });
    assert_eq!(
        session::SessionState::try_from(&valid_digest)
            .unwrap()
            .peer_pq_state()
            .pinned_manifest_digest,
        Some([0xCC; 32])
    );
}
