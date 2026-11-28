//! Targeted regression tests for security, crypto, serialization, storage, clock, and attachment
//! hardening fixes.

mod common;

use bytes::Bytes;
use session::{Client, ErrorKind, PeerPqState, PqConfig, ServerClock};

use common::AUDIENCE;
#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
use common::{SharedStore, V2OnlyHandshake, V2OnlyMailbox, receive_for, register_active_grant};

#[test]
fn compiled_suites_follow_session_crate_features() {
    let suites = PqConfig::compiled_suites();
    assert_eq!(
        suites.contains(&session::PqSuite::MlKem1024),
        cfg!(feature = "ml-kem-1024")
    );
    assert_eq!(
        suites.contains(&session::PqSuite::MlKem768),
        cfg!(feature = "ml-kem-768")
    );
    assert_eq!(
        PqConfig::is_compiled_suite(session::PqSuite::MlKem1024),
        cfg!(feature = "ml-kem-1024")
    );
    assert_eq!(
        PqConfig::is_compiled_suite(session::PqSuite::MlKem768),
        cfg!(feature = "ml-kem-768")
    );
}

#[tokio::test]
async fn missing_manifest_is_downgrade_detected_in_all_feature_builds() {
    let store = common::SharedStore::default();
    let hs = common::V2OnlyHandshake::new(store, AUDIENCE);
    let mut bob = Client::new(hs.clone())
        .with_pq_config(PqConfig {
            pq_enabled: false,
            ..PqConfig::default()
        })
        .unwrap();
    bob.publish_v2(AUDIENCE, 2, 0).await.unwrap();

    let mut alice = Client::new(common::AttackingHandshake {
        inner: hs,
        attack: common::AttackMode::StripManifest,
    })
    .with_pq_config(PqConfig {
        pq_enabled: false,
        ..PqConfig::default()
    })
    .unwrap();
    assert_eq!(
        alice
            .prepare_initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"hi",
                (),
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[tokio::test]
async fn stale_incoming_session_seq_rejected_before_confirming_prekeys() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    bob.publish_v2(AUDIENCE, 4, 4).await.unwrap();
    let suite = PqConfig::default_suite();

    let _ = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &common::hello_bytes("alice", 1, true),
            mb.clone(),
        )
        .await
        .unwrap();
    let _ = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &common::hello_bytes("alice", 2, true),
            mb.clone(),
        )
        .await
        .unwrap();

    let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    assert_eq!(listed.messages.len(), 2);

    let session::AcceptedInitial::Accepted {
        session: bob_sess, ..
    } = bob
        .accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &listed.messages[1],
            mb.clone(),
        )
        .unwrap()
    else {
        panic!("expected seq 2 accepted");
    };
    assert_eq!(bob_sess.peer_pq_state().peer_session_seq, 2);

    let opks_before = bob.current_one_time_count();
    let pq_opks_before = bob.current_pq_one_time_count(suite);
    assert_eq!(
        bob.accept_initial_v2(
            &alice.identity_key(),
            bob_sess.peer_pq_state(),
            &listed.messages[0],
            mb,
        )
        .unwrap_err()
        .kind(),
        ErrorKind::StaleSession
    );
    assert_eq!(bob.current_one_time_count(), opks_before);
    assert_eq!(bob.current_pq_one_time_count(suite), pq_opks_before);
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[tokio::test]
async fn relay_pq_off_fallback_allocates_fresh_manifest_seq_and_records_off_digest() {
    use common::ToggleableHandshake;
    use std::sync::atomic::Ordering;

    let store = SharedStore::default();
    let (hs, enabled) = ToggleableHandshake::new(store.clone(), AUDIENCE);
    let mut bob = Client::new(hs.clone());
    let alice = Client::new(hs);

    bob.publish_v2(AUDIENCE, 3, 3).await.unwrap();
    assert_eq!(bob.manifest_seq(), 1);

    enabled.store(false, Ordering::Relaxed);
    let prep = bob.prepare_publish_v2(AUDIENCE, 3, 3).unwrap();
    assert_eq!(bob.manifest_seq(), 2);
    let outcome = bob.transmit_publish_v2(&prep).await.unwrap();
    assert_eq!(outcome, session::PublishV2Outcome::ServerPqDisabled);
    assert_eq!(bob.manifest_seq(), 2);
    let still_on = storage::LocalPqHandshakeStore::get_manifest(&store, &bob.identity_key())
        .await
        .unwrap()
        .unwrap();
    assert!(still_on.pq_enabled);
    assert_eq!(still_on.manifest_seq, 1);

    let off_prep = bob.prepare_publish_v2_classical_off(prep, &[]).unwrap();
    assert_eq!(bob.manifest_seq(), 3);
    assert_eq!(bob.current_pq_one_time_count(PqConfig::default_suite()), 0);
    assert_eq!(bob.current_one_time_count(), 3);
    assert_eq!(
        bob.transmit_publish_v2(&off_prep).await.unwrap(),
        session::PublishV2Outcome::V2ClassicalOff
    );
    bob.commit_publish_v2(off_prep);
    assert_eq!(bob.manifest_seq(), 3);

    let stored = storage::LocalPqHandshakeStore::get_manifest(&store, &bob.identity_key())
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.pq_enabled);
    assert_eq!(stored.manifest_seq, 3);
    enabled.store(true, Ordering::Relaxed);
    let published = alice
        .fetch_peer_manifest(AUDIENCE, &bob.identity_key())
        .await
        .unwrap()
        .unwrap();
    assert!(!published.pq_enabled);
    assert_eq!(published.manifest_seq, 3);
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[tokio::test]
async fn full_preserve_list_never_evicts_new_digest_and_rollback_preserves_fifo_order() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);

    let mut digests = Vec::new();
    for _ in 0..4 {
        let p = bob.prepare_publish_v2(AUDIENCE, 2, 2).unwrap();
        digests.push(
            protocol::handshake_v2::manifest_digest(p.request.manifest.as_ref().unwrap()).unwrap(),
        );
        bob.transmit_publish_v2(&p).await.unwrap();
        bob.commit_publish_v2(p);
    }

    let p5 = bob
        .prepare_publish_v2_preserving(AUDIENCE, 2, 2, &[], &digests)
        .unwrap();
    bob.transmit_publish_v2(&p5).await.unwrap();
    bob.commit_publish_v2(p5);

    let _ = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"against-5th-manifest",
            mb.clone(),
        )
        .await
        .unwrap();
    let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    assert!(matches!(
        bob.accept_initial_v2(
            &alice.identity_key(),
            &PeerPqState::default(),
            &listed.messages[0],
            mb,
        )
        .unwrap(),
        session::AcceptedInitial::Accepted { .. }
    ));

    let seq_before = bob.manifest_seq();
    let p6 = bob.prepare_publish_v2(AUDIENCE, 1, 1).unwrap();
    bob.rollback_publish_v2_on_refusal(p6);
    assert_eq!(bob.manifest_seq(), seq_before);
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[tokio::test]
async fn approved_signed_pq_off_inbound_classical_clears_downgrade_detected() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mb = V2OnlyMailbox::new(store, AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs);
    alice.publish_v2(AUDIENCE, 4, 4).await.unwrap();
    bob.publish_v2(AUDIENCE, 4, 4).await.unwrap();

    let _ = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &common::hello_bytes("alice", 1, true),
            mb.clone(),
        )
        .await
        .unwrap();
    let page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let mut batch = bob.accept_listed_v2(&page, mb.clone(), |_| PeerPqState::default());
    bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
        .await
        .unwrap();
    let mut bob_sess = match batch.outcomes.pop().unwrap().1 {
        session::AcceptedInitial::Accepted { session, .. } => session,
        _ => panic!("expected PQ accepted"),
    };

    bob_sess.peer_pq_state_mut().downgrade_detected = true;
    bob_sess.peer_pq_state_mut().peer_pq_capable = false;
    bob_sess.peer_pq_state_mut().approve_classical_exception();
    assert!(!bob_sess.peer_pq_state().downgrade_detected);

    alice
        .set_pq_config(PqConfig {
            pq_enabled: false,
            strict_pq: false,
            ..PqConfig::default()
        })
        .unwrap();
    alice.publish_v2(AUDIENCE, 4, 0).await.unwrap();
    let _ = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &common::hello_bytes("alice", 2, false),
            mb.clone(),
        )
        .await
        .unwrap();

    // R19-P1-3: A live `downgrade_detected` alarm MUST block inbound classical replacement and
    // remain preserved in the quarantined session even when a prior signed-PQ-OFF exception was
    // set, until explicitly cleared by fresh approval.
    bob_sess.peer_pq_state_mut().pinned_manifest_seq = 2;
    bob_sess.peer_pq_state_mut().downgrade_detected = true;
    let listed = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let quarantined = match bob
        .accept_initial_v2(
            &alice.identity_key(),
            bob_sess.peer_pq_state(),
            &listed.messages[0],
            mb.clone(),
        )
        .unwrap()
    {
        session::AcceptedInitial::Quarantined { session, .. } => session,
        session::AcceptedInitial::Accepted { .. } => {
            panic!("live downgrade_detected must quarantine inbound classical initial");
        }
    };
    assert!(quarantined.peer_pq_state().downgrade_detected);
    assert_eq!(
        bob_sess
            .accept_replacement_with_policy(quarantined, true)
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );
    assert!(bob_sess.peer_pq_state().downgrade_detected);

    // Once the live downgrade alarm is explicitly cleared via fresh approval on the signed-OFF
    // peer (`pinned_manifest_seq > 0 && !peer_pq_capable`), a subsequent classical rekey succeeds.
    bob_sess.peer_pq_state_mut().approve_classical_exception();
    assert!(!bob_sess.peer_pq_state().downgrade_detected);
    let _ = alice
        .initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            &common::hello_bytes("alice", 3, false),
            mb.clone(),
        )
        .await
        .unwrap();
    let listed2 = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let incoming = match bob
        .accept_initial_v2(
            &alice.identity_key(),
            bob_sess.peer_pq_state(),
            listed2.messages.last().unwrap(),
            mb,
        )
        .unwrap()
    {
        session::AcceptedInitial::Accepted { session, .. } => session,
        session::AcceptedInitial::Quarantined { .. } => {
            panic!("clean approved signed PQ-OFF inbound classical must be accepted");
        }
    };
    assert!(!incoming.peer_pq_state().downgrade_detected);
    assert!(
        bob_sess
            .accept_replacement_with_policy(incoming, true)
            .unwrap()
    );
    assert!(!bob_sess.peer_pq_state().downgrade_detected);
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[tokio::test]
async fn old_chain_duplicate_message_surfaces_duplicate_without_stalling_unified_mailbox() {
    use protocol::mailbox_v2::LocalMailboxV2 as _;

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
            b"hi",
            mb.clone(),
        )
        .await
        .unwrap();
    register_active_grant(&mut alice, &alice_sess, &mb).await;

    let page = bob.list_initial_messages_v2(AUDIENCE, 0, 10).await.unwrap();
    let mut batch = bob.accept_listed_v2(&page, mb.clone(), |_| PeerPqState::default());
    bob.ack_initial_messages_v2(AUDIENCE, batch.ack_ids)
        .await
        .unwrap();
    let mut bob_sess = match batch.outcomes.pop().unwrap().1 {
        session::AcceptedInitial::Accepted { session, .. } => session,
        _ => panic!("expected accepted"),
    };
    register_active_grant(&mut bob, &bob_sess, &mb).await;

    let _held_msg0 = alice_sess.encrypt(b"chain1-skipped").unwrap();
    let old_msg = alice_sess.encrypt(b"chain1-msg").unwrap();
    alice_sess.push_v2(&old_msg).await.unwrap();
    assert_eq!(
        receive_for(&mut bob, &mut bob_sess, &mb).await[0]
            .as_ref()
            .unwrap()
            .content,
        b"chain1-msg"
    );

    bob_sess.send_v2(b"bob-turn").await.unwrap();
    assert_eq!(
        receive_for(&mut alice, &mut alice_sess, &mb).await[0]
            .as_ref()
            .unwrap()
            .content,
        b"bob-turn"
    );

    alice_sess.send_v2(b"chain2-msg1").await.unwrap();
    assert_eq!(
        receive_for(&mut bob, &mut bob_sess, &mb).await[0]
            .as_ref()
            .unwrap()
            .content,
        b"chain2-msg1"
    );

    let dup_req = alice_sess.push_v2_request_with_id(&old_msg, Some([0x99; 16]));
    mb.push_v2(dup_req).await.unwrap();
    alice_sess.send_v2(b"chain2-after-dup").await.unwrap();

    let rx = receive_for(&mut bob, &mut bob_sess, &mb).await;
    assert_eq!(rx.len(), 2, "old-chain duplicate must NOT stall decryption");
    assert_eq!(
        rx[0].as_ref().unwrap_err().kind(),
        ErrorKind::DuplicateMessage
    );
    assert_eq!(rx[1].as_ref().unwrap().content, b"chain2-after-dup");
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[tokio::test]
async fn claim_bundle_preserves_opks_on_strict_pq_empty_or_disjoint_suites() {
    use protocol::handshake_v2::{ClaimBundleRequest, LocalHandshakeV2 as _};
    use storage::LocalPqHandshakeStore as _;

    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mut strict_bob = Client::new(hs.clone())
        .with_pq_config(PqConfig {
            strict_pq: true,
            ..PqConfig::default()
        })
        .unwrap();
    strict_bob.publish_v2(AUDIENCE, 3, 3).await.unwrap();

    let before = store.pq_snapshot(&strict_bob.identity_key()).await.unwrap();
    assert_eq!(before.classical_one_time_count, 3);

    let empty_resp = hs
        .claim_bundle(ClaimBundleRequest {
            identity_key: Bytes::copy_from_slice(&strict_bob.identity_key()),
            preferred_suites: vec![],
        })
        .await
        .unwrap();
    assert!(empty_resp.one_time_prekey.is_none());
    assert!(empty_resp.pq_last_resort.is_none());
    assert!(empty_resp.pq_one_time_prekey.is_none());
    assert!(empty_resp.manifest.as_ref().unwrap().strict_pq);

    assert_eq!(
        hs.claim_bundle(ClaimBundleRequest {
            identity_key: Bytes::copy_from_slice(&strict_bob.identity_key()),
            preferred_suites: vec![99],
        })
        .await
        .unwrap_err()
        .kind(),
        protocol::ErrorKind::Malformed
    );

    let after = store.pq_snapshot(&strict_bob.identity_key()).await.unwrap();
    assert_eq!(
        after.classical_one_time_count,
        before.classical_one_time_count
    );
    assert_eq!(after.pq_one_time_counts, before.pq_one_time_counts);
}

#[cfg(all(
    feature = "prost",
    any(feature = "ml-kem-1024", feature = "ml-kem-768")
))]
#[tokio::test]
async fn state_restore_rejects_empty_manifest_digests_when_manifest_seq_nonzero() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store, AUDIENCE);
    let mut bob = Client::new(hs);
    bob.publish_v2(AUDIENCE, 2, 2).await.unwrap();
    assert_eq!(bob.manifest_seq(), 1);

    let mut proto_client: session::proto::ClientState = bob.state().into();
    assert!(!proto_client.recent_manifest_digests.is_empty());
    proto_client.recent_manifest_digests.clear();
    assert_eq!(
        session::ClientState::try_from(&proto_client)
            .unwrap_err()
            .kind(),
        ErrorKind::MalformedState
    );
}

#[cfg(feature = "serde")]
#[test]
fn serde_bounded_visitors_reject_oversized_collections() {
    use serde::de::{self, Deserialize as _, SeqAccess, Visitor};

    struct HugeSeq {
        remaining: usize,
    }
    impl<'de> SeqAccess<'de> for HugeSeq {
        type Error = de::value::Error;
        fn next_element_seed<T: de::DeserializeSeed<'de>>(
            &mut self,
            seed: T,
        ) -> Result<Option<T::Value>, Self::Error> {
            if self.remaining == 0 {
                return Ok(None);
            }
            self.remaining -= 1;
            seed.deserialize(de::value::U8Deserializer::new(0))
                .map(Some)
        }
        fn size_hint(&self) -> Option<usize> {
            Some(1_000_000_000)
        }
    }

    struct MapWithHugeField(&'static str);
    impl<'de> de::Deserializer<'de> for MapWithHugeField {
        type Error = de::value::Error;
        fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            struct HugeSeqDe;
            impl<'de> de::Deserializer<'de> for HugeSeqDe {
                type Error = de::value::Error;
                fn deserialize_any<V: Visitor<'de>>(
                    self,
                    visitor: V,
                ) -> Result<V::Value, Self::Error> {
                    visitor.visit_seq(HugeSeq { remaining: 50_000 })
                }
                serde::forward_to_deserialize_any! {
                    bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf
                    option unit unit_struct newtype_struct seq tuple tuple_struct map struct
                    enum identifier ignored_any
                }
            }
            struct OneFieldMap(Option<&'static str>);
            impl<'de> de::MapAccess<'de> for OneFieldMap {
                type Error = de::value::Error;
                fn next_key_seed<K: de::DeserializeSeed<'de>>(
                    &mut self,
                    seed: K,
                ) -> Result<Option<K::Value>, Self::Error> {
                    match self.0.take() {
                        Some(k) => seed
                            .deserialize(de::value::StrDeserializer::new(k))
                            .map(Some),
                        None => Ok(None),
                    }
                }
                fn next_value_seed<V: de::DeserializeSeed<'de>>(
                    &mut self,
                    seed: V,
                ) -> Result<V::Value, Self::Error> {
                    seed.deserialize(HugeSeqDe)
                }
            }
            visitor.visit_map(OneFieldMap(Some(self.0)))
        }
        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf
            option unit unit_struct newtype_struct seq tuple tuple_struct map struct
            enum identifier ignored_any
        }
    }

    assert!(
        session::ClientState::deserialize(MapWithHugeField("recent_manifest_digests")).is_err()
    );
    assert!(session::SessionState::deserialize(MapWithHugeField("others")).is_err());
    assert!(
        session::SessionState::deserialize(MapWithHugeField("pending_register_grants")).is_err()
    );
    assert!(party::Party::deserialize(MapWithHugeField("associated_data")).is_err());
    assert!(x3dh::LocalPrekeys::deserialize(MapWithHugeField("generations")).is_err());
}

#[test]
fn clock_http_date_validation_observe_cap_and_skew_boundary() {
    let clock = ServerClock::default();
    let base = clock.now();
    clock.observe(protocol::MAX_SAFE_INTEGER + 1);
    clock.observe(u64::MAX);
    assert!(clock.now().abs_diff(base) < 5_000);

    for bad in [
        "Tue, 06 Nov 1994 08:49:37 GMT",
        "Wed, 31 Feb 2024 00:00:00 GMT",
        "Fri, 29 Feb 2023 00:00:00 GMT",
        "Sun, 06 Nov 1994 08:49:37:00 GMT",
        "Sun, +6 Nov 1994 08:49:37 GMT",
    ] {
        clock.observe_date(bad);
        assert!(
            clock.now().abs_diff(base) < 5_000,
            "bad HTTP date {bad:?} must be ignored"
        );
    }

    clock.observe_date("Thu, 29 Feb 2024 12:00:00 GMT");
    assert_eq!(clock.now() / 1_000, 1_709_208_000);
}

#[tokio::test]
async fn attachment_hardening_short_chunk_sparse_resume_and_debug_redaction() {
    use session::attachment;

    let upload = attachment::Upload::resume(
        [0x11; protocol::attachment::ID_LENGTH],
        [0x22; protocol::attachment::TOKEN_LENGTH],
        zeroize::Zeroizing::new([0x42; 32]),
        2,
    );
    assert_eq!(
        upload.try_encrypt(0, b"too-short").unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );

    let sparse = attachment::Upload::resume_from(
        [0x12; protocol::attachment::ID_LENGTH],
        [0x23; protocol::attachment::TOKEN_LENGTH],
        zeroize::Zeroizing::new([0x43; 32]),
        4,
        1,
    );
    assert_eq!(
        sparse
            .try_encrypt(0, &[0u8; attachment::CHUNK_SIZE])
            .unwrap_err()
            .kind(),
        ErrorKind::NonceReuse
    );
    assert!(
        sparse
            .try_encrypt(2, &[7u8; attachment::CHUNK_SIZE])
            .is_ok()
    );
    assert_eq!(sparse.sealed_chunks(), 3);
    assert_eq!(
        sparse
            .try_encrypt(1, &[0u8; attachment::CHUNK_SIZE])
            .unwrap_err()
            .kind(),
        ErrorKind::NonceReuse
    );
    assert!(
        sparse
            .try_encrypt(2, &[7u8; attachment::CHUNK_SIZE])
            .is_ok()
    );
    assert_eq!(
        sparse
            .try_encrypt(2, &[8u8; attachment::CHUNK_SIZE])
            .unwrap_err()
            .kind(),
        ErrorKind::NonceReuse
    );
    assert!(sparse.try_encrypt(3, b"final").is_ok());

    let start_resp = protocol::attachment::StartUploadResponse {
        id: Bytes::from_static(&[1; 16]),
        upload_token: Bytes::from_static(b"SUPER_SECRET_TKN"),
        expires: 123,
    };
    let dbg_start = format!("{start_resp:?}");
    assert!(!dbg_start.contains("SUPER_SECRET_TKN") && !dbg_start.contains("upload_token"));

    let ptr = protocol::content::AttachmentPointer {
        id: vec![2; 16],
        key: vec![0xDE; 32],
        size: 10,
        expires: 999,
        name: "f.bin".into(),
        mime: "application/octet-stream".into(),
    };
    let dbg_ptr = format!("{ptr:?}");
    assert!(!dbg_ptr.contains("222") && !dbg_ptr.contains("key"));
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[tokio::test]
async fn prekey_rollback_cleans_new_pq_last_resort_and_refill_requires_last_resort() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store, AUDIENCE);
    let suite = PqConfig::default_suite();

    let mut bob = Client::new(hs);
    bob.set_pq_config(PqConfig {
        pq_enabled: false,
        ..PqConfig::default()
    })
    .unwrap();
    bob.publish_v2(AUDIENCE, 2, 0).await.unwrap();
    let spk_gen1 = bob.current_signed_prekey().unwrap();

    bob.set_pq_config(PqConfig::default()).unwrap();
    assert!(bob.prepare_refill_v2(AUDIENCE, 1, 1).is_err());
    let classical_refill = bob.prepare_refill_v2(AUDIENCE, 1, 0).unwrap();
    bob.rollback_refill_v2_on_refusal(classical_refill);
    assert_eq!(bob.current_one_time_count(), 2);

    let prep_ext = bob
        .prepare_publish_v2_preserving(AUDIENCE, 1, 1, &[spk_gen1], &[])
        .unwrap();
    assert_eq!(bob.current_pq_one_time_count(suite), 1);
    bob.rollback_publish_v2_on_refusal(prep_ext);
    assert_eq!(bob.current_pq_one_time_count(suite), 0);
    assert!(bob.prepare_refill_v2(AUDIENCE, 1, 1).is_err());
}

#[tokio::test]
async fn server_clock_combined_policy_and_manifest_equivocation_rejected_across_all_sites() {
    use protocol::handshake_v2::{
        CapabilityManifest, ClaimBundleRequest, ClaimBundleResponse, GetManifestRequest,
        GetManifestResponse, GetServerInfoRequest, GetServerInfoResponse,
        ListInitialMessagesRequest, ListInitialMessagesResponse, LocalHandshakeV2,
        PublishV2Request, PublishV2Response, RefillPrekeysRequest, RefillPrekeysResponse,
        SendInitialV2Request, SendInitialV2Response, manifest_digest, sign_manifest,
    };
    use std::sync::{Arc, Mutex};

    struct StaticManifestHandshake {
        manifest: Arc<Mutex<CapabilityManifest>>,
        spk: [u8; 32],
        spk_sig: [u8; 64],
    }

    impl LocalHandshakeV2 for StaticManifestHandshake {
        async fn get_server_info(
            &self,
            _: GetServerInfoRequest,
        ) -> protocol::Result<GetServerInfoResponse> {
            Ok(GetServerInfoResponse {
                server_id: AUDIENCE.to_string(),
                pq_enabled: false,
                supported_suites: vec![],
                pq_ratchet_supported: false,
            })
        }
        async fn publish_v2(&self, _: PublishV2Request) -> protocol::Result<PublishV2Response> {
            unreachable!()
        }
        async fn refill_prekeys(
            &self,
            _: RefillPrekeysRequest,
        ) -> protocol::Result<RefillPrekeysResponse> {
            unreachable!()
        }
        async fn get_manifest(
            &self,
            _: GetManifestRequest,
        ) -> protocol::Result<GetManifestResponse> {
            Ok(GetManifestResponse {
                manifest: Some(self.manifest.lock().unwrap().clone()),
            })
        }
        async fn claim_bundle(
            &self,
            _: ClaimBundleRequest,
        ) -> protocol::Result<ClaimBundleResponse> {
            let m = self.manifest.lock().unwrap().clone();
            Ok(ClaimBundleResponse {
                signed_prekey: Bytes::copy_from_slice(&self.spk),
                signed_prekey_signature: Some(Bytes::copy_from_slice(&self.spk_sig)),
                one_time_prekey: None,
                manifest: Some(m),
                pq_last_resort: None,
                pq_one_time_prekey: None,
            })
        }
        async fn send_initial_v2(
            &self,
            _: SendInitialV2Request,
        ) -> protocol::Result<SendInitialV2Response> {
            Ok(SendInitialV2Response { id: 1 })
        }
        async fn list_initial_messages(
            &self,
            _: ListInitialMessagesRequest,
        ) -> protocol::Result<ListInitialMessagesResponse> {
            unreachable!()
        }
        async fn ack_initial_messages(
            &self,
            _: protocol::handshake_v2::AckInitialMessagesRequest,
        ) -> protocol::Result<protocol::handshake_v2::AckInitialMessagesResponse> {
            unreachable!()
        }
    }

    let now_ms = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let bob_id = xeddsa::XEdDSAPrivateKey::generate();
    let bob_pub = bob_id.compute_public_key().to_bytes();
    let bob_spk = xeddsa::XEdDSAPrivateKey::generate()
        .compute_public_key()
        .to_bytes();
    let bob_spk_sig = bob_id.sign(bob_spk);

    let hour = 60 * 60 * 1000u64;
    let mut expired_manifest = CapabilityManifest {
        audience: AUDIENCE.to_string(),
        identity_key: Bytes::new(),
        manifest_seq: 1,
        generation: 1,
        issued_at: now_ms - 48 * hour,
        expires_at: now_ms - hour,
        pq_enabled: false,
        strict_pq: false,
        pq_ratchet_supported: false,
        offered_suites: vec![],
        signed_prekey: Bytes::copy_from_slice(&bob_spk),
        pq_last_resort: vec![],
        signature: Bytes::new(),
    };
    sign_manifest(&bob_id, &mut expired_manifest).unwrap();
    let shared_manifest = Arc::new(Mutex::new(expired_manifest.clone()));
    let hs = StaticManifestHandshake {
        manifest: shared_manifest.clone(),
        spk: bob_spk,
        spk_sig: bob_spk_sig,
    };

    let rewound_clock = ServerClock::default();
    rewound_clock.observe(now_ms - 12 * hour);
    assert!(!rewound_clock.is_drift_exceeded());
    let mut alice = Client::new(hs).with_clock(rewound_clock.clone());
    assert_eq!(
        alice
            .get_peer_manifest(AUDIENCE, &bob_pub)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PeerManifestExpired
    );
    let mut peer_state = PeerPqState::default();
    peer_state.approve_classical_exception();
    assert_eq!(
        alice
            .get_peer_manifest_for(AUDIENCE, &bob_pub, &mut peer_state)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PeerManifestExpired
    );
    assert_eq!(peer_state.pinned_manifest_seq, 0);
    assert_eq!(peer_state.pinned_manifest_digest, None);
    assert_eq!(
        alice
            .prepare_initiate_v2(AUDIENCE, &bob_pub, &peer_state, b"hi", ())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PeerManifestExpired
    );

    let mut valid_manifest_a = CapabilityManifest {
        issued_at: now_ms - hour,
        expires_at: now_ms + 24 * hour,
        ..expired_manifest.clone()
    };
    sign_manifest(&bob_id, &mut valid_manifest_a).unwrap();
    let digest_a = manifest_digest(&valid_manifest_a).unwrap();
    *shared_manifest.lock().unwrap() = valid_manifest_a.clone();

    for skewed_time in [now_ms + 25 * hour, now_ms - 25 * hour] {
        alice.clock().observe(skewed_time);
        assert!(alice.clock().is_drift_exceeded());
        assert_eq!(
            alice
                .get_peer_manifest(AUDIENCE, &bob_pub)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::ClockSkew
        );
        assert_eq!(
            alice
                .prepare_initiate_v2(AUDIENCE, &bob_pub, &peer_state, b"hi", ())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::ClockSkew
        );
        assert_eq!(
            alice
                .prepare_publish_v2_preserving(AUDIENCE, 2, 0, &[], &[])
                .unwrap_err()
                .kind(),
            ErrorKind::ClockSkew
        );
        assert_eq!(alice.manifest_seq(), 0);
        assert_eq!(alice.prekey_generation(), 0);
    }

    alice.clock().observe(now_ms);
    let fetched = alice
        .get_peer_manifest_for(AUDIENCE, &bob_pub, &mut peer_state)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.manifest_seq, 1);
    assert_eq!(peer_state.pinned_manifest_seq, 1);
    assert_eq!(peer_state.pinned_manifest_digest, Some(digest_a));

    let mut equivocating_manifest_b = CapabilityManifest {
        issued_at: now_ms - 10 * hour,
        expires_at: now_ms - 2 * hour,
        ..valid_manifest_a
    };
    sign_manifest(&bob_id, &mut equivocating_manifest_b).unwrap();
    assert_ne!(manifest_digest(&equivocating_manifest_b).unwrap(), digest_a);
    *shared_manifest.lock().unwrap() = equivocating_manifest_b;

    alice.clock().observe(now_ms + 25 * hour);
    assert_eq!(
        alice
            .get_peer_manifest_for(AUDIENCE, &bob_pub, &mut peer_state)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );
    assert_eq!(
        alice
            .prepare_initiate_v2(AUDIENCE, &bob_pub, &peer_state, b"hi", ())
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );
    assert_eq!(peer_state.pinned_manifest_digest, Some(digest_a));
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[tokio::test]
async fn prepare_publish_v2_classical_off_rollback_contract_on_error_and_refusal() {
    use common::ToggleableHandshake;
    use std::sync::atomic::Ordering;

    let store = SharedStore::default();
    let (hs, enabled) = ToggleableHandshake::new(store.clone(), AUDIENCE);
    let suite = PqConfig::default_suite();
    let mut bob = Client::new(hs);

    bob.publish_v2(AUDIENCE, 4, 3).await.unwrap();
    let spk_gen1 = bob.current_signed_prekey().unwrap();
    assert_eq!(bob.manifest_seq(), 1);
    assert_eq!(bob.prekey_generation(), 1);
    assert_eq!(bob.current_one_time_count(), 4);
    assert_eq!(bob.current_pq_one_time_count(suite), 3);

    enabled.store(false, Ordering::Relaxed);

    let prep1 = bob.prepare_publish_v2(AUDIENCE, 2, 2).unwrap();
    assert_eq!(bob.manifest_seq(), 2);
    assert_eq!(bob.prekey_generation(), 2);
    assert_eq!(
        bob.transmit_publish_v2(&prep1).await.unwrap(),
        session::PublishV2Outcome::ServerPqDisabled
    );
    let now_ms = bob.clock().now();
    bob.clock().observe(now_ms + 25 * 60 * 60 * 1000);
    assert_eq!(
        bob.prepare_publish_v2_classical_off(prep1, &[])
            .unwrap_err()
            .kind(),
        ErrorKind::ClockSkew
    );
    assert_eq!(bob.manifest_seq(), 1);
    assert_eq!(bob.prekey_generation(), 1);
    assert_eq!(bob.current_signed_prekey(), Some(spk_gen1));
    assert_eq!(bob.current_one_time_count(), 4);
    assert_eq!(bob.current_pq_one_time_count(suite), 3);

    bob.clock().observe(now_ms);
    let prep2 = bob.prepare_publish_v2(AUDIENCE, 2, 2).unwrap();
    assert_eq!(
        bob.transmit_publish_v2(&prep2).await.unwrap(),
        session::PublishV2Outcome::ServerPqDisabled
    );
    let off_prep = bob.prepare_publish_v2_classical_off(prep2, &[]).unwrap();
    assert_eq!(bob.manifest_seq(), 3);
    assert_eq!(bob.prekey_generation(), 2);
    assert_eq!(bob.current_pq_one_time_count(suite), 0);
    bob.rollback_publish_v2_on_refusal(off_prep);
    assert_eq!(bob.manifest_seq(), 1);
    assert_eq!(bob.prekey_generation(), 1);
    assert_eq!(bob.current_signed_prekey(), Some(spk_gen1));
    assert_eq!(bob.current_one_time_count(), 4);
    assert_eq!(bob.current_pq_one_time_count(suite), 3);
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[tokio::test]
async fn r19_p2_1_get_peer_manifest_for_commits_signed_pq_off_capability_for_next_claim() {
    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs.clone());
    alice.publish_v2(AUDIENCE, 4, 4).await.unwrap();
    bob.publish_v2(AUDIENCE, 4, 4).await.unwrap();

    // Alice pins Bob at PQ-ON seq 1.
    let mut peer_state = PeerPqState::default();
    let _ = alice
        .get_peer_manifest_for(AUDIENCE, &bob.identity_key(), &mut peer_state)
        .await
        .unwrap()
        .unwrap();
    assert!(peer_state.pq_pinned && peer_state.peer_pq_capable);
    assert_eq!(peer_state.pinned_manifest_seq, 1);

    // Bob legitimately turns PQ OFF and publishes a signed OFF manifest at seq 2.
    bob.set_pq_config(PqConfig {
        pq_enabled: false,
        strict_pq: false,
        ..PqConfig::default()
    })
    .unwrap();
    bob.publish_v2(AUDIENCE, 4, 0).await.unwrap();

    // Non-consuming read via `get_peer_manifest_for` advances sequence/digest AND clears
    // `peer_pq_capable`, so claiming that same seq-2 manifest immediately afterward does NOT hit
    // `DowngradeDetected` (`<= pinned_manifest_seq`).
    let off_manifest = alice
        .get_peer_manifest_for(AUDIENCE, &bob.identity_key(), &mut peer_state)
        .await
        .unwrap()
        .unwrap();
    assert!(!off_manifest.pq_enabled);
    assert_eq!(off_manifest.manifest_seq, 2);
    assert_eq!(peer_state.pinned_manifest_seq, 2);
    assert!(!peer_state.peer_pq_capable);

    // Before approval: returns `ClassicalApprovalRequired` carrying the verified `(seq, digest)`.
    let err = session::claim_peer_bundle_v2(
        &hs,
        AUDIENCE,
        &bob.identity_key(),
        &peer_state,
        alice.pq_config(),
        alice.clock(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ClassicalApprovalRequired);
    assert_eq!(
        err.signed_pq_off_manifest(),
        Some((2, peer_state.pinned_manifest_digest.unwrap()))
    );

    // After explicit approval: claiming the exact same seq-2 manifest succeeds cleanly.
    peer_state.approve_classical_exception();
    let claimed = session::claim_peer_bundle_v2(
        &hs,
        AUDIENCE,
        &bob.identity_key(),
        &peer_state,
        alice.pq_config(),
        alice.clock(),
    )
    .await
    .unwrap();
    let prepared = alice
        .finish_prepare_initiate_v2(claimed, &peer_state, b"hi", ())
        .unwrap();
    assert_eq!(prepared.session.peer_pq_state().pinned_manifest_seq, 2);
    assert!(!prepared.session.peer_pq_state().peer_pq_capable);
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[tokio::test]
async fn r20_p1_1_p1_2_p1_3_p2_1_pre_manifest_pin_batch_quarantine_started_here_merge_and_downgrade_gate()
 {
    use prost::Message as _;

    let store = SharedStore::default();
    let hs = V2OnlyHandshake::new(store.clone(), AUDIENCE);
    let mut bob = Client::new(hs.clone());
    let mut alice = Client::new(hs.clone());
    let classical_cfg = PqConfig {
        pq_enabled: false,
        strict_pq: false,
        ..PqConfig::default()
    };

    // 1. R20-P1-1 / R20-P1-4: Once a peer is pinned at a manifest sequence (`pinned_manifest_seq > 0`)
    //    with `peer_pq_capable = true`, `commit_signed_pq_off_manifest`, `claim_peer_bundle_v2`,
    //    and `get_peer_manifest_for` MUST all reject any signed PQ-OFF manifest with `seq <= pinned`
    //    as `DowngradeDetected` without mutating `peer_state`. Meanwhile an inbound-initiated PQ
    //    contact with `pinned_manifest_seq == 0` still prompts for explicit user approval
    //    (`ClassicalApprovalRequired`) when the peer legitimately publishes a signed `PQ-OFF`
    //    manifest (never silently downgrading, and never permanently bricking inbound PQ chats).
    bob.set_pq_config(classical_cfg.clone()).unwrap();
    bob.publish_v2(AUDIENCE, 5, 0).await.unwrap();
    assert_eq!(bob.manifest_seq(), 1);

    let mut inbound_no_manifest_pin = PeerPqState::default();
    inbound_no_manifest_pin.pin_peer_pq();
    assert_eq!(inbound_no_manifest_pin.pinned_manifest_seq, 0);
    assert_eq!(
        session::claim_peer_bundle_v2(
            &hs,
            AUDIENCE,
            &bob.identity_key(),
            &inbound_no_manifest_pin,
            alice.pq_config(),
            alice.clock(),
        )
        .await
        .unwrap_err()
        .kind(),
        ErrorKind::ClassicalApprovalRequired
    );
    let mut seq_pinned = PeerPqState::default();
    seq_pinned.pin_peer_pq();
    seq_pinned.pinned_manifest_seq = 1;
    assert_eq!(
        session::claim_peer_bundle_v2(
            &hs,
            AUDIENCE,
            &bob.identity_key(),
            &seq_pinned,
            alice.pq_config(),
            alice.clock(),
        )
        .await
        .unwrap_err()
        .kind(),
        ErrorKind::DowngradeDetected
    );
    assert_eq!(
        alice
            .get_peer_manifest_for(AUDIENCE, &bob.identity_key(), &mut seq_pinned)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );
    assert!(seq_pinned.pq_pinned && seq_pinned.peer_pq_capable);
    assert_eq!(seq_pinned.pinned_manifest_seq, 1);

    // 2. R20-P1-2: `accept_listed_v2` must propagate `PeerPqState` from `Quarantined` outcomes
    //    across the same batch so a second classical initial cannot ride on a stale pre-batch
    //    `allow_classical_exception` after an earlier `Hello { pq_capable: true }` quarantine.
    let mut carol = Client::new(hs.clone());
    carol.set_pq_config(classical_cfg.clone()).unwrap();
    carol.publish_v2(AUDIENCE, 5, 0).await.unwrap();
    alice.publish_v2(AUDIENCE, 5, 5).await.unwrap();

    let hello_pq_true = session::protocol::content::Content {
        kind: Some(session::protocol::content::content::Kind::Hello(
            session::protocol::content::Hello {
                name: "Carol".into(),
                pq_capable: true,
                session_seq: 10,
                ..Default::default()
            },
        )),
        ..Default::default()
    }
    .encode_to_vec();
    let hello_pq_false = session::protocol::content::Content {
        kind: Some(session::protocol::content::content::Kind::Hello(
            session::protocol::content::Hello {
                name: "Carol".into(),
                pq_capable: false,
                session_seq: 11,
                ..Default::default()
            },
        )),
        ..Default::default()
    }
    .encode_to_vec();

    let p1 = carol
        .prepare_initiate_v2(
            AUDIENCE,
            &alice.identity_key(),
            &PeerPqState::default(),
            &hello_pq_true,
            (),
        )
        .await
        .unwrap();
    carol.send_prepared_initiate_v2(&p1.request).await.unwrap();
    let p2 = carol
        .prepare_initiate_v2(
            AUDIENCE,
            &alice.identity_key(),
            &PeerPqState::default(),
            &hello_pq_false,
            (),
        )
        .await
        .unwrap();
    carol.send_prepared_initiate_v2(&p2.request).await.unwrap();

    let listed = alice
        .list_initial_messages_v2(AUDIENCE, 0, 10)
        .await
        .unwrap();
    assert_eq!(listed.messages.len(), 2);
    let mut pre_batch = PeerPqState::default();
    pre_batch.approve_classical_exception();
    let batch = alice.accept_listed_v2(&listed, (), |_| pre_batch.clone());
    assert_eq!(batch.outcomes.len(), 2);
    assert!(
        matches!(
            batch.outcomes[0].1,
            session::AcceptedInitial::Quarantined {
                peer_was_pq_pinned: true,
                ..
            }
        ),
        "Msg 1 (Hello pq_capable=true) must quarantine and pin PQ"
    );
    assert!(
        matches!(
            batch.outcomes[1].1,
            session::AcceptedInitial::Quarantined {
                peer_was_pq_pinned: true,
                ..
            }
        ),
        "R20-P1-2: Msg 2 in the same batch must inherit Msg 1's quarantined PQ pin (not Accepted)"
    );

    // 3. R20-P1-3 + R20-P2-1: Locally prepared classical replacement (`started_here`) must NEVER
    //    take over after the live session observes a newer PQ pin OR while `downgrade_detected` is
    //    active; and `evaluate_claimed_bundle_policy` must reject outbound classical fallback while
    //    `downgrade_detected == true`.
    let mut off_approved = PeerPqState::default();
    off_approved.approve_classical_exception();
    let initial_classical = alice
        .prepare_initiate_v2(AUDIENCE, &bob.identity_key(), &off_approved, b"hi-1", ())
        .await
        .unwrap();
    let mut live_session = initial_classical.session;
    assert_eq!(live_session.peer_pq_state().pinned_manifest_seq, 1);

    // Prepare a second local classical replacement against seq = 1 (before Bob upgrades to PQ).
    let stale_local_classical = alice
        .prepare_initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            live_session.peer_pq_state(),
            b"hi-2",
            (),
        )
        .await
        .unwrap()
        .session;

    // R20-P2-1: Live downgrade alarm blocks outbound classical claim AND `approve_classical_exception`
    // is a no-op while `peer_pq_capable && downgrade_detected`.
    let mut downgraded_state = live_session.peer_pq_state().clone();
    downgraded_state.downgrade_detected = true;
    assert_eq!(
        session::claim_peer_bundle_v2(
            &hs,
            AUDIENCE,
            &bob.identity_key(),
            &downgraded_state,
            alice.pq_config(),
            alice.clock(),
        )
        .await
        .unwrap_err()
        .kind(),
        ErrorKind::DowngradeDetected
    );
    let mut pq_downgraded = PeerPqState::default();
    pq_downgraded.pin_peer_pq();
    pq_downgraded.downgrade_detected = true;
    pq_downgraded.approve_classical_exception();
    assert!(!pq_downgraded.allow_classical_exception);

    // Live downgrade alarm also blocks merging `stale_local_classical` without clearing the alarm.
    live_session.peer_pq_state_mut().downgrade_detected = true;
    let stale_copy = session::Session::restore(
        (),
        session::SessionState::try_from(&session::proto::SessionState::from(
            stale_local_classical.state(),
        ))
        .unwrap(),
    );
    assert_eq!(
        live_session
            .accept_replacement(stale_copy)
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );
    assert!(live_session.peer_pq_state().downgrade_detected);
    live_session.peer_pq_state_mut().downgrade_detected = false;

    // Now Bob publishes signed PQ-ON at seq = 2, and Alice's live session observes it!
    bob.set_pq_config(PqConfig::default()).unwrap();
    bob.publish_v2(AUDIENCE, 5, 5).await.unwrap();
    assert_eq!(bob.manifest_seq(), 2);
    alice
        .get_peer_manifest_for(
            AUDIENCE,
            &bob.identity_key(),
            live_session.peer_pq_state_mut(),
        )
        .await
        .unwrap();
    assert!(live_session.peer_pq_state().pq_pinned);
    assert!(live_session.peer_pq_state().peer_pq_capable);
    assert_eq!(live_session.peer_pq_state().pinned_manifest_seq, 2);
    assert!(!live_session.peer_pq_state().allow_classical_exception);

    // R20-P1-3: Merging `stale_local_classical` (`started_here`, seq = 1) MUST be rejected with
    // `DowngradeDetected` and must NOT restore `allow_classical_exception` or replace the ratchet!
    let live_active_before = live_session.active_id().copied();
    assert_eq!(
        live_session
            .accept_replacement(stale_local_classical)
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected
    );
    assert_eq!(live_session.active_id().copied(), live_active_before);
    assert!(live_session.peer_pq_state().peer_pq_capable);
    assert!(!live_session.peer_pq_state().allow_classical_exception);
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[tokio::test]
async fn r21_p1_1_p1_2_p2_1_p2_2_rekey_pq_disabled_stale_merge_server_disabled_and_manifest_downgrade()
 {
    use std::sync::atomic::Ordering;

    let store = SharedStore::default();
    let (hs, pq_server_enabled) = common::ToggleableHandshake::new(store.clone(), AUDIENCE);

    let mut alice = Client::new(hs.clone());
    let mut bob = Client::new(hs.clone());
    alice.publish_v2(AUDIENCE, 5, 5).await.unwrap();
    bob.publish_v2(AUDIENCE, 5, 5).await.unwrap();

    // 1. R21-P1-1: Disabling local PQ (`pq_enabled = false, strict_pq = false`) on a previously
    //    PQ-pinned contact must allow `finish_prepare_start_again_v2` to rekey classically without
    //    tripping `DowngradeDetected` (and without granting persistent `allow_classical_exception`).
    let mut pq_session = alice
        .prepare_initiate_v2(
            AUDIENCE,
            &bob.identity_key(),
            &PeerPqState::default(),
            b"hi-pq",
            (),
        )
        .await
        .unwrap()
        .session;
    assert!(pq_session.peer_pq_state().pq_pinned);
    assert!(pq_session.peer_pq_state().peer_pq_capable);
    assert_eq!(pq_session.peer_pq_state().pinned_manifest_seq, 1);

    let mut alice_pq_off = Client::restore(
        hs.clone(),
        session::ClientState::try_from(&session::proto::ClientState::from(alice.state())).unwrap(),
    );
    alice_pq_off
        .set_pq_config(PqConfig {
            pq_enabled: false,
            strict_pq: false,
            ..PqConfig::default()
        })
        .unwrap();
    pq_session.retire();
    let claimed_rekey = session::claim_peer_bundle_v2(
        &hs,
        AUDIENCE,
        &bob.identity_key(),
        pq_session.peer_pq_state(),
        alice_pq_off.pq_config(),
        alice_pq_off.clock(),
    )
    .await
    .unwrap();
    alice_pq_off
        .finish_prepare_start_again_v2(claimed_rekey, &mut pq_session, b"rekey-cl")
        .expect("R21-P1-1: classical rekey with local PQ disabled must succeed on PQ-pinned peer");
    assert!(
        !pq_session.peer_pq_state().allow_classical_exception,
        "R21-P1-1: disabling PQ for rekey must not grant persistent allow_classical_exception"
    );
    assert!(!pq_session.peer_pq_state().downgrade_detected);

    // 2. R21-P1-2 (Part A & B): Stale locally prepared classical replacement (`started_here`,
    //    `allow_classical_exception = true`) must NOT overwrite an unmanifested inbound PQ session
    //    (`pinned_manifest_seq == 0`) AND must NOT restore revoked classical consent onto a newer
    //    unapproved signed PQ-OFF manifest (`seq = 3`).
    let mut carol = Client::new(hs.clone());
    carol
        .set_pq_config(PqConfig {
            pq_enabled: false,
            strict_pq: false,
            ..PqConfig::default()
        })
        .unwrap();
    carol.publish_v2(AUDIENCE, 5, 0).await.unwrap();
    assert_eq!(carol.manifest_seq(), 1);

    let mut approved_off = PeerPqState::default();
    approved_off.approve_classical_exception();
    let stale_seq1_classical = alice
        .prepare_initiate_v2(
            AUDIENCE,
            &carol.identity_key(),
            &approved_off,
            b"stale-seq1",
            (),
        )
        .await
        .unwrap()
        .session;
    assert_eq!(stale_seq1_classical.peer_pq_state().pinned_manifest_seq, 1);
    assert!(
        stale_seq1_classical
            .peer_pq_state()
            .allow_classical_exception
    );

    // Carol enables PQ (`seq = 2`) and sends Alice an inbound PQ initial (`pinned_manifest_seq == 0`).
    carol.set_pq_config(PqConfig::default()).unwrap();
    carol.publish_v2(AUDIENCE, 5, 5).await.unwrap();
    assert_eq!(carol.manifest_seq(), 2);
    let carol_to_alice = carol
        .prepare_initiate_v2(
            AUDIENCE,
            &alice.identity_key(),
            &PeerPqState::default(),
            b"carol-pq-init",
            (),
        )
        .await
        .unwrap();
    let incoming_pq =
        session::InitialMessageV2::try_from(carol_to_alice.request.message.as_ref().unwrap())
            .unwrap();
    let mut live_inbound_pq = match alice
        .accept_initial_v2(
            &carol.identity_key(),
            &PeerPqState::default(),
            &incoming_pq,
            (),
        )
        .unwrap()
    {
        session::AcceptedInitial::Accepted { session, .. } => session,
        _ => panic!("expected accepted inbound PQ session"),
    };
    assert_eq!(live_inbound_pq.peer_pq_state().pinned_manifest_seq, 0);
    assert!(live_inbound_pq.peer_pq_state().pq_pinned);
    assert!(live_inbound_pq.peer_pq_state().peer_pq_capable);

    // Part A: stale seq=1 classical MUST fail against unmanifested live inbound PQ (`seq == 0`).
    let stale_copy_a = session::Session::restore(
        (),
        session::SessionState::try_from(&session::proto::SessionState::from(
            stale_seq1_classical.state(),
        ))
        .unwrap(),
    );
    let inbound_id_before = live_inbound_pq.active_id().copied();
    assert_eq!(
        live_inbound_pq
            .accept_replacement(stale_copy_a)
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected,
        "R21-P1-2A: stale seq=1 classical must not overwrite unmanifested inbound PQ (seq=0)"
    );
    assert_eq!(live_inbound_pq.active_id().copied(), inbound_id_before);
    assert!(live_inbound_pq.peer_pq_state().peer_pq_capable);
    assert!(!live_inbound_pq.peer_pq_state().allow_classical_exception);

    // Part B: live session observes PQ-ON seq=2, then Carol signs PQ-OFF seq=3 (`allow = false`).
    alice
        .get_peer_manifest_for(
            AUDIENCE,
            &carol.identity_key(),
            live_inbound_pq.peer_pq_state_mut(),
        )
        .await
        .unwrap();
    assert_eq!(live_inbound_pq.peer_pq_state().pinned_manifest_seq, 2);
    carol
        .set_pq_config(PqConfig {
            pq_enabled: false,
            strict_pq: false,
            ..PqConfig::default()
        })
        .unwrap();
    carol.publish_v2(AUDIENCE, 5, 0).await.unwrap();
    assert_eq!(carol.manifest_seq(), 3);

    // 3. R21-P2-2: While `downgrade_detected == true`, `get_peer_manifest_for` must refuse to
    //    clear `peer_pq_capable` via signed PQ-OFF.
    let mut live_downgraded_pq = live_inbound_pq.peer_pq_state().clone();
    live_downgraded_pq.downgrade_detected = true;
    assert_eq!(
        alice
            .get_peer_manifest_for(AUDIENCE, &carol.identity_key(), &mut live_downgraded_pq)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected,
        "R21-P2-2: get_peer_manifest_for must not clear peer_pq_capable under downgrade_detected"
    );
    assert!(live_downgraded_pq.peer_pq_capable);

    // Without downgrade alarm, live session observes Carol's signed PQ-OFF seq=3 (`allow = false`).
    alice
        .get_peer_manifest_for(
            AUDIENCE,
            &carol.identity_key(),
            live_inbound_pq.peer_pq_state_mut(),
        )
        .await
        .unwrap();
    assert_eq!(live_inbound_pq.peer_pq_state().pinned_manifest_seq, 3);
    assert!(!live_inbound_pq.peer_pq_state().peer_pq_capable);
    assert!(!live_inbound_pq.peer_pq_state().allow_classical_exception);

    // Stale seq=1 classical (`allow = true`) MUST be rejected against seq=3 (`allow = false`)!
    assert_eq!(
        live_inbound_pq
            .accept_replacement(stale_seq1_classical)
            .unwrap_err()
            .kind(),
        ErrorKind::DowngradeDetected,
        "R21-P1-2B: stale seq=1 classical must not restore revoked consent on seq=3 PQ-OFF"
    );
    assert!(!live_inbound_pq.peer_pq_state().allow_classical_exception);

    // 4. R21-P2-1: Unpinned peer (`pq_pinned = false, allow = false`) with `downgrade_detected = true`
    //    hitting a `PQ_ENABLED=false` server must return `DowngradeDetected` (NOT
    //    `ServerPqDisabledApprovalRequired` / `ClassicalApprovalRequired`).
    pq_server_enabled.store(false, Ordering::Relaxed);
    let unpinned_downgraded = PeerPqState {
        pq_pinned: false,
        peer_pq_capable: false,
        allow_classical_exception: false,
        downgrade_detected: true,
        ..PeerPqState::default()
    };
    let err = session::claim_peer_bundle_v2(
        &hs,
        AUDIENCE,
        &bob.identity_key(),
        &unpinned_downgraded,
        alice.pq_config(),
        alice.clock(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::DowngradeDetected,
        "R21-P2-1: ServerPqDisabled pre-check must reject downgrade_detected as DowngradeDetected"
    );
}
