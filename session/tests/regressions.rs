//! Targeted regression tests for Phase 2 security, crypto, serialization, storage, clock, and
//! attachment hardening fixes.

mod common;

use bytes::Bytes;
use session::{Client, ErrorKind, PeerPqState, PqConfig, ServerClock};

use common::AUDIENCE;
#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
use common::{SharedStore, V2OnlyHandshake, V2OnlyMailbox};

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[allow(deprecated)]
#[tokio::test]
async fn strict_pq_blocks_deprecated_v1_initiate_start_again_and_accept() {
    use common::{DualHandshake, DualMailbox};

    let store = SharedStore::default();
    let hs = DualHandshake::new(store.clone(), AUDIENCE);
    let mb = DualMailbox::new(store, AUDIENCE);

    let mut bob_v1 = Client::new(hs.clone());
    bob_v1.publish_keys(4).await.unwrap();

    {
        let mut strict_alice = Client::new(hs.clone())
            .with_pq_config(PqConfig {
                strict_pq: true,
                ..PqConfig::default()
            })
            .unwrap();
        // Deprecated v1 `prepare_initiate` / `initiate` MUST fail closed under strict_pq.
        assert_eq!(
            strict_alice
                .prepare_initiate(&bob_v1.identity_key(), b"hi", mb.clone())
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::PqRequired
        );

        // Deprecated v1 `prepare_start_again` MUST also fail closed under strict_pq.
        let mut bob_pq = Client::new(hs.clone());
        bob_pq.publish_v2(AUDIENCE, 4, 4).await.unwrap();
        let mut session = strict_alice
            .initiate_v2(
                AUDIENCE,
                &bob_pq.identity_key(),
                &PeerPqState::default(),
                b"pq-first",
                mb.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            strict_alice
                .prepare_start_again(&mut session, b"v1-downgrade")
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::PqRequired
        );

        // Deprecated v1 `accept` MUST reject inbound classical initials under strict_pq without
        // consuming OPKs.
        let mut strict_bob = Client::new(hs.clone());
        strict_bob.publish_keys(3).await.unwrap();
        let _ = bob_v1
            .initiate(&strict_bob.identity_key(), b"classical", mb.clone())
            .await
            .unwrap();
        strict_bob
            .set_pq_config(PqConfig {
                strict_pq: true,
                ..PqConfig::default()
            })
            .unwrap();
        let inbox = strict_bob.take_initial_messages().await.unwrap();
        let opks_before = strict_bob.current_one_time_count();
        assert_eq!(
            strict_bob
                .accept(&bob_v1.identity_key(), &inbox[0], mb)
                .unwrap_err()
                .kind(),
            ErrorKind::PqRequired
        );
        assert_eq!(strict_bob.current_one_time_count(), opks_before);
    }

    // Even when `strict_pq == false`, a PQ-pinned session cannot be downgraded via v1
    // `prepare_start_again`.
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    {
        let store2 = SharedStore::default();
        let hs2 = DualHandshake::new(store2.clone(), AUDIENCE);
        let mb2 = DualMailbox::new(store2, AUDIENCE);
        let mut alice = Client::new(hs2.clone());
        let mut bob = Client::new(hs2);
        bob.publish_v2(AUDIENCE, 4, 4).await.unwrap();
        let mut sess = alice
            .initiate_v2(
                AUDIENCE,
                &bob.identity_key(),
                &PeerPqState::default(),
                b"pq",
                mb2,
            )
            .await
            .unwrap();
        assert_eq!(
            alice
                .prepare_start_again(&mut sess, b"downgrade-v1")
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::DowngradeDetected
        );
    }
}

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

    // Alice sends session_seq = 1 (withheld) and session_seq = 2 (delivered first).
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

    let listed = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
    assert_eq!(listed.messages.len(), 2);

    // Accept seq = 2 first.
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

    // Now attempting to accept stale seq = 1 MUST fail with `StaleSession` BEFORE calling
    // `confirm_pq`, preserving BOTH classical OPK and PQOPK counts!
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

    // Publish gen 1 PQ-ON (manifest_seq = 1).
    bob.publish_v2(AUDIENCE, 3, 3).await.unwrap();
    assert_eq!(bob.manifest_seq(), 1);

    // Flip relay to PQ_ENABLED = false.
    enabled.store(false, Ordering::Relaxed);
    let prep = bob.prepare_publish_v2(AUDIENCE, 3, 3).unwrap();
    // Prepared PQ-ON took seq = 2; transmit returns ServerPqDisabled with ZERO mutation and ZERO
    // OFF write on the server so callers can persist `prepare_publish_v2_classical_off` first.
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

    // Prepare classical OFF -> allocates fresh seq = 3 (never reusing 2), retracts unused PQ
    // prekeys, and lets caller persist before transmitting!
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

    // Confirm stored manifest has seq = 3 and verifies cleanly once GetManifest is re-enabled.
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

    // Publish 4 manifests so `recent_manifest_digests` is at capacity (4).
    let mut digests = Vec::new();
    for _ in 0..4 {
        let p = bob.prepare_publish_v2(AUDIENCE, 2, 2).unwrap();
        digests.push(
            protocol::handshake_v2::manifest_digest(p.request.manifest.as_ref().unwrap()).unwrap(),
        );
        bob.transmit_publish_v2(&p).await.unwrap();
        bob.commit_publish_v2(p);
    }

    // Prepare a 5th publish while trying to preserve ALL 4 old digests: the newly pushed 5th
    // digest MUST NOT be evicted by the full preserve list, and Alice's PQXDH initial against
    // the 5th manifest MUST succeed!
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
    let listed = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
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

    // Roll back a 6th prepared publish: evicted digest must be restored cleanly without panicking
    // or losing recent digests.
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

    // Establish a PQ session first so Bob pins Alice at seq 1.
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
    let mut bob_sess = match bob
        .list_and_accept_v2(AUDIENCE, 10, mb.clone(), |_| PeerPqState::default())
        .await
        .unwrap()
        .outcomes
        .pop()
        .unwrap()
        .1
    {
        session::AcceptedInitial::Accepted { session, .. } => session,
        _ => panic!("expected PQ accepted"),
    };

    // Simulate a previous downgrade flag, then Alice legitimately turns PQ OFF and Bob approves
    // classical fallback (`peer_pq_capable = false, allow_classical_exception = true`).
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

    // Even if Bob still had `downgrade_detected = true` on the state passed into
    // `accept_initial_v2` (with approved signed PQ-OFF), accepting the approved classical
    // replacement clears `downgrade_detected`.
    bob_sess.peer_pq_state_mut().downgrade_detected = true;
    let listed = bob.list_initial_messages_v2(AUDIENCE, 10).await.unwrap();
    let incoming = match bob
        .accept_initial_v2(
            &alice.identity_key(),
            bob_sess.peer_pq_state(),
            &listed.messages[0],
            mb,
        )
        .unwrap()
    {
        session::AcceptedInitial::Quarantined { session, .. }
        | session::AcceptedInitial::Accepted { session, .. } => session,
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
async fn old_chain_duplicate_message_does_not_stall_receive_v2() {
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
    let mut bob_sess = match bob
        .list_and_accept_v2(AUDIENCE, 10, mb.clone(), |_| PeerPqState::default())
        .await
        .unwrap()
        .outcomes
        .pop()
        .unwrap()
        .1
    {
        session::AcceptedInitial::Accepted { session, .. } => session,
        _ => panic!("expected accepted"),
    };

    // Chain 1: Alice encrypts msg0 (held back -> skipped on Bob) and msg1 (delivered, kept for
    // replay after Bob advances to chain 2 so chain 1's HK remains in `skipped_message_keys`).
    let _held_msg0 = alice_sess.encrypt(b"chain1-skipped").unwrap();
    let old_msg = alice_sess.encrypt(b"chain1-msg").unwrap();
    alice_sess.push_v2(old_msg.clone()).await.unwrap();
    assert_eq!(
        bob_sess.receive_v2(&bob, AUDIENCE).await.unwrap()[0]
            .content
            .as_deref()
            .unwrap(),
        b"chain1-msg"
    );

    // Direction change advances DH receiving chain on Bob!
    bob_sess.send_v2(b"bob-turn").await.unwrap();
    assert_eq!(
        alice_sess.receive_v2(&alice, AUDIENCE).await.unwrap()[0]
            .content
            .as_deref()
            .unwrap(),
        b"bob-turn"
    );

    // Chain 2: Alice sends a fresh message so Bob's receiving HK moves to chain 2.
    alice_sess.send_v2(b"chain2-msg1").await.unwrap();
    assert_eq!(
        bob_sess.receive_v2(&bob, AUDIENCE).await.unwrap()[0]
            .content
            .as_deref()
            .unwrap(),
        b"chain2-msg1"
    );

    // Replay `old_msg` (from chain 1, with a new client_message_id so the relay appends it)
    // followed by a fresh chain 2 message! Bob MUST surface `DuplicateMessage` and NOT stall!
    let mut dup_req = alice_sess.push_v2_request_with_id(old_msg, Some([0x99; 16]));
    dup_req.client_message_id = Bytes::copy_from_slice(&[0x99; 16]);
    mb.push_v2(dup_req).await.unwrap();
    alice_sess.send_v2(b"chain2-after-dup").await.unwrap();

    let rx = bob_sess.receive_v2(&bob, AUDIENCE).await.unwrap();
    assert_eq!(rx.len(), 2, "old-chain duplicate must NOT stall receive_v2");
    assert_eq!(
        rx[0].content.as_ref().unwrap_err().kind(),
        ErrorKind::DuplicateMessage
    );
    assert_eq!(rx[1].content.as_deref().unwrap(), b"chain2-after-dup");
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

    // Empty preferred_suites against strict_pq identity -> returns manifest with ZERO OPKs popped!
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

    // Unknown suite -> rejected with Malformed without consuming any OPK.
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

    /// Malicious sequence deserializer advertising a huge `size_hint` (1_000_000_000) and yielding
    /// elements past the cap, verifying bounded visitors reject before allocating or looping.
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

    // All bounded fields reject immediately without OOMing on the 1B `size_hint`.
    assert!(
        session::ClientState::deserialize(MapWithHugeField("recent_manifest_digests")).is_err()
    );
    assert!(session::SessionState::deserialize(MapWithHugeField("others")).is_err());
    assert!(session::SessionState::deserialize(MapWithHugeField("delivered")).is_err());
    assert!(party::Party::deserialize(MapWithHugeField("associated_data")).is_err());
    assert!(x3dh::LocalPrekeys::deserialize(MapWithHugeField("generations")).is_err());
}

#[test]
fn clock_http_date_validation_observe_cap_and_skew_boundary() {
    let clock = ServerClock::default();
    let base = clock.now();
    // Out-of-range server timestamps (> MAX_SAFE_INTEGER) are ignored.
    clock.observe(protocol::MAX_SAFE_INTEGER + 1);
    clock.observe(u64::MAX);
    assert!(clock.now().abs_diff(base) < 5_000);

    // Invalid HTTP dates are ignored (do not shift the clock).
    for bad in [
        "Tue, 06 Nov 1994 08:49:37 GMT", // wrong weekday (6 Nov 1994 was Sun)
        "Wed, 31 Feb 2024 00:00:00 GMT", // impossible calendar day
        "Fri, 29 Feb 2023 00:00:00 GMT", // non-leap year Feb 29
        "Sun, 06 Nov 1994 08:49:37:00 GMT", // trailing time field
        "Sun, +6 Nov 1994 08:49:37 GMT", // signed digit
    ] {
        clock.observe_date(bad);
        assert!(
            clock.now().abs_diff(base) < 5_000,
            "bad HTTP date {bad:?} must be ignored"
        );
    }

    // Valid leap-day HTTP date IS accepted (`Thu, 29 Feb 2024 12:00:00 GMT`).
    clock.observe_date("Thu, 29 Feb 2024 12:00:00 GMT");
    assert_eq!(clock.now() / 1_000, 1_709_208_000);
}

#[tokio::test]
async fn attachment_hardening_short_chunk_sparse_resume_and_debug_redaction() {
    use session::attachment;

    // 1. Short non-last chunk returns `InvalidArgument` (distinct from `NonceReuse`).
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

    // 2. Out-of-order sealing advances the monotonic high-water mark so unrecorded earlier indices
    //    cannot be back-filled with a potentially reused nonce (`NonceReuse`).
    let sparse = attachment::Upload::resume_from(
        [0x12; protocol::attachment::ID_LENGTH],
        [0x23; protocol::attachment::TOKEN_LENGTH],
        zeroize::Zeroizing::new([0x43; 32]),
        4,
        1,
    );
    // Index 0 < resumed floor 1 -> NonceReuse.
    assert_eq!(
        sparse
            .try_encrypt(0, &[0u8; attachment::CHUNK_SIZE])
            .unwrap_err()
            .kind(),
        ErrorKind::NonceReuse
    );
    // Encrypt chunk 2 first -> monotonic watermark advances to 3, sealing gap index 1 against
    // later back-fill!
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
    // Idempotent retry of index 2 with identical plaintext succeeds; different plaintext fails.
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
    // Final chunk 3 succeeds with any size <= CHUNK_SIZE.
    assert!(sparse.try_encrypt(3, b"final").is_ok());

    // 3. `Debug` formatting on protocol attachment tokens & `AttachmentPointer` redacts secrets.
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

    // 1. Client starts with a classical-only publish (generation 1, no PQ last resort).
    let mut bob = Client::new(hs);
    bob.set_pq_config(PqConfig {
        pq_enabled: false,
        ..PqConfig::default()
    })
    .unwrap();
    bob.publish_v2(AUDIENCE, 2, 0).await.unwrap();
    let spk_gen1 = bob.current_signed_prekey().unwrap();

    // 2. Re-enable PQ locally without publishing a PQ generation yet: `prepare_refill_v2` with
    //    `pq_one_time_count > 0` MUST reject rather than silently minting an unpublished
    //    `pq_last_resort`, while classical-only refill (`pq_one_time_count == 0`) succeeds!
    bob.set_pq_config(PqConfig::default()).unwrap();
    assert!(bob.prepare_refill_v2(AUDIENCE, 1, 1).is_err());
    let classical_refill = bob.prepare_refill_v2(AUDIENCE, 1, 0).unwrap();
    bob.rollback_refill_v2_on_refusal(classical_refill);
    assert_eq!(bob.current_one_time_count(), 2);

    // 3. Refused `prepare_publish_v2_preserving` (which extends gen 1 and newly mints
    //    `pq_last_resort`) MUST retract that newly minted `pq_last_resort` on rollback!
    let prep_ext = bob
        .prepare_publish_v2_preserving(AUDIENCE, 1, 1, &[spk_gen1], &[])
        .unwrap();
    assert_eq!(bob.current_pq_one_time_count(suite), 1);
    bob.rollback_publish_v2_on_refusal(prep_ext);
    assert_eq!(bob.current_pq_one_time_count(suite), 0);
    // And `prepare_refill_v2(1, 1)` STILL fails because the newly minted `pq_last_resort` was
    // retracted cleanly!
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
                ..GetServerInfoResponse::default()
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

    // 1. Within-24h relay rewind (-12h) MUST still reject a manifest that expired 1h ago vs local.
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

    // 2. Beyond-24h drift (±25h) fails closed with ClockSkew across get_peer_manifest,
    //    prepare_initiate_v2, and prepare_publish_v2_preserving (no silent clamping).
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

    // 3. Honest clock pins (seq = 1, digest_a); equivocating manifest at same seq = 1 with a
    //    different digest MUST fail with DowngradeDetected BEFORE clock/expiry checks!
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
        // Different issued_at/expires_at -> different canonical digest at SAME manifest_seq == 1!
        // Also expired to verify DowngradeDetected takes precedence over PeerManifestExpired.
        issued_at: now_ms - 10 * hour,
        expires_at: now_ms - 2 * hour,
        ..valid_manifest_a
    };
    sign_manifest(&bob_id, &mut equivocating_manifest_b).unwrap();
    assert_ne!(manifest_digest(&equivocating_manifest_b).unwrap(), digest_a);
    *shared_manifest.lock().unwrap() = equivocating_manifest_b;

    // Even under excessive clock drift, equivocation is caught BEFORE clock/window checks!
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
    // Pin stays unchanged on digest_a.
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

    // Establish gen 1 (manifest_seq = 1).
    bob.publish_v2(AUDIENCE, 4, 3).await.unwrap();
    let spk_gen1 = bob.current_signed_prekey().unwrap();
    assert_eq!(bob.manifest_seq(), 1);
    assert_eq!(bob.prekey_generation(), 1);
    assert_eq!(bob.current_one_time_count(), 4);
    assert_eq!(bob.current_pq_one_time_count(suite), 3);

    // Flip server to PQ_ENABLED = false.
    enabled.store(false, Ordering::Relaxed);

    // (a) Error path: ClockSkew during `prepare_publish_v2_classical_off` MUST roll back
    //     `prepared` completely, restoring gen 1, SPK, OPKs, PQOPKs, and manifest_seq = 1!
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

    // (b) `Ok(off_prepared)` followed by post-prepare save failure or refusal rollback MUST
    //     restore pre-prepare state completely (prev_manifest_seq, prev_prekey_generation,
    //     evicted gen 1 SPK/OPKs/PQOPKs).
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
