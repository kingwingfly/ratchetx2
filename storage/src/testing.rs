//! Conformance suites every backend should pass.
//!
//! Each suite takes a fresh, empty store and panics on the first failure.

use bytes::Bytes;

use crate::{
    ErrorKind, LocalAttachmentStore, LocalIdempotentMailboxStore, LocalPqHandshakeStore,
    MAX_SAFE_INTEGER, MailboxPage, PqLastResortCommitment, PublishV2Record, PublishV2Status,
    RefillPrekeysRecord, RefillStatus, RegisterWriteTokenRecord, RevokeWriteTokenRecord,
    StoredAttachment, StoredCapabilityManifest, StoredInitialMessageV2, StoredMessage,
    StoredPqPrekey,
};

/// Conformance suite for [`LocalAttachmentStore`].
pub async fn attachment_store<S: LocalAttachmentStore>(store: &S) {
    let attachment = StoredAttachment {
        id: [1; 16],
        chunks: 2,
        token_hash: [3; 32],
        delete_hash: [5; 32],
        uploaded: 0,
    };
    assert_eq!(store.attachment(&attachment.id).await.unwrap(), None);
    assert!(store.add_attachment(attachment.clone()).await.unwrap());
    // An ID is taken once.
    let other = StoredAttachment {
        chunks: 5,
        ..attachment.clone()
    };
    assert!(!store.add_attachment(other).await.unwrap());
    assert_eq!(
        store.attachment(&attachment.id).await.unwrap(),
        Some(attachment.clone())
    );

    assert_eq!(store.chunk(&attachment.id, 0).await.unwrap(), None);
    store
        .put_chunk(&attachment.id, 1, Bytes::from_static(b"second"))
        .await
        .unwrap();
    store
        .put_chunk(&attachment.id, 0, Bytes::from_static(b"first"))
        .await
        .unwrap();
    // Putting a chunk again keeps the first copy.
    store
        .put_chunk(&attachment.id, 0, Bytes::from_static(b"first again"))
        .await
        .unwrap();
    assert_eq!(
        store.chunk(&attachment.id, 0).await.unwrap(),
        Some(Bytes::from_static(b"first"))
    );
    assert_eq!(
        store.chunk(&attachment.id, 1).await.unwrap(),
        Some(Bytes::from_static(b"second"))
    );
    // Both are noted as uploaded, whatever order they came in.
    let uploaded = store.attachment(&attachment.id).await.unwrap().unwrap();
    assert!(uploaded.was_uploaded(0) && uploaded.was_uploaded(1));
    assert!(!uploaded.was_uploaded(2));
    assert!(uploaded.is_complete());
    assert_eq!(store.chunk(&[9; 16], 0).await.unwrap(), None);

    // Conditional incomplete-only delete preserves a completed attachment and deletes an
    // incomplete one.
    assert!(
        !store
            .delete_attachment_if_incomplete(&attachment.id)
            .await
            .unwrap()
    );
    assert!(store.attachment(&attachment.id).await.unwrap().is_some());
    assert_eq!(
        store.chunk(&attachment.id, 0).await.unwrap(),
        Some(Bytes::from_static(b"first"))
    );
    let incomplete = StoredAttachment {
        id: [2; 16],
        chunks: 2,
        token_hash: [4; 32],
        delete_hash: [6; 32],
        uploaded: 0,
    };
    assert!(store.add_attachment(incomplete.clone()).await.unwrap());
    store
        .put_chunk(&incomplete.id, 0, Bytes::from_static(b"part0"))
        .await
        .unwrap();
    assert!(
        !store
            .attachment(&incomplete.id)
            .await
            .unwrap()
            .unwrap()
            .is_complete()
    );
    assert!(
        store
            .delete_attachment_if_incomplete(&incomplete.id)
            .await
            .unwrap()
    );
    assert_eq!(store.attachment(&incomplete.id).await.unwrap(), None);
    assert_eq!(store.chunk(&incomplete.id, 0).await.unwrap(), None);
    assert!(
        !store
            .delete_attachment_if_incomplete(&incomplete.id)
            .await
            .unwrap()
    );

    // Deleted, it is gone with its chunks, and deleting it again does nothing.
    store.delete_attachment(&attachment.id).await.unwrap();
    assert_eq!(store.attachment(&attachment.id).await.unwrap(), None);
    assert_eq!(store.chunk(&attachment.id, 0).await.unwrap(), None);
    store.delete_attachment(&attachment.id).await.unwrap();
    // Putting a chunk on a missing/deleted attachment returns NotFound.
    assert_eq!(
        store
            .put_chunk(&attachment.id, 0, Bytes::from_static(b"after-delete"))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
}

/// Conformance suite for [`LocalPqHandshakeStore`].
pub async fn pq_handshake_store<S: LocalPqHandshakeStore>(store: &S) {
    let (alice, bob) = ([11; 32], [12; 32]);
    let pq_key = |suite: u8, tag: u8| StoredPqPrekey {
        suite,
        id: [tag; 32],
        encapsulation_key: Bytes::from(vec![tag; if suite == 1 { 1568 } else { 1184 }]),
        signature: [tag; 64],
    };
    let manifest =
        |seq: u64, generation: u64, pq_enabled: bool, strict_pq: bool| StoredCapabilityManifest {
            audience: "chat.example".to_string(),
            identity_key: bob,
            manifest_seq: seq,
            generation,
            issued_at: 1000 + seq,
            expires_at: 100_000 + seq,
            pq_enabled,
            strict_pq,
            pq_ratchet_supported: pq_enabled,
            offered_suites: if pq_enabled { vec![1, 2] } else { vec![] },
            signed_prekey: [20 + (generation as u8); 32],
            pq_last_resort: if pq_enabled {
                vec![
                    PqLastResortCommitment {
                        suite: 1,
                        prekey_id: [0xA1; 32],
                    },
                    PqLastResortCommitment {
                        suite: 2,
                        prekey_id: [0xA2; 32],
                    },
                ]
            } else {
                vec![]
            },
            signature: [0x55; 64],
        };

    // Unknown identity returns None / empty without allocating, and rejects inbox writes.
    assert_eq!(store.get_manifest(&bob).await.unwrap(), None);
    assert_eq!(store.claim_bundle(&bob, &[1, 2]).await.unwrap(), None);
    assert!(
        store
            .list_initial_messages(&bob, 0, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.ack_initial_messages(&bob, &[1]).await.unwrap(), 0);
    assert_eq!(
        store
            .add_initial_message_v2(
                StoredInitialMessageV2 {
                    id: 0,
                    version: 1,
                    sender: alice,
                    recipient: bob,
                    ephemeral_key: [79; 32],
                    signed_prekey: [21; 32],
                    one_time_prekey: None,
                    header: Bytes::from_static(b"unreg"),
                    content: Bytes::new(),
                    pq_suite: None,
                    pq_last_resort: false,
                    pq_prekey_id: None,
                    pq_ciphertext: None,
                    manifest_digest: None,
                },
                10,
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );

    // Duplicate OPK or PQOPK is rejected.
    let dup = PublishV2Record {
        manifest: manifest(1, 1, true, false),
        signed_prekey_signature: Some([0x44; 64]),
        one_time_prekeys: vec![[40; 32], [40; 32]],
        pq_last_resort: vec![pq_key(1, 0xA1), pq_key(2, 0xA2)],
        pq_one_time_prekeys: vec![pq_key(1, 0xB1)],
        timestamp: 1001,
    };
    assert_eq!(
        store.publish_v2(dup).await.unwrap(),
        PublishV2Status::DuplicatePrekey
    );

    // Duplicate PQ last-resort suite (even with distinct prekey IDs) is rejected.
    let dup_lr_suite = PublishV2Record {
        manifest: manifest(1, 1, true, false),
        signed_prekey_signature: Some([0x44; 64]),
        one_time_prekeys: vec![[40; 32]],
        pq_last_resort: vec![pq_key(1, 0xA1), pq_key(1, 0xA9)],
        pq_one_time_prekeys: vec![],
        timestamp: 1001,
    };
    assert_eq!(
        store.publish_v2(dup_lr_suite).await.unwrap(),
        PublishV2Status::DuplicatePrekey
    );

    // Valid compat v2 publish succeeds and is visible via non-consuming get_manifest.
    let valid = PublishV2Record {
        manifest: manifest(1, 1, true, false),
        signed_prekey_signature: Some([0x44; 64]),
        one_time_prekeys: vec![[40; 32], [41; 32]],
        pq_last_resort: vec![pq_key(1, 0xA1), pq_key(2, 0xA2)],
        pq_one_time_prekeys: vec![pq_key(1, 0xB1), pq_key(2, 0xB2)],
        timestamp: 1001,
    };
    assert_eq!(
        store.publish_v2(valid).await.unwrap(),
        PublishV2Status::Stored
    );
    assert_eq!(
        store.get_manifest(&bob).await.unwrap(),
        Some(manifest(1, 1, true, false))
    );

    // Stale manifest_seq is rejected.
    let stale = PublishV2Record {
        manifest: manifest(1, 2, true, false),
        signed_prekey_signature: Some([0x44; 64]),
        one_time_prekeys: vec![],
        pq_last_resort: vec![pq_key(1, 0xA1), pq_key(2, 0xA2)],
        pq_one_time_prekeys: vec![],
        timestamp: 1002,
    };
    assert_eq!(
        store.publish_v2(stale).await.unwrap(),
        PublishV2Status::StaleSequence
    );

    // Classical claim (empty preferred_suites) pops a classical OPK and preserves
    // signed_prekey_signature while NEVER consuming PQOPKs.
    let classical_claim = store.claim_bundle(&bob, &[]).await.unwrap().unwrap();
    assert_eq!(classical_claim.signed_prekey, [21; 32]);
    assert_eq!(classical_claim.signed_prekey_signature, Some([0x44; 64]));
    assert_eq!(classical_claim.one_time_prekey, Some([40; 32]));
    assert_eq!(classical_claim.pq_last_resort, None);
    assert_eq!(classical_claim.pq_one_time_prekey, None);
    let snap = store.pq_snapshot(&bob).await.unwrap();
    assert_eq!(snap.pq_one_time_counts, vec![(1, 1), (2, 1)]);

    // Claim ML-KEM-768 (suite 2) pops suite 2 PQOPK and remaining classical OPK [41; 32];
    // second claim falls back to last-resort.
    let claim1 = store.claim_bundle(&bob, &[2]).await.unwrap().unwrap();
    assert_eq!(claim1.one_time_prekey, Some([41; 32]));
    assert_eq!(claim1.pq_last_resort, Some(pq_key(2, 0xA2)));
    assert_eq!(claim1.pq_one_time_prekey, Some(pq_key(2, 0xB2)));
    let claim2 = store.claim_bundle(&bob, &[2]).await.unwrap().unwrap();
    assert_eq!(claim2.one_time_prekey, None);
    assert_eq!(claim2.pq_last_resort, Some(pq_key(2, 0xA2)));
    assert_eq!(claim2.pq_one_time_prekey, None);

    // RefillPrekeys appends to current generation without rotating SPK.
    assert_eq!(
        store
            .refill_prekeys(RefillPrekeysRecord {
                identity_key: bob,
                generation: 99,
                one_time_prekeys: vec![[50; 32]],
                pq_one_time_prekeys: vec![],
                max_one_time_prekeys: 10,
                max_pq_one_time_prekeys: 10,
                timestamp: 2000,
            })
            .await
            .unwrap(),
        RefillStatus::StaleGeneration
    );
    assert_eq!(
        store
            .refill_prekeys(RefillPrekeysRecord {
                identity_key: bob,
                generation: 1,
                one_time_prekeys: vec![[50; 32]],
                pq_one_time_prekeys: vec![pq_key(2, 0xB3)],
                max_one_time_prekeys: 10,
                max_pq_one_time_prekeys: 10,
                timestamp: 2001,
            })
            .await
            .unwrap(),
        RefillStatus::Stored {
            classical_count: 1,
            pq_counts: vec![(1, 1), (2, 1)],
        }
    );
    // Replaying RefillPrekeys with the same or older timestamp fails even after claiming keys.
    assert_eq!(
        store
            .refill_prekeys(RefillPrekeysRecord {
                identity_key: bob,
                generation: 1,
                one_time_prekeys: vec![[51; 32]],
                pq_one_time_prekeys: vec![],
                max_one_time_prekeys: 10,
                max_pq_one_time_prekeys: 10,
                timestamp: 2001,
            })
            .await
            .unwrap(),
        RefillStatus::StaleTimestamp
    );
    // Refill rejects duplicate PQOPK ID on a newer timestamp.
    assert_eq!(
        store
            .refill_prekeys(RefillPrekeysRecord {
                identity_key: bob,
                generation: 1,
                one_time_prekeys: vec![],
                pq_one_time_prekeys: vec![pq_key(2, 0xB3)],
                max_one_time_prekeys: 10,
                max_pq_one_time_prekeys: 10,
                timestamp: 2002,
            })
            .await
            .unwrap(),
        RefillStatus::DuplicatePrekey
    );

    // Strict PQ publish omits raw SPK signature and claims cleanly.
    assert_eq!(
        store
            .publish_v2(PublishV2Record {
                manifest: manifest(2, 2, true, true),
                signed_prekey_signature: None,
                one_time_prekeys: vec![[60; 32]],
                pq_last_resort: vec![pq_key(1, 0xA1), pq_key(2, 0xA2)],
                pq_one_time_prekeys: vec![pq_key(1, 0xB4)],
                timestamp: 2002,
            })
            .await
            .unwrap(),
        PublishV2Status::Stored
    );
    let strict_claim = store.claim_bundle(&bob, &[1]).await.unwrap().unwrap();
    assert_eq!(strict_claim.one_time_prekey, Some([60; 32]));
    assert_eq!(strict_claim.signed_prekey_signature, None);
    assert_eq!(strict_claim.pq_one_time_prekey, Some(pq_key(1, 0xB4)));

    // Affirmative PQ OFF clears stored PQ prekeys while persisting the signed OFF manifest and
    // preserving signed_prekey_signature for intentional classical X3DH.
    assert_eq!(
        store
            .publish_v2(PublishV2Record {
                manifest: manifest(3, 3, false, false),
                signed_prekey_signature: Some([0x77; 64]),
                one_time_prekeys: vec![[70; 32]],
                pq_last_resort: vec![],
                pq_one_time_prekeys: vec![],
                timestamp: 2003,
            })
            .await
            .unwrap(),
        PublishV2Status::Stored
    );
    let off_snap = store.pq_snapshot(&bob).await.unwrap();
    assert!(!off_snap.manifest.as_ref().unwrap().pq_enabled);
    assert!(off_snap.pq_last_resort_suites.is_empty());
    assert!(off_snap.pq_one_time_counts.is_empty());
    let off_claim = store.claim_bundle(&bob, &[1, 2]).await.unwrap().unwrap();
    assert_eq!(off_claim.signed_prekey_signature, Some([0x77; 64]));
    assert_eq!(off_claim.one_time_prekey, Some([70; 32]));

    // Two-phase inbox with idempotency on (sender, ephemeral_key) + payload match, and cursor
    // pagination via after_id.
    let v1_msg = StoredInitialMessageV2 {
        id: 0,
        version: 1,
        sender: alice,
        recipient: bob,
        ephemeral_key: [80; 32],
        signed_prekey: [23; 32],
        one_time_prekey: None,
        header: Bytes::from_static(b"v1-h"),
        content: Bytes::from_static(b"v1-c"),
        pq_suite: None,
        pq_last_resort: false,
        pq_prekey_id: None,
        pq_ciphertext: None,
        manifest_digest: None,
    };
    let v1_id = store
        .add_initial_message_v2(v1_msg.clone(), 2)
        .await
        .unwrap()
        .unwrap();
    assert!(v1_id > 0);
    // Retrying the exact same (sender, ephemeral_key) payload is idempotent and consumes 1 slot.
    assert_eq!(
        store
            .add_initial_message_v2(v1_msg.clone(), 2)
            .await
            .unwrap(),
        Some(v1_id)
    );
    // Mismatched payload for the same (sender, ephemeral_key) fails with InvalidArgument.
    let mut bad_retry = v1_msg.clone();
    bad_retry.content = Bytes::from_static(b"tampered");
    assert_eq!(
        store
            .add_initial_message_v2(bad_retry, 2)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );

    let pq_msg = StoredInitialMessageV2 {
        id: 0,
        version: 2,
        sender: alice,
        recipient: bob,
        ephemeral_key: [81; 32],
        signed_prekey: [23; 32],
        one_time_prekey: Some([70; 32]),
        header: Bytes::from_static(b"v2-h"),
        content: Bytes::from_static(b"v2-c"),
        pq_suite: Some(1),
        pq_last_resort: false,
        pq_prekey_id: Some([0xB4; 32]),
        pq_ciphertext: Some(Bytes::from(vec![0xCC; 1568])),
        manifest_digest: Some([0xDD; 32]),
    };
    let pq_id = store
        .add_initial_message_v2(pq_msg.clone(), 2)
        .await
        .unwrap()
        .unwrap();
    assert!(pq_id > v1_id);
    // Idempotent retry STILL succeeds even when inbox is full at limit=2.
    assert_eq!(
        store.add_initial_message_v2(pq_msg, 2).await.unwrap(),
        Some(pq_id)
    );
    // A distinct 3rd initial hits the inbox limit.
    assert_eq!(
        store
            .add_initial_message_v2(
                StoredInitialMessageV2 {
                    id: 0,
                    version: 1,
                    sender: alice,
                    recipient: bob,
                    ephemeral_key: [82; 32],
                    signed_prekey: [23; 32],
                    one_time_prekey: None,
                    header: Bytes::from_static(b"full"),
                    content: Bytes::new(),
                    pq_suite: None,
                    pq_last_resort: false,
                    pq_prekey_id: None,
                    pq_ciphertext: None,
                    manifest_digest: None,
                },
                2,
            )
            .await
            .unwrap(),
        None
    );

    // Cursor pagination via after_id.
    let page1 = store.list_initial_messages(&bob, 0, 1).await.unwrap();
    assert_eq!(page1.len(), 1);
    assert_eq!(page1[0].id, v1_id);
    let page2 = store.list_initial_messages(&bob, v1_id, 10).await.unwrap();
    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].id, pq_id);
    assert!(
        store
            .list_initial_messages(&bob, pq_id, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .list_initial_messages(&bob, MAX_SAFE_INTEGER + 1, 10)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );

    // Ack deletes only the acknowledged IDs.
    assert_eq!(store.ack_initial_messages(&bob, &[v1_id]).await.unwrap(), 1);
    let remaining = store.list_initial_messages(&bob, 0, 10).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, pq_id);

    assert_eq!(store.ack_initial_messages(&bob, &[pq_id]).await.unwrap(), 1);
    assert!(
        store
            .list_initial_messages(&bob, 0, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Conformance suite for [`LocalIdempotentMailboxStore`] (paired with [`LocalPqHandshakeStore`]
/// so recipients can register manifests before registering write tokens).
#[cfg(not(target_arch = "wasm32"))]
pub async fn idempotent_mailbox_store<S: LocalPqHandshakeStore + LocalIdempotentMailboxStore>(
    store: &S,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(MAX_SAFE_INTEGER)) as u64;
    idempotent_mailbox_store_at(store, now_ms).await;
}

/// Conformance suite for [`LocalIdempotentMailboxStore`] using an explicit wall-clock `now_ms`
/// (required on `wasm32` targets where `std::time::SystemTime` is unavailable).
pub async fn idempotent_mailbox_store_at<S: LocalPqHandshakeStore + LocalIdempotentMailboxStore>(
    store: &S,
    now_ms: u64,
) {
    let bob = [22; 32];
    let peer_a = [0xA0; 32];
    let peer_b = [0xB0; 32];
    let tok_a1 = [0xA1; 32];
    let tok_a2 = [0xA2; 32];
    let tok_a3 = [0xA3; 32];
    let tok_a4 = [0xA4; 32];
    let tok_a5 = [0xA5; 32];
    let tok_b1 = [0xB1; 32];
    let cid1 = [0x42; 16];

    // 1. Unregistered recipient fails closed on grants, writes, and non-zero ACK without alloc.
    assert_eq!(
        store
            .register_write_token(RegisterWriteTokenRecord {
                recipient: bob,
                peer_slot_id: peer_a,
                token_hash: tok_a1,
                grant_version: 1,
                pin_active: true,
                timestamp: now_ms,
            })
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        store
            .append_idempotent(
                &bob,
                &tok_a1,
                Bytes::from_static(b"h"),
                Bytes::from_static(b"c"),
                None,
                Some(cid1),
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::WriteTokenRejected
    );
    assert_eq!(
        store.read_mailbox(&bob, 0, 10, 1024, 0).await.unwrap(),
        MailboxPage::default()
    );
    assert_eq!(
        store.ack_messages(&bob, 1).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );

    // Register Bob's manifest.
    let manifest = StoredCapabilityManifest {
        audience: "chat.example".to_string(),
        identity_key: bob,
        manifest_seq: 1,
        generation: 1,
        issued_at: 1000,
        expires_at: 100_000,
        pq_enabled: false,
        strict_pq: false,
        pq_ratchet_supported: false,
        offered_suites: vec![],
        signed_prekey: [0x20; 32],
        pq_last_resort: vec![],
        signature: [0x55; 64],
    };
    assert_eq!(
        store
            .publish_v2(PublishV2Record {
                manifest,
                signed_prekey_signature: Some([0x44; 64]),
                one_time_prekeys: vec![],
                pq_last_resort: vec![],
                pq_one_time_prekeys: vec![],
                timestamp: 1001,
            })
            .await
            .unwrap(),
        PublishV2Status::Stored
    );

    // 1b. Zero/stale timestamp on register_write_token is unconditionally rejected.
    assert_eq!(
        store
            .register_write_token(RegisterWriteTokenRecord {
                recipient: bob,
                peer_slot_id: peer_a,
                token_hash: tok_a1,
                grant_version: 1,
                pin_active: true,
                timestamp: 0,
            })
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::StaleTimestamp
    );

    // 2. Grant registration invariants: pinned active preserved across 5th grant eviction,
    //    duplicate token never refreshes eviction priority, cross-peer token_hash rejected.
    store
        .register_write_token(RegisterWriteTokenRecord {
            recipient: bob,
            peer_slot_id: peer_a,
            token_hash: tok_a1,
            grant_version: 1,
            pin_active: true,
            timestamp: now_ms,
        })
        .await
        .unwrap();
    // Cross-peer token_hash collision -> InvalidArgument.
    assert_eq!(
        store
            .register_write_token(RegisterWriteTokenRecord {
                recipient: bob,
                peer_slot_id: peer_b,
                token_hash: tok_a1,
                grant_version: 1,
                pin_active: true,
                timestamp: now_ms,
            })
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    // Register grants 2, 3, 4 (not pinning active) so tok_a1 (v=1) stays pinned active.
    for (tok, ver) in [(tok_a2, 2), (tok_a3, 3), (tok_a4, 4)] {
        store
            .register_write_token(RegisterWriteTokenRecord {
                recipient: bob,
                peer_slot_id: peer_a,
                token_hash: tok,
                grant_version: ver,
                pin_active: false,
                timestamp: now_ms,
            })
            .await
            .unwrap();
    }
    // Duplicate registration of tok_a2 with higher version must NOT refresh its eviction priority.
    store
        .register_write_token(RegisterWriteTokenRecord {
            recipient: bob,
            peer_slot_id: peer_a,
            token_hash: tok_a2,
            grant_version: 99,
            pin_active: false,
            timestamp: now_ms,
        })
        .await
        .unwrap();
    // Register 5th grant tok_a5 (v=5): must evict tok_a2 (v=2), strictly preserving pinned tok_a1!
    store
        .register_write_token(RegisterWriteTokenRecord {
            recipient: bob,
            peer_slot_id: peer_a,
            token_hash: tok_a5,
            grant_version: 5,
            pin_active: false,
            timestamp: now_ms,
        })
        .await
        .unwrap();
    // tok_a2 was evicted -> WriteTokenRejected.
    assert_eq!(
        store
            .append_idempotent(&bob, &tok_a2, Bytes::new(), Bytes::new(), None, None)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::WriteTokenRejected
    );
    // Pinned tok_a1 still works!
    let seq1 = store
        .append_idempotent(
            &bob,
            &tok_a1,
            Bytes::from_static(b"h1"),
            Bytes::from_static(b"c1"),
            Some(Bytes::from_static(b"initial")),
            Some(cid1),
        )
        .await
        .unwrap();
    assert_eq!(seq1, 1);

    // 3. Idempotent retry returns original sequence.
    assert_eq!(
        store
            .append_idempotent(
                &bob,
                &tok_a1,
                Bytes::from_static(b"h1"),
                Bytes::from_static(b"c1"),
                Some(Bytes::from_static(b"initial")),
                Some(cid1),
            )
            .await
            .unwrap(),
        1
    );

    // 4. Unified monotonic sequence across multiple peers.
    store
        .register_write_token(RegisterWriteTokenRecord {
            recipient: bob,
            peer_slot_id: peer_b,
            token_hash: tok_b1,
            grant_version: 1,
            pin_active: true,
            timestamp: now_ms,
        })
        .await
        .unwrap();
    let seq2 = store
        .append_idempotent(
            &bob,
            &tok_b1,
            Bytes::from_static(b"h2"),
            Bytes::from_static(b"c2"),
            None,
            Some(cid1), // Same client_message_id under a DIFFERENT token_hash is independent!
        )
        .await
        .unwrap();
    assert_eq!(seq2, 2);

    // 5. Read pagination with has_more (limit & byte cap) and token_hash metadata.
    let page1 = store.read_mailbox(&bob, 0, 1, 1024, 0).await.unwrap();
    assert!(page1.has_more);
    assert_eq!(
        page1.messages,
        vec![StoredMessage {
            sequence: 1,
            token_hash: tok_a1,
            header: Bytes::from_static(b"h1"),
            content: Bytes::from_static(b"c1"),
            initial_message: Some(Bytes::from_static(b"initial")),
        }]
    );
    // Piggybacked ACK of seq 1 while reading after seq 1 returns seq 2 with has_more = false.
    let page2 = store.read_mailbox(&bob, 1, 10, 1024, 1).await.unwrap();
    assert!(!page2.has_more);
    assert_eq!(page2.messages.len(), 1);
    assert_eq!(page2.messages[0].sequence, 2);
    assert_eq!(page2.messages[0].token_hash, tok_b1);

    // Seq 1 was deleted, yet retrying cid1 under still-valid tok_a1 returns seq 1 without duplicating.
    assert_eq!(
        store
            .append_idempotent(&bob, &tok_a1, Bytes::new(), Bytes::new(), None, Some(cid1))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .read_mailbox(&bob, 0, 10, 1024, 0)
            .await
            .unwrap()
            .messages
            .len(),
        1
    );

    // 6. AckMessages bounds: rejects 0, rejects > last_sequence, idempotent on <= last_sequence,
    //    and preserves monotonic last_sequence.
    assert_eq!(
        store.ack_messages(&bob, 0).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(
        store.ack_messages(&bob, 3).await.unwrap_err().kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(
        store
            .read_mailbox(&bob, 0, 10, 1024, 3)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(store.ack_messages(&bob, 2).await.unwrap(), 1);
    assert_eq!(store.ack_messages(&bob, 2).await.unwrap(), 0);
    assert!(
        store
            .read_mailbox(&bob, 0, 10, 1024, 0)
            .await
            .unwrap()
            .messages
            .is_empty()
    );
    let seq3 = store
        .append_idempotent(
            &bob,
            &tok_b1,
            Bytes::from_static(b"h3"),
            Bytes::from_static(b"c3"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(seq3, 3);

    // 7. Auth-before-dedup on revocation & monotonic version-floor enforcement.
    // Targeted revoke of tok_a1 with min_grant_version = 2 removes only tok_a1 (v=1), leaving
    // tok_a3 (v=3), tok_a4 (v=4), tok_a5 (v=5) live and promoting tok_a5.
    assert_eq!(
        store
            .revoke_write_token(RevokeWriteTokenRecord {
                recipient: bob,
                peer_slot_id: peer_a,
                token_hash: Some(tok_a1),
                min_grant_version: 2,
            })
            .await
            .unwrap(),
        1
    );
    // Retrying cid1 with the REVOKED tok_a1 MUST return WriteTokenRejected (NOT Ok(1))!
    assert_eq!(
        store
            .append_idempotent(&bob, &tok_a1, Bytes::new(), Bytes::new(), None, Some(cid1))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::WriteTokenRejected
    );
    // Targeted revoke of tok_a5 with min_grant_version = 10 MUST also delete every older token
    // with grant_version <= 10 (tok_a3, tok_a4, tok_a5 -> 3 removed) so no below-floor token
    // stays live or gets promoted to active.
    assert_eq!(
        store
            .revoke_write_token(RevokeWriteTokenRecord {
                recipient: bob,
                peer_slot_id: peer_a,
                token_hash: Some(tok_a5),
                min_grant_version: 10,
            })
            .await
            .unwrap(),
        3
    );
    for revoked_tok in [tok_a3, tok_a4, tok_a5] {
        assert_eq!(
            store
                .append_idempotent(&bob, &revoked_tok, Bytes::new(), Bytes::new(), None, None)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::WriteTokenRejected
        );
    }
    // Registering a grant <= min_grant_version (10) fails with StaleVersion.
    assert_eq!(
        store
            .register_write_token(RegisterWriteTokenRecord {
                recipient: bob,
                peer_slot_id: peer_a,
                token_hash: [0xA9; 32],
                grant_version: 10,
                pin_active: true,
                timestamp: now_ms,
            })
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::StaleVersion
    );
    // Registering with grant_version = 11 (> 10) succeeds!
    store
        .register_write_token(RegisterWriteTokenRecord {
            recipient: bob,
            peer_slot_id: peer_a,
            token_hash: [0xA9; 32],
            grant_version: 11,
            pin_active: true,
            timestamp: now_ms,
        })
        .await
        .unwrap();
    // A delayed unconditional revoke with min_grant_version = 10 MUST NOT delete the newer
    // grant_version = 11 token!
    assert_eq!(
        store
            .revoke_write_token(RevokeWriteTokenRecord {
                recipient: bob,
                peer_slot_id: peer_a,
                token_hash: None,
                min_grant_version: 10,
            })
            .await
            .unwrap(),
        0
    );
    let seq4 = store
        .append_idempotent(
            &bob,
            &[0xA9; 32],
            Bytes::from_static(b"h4"),
            Bytes::from_static(b"c4"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(seq4, 4);
    // Revoking peer_a with min_grant_version = 12 removes [0xA9; 32] (1 token).
    assert_eq!(
        store
            .revoke_write_token(RevokeWriteTokenRecord {
                recipient: bob,
                peer_slot_id: peer_a,
                token_hash: None,
                min_grant_version: 12,
            })
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .append_idempotent(&bob, &[0xA9; 32], Bytes::new(), Bytes::new(), None, None)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::WriteTokenRejected
    );
}
