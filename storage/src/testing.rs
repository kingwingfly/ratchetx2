//! Conformance suites every backend should pass.
//!
//! Each suite takes a fresh, empty store and panics on the first failure.

use bytes::Bytes;

#[allow(deprecated)]
use crate::{
    Bundle, ErrorKind, LocalHandshakeStore, LocalMailboxStore, MAX_SAFE_INTEGER,
    StoredInitialMessage,
};
use crate::{LocalAttachmentStore, StoredAttachment, StoredMessage};
#[cfg(feature = "pq")]
use crate::{
    LocalIdempotentMailboxStore, LocalPqHandshakeStore, PqLastResortCommitment, PublishV2Record,
    PublishV2Status, RefillPrekeysRecord, RefillStatus, StoredCapabilityManifest,
    StoredInitialMessageV2, StoredPqPrekey,
};

/// Conformance suite for legacy v1 [`LocalHandshakeStore`].
#[deprecated(
    note = "legacy v1 handshake store conformance is deprecated; use pq_handshake_store (see git tag archive/legacy-v1)"
)]
#[allow(deprecated)]
pub async fn handshake_store<S: LocalHandshakeStore>(store: &S) {
    let (alice, bob) = ([1; 32], [2; 32]);
    let bundle = |timestamp| Bundle {
        identity_key: bob,
        signed_prekey: [3; 32],
        signed_prekey_signature: [4; 64],
        timestamp,
    };

    assert_eq!(store.take_bundle(&bob).await.unwrap(), None);
    assert!(
        store
            .publish(bundle(10), vec![[5; 32], [6; 32]])
            .await
            .unwrap()
    );
    // Publishing needs a newer timestamp.
    assert!(!store.publish(bundle(10), vec![]).await.unwrap());
    assert!(!store.publish(bundle(9), vec![]).await.unwrap());

    // Each take consumes one one-time prekey; then the bundle comes without one.
    let (taken, first) = store.take_bundle(&bob).await.unwrap().unwrap();
    assert_eq!(taken, bundle(10));
    let (_, second) = store.take_bundle(&bob).await.unwrap().unwrap();
    let mut one_time_prekeys = [first.unwrap(), second.unwrap()];
    one_time_prekeys.sort();
    assert_eq!(one_time_prekeys, [[5; 32], [6; 32]]);
    assert_eq!(
        store.take_bundle(&bob).await.unwrap(),
        Some((bundle(10), None))
    );

    // Publishing again replaces the one-time prekeys.
    assert!(store.publish(bundle(11), vec![[7; 32]]).await.unwrap());
    assert_eq!(
        store.take_bundle(&bob).await.unwrap(),
        Some((bundle(11), Some([7; 32])))
    );
    assert_eq!(store.take_bundle(&alice).await.unwrap(), None);

    let initial_message = StoredInitialMessage {
        sender: alice,
        recipient: bob,
        ephemeral_key: [8; 32],
        signed_prekey: [3; 32],
        one_time_prekey: Some([5; 32]),
        header: Bytes::from_static(b"header"),
        content: Bytes::from_static(b"content"),
    };
    let without_one_time_prekey = StoredInitialMessage {
        one_time_prekey: None,
        content: Bytes::new(),
        ..initial_message.clone()
    };
    assert!(
        store
            .add_initial_message(initial_message.clone(), 2)
            .await
            .unwrap()
    );
    assert!(
        store
            .add_initial_message(without_one_time_prekey.clone(), 2)
            .await
            .unwrap()
    );
    // The inbox is full.
    assert!(
        !store
            .add_initial_message(initial_message.clone(), 2)
            .await
            .unwrap()
    );

    assert_eq!(
        store.take_initial_messages(&bob, 1).await.unwrap(),
        Some(vec![initial_message, without_one_time_prekey])
    );
    // Taking needs a newer timestamp, and takes only what arrived since.
    assert_eq!(store.take_initial_messages(&bob, 1).await.unwrap(), None);
    assert_eq!(
        store.take_initial_messages(&bob, 2).await.unwrap(),
        Some(vec![])
    );
    assert_eq!(
        store.take_initial_messages(&alice, 1).await.unwrap(),
        Some(vec![])
    );

    // Timestamps above MAX_SAFE_INTEGER are rejected rather than silently clamped.
    assert_eq!(
        store
            .publish(bundle(MAX_SAFE_INTEGER + 1), vec![])
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(
        store
            .take_initial_messages(&bob, MAX_SAFE_INTEGER + 1)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
}

/// Conformance suite for legacy v1 [`LocalMailboxStore`].
#[deprecated(
    note = "legacy v1 mailbox store conformance is deprecated; use idempotent_mailbox_store (see git tag archive/legacy-v1)"
)]
#[allow(deprecated)]
pub async fn mailbox_store<S: LocalMailboxStore>(store: &S) {
    let (alice, bob) = ([1; 32], [2; 32]);

    assert!(store.read(&alice, &bob, 0, 10).await.unwrap().is_empty());
    for i in 1..=3 {
        let initial_message = (i == 2).then(|| Bytes::from_static(b"initial"));
        let sequence = store
            .append(
                &alice,
                &bob,
                Bytes::from(vec![i]),
                Bytes::from(vec![i, i]),
                initial_message,
                Some([i; 32]),
            )
            .await
            .unwrap();
        assert_eq!(sequence, u64::from(i));
    }
    // The other direction is a separate queue.
    let sequence = store
        .append(
            &bob,
            &alice,
            Bytes::from_static(b"h"),
            Bytes::from_static(b"c"),
            None,
            Some([1; 32]),
        )
        .await
        .unwrap();
    assert_eq!(sequence, 1);

    let messages = store.read(&alice, &bob, 0, 10).await.unwrap();
    let sequences: Vec<_> = messages.iter().map(|m| m.sequence).collect();
    assert_eq!(sequences, [1, 2, 3]);
    assert_eq!(
        messages[1],
        StoredMessage {
            sender: alice,
            recipient: bob,
            sequence: 2,
            header: Bytes::from(vec![2]),
            content: Some(Bytes::from(vec![2, 2])),
            initial_message: Some(Bytes::from_static(b"initial")),
        }
    );
    let page = store.read(&alice, &bob, 1, 1).await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].sequence, 2);
    assert!(store.read(&alice, &bob, 3, 10).await.unwrap().is_empty());
    assert!(
        store
            .read(&alice, &bob, u64::MAX, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.read(&bob, &alice, 0, 10).await.unwrap().len(), 1);

    // Delivered, the first two go, of their queue only; a hash naming none changes nothing.
    store
        .delete_delivered(&alice, &bob, &[[1; 32], [2; 32], [9; 32]])
        .await
        .unwrap();
    let messages = store.read(&alice, &bob, 0, 10).await.unwrap();
    let sequences: Vec<_> = messages.iter().map(|m| m.sequence).collect();
    assert_eq!(sequences, [3]);
    assert_eq!(store.read(&bob, &alice, 0, 10).await.unwrap().len(), 1);
    // Numbers go on, and a page reads past the gap.
    for i in 4..=6 {
        let sequence = store
            .append(
                &alice,
                &bob,
                Bytes::from(vec![i]),
                Bytes::from(vec![i]),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(sequence, u64::from(i));
    }
    store
        .delete_delivered(&alice, &bob, &[[3; 32]])
        .await
        .unwrap();
    let page = store.read(&alice, &bob, 0, 2).await.unwrap();
    let sequences: Vec<_> = page.iter().map(|m| m.sequence).collect();
    assert_eq!(sequences, [4, 5]);
    // A message without a delivery hash stays.
    store.delete_delivered(&alice, &bob, &[]).await.unwrap();
    assert_eq!(store.read(&alice, &bob, 3, 10).await.unwrap().len(), 3);
}

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
    assert_eq!(store.chunk(&[9; 16], 0).await.unwrap(), None);

    // Deleted, it is gone with its chunks, and deleting it again does nothing.
    store.delete_attachment(&attachment.id).await.unwrap();
    assert_eq!(store.attachment(&attachment.id).await.unwrap(), None);
    assert_eq!(store.chunk(&attachment.id, 0).await.unwrap(), None);
    store.delete_attachment(&attachment.id).await.unwrap();
}

/// Conformance suite for [`LocalPqHandshakeStore`].
#[cfg(feature = "pq")]
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

    // Unknown identity returns None / empty without allocating.
    assert_eq!(store.get_manifest(&bob).await.unwrap(), None);
    assert_eq!(store.claim_bundle(&bob, &[1, 2]).await.unwrap(), None);
    assert!(
        store
            .list_initial_messages(&bob, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.ack_initial_messages(&bob, &[1]).await.unwrap(), 0);

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

    // Classical claim (empty preferred_suites) pops a classical OPK and NEVER consumes PQOPKs.
    let classical_claim = store.claim_bundle(&bob, &[]).await.unwrap().unwrap();
    assert_eq!(classical_claim.signed_prekey, [21; 32]);
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

    // Affirmative PQ OFF clears stored PQ prekeys while persisting the signed OFF manifest.
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

    // Two-phase inbox: add 1 classical (version 1) initial and 1 PQXDH (version 2) initial.
    let v1_id = store
        .add_initial_message_v2(
            StoredInitialMessageV2 {
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
            },
            2,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(v1_id > 0);
    let pq_id = store
        .add_initial_message_v2(
            StoredInitialMessageV2 {
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
            },
            2,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(pq_id > v1_id);
    // Inbox limit is enforced.
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

    // Non-destructive list returns BOTH v1 and v2 oldest-first.
    let listed = store.list_initial_messages(&bob, 10).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id, v1_id);
    assert_eq!(listed[0].version, 1);
    assert_eq!(listed[1].id, pq_id);
    assert_eq!(listed[1].version, 2);

    // Ack deletes only the acknowledged IDs.
    assert_eq!(store.ack_initial_messages(&bob, &[v1_id]).await.unwrap(), 1);
    let remaining = store.list_initial_messages(&bob, 10).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, pq_id);
    assert_eq!(remaining[0].version, 2);

    assert_eq!(store.ack_initial_messages(&bob, &[pq_id]).await.unwrap(), 1);
    assert!(
        store
            .list_initial_messages(&bob, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Conformance suite for [`LocalIdempotentMailboxStore`].
#[cfg(feature = "pq")]
pub async fn idempotent_mailbox_store<S: LocalIdempotentMailboxStore>(store: &S) {
    let (alice, bob) = ([21; 32], [22; 32]);
    let cid = [0x42; 16];

    assert!(store.read(&alice, &bob, 0, 10).await.unwrap().is_empty());

    let seq1 = store
        .append_idempotent(
            &alice,
            &bob,
            Bytes::from_static(b"h1"),
            Bytes::from_static(b"c1"),
            Some(Bytes::from_static(b"initial")),
            Some([1; 32]),
            Some(cid),
        )
        .await
        .unwrap();
    assert_eq!(seq1, 1);
    // Retrying with the same client_message_id returns the original sequence without duplicating.
    let seq1_retry = store
        .append_idempotent(
            &alice,
            &bob,
            Bytes::from_static(b"h1"),
            Bytes::from_static(b"c1"),
            Some(Bytes::from_static(b"initial")),
            Some([1; 32]),
            Some(cid),
        )
        .await
        .unwrap();
    assert_eq!(seq1_retry, 1);

    // The opposite direction is an independent queue.
    let reverse = store
        .append_idempotent(
            &bob,
            &alice,
            Bytes::from_static(b"rh"),
            Bytes::from_static(b"rc"),
            None,
            Some([1; 32]),
            Some(cid),
        )
        .await
        .unwrap();
    assert_eq!(reverse, 1);

    let messages = store.read(&alice, &bob, 0, 10).await.unwrap();
    assert_eq!(
        messages,
        vec![StoredMessage {
            sender: alice,
            recipient: bob,
            sequence: 1,
            header: Bytes::from_static(b"h1"),
            content: Some(Bytes::from_static(b"c1")),
            initial_message: Some(Bytes::from_static(b"initial")),
        }]
    );

    // Tombstone survives delete_delivered, and deleting only affects the matching direction.
    store
        .delete_delivered(&alice, &bob, &[[1; 32], [9; 32]])
        .await
        .unwrap();
    assert_eq!(store.read(&bob, &alice, 0, 10).await.unwrap().len(), 1);
    let retry = store
        .append_idempotent(
            &alice,
            &bob,
            Bytes::new(),
            Bytes::new(),
            None,
            Some([1; 32]),
            Some(cid),
        )
        .await
        .unwrap();
    assert_eq!(retry, seq1);
    assert!(store.read(&alice, &bob, 0, 10).await.unwrap().is_empty());

    let next = store
        .append_idempotent(
            &alice,
            &bob,
            Bytes::from_static(b"h2"),
            Bytes::from_static(b"c2"),
            None,
            Some([2; 32]),
            Some([0x43; 16]),
        )
        .await
        .unwrap();
    assert_eq!(next, seq1 + 1);

    // Appending without a client_message_id allocates the next sequence cleanly.
    let seq3 = store
        .append_idempotent(
            &alice,
            &bob,
            Bytes::from_static(b"h3"),
            Bytes::from_static(b"c3"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(seq3, next + 1);

    let messages = store.read(&alice, &bob, 0, 10).await.unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].sequence, next);
    assert_eq!(messages[1].sequence, seq3);

    // Pagination and bounds.
    let page = store.read(&alice, &bob, 0, 1).await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].sequence, next);
    let page2 = store.read(&alice, &bob, next, 10).await.unwrap();
    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].sequence, seq3);
    assert!(
        store
            .read(&alice, &bob, u64::MAX, 10)
            .await
            .unwrap()
            .is_empty()
    );
    // Empty hashes list leaves remaining messages untouched.
    store.delete_delivered(&alice, &bob, &[]).await.unwrap();
    assert_eq!(store.read(&alice, &bob, 0, 10).await.unwrap().len(), 2);
}
