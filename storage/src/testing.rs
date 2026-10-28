//! Conformance suites every backend should pass.
//!
//! Each suite takes a fresh, empty store and panics on the first failure.

use bytes::Bytes;

use crate::{
    Bundle, LocalAttachmentStore, LocalHandshakeStore, LocalMailboxStore, StoredAttachment,
    StoredInitialMessage, StoredMessage,
};

/// Conformance suite for [`LocalHandshakeStore`].
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
}

/// Conformance suite for [`LocalMailboxStore`].
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
        uploader: [2; 32],
        chunks: 2,
        token_hash: [3; 32],
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
