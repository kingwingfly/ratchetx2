//! Conformance suites every backend should pass.
//!
//! Each suite takes a fresh, empty store and panics on the first failure.

use bytes::Bytes;

use crate::{Bundle, Introduction, LocalHandshakeStore, LocalMailboxStore, StoredMessage};

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

    let introduction = Introduction {
        sender: alice,
        recipient: bob,
        ephemeral_key: [8; 32],
        signed_prekey: [3; 32],
        one_time_prekey: Some([5; 32]),
    };
    let without_one_time_prekey = Introduction {
        one_time_prekey: None,
        ..introduction.clone()
    };
    assert!(
        store
            .add_introduction(introduction.clone(), 2)
            .await
            .unwrap()
    );
    assert!(
        store
            .add_introduction(without_one_time_prekey.clone(), 2)
            .await
            .unwrap()
    );
    // The inbox is full.
    assert!(
        !store
            .add_introduction(introduction.clone(), 2)
            .await
            .unwrap()
    );

    assert_eq!(
        store.take_introductions(&bob, 1).await.unwrap(),
        Some(vec![introduction, without_one_time_prekey])
    );
    // Taking needs a newer timestamp, and takes only what arrived since.
    assert_eq!(store.take_introductions(&bob, 1).await.unwrap(), None);
    assert_eq!(
        store.take_introductions(&bob, 2).await.unwrap(),
        Some(vec![])
    );
    assert_eq!(
        store.take_introductions(&alice, 1).await.unwrap(),
        Some(vec![])
    );
}

/// Conformance suite for [`LocalMailboxStore`].
pub async fn mailbox_store<S: LocalMailboxStore>(store: &S) {
    let (alice, bob) = ([1; 32], [2; 32]);

    assert!(store.read(&alice, &bob, 0, 10).await.unwrap().is_empty());
    for i in 1..=3 {
        let sequence = store
            .append(&alice, &bob, Bytes::from(vec![i]), Bytes::from(vec![i, i]))
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
            content: Bytes::from(vec![2, 2]),
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
}
