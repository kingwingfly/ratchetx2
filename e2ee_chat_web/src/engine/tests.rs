use super::contact::{
    accept_contact_request_state, contact_state_is_new_quarantined, place_of,
    record_quarantined_initial_state, restore_contacts, stored_contacts,
};
use super::handshake::{PublishError, refill_batch_counts, stage_inbox_ack};
use super::settings::{describe_upgrade_pq_error, finalize_upgrade_to_pq_request_state};
use super::{
    AttachmentKey, ChunkOf, HistoryStore, Inner, NAME_MAX, ONE_TIME_PREKEYS, REFILL_USED,
    SERVER_MAX_ONE_TIME_PREKEYS, attachment_key_hash, build_invitation_link, checked_name,
    parse_invitation_hash,
};
use crate::content::{Content, Kind};
use crate::state::{Delivery, Dialog, Me, ServerPqStatus};
use crate::transport::Fetch;
use crate::util::{hex, key_from_text, key_to_url, short};
#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
use crate::vault::Farewell;
use crate::vault::{
    AppState, Awaiting, ContactState, HistoryEntry, Outgoing, OutgoingRecord, history_key,
    outbox_key,
};
#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
use bytes::Bytes;
use prost::Message;
use session::protocol::content::Hello;
#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
use session::protocol::{
    handshake_v2::InitialMessageV2 as WireInitialMessageV2, mailbox_v2::PushV2Request,
};
use session::{Client, ErrorKind, PqConfig, PublicKey, Session, SessionState, proto};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};

#[test]
fn names_have_at_most_name_max_characters() {
    assert_eq!(checked_name("  alice \n").as_deref(), Ok("alice"));
    // Characters, not bytes: 64 of four bytes each.
    assert!(checked_name(&"😀".repeat(NAME_MAX)).is_ok());
    assert!(checked_name(&"a".repeat(NAME_MAX + 1)).is_err());
    // The longest greeting is far below the 4 KiB a first message may take.
    let greeting = Kind::Hello(Hello {
        name: "😀".repeat(NAME_MAX),
        ..Hello::default()
    });
    assert!(greeting.to_bytes().len() < 512);
}

#[test]
fn a_peer_cannot_place_a_message_before_what_it_saw() {
    let state = ContactState {
        clock: 9,
        peer_last: 5,
        read_by_peer: 7,
        ..ContactState::default()
    };
    // An honest peer's clock is past both.
    assert_eq!(place_of(8, &state), 8);
    // Backdated, it goes after the peer's last message, and the one it read.
    assert_eq!(place_of(2, &state), 8);
    // Without a clock, where it came.
    assert_eq!(place_of(0, &state), 10);
    // Nor far past the chat's highest place, where it would pin the chat's clock.
    assert_eq!(
        place_of(u64::MAX, &state),
        9 + session::protocol::content::MAX_AHEAD
    );
}

#[test]
fn invitation_link_generation_and_parsing_with_pq_pinning() {
    let key = [0x3Au8; 32];
    let me = Me {
        name: "Alice & Bob".to_string(),
        key,
        server: "https://relay.example.com".to_string(),
        pq_config: PqConfig::default(),
        server_pq: ServerPqStatus::Unknown,
    };
    let link = build_invitation_link("https://chat.example.com", &me);
    let (_, hash) = link.split_once('#').expect("has fragment");
    let parsed = parse_invitation_hash(hash).expect("parses");
    let expected_pq = me.pq_config.pq_enabled && !me.pq_config.offered_suites().is_empty();
    assert_eq!(link.contains("&pq=1"), expected_pq);
    assert_eq!(
        parsed,
        Dialog::NewChat {
            key: key_to_url(&key),
            name: "Alice & Bob".to_string(),
            server: Some("https://relay.example.com".to_string()),
            pq_pinned: expected_pq,
        }
    );

    // Explicit `#chat=<hex>&name=...&pq=1` link sets pq_pinned = true and parses hex key.
    let hex_key = hex(&key);
    let hex_parsed = parse_invitation_hash(&format!("#chat={hex_key}&name=Carol&pq=1")).unwrap();
    assert_eq!(
        hex_parsed,
        Dialog::NewChat {
            key: hex_key.clone(),
            name: "Carol".to_string(),
            server: None,
            pq_pinned: true,
        }
    );
    assert_eq!(key_from_text(&hex_key), Some(key));

    // Legacy link without `&pq=1` does NOT pin PQ.
    let legacy = parse_invitation_hash(&format!("#chat={hex_key}&name=Carol")).unwrap();
    assert_eq!(
        legacy,
        Dialog::NewChat {
            key: hex_key,
            name: "Carol".to_string(),
            server: None,
            pq_pinned: false,
        }
    );
}

#[test]
fn invitation_link_omits_pq_pin_when_server_disables_pq() {
    let key = [0x4Bu8; 32];
    let mut me = Me {
        name: "Alice".to_string(),
        key,
        server: "https://chat.example.com".to_string(),
        pq_config: PqConfig::default(),
        server_pq: ServerPqStatus::Disabled,
    };
    let link = build_invitation_link("https://chat.example.com", &me);
    assert!(
        !link.contains("&pq=1"),
        "invitation link must omit &pq=1 on classical-only servers: {link}"
    );
    let (_, hash) = link.split_once('#').expect("has fragment");
    assert_eq!(
        parse_invitation_hash(hash),
        Some(Dialog::NewChat {
            key: key_to_url(&key),
            name: "Alice".to_string(),
            server: None,
            pq_pinned: false,
        })
    );

    // Once the server advertises PQ enabled (in PQ builds), `&pq=1` is emitted again.
    me.server_pq = ServerPqStatus::Enabled {
        suites: PqConfig::compiled_suites(),
        pq_ratchet: true,
    };
    let enabled_link = build_invitation_link("https://chat.example.com", &me);
    let expected_pq = me.pq_config.pq_enabled && !me.pq_config.offered_suites().is_empty();
    assert_eq!(enabled_link.contains("&pq=1"), expected_pq);
}

#[test]
fn describe_upgrade_pq_error_maps_plain_english_and_prioritizes_server_disabled() {
    let disabled = ServerPqStatus::Disabled;
    let msg = describe_upgrade_pq_error(
        ErrorKind::ClassicalApprovalRequired {
            peer_signed_off: true,
        },
        &disabled,
        "raw".to_string(),
    );
    assert!(
        msg.contains("this server does not have post-quantum encryption enabled"),
        "{msg}"
    );
    assert!(!msg.contains("peer_signed_off"), "{msg}");

    let unknown = ServerPqStatus::Unknown;
    let signed_off = describe_upgrade_pq_error(
        ErrorKind::ClassicalApprovalRequired {
            peer_signed_off: true,
        },
        &unknown,
        "raw".to_string(),
    );
    assert!(
        signed_off.contains("peer has post-quantum encryption turned off"),
        "{signed_off}"
    );
    assert!(!signed_off.contains("peer_signed_off"), "{signed_off}");

    let legacy = describe_upgrade_pq_error(
        ErrorKind::ClassicalApprovalRequired {
            peer_signed_off: false,
        },
        &unknown,
        "raw".to_string(),
    );
    assert!(legacy.contains("no post-quantum prekeys"), "{legacy}");

    let expired =
        describe_upgrade_pq_error(ErrorKind::PeerManifestExpired, &unknown, "raw".to_string());
    assert!(expired.contains("expired"), "{expired}");

    let strict = describe_upgrade_pq_error(ErrorKind::PqRequired, &unknown, "raw".to_string());
    assert!(strict.contains("strict mode"), "{strict}");

    let downgrade =
        describe_upgrade_pq_error(ErrorKind::DowngradeDetected, &unknown, "raw".to_string());
    assert!(downgrade.contains("Downgrade detected"), "{downgrade}");
}

#[test]
fn attachment_cache_keys_isolate_peer_and_key() {
    let peer_a = [0x11u8; 32];
    let peer_b = [0x22u8; 32];
    let shared_id = [0x99u8; 16];
    let key_1 = [0x01u8; 32];
    let key_2 = [0x02u8; 32];

    let k_a1: AttachmentKey = (peer_a, shared_id, attachment_key_hash(&key_1));
    let k_a2: AttachmentKey = (peer_a, shared_id, attachment_key_hash(&key_2));
    let k_b1: AttachmentKey = (peer_b, shared_id, attachment_key_hash(&key_1));
    assert_ne!(
        k_a1, k_a2,
        "same peer+id with different keys must not collide"
    );
    assert_ne!(
        k_a1, k_b1,
        "same id+key across different peers must not collide"
    );
    assert_ne!(k_a2, k_b1);

    let c_a1: ChunkOf = (peer_a, shared_id, attachment_key_hash(&key_1), 0);
    let c_a2: ChunkOf = (peer_a, shared_id, attachment_key_hash(&key_2), 0);
    let c_b1: ChunkOf = (peer_b, shared_id, attachment_key_hash(&key_1), 0);
    assert_ne!(c_a1, c_a2);
    assert_ne!(c_a1, c_b1);
}

#[test]
fn quarantined_primary_survives_second_initial_and_blocks_accept() {
    // Brand-new quarantined classical contact created on first initial message.
    let mut state = ContactState {
        peer: vec![0x42; 32],
        request: true,
        quarantined: true,
        quarantined_primary: true,
        quarantined_first_message: b"msg-1".to_vec(),
        ..ContactState::default()
    };
    assert!(contact_state_is_new_quarantined(&state));

    // Zero-click attacker bypass regression: a 2nd classical initial populates
    // `quarantined_session`, but `quarantined_primary` MUST remain true so `receive()` and
    // `flush()` stay blocked until explicit approval.
    record_quarantined_initial_state(
        &mut state,
        Some(proto::SessionState::default()),
        b"msg-2".to_vec(),
        false,
        1234,
    );
    assert!(state.quarantined_session.is_some());
    assert!(state.quarantined_primary);
    assert!(contact_state_is_new_quarantined(&state));
    assert_eq!(state.quarantined_first_message, b"msg-2");

    // UI / Engine::accept() bypass regression: accepting while quarantined MUST be refused
    // and leave `request` and `quarantined_primary` intact.
    assert!(accept_contact_request_state(&mut state, "Mallory").is_err());
    assert!(state.request);
    assert!(state.quarantined);
    assert!(contact_state_is_new_quarantined(&state));

    // Only after explicit approval clears quarantine can `accept` succeed.
    state.quarantined = false;
    state.quarantined_primary = false;
    assert!(!contact_state_is_new_quarantined(&state));
    assert!(accept_contact_request_state(&mut state, "  Alice  ").is_ok());
    assert!(!state.request);
    assert_eq!(state.name, "Alice");
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[test]
fn farewell_push_v2_preserves_carried_initial_message_v2() {
    let pq_initial = WireInitialMessageV2 {
        id: 0,
        version: 2,
        identity_key: Bytes::from(vec![0x11; 32]),
        pq_suite: PqConfig::default_suite().as_u8() as u32,
        pq_prekey_id: Bytes::from(vec![0x33; 32]),
        pq_ciphertext: Bytes::from(vec![0x44; 64]),
        ..WireInitialMessageV2::default()
    };
    let req = PushV2Request {
        sender: Bytes::from(vec![0x11; 32]),
        recipient: Bytes::from(vec![0x22; 32]),
        message: None,
        initial_message: Some(pq_initial.clone()),
        delivery_hash: Bytes::new(),
        client_message_id: Bytes::from(vec![0xAB; 16]),
    };
    let farewell = Farewell {
        push: None,
        client_message_id: vec![0xAB; 16],
        push_v2: req.encode_to_vec(),
    };
    let decoded = PushV2Request::decode(farewell.push_v2.as_slice()).expect("decode push_v2");
    assert_eq!(decoded.initial_message, Some(pq_initial));
    assert_eq!(decoded.client_message_id.as_ref(), &[0xAB; 16]);
}

#[test]
fn refill_batch_counts_stays_under_server_caps_across_many_rounds() {
    // Simulate 100 consecutive refills with 2 PQ suites starting from initial publish (20
    // classical + 40 PQOPKs). Cumulative server counts MUST NEVER exceed 100!
    let mut server_classical: u32 = ONE_TIME_PREKEYS as u32;
    let mut server_pq: u32 = (ONE_TIME_PREKEYS * 2) as u32;
    for _ in 0..100 {
        server_classical = server_classical.saturating_sub(REFILL_USED);
        server_pq = server_pq.saturating_sub(REFILL_USED);
        let (add_c, add_pq_per_suite) = refill_batch_counts(
            REFILL_USED,
            REFILL_USED,
            2,
            Some(server_classical + REFILL_USED),
            Some(server_pq + REFILL_USED),
        );
        assert!(add_c > 0);
        assert!(add_pq_per_suite > 0);
        server_classical += add_c as u32;
        server_pq += (add_pq_per_suite * 2) as u32;
        assert!(
            server_classical as usize <= SERVER_MAX_ONE_TIME_PREKEYS,
            "classical exceeded cap: {server_classical}"
        );
        assert!(server_pq as usize <= 100, "pq exceeded cap: {server_pq}");
    }

    // Unknown server counts (e.g. right after reload) still keep net additions <= 0.
    let (add_c, add_pq_2) = refill_batch_counts(REFILL_USED, REFILL_USED, 2, None, None);
    assert_eq!(add_c, REFILL_USED as usize);
    assert_eq!(add_pq_2 * 2, REFILL_USED as usize);
    let (_, add_pq_1) = refill_batch_counts(0, REFILL_USED, 1, None, None);
    assert_eq!(add_pq_1, REFILL_USED as usize);

    // When server is already at cap (e.g. 100 remaining after burst or over-provisioned),
    // headroom clamps additions so we never exceed 100.
    let (add_c, add_pq) = refill_batch_counts(REFILL_USED, REFILL_USED, 2, Some(100), Some(100));
    assert_eq!(add_c, 10);
    assert_eq!(add_pq, 5);
    let (add_c_full, add_pq_full) =
        refill_batch_counts(REFILL_USED, REFILL_USED, 2, Some(115), Some(115));
    assert_eq!(add_c_full, 0);
    assert_eq!(add_pq_full, 0);
}

#[test]
fn upgrade_to_pq_unlocks_inbound_request_and_records_hello_when_history_empty() {
    let mut state = ContactState {
        peer: vec![0x77; 32],
        request: true,
        history_len: 0,
        ..ContactState::default()
    };
    let hello = Kind::Hello(Hello {
        name: "Alice".to_string(),
        pq_capable: true,
        ..Hello::default()
    });
    let added = finalize_upgrade_to_pq_request_state(&mut state, hello.clone(), 1, 9999);
    assert!(!state.request, "upgrade_to_pq must clear request flag");
    assert_eq!(state.history_len, 1);
    assert_eq!(state.last_activity, 9999);
    let (idx, entry) = added.expect("must record outgoing Hello when history was empty");
    assert_eq!(idx, 0);
    assert!(entry.outgoing);
    assert_eq!(entry.place, 1);
    assert_eq!(entry.delivery(), Delivery::Sent);

    // When history is already non-empty, `request` is still cleared without duplicating Hello.
    state.request = true;
    let second = finalize_upgrade_to_pq_request_state(&mut state, hello, 2, 10000);
    assert!(!state.request);
    assert!(second.is_none());
    assert_eq!(state.history_len, 1);
}

const TEST_SERVER: &str = "https://chat.example";

/// Only these three vault operations participate in an inbox or outbox transaction.
#[derive(Default)]
struct MemoryHistory {
    state: RefCell<AppState>,
    entries: RefCell<HashMap<String, HistoryEntry>>,
    outbox: RefCell<HashMap<String, OutgoingRecord>>,
    fail_read_at: Cell<Option<u64>>,
    fail_save: Cell<bool>,
}

impl HistoryStore for MemoryHistory {
    async fn entry(
        &self,
        peer: &PublicKey,
        index: u64,
    ) -> crate::vault::Result<Option<HistoryEntry>> {
        if self.fail_read_at.get() == Some(index) {
            return Err(crate::vault::Error::Storage("read failed".into()));
        }
        Ok(self
            .entries
            .borrow()
            .get(&history_key(peer, index))
            .cloned())
    }

    async fn content(
        &self,
        _: &PublicKey,
        _: u64,
        entry: &HistoryEntry,
    ) -> crate::vault::Result<Option<Kind>> {
        Ok(entry.content.as_ref().and_then(|c| c.kind.clone()))
    }

    async fn save<'a>(
        &self,
        state: &AppState,
        entries: impl IntoIterator<Item = &'a (String, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (String, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()> {
        if self.fail_save.get() {
            return Err(crate::vault::Error::Storage("write failed".into()));
        }
        self.state.replace(state.clone());
        self.entries
            .borrow_mut()
            .extend(entries.into_iter().cloned());
        let mut outbox = self.outbox.borrow_mut();
        for (key, record) in outgoing {
            if let Some(record) = record {
                outbox.insert(key.clone(), record.clone());
            } else {
                outbox.remove(key);
            }
        }
        Ok(())
    }
}

fn identity() -> PublicKey {
    Client::new(Fetch::client(TEST_SERVER)).identity_key()
}

fn stored_contact(me: PublicKey, peer: PublicKey) -> ContactState {
    let mut session = proto::SessionState::default();
    session.me.extend(me);
    session.peer.extend(peer);
    session.peer_pq.get_or_insert_default().pq_pinned = true;
    ContactState {
        peer: peer.to_vec(),
        session: Some(session),
        ..Default::default()
    }
}

fn unlocked_client() -> (Inner<MemoryHistory>, PublicKey) {
    let client = Client::new(Fetch::client(TEST_SERVER));
    let me = client.identity_key();
    let peer = identity();
    let (contacts, isolated, warnings) =
        restore_contacts(vec![stored_contact(me, peer)], &me, TEST_SERVER);
    assert!(warnings.is_empty());
    (
        Inner::new(
            MemoryHistory::default(),
            TEST_SERVER.into(),
            "chat.example".into(),
            AppState::default(),
            client,
            contacts,
            isolated,
        ),
        peer,
    )
}

#[test]
fn unlock_keeps_healthy_pins_and_preserves_unreadable_contacts() {
    let me = identity();
    let healthy = stored_contact(me, identity());
    let second = stored_contact(me, identity());
    let mut bad_key = stored_contact(me, identity());
    bad_key.peer.pop();
    bad_key.name = "old laptop".into();
    let missing = ContactState {
        peer: identity().to_vec(),
        ..Default::default()
    };
    let mut corrupt = stored_contact(me, identity());
    corrupt.session.as_mut().unwrap().cursor = u64::MAX;
    let mut duplicate = healthy.clone();
    duplicate.name = "duplicate".into();
    let bad = vec![bad_key, missing, corrupt, duplicate];
    let input = vec![
        bad[0].clone(),
        healthy.clone(),
        bad[1].clone(),
        bad[2].clone(),
        second.clone(),
        bad[3].clone(),
    ];
    let (contacts, isolated, warnings) = restore_contacts(input, &me, TEST_SERVER);
    assert_eq!(contacts.len(), 2);
    assert!(contacts.iter().all(|c| c.session.peer_pq_state().pq_pinned));
    assert_eq!(isolated, bad);
    assert_eq!(warnings.len(), bad.len());
    assert!(warnings[0].contains("old laptop") && warnings[0].contains("malformed"));
    for (warning, state) in warnings[1..].iter().zip(&bad[1..]) {
        assert!(warning.contains(&short(&state.peer.as_slice().try_into().unwrap())));
    }
    assert!(warnings[1].contains("missing session"));
    assert!(warnings[2].contains("state"));
    assert!(warnings[3].contains("duplicate"));
    let saved = stored_contacts(&contacts, &isolated);
    assert_eq!(&saved[2..], &bad[..3]);
    let (restored, still_isolated, _) = restore_contacts(saved, &me, TEST_SERVER);
    assert_eq!(restored.len(), 2);
    assert_eq!(still_isolated, bad[..3]);
}

#[test]
fn state_only_inbox_save_precedes_ack_and_refreshes_after_retry() {
    futures::executor::block_on(async {
        let (mut inner, peer) = unlocked_client();
        let pending = &mut inner.state.pending_inbox_acks;
        assert!(!stage_inbox_ack(pending, 0));
        assert!(stage_inbox_ack(pending, 7));
        assert!(!stage_inbox_ack(pending, 7));
        inner.contact(&peer).unwrap().state.quarantined = true;
        inner.vault.fail_save.set(true);
        assert!(inner.save_inbox_changes(vec![], vec![]).await.is_err());
        assert!(inner.unsaved_state && inner.needs_save());
        assert!(!inner.contacts_dirty_late);
        inner
            .ack_persisted_inbox(async |_, _, _| panic!("ack before durable save"))
            .await
            .unwrap();
        assert!(inner.vault.state.borrow().pending_inbox_acks.is_empty());

        inner.vault.fail_save.set(false);
        inner.save(&[]).await.unwrap();
        assert!(!inner.needs_save() && inner.contacts_dirty_late);
        assert!(inner.vault.state.borrow().contacts[0].quarantined);
        assert_eq!(inner.vault.state.borrow().pending_inbox_acks, [7]);
        inner
            .ack_persisted_inbox(async |_, _, ids| {
                assert_eq!(ids, [7]);
                Ok(())
            })
            .await
            .unwrap();
        assert!(inner.vault.state.borrow().pending_inbox_acks.is_empty());
    });
}

#[test]
fn partial_ack_persists_remaining_ids_and_retries_failed_shrink() {
    futures::executor::block_on(async {
        let (mut inner, _) = unlocked_client();
        inner.state.pending_inbox_acks.extend(1..=205);
        inner.save(&[]).await.unwrap();
        let error = inner
            .ack_persisted_inbox(async |_, _, ids| {
                assert_eq!(ids.len(), 100);
                if ids[0] == 1 {
                    Ok(())
                } else {
                    Err("lost acknowledgement".into())
                }
            })
            .await
            .unwrap_err();
        assert!(error.contains("lost acknowledgement"));
        let saved =
            AppState::decode(inner.vault.state.borrow().encode_to_vec().as_slice()).unwrap();
        assert_eq!(saved.pending_inbox_acks, (101..=205).collect::<Vec<_>>());
        assert_eq!(inner.state.pending_inbox_acks, saved.pending_inbox_acks);
        assert!(!stage_inbox_ack(&mut inner.state.pending_inbox_acks, 205));

        inner.vault.fail_save.set(true);
        let mut sizes = vec![];
        assert!(
            inner
                .ack_persisted_inbox(async |_, _, ids| {
                    sizes.push(ids.len());
                    Ok(())
                })
                .await
                .is_err()
        );
        assert_eq!(sizes, [100, 5]);
        assert!(inner.unsaved_state && inner.state.pending_inbox_acks.is_empty());
        assert_eq!(
            inner.vault.state.borrow().pending_inbox_acks,
            saved.pending_inbox_acks
        );
        inner.vault.fail_save.set(false);
        inner.save(&[]).await.unwrap();
        assert!(!inner.unsaved_state);
        assert!(inner.vault.state.borrow().pending_inbox_acks.is_empty());
    });
}

#[test]
fn local_pq_off_accepts_classical_replacement_without_granting_an_exception() {
    use session::protocol::{
        self,
        connect::{ConnectClient, LocalPost},
        handshake::FetchBundleResponse,
    };

    struct Bundle(FetchBundleResponse);
    impl LocalPost for Bundle {
        async fn post(&self, path: &str, _: Vec<u8>) -> protocol::Result<(u16, Vec<u8>)> {
            assert!(path.ends_with("/FetchBundle"));
            Ok((200, self.0.encode_to_vec()))
        }
    }

    futures::executor::block_on(async {
        let mut bob = Client::new(Fetch::client(TEST_SERVER));
        let publish = bob.prepare_publish(1).unwrap().request;
        let mut alice = Client::new(ConnectClient::new(Bundle(FetchBundleResponse {
            signed_prekey: publish.signed_prekey,
            signed_prekey_signature: publish.signed_prekey_signature,
            one_time_prekey: publish.one_time_prekeys.first().cloned(),
        })));
        let initiation = alice
            .prepare_initiate(&bob.identity_key(), b"hello", ())
            .await
            .unwrap();
        let message =
            session::InitialMessage::try_from(initiation.request.message.as_ref().unwrap())
                .unwrap();
        let (incoming, _) = bob
            .accept(&alice.identity_key(), &message, Fetch::client(TEST_SERVER))
            .unwrap();
        let stored: proto::SessionState = incoming.state().into();
        let (mut contacts, _, _) = restore_contacts(
            vec![stored_contact(bob.identity_key(), alice.identity_key())],
            &bob.identity_key(),
            TEST_SERVER,
        );
        let contact = &mut contacts[0];
        contact.state.outbox.push(Outgoing {
            sealed: true,
            ..Default::default()
        });
        assert_eq!(
            contact.replace_session(incoming, true).unwrap_err().kind(),
            ErrorKind::DowngradeDetected
        );
        let incoming = Session::restore(
            Fetch::client(TEST_SERVER),
            SessionState::try_from(&stored).unwrap(),
        );
        assert!(contact.replace_session(incoming, false).unwrap());
        assert!(contact.state.needs_requeue_sealed);
        assert!(contact.session.peer_pq_state().pq_pinned);
        assert!(!contact.session.peer_pq_state().allow_classical_exception);
    });
}

fn waiting(index: u64, sealed: bool) -> Outgoing {
    Outgoing {
        history_index: index,
        sealed,
        clock: if sealed { 9 } else { 0 },
        ..Default::default()
    }
}

fn history(text: &str) -> HistoryEntry {
    HistoryEntry {
        outgoing: true,
        delivery: Delivery::Pending.into(),
        content: Some(Content {
            kind: Some(Kind::Text(text.into())),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn requeue_reads_before_mutation_and_drops_only_messages_with_missing_originals() {
    futures::executor::block_on(async {
        let (mut inner, peer) = unlocked_client();
        inner.contacts[0].state.outbox = vec![
            waiting(0, true),
            waiting(1, true),
            waiting(2, true),
            waiting(3, false),
        ];
        inner.contacts[0].state.needs_requeue_sealed = true;
        let before = inner.contacts[0].state.clone();
        assert_eq!(
            ContactState::decode(before.encode_to_vec().as_slice()).unwrap(),
            before
        );
        let first = history("keep me");
        inner.vault.entries.borrow_mut().extend([
            (history_key(&peer, 0), first.clone()),
            (
                history_key(&peer, 2),
                HistoryEntry {
                    outgoing: true,
                    ..Default::default()
                },
            ),
        ]);
        inner.vault.fail_read_at.set(Some(2));
        assert!(inner.requeue_before_push(&peer).await.is_err());
        assert_eq!(inner.contacts[0].state, before);

        inner.vault.fail_read_at.set(None);
        inner.vault.fail_save.set(true);
        assert!(inner.requeue_before_push(&peer).await.is_err());
        assert_eq!(inner.contacts[0].state, before);
        inner.vault.fail_save.set(false);
        let outcome = inner.requeue_before_push(&peer).await.unwrap().unwrap();
        assert!(!inner.vault.state.borrow().contacts[0].needs_requeue_sealed);
        assert_eq!(
            inner.vault.entries.borrow()[&history_key(&peer, 2)].delivery(),
            Delivery::Failed
        );
        assert_eq!(
            inner.contacts[0].state.outbox,
            [waiting(0, false), waiting(3, false)]
        );
        assert!(!inner.contacts[0].state.needs_requeue_sealed);
        assert_eq!(
            outcome.outbox,
            [
                (
                    outbox_key(&peer, 0),
                    Some(OutgoingRecord {
                        content: first.content.unwrap().kind.unwrap().to_bytes(),
                        ..Default::default()
                    })
                ),
                (outbox_key(&peer, 1), None),
                (outbox_key(&peer, 2), None),
            ]
        );
        assert_eq!(outcome.history.len(), 1);
        assert_eq!(outcome.history[0].0, 2);
        assert_eq!(outcome.history[0].1.delivery(), Delivery::Failed);

        // A peer deleting its chat requeues previously sent, unread messages through the same path.
        inner.contacts[0].state.awaiting = vec![Awaiting {
            history_index: 2,
            ..Default::default()
        }];
        let outcome = inner.requeue(&peer, true, &BTreeMap::new()).await.unwrap();
        assert_eq!(outcome.outbox, [(outbox_key(&peer, 2), None)]);
        assert_eq!(outcome.history[0].1.delivery(), Delivery::Failed);
        assert!(inner.contacts[0].state.awaiting.is_empty());
        assert_eq!(
            inner.contacts[0].state.outbox,
            [waiting(0, false), waiting(3, false)]
        );
    });
}

#[test]
fn fail_waiting_preserves_queue_on_read_or_commit_failure() {
    futures::executor::block_on(async {
        let (mut inner, peer) = unlocked_client();
        let outbox = vec![waiting(0, false), waiting(1, true)];
        inner.contacts[0].state.outbox = outbox.clone();
        let key = history_key(&peer, 0);
        inner
            .vault
            .entries
            .borrow_mut()
            .insert(key.clone(), history("queued"));
        inner
            .save_with(
                &[],
                &[(outbox_key(&peer, 0), Some(OutgoingRecord::default()))],
            )
            .await
            .unwrap();
        inner.vault.fail_read_at.set(Some(0));
        assert!(inner.fail_waiting(&peer, "refused".into()).await.is_err());
        assert_eq!(inner.contacts[0].state.outbox, outbox);
        inner.vault.fail_read_at.set(None);
        inner.vault.fail_save.set(true);
        assert!(inner.fail_waiting(&peer, "refused".into()).await.is_err());
        assert_eq!(inner.contacts[0].state.outbox, outbox);
        assert_eq!(inner.vault.state.borrow().contacts[0].outbox, outbox);
        assert_eq!(
            inner.vault.entries.borrow()[&key].delivery(),
            Delivery::Pending
        );
        assert!(
            inner
                .vault
                .outbox
                .borrow()
                .contains_key(&outbox_key(&peer, 0))
        );
        inner.vault.fail_save.set(false);
        inner.fail_waiting(&peer, "refused".into()).await.unwrap();
        assert_eq!(inner.contacts[0].state.outbox, [waiting(1, true)]);
        assert_eq!(
            inner.vault.entries.borrow()[&key].delivery(),
            Delivery::Failed
        );
        assert!(inner.vault.outbox.borrow().is_empty());
    });
}

#[test]
fn receive_failure_restores_cursor_and_delivery_receipts() {
    futures::executor::block_on(async {
        let (mut inner, _) = unlocked_client();
        let mut before: proto::SessionState = inner.contacts[0].session.state().into();
        before.cursor = 4;
        before
            .delivered
            .push(vec![2; session::protocol::mailbox::DELIVERY_TOKEN_LENGTH]);
        let session = SessionState::try_from(&before).unwrap();
        inner.contacts[0].session = Session::restore(Fetch::client(TEST_SERVER), session);
        let result = inner
            .fetch_page(0, async |session, _, _| {
                let mut advanced: proto::SessionState = session.state().into();
                advanced.cursor += 1;
                advanced.delivered.clear();
                *session = Session::restore(
                    Fetch::client(TEST_SERVER),
                    SessionState::try_from(&advanced).unwrap(),
                );
                Err::<(), _>(session::Error::from(ErrorKind::Server))
            })
            .await;
        assert!(result.is_err());
        assert_eq!(
            proto::SessionState::from(inner.contacts[0].session.state()),
            before
        );
    });
}

#[test]
fn publish_rolls_back_only_definitive_refusals_and_strict_v2_fallback() {
    use session::protocol::{Error, ErrorKind as WireError};
    let refused = PublishError::transmitted(Error::from(WireError::LimitExceeded).into(), true);
    assert!(refused.rejects_settings());
    for kind in [
        WireError::LimitExceeded,
        WireError::InvalidResponse,
        WireError::Connect,
    ] {
        let ambiguous = PublishError::transmitted(
            Error::ambiguous_response(kind, "reply unreadable").into(),
            true,
        );
        assert!(!ambiguous.rejects_settings() && !ambiguous.needs_sign_in());
    }
    assert!(
        PublishError::transmitted(Error::from(WireError::SignInRequired).into(), true)
            .needs_sign_in()
    );
    assert!(PublishError::transmitted(ErrorKind::PqRequired.into(), true).rejects_settings());
    assert!(!PublishError::transmitted(ErrorKind::PqRequired.into(), false).rejects_settings());
}

#[test]
fn refused_settings_rollback_survives_a_failed_vault_save() {
    futures::executor::block_on(async {
        let (mut inner, _) = unlocked_client();
        let previous = inner.client.pq_config().clone();
        let rejected = PqConfig {
            pq_ratchet_enabled: !previous.pq_ratchet_enabled,
            ..previous.clone()
        };
        inner.client.set_pq_config(rejected).unwrap();
        inner.state.needs_publish = true;
        inner.save(&[]).await.unwrap();
        inner.vault.fail_save.set(true);
        let warning = inner
            .rollback_pq_settings(previous.clone(), false)
            .await
            .unwrap_err();
        assert!(
            warning.contains("rollback")
                && warning.contains("will retry")
                && warning.contains("write failed")
        );
        assert_eq!(inner.client.pq_config(), &previous);
        assert!(!inner.state.needs_publish && inner.unsaved_state);
        assert!(inner.vault.state.borrow().needs_publish);
        inner.vault.fail_save.set(false);
        inner.save(&[]).await.unwrap();
        let saved = inner.vault.state.borrow();
        assert!(!saved.needs_publish && !inner.unsaved_state);
        assert_eq!(
            saved.client.as_ref().unwrap().pq_ratchet_disabled,
            !previous.pq_ratchet_enabled
        );
    });
}

#[test]
fn strict_mode_blocks_releasing_a_classical_request() {
    let mut config = PqConfig {
        strict_pq: true,
        ..Default::default()
    };
    assert!(
        super::settings::check_classical_approval(&config)
            .unwrap_err()
            .contains("strict mode")
    );
    config.strict_pq = false;
    assert!(super::settings::check_classical_approval(&config).is_ok());
}

#[test]
fn a_later_save_commits_staged_history_outbox_and_inbox_ids_together() {
    futures::executor::block_on(async {
        let (mut inner, peer) = unlocked_client();
        let record = (history_key(&peer, 0), history("greeting"));
        let outgoing = (
            outbox_key(&peer, 1),
            Some(OutgoingRecord {
                content: Kind::Text("retry".into()).to_bytes(),
                ..Default::default()
            }),
        );
        inner.state.pending_inbox_acks.push(9);
        inner.vault.fail_save.set(true);
        assert!(
            inner
                .save_inbox_changes(vec![(peer, record.clone())], vec![(peer, outgoing.clone())])
                .await
                .is_err()
        );
        assert!(inner.vault.entries.borrow().is_empty() && inner.vault.outbox.borrow().is_empty());
        assert!(inner.vault.state.borrow().pending_inbox_acks.is_empty());
        inner.vault.fail_save.set(false);
        inner.save(&[]).await.unwrap();
        assert_eq!(inner.vault.entries.borrow()[&record.0], record.1);
        assert_eq!(
            inner.vault.outbox.borrow()[&outgoing.0],
            outgoing.1.unwrap()
        );
        assert_eq!(inner.vault.state.borrow().pending_inbox_acks, [9]);
        assert!(!inner.needs_save() && inner.contacts_dirty_late);
        assert_eq!(inner.saved_late, [peer]);
    });
}
