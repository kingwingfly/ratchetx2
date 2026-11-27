#[cfg(not(target_arch = "wasm32"))]
use super::attachments::ChunkSource;
use super::attachments::{ResumeVerifier, expected_chunk_len, upload_of_with_digests};
use super::contact::{
    accept_contact_request_state, contact_state_is_new_quarantined, insert_acked_range, place_of,
    record_quarantined_initial_state, restore_contacts, stored_contacts,
};
use super::handshake::{
    DEFERRED_REPLAY_WINDOW_MS, Incoming, InitialBatch, PublishError, preserved_deferred_prekeys,
    prune_invalid_inbox_acks, refill_batch_counts, sanitize_deferred_initials,
    stage_carried_initials, stage_inbox_ack, validate_start_chat_server,
};
use super::outbox::CorruptOutboxRecovery;
use super::settings::{
    classify_set_pq_publish_result, describe_upgrade_pq_error,
    finalize_upgrade_to_pq_request_state, validate_pq_config_for_server,
};
use super::streaming::stream_mime;
use super::sync::farewell_push_v2_request;
use super::{
    EVENTS_KEPT, Engine, Inner, NAME_MAX, ONE_TIME_PREKEYS, OpenTracker, PqSaveOutcome,
    ProtocolRpcScope, REFILL_USED, SERVER_MAX_ONE_TIME_PREKEYS, Sending, StartChatError,
    VaultStore, build_invitation_link, checked_name, normalize_update_reason,
    parse_invitation_hash, same_server, sanitize_shared_name, should_require_update_for_rpc,
};
#[cfg(not(target_arch = "wasm32"))]
use super::{HISTORY_SHOWN, MAX_TEXT_BYTES, OpenOutcome};
use crate::content::{Contact as WireContact, Content, Events, Kind};
use crate::state::{Body, Delivery, Dialog, Me, Opening, ServerPqStatus, SharedContact, Step, Ui};
use crate::transport::{Connect, Fetch};
use crate::util::{hex, key_from_text, key_to_url, short, validate_relay_url};
use crate::vault::{
    AppState, Awaiting, CarriedDeferredTimestamp, ContactState, DeferredInitial, DeferredRecord,
    Farewell, HistoryEntry, Outgoing, OutgoingRecord, PendingUpload, UPLOAD_STATE_STARTED,
};
use bytes::Bytes;
use leptos::prelude::GetUntracked;
use prost::Message;
use session::protocol::{
    self, MAX_SAFE_INTEGER,
    connect::{ConnectClient, LocalPost},
    content::Hello,
    handshake_v2::InitialMessageV2 as WireInitialMessageV2,
    mailbox_v2::PushV2Request,
};
use session::{
    AcceptedInitial, Client, ClientState, ErrorKind, ListedInitialMessages, PqConfig, PqSuite,
    PublicKey, Session, SessionState, proto,
};
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
fn shared_contact_sanitizes_names_and_validates_key_length() {
    assert_eq!(sanitize_shared_name("  Alice\n\tBob\x00  "), "Alice Bob");
    assert_eq!(
        sanitize_shared_name("Alice\u{202E}boB\u{2066}x\u{2069}"),
        "AliceboBx"
    );
    // Trailing whitespace right at the `NAME_MAX` boundary is never preserved.
    let boundary = format!("{} tail", "a".repeat(NAME_MAX - 1));
    assert_eq!(sanitize_shared_name(&boundary), "a".repeat(NAME_MAX - 1));
    assert_eq!(
        sanitize_shared_name(&"😀".repeat(NAME_MAX + 5))
            .chars()
            .count(),
        NAME_MAX
    );

    let (mut inner, bob_peer) = unlocked_client();
    let carol_key = [0x99u8; 32];
    let contact = inner.contact(&bob_peer).expect("bob exists");

    let valid_entry = HistoryEntry {
        outgoing: false,
        at: 1_000,
        place: 1,
        content: Some(Content {
            clock: 1,
            kind: Some(Kind::Contact(WireContact {
                key: carol_key.to_vec(),
                name: "  Carol\nDev\x07 ".to_string(),
                pq_pinned: true,
            })),
            events: None,
        }),
        ..HistoryEntry::default()
    };
    let view = contact.message(0, valid_entry);
    assert_eq!(
        view.body,
        Body::Contact(SharedContact {
            key: carol_key,
            name: "Carol Dev".to_string(),
            pq_pinned: true,
        })
    );

    // Malformed key length (!= 32 bytes) falls back cleanly to `Body::Unknown`.
    let bad_entry = HistoryEntry {
        outgoing: false,
        at: 1_001,
        place: 2,
        content: Some(Content {
            clock: 2,
            kind: Some(Kind::Contact(WireContact {
                key: vec![0xAA; 16],
                name: "Short Key".to_string(),
                pq_pinned: false,
            })),
            events: None,
        }),
        ..HistoryEntry::default()
    };
    assert_eq!(contact.message(1, bad_entry).body, Body::Unknown);
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
        ErrorKind::ClassicalApprovalRequired,
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
        ErrorKind::ClassicalApprovalRequired,
        &unknown,
        "raw".to_string(),
    );
    assert!(
        signed_off.contains("peer has post-quantum encryption turned off"),
        "{signed_off}"
    );
    assert!(!signed_off.contains("peer_signed_off"), "{signed_off}");

    let expired =
        describe_upgrade_pq_error(ErrorKind::PeerManifestExpired, &unknown, "raw".to_string());
    assert!(expired.contains("expired"), "{expired}");

    let strict = describe_upgrade_pq_error(ErrorKind::PqRequired, &unknown, "raw".to_string());
    assert!(strict.contains("strict mode"), "{strict}");

    let downgrade =
        describe_upgrade_pq_error(ErrorKind::DowngradeDetected, &unknown, "raw".to_string());
    assert!(downgrade.contains("Downgrade detected"), "{downgrade}");

    // Genuine Connect `Unimplemented` while server PQ is NOT known disabled falls back to raw
    // error instead of falsely blaming PQ-disabled.
    let missing_rpc = describe_upgrade_pq_error(
        ErrorKind::Unimplemented,
        &unknown,
        "procedure not implemented by server".to_string(),
    );
    assert_eq!(missing_rpc, "procedure not implemented by server");
    let disabled_rpc = describe_upgrade_pq_error(
        ErrorKind::Unimplemented,
        &disabled,
        "procedure not implemented by server".to_string(),
    );
    assert!(
        disabled_rpc.contains("this server does not have post-quantum encryption enabled"),
        "{disabled_rpc}"
    );
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
        true,
        1234,
    );
    assert!(state.quarantined_session.is_some());
    assert!(state.quarantined_primary);
    assert!(contact_state_is_new_quarantined(&state));
    assert_eq!(state.quarantined_first_message, b"msg-2");
    assert!(!state.quarantined_was_pq_pinned);
    assert_eq!(state.security_alert, crate::vault::SECURITY_ALERT_DOWNGRADE);

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

type MemoryChunkKey = (PublicKey, Vec<u8>, u32);

/// In-memory [`VaultStore`] indexed directly by typed keys with deterministic fault injection.
#[derive(Default)]
struct MemoryVault {
    state: RefCell<AppState>,
    deferred: RefCell<DeferredRecord>,
    entries: RefCell<HashMap<(PublicKey, u64), HistoryEntry>>,
    files: RefCell<HashMap<(PublicKey, u64), Vec<u8>>>,
    outbox: RefCell<HashMap<(PublicKey, u64), OutgoingRecord>>,
    chunks: RefCell<HashMap<MemoryChunkKey, Vec<u8>>>,
    uploads: RefCell<HashMap<(PublicKey, Vec<u8>), PendingUpload>>,
    fail_read_at: Cell<Option<u64>>,
    corrupt_read_at: Cell<Option<u64>>,
    fail_history: Cell<bool>,
    fail_save: Cell<bool>,
    fail_put_chunk: Cell<bool>,
    fail_promote_upload: Cell<bool>,
    fail_forget: Cell<bool>,
    saved_manifest_seqs: std::rc::Rc<RefCell<Vec<u64>>>,
    save_count: std::rc::Rc<Cell<usize>>,
    on_save: RefCell<Option<Box<dyn FnMut()>>>,
}

impl MemoryVault {
    fn apply_entries<'a>(
        &self,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
    ) {
        let mut entry_map = self.entries.borrow_mut();
        let mut file_map = self.files.borrow_mut();
        for (peer, index, entry) in entries {
            let (stripped, file_data) = entry.without_file();
            if let Some(data) = file_data {
                file_map.insert((*peer, *index), data.to_vec());
            }
            entry_map.insert((*peer, *index), stripped);
        }
    }

    fn apply_outgoing<'a>(
        &self,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) {
        let mut outbox = self.outbox.borrow_mut();
        for (peer, index, record) in outgoing {
            if let Some(record) = record {
                outbox.insert((*peer, *index), record.clone());
            } else {
                outbox.remove(&(*peer, *index));
            }
        }
    }
}

impl VaultStore for MemoryVault {
    async fn entry(
        &self,
        peer: &PublicKey,
        index: u64,
    ) -> crate::vault::Result<Option<HistoryEntry>> {
        if self.fail_read_at.get() == Some(index) {
            return Err(crate::vault::Error::Storage("read failed".into()));
        }
        if self.corrupt_read_at.get() == Some(index) {
            return Err(crate::vault::Error::Corrupt(
                "corrupt history record".into(),
            ));
        }
        Ok(self.entries.borrow().get(&(*peer, index)).cloned())
    }

    async fn content(
        &self,
        peer: &PublicKey,
        index: u64,
        entry: &HistoryEntry,
    ) -> crate::vault::Result<Option<Kind>> {
        let mut kind = entry.content.as_ref().and_then(|c| c.kind.clone());
        if entry.file > 0 {
            let Some(data) = self.files.borrow().get(&(*peer, index)).cloned() else {
                return Ok(None);
            };
            match kind.as_mut() {
                Some(Kind::File(file)) => file.data = data,
                Some(Kind::Image(image)) => *image = data,
                _ => {}
            }
        }
        Ok(kind)
    }

    async fn save<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredRecord,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()> {
        if self.fail_save.get() {
            return Err(crate::vault::Error::Storage("write failed".into()));
        }
        self.save_count.set(self.save_count.get() + 1);
        if let Some(client) = state.client.as_ref() {
            self.saved_manifest_seqs
                .borrow_mut()
                .push(client.manifest_seq);
        }
        self.state.replace(state.clone());
        self.deferred.replace(deferred.clone());
        self.apply_entries(entries);
        self.apply_outgoing(outgoing);
        let callback = self.on_save.borrow_mut().take();
        if let Some(mut callback) = callback {
            callback();
        }
        Ok(())
    }

    async fn history(
        &self,
        peer: &PublicKey,
        history_len: u64,
        limit: u64,
    ) -> crate::vault::Result<Vec<(u64, HistoryEntry)>> {
        if self.fail_history.get() {
            return Err(crate::vault::Error::Storage("history read failed".into()));
        }
        if limit == 0 || history_len == 0 {
            return Ok(vec![]);
        }
        let last = history_len - 1;
        let first = history_len.saturating_sub(limit);
        let mut page: Vec<(u64, HistoryEntry)> = self
            .entries
            .borrow()
            .iter()
            .filter(|((p, idx), _)| p == peer && *idx >= first && *idx <= last)
            .map(|((_, idx), entry)| (*idx, entry.clone()))
            .collect();
        page.sort_by_key(|(idx, _)| *idx);
        Ok(page)
    }

    async fn file(&self, peer: &PublicKey, index: u64) -> crate::vault::Result<Vec<u8>> {
        self.files
            .borrow()
            .get(&(*peer, index))
            .cloned()
            .ok_or_else(|| crate::vault::Error::Corrupt("file is missing".into()))
    }

    async fn outgoing(&self, peer: &PublicKey, index: u64) -> crate::vault::Result<OutgoingRecord> {
        self.outbox
            .borrow()
            .get(&(*peer, index))
            .cloned()
            .ok_or_else(|| crate::vault::Error::Corrupt("outbox record is missing".into()))
    }

    async fn put_chunk(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
        chunk: &[u8],
    ) -> crate::vault::Result<()> {
        if self.fail_put_chunk.get() {
            return Err(crate::vault::Error::Storage("put_chunk failed".into()));
        }
        self.chunks
            .borrow_mut()
            .insert((*peer, id.to_vec(), index), chunk.to_vec());
        Ok(())
    }

    async fn chunk(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
    ) -> crate::vault::Result<Option<Vec<u8>>> {
        Ok(self
            .chunks
            .borrow()
            .get(&(*peer, id.to_vec(), index))
            .cloned())
    }

    async fn chunks_kept(&self, peer: &PublicKey, id: &[u8]) -> crate::vault::Result<u32> {
        let count = self
            .chunks
            .borrow()
            .keys()
            .filter(|(p, i, _)| p == peer && i.as_slice() == id)
            .count();
        Ok(count as u32)
    }

    async fn save_upload(
        &self,
        peer: &PublicKey,
        upload: &PendingUpload,
    ) -> crate::vault::Result<()> {
        if self.fail_save.get() {
            return Err(crate::vault::Error::Storage("save_upload failed".into()));
        }
        self.uploads
            .borrow_mut()
            .insert((*peer, upload.id.clone()), upload.clone());
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn promote_upload<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredRecord,
        peer: &PublicKey,
        old_id: &[u8],
        new_upload: &PendingUpload,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()> {
        if self.fail_promote_upload.get() || self.fail_save.get() {
            return Err(crate::vault::Error::Storage("promote_upload failed".into()));
        }
        {
            let mut uploads = self.uploads.borrow_mut();
            uploads.remove(&(*peer, old_id.to_vec()));
            uploads.insert((*peer, new_upload.id.clone()), new_upload.clone());
        }
        self.state.replace(state.clone());
        self.deferred.replace(deferred.clone());
        self.apply_entries(entries);
        self.apply_outgoing(outgoing);
        let callback = self.on_save.borrow_mut().take();
        if let Some(mut callback) = callback {
            callback();
        }
        Ok(())
    }

    async fn forget_upload(&self, peer: &PublicKey, id: &[u8]) -> crate::vault::Result<()> {
        if self.fail_save.get() {
            return Err(crate::vault::Error::Storage("forget_upload failed".into()));
        }
        self.uploads.borrow_mut().remove(&(*peer, id.to_vec()));
        Ok(())
    }

    async fn upload(
        &self,
        peer: &PublicKey,
        id: &[u8],
    ) -> crate::vault::Result<Option<PendingUpload>> {
        Ok(self.uploads.borrow().get(&(*peer, id.to_vec())).cloned())
    }

    async fn uploads(
        &self,
        peer: Option<&PublicKey>,
    ) -> crate::vault::Result<Vec<(PublicKey, PendingUpload)>> {
        Ok(self
            .uploads
            .borrow()
            .iter()
            .filter(|((p, _), _)| peer.is_none_or(|target| target == p))
            .map(|((p, _), upload)| (*p, upload.clone()))
            .collect())
    }

    async fn forget<'a>(
        &self,
        state: &AppState,
        deferred: &DeferredRecord,
        peer: &PublicKey,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()> {
        if self.fail_forget.get() || self.fail_save.get() {
            return Err(crate::vault::Error::Storage("forget failed".into()));
        }
        self.save_count.set(self.save_count.get() + 1);
        self.entries.borrow_mut().retain(|(p, _), _| p != peer);
        self.files.borrow_mut().retain(|(p, _), _| p != peer);
        self.outbox.borrow_mut().retain(|(p, _), _| p != peer);
        self.chunks.borrow_mut().retain(|(p, _, _), _| p != peer);
        self.uploads.borrow_mut().retain(|(p, _), _| p != peer);
        self.state.replace(state.clone());
        self.deferred.replace(deferred.clone());
        self.apply_entries(entries);
        self.apply_outgoing(outgoing);
        let callback = self.on_save.borrow_mut().take();
        if let Some(mut callback) = callback {
            callback();
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

/// Reopen only the committed vault bytes, discarding all transient engine state.
fn reload(vault: MemoryVault) -> Inner<MemoryVault> {
    let mut state = AppState::decode(vault.state.borrow().encode_to_vec().as_slice()).unwrap();
    let mut deferred =
        DeferredRecord::decode(vault.deferred.borrow().encode_to_vec().as_slice()).unwrap();
    let client = Client::restore(
        Fetch::client(TEST_SERVER),
        ClientState::try_from(&state.client.take().unwrap()).unwrap(),
    );
    let (contacts, isolated, _) = restore_contacts(
        std::mem::take(&mut state.contacts),
        &client.identity_key(),
        TEST_SERVER,
    );
    let _ = sanitize_deferred_initials(&mut deferred.entries, crate::util::now());
    Inner::new(
        vault,
        TEST_SERVER.into(),
        "chat.example".into(),
        state,
        client,
        contacts,
        isolated,
        deferred,
    )
}

fn load_contacts(client: &Client<Connect>, contacts: Vec<ContactState>) -> Inner<MemoryVault> {
    reload(MemoryVault {
        state: RefCell::new(AppState {
            client: Some(client.state().into()),
            contacts,
            ..Default::default()
        }),
        ..Default::default()
    })
}

struct BundleResponse<T>(&'static str, T);

impl<T: Message> LocalPost for BundleResponse<T> {
    async fn post(&self, path: &str, _: Vec<u8>) -> protocol::Result<(u16, Vec<u8>)> {
        assert!(path.ends_with(self.0));
        Ok((200, self.1.encode_to_vec()))
    }
}

/// Encrypt a real first message for the recipient using the v2 wire format (PQXDH when ML-KEM
/// suites are compiled in, or classical X3DH over v2 in classical-only builds).
async fn carried_initial(recipient: &mut Client<Connect>) -> (PublicKey, Incoming) {
    let greeting = Kind::Text("first message".into()).to_bytes();
    let published = recipient.prepare_publish_v2("chat.example", 1, 1).unwrap();
    let p = &published.request;
    let bundle = protocol::handshake_v2::ClaimBundleResponse {
        signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
        signed_prekey_signature: p.signed_prekey_signature.clone(),
        one_time_prekey: p.one_time_prekeys.first().cloned(),
        pq_last_resort: p.pq_last_resort.first().cloned(),
        pq_one_time_prekey: p.pq_one_time_prekeys.first().cloned(),
        manifest: p.manifest.clone(),
    };
    recipient.commit_publish_v2(published);
    let mut sender = Client::new(ConnectClient::new(BundleResponse("/ClaimBundle", bundle)));
    let prepared = sender
        .prepare_initiate_v2(
            "chat.example",
            &recipient.identity_key(),
            &Default::default(),
            &greeting,
            (),
        )
        .await
        .unwrap();
    assert_eq!(
        prepared.security.is_pq,
        cfg!(any(feature = "ml-kem-1024", feature = "ml-kem-768"))
    );
    (
        sender.identity_key(),
        Incoming::try_from(prepared.request.message.as_ref().unwrap()).unwrap(),
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn change_session(session: &mut Session<Connect>, change: impl FnOnce(&mut proto::SessionState)) {
    let mut stored = proto::SessionState::from(session.state());
    change(&mut stored);
    *session = Session::restore(
        Fetch::client(TEST_SERVER),
        SessionState::try_from(&stored).unwrap(),
    );
}

fn unlocked_client() -> (Inner<MemoryVault>, PublicKey) {
    let client = Client::new(Fetch::client(TEST_SERVER));
    let me = client.identity_key();
    let peer = identity();
    let (contacts, isolated, warnings) =
        restore_contacts(vec![stored_contact(me, peer)], &me, TEST_SERVER);
    assert!(warnings.is_empty());
    (
        Inner::new(
            MemoryVault::default(),
            TEST_SERVER.into(),
            "chat.example".into(),
            AppState::default(),
            client,
            contacts,
            isolated,
            DeferredRecord::default(),
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
    corrupt.session.as_mut().unwrap().me.pop();
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
fn isolated_peer_blocks_both_handshake_directions_until_forgotten() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let mut client = Client::new(Fetch::client(TEST_SERVER));
        let (peer, message) = carried_initial(&mut client).await;
        let mut corrupt = stored_contact(client.identity_key(), peer);
        corrupt.name = "Pinned Peer".into();
        corrupt.session.as_mut().unwrap().me.pop();
        let missing_session = ContactState {
            peer: peer.to_vec(),
            ..Default::default()
        };
        let original = vec![corrupt, missing_session];
        let mut inner = load_contacts(&client, original.clone());
        assert!(inner.is_isolated_peer(&peer));
        let views = inner.isolated_views();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].peer, Some(peer));
        assert!(views[0].label.contains("Pinned Peer") && views[0].label.contains(&short(&peer)));
        assert!(views[0].pq_pinned);
        assert_eq!(views[0].records, 2);
        assert!(
            matches!(inner.check_outgoing_peer(&peer), Err(super::StartChatError::Other(reason)) if reason.contains("isolated"))
        );
        let prekeys = proto::ClientState::from(inner.client.state());
        engine.process_initial(&mut inner, &peer, &message, &mut InitialBatch::default());
        assert!(
            engine
                .join_carried(&mut inner, &peer)
                .await
                .unwrap_err()
                .contains("isolated")
        );
        assert!(inner.contacts.is_empty());
        assert_eq!(proto::ClientState::from(inner.client.state()), prekeys);
        assert_eq!(inner.state.used_one_time_prekeys, 0);
        assert_eq!(inner.isolated_contacts, original);
        assert_eq!(
            stored_contacts(&inner.contacts, &inner.isolated_contacts),
            original
        );
        inner.save(&[]).await.unwrap();
        let mut inner = reload(inner.vault);
        assert!(inner.is_isolated_peer(&peer));
        assert_eq!(inner.isolated_views().len(), 1);
        assert!(
            inner.isolated_contacts[0]
                .session
                .as_ref()
                .unwrap()
                .peer_pq
                .as_ref()
                .unwrap()
                .pq_pinned
        );

        inner.forget_isolated_peer(&peer);
        assert!(inner.isolated_contacts.is_empty());
        assert!(inner.isolated_views().is_empty());
        assert!(inner.check_outgoing_peer(&peer).is_ok());
        engine.process_initial(&mut inner, &peer, &message, &mut InitialBatch::default());
        assert_eq!(inner.contacts.len(), 1);
        assert_eq!(inner.contacts[0].state.history_len, 1);
        assert_eq!(inner.state.used_one_time_prekeys, 1);
    });
}

#[test]
fn corrupt_duplicate_before_healthy_row_keeps_healthy_contact_active() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let mut client = Client::new(Fetch::client(TEST_SERVER));
        let (peer, message) = carried_initial(&mut client).await;
        let mut healthy = stored_contact(client.identity_key(), peer);
        healthy.name = "Alice".into();
        healthy.history_len = 5;
        let mut corrupt = healthy.clone();
        corrupt.name = "Corrupt Duplicate".into();
        corrupt.session.as_mut().unwrap().me.pop();

        // Direct restore_contacts check: [corrupt_row(peer), healthy_row(peer)] keeps healthy active.
        let (contacts, isolated, warnings) = restore_contacts(
            vec![corrupt.clone(), healthy.clone()],
            &client.identity_key(),
            TEST_SERVER,
        );
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].peer, peer);
        assert_eq!(contacts[0].state.name, "Alice");
        assert_eq!(contacts[0].state.history_len, 5);
        assert!(contacts[0].session.peer_pq_state().pq_pinned);
        assert_eq!(isolated, vec![corrupt.clone()]);
        assert_eq!(warnings.len(), 1);

        // Full Inner load drops the superseded corrupt duplicate without isolating `peer`.
        let mut inner = load_contacts(&client, vec![corrupt, healthy]);
        assert!(!inner.is_isolated_peer(&peer));
        assert!(inner.isolated_contacts.is_empty());
        assert!(inner.isolated_views().is_empty());
        assert_eq!(inner.contacts.len(), 1);
        assert_eq!(inner.contacts[0].state.name, "Alice");
        assert_eq!(inner.contacts[0].state.history_len, 5);
        assert!(inner.contacts[0].session.peer_pq_state().pq_pinned);
        assert!(inner.check_outgoing_peer(&peer).is_ok());

        // Saving and reloading retains only the healthy contact and keeps it usable.
        inner.save(&[]).await.unwrap();
        let mut inner = reload(inner.vault);
        assert!(!inner.is_isolated_peer(&peer));
        assert!(inner.isolated_contacts.is_empty());
        assert_eq!(inner.contacts.len(), 1);
        assert_eq!(inner.contacts[0].state.name, "Alice");
        assert_eq!(inner.contacts[0].state.history_len, 5);
        let mut batch = InitialBatch::default();
        engine.process_initial(&mut inner, &peer, &message, &mut batch);
        assert_eq!(inner.contacts[0].state.name, "Alice");
        assert!(inner.contacts[0].session.peer_pq_state().pq_pinned);
    });
}

#[test]
fn delete_isolated_raw_removes_malformed_key_record_atomically() {
    futures::executor::block_on(async {
        let client = Client::new(Fetch::client(TEST_SERVER));
        let me = client.identity_key();
        let valid_peer = identity();
        let mut valid_corrupt = stored_contact(me, valid_peer);
        valid_corrupt.session.as_mut().unwrap().me.pop();
        let mut bad_key = stored_contact(me, identity());
        bad_key.peer.pop();
        bad_key.name = "broken tablet".into();
        let bad_bytes = bad_key.peer.clone();

        let mut inner = load_contacts(&client, vec![bad_key.clone(), valid_corrupt.clone()]);
        let views = inner.isolated_views();
        assert_eq!(views.len(), 2);
        assert!(views[0].peer.is_none());
        assert!(views[0].label.contains("broken tablet"));
        assert_eq!(views[1].peer, Some(valid_peer));

        // Failed save rolls back in-memory removal cleanly.
        inner.vault.fail_save.set(true);
        assert!(inner.delete_isolated_raw(&bad_bytes).await.is_err());
        assert_eq!(inner.isolated_contacts.len(), 2);

        // Successful save removes only the malformed-key record and preserves the other peer.
        inner.vault.fail_save.set(false);
        assert_eq!(inner.delete_isolated_raw(&bad_bytes).await, Ok(true));
        assert_eq!(inner.delete_isolated_raw(&bad_bytes).await, Ok(false));
        let reloaded = reload(inner.vault);
        assert_eq!(reloaded.isolated_contacts, vec![valid_corrupt]);
        assert!(reloaded.is_isolated_peer(&valid_peer));
        assert_eq!(reloaded.isolated_views().len(), 1);
    });
}

#[test]
fn invalid_history_counters_and_references_are_isolated_verbatim() {
    let me = identity();
    let mut invalid = vec![
        ContactState {
            history_len: u64::MAX,
            ..stored_contact(me, identity())
        },
        ContactState {
            history_len: MAX_SAFE_INTEGER + 1,
            ..stored_contact(me, identity())
        },
        ContactState {
            history_len: 1,
            unread: 2,
            ..stored_contact(me, identity())
        },
        ContactState {
            history_len: 1,
            outbox: vec![waiting(1, true)],
            ..stored_contact(me, identity())
        },
        ContactState {
            history_len: 3,
            awaiting: vec![Awaiting {
                history_index: 3,
                ..Default::default()
            }],
            ..stored_contact(me, identity())
        },
    ];
    let original = invalid.clone();
    let healthy = ContactState {
        history_len: MAX_SAFE_INTEGER,
        unread: u32::MAX,
        outbox: vec![waiting(MAX_SAFE_INTEGER - 1, false)],
        ..stored_contact(me, identity())
    };
    invalid.push(healthy.clone());
    let (contacts, isolated, warnings) = restore_contacts(invalid, &me, TEST_SERVER);
    assert_eq!(warnings.len(), original.len());
    assert_eq!(isolated, original);
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].state.peer, healthy.peer);
    assert_eq!(&stored_contacts(&contacts, &isolated)[1..], original);
}

#[test]
fn full_history_refuses_all_allocations_before_any_contact_change() {
    let (mut inner, _) = unlocked_client();
    let contact = &mut inner.contacts[0];
    let message = Content {
        clock: 7,
        kind: Some(Kind::Text("hello".into())),
        events: None,
    };
    contact.state.unread = u32::MAX;
    contact.state.history_len = MAX_SAFE_INTEGER - 1;
    let (index, _) = contact.add_received(message.clone(), false).unwrap();
    assert_eq!(index, MAX_SAFE_INTEGER - 1);
    assert_eq!(contact.state.unread, u32::MAX);
    for full in [MAX_SAFE_INTEGER, u64::MAX] {
        contact.state.history_len = full;
        let before = contact.snapshot();
        assert!(contact.next_history_index().is_err());
        assert!(contact.add_received(message.clone(), false).is_err());
        assert!(contact.add_evicted().is_err());
        assert_eq!(contact.snapshot(), before);
    }
}

#[test]
fn ack_ids_must_fit_the_signed_wire_range_and_remain_in_order() {
    let mut pending = vec![];
    for id in [0, MAX_SAFE_INTEGER + 1, u64::MAX] {
        assert!(!stage_inbox_ack(&mut pending, id));
    }
    assert!(stage_inbox_ack(&mut pending, 1));
    assert!(stage_inbox_ack(&mut pending, MAX_SAFE_INTEGER));
    pending.extend([0, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER + 1, 4, u64::MAX, 1]);
    assert_eq!(prune_invalid_inbox_acks(&mut pending), 5);
    assert_eq!(pending, [1, MAX_SAFE_INTEGER, 4]);
    assert_eq!(prune_invalid_inbox_acks(&mut pending), 0);
}

#[test]
fn invalid_persisted_ids_are_cleaned_before_contacting_the_inbox() {
    futures::executor::block_on(async {
        let (mut inner, _) = unlocked_client();
        inner.state.pending_inbox_acks = vec![9, u64::MAX, 0, 9, MAX_SAFE_INTEGER];
        inner.save(&[]).await.unwrap();
        let mut inner = reload(inner.vault);
        inner.vault.fail_save.set(true);
        assert!(
            inner
                .ack_persisted_inbox(async |_, _, _| panic!("cleanup was not saved"))
                .await
                .is_err()
        );
        assert!(inner.unsaved_state);
        assert_eq!(inner.vault.state.borrow().pending_inbox_acks.len(), 5);
        inner.vault.fail_save.set(false);
        // Simulate closing the tab before the retry. The next ack must repair the old disk state.
        let mut inner = reload(inner.vault);
        let mut sent = vec![];
        inner
            .ack_persisted_inbox(async |_, _, ids| {
                sent.extend(ids);
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(sent, [9, MAX_SAFE_INTEGER]);
        assert!(inner.vault.state.borrow().pending_inbox_acks.is_empty());
    });
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
    use session::protocol::handshake_v2::ClaimBundleResponse;

    futures::executor::block_on(async {
        let classical_cfg = PqConfig {
            pq_enabled: false,
            pq_ratchet_enabled: false,
            strict_pq: false,
            ..PqConfig::default()
        };
        let mut bob = Client::new(Fetch::client(TEST_SERVER));
        bob.set_pq_config(classical_cfg.clone()).unwrap();
        let published = bob.prepare_publish_v2("chat.example", 1, 0).unwrap();
        let p = &published.request;
        let bundle = ClaimBundleResponse {
            signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: p.signed_prekey_signature.clone(),
            one_time_prekey: p.one_time_prekeys.first().cloned(),
            pq_last_resort: None,
            pq_one_time_prekey: None,
            manifest: p.manifest.clone(),
        };
        bob.commit_publish_v2(published);
        let mut alice = Client::new(ConnectClient::new(BundleResponse("/ClaimBundle", bundle)));
        alice.set_pq_config(classical_cfg).unwrap();
        let initiation = alice
            .prepare_initiate_v2(
                "chat.example",
                &bob.identity_key(),
                &Default::default(),
                b"hello",
                (),
            )
            .await
            .unwrap();
        assert!(!initiation.security.is_pq);
        let message = Incoming::try_from(initiation.request.message.as_ref().unwrap()).unwrap();
        let AcceptedInitial::Accepted {
            session: incoming, ..
        } = bob
            .accept_initial_v2(
                &alice.identity_key(),
                &Default::default(),
                &message,
                Fetch::client(TEST_SERVER),
            )
            .unwrap()
        else {
            panic!("expected classical initial accepted when local PQ is off");
        };
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
        let first = history("keep me");
        let first_digest = crate::vault::content_kind_digest(
            &first
                .content
                .as_ref()
                .unwrap()
                .kind
                .as_ref()
                .unwrap()
                .to_bytes(),
        );
        let mut waiting0_sealed = waiting(0, true);
        waiting0_sealed.content_digest = first_digest.clone();
        let mut waiting0_unsealed = waiting(0, false);
        waiting0_unsealed.content_digest = first_digest;
        inner.contacts[0].state.outbox = vec![
            waiting0_sealed,
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
        inner.vault.entries.borrow_mut().extend([
            ((peer, 0), first.clone()),
            (
                (peer, 2),
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
            inner.vault.entries.borrow()[&(peer, 2)].delivery(),
            Delivery::Failed
        );
        assert_eq!(
            inner.contacts[0].state.outbox,
            [waiting0_unsealed.clone(), waiting(3, false)]
        );
        assert!(!inner.contacts[0].state.needs_requeue_sealed);
        assert_eq!(
            outcome.outbox,
            [
                (
                    peer,
                    0,
                    Some(OutgoingRecord::unsealed(
                        first.content.unwrap().kind.unwrap().to_bytes(),
                    )),
                ),
                (peer, 1, None),
                (peer, 2, None),
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
        assert_eq!(outcome.outbox, [(peer, 2, None)]);
        assert_eq!(outcome.history[0].1.delivery(), Delivery::Failed);
        assert!(inner.contacts[0].state.awaiting.is_empty());
        assert_eq!(
            inner.contacts[0].state.outbox,
            [waiting0_unsealed, waiting(3, false)]
        );
    });
}

#[test]
fn fail_waiting_preserves_queue_on_read_or_commit_failure() {
    futures::executor::block_on(async {
        let (mut inner, peer) = unlocked_client();
        let outbox = vec![waiting(0, false), waiting(1, true)];
        inner.contacts[0].state.outbox = outbox.clone();
        let key = (peer, 0);
        inner
            .vault
            .entries
            .borrow_mut()
            .insert(key, history("queued"));
        inner
            .save_with(&[], &[(peer, 0, Some(OutgoingRecord::default()))])
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
        assert!(inner.vault.outbox.borrow().contains_key(&(peer, 0)));
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
fn carried_initial_survives_a_failed_join_and_reload() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let mut client = Client::new(Fetch::client(TEST_SERVER));
        let (peer, initial) = carried_initial(&mut client).await;
        let mut inner = load_contacts(&client, vec![stored_contact(client.identity_key(), peer)]);
        let initials = [initial.clone(), initial];
        stage_carried_initials(&mut inner.contacts[0].state, initials.iter()).unwrap();
        inner.save(&[]).await.unwrap();

        let mut inner = reload(inner.vault);
        let pending = inner.contacts[0].state.pending_carried_initials.clone();
        assert_eq!(pending.len(), 1);
        assert_eq!(inner.client.current_one_time_count(), 1);
        assert!(inner.contacts[0].session.active_id().is_none());

        inner.vault.fail_save.set(true);
        assert!(engine.join_carried(&mut inner, &peer).await.is_err());
        assert!(inner.unsaved_state);
        assert_eq!(inner.unsaved.len(), 1);
        assert_eq!(inner.client.current_one_time_count(), 0);
        assert!(inner.contacts[0].state.pending_carried_initials.is_empty());
        assert!(inner.vault.entries.borrow().is_empty());
        let disk = inner.vault.state.borrow().clone();
        assert_eq!(disk.contacts[0].pending_carried_initials, pending);
        assert_eq!(disk.contacts[0].history_len, 0);
        assert_eq!(disk.used_one_time_prekeys, 0);
        assert_eq!(
            disk.client.as_ref().unwrap(),
            &proto::ClientState::from(client.state())
        );

        // Retry both ways: keeping the consumed prekeys in memory, or restarting from disk.
        let restarted = reload(MemoryVault {
            state: RefCell::new(disk),
            ..Default::default()
        });
        for mut recovered in [inner, restarted] {
            recovered.vault.fail_save.set(false);
            engine.join_carried(&mut recovered, &peer).await.unwrap();
            let saved = recovered.vault.state.borrow();
            assert_eq!(saved.contacts[0].history_len, 1);
            assert!(saved.contacts[0].pending_carried_initials.is_empty());
            let session = saved.contacts[0].session.as_ref().unwrap();
            assert!(session.party.is_some());
            assert_eq!(saved.used_one_time_prekeys, 1);
            assert_eq!(
                saved.used_pq_one_time_prekeys,
                u32::from(cfg!(any(feature = "ml-kem-1024", feature = "ml-kem-768")))
            );
            assert!(!recovered.needs_save());
            let history = recovered.vault.entries.borrow();
            assert_eq!(history.len(), 1);
            assert_eq!(
                history[&(peer, 0)].content.as_ref().unwrap().kind,
                Some(Kind::Text("first message".into()))
            );
        }
    });
}

fn classical_wire_initial(ephemeral: u8) -> WireInitialMessageV2 {
    WireInitialMessageV2 {
        version: 1,
        identity_key: vec![1; 32].into(),
        ephemeral_key: vec![ephemeral; 32].into(),
        signed_prekey: vec![2; 32].into(),
        first_message: Some(Default::default()),
        ..Default::default()
    }
}

#[test]
fn staging_bounds_distinct_carried_initials_and_encodes_wire_bytes() {
    let mut state = ContactState::default();
    for i in 0..=128 {
        let wire = classical_wire_initial(i);
        let initial = Incoming::try_from(&wire).unwrap();
        let staged = stage_carried_initials(&mut state, [&initial, &initial]);
        if i < 128 {
            staged.unwrap();
            assert_eq!(
                state.pending_carried_initials[usize::from(i)],
                protocol::mailbox_v2::encode_carried_initial(&wire)
                    .unwrap()
                    .to_vec()
            );
        } else {
            assert!(staged.is_err());
        }
    }
    assert_eq!(state.pending_carried_initials.len(), 128);
}

#[test]
fn unreadable_or_rejected_carried_initial_is_removed_only_by_a_successful_state_save() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let invalid_classical =
            protocol::mailbox_v2::encode_carried_initial(&classical_wire_initial(3))
                .unwrap()
                .to_vec();
        for bytes in [vec![0xff], invalid_classical] {
            let (mut inner, peer) = unlocked_client();
            let before = inner.contacts[0].snapshot();
            let invalid = vec![bytes];
            inner.contacts[0]
                .state
                .pending_carried_initials
                .clone_from(&invalid);
            inner.save(&[]).await.unwrap();
            inner.vault.fail_save.set(true);
            assert!(engine.join_carried(&mut inner, &peer).await.is_err());
            assert_eq!(inner.contacts[0].state.pending_carried_initials, invalid);
            assert_eq!(
                inner.vault.state.borrow().contacts[0].pending_carried_initials,
                invalid
            );
            inner.vault.fail_save.set(false);
            engine.join_carried(&mut inner, &peer).await.unwrap();
            assert!(
                inner.vault.state.borrow().contacts[0]
                    .pending_carried_initials
                    .is_empty()
            );
            assert_eq!(inner.contacts[0].snapshot(), before);
            assert_eq!(inner.state.used_one_time_prekeys, 0);
            assert!(inner.vault.entries.borrow().is_empty());
        }
    });
}

#[test]
fn publish_rolls_back_only_definitive_refusals_and_strict_v2_fallback() {
    use session::protocol::{Error, ErrorKind as WireError};
    let refused = PublishError::transmitted(Error::from(WireError::LimitExceeded).into());
    assert!(refused.rejects_settings());
    assert!(PublishError::transmitted(Error::from(WireError::Malformed).into()).rejects_settings());
    for kind in [WireError::StaleTimestamp, WireError::InvalidSignature] {
        assert!(!PublishError::transmitted(Error::from(kind).into()).rejects_settings());
    }
    for kind in [
        WireError::Malformed,
        WireError::LimitExceeded,
        WireError::InvalidResponse,
        WireError::Connect,
    ] {
        let ambiguous =
            PublishError::transmitted(Error::ambiguous_response(kind, "reply unreadable").into());
        assert!(
            !ambiguous.rejects_settings()
                && !ambiguous.needs_sign_in()
                && !ambiguous.is_unimplemented()
        );
    }
    assert!(
        PublishError::transmitted(Error::from(WireError::SignInRequired).into()).needs_sign_in()
    );
    assert!(PublishError::transmitted(ErrorKind::PqRequired.into()).rejects_settings());
    let unimplemented = PublishError::transmitted(Error::from(WireError::Unimplemented).into());
    assert!(unimplemented.is_unimplemented());
    assert!(!unimplemented.rejects_settings());
    assert!(!unimplemented.needs_sign_in());
}

#[test]
fn offered_suites_must_all_be_supported_by_the_relay() {
    let config = PqConfig {
        pq_enabled: true,
        ..Default::default()
    };
    let enabled = |suites| ServerPqStatus::Enabled {
        suites,
        pq_ratchet: true,
    };
    let all = vec![PqSuite::MlKem1024, PqSuite::MlKem768];
    assert!(validate_pq_config_for_server(&config, &enabled(all.clone())).is_ok());
    let empty = enabled(vec![]);
    assert!(validate_pq_config_for_server(&config, &empty).is_err());
    for offered in config.offered_suites() {
        let other = all.iter().copied().filter(|s| *s != offered).collect();
        let reason = validate_pq_config_for_server(&config, &enabled(other)).unwrap_err();
        assert!(reason.contains(offered.label()));
    }
    let strict = PqConfig {
        strict_pq: true,
        ..config.clone()
    };
    assert!(validate_pq_config_for_server(&strict, &ServerPqStatus::Disabled).is_err());
    let off = PqConfig {
        pq_enabled: false,
        ..config
    };
    for server in [empty, enabled(all), ServerPqStatus::Disabled] {
        assert!(validate_pq_config_for_server(&off, &server).is_ok());
    }
}

#[test]
fn refused_settings_rollback_survives_a_failed_vault_save() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let (mut inner, _) = unlocked_client();
        let previous = inner.client.pq_config().clone();
        let rejected = PqConfig {
            pq_ratchet_enabled: !previous.pq_ratchet_enabled,
            ..previous.clone()
        };
        inner.save_pq_config(rejected).await.unwrap();
        inner.vault.fail_save.set(true);
        let refusal =
            PublishError::transmitted(protocol::Error::from(protocol::ErrorKind::Malformed).into());
        let warning = engine
            .finish_publish_rollback(&mut inner, refusal, false)
            .await
            .unwrap_err()
            .message;
        assert!(
            warning.contains("rollback")
                && warning.contains("will retry")
                && warning.contains("write failed")
        );
        assert_eq!(inner.client.pq_config(), &previous);
        assert_eq!(engine.ui.me.get_untracked().unwrap().pq_config, previous);
        assert!(
            engine
                .ui
                .log
                .get_untracked()
                .iter()
                .any(|(_, line)| line.contains("refused") && line.contains("Restored"))
        );
        assert!(!inner.state.needs_publish && inner.unsaved_state);
        assert!(inner.state.pending_pq_rollback.is_none());
        assert!(inner.vault.state.borrow().pending_pq_rollback.is_some());
        assert!(inner.vault.state.borrow().needs_publish);
        inner.vault.fail_save.set(false);
        inner.save(&[]).await.unwrap();
        let saved = inner.vault.state.borrow();
        assert!(!saved.needs_publish && !inner.unsaved_state);
        assert!(saved.pending_pq_rollback.is_none());
        assert_eq!(
            saved.client.as_ref().unwrap().pq_ratchet_disabled,
            !previous.pq_ratchet_enabled
        );
    });
}

#[test]
fn offline_edits_keep_the_original_rollback_across_reload_until_publication() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let (mut inner, _) = unlocked_client();
        // A scheduled key rotation already needed publication before the user edited settings.
        inner.state.needs_publish = true;
        inner.save(&[]).await.unwrap();
        let accepted = inner.client.pq_config().clone();
        let first = PqConfig {
            pq_ratchet_enabled: !accepted.pq_ratchet_enabled,
            ..accepted.clone()
        };
        let last = PqConfig {
            pq_enabled: false,
            preferred_suite: PqSuite::MlKem768,
            ..accepted.clone()
        };
        inner.vault.fail_save.set(true);
        assert!(inner.save_pq_config(first.clone()).await.is_err());
        assert_eq!(inner.client.pq_config(), &accepted);
        assert!(inner.state.pending_pq_rollback.is_none());
        inner.vault.fail_save.set(false);
        inner.save_pq_config(first.clone()).await.unwrap();
        let rollback = inner.state.pending_pq_rollback.clone().unwrap();
        assert_eq!(rollback.config(), accepted);
        assert!(rollback.previous_needs_publish);
        let mut invalid_suite = rollback.clone();
        invalid_suite.preferred_suite = u32::MAX;
        assert_eq!(
            invalid_suite.config().preferred_suite,
            PqConfig::default_suite()
        );

        inner.vault.fail_save.set(true);
        assert!(inner.save_pq_config(last.clone()).await.is_err());
        assert_eq!(inner.client.pq_config(), &first);
        assert_eq!(inner.state.pending_pq_rollback.as_ref(), Some(&rollback));
        inner.vault.fail_save.set(false);
        inner.save_pq_config(last.clone()).await.unwrap();
        let sign_in = PublishError::transmitted(
            protocol::Error::from(protocol::ErrorKind::SignInRequired).into(),
        );
        assert!(
            engine
                .finish_publish_rollback(&mut inner, sign_in, true)
                .await
                .unwrap_err()
                .needs_sign_in()
        );
        let mut inner = reload(inner.vault);
        assert_eq!(inner.client.pq_config(), &last);
        assert_eq!(inner.state.pending_pq_rollback.as_ref(), Some(&rollback));

        let refused =
            PublishError::transmitted(protocol::Error::from(protocol::ErrorKind::Malformed).into());
        assert!(
            engine
                .finish_publish_rollback(&mut inner, refused, false)
                .await
                .unwrap_err()
                .rejects_settings()
        );
        let mut inner = reload(inner.vault);
        assert_eq!(inner.client.pq_config(), &accepted);
        assert!(inner.state.needs_publish);
        assert!(inner.state.pending_pq_rollback.is_none());

        inner.save_pq_config(last.clone()).await.unwrap();
        inner.save_full_publish_success(0).await.unwrap();
        let inner = reload(inner.vault);
        assert_eq!(inner.client.pq_config(), &last);
        assert!(!inner.state.needs_publish);
        assert!(inner.state.pending_pq_rollback.is_none());
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
        let record = (peer, 0, history("greeting"));
        let outgoing = (
            peer,
            1,
            Some(OutgoingRecord::unsealed(
                Kind::Text("retry".into()).to_bytes(),
            )),
        );
        inner.state.pending_inbox_acks.push(9);
        inner.vault.fail_save.set(true);
        assert!(
            inner
                .save_inbox_changes(vec![record.clone()], vec![outgoing.clone()])
                .await
                .is_err()
        );
        assert!(inner.vault.entries.borrow().is_empty() && inner.vault.outbox.borrow().is_empty());
        assert!(inner.vault.state.borrow().pending_inbox_acks.is_empty());
        inner.vault.fail_save.set(false);
        inner.save(&[]).await.unwrap();
        assert_eq!(inner.vault.entries.borrow()[&(peer, 0)], record.2);
        assert_eq!(inner.vault.outbox.borrow()[&(peer, 1)], outgoing.2.unwrap());
        assert_eq!(inner.vault.state.borrow().pending_inbox_acks, [9]);
        assert!(!inner.needs_save() && inner.contacts_dirty_late);
        assert_eq!(inner.saved_late, [peer]);
    });
}

#[test]
fn refused_publish_without_rollback_clears_needs_publish_and_pauses_retries() {
    futures::executor::block_on(async {
        // 1. Upgraded vault already has `needs_publish = true` with `pending_pq_rollback = None`.
        let engine = Engine::new(Ui::new());
        let (mut inner, _) = unlocked_client();
        inner.state.published_at = 1_700_000_000_000;
        inner.state.needs_publish = true;
        inner.state.pending_pq_rollback = None;
        inner.save(&[]).await.unwrap();

        let refusal =
            PublishError::transmitted(protocol::Error::from(protocol::ErrorKind::Malformed).into());
        let err = engine
            .finish_publish_rollback(&mut inner, refusal, false)
            .await
            .unwrap_err();
        assert!(err.rejects_settings());
        assert!(err.message.contains("Settings"));
        assert!(!inner.state.needs_publish);
        assert!(engine.startup.publish_waits_settings());
        assert!(
            engine
                .ui
                .log
                .get_untracked()
                .iter()
                .any(|(_, line)| line.contains("Settings") && line.contains("paused"))
        );
        assert!(
            engine
                .ui
                .notice
                .get_untracked()
                .is_some_and(|(_, text)| text.contains("Settings"))
        );

        // Cleared `needs_publish = false` persists cleanly across reload.
        let mut reloaded = reload(inner.vault);
        assert!(!reloaded.state.needs_publish);
        assert!(reloaded.state.pending_pq_rollback.is_none());

        // 2. Strict PQ refusal (`PqRequired`) without rollback also marks server PQ disabled and
        //    survives a transient vault save failure.
        reloaded.state.needs_publish = true;
        reloaded.save(&[]).await.unwrap();
        reloaded.vault.fail_save.set(true);
        let engine2 = Engine::new(Ui::new());
        let strict_refusal = PublishError::transmitted(ErrorKind::PqRequired.into());
        let err = engine2
            .finish_publish_rollback(&mut reloaded, strict_refusal, true)
            .await
            .unwrap_err();
        assert!(err.message.contains("Settings") && err.message.contains("will retry"));
        assert!(!reloaded.state.needs_publish);
        assert!(reloaded.unsaved_state);
        assert!(engine2.startup.publish_waits_settings());
        assert_eq!(reloaded.server_pq, ServerPqStatus::Disabled);
        assert_eq!(
            engine2.ui.me.get_untracked().unwrap().server_pq,
            ServerPqStatus::Disabled
        );
        // Persisting after storage recovers commits `needs_publish = false`.
        reloaded.vault.fail_save.set(false);
        reloaded.save(&[]).await.unwrap();
        assert!(!reloaded.vault.state.borrow().needs_publish);

        // Adjusting settings re-enables publishing cleanly.
        let adjusted = PqConfig {
            pq_enabled: false,
            strict_pq: false,
            ..reloaded.client.pq_config().clone()
        };
        reloaded.save_pq_config(adjusted).await.unwrap();
        assert!(reloaded.state.needs_publish);
    });
}

#[test]
fn update_required_banner_handles_unimplemented_and_normalizes_reason() {
    assert!(normalize_update_reason("").contains("Refresh the page"));
    assert!(
        normalize_update_reason("procedure not implemented by server").contains("Refresh the page")
    );
    assert_eq!(
        normalize_update_reason("Legacy v1 notifications deprecated; refresh or upgrade the app"),
        "Legacy v1 notifications deprecated; refresh or upgrade the app"
    );
    assert!(normalize_update_reason("protocol mismatch").contains("Refresh the page"));

    let ui = Ui::new();
    let engine = Engine::new(ui);
    assert!(ui.update_required.get_untracked().is_none());

    // Non-Unimplemented errors do not trigger the update banner.
    engine.check_protocol_error(
        ProtocolRpcScope::CoreV2,
        &session::Error::from(ErrorKind::Server),
    );
    assert!(ui.update_required.get_untracked().is_none());

    // Unconfirmed / ambiguous Unimplemented does not trigger the update banner.
    engine.check_protocol_error(
        ProtocolRpcScope::CoreV2,
        &session::Error::from(protocol::Error::ambiguous_response(
            protocol::ErrorKind::Unimplemented,
            "ambiguous",
        )),
    );
    assert!(ui.update_required.get_untracked().is_none());

    #[derive(Clone)]
    struct HttpError(u16, Vec<u8>);
    impl LocalPost for HttpError {
        async fn post(&self, _path: &str, _body: Vec<u8>) -> protocol::Result<(u16, Vec<u8>)> {
            Ok((self.0, self.1.clone()))
        }
    }
    let core_unimpl = futures::executor::block_on(async {
        let proxy = ConnectClient::new(HttpError(404, b"<html>Not Found</html>".to_vec()));
        let proxy_client = Client::new(proxy);
        let err = proxy_client
            .check_server_info("chat.example")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unimplemented);
        assert!(!err.is_server_refusal());
        assert!(!err.is_connect_error());
        engine.check_protocol_error(ProtocolRpcScope::CoreV2, &err);
        assert!(ui.update_required.get_untracked().is_none());

        let worker =
            protocol::connect::error(protocol::ErrorKind::Unimplemented, "upgrade required");
        let relay = ConnectClient::new(HttpError(worker.status, worker.body));
        let client = Client::new(relay.clone());
        let err = client.start_upload(&relay, 16).await.unwrap_err();
        assert!(err.is_connect_error());
        engine.check_protocol_error(ProtocolRpcScope::Attachment, &err);
        assert!(ui.update_required.get_untracked().is_none());

        client.check_server_info("chat.example").await.unwrap_err()
    });

    assert!(core_unimpl.is_connect_error());
    assert!(should_require_update_for_rpc(
        ProtocolRpcScope::CoreV2,
        &core_unimpl
    ));
    engine.check_protocol_error(ProtocolRpcScope::CoreV2, &core_unimpl);
    assert!(
        ui.update_required
            .get_untracked()
            .is_some_and(|msg| msg.contains("upgrade required"))
    );
    assert_eq!(ui.log.get_untracked().len(), 1);
    // Repeated calls do not spam duplicate activity log entries.
    engine.require_update("Please refresh to continue.");
    assert_eq!(ui.log.get_untracked().len(), 1);
    assert_eq!(
        ui.update_required.get_untracked().as_deref(),
        Some("Please refresh to continue.")
    );
}

#[test]
fn permanently_invalid_classical_initial_is_staged_for_ack() {
    let engine = Engine::new(Ui::new());
    let (mut inner, _) = unlocked_client();
    let wire = WireInitialMessageV2 {
        id: 41,
        ..classical_wire_initial(9)
    };
    let mut batch = InitialBatch::default();
    engine.process_inbox_messages(
        &mut inner,
        ListedInitialMessages {
            messages: vec![Incoming::try_from(&wire).unwrap()],
            malformed_ids: vec![],
            has_more: false,
            next_after_id: Some(41),
        },
        &mut batch,
    );
    assert_eq!(inner.state.pending_inbox_acks, vec![41]);
    assert!(inner.deferred_initials.is_empty());
}

#[cfg(not(feature = "ml-kem-1024"))]
fn unsupported_wire_initial(peer: PublicKey, id: u64) -> WireInitialMessageV2 {
    unsupported_wire_initial_with_payload(peer, id, &id.to_be_bytes())
}

#[cfg(not(feature = "ml-kem-1024"))]
fn unsupported_wire_initial_with_payload(
    peer: PublicKey,
    id: u64,
    content: &[u8],
) -> WireInitialMessageV2 {
    WireInitialMessageV2 {
        id,
        version: 2,
        identity_key: Bytes::copy_from_slice(&peer),
        ephemeral_key: Bytes::from_static(&[0x55; 32]),
        signed_prekey: Bytes::from_static(&[0x66; 32]),
        one_time_prekey: Some(Bytes::from_static(&[0x22; 32])),
        first_message: Some(party::EncryptedMessage {
            header: Bytes::from_static(b"header"),
            content: Bytes::copy_from_slice(content),
        }),
        pq_suite: PqSuite::MlKem1024.as_u8().into(),
        pq_last_resort: true,
        pq_prekey_id: Bytes::from_static(&[0x77; 32]),
        pq_ciphertext: Bytes::from(vec![0x88; PqSuite::MlKem1024.ct_len()]),
        manifest_digest: Bytes::from_static(&[0x99; 32]),
    }
}

#[cfg(not(feature = "ml-kem-1024"))]
#[test]
fn unsupported_carried_initial_survives_reload_and_allows_later_joins() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let mut client = Client::new(Fetch::client(TEST_SERVER));
        let (peer, supported) = carried_initial(&mut client).await;
        let mut inner = load_contacts(&client, vec![stored_contact(client.identity_key(), peer)]);
        let wire = unsupported_wire_initial(peer, 0);
        let deferred = Incoming::try_from(&wire).unwrap();
        stage_carried_initials(&mut inner.contacts[0].state, [&deferred, &supported]).unwrap();
        inner.save(&[]).await.unwrap();

        let join = engine.join_carried(&mut inner, &peer).await.unwrap();
        assert!(join.recommend_upgrade.is_none());
        assert!(join.has_deferred);
        let expected = [protocol::mailbox_v2::encode_carried_initial(&wire)
            .unwrap()
            .to_vec()];
        assert_eq!(
            inner.vault.state.borrow().contacts[0].pending_carried_initials,
            expected
        );
        assert_eq!(inner.vault.entries.borrow().len(), 1);
        let logged = engine.ui.log.get_untracked().len();
        inner.vault.fail_save.set(true);
        assert!(
            engine
                .join_carried(&mut inner, &peer)
                .await
                .unwrap()
                .has_deferred
        );
        assert_eq!(engine.ui.log.get_untracked().len(), logged);

        let mut inner = reload(inner.vault);
        assert_eq!(inner.contacts[0].state.pending_carried_initials, expected);
        assert!(
            engine
                .join_carried(&mut inner, &peer)
                .await
                .unwrap()
                .has_deferred
        );
        assert_eq!(engine.ui.log.get_untracked().len(), logged + 1);
        assert_eq!(inner.contacts[0].state.pending_carried_initials, expected);
    });
}

#[cfg(not(feature = "ml-kem-1024"))]
#[test]
fn full_unsupported_carried_queue_still_stages_and_joins_supported_handshake() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let mut client = Client::new(Fetch::client(TEST_SERVER));
        let (peer, supported) = carried_initial(&mut client).await;
        let mut inner = load_contacts(&client, vec![stored_contact(client.identity_key(), peer)]);

        // Fill all 128 unsupported carried-initial slots.
        let unsupported: Vec<_> = (1u64..=129)
            .map(|n| Incoming::try_from(&unsupported_wire_initial(peer, n)).unwrap())
            .collect();
        stage_carried_initials(&mut inner.contacts[0].state, unsupported.iter()).unwrap();
        assert_eq!(inner.contacts[0].state.pending_carried_initials.len(), 128);
        inner.save(&[]).await.unwrap();
        assert!(
            engine
                .join_carried(&mut inner, &peer)
                .await
                .unwrap()
                .has_deferred
        );

        // Even with 128 unsupported entries retained, staging and joining a new supported carried
        // initial succeeds cleanly!
        stage_carried_initials(&mut inner.contacts[0].state, [&supported]).unwrap();
        inner.save(&[]).await.unwrap();
        assert_eq!(inner.contacts[0].state.pending_carried_initials.len(), 129);
        let outcome = engine.join_carried(&mut inner, &peer).await.unwrap();
        assert!(outcome.has_deferred);
        assert_eq!(inner.contacts[0].state.pending_carried_initials.len(), 128);
        assert_eq!(inner.vault.entries.borrow().len(), 1);
    });
}

#[cfg(not(feature = "ml-kem-1024"))]
#[test]
fn deferred_inbox_ack_waits_for_durable_ciphertext_and_survives_restart() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let (mut inner, peer) = unlocked_client();
        inner.save(&[]).await.unwrap();
        let wire = unsupported_wire_initial(peer, 77);
        let normalized_wire = WireInitialMessageV2 {
            id: 0,
            ..wire.clone()
        };
        let message = Incoming::try_from(&wire).unwrap();
        let mut batch = InitialBatch::default();
        engine.process_inbox_messages(
            &mut inner,
            ListedInitialMessages {
                messages: vec![message.clone(), message],
                malformed_ids: vec![],
                has_more: false,
                next_after_id: Some(77),
            },
            &mut batch,
        );
        assert!(inner.needs_save());
        assert!(inner.state.pending_inbox_acks.is_empty());
        assert!(inner.has_deferred_initial_for(&peer));
        inner.vault.fail_save.set(true);
        assert!(engine.save_initial_batch(&mut inner, batch).await.is_err());
        inner
            .ack_persisted_inbox(async |_, _, _| panic!("ack before commit"))
            .await
            .unwrap();
        assert!(inner.state.pending_inbox_acks.is_empty());
        assert!(inner.vault.deferred.borrow().entries.is_empty());
        assert!(inner.vault.state.borrow().pending_inbox_acks.is_empty());

        inner.vault.fail_save.set(false);
        inner.save(&[]).await.unwrap();
        let mut inner = reload(inner.vault);
        assert_eq!(inner.deferred_initials.len(), 1);
        assert_eq!(
            inner.deferred_initials[0].initial.as_ref(),
            Some(&normalized_wire)
        );
        assert!(inner.deferred_initials[0].deferred_at > 0);
        assert_eq!(inner.state.pending_inbox_acks, [77]);
        assert!(
            engine
                .replay_deferred_initials(&mut inner)
                .await
                .unwrap()
                .is_none()
        );
        let mut sent = vec![];
        inner
            .ack_persisted_inbox(async |_, _, ids| {
                sent.extend(ids);
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(sent, [77]);
        assert!(inner.vault.state.borrow().pending_inbox_acks.is_empty());
        assert_eq!(inner.vault.deferred.borrow().entries.len(), 1);
        assert_eq!(
            inner.vault.deferred.borrow().entries[0].initial.as_ref(),
            Some(&normalized_wire)
        );
    });
}

#[cfg(not(feature = "ml-kem-1024"))]
#[test]
fn full_deferred_inbox_dedups_distinct_relay_ids_and_leaves_new_ciphertext_on_server() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let (mut inner, peer) = unlocked_client();
        let listed = |ids: std::ops::RangeInclusive<u64>| ListedInitialMessages {
            messages: ids
                .map(|id| Incoming::try_from(&unsupported_wire_initial(peer, id)).unwrap())
                .collect(),
            malformed_ids: vec![],
            has_more: false,
            next_after_id: None,
        };
        let mut batch = InitialBatch::default();
        engine.process_inbox_messages(&mut inner, listed(1..=100), &mut batch);
        engine.save_initial_batch(&mut inner, batch).await.unwrap();
        inner
            .ack_persisted_inbox(async |_, _, ids| {
                assert_eq!(ids, (1..=100).collect::<Vec<_>>());
                Ok(())
            })
            .await
            .unwrap();

        // A retransmission of entry #100 with a DIFFERENT relay ID (200) shares the existing
        // deferred slot and still gets acknowledged, while a distinct ciphertext (id=101) is
        // left unacked on the server!
        let retransmitted = Incoming::try_from(&unsupported_wire_initial_with_payload(
            peer,
            200,
            &100u64.to_be_bytes(),
        ))
        .unwrap();
        let distinct_new = Incoming::try_from(&unsupported_wire_initial(peer, 101)).unwrap();
        let mut batch = InitialBatch::default();
        engine.process_inbox_messages(
            &mut inner,
            ListedInitialMessages {
                messages: vec![retransmitted, distinct_new],
                malformed_ids: vec![],
                has_more: false,
                next_after_id: None,
            },
            &mut batch,
        );
        engine.save_initial_batch(&mut inner, batch).await.unwrap();
        assert_eq!(inner.vault.state.borrow().pending_inbox_acks, [200]);
        let saved_deferred = inner.vault.deferred.borrow();
        assert_eq!(saved_deferred.entries.len(), 100);
        assert!(
            saved_deferred
                .entries
                .iter()
                .all(|e| e.initial.as_ref().unwrap().id == 0)
        );
    });
}

#[cfg(not(feature = "ml-kem-1024"))]
#[test]
fn pq_incompatible_isolated_contact_defers_greetings_while_corrupt_contact_acks() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let mut client = Client::new(Fetch::client(TEST_SERVER));
        let me = client.identity_key();
        let (pq_peer, classical_or_supported_msg) = carried_initial(&mut client).await;
        let corrupt_peer = identity();

        // Healthy contact isolated ONLY because its active KEM ratchet uses ML-KEM-1024.
        let mut pq_isolated = stored_contact(me, pq_peer);
        let mut party = party::proto::Party::default();
        party.kem_ratchet.get_or_insert_default().suite = PqSuite::MlKem1024.as_u8().into();
        pq_isolated.session.as_mut().unwrap().party = Some(party);
        // Genuinely corrupt contact (invalid cursor, no unsupported PQ suite).
        let mut corrupt_isolated = stored_contact(me, corrupt_peer);
        corrupt_isolated.session.as_mut().unwrap().me.pop();

        let mut inner = load_contacts(&client, vec![pq_isolated, corrupt_isolated]);
        assert!(inner.is_pq_incompatible_isolated_peer(&pq_peer));
        assert!(inner.is_isolated_peer(&corrupt_peer));
        assert!(!inner.is_pq_incompatible_isolated_peer(&corrupt_peer));

        let mut msg_from_pq_peer = classical_or_supported_msg;
        msg_from_pq_peer.id = 51;
        let msg_from_corrupt_peer =
            Incoming::try_from(&unsupported_wire_initial(corrupt_peer, 52)).unwrap();
        let mut batch = InitialBatch::default();
        engine.process_inbox_messages(
            &mut inner,
            ListedInitialMessages {
                messages: vec![msg_from_pq_peer, msg_from_corrupt_peer],
                malformed_ids: vec![],
                has_more: false,
                next_after_id: Some(52),
            },
            &mut batch,
        );
        // Greeting from the PQ-isolated contact is DEFERRED (acked only after durable save);
        // greeting from the genuinely corrupt contact is rejected & staged directly for ack.
        assert_eq!(inner.deferred_initials.len(), 1);
        assert!(inner.has_deferred_initial_for(&pq_peer));
        assert!(!inner.has_deferred_initial_for(&corrupt_peer));
        assert_eq!(inner.state.pending_inbox_acks, [52]);
        assert_eq!(inner.deferred_acks_after_save, [51]);

        // Saving and attempting replay on this build leaves the entry deferred while the contact
        // remains PQ-isolated (does NOT drop or destroy it).
        engine.save_initial_batch(&mut inner, batch).await.unwrap();
        assert!(
            engine
                .replay_deferred_initials(&mut inner)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(inner.deferred_initials.len(), 1);
    });
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "ml-kem-1024")))]
#[test]
fn pq_incompatible_isolated_contact_defers_mailbox_envelopes_and_aborts_on_cap_overflow() {
    use protocol::mailbox_v2::{AckMessagesResponse, EnvelopeV2, FetchSignedResponse};
    use std::rc::Rc;

    futures::executor::block_on(async {
        let client = Client::new(Fetch::client(LOCAL_SERVER));
        let me = client.identity_key();
        let pq_peer = identity();
        let iso_token_hash = [0x6Au8; 32];
        let earlier_token_hash = [0x6Bu8; 32];

        // Healthy contact isolated ONLY because its active KEM ratchet uses ML-KEM-1024.
        let mut pq_isolated = stored_contact(me, pq_peer);
        let mut party = party::proto::Party::default();
        party.kem_ratchet.get_or_insert_default().suite = PqSuite::MlKem1024.as_u8().into();
        let raw_sess = pq_isolated.session.as_mut().unwrap();
        raw_sess.party = Some(party);
        raw_sess.inbound_token_hash = iso_token_hash.to_vec();
        let mut earlier = proto::EarlierSession::default();
        earlier.inbound_token_hash = earlier_token_hash.to_vec();
        raw_sess.others.push(earlier);

        let (contacts, isolated_contacts, _) =
            restore_contacts(vec![pq_isolated], &me, LOCAL_SERVER);
        assert!(contacts.is_empty());
        assert_eq!(isolated_contacts.len(), 1);

        let inner = Inner::new(
            MemoryVault::default(),
            LOCAL_SERVER.into(),
            "localhost".into(),
            AppState::default(),
            client,
            contacts,
            isolated_contacts,
            DeferredRecord::default(),
        );
        let engine = Engine::with_inner(Ui::new(), inner);

        // 1. Mailbox envelopes matching active OR earlier token hash of the PQ-isolated contact
        //    MUST be durably buffered in `DeferredRecord.envelopes` BEFORE cursor commit & ACK.
        let ack_calls = Rc::new(Cell::new(0usize));
        let ack_calls_ref = ack_calls.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/FetchSigned") {
                    let resp = FetchSignedResponse {
                        messages: vec![
                            EnvelopeV2 {
                                sequence: 10,
                                token_hash: bytes::Bytes::copy_from_slice(&iso_token_hash),
                                message: Some(party::EncryptedMessage {
                                    header: bytes::Bytes::from_static(b"hdr1"),
                                    content: bytes::Bytes::from_static(b"ct1"),
                                }),
                                initial_message: None,
                            },
                            EnvelopeV2 {
                                sequence: 11,
                                token_hash: bytes::Bytes::copy_from_slice(&earlier_token_hash),
                                message: Some(party::EncryptedMessage {
                                    header: bytes::Bytes::from_static(b"hdr2"),
                                    content: bytes::Bytes::from_static(b"ct2"),
                                }),
                                initial_message: None,
                            },
                        ],
                        has_more: false,
                    };
                    Ok((200, resp.encode_to_vec()))
                } else if path.ends_with("/AckMessages") {
                    ack_calls_ref.set(ack_calls_ref.get() + 1);
                    Ok((200, AckMessagesResponse { deleted: 2 }.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            engine.receive_mailbox().await.unwrap();
        }
        assert_eq!(ack_calls.get(), 1);
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            assert_eq!(inner.client.mailbox_cursor(), 11);
            assert_eq!(inner.deferred_envelopes.len(), 2);
            assert_eq!(inner.vault.deferred.borrow().envelopes.len(), 2);
            assert_eq!(inner.deferred_envelopes[0].sequence, 10);
            assert_eq!(inner.deferred_envelopes[1].sequence, 11);

            // 2. Unlock pruning MUST preserve deferred envelopes for PQ-isolated contacts even
            //    beyond the 30-day active replay window (`DEFERRED_REPLAY_WINDOW_MS`).
            assert!(inner.deferred_envelopes[0].pq_isolated);
            assert!(inner.deferred_envelopes[1].pq_isolated);
            let mut copy = inner.deferred_envelopes.clone();
            let removed = super::sync::prune_deferred_envelopes(
                &mut copy,
                &mut inner.contacts,
                &mut inner.isolated_contacts,
                &me,
                crate::util::now() + DEFERRED_REPLAY_WINDOW_MS + 60_000,
            );
            assert_eq!(removed, 0);
            assert_eq!(copy.len(), 2);
        }

        // 3. Dedicated isolated-peer spool: isolated contacts can buffer well past the 64-item
        //    active cap (up to MAX_ISOLATED_DEFERRED_ENVELOPES_PER_PEER = 2048), and even if that
        //    overflows, `receive_mailbox` records `evicted_while_isolated` and advances
        //    `mailbox_cursor` + ACKs the relay so healthy peers in the unified mailbox never stall!
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            for seq in 100..(100 + super::sync::MAX_ISOLATED_DEFERRED_ENVELOPES_PER_PEER as u64 - 2)
            {
                inner
                    .deferred_envelopes
                    .push(crate::vault::DeferredEnvelope {
                        peer: pq_peer.to_vec(),
                        sequence: seq,
                        message: None,
                        initial_message: None,
                        deferred_at: crate::util::now(),
                        pq_isolated: true,
                    });
            }
            assert_eq!(
                inner.deferred_envelopes.len(),
                super::sync::MAX_ISOLATED_DEFERRED_ENVELOPES_PER_PEER
            );
        }
        let overflow_acks = Rc::new(Cell::new(0usize));
        let overflow_acks_ref = overflow_acks.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/FetchSigned") {
                    let resp = FetchSignedResponse {
                        messages: vec![EnvelopeV2 {
                            sequence: 9999,
                            token_hash: bytes::Bytes::copy_from_slice(&iso_token_hash),
                            message: Some(party::EncryptedMessage {
                                header: bytes::Bytes::from_static(b"hdr-overflow"),
                                content: bytes::Bytes::from_static(b"ct-overflow"),
                            }),
                            initial_message: None,
                        }],
                        has_more: false,
                    };
                    Ok((200, resp.encode_to_vec()))
                } else if path.ends_with("/AckMessages") {
                    overflow_acks_ref.set(overflow_acks_ref.get() + 1);
                    Ok((200, AckMessagesResponse { deleted: 1 }.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            engine.receive_mailbox().await.expect(
                "overflowing the isolated-peer spool must record eviction and advance mailbox",
            );
        }
        assert_eq!(overflow_acks.get(), 1);
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(
            inner.client.mailbox_cursor(),
            9999,
            "mailbox_cursor must advance even when an isolated peer overflows its 2048-item spool"
        );
        assert_eq!(
            inner.isolated_contacts[0].evicted_while_isolated, 1,
            "overflow must durably increment evicted_while_isolated on the isolated contact"
        );
        assert!(
            inner.isolated_views()[0]
                .reason
                .contains("1 message(s) exceeded the local offline buffer"),
            "Settings UI view must surface isolated eviction count: {:?}",
            inner.isolated_views()[0].reason
        );
    });
}

#[test]
fn sanitize_deferred_initials_prunes_malformed_dedups_caps_and_migrates_legacy() {
    let peer = identity();
    let valid_v2 = WireInitialMessageV2 {
        id: 19,
        version: 2,
        identity_key: Bytes::copy_from_slice(&peer),
        ephemeral_key: Bytes::from_static(&[0x55; 32]),
        signed_prekey: Bytes::from_static(&[0x66; 32]),
        first_message: Some(party::EncryptedMessage {
            header: Bytes::from_static(b"h"),
            content: Bytes::from_static(b"c"),
        }),
        pq_suite: PqSuite::MlKem1024.as_u8().into(),
        pq_last_resort: true,
        pq_prekey_id: Bytes::from_static(&[0x77; 32]),
        pq_ciphertext: Bytes::from(vec![0x88; PqSuite::MlKem1024.ct_len()]),
        manifest_digest: Bytes::from_static(&[0x99; 32]),
        ..Default::default()
    };
    let dup_other_id = WireInitialMessageV2 {
        id: 99,
        ..valid_v2.clone()
    };
    // Malformed v2 with suite == 0 must be pruned so it cannot occupy a deferred slot forever.
    let bad_suite_zero = WireInitialMessageV2 {
        pq_suite: 0,
        ..valid_v2.clone()
    };
    let mut entries = vec![
        DeferredInitial {
            initial: None,
            deferred_at: 0,
        },
        DeferredInitial {
            initial: Some(bad_suite_zero),
            deferred_at: 100,
        },
        DeferredInitial {
            initial: Some(valid_v2.clone()),
            deferred_at: 0,
        },
        DeferredInitial {
            initial: Some(dup_other_id),
            deferred_at: 0,
        },
    ];

    let (removed, modified) = sanitize_deferred_initials(&mut entries, 5_000);
    assert_eq!(removed, 3);
    assert!(modified);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].deferred_at, 5_000);
    assert_eq!(entries[0].initial.as_ref().unwrap().id, 0);

    // Deleting `peer` prunes `peer`'s deferred greetings while preserving other peers' entries.
    let (mut inner, other_peer) = unlocked_client();
    let other_v2 = WireInitialMessageV2 {
        identity_key: Bytes::copy_from_slice(&other_peer),
        id: 0,
        ..valid_v2
    };
    inner.deferred_initials = vec![
        entries[0].clone(),
        DeferredInitial {
            initial: Some(other_v2.clone()),
            deferred_at: 6_000,
        },
    ];
    let after_delete = inner.deferred_record_without_peer(&peer);
    assert_eq!(after_delete.entries.len(), 1);
    assert_eq!(after_delete.entries[0].initial.as_ref(), Some(&other_v2));

    // Replay window bounds prekey/digest preservation to DEFERRED_REPLAY_WINDOW_MS (30 days).
    let (spks_fresh, digests_fresh) =
        preserved_deferred_prekeys(&inner, 5_000 + DEFERRED_REPLAY_WINDOW_MS);
    assert_eq!(spks_fresh, vec![[0x66; 32]]);
    assert_eq!(digests_fresh, vec![[0x99; 32]]);
    let (spks_expired, digests_expired) =
        preserved_deferred_prekeys(&inner, 6_000 + DEFERRED_REPLAY_WINDOW_MS + 1);
    assert!(spks_expired.is_empty());
    assert!(digests_expired.is_empty());

    // Carried initial timestamps also respect the 30-day window.
    inner.deferred_initials.clear();
    let carried_bytes = protocol::mailbox_v2::encode_carried_initial(&other_v2)
        .unwrap()
        .to_vec();
    inner.contacts[0]
        .state
        .pending_carried_initials
        .push(carried_bytes);
    inner
        .carried_deferred_timestamps
        .push(CarriedDeferredTimestamp {
            signed_prekey: vec![0x66; 32],
            deferred_at: 10_000,
        });
    let (c_spks_fresh, _) = preserved_deferred_prekeys(&inner, 10_000 + DEFERRED_REPLAY_WINDOW_MS);
    assert_eq!(c_spks_fresh, vec![[0x66; 32]]);
    let (c_spks_old, _) =
        preserved_deferred_prekeys(&inner, 10_000 + DEFERRED_REPLAY_WINDOW_MS + 1);
    assert!(c_spks_old.is_empty());
    // Deleting the contact prunes its orphaned carried timestamp.
    let pruned_for_delete = inner.deferred_record_without_peer(&other_peer);
    assert!(pruned_for_delete.carried_timestamps.is_empty());
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[test]
fn pq_build_replays_deferred_inbox_ciphertext_once_after_reload() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let mut client = Client::new(Fetch::client(TEST_SERVER));
        let (peer, mut message) = carried_initial(&mut client).await;
        message.id = 77;
        client
            .set_pq_config(PqConfig {
                pq_enabled: false,
                pq_ratchet_enabled: false,
                ..client.pq_config().clone()
            })
            .unwrap();
        let mut inner = load_contacts(&client, vec![]);
        // Save the same encrypted wire record and ack as the build lacking this suite.
        assert!(inner.defer_inbox_initial(&message));
        inner.save(&[]).await.unwrap();
        assert_eq!(inner.vault.deferred.borrow().entries.len(), 1);
        inner
            .ack_persisted_inbox(async |_, _, ids| {
                assert_eq!(ids, [77]);
                Ok(())
            })
            .await
            .unwrap();

        let mut inner = reload(inner.vault);
        inner.vault.fail_save.set(true);
        assert!(engine.replay_deferred_initials(&mut inner).await.is_err());
        assert_eq!(inner.vault.deferred.borrow().entries.len(), 1);
        assert!(inner.vault.entries.borrow().is_empty());

        inner.vault.fail_save.set(false);
        let mut inner = reload(inner.vault);
        assert!(
            engine
                .replay_deferred_initials(&mut inner)
                .await
                .unwrap()
                .is_some()
        );
        let mut inner = reload(inner.vault);
        assert!(
            engine
                .replay_deferred_initials(&mut inner)
                .await
                .unwrap()
                .is_none()
        );
        assert!(inner.deferred_initials.is_empty());
        assert!(inner.vault.deferred.borrow().is_empty());
        assert!(inner.state.pending_inbox_acks.is_empty());
        assert_eq!(inner.state.used_one_time_prekeys, 1);
        assert_eq!(inner.state.used_pq_one_time_prekeys, 1);
        assert!(inner.contact(&peer).unwrap().has_healthy_pq_session());
        let entries = inner.vault.entries.borrow();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[&(peer, 0)].content.as_ref().unwrap().kind,
            Some(Kind::Text("first message".into()))
        );
    });
}

#[test]
fn farewell_v2_derives_deterministic_id_and_rejects_corrupt_bytes() {
    let encrypted = party::EncryptedMessage {
        header: Bytes::from_static(b"ratchet-header"),
        content: Bytes::from_static(b"encrypted-farewell-body"),
    };
    let expected_id = session::Sealed::client_message_id_for(&encrypted);
    assert_eq!(expected_id.len(), 16);

    // A push_v2 farewell with empty client_message_id backfills the deterministic ID.
    let v2_without_cid = PushV2Request {
        recipient: Bytes::from_static(&[0x22; 32]),
        message: Some(encrypted.clone()),
        initial_message: None,
        client_message_id: Bytes::new(),
        write_token: Bytes::from_static(&[0x44; 32]),
    };
    let v2_farewell = Farewell {
        push_v2: v2_without_cid.encode_to_vec(),
    };
    let first = farewell_push_v2_request(&v2_farewell).expect("decodes valid v2 farewell");
    let retry = farewell_push_v2_request(&v2_farewell).expect("decodes valid v2 farewell");
    assert_eq!(first.client_message_id.as_ref(), &expected_id);
    assert_eq!(
        first, retry,
        "retries must derive identical client_message_id"
    );

    // Existing explicit 16-byte client_message_id is preserved verbatim.
    let v2_with_cid = PushV2Request {
        recipient: Bytes::from_static(&[0x22; 32]),
        message: Some(encrypted),
        initial_message: None,
        client_message_id: Bytes::from_static(&[0xAB; 16]),
        write_token: Bytes::from_static(&[0x44; 32]),
    };
    assert_eq!(
        farewell_push_v2_request(&Farewell {
            push_v2: v2_with_cid.encode_to_vec(),
        })
        .unwrap()
        .client_message_id
        .as_ref(),
        &[0xAB; 16]
    );

    // Empty or malformed farewell returns None cleanly.
    assert!(farewell_push_v2_request(&Farewell::default()).is_none());
    assert!(
        farewell_push_v2_request(&Farewell {
            push_v2: vec![0xff, 0xff],
        })
        .is_none()
    );
}

#[test]
fn open_tracker_invalidates_only_deleted_peer_tracks_deletion_and_checks_settlement() {
    let alice = [0xAA; 32];
    let bob = [0xBB; 32];
    let mut tracker = OpenTracker::default();

    // Opening Alice then closing immediately supersedes Alice (not marked deleted).
    let gen_alice = tracker.begin_open(alice);
    assert!(tracker.is_current(gen_alice));
    assert!(tracker.is_settled_on(Some(alice), alice));
    tracker.close();
    assert!(!tracker.is_current(gen_alice));
    assert!(!tracker.was_deleted(gen_alice));
    assert!(!tracker.is_settled_on(Some(alice), alice));

    // Queued open for Alice is invalidated AND flagged `was_deleted` when Alice is deleted so
    // `Engine::open` returns `Ignored` and reconciles browser history.
    let gen_alice_2 = tracker.begin_open(alice);
    tracker.invalidate_peer(alice);
    assert!(!tracker.is_current(gen_alice_2));
    assert!(tracker.was_deleted(gen_alice_2));

    // Queued open for Bob must NOT be invalidated when Alice's deletion finishes, and while Alice
    // is still displayed on screen `is_settled_on(Some(alice), alice)` must be false so a deferred
    // `Open(alice)` still supersedes Bob's queued open.
    let gen_bob = tracker.begin_open(bob);
    assert!(!tracker.is_settled_on(Some(alice), alice));
    assert!(tracker.is_settled_on(Some(bob), bob));
    tracker.invalidate_peer(alice);
    assert!(tracker.is_current(gen_bob));
    assert!(!tracker.was_deleted(gen_bob));
}

#[test]
fn idle_sign_in_dismiss_does_not_leak_and_live_submissions_are_ref_counted() {
    // Dismissing an idle SignInDialog after NewChat's original task already finished must not
    // retain stale cancellation IDs in `Engine::cancelled_submissions`.
    let engine = Engine::new(Ui::new());
    let draft = crate::state::PendingNewChat {
        key: "peer-key".into(),
        name: "Alice".into(),
        server: None,
        pq_pinned: false,
        allow_classical: false,
        auto_start: true,
    };
    let id = engine.begin_new_chat_submit(draft.clone());
    engine.finish_submission(id);
    engine.require_sign_in_for_new_chat(id, draft.clone());
    assert!(engine.dismiss_sign_in());
    assert!(!engine.is_submission_cancelled(id));

    // Overlapping `NewChat` and `SignInDialog` tasks sharing a `submission_id` reference-count
    // `live_submissions`: when the original `NewChat` task finishes first, cancellation remains
    // live for the overlapping `SignIn` auto-start task until that second task finishes too.
    let shared_id = engine.begin_new_chat_submit(draft.clone());
    engine.require_sign_in_for_new_chat(shared_id, draft);
    engine.begin_sign_in_auto_start(shared_id);
    engine.finish_submission(shared_id);
    engine.cancel_active_startup_submission();
    assert!(engine.is_submission_cancelled(shared_id));
    engine.finish_submission(shared_id);
    assert!(!engine.is_submission_cancelled(shared_id));
}

#[test]
fn unannounced_greeting_suppresses_farewell_and_displayed_window_reconciles_accurately() {
    use super::contact::{DisplayedEntry, FarewellMode};
    use crate::vault::{
        GREETING_DELIVERY_CONFIRMED, GREETING_DELIVERY_UNCERTAIN, GREETING_DELIVERY_UNSENT,
    };

    let client = Client::new(Fetch::client(TEST_SERVER));
    let peer = Client::new(Fetch::client(TEST_SERVER)).identity_key();
    let mut inner = load_contacts(&client, vec![stored_contact(client.identity_key(), peer)]);

    // Greeting delivery states distinguish:
    // - UNSENT (never attempted / definitively refused) -> suppress farewell completely;
    // - UNCERTAIN (lost response / post-success save failure) -> farewell with `initial_message = None`;
    // - CONFIRMED -> normal farewell.
    {
        let contact = inner.contact(&peer).unwrap();
        contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
        assert_eq!(contact.farewell_mode(), FarewellMode::Suppress);
        contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
        assert_eq!(contact.farewell_mode(), FarewellMode::WithoutInitial);
        contact.state.greeting_delivery = GREETING_DELIVERY_CONFIRMED;
        assert_eq!(contact.farewell_mode(), FarewellMode::Normal);
    }

    // Truncated history window acknowledges ONLY the entries actually loaded onto screen, is
    // idempotent across repeated loads of both clocked AND zero-clock messages, never wipes unread
    // below staged/unseen messages, and handles > EVENTS_KEPT displayed unread entries cleanly.
    {
        let contact = inner.contact(&peer).unwrap();
        for clock in [10u64, 20, 30] {
            contact
                .add_received(
                    Content {
                        clock,
                        kind: Some(Kind::Text(format!("msg-{clock}"))),
                        events: None,
                    },
                    false,
                )
                .unwrap();
        }
        assert_eq!(contact.state.unread, 3);
        assert_eq!(contact.state.unseen, vec![10, 20, 30]);
        let tail = [
            DisplayedEntry {
                index: 1,
                counts_unread: true,
                clock: Some(20),
            },
            DisplayedEntry {
                index: 2,
                counts_unread: true,
                clock: Some(30),
            },
        ];
        assert!(contact.acknowledge_entries(&tail));
        assert_eq!(contact.state.unread, 1);
        assert_eq!(contact.state.unseen, vec![10]);
        assert_eq!(
            contact.state.events.as_ref().map(|e| e.read.clone()),
            Some(vec![20, 30])
        );
        // Second call over the same displayed window must not double-decrement or duplicate receipts.
        assert!(!contact.acknowledge_entries(&tail));
        assert_eq!(contact.state.unread, 1);
        assert_eq!(contact.state.unseen, vec![10]);

        // Loading the earlier page (`index: 0`) clears the remaining unread message and sends its receipt.
        assert!(contact.acknowledge_entries(&[DisplayedEntry {
            index: 0,
            counts_unread: true,
            clock: Some(10),
        }]));
        assert_eq!(contact.state.unread, 0);
        assert!(contact.state.unseen.is_empty());
        assert_eq!(
            contact.state.events.as_ref().map(|e| e.read.clone()),
            Some(vec![20, 30, 10])
        );
    }

    // Zero-clock messages on a partial page are counted as read strictly once per history index,
    // so reopening the same partial page does not clear an older unshown zero-clock message.
    {
        let mut inner_zero =
            load_contacts(&client, vec![stored_contact(client.identity_key(), peer)]);
        let contact = inner_zero.contact(&peer).unwrap();
        let mut page = Vec::new();
        for i in 0..3u64 {
            let (idx, entry) = contact
                .add_received(
                    Content {
                        clock: 0,
                        kind: Some(Kind::Deleted(crate::content::Deleted {})),
                        events: None,
                    },
                    false,
                )
                .unwrap();
            let (counts_unread, clock) = super::handshake::entry_read_tracking(&entry);
            if i > 0 {
                page.push(DisplayedEntry {
                    index: idx,
                    counts_unread,
                    clock,
                });
            }
        }
        assert_eq!(contact.state.unread, 3);
        assert!(contact.acknowledge_entries(&page));
        assert_eq!(contact.state.unread, 1);
        // Reopening the exact same partial page leaves index 0 unread!
        assert!(!contact.acknowledge_entries(&page));
        assert_eq!(contact.state.unread, 1);
        // Loading earlier page (index 0) clears the final unread entry.
        assert!(contact.acknowledge_entries(&[DisplayedEntry {
            index: 0,
            counts_unread: true,
            clock: None,
        }]));
        assert_eq!(contact.state.unread, 0);
    }

    // Displaying more than `EVENTS_KEPT` (1,001) clocked unread messages clears all 1,001 from
    // `unread` even though `unseen` only retains the newest 1,000 clocks.
    {
        let mut inner_many =
            load_contacts(&client, vec![stored_contact(client.identity_key(), peer)]);
        let contact = inner_many.contact(&peer).unwrap();
        let mut displayed = Vec::with_capacity(super::EVENTS_KEPT + 1);
        for i in 0..(super::EVENTS_KEPT + 1) {
            let clock = (i as u64) + 1;
            let (idx, entry) = contact
                .add_received(
                    Content {
                        clock,
                        kind: Some(Kind::Text(format!("bulk-{clock}"))),
                        events: None,
                    },
                    false,
                )
                .unwrap();
            let (counts_unread, readable_clock) = super::handshake::entry_read_tracking(&entry);
            displayed.push(DisplayedEntry {
                index: idx,
                counts_unread,
                clock: readable_clock,
            });
        }
        assert_eq!(contact.state.unread, (super::EVENTS_KEPT + 1) as u32);
        assert_eq!(contact.state.unseen.len(), super::EVENTS_KEPT);
        assert!(contact.acknowledge_entries(&displayed));
        assert_eq!(contact.state.unread, 0);
        assert!(contact.state.unseen.is_empty());
    }

    // Messages displayed while an existing contact's replacement session is quarantined remain
    // unread until quarantine lifts, at which point `acknowledge_displayed_window` reconciles BOTH
    // the previously displayed messages AND the newly released quarantined message together.
    use leptos::prelude::Set;
    let ui = Ui::new();
    ui.open.set(Some(peer));
    let engine = Engine::new(ui);
    let mut displayed_q = Vec::new();
    {
        let contact = inner.contact(&peer).unwrap();
        contact.state.unread = 0;
        contact.state.unseen.clear();
        contact.state.events = None;
        contact.state.quarantined = true;
        for clock in [40u64, 50] {
            let (idx, entry) = contact
                .add_received(
                    Content {
                        clock,
                        kind: Some(Kind::Text(format!("while-quarantined-{clock}"))),
                        events: None,
                    },
                    false,
                )
                .unwrap();
            let (counts_unread, readable_clock) = super::handshake::entry_read_tracking(&entry);
            displayed_q.push(DisplayedEntry {
                index: idx,
                counts_unread,
                clock: readable_clock,
            });
        }
    }
    engine.record_displayed_entries(&peer, &displayed_q);
    assert!(!engine.acknowledge_displayed_window(&mut inner, &peer));
    assert_eq!(inner.contact(&peer).unwrap().state.unread, 2);

    // Lift quarantine and append released first message (clock 60).
    let released_entry = {
        let contact = inner.contact(&peer).unwrap();
        contact.state.quarantined = false;
        let (idx, entry) = contact
            .add_received(
                Content {
                    clock: 60,
                    kind: Some(Kind::Text("released-first".into())),
                    events: None,
                },
                false,
            )
            .unwrap();
        let (counts_unread, clock) = super::handshake::entry_read_tracking(&entry);
        DisplayedEntry {
            index: idx,
            counts_unread,
            clock,
        }
    };
    engine.record_displayed_entries(&peer, &[released_entry]);
    assert!(engine.acknowledge_displayed_window(&mut inner, &peer));
    let contact = inner.contact(&peer).unwrap();
    assert_eq!(contact.state.unread, 0);
    assert!(contact.state.unseen.is_empty());
    assert_eq!(
        contact.state.events.as_ref().map(|e| e.read.clone()),
        Some(vec![40, 50, 60])
    );

    // A staged/undisplayed entry (not in `displayed_history`) must NOT have its unread count wiped
    // when `acknowledge_displayed_window` runs on an already-acknowledged window.
    {
        let contact = inner.contact(&peer).unwrap();
        contact
            .add_received(
                Content {
                    clock: 70,
                    kind: Some(Kind::Text("staged-not-shown".into())),
                    events: None,
                },
                false,
            )
            .unwrap();
    }
    assert!(!engine.acknowledge_displayed_window(&mut inner, &peer));
    let contact = inner.contact(&peer).unwrap();
    assert_eq!(contact.state.unread, 1);
    assert_eq!(contact.state.unseen, vec![70]);

    // `cancel_pending_open` synchronously invalidates a queued open without clearing `ui.open`.
    let engine_close = Engine::new(Ui::new());
    let open_gen = engine_close.open_chat.begin_open(peer);
    assert!(engine_close.open_chat.tracker().is_current(open_gen));
    engine_close.cancel_pending_open();
    assert!(!engine_close.open_chat.tracker().is_current(open_gen));
}

#[test]
fn fallback_farewells_greeting_only_403_and_per_row_signals() {
    use crate::state::{Body, Delivery, Dialog, MessageView, PendingNewChat, Ui};
    use crate::vault::{
        GREETING_DELIVERY_CONFIRMED, GREETING_DELIVERY_UNCERTAIN, GREETING_DELIVERY_UNSENT,
    };
    use leptos::prelude::{Get, GetUntracked, Set, WithUntracked};

    // 1. `encrypt_session_farewells` + `fallback_farewells` preserve a deletion notice on a prior
    // established session until `mark_greeting_confirmed()` clears it.
    let mut recipient = Client::new(Fetch::client(TEST_SERVER));
    let bob_peer = recipient.identity_key();
    let published = recipient.prepare_publish_v2("chat.example", 1, 1).unwrap();
    let p = &published.request;
    let bundle = protocol::handshake_v2::ClaimBundleResponse {
        signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
        signed_prekey_signature: p.signed_prekey_signature.clone(),
        one_time_prekey: p.one_time_prekeys.first().cloned(),
        pq_last_resort: p.pq_last_resort.first().cloned(),
        pq_one_time_prekey: p.pq_one_time_prekeys.first().cloned(),
        manifest: p.manifest.clone(),
    };
    recipient.commit_publish_v2(published);
    let mut sender = Client::new(ConnectClient::new(BundleResponse("/ClaimBundle", bundle)));
    let prepared = futures::executor::block_on(sender.prepare_initiate_v2(
        "chat.example",
        &bob_peer,
        &Default::default(),
        &Kind::Text("hello".into()).to_bytes(),
        Fetch::client(TEST_SERVER),
    ))
    .unwrap();
    let active_state = ContactState {
        peer: bob_peer.to_vec(),
        session: Some(prepared.session.state().into()),
        greeting_delivery: GREETING_DELIVERY_CONFIRMED,
        ..ContactState::default()
    };
    let alice_state = ClientState::try_from(&session::proto::ClientState::from(sender.state()))
        .expect("round-trip sender client state");
    let alice = Client::restore(Fetch::client(TEST_SERVER), alice_state);
    let mut inner = load_contacts(&alice, vec![active_state]);
    let fallback = {
        let contact = inner.contact(&bob_peer).unwrap();
        let mode = contact.farewell_mode();
        assert_eq!(mode, super::contact::FarewellMode::Normal);
        let clock = contact.state.clock.saturating_add(1);
        super::handshake::encrypt_session_farewells(&mut contact.session, clock, None, None, mode)
    };
    assert_eq!(fallback.len(), 1);
    assert_eq!(
        fallback[0].recipient().as_deref(),
        Some(bob_peer.as_slice())
    );
    let normal_req =
        session::protocol::mailbox_v2::PushV2Request::decode(fallback[0].push_v2.as_slice())
            .unwrap();
    assert!(normal_req.initial_message.is_some());

    {
        let contact = inner.contact(&bob_peer).unwrap();
        contact.state.greeting_delivery = GREETING_DELIVERY_UNSENT;
        contact.state.fallback_farewells = fallback.clone();
        assert_eq!(
            contact.farewell_mode(),
            super::contact::FarewellMode::Suppress
        );
        // Persisting through protobuf keeps `fallback_farewells` durable across reloads.
        let encoded = contact.state.encode_to_vec();
        let decoded = ContactState::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.fallback_farewells, fallback);
        // Confirming delivery of the replacement greeting clears `fallback_farewells`.
        assert!(contact.mark_greeting_confirmed());
        assert_eq!(contact.state.greeting_delivery, GREETING_DELIVERY_CONFIRMED);
        assert!(contact.state.fallback_farewells.is_empty());
        assert!(!contact.mark_greeting_confirmed());
    }

    // Also verify `GREETING_DELIVERY_UNCERTAIN` strips carried `initial_message`.
    {
        let contact = inner.contact(&bob_peer).unwrap();
        contact.state.greeting_delivery = GREETING_DELIVERY_UNCERTAIN;
        let mode = contact.farewell_mode();
        assert_eq!(mode, super::contact::FarewellMode::WithoutInitial);
        let clock = contact.state.clock.saturating_add(1);
        let uncertain = super::handshake::encrypt_session_farewells(
            &mut contact.session,
            clock,
            None,
            None,
            mode,
        );
        assert_eq!(uncertain.len(), 1);
        let decoded_req =
            session::protocol::mailbox_v2::PushV2Request::decode(uncertain[0].push_v2.as_slice())
                .unwrap();
        assert!(decoded_req.initial_message.is_none());
    }

    // 2. Greeting-only 403 hook clears auto-start ownership immediately so `SignInDialog` cannot
    // steal the history reservation during an async refusal save.
    let engine = Engine::new(Ui::new());
    engine.startup.set_can_sign_in_here(true);
    let draft = PendingNewChat {
        key: "peer-key".into(),
        name: "Bob".into(),
        server: None,
        pq_pinned: false,
        allow_classical: false,
        auto_start: true,
    };
    let submit_id = engine.begin_new_chat_submit(draft);
    engine.startup.set_in_flight_start_chat(submit_id, true);
    engine.refused_for_sign_in();
    assert_eq!(engine.pending_auto_start_id(), None);
    assert_eq!(engine.ui().dialog.get_untracked(), Some(Dialog::SignIn));

    // 3. `is_settled_on` requires history to actually be loaded for `peer`, and per-row reactive
    // signals update delivery ticks in O(1) without replacing row signals on same-peer refresh.
    let _ = engine.open_chat.begin_open(bob_peer);
    engine.ui().open.set(Some(bob_peer));
    assert!(!engine.is_settled_on(bob_peer));
    engine
        .open_chat
        .set_displayed_history(super::DisplayedHistory {
            peer: bob_peer,
            history_loaded: true,
            loaded_start: 0,
            pending_entries: Vec::new(),
        });
    assert!(engine.is_settled_on(bob_peer));

    let msg0 = MessageView {
        index: 0,
        place: 1,
        outgoing: true,
        at: 100,
        body: Body::Text("hi".into()),
        delivery: Delivery::Sent,
    };
    engine.set_displayed_messages(bob_peer, vec![msg0.clone()], true);
    let sig0 = engine
        .ui()
        .messages
        .with_untracked(|rows| rows[0].delivery_signal)
        .expect("outgoing message has delivery signal");
    assert_eq!(sig0.get_untracked(), Delivery::Sent);

    let updated_entry = HistoryEntry {
        outgoing: true,
        at: 100,
        content: Some(Content {
            clock: 1,
            kind: Some(Kind::Text("hi".into())),
            events: None,
        }),
        delivery: Delivery::Read.into(),
        place: 1,
        ..HistoryEntry::default()
    };
    engine.show_changes(&inner, &bob_peer, &[(0, updated_entry)]);
    assert_eq!(sig0.get_untracked(), Delivery::Read);

    // Refreshing the same peer preserves `sig0` and updates its value in place.
    let mut msg0_downloaded = msg0;
    msg0_downloaded.delivery = Delivery::Downloaded;
    engine.set_displayed_messages(bob_peer, vec![msg0_downloaded], false);
    let sig0_after = engine
        .ui()
        .messages
        .with_untracked(|rows| rows[0].delivery_signal)
        .expect("reused delivery signal");
    assert_eq!(sig0, sig0_after);
    assert_eq!(sig0_after.get_untracked(), Delivery::Downloaded);

    engine.open_chat.clear_displayed_messages(&engine.ui());
    assert!(engine.ui().messages.with_untracked(Vec::is_empty));

    // 4. `show_dialog_if_changed` does not re-notify `ui.dialog` when `Dialog::SignIn` is already
    // open (preserving an active auto-starting `SignInDialog` and its reservation on greeting 403).
    let dialog_notifies = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dialog_signal = engine.ui().dialog;
    dialog_signal.set(Some(Dialog::SignIn));
    let memo_counter = dialog_notifies.clone();
    let observer = leptos::prelude::Memo::new(move |_| {
        let _ = dialog_signal.get();
        memo_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
    observer.get();
    assert_eq!(
        dialog_notifies.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    let submit_id_2 = engine.begin_new_chat_submit(PendingNewChat {
        key: "peer-key".into(),
        name: "Bob".into(),
        server: None,
        pq_pinned: false,
        allow_classical: false,
        auto_start: true,
    });
    engine.startup.set_in_flight_start_chat(submit_id_2, true);
    engine.refused_for_sign_in();
    observer.get();
    assert_eq!(engine.pending_auto_start_id(), None);
    assert_eq!(
        dialog_notifies.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "greeting-only 403 must not re-set Dialog::SignIn when already mounted"
    );

    // `require_sign_in_for_new_chat` must also avoid remounting an already-mounted SignInDialog,
    // and `clear_pending_new_chat` clears a stale auto-start draft without closing SignInDialog.
    let draft_3 = PendingNewChat {
        key: "peer-key".into(),
        name: "Bob".into(),
        server: None,
        pq_pinned: false,
        allow_classical: false,
        auto_start: true,
    };
    let submit_id_3 = engine.begin_new_chat_submit(draft_3.clone());
    engine.require_sign_in_for_new_chat(submit_id_3, draft_3);
    observer.get();
    assert_eq!(
        dialog_notifies.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "require_sign_in_for_new_chat must not remount an already-mounted Dialog::SignIn"
    );
    assert_eq!(engine.pending_auto_start_id(), Some(submit_id_3));
    engine.clear_pending_new_chat(submit_id_3);
    assert_eq!(engine.pending_auto_start_id(), None);
    assert!(!engine.is_submission_cancelled(submit_id_3));
    assert_eq!(engine.ui().dialog.get_untracked(), Some(Dialog::SignIn));

    // 5. Vault writes fail closed once `pagehide` marks the tab lock released.
    struct RestoreLock(bool);
    impl Drop for RestoreLock {
        fn drop(&mut self) {
            crate::glue::set_lock_released_for_test(self.0);
        }
    }
    let _restore = RestoreLock(crate::glue::set_lock_released_for_test(true));
    assert!(!crate::glue::owns_lock());
    assert!(futures::executor::block_on(inner.save(&[])).is_err());
}

#[test]
fn session_seq_is_monotonic_and_quarantined_carried_initial_not_restaged() {
    let mut client = Client::new(Fetch::client(TEST_SERVER));
    let (peer, incoming) = futures::executor::block_on(carried_initial(&mut client));
    let session = match client
        .accept_initial_v2(
            &peer,
            &Default::default(),
            &incoming,
            Fetch::client(TEST_SERVER),
        )
        .unwrap()
    {
        session::AcceptedInitial::Accepted { session, .. }
        | session::AcceptedInitial::Quarantined { session, .. } => session,
    };
    let mut inner = load_contacts(&client, vec![]);
    inner.contacts.push(super::contact::Contact {
        peer,
        session,
        deferred_carried: 0,
        state: ContactState {
            peer: peer.to_vec(),
            quarantined: true,
            quarantined_primary: false,
            ..ContactState::default()
        },
    });

    // Monotonic new-chat session_seq stays strictly above prior AppState floor (used by start_chat,
    // upgrade_to_pq, and seal_next so delete + inbound reconnect never reuses a low session_seq).
    let first = inner.next_new_chat_session_seq();
    assert!(first >= 1);
    inner.state.next_session_seq = first.saturating_add(500);
    let second = inner.next_new_chat_session_seq();
    assert!(second >= first + 500);
    let hello = inner.client.make_hello("Alice".to_string(), second);
    assert_eq!(hello.session_seq, second);

    // E3: `stage_carried_initials` skips a classical carried initial whose ephemeral key matches
    // an already-held `quarantined_session.id`, preventing a re-quarantine/re-stage loop.
    let classical_wire = session::protocol::handshake_v2::InitialMessageV2 {
        version: 1,
        identity_key: bytes::Bytes::from_static(&[7u8; 32]),
        ephemeral_key: bytes::Bytes::from_static(&[9u8; 32]),
        signed_prekey: bytes::Bytes::from_static(&[8u8; 32]),
        first_message: Some(Default::default()),
        ..Default::default()
    };
    let classical_init = session::InitialMessageV2::try_from(&classical_wire).unwrap();
    let mut q_state = ContactState {
        quarantined: true,
        quarantined_session: Some({
            let mut s = session::proto::SessionState::default();
            s.id = vec![9u8; 32];
            s
        }),
        ..ContactState::default()
    };
    super::handshake::stage_carried_initials(&mut q_state, [&classical_init]).unwrap();
    assert!(
        q_state.pending_carried_initials.is_empty(),
        "already-quarantined classical initial must not be re-staged"
    );
}

#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
#[test]
fn process_initial_enforces_quarantine_session_seq_high_water_mark() {
    use session::protocol::handshake_v2::ClaimBundleResponse;

    futures::executor::block_on(async {
        let mut recipient = Client::new(Fetch::client(TEST_SERVER));
        recipient
            .set_pq_config(PqConfig {
                pq_enabled: true,
                strict_pq: false,
                ..PqConfig::default()
            })
            .unwrap();
        let published = recipient.prepare_publish_v2("chat.example", 4, 0).unwrap();
        let p = published.request.clone();
        let make_classical_bundle = |opk_idx: usize| ClaimBundleResponse {
            signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: p.signed_prekey_signature.clone(),
            one_time_prekey: p.one_time_prekeys.get(opk_idx).cloned(),
            pq_last_resort: None,
            pq_one_time_prekey: None,
            manifest: p.manifest.clone(),
        };
        recipient.commit_publish_v2(published);

        let make_classical_initial = |sender_proto: &proto::ClientState,
                                      opk_idx: usize,
                                      seq: u64| {
            let bundle = make_classical_bundle(opk_idx);
            let mut sender = Client::restore(
                ConnectClient::new(BundleResponse("/ClaimBundle", bundle)),
                ClientState::try_from(sender_proto).unwrap(),
            );
            sender
                .set_pq_config(PqConfig {
                    pq_enabled: false,
                    pq_ratchet_enabled: false,
                    strict_pq: false,
                    ..PqConfig::default()
                })
                .unwrap();
            let greeting = Kind::Hello(sender.make_hello(format!("seq-{seq}"), seq)).to_bytes();
            let peer_id = recipient.identity_key();
            async move {
                let prepared = sender
                    .prepare_initiate_v2(
                        "chat.example",
                        &peer_id,
                        &Default::default(),
                        &greeting,
                        (),
                    )
                    .await
                    .unwrap();
                assert!(!prepared.security.is_pq);
                let msg = Incoming::try_from(prepared.request.message.as_ref().unwrap()).unwrap();
                (sender.identity_key(), msg, greeting)
            }
        };

        let sender_base = Client::new(Fetch::client(TEST_SERVER));
        let sender_proto = proto::ClientState::from(sender_base.state());

        let (peer, init_42, greeting_42) = make_classical_initial(&sender_proto, 0, 42).await;
        let (_, init_30, _) = make_classical_initial(&sender_proto, 1, 30).await;
        let (_, init_50, greeting_50) = make_classical_initial(&sender_proto, 2, 50).await;
        let (_, init_45, _) = make_classical_initial(&sender_proto, 3, 45).await;

        let engine = Engine::new(Ui::new());
        let mut inner = load_contacts(&recipient, vec![]);

        // 1. First classical initial creates a brand-new quarantined primary contact at seq 42.
        let mut batch = InitialBatch::default();
        engine.process_initial(&mut inner, &peer, &init_42, &mut batch);
        let contact = inner.contact(&peer).expect("quarantined contact created");
        assert!(contact.is_new_quarantined());
        assert_eq!(contact.session.active_peer_session_seq(), 42);
        assert_eq!(contact.state.quarantined_first_message, greeting_42);
        assert!(contact.state.quarantined_session.is_none());

        // 2. Stale classical initial (seq 30 <= 42) is rejected against primary high-water mark.
        engine.process_initial(&mut inner, &peer, &init_30, &mut batch);
        let contact = inner.contact(&peer).unwrap();
        assert!(contact.state.quarantined_session.is_none());
        assert_eq!(contact.state.quarantined_first_message, greeting_42);

        // 3. Newer classical initial (seq 50 > 42) updates the held quarantined session.
        engine.process_initial(&mut inner, &peer, &init_50, &mut batch);
        let contact = inner.contact(&peer).unwrap();
        assert!(contact.is_new_quarantined());
        assert_eq!(
            contact
                .state
                .quarantined_session
                .as_ref()
                .map(|s| s.active_peer_session_seq),
            Some(50)
        );
        assert_eq!(contact.state.quarantined_first_message, greeting_50);

        // 4. Stale classical initial (seq 45 <= 50) is rejected against held quarantined high-water.
        engine.process_initial(&mut inner, &peer, &init_45, &mut batch);
        let contact = inner.contact(&peer).unwrap();
        assert_eq!(
            contact
                .state
                .quarantined_session
                .as_ref()
                .map(|s| s.active_peer_session_seq),
            Some(50)
        );
        assert_eq!(contact.state.quarantined_first_message, greeting_50);
    });
}

#[test]
fn same_server_normalizes_default_ports_and_validate_relay_url_rejects_unsafe() {
    assert!(same_server(
        "https://chat.example.com:443",
        "https://chat.example.com"
    ));
    assert!(same_server(
        "https://CHAT.EXAMPLE.COM:443/",
        "https://chat.example.com"
    ));
    assert!(same_server("http://localhost:80", "http://localhost"));
    assert!(!same_server(
        "https://chat.example.com:8443",
        "https://chat.example.com"
    ));
    assert!(!same_server(
        "http://chat.example.com",
        "https://chat.example.com"
    ));
    assert!(!same_server("", ""));
    assert!(!same_server("not-a-url", "not-a-url"));

    assert_eq!(
        validate_relay_url("https://CHAT.example.com:443/").as_deref(),
        Ok("https://chat.example.com")
    );
    assert_eq!(
        validate_relay_url("http://localhost:8080/").as_deref(),
        Ok("http://localhost:8080")
    );
    assert_eq!(
        validate_relay_url("http://127.0.0.1:8787").as_deref(),
        Ok("http://127.0.0.1:8787")
    );
    for bad in [
        "",
        "http://evil.example.com",
        "ws://chat.example.com",
        "wss://chat.example.com",
        "javascript:alert(1)",
        "https://user:pass@chat.example.com",
        "https://chat.example.com/path",
        "https://chat.example.com/?q=1",
        "https://chat.example.com/#frag",
    ] {
        assert!(validate_relay_url(bad).is_err(), "expected Err for {bad:?}");
    }
}

#[test]
fn sanitize_shared_name_strips_unicode_format_bidi_controls_and_hello_and_invite_names() {
    // Strips Unicode Format (Cf) including BiDi overrides/isolates, ZWJ/ZWNJ, BOM, tag chars,
    // and Control (Cc) characters.
    let spoofing = "Al\u{200D}i\u{200C}ce\u{FEFF}\u{202E}txt.exe\u{2066}\u{E0061}\u{0007}  \tBob";
    assert_eq!(sanitize_shared_name(spoofing), "Alicetxt.exe Bob");

    // `Contact::add_received` sanitizes `Hello.name` into `hello_name` and `Contact::message`.
    let (mut inner, peer) = unlocked_client();
    let contact = inner.contact(&peer).unwrap();
    let (idx, entry) = contact
        .add_received(
            Content {
                clock: 1,
                kind: Some(Kind::Hello(Hello {
                    name: "  Mallory\u{202E}Admin\u{200B}\x00 ".into(),
                    ..Hello::default()
                })),
                events: None,
            },
            false,
        )
        .unwrap();
    assert_eq!(contact.state.hello_name, "MalloryAdmin");
    assert_eq!(
        contact.message(idx, entry).body,
        Body::Hello("MalloryAdmin".into())
    );

    // `parse_invitation_hash` sanitizes percent-encoded BiDi/control characters in `#name=`.
    let key = key_to_url(&[0x55u8; 32]);
    let hash = format!("#chat={key}&name=Bob%E2%80%AE%07%20%20Dev&pq=1");
    assert_eq!(
        parse_invitation_hash(&hash),
        Some(Dialog::NewChat {
            key,
            name: "Bob Dev".to_string(),
            server: None,
            pq_pinned: true,
        })
    );
}

#[test]
fn acked_ranges_caps_at_events_kept_by_coalescing_oldest_gaps() {
    let mut ranges = Vec::new();
    // Insert `EVENTS_KEPT + 25` disjoint single-index ranges (`[0,1), [2,3), [4,5), ...`).
    for i in 0..(EVENTS_KEPT as u64 + 25) {
        let start = i * 2;
        insert_acked_range(&mut ranges, start, start + 1);
        assert!(
            ranges.len() <= EVENTS_KEPT,
            "acked_ranges exceeded EVENTS_KEPT ({} > {})",
            ranges.len(),
            EVENTS_KEPT
        );
    }
    assert_eq!(ranges.len(), EVENTS_KEPT);
    // Oldest 25 gaps coalesced into ranges[0] = [0, 51), preserving every acknowledged index.
    assert_eq!(ranges[0].start, 0);
    assert_eq!(ranges[0].end, 51);
    assert_eq!(ranges.last().unwrap().start, (EVENTS_KEPT as u64 + 24) * 2);
}

#[test]
fn contact_told_bounds_dedups_and_settles_sealed_pending_outbox_entries() {
    let (mut inner, peer) = unlocked_client();
    let contact = inner.contact(&peer).unwrap();
    contact.state.awaiting = vec![
        Awaiting {
            place: 10,
            history_index: 1,
            read: false,
            attachment: false,
            content_digest: vec![],
        },
        Awaiting {
            place: 20,
            history_index: 2,
            read: false,
            attachment: true,
            content_digest: vec![],
        },
    ];
    // Sealed pending outbox entries (push succeeded on relay, ack lost locally) + unsealed entry.
    contact.state.outbox = vec![
        Outgoing {
            history_index: 3,
            sealed: true,
            clock: 30,
            awaits_upload: false,
            content_digest: vec![],
            dispatched: false,
        },
        Outgoing {
            history_index: 4,
            sealed: true,
            clock: 40,
            awaits_upload: false,
            content_digest: vec![],
            dispatched: false,
        },
        Outgoing {
            history_index: 5,
            sealed: false,
            clock: 0,
            awaits_upload: false,
            content_digest: vec![],
            dispatched: false,
        },
    ];

    // Flood incoming receipt list with duplicates + > EVENTS_KEPT clocks: clocks beyond
    // `EVENTS_KEPT` are capped, duplicates are deduplicated, and sealed outbox clocks 30 & 40
    // settle cleanly without dropping receipts.
    let mut read_clocks = vec![10, 10, 20, 30, 30];
    read_clocks.extend(1_000..(1_000 + EVENTS_KEPT as u64 + 50));
    let events = Events {
        read: read_clocks,
        downloaded: vec![40, 40],
        accepted: false,
    };
    let outcome = contact.told(&events);
    assert_eq!(
        outcome.steps,
        vec![
            (1, Step::Read),
            (2, Step::Read),
            (3, Step::Read),
            (4, Step::Downloaded),
        ]
    );
    assert_eq!(outcome.settled_outbox, vec![(3, 30), (4, 40)]);
    assert_eq!(contact.state.read_by_peer, 40);
    // Sealed outbox entries 3 and 4 are retired; unsealed entry 5 stays queued.
    assert_eq!(contact.state.outbox.len(), 1);
    assert_eq!(contact.state.outbox[0].history_index, 5);
    // Attachment #2 and tentatively tracked #3 remain in `awaiting` with `read = true` so peer
    // chat deletion will never requeue them, while a later `Downloaded` receipt still settles #3.
    assert!(contact.state.awaiting.iter().all(|a| a.read));
    let dl = contact.told(&Events {
        read: vec![],
        downloaded: vec![20, 30],
        accepted: false,
    });
    assert_eq!(dl.steps, vec![(2, Step::Downloaded), (3, Step::Downloaded)]);
    assert!(contact.state.awaiting.is_empty());

    // `tell_downloaded` deduplicates repeated final-chunk notifications.
    assert!(contact.tell_downloaded(77));
    assert!(!contact.tell_downloaded(77));
    assert_eq!(
        contact.state.events.as_ref().map(|e| e.downloaded.clone()),
        Some(vec![77])
    );
}

#[test]
fn stream_mime_accepts_codec_params_and_rejects_non_media_or_malformed() {
    assert_eq!(stream_mime("video/mp4; codecs=avc1"), "video/mp4");
    assert_eq!(stream_mime("audio/webm; codecs=opus"), "audio/webm");
    assert_eq!(
        stream_mime("VIDEO/MP4; codecs=\"avc1.42E01E, mp4a.40.2\""),
        "video/mp4"
    );
    assert_eq!(
        stream_mime("text/html; codecs=avc1"),
        "application/octet-stream"
    );
    assert_eq!(
        stream_mime("application/javascript"),
        "application/octet-stream"
    );
    assert_eq!(stream_mime("video/mp4; bad"), "application/octet-stream");
    assert_eq!(
        stream_mime("video/mp4; codecs=\"bad\r\nheader: 1\""),
        "application/octet-stream"
    );
}

#[test]
fn start_chat_rejects_foreign_and_invalid_relay_before_contact_lookup() {
    assert!(validate_start_chat_server(None, "https://chat.example.com").is_ok());
    assert!(validate_start_chat_server(Some("  "), "https://chat.example.com").is_ok());
    assert!(
        validate_start_chat_server(
            Some("https://CHAT.example.com:443/"),
            "https://chat.example.com"
        )
        .is_ok()
    );
    let foreign = validate_start_chat_server(
        Some("https://other.example.com"),
        "https://chat.example.com",
    )
    .unwrap_err();
    assert!(
        matches!(foreign, StartChatError::Other(ref msg) if msg.contains("different server")),
        "{foreign:?}"
    );
    let invalid =
        validate_start_chat_server(Some("ws://chat.example.com"), "https://chat.example.com")
            .unwrap_err();
    assert!(
        matches!(invalid, StartChatError::Other(ref msg) if msg.contains("Invalid invitation server")),
        "{invalid:?}"
    );
}

#[test]
fn settings_unimplemented_returns_err_and_rollback_preserves_contact_flags() {
    // 1. Definitive `ErrorKind::Unimplemented` returns `Err(message)`, NOT SavedLocallyPendingPublish.
    let unimpl = PublishError::transmitted(
        protocol::Error::new(protocol::ErrorKind::Unimplemented, "upgrade client").into(),
    );
    let err = classify_set_pq_publish_result(Err(unimpl)).unwrap_err();
    assert!(err.contains("upgrade client"), "{err}");

    let transient = PublishError::transmitted(session::Error::from(ErrorKind::Server));
    assert_eq!(
        classify_set_pq_publish_result(Err(transient)),
        Ok(PqSaveOutcome::SavedLocallyPendingPublish)
    );
    let sign_in = PublishError::transmitted(
        protocol::Error::from(protocol::ErrorKind::SignInRequired).into(),
    );
    assert_eq!(
        classify_set_pq_publish_result(Err(sign_in)),
        Ok(PqSaveOutcome::SavedLocallyNeedsSignIn)
    );

    // 2. Rejected PQ settings rollback restores per-contact `security_alert` and
    // `classical_approval_needed` flags cleared by `save_pq_config`.
    #[cfg(any(feature = "ml-kem-768", feature = "ml-kem-1024"))]
    futures::executor::block_on(async {
        use crate::vault::{
            CLASSICAL_APPROVAL_NONE, CLASSICAL_APPROVAL_SIGNED_OFF, SECURITY_ALERT_NONE,
            SECURITY_ALERT_PQ_REQUIRED,
        };

        let engine = Engine::new(Ui::new());
        let (mut inner, peer) = unlocked_client();
        inner
            .client
            .set_pq_config(PqConfig {
                pq_enabled: true,
                strict_pq: true,
                ..PqConfig::default()
            })
            .unwrap();
        {
            let contact = inner.contact(&peer).unwrap();
            contact.state.security_alert = SECURITY_ALERT_PQ_REQUIRED;
            contact.state.classical_approval_needed = CLASSICAL_APPROVAL_SIGNED_OFF;
        }
        inner.save(&[]).await.unwrap();

        inner
            .save_pq_config(PqConfig {
                pq_enabled: false,
                strict_pq: false,
                pq_ratchet_enabled: false,
                ..PqConfig::default()
            })
            .await
            .unwrap();
        {
            let contact = inner.contact(&peer).unwrap();
            assert_eq!(contact.state.security_alert, SECURITY_ALERT_NONE);
            assert_eq!(
                contact.state.classical_approval_needed,
                CLASSICAL_APPROVAL_NONE
            );
        }

        let refusal =
            PublishError::transmitted(protocol::Error::from(protocol::ErrorKind::Malformed).into());
        assert!(
            engine
                .finish_publish_rollback(&mut inner, refusal, true)
                .await
                .unwrap_err()
                .rejects_settings()
        );
        let contact = inner.contact(&peer).unwrap();
        assert_eq!(contact.state.security_alert, SECURITY_ALERT_PQ_REQUIRED);
        assert_eq!(
            contact.state.classical_approval_needed,
            CLASSICAL_APPROVAL_SIGNED_OFF
        );
    });
}

#[test]
fn is_cancelled_and_delete_purge_sending_and_opening_state() {
    use leptos::prelude::Set;

    let ui = Ui::new();
    let engine = Engine::new(ui);
    let peer_a = [0x11u8; 32];
    let peer_b = [0x22u8; 32];
    let id_a = [0xAAu8; 16];
    let id_b = [0xBBu8; 16];

    assert!(!engine.is_cancelled(&id_a));
    engine.uploads.mark_cancelled(id_a);
    assert!(engine.is_cancelled(&id_a));
    assert!(!engine.is_cancelled(&id_b));

    engine
        .queue
        .push_sending(Sending::Content(peer_a, Kind::Text("stale".into())));
    engine
        .queue
        .push_sending(Sending::Content(peer_b, Kind::Text("keep".into())));
    ui.opening.set(Some(Opening {
        token: 7,
        peer: peer_a,
        id: id_a,
        name: "doc.pdf".into(),
        size: 1024,
        done: 0,
        waiting: false,
    }));

    engine.purge_peer_transient_state(&peer_a);
    assert_eq!(engine.queue.sending_peers(), vec![peer_b]);
    assert!(ui.opening.get_untracked().is_none());

    // Purging `peer_a` when `ui.opening` belongs to `peer_b` leaves `peer_b`'s opening intact.
    ui.opening.set(Some(Opening {
        token: 8,
        peer: peer_b,
        id: id_b,
        name: "keep.pdf".into(),
        size: 2048,
        done: 0,
        waiting: false,
    }));
    engine.purge_peer_transient_state(&peer_a);
    assert_eq!(ui.opening.get_untracked().map(|o| o.peer), Some(peer_b));
}

#[test]
fn expected_chunk_len_validates_non_last_and_last_chunk_boundaries() {
    use session::attachment::CHUNK_SIZE;

    assert_eq!(expected_chunk_len(0, 0, 1), Some(0));
    assert_eq!(expected_chunk_len(0, 0, 0), None);
    assert_eq!(expected_chunk_len(123, 0, 1), Some(123));
    assert_eq!(
        expected_chunk_len(CHUNK_SIZE as u64, 0, 1),
        Some(CHUNK_SIZE)
    );
    assert_eq!(
        expected_chunk_len(CHUNK_SIZE as u64 + 1, 0, 2),
        Some(CHUNK_SIZE)
    );
    assert_eq!(expected_chunk_len(CHUNK_SIZE as u64 + 1, 1, 2), Some(1));
    assert_eq!(expected_chunk_len(CHUNK_SIZE as u64 + 1, 2, 2), None);
    // Spoofed chunk count exceeding total_size is rejected.
    assert_eq!(expected_chunk_len(100, 0, 2), None);
    assert_eq!(expected_chunk_len(100, 1, 2), None);
}

#[test]
fn resume_verifier_checks_prefix_and_sealed_chunk_hash_and_guards_upload_digests() {
    use session::attachment::CHUNK_SIZE;
    use sha2::{Digest, Sha256};

    let chunk0 = vec![0x11u8; CHUNK_SIZE];
    let chunk1 = vec![0x22u8; 512];
    let total_size = (chunk0.len() + chunk1.len()) as u64;
    let mut prefix = Sha256::new();
    prefix.update(&chunk0);
    prefix.update(&chunk1);
    let prefix_hash = prefix.finalize().to_vec();
    let sealed_chunk_hash = Sha256::digest(&chunk1).to_vec();

    let pending = PendingUpload {
        id: vec![0xAA; 16],
        token: vec![0xBB; 16],
        key: vec![0xCC; 32],
        name: "clip.mp4".into(),
        mime: "video/mp4".into(),
        size: total_size,
        uploaded: 1,
        encrypted: 2,
        prefix_hash,
        announced: true,
        history_index: 0,
        expires: 0,
        upload_state: UPLOAD_STATE_STARTED,
        sealed_chunk_hash,
    };

    // Valid resume returns verified chunk 1 bytes + digest; `Upload` allows encrypting identical
    // chunk 1, rejects modified chunk 1 with `NonceReuse`, and rejects already-uploaded chunk 0.
    let mut verifier = ResumeVerifier::new(&pending, total_size).unwrap();
    verifier.push_chunk(chunk0.clone()).unwrap();
    verifier.push_chunk(chunk1.clone()).unwrap();
    let verified = verifier.finish().unwrap();
    assert_eq!(
        verified.verified_chunks.get(&1).map(|v| v.as_slice()),
        Some(chunk1.as_slice())
    );
    let upload = upload_of_with_digests(&pending, verified.digests).unwrap();
    assert!(upload.try_encrypt(1, &chunk1).is_ok());
    let mut tampered = chunk1.clone();
    tampered[0] ^= 0xFF;
    assert_eq!(
        upload.try_encrypt(1, &tampered).unwrap_err().kind(),
        ErrorKind::NonceReuse
    );
    assert_eq!(
        upload.try_encrypt(0, &chunk0).unwrap_err().kind(),
        ErrorKind::NonceReuse
    );

    // Tampered chunk 1 fails `ResumeVerifier` immediately on `sealed_chunk_hash` mismatch.
    let mut bad_verifier = ResumeVerifier::new(&pending, total_size).unwrap();
    bad_verifier.push_chunk(chunk0).unwrap();
    assert!(bad_verifier.push_chunk(tampered).is_err());

    // Wrong file size is rejected upfront.
    assert!(ResumeVerifier::new(&pending, total_size + 1).is_err());
}

#[test]
fn recover_corrupt_outbox_rebuilds_from_history_or_drops_and_marks_failed() {
    futures::executor::block_on(async {
        let (mut inner, peer) = unlocked_client();
        let mut w0 = waiting(0, true);
        w0.content_digest =
            crate::vault::content_kind_digest(&Kind::Text("recoverable message".into()).to_bytes());
        inner.contacts[0].state.outbox = vec![w0, waiting(1, true), waiting(2, false)];
        inner
            .vault
            .entries
            .borrow_mut()
            .insert((peer, 0), history("recoverable message"));
        // Entry 1 has missing content (unrecoverable), so it must be dropped & marked Failed.
        inner.vault.entries.borrow_mut().insert(
            (peer, 1),
            HistoryEntry {
                outgoing: true,
                delivery: Delivery::Pending.into(),
                content: None,
                ..Default::default()
            },
        );
        inner.save(&[]).await.unwrap();

        match inner.recover_corrupt_outbox(&peer, 0).await.unwrap() {
            CorruptOutboxRecovery::Rebuilt(bytes) => {
                assert_eq!(bytes, Kind::Text("recoverable message".into()).to_bytes());
            }
            CorruptOutboxRecovery::Dropped { .. } => panic!("expected rebuild from intact history"),
        }
        assert!(!inner.contacts[0].state.outbox[0].sealed);
        assert_eq!(inner.contacts[0].state.outbox[0].clock, 0);
        assert!(inner.vault.outbox.borrow().contains_key(&(peer, 0)));

        match inner.recover_corrupt_outbox(&peer, 1).await.unwrap() {
            CorruptOutboxRecovery::Dropped { history } => {
                assert_eq!(history.len(), 1);
                assert_eq!(history[0].0, 1);
                assert_eq!(history[0].1.delivery(), Delivery::Failed);
            }
            CorruptOutboxRecovery::Rebuilt(_) => {
                panic!("expected drop when history content absent")
            }
        }
        assert_eq!(
            inner.contacts[0]
                .state
                .outbox
                .iter()
                .map(|o| o.history_index)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
        assert_eq!(
            inner.vault.entries.borrow()[&(peer, 1)].delivery(),
            Delivery::Failed
        );
    });
}

#[test]
fn last_message_preview_formats_sanitizes_and_orders_all_entry_kinds() {
    use super::contact::{LAST_MESSAGE_PREVIEW_MAX_CHARS, latest_entry_preview, preview_for_entry};
    use crate::content::{AttachmentPointer, Contact as SharedContactProto, Deleted, File};
    use crate::state::{LastMessage, LastMessageKind};
    use session::protocol::content::Hello;

    let entry_of = |outgoing: bool, kind: Option<Kind>| HistoryEntry {
        outgoing,
        content: Some(Content {
            clock: 1,
            kind,
            events: None,
        }),
        ..HistoryEntry::default()
    };
    let expected = |kind: LastMessageKind, outgoing: bool, text: &str| {
        Some(LastMessage {
            kind,
            outgoing,
            text: text.to_string(),
        })
    };

    // Text: whitespace collapse, BiDi/control stripping, ZWJ emoji preserved, outgoing flag, truncation.
    assert_eq!(
        preview_for_entry(&entry_of(
            false,
            Some(Kind::Text(
                "  Hello\n\tworld \u{202E}rtl\x07 👩\u{200D}💻  ".into()
            ))
        ))
        .to_view(),
        expected(LastMessageKind::Text, false, "Hello world rtl 👩\u{200D}💻")
    );
    assert_eq!(
        preview_for_entry(&entry_of(true, Some(Kind::Text("On my way".into())))).to_view(),
        expected(LastMessageKind::Text, true, "On my way")
    );
    // Plain text mimicking media labels stays strictly `LastMessageKind::Text` (cannot spoof badges).
    assert_eq!(
        preview_for_entry(&entry_of(
            false,
            Some(Kind::Text("Photo - super girl.jpeg".into()))
        ))
        .to_view(),
        expected(LastMessageKind::Text, false, "Photo - super girl.jpeg")
    );
    assert_eq!(
        preview_for_entry(&entry_of(false, Some(Kind::Text("   \n\t  ".into())))).to_view(),
        expected(LastMessageKind::Text, false, "")
    );
    let long = preview_for_entry(&entry_of(true, Some(Kind::Text("a".repeat(200)))))
        .to_view()
        .expect("long text preview");
    assert_eq!(long.kind, LastMessageKind::Text);
    assert!(long.outgoing);
    assert!(long.text.ends_with('…'));
    assert_eq!(long.text.chars().count(), LAST_MESSAGE_PREVIEW_MAX_CHARS);

    // Media, inline files (both live bytes and vaulted `file > 0` + `entry.media`), attachments, contacts.
    assert_eq!(
        preview_for_entry(&entry_of(true, Some(Kind::Image(vec![1, 2, 3])))).to_view(),
        expected(LastMessageKind::Image, true, "")
    );
    let mut vaulted_video = entry_of(
        false,
        Some(Kind::File(File {
            name: "clip_\u{202E}gpj.mp4".into(),
            mime: String::new(),
            data: Vec::new(),
        })),
    );
    vaulted_video.file = 4096;
    vaulted_video.media = "video/mp4".into();
    assert_eq!(
        preview_for_entry(&vaulted_video).to_view(),
        expected(LastMessageKind::Video, false, "clip_gpj.mp4")
    );

    assert_eq!(
        preview_for_entry(&entry_of(
            true,
            Some(Kind::Attachment(AttachmentPointer {
                id: vec![1; 16],
                key: vec![2; 32],
                size: 1024,
                name: "report.pdf".into(),
                mime: "application/pdf".into(),
                expires: 0,
            }))
        ))
        .to_view(),
        expected(LastMessageKind::File, true, "report.pdf")
    );
    assert_eq!(
        preview_for_entry(&entry_of(
            false,
            Some(Kind::Attachment(AttachmentPointer {
                id: vec![1; 16],
                key: vec![2; 32],
                size: 1024,
                name: "track.flac".into(),
                mime: "audio/flac".into(),
                expires: 0,
            }))
        ))
        .to_view(),
        expected(LastMessageKind::Audio, false, "track.flac")
    );
    assert_eq!(
        preview_for_entry(&entry_of(
            true,
            Some(Kind::Contact(SharedContactProto {
                key: vec![0xab; 32],
                name: "Bob\u{202E}".into(),
                pq_pinned: true,
            }))
        ))
        .to_view(),
        expected(LastMessageKind::Contact, true, "Bob")
    );
    // Malformed shared-contact keys fall back to `Unknown` just like `Contact::message()`.
    assert_eq!(
        preview_for_entry(&entry_of(
            false,
            Some(Kind::Contact(SharedContactProto {
                key: vec![0xab; 4],
                name: "Spoof".into(),
                pq_pinned: false,
            }))
        ))
        .to_view(),
        expected(LastMessageKind::Unknown, false, "")
    );

    // Notes: Hello, Deleted, Evicted, Unknown.
    assert_eq!(
        preview_for_entry(&entry_of(true, Some(Kind::Hello(Hello::default())))).to_view(),
        expected(LastMessageKind::Hello, true, "")
    );
    assert_eq!(
        preview_for_entry(&entry_of(false, Some(Kind::Hello(Hello::default())))).to_view(),
        expected(LastMessageKind::Hello, false, "")
    );
    assert_eq!(
        preview_for_entry(&entry_of(false, Some(Kind::Deleted(Deleted {})))).to_view(),
        expected(LastMessageKind::Deleted, false, "")
    );
    let evicted = HistoryEntry {
        evicted: true,
        ..HistoryEntry::default()
    };
    assert_eq!(
        preview_for_entry(&evicted).to_view(),
        expected(LastMessageKind::Evicted, false, "")
    );
    assert_eq!(
        preview_for_entry(&entry_of(false, None)).to_view(),
        expected(LastMessageKind::Unknown, false, "")
    );

    // `latest_entry_preview` picks the bottom-most message in chat display order.
    let me = [1u8; 32];
    let peer = [2u8; 32];
    let mut older_stamped = entry_of(false, Some(Kind::Text("earlier".into())));
    older_stamped.place = 5;
    let mut newer_stamped = entry_of(false, Some(Kind::Text("newer".into())));
    newer_stamped.place = 8;
    assert_eq!(
        latest_entry_preview(
            &[(0, newer_stamped.clone()), (1, older_stamped.clone())],
            &me,
            &peer
        )
        .and_then(|rec| rec.to_view()),
        expected(LastMessageKind::Text, false, "newer")
    );
    let pending_outgoing = entry_of(true, Some(Kind::Text("sending now".into())));
    assert_eq!(
        latest_entry_preview(&[(0, newer_stamped), (1, pending_outgoing)], &me, &peer)
            .and_then(|rec| rec.to_view()),
        expected(LastMessageKind::Text, true, "sending now")
    );
}

#[test]
fn contact_updates_and_zeroizes_last_message_on_send_receive_and_evict() {
    use crate::state::{LastMessage, LastMessageKind};
    use session::protocol::content::Hello;

    let (mut inner, _peer) = unlocked_client();
    let contact = &mut inner.contacts[0];

    let outgoing = history("first outbound");
    contact.record_last_message(&outgoing);
    assert_eq!(
        contact.view().last_message,
        Some(LastMessage {
            kind: LastMessageKind::Text,
            outgoing: true,
            text: "first outbound".into(),
        })
    );

    contact
        .add_received(
            Content {
                clock: 2,
                kind: Some(Kind::Text("peer reply".into())),
                events: None,
            },
            false,
        )
        .unwrap();
    assert_eq!(
        contact.view().last_message,
        Some(LastMessage {
            kind: LastMessageKind::Text,
            outgoing: false,
            text: "peer reply".into(),
        })
    );

    contact.add_evicted().unwrap();
    assert_eq!(
        contact.view().last_message,
        Some(LastMessage {
            kind: LastMessageKind::Evicted,
            outgoing: false,
            text: String::new(),
        })
    );

    let mut fresh = ContactState::default();
    let _ =
        finalize_upgrade_to_pq_request_state(&mut fresh, Kind::Hello(Hello::default()), 1, 1234);
    assert_eq!(
        fresh.last_message.as_ref().and_then(|m| m.to_view()),
        Some(LastMessage {
            kind: LastMessageKind::Hello,
            outgoing: true,
            text: String::new(),
        })
    );

    // Zeroize wipes text, kind, outgoing, and clears the Option.
    contact.record_last_message(&outgoing);
    contact.state.zeroize_secrets();
    assert!(contact.state.last_message.is_none());
}

#[cfg(not(target_arch = "wasm32"))]
const LOCAL_SERVER: &str = "http://localhost";

/// Construct an unlocked `Engine<MemoryVault>` on `http://localhost` with one active established
/// session to `bob_peer` (with `GREETING_DELIVERY_CONFIRMED`), ready for deterministic native
/// async tests using [`crate::transport::mock_fetch`].
#[cfg(not(target_arch = "wasm32"))]
async fn established_engine_on_localhost()
-> (std::rc::Rc<Engine<MemoryVault>>, PublicKey, Client<Connect>) {
    use crate::vault::GREETING_DELIVERY_CONFIRMED;

    let mut bob = Client::new(Fetch::client(LOCAL_SERVER));
    let bob_peer = bob.identity_key();
    let published = bob.prepare_publish_v2("localhost", 2, 2).unwrap();
    let p = &published.request;
    let bundle = protocol::handshake_v2::ClaimBundleResponse {
        signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
        signed_prekey_signature: p.signed_prekey_signature.clone(),
        one_time_prekey: p.one_time_prekeys.first().cloned(),
        pq_last_resort: p.pq_last_resort.first().cloned(),
        pq_one_time_prekey: p.pq_one_time_prekeys.first().cloned(),
        manifest: p.manifest.clone(),
    };
    bob.commit_publish_v2(published);

    let mut alice_boot = Client::new(ConnectClient::new(BundleResponse("/ClaimBundle", bundle)));
    let prepared = alice_boot
        .prepare_initiate_v2(
            "localhost",
            &bob_peer,
            &Default::default(),
            &Kind::Text("init".into()).to_bytes(),
            Fetch::client(LOCAL_SERVER),
        )
        .await
        .unwrap();
    let alice_state = ClientState::try_from(&proto::ClientState::from(alice_boot.state())).unwrap();
    let alice = Client::restore(Fetch::client(LOCAL_SERVER), alice_state);
    let contact = super::contact::Contact {
        peer: bob_peer,
        session: prepared.session,
        deferred_carried: 0,
        state: ContactState {
            peer: bob_peer.to_vec(),
            name: "Bob".into(),
            greeting_delivery: GREETING_DELIVERY_CONFIRMED,
            ..ContactState::default()
        },
    };
    let inner = Inner::new(
        MemoryVault::default(),
        LOCAL_SERVER.into(),
        "localhost".into(),
        AppState {
            name: "Alice".into(),
            ..AppState::default()
        },
        alice,
        vec![contact],
        vec![],
        DeferredRecord::default(),
    );
    let engine = Engine::with_inner(Ui::new(), inner);
    (engine, bob_peer, bob)
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn engine_open_and_load_earlier_paginates_and_acknowledges_only_displayed_pages() {
    use leptos::prelude::WithUntracked;
    use std::rc::Rc;

    futures::executor::block_on(async {
        let pushed_receipts = Rc::new(Cell::new(0usize));
        let pushed_counter = pushed_receipts.clone();
        let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
            if path.ends_with("/PushV2") {
                pushed_counter.set(pushed_counter.get() + 1);
                Ok((
                    200,
                    protocol::mailbox_v2::PushV2Response { sequence: 1 }.encode_to_vec(),
                ))
            } else {
                Err(protocol::Error::new(
                    protocol::ErrorKind::Unimplemented,
                    format!("unexpected path {path}"),
                ))
            }
        });

        let (engine, peer, _bob) = established_engine_on_localhost().await;
        let total = HISTORY_SHOWN + 15;
        let me = {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let me = inner.client.identity_key();
            let mut records = Vec::with_capacity(total as usize);
            {
                let contact = inner.contact(&peer).unwrap();
                for i in 0..total {
                    let clock = i + 1;
                    let (idx, entry) = contact
                        .add_received(
                            Content {
                                clock,
                                kind: Some(Kind::Text(format!("msg-{i}"))),
                                events: None,
                            },
                            false,
                        )
                        .unwrap();
                    records.push((peer, idx, entry));
                }
            }
            inner.save(&records).await.unwrap();
            me
        };

        // Self-peer and unknown peer are ignored cleanly.
        assert_eq!(engine.open(Some(me)).await, OpenOutcome::Ignored);
        assert_eq!(engine.open(Some(identity())).await, OpenOutcome::Ignored);

        // Opening the chat loads only the tail `HISTORY_SHOWN` entries, acknowledges only those
        // entries, and leaves the 15 older messages unread until `load_earlier` fetches them.
        assert_eq!(engine.open(Some(peer)).await, OpenOutcome::Opened);
        assert_eq!(engine.ui().open.get_untracked(), Some(peer));
        assert_eq!(
            engine.ui().messages.with_untracked(Vec::len),
            HISTORY_SHOWN as usize
        );
        assert!(engine.ui().has_older_messages.get_untracked());
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let contact = inner.contacts.iter().find(|c| c.peer == peer).unwrap();
            assert_eq!(contact.state.unread, 15);
            assert_eq!(contact.state.unseen.len(), 15);
            assert_eq!(contact.state.unseen[0], 1);
            assert_eq!(*contact.state.unseen.last().unwrap(), 15);
        }
        assert_eq!(
            pushed_receipts.get(),
            1,
            "tail read receipt should flush via PushV2"
        );

        // Loading the earlier page prepends the remaining 15 entries and clears remaining unread.
        assert_eq!(engine.load_earlier(peer).await, Ok(true));
        assert_eq!(
            engine.ui().messages.with_untracked(Vec::len),
            total as usize
        );
        assert!(!engine.ui().has_older_messages.get_untracked());
        assert_eq!(engine.ui().messages.with_untracked(|rows| rows[0].index), 0);
        assert_eq!(
            engine
                .ui()
                .messages
                .with_untracked(|rows| rows.last().unwrap().index),
            total - 1
        );
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let contact = inner.contacts.iter().find(|c| c.peer == peer).unwrap();
            assert_eq!(contact.state.unread, 0);
            assert!(contact.state.unseen.is_empty());
            assert_eq!(
                contact.state.events.as_ref().map(|e| e.read.len()),
                Some(15)
            );
        }
        // Further pagination at start of history is a clean no-op.
        assert_eq!(engine.load_earlier(peer).await, Ok(false));

        // Closing returns to the chat list cleanly.
        assert_eq!(engine.open(None).await, OpenOutcome::Opened);
        assert_eq!(engine.ui().open.get_untracked(), None);
        assert!(engine.ui().messages.with_untracked(Vec::is_empty));

        // Fault injection on `VaultStore::history` opens with empty rows without clearing unread.
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let mut extra = Vec::new();
            {
                let contact = inner.contact(&peer).unwrap();
                for n in 0..3u64 {
                    let clock = total + 1 + n;
                    let (idx, entry) = contact
                        .add_received(
                            Content {
                                clock,
                                kind: Some(Kind::Text(format!("unread-{n}"))),
                                events: None,
                            },
                            false,
                        )
                        .unwrap();
                    extra.push((peer, idx, entry));
                }
            }
            inner.save_with(&extra, &[]).await.unwrap();
            inner.vault.fail_history.set(true);
        }
        assert_eq!(engine.open(Some(peer)).await, OpenOutcome::Opened);
        assert!(engine.ui().messages.with_untracked(Vec::is_empty));
        assert!(!engine.ui().has_older_messages.get_untracked());
        assert!(engine.ui().notice.get_untracked().is_some());
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let contact = inner.contacts.iter().find(|c| c.peer == peer).unwrap();
            assert_eq!(contact.state.unread, 3);
            assert_eq!(contact.state.unseen.len(), 3);
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn streaming_media_range_and_stream_chunk_decrypt_cache_and_fault_injection() {
    use crate::content::AttachmentPointer;
    use crate::glue::{MediaError, MediaRange};
    use session::attachment::{CHUNK_SIZE, encrypt_chunk};
    use std::rc::Rc;

    futures::executor::block_on(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;

        let id = [0x42u8; 16];
        let key = [0x7Au8; session::attachment::KEY_LENGTH];
        let mut chunk0_plain = vec![0xA1u8; CHUNK_SIZE];
        chunk0_plain[..4].copy_from_slice(b"OggS");
        for (i, byte) in chunk0_plain[4..64].iter_mut().enumerate() {
            *byte = i as u8;
        }
        let chunk1_plain: Vec<u8> = (0u8..64).map(|b| b.wrapping_mul(3)).collect();
        let total_size = (chunk0_plain.len() + chunk1_plain.len()) as u64;
        let ct0 = encrypt_chunk(&key, &id, 0, false, &chunk0_plain);
        let ct1 = encrypt_chunk(&key, &id, 1, true, &chunk1_plain);

        let get_counts: Rc<RefCell<HashMap<u32, usize>>> = Rc::default();
        let push_count = Rc::new(Cell::new(0usize));
        let counts_ref = get_counts.clone();
        let push_ref = push_count.clone();
        let ct0_net = ct0.clone();
        let ct1_net = ct1.clone();
        let _mock = crate::transport::mock_fetch(move |_server, path, body| {
            if path.ends_with("/GetChunk") {
                let req = protocol::attachment::GetChunkRequest::decode(body.as_slice()).unwrap();
                *counts_ref.borrow_mut().entry(req.index).or_insert(0) += 1;
                let data = match req.index {
                    0 => ct0_net.clone(),
                    1 => ct1_net.clone(),
                    other => panic!("unexpected chunk index {other}"),
                };
                Ok((
                    200,
                    protocol::attachment::GetChunkResponse {
                        data: data.into(),
                        uploaded: true,
                    }
                    .encode_to_vec(),
                ))
            } else if path.ends_with("/PushV2") {
                push_ref.set(push_ref.get() + 1);
                Ok((
                    200,
                    protocol::mailbox_v2::PushV2Response { sequence: 1 }.encode_to_vec(),
                ))
            } else {
                Err(protocol::Error::new(
                    protocol::ErrorKind::Unimplemented,
                    format!("unexpected path {path}"),
                ))
            }
        });

        let pointer = AttachmentPointer {
            id: id.to_vec(),
            key: key.to_vec(),
            size: total_size,
            name: "track.ogg".into(),
            mime: "audio/ogg".into(),
            expires: 0,
        };
        let url = engine
            .stream(peer, 0, &pointer, 7)
            .await
            .expect("native glue::streaming() enables streaming URL");
        let token = url.strip_prefix("/media/").unwrap();
        let not_aborted = || false;

        // 1. First range fetch hits server for chunk 0, caches in vault & LRU decrypted cache.
        let (size, start, mime, slice0) = engine
            .media_range(
                token,
                &MediaRange::From {
                    start: 0,
                    end: Some(15),
                },
                &not_aborted,
            )
            .await
            .ok()
            .expect("first range succeeds");
        assert_eq!(size, total_size);
        assert_eq!(start, 0);
        assert_eq!(mime, "audio/ogg");
        assert_eq!(slice0, &chunk0_plain[..16]);
        assert_eq!(get_counts.borrow().get(&0).copied(), Some(1));
        let key_hash = super::attachment_key_hash(&key);
        assert!(engine.decrypted_chunk(&(peer, id, key_hash, 0)).is_some());

        // 2. Second range in chunk 0 serves directly from in-memory LRU cache (0 extra RPCs).
        let (_, start2, _, slice1) = engine
            .media_range(
                token,
                &MediaRange::From {
                    start: 16,
                    end: Some(31),
                },
                &not_aborted,
            )
            .await
            .ok()
            .expect("LRU cache hit succeeds");
        assert_eq!(start2, 16);
        assert_eq!(slice1, &chunk0_plain[16..32]);
        assert_eq!(get_counts.borrow().get(&0).copied(), Some(1));

        // 3. After evicting the plaintext LRU cache, chunk 0 still serves from MemoryVault without
        //    re-fetching from the server.
        engine.media.clear_decrypted_cache();
        let (_, start3, _, slice2) = engine
            .media_range(
                token,
                &MediaRange::From {
                    start: 32,
                    end: Some(47),
                },
                &not_aborted,
            )
            .await
            .ok()
            .expect("vault chunk cache hit succeeds");
        assert_eq!(start3, 32);
        assert_eq!(slice2, &chunk0_plain[32..48]);
        assert_eq!(get_counts.borrow().get(&0).copied(), Some(1));

        // 4. Fault-injecting `fail_put_chunk` fails chunk 1 persistence cleanly with HTTP 502.
        {
            let guard = engine.inner.lock().await;
            guard.as_ref().unwrap().vault.fail_put_chunk.set(true);
        }
        assert!(matches!(
            engine
                .media_range(token, &MediaRange::Suffix(32), &not_aborted)
                .await,
            Err(MediaError::Status(502))
        ));
        assert_eq!(get_counts.borrow().get(&1).copied(), Some(1));
        {
            let guard = engine.inner.lock().await;
            guard.as_ref().unwrap().vault.fail_put_chunk.set(false);
        }

        // 5. Clearing `fail_put_chunk` lets Suffix(32) fetch chunk 1, complete `all_kept`, and
        //    trigger the `downloaded` receipt for message clock 7.
        let (_, suffix_start, _, suffix_bytes) = engine
            .media_range(token, &MediaRange::Suffix(32), &not_aborted)
            .await
            .ok()
            .expect("suffix range on chunk 1 succeeds");
        assert_eq!(suffix_start, total_size - 32);
        assert_eq!(suffix_bytes, &chunk1_plain[32..64]);
        assert_eq!(get_counts.borrow().get(&1).copied(), Some(2));
        let fetching = engine.media.stream_fetching(token).unwrap();
        assert!(engine.all_kept(&fetching).await);
        assert_eq!(
            push_count.get(),
            1,
            "all_kept should flush downloaded receipt"
        );

        // 6. Invalid / out-of-range and aborted requests return the expected HTTP statuses.
        assert!(matches!(
            engine
                .media_range(token, &MediaRange::Invalid, &not_aborted)
                .await,
            Err(MediaError::OutOfRange { size: s }) if s == total_size
        ));
        assert!(matches!(
            engine
                .media_range(
                    token,
                    &MediaRange::From {
                        start: total_size,
                        end: None
                    },
                    &not_aborted,
                )
                .await,
            Err(MediaError::OutOfRange { size: s }) if s == total_size
        ));
        assert!(matches!(
            engine
                .media_range(token, &MediaRange::Whole, &|| true)
                .await,
            Err(MediaError::Status(404))
        ));

        // 7. Streaming from a sender-side local `ChunkSource::Bytes` reads directly without network.
        let local_id = [0x99u8; 16];
        let local_key = [0x55u8; session::attachment::KEY_LENGTH];
        let local_bytes = b"OggS-local-stream-bytes".to_vec();
        engine.uploads.insert_file(
            (peer, local_id, super::attachment_key_hash(&local_key)),
            ChunkSource::from_bytes("local.ogg", "audio/ogg", local_bytes.clone()),
        );
        let local_ptr = AttachmentPointer {
            id: local_id.to_vec(),
            key: local_key.to_vec(),
            size: local_bytes.len() as u64,
            name: "local.ogg".into(),
            mime: "audio/ogg".into(),
            expires: 0,
        };
        let local_url = engine.stream(peer, 1, &local_ptr, 0).await.unwrap();
        let local_tok = local_url.strip_prefix("/media/").unwrap();
        let (_, _, _, got_local) = engine
            .media_range(local_tok, &MediaRange::Whole, &not_aborted)
            .await
            .ok()
            .expect("ChunkSource::Bytes streams directly");
        assert_eq!(got_local, local_bytes);
        engine.end_stream(&local_url);
        assert!(
            engine
                .stream_chunk(local_tok, 0, &not_aborted)
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn outbox_flush_retries_idempotently_handles_partial_failure_and_fail_waiting() {
    use std::rc::Rc;

    futures::executor::block_on(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .add(&peer, Kind::Text("first".into()), false)
                .await
                .unwrap();
            inner
                .add(&peer, Kind::Text("second".into()), false)
                .await
                .unwrap();
        }

        // First flush: message #0 succeeds, message #1 fails transiently on the network.
        let recorded: Rc<RefCell<Vec<PushV2Request>>> = Rc::default();
        let rec_ref = recorded.clone();
        let fail_second = Rc::new(Cell::new(true));
        let fail_ref = fail_second.clone();
        let seq = Rc::new(Cell::new(0u64));
        let seq_ref = seq.clone();
        let _mock = crate::transport::mock_fetch(move |_server, path, body| {
            assert!(path.ends_with("/PushV2"), "unexpected path {path}");
            let req = PushV2Request::decode(body.as_slice()).unwrap();
            rec_ref.borrow_mut().push(req);
            if rec_ref.borrow().len() == 2 && fail_ref.get() {
                return Err(protocol::Error::new(
                    protocol::ErrorKind::Connect,
                    "transient drop",
                ));
            }
            let next = seq_ref.get() + 1;
            seq_ref.set(next);
            Ok((
                200,
                protocol::mailbox_v2::PushV2Response { sequence: next }.encode_to_vec(),
            ))
        });

        // Partial failure commits message #0 while leaving message #1 sealed in the outbox.
        assert!(engine.flush(&peer).await.is_err());
        assert_eq!(recorded.borrow().len(), 2);
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let contact = inner.contacts.iter().find(|c| c.peer == peer).unwrap();
            assert_eq!(contact.state.outbox.len(), 1);
            assert_eq!(contact.state.outbox[0].history_index, 1);
            assert!(contact.state.outbox[0].sealed);
            assert_eq!(
                inner.vault.entries.borrow()[&(peer, 0)].delivery(),
                Delivery::Sent
            );
            assert_eq!(
                inner.vault.entries.borrow()[&(peer, 1)].delivery(),
                Delivery::Pending
            );
            assert!(!inner.vault.outbox.borrow().contains_key(&(peer, 0)));
            assert!(inner.vault.outbox.borrow().contains_key(&(peer, 1)));
        }

        // Retry succeeds and reuses the EXACT same ciphertext + client_message_id (idempotency).
        fail_second.set(false);
        assert_eq!(engine.flush(&peer).await, Ok(true));
        assert_eq!(recorded.borrow().len(), 3);
        assert_eq!(
            recorded.borrow()[1].client_message_id,
            recorded.borrow()[2].client_message_id,
            "retrying sealed message must preserve deterministic client_message_id"
        );
        assert_eq!(
            recorded.borrow()[1].message,
            recorded.borrow()[2].message,
            "retrying sealed message must reuse sealed ciphertext without re-encrypting"
        );
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let contact = inner.contacts.iter().find(|c| c.peer == peer).unwrap();
            assert!(contact.state.outbox.is_empty());
            assert!(inner.vault.outbox.borrow().is_empty());
            assert_eq!(
                inner.vault.entries.borrow()[&(peer, 1)].delivery(),
                Delivery::Sent
            );
        }

        // Pending read events flush cleanly via `push_events` and clear `sealed_events`.
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contact(&peer).unwrap().state.events = Some(Events {
                read: vec![42],
                downloaded: vec![],
                accepted: false,
            });
            inner.save(&[]).await.unwrap();
        }
        assert_eq!(engine.flush(&peer).await, Ok(true));
        assert_eq!(recorded.borrow().len(), 4);
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let contact = inner.contacts.iter().find(|c| c.peer == peer).unwrap();
            assert!(contact.state.events.is_none());
            assert!(contact.state.sealed_events.is_none());
        }

        // SignInRequired holds the message, opens SignIn dialog, and `fail_waiting` cancels it.
        let held_idx = {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .add(&peer, Kind::Text("needs-auth".into()), false)
                .await
                .unwrap()
                .index
        };
        let _auth_mock = crate::transport::mock_fetch(|_server, _path, _body| {
            let err = protocol::connect::error(
                protocol::ErrorKind::SignInRequired,
                "sign in to this server",
            );
            Ok((err.status, err.body))
        });
        assert_eq!(engine.flush(&peer).await, Ok(false));
        assert!(engine.queue.waits_for_sign_in(&peer));
        assert!(engine.ui().held.get_untracked().contains(&(peer, held_idx)));
        assert_eq!(engine.ui().dialog.get_untracked(), Some(Dialog::SignIn));

        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            engine.fail_waiting(inner, &peer, held_idx).await.unwrap();
            let contact = inner.contacts.iter().find(|c| c.peer == peer).unwrap();
            assert!(contact.state.outbox.is_empty());
            assert!(!inner.vault.outbox.borrow().contains_key(&(peer, held_idx)));
            assert_eq!(
                inner.vault.entries.borrow()[&(peer, held_idx)].delivery(),
                Delivery::Failed
            );
        }
        assert!(!engine.ui().held.get_untracked().contains(&(peer, held_idx)));
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn attachments_promote_upload_rollback_cancel_upload_and_note_gone_by_id() {
    use std::rc::Rc;

    futures::executor::block_on(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        let payload = b"native-attachment-payload-bytes".to_vec();
        let source = ChunkSource::from_bytes("report.pdf", "application/pdf", payload.clone());

        // 1. `send_attachment` encountering SignInRequired stages a waiting upload (`!started()`).
        {
            let _auth_mock = crate::transport::mock_fetch(|_server, path, _body| {
                assert!(path.ends_with("/StartUpload"));
                let err = protocol::connect::error(
                    protocol::ErrorKind::SignInRequired,
                    "sign in required",
                );
                Ok((err.status, err.body))
            });
            engine.send_attachment(peer, source.clone()).await.unwrap();
        }
        let (waiting_id, waiting_hist_idx) = {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let uploads = inner.vault.uploads(Some(&peer)).await.unwrap();
            assert_eq!(uploads.len(), 1);
            let pending = &uploads[0].1;
            assert!(!pending.started());
            let id: [u8; 16] = pending.id.as_slice().try_into().unwrap();
            let contact = inner.contacts.iter().find(|c| c.peer == peer).unwrap();
            assert!(
                contact
                    .state
                    .outbox
                    .iter()
                    .any(|o| { o.history_index == pending.history_index && o.awaits_upload })
            );
            (id, pending.history_index)
        };
        assert!(
            engine
                .ui()
                .held
                .get_untracked()
                .contains(&(peer, waiting_hist_idx))
        );

        // 2. Inject `fail_promote_upload`: `start_waiting` MUST roll back `outbox.awaits_upload`,
        //    keep the waiting placeholder upload intact, and cancel the newly allocated server ID.
        let server_id_1 = [0x11u8; 16];
        let server_token_1 = [0x22u8; 16];
        let server_id_2 = [0x33u8; 16];
        let server_token_2 = [0x44u8; 16];
        let start_call = Rc::new(Cell::new(0usize));
        type PutChunkLog = Vec<(Vec<u8>, u32)>;
        let cancelled_ids: Rc<RefCell<Vec<Vec<u8>>>> = Rc::default();
        let put_chunks: Rc<RefCell<PutChunkLog>> = Rc::default();
        let start_ref = start_call.clone();
        let cancel_ref = cancelled_ids.clone();
        let put_ref = put_chunks.clone();
        let _mock = crate::transport::mock_fetch(move |_server, path, body| {
            if path.ends_with("/StartUpload") {
                let n = start_ref.get();
                start_ref.set(n + 1);
                let (id, tok) = if n == 0 {
                    (server_id_1, server_token_1)
                } else {
                    (server_id_2, server_token_2)
                };
                Ok((
                    200,
                    protocol::attachment::StartUploadResponse {
                        id: id.to_vec().into(),
                        upload_token: tok.to_vec().into(),
                        expires: 0,
                    }
                    .encode_to_vec(),
                ))
            } else if path.ends_with("/DeleteAttachment") {
                let req =
                    protocol::attachment::DeleteAttachmentRequest::decode(body.as_slice()).unwrap();
                cancel_ref.borrow_mut().push(req.id.to_vec());
                Ok((
                    200,
                    protocol::attachment::DeleteAttachmentResponse {}.encode_to_vec(),
                ))
            } else if path.ends_with("/PutChunk") {
                let req = protocol::attachment::PutChunkRequest::decode(body.as_slice()).unwrap();
                put_ref.borrow_mut().push((req.id.to_vec(), req.index));
                Ok((
                    200,
                    protocol::attachment::PutChunkResponse {}.encode_to_vec(),
                ))
            } else if path.ends_with("/PushV2") {
                Ok((
                    200,
                    protocol::mailbox_v2::PushV2Response { sequence: 1 }.encode_to_vec(),
                ))
            } else {
                Err(protocol::Error::new(
                    protocol::ErrorKind::Unimplemented,
                    format!("unexpected path {path}"),
                ))
            }
        });

        {
            let guard = engine.inner.lock().await;
            guard.as_ref().unwrap().vault.fail_promote_upload.set(true);
        }
        assert!(
            engine
                .start_waiting(peer, waiting_id, source.clone())
                .await
                .is_err()
        );
        assert_eq!(
            cancelled_ids.borrow().as_slice(),
            &[server_id_1.to_vec()],
            "failed promote_upload must cancel the orphaned server upload"
        );
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            inner.vault.fail_promote_upload.set(false);
            // Waiting placeholder and outbox flag remain cleanly rolled back.
            let still_waiting = inner.vault.upload(&peer, &waiting_id).await.unwrap();
            assert!(still_waiting.is_some_and(|u| !u.started()));
            assert!(
                inner
                    .vault
                    .upload(&peer, &server_id_1)
                    .await
                    .unwrap()
                    .is_none()
            );
            let contact = inner.contacts.iter().find(|c| c.peer == peer).unwrap();
            assert!(
                contact
                    .state
                    .outbox
                    .iter()
                    .any(|o| { o.history_index == waiting_hist_idx && o.awaits_upload })
            );
        }

        // 3. Retry with fault cleared: promotes atomically, announces, uploads & caches chunk 0,
        //    and forgets the completed upload record.
        engine
            .start_waiting(peer, waiting_id, source.clone())
            .await
            .unwrap();
        assert_eq!(put_chunks.borrow().as_slice(), &[(server_id_2.to_vec(), 0)]);
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(inner.vault.uploads(Some(&peer)).await.unwrap().is_empty());
            assert_eq!(
                inner.vault.chunks_kept(&peer, &server_id_2).await.unwrap(),
                1
            );
            let entry = inner
                .vault
                .entry(&peer, waiting_hist_idx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(entry.delivery(), Delivery::Sent);
            assert!(matches!(
                entry.content.as_ref().and_then(|c| c.kind.as_ref()),
                Some(Kind::Attachment(p)) if p.id == server_id_2
            ));
        }

        // 4. `note_gone_by_id` locates the entry even with `hint_index = None` (backwards scan)
        //    and persists `gone = true` + `ui.gone` idempotently.
        engine
            .note_gone_by_id(&peer, None, &server_id_2)
            .await
            .unwrap();
        assert!(
            engine
                .ui()
                .gone
                .get_untracked()
                .contains(&(peer, waiting_hist_idx))
        );
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(
                inner
                    .vault
                    .entry(&peer, waiting_hist_idx)
                    .await
                    .unwrap()
                    .unwrap()
                    .gone
            );
        }
        // Idempotent second call with explicit hint succeeds without error.
        engine
            .note_gone_by_id(&peer, Some(waiting_hist_idx), &server_id_2)
            .await
            .unwrap();

        // 5. `cancel_upload` on a waiting upload fails its outbox message & forgets it.
        engine.wait_for_sign_in(peer, source).await.unwrap();
        let (wait2_id, wait2_idx) = {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let uploads = inner.vault.uploads(Some(&peer)).await.unwrap();
            assert_eq!(uploads.len(), 1);
            let id: [u8; 16] = uploads[0].1.id.as_slice().try_into().unwrap();
            (id, uploads[0].1.history_index)
        };
        engine.cancel_upload(peer, wait2_id).await.unwrap();
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(
                inner
                    .vault
                    .upload(&peer, &wait2_id)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                inner
                    .vault
                    .entry(&peer, wait2_idx)
                    .await
                    .unwrap()
                    .unwrap()
                    .delivery(),
                Delivery::Failed
            );
            let contact = inner.contacts.iter().find(|c| c.peer == peer).unwrap();
            assert!(
                contact
                    .state
                    .outbox
                    .iter()
                    .all(|o| o.history_index != wait2_idx)
            );
        }

        // 6. `cancel_upload` on a started & announced upload forgets it, cancels on server, and
        //    marks its history entry `gone = true`.
        let started_id = [0x77u8; 16];
        let started_hist_idx = {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let pointer = crate::content::AttachmentPointer {
                id: started_id.to_vec(),
                key: vec![0x88; 32],
                size: 1024,
                name: "video.mp4".into(),
                mime: "video/mp4".into(),
                expires: 0,
            };
            let idx = inner
                .add(&peer, Kind::Attachment(pointer), false)
                .await
                .unwrap()
                .index;
            let pending = PendingUpload {
                id: started_id.to_vec(),
                token: vec![0x99; 16],
                key: vec![0x88; 32],
                name: "video.mp4".into(),
                mime: "video/mp4".into(),
                size: 1024,
                uploaded: 0,
                encrypted: 0,
                prefix_hash: vec![],
                announced: true,
                history_index: idx,
                expires: 0,
                upload_state: crate::vault::UPLOAD_STATE_ANNOUNCED,
                sealed_chunk_hash: vec![],
            };
            inner.vault.save_upload(&peer, &pending).await.unwrap();
            idx
        };
        engine.cancel_upload(peer, started_id).await.unwrap();
        assert!(engine.is_cancelled(&started_id));
        assert!(cancelled_ids.borrow().contains(&started_id.to_vec()));
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(
                inner
                    .vault
                    .upload(&peer, &started_id)
                    .await
                    .unwrap()
                    .is_none()
            );
            let entry = inner
                .vault
                .entry(&peer, started_hist_idx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(entry.delivery(), Delivery::Failed);
            assert!(entry.gone);
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn engine_delete_cleans_up_peer_and_rolls_back_on_forget_fault() {
    use crate::content::{AttachmentPointer, File};
    use leptos::prelude::{Set, Update, WithUntracked};
    use std::rc::Rc;

    futures::executor::block_on(async {
        let cancelled_on_server: Rc<RefCell<Vec<Vec<u8>>>> = Rc::default();
        let cancel_ref = cancelled_on_server.clone();
        let _mock = crate::transport::mock_fetch(move |_server, path, body| {
            if path.ends_with("/DeleteAttachment") {
                let req =
                    protocol::attachment::DeleteAttachmentRequest::decode(body.as_slice()).unwrap();
                cancel_ref.borrow_mut().push(req.id.to_vec());
                Ok((
                    200,
                    protocol::attachment::DeleteAttachmentResponse {}.encode_to_vec(),
                ))
            } else {
                Err(protocol::Error::new(
                    protocol::ErrorKind::Unimplemented,
                    format!("unexpected path {path}"),
                ))
            }
        });

        let (engine, alice_peer, _bob) = established_engine_on_localhost().await;
        let bob_peer = identity();
        let alice_upload_id = [0xA1u8; 16];
        let bob_upload_id = [0xB2u8; 16];
        let alice_key_hash = super::attachment_key_hash(&[0x31; 32]);
        let bob_key_hash = super::attachment_key_hash(&[0x32; 32]);

        let alice_file_idx = {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let me = inner.client.identity_key();
            let (mut extra, _, _) =
                restore_contacts(vec![stored_contact(me, bob_peer)], &me, LOCAL_SERVER);
            inner.contacts.push(extra.pop().unwrap());

            // Seed Alice with an inline file (stored separately in `vault.files`), an outbox
            // message, a cached chunk, an unfinished started upload, and a deferred initial.
            let file_idx = inner
                .add(
                    &alice_peer,
                    Kind::File(File {
                        name: "secret.txt".into(),
                        mime: "text/plain".into(),
                        data: b"secret-contents".to_vec(),
                    }),
                    false,
                )
                .await
                .unwrap()
                .index;
            inner
                .vault
                .put_chunk(&alice_peer, &alice_upload_id, 0, b"alice-chunk")
                .await
                .unwrap();
            inner
                .vault
                .save_upload(
                    &alice_peer,
                    &PendingUpload {
                        id: alice_upload_id.to_vec(),
                        token: vec![0xAA; 16],
                        key: vec![0x31; 32],
                        name: "unfinished.bin".into(),
                        mime: "application/octet-stream".into(),
                        size: 2048,
                        uploaded: 0,
                        encrypted: 0,
                        prefix_hash: vec![],
                        announced: false,
                        history_index: 0,
                        expires: 0,
                        upload_state: UPLOAD_STATE_STARTED,
                        sealed_chunk_hash: vec![],
                    },
                )
                .await
                .unwrap();

            // Seed Bob with his own history, outbox, chunk, upload, and deferred initial.
            inner
                .add(&bob_peer, Kind::Text("keep-bob".into()), false)
                .await
                .unwrap();
            inner
                .vault
                .put_chunk(&bob_peer, &bob_upload_id, 0, b"bob-chunk")
                .await
                .unwrap();
            inner
                .vault
                .save_upload(
                    &bob_peer,
                    &PendingUpload {
                        id: bob_upload_id.to_vec(),
                        token: vec![0xBB; 16],
                        key: vec![0x32; 32],
                        name: "bob.bin".into(),
                        mime: "application/octet-stream".into(),
                        size: 512,
                        uploaded: 0,
                        encrypted: 0,
                        prefix_hash: vec![],
                        announced: false,
                        history_index: 0,
                        expires: 0,
                        upload_state: UPLOAD_STATE_STARTED,
                        sealed_chunk_hash: vec![],
                    },
                )
                .await
                .unwrap();

            inner.deferred_initials = vec![
                DeferredInitial {
                    initial: Some(WireInitialMessageV2 {
                        identity_key: Bytes::copy_from_slice(&alice_peer),
                        ..Default::default()
                    }),
                    deferred_at: 100,
                },
                DeferredInitial {
                    initial: Some(WireInitialMessageV2 {
                        identity_key: Bytes::copy_from_slice(&bob_peer),
                        ..Default::default()
                    }),
                    deferred_at: 200,
                },
            ];
            inner.save(&[]).await.unwrap();
            file_idx
        };

        // Verify `Engine::file` reads the separately stored inline file record.
        assert_eq!(
            engine
                .file(alice_peer, alice_file_idx)
                .await
                .unwrap()
                .as_slice(),
            b"secret-contents"
        );

        // Seed transient engine & UI state for both peers.
        engine.open(Some(alice_peer)).await;
        engine.uploads.insert_file(
            (alice_peer, alice_upload_id, alice_key_hash),
            ChunkSource::from_bytes("a.bin", "application/octet-stream", vec![1, 2, 3]),
        );
        engine.uploads.insert_file(
            (bob_peer, bob_upload_id, bob_key_hash),
            ChunkSource::from_bytes("b.bin", "application/octet-stream", vec![4, 5, 6]),
        );
        engine.media.cache_decrypted(
            (alice_peer, alice_upload_id, alice_key_hash, 0),
            Rc::new(zeroize::Zeroizing::new(vec![1])),
        );
        engine.media.cache_decrypted(
            (bob_peer, bob_upload_id, bob_key_hash, 0),
            Rc::new(zeroize::Zeroizing::new(vec![2])),
        );
        engine
            .queue
            .push_sending(Sending::Content(alice_peer, Kind::Text("drop".into())));
        engine
            .queue
            .push_sending(Sending::Content(bob_peer, Kind::Text("stay".into())));
        engine.ui().held.update(|h| {
            h.insert((alice_peer, 0));
            h.insert((bob_peer, 0));
        });
        engine.ui().gone.update(|g| {
            g.insert((alice_peer, 0));
            g.insert((bob_peer, 0));
        });
        let alice_stream = engine
            .stream(
                alice_peer,
                0,
                &AttachmentPointer {
                    id: alice_upload_id.to_vec(),
                    key: vec![0x31; 32],
                    size: 16,
                    name: "a.ogg".into(),
                    mime: "audio/ogg".into(),
                    expires: 0,
                },
                0,
            )
            .await
            .unwrap();
        let bob_stream = engine
            .stream(
                bob_peer,
                0,
                &AttachmentPointer {
                    id: bob_upload_id.to_vec(),
                    key: vec![0x32; 32],
                    size: 16,
                    name: "b.ogg".into(),
                    mime: "audio/ogg".into(),
                    expires: 0,
                },
                0,
            )
            .await
            .unwrap();
        let _ = (&alice_stream, &bob_stream);

        // 1. Fault-inject `fail_forget`: `delete` fails and rolls back session/state cleanly.
        let session_before = {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            inner.vault.fail_forget.set(true);
            proto::SessionState::from(
                inner
                    .contacts
                    .iter()
                    .find(|c| c.peer == alice_peer)
                    .unwrap()
                    .session
                    .state(),
            )
        };
        assert!(engine.delete(alice_peer).await.is_err());
        assert_eq!(engine.ui().open.get_untracked(), Some(alice_peer));
        assert!(cancelled_on_server.borrow().is_empty());
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let alice_contact = inner
                .contacts
                .iter()
                .find(|c| c.peer == alice_peer)
                .unwrap();
            assert_eq!(
                proto::SessionState::from(alice_contact.session.state()),
                session_before,
                "failed VaultStore::forget must roll back contact session cleanly"
            );
            assert!(inner.state.farewells.is_empty());
            assert!(inner.vault.entries.borrow().contains_key(&(alice_peer, 0)));
            inner.vault.fail_forget.set(false);
        }

        // 2. Retry `delete(alice_peer)`: purges all Alice state, cancels unfinished upload on
        //    server, queues farewell, and leaves Bob completely untouched.
        engine.delete(alice_peer).await.unwrap();
        assert_eq!(engine.ui().open.get_untracked(), None);
        assert!(engine.ui().messages.with_untracked(Vec::is_empty));
        assert_eq!(
            engine.ui().deleted_peer.get_untracked().map(|(_, p)| p),
            Some(alice_peer)
        );
        assert_eq!(
            cancelled_on_server.borrow().as_slice(),
            &[alice_upload_id.to_vec()]
        );
        assert!(engine.is_cancelled(&alice_upload_id));
        assert_eq!(engine.uploads.file_peers(), vec![bob_peer]);
        assert_eq!(engine.media.decrypted_peers(), vec![bob_peer]);
        assert_eq!(engine.media.stream_peers(), vec![bob_peer]);
        assert_eq!(engine.queue.sending_peers(), vec![bob_peer]);
        assert_eq!(engine.ui().held.get_untracked().len(), 1);
        assert!(engine.ui().held.get_untracked().contains(&(bob_peer, 0)));
        assert_eq!(engine.ui().gone.get_untracked().len(), 1);
        assert!(engine.ui().gone.get_untracked().contains(&(bob_peer, 0)));
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(inner.contacts.iter().all(|c| c.peer != alice_peer));
            assert!(inner.contacts.iter().any(|c| c.peer == bob_peer));
            assert_eq!(inner.state.farewells.len(), 1);
            assert_eq!(inner.vault.state.borrow().farewells.len(), 1);
            assert!(
                inner
                    .vault
                    .entries
                    .borrow()
                    .keys()
                    .all(|(p, _)| *p == bob_peer)
            );
            assert!(
                inner
                    .vault
                    .files
                    .borrow()
                    .keys()
                    .all(|(p, _)| *p == bob_peer)
            );
            assert!(
                inner
                    .vault
                    .outbox
                    .borrow()
                    .keys()
                    .all(|(p, _)| *p == bob_peer)
            );
            assert!(
                inner
                    .vault
                    .chunks
                    .borrow()
                    .keys()
                    .all(|(p, _, _)| *p == bob_peer)
            );
            assert!(
                inner
                    .vault
                    .uploads
                    .borrow()
                    .keys()
                    .all(|(p, _)| *p == bob_peer)
            );
            assert_eq!(inner.deferred_initials.len(), 1);
            assert_eq!(
                inner.deferred_initials[0]
                    .initial
                    .as_ref()
                    .unwrap()
                    .identity_key
                    .as_ref(),
                bob_peer.as_slice()
            );
        }
        // Reset dialog/signal cleanly.
        engine.ui().dialog.set(None);
    });
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "ml-kem-1024", feature = "ml-kem-768")
))]
#[test]
fn publish_full_persists_pq_off_before_transmitting_and_handles_clock_skew() {
    use protocol::handshake_v2::{GetServerInfoResponse, PublishV2Request, PublishV2Response};
    use std::rc::Rc;

    futures::executor::block_on(async {
        let (inner, _peer) = unlocked_client();
        let saved_seqs = inner.vault.saved_manifest_seqs.clone();
        let engine = Engine::with_inner(Ui::new(), inner);

        // 1. Relay has runtime PQ_ENABLED=false: first PublishV2 (PQ-ON, seq 1) returns Connect
        //    `unimplemented`, GetServerInfo confirms `pq_enabled: false`, and `publish_full` MUST
        //    persist seq 2 (PQ-OFF) to the vault BEFORE transmitting the second PublishV2!
        type PublishLog = Rc<RefCell<Vec<(u64, bool, Vec<u64>)>>>;
        let publish_log: PublishLog = Rc::default();
        let publish_log_ref = publish_log.clone();
        let saved_seqs_ref = saved_seqs.clone();
        let _mock = crate::transport::mock_fetch(move |_server, path, body| {
            if path.ends_with("/PublishV2") {
                let req = PublishV2Request::decode(body.as_slice()).unwrap();
                let manifest = req.manifest.as_ref().unwrap();
                let persisted_before_rpc = saved_seqs_ref.borrow().clone();
                publish_log_ref.borrow_mut().push((
                    manifest.manifest_seq,
                    manifest.pq_enabled,
                    persisted_before_rpc,
                ));
                if manifest.pq_enabled {
                    Ok((
                        404,
                        br#"{"code":"unimplemented","message":"server PQ disabled"}"#.to_vec(),
                    ))
                } else {
                    Ok((200, PublishV2Response {}.encode_to_vec()))
                }
            } else if path.ends_with("/GetServerInfo") {
                Ok((
                    200,
                    GetServerInfoResponse {
                        server_id: "chat.example".to_string(),
                        pq_enabled: false,
                        supported_suites: vec![],
                        pq_ratchet_supported: false,
                    }
                    .encode_to_vec(),
                ))
            } else {
                panic!("unexpected path: {path}");
            }
        });

        {
            let vgen = engine.vault_gen();
            engine.publish_full(vgen, true).await.unwrap();
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            assert_eq!(inner.client.manifest_seq(), 2);
            assert_eq!(inner.server_pq, ServerPqStatus::Disabled);
            assert_eq!(
                inner
                    .client
                    .current_pq_one_time_count(PqConfig::default_suite()),
                0
            );
            assert_eq!(inner.client.current_one_time_count(), ONE_TIME_PREKEYS);
        }

        {
            let log = publish_log.borrow();
            assert_eq!(log.len(), 2);
            // Call 1: PQ-ON seq 1 persisted before transmit.
            assert_eq!(log[0].0, 1);
            assert!(log[0].1);
            assert_eq!(log[0].2, vec![1]);
            // Call 2: PQ-OFF seq 2 persisted BEFORE transmit!
            assert_eq!(log[1].0, 2);
            assert!(!log[1].1);
            assert_eq!(log[1].2, vec![1, 2]);
        }

        // 2. ClockSkew (>24h drift) fails closed cleanly without rejecting PQ settings or
        //    mutating manifest_seq, and surfaces the plain-English clock-skew guidance.
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let now_ms = inner.client.clock().now();
            inner.client.clock().observe(now_ms + 25 * 60 * 60 * 1000);
        }
        let vgen = engine.vault_gen();
        let err = engine.publish_full(vgen, true).await.unwrap_err();
        assert_eq!(err.kind, Some(ErrorKind::ClockSkew));
        assert!(!err.rejects_settings());
        assert!(err.message.contains("24 hours"), "{}", err.message);
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            assert_eq!(inner.client.manifest_seq(), 2);
        }
        assert!(
            describe_upgrade_pq_error(
                ErrorKind::ClockSkew,
                &ServerPqStatus::Unknown,
                "raw".to_string()
            )
            .contains("24 hours")
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn unified_receive_mailbox_isolates_quarantined_peer_defers_replays_and_evicts_on_cap() {
    use protocol::mailbox_v2::{
        AckMessagesRequest, AckMessagesResponse, EnvelopeV2, FetchSignedResponse,
    };
    use std::rc::Rc;

    futures::executor::block_on(async {
        // Set up Bob (`engine`) with two real established sessions:
        // - `peer_a` (quarantined)
        // - `peer_b` (active)
        let mut bob_client = Client::new(Fetch::client(LOCAL_SERVER));
        let bob_id = bob_client.identity_key();
        let published = bob_client.prepare_publish_v2("localhost", 4, 4).unwrap();
        let p = &published.request;
        let make_bundle = |idx: usize| protocol::handshake_v2::ClaimBundleResponse {
            signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: p.signed_prekey_signature.clone(),
            one_time_prekey: p.one_time_prekeys.get(idx).cloned(),
            pq_last_resort: p.pq_last_resort.first().cloned(),
            pq_one_time_prekey: p.pq_one_time_prekeys.get(idx).cloned(),
            manifest: p.manifest.clone(),
        };
        let bundle_a = make_bundle(0);
        let bundle_b = make_bundle(1);
        bob_client.commit_publish_v2(published);

        let mut alice_a = Client::new(ConnectClient::new(BundleResponse("/ClaimBundle", bundle_a)));
        let prep_a = alice_a
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(alice_a.make_hello("AliceA", 1)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let peer_a = alice_a.identity_key();
        let mut session_a_sender = prep_a.session;
        let inc_a = Incoming::try_from(prep_a.request.message.as_ref().unwrap()).unwrap();
        let AcceptedInitial::Accepted {
            session: session_a_bob,
            ..
        } = bob_client
            .accept_initial_v2(
                &peer_a,
                &Default::default(),
                &inc_a,
                Fetch::client(LOCAL_SERVER),
            )
            .unwrap()
        else {
            panic!("expected accepted initial for A");
        };
        let token_hash_a = session_a_bob.active_inbound_token_hash().unwrap();

        let mut alice_b = Client::new(ConnectClient::new(BundleResponse("/ClaimBundle", bundle_b)));
        let prep_b = alice_b
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(alice_b.make_hello("AliceB", 1)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let peer_b = alice_b.identity_key();
        let mut session_b_sender = prep_b.session;
        let inc_b = Incoming::try_from(prep_b.request.message.as_ref().unwrap()).unwrap();
        let AcceptedInitial::Accepted {
            session: session_b_bob,
            ..
        } = bob_client
            .accept_initial_v2(
                &peer_b,
                &Default::default(),
                &inc_b,
                Fetch::client(LOCAL_SERVER),
            )
            .unwrap()
        else {
            panic!("expected accepted initial for B");
        };
        let token_hash_b = session_b_bob.active_inbound_token_hash().unwrap();

        // Seal one message from A (seq 102) and one from B (seq 103).
        let sealed_a = session_a_sender
            .encrypt(&Kind::Text("secret from A".into()).to_bytes())
            .unwrap();
        let sealed_b = session_b_sender
            .encrypt(&Kind::Text("hello from B".into()).to_bytes())
            .unwrap();

        let contacts = vec![
            super::contact::Contact {
                peer: peer_a,
                session: session_a_bob,
                deferred_carried: 0,
                state: ContactState {
                    peer: peer_a.to_vec(),
                    name: "AliceA".into(),
                    quarantined: true,
                    ..ContactState::default()
                },
            },
            super::contact::Contact {
                peer: peer_b,
                session: session_b_bob,
                deferred_carried: 0,
                state: ContactState {
                    peer: peer_b.to_vec(),
                    name: "AliceB".into(),
                    ..ContactState::default()
                },
            },
        ];
        let inner = Inner::new(
            MemoryVault::default(),
            LOCAL_SERVER.into(),
            "localhost".into(),
            AppState {
                name: "Bob".into(),
                ..AppState::default()
            },
            bob_client,
            contacts,
            vec![],
            DeferredRecord::default(),
        );
        let engine = Engine::with_inner(Ui::new(), inner);

        let acked_seqs: Rc<RefCell<Vec<u64>>> = Rc::default();
        let acked_ref = acked_seqs.clone();
        let page1_envelopes = vec![
            EnvelopeV2 {
                sequence: 102,
                token_hash: Bytes::copy_from_slice(&token_hash_a),
                message: Some(sealed_a.message.clone()),
                initial_message: None,
            },
            EnvelopeV2 {
                sequence: 103,
                token_hash: Bytes::copy_from_slice(&token_hash_b),
                message: Some(sealed_b.message.clone()),
                initial_message: None,
            },
        ];
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, body| {
                if path.ends_with("/FetchSigned") {
                    Ok((
                        200,
                        FetchSignedResponse {
                            messages: page1_envelopes.clone(),
                            has_more: false,
                        }
                        .encode_to_vec(),
                    ))
                } else if path.ends_with("/AckMessages") {
                    let req = AckMessagesRequest::decode(body.as_slice()).unwrap();
                    acked_ref.borrow_mut().push(req.up_to_sequence);
                    Ok((200, AckMessagesResponse { deleted: 2 }.encode_to_vec()))
                } else {
                    panic!("unexpected path during unified receive_mailbox: {path}");
                }
            });

            let affected = engine.receive_mailbox().await.unwrap();
            assert_eq!(affected, vec![peer_b]);
        }

        // Server mailbox ACK unconditionally advanced to 103 past quarantined peer A!
        assert_eq!(acked_seqs.borrow().as_slice(), &[103]);
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            // Peer B delivered immediately; Peer A buffered in DeferredRecord.envelopes.
            assert_eq!(
                inner.vault.entries.borrow()[&(peer_b, 0)]
                    .content
                    .as_ref()
                    .and_then(|c| c.kind.as_ref()),
                Some(&Kind::Text("hello from B".into()))
            );
            assert!(!inner.vault.entries.borrow().contains_key(&(peer_a, 0)));
            assert_eq!(inner.deferred_envelopes.len(), 1);
            assert_eq!(inner.deferred_envelopes[0].sequence, 102);
            assert_eq!(inner.vault.deferred.borrow().envelopes.len(), 1);
        }

        // Unquarantine peer A and replay locally with ZERO network calls!
        {
            let _no_net = crate::transport::mock_fetch(|_s, path, _b| {
                panic!("local replay must not hit server: {path}");
            });
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contact(&peer_a).unwrap().state.quarantined = false;
            let (replayed, _, _) = engine
                .replay_deferred_envelopes(inner, Some(&peer_a), Some(u64::MAX), None)
                .await
                .unwrap();
            assert!(replayed.contains(&peer_a));
            assert!(inner.deferred_envelopes.is_empty());
            assert!(inner.vault.deferred.borrow().envelopes.is_empty());
            assert_eq!(
                inner.vault.entries.borrow()[&(peer_a, 0)]
                    .content
                    .as_ref()
                    .and_then(|c| c.kind.as_ref()),
                Some(&Kind::Text("secret from A".into()))
            );
        }

        // Overflow per-peer deferred envelope cap (64): 65th envelope drops & appends evicted gap.
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contact(&peer_a).unwrap().state.quarantined = true;
            inner.save_state().await.unwrap();
        }
        let overflow_page: Vec<EnvelopeV2> = (200u64..265)
            .map(|seq| {
                let s = session_a_sender
                    .encrypt(&Kind::Text(format!("burst-{seq}")).to_bytes())
                    .unwrap();
                EnvelopeV2 {
                    sequence: seq,
                    token_hash: Bytes::copy_from_slice(&token_hash_a),
                    message: Some(s.message.clone()),
                    initial_message: None,
                }
            })
            .collect();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/FetchSigned") {
                    Ok((
                        200,
                        FetchSignedResponse {
                            messages: overflow_page.clone(),
                            has_more: false,
                        }
                        .encode_to_vec(),
                    ))
                } else if path.ends_with("/AckMessages") {
                    Ok((200, AckMessagesResponse { deleted: 65 }.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            engine.receive_mailbox().await.unwrap();
        }
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert_eq!(inner.deferred_envelopes.len(), 64);
            let evicted_entry = inner
                .vault
                .entries
                .borrow()
                .get(&(peer_a, 1))
                .cloned()
                .expect("cap overflow must record atomic evicted gap marker");
            assert!(evicted_entry.evicted);
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn human_approved_grants_backoff_revokes_and_farewell_write_token_rejected() {
    use protocol::handshake_v2::SendInitialV2Response;
    use protocol::mailbox_v2::{
        RegisterWriteTokenRequest, RegisterWriteTokenResponse, RevokeWriteTokenRequest,
        RevokeWriteTokenResponse,
    };
    use std::rc::Rc;

    futures::executor::block_on(async {
        // 1. Brand-new inbound `process_initial` sets `request = true` with ZERO staged grants.
        let mut bob_client = Client::new(Fetch::client(LOCAL_SERVER));
        let (alice_peer, incoming) = carried_initial(&mut bob_client).await;
        let bob_inner = Inner::new(
            MemoryVault::default(),
            LOCAL_SERVER.into(),
            "localhost".into(),
            AppState {
                name: "Bob".into(),
                ..AppState::default()
            },
            bob_client,
            vec![],
            vec![],
            DeferredRecord::default(),
        );
        let bob_engine = Engine::with_inner(Ui::new(), bob_inner);
        {
            let mut guard = bob_engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let mut batch = InitialBatch::default();
            bob_engine.process_initial(inner, &alice_peer, &incoming, &mut batch);
            bob_engine.save_initial_batch(inner, batch).await.unwrap();
            let contact = inner.contact(&alice_peer).unwrap();
            assert!(contact.state.request);
            assert!(
                contact.session.pending_register_grants().is_empty(),
                "unapproved chat request must NOT stage a write-token grant"
            );
        }

        // 2. Explicit `Engine::accept` registers write token AND pushes `Events { accepted: true }`.
        let register_reqs: Rc<RefCell<Vec<RegisterWriteTokenRequest>>> = Rc::default();
        let push_reqs: Rc<RefCell<Vec<PushV2Request>>> = Rc::default();
        let reg_ref = register_reqs.clone();
        let push_ref = push_reqs.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, body| {
                if path.ends_with("/RegisterWriteToken") {
                    let req = RegisterWriteTokenRequest::decode(body.as_slice()).unwrap();
                    reg_ref.borrow_mut().push(req);
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else if path.ends_with("/PushV2") {
                    let req = PushV2Request::decode(body.as_slice()).unwrap();
                    push_ref.borrow_mut().push(req);
                    Ok((
                        200,
                        protocol::mailbox_v2::PushV2Response { sequence: 1 }.encode_to_vec(),
                    ))
                } else {
                    panic!("unexpected path during accept: {path}");
                }
            });
            bob_engine.accept(alice_peer, "Alice".into()).await.unwrap();
        }
        assert_eq!(register_reqs.borrow().len(), 1);
        assert!(register_reqs.borrow()[0].pin_active);
        assert_eq!(push_reqs.borrow().len(), 1);
        {
            let guard = bob_engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let contact = inner
                .contacts
                .iter()
                .find(|c| c.peer == alice_peer)
                .unwrap();
            assert!(!contact.state.request);
            assert!(contact.session.pending_register_grants().is_empty());
        }

        // 3. Outbound `WriteTokenRejected` on `!known_by_peer`: retries SendInitialV2 once when
        //    unconfirmed, keeps outbox intact under backoff (15s->30s->60s->5m), non-error Ok(false).
        let (alice_engine, bob_peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = alice_engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let contact = inner.contact(&bob_peer).unwrap();
            assert!(!contact.session.is_known_by_peer());
            contact.state.greeting_delivery = crate::vault::GREETING_DELIVERY_UNCERTAIN;
            inner
                .add(&bob_peer, Kind::Text("waiting for approval".into()), false)
                .await
                .unwrap();
        }
        let send_initial_calls = Rc::new(Cell::new(0usize));
        let push_calls = Rc::new(Cell::new(0usize));
        let init_ref = send_initial_calls.clone();
        let push_cnt_ref = push_calls.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/PushV2") {
                    push_cnt_ref.set(push_cnt_ref.get() + 1);
                    let err = protocol::connect::error(
                        protocol::ErrorKind::WriteTokenRejected,
                        "write token rejected",
                    );
                    Ok((err.status, err.body))
                } else if path.ends_with("/SendInitialV2") {
                    init_ref.set(init_ref.get() + 1);
                    Ok((200, SendInitialV2Response { id: 1 }.encode_to_vec()))
                } else if path.ends_with("/GetManifest") {
                    // Bob's manifest hasn't rotated SPK yet (or is unavailable): no redundant SendInitialV2.
                    Ok((
                        200,
                        protocol::handshake_v2::GetManifestResponse { manifest: None }
                            .encode_to_vec(),
                    ))
                } else {
                    panic!("unexpected path: {path}");
                }
            });

            // 1st flush: PushV2 rejected -> retries SendInitialV2 once, enters backoff, returns Ok(false).
            assert_eq!(alice_engine.flush(&bob_peer).await, Ok(false));
            assert_eq!(push_calls.get(), 1);
            assert_eq!(send_initial_calls.get(), 1);
            assert!(alice_engine.queue.is_approval_backed_off(&bob_peer));

            // 2nd immediate flush: skipped silently while backed off.
            assert_eq!(alice_engine.flush(&bob_peer).await, Ok(false));
            assert_eq!(push_calls.get(), 1);

            // Clearing backoff (e.g. manual Sync) allows retry; greeting is now CONFIRMED so
            // SendInitialV2 is NOT retried a second time!
            alice_engine.clear_approval_backoff(&bob_peer);
            assert_eq!(alice_engine.flush(&bob_peer).await, Ok(false));
            assert_eq!(push_calls.get(), 2);
            assert_eq!(send_initial_calls.get(), 1);
        }
        {
            let guard = alice_engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let contact = inner.contacts.iter().find(|c| c.peer == bob_peer).unwrap();
            assert_eq!(contact.state.outbox.len(), 1);
            assert!(!contact.session.needs_new_session());
        }

        // 4. Outbound `WriteTokenRejected` when `known_by_peer == true`: retires session and sets
        //    `needs_requeue_sealed = true`.
        alice_engine.clear_approval_backoff(&bob_peer);
        {
            let mut guard = alice_engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            change_session(&mut inner.contact(&bob_peer).unwrap().session, |s| {
                s.known_by_peer = true;
            });
            inner.save_state().await.unwrap();
        }
        {
            let _mock = crate::transport::mock_fetch(|_server, path, _body| {
                assert!(path.ends_with("/PushV2"), "unexpected path {path}");
                let err = protocol::connect::error(
                    protocol::ErrorKind::WriteTokenRejected,
                    "write token revoked",
                );
                Ok((err.status, err.body))
            });
            assert_eq!(alice_engine.flush(&bob_peer).await, Ok(false));
        }
        {
            let guard = alice_engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let contact = inner.contacts.iter().find(|c| c.peer == bob_peer).unwrap();
            assert!(contact.session.needs_new_session());
            assert!(contact.state.needs_requeue_sealed);
        }

        // 5. `delete` stages `PendingRevoke`, bumps `next_grant_version`, prunes deferred envelopes,
        //    `flush_pending_revokes` sends `/RevokeWriteToken`, and `say_farewells` drops on
        //    `WriteTokenRejected`.
        {
            let mut guard = bob_engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .deferred_envelopes
                .push(crate::vault::DeferredEnvelope {
                    peer: alice_peer.to_vec(),
                    sequence: 55,
                    message: None,
                    initial_message: None,
                    deferred_at: 1000,
                    pq_isolated: false,
                });
            inner.save_state().await.unwrap();
        }
        bob_engine.delete(alice_peer).await.unwrap();
        {
            let guard = bob_engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(inner.deferred_envelopes.is_empty());
            assert_eq!(inner.state.pending_revokes.len(), 1);
            assert!(inner.state.pending_revokes[0].min_grant_version >= 2);
            assert_eq!(inner.state.farewells.len(), 1);
        }
        let revokes_sent: Rc<RefCell<Vec<RevokeWriteTokenRequest>>> = Rc::default();
        let revokes_ref = revokes_sent.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, body| {
                if path.ends_with("/RevokeWriteToken") {
                    let req = RevokeWriteTokenRequest::decode(body.as_slice()).unwrap();
                    revokes_ref.borrow_mut().push(req);
                    Ok((200, RevokeWriteTokenResponse { revoked: 1 }.encode_to_vec()))
                } else if path.ends_with("/PushV2") {
                    let err = protocol::connect::error(
                        protocol::ErrorKind::WriteTokenRejected,
                        "already revoked",
                    );
                    Ok((err.status, err.body))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            bob_engine.flush_pending_revokes().await.unwrap();
            bob_engine.say_farewells().await.unwrap();
        }
        assert_eq!(revokes_sent.borrow().len(), 1);
        {
            let guard = bob_engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(inner.state.pending_revokes.is_empty());
            assert!(inner.state.farewells.is_empty());
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn take_initial_messages_commits_and_acks_per_page_and_breaks_on_non_advancing_cursor() {
    use protocol::handshake_v2::{
        AckInitialMessagesRequest, AckInitialMessagesResponse, ListInitialMessagesRequest,
        ListInitialMessagesResponse,
    };
    use std::rc::Rc;

    futures::executor::block_on(async {
        let mut bob_client = Client::new(Fetch::client(LOCAL_SERVER));
        let (_alice_peer, mut inc1) = carried_initial(&mut bob_client).await;
        inc1.id = 5;
        let wire1 = WireInitialMessageV2 {
            id: 5,
            ..match &inc1.kind {
                session::InitialMessageKind::Classical {
                    x3dh,
                    first_message,
                } => WireInitialMessageV2 {
                    first_message: Some(first_message.clone()),
                    ..WireInitialMessageV2::from(x3dh)
                },
                session::InitialMessageKind::Pq {
                    x3dh,
                    first_message,
                    manifest_digest,
                } => WireInitialMessageV2 {
                    first_message: Some(first_message.clone()),
                    manifest_digest: manifest_digest
                        .as_ref()
                        .map_or_else(Bytes::new, |d| Bytes::copy_from_slice(d)),
                    ..WireInitialMessageV2::from(x3dh)
                },
            }
        };

        let (_, mut inc2) = carried_initial(&mut bob_client).await;
        inc2.id = 10;
        let wire2 = WireInitialMessageV2 {
            id: 10,
            ..match &inc2.kind {
                session::InitialMessageKind::Classical {
                    x3dh,
                    first_message,
                } => WireInitialMessageV2 {
                    first_message: Some(first_message.clone()),
                    ..WireInitialMessageV2::from(x3dh)
                },
                session::InitialMessageKind::Pq {
                    x3dh,
                    first_message,
                    manifest_digest,
                } => WireInitialMessageV2 {
                    first_message: Some(first_message.clone()),
                    manifest_digest: manifest_digest
                        .as_ref()
                        .map_or_else(Bytes::new, |d| Bytes::copy_from_slice(d)),
                    ..WireInitialMessageV2::from(x3dh)
                },
            }
        };

        let inner = Inner::new(
            MemoryVault::default(),
            LOCAL_SERVER.into(),
            "localhost".into(),
            AppState {
                name: "Bob".into(),
                ..AppState::default()
            },
            bob_client,
            vec![],
            vec![],
            DeferredRecord::default(),
        );
        let engine = Engine::with_inner(Ui::new(), inner);

        // Log the exact RPC sequence to verify ACK of page 1 precedes List(after_id=5),
        // page 2 commits & ACKs before List(after_id=10), and page 3 returning non-advancing
        // id <= after_id with has_more=true breaks defensively without an infinite loop.
        let rpc_log: Rc<RefCell<Vec<String>>> = Rc::default();
        let log_ref = rpc_log.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, body| {
                if path.ends_with("/ListInitialMessages") {
                    let req = ListInitialMessagesRequest::decode(body.as_slice()).unwrap();
                    log_ref.borrow_mut().push(format!("list:{}", req.after_id));
                    let resp = match req.after_id {
                        0 => ListInitialMessagesResponse {
                            messages: vec![wire1.clone()],
                            has_more: true,
                        },
                        5 => ListInitialMessagesResponse {
                            messages: vec![wire2.clone()],
                            has_more: true,
                        },
                        10 => ListInitialMessagesResponse {
                            messages: vec![],
                            has_more: true, // non-advancing!
                        },
                        other => panic!("unexpected after_id {other}"),
                    };
                    Ok((200, resp.encode_to_vec()))
                } else if path.ends_with("/AckInitialMessages") {
                    let req = AckInitialMessagesRequest::decode(body.as_slice()).unwrap();
                    log_ref.borrow_mut().push(format!("ack:{:?}", req.ids));
                    Ok((
                        200,
                        AckInitialMessagesResponse {
                            deleted: req.ids.len() as u32,
                        }
                        .encode_to_vec(),
                    ))
                } else {
                    panic!("unexpected path: {path}");
                }
            });

            assert!(engine.take_initial_messages().await.unwrap());
        }

        assert_eq!(
            rpc_log.borrow().as_slice(),
            &["list:0", "ack:[5]", "list:5", "ack:[10]", "list:10"]
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn max_text_bytes_guard_and_zero_byte_attachment_upload() {
    use std::rc::Rc;

    futures::executor::block_on(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;

        // 1. MAX_TEXT_BYTES (32 KiB) boundary check in Inner::add.
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let ok_text = "a".repeat(MAX_TEXT_BYTES);
            inner.add(&peer, Kind::Text(ok_text), false).await.unwrap();
            let too_big = "a".repeat(MAX_TEXT_BYTES + 1);
            assert!(inner.add(&peer, Kind::Text(too_big), false).await.is_err());
        }

        // 2. 0-byte file uploads cleanly through unconditional send_attachment (1 chunk = 16B tag).
        let put_sizes: Rc<RefCell<Vec<(u32, usize)>>> = Rc::default();
        let put_ref = put_sizes.clone();
        let _mock = crate::transport::mock_fetch(move |_server, path, body| {
            if path.ends_with("/StartUpload") {
                Ok((
                    200,
                    protocol::attachment::StartUploadResponse {
                        id: vec![0xE0; 16].into(),
                        upload_token: vec![0xE1; 16].into(),
                        expires: 0,
                    }
                    .encode_to_vec(),
                ))
            } else if path.ends_with("/PutChunk") {
                let req = protocol::attachment::PutChunkRequest::decode(body.as_slice()).unwrap();
                put_ref.borrow_mut().push((req.index, req.data.len()));
                Ok((
                    200,
                    protocol::attachment::PutChunkResponse {}.encode_to_vec(),
                ))
            } else if path.ends_with("/PushV2") {
                Ok((
                    200,
                    protocol::mailbox_v2::PushV2Response { sequence: 1 }.encode_to_vec(),
                ))
            } else {
                panic!("unexpected path: {path}");
            }
        });
        let empty = ChunkSource::from_bytes("empty.txt", "text/plain", vec![]);
        engine.send_attachment(peer, empty).await.unwrap();
        assert_eq!(put_sizes.borrow().as_slice(), &[(0, 16)]);
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert_eq!(
                inner.vault.chunks_kept(&peer, &[0xE0; 16]).await.unwrap(),
                1
            );
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn replay_deferred_envelopes_prepass_handles_out_of_order_rekey_rollback_and_quarantine() {
    use protocol::mailbox_v2::{RegisterWriteTokenRequest, RegisterWriteTokenResponse};
    use std::rc::Rc;

    futures::executor::block_on(async {
        let mut bob_client = Client::new(Fetch::client(LOCAL_SERVER));
        let bob_id = bob_client.identity_key();
        let published = bob_client.prepare_publish_v2("localhost", 4, 4).unwrap();
        let p = &published.request;
        let make_bundle = |idx: usize, pq: bool| protocol::handshake_v2::ClaimBundleResponse {
            signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: p.signed_prekey_signature.clone(),
            one_time_prekey: p.one_time_prekeys.get(idx).cloned(),
            pq_last_resort: pq.then(|| p.pq_last_resort.first().cloned()).flatten(),
            pq_one_time_prekey: pq
                .then(|| p.pq_one_time_prekeys.get(idx).cloned())
                .flatten(),
            manifest: p.manifest.clone(),
        };
        let bundle_1 = make_bundle(0, true);
        let bundle_2 = make_bundle(1, true);
        let bundle_classical = make_bundle(2, false);
        bob_client.commit_publish_v2(published);

        let mut alice_1 = Client::new(ConnectClient::new(BundleResponse("/ClaimBundle", bundle_1)));
        let alice_proto = proto::ClientState::from(alice_1.state());
        let alice_peer = alice_1.identity_key();
        let prep_1 = alice_1
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(alice_1.make_hello("Alice", 1)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let inc_1 = Incoming::try_from(prep_1.request.message.as_ref().unwrap()).unwrap();
        let AcceptedInitial::Accepted {
            session: session_1_bob,
            ..
        } = bob_client
            .accept_initial_v2(
                &alice_peer,
                &Default::default(),
                &inc_1,
                Fetch::client(LOCAL_SERVER),
            )
            .unwrap()
        else {
            panic!("expected accepted initial 1");
        };

        // Alice rekeys (session_seq = 2) and encrypts two messages on the new session:
        // seq 100 (NO initial_message) and seq 101 (CARRIES rekey wire initial).
        let mut alice_2 = Client::restore(
            ConnectClient::new(BundleResponse("/ClaimBundle", bundle_2)),
            ClientState::try_from(&alice_proto).unwrap(),
        );
        let prep_2 = alice_2
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(alice_2.make_hello("Alice", 2)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let rekey_wire_2 = prep_2.request.message.clone().unwrap();
        let mut session_2_sender = prep_2.session;
        let msg_100 = session_2_sender
            .encrypt(&Kind::Text("out-of-order-first".into()).to_bytes())
            .unwrap();
        let msg_101 = session_2_sender
            .encrypt(&Kind::Text("carries-rekey-second".into()).to_bytes())
            .unwrap();

        let contacts = vec![super::contact::Contact {
            peer: alice_peer,
            session: session_1_bob,
            deferred_carried: 0,
            state: ContactState {
                peer: alice_peer.to_vec(),
                name: "Alice".into(),
                ..ContactState::default()
            },
        }];
        let inner = Inner::new(
            MemoryVault::default(),
            LOCAL_SERVER.into(),
            "localhost".into(),
            AppState {
                name: "Bob".into(),
                ..AppState::default()
            },
            bob_client,
            contacts,
            vec![],
            DeferredRecord::default(),
        );
        let engine = Engine::with_inner(Ui::new(), inner);

        // Buffer seq 100 (no initial) and seq 101 (with rekey initial) in Bob's deferred envelopes.
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.deferred_envelopes = vec![
                crate::vault::DeferredEnvelope {
                    peer: alice_peer.to_vec(),
                    sequence: 100,
                    message: Some(msg_100.message.clone()),
                    initial_message: None,
                    deferred_at: crate::util::now(),
                    pq_isolated: false,
                },
                crate::vault::DeferredEnvelope {
                    peer: alice_peer.to_vec(),
                    sequence: 101,
                    message: Some(msg_101.message.clone()),
                    initial_message: Some(rekey_wire_2.clone()),
                    deferred_at: crate::util::now(),
                    pq_isolated: false,
                },
            ];
            inner.save_state().await.unwrap();
        }

        // 1. Track RegisterWriteToken RPCs: Phase A runs `join_carried`, returning the staged
        //    grant peer without holding `self.inner` across network I/O while keeping BOTH
        //    deferred envelopes intact on disk, and Phase B decrypts BOTH seq 100 AND seq 101!
        let register_count = Rc::new(Cell::new(0usize));
        let reg_ref = register_count.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, body| {
                if path.ends_with("/RegisterWriteToken") {
                    let _ = RegisterWriteTokenRequest::decode(body.as_slice()).unwrap();
                    reg_ref.set(reg_ref.get() + 1);
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else {
                    panic!("unexpected path during replay_deferred_envelopes: {path}");
                }
            });
            let grant_peers = {
                let mut guard = engine.inner.lock().await;
                let inner = guard.as_mut().unwrap();

                // Inject save fault on Phase A -> nothing lost on disk or in memory.
                inner.vault.fail_save.set(true);
                assert!(
                    engine
                        .replay_deferred_envelopes(inner, Some(&alice_peer), Some(u64::MAX), None)
                        .await
                        .is_err()
                );
                assert_eq!(inner.deferred_envelopes.len(), 2);
                assert!(inner.deferred_envelopes[1].initial_message.is_some());
                inner.vault.fail_save.set(false);

                let (replayed, _, grant_peers) = engine
                    .replay_deferred_envelopes(inner, Some(&alice_peer), Some(u64::MAX), None)
                    .await
                    .unwrap();
                assert!(replayed.contains(&alice_peer));
                assert!(grant_peers.contains(&alice_peer));
                assert!(inner.deferred_envelopes.is_empty());
                assert!(inner.vault.deferred.borrow().envelopes.is_empty());
                let texts: Vec<String> = inner
                    .vault
                    .entries
                    .borrow()
                    .values()
                    .filter_map(|e| match e.content.as_ref()?.kind.as_ref()? {
                        Kind::Text(t) => Some(t.clone()),
                        _ => None,
                    })
                    .collect();
                assert!(
                    texts.contains(&"out-of-order-first".to_string()),
                    "{texts:?}"
                );
                assert!(
                    texts.contains(&"carries-rekey-second".to_string()),
                    "{texts:?}"
                );
                grant_peers
            };
            // Callers flush returned grant peers outside `self.inner` (R2-P2-4).
            for peer in grant_peers {
                engine.flush_pending_grants_for_peer(&peer).await.unwrap();
            }
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            assert!(
                inner
                    .contact(&alice_peer)
                    .unwrap()
                    .session
                    .pending_register_grants()
                    .is_empty(),
                "flushing returned grant peers must clear staged write-token grants"
            );
        }
        assert_eq!(
            register_count.get(),
            1,
            "flushing grant_peers must call RegisterWriteToken once"
        );

        // 2. Quarantine during Phase A: if a buffered envelope carries a classical downgrade
        //    initial (on a PQ-enabled build), `join_carried` quarantines the peer and Phase B
        //    recomputes eligibility, PRESERVING the peer's buffered envelopes instead of dropping!
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        {
            let mut alice_cls = Client::restore(
                ConnectClient::new(BundleResponse("/ClaimBundle", bundle_classical)),
                ClientState::try_from(&alice_proto).unwrap(),
            );
            alice_cls
                .set_pq_config(PqConfig {
                    pq_enabled: false,
                    pq_ratchet_enabled: false,
                    strict_pq: false,
                    ..PqConfig::default()
                })
                .unwrap();
            let prep_cls = alice_cls
                .prepare_initiate_v2(
                    "localhost",
                    &bob_id,
                    &Default::default(),
                    &Kind::Hello(alice_cls.make_hello("Alice", 3)).to_bytes(),
                    Fetch::client(LOCAL_SERVER),
                )
                .await
                .unwrap();
            let cls_wire = prep_cls.request.message.clone().unwrap();
            let mut cls_sender = prep_cls.session;
            let cls_msg = cls_sender
                .encrypt(&Kind::Text("must-not-be-dropped-while-quarantined".into()).to_bytes())
                .unwrap();

            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.deferred_envelopes = vec![crate::vault::DeferredEnvelope {
                peer: alice_peer.to_vec(),
                sequence: 200,
                message: Some(cls_msg.message.clone()),
                initial_message: Some(cls_wire),
                deferred_at: crate::util::now(),
                pq_isolated: false,
            }];
            inner.save_state().await.unwrap();

            let (replayed, _, _) = engine
                .replay_deferred_envelopes(inner, Some(&alice_peer), Some(u64::MAX), None)
                .await
                .unwrap();
            assert!(
                replayed.is_empty(),
                "newly quarantined peer must not decrypt or drop buffered messages"
            );
            assert!(inner.contact(&alice_peer).unwrap().state.quarantined);
            assert_eq!(
                inner.deferred_envelopes.len(),
                1,
                "buffered message for newly quarantined peer must be preserved"
            );
            assert!(
                inner.deferred_envelopes[0].initial_message.is_none(),
                "quarantined carried initial must not remain duplicated on DeferredEnvelope"
            );
        }
        #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
        let _ = bundle_classical;
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn receive_mailbox_avoids_duplicate_carried_initial_and_grants_flush_on_replays() {
    use protocol::handshake_v2::{AckInitialMessagesResponse, ListInitialMessagesResponse};
    use protocol::mailbox_v2::{
        AckMessagesResponse, EnvelopeV2, FetchSignedResponse, RegisterWriteTokenResponse,
    };
    use std::rc::Rc;

    futures::executor::block_on(async {
        let mut bob_client = Client::new(Fetch::client(LOCAL_SERVER));
        let bob_id = bob_client.identity_key();
        let published = bob_client.prepare_publish_v2("localhost", 5, 5).unwrap();
        let p = &published.request;
        let make_bundle = |idx: usize| protocol::handshake_v2::ClaimBundleResponse {
            signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: p.signed_prekey_signature.clone(),
            one_time_prekey: p.one_time_prekeys.get(idx).cloned(),
            pq_last_resort: p.pq_last_resort.first().cloned(),
            pq_one_time_prekey: p.pq_one_time_prekeys.get(idx).cloned(),
            manifest: p.manifest.clone(),
        };
        let bundle_1 = make_bundle(0);
        let bundle_2 = make_bundle(1);
        let bundle_3 = make_bundle(2);
        let bundle_4 = make_bundle(3);
        bob_client.commit_publish_v2(published);

        let mut alice_1 = Client::new(ConnectClient::new(BundleResponse("/ClaimBundle", bundle_1)));
        let alice_proto = proto::ClientState::from(alice_1.state());
        let alice_peer = alice_1.identity_key();
        let prep_1 = alice_1
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(alice_1.make_hello("Alice", 1)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let inc_1 = Incoming::try_from(prep_1.request.message.as_ref().unwrap()).unwrap();
        let AcceptedInitial::Accepted {
            session: session_1_bob,
            ..
        } = bob_client
            .accept_initial_v2(
                &alice_peer,
                &Default::default(),
                &inc_1,
                Fetch::client(LOCAL_SERVER),
            )
            .unwrap()
        else {
            panic!("expected accepted initial 1");
        };
        let token_hash_1 = session_1_bob.active_inbound_token_hash().unwrap();

        // 1. Rekey #2: carried on a mailbox envelope whose ciphertext is encrypted under session #2
        //    (immediate decrypt under session #1 fails -> buffers DeferredEnvelope WITHOUT
        //    duplicating `initial_message`, joins carried initial ONCE, flushes RegisterWriteToken,
        //    and replays cleanly!).
        let mut alice_2 = Client::restore(
            ConnectClient::new(BundleResponse("/ClaimBundle", bundle_2)),
            ClientState::try_from(&alice_proto).unwrap(),
        );
        let prep_2 = alice_2
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(alice_2.make_hello("Alice", 2)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let rekey_wire_2 = prep_2.request.message.clone().unwrap();
        let mut session_2_sender = prep_2.session;
        let msg_2 = session_2_sender
            .encrypt(&Kind::Text("delivered-after-carried-rekey".into()).to_bytes())
            .unwrap();

        let contacts = vec![super::contact::Contact {
            peer: alice_peer,
            session: session_1_bob,
            deferred_carried: 0,
            state: ContactState {
                peer: alice_peer.to_vec(),
                name: "Alice".into(),
                ..ContactState::default()
            },
        }];
        let inner = Inner::new(
            MemoryVault::default(),
            LOCAL_SERVER.into(),
            "localhost".into(),
            AppState {
                name: "Bob".into(),
                ..AppState::default()
            },
            bob_client,
            contacts,
            vec![],
            DeferredRecord::default(),
        );
        let engine = Engine::with_inner(Ui::new(), inner);

        let reg_calls = Rc::new(Cell::new(0usize));
        let reg_ref = reg_calls.clone();
        let env_rekey = EnvelopeV2 {
            sequence: 50,
            token_hash: Bytes::copy_from_slice(&token_hash_1),
            message: Some(msg_2.message.clone()),
            initial_message: Some(rekey_wire_2),
        };
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/FetchSigned") {
                    Ok((
                        200,
                        FetchSignedResponse {
                            messages: vec![env_rekey.clone()],
                            has_more: false,
                        }
                        .encode_to_vec(),
                    ))
                } else if path.ends_with("/AckMessages") {
                    Ok((200, AckMessagesResponse { deleted: 1 }.encode_to_vec()))
                } else if path.ends_with("/ListInitialMessages") {
                    Ok((
                        200,
                        ListInitialMessagesResponse {
                            messages: vec![],
                            has_more: false,
                        }
                        .encode_to_vec(),
                    ))
                } else if path.ends_with("/RegisterWriteToken") {
                    reg_ref.set(reg_ref.get() + 1);
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            let affected = engine.receive_mailbox().await.unwrap();
            assert_eq!(affected, vec![alice_peer]);
        }
        assert_eq!(
            reg_calls.get(),
            1,
            "receive_mailbox -> join_carried must flush RegisterWriteToken immediately"
        );
        assert!(
            !engine
                .ui()
                .log
                .get_untracked()
                .iter()
                .any(|(_, line)| line.contains("could not accept") || line.contains("rejected")),
            "carried initial must not be processed twice: {:?}",
            engine.ui().log.get_untracked()
        );
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(inner.deferred_envelopes.is_empty());
            let texts: Vec<String> = inner
                .vault
                .entries
                .borrow()
                .values()
                .filter_map(|e| match e.content.as_ref()?.kind.as_ref()? {
                    Kind::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect();
            assert!(
                texts.contains(&"delivered-after-carried-rekey".to_string()),
                "{texts:?}"
            );
        }

        // 2. `take_initial_messages` receiving Rekey #3 via inbox immediately replays a buffered
        //    `DeferredEnvelope` encrypted under session #3 without waiting for next POLL_LIVE!
        let mut alice_3 = Client::restore(
            ConnectClient::new(BundleResponse("/ClaimBundle", bundle_3)),
            ClientState::try_from(&alice_proto).unwrap(),
        );
        let prep_3 = alice_3
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(alice_3.make_hello("Alice", 3)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let mut rekey_wire_3 = prep_3.request.message.clone().unwrap();
        rekey_wire_3.id = 88;
        let mut session_3_sender = prep_3.session;
        let msg_3 = session_3_sender
            .encrypt(&Kind::Text("replayed-immediately-on-inbox-rekey".into()).to_bytes())
            .unwrap();

        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .deferred_envelopes
                .push(crate::vault::DeferredEnvelope {
                    peer: alice_peer.to_vec(),
                    sequence: 90,
                    message: Some(msg_3.message.clone()),
                    initial_message: None,
                    deferred_at: crate::util::now(),
                    pq_isolated: false,
                });
            inner.save_state().await.unwrap();
        }
        let reg_ref_3 = reg_calls.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/ListInitialMessages") {
                    Ok((
                        200,
                        ListInitialMessagesResponse {
                            messages: vec![rekey_wire_3.clone()],
                            has_more: false,
                        }
                        .encode_to_vec(),
                    ))
                } else if path.ends_with("/AckInitialMessages") {
                    Ok((
                        200,
                        AckInitialMessagesResponse { deleted: 1 }.encode_to_vec(),
                    ))
                } else if path.ends_with("/RegisterWriteToken") {
                    reg_ref_3.set(reg_ref_3.get() + 1);
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            assert!(engine.take_initial_messages().await.unwrap());
        }
        assert_eq!(reg_calls.get(), 2);
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(
                inner.deferred_envelopes.is_empty(),
                "take_initial_messages must replay buffered envelopes immediately"
            );
            let texts: Vec<String> = inner
                .vault
                .entries
                .borrow()
                .values()
                .filter_map(|e| match e.content.as_ref()?.kind.as_ref()? {
                    Kind::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect();
            assert!(
                texts.contains(&"replayed-immediately-on-inbox-rekey".to_string()),
                "{texts:?}"
            );
        }

        // 3. `replay_deferred_initials` immediately flushes `RegisterWriteToken` for a deferred
        //    rekey on an already-approved contact!
        let mut alice_4 = Client::restore(
            ConnectClient::new(BundleResponse("/ClaimBundle", bundle_4)),
            ClientState::try_from(&alice_proto).unwrap(),
        );
        let prep_4 = alice_4
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(alice_4.make_hello("Alice", 4)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let rekey_wire_4 = prep_4.request.message.clone().unwrap();
        let reg_ref_4 = reg_calls.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/RegisterWriteToken") {
                    reg_ref_4.set(reg_ref_4.get() + 1);
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else {
                    panic!("unexpected path during replay_deferred_initials: {path}");
                }
            });
            let grant_peers = {
                let mut guard = engine.inner.lock().await;
                let inner = guard.as_mut().unwrap();
                inner.deferred_initials.push(DeferredInitial {
                    initial: Some(rekey_wire_4),
                    deferred_at: crate::util::now(),
                });
                let (_upgrades, grant_peers) = engine
                    .replay_deferred_initials(inner)
                    .await
                    .unwrap()
                    .expect("replay_deferred_initials should process rekey");
                assert!(grant_peers.contains(&alice_peer));
                grant_peers
            };
            // Callers flush returned grant peers outside `self.inner` (R2-P2-4).
            for peer in grant_peers {
                engine.flush_pending_grants_for_peer(&peer).await.unwrap();
            }
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            assert!(
                inner
                    .contact(&alice_peer)
                    .unwrap()
                    .session
                    .pending_register_grants()
                    .is_empty(),
                "flushing grant_peers from replay_deferred_initials must clear pending grants"
            );
        }
        assert_eq!(reg_calls.get(), 3);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn deferred_envelopes_survive_cross_peer_and_multipage_inbox_replay() {
    use protocol::handshake_v2::{
        AckInitialMessagesResponse, ListInitialMessagesRequest, ListInitialMessagesResponse,
    };
    use protocol::mailbox_v2::{
        AckMessagesResponse, EnvelopeV2, FetchSignedResponse, RegisterWriteTokenResponse,
    };
    use std::rc::Rc;

    futures::executor::block_on(async {
        let mut bob_client = Client::new(Fetch::client(LOCAL_SERVER));
        let bob_id = bob_client.identity_key();
        let published = bob_client.prepare_publish_v2("localhost", 8, 8).unwrap();
        let p = &published.request;
        let make_bundle = |idx: usize| protocol::handshake_v2::ClaimBundleResponse {
            signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: p.signed_prekey_signature.clone(),
            one_time_prekey: p.one_time_prekeys.get(idx).cloned(),
            pq_last_resort: p.pq_last_resort.first().cloned(),
            pq_one_time_prekey: p.pq_one_time_prekeys.get(idx).cloned(),
            manifest: p.manifest.clone(),
        };
        let bundle_a1 = make_bundle(0);
        let bundle_a2 = make_bundle(1);
        let bundle_b1 = make_bundle(2);
        let bundle_a3 = make_bundle(3);
        let bundle_c1 = make_bundle(4);
        let bundle_a4 = make_bundle(5);
        bob_client.commit_publish_v2(published);

        // Establish Peer A (Alice) session #1 with Bob.
        let mut alice_1 = Client::new(ConnectClient::new(BundleResponse(
            "/ClaimBundle",
            bundle_a1,
        )));
        let alice_proto = proto::ClientState::from(alice_1.state());
        let peer_a = alice_1.identity_key();
        let prep_a1 = alice_1
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(alice_1.make_hello("Alice", 1)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let inc_a1 = Incoming::try_from(prep_a1.request.message.as_ref().unwrap()).unwrap();
        let AcceptedInitial::Accepted {
            session: session_a1_bob,
            ..
        } = bob_client
            .accept_initial_v2(
                &peer_a,
                &Default::default(),
                &inc_a1,
                Fetch::client(LOCAL_SERVER),
            )
            .unwrap()
        else {
            panic!("expected accepted initial a1");
        };
        let token_hash_a1 = session_a1_bob.active_inbound_token_hash().unwrap();

        let contacts = vec![super::contact::Contact {
            peer: peer_a,
            session: session_a1_bob,
            deferred_carried: 0,
            state: ContactState {
                peer: peer_a.to_vec(),
                name: "Alice".into(),
                ..ContactState::default()
            },
        }];
        let inner = Inner::new(
            MemoryVault::default(),
            LOCAL_SERVER.into(),
            "localhost".into(),
            AppState {
                name: "Bob".into(),
                ..AppState::default()
            },
            bob_client,
            contacts,
            vec![],
            DeferredRecord::default(),
        );
        let engine = Engine::with_inner(Ui::new(), inner);

        // 1. Cross-peer race in `receive_mailbox`:
        //    Peer A sends a mailbox envelope carrying rekey_A2 + message encrypted under rekey_A2
        //    (buffered with `initial_message = None` while `rekey_A2` sits in
        //    `pending_carried_initials`). During `receive_mailbox`'s `take_initial_messages()`,
        //    unrelated Peer B delivers an inbox initial (`batch.dirty == true`).
        //    Peer A's buffered envelope MUST NOT be prematurely dropped during Peer B's inbox pass!
        let mut alice_2 = Client::restore(
            ConnectClient::new(BundleResponse("/ClaimBundle", bundle_a2)),
            ClientState::try_from(&alice_proto).unwrap(),
        );
        let prep_a2 = alice_2
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(alice_2.make_hello("Alice", 2)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let rekey_a2_wire = prep_a2.request.message.clone().unwrap();
        let mut sender_a2 = prep_a2.session;
        let msg_a2 = sender_a2
            .encrypt(&Kind::Text("peer-a-after-carried-rekey".into()).to_bytes())
            .unwrap();

        let mut peer_b_client = Client::new(ConnectClient::new(BundleResponse(
            "/ClaimBundle",
            bundle_b1,
        )));
        let peer_b = peer_b_client.identity_key();
        let prep_b1 = peer_b_client
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(peer_b_client.make_hello("PeerB", 1)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let mut peer_b_wire = prep_b1.request.message.clone().unwrap();
        peer_b_wire.id = 7;

        let env_a2 = EnvelopeV2 {
            sequence: 101,
            token_hash: Bytes::copy_from_slice(&token_hash_a1),
            message: Some(msg_a2.message.clone()),
            initial_message: Some(rekey_a2_wire),
        };
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/FetchSigned") {
                    Ok((
                        200,
                        FetchSignedResponse {
                            messages: vec![env_a2.clone()],
                            has_more: false,
                        }
                        .encode_to_vec(),
                    ))
                } else if path.ends_with("/AckMessages") {
                    Ok((200, AckMessagesResponse { deleted: 1 }.encode_to_vec()))
                } else if path.ends_with("/ListInitialMessages") {
                    Ok((
                        200,
                        ListInitialMessagesResponse {
                            messages: vec![peer_b_wire.clone()],
                            has_more: false,
                        }
                        .encode_to_vec(),
                    ))
                } else if path.ends_with("/AckInitialMessages") {
                    Ok((
                        200,
                        AckInitialMessagesResponse { deleted: 1 }.encode_to_vec(),
                    ))
                } else if path.ends_with("/RegisterWriteToken") {
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            let affected = engine.receive_mailbox().await.unwrap();
            assert_eq!(affected, vec![peer_a]);
        }
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(
                inner
                    .contacts
                    .iter()
                    .find(|c| c.peer == peer_b)
                    .is_some_and(|c| c.state.request),
                "unrelated Peer B inbox request must be persisted"
            );
            assert!(
                inner.deferred_envelopes.is_empty(),
                "Peer A buffered envelope must replay cleanly after carried rekey joins"
            );
            let texts: Vec<String> = inner
                .vault
                .entries
                .borrow()
                .values()
                .filter_map(|e| match e.content.as_ref()?.kind.as_ref()? {
                    Kind::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect();
            assert!(
                texts.contains(&"peer-a-after-carried-rekey".to_string()),
                "Peer A message must not be dropped during Peer B inbox replay: {texts:?}"
            );
        }

        // 2. Direct `replay_deferred_envelopes` Phase A pre-pass must join ALREADY-staged
        //    `pending_carried_initials` even when `DeferredEnvelope.initial_message` is `None`.
        let mut alice_3 = Client::restore(
            ConnectClient::new(BundleResponse("/ClaimBundle", bundle_a3)),
            ClientState::try_from(&alice_proto).unwrap(),
        );
        let prep_a3 = alice_3
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(alice_3.make_hello("Alice", 3)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let inc_a3 = Incoming::try_from(prep_a3.request.message.as_ref().unwrap()).unwrap();
        let mut sender_a3 = prep_a3.session;
        let msg_a3 = sender_a3
            .encrypt(&Kind::Text("direct-replay-joins-staged-carried".into()).to_bytes())
            .unwrap();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/RegisterWriteToken") {
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            super::handshake::stage_carried_initials(
                &mut inner.contact(&peer_a).unwrap().state,
                [&inc_a3],
            )
            .unwrap();
            inner
                .deferred_envelopes
                .push(crate::vault::DeferredEnvelope {
                    peer: peer_a.to_vec(),
                    sequence: 202,
                    message: Some(msg_a3.message.clone()),
                    initial_message: None,
                    deferred_at: crate::util::now(),
                    pq_isolated: false,
                });
            inner.save_state().await.unwrap();

            let (replayed, _, _) = engine
                .replay_deferred_envelopes(inner, Some(&peer_a), Some(u64::MAX), None)
                .await
                .unwrap();
            assert!(replayed.contains(&peer_a));
            assert!(inner.deferred_envelopes.is_empty());
            assert!(
                inner
                    .contact(&peer_a)
                    .unwrap()
                    .state
                    .pending_carried_initials
                    .is_empty()
            );
            let texts: Vec<String> = inner
                .vault
                .entries
                .borrow()
                .values()
                .filter_map(|e| match e.content.as_ref()?.kind.as_ref()? {
                    Kind::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect();
            assert!(
                texts.contains(&"direct-replay-joins-staged-carried".to_string()),
                "{texts:?}"
            );
        }

        // 3. Multi-page inbox pagination (`has_more = true`):
        //    Bob has a buffered envelope for Peer A encrypted under rekey_A4.
        //    Page 1 (`after_id = 0`) returns an unrelated Peer C initial (`id = 15`, `has_more = true`).
        //    Page 2 (`after_id = 15`) returns Peer A's rekey_A4 (`id = 30`, `has_more = false`).
        //    Page 1 MUST NOT drop Peer A's buffered envelope; replay happens AFTER Page 2!
        let mut peer_c_client = Client::new(ConnectClient::new(BundleResponse(
            "/ClaimBundle",
            bundle_c1,
        )));
        let peer_c = peer_c_client.identity_key();
        let prep_c1 = peer_c_client
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(peer_c_client.make_hello("PeerC", 1)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let mut peer_c_wire = prep_c1.request.message.clone().unwrap();
        peer_c_wire.id = 15;

        let mut alice_4 = Client::restore(
            ConnectClient::new(BundleResponse("/ClaimBundle", bundle_a4)),
            ClientState::try_from(&alice_proto).unwrap(),
        );
        let prep_a4 = alice_4
            .prepare_initiate_v2(
                "localhost",
                &bob_id,
                &Default::default(),
                &Kind::Hello(alice_4.make_hello("Alice", 4)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let mut rekey_a4_wire = prep_a4.request.message.clone().unwrap();
        rekey_a4_wire.id = 30;
        let mut sender_a4 = prep_a4.session;
        let msg_a4 = sender_a4
            .encrypt(&Kind::Text("delivered-after-page-2-rekey".into()).to_bytes())
            .unwrap();

        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .deferred_envelopes
                .push(crate::vault::DeferredEnvelope {
                    peer: peer_a.to_vec(),
                    sequence: 303,
                    message: Some(msg_a4.message.clone()),
                    initial_message: None,
                    deferred_at: crate::util::now(),
                    pq_isolated: false,
                });
            inner.save_state().await.unwrap();
        }
        let seen_after_ids: Rc<RefCell<Vec<u64>>> = Rc::default();
        let seen_ref = seen_after_ids.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, body| {
                if path.ends_with("/ListInitialMessages") {
                    let req = ListInitialMessagesRequest::decode(body.as_slice()).unwrap();
                    seen_ref.borrow_mut().push(req.after_id);
                    if req.after_id == 0 {
                        Ok((
                            200,
                            ListInitialMessagesResponse {
                                messages: vec![peer_c_wire.clone()],
                                has_more: true,
                            }
                            .encode_to_vec(),
                        ))
                    } else if req.after_id == 15 {
                        Ok((
                            200,
                            ListInitialMessagesResponse {
                                messages: vec![rekey_a4_wire.clone()],
                                has_more: false,
                            }
                            .encode_to_vec(),
                        ))
                    } else {
                        panic!("unexpected after_id: {}", req.after_id);
                    }
                } else if path.ends_with("/AckInitialMessages") {
                    Ok((
                        200,
                        AckInitialMessagesResponse { deleted: 1 }.encode_to_vec(),
                    ))
                } else if path.ends_with("/RegisterWriteToken") {
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            assert!(engine.take_initial_messages().await.unwrap());
        }
        assert_eq!(seen_after_ids.borrow().as_slice(), &[0, 15]);
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(
                inner
                    .contacts
                    .iter()
                    .find(|c| c.peer == peer_c)
                    .is_some_and(|c| c.state.request)
            );
            assert!(
                inner.deferred_envelopes.is_empty(),
                "Page 2 rekey must replay Peer A buffered envelope after pagination completes"
            );
            let texts: Vec<String> = inner
                .vault
                .entries
                .borrow()
                .values()
                .filter_map(|e| match e.content.as_ref()?.kind.as_ref()? {
                    Kind::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect();
            assert!(
                texts.contains(&"delivered-after-page-2-rekey".to_string()),
                "{texts:?}"
            );
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn teardown_on_pagehide_revokes_generation_while_inner_is_held_and_blocks_post_pagehide_writes() {
    use crate::kdf_worker::{KdfCancelToken, derive_kek_async};
    use crate::notify::{CloseHandle, Event};
    use crate::state::{Link, Phase};
    use leptos::prelude::Set;

    futures::executor::block_on(async {
        let (mut inner, peer) = unlocked_client();
        inner.state.name = "Alice Secret".into();
        inner.contacts[0].state.name = "Bob Secret".into();
        inner.contacts[0].state.history_len = 1;
        inner.vault.entries.borrow_mut().insert(
            (peer, 0),
            HistoryEntry {
                outgoing: false,
                at: 100,
                place: 1,
                content: Some(Content {
                    clock: 1,
                    kind: Some(Kind::Text("classified payload".into())),
                    events: None,
                }),
                ..HistoryEntry::default()
            },
        );
        let ui = Ui::new();
        let engine = Engine::with_inner(ui, inner);
        assert_eq!(engine.open(Some(peer)).await, OpenOutcome::Opened);
        ui.dialog.set(Some(Dialog::Settings));
        ui.notify("sensitive notice");
        ui.log("sensitive log line");
        ui.live.set(true);
        ui.syncing.set(true);
        ui.link.set(Link::Synced(123));

        // Attach a live WebSocket CloseHandle and a tracked blob URL.
        let (handle, mut ws_events) = CloseHandle::test_pair();
        *engine.ws_close.borrow_mut() = Some(handle.clone());
        crate::app::register_blob_url("blob:https://example.test/pagehide-leak-check");
        assert!(crate::app::live_blob_url_count() >= 1);

        let before_gen = engine.vault_gen();
        let before_lock_gen = crate::glue::lock_generation();
        assert!(engine.is_live(before_gen));

        // Hold `self.inner` across an `.await` boundary via `lock_inner()` (simulating an
        // in-flight sync/flush/send task) while synchronous `pagehide` teardown fires.
        {
            let mut held_guard = engine.lock_inner().await;
            assert!(held_guard.is_some());

            engine.teardown_on_pagehide();

            // 1. Both Engine and glue generations bumped synchronously.
            assert!(!engine.is_live(before_gen));
            assert_ne!(engine.vault_gen(), before_gen);
            assert_ne!(crate::glue::lock_generation(), before_lock_gen);

            // 2. Notification WebSocket closed synchronously via CloseHandle without awaiting inner.
            assert!(handle.is_closed());
            assert!(matches!(ws_events.try_recv(), Ok(Event::Closed)));
            assert!(engine.ws_close.borrow().is_none());

            // 3. All tracked blob URLs drained synchronously.
            assert_eq!(crate::app::live_blob_url_count(), 0);
            assert_eq!(crate::glue::active_media_port_count(), 0);

            // 4. ALL sensitive UI signals scrubbed synchronously.
            assert_eq!(ui.phase.get_untracked(), Phase::Locked);
            assert!(ui.me.get_untracked().is_none());
            assert!(ui.contacts.get_untracked().is_empty());
            assert!(ui.isolated_contacts.get_untracked().is_empty());
            assert!(ui.open.get_untracked().is_none());
            assert!(ui.messages.get_untracked().is_empty());
            assert!(ui.uploads.get_untracked().is_empty());
            assert!(ui.dialog.get_untracked().is_none());
            assert!(ui.viewer.get_untracked().is_none());
            assert!(ui.opening.get_untracked().is_none());
            assert!(ui.streaming.get_untracked().is_none());
            assert!(ui.log.get_untracked().is_empty());
            assert!(ui.notice.get_untracked().is_none());
            assert!(!ui.live.get_untracked());
            assert!(!ui.syncing.get_untracked());

            // 5. While the suspended task still holds `held_guard`, every persistence write MUST
            //    fail closed without modifying `MemoryVault`!
            let inner = held_guard.as_mut().expect("still held until guard drops");
            let entries_before = inner.vault.entries.borrow().len();
            inner.state.name = "Post-Pagehide Mutation".into();
            let err = inner
                .save(&[(
                    peer,
                    1,
                    HistoryEntry {
                        outgoing: true,
                        at: 200,
                        place: 2,
                        content: Some(Content {
                            clock: 2,
                            kind: Some(Kind::Text("must not persist".into())),
                            events: None,
                        }),
                        ..HistoryEntry::default()
                    },
                )])
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("page is closing"),
                "unexpected error: {err}"
            );
            assert_eq!(inner.vault.entries.borrow().len(), entries_before);
            assert_ne!(
                inner.vault.state.borrow().name,
                "Post-Pagehide Mutation",
                "vault state must not be overwritten after pagehide"
            );

            // Forget also fails closed.
            let state = inner.app_state();
            let deferred = inner.deferred_record();
            assert!(inner.forget_peer(&peer, state, deferred).await.is_err());
        }

        // 6. As soon as `InnerGuard` drops, `Inner` is automatically wiped.
        assert!(
            engine.inner.try_lock().expect("uncontended").is_none(),
            "InnerGuard::drop must take and drop Inner once teardown fired"
        );

        // 7. Subsequent async engine calls must fail/no-op cleanly with zero UI repaints.
        assert_eq!(engine.open(Some(peer)).await, OpenOutcome::Ignored);
        assert!(
            engine
                .send_returning_index(peer, Kind::Text("late".into()))
                .await
                .is_err()
        );
        assert_eq!(ui.phase.get_untracked(), Phase::Locked);
        assert!(ui.contacts.get_untracked().is_empty());
        assert!(ui.messages.get_untracked().is_empty());
        assert!(ui.open.get_untracked().is_none());

        // 8. Cancelled KdfCancelToken aborts host KDF derivation immediately (before running Argon2id).
        let token = KdfCancelToken::new();
        token.cancel();
        let res = derive_kek_async(
            b"passphrase",
            &[0x55u8; 16],
            crate::vault::ARGON2_MEMORY_MIN,
            1,
            1,
            &token,
        )
        .await;
        assert_eq!(res, Err(crate::kdf_worker::KdfError::Cancelled));
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn start_chat_aborts_without_ui_repaint_when_teardown_fires_during_save() {
    use crate::state::{PendingNewChat, Phase};
    use crate::util::key_to_text;

    futures::executor::block_on(async {
        let prev_released = crate::glue::set_lock_released_for_test(false);
        let _restore_lock = scopeguard::guard(prev_released, |prev| {
            crate::glue::set_lock_released_for_test(prev);
        });

        let (mut inner, peer) = unlocked_client();
        inner.contacts[0].state.name = "Bob Before".into();
        let ui = Ui::new();
        let engine = Engine::with_inner(ui, inner);

        // Register a live startup submission so `teardown_on_pagehide()` cancels it just like a
        // real browser `pagehide` / manual Lock during an in-flight `start_chat`.
        let key_text = key_to_text(&peer);
        let submission_id = engine.begin_new_chat_submit(PendingNewChat {
            key: key_text.clone(),
            name: "Bob Renamed".into(),
            server: None,
            pq_pinned: false,
            allow_classical: false,
            auto_start: true,
        });

        // Fire `glue::teardown_and_release_lock()` right as `inner.save(&[]).await` finishes
        // inside `start_chat`'s existing-contact branch.
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            *inner.vault.on_save.borrow_mut() = Some(Box::new(|| {
                crate::glue::teardown_and_release_lock();
            }));
        }

        let res = engine
            .start_chat(
                submission_id,
                &key_text,
                "Bob Renamed".into(),
                None,
                false,
                false,
            )
            .await;

        assert_eq!(res, Err(StartChatError::Cancelled));
        assert!(crate::glue::lock_released());
        assert!(engine.is_shutting_down());
        assert_eq!(ui.phase.get_untracked(), Phase::Locked);
        assert!(
            ui.contacts.get_untracked().is_empty(),
            "post-teardown start_chat must not repopulate ui.contacts"
        );
        assert!(
            ui.log.get_untracked().is_empty(),
            "post-teardown start_chat must not append ui.log"
        );
        assert!(
            ui.notice.get_untracked().is_none(),
            "post-teardown start_chat must not set ui.notice"
        );
        assert!(
            engine.inner.try_lock().expect("uncontended").is_none(),
            "InnerGuard::drop must clear Inner on exit"
        );
    });
}

/// Suspend on an optional oneshot gate without holding the `RefCell` borrow across `.await`.
#[cfg(not(target_arch = "wasm32"))]
async fn await_gate(slot: &RefCell<Option<futures::channel::oneshot::Receiver<()>>>) {
    let rx = slot.borrow_mut().take();
    if let Some(rx) = rx {
        let _ = rx.await;
    }
}

/// Publish a v2 bundle on `client` and return a `ClaimBundleResponse` using prekey slot `idx`.
#[cfg(not(target_arch = "wasm32"))]
fn publish_bundle_for_test(
    client: &mut Client<Connect>,
    audience: &str,
    count: usize,
) -> Vec<protocol::handshake_v2::ClaimBundleResponse> {
    let published = client.prepare_publish_v2(audience, count, count).unwrap();
    let p = &published.request;
    let bundles = (0..count)
        .map(|idx| protocol::handshake_v2::ClaimBundleResponse {
            signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: p.signed_prekey_signature.clone(),
            one_time_prekey: p.one_time_prekeys.get(idx).cloned(),
            pq_last_resort: p.pq_last_resort.first().cloned(),
            pq_one_time_prekey: p.pq_one_time_prekeys.get(idx).cloned(),
            manifest: p.manifest.clone(),
        })
        .collect();
    client.commit_publish_v2(published);
    bundles
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn start_chat_claim_bundle_and_send_initial_release_inner_lock() {
    use crate::state::PendingNewChat;
    use crate::util::key_to_text;
    use crate::vault::GREETING_DELIVERY_CONFIRMED;
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use protocol::handshake_v2::{ClaimBundleRequest, SendInitialV2Response};
    use protocol::mailbox_v2::{PushV2Response, RegisterWriteTokenResponse};
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    let (engine, peer_b, peer_a_client, bundle_a1, bundle_a2, alice_bundle) =
        pool.run_until(async {
            let (engine, peer_b, _bob) = established_engine_on_localhost().await;
            // Mark Alice's own manifest published so `start_chat` goes straight to ClaimBundle ->
            // RegisterWriteToken -> SendInitialV2.
            let alice_bundle = {
                let mut guard = engine.inner.lock().await;
                let inner = guard.as_mut().unwrap();
                let bundles = publish_bundle_for_test(&mut inner.client, "localhost", 2);
                inner.state.published_at = crate::util::now();
                inner.save_state().await.unwrap();
                bundles.into_iter().next().unwrap()
            };
            let mut peer_a_client = Client::new(Fetch::client(LOCAL_SERVER));
            let mut bundles = publish_bundle_for_test(&mut peer_a_client, "localhost", 2);
            let bundle_a1 = bundles.remove(0);
            let bundle_a2 = bundles.remove(0);
            (
                engine,
                peer_b,
                peer_a_client,
                bundle_a1,
                bundle_a2,
                alice_bundle,
            )
        });
    let peer_a = peer_a_client.identity_key();

    // Part 1: Suspend ClaimBundle in start_chat(peer_a) -> verify open(peer_b) / send(peer_b) /
    // flush(peer_b) complete immediately; also suspend SendInitialV2 and verify peer_b still
    // completes immediately; then release and verify peer_a finishes cleanly.
    let (claim_tx, claim_rx) = oneshot::channel::<()>();
    let (send_init_tx, send_init_rx) = oneshot::channel::<()>();
    let claim_rx = Rc::new(RefCell::new(Some(claim_rx)));
    let send_init_rx = Rc::new(RefCell::new(Some(send_init_rx)));
    let claim_started = Rc::new(Cell::new(false));
    let send_init_started = Rc::new(Cell::new(false));
    let reg_calls = Rc::new(Cell::new(0usize));
    let peer_b_pushes = Rc::new(Cell::new(0usize));
    let seq = Rc::new(Cell::new(0u64));

    let claim_rx_ref = claim_rx.clone();
    let send_init_rx_ref = send_init_rx.clone();
    let claim_started_ref = claim_started.clone();
    let send_init_started_ref = send_init_started.clone();
    let reg_calls_ref = reg_calls.clone();
    let peer_b_pushes_ref = peer_b_pushes.clone();
    let seq_ref = seq.clone();
    let bundle_a1_clone = bundle_a1.clone();

    let _mock = crate::transport::mock_fetch_async(move |_server, path, body| {
        let claim_rx_ref = claim_rx_ref.clone();
        let send_init_rx_ref = send_init_rx_ref.clone();
        let claim_started_ref = claim_started_ref.clone();
        let send_init_started_ref = send_init_started_ref.clone();
        let reg_calls_ref = reg_calls_ref.clone();
        let peer_b_pushes_ref = peer_b_pushes_ref.clone();
        let seq_ref = seq_ref.clone();
        let bundle_a1_clone = bundle_a1_clone.clone();
        async move {
            if path.ends_with("/ClaimBundle") {
                let req = ClaimBundleRequest::decode(body.as_slice()).unwrap();
                assert_eq!(req.identity_key.as_ref(), peer_a.as_slice());
                claim_started_ref.set(true);
                await_gate(&claim_rx_ref).await;
                Ok((200, bundle_a1_clone.encode_to_vec()))
            } else if path.ends_with("/RegisterWriteToken") {
                reg_calls_ref.set(reg_calls_ref.get() + 1);
                Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
            } else if path.ends_with("/SendInitialV2") {
                send_init_started_ref.set(true);
                await_gate(&send_init_rx_ref).await;
                Ok((200, SendInitialV2Response { id: 1 }.encode_to_vec()))
            } else if path.ends_with("/PushV2") {
                let req = PushV2Request::decode(body.as_slice()).unwrap();
                assert_eq!(req.recipient.as_ref(), peer_b.as_slice());
                peer_b_pushes_ref.set(peer_b_pushes_ref.get() + 1);
                let next = seq_ref.get() + 1;
                seq_ref.set(next);
                Ok((200, PushV2Response { sequence: next }.encode_to_vec()))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });

    let key_a_text = key_to_text(&peer_a);
    let sub_id = engine.begin_new_chat_submit(PendingNewChat {
        key: key_a_text.clone(),
        name: "Carol".into(),
        server: None,
        pq_pinned: false,
        allow_classical: false,
        auto_start: false,
    });
    let start_done = Rc::new(RefCell::new(None::<Result<PublicKey, StartChatError>>));
    let start_done_ref = start_done.clone();
    let eng_clone = engine.clone();
    spawner
        .spawn_local(async move {
            let res = eng_clone
                .start_chat(sub_id, &key_a_text, "Carol".into(), None, false, false)
                .await;
            *start_done_ref.borrow_mut() = Some(res);
        })
        .unwrap();

    // Advance until `start_chat` suspends inside `ClaimBundle`.
    pool.run_until_stalled();
    assert!(
        claim_started.get(),
        "start_chat must have issued ClaimBundle"
    );
    assert!(
        start_done.borrow().is_none(),
        "start_chat must remain suspended while ClaimBundle is gated"
    );

    // While ClaimBundle(peer_a) is suspended, open(peer_b), send(peer_b), and flush(peer_b) MUST
    // complete immediately without blocking on Engine::inner!
    let outcome = pool.run_until(engine.open(Some(peer_b)));
    assert_eq!(outcome, OpenOutcome::Opened);
    let idx1 = pool
        .run_until(engine.send_returning_index(peer_b, Kind::Text("during-claim".into())))
        .unwrap();
    assert_eq!(peer_b_pushes.get(), 1);
    assert!(
        start_done.borrow().is_none(),
        "start_chat must still be suspended"
    );
    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(
            inner.vault.entries.borrow()[&(peer_b, idx1)].delivery(),
            Delivery::Sent
        );
        assert!(
            inner
                .contacts
                .iter()
                .find(|c| c.peer == peer_b)
                .unwrap()
                .state
                .outbox
                .is_empty()
        );
    });

    // Release ClaimBundle -> start_chat persists, flushes RegisterWriteToken, and suspends in SendInitialV2.
    claim_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(reg_calls.get(), 1);
    assert!(
        send_init_started.get(),
        "start_chat must have issued SendInitialV2 after RegisterWriteToken"
    );
    assert!(start_done.borrow().is_none());

    // While SendInitialV2(peer_a) is suspended, send(peer_b) + flush(peer_b) still runs unblocked!
    let idx2 = pool
        .run_until(engine.send_returning_index(peer_b, Kind::Text("during-send-initial".into())))
        .unwrap();
    assert_eq!(peer_b_pushes.get(), 2);
    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(
            inner.vault.entries.borrow()[&(peer_b, idx2)].delivery(),
            Delivery::Sent
        );
    });

    // Release SendInitialV2 -> start_chat finishes cleanly and confirms greeting delivery.
    send_init_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*start_done.borrow(), Some(Ok(peer_a)));
    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        let contact_a = inner
            .contacts
            .iter()
            .find(|c| c.peer == peer_a)
            .expect("peer_a persisted");
        assert_eq!(
            contact_a.state.greeting_delivery,
            GREETING_DELIVERY_CONFIRMED
        );
        assert!(contact_a.session.pending_register_grants().is_empty());
    });
    drop(_mock);

    // Part 2: Inbound initial arrives from a new peer (peer_c) while start_chat(peer_c)'s
    // ClaimBundle is suspended -> stale bundle is discarded without corrupting peer_c's ratchet!
    let mut peer_c_client = Client::new(ConnectClient::new(BundleResponse(
        "/ClaimBundle",
        alice_bundle,
    )));
    let peer_c = peer_c_client.identity_key();
    let alice_id = pool.run_until(async {
        engine
            .inner
            .lock()
            .await
            .as_ref()
            .unwrap()
            .client
            .identity_key()
    });
    let prep_c = pool.run_until(async {
        peer_c_client
            .prepare_initiate_v2(
                "localhost",
                &alice_id,
                &Default::default(),
                &Kind::Hello(peer_c_client.make_hello("Dave", 1)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap()
    });
    let inbound_c = Incoming::try_from(prep_c.request.message.as_ref().unwrap()).unwrap();
    let mut dave_sender_session = prep_c.session;
    let dave_expected_id = *dave_sender_session.active_id().unwrap();

    // Publish a real bundle for peer_c so `claim_peer_bundle_v2` returns `Ok(ClaimedPeerBundle)`.
    let bundle_c = {
        let mut peer_c_pub = Client::restore(
            Fetch::client(LOCAL_SERVER),
            ClientState::try_from(&proto::ClientState::from(peer_c_client.state())).unwrap(),
        );
        publish_bundle_for_test(&mut peer_c_pub, "localhost", 1)
            .into_iter()
            .next()
            .unwrap()
    };
    let (claim_c_tx, claim_c_rx) = oneshot::channel::<()>();
    let claim_c_rx = Rc::new(RefCell::new(Some(claim_c_rx)));
    let claim_c_started = Rc::new(Cell::new(false));
    let send_init_c_calls = Rc::new(Cell::new(0usize));
    let claim_c_rx_ref = claim_c_rx.clone();
    let claim_c_started_ref = claim_c_started.clone();
    let send_init_c_calls_ref = send_init_c_calls.clone();
    let _mock_c = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let claim_c_rx_ref = claim_c_rx_ref.clone();
        let claim_c_started_ref = claim_c_started_ref.clone();
        let send_init_c_calls_ref = send_init_c_calls_ref.clone();
        let bundle_c = bundle_c.clone();
        async move {
            if path.ends_with("/ClaimBundle") {
                claim_c_started_ref.set(true);
                await_gate(&claim_c_rx_ref).await;
                Ok((200, bundle_c.encode_to_vec()))
            } else if path.ends_with("/RegisterWriteToken") {
                Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
            } else if path.ends_with("/PushV2") {
                Ok((200, PushV2Response { sequence: 99 }.encode_to_vec()))
            } else if path.ends_with("/SendInitialV2") {
                send_init_c_calls_ref.set(send_init_c_calls_ref.get() + 1);
                Ok((200, SendInitialV2Response { id: 1 }.encode_to_vec()))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });
    let _ = bundle_a2;

    let key_c_text = key_to_text(&peer_c);
    let sub_c = engine.begin_new_chat_submit(PendingNewChat {
        key: key_c_text.clone(),
        name: "Dave".into(),
        server: None,
        pq_pinned: false,
        allow_classical: false,
        auto_start: false,
    });
    let start_c_done = Rc::new(RefCell::new(None::<Result<PublicKey, StartChatError>>));
    let start_c_done_ref = start_c_done.clone();
    let eng_c = engine.clone();
    spawner
        .spawn_local(async move {
            let res = eng_c
                .start_chat(sub_c, &key_c_text, "Dave".into(), None, false, false)
                .await;
            *start_c_done_ref.borrow_mut() = Some(res);
        })
        .unwrap();

    pool.run_until_stalled();
    assert!(claim_c_started.get());
    assert!(start_c_done.borrow().is_none());

    // Inject Dave's inbound initial while start_chat(Dave)'s ClaimBundle is suspended!
    pool.run_until(async {
        let mut guard = engine.lock_inner().await;
        let inner = guard.as_mut().unwrap();
        let mut batch = InitialBatch::default();
        engine.process_initial(inner, &peer_c, &inbound_c, &mut batch);
        engine.save_initial_batch(inner, batch).await.unwrap();
    });

    // Release ClaimBundle -> start_chat sees peer_c already exists, discards stale bundle, accepts
    // the inbound request cleanly without calling SendInitialV2 or corrupting Dave's ratchet!
    claim_c_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*start_c_done.borrow(), Some(Ok(peer_c)));
    assert_eq!(
        send_init_c_calls.get(),
        0,
        "stale ClaimBundle must be discarded without transmitting SendInitialV2"
    );
    pool.run_until(async {
        let mut guard = engine.inner.lock().await;
        let inner = guard.as_mut().unwrap();
        let contact_c = inner.contact(&peer_c).expect("Dave exists");
        assert_eq!(contact_c.session.active_id(), Some(&dave_expected_id));
        assert!(!contact_c.state.request);
        // Verify the inbound ratchet is completely uncorrupted: Dave encrypts, Alice decrypts.
        let sealed = dave_sender_session
            .encrypt(&Kind::Text("ratchet-intact".into()).to_bytes())
            .unwrap();
        let decrypted = contact_c.session.decrypt_envelope(&sealed.message).unwrap();
        assert_eq!(
            Content::from_bytes(&decrypted.content).kind,
            Some(Kind::Text("ratchet-intact".into()))
        );
    });
    drop(_mock_c);

    // Part 3: User changes `pq_config` while `ClaimBundle` is suspended in `start_chat` ->
    // stale bundle is discarded cleanly and `start_chat` re-claims under the updated `pq_config`!
    let mut peer_d_client = Client::new(Fetch::client(LOCAL_SERVER));
    let peer_d = peer_d_client.identity_key();
    let mut bundles_d = publish_bundle_for_test(&mut peer_d_client, "localhost", 2);
    let bundle_d1 = bundles_d.remove(0);
    let bundle_d2 = bundles_d.remove(0);
    let (claim_d1_tx, claim_d1_rx) = oneshot::channel::<()>();
    let claim_d1_rx = Rc::new(RefCell::new(Some(claim_d1_rx)));
    let claim_d_calls = Rc::new(Cell::new(0usize));
    let seen_pref_suites: Rc<RefCell<Vec<Vec<u32>>>> = Rc::default();
    let claim_d1_rx_ref = claim_d1_rx.clone();
    let claim_d_calls_ref = claim_d_calls.clone();
    let seen_pref_ref = seen_pref_suites.clone();
    let _mock_d = crate::transport::mock_fetch_async(move |_server, path, body| {
        let claim_d1_rx_ref = claim_d1_rx_ref.clone();
        let claim_d_calls_ref = claim_d_calls_ref.clone();
        let seen_pref_ref = seen_pref_ref.clone();
        let bundle_d1 = bundle_d1.clone();
        let bundle_d2 = bundle_d2.clone();
        async move {
            if path.ends_with("/ClaimBundle") {
                let req = ClaimBundleRequest::decode(body.as_slice()).unwrap();
                seen_pref_ref.borrow_mut().push(req.preferred_suites);
                let call = claim_d_calls_ref.get() + 1;
                claim_d_calls_ref.set(call);
                if call == 1 {
                    await_gate(&claim_d1_rx_ref).await;
                    Ok((200, bundle_d1.encode_to_vec()))
                } else {
                    Ok((200, bundle_d2.encode_to_vec()))
                }
            } else if path.ends_with("/RegisterWriteToken") {
                Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
            } else if path.ends_with("/SendInitialV2") {
                Ok((200, SendInitialV2Response { id: 2 }.encode_to_vec()))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });

    let key_d_text = key_to_text(&peer_d);
    let sub_d = engine.begin_new_chat_submit(PendingNewChat {
        key: key_d_text.clone(),
        name: "Eve".into(),
        server: None,
        pq_pinned: false,
        allow_classical: false,
        auto_start: false,
    });
    let start_d_done = Rc::new(RefCell::new(None::<Result<PublicKey, StartChatError>>));
    let start_d_done_ref = start_d_done.clone();
    let eng_d = engine.clone();
    spawner
        .spawn_local(async move {
            *start_d_done_ref.borrow_mut() = Some(
                eng_d
                    .start_chat(sub_d, &key_d_text, "Eve".into(), None, false, false)
                    .await,
            );
        })
        .unwrap();

    pool.run_until_stalled();
    assert_eq!(claim_d_calls.get(), 1);
    assert!(start_d_done.borrow().is_none());

    // Change local `pq_config` (toggle `pq_ratchet_enabled`) while `ClaimBundle` #1 is suspended.
    pool.run_until(async {
        let mut guard = engine.lock_inner().await;
        let inner = guard.as_mut().unwrap();
        let mut cfg = inner.client.pq_config().clone();
        cfg.pq_ratchet_enabled = !cfg.pq_ratchet_enabled;
        inner.client.set_pq_config(cfg).unwrap();
    });

    // Release ClaimBundle #1 -> `start_chat` detects `pq_config` mismatch, discards stale bundle,
    // re-claims under the updated `pq_config`, and succeeds!
    claim_d1_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*start_d_done.borrow(), Some(Ok(peer_d)));
    assert_eq!(
        claim_d_calls.get(),
        2,
        "start_chat must re-claim when pq_config changes mid-flight"
    );
    let _ = seen_pref_suites;
    let _ = peer_a_client;
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn outbox_rekey_claim_bundle_discards_stale_bundle_when_inbound_session_arrives() {
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use protocol::handshake_v2::{ListInitialMessagesResponse, SendInitialV2Response};
    use protocol::mailbox_v2::{PushV2Response, RegisterWriteTokenResponse};
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    let (engine, peer_a, alice_id, alice_bundle, bob_bundle, bob_client) = pool.run_until(async {
        let (engine, peer_a, mut bob) = established_engine_on_localhost().await;
        let bob_bundle = publish_bundle_for_test(&mut bob, "localhost", 1)
            .into_iter()
            .next()
            .unwrap();
        let (alice_id, alice_bundle) = {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let alice_bundle = publish_bundle_for_test(&mut inner.client, "localhost", 1)
                .into_iter()
                .next()
                .unwrap();
            let alice_id = inner.client.identity_key();
            // Retire peer_a's session so `flush(&peer_a)` must rekey via `ClaimBundle`, and
            // enqueue an unsealed message waiting for the new session.
            inner.contact(&peer_a).unwrap().session.retire();
            inner
                .add(&peer_a, Kind::Text("sent-on-inbound-ratchet".into()), false)
                .await
                .unwrap();
            (alice_id, alice_bundle)
        };
        (engine, peer_a, alice_id, alice_bundle, bob_bundle, bob)
    });

    // Prepare Bob's real inbound replacement session against Alice's published bundle.
    let mut bob_initiator = Client::restore(
        ConnectClient::new(BundleResponse("/ClaimBundle", alice_bundle)),
        ClientState::try_from(&proto::ClientState::from(bob_client.state())).unwrap(),
    );
    let bob_prep = pool.run_until(async {
        bob_initiator
            .prepare_initiate_v2(
                "localhost",
                &alice_id,
                &Default::default(),
                &Kind::Hello(bob_initiator.make_hello("Bob", 10)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap()
    });
    let inbound_initial = Incoming::try_from(bob_prep.request.message.as_ref().unwrap()).unwrap();
    let mut bob_new_session = bob_prep.session;
    let expected_inbound_id = *bob_new_session.active_id().unwrap();

    let (claim_tx, claim_rx) = oneshot::channel::<()>();
    let claim_rx = Rc::new(RefCell::new(Some(claim_rx)));
    let claim_started = Rc::new(Cell::new(false));
    let send_init_calls = Rc::new(Cell::new(0usize));
    let pushed_reqs: Rc<RefCell<Vec<PushV2Request>>> = Rc::default();

    let claim_rx_ref = claim_rx.clone();
    let claim_started_ref = claim_started.clone();
    let send_init_calls_ref = send_init_calls.clone();
    let pushed_reqs_ref = pushed_reqs.clone();

    let _mock = crate::transport::mock_fetch_async(move |_server, path, body| {
        let claim_rx_ref = claim_rx_ref.clone();
        let claim_started_ref = claim_started_ref.clone();
        let send_init_calls_ref = send_init_calls_ref.clone();
        let pushed_reqs_ref = pushed_reqs_ref.clone();
        let bob_bundle = bob_bundle.clone();
        async move {
            if path.ends_with("/ListInitialMessages") {
                Ok((
                    200,
                    ListInitialMessagesResponse {
                        messages: vec![],
                        has_more: false,
                    }
                    .encode_to_vec(),
                ))
            } else if path.ends_with("/ClaimBundle") {
                claim_started_ref.set(true);
                await_gate(&claim_rx_ref).await;
                Ok((200, bob_bundle.encode_to_vec()))
            } else if path.ends_with("/SendInitialV2") {
                send_init_calls_ref.set(send_init_calls_ref.get() + 1);
                Ok((200, SendInitialV2Response { id: 1 }.encode_to_vec()))
            } else if path.ends_with("/RegisterWriteToken") {
                Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
            } else if path.ends_with("/PushV2") {
                let req = PushV2Request::decode(body.as_slice()).unwrap();
                pushed_reqs_ref.borrow_mut().push(req);
                Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });

    let flush_done = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let flush_done_ref = flush_done.clone();
    let eng_clone = engine.clone();
    spawner
        .spawn_local(async move {
            let res = eng_clone.flush(&peer_a).await;
            *flush_done_ref.borrow_mut() = Some(res);
        })
        .unwrap();

    // Advance until outbox rekey suspends inside ClaimBundle.
    pool.run_until_stalled();
    assert!(
        claim_started.get(),
        "outbox rekey must have issued ClaimBundle"
    );
    assert!(flush_done.borrow().is_none());

    // Inject Bob's inbound replacement session while Alice's ClaimBundle is suspended!
    // Acquiring `engine.lock_inner()` succeeds immediately because ClaimBundle dropped the lock.
    pool.run_until(async {
        let mut guard = engine.lock_inner().await;
        let inner = guard.as_mut().unwrap();
        let mut batch = InitialBatch::default();
        engine.process_initial(inner, &peer_a, &inbound_initial, &mut batch);
        engine.save_initial_batch(inner, batch).await.unwrap();
        assert_eq!(
            inner.contact(&peer_a).unwrap().session.active_id(),
            Some(&expected_inbound_id)
        );
    });

    // Release ClaimBundle -> Alice MUST discard the stale bundle, NEVER transmit SendInitialV2,
    // keep Bob's inbound session as active, and encrypt/push the queued message on Bob's ratchet!
    claim_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*flush_done.borrow(), Some(Ok(true)));
    assert_eq!(
        send_init_calls.get(),
        0,
        "stale ClaimBundle must not produce an outgoing SendInitialV2"
    );
    assert_eq!(pushed_reqs.borrow().len(), 1);
    let pushed_msg = pushed_reqs.borrow()[0]
        .message
        .as_ref()
        .expect("encrypted message")
        .clone();
    let decrypted = bob_new_session.decrypt_envelope(&pushed_msg).unwrap();
    assert_eq!(
        Content::from_bytes(&decrypted.content).kind,
        Some(Kind::Text("sent-on-inbound-ratchet".into()))
    );
    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        let contact = inner.contacts.iter().find(|c| c.peer == peer_a).unwrap();
        assert_eq!(contact.session.active_id(), Some(&expected_inbound_id));
        assert!(contact.state.outbox.is_empty());
    });
    let _ = bob_client;
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn push_v2_releases_inner_lock_allows_peer_b_and_ui_and_handles_concurrent_delete() {
    use crate::vault::GREETING_DELIVERY_CONFIRMED;
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use protocol::mailbox_v2::{PushV2Response, RevokeWriteTokenResponse};
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    // Build an engine with TWO established contacts: peer_a and peer_b.
    let (engine, peer_a, peer_b) = pool.run_until(async {
        let (engine, peer_a, _bob_a) = established_engine_on_localhost().await;
        let mut bob_b = Client::new(Fetch::client(LOCAL_SERVER));
        let peer_b = bob_b.identity_key();
        let bundle_b = publish_bundle_for_test(&mut bob_b, "localhost", 1)
            .into_iter()
            .next()
            .unwrap();
        let mut guard = engine.inner.lock().await;
        let inner = guard.as_mut().unwrap();
        let mut alice_tmp = Client::restore(
            ConnectClient::new(BundleResponse("/ClaimBundle", bundle_b)),
            ClientState::try_from(&proto::ClientState::from(inner.client.state())).unwrap(),
        );
        let prep_b = alice_tmp
            .prepare_initiate_v2(
                "localhost",
                &peer_b,
                &Default::default(),
                &Kind::Text("init-b".into()).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let mut contact_b = super::contact::Contact {
            peer: peer_b,
            session: prep_b.session,
            deferred_carried: 0,
            state: ContactState {
                peer: peer_b.to_vec(),
                name: "Peer B".into(),
                greeting_delivery: GREETING_DELIVERY_CONFIRMED,
                ..ContactState::default()
            },
        };
        // Seed one unread incoming message on peer_b so `mark_read(peer_b)` exercises a real
        // read-receipt + `push_events` while peer_a's `PushV2` is suspended!
        let (unread_idx, unread_entry) = contact_b
            .add_received(
                Content {
                    clock: 5,
                    kind: Some(Kind::Text("unread-from-b".into())),
                    events: None,
                },
                false,
            )
            .unwrap();
        inner.contacts.push(contact_b);
        inner
            .save(&[(peer_b, unread_idx, unread_entry)])
            .await
            .unwrap();
        // Queue an outgoing message for peer_a.
        inner
            .add(&peer_a, Kind::Text("msg-a1".into()), false)
            .await
            .unwrap();
        drop(guard);
        (engine, peer_a, peer_b)
    });

    // Part A: Suspend PushV2 for peer_a -> verify peer_flush_locks serializes a 2nd flush(peer_a),
    // while open/mark_read/send/flush for peer_b all complete immediately!
    let (push_a1_tx, push_a1_rx) = oneshot::channel::<()>();
    let push_a1_rx = Rc::new(RefCell::new(Some(push_a1_rx)));
    let push_a_calls = Rc::new(Cell::new(0usize));
    let push_b_calls = Rc::new(Cell::new(0usize));
    let seq = Rc::new(Cell::new(0u64));

    let push_a1_rx_ref = push_a1_rx.clone();
    let push_a_calls_ref = push_a_calls.clone();
    let push_b_calls_ref = push_b_calls.clone();
    let seq_ref = seq.clone();

    let _mock = crate::transport::mock_fetch_async(move |_server, path, body| {
        let push_a1_rx_ref = push_a1_rx_ref.clone();
        let push_a_calls_ref = push_a_calls_ref.clone();
        let push_b_calls_ref = push_b_calls_ref.clone();
        let seq_ref = seq_ref.clone();
        async move {
            assert!(path.ends_with("/PushV2"), "unexpected path: {path}");
            let req = PushV2Request::decode(body.as_slice()).unwrap();
            if req.recipient.as_ref() == peer_a.as_slice() {
                push_a_calls_ref.set(push_a_calls_ref.get() + 1);
                await_gate(&push_a1_rx_ref).await;
            } else if req.recipient.as_ref() == peer_b.as_slice() {
                push_b_calls_ref.set(push_b_calls_ref.get() + 1);
            } else {
                panic!("unexpected recipient");
            }
            let next = seq_ref.get() + 1;
            seq_ref.set(next);
            Ok((200, PushV2Response { sequence: next }.encode_to_vec()))
        }
    });

    let flush_a1_done = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let flush_a2_done = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let f1_ref = flush_a1_done.clone();
    let f2_ref = flush_a2_done.clone();
    let e1 = engine.clone();
    let e2 = engine.clone();
    spawner
        .spawn_local(async move {
            *f1_ref.borrow_mut() = Some(e1.flush(&peer_a).await);
        })
        .unwrap();
    spawner
        .spawn_local(async move {
            *f2_ref.borrow_mut() = Some(e2.flush(&peer_a).await);
        })
        .unwrap();

    pool.run_until_stalled();
    assert_eq!(
        push_a_calls.get(),
        1,
        "peer_flush_locks must serialize concurrent flushes for peer_a so PushV2 is issued once"
    );
    assert!(flush_a1_done.borrow().is_none());
    assert!(flush_a2_done.borrow().is_none());

    // While peer_a's PushV2 is paused, open(peer_b) (which marks unread read & pushes read receipt),
    // mark_read(peer_b), and send(peer_b) + flush(peer_b) all run unblocked!
    assert_eq!(
        pool.run_until(engine.open(Some(peer_b))),
        OpenOutcome::Opened
    );
    // Opening peer_b already acknowledged its unread message and flushed its read receipt via push_events!
    assert_eq!(push_b_calls.get(), 1);
    pool.run_until(engine.mark_read(peer_b));
    let idx_b = pool
        .run_until(engine.send_returning_index(peer_b, Kind::Text("msg-b1".into())))
        .unwrap();
    assert_eq!(push_b_calls.get(), 2);
    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(
            inner.vault.entries.borrow()[&(peer_b, idx_b)].delivery(),
            Delivery::Sent
        );
        let contact_b = inner.contacts.iter().find(|c| c.peer == peer_b).unwrap();
        assert_eq!(contact_b.state.unread, 0);
        assert!(contact_b.state.outbox.is_empty());
        assert!(contact_b.state.sealed_events.is_none());
    });

    // Release peer_a's PushV2 -> first flush commits msg-a1, second flush runs next and finds empty outbox.
    push_a1_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*flush_a1_done.borrow(), Some(Ok(true)));
    assert_eq!(*flush_a2_done.borrow(), Some(Ok(false)));
    assert_eq!(push_a_calls.get(), 1);
    drop(_mock);

    // Part B: Concurrent `delete(peer_a)` while `PushV2` for peer_a is suspended ->
    // `flush(&peer_a)` exits cleanly without recreating or corrupting state, and lock-free
    // `flush_pending_revokes` + `say_farewells` also release `self.inner` across RPCs!
    pool.run_until(async {
        let mut guard = engine.inner.lock().await;
        guard
            .as_mut()
            .unwrap()
            .add(
                &peer_a,
                Kind::Text("msg-a2-deleted-midflight".into()),
                false,
            )
            .await
            .unwrap();
    });
    let (push_a2_tx, push_a2_rx) = oneshot::channel::<()>();
    let (revoke_tx, revoke_rx) = oneshot::channel::<()>();
    let (farewell_tx, farewell_rx) = oneshot::channel::<()>();
    let push_a2_rx = Rc::new(RefCell::new(Some(push_a2_rx)));
    let revoke_rx = Rc::new(RefCell::new(Some(revoke_rx)));
    let farewell_rx = Rc::new(RefCell::new(Some(farewell_rx)));
    let push_a2_started = Rc::new(Cell::new(false));
    let revoke_started = Rc::new(Cell::new(false));
    let farewell_started = Rc::new(Cell::new(false));

    let push_a2_rx_ref = push_a2_rx.clone();
    let revoke_rx_ref = revoke_rx.clone();
    let farewell_rx_ref = farewell_rx.clone();
    let push_a2_started_ref = push_a2_started.clone();
    let revoke_started_ref = revoke_started.clone();
    let farewell_started_ref = farewell_started.clone();

    let _mock2 = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let push_a2_rx_ref = push_a2_rx_ref.clone();
        let revoke_rx_ref = revoke_rx_ref.clone();
        let farewell_rx_ref = farewell_rx_ref.clone();
        let push_a2_started_ref = push_a2_started_ref.clone();
        let revoke_started_ref = revoke_started_ref.clone();
        let farewell_started_ref = farewell_started_ref.clone();
        async move {
            if path.ends_with("/PushV2") {
                let push_rx = push_a2_rx_ref.borrow_mut().take();
                if let Some(rx) = push_rx {
                    push_a2_started_ref.set(true);
                    let _ = rx.await;
                } else {
                    let fw_rx = farewell_rx_ref.borrow_mut().take();
                    if let Some(rx) = fw_rx {
                        farewell_started_ref.set(true);
                        let _ = rx.await;
                    }
                }
                Ok((200, PushV2Response { sequence: 50 }.encode_to_vec()))
            } else if path.ends_with("/RevokeWriteToken") {
                revoke_started_ref.set(true);
                await_gate(&revoke_rx_ref).await;
                Ok((200, RevokeWriteTokenResponse { revoked: 1 }.encode_to_vec()))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });

    let flush_del_done = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let flush_del_ref = flush_del_done.clone();
    let eng_del = engine.clone();
    spawner
        .spawn_local(async move {
            *flush_del_ref.borrow_mut() = Some(eng_del.flush(&peer_a).await);
        })
        .unwrap();

    pool.run_until_stalled();
    assert!(push_a2_started.get());
    assert!(flush_del_done.borrow().is_none());

    // Delete peer_a concurrently while PushV2(peer_a) is suspended! The live `Weak` lock entry
    // remains tracked until the in-flight flush exits, then prunes automatically.
    pool.run_until(engine.delete(peer_a)).unwrap();
    assert_eq!(
        engine.queue.peer_flush_lock_strong_count(&peer_a),
        Some(1),
        "live per-peer flush lock must stay registered until in-flight flush exits"
    );

    // Release PushV2(peer_a) -> flush exits cleanly without recreating peer_a or corrupting vault,
    // and prunes the peer_flush_locks entry once strong_count drops to 0.
    push_a2_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*flush_del_done.borrow(), Some(Ok(false)));
    assert!(
        !engine.queue.has_peer_flush_lock(&peer_a),
        "peer_flush_locks entry must be pruned once the last flush holder exits"
    );
    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert!(inner.contacts.iter().all(|c| c.peer != peer_a));
        assert!(inner.contacts.iter().any(|c| c.peer == peer_b));
        assert!(
            inner
                .vault
                .outbox
                .borrow()
                .keys()
                .all(|(p, _)| *p != peer_a)
        );
        assert_eq!(inner.state.pending_revokes.len(), 1);
        assert_eq!(inner.state.farewells.len(), 1);
    });

    // Verify `flush_pending_revokes` and `say_farewells` ALSO release `self.inner` across RPCs!
    let revoke_done = Rc::new(RefCell::new(None::<Result<(), String>>));
    let revoke_done_ref = revoke_done.clone();
    let eng_rev = engine.clone();
    spawner
        .spawn_local(async move {
            *revoke_done_ref.borrow_mut() = Some(eng_rev.flush_pending_revokes().await);
        })
        .unwrap();
    pool.run_until_stalled();
    assert!(revoke_started.get());
    assert!(revoke_done.borrow().is_none());
    // UI `open(peer_b)` completes immediately while RevokeWriteToken is suspended!
    assert_eq!(
        pool.run_until(engine.open(Some(peer_b))),
        OpenOutcome::Opened
    );
    revoke_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*revoke_done.borrow(), Some(Ok(())));

    let farewell_done = Rc::new(RefCell::new(None::<Result<(), String>>));
    let farewell_done_ref = farewell_done.clone();
    let eng_fw = engine.clone();
    spawner
        .spawn_local(async move {
            *farewell_done_ref.borrow_mut() = Some(eng_fw.say_farewells().await);
        })
        .unwrap();
    pool.run_until_stalled();
    assert!(farewell_started.get());
    assert!(farewell_done.borrow().is_none());
    // UI `open(peer_b)` completes immediately while farewell PushV2 is suspended!
    assert_eq!(
        pool.run_until(engine.open(Some(peer_b))),
        OpenOutcome::Opened
    );
    farewell_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*farewell_done.borrow(), Some(Ok(())));

    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert!(inner.state.pending_revokes.is_empty());
        assert!(inner.state.farewells.is_empty());
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn pagehide_during_suspended_claim_bundle_and_push_v2_blocks_all_writes_and_ui() {
    use crate::state::{PendingNewChat, Phase};
    use crate::util::key_to_text;
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use protocol::mailbox_v2::PushV2Response;
    use std::rc::Rc;

    // Subcase A: Trigger `glue::teardown_and_release_lock()` while `ClaimBundle` is suspended.
    {
        let prev_released = crate::glue::set_lock_released_for_test(false);
        let _restore_lock = scopeguard::guard(prev_released, |prev| {
            crate::glue::set_lock_released_for_test(prev);
        });

        let mut pool = LocalPool::new();
        let spawner = pool.spawner();
        let (engine, ui, save_count, peer_a, bundle_a) = pool.run_until(async {
            let (engine, _peer_b, _bob) = established_engine_on_localhost().await;
            let save_count = {
                let mut guard = engine.inner.lock().await;
                let inner = guard.as_mut().unwrap();
                let _ = publish_bundle_for_test(&mut inner.client, "localhost", 1);
                inner.state.published_at = crate::util::now();
                inner.save_state().await.unwrap();
                inner.vault.save_count.clone()
            };
            let mut peer_a_client = Client::new(Fetch::client(LOCAL_SERVER));
            let peer_a = peer_a_client.identity_key();
            let bundle_a = publish_bundle_for_test(&mut peer_a_client, "localhost", 1)
                .into_iter()
                .next()
                .unwrap();
            let ui = engine.ui();
            (engine, ui, save_count, peer_a, bundle_a)
        });

        let (claim_tx, claim_rx) = oneshot::channel::<()>();
        let claim_rx = Rc::new(RefCell::new(Some(claim_rx)));
        let claim_started = Rc::new(Cell::new(false));
        let claim_rx_ref = claim_rx.clone();
        let claim_started_ref = claim_started.clone();
        let _mock = crate::transport::mock_fetch_async(move |_server, path, _body| {
            let claim_rx_ref = claim_rx_ref.clone();
            let claim_started_ref = claim_started_ref.clone();
            let bundle_a = bundle_a.clone();
            async move {
                assert!(path.ends_with("/ClaimBundle"), "unexpected path: {path}");
                claim_started_ref.set(true);
                await_gate(&claim_rx_ref).await;
                Ok((200, bundle_a.encode_to_vec()))
            }
        });

        let key_a_text = key_to_text(&peer_a);
        let sub_id = engine.begin_new_chat_submit(PendingNewChat {
            key: key_a_text.clone(),
            name: "Carol".into(),
            server: None,
            pq_pinned: false,
            allow_classical: false,
            auto_start: false,
        });
        let start_done = Rc::new(RefCell::new(None::<Result<PublicKey, StartChatError>>));
        let start_done_ref = start_done.clone();
        let eng_clone = engine.clone();
        spawner
            .spawn_local(async move {
                *start_done_ref.borrow_mut() = Some(
                    eng_clone
                        .start_chat(sub_id, &key_a_text, "Carol".into(), None, false, false)
                        .await,
                );
            })
            .unwrap();

        pool.run_until_stalled();
        assert!(claim_started.get());
        assert!(start_done.borrow().is_none());

        // Fire synchronous `pagehide` teardown while `ClaimBundle` is suspended!
        crate::glue::teardown_and_release_lock();
        let saves_at_teardown = save_count.get();

        // Because `Engine::inner` was released across `ClaimBundle`, `Inner` dropped IMMEDIATELY!
        assert!(
            engine.inner.try_lock().expect("uncontended").is_none(),
            "Inner must be dropped synchronously on pagehide while ClaimBundle is suspended"
        );
        assert!(engine.queue.peer_flush_locks_is_empty());

        // Release ClaimBundle -> continuation MUST abort with zero IDB writes and zero UI repaints!
        claim_tx.send(()).unwrap();
        pool.run_until_stalled();
        assert_eq!(*start_done.borrow(), Some(Err(StartChatError::Cancelled)));
        assert_eq!(
            save_count.get(),
            saves_at_teardown,
            "zero post-pagehide IDB writes permitted after ClaimBundle resumes"
        );
        assert_eq!(ui.phase.get_untracked(), Phase::Locked);
        assert!(ui.contacts.get_untracked().is_empty());
        assert!(ui.log.get_untracked().is_empty());
        assert!(ui.notice.get_untracked().is_none());
        assert!(engine.inner.try_lock().expect("uncontended").is_none());
    }

    // Subcase B: Trigger `glue::teardown_and_release_lock()` while `PushV2` is suspended.
    {
        let prev_released = crate::glue::set_lock_released_for_test(false);
        let _restore_lock = scopeguard::guard(prev_released, |prev| {
            crate::glue::set_lock_released_for_test(prev);
        });

        let mut pool = LocalPool::new();
        let spawner = pool.spawner();
        let (engine, ui, save_count, peer_a) = pool.run_until(async {
            let (engine, peer_a, _bob) = established_engine_on_localhost().await;
            let save_count = {
                let mut guard = engine.inner.lock().await;
                let inner = guard.as_mut().unwrap();
                inner
                    .add(&peer_a, Kind::Text("in-flight-at-pagehide".into()), false)
                    .await
                    .unwrap();
                inner.vault.save_count.clone()
            };
            let ui = engine.ui();
            (engine, ui, save_count, peer_a)
        });

        let (push_tx, push_rx) = oneshot::channel::<()>();
        let push_rx = Rc::new(RefCell::new(Some(push_rx)));
        let push_started = Rc::new(Cell::new(false));
        let push_rx_ref = push_rx.clone();
        let push_started_ref = push_started.clone();
        let _mock = crate::transport::mock_fetch_async(move |_server, path, _body| {
            let push_rx_ref = push_rx_ref.clone();
            let push_started_ref = push_started_ref.clone();
            async move {
                assert!(path.ends_with("/PushV2"), "unexpected path: {path}");
                push_started_ref.set(true);
                await_gate(&push_rx_ref).await;
                Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
            }
        });

        let flush_done = Rc::new(RefCell::new(None::<Result<bool, String>>));
        let flush_done_ref = flush_done.clone();
        let eng_clone = engine.clone();
        spawner
            .spawn_local(async move {
                *flush_done_ref.borrow_mut() = Some(eng_clone.flush(&peer_a).await);
            })
            .unwrap();

        pool.run_until_stalled();
        assert!(push_started.get());
        assert!(flush_done.borrow().is_none());

        // Fire synchronous `pagehide` teardown while `PushV2` is suspended!
        crate::glue::teardown_and_release_lock();
        let saves_at_teardown = save_count.get();

        // Because `Engine::inner` was released across `PushV2`, `Inner` dropped IMMEDIATELY!
        assert!(
            engine.inner.try_lock().expect("uncontended").is_none(),
            "Inner must be dropped synchronously on pagehide while PushV2 is suspended"
        );
        assert!(engine.queue.peer_flush_locks_is_empty());

        // Release PushV2 -> flush MUST abort with zero IDB writes and zero UI repaints!
        push_tx.send(()).unwrap();
        pool.run_until_stalled();
        assert_eq!(*flush_done.borrow(), Some(Ok(false)));
        assert_eq!(
            save_count.get(),
            saves_at_teardown,
            "zero post-pagehide IDB writes permitted after PushV2 resumes"
        );
        assert_eq!(ui.phase.get_untracked(), Phase::Locked);
        assert!(ui.contacts.get_untracked().is_empty());
        assert!(ui.messages.get_untracked().is_empty());
        assert!(ui.log.get_untracked().is_empty());
        assert!(ui.notice.get_untracked().is_none());
        assert!(engine.inner.try_lock().expect("uncontended").is_none());
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn delete_recreate_during_suspended_push_v2_preserves_per_peer_serialization_and_prunes() {
    use crate::vault::GREETING_DELIVERY_CONFIRMED;
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use protocol::mailbox_v2::PushV2Response;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    let (engine, peer_a, mut bob_client) = pool.run_until(async {
        let (engine, peer_a, bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .add(&peer_a, Kind::Text("old-session-msg".into()), false)
                .await
                .unwrap();
        }
        (engine, peer_a, bob)
    });
    let bundle_a_new = publish_bundle_for_test(&mut bob_client, "localhost", 1)
        .into_iter()
        .next()
        .unwrap();

    let (push1_tx, push1_rx) = oneshot::channel::<()>();
    let push1_rx = Rc::new(RefCell::new(Some(push1_rx)));
    let push_reqs: Rc<RefCell<Vec<PushV2Request>>> = Rc::default();
    let seq = Rc::new(Cell::new(0u64));
    let push1_rx_ref = push1_rx.clone();
    let push_reqs_ref = push_reqs.clone();
    let seq_ref = seq.clone();

    let _mock = crate::transport::mock_fetch_async(move |_server, path, body| {
        let push1_rx_ref = push1_rx_ref.clone();
        let push_reqs_ref = push_reqs_ref.clone();
        let seq_ref = seq_ref.clone();
        async move {
            assert!(path.ends_with("/PushV2"), "unexpected path: {path}");
            let req = PushV2Request::decode(body.as_slice()).unwrap();
            push_reqs_ref.borrow_mut().push(req);
            if push_reqs_ref.borrow().len() == 1 {
                await_gate(&push1_rx_ref).await;
            }
            let next = seq_ref.get() + 1;
            seq_ref.set(next);
            Ok((200, PushV2Response { sequence: next }.encode_to_vec()))
        }
    });

    // 1. Start flush #1 for peer_a and pause inside PushV2 for the old session.
    let f1_done = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let f1_ref = f1_done.clone();
    let e1 = engine.clone();
    spawner
        .spawn_local(async move {
            *f1_ref.borrow_mut() = Some(e1.flush(&peer_a).await);
        })
        .unwrap();
    pool.run_until_stalled();
    assert_eq!(push_reqs.borrow().len(), 1);
    assert!(f1_done.borrow().is_none());

    // 2. Delete peer_a concurrently, then immediately recreate peer_a with a brand-new session S2
    //    and queue a message on S2, then spawn flush #2 for peer_a while flush #1 is still paused!
    pool.run_until(engine.delete(peer_a)).unwrap();
    assert_eq!(
        engine.queue.peer_flush_lock_strong_count(&peer_a),
        Some(1),
        "delete must not evict a live Weak flush lock"
    );

    let mut bob_s2_session = pool.run_until(async {
        let mut guard = engine.lock_inner().await;
        let inner = guard.as_mut().unwrap();
        let mut alice_tmp = Client::restore(
            ConnectClient::new(BundleResponse("/ClaimBundle", bundle_a_new)),
            ClientState::try_from(&proto::ClientState::from(inner.client.state())).unwrap(),
        );
        let prep = alice_tmp
            .prepare_initiate_v2(
                "localhost",
                &peer_a,
                &Default::default(),
                &Kind::Hello(alice_tmp.make_hello("Alice", 99)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let inc = Incoming::try_from(prep.request.message.as_ref().unwrap()).unwrap();
        let AcceptedInitial::Accepted {
            session: bob_session,
            ..
        } = bob_client
            .accept_initial_v2(
                &inner.client.identity_key(),
                &Default::default(),
                &inc,
                Fetch::client(LOCAL_SERVER),
            )
            .unwrap()
        else {
            panic!("expected accepted initial on S2");
        };
        inner.contacts.push(super::contact::Contact {
            peer: peer_a,
            session: prep.session,
            deferred_carried: 0,
            state: ContactState {
                peer: peer_a.to_vec(),
                name: "Peer A Recreated".into(),
                greeting_delivery: GREETING_DELIVERY_CONFIRMED,
                ..ContactState::default()
            },
        });
        inner
            .add(&peer_a, Kind::Text("recreated-session-msg".into()), false)
            .await
            .unwrap();
        bob_session
    });

    let f2_done = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let f2_ref = f2_done.clone();
    let e2 = engine.clone();
    spawner
        .spawn_local(async move {
            *f2_ref.borrow_mut() = Some(e2.flush(&peer_a).await);
        })
        .unwrap();

    // Flush #2 MUST serialize behind flush #1's shared Weak-upgraded mutex (NO concurrent PushV2!).
    pool.run_until_stalled();
    assert_eq!(
        push_reqs.borrow().len(),
        1,
        "flush #2 after delete+recreate must wait on the exact same per-peer mutex as flush #1"
    );
    assert_eq!(engine.queue.peer_flush_lock_strong_count(&peer_a), Some(2));
    assert!(f2_done.borrow().is_none());

    // 3. Release flush #1 -> S2's message is pushed ONCE (zero duplicate PushV2), decrypts cleanly
    //    on S2, both flushes complete, and `peer_flush_locks` is pruned to empty!
    push1_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert!(f1_done.borrow().is_some());
    assert!(f2_done.borrow().is_some());
    assert_eq!(
        push_reqs.borrow().len(),
        2,
        "recreated session message must be pushed exactly once (1 old + 1 new)"
    );
    let decrypted = bob_s2_session
        .decrypt_envelope(push_reqs.borrow()[1].message.as_ref().unwrap())
        .unwrap();
    assert_eq!(
        Content::from_bytes(&decrypted.content).kind,
        Some(Kind::Text("recreated-session-msg".into()))
    );
    assert!(
        !engine.queue.has_peer_flush_lock(&peer_a),
        "peer_flush_locks entry must be pruned once both flushes exit"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn cancelled_start_chat_during_suspended_rpc_preserves_concurrent_farewells() {
    use crate::state::PendingNewChat;
    use crate::util::key_to_text;
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use protocol::handshake_v2::SendInitialV2Response;
    use protocol::mailbox_v2::{PushV2Response, RegisterWriteTokenResponse};
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    let (engine, peer_a, peer_b, bundle_a1, bundle_a2, fw_a, fw_c) = pool.run_until(async {
        let (engine, peer_b, _bob) = established_engine_on_localhost().await;
        let mut peer_a_client = Client::new(Fetch::client(LOCAL_SERVER));
        let peer_a = peer_a_client.identity_key();
        let mut bundles_a = publish_bundle_for_test(&mut peer_a_client, "localhost", 2);
        let bundle_a1 = bundles_a.remove(0);
        let bundle_a2 = bundles_a.remove(0);

        let peer_c = [0xCCu8; 32];
        let fw_a = Farewell {
            push_v2: PushV2Request {
                recipient: Bytes::copy_from_slice(&peer_a),
                message: Some(party::EncryptedMessage {
                    header: Bytes::from_static(b"hdr-a"),
                    content: Bytes::from_static(b"ct-a"),
                }),
                write_token: Bytes::from_static(&[0x11u8; 32]),
                client_message_id: Bytes::from_static(&[0xAAu8; 16]),
                initial_message: None,
            }
            .encode_to_vec(),
        };
        let fw_c = Farewell {
            push_v2: PushV2Request {
                recipient: Bytes::copy_from_slice(&peer_c),
                message: Some(party::EncryptedMessage {
                    header: Bytes::from_static(b"hdr-c"),
                    content: Bytes::from_static(b"ct-c"),
                }),
                write_token: Bytes::from_static(&[0x22u8; 32]),
                client_message_id: Bytes::from_static(&[0xCCu8; 16]),
                initial_message: None,
            }
            .encode_to_vec(),
        };
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let _ = publish_bundle_for_test(&mut inner.client, "localhost", 1);
            inner.state.published_at = crate::util::now();
            inner.state.farewells.push(fw_a.clone());
            inner.state.farewells.push(fw_c.clone());
            inner.save_state().await.unwrap();
        }
        (engine, peer_a, peer_b, bundle_a1, bundle_a2, fw_a, fw_c)
    });

    // Subcase 1: Cancel `start_chat(peer_a)` while `RegisterWriteToken` is suspended, after
    // concurrently delivering `fw_c` via `say_farewells()` AND deleting `peer_b` (appending `fw_b`).
    let (reg_tx, reg_rx) = oneshot::channel::<()>();
    let reg_rx = Rc::new(RefCell::new(Some(reg_rx)));
    let reg_started = Rc::new(Cell::new(false));
    let reg_rx_ref = reg_rx.clone();
    let reg_started_ref = reg_started.clone();
    let bundle_a1_clone = bundle_a1.clone();

    let _mock1 = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let reg_rx_ref = reg_rx_ref.clone();
        let reg_started_ref = reg_started_ref.clone();
        let bundle_a1_clone = bundle_a1_clone.clone();
        async move {
            if path.ends_with("/ClaimBundle") {
                Ok((200, bundle_a1_clone.encode_to_vec()))
            } else if path.ends_with("/RegisterWriteToken") {
                reg_started_ref.set(true);
                await_gate(&reg_rx_ref).await;
                Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
            } else if path.ends_with("/PushV2") {
                Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
            } else if path.ends_with("/SendInitialV2") {
                Ok((200, SendInitialV2Response { id: 1 }.encode_to_vec()))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });

    let key_a_text = key_to_text(&peer_a);
    let sub1 = engine.begin_new_chat_submit(PendingNewChat {
        key: key_a_text.clone(),
        name: "Peer A".into(),
        server: None,
        pq_pinned: false,
        allow_classical: false,
        auto_start: false,
    });
    let start1_done = Rc::new(RefCell::new(None::<Result<PublicKey, StartChatError>>));
    let start1_ref = start1_done.clone();
    let e1 = engine.clone();
    let k1 = key_a_text.clone();
    spawner
        .spawn_local(async move {
            *start1_ref.borrow_mut() = Some(
                e1.start_chat(sub1, &k1, "Peer A".into(), None, false, false)
                    .await,
            );
        })
        .unwrap();

    pool.run_until_stalled();
    assert!(reg_started.get());
    assert!(start1_done.borrow().is_none());

    // Concurrently deliver `fw_c` via `say_farewells()`, delete `peer_b` (appending `fw_b`), and
    // cancel `start_chat(peer_a)` while `RegisterWriteToken` is still suspended!
    pool.run_until(engine.say_farewells()).unwrap();
    pool.run_until(engine.delete(peer_b)).unwrap();
    let fw_b_bytes = pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(inner.state.farewells.len(), 1);
        assert_eq!(
            inner.state.farewells[0].recipient().as_deref(),
            Some(peer_b.as_slice())
        );
        inner.state.farewells[0].push_v2.clone()
    });
    engine.cancel_startup_submission(sub1);

    reg_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*start1_done.borrow(), Some(Err(StartChatError::Cancelled)));
    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert!(inner.contacts.iter().all(|c| c.peer != peer_a));
        let fws: Vec<&[u8]> = inner
            .state
            .farewells
            .iter()
            .map(|f| f.push_v2.as_slice())
            .collect();
        assert!(
            fws.contains(&fw_b_bytes.as_slice()),
            "concurrently added peer_b farewell must not be clobbered by start_chat rollback"
        );
        assert!(
            fws.contains(&fw_a.push_v2.as_slice()),
            "peer_a retained farewell must be restored on start_chat rollback"
        );
        assert!(
            !fws.contains(&fw_c.push_v2.as_slice()),
            "concurrently delivered peer_c farewell must not be resurrected by rollback"
        );
    });
    drop(_mock1);

    // Subcase 2: Cancel `start_chat(peer_a)` while `SendInitialV2` is suspended and returns a
    // definitive server refusal, after concurrently appending a farewell `fw_d`.
    let peer_d = [0xDDu8; 32];
    let fw_d = Farewell {
        push_v2: PushV2Request {
            recipient: Bytes::copy_from_slice(&peer_d),
            message: Some(party::EncryptedMessage {
                header: Bytes::from_static(b"hdr-d"),
                content: Bytes::from_static(b"ct-d"),
            }),
            write_token: Bytes::from_static(&[0x33u8; 32]),
            client_message_id: Bytes::from_static(&[0xDDu8; 16]),
            initial_message: None,
        }
        .encode_to_vec(),
    };
    let (send_tx, send_rx) = oneshot::channel::<()>();
    let send_rx = Rc::new(RefCell::new(Some(send_rx)));
    let send_started = Rc::new(Cell::new(false));
    let send_rx_ref = send_rx.clone();
    let send_started_ref = send_started.clone();

    let _mock2 = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let send_rx_ref = send_rx_ref.clone();
        let send_started_ref = send_started_ref.clone();
        let bundle_a2 = bundle_a2.clone();
        async move {
            if path.ends_with("/ClaimBundle") {
                Ok((200, bundle_a2.encode_to_vec()))
            } else if path.ends_with("/RegisterWriteToken") {
                Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
            } else if path.ends_with("/SendInitialV2") {
                send_started_ref.set(true);
                await_gate(&send_rx_ref).await;
                let err =
                    protocol::connect::error(protocol::ErrorKind::LimitExceeded, "inbox full");
                Ok((err.status, err.body))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });

    let sub2 = engine.begin_new_chat_submit(PendingNewChat {
        key: key_a_text.clone(),
        name: "Peer A".into(),
        server: None,
        pq_pinned: false,
        allow_classical: false,
        auto_start: false,
    });
    let start2_done = Rc::new(RefCell::new(None::<Result<PublicKey, StartChatError>>));
    let start2_ref = start2_done.clone();
    let e2 = engine.clone();
    spawner
        .spawn_local(async move {
            *start2_ref.borrow_mut() = Some(
                e2.start_chat(sub2, &key_a_text, "Peer A".into(), None, false, false)
                    .await,
            );
        })
        .unwrap();

    pool.run_until_stalled();
    assert!(send_started.get());
    assert!(start2_done.borrow().is_none());

    pool.run_until(async {
        let mut guard = engine.lock_inner().await;
        let inner = guard.as_mut().unwrap();
        inner.state.farewells.push(fw_d.clone());
        inner.save_state().await.unwrap();
    });
    engine.cancel_startup_submission(sub2);

    send_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*start2_done.borrow(), Some(Err(StartChatError::Cancelled)));
    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert!(inner.contacts.iter().all(|c| c.peer != peer_a));
        let fws: Vec<&[u8]> = inner
            .state
            .farewells
            .iter()
            .map(|f| f.push_v2.as_slice())
            .collect();
        assert!(fws.contains(&fw_b_bytes.as_slice()));
        assert!(fws.contains(&fw_d.push_v2.as_slice()));
        assert!(fws.contains(&fw_a.push_v2.as_slice()));
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn greeting_delivery_never_downgrades_from_confirmed_and_stays_uncertain_on_write_token_retry() {
    use crate::vault::{
        GREETING_DELIVERY_CONFIRMED, GREETING_DELIVERY_UNCERTAIN, GREETING_DELIVERY_UNSENT,
    };
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    // Part 1: While `PushV2` (promoted UNSENT -> UNCERTAIN) is suspended, concurrent confirmation
    // sets `GREETING_DELIVERY_CONFIRMED`; a late server refusal (`LimitExceeded`) MUST NOT
    // downgrade `greeting_delivery` back to `UNSENT`!
    let (engine, peer) = pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contact(&peer).unwrap().state.greeting_delivery = GREETING_DELIVERY_UNSENT;
            inner
                .add(&peer, Kind::Text("refused-after-confirm".into()), false)
                .await
                .unwrap();
        }
        (engine, peer)
    });

    let (push_tx, push_rx) = oneshot::channel::<()>();
    let push_rx = Rc::new(RefCell::new(Some(push_rx)));
    let push_started = Rc::new(Cell::new(false));
    let push_rx_ref = push_rx.clone();
    let push_started_ref = push_started.clone();

    let _mock1 = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let push_rx_ref = push_rx_ref.clone();
        let push_started_ref = push_started_ref.clone();
        async move {
            assert!(path.ends_with("/PushV2"), "unexpected path: {path}");
            push_started_ref.set(true);
            await_gate(&push_rx_ref).await;
            let err = protocol::connect::error(protocol::ErrorKind::LimitExceeded, "too big");
            Ok((err.status, err.body))
        }
    });

    let flush_done = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let flush_ref = flush_done.clone();
    let e1 = engine.clone();
    spawner
        .spawn_local(async move {
            *flush_ref.borrow_mut() = Some(e1.flush(&peer).await);
        })
        .unwrap();

    pool.run_until_stalled();
    assert!(push_started.get());
    assert!(flush_done.borrow().is_none());

    // Confirm greeting concurrently while `PushV2` is suspended!
    pool.run_until(async {
        let mut guard = engine.lock_inner().await;
        let inner = guard.as_mut().unwrap();
        assert_eq!(
            inner.contact(&peer).unwrap().state.greeting_delivery,
            GREETING_DELIVERY_UNCERTAIN
        );
        inner.contact(&peer).unwrap().mark_greeting_confirmed();
        inner.save_state().await.unwrap();
    });

    push_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*flush_done.borrow(), Some(Ok(true)));
    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(
            inner
                .contacts
                .iter()
                .find(|c| c.peer == peer)
                .unwrap()
                .state
                .greeting_delivery,
            GREETING_DELIVERY_CONFIRMED,
            "late server refusal must never downgrade GREETING_DELIVERY_CONFIRMED back to UNSENT"
        );
    });
    drop(_mock1);

    // Part 2: `WriteTokenRejected` -> `SendInitialV2` retry keeps `GREETING_DELIVERY_UNCERTAIN`
    // durably persisted BEFORE transmitting and across transient network drop, and reverts to
    // `UNSENT` ONLY on definitive server refusal while still `UNCERTAIN`.
    let (engine2, peer2) = pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contact(&peer).unwrap().state.greeting_delivery = GREETING_DELIVERY_UNSENT;
            inner
                .add(&peer, Kind::Text("needs-approval-retry".into()), false)
                .await
                .unwrap();
        }
        (engine, peer)
    });

    // Subcase 2a: PushV2 -> WriteTokenRejected, SendInitialV2 retry is suspended -> verify vault
    // has `GREETING_DELIVERY_UNCERTAIN` BEFORE/DURING SendInitialV2, and stays `UNCERTAIN` when
    // SendInitialV2 drops transiently (`Connect` error)!
    let (retry_tx, retry_rx) = oneshot::channel::<()>();
    let retry_rx = Rc::new(RefCell::new(Some(retry_rx)));
    let retry_started = Rc::new(Cell::new(false));
    let retry_rx_ref = retry_rx.clone();
    let retry_started_ref = retry_started.clone();
    let _mock2a = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let retry_rx_ref = retry_rx_ref.clone();
        let retry_started_ref = retry_started_ref.clone();
        async move {
            if path.ends_with("/PushV2") {
                let err = protocol::connect::error(
                    protocol::ErrorKind::WriteTokenRejected,
                    "not accepted yet",
                );
                Ok((err.status, err.body))
            } else if path.ends_with("/SendInitialV2") {
                retry_started_ref.set(true);
                await_gate(&retry_rx_ref).await;
                Err(protocol::Error::new(
                    protocol::ErrorKind::Connect,
                    "response lost after server accepted",
                ))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });

    let f2a_done = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let f2a_ref = f2a_done.clone();
    let e2a = engine2.clone();
    spawner
        .spawn_local(async move {
            *f2a_ref.borrow_mut() = Some(e2a.flush(&peer2).await);
        })
        .unwrap();

    pool.run_until_stalled();
    assert!(retry_started.get());
    assert!(f2a_done.borrow().is_none());
    // While `SendInitialV2` retry is in flight, persisted vault state MUST be `UNCERTAIN` (not `UNSENT`)!
    pool.run_until(async {
        let guard = engine2.lock_inner().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(
            inner.vault.state.borrow().contacts[0].greeting_delivery,
            GREETING_DELIVERY_UNCERTAIN,
            "WriteTokenRejected SendInitialV2 retry must transmit with persisted UNCERTAIN"
        );
    });

    // Transient network drop on `SendInitialV2` MUST surface Err (not silently apply approval
    // backoff) AND preserve `GREETING_DELIVERY_UNCERTAIN`!
    retry_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert!(matches!(&*f2a_done.borrow(), Some(Err(_))));
    assert!(
        !engine2.queue.has_approval_backoff(&peer2),
        "failed SendInitialV2 retry must not record peer-approval backoff"
    );
    pool.run_until(async {
        let guard = engine2.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(
            inner.vault.state.borrow().contacts[0].greeting_delivery,
            GREETING_DELIVERY_UNCERTAIN,
            "transient SendInitialV2 retry error must preserve GREETING_DELIVERY_UNCERTAIN"
        );
    });
    drop(_mock2a);

    // Subcase 2b: Clear backoff, reset to `UNSENT`, and have `SendInitialV2` retry return a
    // definitive server refusal -> reverts cleanly `UNCERTAIN -> UNSENT` AND surfaces Err.
    engine2.clear_approval_backoff(&peer2);
    pool.run_until(async {
        let mut guard = engine2.inner.lock().await;
        let inner = guard.as_mut().unwrap();
        inner.contact(&peer2).unwrap().state.greeting_delivery = GREETING_DELIVERY_UNSENT;
        inner.save_state().await.unwrap();
    });
    let _mock2b = crate::transport::mock_fetch(|_server, path, _body| {
        if path.ends_with("/PushV2") {
            let err = protocol::connect::error(
                protocol::ErrorKind::WriteTokenRejected,
                "not accepted yet",
            );
            Ok((err.status, err.body))
        } else if path.ends_with("/SendInitialV2") {
            let err = protocol::connect::error(protocol::ErrorKind::LimitExceeded, "inbox full");
            Ok((err.status, err.body))
        } else {
            panic!("unexpected path: {path}");
        }
    });
    assert!(pool.run_until(engine2.flush(&peer2)).is_err());
    assert!(!engine2.queue.has_approval_backoff(&peer2));
    pool.run_until(async {
        let guard = engine2.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(
            inner.vault.state.borrow().contacts[0].greeting_delivery,
            GREETING_DELIVERY_UNSENT,
            "definitive server refusal on promoted SendInitialV2 retry should revert to UNSENT"
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn awaiting_acceptance_tracks_pending_requests_and_clears_on_accept_or_push() {
    use prost::Message as _;

    futures::executor::block_on(async {
        let (alice_engine, bob_peer, _bob) = established_engine_on_localhost().await;

        // 1. Freshly initiated chat: awaiting acceptance immediately before any message is sent.
        {
            let mut guard = alice_engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            alice_engine.refresh_contacts(inner);
            assert!(
                alice_engine
                    .ui
                    .contact(&bob_peer)
                    .unwrap()
                    .awaiting_acceptance,
                "newly initiated chat must surface awaiting_acceptance before peer accepts"
            );
            inner.contact(&bob_peer).unwrap().state.greeting_delivery =
                crate::vault::GREETING_DELIVERY_CONFIRMED;
            inner
                .add(&bob_peer, Kind::Text("hello before accept".into()), false)
                .await
                .unwrap();
            alice_engine.refresh_contacts(inner);
        }

        // 2. WriteTokenRejected on `!known_by_peer` keeps awaiting_acceptance active under backoff.
        {
            let _mock = crate::transport::mock_fetch(|_server, path, _body| {
                if path.ends_with("/PushV2") {
                    let err = protocol::connect::error(
                        protocol::ErrorKind::WriteTokenRejected,
                        "write token rejected",
                    );
                    Ok((err.status, err.body))
                } else if path.ends_with("/GetManifest") {
                    Ok((
                        200,
                        protocol::handshake_v2::GetManifestResponse { manifest: None }
                            .encode_to_vec(),
                    ))
                } else {
                    panic!("unexpected path {path}");
                }
            });
            assert_eq!(alice_engine.flush(&bob_peer).await, Ok(false));
            assert!(alice_engine.queue.has_approval_backoff(&bob_peer));
            assert!(
                alice_engine
                    .ui
                    .contact(&bob_peer)
                    .unwrap()
                    .awaiting_acceptance
            );
        }

        // 3. Rekeyed existing chat (`peer_last > 0`, `!known_by_peer`, no prior WriteTokenRejected):
        //    not flagged until PushV2 actually hits WriteTokenRejected (e.g. after peer deleted chat).
        alice_engine.clear_approval_backoff(&bob_peer);
        {
            let mut guard = alice_engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let contact = inner.contact(&bob_peer).unwrap();
            contact.state.peer_last = 5;
            contact.state.awaiting_peer_acceptance = false;
            alice_engine.refresh_contacts(inner);
            assert!(
                !alice_engine
                    .ui
                    .contact(&bob_peer)
                    .unwrap()
                    .awaiting_acceptance,
                "existing chat rekey must not show awaiting_acceptance without WriteTokenRejected"
            );
        }
        {
            let _mock = crate::transport::mock_fetch(|_server, path, _body| {
                if path.ends_with("/PushV2") {
                    let err = protocol::connect::error(
                        protocol::ErrorKind::WriteTokenRejected,
                        "write token rejected",
                    );
                    Ok((err.status, err.body))
                } else if path.ends_with("/GetManifest") {
                    Ok((
                        200,
                        protocol::handshake_v2::GetManifestResponse { manifest: None }
                            .encode_to_vec(),
                    ))
                } else {
                    panic!("unexpected path {path}");
                }
            });
            assert_eq!(alice_engine.flush(&bob_peer).await, Ok(false));
            assert!(
                alice_engine
                    .ui
                    .contact(&bob_peer)
                    .unwrap()
                    .awaiting_acceptance,
                "WriteTokenRejected on rekeyed !known_by_peer chat must surface awaiting_acceptance"
            );
            // Durable flag survives clearing in-memory approval backoff (e.g. sync_now() or reload).
            alice_engine.clear_approval_backoff(&bob_peer);
            let guard = alice_engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(
                inner.vault.state.borrow().contacts[0].awaiting_peer_acceptance,
                "awaiting_peer_acceptance must be persisted durably"
            );
            alice_engine.refresh_contacts(inner);
            assert!(
                alice_engine
                    .ui
                    .contact(&bob_peer)
                    .unwrap()
                    .awaiting_acceptance,
                "awaiting_acceptance must survive sync_now()/reload until peer accepts or PushV2 succeeds"
            );
        }

        // 4. Once PushV2 succeeds (even before Events { accepted: true } arrives), backoff and
        //    durable awaiting_peer_acceptance both clear immediately.
        alice_engine.clear_approval_backoff(&bob_peer);
        {
            let _mock = crate::transport::mock_fetch(|_server, path, _body| {
                assert!(path.ends_with("/PushV2"), "unexpected path {path}");
                Ok((
                    200,
                    protocol::mailbox_v2::PushV2Response { sequence: 1 }.encode_to_vec(),
                ))
            });
            assert_eq!(alice_engine.flush(&bob_peer).await, Ok(true));
            assert!(!alice_engine.queue.has_approval_backoff(&bob_peer));
            assert!(
                !alice_engine
                    .ui
                    .contact(&bob_peer)
                    .unwrap()
                    .awaiting_acceptance,
                "successful PushV2 must clear awaiting_acceptance"
            );
        }

        // 5. Once peer is known (e.g. Events { accepted: true } / peer reply), awaiting_acceptance
        //    is false even with peer_last == 0 and empty awaiting.
        {
            let mut guard = alice_engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let contact = inner.contact(&bob_peer).unwrap();
            contact.state.peer_last = 0;
            contact.state.awaiting.clear();
            change_session(&mut contact.session, |s| {
                s.known_by_peer = true;
            });
            alice_engine.refresh_contacts(inner);
            assert!(
                !alice_engine
                    .ui
                    .contact(&bob_peer)
                    .unwrap()
                    .awaiting_acceptance
            );
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn flush_pending_grants_drops_only_stale_version_and_accept_gates_events_until_registered() {
    use protocol::mailbox_v2::{PushV2Response, RegisterWriteTokenResponse};
    use std::rc::Rc;

    futures::executor::block_on(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        let token_hash = [0x33u8; 32];
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let contact = inner.contact(&peer).unwrap();
            contact.state.request = true;
            contact
                .session
                .queue_pending_grant(session::PendingGrant {
                    token_hash,
                    grant_version: 1,
                    pin_active: true,
                })
                .unwrap();
            inner.save_state().await.unwrap();
        }

        // 1. Transient Protocol / StaleTimestamp refusal MUST keep the staged grant.
        {
            let _mock = crate::transport::mock_fetch(|_server, path, _body| {
                assert!(path.ends_with("/RegisterWriteToken"), "unexpected {path}");
                let err = protocol::connect::error(
                    protocol::ErrorKind::StaleTimestamp,
                    "stale timestamp",
                );
                Ok((err.status, err.body))
            });
            assert!(engine.flush_pending_grants_for_peer(&peer).await.is_err());
        }
        {
            let guard = engine.inner.lock().await;
            assert_eq!(
                guard.as_ref().unwrap().contacts[0]
                    .session
                    .pending_register_grants()
                    .len(),
                1,
                "StaleTimestamp must NOT drop staged grant"
            );
        }

        // 2. LimitExceeded MUST keep the staged grant and notify the user.
        {
            let _mock = crate::transport::mock_fetch(|_server, path, _body| {
                assert!(path.ends_with("/RegisterWriteToken"), "unexpected {path}");
                let err =
                    protocol::connect::error(protocol::ErrorKind::LimitExceeded, "too many grants");
                Ok((err.status, err.body))
            });
            assert!(engine.flush_pending_grants_for_peer(&peer).await.is_err());
        }
        {
            let guard = engine.inner.lock().await;
            assert_eq!(
                guard.as_ref().unwrap().contacts[0]
                    .session
                    .pending_register_grants()
                    .len(),
                1,
                "LimitExceeded must NOT drop staged grant"
            );
        }

        // 3. Explicit StaleVersion (Code::OutOfRange) MUST drop the superseded grant cleanly.
        {
            let _mock = crate::transport::mock_fetch(|_server, path, _body| {
                assert!(path.ends_with("/RegisterWriteToken"), "unexpected {path}");
                let err = protocol::connect::error(
                    protocol::ErrorKind::StaleVersion,
                    "grant_version <= revoked_below_version",
                );
                Ok((err.status, err.body))
            });
            assert_eq!(engine.flush_pending_grants_for_peer(&peer).await, Ok(()));
        }
        {
            let guard = engine.inner.lock().await;
            assert!(
                guard.as_ref().unwrap().contacts[0]
                    .session
                    .pending_register_grants()
                    .is_empty(),
                "StaleVersion must drop superseded grant"
            );
        }

        // 4. `Engine::accept` when RegisterWriteToken fails MUST NOT transmit Events { accepted: true };
        //    even an explicit `flush(&peer)` stays gated until grant registration succeeds!
        let push_calls = Rc::new(Cell::new(0usize));
        let push_calls_ref = push_calls.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/RegisterWriteToken") {
                    let err =
                        protocol::connect::error(protocol::ErrorKind::StaleTimestamp, "clock skew");
                    Ok((err.status, err.body))
                } else if path.ends_with("/PushV2") {
                    push_calls_ref.set(push_calls_ref.get() + 1);
                    Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            engine.accept(peer, "Bob".into()).await.unwrap();
            assert_eq!(
                push_calls.get(),
                0,
                "accept() must not push Events {{ accepted: true }} before grant registers"
            );
            assert_eq!(engine.flush(&peer).await, Ok(false));
            assert_eq!(
                push_calls.get(),
                0,
                "push_events must gate accepted=true while pending_register_grants is non-empty"
            );
        }

        // 5. Once RegisterWriteToken succeeds, `flush(&peer)` immediately pushes Events { accepted: true }!
        {
            let push_calls_ref = push_calls.clone();
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/RegisterWriteToken") {
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else if path.ends_with("/PushV2") {
                    push_calls_ref.set(push_calls_ref.get() + 1);
                    Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            engine.flush_pending_grants_for_peer(&peer).await.unwrap();
            assert_eq!(engine.flush(&peer).await, Ok(true));
        }
        assert_eq!(
            push_calls.get(),
            1,
            "once grant registers, flush() must push Events {{ accepted: true }}"
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn mailbox_full_unavailable_retains_outbox_and_retries_while_limit_exceeded_refuses() {
    use protocol::mailbox_v2::{PushV2Request, PushV2Response};
    use std::rc::Rc;

    futures::executor::block_on(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .add(&peer, Kind::Text("retry when mailbox frees".into()), false)
                .await
                .unwrap();
        }

        // 1. Temporary MailboxFull (Code::Unavailable / HTTP 503) returns Err, keeps outbox item
        //    sealed with the same client_message_id, and does NOT mark Delivery::Failed.
        let first_id = Rc::new(RefCell::new(Vec::<u8>::new()));
        let first_id_ref = first_id.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, body| {
                assert!(path.ends_with("/PushV2"));
                let req = PushV2Request::decode(body.as_slice()).unwrap();
                *first_id_ref.borrow_mut() = req.client_message_id.to_vec();
                let err = protocol::connect::error(
                    protocol::ErrorKind::MailboxFull,
                    "recipient mailbox queue is full",
                );
                assert_eq!(err.status, 503);
                Ok((err.status, err.body))
            });
            assert!(engine.flush(&peer).await.is_err());
        }
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert_eq!(inner.contacts[0].state.outbox.len(), 1);
            assert!(inner.contacts[0].state.outbox[0].sealed);
            assert_eq!(
                inner.vault.entries.borrow()[&(peer, 0)].delivery(),
                Delivery::Pending
            );
        }

        // 2. Retry succeeds with identical client_message_id and marks Sent.
        let retry_id = Rc::new(RefCell::new(Vec::<u8>::new()));
        let retry_id_ref = retry_id.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, body| {
                assert!(path.ends_with("/PushV2"));
                let req = PushV2Request::decode(body.as_slice()).unwrap();
                *retry_id_ref.borrow_mut() = req.client_message_id.to_vec();
                Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
            });
            assert_eq!(engine.flush(&peer).await, Ok(true));
        }
        assert_eq!(*first_id.borrow(), *retry_id.borrow());
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert!(inner.contacts[0].state.outbox.is_empty());
            assert_eq!(
                inner.vault.entries.borrow()[&(peer, 0)].delivery(),
                Delivery::Sent
            );
            // 3. Permanent LimitExceeded (oversize payload, HTTP 429) DOES mark Delivery::Failed.
            drop(guard);
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .add(&peer, Kind::Text("oversize message".into()), false)
                .await
                .unwrap();
        }
        {
            let _mock = crate::transport::mock_fetch(|_server, path, _body| {
                assert!(path.ends_with("/PushV2"));
                let err = protocol::connect::error(
                    protocol::ErrorKind::LimitExceeded,
                    "message exceeds max size",
                );
                assert_eq!(err.status, 429);
                Ok((err.status, err.body))
            });
            assert_eq!(engine.flush(&peer).await, Ok(true));
        }
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert!(inner.contacts[0].state.outbox.is_empty());
        assert_eq!(
            inner.vault.entries.borrow()[&(peer, 1)].delivery(),
            Delivery::Failed
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn ensure_session_for_outbox_aborts_send_initial_when_contact_deleted_during_grant_flush() {
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use protocol::mailbox_v2::RegisterWriteTokenResponse;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    let (engine, peer, bob_bundle) = pool.run_until(async {
        let (engine, peer, mut bob) = established_engine_on_localhost().await;
        let bundle = publish_bundle_for_test(&mut bob, "localhost", 1)
            .into_iter()
            .next()
            .unwrap();
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .add(&peer, Kind::Text("rekey message".into()), false)
                .await
                .unwrap();
            inner.contact(&peer).unwrap().session.retire();
            inner.save_state().await.unwrap();
        }
        (engine, peer, bundle)
    });

    let (reg_tx, reg_rx) = oneshot::channel::<()>();
    let reg_rx = Rc::new(RefCell::new(Some(reg_rx)));
    let reg_started = Rc::new(Cell::new(false));
    let send_initial_calls = Rc::new(Cell::new(0usize));

    let reg_rx_ref = reg_rx.clone();
    let reg_started_ref = reg_started.clone();
    let send_init_ref = send_initial_calls.clone();

    let _mock = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let reg_rx_ref = reg_rx_ref.clone();
        let reg_started_ref = reg_started_ref.clone();
        let send_init_ref = send_init_ref.clone();
        let bob_bundle = bob_bundle.clone();
        async move {
            if path.ends_with("/ListInitialMessages") {
                Ok((
                    200,
                    protocol::handshake_v2::ListInitialMessagesResponse::default().encode_to_vec(),
                ))
            } else if path.ends_with("/ClaimBundle") {
                Ok((200, bob_bundle.encode_to_vec()))
            } else if path.ends_with("/RegisterWriteToken") {
                reg_started_ref.set(true);
                await_gate(&reg_rx_ref).await;
                Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
            } else if path.ends_with("/SendInitialV2") {
                send_init_ref.set(send_init_ref.get() + 1);
                Ok((
                    200,
                    protocol::handshake_v2::SendInitialV2Response { id: 1 }.encode_to_vec(),
                ))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });

    let done = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let done_ref = done.clone();
    let eng = engine.clone();
    spawner
        .spawn_local(async move {
            *done_ref.borrow_mut() = Some(eng.flush(&peer).await);
        })
        .unwrap();

    pool.run_until_stalled();
    assert!(reg_started.get());
    assert!(done.borrow().is_none());

    // Delete the contact concurrently while `RegisterWriteToken` is suspended!
    pool.run_until(async {
        engine.delete(peer).await.unwrap();
    });

    reg_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*done.borrow(), Some(Ok(false)));
    assert_eq!(
        send_initial_calls.get(),
        0,
        "ensure_session_for_outbox MUST NOT transmit SendInitialV2 after contact was deleted"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn unsent_greeting_shows_sending_state_and_auto_retries_in_sync_even_with_empty_outbox() {
    use crate::vault::{GREETING_DELIVERY_CONFIRMED, GREETING_DELIVERY_UNSENT};
    use protocol::handshake_v2::SendInitialV2Response;
    use std::rc::Rc;

    futures::executor::block_on(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contact(&peer).unwrap().state.greeting_delivery = GREETING_DELIVERY_UNSENT;
            inner.save_state().await.unwrap();
            engine.refresh_contacts(inner);
        }
        let view = engine.ui.contact(&peer).unwrap();
        assert!(
            view.greeting_unsent,
            "unsent initial greeting must surface greeting_unsent"
        );
        assert!(
            !view.awaiting_acceptance,
            "unsent initial greeting must NOT falsely claim awaiting_acceptance"
        );

        // Even with an empty outbox, `retry_pending_greetings` automatically retries SendInitialV2!
        let init_calls = Rc::new(Cell::new(0usize));
        let init_calls_ref = init_calls.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                assert!(path.ends_with("/SendInitialV2"), "unexpected path {path}");
                init_calls_ref.set(init_calls_ref.get() + 1);
                Ok((200, SendInitialV2Response { id: 1 }.encode_to_vec()))
            });
            assert_eq!(engine.retry_pending_greetings().await, Ok(true));
        }
        assert_eq!(init_calls.get(), 1);
        let view_after = engine.ui.contact(&peer).unwrap();
        assert!(!view_after.greeting_unsent);
        assert!(view_after.awaiting_acceptance);
        let guard = engine.inner.lock().await;
        assert_eq!(
            guard.as_ref().unwrap().contacts[0].state.greeting_delivery,
            GREETING_DELIVERY_CONFIRMED
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn outbox_recovery_and_requeue_reject_tampered_history_digest() {
    futures::executor::block_on(async {
        let (mut inner, peer) = unlocked_client();
        inner
            .add(&peer, Kind::Text("original authentic text".into()), false)
            .await
            .unwrap();
        let idx = inner.contacts[0].state.outbox[0].history_index;
        let orig_digest = inner.contacts[0].state.outbox[0].content_digest.clone();
        assert_eq!(orig_digest.len(), 32);

        // Tamper the stored HistoryEntry plaintext without changing authenticated STATE digest.
        inner
            .vault
            .entries
            .borrow_mut()
            .insert((peer, idx), history("TAMPERED PAYLOAD"));

        // 1. `recover_corrupt_outbox` MUST reject the tampered content and mark it Failed.
        match inner.recover_corrupt_outbox(&peer, idx).await.unwrap() {
            CorruptOutboxRecovery::Dropped { history } => {
                assert_eq!(history.len(), 1);
                assert_eq!(history[0].1.delivery(), Delivery::Failed);
            }
            CorruptOutboxRecovery::Rebuilt(_) => {
                panic!("recover_corrupt_outbox must reject tampered history content")
            }
        }
        assert!(inner.contacts[0].state.outbox.is_empty());

        // 2. `rebuild_outbox` (sealed requeue & peer-delete awaiting resend) MUST also reject
        //    tampered history content.
        inner
            .add(&peer, Kind::Text("second authentic text".into()), false)
            .await
            .unwrap();
        let idx2 = inner.contacts[0].state.outbox[0].history_index;
        inner.contacts[0].state.outbox[0].sealed = true;
        inner.contacts[0].state.needs_requeue_sealed = true;
        inner
            .vault
            .entries
            .borrow_mut()
            .insert((peer, idx2), history("TAMPERED REQUEUE"));
        let outcome = inner.requeue_before_push(&peer).await.unwrap().unwrap();
        assert_eq!(outcome.outbox, vec![(peer, idx2, None)]);
        assert!(inner.contacts[0].state.outbox.is_empty());
        assert_eq!(
            inner.vault.entries.borrow()[&(peer, idx2)].delivery(),
            Delivery::Failed
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn cancelled_start_chat_after_register_write_token_stages_pending_revoke() {
    use crate::state::PendingNewChat;
    use crate::util::key_to_text;
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use protocol::mailbox_v2::RegisterWriteTokenResponse;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    let (engine, peer_a, bundle_a) = pool.run_until(async {
        let (engine, _peer_b, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let _ = publish_bundle_for_test(&mut inner.client, "localhost", 1);
            inner.state.published_at = crate::util::now();
            inner.save_state().await.unwrap();
        }
        let mut peer_a_client = Client::new(Fetch::client(LOCAL_SERVER));
        let bundle_a = publish_bundle_for_test(&mut peer_a_client, "localhost", 1)
            .into_iter()
            .next()
            .unwrap();
        (engine, peer_a_client.identity_key(), bundle_a)
    });

    let (reg_tx, reg_rx) = oneshot::channel::<()>();
    let reg_rx = Rc::new(RefCell::new(Some(reg_rx)));
    let reg_started = Rc::new(Cell::new(false));
    let send_initial_calls = Rc::new(Cell::new(0usize));

    let reg_rx_ref = reg_rx.clone();
    let reg_started_ref = reg_started.clone();
    let send_init_ref = send_initial_calls.clone();

    let _mock = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let reg_rx_ref = reg_rx_ref.clone();
        let reg_started_ref = reg_started_ref.clone();
        let send_init_ref = send_init_ref.clone();
        let bundle_a = bundle_a.clone();
        async move {
            if path.ends_with("/ClaimBundle") {
                Ok((200, bundle_a.encode_to_vec()))
            } else if path.ends_with("/RegisterWriteToken") {
                reg_started_ref.set(true);
                await_gate(&reg_rx_ref).await;
                Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
            } else if path.ends_with("/SendInitialV2") {
                send_init_ref.set(send_init_ref.get() + 1);
                Ok((
                    200,
                    protocol::handshake_v2::SendInitialV2Response { id: 1 }.encode_to_vec(),
                ))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });

    let submission_id = engine.begin_new_chat_submit(PendingNewChat {
        key: key_to_text(&peer_a),
        name: "PeerA".into(),
        server: None,
        pq_pinned: false,
        allow_classical: false,
        auto_start: false,
    });
    let done = Rc::new(RefCell::new(None::<Result<PublicKey, StartChatError>>));
    let done_ref = done.clone();
    let eng = engine.clone();
    spawner
        .spawn_local(async move {
            *done_ref.borrow_mut() = Some(
                eng.start_chat(
                    submission_id,
                    &key_to_text(&peer_a),
                    "PeerA".into(),
                    None,
                    false,
                    false,
                )
                .await,
            );
        })
        .unwrap();

    pool.run_until_stalled();
    assert!(reg_started.get());
    engine.cancel_startup_submission(submission_id);

    reg_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert!(matches!(
        *done.borrow(),
        Some(Err(StartChatError::Cancelled))
    ));
    assert_eq!(send_initial_calls.get(), 0);

    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert!(inner.contacts.iter().all(|c| c.peer != peer_a));
        let expected_slot = inner.client.peer_slot_id(&peer_a);
        assert!(
            inner
                .state
                .pending_revokes
                .iter()
                .any(|r| r.peer_slot_id.as_slice() == expected_slot.as_slice()),
            "cancelled start_chat after RegisterWriteToken must stage PendingRevoke"
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn receive_mailbox_releases_inner_lock_and_push_ok_commits_even_after_session_rotation() {
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use protocol::mailbox_v2::{AckMessagesResponse, FetchSignedResponse, PushV2Response};
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    let (engine, peer) = pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .add(&peer, Kind::Text("in-flight message".into()), false)
                .await
                .unwrap();
        }
        (engine, peer)
    });

    // 1. Suspend `FetchSigned` inside `receive_mailbox` -> `engine.inner.try_lock()` MUST succeed!
    let (fetch_tx, fetch_rx) = oneshot::channel::<()>();
    let fetch_rx = Rc::new(RefCell::new(Some(fetch_rx)));
    let fetch_started = Rc::new(Cell::new(false));
    let fetch_rx_ref = fetch_rx.clone();
    let fetch_started_ref = fetch_started.clone();
    let _mock_rx = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let fetch_rx_ref = fetch_rx_ref.clone();
        let fetch_started_ref = fetch_started_ref.clone();
        async move {
            if path.ends_with("/FetchSigned") {
                fetch_started_ref.set(true);
                await_gate(&fetch_rx_ref).await;
                Ok((
                    200,
                    FetchSignedResponse {
                        messages: vec![],
                        has_more: false,
                    }
                    .encode_to_vec(),
                ))
            } else if path.ends_with("/AckMessages") {
                Ok((200, AckMessagesResponse { deleted: 0 }.encode_to_vec()))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });

    let rx_done = Rc::new(RefCell::new(None::<Result<Vec<PublicKey>, String>>));
    let rx_done_ref = rx_done.clone();
    let eng_rx = engine.clone();
    spawner
        .spawn_local(async move {
            *rx_done_ref.borrow_mut() = Some(eng_rx.receive_mailbox().await);
        })
        .unwrap();
    pool.run_until_stalled();
    assert!(fetch_started.get());
    assert!(
        engine.inner.try_lock().is_some(),
        "receive_mailbox must NOT hold self.inner across FetchSigned network RTT"
    );
    fetch_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*rx_done.borrow(), Some(Ok(vec![])));
    drop(_mock_rx);

    // 2. Suspend `PushV2` in `flush(&peer)`, mark `needs_requeue_sealed = true` concurrently while
    //    `PushV2` is in flight, then let `PushV2` return 200 OK -> MUST commit `Step::Pushed`
    //    immediately (zero duplicate re-send!).
    let (push_tx, push_rx) = oneshot::channel::<()>();
    let push_rx = Rc::new(RefCell::new(Some(push_rx)));
    let push_calls = Rc::new(Cell::new(0usize));
    let push_rx_ref = push_rx.clone();
    let push_calls_ref = push_calls.clone();
    let _mock_push = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let push_rx_ref = push_rx_ref.clone();
        let push_calls_ref = push_calls_ref.clone();
        async move {
            assert!(path.ends_with("/PushV2"), "unexpected path: {path}");
            push_calls_ref.set(push_calls_ref.get() + 1);
            await_gate(&push_rx_ref).await;
            Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
        }
    });

    let push_done = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let push_done_ref = push_done.clone();
    let eng_push = engine.clone();
    spawner
        .spawn_local(async move {
            *push_done_ref.borrow_mut() = Some(eng_push.flush(&peer).await);
        })
        .unwrap();
    pool.run_until_stalled();
    assert_eq!(push_calls.get(), 1);
    // Simulate concurrent inbound session replacement marking `needs_requeue_sealed = true`.
    pool.run_until(async {
        let mut guard = engine.inner.lock().await;
        guard
            .as_mut()
            .unwrap()
            .contact(&peer)
            .unwrap()
            .state
            .needs_requeue_sealed = true;
    });
    push_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*push_done.borrow(), Some(Ok(true)));
    assert_eq!(
        push_calls.get(),
        1,
        "PushV2 Ok(()) after concurrent session rotation must commit Step::Pushed without duplicating"
    );
    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert!(inner.contacts[0].state.outbox.is_empty());
        assert_eq!(
            inner.vault.entries.borrow()[&(peer, 0)].delivery(),
            Delivery::Sent
        );
    });
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "ml-kem-1024", feature = "ml-kem-768")
))]
#[test]
fn r2_p0_1_flush_with_needs_new_session_and_upgrade_does_not_deadlock() {
    use futures::executor::LocalPool;
    use protocol::handshake_v2::{
        AckInitialMessagesResponse, ClaimBundleResponse, ListInitialMessagesResponse,
        SendInitialV2Response,
    };
    use protocol::mailbox_v2::{PushV2Response, RegisterWriteTokenResponse};
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        // Bob starts classical-only, then later publishes a full PQ bundle.
        let mut bob_cls = Client::new(Fetch::client(LOCAL_SERVER));
        bob_cls
            .set_pq_config(PqConfig {
                pq_enabled: false,
                pq_ratchet_enabled: false,
                strict_pq: false,
                ..PqConfig::default()
            })
            .unwrap();
        let bob_peer = bob_cls.identity_key();
        let pub_cls = bob_cls.prepare_publish_v2("localhost", 2, 0).unwrap();
        let p_cls = &pub_cls.request;
        let bundle_cls = ClaimBundleResponse {
            signed_prekey: p_cls.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: p_cls.signed_prekey_signature.clone(),
            one_time_prekey: p_cls.one_time_prekeys.first().cloned(),
            pq_last_resort: None,
            pq_one_time_prekey: None,
            manifest: p_cls.manifest.clone(),
        };
        bob_cls.commit_publish_v2(pub_cls);

        // Alice establishes a classical session with Bob (simulating classical-approved chat).
        let mut alice_boot = Client::new(ConnectClient::new(BundleResponse(
            "/ClaimBundle",
            bundle_cls,
        )));
        alice_boot
            .set_pq_config(PqConfig {
                pq_enabled: false,
                pq_ratchet_enabled: false,
                strict_pq: false,
                ..PqConfig::default()
            })
            .unwrap();
        let prep_cls = alice_boot
            .prepare_initiate_v2(
                "localhost",
                &bob_peer,
                &Default::default(),
                &Kind::Hello(alice_boot.make_hello("Alice", 1)).to_bytes(),
                Fetch::client(LOCAL_SERVER),
            )
            .await
            .unwrap();
        let cls_wire = prep_cls.request.message.clone().unwrap();
        let mut bob_cls_session = match bob_cls
            .accept_initial_v2(
                &alice_boot.identity_key(),
                &Default::default(),
                &Incoming::try_from(&cls_wire).unwrap(),
                Fetch::client(LOCAL_SERVER),
            )
            .unwrap()
        {
            session::AcceptedInitial::Accepted { session, .. } => session,
            other => panic!("expected classical accept, got {other:?}"),
        };

        // Bob upgrades to PQ, publishes a PQ bundle, and encrypts a Hello advertising PQ on the
        // existing classical session (which triggers `recommend_start_again` -> `upgrade_to_pq`
        // when replayed inside `take_initial_messages`).
        bob_cls.set_pq_config(PqConfig::default()).unwrap();
        let pub_pq = bob_cls.prepare_publish_v2("localhost", 2, 2).unwrap();
        let p_pq = &pub_pq.request;
        let bundle_pq = ClaimBundleResponse {
            signed_prekey: p_pq.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: p_pq.signed_prekey_signature.clone(),
            one_time_prekey: p_pq.one_time_prekeys.first().cloned(),
            pq_last_resort: p_pq.pq_last_resort.first().cloned(),
            pq_one_time_prekey: p_pq.pq_one_time_prekeys.first().cloned(),
            manifest: p_pq.manifest.clone(),
        };
        bob_cls.commit_publish_v2(pub_pq);
        let pq_hello_env = bob_cls_session
            .encrypt(&Kind::Hello(bob_cls.make_hello("Bob", 2)).to_bytes())
            .unwrap();

        let alice_state =
            ClientState::try_from(&proto::ClientState::from(alice_boot.state())).unwrap();
        let mut alice = Client::restore(Fetch::client(LOCAL_SERVER), alice_state);
        alice.set_pq_config(PqConfig::default()).unwrap();
        let mut contact = super::contact::Contact {
            peer: bob_peer,
            session: prep_cls.session,
            deferred_carried: 0,
            state: ContactState {
                peer: bob_peer.to_vec(),
                name: "Bob".into(),
                greeting_delivery: crate::vault::GREETING_DELIVERY_CONFIRMED,
                conversation_gen: 1,
                ..ContactState::default()
            },
        };
        // Mark `needs_new_session()` so `flush(&bob_peer)` runs `take_initial_messages()` first,
        // and queue a deferred envelope carrying Bob's PQ-advertising Hello so
        // `take_initial_messages()` invokes `upgrade_to_pq(bob_peer)`!
        contact.session.retire();
        let mut inner = Inner::new(
            MemoryVault::default(),
            LOCAL_SERVER.into(),
            "localhost".into(),
            AppState {
                name: "Alice".into(),
                next_conversation_gen: 2,
                ..AppState::default()
            },
            alice,
            vec![contact],
            vec![],
            DeferredRecord::default(),
        );
        inner
            .deferred_envelopes
            .push(crate::vault::DeferredEnvelope {
                peer: bob_peer.to_vec(),
                sequence: 7,
                message: Some(pq_hello_env.message.clone()),
                initial_message: None,
                deferred_at: crate::util::now(),
                pq_isolated: false,
            });
        inner
            .add(&bob_peer, Kind::Text("after upgrade".into()), false)
            .await
            .unwrap();
        let engine = Engine::with_inner(Ui::new(), inner);

        let claim_calls = Rc::new(Cell::new(0usize));
        let claim_calls_ref = claim_calls.clone();
        let send_init_calls = Rc::new(Cell::new(0usize));
        let send_init_ref = send_init_calls.clone();
        let push_calls = Rc::new(Cell::new(0usize));
        let push_ref = push_calls.clone();
        let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
            if path.ends_with("/ListInitialMessages") {
                Ok((
                    200,
                    ListInitialMessagesResponse {
                        messages: vec![],
                        has_more: false,
                    }
                    .encode_to_vec(),
                ))
            } else if path.ends_with("/AckInitialMessages") {
                Ok((
                    200,
                    AckInitialMessagesResponse { deleted: 0 }.encode_to_vec(),
                ))
            } else if path.ends_with("/ClaimBundle") {
                claim_calls_ref.set(claim_calls_ref.get() + 1);
                Ok((200, bundle_pq.encode_to_vec()))
            } else if path.ends_with("/RegisterWriteToken") {
                Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
            } else if path.ends_with("/SendInitialV2") {
                send_init_ref.set(send_init_ref.get() + 1);
                Ok((200, SendInitialV2Response { id: 1 }.encode_to_vec()))
            } else if path.ends_with("/PushV2") {
                push_ref.set(push_ref.get() + 1);
                Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
            } else {
                panic!("unexpected path: {path}");
            }
        });

        // Must complete without self-deadlocking on `peer_flush_lock(&bob_peer)`!
        assert!(engine.flush(&bob_peer).await.unwrap());
        assert_eq!(
            claim_calls.get(),
            1,
            "upgrade_to_pq should have claimed PQ bundle"
        );
        assert_eq!(
            send_init_calls.get(),
            1,
            "upgrade_to_pq should have sent PQ initial"
        );
        assert_eq!(
            push_calls.get(),
            1,
            "queued message should flush on upgraded PQ session"
        );
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert!(
            inner.contacts[0].has_healthy_pq_session(),
            "contact should now have a healthy PQ session"
        );
    });
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "ml-kem-1024", feature = "ml-kem-768")
))]
#[test]
fn r2_p1_1_upgrade_to_pq_revalidates_generation_after_delete_and_recreate() {
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use protocol::handshake_v2::ClaimBundleResponse;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    let (engine, peer, pq_bundle, fresh_request_session) = pool.run_until(async {
        let (engine, peer, mut bob) = established_engine_on_localhost().await;
        let pub_pq = bob.prepare_publish_v2("localhost", 2, 2).unwrap();
        let p = &pub_pq.request;
        let pq_bundle = ClaimBundleResponse {
            signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: p.signed_prekey_signature.clone(),
            one_time_prekey: p.one_time_prekeys.first().cloned(),
            pq_last_resort: p.pq_last_resort.first().cloned(),
            pq_one_time_prekey: p.pq_one_time_prekeys.first().cloned(),
            manifest: p.manifest.clone(),
        };
        bob.commit_publish_v2(pub_pq);

        let fresh_request_session = {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            // Assign conversation_gen = 1 and retire so `upgrade_to_pq` proceeds past `has_healthy_pq_session`.
            inner.contacts[0].state.conversation_gen = 1;
            inner.state.next_conversation_gen = 2;
            inner.contacts[0].session.retire();
            // Build an independent inbound request session for the recreated gen-2 contact.
            let pub_alice = inner.client.prepare_publish_v2("localhost", 2, 2).unwrap();
            let pa = &pub_alice.request;
            let alice_bundle = ClaimBundleResponse {
                signed_prekey: pa.manifest.as_ref().unwrap().signed_prekey.clone(),
                signed_prekey_signature: pa.signed_prekey_signature.clone(),
                one_time_prekey: pa.one_time_prekeys.first().cloned(),
                pq_last_resort: pa.pq_last_resort.first().cloned(),
                pq_one_time_prekey: pa.pq_one_time_prekeys.first().cloned(),
                manifest: pa.manifest.clone(),
            };
            inner.client.commit_publish_v2(pub_alice);
            let bob_proto = proto::ClientState::from(bob.state());
            let mut bob_init = Client::restore(
                ConnectClient::new(BundleResponse("/ClaimBundle", alice_bundle)),
                ClientState::try_from(&bob_proto).unwrap(),
            );
            let prep = bob_init
                .prepare_initiate_v2(
                    "localhost",
                    &inner.client.identity_key(),
                    &Default::default(),
                    &Kind::Hello(bob_init.make_hello("Bob", 9)).to_bytes(),
                    Fetch::client(LOCAL_SERVER),
                )
                .await
                .unwrap();
            let inc = Incoming::try_from(prep.request.message.as_ref().unwrap()).unwrap();
            match inner
                .client
                .accept_initial_v2(
                    &peer,
                    &Default::default(),
                    &inc,
                    Fetch::client(LOCAL_SERVER),
                )
                .unwrap()
            {
                session::AcceptedInitial::Accepted { session, .. } => session,
                other => panic!("expected accepted inbound request, got {other:?}"),
            }
        };
        (engine, peer, pq_bundle, fresh_request_session)
    });

    // Suspend `ClaimBundle` inside `upgrade_to_pq(peer)`.
    let (claim_tx, claim_rx) = oneshot::channel::<()>();
    let claim_rx = Rc::new(RefCell::new(Some(claim_rx)));
    let claim_started = Rc::new(Cell::new(false));
    let reg_calls = Rc::new(Cell::new(0usize));
    let claim_rx_ref = claim_rx.clone();
    let claim_started_ref = claim_started.clone();
    let reg_ref = reg_calls.clone();
    let _mock = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let claim_rx_ref = claim_rx_ref.clone();
        let claim_started_ref = claim_started_ref.clone();
        let reg_ref = reg_ref.clone();
        let pq_bundle = pq_bundle.clone();
        async move {
            if path.ends_with("/ClaimBundle") {
                claim_started_ref.set(true);
                await_gate(&claim_rx_ref).await;
                Ok((200, pq_bundle.encode_to_vec()))
            } else if path.ends_with("/RegisterWriteToken") {
                reg_ref.set(reg_ref.get() + 1);
                Ok((
                    200,
                    protocol::mailbox_v2::RegisterWriteTokenResponse {}.encode_to_vec(),
                ))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });

    let done = Rc::new(RefCell::new(None::<Result<(), String>>));
    let done_ref = done.clone();
    let eng = engine.clone();
    spawner
        .spawn_local(async move {
            *done_ref.borrow_mut() = Some(eng.upgrade_to_pq(peer).await);
        })
        .unwrap();
    pool.run_until_stalled();
    assert!(claim_started.get());

    // Concurrently delete the gen-1 contact and receive a fresh unaccepted inbound chat request
    // (gen 2, `request: true`, zero staged write-token grants).
    pool.run_until(async {
        let mut guard = engine.inner.lock().await;
        let inner = guard.as_mut().unwrap();
        let new_gen = inner.allocate_conversation_gen();
        assert_eq!(new_gen, 2);
        inner.contacts.retain(|c| c.peer != peer);
        inner.contacts.push(super::contact::Contact {
            peer,
            session: fresh_request_session,
            deferred_carried: 0,
            state: ContactState {
                peer: peer.to_vec(),
                name: "Bob".into(),
                request: true,
                conversation_gen: new_gen,
                ..ContactState::default()
            },
        });
    });

    claim_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert!(
        done.borrow().as_ref().is_some_and(Result::is_err),
        "stale upgrade_to_pq must abort with error when chat generation changes: {:?}",
        *done.borrow()
    );
    assert_eq!(
        reg_calls.get(),
        0,
        "stale upgrade_to_pq MUST NOT register a write-token grant for a recreated inbound request"
    );
    pool.run_until(async {
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        let contact = inner.contacts.iter().find(|c| c.peer == peer).unwrap();
        assert_eq!(contact.state.conversation_gen, 2);
        assert!(
            contact.state.request,
            "fresh inbound request must remain unaccepted"
        );
        assert!(
            contact.session.pending_register_grants().is_empty(),
            "fresh inbound request must have zero staged write-token grants"
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r2_p1_2_pending_active_grant_gates_push_v2_and_send_initial_v2_and_reconciles_stale() {
    use futures::executor::LocalPool;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        let (active_hash, first_grant_ver) = {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let active_hash = inner.contacts[0]
                .session
                .active_inbound_token_hash()
                .unwrap();
            inner
                .stage_write_token_grant(&peer, active_hash, true)
                .unwrap();
            let ver = inner.contacts[0].session.pending_register_grants()[0].grant_version;
            inner.contacts[0].state.greeting_delivery = crate::vault::GREETING_DELIVERY_UNSENT;
            inner
                .add(&peer, Kind::Text("must stay gated".into()), false)
                .await
                .unwrap();
            (active_hash, ver)
        };

        // 1. RegisterWriteToken returns 503 unavailable -> BOTH `flush` AND `retry_pending_greetings`
        //    MUST gate PushV2 and SendInitialV2!
        let push_calls = Rc::new(Cell::new(0usize));
        let send_init_calls = Rc::new(Cell::new(0usize));
        let reg_calls = Rc::new(Cell::new(0usize));
        {
            let push_ref = push_calls.clone();
            let send_ref = send_init_calls.clone();
            let reg_ref = reg_calls.clone();
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/RegisterWriteToken") {
                    reg_ref.set(reg_ref.get() + 1);
                    Ok((
                        503,
                        br#"{"code":"unavailable","message":"try again"}"#.to_vec(),
                    ))
                } else if path.ends_with("/PushV2") {
                    push_ref.set(push_ref.get() + 1);
                    panic!("PushV2 must be gated while active grant is pending");
                } else if path.ends_with("/SendInitialV2") {
                    send_ref.set(send_ref.get() + 1);
                    panic!("SendInitialV2 must be gated while active grant is pending");
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            assert!(engine.flush(&peer).await.is_err());
            assert!(
                !engine.retry_pending_greetings().await.unwrap(),
                "retry_pending_greetings must skip peers with pending active grants"
            );
        }
        assert!(reg_calls.get() >= 1);
        assert_eq!(push_calls.get(), 0);
        assert_eq!(send_init_calls.get(), 0);

        // 2. RegisterWriteToken returns 400 out_of_range (`StaleVersion`) for the active grant ->
        //    `flush_pending_grants_for_peer` re-stages the active grant with a HIGHER version and
        //    keeps `has_pending_active_grant() == true` so outbound sends remain gated!
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/RegisterWriteToken") {
                    Ok((
                        400,
                        br#"{"code":"out_of_range","message":"stale grant version"}"#.to_vec(),
                    ))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            assert!(engine.flush_pending_grants_for_peer(&peer).await.is_err());
        }
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert!(
            inner.contacts[0].session.has_pending_active_grant(),
            "active grant hitting StaleVersion must be re-staged, not dropped"
        );
        let restaged = inner.contacts[0].session.pending_register_grants();
        assert_eq!(restaged.len(), 1);
        assert_eq!(restaged[0].token_hash, active_hash);
        assert!(
            restaged[0].grant_version > first_grant_ver,
            "re-staged active grant must allocate a strictly higher grant_version"
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r2_p1_4_pq_isolated_envelopes_survive_30d_pruning_and_replay_on_capable_build() {
    use futures::executor::LocalPool;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        let (engine, peer, bob) = established_engine_on_localhost().await;
        let alice_id = {
            let guard = engine.inner.lock().await;
            guard.as_ref().unwrap().client.identity_key()
        };
        let mut bob_session = {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let pub_alice = inner.client.prepare_publish_v2("localhost", 2, 2).unwrap();
            let pa = &pub_alice.request;
            let alice_bundle = protocol::handshake_v2::ClaimBundleResponse {
                signed_prekey: pa.manifest.as_ref().unwrap().signed_prekey.clone(),
                signed_prekey_signature: pa.signed_prekey_signature.clone(),
                one_time_prekey: pa.one_time_prekeys.first().cloned(),
                pq_last_resort: pa.pq_last_resort.first().cloned(),
                pq_one_time_prekey: pa.pq_one_time_prekeys.first().cloned(),
                manifest: pa.manifest.clone(),
            };
            inner.client.commit_publish_v2(pub_alice);
            let bob_proto = proto::ClientState::from(bob.state());
            let mut bob_sender = Client::restore(
                ConnectClient::new(BundleResponse("/ClaimBundle", alice_bundle)),
                ClientState::try_from(&bob_proto).unwrap(),
            );
            let prep = bob_sender
                .prepare_initiate_v2(
                    "localhost",
                    &alice_id,
                    &Default::default(),
                    &Kind::Hello(bob_sender.make_hello("Bob", 1)).to_bytes(),
                    Fetch::client(LOCAL_SERVER),
                )
                .await
                .unwrap();
            let inc = Incoming::try_from(prep.request.message.as_ref().unwrap()).unwrap();
            let accepted = match inner
                .client
                .accept_initial_v2(
                    &peer,
                    &Default::default(),
                    &inc,
                    Fetch::client(LOCAL_SERVER),
                )
                .unwrap()
            {
                session::AcceptedInitial::Accepted { session, .. } => session,
                other => panic!("expected accepted, got {other:?}"),
            };
            inner.contacts[0].session = accepted;
            prep.session
        };
        let encrypted = bob_session
            .encrypt(&Kind::Text("45-days-later-isolated-msg".into()).to_bytes())
            .unwrap();

        let now_ms = crate::util::now();
        let forty_five_days_ago =
            now_ms.saturating_sub(DEFERRED_REPLAY_WINDOW_MS + 15 * 86_400_000);
        let mut guard = engine.inner.lock().await;
        let inner = guard.as_mut().unwrap();
        // Contact is now active (simulating unlock on a PQ-capable build 45 days later), with
        // an acknowledged `pq_isolated: true` envelope buffered while previously isolated.
        inner
            .deferred_envelopes
            .push(crate::vault::DeferredEnvelope {
                peer: peer.to_vec(),
                sequence: 500,
                message: Some(encrypted.message.clone()),
                initial_message: None,
                deferred_at: forty_five_days_ago,
                pq_isolated: true,
            });
        // Unlock pruning MUST preserve `pq_isolated: true` envelopes even past 30 days.
        let removed = super::sync::prune_deferred_envelopes(
            &mut inner.deferred_envelopes,
            &mut inner.contacts,
            &mut inner.isolated_contacts,
            &alice_id,
            now_ms,
        );
        assert_eq!(removed, 0);
        assert_eq!(inner.deferred_envelopes.len(), 1);

        // `replay_deferred_envelopes` MUST decrypt and deliver the 45-day-old `pq_isolated` message!
        let (replayed, _, _) = engine
            .replay_deferred_envelopes(inner, Some(&peer), Some(u64::MAX), None)
            .await
            .unwrap();
        assert!(replayed.contains(&peer));
        assert!(inner.deferred_envelopes.is_empty());
        let texts: Vec<String> = inner
            .vault
            .entries
            .borrow()
            .values()
            .filter_map(|e| match e.content.as_ref()?.kind.as_ref()? {
                Kind::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect();
        assert!(
            texts.contains(&"45-days-later-isolated-msg".to_string()),
            "{texts:?}"
        );
    });
}

#[cfg(all(
    not(target_arch = "wasm32"),
    not(all(feature = "ml-kem-1024", feature = "ml-kem-768"))
))]
#[test]
fn r2_p1_3_isolated_peer_70_envelopes_do_not_stall_healthy_peer_in_same_page() {
    use futures::executor::LocalPool;
    use protocol::mailbox_v2::{AckMessagesResponse, EnvelopeV2, FetchSignedResponse};

    let mut pool = LocalPool::new();
    pool.run_until(async {
        let (engine, healthy_peer, _bob) = established_engine_on_localhost().await;
        let (alice_id, healthy_token_hash, mut healthy_sender) = {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let alice_id = inner.client.identity_key();
            let pub_alice = inner.client.prepare_publish_v2("localhost", 2, 2).unwrap();
            let pa = &pub_alice.request;
            let alice_bundle = protocol::handshake_v2::ClaimBundleResponse {
                signed_prekey: pa.manifest.as_ref().unwrap().signed_prekey.clone(),
                signed_prekey_signature: pa.signed_prekey_signature.clone(),
                one_time_prekey: pa.one_time_prekeys.first().cloned(),
                pq_last_resort: pa.pq_last_resort.first().cloned(),
                pq_one_time_prekey: pa.pq_one_time_prekeys.first().cloned(),
                manifest: pa.manifest.clone(),
            };
            inner.client.commit_publish_v2(pub_alice);
            let mut sender = Client::new(ConnectClient::new(BundleResponse(
                "/ClaimBundle",
                alice_bundle,
            )));
            let sender_id = sender.identity_key();
            let prep = sender
                .prepare_initiate_v2(
                    "localhost",
                    &alice_id,
                    &Default::default(),
                    &Kind::Hello(sender.make_hello("Healthy", 1)).to_bytes(),
                    Fetch::client(LOCAL_SERVER),
                )
                .await
                .unwrap();
            let inc = Incoming::try_from(prep.request.message.as_ref().unwrap()).unwrap();
            let accepted = match inner
                .client
                .accept_initial_v2(
                    &sender_id,
                    &Default::default(),
                    &inc,
                    Fetch::client(LOCAL_SERVER),
                )
                .unwrap()
            {
                session::AcceptedInitial::Accepted { session, .. } => session,
                other => panic!("expected accepted, got {other:?}"),
            };
            let th = accepted.active_inbound_token_hash().unwrap();
            inner.contacts.push(super::contact::Contact {
                peer: sender_id,
                session: accepted,
                deferred_carried: 0,
                state: ContactState {
                    peer: sender_id.to_vec(),
                    name: "Healthy".into(),
                    ..ContactState::default()
                },
            });
            let _ = healthy_peer;
            (alice_id, th, prep.session)
        };
        let healthy_peer = *healthy_sender.peer();
        let _ = healthy_peer;
        let healthy_msg = healthy_sender
            .encrypt(&Kind::Text("healthy-peer-delivered".into()).to_bytes())
            .unwrap();

        let unsupported_suite = if !PqSuite::MlKem1024.is_supported() {
            PqSuite::MlKem1024.as_u8()
        } else {
            PqSuite::MlKem768.as_u8()
        };
        let iso_peer = identity();
        let iso_token_hash = [0xD7u8; 32];
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let mut iso_session = proto::SessionState::default();
            iso_session.me = alice_id.to_vec();
            iso_session.peer = iso_peer.to_vec();
            iso_session.inbound_token_hash = iso_token_hash.to_vec();
            iso_session.active_security = Some(proto::SessionSecurity {
                is_pq: true,
                suite: unsupported_suite.into(),
                pq_ratchet: true,
            });
            inner.isolated_contacts.push(ContactState {
                peer: iso_peer.to_vec(),
                name: "Iso".into(),
                session: Some(iso_session),
                ..ContactState::default()
            });
        }

        // Single FetchSigned page containing 70 isolated envelopes (> 64 active cap) + 1 healthy msg!
        let mut page_msgs: Vec<EnvelopeV2> = (1..=70u64)
            .map(|seq| EnvelopeV2 {
                sequence: seq,
                token_hash: bytes::Bytes::copy_from_slice(&iso_token_hash),
                message: Some(party::EncryptedMessage {
                    header: bytes::Bytes::from_static(b"h"),
                    content: bytes::Bytes::from_static(b"c"),
                }),
                initial_message: None,
            })
            .collect();
        page_msgs.push(EnvelopeV2 {
            sequence: 71,
            token_hash: bytes::Bytes::copy_from_slice(&healthy_token_hash),
            message: Some(healthy_msg.message.clone()),
            initial_message: None,
        });

        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/FetchSigned") {
                    Ok((
                        200,
                        FetchSignedResponse {
                            messages: page_msgs.clone(),
                            has_more: false,
                        }
                        .encode_to_vec(),
                    ))
                } else if path.ends_with("/AckMessages") {
                    Ok((200, AckMessagesResponse { deleted: 71 }.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            engine.receive_mailbox().await.unwrap();
        }
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(inner.client.mailbox_cursor(), 71);
        assert_eq!(inner.deferred_envelopes.len(), 70);
        assert!(inner.deferred_envelopes.iter().all(|e| e.pq_isolated));
        let texts: Vec<String> = inner
            .vault
            .entries
            .borrow()
            .values()
            .filter_map(|e| match e.content.as_ref()?.kind.as_ref()? {
                Kind::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect();
        assert!(texts.contains(&"healthy-peer-delivered".to_string()));
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r2_p1_5_start_chat_serializes_with_retry_pending_greetings() {
    use crate::state::PendingNewChat;
    use crate::util::key_to_text;
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use protocol::handshake_v2::{ClaimBundleResponse, SendInitialV2Response};
    use protocol::mailbox_v2::RegisterWriteTokenResponse;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    let (engine, peer_a, bundle_a) = pool.run_until(async {
        let mut bob = Client::new(Fetch::client(LOCAL_SERVER));
        let peer_a = bob.identity_key();
        let published = bob.prepare_publish_v2("localhost", 2, 2).unwrap();
        let p = &published.request;
        let bundle = ClaimBundleResponse {
            signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: p.signed_prekey_signature.clone(),
            one_time_prekey: p.one_time_prekeys.first().cloned(),
            pq_last_resort: p.pq_last_resort.first().cloned(),
            pq_one_time_prekey: p.pq_one_time_prekeys.first().cloned(),
            manifest: p.manifest.clone(),
        };
        bob.commit_publish_v2(published);

        let mut alice = Client::new(Fetch::client(LOCAL_SERVER));
        let pub_a = alice.prepare_publish_v2("localhost", 2, 2).unwrap();
        alice.commit_publish_v2(pub_a);
        let inner = Inner::new(
            MemoryVault::default(),
            LOCAL_SERVER.into(),
            "localhost".into(),
            AppState {
                name: "Alice".into(),
                published_at: crate::util::now(),
                ..AppState::default()
            },
            alice,
            vec![],
            vec![],
            DeferredRecord::default(),
        );
        (Engine::with_inner(Ui::new(), inner), peer_a, bundle)
    });

    let (reg_tx, reg_rx) = oneshot::channel::<()>();
    let reg_rx = Rc::new(RefCell::new(Some(reg_rx)));
    let reg_started = Rc::new(Cell::new(false));
    let send_initial_calls = Rc::new(Cell::new(0usize));
    let reg_rx_ref = reg_rx.clone();
    let reg_started_ref = reg_started.clone();
    let send_ref = send_initial_calls.clone();
    let _mock = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let reg_rx_ref = reg_rx_ref.clone();
        let reg_started_ref = reg_started_ref.clone();
        let send_ref = send_ref.clone();
        let bundle_a = bundle_a.clone();
        async move {
            if path.ends_with("/ClaimBundle") {
                Ok((200, bundle_a.encode_to_vec()))
            } else if path.ends_with("/RegisterWriteToken") {
                reg_started_ref.set(true);
                await_gate(&reg_rx_ref).await;
                Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
            } else if path.ends_with("/SendInitialV2") {
                send_ref.set(send_ref.get() + 1);
                Ok((200, SendInitialV2Response { id: 1 }.encode_to_vec()))
            } else {
                panic!("unexpected path: {path}");
            }
        }
    });

    let submission_id = engine.begin_new_chat_submit(PendingNewChat {
        key: key_to_text(&peer_a),
        name: "PeerA".into(),
        server: None,
        pq_pinned: false,
        allow_classical: false,
        auto_start: false,
    });
    let start_done = Rc::new(RefCell::new(None::<Result<PublicKey, StartChatError>>));
    let start_done_ref = start_done.clone();
    let eng_start = engine.clone();
    spawner
        .spawn_local(async move {
            *start_done_ref.borrow_mut() = Some(
                eng_start
                    .start_chat(
                        submission_id,
                        &key_to_text(&peer_a),
                        "PeerA".into(),
                        None,
                        false,
                        false,
                    )
                    .await,
            );
        })
        .unwrap();
    pool.run_until_stalled();
    assert!(reg_started.get());

    // Concurrently invoke `retry_pending_greetings()` while `start_chat` holds `peer_flush_lock`.
    let retry_done = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let retry_done_ref = retry_done.clone();
    let eng_retry = engine.clone();
    spawner
        .spawn_local(async move {
            *retry_done_ref.borrow_mut() = Some(eng_retry.retry_pending_greetings().await);
        })
        .unwrap();
    pool.run_until_stalled();
    assert_eq!(
        send_initial_calls.get(),
        0,
        "retry_pending_greetings must wait on peer_flush_lock and never transmit SendInitialV2 while start_chat is in flight"
    );

    reg_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*start_done.borrow(), Some(Ok(peer_a)));
    assert_eq!(*retry_done.borrow(), Some(Ok(false)));
    assert_eq!(
        send_initial_calls.get(),
        1,
        "SendInitialV2 must be sent exactly once"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r2_p2_1_in_flight_push_protects_head_from_requeue_sealed_and_recreate() {
    use futures::channel::oneshot;
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use protocol::mailbox_v2::PushV2Response;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    let (engine, peer) = pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contacts[0].state.conversation_gen = 1;
            inner.state.next_conversation_gen = 2;
            inner
                .add(&peer, Kind::Text("msg-0-in-flight".into()), false)
                .await
                .unwrap();
        }
        (engine, peer)
    });

    // 1. Suspend `PushV2` for msg 0; concurrently invoke REAL `rebuild_outbox` while `PushV2` is
    //    in flight -> msg 0 must stay sealed (protected by `in_flight_push`), and when `PushV2`
    //    returns 200 OK it commits `Step::Pushed` with zero duplicate push!
    let (push_tx, push_rx) = oneshot::channel::<()>();
    let push_rx = Rc::new(RefCell::new(Some(push_rx)));
    let push_calls = Rc::new(Cell::new(0usize));
    let push_rx_ref = push_rx.clone();
    let push_calls_ref = push_calls.clone();
    let _mock = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let push_rx_ref = push_rx_ref.clone();
        let push_calls_ref = push_calls_ref.clone();
        async move {
            assert!(path.ends_with("/PushV2"), "unexpected path: {path}");
            push_calls_ref.set(push_calls_ref.get() + 1);
            await_gate(&push_rx_ref).await;
            Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
        }
    });

    let done = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let done_ref = done.clone();
    let eng = engine.clone();
    spawner
        .spawn_local(async move {
            *done_ref.borrow_mut() = Some(eng.flush(&peer).await);
        })
        .unwrap();
    pool.run_until_stalled();
    assert_eq!(push_calls.get(), 1);

    // Run real `requeue_sealed` (`all_sealed = true`) concurrently while PushV2 is suspended.
    pool.run_until(async {
        let mut guard = engine.inner.lock().await;
        let inner = guard.as_mut().unwrap();
        assert!(inner.in_flight_push.contains_key(&peer));
        let outcome = inner.requeue_sealed(&peer).await.unwrap();
        assert!(
            outcome.outbox.is_empty(),
            "in-flight head must NOT be unsealed/deleted by concurrent rebuild_outbox"
        );
        assert!(
            inner.contacts[0].state.outbox[0].sealed,
            "in-flight head must remain sealed until PushV2 resolves"
        );
        assert!(
            inner.contacts[0].state.needs_requeue_sealed,
            "deferred in-flight head must keep needs_requeue_sealed armed"
        );
    });

    push_tx.send(()).unwrap();
    pool.run_until_stalled();
    assert_eq!(*done.borrow(), Some(Ok(true)));
    assert_eq!(push_calls.get(), 1);
    drop(_mock);

    // 2. Delete + recreate conversation (gen 2, same peer, same history_index 0 & clock 1) while
    //    gen 1's `PushV2` is suspended -> gen 1's 200 OK MUST NOT mark gen 2's head as Pushed!
    let (engine2, peer2) = pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contacts[0].state.conversation_gen = 1;
            inner.state.next_conversation_gen = 2;
            inner
                .add(&peer, Kind::Text("gen1-msg0".into()), false)
                .await
                .unwrap();
        }
        (engine, peer)
    });
    let (push2_tx, push2_rx) = oneshot::channel::<()>();
    let push2_rx = Rc::new(RefCell::new(Some(push2_rx)));
    let push2_started = Rc::new(Cell::new(false));
    let push2_rx_ref = push2_rx.clone();
    let push2_started_ref = push2_started.clone();
    let _mock2 = crate::transport::mock_fetch_async(move |_server, path, _body| {
        let push2_rx_ref = push2_rx_ref.clone();
        let push2_started_ref = push2_started_ref.clone();
        async move {
            assert!(path.ends_with("/PushV2"), "unexpected path: {path}");
            push2_started_ref.set(true);
            await_gate(&push2_rx_ref).await;
            Ok((200, PushV2Response { sequence: 9 }.encode_to_vec()))
        }
    });
    let done2 = Rc::new(RefCell::new(None::<Result<bool, String>>));
    let done2_ref = done2.clone();
    let eng2 = engine2.clone();
    spawner
        .spawn_local(async move {
            *done2_ref.borrow_mut() = Some(eng2.flush(&peer2).await);
        })
        .unwrap();
    pool.run_until_stalled();
    assert!(push2_started.get());

    // Simulate delete + recreate with gen 2 and a brand-new unsent message at (history_index 0, clock 1).
    pool.run_until(async {
        let mut guard = engine2.inner.lock().await;
        let inner = guard.as_mut().unwrap();
        inner.contacts[0].state.conversation_gen = 2;
        inner.contacts[0].state.outbox[0].sealed = false;
    });
    push2_tx.send(()).unwrap();
    pool.run_until_stalled();
    pool.run_until(async {
        let guard = engine2.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(
            inner.contacts[0].state.outbox.len(),
            1,
            "gen-1 PushV2 completion MUST NOT clear gen-2's outbox head"
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r2_p2_2_stale_version_retired_spk_reclaims_fresh_bundle_preserving_outbox() {
    use futures::executor::LocalPool;
    use protocol::handshake_v2::{ClaimBundleResponse, SendInitialV2Response};
    use protocol::mailbox_v2::RegisterWriteTokenResponse;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        let (engine, peer, mut bob) = established_engine_on_localhost().await;
        // Bob rotates to a fresh bundle that the client will claim on `StaleVersion`.
        let pub_fresh = bob.prepare_publish_v2("localhost", 2, 2).unwrap();
        let pf = &pub_fresh.request;
        let fresh_bundle = ClaimBundleResponse {
            signed_prekey: pf.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: pf.signed_prekey_signature.clone(),
            one_time_prekey: pf.one_time_prekeys.first().cloned(),
            pq_last_resort: pf.pq_last_resort.first().cloned(),
            pq_one_time_prekey: pf.pq_one_time_prekeys.first().cloned(),
            manifest: pf.manifest.clone(),
        };
        bob.commit_publish_v2(pub_fresh);

        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contacts[0].state.greeting_delivery = crate::vault::GREETING_DELIVERY_UNSENT;
            inner
                .add(
                    &peer,
                    Kind::Text("queued-across-spk-rotation".into()),
                    false,
                )
                .await
                .unwrap();
        }

        let send_attempts = Rc::new(Cell::new(0usize));
        let claim_calls = Rc::new(Cell::new(0usize));
        let send_ref = send_attempts.clone();
        let claim_ref = claim_calls.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_server, path, _body| {
                if path.ends_with("/SendInitialV2") {
                    let n = send_ref.get() + 1;
                    send_ref.set(n);
                    if n == 1 {
                        // First attempt hits retired SPK -> Connect Code::OutOfRange -> ErrorKind::StaleVersion.
                        Ok((
                            400,
                            br#"{"code":"out_of_range","message":"signed prekey retired"}"#
                                .to_vec(),
                        ))
                    } else {
                        Ok((200, SendInitialV2Response { id: 2 }.encode_to_vec()))
                    }
                } else if path.ends_with("/ClaimBundle") {
                    claim_ref.set(claim_ref.get() + 1);
                    Ok((200, fresh_bundle.encode_to_vec()))
                } else if path.ends_with("/RegisterWriteToken") {
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            assert!(engine.retry_pending_greetings().await.unwrap());
        }
        assert_eq!(
            send_attempts.get(),
            2,
            "must re-send greeting on fresh bundle"
        );
        assert_eq!(
            claim_calls.get(),
            1,
            "must claim fresh bundle after StaleVersion"
        );
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(
            inner.contacts[0].state.greeting_delivery,
            crate::vault::GREETING_DELIVERY_CONFIRMED
        );
        assert_eq!(
            inner.contacts[0].state.outbox.len(),
            1,
            "queued user message must be preserved across SPK reclaim"
        );
        assert!(
            !inner.contacts[0].state.outbox[0].sealed,
            "queued message must be unsealed for re-encryption on the fresh session"
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r2_p2_3_corrupt_outbox_history_entry_does_not_wedge_rebuild_outbox() {
    use futures::executor::LocalPool;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        let mut guard = engine.inner.lock().await;
        let inner = guard.as_mut().unwrap();
        inner
            .add(&peer, Kind::Text("corrupt-entry-0".into()), false)
            .await
            .unwrap();
        inner
            .add(&peer, Kind::Text("valid-entry-1".into()), false)
            .await
            .unwrap();
        // Mark both entries sealed so `requeue` invokes `rebuild_outbox` and reads `vault.entry`.
        for item in &mut inner.contacts[0].state.outbox {
            item.sealed = true;
            item.clock = item.history_index + 1;
        }
        // Inject `Error::Corrupt` on history index 0 ONLY.
        inner.vault.corrupt_read_at.set(Some(0));
        let _outcome = inner
            .requeue_sealed(&peer)
            .await
            .expect("corrupt single entry must be dropped, not wedge rebuild_outbox");
        assert_eq!(inner.contacts[0].state.outbox.len(), 1);
        assert_eq!(inner.contacts[0].state.outbox[0].history_index, 1);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r2_p2_5_and_r2_p3_2_pq_send_initial_unimplemented_and_greeting_uncertain_view() {
    use futures::executor::LocalPool;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        let mut guard = engine.inner.lock().await;
        let inner = guard.as_mut().unwrap();

        // R2-P2-5: PQ v2 `SendInitialV2` hitting `Unimplemented` flips `server_pq` to `Disabled`
        // and MUST NOT trigger `ui.update_required`!
        let unimpl_err = session::Error::from(protocol::Error::new(
            protocol::ErrorKind::Unimplemented,
            "post-quantum routes are disabled",
        ));
        assert!(!engine.check_send_initial_protocol_error(inner, true, &unimpl_err));
        assert_eq!(inner.server_pq, ServerPqStatus::Disabled);
        assert!(
            engine.ui.update_required.get_untracked().is_none(),
            "PQ SendInitialV2 Unimplemented must NOT set update_required"
        );

        // Classical v1 `SendInitialV2` hitting `Unimplemented` DOES set `update_required`.
        assert!(engine.check_send_initial_protocol_error(inner, false, &unimpl_err));
        assert!(engine.ui.update_required.get_untracked().is_some());

        // R2-P3-2: `ContactView.greeting_uncertain` distinguishes UNSENT vs UNCERTAIN.
        let contact = inner.contact(&peer).unwrap();
        contact.state.greeting_delivery = crate::vault::GREETING_DELIVERY_UNSENT;
        let unsent_view = contact.view();
        assert!(unsent_view.greeting_unsent);
        assert!(!unsent_view.greeting_uncertain);

        contact.state.greeting_delivery = crate::vault::GREETING_DELIVERY_UNCERTAIN;
        let uncertain_view = contact.view();
        assert!(!uncertain_view.greeting_unsent);
        assert!(uncertain_view.greeting_uncertain);
        assert!(!uncertain_view.awaiting_acceptance);
    });
}

#[test]
fn r2_p2_10_preserved_deferred_prekeys_scans_envelopes_and_isolated_contacts() {
    let (mut inner, _peer) = unlocked_client();
    let spk_env = [0x61; 32];
    let digest_env = [0x62; 32];
    let spk_iso = [0x71; 32];
    let digest_iso = [0x72; 32];

    let mk_wire = |spk: [u8; 32], digest: [u8; 32]| WireInitialMessageV2 {
        id: 0,
        version: 2,
        identity_key: Bytes::from_static(&[0x44; 32]),
        ephemeral_key: Bytes::from_static(&[0x55; 32]),
        signed_prekey: Bytes::copy_from_slice(&spk),
        first_message: Some(party::EncryptedMessage {
            header: Bytes::from_static(b"h"),
            content: Bytes::from_static(b"c"),
        }),
        pq_suite: PqSuite::MlKem1024.as_u8().into(),
        pq_prekey_id: Bytes::from_static(&[0x88; 32]),
        pq_ciphertext: Bytes::from(vec![0x88; PqSuite::MlKem1024.ct_len()]),
        manifest_digest: Bytes::copy_from_slice(&digest),
        ..WireInitialMessageV2::default()
    };

    // 1. `DeferredEnvelope` with `pq_isolated: true` carrying an initial message past 30 days.
    let wire_env = mk_wire(spk_env, digest_env);
    inner
        .deferred_envelopes
        .push(crate::vault::DeferredEnvelope {
            peer: vec![0x44; 32],
            sequence: 1,
            message: None,
            initial_message: Some(wire_env),
            deferred_at: 1_000,
            pq_isolated: true,
        });

    // 2. `isolated_contacts[*].pending_carried_initials`.
    let wire_iso = mk_wire(spk_iso, digest_iso);
    let mut iso_state = ContactState {
        peer: vec![0x45; 32],
        ..ContactState::default()
    };
    iso_state
        .pending_carried_initials
        .push(wire_iso.encode_to_vec());
    inner.isolated_contacts.push(iso_state);

    // Within 30d window: BOTH envelope and isolated contact SPKs/digests are preserved.
    let (spks, digests) = preserved_deferred_prekeys(&inner, 5_000);
    assert!(spks.contains(&spk_env));
    assert!(digests.contains(&digest_env));
    assert!(spks.contains(&spk_iso));
    assert!(digests.contains(&digest_iso));

    // Past 30d window: `pq_isolated: true` envelope SPK/digest STILL preserved!
    let (spks_old, digests_old) =
        preserved_deferred_prekeys(&inner, 1_000 + DEFERRED_REPLAY_WINDOW_MS + 60_000);
    assert!(spks_old.contains(&spk_env));
    assert!(digests_old.contains(&digest_env));
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "ml-kem-1024", feature = "ml-kem-768")
))]
#[test]
fn r3_p1_1_auto_upgrade_and_pq_config_retry_never_accept_recreated_request() {
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt as _;
    use protocol::handshake_v2::{ClaimBundleResponse, SendInitialV2Response};
    use protocol::mailbox_v2::RegisterWriteTokenResponse;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    pool.run_until(async {
        let (engine, peer, mut bob) = established_engine_on_localhost().await;
        let orig_gen = {
            let guard = engine.inner.lock().await;
            guard.as_ref().unwrap().contacts[0].state.conversation_gen
        };
        let bob_bundle = {
            let pub_req = bob
                .prepare_publish_v2("localhost", 2, 2)
                .expect("bob publish");
            let m = pub_req.request.manifest.clone().unwrap();
            let spk = m.signed_prekey.clone();
            let spk_sig = pub_req.request.signed_prekey_signature.clone();
            let pq_lr = pub_req.request.pq_last_resort.first().cloned();
            let pq_opk = pub_req.request.pq_one_time_prekeys.first().cloned();
            let opk = pub_req.request.one_time_prekeys.first().cloned();
            bob.commit_publish_v2(pub_req);
            ClaimBundleResponse {
                signed_prekey: spk,
                signed_prekey_signature: spk_sig,
                one_time_prekey: opk,
                manifest: Some(m),
                pq_last_resort: pq_lr,
                pq_one_time_prekey: pq_opk,
            }
        };

        // Part 1: Queued automatic upgrade pinned to `orig_gen` must refuse to accept a recreated
        // inbound request (even before `ClaimBundle` is ever issued).
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let contact = inner.contact(&peer).unwrap();
            contact.state.conversation_gen = orig_gen + 1;
            contact.state.request = true;
            contact.session.clear_pending_grants();
        }
        let claim_calls = Rc::new(Cell::new(0usize));
        let claim_cnt = claim_calls.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                claim_cnt.set(claim_cnt.get() + 1);
                panic!("auto-upgrade must abort before network on stale gen: {path}");
            });
            let err = engine.upgrade_to_pq_auto(peer, orig_gen).await.unwrap_err();
            assert!(err.contains("chat changed"), "{err}");
            assert_eq!(claim_calls.get(), 0);
        }
        {
            let guard = engine.inner.lock().await;
            let c = guard
                .as_ref()
                .unwrap()
                .contacts
                .iter()
                .find(|c| c.peer == peer)
                .unwrap();
            assert!(c.state.request);
            assert!(c.session.pending_register_grants().is_empty());
        }

        // Part 2: Manual `upgrade_to_pq` suspended in `ClaimBundle` while BOTH `pq_config` AND
        // conversation incarnation change (chat deleted & recreated as inbound request) MUST abort
        // instead of continuing the `pq_config` retry loop and adopting the new request!
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let contact = inner.contact(&peer).unwrap();
            contact.state.request = false;
            contact.state.conversation_gen = orig_gen + 2;
        }
        let (tx, rx) = futures::channel::oneshot::channel::<()>();
        let rx_cell = Rc::new(RefCell::new(Some(rx)));
        let (entered_tx, entered_rx) = futures::channel::oneshot::channel::<()>();
        let entered_cell = Rc::new(RefCell::new(Some(entered_tx)));
        let bundle_clone = bob_bundle.clone();
        let _mock = crate::transport::mock_fetch_async(move |_s, path, _b| {
            let rx_cell = rx_cell.clone();
            let entered_cell = entered_cell.clone();
            let bundle = bundle_clone.clone();
            async move {
                if path.ends_with("/ClaimBundle") {
                    if let Some(etx) = entered_cell.borrow_mut().take() {
                        let _ = etx.send(());
                    }
                    let rx = rx_cell.borrow_mut().take();
                    if let Some(rx) = rx {
                        let _ = rx.await;
                    }
                    Ok((200, bundle.encode_to_vec()))
                } else if path.ends_with("/RegisterWriteToken") {
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else if path.ends_with("/SendInitialV2") {
                    Ok((200, SendInitialV2Response { id: 1 }.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            }
        });

        let eng_up = engine.clone();
        let (done_tx, done_rx) = futures::channel::oneshot::channel::<Result<(), String>>();
        spawner
            .spawn_local(async move {
                let _ = done_tx.send(eng_up.upgrade_to_pq(peer).await);
            })
            .unwrap();
        let _ = entered_rx.await;

        // Mutate BOTH `pq_config` (toggle `pq_ratchet_enabled`) AND recreate chat as inbound request.
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let mut new_cfg = inner.client.pq_config().clone();
            new_cfg.pq_ratchet_enabled = !new_cfg.pq_ratchet_enabled;
            inner.client.set_pq_config(new_cfg).unwrap();
            let contact = inner.contact(&peer).unwrap();
            contact.state.conversation_gen = orig_gen + 3;
            contact.state.request = true;
            contact.session.clear_pending_grants();
        }
        let _ = tx.send(());
        let err = done_rx.await.unwrap().unwrap_err();
        assert!(err.contains("chat changed"), "{err}");
        let guard = engine.inner.lock().await;
        let c = guard
            .as_ref()
            .unwrap()
            .contacts
            .iter()
            .find(|c| c.peer == peer)
            .unwrap();
        assert!(
            c.state.request,
            "pq_config retry must NEVER adopt and accept recreated inbound request"
        );
        assert!(c.session.pending_register_grants().is_empty());
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r3_p1_2_transient_list_initial_failure_preserves_buffered_envelope() {
    use super::contact::Contact;
    use futures::executor::LocalPool;
    use protocol::handshake_v2::{AckInitialMessagesResponse, ListInitialMessagesResponse};
    use protocol::mailbox_v2::{
        AckMessagesResponse, EnvelopeV2, FetchSignedResponse, RegisterWriteTokenResponse,
    };
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        let (mut inner, alice_peer) = unlocked_client();
        let me = inner.client.identity_key();
        let alice = Client::new(Fetch::client("https://chat.example"));
        let bob_pub = inner
            .client
            .prepare_publish_v2("chat.example", 4, 4)
            .unwrap();
        let bob_manifest = bob_pub.request.manifest.clone().unwrap();
        let bob_bundle = protocol::handshake_v2::ClaimBundleResponse {
            signed_prekey: bob_manifest.signed_prekey.clone(),
            signed_prekey_signature: bob_pub.request.signed_prekey_signature.clone(),
            one_time_prekey: bob_pub.request.one_time_prekeys.first().cloned(),
            manifest: Some(bob_manifest.clone()),
            pq_last_resort: bob_pub.request.pq_last_resort.first().cloned(),
            pq_one_time_prekey: bob_pub.request.pq_one_time_prekeys.first().cloned(),
        };
        inner.client.commit_publish_v2(bob_pub);

        // Establish initial session S1 between Alice and Bob.
        let mut alice_s1 = {
            let claimed = {
                let _mock = crate::transport::mock_fetch({
                    let bundle = bob_bundle.clone();
                    move |_s, path, _b| {
                        assert!(path.ends_with("/ClaimBundle"), "{path}");
                        Ok((200, bundle.encode_to_vec()))
                    }
                });
                session::claim_peer_bundle_v2(
                    &Fetch::client("https://chat.example"),
                    "chat.example",
                    &me,
                    &session::PeerPqState::default(),
                    alice.pq_config(),
                    alice.clock(),
                )
                .await
                .unwrap()
            };
            let hello1 = Kind::Hello(alice.make_hello("Alice", 1)).to_bytes();
            let prep = alice
                .finish_prepare_initiate_v2(
                    claimed,
                    &session::PeerPqState::default(),
                    &hello1,
                    Fetch::client("https://chat.example"),
                )
                .unwrap();
            let wire = prep.request.message.unwrap();
            let inc = super::handshake::Incoming::try_from(&wire).unwrap();
            let AcceptedInitial::Accepted {
                session: bob_s1, ..
            } = inner
                .client
                .accept_initial_v2(
                    &alice.identity_key(),
                    &session::PeerPqState::default(),
                    &inc,
                    Fetch::client("https://chat.example"),
                )
                .unwrap()
            else {
                panic!("expected accepted S1");
            };
            let token_hash_s1 = bob_s1.active_inbound_token_hash().unwrap();
            inner.contacts.retain(|c| c.peer != alice_peer);
            inner.contacts.push(Contact {
                peer: alice.identity_key(),
                session: bob_s1,
                deferred_carried: 0,
                state: ContactState {
                    peer: alice.identity_key().to_vec(),
                    conversation_gen: 1,
                    ..ContactState::default()
                },
            });
            let _ = token_hash_s1;
            prep.session
        };
        let alice_id = alice.identity_key();
        let s1_inbound_hash = inner
            .contacts
            .iter()
            .find(|c| c.peer == alice_id)
            .unwrap()
            .session
            .active_inbound_token_hash()
            .unwrap();

        // Now Alice rekeys to S2 (inbox initial NOT delivered to Bob yet) and pushes ciphertext on S2
        // routed under S1's token hash (simulating rekeyed ciphertext arriving before inbox initial).
        let bob_bundle2 = protocol::handshake_v2::ClaimBundleResponse {
            one_time_prekey: None,
            pq_one_time_prekey: None,
            ..bob_bundle
        };
        let s2_wire = {
            let claimed2 = {
                let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                    assert!(path.ends_with("/ClaimBundle"), "{path}");
                    Ok((200, bob_bundle2.encode_to_vec()))
                });
                session::claim_peer_bundle_v2(
                    &Fetch::client("https://chat.example"),
                    "chat.example",
                    &me,
                    alice_s1.peer_pq_state(),
                    alice.pq_config(),
                    alice.clock(),
                )
                .await
                .unwrap()
            };
            let hello2 = Kind::Hello(alice.make_hello("Alice", 2)).to_bytes();
            let req2 = alice
                .finish_prepare_start_again_v2(claimed2, &mut alice_s1, &hello2)
                .unwrap();
            let mut w = req2.message.unwrap();
            w.id = 77;
            w
        };
        let mut body = Kind::Text("precious rekeyed message".into()).to_bytes();
        crate::content::stamp(&mut body, 2);
        let sealed_s2 = alice_s1.encrypt(&body).unwrap();

        let engine = Engine::with_inner(Ui::new(), inner);

        // Pass 1: `receive_mailbox` fetches the rekeyed ciphertext, ACKs the mailbox, and hits a
        // transient 503 on `/ListInitialMessages`. The buffered envelope MUST NOT be dropped!
        let fetched = Rc::new(Cell::new(false));
        let fetched_ref = fetched.clone();
        let sealed_msg = sealed_s2.message.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                if path.ends_with("/FetchSigned") {
                    if !fetched_ref.replace(true) {
                        Ok((
                            200,
                            FetchSignedResponse {
                                messages: vec![EnvelopeV2 {
                                    sequence: 1,
                                    token_hash: Bytes::copy_from_slice(&s1_inbound_hash),
                                    message: Some(sealed_msg.clone()),
                                    initial_message: None,
                                }],
                                has_more: false,
                            }
                            .encode_to_vec(),
                        ))
                    } else {
                        Ok((200, FetchSignedResponse::default().encode_to_vec()))
                    }
                } else if path.ends_with("/AckMessages") {
                    Ok((200, AckMessagesResponse { deleted: 1 }.encode_to_vec()))
                } else if path.ends_with("/ListInitialMessages") {
                    Ok((503, b"transient inbox outage".to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            engine.receive_mailbox().await.unwrap();
        }
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert_eq!(
                inner.deferred_envelopes.len(),
                1,
                "transient ListInitialMessages failure must preserve buffered rekeyed envelope"
            );
        }

        // Next sync's `recover_local_changes` (runs BEFORE `take_initial_messages`) must ALSO
        // preserve the buffered envelope!
        assert!(!engine.recover_local_changes().await.unwrap());
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert_eq!(
                inner.deferred_envelopes.len(),
                1,
                "recover_local_changes must preserve undecryptable envelopes awaiting inbox pull"
            );
        }

        // Pass 2: `/ListInitialMessages` recovers with S2's initial -> Bob accepts S2 and
        // immediately replays & decrypts `"precious rekeyed message"`!
        let listed = Rc::new(Cell::new(false));
        let listed_ref = listed.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                if path.ends_with("/ListInitialMessages") {
                    if !listed_ref.replace(true) {
                        Ok((
                            200,
                            ListInitialMessagesResponse {
                                messages: vec![s2_wire.clone()],
                                has_more: false,
                            }
                            .encode_to_vec(),
                        ))
                    } else {
                        Ok((200, ListInitialMessagesResponse::default().encode_to_vec()))
                    }
                } else if path.ends_with("/RegisterWriteToken") {
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else if path.ends_with("/AckInitialMessages") {
                    Ok((
                        200,
                        AckInitialMessagesResponse { deleted: 1 }.encode_to_vec(),
                    ))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            let (progress, replayed, _) =
                engine.take_initial_messages_with_replayed().await.unwrap();
            assert!(progress);
            assert!(replayed.contains(&alice_id));
        }
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert!(inner.deferred_envelopes.is_empty());
        let texts: Vec<String> = inner
            .vault
            .entries
            .borrow()
            .values()
            .filter_map(|e| match e.content.as_ref()?.kind.as_ref()? {
                Kind::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect();
        assert!(
            texts.contains(&"precious rekeyed message".to_string()),
            "{texts:?}"
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r3_p1_3_corrupt_receipt_history_entry_does_not_block_healthy_peer_mailbox_page() {
    use super::contact::Contact;
    use futures::executor::LocalPool;
    use protocol::mailbox_v2::{AckMessagesResponse, EnvelopeV2, FetchSignedResponse};
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        let (mut inner, old_peer) = unlocked_client();
        inner.contacts.retain(|c| c.peer != old_peer);
        let me = inner.client.identity_key();
        let my_pub = inner
            .client
            .prepare_publish_v2("chat.example", 4, 4)
            .unwrap();
        let my_manifest = my_pub.request.manifest.clone().unwrap();
        let make_bundle = |idx: usize| protocol::handshake_v2::ClaimBundleResponse {
            signed_prekey: my_manifest.signed_prekey.clone(),
            signed_prekey_signature: my_pub.request.signed_prekey_signature.clone(),
            one_time_prekey: my_pub.request.one_time_prekeys.get(idx).cloned(),
            manifest: Some(my_manifest.clone()),
            pq_last_resort: my_pub.request.pq_last_resort.first().cloned(),
            pq_one_time_prekey: my_pub.request.pq_one_time_prekeys.get(idx).cloned(),
        };
        let bundle_a = make_bundle(0);
        let bundle_b = make_bundle(1);
        inner.client.commit_publish_v2(my_pub);

        let (peer_a, mut session_a, hash_a, peer_b, mut session_b, hash_b) = {
            let mut out = Vec::new();
            for (bundle, name) in [(bundle_a, "PeerA"), (bundle_b, "PeerB")] {
                let peer_client = Client::new(Fetch::client("https://chat.example"));
                let peer_id = peer_client.identity_key();
                let claimed = {
                    let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                        assert!(path.ends_with("/ClaimBundle"), "{path}");
                        Ok((200, bundle.encode_to_vec()))
                    });
                    session::claim_peer_bundle_v2(
                        &Fetch::client("https://chat.example"),
                        "chat.example",
                        &me,
                        &session::PeerPqState::default(),
                        peer_client.pq_config(),
                        peer_client.clock(),
                    )
                    .await
                    .unwrap()
                };
                let hello = Kind::Hello(peer_client.make_hello(name, 1)).to_bytes();
                let prep = peer_client
                    .finish_prepare_initiate_v2(
                        claimed,
                        &session::PeerPqState::default(),
                        &hello,
                        Fetch::client("https://chat.example"),
                    )
                    .unwrap();
                let inc = Incoming::try_from(&prep.request.message.unwrap()).unwrap();
                let AcceptedInitial::Accepted {
                    session: my_session,
                    ..
                } = inner
                    .client
                    .accept_initial_v2(
                        &peer_id,
                        &session::PeerPqState::default(),
                        &inc,
                        Fetch::client("https://chat.example"),
                    )
                    .unwrap()
                else {
                    panic!("expected accepted session");
                };
                let hash = my_session.active_inbound_token_hash().unwrap();
                inner.contacts.push(Contact {
                    peer: peer_id,
                    session: my_session,
                    deferred_carried: 0,
                    state: ContactState {
                        peer: peer_id.to_vec(),
                        conversation_gen: 1,
                        ..ContactState::default()
                    },
                });
                out.push((peer_id, prep.session, hash));
            }
            let mut it = out.into_iter();
            let (pa, sa, ha) = it.next().unwrap();
            let (pb, sb, hb) = it.next().unwrap();
            (pa, sa, ha, pb, sb, hb)
        };

        // Give Peer A an awaiting outgoing entry at index 0 (place 1), then corrupt index 0!
        inner
            .contact(&peer_a)
            .unwrap()
            .state
            .awaiting
            .push(crate::vault::Awaiting {
                place: 1,
                history_index: 0,
                read: false,
                attachment: false,
                content_digest: vec![0; 32],
            });
        inner.vault.corrupt_read_at.set(Some(0));

        // Peer A sends a read receipt targeting place 1 (corrupt index 0); Peer B sends a normal msg.
        let receipt_content = crate::content::Content {
            clock: 2,
            events: Some(crate::content::Events {
                read: vec![1],
                ..Default::default()
            }),
            kind: None,
        };
        let mut receipt_bytes = Vec::new();
        prost::Message::encode(&receipt_content, &mut receipt_bytes).unwrap();
        let sealed_a = session_a.encrypt(&receipt_bytes).unwrap();

        let mut body_b = Kind::Text("healthy peer B survives corrupt receipt".into()).to_bytes();
        crate::content::stamp(&mut body_b, 1);
        let sealed_b = session_b.encrypt(&body_b).unwrap();

        let engine = Engine::with_inner(Ui::new(), inner);
        let acked_seq = Rc::new(Cell::new(0u64));
        let acked_ref = acked_seq.clone();
        let delivered = Rc::new(Cell::new(false));
        let delivered_ref = delivered.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_s, path, body| {
                if path.ends_with("/FetchSigned") {
                    if !delivered_ref.replace(true) {
                        Ok((
                            200,
                            FetchSignedResponse {
                                messages: vec![
                                    EnvelopeV2 {
                                        sequence: 10,
                                        token_hash: Bytes::copy_from_slice(&hash_a),
                                        message: Some(sealed_a.message.clone()),
                                        initial_message: None,
                                    },
                                    EnvelopeV2 {
                                        sequence: 11,
                                        token_hash: Bytes::copy_from_slice(&hash_b),
                                        message: Some(sealed_b.message.clone()),
                                        initial_message: None,
                                    },
                                ],
                                has_more: false,
                            }
                            .encode_to_vec(),
                        ))
                    } else {
                        Ok((200, FetchSignedResponse::default().encode_to_vec()))
                    }
                } else if path.ends_with("/AckMessages") {
                    let req =
                        protocol::mailbox_v2::AckMessagesRequest::decode(body.as_slice()).unwrap();
                    acked_ref.set(req.up_to_sequence);
                    Ok((200, AckMessagesResponse { deleted: 2 }.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            let affected = engine.receive_mailbox().await.unwrap();
            assert!(affected.contains(&peer_b));
        }
        assert_eq!(acked_seq.get(), 11);
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert_eq!(inner.client.mailbox_cursor(), 11);
        assert_eq!(
            inner.vault.entries.borrow()[&(peer_b, 0)]
                .content
                .as_ref()
                .and_then(|c| c.kind.as_ref()),
            Some(&Kind::Text(
                "healthy peer B survives corrupt receipt".into()
            ))
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r3_p1_4_confirmed_greeting_reclaims_after_spk_rotation_for_queued_and_empty_outbox() {
    use futures::executor::LocalPool;
    use protocol::handshake_v2::{ClaimBundleResponse, GetManifestResponse, SendInitialV2Response};
    use protocol::mailbox_v2::RegisterWriteTokenResponse;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        // Subcase 1: Queued outbox + CONFIRMED greeting -> PushV2 hits WriteTokenRejected ->
        // GetManifest shows SPK rotated 2+ generations past target -> SendInitialV2 returns
        // StaleVersion -> reclaims fresh bundle!
        let (engine, bob_peer, mut bob) = established_engine_on_localhost().await;
        // Advance Bob through 2 SPK rotations (gen 1 -> gen 2 -> gen 3) so target gen 1 is evicted.
        let rot1 = bob.prepare_publish_v2("localhost", 2, 2).unwrap();
        bob.commit_publish_v2(rot1);
        let fresh_pub = bob.prepare_publish_v2("localhost", 2, 2).unwrap();
        let fresh_manifest = fresh_pub.request.manifest.clone().unwrap();
        let fresh_bundle = ClaimBundleResponse {
            signed_prekey: fresh_manifest.signed_prekey.clone(),
            signed_prekey_signature: fresh_pub.request.signed_prekey_signature.clone(),
            one_time_prekey: fresh_pub.request.one_time_prekeys.first().cloned(),
            manifest: Some(fresh_manifest.clone()),
            pq_last_resort: fresh_pub.request.pq_last_resort.first().cloned(),
            pq_one_time_prekey: fresh_pub.request.pq_one_time_prekeys.first().cloned(),
        };
        bob.commit_publish_v2(fresh_pub);

        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let c = inner.contact(&bob_peer).unwrap();
            c.state.greeting_delivery = crate::vault::GREETING_DELIVERY_CONFIRMED;
            c.state.greeting_target_generation = 1;
            c.state.greeting_sent_at = crate::util::now();
            c.state.greeting_delivery_verified = false;
            inner
                .add(
                    &bob_peer,
                    Kind::Text("hello after spk eviction".into()),
                    false,
                )
                .await
                .unwrap();
        }
        let claim_calls = Rc::new(Cell::new(0usize));
        let send_calls = Rc::new(Cell::new(0usize));
        let push_calls = Rc::new(Cell::new(0usize));
        {
            let claim_ref = claim_calls.clone();
            let send_ref = send_calls.clone();
            let push_ref = push_calls.clone();
            let manifest_resp = fresh_manifest.clone();
            let bundle_resp = fresh_bundle.clone();
            let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                if path.ends_with("/PushV2") {
                    let n = push_ref.get() + 1;
                    push_ref.set(n);
                    if n == 1 {
                        let err = protocol::connect::error(
                            protocol::ErrorKind::WriteTokenRejected,
                            "write token rejected",
                        );
                        Ok((err.status, err.body))
                    } else {
                        Ok((
                            200,
                            protocol::mailbox_v2::PushV2Response { sequence: 1 }.encode_to_vec(),
                        ))
                    }
                } else if path.ends_with("/GetManifest") {
                    Ok((
                        200,
                        GetManifestResponse {
                            manifest: Some(manifest_resp.clone()),
                        }
                        .encode_to_vec(),
                    ))
                } else if path.ends_with("/SendInitialV2") {
                    let n = send_ref.get() + 1;
                    send_ref.set(n);
                    if n == 1 {
                        Ok((
                            400,
                            br#"{"code":"out_of_range","message":"signed prekey retired"}"#
                                .to_vec(),
                        ))
                    } else {
                        Ok((200, SendInitialV2Response { id: 2 }.encode_to_vec()))
                    }
                } else if path.ends_with("/ClaimBundle") {
                    claim_ref.set(claim_ref.get() + 1);
                    Ok((200, bundle_resp.encode_to_vec()))
                } else if path.ends_with("/RegisterWriteToken") {
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            assert_eq!(engine.flush(&bob_peer).await, Ok(true));
        }
        assert_eq!(claim_calls.get(), 1);
        assert_eq!(send_calls.get(), 2);
        assert_eq!(push_calls.get(), 2);

        // Subcase 2: Empty outbox + CONFIRMED greeting -> retry_pending_greetings probes
        // GetManifest -> detects SPK rotated 2+ generations -> probes SendInitialV2 -> gets
        // StaleVersion -> reclaims fresh bundle cleanly!
        let (engine2, bob_peer2, mut bob2) = established_engine_on_localhost().await;
        let rot2 = bob2.prepare_publish_v2("localhost", 2, 2).unwrap();
        bob2.commit_publish_v2(rot2);
        let fresh_pub2 = bob2.prepare_publish_v2("localhost", 2, 2).unwrap();
        let fresh_manifest2 = fresh_pub2.request.manifest.clone().unwrap();
        let fresh_bundle2 = ClaimBundleResponse {
            signed_prekey: fresh_manifest2.signed_prekey.clone(),
            signed_prekey_signature: fresh_pub2.request.signed_prekey_signature.clone(),
            one_time_prekey: fresh_pub2.request.one_time_prekeys.first().cloned(),
            manifest: Some(fresh_manifest2.clone()),
            pq_last_resort: fresh_pub2.request.pq_last_resort.first().cloned(),
            pq_one_time_prekey: fresh_pub2.request.pq_one_time_prekeys.first().cloned(),
        };
        bob2.commit_publish_v2(fresh_pub2);
        {
            let mut guard = engine2.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let c = inner.contact(&bob_peer2).unwrap();
            c.state.greeting_delivery = crate::vault::GREETING_DELIVERY_CONFIRMED;
            c.state.greeting_target_generation = 1;
            c.state.greeting_sent_at = crate::util::now();
            c.state.greeting_delivery_verified = false;
            assert!(c.state.outbox.is_empty());
        }
        let claim2 = Rc::new(Cell::new(0usize));
        let send2 = Rc::new(Cell::new(0usize));
        {
            let claim_ref = claim2.clone();
            let send_ref = send2.clone();
            let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                if path.ends_with("/GetManifest") {
                    Ok((
                        200,
                        GetManifestResponse {
                            manifest: Some(fresh_manifest2.clone()),
                        }
                        .encode_to_vec(),
                    ))
                } else if path.ends_with("/SendInitialV2") {
                    let n = send_ref.get() + 1;
                    send_ref.set(n);
                    if n == 1 {
                        Ok((
                            400,
                            br#"{"code":"out_of_range","message":"signed prekey retired"}"#
                                .to_vec(),
                        ))
                    } else {
                        Ok((200, SendInitialV2Response { id: 3 }.encode_to_vec()))
                    }
                } else if path.ends_with("/ClaimBundle") {
                    claim_ref.set(claim_ref.get() + 1);
                    Ok((200, fresh_bundle2.encode_to_vec()))
                } else if path.ends_with("/RegisterWriteToken") {
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            assert_eq!(engine2.retry_pending_greetings().await, Ok(true));
        }
        assert_eq!(claim2.get(), 1);
        assert_eq!(send2.get(), 2);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r3_p2_1_inbox_lock_serializes_concurrent_take_initial_messages() {
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt as _;
    use protocol::handshake_v2::ListInitialMessagesResponse;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    pool.run_until(async {
        let (inner, _) = unlocked_client();
        let engine = Engine::with_inner(Ui::new(), inner);

        let in_flight = Rc::new(Cell::new(0usize));
        let max_concurrent = Rc::new(Cell::new(0usize));
        let (tx, rx) = futures::channel::oneshot::channel::<()>();
        let rx_cell = Rc::new(RefCell::new(Some(rx)));
        let (entered_tx, entered_rx) = futures::channel::oneshot::channel::<()>();
        let entered_cell = Rc::new(RefCell::new(Some(entered_tx)));
        let in_flight_ref = in_flight.clone();
        let max_ref = max_concurrent.clone();
        let _mock = crate::transport::mock_fetch_async(move |_s, path, _b| {
            let in_flight = in_flight_ref.clone();
            let max_c = max_ref.clone();
            let rx_cell = rx_cell.clone();
            let entered_cell = entered_cell.clone();
            async move {
                assert!(path.ends_with("/ListInitialMessages"), "{path}");
                let cur = in_flight.get() + 1;
                in_flight.set(cur);
                max_c.set(max_c.get().max(cur));
                if let Some(etx) = entered_cell.borrow_mut().take() {
                    let _ = etx.send(());
                }
                let rx = rx_cell.borrow_mut().take();
                if let Some(rx) = rx {
                    let _ = rx.await;
                }
                in_flight.set(in_flight.get() - 1);
                Ok((200, ListInitialMessagesResponse::default().encode_to_vec()))
            }
        });

        let (done1_tx, done1_rx) = futures::channel::oneshot::channel::<()>();
        let (done2_tx, done2_rx) = futures::channel::oneshot::channel::<()>();
        let e1 = engine.clone();
        spawner
            .spawn_local(async move {
                e1.take_initial_messages().await.unwrap();
                let _ = done1_tx.send(());
            })
            .unwrap();
        let _ = entered_rx.await;

        let e2 = engine.clone();
        spawner
            .spawn_local(async move {
                e2.take_initial_messages().await.unwrap();
                let _ = done2_tx.send(());
            })
            .unwrap();
        // Yield to the LocalPool so Task 2 runs up to `inbox_lock.lock().await`.
        for _ in 0..4 {
            let mut yielded = false;
            futures_util::future::poll_fn(|cx| {
                if yielded {
                    std::task::Poll::Ready(())
                } else {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            })
            .await;
        }
        assert_eq!(
            in_flight.get(),
            1,
            "second take_initial_messages must block on inbox_lock while first is in flight"
        );
        let _ = tx.send(());
        let _ = done1_rx.await;
        let _ = done2_rx.await;
        assert_eq!(max_concurrent.get(), 1);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r3_p2_2_flush_pending_grants_stale_version_atomic_restage_and_concurrent_guard() {
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt as _;
    use protocol::mailbox_v2::RegisterWriteTokenResponse;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        let active_hash = {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let h = inner
                .contact(&peer)
                .unwrap()
                .session
                .active_inbound_token_hash()
                .unwrap();
            inner.contact(&peer).unwrap().session.clear_pending_grants();
            inner.stage_write_token_grant(&peer, h, true).unwrap();
            h
        };

        // Part 1: Concurrent flush #1 confirms `(active_hash, v1)`, while concurrent flush #2
        // receives a stale `StaleVersion` for `(active_hash, v1)` -> flush #2 MUST NOT re-stage
        // the already-confirmed active grant!
        let (tx, rx) = futures::channel::oneshot::channel::<()>();
        let rx_cell = Rc::new(RefCell::new(Some(rx)));
        let (entered_tx, entered_rx) = futures::channel::oneshot::channel::<()>();
        let entered_cell = Rc::new(RefCell::new(Some(entered_tx)));
        let call_n = Rc::new(Cell::new(0usize));
        let call_n_ref = call_n.clone();
        {
            let _mock = crate::transport::mock_fetch_async(move |_s, path, _b| {
                let n = call_n_ref.get() + 1;
                call_n_ref.set(n);
                let rx_cell = rx_cell.clone();
                let entered_cell = entered_cell.clone();
                async move {
                    assert!(path.ends_with("/RegisterWriteToken"), "{path}");
                    if n == 1 {
                        if let Some(etx) = entered_cell.borrow_mut().take() {
                            let _ = etx.send(());
                        }
                        let rx = rx_cell.borrow_mut().take();
                        if let Some(rx) = rx {
                            let _ = rx.await;
                        }
                        let err = protocol::connect::error(
                            protocol::ErrorKind::StaleVersion,
                            "delayed stale version",
                        );
                        Ok((err.status, err.body))
                    } else {
                        Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                    }
                }
            });

            let (done1_tx, done1_rx) = futures::channel::oneshot::channel::<()>();
            let e1 = engine.clone();
            spawner
                .spawn_local(async move {
                    let _ = e1.flush_pending_grants_for_peer(&peer).await;
                    let _ = done1_tx.send(());
                })
                .unwrap();
            let _ = entered_rx.await;

            // Flush #2 succeeds and clears the active grant.
            engine.flush_pending_grants_for_peer(&peer).await.unwrap();
            assert!(
                !engine.inner.lock().await.as_ref().unwrap().contacts[0]
                    .session
                    .has_pending_active_grant()
            );

            // Now let stale Flush #1 resume with StaleVersion -> must NOT re-stage!
            let _ = tx.send(());
            let _ = done1_rx.await;
            assert!(
                !engine.inner.lock().await.as_ref().unwrap().contacts[0]
                    .session
                    .has_pending_active_grant(),
                "stale concurrent StaleVersion must not re-stage an already-confirmed active grant"
            );
        }

        // Part 2: When grant version allocation fails (`next_grant_version` exhausted), StaleVersion
        // MUST preserve the old pending grant as a send gate (never ungating sends).
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .stage_write_token_grant(&peer, active_hash, true)
                .unwrap();
            let mut proto_client = session::proto::ClientState::from(inner.client.state());
            proto_client.next_grant_version = session::protocol::MAX_SAFE_INTEGER;
            inner.client = session::Client::restore(
                Fetch::client(&inner.server),
                session::ClientState::try_from(&proto_client).unwrap(),
            );
        }
        {
            let _mock = crate::transport::mock_fetch(|_s, path, _b| {
                assert!(path.ends_with("/RegisterWriteToken"), "{path}");
                let err = protocol::connect::error(protocol::ErrorKind::StaleVersion, "stale");
                Ok((err.status, err.body))
            });
            assert!(engine.flush_pending_grants_for_peer(&peer).await.is_err());
        }
        assert!(
            engine.inner.lock().await.as_ref().unwrap().contacts[0]
                .session
                .has_pending_active_grant(),
            "failed grant re-stage must keep old pending active grant as durable send gate"
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r3_p2_3_late_greeting_retry_never_retires_working_session_or_marks_recreated_chat() {
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt as _;
    use protocol::handshake_v2::SendInitialV2Response;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    pool.run_until(async {
        // Part 1: `retry_pending_greetings` suspended in `SendInitialV2` -> inbound reply marks
        // `known_by_peer = true` -> late `StaleVersion` MUST NOT retire the working session!
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contact(&peer).unwrap().state.greeting_delivery =
                crate::vault::GREETING_DELIVERY_UNSENT;
        }
        let (tx, rx) = futures::channel::oneshot::channel::<()>();
        let rx_cell = Rc::new(RefCell::new(Some(rx)));
        let (entered_tx, entered_rx) = futures::channel::oneshot::channel::<()>();
        let entered_cell = Rc::new(RefCell::new(Some(entered_tx)));
        {
            let _mock = crate::transport::mock_fetch_async(move |_s, path, _b| {
                let rx_cell = rx_cell.clone();
                let entered_cell = entered_cell.clone();
                async move {
                    assert!(path.ends_with("/SendInitialV2"), "{path}");
                    if let Some(etx) = entered_cell.borrow_mut().take() {
                        let _ = etx.send(());
                    }
                    let rx = rx_cell.borrow_mut().take();
                    if let Some(rx) = rx {
                        let _ = rx.await;
                    }
                    Ok((
                        400,
                        br#"{"code":"out_of_range","message":"signed prekey retired"}"#.to_vec(),
                    ))
                }
            });
            let (done_tx, done_rx) = futures::channel::oneshot::channel::<()>();
            let e1 = engine.clone();
            spawner
                .spawn_local(async move {
                    let _ = e1.retry_pending_greetings().await;
                    let _ = done_tx.send(());
                })
                .unwrap();
            let _ = entered_rx.await;
            {
                let mut guard = engine.inner.lock().await;
                let inner = guard.as_mut().unwrap();
                change_session(&mut inner.contact(&peer).unwrap().session, |s| {
                    s.known_by_peer = true;
                });
            }
            let _ = tx.send(());
            let _ = done_rx.await;
        }
        assert!(
            !engine.inner.lock().await.as_ref().unwrap().contacts[0]
                .session
                .needs_new_session(),
            "late StaleVersion must NOT retire a session after known_by_peer became true"
        );

        // Part 2: `flush` WriteTokenRejected -> `SendInitialV2` retry suspended -> conversation
        // recreated with new `conversation_gen` -> `Ok(())` MUST NOT mark replacement chat
        // `awaiting_peer_acceptance = true`!
        let (engine2, peer2, _bob2) = established_engine_on_localhost().await;
        {
            let mut guard = engine2.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contact(&peer2).unwrap().state.greeting_delivery =
                crate::vault::GREETING_DELIVERY_UNCERTAIN;
            inner
                .add(&peer2, Kind::Text("msg".into()), false)
                .await
                .unwrap();
        }
        let (tx2, rx2) = futures::channel::oneshot::channel::<()>();
        let rx2_cell = Rc::new(RefCell::new(Some(rx2)));
        let (entered2_tx, entered2_rx) = futures::channel::oneshot::channel::<()>();
        let entered2_cell = Rc::new(RefCell::new(Some(entered2_tx)));
        {
            let _mock = crate::transport::mock_fetch_async(move |_s, path, _b| {
                let rx2_cell = rx2_cell.clone();
                let entered2_cell = entered2_cell.clone();
                async move {
                    if path.ends_with("/PushV2") {
                        let err = protocol::connect::error(
                            protocol::ErrorKind::WriteTokenRejected,
                            "rejected",
                        );
                        Ok((err.status, err.body))
                    } else if path.ends_with("/SendInitialV2") {
                        if let Some(etx) = entered2_cell.borrow_mut().take() {
                            let _ = etx.send(());
                        }
                        let rx = rx2_cell.borrow_mut().take();
                        if let Some(rx) = rx {
                            let _ = rx.await;
                        }
                        Ok((200, SendInitialV2Response { id: 1 }.encode_to_vec()))
                    } else {
                        panic!("unexpected path: {path}");
                    }
                }
            });
            let (done2_tx, done2_rx) = futures::channel::oneshot::channel::<()>();
            let e2 = engine2.clone();
            spawner
                .spawn_local(async move {
                    let _ = e2.flush(&peer2).await;
                    let _ = done2_tx.send(());
                })
                .unwrap();
            let _ = entered2_rx.await;
            {
                let mut guard = engine2.inner.lock().await;
                let inner = guard.as_mut().unwrap();
                let c = inner.contact(&peer2).unwrap();
                c.state.conversation_gen += 1;
                c.state.awaiting_peer_acceptance = false;
            }
            let _ = tx2.send(());
            let _ = done2_rx.await;
        }
        assert!(
            !engine2.inner.lock().await.as_ref().unwrap().contacts[0]
                .state
                .awaiting_peer_acceptance,
            "stale SendInitialV2 Ok(()) must NOT mark recreated conversation awaiting_peer_acceptance"
        );
        assert!(!engine2.queue.has_approval_backoff(&peer2));
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r3_p2_5_in_flight_push_relayed_retries_commit_without_duplicate_push() {
    use futures::executor::LocalPool;
    use protocol::mailbox_v2::PushV2Response;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .add(&peer, Kind::Text("deliver exactly once".into()), false)
                .await
                .unwrap();
            // Pre-seal head (and mark `dispatched = true`, as persisted right before `PushV2`)
            // so only `commit_outbox_item` save fails after `PushV2` returns 200 OK.
            inner.seal_head_on_active_session(&peer).await.unwrap();
            inner.contact(&peer).unwrap().state.outbox[0].dispatched = true;
            inner.save_state().await.unwrap();
            inner.vault.fail_save.set(true);
        }

        let push_calls = Rc::new(Cell::new(0usize));
        let push_ref = push_calls.clone();
        {
            let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                assert!(path.ends_with("/PushV2"), "{path}");
                push_ref.set(push_ref.get() + 1);
                Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
            });
            assert!(engine.flush(&peer).await.is_err());
        }
        assert_eq!(push_calls.get(), 1);

        // `in_flight_push` stays armed with `relayed = true`, so a concurrent `requeue_sealed`
        // MUST NOT unseal the already-relayed head!
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            assert!(inner.in_flight_push.get(&peer).is_some_and(|f| f.relayed));
            inner.vault.fail_save.set(false);
            let _ = inner.requeue_sealed(&peer).await.unwrap();
            assert!(
                inner.contacts[0].state.outbox[0].sealed,
                "requeue_sealed must not unseal an already-relayed outbox head"
            );
        }

        // Next `flush` commits `Step::Pushed` locally with ZERO second `PushV2` RPC!
        {
            let _no_net = crate::transport::mock_fetch(|_s, path, _b| {
                panic!("retried local commit must NOT re-send PushV2: {path}");
            });
            assert_eq!(engine.flush(&peer).await, Ok(true));
        }
        let guard = engine.inner.lock().await;
        let inner = guard.as_ref().unwrap();
        assert!(!inner.in_flight_push.contains_key(&peer));
        assert!(inner.contacts[0].state.outbox.is_empty());
        assert_eq!(push_calls.get(), 1);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r3_p2_6_and_r3_p2_7_digest_cap_unlock_eviction_and_phase_a_cap() {
    use futures::executor::LocalPool;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        // R3-P2-6 + R4-P2-11: With 16 pinned digests, scheduled SPK rotation MUST still have
        // spare slots (`MAX_RETAINED_MANIFEST_DIGESTS == 144`: 16 rolling + 128 preserved), AND
        // once all 144 slots are pinned in `deferred_initials`, `has_spare_manifest_digest_slot`
        // returns `false` and scheduled `publish_full(vgen, false)` skips without network or eviction!
        let (mut inner, _) = unlocked_client();
        let mut pinned_digests = Vec::new();
        for i in 0..16u16 {
            let prep = inner
                .client
                .prepare_publish_v2("chat.example", 1, 1)
                .unwrap();
            let digest = session::protocol::handshake_v2::manifest_digest(
                prep.request.manifest.as_ref().unwrap(),
            )
            .unwrap();
            pinned_digests.push(digest);
            inner.client.commit_publish_v2(prep);
            let mut id_key = [0x40u8; 32];
            id_key[..2].copy_from_slice(&i.to_be_bytes());
            let mut eph_key = [0x60u8; 32];
            eph_key[..2].copy_from_slice(&i.to_be_bytes());
            inner.deferred_initials.push(crate::vault::DeferredInitial {
                initial: Some(WireInitialMessageV2 {
                    id: 0,
                    version: 2,
                    identity_key: Bytes::copy_from_slice(&id_key),
                    ephemeral_key: Bytes::copy_from_slice(&eph_key),
                    signed_prekey: Bytes::copy_from_slice(&[0x70; 32]),
                    first_message: Some(party::EncryptedMessage {
                        header: Bytes::from_static(b"h"),
                        content: Bytes::from_static(b"c"),
                    }),
                    pq_suite: PqSuite::MlKem1024.as_u8().into(),
                    pq_prekey_id: Bytes::from_static(&[0x88; 32]),
                    pq_ciphertext: Bytes::from(vec![0x88; PqSuite::MlKem1024.ct_len()]),
                    manifest_digest: Bytes::copy_from_slice(&digest),
                    ..WireInitialMessageV2::default()
                }),
                deferred_at: crate::util::now(),
            });
        }
        assert!(
            inner.client.has_spare_manifest_digest_slot(&pinned_digests),
            "16 pinned deferred digests must NOT block scheduled SPK rotation (capacity is 144)"
        );
        for i in 16..(session::MAX_RETAINED_MANIFEST_DIGESTS as u16) {
            let prep = inner
                .client
                .prepare_publish_v2_preserving("chat.example", 1, 1, &[], &pinned_digests)
                .unwrap();
            let digest = session::protocol::handshake_v2::manifest_digest(
                prep.request.manifest.as_ref().unwrap(),
            )
            .unwrap();
            pinned_digests.push(digest);
            inner.client.commit_publish_v2(prep);
            let mut id_key = [0x40u8; 32];
            id_key[..2].copy_from_slice(&i.to_be_bytes());
            let mut eph_key = [0x60u8; 32];
            eph_key[..2].copy_from_slice(&i.to_be_bytes());
            inner.deferred_initials.push(crate::vault::DeferredInitial {
                initial: Some(WireInitialMessageV2 {
                    id: 0,
                    version: 2,
                    identity_key: Bytes::copy_from_slice(&id_key),
                    ephemeral_key: Bytes::copy_from_slice(&eph_key),
                    signed_prekey: Bytes::copy_from_slice(&[0x70; 32]),
                    first_message: Some(party::EncryptedMessage {
                        header: Bytes::from_static(b"h"),
                        content: Bytes::from_static(b"c"),
                    }),
                    pq_suite: PqSuite::MlKem1024.as_u8().into(),
                    pq_prekey_id: Bytes::from_static(&[0x88; 32]),
                    pq_ciphertext: Bytes::from(vec![0x88; PqSuite::MlKem1024.ct_len()]),
                    manifest_digest: Bytes::copy_from_slice(&digest),
                    ..WireInitialMessageV2::default()
                }),
                deferred_at: crate::util::now(),
            });
        }
        assert!(!inner.client.has_spare_manifest_digest_slot(&pinned_digests));
        inner.state.published_at = 1;
        inner.state.needs_publish = false;
        let engine = Engine::with_inner(Ui::new(), inner);
        {
            let _no_net = crate::transport::mock_fetch(|_s, path, _b| {
                panic!(
                    "scheduled rotation with all 144 digest slots pinned must skip without network: {path}"
                );
            });
            let vgen = engine.vault_gen();
            engine.publish_full(vgen, false).await.unwrap();
            assert_eq!(
                engine
                    .inner
                    .lock()
                    .await
                    .as_ref()
                    .unwrap()
                    .client
                    .manifest_seq(),
                session::MAX_RETAINED_MANIFEST_DIGESTS as u64
            );
        }

        // R3-P2-7 Part 1: `prune_deferred_envelopes` increments `evicted_while_isolated` on overflow.
        let (mut inner2, peer) = unlocked_client();
        let me = inner2.client.identity_key();
        let mut envs = Vec::new();
        for seq in 1..=(super::sync::MAX_ISOLATED_DEFERRED_ENVELOPES_PER_PEER as u64 + 3) {
            envs.push(crate::vault::DeferredEnvelope {
                peer: peer.to_vec(),
                sequence: seq,
                message: None,
                initial_message: None,
                deferred_at: 1_000,
                pq_isolated: true,
            });
        }
        let removed = super::sync::prune_deferred_envelopes(
            &mut envs,
            &mut inner2.contacts,
            &mut inner2.isolated_contacts,
            &me,
            2_000,
        );
        assert_eq!(removed, 3);
        assert_eq!(inner2.contacts[0].state.evicted_while_isolated, 3);

        // R3-P2-7 Part 2: Phase-A 128-entry cap overflow retains overflow envelope with
        // `initial_message.is_some()` in `inner.deferred_envelopes` instead of discarding it!
        let (engine3, peer3, _bob3) = established_engine_on_localhost().await;
        {
            let mut guard = engine3.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let c = inner.contact(&peer3).unwrap();
            // Fill `pending_carried_initials` with 128 distinct valid classical carried initials so
            // staging a 129th fails with cap error, and mark them deferred so `join_carried` won't
            // drain them before we inspect Phase B retention. Actually use 128 dummy valid v1 wire
            // entries that fail open gracefully? Even simpler: fill with 128 unique entries and a
            // 129th on `DeferredEnvelope`: `stage_carried_initials` fails for the 129th -> stays
            // in `retained`!
            for i in 0..128u16 {
                let mut eph = [0x10u8; 32];
                eph[..2].copy_from_slice(&i.to_be_bytes());
                let wire = WireInitialMessageV2 {
                    id: 0,
                    version: 1,
                    identity_key: Bytes::copy_from_slice(&peer3),
                    ephemeral_key: Bytes::copy_from_slice(&eph),
                    signed_prekey: Bytes::from_static(&[0x22; 32]),
                    first_message: Some(party::EncryptedMessage {
                        header: Bytes::from_static(b"h"),
                        content: Bytes::from_static(b"c"),
                    }),
                    ..WireInitialMessageV2::default()
                };
                c.state.pending_carried_initials.push(
                    session::protocol::mailbox_v2::encode_carried_initial(&wire)
                        .unwrap()
                        .to_vec(),
                );
            }
            let overflow_wire = WireInitialMessageV2 {
                id: 0,
                version: 1,
                identity_key: Bytes::copy_from_slice(&peer3),
                ephemeral_key: Bytes::from_static(&[0xFF; 32]),
                signed_prekey: Bytes::from_static(&[0x22; 32]),
                first_message: Some(party::EncryptedMessage {
                    header: Bytes::from_static(b"h"),
                    content: Bytes::from_static(b"c"),
                }),
                ..WireInitialMessageV2::default()
            };
            inner
                .deferred_envelopes
                .push(crate::vault::DeferredEnvelope {
                    peer: peer3.to_vec(),
                    sequence: 500,
                    message: Some(party::EncryptedMessage {
                        header: Bytes::from_static(b"undecryptable"),
                        content: Bytes::from_static(b"body"),
                    }),
                    initial_message: Some(overflow_wire),
                    deferred_at: crate::util::now(),
                    pq_isolated: false,
                });
            let _ = engine3
                .replay_deferred_envelopes(inner, Some(&peer3), Some(u64::MAX), None)
                .await
                .unwrap();
            assert_eq!(
                inner.deferred_envelopes.len(),
                1,
                "Phase-A cap overflow must retain the unstaged carried-initial envelope in Phase B"
            );
            assert!(inner.deferred_envelopes[0].initial_message.is_some());
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r3_p2_8_p2_9_p2_11_p3_3_rollback_backoff_refusal_pause_and_lock_free_publish() {
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt as _;
    use protocol::handshake_v2::{ClaimBundleResponse, PublishV2Response};
    use protocol::mailbox_v2::RegisterWriteTokenResponse;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    pool.run_until(async {
        // R3-P2-4: `forget_peer` advances `inner.state.next_conversation_gen` immediately so
        // subsequent `app_state()` snapshots persist the monotonic floor without regressing.
        {
            let (mut inner_fg, peer_fg) = unlocked_client();
            inner_fg.state.next_conversation_gen = 5;
            inner_fg.contact(&peer_fg).unwrap().state.conversation_gen = 5;
            let state_fg = inner_fg.app_state();
            let deferred_fg = inner_fg.deferred_record();
            inner_fg
                .forget_peer(&peer_fg, state_fg, deferred_fg)
                .await
                .unwrap();
            assert_eq!(inner_fg.state.next_conversation_gen, 6);
            assert_eq!(inner_fg.app_state().next_conversation_gen, 6);
        }

        // R3-P2-8: Failed `rollback_cancelled_start_chat` neutralizes lingering contact so
        // `retry_pending_greetings()` never transmits its greeting!
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contact(&peer).unwrap().state.greeting_delivery =
                crate::vault::GREETING_DELIVERY_UNCERTAIN;
            inner.vault.fail_save.set(true);
            engine
                .rollback_cancelled_start_chat(inner, &peer, &[], false)
                .await;
            inner.vault.fail_save.set(false);
            let neutralized = inner.contact(&peer).unwrap();
            assert!(neutralized.state.request);
            assert!(neutralized.state.provisional);
        }
        {
            let _no_net = crate::transport::mock_fetch(|_s, path, _b| {
                panic!("neutralized cancelled contact must NEVER retry SendInitialV2: {path}");
            });
            assert_eq!(engine.retry_pending_greetings().await, Ok(false));
        }

        // R3-P2-9: Retired-SPK reclaim hitting `NotFound` with EMPTY outbox applies approval
        // backoff AND does NOT fire a `"messages could not be sent"` toast!
        let (engine2, peer2, _bob2) = established_engine_on_localhost().await;
        {
            let mut guard = engine2.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let c = inner.contact(&peer2).unwrap();
            c.session.retire();
            c.state.greeting_delivery = crate::vault::GREETING_DELIVERY_UNSENT;
            assert!(c.state.outbox.is_empty());
        }
        {
            let _mock = crate::transport::mock_fetch(|_s, path, _b| {
                assert!(path.ends_with("/ClaimBundle"), "{path}");
                let err = protocol::connect::error(protocol::ErrorKind::NotFound, "not found");
                Ok((err.status, err.body))
            });
            assert_eq!(engine2.retry_pending_greetings().await, Ok(false));
        }
        assert!(
            engine2.queue.is_approval_backed_off(&peer2),
            "failed empty-outbox reclaim must record approval backoff"
        );
        assert!(
            engine2.ui.notice.get_untracked().is_none(),
            "empty-outbox reclaim failure must NOT fire 'messages could not be sent' toast"
        );

        // R3-P3-3: `ensure_session_for_outbox` when `SendInitialV2` fails with a server refusal
        // records approval backoff and returns `RekeyOutcome::Paused` (not `Ready`).
        let (engine3, peer3, mut bob3) = established_engine_on_localhost().await;
        let fresh_pub3 = bob3.prepare_publish_v2("localhost", 2, 2).unwrap();
        let fresh_manifest3 = fresh_pub3.request.manifest.clone().unwrap();
        let fresh_bundle3 = ClaimBundleResponse {
            signed_prekey: fresh_manifest3.signed_prekey.clone(),
            signed_prekey_signature: fresh_pub3.request.signed_prekey_signature.clone(),
            one_time_prekey: fresh_pub3.request.one_time_prekeys.first().cloned(),
            manifest: Some(fresh_manifest3),
            pq_last_resort: fresh_pub3.request.pq_last_resort.first().cloned(),
            pq_one_time_prekey: fresh_pub3.request.pq_one_time_prekeys.first().cloned(),
        };
        bob3.commit_publish_v2(fresh_pub3);
        {
            let mut guard = engine3.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.contact(&peer3).unwrap().session.retire();
        }
        {
            let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                if path.ends_with("/ClaimBundle") {
                    Ok((200, fresh_bundle3.encode_to_vec()))
                } else if path.ends_with("/RegisterWriteToken") {
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else if path.ends_with("/SendInitialV2") {
                    let err =
                        protocol::connect::error(protocol::ErrorKind::LimitExceeded, "inbox full");
                    Ok((err.status, err.body))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            let mut deletes = Vec::new();
            let outcome = engine3
                .ensure_session_for_outbox(engine3.vault_gen(), &peer3, &mut deletes)
                .await
                .unwrap();
            assert!(matches!(outcome, super::outbox::RekeyOutcome::Paused));
            assert!(engine3.queue.is_approval_backed_off(&peer3));
        }

        // R3-P2-11: `publish_full` releases `self.inner` across the `/PublishV2` network RTT!
        let (inner4, _) = unlocked_client();
        let engine4 = Engine::with_inner(Ui::new(), inner4);
        let (tx, rx) = futures::channel::oneshot::channel::<()>();
        let rx_cell = Rc::new(RefCell::new(Some(rx)));
        let (entered_tx, entered_rx) = futures::channel::oneshot::channel::<()>();
        let entered_cell = Rc::new(RefCell::new(Some(entered_tx)));
        {
            let _mock = crate::transport::mock_fetch_async(move |_s, path, _b| {
                let rx_cell = rx_cell.clone();
                let entered_cell = entered_cell.clone();
                async move {
                    assert!(path.ends_with("/PublishV2"), "{path}");
                    if let Some(etx) = entered_cell.borrow_mut().take() {
                        let _ = etx.send(());
                    }
                    let rx = rx_cell.borrow_mut().take();
                    if let Some(rx) = rx {
                        let _ = rx.await;
                    }
                    Ok((200, PublishV2Response {}.encode_to_vec()))
                }
            });
            let (done_tx, done_rx) = futures::channel::oneshot::channel::<()>();
            let e4 = engine4.clone();
            let vgen = e4.vault_gen();
            spawner
                .spawn_local(async move {
                    e4.publish_full(vgen, true).await.unwrap();
                    let _ = done_tx.send(());
                })
                .unwrap();
            let _ = entered_rx.await;
            assert!(
                engine4.inner.try_lock().is_some(),
                "publish_full MUST release self.inner across PublishV2 network RTT"
            );
            let _ = tx.send(());
            let _ = done_rx.await;
        }
    });
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "ml-kem-1024", feature = "ml-kem-768")
))]
#[test]
fn r4_p1_1_queued_upgrade_to_pq_aborts_on_delete_and_recreate_request() {
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt as _;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        let orig_gen = {
            let guard = engine.inner.lock().await;
            guard
                .as_ref()
                .unwrap()
                .contacts
                .iter()
                .find(|c| c.peer == peer)
                .unwrap()
                .state
                .conversation_gen
        };

        // Hold `peer_flush_lock(&peer)` so queued `upgrade_to_pq` & `upgrade_to_pq_for_gen`
        // suspend waiting for it.
        let lock_handle = engine.queue.peer_flush_lock(&peer);
        let held_guard = lock_handle.lock().await;

        let res1: Rc<RefCell<Option<Result<(), String>>>> = Rc::new(RefCell::new(None));
        let res2: Rc<RefCell<Option<Result<(), String>>>> = Rc::new(RefCell::new(None));
        let (done1_tx, done1_rx) = futures::channel::oneshot::channel::<()>();
        let (done2_tx, done2_rx) = futures::channel::oneshot::channel::<()>();
        // Yield once after spawning so `upgrade_to_pq` snapshots `orig_gen` BEFORE we mutate the
        // contact!
        let (snap_tx, snap_rx) = futures::channel::oneshot::channel::<()>();
        let e1 = engine.clone();
        let r1 = res1.clone();
        spawner
            .spawn_local(async move {
                let _ = snap_tx.send(());
                *r1.borrow_mut() = Some(e1.upgrade_to_pq(peer).await);
                let _ = done1_tx.send(());
            })
            .unwrap();
        let e2 = engine.clone();
        let r2 = res2.clone();
        spawner
            .spawn_local(async move {
                *r2.borrow_mut() = Some(e2.upgrade_to_pq_for_gen(peer, orig_gen).await);
                let _ = done2_tx.send(());
            })
            .unwrap();

        // Wait until the first task has started and snapshotted `orig_gen` under `self.inner`
        // (then blocked on `peer_flush_lock`).
        let _ = snap_rx.await;
        // Let the spawned task run past its `lock_inner()` snapshot onto `peer_flush_lock`.
        let mut yielded = false;
        futures::future::poll_fn(|cx| {
            if !yielded {
                yielded = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(())
            }
        })
        .await;

        // Simulate deleting the chat and recreating it as a brand-new inbound request
        // (`conversation_gen` bumped, `request = true`).
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let c = inner.contact(&peer).unwrap();
            c.state.conversation_gen = orig_gen + 1;
            c.state.request = true;
        }

        let _no_net = crate::transport::mock_fetch(|_s, path, _b| {
            panic!("stale queued upgrade_to_pq must NEVER hit network: {path}");
        });
        drop(held_guard);
        let _ = done1_rx.await;
        let _ = done2_rx.await;

        assert!(
            res1.borrow()
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap_err()
                .contains("chat changed"),
            "upgrade_to_pq must reject recreated chat: {:?}",
            *res1.borrow()
        );
        assert!(
            res2.borrow()
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap_err()
                .contains("chat changed"),
            "upgrade_to_pq_for_gen must reject recreated chat: {:?}",
            *res2.borrow()
        );
        let guard = engine.inner.lock().await;
        assert!(
            guard
                .as_ref()
                .unwrap()
                .contacts
                .iter()
                .find(|c| c.peer == peer)
                .unwrap()
                .state
                .request,
            "fresh inbound request must remain unaccepted"
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r4_p1_2_replay_deferred_preserves_unlisted_and_concurrent_envelopes() {
    use futures::executor::LocalPool;
    use protocol::handshake_v2::ListInitialMessagesResponse;
    use std::collections::BTreeSet;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        let other_peer = [0x9Bu8; 32];

        // Subcase A: `approve_classical` preserves undecryptable deferred envelopes (never drops).
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let c = inner.contact(&peer).unwrap();
            c.state.quarantined = true;
            inner
                .deferred_envelopes
                .push(crate::vault::DeferredEnvelope {
                    peer: peer.to_vec(),
                    sequence: 10,
                    message: Some(party::EncryptedMessage {
                        header: Bytes::from_static(b"undecryptable-10"),
                        content: Bytes::from_static(b"body-10"),
                    }),
                    initial_message: None,
                    deferred_at: crate::util::now(),
                    pq_isolated: false,
                });
            inner.save_state().await.unwrap();
        }
        {
            let _mock = crate::transport::mock_fetch(|_s, path, _b| {
                if path.ends_with("/RegisterWriteToken") {
                    Ok((
                        200,
                        protocol::mailbox_v2::RegisterWriteTokenResponse {}.encode_to_vec(),
                    ))
                } else if path.ends_with("/PushV2") {
                    Ok((
                        200,
                        protocol::mailbox_v2::PushV2Response { sequence: 1 }.encode_to_vec(),
                    ))
                } else {
                    panic!("unexpected path in approve_classical: {path}");
                }
            });
            engine.approve_classical(peer).await.unwrap();
        }
        {
            let guard = engine.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert_eq!(
                inner.deferred_envelopes.len(),
                1,
                "approve_classical must NOT drop undecryptable envelopes whose initial wasn't fetched"
            );
            assert_eq!(inner.deferred_envelopes[0].sequence, 10);
        }

        // Subcase B & C: sequence upper bound `Some(5)` and peer filter `Some(&other_only)`.
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner.deferred_envelopes = vec![
                crate::vault::DeferredEnvelope {
                    peer: peer.to_vec(),
                    sequence: 5,
                    message: Some(party::EncryptedMessage {
                        header: Bytes::from_static(b"u5"),
                        content: Bytes::from_static(b"b5"),
                    }),
                    initial_message: None,
                    deferred_at: crate::util::now(),
                    pq_isolated: false,
                },
                crate::vault::DeferredEnvelope {
                    peer: peer.to_vec(),
                    sequence: 6,
                    message: Some(party::EncryptedMessage {
                        header: Bytes::from_static(b"u6"),
                        content: Bytes::from_static(b"b6"),
                    }),
                    initial_message: None,
                    deferred_at: crate::util::now(),
                    pq_isolated: false,
                },
            ];
            let other_only = BTreeSet::from([other_peer]);
            let _ = engine
                .replay_deferred_envelopes(inner, Some(&peer), Some(10), Some(&other_only))
                .await
                .unwrap();
            assert_eq!(
                inner.deferred_envelopes.len(),
                2,
                "peer excluded from drop_only_peers must retain its undecryptable envelopes"
            );

            let _ = engine
                .replay_deferred_envelopes(inner, Some(&peer), Some(5), None)
                .await
                .unwrap();
            assert_eq!(
                inner.deferred_envelopes.len(),
                1,
                "only sequence <= 5 may be dropped; concurrent sequence 6 > 5 must be preserved"
            );
            assert_eq!(inner.deferred_envelopes[0].sequence, 6);
        }

        // Subcase D: `take_initial_messages_with_replayed` truncated by MAX_INBOX_PAGES returns
        // `drained_all == false` and preserves undecryptable envelopes.
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let mut cs = proto::ClientState::from(inner.client.state());
            cs.mailbox_cursor = 100;
            inner.client = Client::restore(
                Fetch::client(TEST_SERVER),
                ClientState::try_from(&cs).unwrap(),
            );
        }
        let list_calls = Rc::new(Cell::new(0usize));
        {
            let list_ref = list_calls.clone();
            let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                assert!(path.ends_with("/ListInitialMessages"), "{path}");
                list_ref.set(list_ref.get() + 1);
                Ok((
                    200,
                    ListInitialMessagesResponse {
                        messages: vec![],
                        has_more: true,
                    }
                    .encode_to_vec(),
                ))
            });
            let (_, _, drained_all) = engine.take_initial_messages_with_replayed().await.unwrap();
            assert!(!drained_all, "truncated inbox listing must report drained_all = false");
        }
        assert_eq!(list_calls.get(), 1);
        assert_eq!(
            engine
                .inner
                .lock()
                .await
                .as_ref()
                .unwrap()
                .deferred_envelopes
                .len(),
            1,
            "truncated inbox drain must preserve undecryptable deferred envelope"
        );
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r4_p1_3_refused_rotating_publish_leaves_displaced_spk_greeting_unacked() {
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt as _;
    use protocol::handshake_v2::ClaimBundleResponse;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    pool.run_until(async {
        let (mut inner, _) = unlocked_client();
        // Publish generation 1 (`spk1`) and generation 2 (`spk2`); a 3rd publish will tentatively
        // displace `spk1`.
        let pub1 = inner.client.prepare_publish_v2("localhost", 2, 2).unwrap();
        let manifest1 = pub1.request.manifest.clone().unwrap();
        let bundle1 = ClaimBundleResponse {
            signed_prekey: manifest1.signed_prekey.clone(),
            signed_prekey_signature: pub1.request.signed_prekey_signature.clone(),
            one_time_prekey: pub1.request.one_time_prekeys.first().cloned(),
            manifest: Some(manifest1.clone()),
            pq_last_resort: pub1.request.pq_last_resort.first().cloned(),
            pq_one_time_prekey: pub1.request.pq_one_time_prekeys.first().cloned(),
        };
        let spk1 = <[u8; 32]>::try_from(manifest1.signed_prekey.as_ref()).unwrap();
        inner.client.commit_publish_v2(pub1);

        let pub2 = inner.client.prepare_publish_v2("localhost", 2, 2).unwrap();
        inner.client.commit_publish_v2(pub2);
        let alice_id = inner.client.identity_key();

        // Carol builds a valid greeting targeting `spk1`.
        let carol = Client::new(Fetch::client(TEST_SERVER));
        let carol_id = carol.identity_key();
        let claimed = {
            let b = bundle1.clone();
            let _mock = crate::transport::mock_fetch(move |_s, path, _body| {
                assert!(path.ends_with("/ClaimBundle"), "{path}");
                Ok((200, b.encode_to_vec()))
            });
            session::claim_peer_bundle_v2(
                &Fetch::client(TEST_SERVER),
                "localhost",
                &alice_id,
                &session::PeerPqState::default(),
                carol.pq_config(),
                carol.clock(),
            )
            .await
            .unwrap()
        };
        let hello = Kind::Hello(carol.make_hello("Carol", 1)).to_bytes();
        let prepared_init = carol
            .finish_prepare_initiate_v2(
                claimed,
                &session::PeerPqState::default(),
                &hello,
                Fetch::client(TEST_SERVER),
            )
            .unwrap();
        let mut wire_msg = prepared_init.request.message.unwrap();
        wire_msg.id = 77;
        let incoming = Incoming::try_from(&wire_msg).unwrap();

        inner.server = TEST_SERVER.to_string();
        inner.audience = "localhost".to_string();
        let engine = Engine::with_inner(Ui::new(), inner);

        // Start a rotating 3rd publish that tentatively displaces `spk1`, pause inside `/PublishV2`,
        // verify the `spk1` greeting yields `deferred_retry_later` (un-ACKed!), then fail
        // `/PublishV2` with `SignInRequired` (definitive refusal -> rolls back `spk1`!).
        let (entered_tx, entered_rx) = futures::channel::oneshot::channel::<()>();
        let entered_cell = Rc::new(RefCell::new(Some(entered_tx)));
        let (release_tx, release_rx) = futures::channel::oneshot::channel::<()>();
        let release_cell = Rc::new(RefCell::new(Some(release_rx)));
        let (done_tx, done_rx) = futures::channel::oneshot::channel::<()>();

        let _mock = crate::transport::mock_fetch_async(move |_s, path, _b| {
            let entered_cell = entered_cell.clone();
            let release_cell = release_cell.clone();
            async move {
                assert!(path.ends_with("/PublishV2"), "{path}");
                if let Some(etx) = entered_cell.borrow_mut().take() {
                    let _ = etx.send(());
                }
                let rx = release_cell.borrow_mut().take();
                if let Some(rx) = rx {
                    let _ = rx.await;
                }
                let err = protocol::connect::error(
                    protocol::ErrorKind::SignInRequired,
                    "sign in required",
                );
                Ok((err.status, err.body))
            }
        });
        let e_pub = engine.clone();
        let vgen = engine.vault_gen();
        spawner
            .spawn_local(async move {
                let _ = e_pub.publish_full(vgen, true).await;
                let _ = done_tx.send(());
            })
            .unwrap();

        let _ = entered_rx.await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            assert_eq!(inner.tentatively_displaced_spk, Some(spk1));
            let mut batch = InitialBatch::default();
            engine.process_inbox_messages(
                inner,
                ListedInitialMessages {
                    messages: vec![incoming.clone()],
                    has_more: false,
                    malformed_ids: vec![],
                    next_after_id: None,
                },
                &mut batch,
            );
            assert!(
                batch.deferred_retry_later,
                "greeting targeting tentatively displaced SPK must return RetryLater"
            );
            assert!(
                !inner.state.pending_inbox_acks.contains(&77),
                "RetryLater greeting must NEVER be staged for server ACK"
            );
        }

        let _ = release_tx.send(());
        let _ = done_rx.await;

        // After refusal rollback restores `spk1`, the exact same greeting decrypts and accepts!
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            assert_eq!(inner.tentatively_displaced_spk, None);
            let mut batch = InitialBatch::default();
            engine.process_inbox_messages(
                inner,
                ListedInitialMessages {
                    messages: vec![incoming],
                    has_more: false,
                    malformed_ids: vec![],
                    next_after_id: None,
                },
                &mut batch,
            );
            assert!(!batch.deferred_retry_later);
            assert!(inner.state.pending_inbox_acks.contains(&77));
            assert!(
                inner.contact(&carol_id).is_some(),
                "greeting must decrypt and create chat cleanly after publish rollback"
            );
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r4_p1_4_p2_1_p2_3_p3_2_confirmed_probe_two_rotations_verified_revalidate_and_backoff() {
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt as _;
    use protocol::handshake_v2::{GetManifestResponse, SendInitialV2Response};
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    pool.run_until(async {
        // Subcase A (G+1 no SendInitialV2) + Subcase B (G+2 + 200 OK -> greeting_delivery_verified)
        let (engine, bob_peer, mut bob) = established_engine_on_localhost().await;
        let rot1 = bob.prepare_publish_v2("localhost", 2, 2).unwrap();
        let manifest_g2 = rot1.request.manifest.clone().unwrap();
        bob.commit_publish_v2(rot1);
        let rot2 = bob.prepare_publish_v2("localhost", 2, 2).unwrap();
        let manifest_g3 = rot2.request.manifest.clone().unwrap();
        bob.commit_publish_v2(rot2);

        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let c = inner.contact(&bob_peer).unwrap();
            c.state.greeting_delivery = crate::vault::GREETING_DELIVERY_CONFIRMED;
            c.state.greeting_target_generation = 1;
            c.state.greeting_sent_at = crate::util::now();
            c.state.greeting_delivery_verified = false;
        }
        // At G+1 (generation 2), GetManifest runs but MUST NOT transmit SendInitialV2.
        {
            let m2 = manifest_g2.clone();
            let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                if path.ends_with("/GetManifest") {
                    Ok((
                        200,
                        GetManifestResponse {
                            manifest: Some(m2.clone()),
                        }
                        .encode_to_vec(),
                    ))
                } else {
                    panic!("G+1 rotation must NOT transmit SendInitialV2: {path}");
                }
            });
            assert_eq!(engine.retry_pending_greetings().await, Ok(false));
        }
        assert!(engine.queue.is_confirmed_probe_backed_off(&bob_peer));

        // Clear confirmed-probe backoff and advance Bob to G+2 (generation 3): SendInitialV2
        // returns 200 OK (ACK tombstone) -> sets `greeting_delivery_verified = true` so subsequent
        // calls make ZERO network requests even with backoff cleared!
        engine.queue.clear_confirmed_probe_backoff(&bob_peer);
        let send_calls = Rc::new(Cell::new(0usize));
        {
            let m3 = manifest_g3.clone();
            let send_ref = send_calls.clone();
            let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                if path.ends_with("/GetManifest") {
                    Ok((
                        200,
                        GetManifestResponse {
                            manifest: Some(m3.clone()),
                        }
                        .encode_to_vec(),
                    ))
                } else if path.ends_with("/SendInitialV2") {
                    send_ref.set(send_ref.get() + 1);
                    Ok((200, SendInitialV2Response { id: 9 }.encode_to_vec()))
                } else {
                    panic!("unexpected path: {path}");
                }
            });
            assert_eq!(engine.retry_pending_greetings().await, Ok(false));
        }
        assert_eq!(send_calls.get(), 1);
        assert!(
            engine
                .inner
                .lock()
                .await
                .as_ref()
                .unwrap()
                .contacts
                .iter()
                .find(|c| c.peer == bob_peer)
                .unwrap()
                .state
                .greeting_delivery_verified
        );
        engine.queue.clear_confirmed_probe_backoff(&bob_peer);
        {
            let _no_net = crate::transport::mock_fetch(|_s, path, _b| {
                panic!("delivery-verified contact must NEVER probe again: {path}");
            });
            assert_eq!(engine.retry_pending_greetings().await, Ok(false));
        }

        // Subcase C (R4-P2-3): Delete contact while GetManifest is in flight -> ZERO SendInitialV2.
        let (engine2, bob_peer2, mut bob2) = established_engine_on_localhost().await;
        let p2a = bob2.prepare_publish_v2("localhost", 2, 2).unwrap();
        bob2.commit_publish_v2(p2a);
        let p2b = bob2.prepare_publish_v2("localhost", 2, 2).unwrap();
        let m2_g3 = p2b.request.manifest.clone().unwrap();
        bob2.commit_publish_v2(p2b);
        {
            let mut guard = engine2.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let c = inner.contact(&bob_peer2).unwrap();
            c.state.greeting_delivery = crate::vault::GREETING_DELIVERY_CONFIRMED;
            c.state.greeting_target_generation = 1;
            c.state.greeting_sent_at = crate::util::now();
            c.state.greeting_delivery_verified = false;
        }
        let (entered_tx, entered_rx) = futures::channel::oneshot::channel::<()>();
        let entered_cell = Rc::new(RefCell::new(Some(entered_tx)));
        let (release_tx, release_rx) = futures::channel::oneshot::channel::<()>();
        let release_cell = Rc::new(RefCell::new(Some(release_rx)));
        let (done_tx, done_rx) = futures::channel::oneshot::channel::<()>();
        {
            let _mock = crate::transport::mock_fetch_async(move |_s, path, _b| {
                let entered_cell = entered_cell.clone();
                let release_cell = release_cell.clone();
                let m = m2_g3.clone();
                async move {
                    if path.ends_with("/GetManifest") {
                        if let Some(etx) = entered_cell.borrow_mut().take() {
                            let _ = etx.send(());
                        }
                        let rx = release_cell.borrow_mut().take();
                        if let Some(rx) = rx {
                            let _ = rx.await;
                        }
                        Ok((
                            200,
                            GetManifestResponse { manifest: Some(m) }.encode_to_vec(),
                        ))
                    } else {
                        panic!("deleted contact must NOT transmit SendInitialV2: {path}");
                    }
                }
            });
            let e2 = engine2.clone();
            spawner
                .spawn_local(async move {
                    let _ = e2.retry_pending_greetings().await;
                    let _ = done_tx.send(());
                })
                .unwrap();
            let _ = entered_rx.await;
            {
                let mut guard = engine2.inner.lock().await;
                guard
                    .as_mut()
                    .unwrap()
                    .contacts
                    .retain(|c| c.peer != bob_peer2);
            }
            let _ = release_tx.send(());
            let _ = done_rx.await;
        }

        // Subcase D (R4-P3-2): `outbox.rs` WriteTokenRejected throttles `GetManifest` with
        // `confirmed_probe_backoff`.
        let (engine3, bob_peer3, mut bob3) = established_engine_on_localhost().await;
        let p3 = bob3.prepare_publish_v2("localhost", 2, 2).unwrap();
        let m3_g2 = p3.request.manifest.clone().unwrap();
        bob3.commit_publish_v2(p3);
        {
            let mut guard = engine3.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let c = inner.contact(&bob_peer3).unwrap();
            c.state.greeting_delivery = crate::vault::GREETING_DELIVERY_CONFIRMED;
            c.state.greeting_target_generation = 1;
            c.state.greeting_sent_at = crate::util::now();
            c.state.greeting_delivery_verified = false;
            inner
                .add(&bob_peer3, Kind::Text("queued".into()), false)
                .await
                .unwrap();
        }
        let manifest_calls = Rc::new(Cell::new(0usize));
        {
            let m_ref = manifest_calls.clone();
            let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                if path.ends_with("/PushV2") {
                    let err = protocol::connect::error(
                        protocol::ErrorKind::WriteTokenRejected,
                        "write token rejected",
                    );
                    Ok((err.status, err.body))
                } else if path.ends_with("/GetManifest") {
                    m_ref.set(m_ref.get() + 1);
                    Ok((
                        200,
                        GetManifestResponse {
                            manifest: Some(m3_g2.clone()),
                        }
                        .encode_to_vec(),
                    ))
                } else {
                    panic!("unexpected path in throttled flush probe: {path}");
                }
            });
            assert_eq!(engine3.flush(&bob_peer3).await, Ok(false));
            assert_eq!(manifest_calls.get(), 1);
            assert!(engine3.queue.is_confirmed_probe_backed_off(&bob_peer3));
            // Clear only approval backoff (simulating a user-initiated send retry) while
            // confirmed_probe_backoff remains active: GetManifest must NOT fire a second time!
            engine3.queue.clear_approval_backoff_only(&bob_peer3);
            assert_eq!(engine3.flush(&bob_peer3).await, Ok(false));
            assert_eq!(
                manifest_calls.get(),
                1,
                "outbox WriteTokenRejected must respect confirmed_probe_backoff"
            );
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r4_p2_2_pre_approval_write_token_rejected_retries_without_retiring_newly_known_session() {
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt as _;
    use protocol::mailbox_v2::PushV2Response;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    pool.run_until(async {
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            assert!(!inner.contact(&peer).unwrap().session.is_known_by_peer());
            inner
                .add(&peer, Kind::Text("race with peer acceptance".into()), false)
                .await
                .unwrap();
        }
        let (entered_tx, entered_rx) = futures::channel::oneshot::channel::<()>();
        let entered_cell = Rc::new(RefCell::new(Some(entered_tx)));
        let (release_tx, release_rx) = futures::channel::oneshot::channel::<()>();
        let release_cell = Rc::new(RefCell::new(Some(release_rx)));
        let push_calls = Rc::new(Cell::new(0usize));
        let (done_tx, done_rx) = futures::channel::oneshot::channel::<Result<bool, String>>();
        {
            let push_ref = push_calls.clone();
            let _mock = crate::transport::mock_fetch_async(move |_s, path, _b| {
                let entered_cell = entered_cell.clone();
                let release_cell = release_cell.clone();
                let push_ref = push_ref.clone();
                async move {
                    assert!(path.ends_with("/PushV2"), "{path}");
                    let n = push_ref.get() + 1;
                    push_ref.set(n);
                    if n == 1 {
                        if let Some(etx) = entered_cell.borrow_mut().take() {
                            let _ = etx.send(());
                        }
                        let rx = release_cell.borrow_mut().take();
                        if let Some(rx) = rx {
                            let _ = rx.await;
                        }
                        let err = protocol::connect::error(
                            protocol::ErrorKind::WriteTokenRejected,
                            "write token rejected",
                        );
                        Ok((err.status, err.body))
                    } else {
                        Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
                    }
                }
            });
            let e = engine.clone();
            spawner
                .spawn_local(async move {
                    let _ = done_tx.send(e.flush(&peer).await);
                })
                .unwrap();
            let _ = entered_rx.await;
            // While `PushV2` #1 is in flight (`known_at_dispatch == false`), peer acceptance
            // arrives and marks the session known!
            {
                let mut guard = engine.inner.lock().await;
                let inner = guard.as_mut().unwrap();
                let c = inner.contact(&peer).unwrap();
                let mut state = proto::SessionState::from(c.session.state());
                state.known_by_peer = true;
                c.session = Session::restore(
                    Fetch::client(TEST_SERVER),
                    SessionState::try_from(&state).unwrap(),
                );
            }
            let _ = release_tx.send(());
            assert_eq!(done_rx.await.unwrap(), Ok(true));
        }
        assert_eq!(push_calls.get(), 2);
        let guard = engine.inner.lock().await;
        let c = guard
            .as_ref()
            .unwrap()
            .contacts
            .iter()
            .find(|c| c.peer == peer)
            .unwrap();
        assert!(
            !c.session.needs_new_session(),
            "session must NOT be retired"
        );
        assert!(c.state.outbox.is_empty());
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r4_p2_4_p2_5_carried_cap_preserves_earlier_seq_and_expired_non_isolated_does_not_block() {
    use futures::executor::LocalPool;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        // R4-P2-4: 128 carried initials (supported on PQ builds, unsupported on classical-only
        // builds) + earlier undecryptable envelope `seq = 10` + 129th carried initial on
        // `seq = 11` -> BOTH `seq = 10` and `seq = 11` stay preserved even with
        // `drop_undecryptable_up_to_seq = Some(u64::MAX)`!
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let c = inner.contact(&peer).unwrap();
            for i in 0..128u16 {
                let mut eph = [0x30u8; 32];
                eph[..2].copy_from_slice(&i.to_be_bytes());
                let wire = WireInitialMessageV2 {
                    id: 0,
                    version: 2,
                    identity_key: Bytes::copy_from_slice(&peer),
                    ephemeral_key: Bytes::copy_from_slice(&eph),
                    signed_prekey: Bytes::from_static(&[0x22; 32]),
                    first_message: Some(party::EncryptedMessage {
                        header: Bytes::from_static(b"h"),
                        content: Bytes::from_static(b"c"),
                    }),
                    pq_suite: PqSuite::MlKem1024.as_u8().into(),
                    pq_prekey_id: Bytes::from_static(&[0x44; 32]),
                    pq_ciphertext: Bytes::from(vec![0x55; PqSuite::MlKem1024.ct_len()]),
                    ..WireInitialMessageV2::default()
                };
                c.state.pending_carried_initials.push(
                    session::protocol::mailbox_v2::encode_carried_initial(&wire)
                        .unwrap()
                        .to_vec(),
                );
            }
            let wire_129 = WireInitialMessageV2 {
                id: 0,
                version: 2,
                identity_key: Bytes::copy_from_slice(&peer),
                ephemeral_key: Bytes::from_static(&[0xEE; 32]),
                signed_prekey: Bytes::from_static(&[0x22; 32]),
                first_message: Some(party::EncryptedMessage {
                    header: Bytes::from_static(b"h"),
                    content: Bytes::from_static(b"c"),
                }),
                pq_suite: PqSuite::MlKem1024.as_u8().into(),
                pq_prekey_id: Bytes::from_static(&[0x44; 32]),
                pq_ciphertext: Bytes::from(vec![0x55; PqSuite::MlKem1024.ct_len()]),
                ..WireInitialMessageV2::default()
            };
            inner.deferred_envelopes = vec![
                crate::vault::DeferredEnvelope {
                    peer: peer.to_vec(),
                    sequence: 10,
                    message: Some(party::EncryptedMessage {
                        header: Bytes::from_static(b"dep-10"),
                        content: Bytes::from_static(b"body-10"),
                    }),
                    initial_message: None,
                    deferred_at: crate::util::now(),
                    pq_isolated: false,
                },
                crate::vault::DeferredEnvelope {
                    peer: peer.to_vec(),
                    sequence: 11,
                    message: Some(party::EncryptedMessage {
                        header: Bytes::from_static(b"dep-11"),
                        content: Bytes::from_static(b"body-11"),
                    }),
                    initial_message: Some(wire_129),
                    deferred_at: crate::util::now(),
                    pq_isolated: false,
                },
            ];
            let _ = engine
                .replay_deferred_envelopes(inner, Some(&peer), Some(u64::MAX), None)
                .await
                .unwrap();
            assert_eq!(
                inner.deferred_envelopes.len(),
                2,
                "both earlier seq=10 and capped unsupported seq=11 must be preserved"
            );
            assert!(
                inner
                    .deferred_envelopes
                    .iter()
                    .any(|e| e.sequence == 11 && e.initial_message.is_some())
            );
        }

        // R4-P2-5: An EXPIRED non-isolated envelope carrying `initial_message = Some(...)` MUST be
        // discarded cleanly instead of blocking a newer decryptable envelope!
        let (engine2, peer2, mut bob2) = established_engine_on_localhost().await;
        // Let Alice send first message so Bob can open Alice's initial and send a valid reply.
        let mut bob_session = {
            let guard = engine2.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let req = inner
                .contacts
                .iter()
                .find(|c| c.peer == peer2)
                .unwrap()
                .session
                .pending_initial_request()
                .unwrap();
            let inc = Incoming::try_from(req.message.as_ref().unwrap()).unwrap();
            match bob2
                .accept_initial_v2(
                    &inner.client.identity_key(),
                    &session::PeerPqState::default(),
                    &inc,
                    Fetch::client(TEST_SERVER),
                )
                .unwrap()
            {
                AcceptedInitial::Accepted { session, .. } => session,
                AcceptedInitial::Quarantined { session, .. } => session,
            }
        };
        let fresh_msg = bob_session
            .encrypt(&Kind::Text("not blocked by expired carried!".into()).to_bytes())
            .unwrap();
        {
            let mut guard = engine2.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let expired_wire = WireInitialMessageV2 {
                id: 0,
                version: 1,
                identity_key: Bytes::copy_from_slice(&peer2),
                ephemeral_key: Bytes::from_static(&[0xAB; 32]),
                signed_prekey: Bytes::from_static(&[0xCD; 32]),
                first_message: Some(party::EncryptedMessage {
                    header: Bytes::from_static(b"expired"),
                    content: Bytes::from_static(b"expired"),
                }),
                ..WireInitialMessageV2::default()
            };
            inner.deferred_envelopes = vec![
                crate::vault::DeferredEnvelope {
                    peer: peer2.to_vec(),
                    sequence: 10,
                    message: Some(party::EncryptedMessage {
                        header: Bytes::from_static(b"old"),
                        content: Bytes::from_static(b"old"),
                    }),
                    initial_message: Some(expired_wire),
                    deferred_at: 1, // > 30d old
                    pq_isolated: false,
                },
                crate::vault::DeferredEnvelope {
                    peer: peer2.to_vec(),
                    sequence: 11,
                    message: Some(fresh_msg.message.clone()),
                    initial_message: None,
                    deferred_at: crate::util::now(),
                    pq_isolated: false,
                },
            ];
            let (replayed, _, _) = engine2
                .replay_deferred_envelopes(inner, Some(&peer2), Some(u64::MAX), None)
                .await
                .unwrap();
            assert!(replayed.contains(&peer2));
            assert!(
                inner.deferred_envelopes.is_empty(),
                "expired non-isolated envelope must be discarded and seq=11 delivered"
            );
            assert!(inner.vault.entries.borrow().values().any(|e| {
                e.content.as_ref().and_then(|c| c.kind.as_ref())
                    == Some(&Kind::Text("not blocked by expired carried!".into()))
            }));
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r4_p2_6_p2_7_p2_8_dispatched_survives_reload_corrupt_history_commit_and_cancel_relayed_upload() {
    use futures::executor::LocalPool;
    use protocol::mailbox_v2::PushV2Response;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        // R4-P2-6: Durable `Outgoing.dispatched` protects an already-dispatched head across reload
        // + concurrent `needs_requeue_sealed`, reconciling the exact same `client_message_id`!
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        let orig_cmid: Vec<u8>;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .add(&peer, Kind::Text("no duplicate on reload".into()), false)
                .await
                .unwrap();
            let _ = inner.seal_head_on_active_session(&peer).await.unwrap();
            let c = inner.contact(&peer).unwrap();
            c.state.outbox[0].dispatched = true;
            c.state.needs_requeue_sealed = true;
            orig_cmid = inner.vault.outbox.borrow()[&(peer, 0)]
                .to_sealed()
                .unwrap()
                .push_v2_request(&peer)
                .client_message_id
                .to_vec();
            assert_eq!(orig_cmid.len(), 16);
            // Simulate post-reload `requeue_before_push` (`in_flight_push` is empty!): MUST keep
            // `dispatched` head sealed!
            assert!(inner.in_flight_push.is_empty());
            let _ = inner.requeue_before_push(&peer).await.unwrap();
            let c = inner.contact(&peer).unwrap();
            assert!(c.state.outbox[0].sealed);
            assert!(c.state.outbox[0].dispatched);
            assert!(c.state.needs_requeue_sealed);
        }
        let pushed_cmids: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(Vec::new()));
        {
            let cmids = pushed_cmids.clone();
            let _mock = crate::transport::mock_fetch(move |_s, path, body| {
                assert!(path.ends_with("/PushV2"), "{path}");
                let req = PushV2Request::decode(body.as_slice()).unwrap();
                cmids.borrow_mut().push(req.client_message_id.to_vec());
                Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
            });
            assert_eq!(engine.flush(&peer).await, Ok(true));
        }
        assert_eq!(pushed_cmids.borrow().as_slice(), &[orig_cmid]);
        assert!(
            engine
                .inner
                .lock()
                .await
                .as_ref()
                .unwrap()
                .contacts
                .iter()
                .find(|c| c.peer == peer)
                .unwrap()
                .state
                .outbox
                .is_empty()
        );

        // R4-P2-7: Permanently corrupt history entry in `commit_outbox_item` settles the outbox
        // head instead of stalling all subsequent messages.
        let (engine2, peer2, _bob2) = established_engine_on_localhost().await;
        {
            let mut guard = engine2.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .add(&peer2, Kind::Text("corrupt row".into()), false)
                .await
                .unwrap();
            inner
                .add(&peer2, Kind::Text("second healthy row".into()), false)
                .await
                .unwrap();
            inner.vault.corrupt_read_at.set(Some(0));
        }
        {
            let _mock = crate::transport::mock_fetch(|_s, path, _b| {
                assert!(path.ends_with("/PushV2"), "{path}");
                Ok((200, PushV2Response { sequence: 1 }.encode_to_vec()))
            });
            assert_eq!(engine2.flush(&peer2).await, Ok(true));
        }
        assert!(
            engine2
                .inner
                .lock()
                .await
                .as_ref()
                .unwrap()
                .contacts
                .iter()
                .find(|c| c.peer == peer2)
                .unwrap()
                .state
                .outbox
                .is_empty(),
            "corrupt history entry #0 must not wedge healthy message #1"
        );

        // R4-P2-8: `cancel_upload` settles a `relayed = true` announcement as `Step::Pushed`
        // instead of rewriting it to `Step::Refused` (`Delivery::Failed`).
        let (engine3, peer3, _bob3) = established_engine_on_localhost().await;
        let upload_id = [0x42u8; 16];
        {
            let mut guard = engine3.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            inner
                .add(&peer3, Kind::Text("announced file".into()), false)
                .await
                .unwrap();
            let _ = inner.seal_head_on_active_session(&peer3).await.unwrap();
            let c = inner.contact(&peer3).unwrap();
            let conv_gen = c.state.conversation_gen;
            let clock = c.state.outbox[0].clock;
            let active_id = c.session.active_id().copied();
            inner.in_flight_push.insert(
                peer3,
                super::InFlightPush {
                    conversation_gen: conv_gen,
                    history_index: 0,
                    clock,
                    session_id: active_id,
                    relayed: true,
                },
            );
            inner.vault.uploads.borrow_mut().insert(
                (peer3, upload_id.to_vec()),
                PendingUpload {
                    id: upload_id.to_vec(),
                    token: vec![1u8; 16],
                    key: vec![2u8; 32],
                    size: 1024,
                    uploaded: 0,
                    encrypted: 0,
                    prefix_hash: vec![],
                    announced: true,
                    expires: 0,
                    name: "photo.jpg".into(),
                    mime: "image/jpeg".into(),
                    history_index: 0,
                    upload_state: crate::vault::UPLOAD_STATE_ANNOUNCED,
                    sealed_chunk_hash: vec![],
                },
            );
        }
        {
            let _mock = crate::transport::mock_fetch(|_s, path, _b| {
                if path.ends_with("/DeleteAttachment") {
                    Ok((
                        200,
                        protocol::attachment::DeleteAttachmentResponse {}.encode_to_vec(),
                    ))
                } else {
                    panic!("unexpected path in cancel_upload: {path}");
                }
            });
            engine3.cancel_upload(peer3, upload_id).await.unwrap();
        }
        {
            let guard = engine3.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            let c = inner.contacts.iter().find(|c| c.peer == peer3).unwrap();
            assert!(!inner.in_flight_push.contains_key(&peer3));
            assert!(c.state.outbox.is_empty());
            assert_eq!(c.state.awaiting.len(), 1);
            assert_eq!(
                inner.vault.entries.borrow()[&(peer3, 0)].delivery(),
                Delivery::Sent,
                "already-relayed announcement must settle as Sent (Step::Pushed), not Failed"
            );
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn r4_p2_9_p2_10_p2_12_p2_13_p2_14_provisional_publish_lock_deltas_and_persisted_rollback() {
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt as _;
    use protocol::handshake_v2::PublishV2Response;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    pool.run_until(async {
        // R4-P2-9 & R4-P2-10: `provisional` contact is skipped by background `flush_pending_grants`
        // AND `retry_pending_greetings`.
        let (engine, peer, _bob) = established_engine_on_localhost().await;
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let c = inner.contact(&peer).unwrap();
            c.state.provisional = true;
            c.state.greeting_delivery = crate::vault::GREETING_DELIVERY_UNSENT;
            let hash = c.session.active_inbound_token_hash().unwrap();
            inner.stage_write_token_grant(&peer, hash, true).unwrap();
        }
        {
            let _no_net = crate::transport::mock_fetch(|_s, path, _b| {
                panic!("provisional contact must NOT flush grants or retry greetings: {path}");
            });
            engine.flush_pending_grants().await.unwrap();
            assert_eq!(engine.retry_pending_greetings().await, Ok(false));
        }

        // R4-P2-12 + R4-P2-13: Two concurrent `publish()` calls serialize under `publish_lock` so
        // only ONE `/PublishV2` fires (second re-checks `full_due`), AND concurrent OPK/PQOPK
        // consumption during `/PublishV2` is preserved in the committed counters!
        let (mut inner2, _) = unlocked_client();
        inner2.state.published_at = 0;
        inner2.state.needs_publish = true;
        inner2.state.used_one_time_prekeys = 5;
        inner2.state.used_pq_one_time_prekeys = 3;
        let engine2 = Engine::with_inner(Ui::new(), inner2);
        let pub_calls = Rc::new(Cell::new(0usize));
        let (entered_tx, entered_rx) = futures::channel::oneshot::channel::<()>();
        let entered_cell = Rc::new(RefCell::new(Some(entered_tx)));
        let (release_tx, release_rx) = futures::channel::oneshot::channel::<()>();
        let release_cell = Rc::new(RefCell::new(Some(release_rx)));
        let (d1_tx, d1_rx) = futures::channel::oneshot::channel::<()>();
        let (d2_tx, d2_rx) = futures::channel::oneshot::channel::<()>();
        {
            let p_ref = pub_calls.clone();
            let _mock = crate::transport::mock_fetch_async(move |_s, path, _b| {
                let p_ref = p_ref.clone();
                let entered_cell = entered_cell.clone();
                let release_cell = release_cell.clone();
                async move {
                    assert!(path.ends_with("/PublishV2"), "{path}");
                    p_ref.set(p_ref.get() + 1);
                    if let Some(etx) = entered_cell.borrow_mut().take() {
                        let _ = etx.send(());
                    }
                    let rx = release_cell.borrow_mut().take();
                    if let Some(rx) = rx {
                        let _ = rx.await;
                    }
                    Ok((200, PublishV2Response {}.encode_to_vec()))
                }
            });
            let e_a = engine2.clone();
            let e_b = engine2.clone();
            spawner
                .spawn_local(async move {
                    e_a.publish(false).await.unwrap();
                    let _ = d1_tx.send(());
                })
                .unwrap();
            let _ = entered_rx.await;
            // Spawn second concurrent `publish()` while first holds `publish_lock`, AND simulate
            // concurrent OPK/PQOPK consumption (+2 classical, +1 PQ) while `/PublishV2` is in flight!
            spawner
                .spawn_local(async move {
                    e_b.publish(false).await.unwrap();
                    let _ = d2_tx.send(());
                })
                .unwrap();
            {
                let mut guard = engine2.inner.lock().await;
                let inner = guard.as_mut().unwrap();
                inner.state.used_one_time_prekeys += 2;
                inner.state.used_pq_one_time_prekeys += 1;
            }
            let _ = release_tx.send(());
            let _ = d1_rx.await;
            let _ = d2_rx.await;
        }
        assert_eq!(
            pub_calls.get(),
            1,
            "second concurrent publish() must see !full_due under publish_lock and NOT double-rotate"
        );
        {
            let guard = engine2.inner.lock().await;
            let inner = guard.as_ref().unwrap();
            assert_eq!(inner.state.used_one_time_prekeys, 2);
            assert_eq!(inner.state.used_pq_one_time_prekeys, 1);
            assert_eq!(
                inner.last_server_classical_opks,
                Some(ONE_TIME_PREKEYS as u32 - 2)
            );
        }

        // R4-P2-14: Persisted `PendingPqRollback.contact_flags` survives reload (`AppState` round
        // trip) and restores cleared contact flags on definitive settings refusal.
        let (mut inner3, peer3) = unlocked_client();
        inner3.contact(&peer3).unwrap().state.security_alert =
            crate::vault::SECURITY_ALERT_PQ_REQUIRED;
        inner3.contact(&peer3).unwrap().state.classical_approval_needed =
            crate::vault::CLASSICAL_APPROVAL_SIGNED_OFF;
        let orig_cfg = inner3.client.pq_config().clone();
        let mut rollback = crate::vault::PendingPqRollback::from_config(&orig_cfg, false);
        rollback.record_contact_flag(
            &peer3,
            Some(crate::vault::SECURITY_ALERT_PQ_REQUIRED),
            Some(crate::vault::CLASSICAL_APPROVAL_SIGNED_OFF),
        );
        inner3.state.pending_pq_rollback = Some(rollback);
        inner3.contact(&peer3).unwrap().state.security_alert = crate::vault::SECURITY_ALERT_NONE;
        inner3.contact(&peer3).unwrap().state.classical_approval_needed =
            crate::vault::CLASSICAL_APPROVAL_NONE;
        inner3.save_state().await.unwrap();
        // Round-trip `AppState` bytes (simulating full page reload!).
        let encoded_state = inner3.vault.state.borrow().encode_to_vec();
        let decoded_state = AppState::decode(encoded_state.as_slice()).unwrap();
        assert_eq!(
            decoded_state
                .pending_pq_rollback
                .as_ref()
                .unwrap()
                .contact_flags
                .len(),
            1
        );
        inner3.state.pending_pq_rollback = decoded_state.pending_pq_rollback;
        let engine3 = Engine::with_inner(Ui::new(), inner3);
        {
            let mut guard = engine3.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let err = PublishError::transmitted(session::Error::from(
                protocol::Error::from(protocol::ErrorKind::Malformed),
            ));
            let _ = engine3.finish_publish_rollback(inner, err, true).await;
            let c = inner.contact(&peer3).unwrap();
            assert_eq!(c.state.security_alert, crate::vault::SECURITY_ALERT_PQ_REQUIRED);
            assert_eq!(
                c.state.classical_approval_needed,
                crate::vault::CLASSICAL_APPROVAL_SIGNED_OFF
            );
            assert!(inner.state.pending_pq_rollback.is_none());
        }
    });
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "ml-kem-1024", feature = "ml-kem-768")
))]
#[test]
fn r4_p2_15_accept_request_dispatches_replay_pq_upgrades() {
    use futures::executor::LocalPool;
    use protocol::handshake_v2::{ClaimBundleResponse, SendInitialV2Response};
    use protocol::mailbox_v2::RegisterWriteTokenResponse;
    use std::rc::Rc;

    let mut pool = LocalPool::new();
    pool.run_until(async {
        let (engine, peer, mut bob) = established_engine_on_localhost().await;
        // Bob prepares a PQ bundle that Alice will claim when `accept_request` dispatches the
        // automatic PQ upgrade recommended by a buffered classical `Hello` claiming PQ support!
        let bob_pub = bob.prepare_publish_v2("localhost", 2, 2).unwrap();
        let bob_manifest = bob_pub.request.manifest.clone().unwrap();
        let bob_bundle = ClaimBundleResponse {
            signed_prekey: bob_manifest.signed_prekey.clone(),
            signed_prekey_signature: bob_pub.request.signed_prekey_signature.clone(),
            one_time_prekey: bob_pub.request.one_time_prekeys.first().cloned(),
            manifest: Some(bob_manifest),
            pq_last_resort: bob_pub.request.pq_last_resort.first().cloned(),
            pq_one_time_prekey: bob_pub.request.pq_one_time_prekeys.first().cloned(),
        };
        bob.commit_publish_v2(bob_pub);

        // Put Alice's session with Bob on classical (not PQ) and quarantined with a buffered
        // encrypted `Kind::Hello` advertising PQ support (which triggers `check_peer_hello`
        // downgrade + `recommend_start_again = true` during `approve_classical` replay).
        {
            let mut guard = engine.inner.lock().await;
            let inner = guard.as_mut().unwrap();
            let alice_id = inner.client.identity_key();
            let classical_cfg = PqConfig {
                pq_enabled: false,
                strict_pq: false,
                ..PqConfig::default()
            };
            bob.set_pq_config(classical_cfg.clone()).unwrap();
            let a_cls_pub = {
                let saved_cfg = inner.client.pq_config().clone();
                inner.client.set_pq_config(classical_cfg).unwrap();
                let p = inner.client.prepare_publish_v2("localhost", 2, 0).unwrap();
                let m = p.request.manifest.clone().unwrap();
                let cb = ClaimBundleResponse {
                    signed_prekey: m.signed_prekey.clone(),
                    signed_prekey_signature: p.request.signed_prekey_signature.clone(),
                    one_time_prekey: p.request.one_time_prekeys.first().cloned(),
                    manifest: Some(m),
                    pq_last_resort: None,
                    pq_one_time_prekey: None,
                };
                inner.client.commit_publish_v2(p);
                inner.client.set_pq_config(saved_cfg).unwrap();
                cb
            };
            let claimed2 = {
                let b = a_cls_pub.clone();
                let _mock =
                    crate::transport::mock_fetch(move |_s, _p, _body| Ok((200, b.encode_to_vec())));
                session::claim_peer_bundle_v2(
                    &Fetch::client(TEST_SERVER),
                    "localhost",
                    &alice_id,
                    &session::PeerPqState::default(),
                    bob.pq_config(),
                    bob.clock(),
                )
                .await
                .unwrap()
            };
            let mut prepared2 = bob
                .finish_prepare_initiate_v2(
                    claimed2,
                    &session::PeerPqState::default(),
                    &Kind::Hello(bob.make_hello("Bob", 10)).to_bytes(),
                    Fetch::client(TEST_SERVER),
                )
                .unwrap();
            let inc2 = Incoming::try_from(prepared2.request.message.as_ref().unwrap()).unwrap();
            let a_real = match inner
                .client
                .accept_initial_v2(
                    &peer,
                    &session::PeerPqState::default(),
                    &inc2,
                    Fetch::client(TEST_SERVER),
                )
                .unwrap()
            {
                AcceptedInitial::Accepted { session, .. }
                | AcceptedInitial::Quarantined { session, .. } => session,
            };
            // Re-enable PQ on Bob so his second `Hello` advertises PQ capability over the
            // classical session (triggering `downgrade_detected + recommend_start_again`).
            bob.set_pq_config(PqConfig::default()).unwrap();
            let hello_pq = Kind::Hello(bob.make_hello("Bob", 11)).to_bytes();
            let msg = prepared2.session.encrypt(&hello_pq).unwrap();

            let c = inner.contact(&peer).unwrap();
            c.session = a_real;
            c.state.request = false;
            c.state.quarantined = true;
            inner.deferred_envelopes = vec![crate::vault::DeferredEnvelope {
                peer: peer.to_vec(),
                sequence: 50,
                message: Some(msg.message.clone()),
                initial_message: None,
                deferred_at: crate::util::now(),
                pq_isolated: false,
            }];
            inner.save_state().await.unwrap();
        }

        let claim_calls = Rc::new(Cell::new(0usize));
        {
            let c_ref = claim_calls.clone();
            let b_resp = bob_bundle.clone();
            let _mock = crate::transport::mock_fetch(move |_s, path, _b| {
                if path.ends_with("/RegisterWriteToken") {
                    Ok((200, RegisterWriteTokenResponse {}.encode_to_vec()))
                } else if path.ends_with("/ClaimBundle") {
                    c_ref.set(c_ref.get() + 1);
                    Ok((200, b_resp.encode_to_vec()))
                } else if path.ends_with("/SendInitialV2") {
                    Ok((200, SendInitialV2Response { id: 42 }.encode_to_vec()))
                } else if path.ends_with("/PushV2") {
                    Ok((
                        200,
                        protocol::mailbox_v2::PushV2Response { sequence: 1 }.encode_to_vec(),
                    ))
                } else {
                    panic!("unexpected path in approve_classical replay upgrade: {path}");
                }
            });
            // `approve_classical` unquarantines + replays the buffered `Hello` downgrade -> MUST
            // dispatch `upgrade_to_pq_auto` -> ClaimBundle!
            engine.approve_classical(peer).await.unwrap();
        }
        assert_eq!(
            claim_calls.get(),
            1,
            "approve_classical must dispatch PQ upgrade recommended during deferred replay"
        );
    });
}
