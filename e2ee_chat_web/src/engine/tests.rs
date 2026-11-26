#[cfg(not(target_arch = "wasm32"))]
use super::attachments::ChunkSource;
use super::attachments::{ResumeVerifier, expected_chunk_len, upload_of_with_digests};
use super::contact::{
    accept_contact_request_state, contact_state_is_new_quarantined, insert_acked_range, place_of,
    record_quarantined_initial_state, restore_contacts, stored_contacts,
};
use super::handshake::{
    DEFERRED_REPLAY_WINDOW_MS, Incoming, InitialBatch, JoinCarriedOutcome, PublishError,
    backfill_carried_timestamps_for_contacts, merge_legacy_deferred_initials,
    preserved_deferred_prekeys, prune_invalid_inbox_acks, refill_batch_counts,
    sanitize_deferred_initials, stage_carried_initials, stage_inbox_ack,
    validate_start_chat_server,
};
use super::outbox::CorruptOutboxRecovery;
use super::settings::{
    classify_set_pq_publish_result, describe_upgrade_pq_error,
    finalize_upgrade_to_pq_request_state, validate_pq_config_for_server,
};
use super::streaming::stream_mime;
use super::sync::{farewell_push_v2_request, resolve_stalled_peer};
use super::{
    EVENTS_KEPT, Engine, Inner, NAME_MAX, ONE_TIME_PREKEYS, OpenTracker, PqSaveOutcome,
    ProtocolRpcScope, REFILL_USED, SERVER_MAX_ONE_TIME_PREKEYS, Sending, StartChatError,
    VaultStore, build_invitation_link, checked_name, normalize_update_reason,
    parse_invitation_hash, same_server, sanitize_shared_name, should_require_update_for_rpc,
};
#[cfg(not(target_arch = "wasm32"))]
use super::{HISTORY_SHOWN, OpenOutcome};
use crate::content::{Contact as WireContact, Content, Events, Kind};
use crate::state::{Body, Delivery, Dialog, Me, Opening, ServerPqStatus, SharedContact, Step, Ui};
use crate::transport::{Connect, Fetch};
use crate::util::{hex, key_from_text, key_to_url, short, validate_relay_url};
use crate::vault::{
    AppState, Awaiting, CarriedDeferredTimestamp, ContactState, DeferredInitial,
    DeferredInitialsRecord, Farewell, HistoryEntry, Outgoing, OutgoingRecord, PendingUpload,
    UPLOAD_STATE_STARTED,
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
    deferred: RefCell<DeferredInitialsRecord>,
    entries: RefCell<HashMap<(PublicKey, u64), HistoryEntry>>,
    files: RefCell<HashMap<(PublicKey, u64), Vec<u8>>>,
    outbox: RefCell<HashMap<(PublicKey, u64), OutgoingRecord>>,
    chunks: RefCell<HashMap<MemoryChunkKey, Vec<u8>>>,
    uploads: RefCell<HashMap<(PublicKey, Vec<u8>), PendingUpload>>,
    fail_read_at: Cell<Option<u64>>,
    fail_history: Cell<bool>,
    fail_save: Cell<bool>,
    fail_put_chunk: Cell<bool>,
    fail_promote_upload: Cell<bool>,
    fail_forget: Cell<bool>,
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
        deferred: &DeferredInitialsRecord,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()> {
        if self.fail_save.get() {
            return Err(crate::vault::Error::Storage("write failed".into()));
        }
        self.state.replace(state.clone());
        self.deferred.replace(deferred.clone());
        self.apply_entries(entries);
        self.apply_outgoing(outgoing);
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
        deferred: &DeferredInitialsRecord,
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
        deferred: &DeferredInitialsRecord,
        peer: &PublicKey,
        entries: impl IntoIterator<Item = &'a (PublicKey, u64, HistoryEntry)>,
        outgoing: impl IntoIterator<Item = &'a (PublicKey, u64, Option<OutgoingRecord>)>,
    ) -> crate::vault::Result<()> {
        if self.fail_forget.get() || self.fail_save.get() {
            return Err(crate::vault::Error::Storage("forget failed".into()));
        }
        self.entries.borrow_mut().retain(|(p, _), _| p != peer);
        self.files.borrow_mut().retain(|(p, _), _| p != peer);
        self.outbox.borrow_mut().retain(|(p, _), _| p != peer);
        self.chunks.borrow_mut().retain(|(p, _, _), _| p != peer);
        self.uploads.borrow_mut().retain(|(p, _), _| p != peer);
        self.state.replace(state.clone());
        self.deferred.replace(deferred.clone());
        self.apply_entries(entries);
        self.apply_outgoing(outgoing);
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
        DeferredInitialsRecord::decode(vault.deferred.borrow().encode_to_vec().as_slice()).unwrap();
    let client = Client::restore(
        Fetch::client(TEST_SERVER),
        ClientState::try_from(&state.client.take().unwrap()).unwrap(),
    );
    let (contacts, isolated, _) = restore_contacts(
        std::mem::take(&mut state.contacts),
        &client.identity_key(),
        TEST_SERVER,
    );
    let _ = merge_legacy_deferred_initials(
        &mut deferred.entries,
        std::mem::take(&mut state.deferred_initials),
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
            DeferredInitialsRecord::default(),
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
fn isolated_peer_blocks_both_handshake_directions_until_forgotten() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let mut client = Client::new(Fetch::client(TEST_SERVER));
        let (peer, message) = carried_initial(&mut client).await;
        let mut corrupt = stored_contact(client.identity_key(), peer);
        corrupt.name = "Pinned Peer".into();
        corrupt.session.as_mut().unwrap().cursor = u64::MAX;
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
        corrupt.session.as_mut().unwrap().cursor = u64::MAX;

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
        valid_corrupt.session.as_mut().unwrap().cursor = u64::MAX;
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
            [waiting(0, false), waiting(3, false)]
        );
        assert!(!inner.contacts[0].state.needs_requeue_sealed);
        assert_eq!(
            outcome.outbox,
            [
                (
                    peer,
                    0,
                    Some(OutgoingRecord {
                        content: first.content.unwrap().kind.unwrap().to_bytes(),
                        ..Default::default()
                    })
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
fn carried_initial_and_cursor_commit_together_and_survive_a_failed_join_and_reload() {
    futures::executor::block_on(async {
        let engine = Engine::new(Ui::new());
        let mut client = Client::new(Fetch::client(TEST_SERVER));
        let (peer, initial) = carried_initial(&mut client).await;
        let mut inner = load_contacts(&client, vec![stored_contact(client.identity_key(), peer)]);
        let before = inner.contacts[0].snapshot();
        let initials = [initial.clone(), initial];
        change_session(&mut inner.contacts[0].session, |s| s.cursor = 8);
        inner.vault.fail_save.set(true);
        assert!(
            inner
                .persist_received_page(0, before.clone(), &initials, &[], &[])
                .await
                .is_err()
        );
        assert_eq!(inner.contacts[0].snapshot(), before);
        {
            let disk = inner.vault.state.borrow();
            assert_eq!(disk.contacts[0].session.as_ref().unwrap().cursor, 0);
            assert!(disk.contacts[0].pending_carried_initials.is_empty());
        }
        inner.vault.fail_save.set(false);
        change_session(&mut inner.contacts[0].session, |s| s.cursor = 8);
        inner
            .persist_received_page(0, before, &initials, &[], &[])
            .await
            .unwrap();
        let mut inner = reload(inner.vault);
        let pending = inner.contacts[0].state.pending_carried_initials.clone();
        assert_eq!(pending.len(), 1);
        assert_eq!(inner.contacts[0].snapshot().0.cursor, 8);
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
            assert_eq!(session.cursor, 8);
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

fn legacy_wire_initial(ephemeral: u8) -> protocol::handshake::InitialMessage {
    protocol::handshake::InitialMessage {
        identity_key: vec![1; 32].into(),
        ephemeral_key: vec![ephemeral; 32].into(),
        signed_prekey: vec![2; 32].into(),
        first_message: Some(Default::default()),
        ..Default::default()
    }
}

#[test]
fn staging_bounds_distinct_carried_initials_and_preserves_legacy_wire_bytes() {
    let mut state = ContactState::default();
    for i in 0..=128 {
        let wire = legacy_wire_initial(i);
        let initial = Incoming::try_from(&WireInitialMessageV2::from(&wire)).unwrap();
        let staged = stage_carried_initials(&mut state, [&initial, &initial]);
        if i < 128 {
            staged.unwrap();
            assert_eq!(
                state.pending_carried_initials[usize::from(i)],
                wire.encode_to_vec()
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
        for bytes in [vec![0xff], legacy_wire_initial(3).encode_to_vec()] {
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
fn empty_receive_persists_changed_cursor_and_receipts_and_skips_idle_writes() {
    futures::executor::block_on(async {
        let (mut inner, peer) = unlocked_client();
        change_session(&mut inner.contacts[0].session, |s| {
            s.cursor = 3;
            s.delivered
                .push(vec![1; protocol::mailbox::DELIVERY_TOKEN_LENGTH]);
        });
        inner.save(&[]).await.unwrap();
        let before = inner.contacts[0].snapshot();
        for fail in [true, false] {
            inner.vault.fail_save.set(fail);
            let (page, snapshot) = inner
                .fetch_page(0, async |session, _, _| {
                    change_session(session, |s| {
                        s.cursor = 12;
                        s.delivered.clear();
                    });
                    Ok(Vec::<()>::new())
                })
                .await
                .unwrap();
            assert!(page.is_empty());
            let result = inner.persist_empty_page_progress(&peer, snapshot).await;
            let disk = inner.vault.state.borrow();
            let saved = disk.contacts[0].session.as_ref().unwrap();
            if fail {
                assert!(result.is_err());
                assert_eq!(inner.contacts[0].snapshot(), before);
                assert_eq!(saved, &before.0);
            } else {
                assert_eq!(result, Ok(true));
                assert_eq!(saved.cursor, 12);
                assert!(saved.delivered.is_empty());
            }
        }
        inner.vault.fail_save.set(true);
        let unchanged = inner.contacts[0].snapshot();
        assert_eq!(
            inner.persist_empty_page_progress(&peer, unchanged).await,
            Ok(false)
        );
        assert!(!inner.needs_save());
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
        inner.save_full_publish_success().await.unwrap();
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
            Some(OutgoingRecord {
                content: Kind::Text("retry".into()).to_bytes(),
                ..Default::default()
            }),
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
        assert!(engine.publish_waits_settings.get());
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
        assert!(engine2.publish_waits_settings.get());
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
        ..WireInitialMessageV2::from(&legacy_wire_initial(9))
    };
    let mut batch = InitialBatch::default();
    engine.process_inbox_messages(
        &mut inner,
        ListedInitialMessages {
            messages: vec![Incoming::try_from(&wire).unwrap()],
            malformed_ids: vec![],
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
        assert_eq!(
            join,
            JoinCarriedOutcome {
                recommend_upgrade: false,
                has_deferred: true,
            }
        );
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
        // initial succeeds cleanly without cursor rollback!
        let before = inner.contacts[0].snapshot();
        inner
            .persist_received_page(0, before, &[supported], &[], &[])
            .await
            .unwrap();
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
        assert!(inner.vault.state.borrow().deferred_initials.is_empty());
        assert!(inner.vault.state.borrow().pending_inbox_acks.is_empty());

        inner.vault.fail_save.set(false);
        inner.save(&[]).await.unwrap();
        // Separate record holds the deferred initial; `AppState` tag 12 remains empty!
        assert!(inner.vault.state.borrow().deferred_initials.is_empty());
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
        corrupt_isolated.session.as_mut().unwrap().cursor = u64::MAX;

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
    ];
    assert!(merge_legacy_deferred_initials(
        &mut entries,
        vec![dup_other_id]
    ));

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

#[test]
fn stalled_receive_pauses_without_skipping_when_peer_has_deferred_initial() {
    let (mut inner, peer) = unlocked_client();
    change_session(&mut inner.contacts[0].session, |s| {
        s.cursor = 4;
        s.stalled_through = 12;
        s.skip_through = 0;
    });

    // 1. Deferred carried initial pauses receive and preserves skip_through == 0.
    assert!(resolve_stalled_peer(
        &mut inner,
        &peer,
        JoinCarriedOutcome {
            recommend_upgrade: false,
            has_deferred: true,
        },
    ));
    assert_eq!(
        proto::SessionState::from(inner.contacts[0].session.state()).skip_through,
        0
    );

    // 2. Deferred inbox initial for `peer` also pauses receive and preserves skip_through == 0.
    let deferred_wire = WireInitialMessageV2 {
        version: 2,
        identity_key: Bytes::copy_from_slice(&peer),
        ephemeral_key: Bytes::from_static(&[0x55; 32]),
        signed_prekey: Bytes::from_static(&[0x66; 32]),
        first_message: Some(party::EncryptedMessage::default()),
        pq_suite: PqSuite::MlKem1024.as_u8().into(),
        pq_last_resort: true,
        pq_prekey_id: Bytes::from_static(&[0x77; 32]),
        pq_ciphertext: Bytes::from(vec![0x88; PqSuite::MlKem1024.ct_len()]),
        ..Default::default()
    };
    inner.deferred_initials.push(DeferredInitial {
        initial: Some(deferred_wire),
        deferred_at: 1_000,
    });
    assert!(resolve_stalled_peer(
        &mut inner,
        &peer,
        JoinCarriedOutcome::default(),
    ));
    assert_eq!(
        proto::SessionState::from(inner.contacts[0].session.state()).skip_through,
        0
    );

    // 3. Once no deferred initials remain for `peer`, stalled receive calls skip_stalled().
    inner.deferred_initials.clear();
    assert!(!resolve_stalled_peer(
        &mut inner,
        &peer,
        JoinCarriedOutcome::default(),
    ));
    assert_eq!(
        proto::SessionState::from(inner.contacts[0].session.state()).skip_through,
        12
    );
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
        assert!(inner.vault.state.borrow().deferred_initials.is_empty());
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
fn legacy_farewell_without_client_message_id_derives_deterministic_id() {
    let encrypted = party::EncryptedMessage {
        header: Bytes::from_static(b"ratchet-header"),
        content: Bytes::from_static(b"encrypted-farewell-body"),
    };
    let expected_id = session::Sealed::client_message_id_for(&encrypted);
    assert_eq!(expected_id.len(), 16);

    let legacy_farewell = Farewell {
        push: Some(session::protocol::mailbox::PushRequest {
            sender: Bytes::from_static(&[0x11; 32]),
            recipient: Bytes::from_static(&[0x22; 32]),
            message: Some(encrypted.clone()),
            initial_message: None,
            delivery_hash: Bytes::from_static(&[0x33; 32]),
        }),
        client_message_id: vec![],
        push_v2: vec![],
    };

    let first = farewell_push_v2_request(&legacy_farewell);
    let retry = farewell_push_v2_request(&legacy_farewell);
    assert_eq!(first.client_message_id.as_ref(), &expected_id);
    assert_eq!(
        first, retry,
        "retries must derive identical client_message_id"
    );

    // Existing explicit 16-byte client_message_id is preserved verbatim.
    let explicit_farewell = Farewell {
        client_message_id: vec![0xAB; 16],
        ..legacy_farewell.clone()
    };
    assert_eq!(
        farewell_push_v2_request(&explicit_farewell)
            .client_message_id
            .as_ref(),
        &[0xAB; 16]
    );

    // A push_v2 farewell with empty client_message_id also backfills the deterministic ID.
    let v2_without_cid = PushV2Request {
        sender: Bytes::from_static(&[0x11; 32]),
        recipient: Bytes::from_static(&[0x22; 32]),
        message: Some(encrypted),
        initial_message: None,
        delivery_hash: Bytes::new(),
        client_message_id: Bytes::new(),
    };
    let v2_farewell = Farewell {
        push: None,
        client_message_id: vec![],
        push_v2: v2_without_cid.encode_to_vec(),
    };
    assert_eq!(
        farewell_push_v2_request(&v2_farewell)
            .client_message_id
            .as_ref(),
        &expected_id
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
        GREETING_DELIVERY_CONFIRMED, GREETING_DELIVERY_LEGACY_UNKNOWN, GREETING_DELIVERY_UNCERTAIN,
        GREETING_DELIVERY_UNSENT,
    };

    let client = Client::new(Fetch::client(TEST_SERVER));
    let peer = Client::new(Fetch::client(TEST_SERVER)).identity_key();
    let mut inner = load_contacts(&client, vec![stored_contact(client.identity_key(), peer)]);

    // Greeting delivery states distinguish:
    // - LEGACY_UNKNOWN (0): WithoutInitial if active session still carries an initial, else Normal;
    // - UNSENT (never attempted / definitively refused) -> suppress farewell completely;
    // - UNCERTAIN (lost response / post-success save failure) -> farewell with `initial_message = None`;
    // - CONFIRMED -> normal farewell.
    {
        let contact = inner.contact(&peer).unwrap();
        assert_eq!(
            contact.state.greeting_delivery,
            GREETING_DELIVERY_LEGACY_UNKNOWN
        );
        // Without a carried initial message, legacy unknown sends a normal farewell.
        assert!(!contact.has_carried_initial());
        assert_eq!(contact.farewell_mode(), FarewellMode::Normal);
        // With a carried initial message, legacy unknown strips the initial (`WithoutInitial`).
        let mut carried_recipient = Client::new(Fetch::client(TEST_SERVER));
        let carried_peer = carried_recipient.identity_key();
        let published = carried_recipient
            .prepare_publish_v2("chat.example", 1, 1)
            .unwrap();
        let p = &published.request;
        let bundle = protocol::handshake_v2::ClaimBundleResponse {
            signed_prekey: p.manifest.as_ref().unwrap().signed_prekey.clone(),
            signed_prekey_signature: p.signed_prekey_signature.clone(),
            one_time_prekey: p.one_time_prekeys.first().cloned(),
            pq_last_resort: p.pq_last_resort.first().cloned(),
            pq_one_time_prekey: p.pq_one_time_prekeys.first().cloned(),
            manifest: p.manifest.clone(),
        };
        carried_recipient.commit_publish_v2(published);
        let mut carried_sender =
            Client::new(ConnectClient::new(BundleResponse("/ClaimBundle", bundle)));
        let prepared = futures::executor::block_on(carried_sender.prepare_initiate_v2(
            "chat.example",
            &carried_peer,
            &Default::default(),
            &Kind::Text("hello".into()).to_bytes(),
            Fetch::client(TEST_SERVER),
        ))
        .unwrap();
        let legacy_carried_contact = super::contact::Contact {
            peer: carried_peer,
            session: prepared.session,
            deferred_carried: 0,
            state: ContactState {
                peer: carried_peer.to_vec(),
                greeting_delivery: GREETING_DELIVERY_LEGACY_UNKNOWN,
                ..ContactState::default()
            },
        };
        assert!(legacy_carried_contact.has_carried_initial());
        assert_eq!(
            legacy_carried_contact.farewell_mode(),
            FarewellMode::WithoutInitial
        );

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
    let mut t = engine_close.open_tracker.get();
    let open_gen = t.begin_open(peer);
    engine_close.open_tracker.set(t);
    assert!(engine_close.open_tracker.get().is_current(open_gen));
    engine_close.cancel_pending_open();
    assert!(!engine_close.open_tracker.get().is_current(open_gen));
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
    engine.can_sign_in_here.set(true);
    let draft = PendingNewChat {
        key: "peer-key".into(),
        name: "Bob".into(),
        server: None,
        pq_pinned: false,
        allow_classical: false,
        auto_start: true,
    };
    let submit_id = engine.begin_new_chat_submit(draft);
    engine.in_flight_start_chat.set(Some((submit_id, true)));
    engine.refused_for_sign_in();
    assert_eq!(engine.pending_auto_start_id(), None);
    assert_eq!(engine.ui().dialog.get_untracked(), Some(Dialog::SignIn));

    // 3. `is_settled_on` requires history to actually be loaded for `peer`, and per-row reactive
    // signals update delivery ticks in O(1) without replacing row signals on same-peer refresh.
    let mut tracker = engine.open_tracker.get();
    let _ = tracker.begin_open(bob_peer);
    engine.open_tracker.set(tracker);
    engine.ui().open.set(Some(bob_peer));
    assert!(!engine.is_settled_on(bob_peer));
    *engine.displayed_history.borrow_mut() = Some(super::DisplayedHistory {
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

    engine.clear_displayed_messages();
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
    engine.in_flight_start_chat.set(Some((submit_id_2, true)));
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
fn resolve_stalled_pauses_existing_quarantined_contacts_and_session_seq_is_monotonic() {
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
    // Existing contact with a quarantined inbound classical session must pause without skipping
    // queued messages encrypted under the pending classical session.
    assert!(super::sync::resolve_stalled_peer(
        &mut inner,
        &peer,
        super::handshake::JoinCarriedOutcome::default(),
    ));

    // Once quarantine lifts, stalling skips normally.
    inner.contact(&peer).unwrap().state.quarantined = false;
    assert!(!super::sync::resolve_stalled_peer(
        &mut inner,
        &peer,
        super::handshake::JoinCarriedOutcome::default(),
    ));

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
        },
        Awaiting {
            place: 20,
            history_index: 2,
            read: false,
            attachment: true,
        },
    ];
    // Sealed pending outbox entries (push succeeded on relay, ack lost locally) + unsealed entry.
    contact.state.outbox = vec![
        Outgoing {
            history_index: 3,
            sealed: true,
            clock: 30,
            awaits_upload: false,
        },
        Outgoing {
            history_index: 4,
            sealed: true,
            clock: 40,
            awaits_upload: false,
        },
        Outgoing {
            history_index: 5,
            sealed: false,
            clock: 0,
            awaits_upload: false,
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
            CLASSICAL_APPROVAL_LEGACY, CLASSICAL_APPROVAL_NONE, SECURITY_ALERT_NONE,
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
            contact.state.classical_approval_needed = CLASSICAL_APPROVAL_LEGACY;
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
            CLASSICAL_APPROVAL_LEGACY
        );
    });
}

#[test]
fn unlock_backfills_carried_timestamps_for_restored_contacts() {
    #[cfg_attr(feature = "ml-kem-1024", allow(unused_mut))]
    let (mut inner, peer) = unlocked_client();
    let spk = [0x44u8; 32];
    // Encode an unsupported-suite carried initial (in PQ builds, pick a suite if unsupported, or
    // verify zero-timestamp backfill on existing `CarriedDeferredTimestamp` entries as well).
    let mut timestamps = vec![CarriedDeferredTimestamp {
        signed_prekey: spk.to_vec(),
        deferred_at: 0,
    }];
    assert!(backfill_carried_timestamps_for_contacts(
        &mut timestamps,
        inner.contacts.iter(),
        12_345,
    ));
    assert_eq!(timestamps[0].deferred_at, 12_345);
    assert!(!backfill_carried_timestamps_for_contacts(
        &mut timestamps,
        inner.contacts.iter(),
        99_999,
    ));

    #[cfg(not(feature = "ml-kem-1024"))]
    {
        let wire = unsupported_wire_initial(peer, 0);
        let carried = protocol::mailbox_v2::encode_carried_initial(&wire)
            .unwrap()
            .to_vec();
        inner.contacts[0]
            .state
            .pending_carried_initials
            .push(carried);
        let mut missing = Vec::new();
        assert!(backfill_carried_timestamps_for_contacts(
            &mut missing,
            inner.contacts.iter(),
            55_000,
        ));
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].signed_prekey, vec![0x66; 32]);
        assert_eq!(missing[0].deferred_at, 55_000);
    }
    let _ = peer;
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
    engine.cancelled.borrow_mut().insert(id_a);
    assert!(engine.is_cancelled(&id_a));
    assert!(!engine.is_cancelled(&id_b));

    engine
        .sending
        .borrow_mut()
        .push_back(Sending::Content(peer_a, Kind::Text("stale".into())));
    engine
        .sending
        .borrow_mut()
        .push_back(Sending::Content(peer_b, Kind::Text("keep".into())));
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
    assert_eq!(engine.sending.borrow().len(), 1);
    assert_eq!(engine.sending.borrow()[0].peer(), peer_b);
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
        inner.contacts[0].state.outbox =
            vec![waiting(0, true), waiting(1, true), waiting(2, false)];
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
        DeferredInitialsRecord::default(),
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
        let ct0 = encrypt_chunk(&key, 0, false, &chunk0_plain);
        let ct1 = encrypt_chunk(&key, 1, true, &chunk1_plain);

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
        engine.decrypted.borrow_mut().clear();
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
        let fetching = engine.streams.borrow().get(token).unwrap().fetching.clone();
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
        engine.files.borrow_mut().insert(
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
        assert!(engine.waits_sign_in.borrow().contains(&peer));
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
        engine.files.borrow_mut().insert(
            (alice_peer, alice_upload_id, alice_key_hash),
            ChunkSource::from_bytes("a.bin", "application/octet-stream", vec![1, 2, 3]),
        );
        engine.files.borrow_mut().insert(
            (bob_peer, bob_upload_id, bob_key_hash),
            ChunkSource::from_bytes("b.bin", "application/octet-stream", vec![4, 5, 6]),
        );
        engine.decrypted.borrow_mut().push_back((
            (alice_peer, alice_upload_id, alice_key_hash, 0),
            Rc::new(zeroize::Zeroizing::new(vec![1])),
        ));
        engine.decrypted.borrow_mut().push_back((
            (bob_peer, bob_upload_id, bob_key_hash, 0),
            Rc::new(zeroize::Zeroizing::new(vec![2])),
        ));
        engine
            .sending
            .borrow_mut()
            .push_back(Sending::Content(alice_peer, Kind::Text("drop".into())));
        engine
            .sending
            .borrow_mut()
            .push_back(Sending::Content(bob_peer, Kind::Text("stay".into())));
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
        assert_eq!(engine.files.borrow().len(), 1);
        assert!(engine.files.borrow().keys().all(|(p, _, _)| *p == bob_peer));
        assert_eq!(engine.decrypted.borrow().len(), 1);
        assert!(
            engine
                .decrypted
                .borrow()
                .iter()
                .all(|((p, _, _, _), _)| *p == bob_peer)
        );
        assert_eq!(engine.streams.borrow().len(), 1);
        assert!(
            engine
                .streams
                .borrow()
                .values()
                .all(|s| s.fetching.peer == bob_peer)
        );
        assert_eq!(engine.sending.borrow().len(), 1);
        assert_eq!(engine.sending.borrow()[0].peer(), bob_peer);
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
