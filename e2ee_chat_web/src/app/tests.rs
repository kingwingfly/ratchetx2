use session::PqSuite;

use crate::{
    state::{ClassicalPrompt, ContactView, SecurityAlert, SecurityView},
    util::{hex, key_to_text, key_to_url},
};

use super::{
    chat::{contact_can_upgrade_to_pq, security_badge_parts},
    composer::should_autofocus_composer,
    files::file_status_suffix,
    history::{ChatHistory, HistoryOp, MAX_ENTRIES, Reservation, Transition, UiAction},
    sidebar::chat_item_meta,
    viewer::preview_fragment_candidates,
};

fn sample_contact() -> ContactView {
    ContactView {
        peer: [7; 32],
        name: "Alice".to_string(),
        request: false,
        hello_name: String::new(),
        unread: 0,
        last_activity: 0,
        security: SecurityView::default(),
        has_active_session: false,
        pq_pinned: false,
        peer_pq_capable: false,
        allow_classical_exception: false,
        downgrade_detected: false,
        alert: SecurityAlert::None,
        classical_prompt: ClassicalPrompt::None,
    }
}

#[test]
fn retired_pq_pinned_session_shows_neutral_ended_badge_and_not_classical() {
    let mut contact = sample_contact();
    contact.pq_pinned = true;
    contact.has_active_session = false;
    contact.security = SecurityView::default();

    let (class, compact, title) = security_badge_parts(&contact, false);
    assert_eq!(class, "sec-badge neutral");
    assert_eq!(compact, "PQ · Session ended");
    assert_eq!(
        title,
        "Session ended; post-quantum encryption is pinned for the next session"
    );

    let (class, detailed, _) = security_badge_parts(&contact, true);
    assert_eq!(class, "sec-badge neutral");
    assert_eq!(
        detailed,
        "Session ended — next message starts a new post-quantum session"
    );
    assert!(
        !contact_can_upgrade_to_pq(&contact),
        "retired pq_pinned session must not offer Upgrade to PQ as if it were classical"
    );
}

#[test]
fn retired_unpinned_session_shows_neutral_ended_badge() {
    let contact = sample_contact();

    let (class, compact, title) = security_badge_parts(&contact, false);
    assert_eq!(class, "sec-badge neutral");
    assert_eq!(compact, "Session ended");
    assert_eq!(
        title,
        "No active session — next message starts a new session"
    );

    let (class, detailed, _) = security_badge_parts(&contact, true);
    assert_eq!(class, "sec-badge neutral");
    assert_eq!(
        detailed,
        "No active session — next message starts a new session"
    );
    assert!(!contact_can_upgrade_to_pq(&contact));
}

#[test]
fn downgrade_takes_precedence_even_without_active_session() {
    let mut contact = sample_contact();
    contact.pq_pinned = true;
    contact.downgrade_detected = true;

    let (class, label, _) = security_badge_parts(&contact, false);
    assert_eq!(class, "sec-badge danger");
    assert_eq!(label, "Downgrade detected");
    assert!(contact_can_upgrade_to_pq(&contact));
}

#[test]
fn active_sessions_show_pq_or_classical_badges_and_upgrade_rules() {
    let mut classical = sample_contact();
    classical.has_active_session = true;
    let (class, label, _) = security_badge_parts(&classical, false);
    assert_eq!(class, "sec-badge classical");
    assert_eq!(label, "Classical only");
    assert!(contact_can_upgrade_to_pq(&classical));

    let mut pq = sample_contact();
    pq.has_active_session = true;
    pq.pq_pinned = true;
    pq.security = SecurityView {
        is_pq: true,
        suite: Some(PqSuite::MlKem1024.as_u8()),
        pq_ratchet: true,
    };
    let (class, compact, _) = security_badge_parts(&pq, false);
    assert_eq!(class, "sec-badge pq");
    assert_eq!(compact, "PQ · ML-KEM-1024 + Ratchet");
    let (class, detailed, _) = security_badge_parts(&pq, true);
    assert_eq!(class, "sec-badge pq");
    assert_eq!(detailed, "Quantum-resistant · ML-KEM-1024 + PQ Ratchet");
    assert!(!contact_can_upgrade_to_pq(&pq));

    let mut quarantined = sample_contact();
    quarantined.has_active_session = true;
    quarantined.classical_prompt = ClassicalPrompt::InboundQuarantined {
        peer_was_pq_pinned: false,
    };
    assert!(contact_can_upgrade_to_pq(&quarantined));
    let (class, compact, title) = security_badge_parts(&quarantined, false);
    assert_eq!(class, "sec-badge classical");
    assert_eq!(compact, "Quarantined");
    assert_eq!(title, "Classical chat quarantined — review before replying");
    let (class, detailed, _) = security_badge_parts(&quarantined, true);
    assert_eq!(class, "sec-badge classical");
    assert_eq!(
        detailed,
        "Classical chat quarantined — review before replying"
    );
}

#[test]
fn chat_item_meta_distinguishes_quarantined_chats_requests_and_alerts() {
    // Accepted quarantined chat -> warn style + "classical chat (quarantined)".
    let mut accepted_q = sample_contact();
    accepted_q.request = false;
    accepted_q.classical_prompt = ClassicalPrompt::InboundQuarantined {
        peer_was_pq_pinned: false,
    };
    assert_eq!(
        chat_item_meta(&accepted_q),
        (
            false,
            true,
            false,
            "classical chat (quarantined)".to_string()
        )
    );

    // Unaccepted quarantined request -> warn style + "classical request (quarantined)".
    let mut request_q = accepted_q.clone();
    request_q.request = true;
    assert_eq!(
        chat_item_meta(&request_q),
        (
            false,
            true,
            false,
            "classical request (quarantined)".to_string()
        )
    );

    // Downgraded + quarantined -> danger style.
    let mut downgrade_q = accepted_q;
    downgrade_q.downgrade_detected = true;
    assert_eq!(
        chat_item_meta(&downgrade_q),
        (
            false,
            false,
            true,
            "downgrade detected (quarantined)".to_string()
        )
    );

    // Outbound classical approval prompt -> warn style.
    let mut outbound = sample_contact();
    outbound.classical_prompt = ClassicalPrompt::Outbound {
        peer_signed_off: true,
    };
    assert_eq!(
        chat_item_meta(&outbound),
        (false, true, false, "classical approval needed".to_string())
    );

    // Security alerts -> warn style.
    let mut expired = sample_contact();
    expired.alert = SecurityAlert::ManifestExpired;
    assert_eq!(
        chat_item_meta(&expired),
        (false, true, false, "peer PQ manifest expired".to_string())
    );
    let mut strict = sample_contact();
    strict.alert = SecurityAlert::PqRequired;
    assert_eq!(
        chat_item_meta(&strict),
        (false, true, false, "PQ required (paused)".to_string())
    );
}

#[test]
fn file_status_suffix_distinguishes_local_cancelled_waiting_and_malformed() {
    assert_eq!(
        file_status_suffix(true, false, false, false, true),
        Some("stored locally")
    );
    assert_eq!(
        file_status_suffix(true, false, true, false, true),
        Some("not sent")
    );
    assert_eq!(
        file_status_suffix(false, true, false, false, true),
        Some("no longer on the server")
    );
    // Cancelled / failed sign-in-held upload must NOT show "waiting to upload".
    assert_eq!(
        file_status_suffix(false, false, true, false, true),
        Some("upload cancelled")
    );
    assert_eq!(
        file_status_suffix(false, false, false, true, true),
        Some("on server")
    );
    // Outgoing unuploaded non-failed attachment -> waiting to upload.
    assert_eq!(
        file_status_suffix(false, false, false, false, true),
        Some("waiting to upload")
    );
    // Malformed incoming remote pointer -> no misleading "waiting to upload".
    assert_eq!(file_status_suffix(false, false, false, false, false), None);
}

#[test]
fn composer_autofocus_is_disabled_on_portable_touch_devices() {
    // Desktop / laptop (hover-capable fine pointer): keep autofocus.
    assert!(should_autofocus_composer(false, false));
    // Phones and tablets (neither hover nor fine pointer): skip autofocus so the virtual keyboard
    // does not pop up automatically on entering a chat.
    assert!(!should_autofocus_composer(true, true));
    // Coarse primary pointer alone (e.g. touch device reporting hover support): skip autofocus.
    assert!(!should_autofocus_composer(false, true));
    // Non-hovering primary input alone (e.g. stylus-only portable device): skip autofocus.
    assert!(!should_autofocus_composer(true, false));
}

#[test]
fn preview_fragment_candidates_decodes_percent_encoded_ids() {
    assert_eq!(preview_fragment_candidates("https://example.com/#a"), None);
    assert_eq!(
        preview_fragment_candidates("#"),
        Some((String::new(), None))
    );
    assert_eq!(
        preview_fragment_candidates("#fn-1"),
        Some(("fn-1".to_string(), None))
    );
    assert_eq!(
        preview_fragment_candidates("#fn-n%6Fte"),
        Some(("fn-n%6Fte".to_string(), Some("fn-note".to_string())))
    );
    assert_eq!(
        preview_fragment_candidates("#fn-bad%ZZ"),
        Some(("fn-bad%ZZ".to_string(), None))
    );
}

#[test]
fn chat_history_open_and_back_gesture_returns_to_list_without_leaking_peer_key() {
    let alice = [0xA1; 32];
    let mut history = ChatHistory::new("sess01".to_string(), None, String::new());

    // Entering a chat from the chat list tags the list entry and pushes an opaque chat token
    // (never leaking the peer's public key).
    let entered = history.user_open(alice, "");
    let (list_token, chat_token) = match entered {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_token),
                    chat_token,
                }),
            ui: UiAction::Open(peer),
            ..
        } => {
            assert_eq!(peer, alice);
            (list_token, chat_token)
        }
        other => panic!("expected Push with list tag + Open(alice), got {other:?}"),
    };
    assert_eq!(list_token, "ratchetx2-list:sess01");
    assert!(chat_token.starts_with("ratchetx2-chat:sess01:"));
    assert!(!chat_token.contains(&hex(&alice)));
    assert!(!chat_token.contains(&key_to_text(&alice)));
    assert!(!chat_token.contains(&key_to_url(&alice)));

    // System "go back" gesture pops back to the tagged list entry -> closes chat and returns to
    // chat list without issuing an extra `history.back()`.
    assert_eq!(
        history.on_popstate(Some(&list_token), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );

    // Browser Forward gesture onto the chat token reopens Alice while the contact still exists.
    assert_eq!(
        history.on_popstate(Some(&chat_token), "", false, |p| *p == alice),
        Transition {
            history: None,
            ui: UiAction::Open(alice),
            dismiss_startup: false,
            fallback_active: None,
        }
    );

    // Going back again returns to the chat list cleanly.
    assert_eq!(
        history.on_popstate(Some(&list_token), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
}

#[test]
fn chat_history_tracks_manual_fragments_including_empty_hash_so_close_and_switch_reach_list() {
    let alice = [0xA2; 32];
    let bob = [0xB2; 32];
    let mut history = ChatHistory::new("sess-frag".to_string(), None, String::new());

    let (list_token, alice_token) = match history.user_open(alice, "") {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_token),
                    chat_token,
                }),
            ..
        } => (list_token, chat_token),
        other => panic!("expected Push, got {other:?}"),
    };

    // Manual `#one` then `#` (empty hash, null state) stacked above Alice must BOTH be treated as
    // fragment entries (NOT the tagged list entry!) and stamped with chat-bound fragment markers so
    // Alice stays open and stepping Back between fragments preserves exact depth.
    let frag_one = match history.on_popstate(None, "#one", false, |_| true) {
        Transition {
            history: Some(HistoryOp::Tag(tag)),
            ui: UiAction::None,
            ..
        } => tag,
        other => panic!("expected Tag for #one fragment, got {other:?}"),
    };
    assert!(frag_one.starts_with("ratchetx2-frag:sess-frag:"));
    assert!(frag_one.ends_with(":1"));
    let frag_empty = match history.on_popstate(None, "", false, |_| true) {
        Transition {
            history: Some(HistoryOp::Tag(tag)),
            ui: UiAction::None,
            ..
        } => tag,
        other => panic!("expected Tag for empty-# fragment, got {other:?}"),
    };
    assert!(frag_empty.ends_with(":2"));

    // Stepping Back manually from `#` (`depth 2`) to `#one` (`depth 1`) keeps Alice open with
    // exact depth 1; in-app Close then unwinds `#one` -> `alice_token` -> tagged list entry.
    assert_eq!(
        history.on_popstate(Some(&frag_one), "#one", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::None,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    assert!(matches!(
        history.user_close(),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert!(matches!(
        history.on_popstate(Some(&alice_token), "", false, |_| true),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert_eq!(
        history.on_popstate(Some(&list_token), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );

    // Direct Forward-menu jump from the list straight to `#one` resolves its underlying chat slot
    // and reopens Alice without overwriting `#one` with a list token.
    assert_eq!(
        history.on_popstate(Some(&frag_one), "#one", false, |p| *p == alice),
        Transition {
            history: None,
            ui: UiAction::Open(alice),
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    // Clicking Switch to Bob from `#one` starts unwinding `#one`; clicking Close BEFORE that
    // unwind settles redirects the traversal to close all the way to the list (not reopen Alice).
    assert!(matches!(
        history.user_open(bob, "#one"),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert_eq!(
        history.user_close(),
        Transition {
            history: None,
            ui: UiAction::None,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    assert!(matches!(
        history.on_popstate(Some(&alice_token), "", false, |p| *p == alice),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert_eq!(
        history
            .on_popstate(Some(&list_token), "", false, |_| true)
            .ui,
        UiAction::Close
    );

    // Peer switch while on `#frag` unwinds `#frag` back onto `alice_token` and replaces it in
    // place with Bob so one Back from Bob returns straight to the tagged list.
    let alice_token_2 = match history.user_open(alice, "") {
        Transition {
            history: Some(HistoryOp::Push { chat_token, .. }),
            ..
        } => chat_token,
        other => panic!("expected Push, got {other:?}"),
    };
    let frag_two = match history.on_popstate(None, "#frag", false, |_| true) {
        Transition {
            history: Some(HistoryOp::Tag(tag)),
            ..
        } => tag,
        other => panic!("expected Tag for #frag, got {other:?}"),
    };
    let switch_attempt = match history.user_open(bob, "#frag") {
        Transition {
            history: Some(HistoryOp::Back(attempt)),
            ui: UiAction::None,
            ..
        } => attempt,
        other => panic!("expected Back, got {other:?}"),
    };
    // If that fragment unwind times out while still on the fragment token, recovery recognizes
    // the fragment and replaces it in place with Bob instead of tagging it as a list and pushing.
    assert!(matches!(
        history.on_back_aborted(switch_attempt, Some(&frag_two), "#frag", |p| *p == bob),
        Transition {
            history: Some(HistoryOp::Replace(_)),
            ui: UiAction::Open(p),
            ..
        } if p == bob
    ));
    assert_eq!(
        history
            .on_popstate(Some(&list_token), "", false, |_| true)
            .ui,
        UiAction::Close
    );
    // Normal (non-timed-out) peer switch unwinds `#frag` onto `alice_token_2` and replaces it.
    let alice_token_3 = match history.user_open(alice, "") {
        Transition {
            history: Some(HistoryOp::Push { chat_token, .. }),
            ..
        } => chat_token,
        other => panic!("expected Push, got {other:?}"),
    };
    let _ = history.on_popstate(None, "#frag", false, |_| true);
    assert!(matches!(
        history.user_open(bob, "#frag"),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert!(matches!(
        history.on_popstate(Some(&alice_token_3), "", false, |p| *p == bob),
        Transition {
            history: Some(HistoryOp::Replace(_)),
            ui: UiAction::Open(p),
            ..
        } if p == bob
    ));
    let _ = alice_token_2;
    assert_eq!(
        history
            .on_popstate(Some(&list_token), "", false, |_| true)
            .ui,
        UiAction::Close
    );

    // Navigating to `#other` while on the list tags that new list entry immediately; jumping back
    // via browser Back menu from a chat to an earlier list entry `/` (tagged on initial load OR
    // even untagged if initial tagging failed) closes the chat instead of mistaking `/` for a
    // fragment above the chat!
    assert_eq!(
        history.on_popstate(None, "#other", false, |_| true),
        Transition {
            history: Some(HistoryOp::Tag(list_token.clone())),
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    assert!(matches!(
        history.user_open(alice, "#other"),
        Transition {
            history: Some(HistoryOp::Push { tag_list: None, .. }),
            ui: UiAction::Open(p),
            ..
        } if p == alice
    ));
    // Jump via Back menu straight to the earlier tagged `/` list entry -> closes Alice cleanly.
    assert_eq!(
        history
            .on_popstate(Some(&list_token), "", false, |_| true)
            .ui,
        UiAction::Close
    );

    // Even if tagging the initial `/` list entry failed (`on_list_tag_failed("")`), jumping back
    // from a chat opened on `#one` straight to untagged `/` (`None`, `""`) still closes the chat
    // instead of keeping it open and letting in-app Close leave the site!
    let mut untagged_root = ChatHistory::new("sess-untagged".to_string(), None, String::new());
    let init_tag = untagged_root
        .tag_current_list_entry()
        .expect("initial tag op");
    untagged_root.on_write_failed(&init_tag, None, "");
    let _ = untagged_root.on_popstate(None, "#one", false, |_| true);
    let _ = untagged_root.user_open(alice, "#one");
    assert_eq!(
        untagged_root.on_popstate(None, "", false, |_| true).ui,
        UiAction::Close
    );
}

#[test]
fn chat_history_switching_chats_replaces_single_entry_so_one_back_returns_to_list() {
    let alice = [0x11; 32];
    let bob = [0x22; 32];
    let mut history = ChatHistory::new("sess02".to_string(), None, String::new());

    // First chat pushes onto the stack.
    let list_token = match history.user_open(alice, "") {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_token),
                    ..
                }),
            ui: UiAction::Open(p),
            ..
        } if p == alice => list_token,
        other => panic!("expected Push + Open(alice), got {other:?}"),
    };

    // Clicking the already-open chat does not push or replace history.
    assert_eq!(
        history.user_open(alice, ""),
        Transition {
            history: None,
            ui: UiAction::Open(alice),
            dismiss_startup: false,
            fallback_active: None,
        }
    );

    // Switching directly to Bob replaces the current chat entry instead of stacking entries.
    let bob_token = match history.user_open(bob, "") {
        Transition {
            history: Some(HistoryOp::Replace(token)),
            ui: UiAction::Open(p),
            ..
        } => {
            assert_eq!(p, bob);
            token
        }
        other => panic!("expected Replace + Open(bob), got {other:?}"),
    };

    // One Back gesture returns directly to the chat list.
    assert_eq!(
        history.on_popstate(Some(&list_token), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );

    // Forward returns to Bob (the last chat on that entry).
    assert_eq!(
        history.on_popstate(Some(&bob_token), "", false, |p| *p == bob),
        Transition {
            history: None,
            ui: UiAction::Open(bob),
            dismiss_startup: false,
            fallback_active: None,
        }
    );
}

#[test]
fn chat_history_in_app_back_prevents_double_back_and_rolls_back_failed_deferred_push_to_list() {
    let alice = [0x33; 32];
    let bob = [0x44; 32];
    let mut history = ChatHistory::new("sess03".to_string(), None, String::new());

    let list_token = match history.user_open(alice, "") {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_token),
                    ..
                }),
            ..
        } => list_token,
        other => panic!("expected Push, got {other:?}"),
    };

    // First click on in-app Back issues a single `history.back()`.
    assert!(matches!(
        history.user_close(),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    // Rapid second click before `popstate` arrives must be ignored (never exit the site).
    assert_eq!(
        history.user_close(),
        Transition {
            history: None,
            ui: UiAction::None,
            dismiss_startup: false,
            fallback_active: None,
        }
    );

    // Opening Bob while `history.back()` is still settling defers Bob until `popstate` lands.
    assert_eq!(
        history.user_open(bob, ""),
        Transition {
            history: None,
            ui: UiAction::None,
            dismiss_startup: false,
            fallback_active: None,
        }
    );

    // Once `popstate(list)` lands on the list entry, Bob is pushed with `fallback_active == None`.
    let deferred = history.on_popstate(Some(&list_token), "", false, |p| *p == bob);
    assert_eq!(deferred.fallback_active, None);
    let push_op = match deferred {
        Transition {
            history: Some(op @ HistoryOp::Push { .. }),
            ui: UiAction::Open(p),
            ..
        } => {
            assert_eq!(p, bob);
            op
        }
        other => panic!("expected Push + Open(bob), got {other:?}"),
    };

    // If that deferred push fails or is throttled, rolling back restores the list entry (`None`),
    // NOT Alice's old entry — so in-app Close closes directly without calling `history.back()`
    // from the list and leaving the site.
    history.on_write_failed(&push_op, deferred.fallback_active, "");
    assert_eq!(
        history.user_close(),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
}

#[test]
fn chat_history_deleting_open_chat_pops_entry_without_trapping_forward() {
    let alice = [0x55; 32];
    let bob = [0x56; 32];
    let mut history = ChatHistory::new("sess04".to_string(), None, String::new());

    let (list_token, chat_token) = match history.user_open(alice, "") {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_token),
                    chat_token,
                }),
            ..
        } => (list_token, chat_token),
        other => panic!("expected Push, got {other:?}"),
    };

    // Deleting Alice closes `ui.open` externally -> pops the chat history entry.
    assert!(matches!(
        history.on_ui_closed(alice),
        Some(HistoryOp::Back(_))
    ));
    // Popstate arrives back on the list.
    assert_eq!(
        history.on_popstate(Some(&list_token), "", false, |_| false),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );

    // Pressing browser Forward onto Alice's now-deleted token stays on the list and marks the
    // slot reusable WITHOUT calling `history.back()`, so any later Forward pages remain reachable.
    assert_eq!(
        history.on_popstate(Some(&chat_token), "", false, |_| false),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    // Opening Bob from that stale slot reuses it via `Replace` (no extra Back stop stacked).
    assert!(matches!(
        history.user_open(bob, ""),
        Transition {
            history: Some(HistoryOp::Replace(_)),
            ui: UiAction::Open(p),
            ..
        } if p == bob
    ));
}

#[test]
fn chat_history_reservation_handles_back_dismissal_ownership_transfer_and_unwind_retry() {
    let alice = [0x88; 32];
    let bob = [0x89; 32];
    let mut history = ChatHistory::new("sess-res".to_string(), None, String::new());

    // Submitting NewChat on the list reserves an opaque entry immediately during the user gesture.
    let (reservation, list_token, chat_token) = match history.reserve("") {
        (
            res @ Reservation::Pushed(_),
            Some(HistoryOp::Push {
                tag_list: Some(list_token),
                chat_token,
            }),
        ) => (res, list_token, chat_token),
        other => panic!("expected (Pushed, Some(Push)), got {other:?}"),
    };
    // Committing binds that reserved token directly to Alice without pushing another entry.
    assert_eq!(
        history.commit_reservation(Some(reservation), alice, ""),
        Transition {
            history: None,
            ui: UiAction::Open(alice),
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    // Back returns to list, Forward reopens Alice via the reserved token.
    assert_eq!(
        history
            .on_popstate(Some(&list_token), "", false, |_| true)
            .ui,
        UiAction::Close
    );
    assert_eq!(
        history
            .on_popstate(Some(&chat_token), "", false, |p| *p == alice)
            .ui,
        UiAction::Open(alice)
    );
    assert_eq!(
        history
            .on_popstate(Some(&list_token), "", false, |_| true)
            .ui,
        UiAction::Close
    );

    // User Back popping a reservation while NewChat is still waiting on the relay dismisses the
    // startup dialog immediately AND causes a late commit to be ignored.
    let (res_back, _) = history.reserve("");
    assert_eq!(
        history.on_popstate(Some(&list_token), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::None,
            dismiss_startup: true,
            fallback_active: None,
        }
    );
    assert_eq!(
        history.commit_reservation(Some(res_back), alice, ""),
        Transition {
            history: None,
            ui: UiAction::None,
            dismiss_startup: false,
            fallback_active: None,
        }
    );

    // Submitting a second peer while a reserved slot is active (even beneath a manual `#fragment`!)
    // transfers ownership of the reserved slot so the older submission is immediately revoked.
    let (res_old, _) = history.reserve("");
    let _ = history.on_popstate(None, "#under", false, |_| true);
    let (res_new, op_new) = history.reserve("#under");
    assert!(matches!(res_new, Reservation::Pushed(_)));
    assert_eq!(op_new, None);
    assert!(!history.is_reservation_owned(Some(res_old)));
    assert!(history.is_reservation_owned(Some(res_new)));
    assert_eq!(
        history.commit_reservation(Some(res_old), alice, "#under"),
        Transition {
            history: None,
            ui: UiAction::None,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    assert_eq!(history.cancel_reservation(Some(res_old)), (false, None));
    // Unwind `#under` back to list via `cancel_active_reservation`.
    assert!(matches!(
        history.cancel_active_reservation(),
        Some(HistoryOp::Back(_))
    ));
    let _ = history.on_popstate(Some(&list_token), "", false, |_| true);

    // Clicking "Allow classical" retry while a failed first submit's programmatic `UnwindToList`
    // is still settling keeps the retry valid when the unwind's `popstate` lands.
    let (res_first, _) = history.reserve("");
    let (still_owned, unwind_op) = history.cancel_reservation(Some(res_first));
    assert!(still_owned);
    assert!(matches!(unwind_op, Some(HistoryOp::Back(_))));
    let (res_retry, retry_op) = history.reserve("");
    assert!(matches!(res_retry, Reservation::Unpushed { .. }));
    assert_eq!(retry_op, None);
    // Programmatic unwind finishes -> preserves the form (`dismiss_startup: false`) AND does NOT
    // supersede `res_retry`.
    assert_eq!(
        history.on_popstate(Some(&list_token), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::None,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    // Retry succeeds -> pushes and opens Alice cleanly!
    assert!(matches!(
        history.commit_reservation(Some(res_retry), alice, ""),
        Transition {
            history: Some(HistoryOp::Push { .. }),
            ui: UiAction::Open(p),
            ..
        } if p == alice
    ));
    let _ = history.on_popstate(Some(&list_token), "", false, |_| true);

    // If a manual `#frag` is pushed while a reserved submission is waiting on the relay:
    // 1. Stepping Back off `#frag` onto the live reservation token keeps the reservation intact.
    // 2. Committing while still on `#frag` unwinds the fragment and opens Bob cleanly.
    let (res_frag, frag_token) = match history.reserve("") {
        (res @ Reservation::Pushed(_), Some(HistoryOp::Push { chat_token, .. })) => {
            (res, chat_token)
        }
        other => panic!("expected (Pushed, Push), got {other:?}"),
    };
    assert_eq!(
        history.on_popstate(None, "#frag", false, |_| true).ui,
        UiAction::None
    );
    assert_eq!(
        history.on_popstate(Some(&frag_token), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::None,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    assert!(history.is_reservation_owned(Some(res_frag)));
    assert_eq!(
        history.on_popstate(None, "#frag2", false, |_| true).ui,
        UiAction::None
    );
    assert!(matches!(
        history.commit_reservation(Some(res_frag), bob, "#frag2"),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert!(matches!(
        history.on_popstate(Some(&frag_token), "", false, |p| *p == bob),
        Transition {
            history: Some(HistoryOp::Replace(_)),
            ui: UiAction::Open(p),
            ..
        } if p == bob
    ));
    let _ = history.on_popstate(Some(&list_token), "", false, |_| true);

    // Native Escape / OS dialog close cancels and unwinds the active pushed reservation so late
    // relay completion cannot open the dismissed chat.
    let (res_esc, _) = history.reserve("");
    assert!(matches!(
        history.cancel_active_reservation(),
        Some(HistoryOp::Back(_))
    ));
    assert!(!history.is_reservation_owned(Some(res_esc)));
    assert_eq!(
        history.on_popstate(Some(&list_token), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::None,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    assert_eq!(
        history.commit_reservation(Some(res_esc), alice, "").ui,
        UiAction::None
    );

    // Submitting SignIn/NewChat from an ALREADY-OPEN chat gets `Reservation::Unpushed`: pressing
    // browser Back closes the chat AND dismisses/cancels the startup modal (`dismiss_startup: true`).
    let alice_live_token = match history.user_open(alice, "") {
        Transition {
            history: Some(HistoryOp::Push { chat_token, .. }),
            ..
        } => chat_token,
        other => panic!("expected Push, got {other:?}"),
    };
    let (res_unpushed, op_unpushed) = history.reserve("");
    assert!(matches!(res_unpushed, Reservation::Unpushed { .. }));
    assert_eq!(op_unpushed, None);
    assert_eq!(
        history.on_popstate(Some(&list_token), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: true,
            fallback_active: None,
        }
    );
    assert!(!history.is_reservation_owned(Some(res_unpushed)));
    assert_eq!(
        history.commit_reservation(Some(res_unpushed), bob, "").ui,
        UiAction::None
    );

    // If a reservation push fails on the list (giving `Unpushed`) and the user takes browser
    // Forward onto a live chat (`alice_live_token`), the superseded startup is ALSO cancelled and
    // dismissed (`dismiss_startup: true`) alongside `Open(alice)`.
    let (_, failed_op) = history.reserve("");
    let failed_res = history.on_reserve_push_failed(failed_op.as_ref().expect("push op"), "");
    assert_eq!(
        history.on_popstate(Some(&alice_live_token), "", false, |p| *p == alice),
        Transition {
            history: None,
            ui: UiAction::Open(alice),
            dismiss_startup: true,
            fallback_active: None,
        }
    );
    assert!(!history.is_reservation_owned(Some(failed_res)));
}

#[test]
fn chat_history_reuses_pre_reload_slot_reconciles_locked_back_and_honors_back_after_timeout() {
    let alice = [0x91; 32];
    let bob = [0x92; 32];

    // Reloading/locking while a chat token is in `history.state` starts in `Reusable` mode: the
    // first chat open replaces in place rather than stacking another Back stop.
    let mut reloaded = ChatHistory::new(
        "new-sess".to_string(),
        Some("ratchetx2-chat:old-sess:7"),
        String::new(),
    );
    assert!(matches!(
        reloaded.user_open(alice, ""),
        Transition {
            history: Some(HistoryOp::Replace(_)),
            ui: UiAction::Open(p),
            ..
        } if p == alice
    ));
    // One Back gesture returns directly to the list (pre-reload null/old list state).
    assert_eq!(
        reloaded.on_popstate(None, "", false, |_| true).ui,
        UiAction::Close
    );

    // If the user reloads on a chat token and steps Back to the list WHILE LOCKED, locked
    // `popstate` clears the reusable slot so the first chat opened after unlock pushes above the
    // list instead of replacing it (ensuring Back returns to the list, not off the site).
    let mut locked_back = ChatHistory::new(
        "locked-sess".to_string(),
        Some("ratchetx2-chat:old-sess:9"),
        String::new(),
    );
    assert!(matches!(
        locked_back.on_locked_popstate(Some("ratchetx2-list:old-sess")),
        Some(HistoryOp::Tag(tag)) if tag == "ratchetx2-list:locked-sess"
    ));
    assert!(matches!(
        locked_back.user_open(alice, ""),
        Transition {
            history: Some(HistoryOp::Push { tag_list: None, .. }),
            ui: UiAction::Open(p),
            ..
        } if p == alice
    ));

    // If the timeout fires before a slow `history.back()` dispatches `popstate`:
    // 1. UI closes directly;
    // 2. Late `popstate(list)` lands cleanly AND Forward onto `alice_token` STILL reopens Alice!
    let mut slow_back = ChatHistory::new("sess-slow".to_string(), None, String::new());
    let (list_token, alice_token) = match slow_back.user_open(alice, "") {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_token),
                    chat_token,
                }),
            ..
        } => (list_token, chat_token),
        other => panic!("expected Push, got {other:?}"),
    };
    let attempt = match slow_back.user_close() {
        Transition {
            history: Some(HistoryOp::Back(attempt)),
            ui: UiAction::None,
            ..
        } => attempt,
        other => panic!("expected Back, got {other:?}"),
    };
    assert_eq!(
        slow_back.on_back_aborted(attempt, Some(&alice_token), "", |_| true),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    assert_eq!(
        slow_back
            .on_popstate(Some(&list_token), "", false, |_| true)
            .ui,
        UiAction::Close
    );
    assert_eq!(
        slow_back.on_popstate(Some(&alice_token), "", false, |p| *p == alice),
        Transition {
            history: None,
            ui: UiAction::Open(alice),
            dismiss_startup: false,
            fallback_active: None,
        }
    );

    // If `history.back()` was ignored while the user switched to Bob, timeout recovery opens Bob
    // via `Replace`, and a subsequent genuine browser Back returns to the list on the FIRST
    // gesture (never undone or re-pushed!).
    let attempt2 = match slow_back.user_close() {
        Transition {
            history: Some(HistoryOp::Back(a)),
            ..
        } => a,
        other => panic!("expected Back, got {other:?}"),
    };
    assert_eq!(slow_back.user_open(bob, "").ui, UiAction::None);
    let recovered = slow_back.on_back_aborted(attempt2, Some(&alice_token), "", |p| *p == bob);
    assert!(matches!(
        recovered,
        Transition {
            history: Some(HistoryOp::Replace(_)),
            ui: UiAction::Open(p),
            ..
        } if p == bob
    ));
    assert_eq!(
        slow_back.on_popstate(Some(&list_token), "", false, |p| *p == bob),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
}

#[test]
fn chat_history_rebinds_failed_replace_and_handles_failed_push_and_open() {
    let alice = [0x66; 32];
    let bob = [0x77; 32];
    let mut history = ChatHistory::new("current-sess".to_string(), None, String::new());

    // If `pushState` fails/is silently ignored, rolling back ensures in-app Back closes directly
    // instead of calling `history.back()` and exiting the site.
    let pushed = history.user_open(alice, "");
    let op = pushed.history.expect("push op");
    history.on_write_failed(&op, pushed.fallback_active, "");
    assert_eq!(
        history.user_close(),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );

    // Open Alice successfully, then switch to Bob with a failed/ignored `replaceState`: the
    // surviving token (`alice_token`) must rebind to Bob so Forward and `on_ui_closed(bob)` match
    // the displayed chat.
    let list_token = "ratchetx2-list:current-sess";
    let alice_token = match history.user_open(alice, "") {
        Transition {
            history: Some(HistoryOp::Push { chat_token, .. }),
            ..
        } => chat_token,
        other => panic!("expected Push, got {other:?}"),
    };
    let replace = history.user_open(bob, "");
    let replace_op = replace.history.expect("replace op");
    history.on_write_failed(&replace_op, replace.fallback_active, "");
    // Back -> Forward onto the surviving token reopens Bob (the displayed chat), NOT Alice.
    assert_eq!(
        history
            .on_popstate(Some(list_token), "", false, |_| true)
            .ui,
        UiAction::Close
    );
    assert_eq!(
        history.on_popstate(Some(&alice_token), "", false, |p| *p == bob),
        Transition {
            history: None,
            ui: UiAction::Open(bob),
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    // Deleting Bob still pops the surviving entry.
    assert!(matches!(
        history.on_ui_closed(bob),
        Some(HistoryOp::Back(_))
    ));
    let _ = history.on_popstate(Some(list_token), "", false, |_| true);

    // If opening a peer fails (`OpenOutcome::Ignored`), reconcile back to actual_open.
    let _ = history.user_open(alice, "");
    assert!(matches!(
        history.on_open_failed(alice, None).history,
        Some(HistoryOp::Back(_))
    ));
    assert_eq!(
        history
            .on_popstate(Some(list_token), "", false, |_| true)
            .ui,
        UiAction::Close
    );
    let _ = history.user_open(alice, "");
    let _ = history.user_open(bob, "");
    assert!(matches!(
        history.on_open_failed(bob, Some(alice)).history,
        Some(HistoryOp::Replace(_))
    ));
}

#[test]
fn chat_history_bounds_cached_forward_entries() {
    let mut history = ChatHistory::new("bounded".to_string(), None, String::new());
    let first_peer = [0x01; 32];
    let (list_token, first_token) = match history.user_open(first_peer, "") {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_token),
                    chat_token,
                }),
            ..
        } => (list_token, chat_token),
        other => panic!("expected Push, got {other:?}"),
    };
    let mut last_token = String::new();
    let mut last_peer = first_peer;
    for i in 1..=(MAX_ENTRIES + 5) {
        last_peer = [(i as u8).wrapping_add(2); 32];
        if let Transition {
            history: Some(HistoryOp::Replace(token)),
            ..
        } = history.user_open(last_peer, "")
        {
            last_token = token;
        }
    }
    // Return to list.
    assert_eq!(
        history
            .on_popstate(Some(&list_token), "", false, |_| true)
            .ui,
        UiAction::Close
    );
    // Latest entry is retained.
    assert_eq!(
        history.on_popstate(Some(&last_token), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Open(last_peer),
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    // Evicted oldest entry stays closed on the list without bouncing Forward backward.
    assert_eq!(
        history.on_popstate(Some(&first_token), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
}

#[test]
fn chat_history_retains_slot_across_retries_rebinds_fragments_and_handles_pre_reload_frags() {
    let alice = [0xA1; 32];
    let bob = [0xB2; 32];

    // 1. Retaining a pushed reservation across retryable errors and `NewChat <-> SignIn` handoffs
    // keeps the submit-gesture entry with zero `history.back()` in flight; closing the modal
    // unwinds the retained slot cleanly.
    let mut ret = ChatHistory::new("sess-retain".to_string(), None, String::new());
    let (res1, list_token) = match ret.reserve("") {
        (
            res @ Reservation::Pushed(_),
            Some(HistoryOp::Push {
                tag_list: Some(list_token),
                ..
            }),
        ) => (res, list_token),
        other => panic!("expected pushed reservation, got {other:?}"),
    };
    assert!(ret.retain_reservation(Some(res1)));
    assert!(!ret.is_reservation_owned(Some(res1)));
    // Retry (e.g. "Allow classical" or SignIn submit) reuses the gesture-pushed slot immediately!
    let (res2, retry_op) = ret.reserve("");
    assert!(matches!(res2, Reservation::Pushed(_)));
    assert_eq!(retry_op, None);
    assert_eq!(
        ret.commit_reservation(Some(res2), alice, ""),
        Transition {
            history: None,
            ui: UiAction::Open(alice),
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    let _ = ret.on_popstate(Some(&list_token), "", false, |_| true);

    // Dismissing SignIn back to NewChat retains the slot, and cancelling NewChat unwinds it;
    // browser Back popping a retained slot dismisses the startup dialog.
    let (res3, _) = ret.reserve("");
    ret.retain_active_reservation();
    assert!(!ret.is_reservation_owned(Some(res3)));
    assert!(matches!(
        ret.cancel_retained_reservation(),
        Some(HistoryOp::Back(_))
    ));
    let _ = ret.on_popstate(Some(&list_token), "", false, |_| true);
    let (res4, _) = ret.reserve("");
    assert!(ret.retain_reservation(Some(res4)));
    assert_eq!(
        ret.on_popstate(Some(&list_token), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::None,
            dismiss_startup: true,
            fallback_active: None,
        }
    );

    // 2. Replacing Alice with Bob keeps any Forward fragment marker (`#one`) bound to Bob so a
    // direct Forward-menu jump from the list opens Bob, not Alice, and deleting Bob invalidates it.
    let mut frag_rebind = ChatHistory::new("sess-slot".to_string(), None, String::new());
    let (list_tok, alice_tok) = match frag_rebind.user_open(alice, "") {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_tok),
                    chat_token,
                }),
            ..
        } => (list_tok, chat_token),
        other => panic!("expected Push, got {other:?}"),
    };
    let frag_tok = match frag_rebind.on_popstate(None, "#one", false, |_| true) {
        Transition {
            history: Some(HistoryOp::Tag(tag)),
            ui: UiAction::None,
            ..
        } => tag,
        other => panic!("expected Tag, got {other:?}"),
    };
    // Back to Alice, switch to Bob, Back to list.
    assert_eq!(
        frag_rebind
            .on_popstate(Some(&alice_tok), "", false, |_| true)
            .ui,
        UiAction::Open(alice)
    );
    let bob_tok = match frag_rebind.user_open(bob, "") {
        Transition {
            history: Some(HistoryOp::Replace(tok)),
            ui: UiAction::Open(p),
            ..
        } => {
            assert_eq!(p, bob);
            tok
        }
        other => panic!("expected Replace(bob), got {other:?}"),
    };
    assert_eq!(
        frag_rebind
            .on_popstate(Some(&list_tok), "", false, |_| true)
            .ui,
        UiAction::Close
    );
    // Direct Forward-menu jump straight to `#one` must open Bob (the surviving peer on this slot)!
    assert_eq!(
        frag_rebind.on_popstate(Some(&frag_tok), "#one", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Open(bob),
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    // Stepping back onto Bob's slot keeps Bob open, and deleting Bob invalidates `#one`.
    assert_eq!(
        frag_rebind
            .on_popstate(Some(&bob_tok), "", false, |_| true)
            .ui,
        UiAction::Open(bob)
    );
    assert!(matches!(
        frag_rebind.on_ui_closed(bob),
        Some(HistoryOp::Back(_))
    ));
    let _ = frag_rebind.on_popstate(Some(&list_tok), "", false, |_| true);
    assert_eq!(
        frag_rebind
            .on_popstate(Some(&frag_tok), "#one", false, |p| *p == alice)
            .ui,
        UiAction::Close
    );

    // 3. Ignored Back while switching from Alice+#one to Bob preserves `fragment_depth = 1` when
    // replacing `#one` with Bob AND stores that depth with Bob's replacement token, so BOTH an
    // immediate in-app Close AND a later Forward onto Bob's token -> in-app Close step past Alice's
    // underlying entry all the way back to the list instead of reopening Alice.
    let mut frag_timeout = ChatHistory::new("sess-ft".to_string(), None, String::new());
    let (ft_list, ft_alice) = match frag_timeout.user_open(alice, "") {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_tok),
                    chat_token,
                }),
            ..
        } => (list_tok, chat_token),
        other => panic!("expected Push, got {other:?}"),
    };
    let ft_frag = match frag_timeout.on_popstate(None, "#one", false, |_| true) {
        Transition {
            history: Some(HistoryOp::Tag(tag)),
            ..
        } => tag,
        other => panic!("expected Tag, got {other:?}"),
    };
    let switch_attempt = match frag_timeout.user_open(bob, "#one") {
        Transition {
            history: Some(HistoryOp::Back(attempt)),
            ui: UiAction::None,
            ..
        } => attempt,
        other => panic!("expected Back, got {other:?}"),
    };
    let ft_bob =
        match frag_timeout.on_back_aborted(switch_attempt, Some(&ft_frag), "#one", |_| true) {
            Transition {
                history: Some(HistoryOp::Replace(tok)),
                ui: UiAction::Open(p),
                ..
            } => {
                assert_eq!(p, bob);
                tok
            }
            other => panic!("expected Replace(bob), got {other:?}"),
        };
    // Next in-app Close pops Bob -> lands on `ft_alice` -> MUST step back again -> lands on list!
    assert!(matches!(
        frag_timeout.user_close(),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert!(matches!(
        frag_timeout.on_popstate(Some(&ft_alice), "", false, |_| true),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert_eq!(
        frag_timeout.on_popstate(Some(&ft_list), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    // Navigating Forward straight back to Bob's Back-recovered token restores `depth = 1`, so
    // in-app Close STILL steps past `ft_alice` back to `ft_list`!
    assert_eq!(
        frag_timeout.on_popstate(Some(&ft_bob), "#one", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Open(bob),
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    assert!(matches!(
        frag_timeout.user_close(),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert!(matches!(
        frag_timeout.on_popstate(Some(&ft_alice), "", false, |_| true),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert_eq!(
        frag_timeout
            .on_popstate(Some(&ft_list), "", false, |_| true)
            .ui,
        UiAction::Close
    );

    // 4. Starting New Chat from an already-open chat gets `Reservation::Unpushed`; retaining it
    // across `NewChat -> SignIn` still keeps the startup modal bound to browser Back so Back both
    // closes the underlying chat AND dismisses `SignIn`.
    let mut open_retry = ChatHistory::new("sess-open-retry".to_string(), None, String::new());
    let (or_list, or_alice) = match open_retry.user_open(alice, "") {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_tok),
                    chat_token,
                }),
            ..
        } => (list_tok, chat_token),
        other => panic!("expected Push, got {other:?}"),
    };
    let (unpushed_res, unpushed_op) = open_retry.reserve("");
    assert!(matches!(unpushed_res, Reservation::Unpushed { .. }));
    assert_eq!(unpushed_op, None);
    assert!(open_retry.retain_reservation(Some(unpushed_res)));
    assert_eq!(
        open_retry.on_popstate(Some(&or_list), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: true,
            fallback_active: None,
        }
    );
    // Deleting Alice AFTER navigating Back to the list still invalidates `or_alice` via
    // `on_peer_deleted` so Forward onto `or_alice` cannot open a later new chat with Alice!
    open_retry.on_peer_deleted(alice);
    assert_eq!(
        open_retry.on_popstate(Some(&or_alice), "", false, |p| *p == alice),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );

    // 5. Reloading/locking on a pre-reload fragment token (`ratchetx2-frag:old-sess:...`) does NOT
    // tag the fragment as a list entry; opening a chat unwinds the pre-reload fragments onto the
    // pre-reload chat slot and replaces it in place.
    let mut pre_frag = ChatHistory::new(
        "new-sess".to_string(),
        Some("ratchetx2-frag:old-sess:7:2"),
        "#two".to_string(),
    );
    assert_eq!(pre_frag.tag_current_list_entry(), None);
    // Navigating across pre-reload fragments while locked also never tags them as list entries.
    assert_eq!(
        pre_frag.on_locked_popstate(Some("ratchetx2-frag:old-sess:7:1")),
        None
    );
    // Unlocking and opening Alice unwinds the remaining pre-reload fragment onto the pre-reload
    // chat slot and replaces it in place.
    assert!(matches!(
        pre_frag.user_open(alice, "#one"),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert!(matches!(
        pre_frag.on_popstate(Some("ratchetx2-chat:old-sess:7"), "", false, |_| true),
        Transition {
            history: Some(HistoryOp::Replace(_)),
            ui: UiAction::Open(p),
            ..
        } if p == alice
    ));
    assert_eq!(
        pre_frag
            .on_popstate(Some("ratchetx2-list:old-sess"), "", false, |_| true)
            .ui,
        UiAction::Close
    );

    // 6. Browser Back from an open chat while an unreserved idle `NewChat` or background `SignIn`
    // modal is open (`startup_dialog_open == true`) MUST still dismiss the startup dialog and
    // discard its pending draft alongside closing the chat.
    let mut unreserved_back = ChatHistory::new("sess-unres".to_string(), None, String::new());
    let unres_list = match unreserved_back.user_open(alice, "") {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_tok),
                    ..
                }),
            ..
        } => list_tok,
        other => panic!("expected Push, got {other:?}"),
    };
    assert_eq!(
        unreserved_back.on_popstate(Some(&unres_list), "", true, |_| true),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: true,
            fallback_active: None,
        }
    );

    // 7. A NewChat / SignIn form (and any Unpushed reservation) opened while an earlier in-app
    // Close (`BackGoal::CloseToList`) is still settling MUST survive that Close's list `popstate`,
    // whereas a subsequent native browser Back DOES dismiss the form.
    let mut close_then_startup =
        ChatHistory::new("sess-close-startup".to_string(), None, String::new());
    let close_list = match close_then_startup.user_open(alice, "") {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_tok),
                    ..
                }),
            ..
        } => list_tok,
        other => panic!("expected Push, got {other:?}"),
    };
    assert!(matches!(
        close_then_startup.user_close(),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    // User clicks NewChat and submits on desktop while the in-app Close is still settling.
    let (startup_res, reserve_op) = close_then_startup.reserve("");
    assert!(matches!(startup_res, Reservation::Unpushed { .. }));
    assert_eq!(reserve_op, None);
    // Earlier in-app Close now settles onto the list entry: closes the chat pane, but MUST NOT
    // dismiss the newer startup form or invalidate its Unpushed reservation.
    assert_eq!(
        close_then_startup.on_popstate(Some(&close_list), "", true, |_| true),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    assert!(close_then_startup.is_reservation_owned(Some(startup_res)));
    // Committing the surviving reservation pushes Bob cleanly above the list.
    assert!(matches!(
        close_then_startup.commit_reservation(Some(startup_res), bob, ""),
        Transition {
            history: Some(HistoryOp::Push { .. }),
            ui: UiAction::Open(p),
            ..
        } if p == bob
    ));

    // 8. Native browser Back directly off a fragment-recovered chat token (created when switching
    // peers from `#fragment` timed out) skips the underlying duplicate chat/fragment entries so
    // the first Back gesture closes the chat instead of reopening the same peer.
    let mut rec_native = ChatHistory::new("sess-rec-native".to_string(), None, String::new());
    let (rec_list, alice_tok) = match rec_native.user_open(alice, "") {
        Transition {
            history:
                Some(HistoryOp::Push {
                    tag_list: Some(list_tok),
                    chat_token,
                }),
            ..
        } => (list_tok, chat_token),
        other => panic!("expected Push, got {other:?}"),
    };
    let frag1 = match rec_native.on_popstate(None, "#s1", false, |_| true) {
        Transition {
            history: Some(HistoryOp::Tag(tok)),
            ..
        } => tok,
        other => panic!("expected Tag for #s1, got {other:?}"),
    };
    let frag2 = match rec_native.on_popstate(None, "#s2", false, |_| true) {
        Transition {
            history: Some(HistoryOp::Tag(tok)),
            ..
        } => tok,
        other => panic!("expected Tag for #s2, got {other:?}"),
    };
    // Switch to Bob from #s2; unwind times out -> Bob replaces #s2 at depth 2.
    let attempt = match rec_native.user_open(bob, "#s2") {
        Transition {
            history: Some(HistoryOp::Back(attempt)),
            ..
        } => attempt,
        other => panic!("expected Back, got {other:?}"),
    };
    let bob_recovered = match rec_native.on_back_aborted(attempt, Some(&frag2), "#s2", |_| true) {
        Transition {
            history: Some(HistoryOp::Replace(tok)),
            ui: UiAction::Open(p),
            ..
        } if p == bob => tok,
        other => panic!("expected Replace with Bob, got {other:?}"),
    };
    // Visiting a new fragment `#s3` above the recovered Bob and pressing Back returns to Bob.
    assert!(matches!(
        rec_native.on_popstate(None, "#s3", false, |_| true),
        Transition {
            history: Some(HistoryOp::Tag(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert_eq!(
        rec_native.on_popstate(Some(&bob_recovered), "#s2", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Open(bob),
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    // Now native Back steps off `bob_recovered` (depth 2) onto `frag1` (depth 1): MUST emit
    // `Back` to skip `frag1` and `alice_tok` all the way to the chat list.
    assert!(matches!(
        rec_native.on_popstate(Some(&frag1), "#s1", false, |_| true),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    // Follow-up hop lands on `alice_tok` (depth 0) with 1 hop remaining -> emits final `Back`.
    assert!(matches!(
        rec_native.on_popstate(Some(&alice_tok), "", false, |_| true),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    // Final hop lands on the list and closes Bob.
    assert_eq!(
        rec_native.on_popstate(Some(&rec_list), "", false, |_| true),
        Transition {
            history: None,
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
}
