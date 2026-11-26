use session::PublicKey;

use crate::util::{hex, key_to_text, key_to_url};

use super::machine::{
    BackGoal, ChatEntry, ChatHistory, CursorState, HistoryOp, MAX_ENTRIES, PendingBack,
    PendingNavigation, Reservation, ReservationOwner, Transition, UiAction, UnpushedStartup,
};

struct HistoryHarness {
    history: ChatHistory,
}

impl HistoryHarness {
    fn new(session: &str) -> Self {
        Self {
            history: ChatHistory::new(session.to_string(), None, String::new()),
        }
    }

    fn reloaded(session: &str, state: Option<&str>, hash: &str) -> Self {
        Self {
            history: ChatHistory::new(session.to_string(), state, hash.to_string()),
        }
    }

    fn transition(ui: UiAction, dismiss_startup: bool) -> Transition {
        Transition {
            history: None,
            ui,
            dismiss_startup,
            fallback_active: None,
        }
    }

    fn open_push(&mut self, peer: PublicKey, hash: &str) -> (Option<String>, String) {
        match self.history.user_open(peer, hash) {
            Transition {
                history:
                    Some(HistoryOp::Push {
                        tag_list,
                        chat_token,
                    }),
                ui: UiAction::Open(p),
                ..
            } if p == peer => (tag_list, chat_token),
            other => panic!("expected Push + Open({peer:?}), got {other:?}"),
        }
    }

    fn open_replace(&mut self, peer: PublicKey, hash: &str) -> String {
        match self.history.user_open(peer, hash) {
            Transition {
                history: Some(HistoryOp::Replace(token)),
                ui: UiAction::Open(p),
                ..
            } if p == peer => token,
            other => panic!("expected Replace + Open({peer:?}), got {other:?}"),
        }
    }

    fn open_back(&mut self, peer: PublicKey, hash: &str) -> u64 {
        match self.history.user_open(peer, hash) {
            Transition {
                history: Some(HistoryOp::Back(attempt)),
                ui: UiAction::None,
                ..
            } => attempt,
            other => panic!("expected Back for open({peer:?}), got {other:?}"),
        }
    }

    fn close_back(&mut self) -> u64 {
        match self.history.user_close() {
            Transition {
                history: Some(HistoryOp::Back(attempt)),
                ui: UiAction::None,
                ..
            } => attempt,
            other => panic!("expected Back for user_close(), got {other:?}"),
        }
    }

    fn tag_frag(&mut self, hash: &str) -> String {
        match self.history.on_popstate(None, hash, false, |_| true) {
            Transition {
                history: Some(HistoryOp::Tag(tag)),
                ui: UiAction::None,
                ..
            } => tag,
            other => panic!("expected Tag for fragment {hash:?}, got {other:?}"),
        }
    }

    fn pop(&mut self, state: Option<&str>, hash: &str) -> Transition {
        self.history.on_popstate(state, hash, false, |_| true)
    }

    fn pop_peer(&mut self, state: Option<&str>, hash: &str, only: PublicKey) -> Transition {
        self.history.on_popstate(state, hash, false, |p| *p == only)
    }

    fn assert_pop_back(&mut self, state: Option<&str>, hash: &str) {
        assert!(matches!(
            self.pop(state, hash),
            Transition {
                history: Some(HistoryOp::Back(_)),
                ui: UiAction::None,
                ..
            }
        ));
    }

    fn reserve_push(&mut self, hash: &str) -> (Reservation, Option<String>, String) {
        match self.history.reserve(hash) {
            (
                res @ Reservation::Pushed(_),
                Some(HistoryOp::Push {
                    tag_list,
                    chat_token,
                }),
            ) => (res, tag_list, chat_token),
            other => panic!("expected (Pushed, Some(Push)), got {other:?}"),
        }
    }

    fn reserve_unpushed(&mut self, hash: &str) -> Reservation {
        match self.history.reserve(hash) {
            (res @ Reservation::Unpushed { .. }, None) => res,
            other => panic!("expected (Unpushed, None), got {other:?}"),
        }
    }

    fn abort_back_replace(
        &mut self,
        attempt: u64,
        state: Option<&str>,
        hash: &str,
        peer: PublicKey,
    ) -> String {
        match self
            .history
            .on_back_aborted(attempt, state, hash, |p| *p == peer)
        {
            Transition {
                history: Some(HistoryOp::Replace(tok)),
                ui: UiAction::Open(p),
                ..
            } if p == peer => tok,
            other => panic!("expected Replace + Open({peer:?}), got {other:?}"),
        }
    }
}

#[test]
fn chat_history_open_and_back_gesture_returns_to_list_without_leaking_peer_key() {
    let alice = [0xA1; 32];
    let mut h = HistoryHarness::new("sess01");

    let (list_token, chat_token) = h.open_push(alice, "");
    let list_token = list_token.expect("initial list tag");
    assert_eq!(list_token, "ratchetx2-list:sess01");
    assert!(chat_token.starts_with("ratchetx2-chat:sess01:"));
    assert!(!chat_token.contains(&hex(&alice)));
    assert!(!chat_token.contains(&key_to_text(&alice)));
    assert!(!chat_token.contains(&key_to_url(&alice)));

    assert_eq!(
        h.pop(Some(&list_token), ""),
        HistoryHarness::transition(UiAction::Close, false)
    );
    assert_eq!(
        h.pop_peer(Some(&chat_token), "", alice),
        HistoryHarness::transition(UiAction::Open(alice), false)
    );
    assert_eq!(
        h.pop(Some(&list_token), ""),
        HistoryHarness::transition(UiAction::Close, false)
    );
}

#[test]
fn chat_history_tracks_manual_fragments_including_empty_hash_so_close_and_switch_reach_list() {
    let alice = [0xA2; 32];
    let bob = [0xB2; 32];
    let mut h = HistoryHarness::new("sess-frag");

    let (list_token, alice_token) = h.open_push(alice, "");
    let list_token = list_token.expect("list tag");

    // Both `#one` and empty `#` above Alice are tagged as fragments (never confused with list).
    let frag_one = h.tag_frag("#one");
    assert!(frag_one.starts_with("ratchetx2-frag:sess-frag:") && frag_one.ends_with(":1"));
    let frag_empty = h.tag_frag("");
    assert!(frag_empty.ends_with(":2"));

    // Stepping back from `#` (depth 2) to `#one` (depth 1) keeps Alice open; Close unwinds both.
    assert_eq!(
        h.pop(Some(&frag_one), "#one"),
        HistoryHarness::transition(UiAction::None, false)
    );
    h.close_back();
    h.assert_pop_back(Some(&alice_token), "");
    assert_eq!(
        h.pop(Some(&list_token), ""),
        HistoryHarness::transition(UiAction::Close, false)
    );

    // Direct Forward-menu jump to `#one` reopens Alice; switching to Bob then clicking Close
    // before unwind settles redirects traversal to close to list.
    assert_eq!(
        h.pop_peer(Some(&frag_one), "#one", alice),
        HistoryHarness::transition(UiAction::Open(alice), false)
    );
    h.open_back(bob, "#one");
    assert_eq!(
        h.history.user_close(),
        HistoryHarness::transition(UiAction::None, false)
    );
    assert!(matches!(
        h.pop_peer(Some(&alice_token), "", alice),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert_eq!(h.pop(Some(&list_token), "").ui, UiAction::Close);

    // Timed-out fragment unwind replaces fragment in place with Bob.
    let _ = h.open_push(alice, "");
    let frag_two = h.tag_frag("#frag");
    let switch_attempt = h.open_back(bob, "#frag");
    h.abort_back_replace(switch_attempt, Some(&frag_two), "#frag", bob);
    assert_eq!(h.pop(Some(&list_token), "").ui, UiAction::Close);

    // Normal peer switch unwinds `#frag` onto `alice_token_3` and replaces it with Bob.
    let (_, alice_token_3) = h.open_push(alice, "");
    let _ = h.tag_frag("#frag");
    h.open_back(bob, "#frag");
    assert!(matches!(
        h.pop_peer(Some(&alice_token_3), "", bob),
        Transition {
            history: Some(HistoryOp::Replace(_)),
            ui: UiAction::Open(p),
            ..
        } if p == bob
    ));
    assert_eq!(h.pop(Some(&list_token), "").ui, UiAction::Close);

    // Navigating to `#other` on the list tags it; jumping back via Back menu to `/` closes chat.
    assert_eq!(
        h.pop(None, "#other"),
        Transition {
            history: Some(HistoryOp::Tag(list_token.clone())),
            ui: UiAction::Close,
            dismiss_startup: false,
            fallback_active: None,
        }
    );
    let (tag_list, _) = h.open_push(alice, "#other");
    assert_eq!(tag_list, None);
    assert_eq!(h.pop(Some(&list_token), "").ui, UiAction::Close);

    // Even if initial `/` tagging failed, jumping back from chat on `#one` to untagged `/` closes.
    let mut untagged = HistoryHarness::new("sess-untagged");
    let init_tag = untagged
        .history
        .tag_current_list_entry()
        .expect("initial tag");
    untagged.history.on_write_failed(&init_tag, None, "");
    let _ = untagged.pop(None, "#one");
    let _ = untagged.history.user_open(alice, "#one");
    assert_eq!(untagged.pop(None, "").ui, UiAction::Close);
}

#[test]
fn chat_history_switching_chats_replaces_single_entry_so_one_back_returns_to_list() {
    let alice = [0x11; 32];
    let bob = [0x22; 32];
    let mut h = HistoryHarness::new("sess02");

    let (list_token, _) = h.open_push(alice, "");
    let list_token = list_token.expect("list tag");
    assert_eq!(
        h.history.user_open(alice, ""),
        HistoryHarness::transition(UiAction::Open(alice), false)
    );
    let bob_token = h.open_replace(bob, "");
    assert_eq!(
        h.pop(Some(&list_token), ""),
        HistoryHarness::transition(UiAction::Close, false)
    );
    assert_eq!(
        h.pop_peer(Some(&bob_token), "", bob),
        HistoryHarness::transition(UiAction::Open(bob), false)
    );
}

#[test]
fn chat_history_in_app_back_prevents_double_back_and_rolls_back_failed_deferred_push_to_list() {
    let alice = [0x33; 32];
    let bob = [0x44; 32];
    let mut h = HistoryHarness::new("sess03");

    let (list_token, _) = h.open_push(alice, "");
    let list_token = list_token.expect("list tag");

    h.close_back();
    assert_eq!(
        h.history.user_close(),
        HistoryHarness::transition(UiAction::None, false)
    );
    assert_eq!(
        h.history.user_open(bob, ""),
        HistoryHarness::transition(UiAction::None, false)
    );

    let deferred = h.pop_peer(Some(&list_token), "", bob);
    assert_eq!(deferred.fallback_active, None);
    let push_op = match deferred {
        Transition {
            history: Some(op @ HistoryOp::Push { .. }),
            ui: UiAction::Open(p),
            ..
        } if p == bob => op,
        other => panic!("expected Push + Open(bob), got {other:?}"),
    };

    h.history
        .on_write_failed(&push_op, deferred.fallback_active, "");
    assert_eq!(
        h.history.user_close(),
        HistoryHarness::transition(UiAction::Close, false)
    );
}

#[test]
fn chat_history_deleting_open_chat_pops_entry_without_trapping_forward() {
    let alice = [0x55; 32];
    let bob = [0x56; 32];
    let mut h = HistoryHarness::new("sess04");

    let (list_token, chat_token) = h.open_push(alice, "");
    let list_token = list_token.expect("list tag");

    assert!(matches!(
        h.history.on_ui_closed(alice),
        Some(HistoryOp::Back(_))
    ));
    assert_eq!(
        h.history
            .on_popstate(Some(&list_token), "", false, |_| false),
        HistoryHarness::transition(UiAction::Close, false)
    );
    assert_eq!(
        h.history
            .on_popstate(Some(&chat_token), "", false, |_| false),
        HistoryHarness::transition(UiAction::Close, false)
    );
    let _ = h.open_replace(bob, "");
}

#[test]
fn chat_history_reservation_handles_back_dismissal_ownership_transfer_and_unwind_retry() {
    let alice = [0x88; 32];
    let bob = [0x89; 32];
    let mut h = HistoryHarness::new("sess-res");

    let (reservation, list_token, chat_token) = h.reserve_push("");
    let list_token = list_token.expect("list tag");
    assert_eq!(
        h.history.commit_reservation(Some(reservation), alice, ""),
        HistoryHarness::transition(UiAction::Open(alice), false)
    );
    assert_eq!(h.pop(Some(&list_token), "").ui, UiAction::Close);
    assert_eq!(
        h.pop_peer(Some(&chat_token), "", alice).ui,
        UiAction::Open(alice)
    );
    assert_eq!(h.pop(Some(&list_token), "").ui, UiAction::Close);

    // Back popping an active reservation dismisses startup and invalidates late commit.
    let (res_back, _, _) = h.reserve_push("");
    assert_eq!(
        h.pop(Some(&list_token), ""),
        HistoryHarness::transition(UiAction::None, true)
    );
    assert_eq!(
        h.history.commit_reservation(Some(res_back), alice, ""),
        HistoryHarness::transition(UiAction::None, false)
    );

    // Reserving again beneath `#under` transfers ownership and revokes old reservation.
    let (res_old, _, _) = h.reserve_push("");
    let _ = h.tag_frag("#under");
    let (res_new, op_new) = h.history.reserve("#under");
    assert!(matches!(res_new, Reservation::Pushed(_)) && op_new.is_none());
    assert!(!h.history.is_reservation_owned(Some(res_old)));
    assert!(h.history.is_reservation_owned(Some(res_new)));
    assert_eq!(
        h.history.commit_reservation(Some(res_old), alice, "#under"),
        HistoryHarness::transition(UiAction::None, false)
    );
    assert_eq!(h.history.cancel_reservation(Some(res_old)), (false, None));
    assert!(matches!(
        h.history.cancel_active_reservation(),
        Some(HistoryOp::Back(_))
    ));
    let _ = h.pop(Some(&list_token), "");

    // Retry during settling programmatic `UnwindToList` survives unwind settlement.
    let (res_first, _, _) = h.reserve_push("");
    let (still_owned, unwind_op) = h.history.cancel_reservation(Some(res_first));
    assert!(still_owned && matches!(unwind_op, Some(HistoryOp::Back(_))));
    let res_retry = h.reserve_unpushed("");
    assert_eq!(
        h.pop(Some(&list_token), ""),
        HistoryHarness::transition(UiAction::None, false)
    );
    assert!(matches!(
        h.history.commit_reservation(Some(res_retry), alice, ""),
        Transition {
            history: Some(HistoryOp::Push { .. }),
            ui: UiAction::Open(p),
            ..
        } if p == alice
    ));
    let _ = h.pop(Some(&list_token), "");

    // Manual fragment above reservation: stepping back keeps it; committing unwinds fragment.
    let (res_frag, _, frag_token) = h.reserve_push("");
    assert_eq!(h.pop(None, "#frag").ui, UiAction::None);
    assert_eq!(
        h.pop(Some(&frag_token), ""),
        HistoryHarness::transition(UiAction::None, false)
    );
    assert!(h.history.is_reservation_owned(Some(res_frag)));
    assert_eq!(h.pop(None, "#frag2").ui, UiAction::None);
    assert!(matches!(
        h.history.commit_reservation(Some(res_frag), bob, "#frag2"),
        Transition {
            history: Some(HistoryOp::Back(_)),
            ui: UiAction::None,
            ..
        }
    ));
    assert!(matches!(
        h.pop_peer(Some(&frag_token), "", bob),
        Transition {
            history: Some(HistoryOp::Replace(_)),
            ui: UiAction::Open(p),
            ..
        } if p == bob
    ));
    let _ = h.pop(Some(&list_token), "");

    // Native Escape cancels and unwinds active reservation.
    let (res_esc, _, _) = h.reserve_push("");
    assert!(matches!(
        h.history.cancel_active_reservation(),
        Some(HistoryOp::Back(_))
    ));
    assert!(!h.history.is_reservation_owned(Some(res_esc)));
    assert_eq!(
        h.pop(Some(&list_token), ""),
        HistoryHarness::transition(UiAction::None, false)
    );
    assert_eq!(
        h.history.commit_reservation(Some(res_esc), alice, "").ui,
        UiAction::None
    );

    // Unpushed reservation from an already-open chat closes chat AND dismisses startup on Back.
    let (_, alice_live_token) = h.open_push(alice, "");
    let res_unpushed = h.reserve_unpushed("");
    assert_eq!(
        h.pop(Some(&list_token), ""),
        HistoryHarness::transition(UiAction::Close, true)
    );
    assert!(!h.history.is_reservation_owned(Some(res_unpushed)));
    assert_eq!(
        h.history.commit_reservation(Some(res_unpushed), bob, "").ui,
        UiAction::None
    );

    // Failed push converted to Unpushed is also dismissed on Forward onto a live chat.
    let (_, failed_op) = h.history.reserve("");
    let failed_res = h
        .history
        .on_reserve_push_failed(failed_op.as_ref().expect("push op"), "");
    assert_eq!(
        h.pop_peer(Some(&alice_live_token), "", alice),
        HistoryHarness::transition(UiAction::Open(alice), true)
    );
    assert!(!h.history.is_reservation_owned(Some(failed_res)));
}

#[test]
fn chat_history_reuses_pre_reload_slot_reconciles_locked_back_and_honors_back_after_timeout() {
    let alice = [0x91; 32];
    let bob = [0x92; 32];

    let mut reloaded = HistoryHarness::reloaded("new-sess", Some("ratchetx2-chat:old-sess:7"), "");
    let _ = reloaded.open_replace(alice, "");
    assert_eq!(reloaded.pop(None, "").ui, UiAction::Close);

    let mut locked_back =
        HistoryHarness::reloaded("locked-sess", Some("ratchetx2-chat:old-sess:9"), "");
    assert!(matches!(
        locked_back
            .history
            .on_locked_popstate(Some("ratchetx2-list:old-sess")),
        Some(HistoryOp::Tag(tag)) if tag == "ratchetx2-list:locked-sess"
    ));
    let (tag_list, _) = locked_back.open_push(alice, "");
    assert_eq!(tag_list, None);

    // Slow `history.back()` timeout closes UI directly; late popstate and Forward still work.
    let mut slow = HistoryHarness::new("sess-slow");
    let (list_token, alice_token) = slow.open_push(alice, "");
    let list_token = list_token.expect("list tag");
    let attempt = slow.close_back();
    assert_eq!(
        slow.history
            .on_back_aborted(attempt, Some(&alice_token), "", |_| true),
        HistoryHarness::transition(UiAction::Close, false)
    );
    assert_eq!(slow.pop(Some(&list_token), "").ui, UiAction::Close);
    assert_eq!(
        slow.pop_peer(Some(&alice_token), "", alice),
        HistoryHarness::transition(UiAction::Open(alice), false)
    );

    // Ignored Back while switching to Bob recovers via Replace; next Back closes directly.
    let attempt2 = slow.close_back();
    assert_eq!(slow.history.user_open(bob, "").ui, UiAction::None);
    slow.abort_back_replace(attempt2, Some(&alice_token), "", bob);
    assert_eq!(
        slow.pop_peer(Some(&list_token), "", bob),
        HistoryHarness::transition(UiAction::Close, false)
    );
}

#[test]
fn chat_history_rebinds_failed_replace_and_handles_failed_push_and_open() {
    let alice = [0x66; 32];
    let bob = [0x77; 32];
    let mut h = HistoryHarness::new("current-sess");

    let pushed = h.history.user_open(alice, "");
    let op = pushed.history.expect("push op");
    h.history.on_write_failed(&op, pushed.fallback_active, "");
    assert_eq!(
        h.history.user_close(),
        HistoryHarness::transition(UiAction::Close, false)
    );

    let list_token = "ratchetx2-list:current-sess";
    let (_, alice_token) = h.open_push(alice, "");
    let replace = h.history.user_open(bob, "");
    let replace_op = replace.history.expect("replace op");
    h.history
        .on_write_failed(&replace_op, replace.fallback_active, "");
    assert_eq!(h.pop(Some(list_token), "").ui, UiAction::Close);
    assert_eq!(
        h.pop_peer(Some(&alice_token), "", bob),
        HistoryHarness::transition(UiAction::Open(bob), false)
    );
    assert!(matches!(
        h.history.on_ui_closed(bob),
        Some(HistoryOp::Back(_))
    ));
    let _ = h.pop(Some(list_token), "");

    let _ = h.open_push(alice, "");
    assert!(matches!(
        h.history.on_open_failed(alice, None).history,
        Some(HistoryOp::Back(_))
    ));
    assert_eq!(h.pop(Some(list_token), "").ui, UiAction::Close);
    let _ = h.open_push(alice, "");
    let _ = h.open_replace(bob, "");
    assert!(matches!(
        h.history.on_open_failed(bob, Some(alice)).history,
        Some(HistoryOp::Replace(_))
    ));
}

#[test]
fn chat_history_bounds_cached_forward_entries() {
    let mut h = HistoryHarness::new("bounded");
    let first_peer = [0x01; 32];
    let (list_token, first_token) = h.open_push(first_peer, "");
    let list_token = list_token.expect("list tag");

    let mut last_token = String::new();
    let mut last_peer = first_peer;
    for i in 1..=(MAX_ENTRIES + 5) {
        last_peer = [(i as u8).wrapping_add(2); 32];
        last_token = h.open_replace(last_peer, "");
    }
    assert_eq!(h.pop(Some(&list_token), "").ui, UiAction::Close);
    assert_eq!(
        h.pop(Some(&last_token), ""),
        HistoryHarness::transition(UiAction::Open(last_peer), false)
    );
    assert_eq!(
        h.pop(Some(&first_token), ""),
        HistoryHarness::transition(UiAction::Close, false)
    );
}

#[test]
fn chat_history_retains_slot_across_retries_and_unpushed_startup() {
    let alice = [0xA1; 32];

    // Retained pushed slot is reused across retries and unwound on modal cancel or Back.
    let mut ret = HistoryHarness::new("sess-retain");
    let (res1, list_token, _) = ret.reserve_push("");
    let list_token = list_token.expect("list tag");
    assert!(ret.history.retain_reservation(Some(res1)));
    assert!(!ret.history.is_reservation_owned(Some(res1)));
    let (res2, retry_op) = ret.history.reserve("");
    assert!(matches!(res2, Reservation::Pushed(_)) && retry_op.is_none());
    assert_eq!(
        ret.history.commit_reservation(Some(res2), alice, ""),
        HistoryHarness::transition(UiAction::Open(alice), false)
    );
    let _ = ret.pop(Some(&list_token), "");

    let (res3, _, _) = ret.reserve_push("");
    ret.history.retain_active_reservation();
    assert!(!ret.history.is_reservation_owned(Some(res3)));
    assert!(matches!(
        ret.history.cancel_retained_reservation(),
        Some(HistoryOp::Back(_))
    ));
    let _ = ret.pop(Some(&list_token), "");
    let (res4, _, _) = ret.reserve_push("");
    assert!(ret.history.retain_reservation(Some(res4)));
    assert_eq!(
        ret.pop(Some(&list_token), ""),
        HistoryHarness::transition(UiAction::None, true)
    );

    // Retained unpushed startup from an open chat still dismisses on Back; `on_peer_deleted`
    // invalidates cached Forward tokens even after returning to the list.
    let mut open_retry = HistoryHarness::new("sess-open-retry");
    let (or_list, or_alice) = open_retry.open_push(alice, "");
    let or_list = or_list.expect("list tag");
    let unpushed_res = open_retry.reserve_unpushed("");
    assert!(open_retry.history.retain_reservation(Some(unpushed_res)));
    assert_eq!(
        open_retry.pop(Some(&or_list), ""),
        HistoryHarness::transition(UiAction::Close, true)
    );
    open_retry.history.on_peer_deleted(alice);
    assert_eq!(
        open_retry.pop_peer(Some(&or_alice), "", alice),
        HistoryHarness::transition(UiAction::Close, false)
    );
}

#[test]
fn chat_history_rebinds_fragments_on_replace_and_timeout_recovery() {
    let alice = [0xA1; 32];
    let bob = [0xB2; 32];

    // Replacing Alice with Bob rebinds Forward fragment markers to Bob; deleting Bob invalidates them.
    let mut h = HistoryHarness::new("sess-slot");
    let (list_tok, alice_tok) = h.open_push(alice, "");
    let list_tok = list_tok.expect("list tag");
    let frag_tok = h.tag_frag("#one");
    assert_eq!(h.pop(Some(&alice_tok), "").ui, UiAction::Open(alice));
    let bob_tok = h.open_replace(bob, "");
    assert_eq!(h.pop(Some(&list_tok), "").ui, UiAction::Close);
    assert_eq!(
        h.pop(Some(&frag_tok), "#one"),
        HistoryHarness::transition(UiAction::Open(bob), false)
    );
    assert_eq!(h.pop(Some(&bob_tok), "").ui, UiAction::Open(bob));
    assert!(matches!(
        h.history.on_ui_closed(bob),
        Some(HistoryOp::Back(_))
    ));
    let _ = h.pop(Some(&list_tok), "");
    assert_eq!(
        h.pop_peer(Some(&frag_tok), "#one", alice).ui,
        UiAction::Close
    );

    // Timeout recovery while switching from `#one` preserves fragment depth for both immediate
    // in-app Close and a later Forward -> in-app Close.
    let mut ft = HistoryHarness::new("sess-ft");
    let (ft_list, ft_alice) = ft.open_push(alice, "");
    let ft_list = ft_list.expect("list tag");
    let ft_frag = ft.tag_frag("#one");
    let attempt = ft.open_back(bob, "#one");
    let ft_bob = ft.abort_back_replace(attempt, Some(&ft_frag), "#one", bob);
    ft.close_back();
    ft.assert_pop_back(Some(&ft_alice), "");
    assert_eq!(
        ft.pop(Some(&ft_list), ""),
        HistoryHarness::transition(UiAction::Close, false)
    );
    assert_eq!(
        ft.pop(Some(&ft_bob), "#one"),
        HistoryHarness::transition(UiAction::Open(bob), false)
    );
    ft.close_back();
    ft.assert_pop_back(Some(&ft_alice), "");
    assert_eq!(ft.pop(Some(&ft_list), "").ui, UiAction::Close);

    // Native browser Back off a depth-2 recovered token skips underlying fragment + chat entries.
    let mut rec = HistoryHarness::new("sess-rec-native");
    let (rec_list, alice_tok) = rec.open_push(alice, "");
    let rec_list = rec_list.expect("list tag");
    let frag1 = rec.tag_frag("#s1");
    let frag2 = rec.tag_frag("#s2");
    let attempt = rec.open_back(bob, "#s2");
    let bob_rec = rec.abort_back_replace(attempt, Some(&frag2), "#s2", bob);
    let _ = rec.tag_frag("#s3");
    assert_eq!(
        rec.pop(Some(&bob_rec), "#s2"),
        HistoryHarness::transition(UiAction::Open(bob), false)
    );
    rec.assert_pop_back(Some(&frag1), "#s1");
    rec.assert_pop_back(Some(&alice_tok), "");
    assert_eq!(
        rec.pop(Some(&rec_list), ""),
        HistoryHarness::transition(UiAction::Close, false)
    );
}

#[test]
fn chat_history_handles_pre_reload_fragments_and_startup_modal_back_edges() {
    let alice = [0xA1; 32];
    let bob = [0xB2; 32];

    // Reloading on a pre-reload fragment token never tags it as a list entry and unwinds cleanly.
    let mut pre = HistoryHarness::reloaded("new-sess", Some("ratchetx2-frag:old-sess:7:2"), "#two");
    assert_eq!(pre.history.tag_current_list_entry(), None);
    assert_eq!(
        pre.history
            .on_locked_popstate(Some("ratchetx2-frag:old-sess:7:1")),
        None
    );
    pre.open_back(alice, "#one");
    assert!(matches!(
        pre.pop(Some("ratchetx2-chat:old-sess:7"), ""),
        Transition {
            history: Some(HistoryOp::Replace(_)),
            ui: UiAction::Open(p),
            ..
        } if p == alice
    ));
    assert_eq!(
        pre.pop(Some("ratchetx2-list:old-sess"), "").ui,
        UiAction::Close
    );

    // Browser Back from an open chat while an unreserved startup modal is open dismisses it.
    let mut unres = HistoryHarness::new("sess-unres");
    let (unres_list, _) = unres.open_push(alice, "");
    let unres_list = unres_list.expect("list tag");
    assert_eq!(
        unres
            .history
            .on_popstate(Some(&unres_list), "", true, |_| true),
        HistoryHarness::transition(UiAction::Close, true)
    );

    // A startup form opened while an earlier in-app Close is settling survives that Close's popstate.
    let mut close_startup = HistoryHarness::new("sess-close-startup");
    let (close_list, _) = close_startup.open_push(alice, "");
    let close_list = close_list.expect("list tag");
    close_startup.close_back();
    let startup_res = close_startup.reserve_unpushed("");
    assert_eq!(
        close_startup
            .history
            .on_popstate(Some(&close_list), "", true, |_| true),
        HistoryHarness::transition(UiAction::Close, false)
    );
    assert!(
        close_startup
            .history
            .is_reservation_owned(Some(startup_res))
    );
    assert!(matches!(
        close_startup
            .history
            .commit_reservation(Some(startup_res), bob, ""),
        Transition {
            history: Some(HistoryOp::Push { .. }),
            ui: UiAction::Open(p),
            ..
        } if p == bob
    ));
}

#[test]
fn chat_history_typed_cursor_and_pending_navigation_invariants() {
    let alice = [0xC1; 32];
    let bob = [0xC2; 32];
    let carol = [0xC3; 32];
    let mut h = HistoryHarness::new("sess-typed");

    // Starts cleanly on List with Idle navigation and no unpushed startup.
    assert_eq!(h.history.cursor_state(), CursorState::List);
    assert_eq!(h.history.pending_navigation(), PendingNavigation::Idle);
    assert_eq!(h.history.unpushed_startup_state(), UnpushedStartup::None);

    // Opening Alice transitions CursorState to Entry(Chat) at fragment_depth 0.
    let (list_tok, alice_tok) = h.open_push(alice, "");
    let list_tok = list_tok.expect("list tag");
    assert_eq!(
        h.history.cursor_state(),
        CursorState::Entry {
            entry: ChatEntry::Chat {
                peer: alice,
                token_id: Some(1),
                slot: 1,
            },
            fragment_depth: 0,
        }
    );

    // Pushing two fragments increments fragment_depth on the Entry variant.
    let _ = h.tag_frag("#f1");
    let _ = h.tag_frag("#f2");
    assert_eq!(
        h.history.cursor_state(),
        CursorState::Entry {
            entry: ChatEntry::Chat {
                peer: alice,
                token_id: Some(1),
                slot: 1,
            },
            fragment_depth: 2,
        }
    );

    // Switching to Bob enters UnwindFragmentsForOpen { peer: bob } with 1 remaining hop.
    let attempt = h.open_back(bob, "#f2");
    assert_eq!(
        h.history.pending_navigation(),
        PendingNavigation::Back(PendingBack {
            attempt,
            goal: BackGoal::UnwindFragmentsForOpen { peer: bob },
            remaining_hops: 1,
        })
    );

    // A newer open(carol) updates the in-flight UnwindFragmentsForOpen peer in place.
    assert_eq!(
        h.history.user_open(carol, "#f2"),
        HistoryHarness::transition(UiAction::None, false)
    );
    assert_eq!(
        h.history.pending_navigation(),
        PendingNavigation::Back(PendingBack {
            attempt,
            goal: BackGoal::UnwindFragmentsForOpen { peer: carol },
            remaining_hops: 1,
        })
    );

    // In-app user_close redirects UnwindFragmentsForOpen into CloseToList and adds 1 hop.
    assert_eq!(
        h.history.user_close(),
        HistoryHarness::transition(UiAction::None, false)
    );
    assert_eq!(
        h.history.pending_navigation(),
        PendingNavigation::Back(PendingBack {
            attempt,
            goal: BackGoal::CloseToList {
                deferred_open: None,
            },
            remaining_hops: 2,
        })
    );

    // Settling back to list clears PendingNavigation to Idle and restores CursorState::List.
    h.assert_pop_back(Some(&alice_tok), "");
    assert_eq!(h.pop(Some(&list_tok), "").ui, UiAction::Close);
    assert_eq!(h.history.cursor_state(), CursorState::List);
    assert_eq!(h.history.pending_navigation(), PendingNavigation::Idle);
}

#[test]
fn chat_history_typed_reservation_owner_and_unpushed_startup_transitions() {
    let alice = [0xD1; 32];
    let mut h = HistoryHarness::new("sess-res-typed");

    // Pushed reservation transitions Reserved(Active(id)) -> Reserved(Retained) -> Active(next).
    let (res1, list_tok, _) = h.reserve_push("");
    let list_tok = list_tok.expect("list tag");
    let Reservation::Pushed(id1) = res1 else {
        panic!("expected pushed reservation");
    };
    assert_eq!(
        h.history.cursor_state(),
        CursorState::Entry {
            entry: ChatEntry::Reserved {
                token_id: 1,
                slot: 1,
                owner: ReservationOwner::Active(id1),
            },
            fragment_depth: 0,
        }
    );
    assert_eq!(h.history.unpushed_startup_state(), UnpushedStartup::None);

    assert!(h.history.retain_reservation(Some(res1)));
    assert_eq!(
        h.history.cursor_state(),
        CursorState::Entry {
            entry: ChatEntry::Reserved {
                token_id: 1,
                slot: 1,
                owner: ReservationOwner::Retained,
            },
            fragment_depth: 0,
        }
    );

    // Cancelling retained reservation unwinds back to List via UnwindToList.
    let cancel_op = h.history.cancel_retained_reservation();
    assert!(matches!(cancel_op, Some(HistoryOp::Back(_))));
    assert!(matches!(
        h.history.pending_navigation(),
        PendingNavigation::Back(PendingBack {
            goal: BackGoal::UnwindToList {
                deferred_open: None
            },
            remaining_hops: 0,
            ..
        })
    ));
    let _ = h.pop(Some(&list_tok), "");
    assert_eq!(h.history.cursor_state(), CursorState::List);
    assert_eq!(h.history.pending_navigation(), PendingNavigation::Idle);

    // Unpushed startup transitions None -> Active(id) -> Retained -> None (never both at once).
    let _ = h.open_push(alice, "");
    let unpushed = h.reserve_unpushed("");
    let Reservation::Unpushed { res_id, .. } = unpushed else {
        panic!("expected unpushed reservation");
    };
    assert_eq!(
        h.history.unpushed_startup_state(),
        UnpushedStartup::Active(res_id)
    );
    // `cancel_retained_reservation` must NOT clear an active (non-retained) unpushed reservation.
    assert_eq!(h.history.cancel_retained_reservation(), None);
    assert_eq!(
        h.history.unpushed_startup_state(),
        UnpushedStartup::Active(res_id)
    );

    assert!(h.history.retain_reservation(Some(unpushed)));
    assert_eq!(
        h.history.unpushed_startup_state(),
        UnpushedStartup::Retained
    );
    assert_eq!(h.history.cancel_retained_reservation(), None);
    assert_eq!(h.history.unpushed_startup_state(), UnpushedStartup::None);

    // Non-null foreign state strings (neither chat/frag/list nor null) are never mistaken for
    // untagged fragments and return cleanly to List.
    assert_eq!(
        h.pop(Some("unrelated-app-state"), "#section").ui,
        UiAction::Close
    );
    assert_eq!(h.history.cursor_state(), CursorState::List);
}
