use e2ee_chat_preview::rpc::{DIAGRAM_SOURCE_MAX, HIGHLIGHT_MAX};
use session::{PqSuite, PublicKey};

use crate::{
    preview::validate_highlight_html,
    state::{ClassicalPrompt, SecurityAlert, SecurityView, ServerPqStatus},
    util::{hex, key_to_text, key_to_url, sanitize_filename, sanitize_shared_name},
};

use super::{
    chat::{contact_can_upgrade_to_pq, security_badge_parts, upload_percent},
    common::{
        avatar_letters, extension, initials, invited_server_from_hash, make_contact,
        validate_invited_server,
    },
    dialogs::effective_invite_context,
    files::file_status_suffix,
    history::{ChatHistory, HistoryOp, MAX_ENTRIES, Reservation, Transition, UiAction},
    media::duration,
    pdf::{MAX_PDF_PAGES, cap_pdf_pages, pdf_aspect_ratio},
    settings::{server_pq_pill, strict_pq_toggle_disabled},
    sidebar::chat_item_meta,
    viewer::{
        EnhancePlan, MAX_ENHANCE_BLOCKS, plan_enhance_block, preview_fragment_candidates,
        sanitize_archive_path,
    },
};

#[test]
fn retired_pq_pinned_session_shows_neutral_ended_badge_and_not_classical() {
    let mut contact = make_contact(7, "Alice");
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
    let contact = make_contact(7, "Alice");

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
    let mut contact = make_contact(7, "Alice");
    contact.pq_pinned = true;
    contact.downgrade_detected = true;

    let (class, label, _) = security_badge_parts(&contact, false);
    assert_eq!(class, "sec-badge danger");
    assert_eq!(label, "Downgrade detected");
    assert!(contact_can_upgrade_to_pq(&contact));
}

#[test]
fn active_sessions_show_pq_or_classical_badges_and_upgrade_rules() {
    let mut classical = make_contact(7, "Alice");
    classical.has_active_session = true;
    let (class, label, _) = security_badge_parts(&classical, false);
    assert_eq!(class, "sec-badge classical");
    assert_eq!(label, "Classical only");
    assert!(contact_can_upgrade_to_pq(&classical));

    let mut pq = make_contact(7, "Alice");
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

    let mut quarantined = make_contact(7, "Alice");
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
    let mut accepted_q = make_contact(7, "Alice");
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

    let mut outbound = make_contact(7, "Alice");
    outbound.classical_prompt = ClassicalPrompt::Outbound {
        peer_signed_off: true,
    };
    assert_eq!(
        chat_item_meta(&outbound),
        (false, true, false, "classical approval needed".to_string())
    );

    let mut expired = make_contact(7, "Alice");
    expired.alert = SecurityAlert::ManifestExpired;
    assert_eq!(
        chat_item_meta(&expired),
        (false, true, false, "peer PQ manifest expired".to_string())
    );
    let mut strict = make_contact(7, "Alice");
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
    assert_eq!(
        file_status_suffix(false, false, true, false, true),
        Some("upload cancelled")
    );
    assert_eq!(
        file_status_suffix(false, false, false, true, true),
        Some("on server")
    );
    assert_eq!(
        file_status_suffix(false, false, false, false, true),
        Some("waiting to upload")
    );
    assert_eq!(file_status_suffix(false, false, false, false, false), None);
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
fn sanitize_filename_strips_bidi_controls_separators_reserved_names_and_caps_length() {
    // BiDi RLO extension spoofing (`invoice_\u{202E}fdp.exe` renders visually as `invoice_exe.pdf`).
    assert_eq!(
        sanitize_filename("invoice_\u{202E}fdp.exe"),
        "invoice_fdp.exe"
    );
    // Isolates, ZWJ, BOM, and ASCII control chars stripped; spaces collapsed.
    assert_eq!(
        sanitize_filename("\u{FEFF}a\u{2066}\u{200D}b\x00\n\r\tc\x07.txt"),
        "abc.txt"
    );
    assert_eq!(sanitize_filename("a   b\u{00A0}\u{00A0}c.txt"), "a b c.txt");
    // Path separators and filesystem-unsafe characters replaced with `_` (leading dots trimmed).
    assert_eq!(
        sanitize_filename("../../etc/passwd:evil*?\"<>|\\x"),
        "_.._etc_passwd_evil_______x"
    );
    // Leading/trailing dots and spaces stripped; empty/dots-only falls back to `"file"`.
    assert_eq!(sanitize_filename("  ...report.pdf...  "), "report.pdf");
    assert_eq!(sanitize_filename("...   ..."), "file");
    assert_eq!(sanitize_filename("\u{202E}\x00"), "file");
    // Windows reserved device names guarded (case-insensitive, with or without extension).
    assert_eq!(sanitize_filename("CON"), "_CON");
    assert_eq!(sanitize_filename("nul.txt"), "_nul.txt");
    assert_eq!(sanitize_filename("com1.pdf"), "_com1.pdf");
    assert_eq!(sanitize_filename("LPT9"), "_LPT9");
    assert_eq!(sanitize_filename("console.txt"), "console.txt");
    // Length cap preserves reasonable extension.
    let long = format!("{}.tar.gz", "a".repeat(250));
    let capped = sanitize_filename(&long);
    assert!(capped.chars().count() <= 200);
    assert!(capped.ends_with(".gz"));
    // Shared-name sanitizer also strips BiDi overrides and control chars.
    assert_eq!(sanitize_shared_name("Alice\u{202E}\x07  Bob"), "Alice Bob");
}

#[test]
fn invited_server_validates_relay_urls_and_rejects_unsafe_schemes() {
    let key = key_to_url(&[0xAB; 32]);
    // Valid HTTPS origins (canonicalized, default port & trailing slash stripped).
    assert_eq!(
        validate_invited_server(Some("https://relay.example.com:443/")),
        Some("https://relay.example.com".to_string())
    );
    assert_eq!(
        validate_invited_server(Some("https://relay.example.com:8443")),
        Some("https://relay.example.com:8443".to_string())
    );
    // Localhost and loopback HTTP allowed for local dev.
    assert_eq!(
        validate_invited_server(Some("http://localhost:8787")),
        Some("http://localhost:8787".to_string())
    );
    assert_eq!(
        validate_invited_server(Some("http://127.0.0.1:8787/")),
        Some("http://127.0.0.1:8787".to_string())
    );
    assert_eq!(
        validate_invited_server(Some("http://[::1]:8787")),
        Some("http://[::1]:8787".to_string())
    );
    // Plaintext non-localhost HTTP, WS, JS, credentials, paths, queries, fragments, bare hosts rejected.
    for bad in [
        "",
        "   ",
        "http://evil.example",
        "http://localhost.evil.example",
        "ws://relay.example",
        "wss://relay.example",
        "javascript:alert(1)",
        "data:text/html,hi",
        "relay.example",
        "https://user:pass@relay.example",
        "https://relay.example/api",
        "https://relay.example/?x=1",
        "https://relay.example/#frag",
    ] {
        assert_eq!(
            validate_invited_server(Some(bad)),
            None,
            "expected {bad:?} to be rejected"
        );
    }
    // End-to-end fragment parsing + validation.
    let valid_hash = format!("#chat={key}&server=https%3A%2F%2Fother.example%3A443%2F&pq=1");
    assert_eq!(
        invited_server_from_hash(&valid_hash),
        Some("https://other.example".to_string())
    );
    let bad_hash = format!("#chat={key}&server=http%3A%2F%2Fattacker.example");
    assert_eq!(invited_server_from_hash(&bad_hash), None);
}

#[test]
fn pdf_aspect_ratio_clamps_extremes_and_pages_cap_truncates_safely() {
    assert_eq!(pdf_aspect_ratio(595.5, 842.0), "595.5 / 842");
    assert_eq!(pdf_aspect_ratio(10.0, 100.0), "10 / 100");
    assert_eq!(pdf_aspect_ratio(100.0, 10.0), "100 / 10");
    // Extreme aspect ratios clamped to 0.1..=10.0.
    assert_eq!(pdf_aspect_ratio(1.0, 1e7), "1 / 10");
    assert_eq!(pdf_aspect_ratio(1e7, 1.0), "10 / 1");
    // Non-positive, NaN, infinite, and overflowing/underflowing ratios fall back to US Letter.
    for (w, h) in [
        (0.0, 842.0),
        (595.0, 0.0),
        (-10.0, 842.0),
        (f64::NAN, 842.0),
        (f64::INFINITY, 842.0),
        (1e308, 1e-308),
        (1e-308, 1e308),
    ] {
        assert_eq!(
            pdf_aspect_ratio(w, h),
            "612 / 792",
            "expected fallback for ({w}, {h})"
        );
    }
    // Page count cap.
    let small = vec![(612.0, 792.0); 5];
    let (kept, total) = cap_pdf_pages(small);
    assert_eq!(kept.len(), 5);
    assert_eq!(total, 5);

    let bomb = vec![(612.0, 792.0); MAX_PDF_PAGES + 123];
    let (kept, total) = cap_pdf_pages(bomb);
    assert_eq!(kept.len(), MAX_PDF_PAGES);
    assert_eq!(total, MAX_PDF_PAGES + 123);
}

#[test]
fn new_chat_key_edit_clears_invited_server_and_pq_pin() {
    let alice = [0x11; 32];
    let bob = [0x22; 32];
    let alice_url = key_to_url(&alice);
    let alice_std = key_to_text(&alice);
    let bob_std = key_to_text(&bob);

    // Exact match preserves both invited server and PQ pin.
    assert_eq!(
        effective_invite_context(&alice_url, &alice_url, Some("https://other.example"), true),
        (Some("https://other.example".to_string()), true)
    );
    // Re-encoding the same key (URL-safe -> standard base64 + whitespace) still matches.
    assert_eq!(
        effective_invite_context(
            &alice_url,
            &format!("  {alice_std}  "),
            Some("https://other.example"),
            true
        ),
        (Some("https://other.example".to_string()), true)
    );
    // Replacing the key with another peer's key clears both server and pq_pinned.
    assert_eq!(
        effective_invite_context(&alice_url, &bob_std, Some("https://other.example"), true),
        (None, false)
    );
    // Clearing or typing an invalid key clears both server and pq_pinned.
    assert_eq!(
        effective_invite_context(&alice_url, "", Some("https://other.example"), true),
        (None, false)
    );
    assert_eq!(
        effective_invite_context(&alice_url, "not-a-key", Some("https://other.example"), true),
        (None, false)
    );
    // Manual "New chat" with empty invited key never inherits invite metadata.
    assert_eq!(
        effective_invite_context("", &alice_std, Some("https://other.example"), true),
        (None, false)
    );
}

#[test]
fn settings_server_pq_pill_and_strict_pq_toggle_rules() {
    let (cls, label, tip) = server_pq_pill(&ServerPqStatus::Enabled {
        suites: vec![PqSuite::MlKem1024, PqSuite::MlKem768],
        pq_ratchet: true,
    });
    assert_eq!((cls, label), ("sec-badge pq", "Server: PQ ready"));
    assert!(tip.contains("ML-KEM-1024, ML-KEM-768"));
    assert!(tip.contains("continuous re-keying"));

    let (cls, label, tip) = server_pq_pill(&ServerPqStatus::Enabled {
        suites: vec![],
        pq_ratchet: false,
    });
    assert_eq!((cls, label), ("sec-badge pq", "Server: PQ ready"));
    assert!(tip.contains("enabled"));
    assert!(!tip.contains("continuous re-keying"));

    assert_eq!(
        server_pq_pill(&ServerPqStatus::Disabled).0,
        "sec-badge classical"
    );
    assert_eq!(
        server_pq_pill(&ServerPqStatus::AudienceMismatch).0,
        "sec-badge danger"
    );
    assert_eq!(
        server_pq_pill(&ServerPqStatus::Unknown).0,
        "sec-badge neutral"
    );

    // Strict PQ toggle rules:
    assert!(!strict_pq_toggle_disabled(false, true, false, false));
    assert!(strict_pq_toggle_disabled(true, true, false, false));
    assert!(strict_pq_toggle_disabled(false, false, false, false));
    assert!(strict_pq_toggle_disabled(false, false, false, true));
    // When server has PQ disabled, user cannot turn strict PQ on, but CAN still turn it off.
    assert!(strict_pq_toggle_disabled(false, true, true, false));
    assert!(!strict_pq_toggle_disabled(false, true, true, true));
}

#[test]
fn common_avatar_letters_initials_and_extension_edge_cases() {
    let peer = [0xA1; 32];
    assert_eq!(initials(""), "");
    assert_eq!(initials("   "), "");
    assert_eq!(initials("Alice"), "A");
    assert_eq!(initials("Alice Bob Carol"), "AB");
    assert_eq!(initials("Élodie 张"), "É张");

    // Unnamed or whitespace-only peer uses first hex byte (not `initials(&short(&peer))` = "ac").
    assert_eq!(avatar_letters("", &peer), "a1");
    assert_eq!(avatar_letters("   ", &peer), "a1");
    assert_eq!(avatar_letters("Alice Smith", &peer), "AS");

    assert_eq!(extension("README"), "file");
    assert_eq!(extension("trailing."), "file");
    assert_eq!(extension(".gitignore"), "gitignore");
    assert_eq!(extension("ARCHIVE.TAR.GZ"), "gz");
    assert_eq!(extension("photo.JPEG"), "jpeg");
}

#[test]
fn media_duration_handles_edge_cases() {
    assert_eq!(duration(0.0), "0:00");
    assert_eq!(duration(-5.0), "0:00");
    assert_eq!(duration(f64::NAN), "0:00");
    assert_eq!(duration(f64::INFINITY), "0:00");
    assert_eq!(duration(f64::NEG_INFINITY), "0:00");
    assert_eq!(duration(5.4), "0:05");
    assert_eq!(duration(59.6), "1:00");
    assert_eq!(duration(60.0), "1:00");
    assert_eq!(duration(3599.6), "1:00:00");
    assert_eq!(duration(3661.0), "1:01:01");
    assert!(duration(1e30).contains(':'));
}

#[test]
fn viewer_enhance_budget_and_highlight_validation_work() {
    // Unknown language is ignored cleanly (`None`).
    assert_eq!(plan_enhance_block("unknown-lang-xyz", 10, 0), None);
    // Mermaid within and over DIAGRAM_SOURCE_MAX.
    assert_eq!(
        plan_enhance_block("mermaid", DIAGRAM_SOURCE_MAX, 0),
        Some(EnhancePlan::Diagram)
    );
    assert_eq!(
        plan_enhance_block("MERMAID", DIAGRAM_SOURCE_MAX + 1, 0),
        Some(EnhancePlan::Skip("diagram source is too large"))
    );
    // Code block within and over HIGHLIGHT_MAX.
    assert!(matches!(
        plan_enhance_block("rust", HIGHLIGHT_MAX, 0),
        Some(EnhancePlan::Highlight(_))
    ));
    assert_eq!(
        plan_enhance_block("rust", HIGHLIGHT_MAX + 1, 0),
        Some(EnhancePlan::Skip("code block is too large to highlight"))
    );
    // Document-wide block count cap.
    assert_eq!(
        plan_enhance_block("rust", 16, MAX_ENHANCE_BLOCKS),
        Some(EnhancePlan::Skip("too many enhanced blocks in document"))
    );
    assert_eq!(
        plan_enhance_block("mermaid", 16, MAX_ENHANCE_BLOCKS),
        Some(EnhancePlan::Skip("too many enhanced blocks in document"))
    );

    // Highlighted HTML validation rejects XSS/unexpected tags while allowing arborium spans.
    assert!(validate_highlight_html("<span class=\"hl-keyword\">fn</span> main() &amp;").is_ok());
    assert!(validate_highlight_html("<img src=x onerror=alert(1)>").is_err());
    assert!(validate_highlight_html("<span class=\"hl-keyword\" onclick=\"x\">a</span>").is_err());
    assert!(validate_highlight_html("<span class=\"hl-keyword\">unclosed").is_err());

    // Archive path display strips BiDi/controls while preserving directory slashes.
    assert_eq!(
        sanitize_archive_path("dir/\u{202E}file\x00.txt"),
        "dir/file.txt"
    );
}

#[test]
fn upload_percent_clamps_and_avoids_overflow() {
    assert_eq!(upload_percent(0, 0), 0);
    assert_eq!(upload_percent(50, 100), 50);
    // XHR framing overhead can report done > size; percentage must stay within 0..=100.
    assert_eq!(upload_percent(120, 100), 100);
    assert_eq!(upload_percent(u64::MAX, u64::MAX), 100);
    assert_eq!(upload_percent((u64::MAX - 1) / 2, u64::MAX - 1), 50);
}

// ---------------------------------------------------------------------------
// ChatHistory state-machine harness and behavioral suite
// ---------------------------------------------------------------------------

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
