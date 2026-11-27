use e2ee_chat_preview::{
    rpc::{DIAGRAM_SOURCE_MAX, HIGHLIGHT_MAX},
    validate_highlight_html,
};
use session::PqSuite;

use crate::{
    icon::Icon,
    state::{
        ClassicalPrompt, LastMessage, LastMessageKind, SecurityAlert, SecurityView, ServerPqStatus,
    },
    util::{key_to_text, key_to_url, sanitize_filename, sanitize_shared_name},
};

use super::{
    chat::{contact_can_upgrade_to_pq, security_badge_parts, upload_percent},
    common::{
        avatar_letters, extension, initials, invited_server_from_hash, make_contact,
        validate_invited_server,
    },
    dialogs::effective_invite_context,
    files::file_status_suffix,
    media::duration,
    pdf::{MAX_PDF_PAGES, cap_pdf_pages, pdf_aspect_ratio},
    settings::{server_pq_pill, strict_pq_toggle_disabled},
    sidebar::{ChatItemMeta, ChatItemSubtitle, KindBadge, chat_item_meta, last_message_badge},
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
    let status = |request_accent, warn, downgrade, text: &str| ChatItemMeta {
        request_accent,
        warn,
        downgrade,
        subtitle: ChatItemSubtitle::Status(text.to_string()),
    };

    let mut accepted_q = make_contact(7, "Alice");
    accepted_q.classical_prompt = ClassicalPrompt::InboundQuarantined {
        peer_was_pq_pinned: false,
    };
    assert_eq!(
        chat_item_meta(&accepted_q),
        status(false, true, false, "classical chat (quarantined)")
    );

    let mut request_q = accepted_q.clone();
    request_q.request = true;
    assert_eq!(
        chat_item_meta(&request_q),
        status(false, true, false, "classical request (quarantined)")
    );

    let mut downgrade_q = accepted_q;
    downgrade_q.downgrade_detected = true;
    assert_eq!(
        chat_item_meta(&downgrade_q),
        status(false, false, true, "downgrade detected (quarantined)")
    );

    let mut outbound = make_contact(7, "Alice");
    outbound.classical_prompt = ClassicalPrompt::Outbound;
    assert_eq!(
        chat_item_meta(&outbound),
        status(false, true, false, "classical approval needed")
    );

    let mut expired = make_contact(7, "Alice");
    expired.alert = SecurityAlert::ManifestExpired;
    assert_eq!(
        chat_item_meta(&expired),
        status(false, true, false, "peer PQ manifest expired")
    );
    let mut strict = make_contact(7, "Alice");
    strict.alert = SecurityAlert::PqRequired;
    assert_eq!(
        chat_item_meta(&strict),
        status(false, true, false, "PQ required (paused)")
    );
}

#[test]
fn chat_item_meta_shows_typed_last_message_and_prevents_text_spoofing() {
    let mut chat = make_contact(7, "Alice");
    assert_eq!(
        chat_item_meta(&chat).subtitle,
        ChatItemSubtitle::Status(crate::util::short(&chat.peer))
    );

    // Plain text that mimics a photo label renders as plain text with NO badge.
    let spoofed_text = LastMessage {
        kind: LastMessageKind::Text,
        outgoing: false,
        text: "Photo - super girl.jpeg".to_string(),
    };
    assert_eq!(last_message_badge(&spoofed_text), None);
    chat.last_message = Some(spoofed_text.clone());
    assert_eq!(
        chat_item_meta(&chat).subtitle,
        ChatItemSubtitle::Message(spoofed_text)
    );

    // A real image/video/audio/file/contact/system event carries a typed badge the sender cannot forge.
    let real_photo = LastMessage {
        kind: LastMessageKind::Image,
        outgoing: false,
        text: "super girl.jpeg".to_string(),
    };
    assert_eq!(
        last_message_badge(&real_photo),
        Some(KindBadge {
            icon: Some(Icon::Photo),
            label: "Photo",
            class: "chat-kind-badge",
        })
    );
    assert_eq!(
        last_message_badge(&LastMessage {
            kind: LastMessageKind::Video,
            outgoing: true,
            text: "clip.mp4".to_string(),
        }),
        Some(KindBadge {
            icon: Some(Icon::Video),
            label: "Video",
            class: "chat-kind-badge",
        })
    );
    assert_eq!(
        last_message_badge(&LastMessage {
            kind: LastMessageKind::Deleted,
            outgoing: false,
            text: String::new(),
        }),
        Some(KindBadge {
            icon: Some(Icon::Delete),
            label: "Deleted chat",
            class: "chat-kind-badge warn",
        })
    );

    // Requests and security alerts still take precedence over last_message.
    chat.last_message = Some(real_photo);
    let mut request = chat.clone();
    request.request = true;
    assert_eq!(
        chat_item_meta(&request),
        ChatItemMeta {
            request_accent: true,
            warn: false,
            downgrade: false,
            subtitle: ChatItemSubtitle::Status("wants to chat".to_string()),
        }
    );

    let mut expired = chat.clone();
    expired.alert = SecurityAlert::ManifestExpired;
    assert_eq!(
        chat_item_meta(&expired).subtitle,
        ChatItemSubtitle::Status("peer PQ manifest expired".to_string())
    );

    let mut downgrade = chat.clone();
    downgrade.downgrade_detected = true;
    assert_eq!(
        chat_item_meta(&downgrade),
        ChatItemMeta {
            request_accent: false,
            warn: false,
            downgrade: true,
            subtitle: ChatItemSubtitle::Status("downgrade detected".to_string()),
        }
    );

    // Unsent outbound chat request shows "sending request…" distinctly from "waiting for acceptance".
    let mut unsent = chat.clone();
    unsent.greeting_unsent = true;
    assert_eq!(
        chat_item_meta(&unsent),
        ChatItemMeta {
            request_accent: false,
            warn: false,
            downgrade: false,
            subtitle: ChatItemSubtitle::Status("sending request…".to_string()),
        }
    );

    // Outbound chat awaiting peer acceptance shows "waiting for acceptance" even with a queued
    // last_message, while incoming requests and security warnings still take precedence.
    let mut awaiting = chat.clone();
    awaiting.awaiting_acceptance = true;
    assert_eq!(
        chat_item_meta(&awaiting),
        ChatItemMeta {
            request_accent: false,
            warn: false,
            downgrade: false,
            subtitle: ChatItemSubtitle::Status("waiting for acceptance".to_string()),
        }
    );
    let mut awaiting_and_request = awaiting.clone();
    awaiting_and_request.request = true;
    assert_eq!(
        chat_item_meta(&awaiting_and_request).subtitle,
        ChatItemSubtitle::Status("wants to chat".to_string())
    );
    let mut awaiting_and_outbound_prompt = awaiting;
    awaiting_and_outbound_prompt.classical_prompt = ClassicalPrompt::Outbound;
    assert_eq!(
        chat_item_meta(&awaiting_and_outbound_prompt),
        ChatItemMeta {
            request_accent: false,
            warn: true,
            downgrade: false,
            subtitle: ChatItemSubtitle::Status("classical approval needed".to_string()),
        }
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
