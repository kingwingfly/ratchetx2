use session::PqSuite;

use crate::state::{ClassicalPrompt, ContactView, SecurityAlert, SecurityView};

use super::{
    chat::{contact_can_upgrade_to_pq, security_badge_parts},
    files::file_status_suffix,
    sidebar::chat_item_meta,
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
