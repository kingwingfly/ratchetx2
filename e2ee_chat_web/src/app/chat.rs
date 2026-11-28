use leptos::{ev, html, prelude::*};
use session::PublicKey;
use wasm_bindgen::JsCast;

use crate::{
    icon::{Icon, icon},
    state::{
        Body, ClassicalPrompt, ContactView, Delivery, Dialog, MessageRow, SecurityAlert,
        SharedContact, UploadState, UploadView,
    },
    util::{clock, hex, sanitize_filename, sanitize_shared_name, short},
};

use super::{
    common::{
        AllowClassical, act, act_while, avatar_letters, can_allow_classical, extension,
        open_new_chat_for_shared, pq_available, pq_retry_ready, server_pq_disabled,
        strict_pq_enabled, upgrade_disabled_tip,
    },
    composer::Composer,
    engine, history,
    media::{InlineMedia, Source, file_card, inline_media},
    ui,
};

/// Compute `(css_class, label, tooltip)` for a contact's security badge (`detailed` shows the full
/// label in `ContactInfo`).
pub(super) fn security_badge_parts(
    contact: &ContactView,
    detailed: bool,
) -> (&'static str, String, String) {
    if contact.has_downgrade() {
        (
            "sec-badge danger",
            "Downgrade detected".to_string(),
            "Post-quantum downgrade detected for this chat".to_string(),
        )
    } else if contact.is_quarantined() {
        let label = if detailed {
            "Classical chat quarantined — review before replying"
        } else {
            "Quarantined"
        };
        (
            "sec-badge classical",
            label.to_string(),
            "Classical chat quarantined — review before replying".to_string(),
        )
    } else if !contact.has_active_session {
        if contact.pq_pinned {
            let label = if detailed {
                "Session ended — next message starts a new post-quantum session"
            } else {
                "PQ · Session ended"
            };
            (
                "sec-badge neutral",
                label.to_string(),
                "Session ended; post-quantum encryption is pinned for the next session".to_string(),
            )
        } else {
            let label = if detailed {
                "No active session — next message starts a new session"
            } else {
                "Session ended"
            };
            (
                "sec-badge neutral",
                label.to_string(),
                "No active session — next message starts a new session".to_string(),
            )
        }
    } else if contact.security.is_pq {
        let text = if detailed {
            contact.security.detail_label()
        } else {
            contact.security.badge_label()
        };
        ("sec-badge pq", text, contact.security.detail_label())
    } else {
        (
            "sec-badge classical",
            "Classical only".to_string(),
            contact.security.detail_label(),
        )
    }
}

/// Whether `ContactInfo` should offer `"Upgrade to PQ"` for `contact` when local PQ is available.
pub(super) fn contact_can_upgrade_to_pq(contact: &ContactView) -> bool {
    contact.has_downgrade()
        || contact.is_quarantined()
        || (!contact.has_active_session && contact.has_classical_earlier)
        || (contact.has_active_session && !contact.security.is_pq)
}

/// Render a security status badge for `contact` (`detailed` shows the full label in `ContactInfo`).
pub(super) fn security_badge(contact: &ContactView, detailed: bool) -> AnyView {
    let (class, label, title) = security_badge_parts(contact, detailed);
    view! {
        <span class=class title=title>
            {label}
        </span>
    }
    .into_any()
}

#[component]
pub(super) fn ChatPane(peer: PublicKey) -> impl IntoView {
    let ui = ui();
    let contact = move || ui.contact(&peer);
    let label = move || contact().map(|contact| contact.label()).unwrap_or_default();
    let request = move || contact().is_some_and(|contact| contact.request);
    let greeting_unsent = move || contact().is_some_and(|contact| contact.greeting_unsent);
    let greeting_uncertain = move || contact().is_some_and(|contact| contact.greeting_uncertain);
    let greeting_unconfirmed = move || greeting_unsent() || greeting_uncertain();
    let awaiting_acceptance = move || contact().is_some_and(|contact| contact.awaiting_acceptance);
    let quarantined = move || contact().is_some_and(|contact| contact.is_quarantined());
    let strict_pq = Memo::new(move |_| strict_pq_enabled(ui));
    let composer_disabled = move || request() || quarantined();
    let composer_placeholder = move || {
        if quarantined() {
            if strict_pq.get() {
                "Strict PQ mode: upgrade to PQ to write"
            } else {
                "Allow classical or upgrade to PQ to write"
            }
        } else if request() {
            "Accept the request to write"
        } else if greeting_unconfirmed() || awaiting_acceptance() {
            "Write a message (delivers once accepted)"
        } else {
            "Write a message"
        }
    };
    let sec_busy = RwSignal::new(false);
    view! {
        <section class="pane">
            <header class="pane-head">
                <button
                    class="btn icon quiet back"
                    title="Back to the chats"
                    aria-label="Back to the chats"
                    on:click=move |_| history::navigate(None)
                >
                    {icon(Icon::Back)}
                </button>
                <span class="avatar">
                    {move || {
                        contact()
                            .map(|c| avatar_letters(&c.name, &peer))
                            .unwrap_or_else(|| hex(&peer[..1]))
                    }}
                </span>
                <div class="pane-title">
                    <strong>{label}</strong>
                    <div class="pane-sub">
                        <span>{short(&peer)}</span>
                        {move || contact().map(|c| security_badge(&c, false))}
                    </div>
                </div>
                <button
                    class="btn icon"
                    title="Files of this chat"
                    aria-label="Files of this chat"
                    on:click=move |_| ui.dialog.set(Some(Dialog::Files(peer)))
                >
                    {icon(Icon::Folder)}
                </button>
                <button
                    class="btn icon"
                    title="About this chat"
                    aria-label="About this chat"
                    on:click=move |_| ui.dialog.set(Some(Dialog::Contact(peer)))
                >
                    {icon(Icon::Info)}
                </button>
                <button
                    class="btn icon quiet close"
                    title="Close the chat"
                    aria-label="Close the chat"
                    on:click=move |_| history::navigate(None)
                >
                    {icon(Icon::Close)}
                </button>
            </header>
            {move || {
                let c = contact()?;
                // Suppress standalone downgrade banner when the merged quarantine banner is active
                // so the user never sees two stacked "Upgrade to PQ" primary buttons.
                if c.has_downgrade() && !c.is_quarantined() {
                    let conv_gen = c.conversation_gen;
                    Some(
                        view! {
                            <div class="banner danger" role="alert">
                                <span>
                                    "Downgrade detected: this peer supports or was pinned for post-quantum encryption, but a classical or tampered handshake was received."
                                </span>
                                <div class="banner-actions">
                                    <Show when=move || pq_available(ui)>
                                        <button
                                            type="button"
                                            class="btn primary small"
                                            title=move || upgrade_disabled_tip(ui)
                                            disabled=move || sec_busy.get() || server_pq_disabled(ui)
                                            on:click=move |_| {
                                                act_while(sec_busy, async move {
                                                    engine()
                                                        .upgrade_to_pq_for_gen(peer, conv_gen)
                                                        .await
                                                });
                                            }
                                        >
                                            "Upgrade to PQ"
                                        </button>
                                    </Show>
                                    <button
                                        type="button"
                                        class="btn small"
                                        disabled=move || sec_busy.get()
                                        on:click=move |_| {
                                            act_while(sec_busy, async move {
                                                engine()
                                                    .dismiss_downgrade_for_gen(peer, conv_gen)
                                                    .await
                                            });
                                        }
                                    >
                                        "Dismiss"
                                    </button>
                                </div>
                            </div>
                        }
                        .into_any(),
                    )
                } else {
                    None
                }
            }}
            {move || {
                let c = contact()?;
                let strict_pq = strict_pq.get();
                let show_allow = can_allow_classical(c.classical_prompt, strict_pq);
                match c.classical_prompt {
                    ClassicalPrompt::InboundQuarantined { peer_was_pq_pinned } => {
                        let downgrade = peer_was_pq_pinned || c.has_downgrade();
                        let banner_class = if downgrade {
                            "banner danger"
                        } else {
                            "banner warn"
                        };
                        Some(
                            view! {
                                <div class=banner_class role="alert">
                                    <span>
                                        {if downgrade {
                                            "Downgrade detected — classical session quarantined: this peer was previously pinned as post-quantum capable. "
                                        } else {
                                            "Classical chat request quarantined: this peer initiated without post-quantum encryption. "
                                        }}
                                        {if strict_pq {
                                            "Require post-quantum (strict mode) blocks classical exceptions. Upgrade to PQ or disable strict mode in Settings."
                                        } else if downgrade {
                                            "Its incoming message is held until you explicitly allow classical encryption or upgrade to PQ."
                                        } else {
                                            "Its message is held until you allow classical encryption."
                                        }}
                                    </span>
                                    <div class="banner-actions">
                                        {show_allow.then(|| {
                                            view! {
                                                <AllowClassical
                                                    peer
                                                    conversation_gen=c.conversation_gen
                                                    busy=sec_busy
                                                />
                                            }
                                        })}
                                        <Show when=move || pq_available(ui)>
                                            <button
                                                type="button"
                                                class="btn primary small"
                                                title=move || upgrade_disabled_tip(ui)
                                                disabled=move || {
                                                    sec_busy.get() || server_pq_disabled(ui)
                                                }
                                                on:click=move |_| {
                                                    let conv_gen = c.conversation_gen;
                                                    act_while(sec_busy, async move {
                                                        engine()
                                                            .upgrade_to_pq_for_gen(peer, conv_gen)
                                                            .await
                                                    });
                                                }
                                            >
                                                "Upgrade to PQ"
                                            </button>
                                        </Show>
                                    </div>
                                </div>
                            }
                            .into_any(),
                        )
                    }
                    ClassicalPrompt::Outbound | ClassicalPrompt::ServerPqDisabled => {
                        let lead = if c.classical_prompt == ClassicalPrompt::ServerPqDisabled {
                            "Sending paused: this server currently has post-quantum encryption disabled. "
                        } else {
                            "Sending paused: this peer published a signed manifest disabling post-quantum encryption. "
                        };
                        Some(
                            view! {
                                <div class="banner warn" role="alert">
                                    <span>
                                        {lead}
                                        {if strict_pq {
                                            "Require post-quantum (strict mode) blocks classical fallback. Retry PQ when available or disable strict mode in Settings."
                                        } else {
                                            "Allow classical fallback to send?"
                                        }}
                                    </span>
                                {move || {
                                    let show_retry = pq_retry_ready(ui);
                                    let conv_gen = c.conversation_gen;
                                    (show_allow || show_retry).then(|| {
                                        view! {
                                            <div class="banner-actions">
                                                {show_allow.then(|| {
                                                    view! {
                                                        <AllowClassical
                                                            peer
                                                            conversation_gen=conv_gen
                                                            busy=sec_busy
                                                        />
                                                    }
                                                })}
                                                {show_retry.then(|| {
                                                    view! {
                                                        <button
                                                            type="button"
                                                            class="btn primary small"
                                                            disabled=move || sec_busy.get()
                                                            on:click=move |_| {
                                                                act_while(sec_busy, async move {
                                                                    engine()
                                                                        .retry_pq_for_gen(peer, conv_gen)
                                                                        .await
                                                                });
                                                            }
                                                        >
                                                            "Retry PQ"
                                                        </button>
                                                    }
                                                })}
                                            </div>
                                        }
                                    })
                                }}
                            </div>
                        }
                        .into_any(),
                    )
                    }
                    ClassicalPrompt::None => None,
                }
            }}
            {move || {
                let c = contact()?;
                let can_dismiss = !c.is_quarantined();
                let show_retry = !c.is_quarantined() && pq_retry_ready(ui);
                match c.alert {
                    SecurityAlert::ManifestExpired => Some(
                        view! {
                            <div class="banner warn" role="alert">
                                <span>
                                    "Peer's signed post-quantum capability manifest has expired (they may have been offline for a while)."
                                </span>
                                {(show_retry || can_dismiss).then(|| {
                                    view! {
                                        <div class="banner-actions">
                                            {show_retry.then(|| {
                                                let conv_gen = c.conversation_gen;
                                                view! {
                                                    <button
                                                        type="button"
                                                        class="btn small"
                                                        disabled=move || sec_busy.get()
                                                        on:click=move |_| {
                                                            act_while(sec_busy, async move {
                                                                engine()
                                                                    .retry_pq_for_gen(peer, conv_gen)
                                                                    .await
                                                            });
                                                        }
                                                    >
                                                        "Retry"
                                                    </button>
                                                }
                                            })}
                                            {can_dismiss.then(|| {
                                                let conv_gen = c.conversation_gen;
                                                view! {
                                                    <button
                                                        type="button"
                                                        class="btn small"
                                                        disabled=move || sec_busy.get()
                                                        on:click=move |_| {
                                                            act_while(sec_busy, async move {
                                                                engine()
                                                                    .dismiss_downgrade_for_gen(
                                                                        peer, conv_gen,
                                                                    )
                                                                    .await
                                                            });
                                                        }
                                                    >
                                                        "Dismiss"
                                                    </button>
                                                }
                                            })}
                                        </div>
                                    }
                                })}
                            </div>
                        }
                        .into_any(),
                    ),
                    SecurityAlert::PqRequired => Some(
                        view! {
                            <div class="banner warn" role="alert">
                                <span>
                                    {if strict_pq_enabled(ui) {
                                        "Require PQ (strict mode) is enabled, and a post-quantum session could not be established with this peer."
                                    } else {
                                        "A post-quantum session could not be established with this peer while strict PQ mode was enabled."
                                    }}
                                </span>
                                {(show_retry || can_dismiss).then(|| {
                                    view! {
                                        <div class="banner-actions">
                                            {show_retry.then(|| {
                                                let conv_gen = c.conversation_gen;
                                                view! {
                                                    <button
                                                        type="button"
                                                        class="btn small"
                                                        disabled=move || sec_busy.get()
                                                        on:click=move |_| {
                                                            act_while(sec_busy, async move {
                                                                engine()
                                                                    .retry_pq_for_gen(peer, conv_gen)
                                                                    .await
                                                            });
                                                        }
                                                    >
                                                        "Retry"
                                                    </button>
                                                }
                                            })}
                                            {can_dismiss.then(|| {
                                                let conv_gen = c.conversation_gen;
                                                view! {
                                                    <button
                                                        type="button"
                                                        class="btn small"
                                                        disabled=move || sec_busy.get()
                                                        on:click=move |_| {
                                                            act_while(sec_busy, async move {
                                                                engine()
                                                                    .dismiss_downgrade_for_gen(
                                                                        peer, conv_gen,
                                                                    )
                                                                    .await
                                                            });
                                                        }
                                                    >
                                                        "Dismiss"
                                                    </button>
                                                }
                                            })}
                                        </div>
                                    }
                                })}
                            </div>
                        }
                        .into_any(),
                    ),
                    _ => None,
                }
            }}
            <Show when=move || request() && !quarantined()>
                <div class="banner">
                    <span>
                        {format!(
                            "{} wants to chat. Read what they sent, then accept or delete the request.",
                            short(&peer),
                        )}
                    </span>
                    <button
                        class="btn primary small"
                        on:click=move |_| ui.dialog.set(Some(Dialog::Contact(peer)))
                    >
                        "accept or delete…"
                    </button>
                </div>
            </Show>
            <Show when=move || greeting_unsent() && !request() && !quarantined()>
                <div class="banner awaiting-acceptance" role="status">
                    <span>
                        {move || {
                            format!(
                                "Sending chat request to {}… It hasn't reached the server yet and will retry automatically once connected.",
                                label(),
                            )
                        }}
                    </span>
                </div>
            </Show>
            <Show when=move || greeting_uncertain() && !request() && !quarantined()>
                <div class="banner awaiting-acceptance" role="status">
                    <span>
                        {move || {
                            format!(
                                "Sending chat request to {}… Delivery hasn't been confirmed yet. Retrying automatically.",
                                label(),
                            )
                        }}
                    </span>
                </div>
            </Show>
            <Show when=move || awaiting_acceptance() && !request() && !quarantined()>
                <div class="banner awaiting-acceptance" role="status">
                    <span>
                        {move || {
                            format!(
                                "Waiting for {} to accept your chat request. Messages you send stay queued here and will deliver automatically once they accept.",
                                label(),
                            )
                        }}
                    </span>
                </div>
            </Show>
            <Messages
                peer
                label=Signal::derive(label)
                greeting_unsent=Signal::derive(greeting_unsent)
                greeting_uncertain=Signal::derive(greeting_uncertain)
                awaiting_acceptance=Signal::derive(awaiting_acceptance)
            />
            <Uploads peer />
            <Composer
                peer
                disabled=Signal::derive(composer_disabled)
                placeholder=Signal::derive(composer_placeholder)
            />
        </section>
    }
}

/// Pixels from the bottom of a chat within which it still follows the latest message.
const FOLLOW_SLACK: i32 = 40;

/// Snapshot of the topmost visible message row before prepending earlier history so the scroll
/// position can be restored after the new rows render (even at `scrollTop == 0` or on browsers
/// without CSS scroll anchoring).
fn capture_visible_anchor(list: &web_sys::Element) -> Option<(String, f64)> {
    let list_top = list.get_bounding_client_rect().top();
    let nodes = list.query_selector_all("[data-index]").ok()?;
    for i in 0..nodes.length() {
        let Some(node) = nodes.get(i) else {
            continue;
        };
        let Ok(el) = node.dyn_into::<web_sys::Element>() else {
            continue;
        };
        let rect = el.get_bounding_client_rect();
        if rect.bottom() > list_top
            && let Some(index) = el.get_attribute("data-index")
        {
            return Some((index, rect.top() - list_top));
        }
    }
    None
}

/// Restore the previously visible message row's offset relative to the scroll viewport after
/// prepending an earlier history page.
fn restore_visible_anchor(list: &web_sys::Element, anchor: &(String, f64)) {
    let selector = format!("[data-index=\"{}\"]", anchor.0);
    if let Ok(Some(el)) = list.query_selector(&selector) {
        let list_top = list.get_bounding_client_rect().top();
        let current_offset = el.get_bounding_client_rect().top() - list_top;
        let delta = (current_offset - anchor.1).round() as i32;
        if delta != 0 {
            list.set_scroll_top(list.scroll_top() + delta);
        }
    }
}

#[component]
fn Messages(
    peer: PublicKey,
    label: Signal<String>,
    greeting_unsent: Signal<bool>,
    greeting_uncertain: Signal<bool>,
    awaiting_acceptance: Signal<bool>,
) -> impl IntoView {
    let ui = ui();
    let list = NodeRef::<html::Div>::new();
    let loading_earlier = RwSignal::new(false);
    // Follow the latest message while at the bottom, so that what changes, as a sync goes,
    // does not move the history away from the user reading it; and on sending one.
    let follow = StoredValue::new(true);
    let newest = StoredValue::new(None::<u64>);
    let oldest = StoredValue::new(None::<u64>);
    // Anchor row refreshed on any user scroll while `load_earlier` awaits the engine mutex or
    // IndexedDB; consumed immediately inside the `ui.messages` effect when earlier rows prepend so
    // scroll position is restored before `inner.save_state().await` yields and before any scroll
    // event can overwrite the anchor.
    let pending_anchor = StoredValue::new(None::<(String, f64)>);
    let awaiting_earlier = StoredValue::new(false);
    Effect::new(move || {
        let (sent, prepended) = ui.messages.with(|messages| {
            let mut min_idx: Option<u64> = None;
            let mut max_msg: Option<(u64, bool)> = None;
            for message in messages {
                min_idx = Some(min_idx.map_or(message.index, |m| m.min(message.index)));
                if max_msg.is_none_or(|(idx, _)| message.index > idx) {
                    max_msg = Some((message.index, message.outgoing));
                }
            }
            let sent = max_msg.map(|(idx, outgoing)| {
                let new = newest.get_value().is_some_and(|prev| idx > prev);
                newest.set_value(Some(idx));
                new && outgoing
            });
            let prepended = min_idx.is_some_and(|idx| {
                let grew_older = oldest.get_value().is_some_and(|prev| idx < prev);
                oldest.set_value(Some(idx));
                grew_older
            });
            (sent, prepended)
        });
        if sent == Some(true) {
            follow.set_value(true);
        }
        let restore_anchor = if prepended && awaiting_earlier.get_value() {
            awaiting_earlier.set_value(false);
            pending_anchor.try_update_value(Option::take).flatten()
        } else {
            None
        };
        if let Some(list) = list.get() {
            // Unless the chat went meanwhile.
            request_animation_frame(move || {
                if !list.is_connected() {
                    return;
                }
                match follow.try_get_value() {
                    Some(true) => list.set_scroll_top(list.scroll_height()),
                    Some(false) => {
                        if let Some(anchor) = restore_anchor {
                            restore_visible_anchor(&list, &anchor);
                        }
                    }
                    None => {}
                }
            });
        }
    });
    let scrolled = move |_| {
        if let Some(list) = list.try_get_untracked().flatten() {
            let below = list.scroll_height() - list.scroll_top() - list.client_height();
            follow.try_set_value(below < FOLLOW_SLACK);
            if awaiting_earlier.try_get_value() == Some(true) {
                pending_anchor.try_set_value(capture_visible_anchor(&list));
            }
        }
    };
    view! {
        <div class="messages" node_ref=list aria-live="polite" on:scroll=scrolled>
            <Show when=move || ui.has_older_messages.get()>
                <button
                    type="button"
                    class="btn small load-earlier"
                    disabled=move || loading_earlier.get()
                    on:click=move |_| {
                        follow.set_value(false);
                        let initial_anchor = list
                            .try_get_untracked()
                            .flatten()
                            .and_then(|el| capture_visible_anchor(&el));
                        awaiting_earlier.set_value(initial_anchor.is_some());
                        pending_anchor.set_value(initial_anchor);
                        act_while(loading_earlier, async move {
                            let result = engine().load_earlier(peer).await;
                            // Only clean up when no older rows were prepended or an error
                            // occurred; when rows WERE prepended (`Ok(true)`), leave the anchor
                            // intact so `Messages`'s microtask `Effect` consumes and restores it
                            // (including when `load_earlier` returns without awaiting `save_state`).
                            if !matches!(result, Ok(true)) {
                                awaiting_earlier.try_set_value(false);
                                let _ = pending_anchor.try_update_value(Option::take);
                            }
                            result.map(|_| ())
                        });
                    }
                >
                    {move || {
                        if loading_earlier.get() {
                            "Loading earlier messages…"
                        } else {
                            "Load earlier messages"
                        }
                    }}
                </button>
            </Show>
            <For
                each=move || ui.messages.get()
                key=|message| message.index
                children=move |message| {
                    message_item(
                        peer,
                        message,
                        label,
                        greeting_unsent,
                        greeting_uncertain,
                        awaiting_acceptance,
                    )
                }
            />
        </div>
    }
}

/// A message, as a bubble, an image, a file, a shared contact card, or a note.
/// The notes name the peer by `label`, which changes once a request is accepted.
/// Delivery ticks and held-attachment pointer upgrades update via per-row reactive signals in O(1)
/// without rescanning `ui.messages` or remounting active `<InlineMedia>` players.
fn message_item(
    chat_peer: PublicKey,
    message: MessageRow,
    label: Signal<String>,
    greeting_unsent: Signal<bool>,
    greeting_uncertain: Signal<bool>,
    awaiting_acceptance: Signal<bool>,
) -> AnyView {
    let ui = ui();
    let index = message.index;
    let outgoing = message.outgoing;
    let initial_delivery = message.delivery;
    let delivery_signal = message.delivery_signal;
    let remote_body_signal = message.remote_body_signal;
    let time = clock(message.at);
    let content = match message.body {
        Body::Text(text) => view! { <div class="bubble">{text}</div> }.into_any(),
        // Small inline files keep stable identity; render directly so delivery ticks never remount them.
        Body::File(_) => match inline_media(&message.body) {
            Some((source, sort)) => view! { <InlineMedia source sort /> }.into_any(),
            None => match Source::of(&message.body) {
                Some(source) => file_card(source),
                None => ().into_any(),
            },
        },
        // Remote attachments track body updates via their per-row signal so held attachments
        // (empty pointer before sign-in) transition seamlessly to live cards/inline media once
        // `start_waiting` populates their pointer, while ordinary delivery ticks never remount them.
        Body::Remote(_) => {
            let initial_body = message.body;
            (move || {
                let current = remote_body_signal
                    .and_then(|signal| signal.try_get())
                    .unwrap_or_else(|| initial_body.clone());
                match inline_media(&current) {
                    Some((source, sort)) => view! { <InlineMedia source sort /> }.into_any(),
                    None => match Source::of(&current) {
                        Some(source) => file_card(source),
                        None => ().into_any(),
                    },
                }
            })
            .into_any()
        }
        Body::Contact(card) => view! { <ContactCard chat_peer card /> }.into_any(),
        Body::Hello(name) => {
            let clean_name = sanitize_shared_name(&name);
            let note = move || match (outgoing, clean_name.is_empty()) {
                (true, _) => format!("You started this chat · {time}"),
                (false, true) => format!("{} started this chat · {time}", label.get()),
                (false, false) => {
                    format!(
                        "{} started this chat, as “{clean_name}” · {time}",
                        label.get()
                    )
                }
            };
            return view! { <div class="note" data-index=index>{note}</div> }.into_any();
        }
        Body::Deleted => {
            let note = move || format!("{} deleted this chat · {time}", label.get());
            return view! { <div class="note" data-index=index>{note}</div> }.into_any();
        }
        Body::Evicted => {
            let note = move || {
                format!(
                    "A message from {} could not be decrypted (its key expired) · {time}",
                    label.get()
                )
            };
            return view! { <div class="note evicted" data-index=index>{note}</div> }.into_any();
        }
        Body::Unknown => {
            let note = move || {
                format!(
                    "{} sent something this client cannot show · {time}",
                    label.get()
                )
            };
            return view! { <div class="note" data-index=index>{note}</div> }.into_any();
        }
    };
    let delivery = move || {
        delivery_signal
            .and_then(|signal| signal.try_get())
            .unwrap_or(initial_delivery)
    };
    // How far it got, right of its time, as Telegram shows it: a clock while it waits, one tick
    // once the server has it, two once the peer read it, and three once it downloaded its
    // attachment; what that says, for its tooltip and screen readers; and whether the peer read
    // it.
    let status = move || match delivery() {
        Delivery::Received => None,
        Delivery::Pending => Some((
            Icon::Pending,
            if ui.held.with(|held| held.contains(&(chat_peer, index))) {
                "waiting for server sign-in"
            } else if greeting_unsent.get() {
                "waiting to send chat request"
            } else if greeting_uncertain.get() {
                "confirming chat request delivery"
            } else if awaiting_acceptance.get() {
                "waiting for peer to accept"
            } else {
                "waiting to be sent"
            },
            false,
        )),
        Delivery::Failed => Some((Icon::Failed, "could not be sent", false)),
        Delivery::Sent => Some((Icon::Sent, "sent", false)),
        Delivery::Read => Some((Icon::Read, "read", true)),
        Delivery::Downloaded => Some((Icon::Downloaded, "read and downloaded", true)),
    };
    // Held until this browser signs in to the server, which keeps it only for those who do: it
    // can be cancelled, which lets what was sent after it go.
    let held = outgoing.then(|| {
        let cancelling = RwSignal::new(false);
        let row_gen = ui.contact(&chat_peer).map_or(0, |c| c.conversation_gen);
        move || {
            ui.held
                .with(|held| held.contains(&(chat_peer, index)))
                .then(|| {
                    view! {
                        <button
                            type="button"
                            class="btn icon quiet cancel-held"
                            title="Cancel it, so that what was sent after it goes"
                            aria-label="Cancel it"
                            disabled=move || cancelling.get()
                            on:click=move |_| {
                                act_while(
                                    cancelling,
                                    async move {
                                        engine()
                                            .cancel_held_for_gen(chat_peer, index, row_gen)
                                            .await
                                    },
                                )
                            }
                        >
                            {icon(Icon::Close)}
                        </button>
                    }
                })
        }
    });
    view! {
        <div class="message" class:me=outgoing data-index=index>
            {content}
            <span class="meta" class:failed=move || delivery() == Delivery::Failed>
                {held}
                {time}
                {move || {
                    status().map(|(shown, title, read)| {
                        view! {
                            <span
                                class="status"
                                class:read=read
                                class:downloaded=shown == Icon::Downloaded
                                title=title
                                role="img"
                                aria-label=title
                            >
                                {icon(shown)}
                            </span>
                        }
                    })
                }}
            </span>
        </div>
    }
    .into_any()
}

/// A peer's identity shared in a chat, with a direct action to open or start a chat with them.
#[component]
fn ContactCard(chat_peer: PublicKey, card: SharedContact) -> impl IntoView {
    let ui = ui();
    let key = card.key;
    let pq_pinned = card.pq_pinned;
    let clean_name = sanitize_shared_name(&card.name);
    let letters = avatar_letters(&clean_name, &key);
    let title = if clean_name.is_empty() {
        short(&key)
    } else {
        clean_name.clone()
    };
    let subtitle = if clean_name.is_empty() {
        "Shared contact".to_string()
    } else {
        short(&key)
    };
    view! {
        <div class="contact-card">
            <div class="contact-card-head">
                <span class="avatar">{letters}</span>
                <div class="contact-card-info">
                    <strong>{title}</strong>
                    <div class="contact-card-meta">
                        <span>{subtitle}</span>
                        {pq_pinned.then(|| view! { <span class="sec-badge pq">"PQ pinned"</span> })}
                    </div>
                </div>
            </div>
            <div class="contact-card-foot">
                {move || {
                    let is_me = ui.me.with(|me| me.as_ref().is_some_and(|me| me.key == key));
                    if is_me {
                        view! { <span class="contact-card-note">"Your identity"</span> }.into_any()
                    } else if key == chat_peer {
                        view! { <span class="contact-card-note">"This chat"</span> }.into_any()
                    } else if let Some(existing) = ui.contact(&key) {
                        let action_label = if existing.request {
                            "View request"
                        } else {
                            "Open chat"
                        };
                        let saved_note = (!existing.name.is_empty() && existing.name != clean_name)
                            .then(|| format!("Saved as {}", existing.name));
                        view! {
                            {saved_note.map(|note| {
                                view! { <span class="contact-card-note saved">{note}</span> }
                            })}
                            <button
                                type="button"
                                class="btn small"
                                on:click=move |_| history::navigate(Some(key))
                            >
                                {action_label}
                            </button>
                        }
                        .into_any()
                    } else {
                        let card = card.clone();
                        view! {
                            <button
                                type="button"
                                class="btn primary small"
                                on:click=move |_| open_new_chat_for_shared(&card)
                            >
                                "Start chat"
                            </button>
                        }
                        .into_any()
                    }
                }}
            </div>
        </div>
    }
}

/// Upload completion percentage clamped to `0..=100` without overflowing for large files.
pub(super) fn upload_percent(done: u64, size: u64) -> u64 {
    if size == 0 {
        return 0;
    }
    ((u128::from(done) * 100) / u128::from(size)).min(100) as u64
}

/// The uploads to `peer`: how far each got, and the means to go on with it or cancel it.
#[component]
fn Uploads(peer: PublicKey) -> impl IntoView {
    let ui = ui();
    let uploads = move || {
        ui.uploads.with(|uploads| {
            uploads
                .iter()
                .filter(|upload| upload.peer == peer)
                .cloned()
                .collect::<Vec<_>>()
        })
    };
    view! {
        <div class="uploads">
            <For each=uploads key=|upload| (upload.peer, upload.id) children=upload_row />
        </div>
    }
}

fn upload_row(initial: UploadView) -> impl IntoView {
    let ui = ui();
    let (peer, id) = (initial.peer, initial.id);
    let name = sanitize_filename(&initial.name);
    let live = Memo::new(move |_| {
        ui.uploads.with(|uploads| {
            uploads
                .iter()
                .find(|u| u.peer == peer && u.id == id)
                .cloned()
                .unwrap_or_else(|| initial.clone())
        })
    });
    let status = move || {
        let upload = live.get();
        let percent = upload_percent(upload.done, upload.size);
        match &upload.state {
            UploadState::Running => format!("uploading · {percent}%"),
            UploadState::Checking => format!("{percent}% · checking the file…"),
            UploadState::Retrying => format!("{percent}% · waiting for the server"),
            UploadState::Paused(reason) => format!("{percent}% · {reason}"),
        }
    };
    let paused = move || matches!(live.get().state, UploadState::Paused(_));
    let resuming = RwSignal::new(false);
    let file_input = NodeRef::<html::Input>::new();
    // Without the file, which went with the page that chose it, the file is chosen again via a
    // declarative hidden `<input type="file">`.
    let resume = move |_| {
        if resuming.get_untracked() {
            return;
        }
        if engine().has_file(&peer, &id) {
            act_while(resuming, async move {
                engine().resume_upload(peer, id, None).await
            });
        } else if let Some(input) = file_input.get_untracked() {
            input.click();
        }
    };
    let on_file_change = move |event: ev::Event| {
        let input: web_sys::HtmlInputElement = event_target(&event);
        if let Some(file) = input.files().and_then(|files| files.get(0)) {
            act_while(resuming, async move {
                engine().resume_upload(peer, id, Some(file)).await
            });
        }
        input.set_value("");
    };
    let cancel = move |_| act(async move { engine().cancel_upload(peer, id).await });
    view! {
        <div class="upload">
            <span class="file-icon">{extension(&name)}</span>
            <span class="upload-text">
                <strong>{name}</strong>
                <span>{status}</span>
            </span>
            <input type="file" hidden node_ref=file_input on:change=on_file_change />
            <Show when=paused>
                <button
                    class="btn icon small"
                    title="Resume"
                    aria-label="Resume"
                    disabled=move || resuming.get()
                    on:click=resume
                >
                    {icon(Icon::Resume)}
                </button>
            </Show>
            <button
                class="btn icon small quiet"
                title="Cancel the upload"
                aria-label="Cancel the upload"
                on:click=cancel
            >
                {icon(Icon::Close)}
            </button>
        </div>
    }
}
