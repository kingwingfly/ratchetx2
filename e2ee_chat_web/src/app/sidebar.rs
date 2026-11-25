use leptos::prelude::*;
use session::PublicKey;

use crate::{
    icon::{Icon, icon},
    state::{ClassicalPrompt, ContactView, Dialog, SecurityAlert},
    util::{clock, short},
};

use super::{
    common::{avatar_letters, lock, new_chat},
    history, ui,
};

#[component]
pub(super) fn Sidebar() -> impl IntoView {
    let ui = ui();
    let me = move || ui.me.get();
    let peers = Memo::new(move |_| {
        ui.contacts
            .with(|contacts| contacts.iter().map(|c| c.peer).collect::<Vec<_>>())
    });
    view! {
        <aside class="sidebar">
            <div class="sidebar-head">
                <h2>"Chats"</h2>
                <div class="sidebar-actions">
                    <button
                        class="btn icon small quiet mobile-activity"
                        title="Activity log"
                        aria-label="Activity log"
                        on:click=move |_| ui.dialog.set(Some(Dialog::Activity))
                    >
                        {icon(Icon::Activity)}
                    </button>
                    <button
                        class="btn icon small"
                        title="New chat"
                        aria-label="New chat"
                        on:click=move |_| new_chat()
                    >
                        {icon(Icon::Compose)}
                    </button>
                </div>
            </div>
            <nav class="chats">
                <Show when=move || !ui.isolated_contacts.with(Vec::is_empty)>
                    <div class="isolated-banner" role="alert">
                        <span>
                            {move || {
                                let count = ui.isolated_contacts.with(Vec::len);
                                if count == 1 {
                                    "1 corrupt contact isolated.".to_string()
                                } else {
                                    format!("{count} corrupt contacts isolated.")
                                }
                            }}
                        </span>
                        <button
                            type="button"
                            class="btn small"
                            on:click=move |_| ui.dialog.set(Some(Dialog::Settings))
                        >
                            "Review"
                        </button>
                    </div>
                </Show>
                <For
                    each=move || peers.get()
                    key=|peer| *peer
                    children=move |peer| view! { <ChatItem peer /> }
                />
                <Show when=move || peers.with(Vec::is_empty)>
                    <p class="chats-empty">
                        "No chats yet. Start one with someone's identity key, or share yours."
                    </p>
                </Show>
            </nav>
            <div class="sidebar-foot">
                <span class="avatar">
                    {move || me().map(|me| avatar_letters(&me.name, &me.key)).unwrap_or_default()}
                </span>
                <div class="whoami">
                    <strong>
                        {move || {
                            me().map(|me| if me.name.is_empty() { "you".into() } else { me.name })
                        }}
                    </strong>
                    <span>{move || me().map(|me| short(&me.key)).unwrap_or_default()}</span>
                </div>
                <button
                    class="btn icon small"
                    title="Your identity"
                    aria-label="Your identity"
                    on:click=move |_| ui.dialog.set(Some(Dialog::Identity))
                >
                    {icon(Icon::Key)}
                </button>
                <button
                    class="btn icon small"
                    title="Settings"
                    aria-label="Settings"
                    on:click=move |_| ui.dialog.set(Some(Dialog::Settings))
                >
                    {icon(Icon::Settings)}
                </button>
                <button
                    class="btn icon small quiet"
                    title="Lock the vault"
                    aria-label="Lock the vault"
                    on:click=move |_| lock()
                >
                    {icon(Icon::Lock)}
                </button>
            </div>
        </aside>
    }
}

/// Compute `(is_request_accent, is_warn, is_downgrade, subtitle)` for a sidebar `ChatItem`.
pub(super) fn chat_item_meta(contact: &ContactView) -> (bool, bool, bool, String) {
    let has_downgrade = contact.has_downgrade();
    let is_quarantined = contact.is_quarantined();
    let has_outbound_prompt = matches!(contact.classical_prompt, ClassicalPrompt::Outbound { .. });
    let has_warn_alert = matches!(
        contact.alert,
        SecurityAlert::ManifestExpired | SecurityAlert::PqRequired
    );
    let warn = !has_downgrade && (is_quarantined || has_outbound_prompt || has_warn_alert);
    let request_accent = contact.request && !has_downgrade && !warn;
    let sub = if has_downgrade && is_quarantined {
        "downgrade detected (quarantined)".to_string()
    } else if has_downgrade {
        "downgrade detected".to_string()
    } else if is_quarantined {
        if contact.request {
            "classical request (quarantined)".to_string()
        } else {
            "classical chat (quarantined)".to_string()
        }
    } else if has_outbound_prompt {
        "classical approval needed".to_string()
    } else if contact.alert == SecurityAlert::ManifestExpired {
        "peer PQ manifest expired".to_string()
    } else if contact.alert == SecurityAlert::PqRequired {
        "PQ required (paused)".to_string()
    } else if contact.request {
        "wants to chat".to_string()
    } else {
        short(&contact.peer)
    };
    (request_accent, warn, has_downgrade, sub)
}

#[component]
fn ChatItem(peer: PublicKey) -> impl IntoView {
    let ui = ui();
    let contact = Memo::new(move |_| ui.contact(&peer));
    let label = Memo::new(move |_| contact.with(|c| c.as_ref().map(ContactView::label)));
    let letters =
        Memo::new(move |_| contact.with(|c| c.as_ref().map(|c| avatar_letters(&c.name, &peer))));
    let meta = Memo::new(move |_| contact.with(|c| c.as_ref().map(chat_item_meta)));
    let unread = Memo::new(move |_| contact.with(|c| c.as_ref().map_or(0, |c| c.unread)));
    let when = Memo::new(move |_| {
        contact.with(|c| {
            let at = c.as_ref()?.last_activity;
            (at > 0).then(|| clock(at))
        })
    });
    view! {
        <button
            class="chat-item"
            class:request=move || meta.with(|m| m.as_ref().is_some_and(|m| m.0))
            class:warn=move || meta.with(|m| m.as_ref().is_some_and(|m| m.1))
            class:downgrade=move || meta.with(|m| m.as_ref().is_some_and(|m| m.2))
            class:active=move || ui.open.get() == Some(peer)
            on:click=move |_| history::navigate(Some(peer))
        >
            <span class="avatar">{letters}</span>
            <span class="chat-text">
                <span class="chat-name">{label}</span>
                <span class="chat-sub">{move || meta.with(|m| m.as_ref().map(|m| m.3.clone()))}</span>
            </span>
            <Show
                when=move || unread.get() != 0
                fallback=move || view! { <span class="chat-when">{when}</span> }
            >
                <span class="badge">{unread}</span>
            </Show>
        </button>
    }
}
