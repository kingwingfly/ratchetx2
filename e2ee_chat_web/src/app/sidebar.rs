use leptos::prelude::*;
use session::PublicKey;

use crate::{
    icon::{Icon, icon},
    state::{ClassicalPrompt, ContactView, Dialog, LastMessage, LastMessageKind, SecurityAlert},
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

/// Styled non-text badge rendered inside a sidebar chat preview so peers cannot forge media,
/// files, shared contacts, or system events with plain text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct KindBadge {
    pub icon: Option<Icon>,
    pub label: &'static str,
    pub class: &'static str,
}

/// What the second line of a sidebar `ChatItem` displays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ChatItemSubtitle {
    /// Security alert, pending request prompt, or short peer-key fallback.
    Status(String),
    /// Structured preview of the most recent message in the chat.
    Message(LastMessage),
}

/// Computed styling flags and subtitle content for a sidebar `ChatItem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ChatItemMeta {
    pub request_accent: bool,
    pub warn: bool,
    pub downgrade: bool,
    pub subtitle: ChatItemSubtitle,
}

/// Return the unspoofable UI badge for `msg`, or `None` for ordinary non-empty plain text.
pub(super) fn last_message_badge(msg: &LastMessage) -> Option<KindBadge> {
    match msg.kind {
        LastMessageKind::Text if !msg.text.is_empty() => None,
        LastMessageKind::Text => Some(KindBadge {
            icon: None,
            label: "Empty",
            class: "chat-kind-badge neutral",
        }),
        LastMessageKind::Image => Some(KindBadge {
            icon: Some(Icon::Photo),
            label: "Photo",
            class: "chat-kind-badge",
        }),
        LastMessageKind::Video => Some(KindBadge {
            icon: Some(Icon::Video),
            label: "Video",
            class: "chat-kind-badge",
        }),
        LastMessageKind::Audio => Some(KindBadge {
            icon: Some(Icon::Music),
            label: "Audio",
            class: "chat-kind-badge",
        }),
        LastMessageKind::File => Some(KindBadge {
            icon: Some(Icon::Document),
            label: "File",
            class: "chat-kind-badge",
        }),
        LastMessageKind::Contact => Some(KindBadge {
            icon: Some(Icon::ShareContact),
            label: "Contact",
            class: "chat-kind-badge",
        }),
        LastMessageKind::Hello => Some(KindBadge {
            icon: None,
            label: if msg.outgoing {
                "You started"
            } else {
                "Started chat"
            },
            class: "chat-kind-badge neutral",
        }),
        LastMessageKind::Deleted => Some(KindBadge {
            icon: Some(Icon::Delete),
            label: "Deleted chat",
            class: "chat-kind-badge warn",
        }),
        LastMessageKind::Evicted => Some(KindBadge {
            icon: Some(Icon::Info),
            label: "Key expired",
            class: "chat-kind-badge neutral",
        }),
        LastMessageKind::Unknown | LastMessageKind::None => Some(KindBadge {
            icon: Some(Icon::Info),
            label: "Unsupported",
            class: "chat-kind-badge neutral",
        }),
    }
}

fn show_you_prefix(msg: &LastMessage) -> bool {
    msg.outgoing
        && !matches!(
            msg.kind,
            LastMessageKind::Hello | LastMessageKind::Deleted | LastMessageKind::Evicted
        )
}

fn subtitle_tooltip(subtitle: &ChatItemSubtitle) -> String {
    match subtitle {
        ChatItemSubtitle::Status(text) => text.clone(),
        ChatItemSubtitle::Message(msg) => {
            let prefix = if show_you_prefix(msg) { "You: " } else { "" };
            match last_message_badge(msg) {
                None => format!("{prefix}{}", msg.text),
                Some(badge) if msg.text.is_empty() => format!("{prefix}{}", badge.label),
                Some(badge) => format!("{prefix}{} · {}", badge.label, msg.text),
            }
        }
    }
}

/// Compute sidebar styling flags and subtitle content for a `ChatItem`.
pub(super) fn chat_item_meta(contact: &ContactView) -> ChatItemMeta {
    let has_downgrade = contact.has_downgrade();
    let is_quarantined = contact.is_quarantined();
    let has_outbound_prompt = matches!(contact.classical_prompt, ClassicalPrompt::Outbound);
    let has_warn_alert = matches!(
        contact.alert,
        SecurityAlert::ManifestExpired | SecurityAlert::PqRequired
    );
    let warn = !has_downgrade && (is_quarantined || has_outbound_prompt || has_warn_alert);
    let request_accent = contact.request && !has_downgrade && !warn;
    let subtitle = if has_downgrade && is_quarantined {
        ChatItemSubtitle::Status("downgrade detected (quarantined)".to_string())
    } else if has_downgrade {
        ChatItemSubtitle::Status("downgrade detected".to_string())
    } else if is_quarantined {
        if contact.request {
            ChatItemSubtitle::Status("classical request (quarantined)".to_string())
        } else {
            ChatItemSubtitle::Status("classical chat (quarantined)".to_string())
        }
    } else if has_outbound_prompt {
        ChatItemSubtitle::Status("classical approval needed".to_string())
    } else if contact.alert == SecurityAlert::ManifestExpired {
        ChatItemSubtitle::Status("peer PQ manifest expired".to_string())
    } else if contact.alert == SecurityAlert::PqRequired {
        ChatItemSubtitle::Status("PQ required (paused)".to_string())
    } else if contact.request {
        ChatItemSubtitle::Status("wants to chat".to_string())
    } else if contact.greeting_unsent || contact.greeting_uncertain {
        ChatItemSubtitle::Status("sending request…".to_string())
    } else if contact.awaiting_acceptance {
        ChatItemSubtitle::Status("waiting for acceptance".to_string())
    } else if let Some(msg) = &contact.last_message {
        ChatItemSubtitle::Message(msg.clone())
    } else {
        ChatItemSubtitle::Status(short(&contact.peer))
    };
    ChatItemMeta {
        request_accent,
        warn,
        downgrade: has_downgrade,
        subtitle,
    }
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
            class:unread=move || unread.get() != 0
            class:request=move || meta.with(|m| m.as_ref().is_some_and(|m| m.request_accent))
            class:warn=move || meta.with(|m| m.as_ref().is_some_and(|m| m.warn))
            class:downgrade=move || meta.with(|m| m.as_ref().is_some_and(|m| m.downgrade))
            class:active=move || ui.open.get() == Some(peer)
            on:click=move |_| history::navigate(Some(peer))
        >
            <span class="avatar">{letters}</span>
            <span class="chat-text">
                <span class="chat-name">{label}</span>
                <span
                    class="chat-sub"
                    title=move || meta.with(|m| m.as_ref().map(|m| subtitle_tooltip(&m.subtitle)))
                >
                    {move || {
                        meta.with(|m| {
                            let m = m.as_ref()?;
                            Some(match &m.subtitle {
                                ChatItemSubtitle::Status(text) => {
                                    let text = text.clone();
                                    view! { <span class="chat-sub-text">{text}</span> }.into_any()
                                }
                                ChatItemSubtitle::Message(msg) => {
                                    let you = show_you_prefix(msg);
                                    let badge = last_message_badge(msg);
                                    let text = (!msg.text.is_empty()).then(|| msg.text.clone());
                                    view! {
                                        {you.then(|| view! { <span class="chat-you">"You:"</span> })}
                                        {badge.map(|badge| {
                                            view! {
                                                <span class=badge.class>
                                                    {badge.icon.map(icon)}
                                                    <span>{badge.label}</span>
                                                </span>
                                            }
                                        })}
                                        {text.map(|text| view! { <span class="chat-sub-text">{text}</span> })}
                                    }
                                    .into_any()
                                }
                            })
                        })
                    }}
                </span>
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
