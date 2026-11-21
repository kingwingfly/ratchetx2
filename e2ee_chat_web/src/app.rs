//! The page: the chat list beside the open chat, the dialogs, the viewer and the dropzone.

use std::{cell::OnceCell, collections::HashSet, rc::Rc, sync::Arc, time::Duration};

use base64::{Engine as _, prelude::BASE64_STANDARD};
use e2ee_chat_preview::language;

use js_sys::Uint8Array;
use leptos::{ev, html, prelude::*, task::spawn_local};
use session::{PqConfig, PqSuite, PublicKey, safety_number};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{
    Blob, BlobPropertyBag, CanvasRenderingContext2d, FileList, HtmlAnchorElement,
    HtmlCanvasElement, IntersectionObserver, IntersectionObserverEntry, IntersectionObserverInit,
    Url,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    content,
    engine::{
        Engine, MAX_FILE_SIZE, MEDIA_INLINE_MAX, NAME_MAX, PqSaveOutcome, Sending, StartChatError,
        build_invitation_link, invitation, origin, same_server,
    },
    glue::copy,
    icon::{Icon, icon},
    preview::{self, DiffLine, Kind, Sort},
    search::Search,
    state::{
        Attachment, Body, ClassicalPrompt, ContactView, Delivery, Dialog, FileView, Link,
        LocalFile, Me, MessageView, PendingNewChat, Phase, RemoteFile, SecurityAlert,
        ServerPqStatus, SignIn, SignInSuccessAction, Streamed, Ui, UnavailableReason, UploadState,
        UploadView,
    },
    util::{clock, day, js_error, key_to_text, month, short, size, size_u64, sleep},
    workers,
};

thread_local! {
    /// The engine, for event handlers and tasks, which run outside the reactive owner and so
    /// cannot read its context.
    static ENGINE: OnceCell<Rc<Engine>> = const { OnceCell::new() };
}

fn engine() -> Rc<Engine> {
    ENGINE.with(|engine| {
        engine
            .get()
            .expect("the app starts the engine first")
            .clone()
    })
}

fn ui() -> Ui {
    engine().ui()
}

#[component]
pub fn App() -> impl IntoView {
    let ui = Ui::new();
    // The app mounts once.
    let _ = ENGINE.with(|cell| cell.set(Engine::new(ui)));
    spawn_local(async move { engine().start().await });

    // Unread messages and requests show in the tab's title.
    Effect::new(move || {
        let unread: u32 = ui.contacts.with(|contacts| {
            contacts
                .iter()
                .map(|contact| contact.unread + u32::from(contact.request))
                .sum()
        });
        document().set_title(&match unread {
            0 => "ratchetx2 chat".to_string(),
            unread => format!("({unread}) ratchetx2 chat"),
        });
    });
    // Back on the page, sync now, and count what came to the open chat meanwhile as read: it
    // shows already, so the chat needs no reloading.
    let _ = window_event_listener(ev::visibilitychange, move |_| {
        if !document().hidden() && ui.phase.get_untracked() == Phase::Unlocked {
            let engine = engine();
            engine.wake();
            if let Some(peer) = ui.open.get_untracked() {
                spawn_local(async move { engine.mark_read(peer).await });
            }
        }
    });

    view! {
        <div class="app">
            <TopBar />
            <Show
                when=move || ui.phase.get() == Phase::Unlocked
                fallback=move || {
                    view! {
                        <div class="locked-screen">
                            {move || match ui.phase.get() {
                                Phase::Loading => "Loading…",
                                Phase::Create => "Create a vault to get started.",
                                Phase::Elsewhere => "The vault is open in another tab.",
                                Phase::Unavailable(UnavailableReason::InsecureContext, _) => {
                                    "A secure context (HTTPS or localhost) is required."
                                }
                                Phase::Unavailable(UnavailableReason::LocksUnavailable, _) => {
                                    "The Web Locks API is not available in this browser."
                                }
                                Phase::Unavailable(UnavailableReason::StorageUnavailable, _) => {
                                    "The browser's storage is not available."
                                }
                                _ => "The vault is locked.",
                            }}
                        </div>
                    }
                }
            >
                <div class="main" class:chat-open=move || ui.open.get().is_some()>
                    <Sidebar />
                    {move || match ui.open.get() {
                        Some(peer) => view! { <ChatPane peer /> }.into_any(),
                        None => view! { <Welcome /> }.into_any(),
                    }}
                </div>
            </Show>
        </div>
        <VaultDialog />
        <Viewer />
        <Toast />
        <Dropzone />
    }
}

#[component]
fn TopBar() -> impl IntoView {
    let ui = ui();
    let offline = move || matches!(ui.link.get(), Link::Offline(_));
    let unlocked = move || ui.phase.get() == Phase::Unlocked;
    let status = move || match ui.phase.get() {
        Phase::Loading => "loading".to_string(),
        Phase::Create => "no vault yet".to_string(),
        Phase::Locked => "locked".to_string(),
        Phase::Elsewhere => "open in another tab".to_string(),
        Phase::Unavailable(UnavailableReason::InsecureContext, _) => "HTTPS required".to_string(),
        Phase::Unavailable(UnavailableReason::LocksUnavailable, _) => {
            "Web Locks unavailable".to_string()
        }
        Phase::Unavailable(UnavailableReason::StorageUnavailable, _) => {
            "storage unavailable".to_string()
        }
        Phase::Unlocked if ui.syncing.get() => "syncing…".to_string(),
        Phase::Unlocked => match ui.link.get() {
            Link::Connecting => "connecting".to_string(),
            Link::Synced(at) => format!("synced {}", clock(at)),
            Link::Offline(_) => "offline, retrying".to_string(),
        },
    };
    let detail = move || match (ui.link.get(), ui.me.get()) {
        (Link::Offline(error), _) => error,
        (_, Some(me)) => format!("server: {}", me.server),
        _ => String::new(),
    };
    view! {
        <header class="topbar">
            <div class="brand">"RATCHETX2" <small>"END-TO-END ENCRYPTED CHAT"</small></div>
            // Unlocked, the status is the button that syncs.
            <Show
                when=unlocked
                fallback=move || {
                    view! {
                        <div class="status">
                            <span class="dot locked"></span>
                            {status}
                        </div>
                    }
                }
            >
                <button
                    class="btn icon quiet sync"
                    class:syncing=move || ui.syncing.get()
                    class:offline=offline
                    title=move || {
                        let notifications = if ui.live.get() {
                            "live"
                        } else if ui.away.get() {
                            "paused while you are away"
                        } else {
                            "polling"
                        };
                        format!(
                            "{}: sync now\n{}\nnotifications: {notifications}",
                            status(),
                            detail(),
                        )
                    }
                    aria-label=move || format!("Sync now; {}", status())
                    on:click=move |_| engine().sync_now()
                >
                    {icon(Icon::Sync)}
                </button>
            </Show>
        </header>
    }
}

/// An avatar's letters: the initials of a name.
fn initials(label: &str) -> String {
    label
        .split_whitespace()
        .take(2)
        .filter_map(|word| word.chars().next())
        .collect()
}

#[component]
fn Sidebar() -> impl IntoView {
    let ui = ui();
    let me = move || ui.me.get();
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
                <For
                    each=move || ui.contacts.get()
                    key=|contact| contact.clone()
                    children=move |contact: ContactView| view! { <ChatItem contact /> }
                />
                <Show when=move || ui.contacts.with(Vec::is_empty)>
                    <p class="chats-empty">
                        "No chats yet. Start one with someone's identity key, or share yours."
                    </p>
                </Show>
            </nav>
            <div class="sidebar-foot">
                <span class="avatar">
                    {move || me().map(|me| initials(&me.name)).unwrap_or_default()}
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
fn chat_item_meta(contact: &ContactView) -> (bool, bool, bool, String) {
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
fn ChatItem(contact: ContactView) -> impl IntoView {
    let ui = ui();
    let peer = contact.peer;
    let label = contact.label();
    // An unnamed peer goes by its key's first hex digits.
    let letters = if contact.name.is_empty() {
        label.chars().take(2).collect()
    } else {
        initials(&label)
    };
    let (request_accent, warn, has_downgrade, sub) = chat_item_meta(&contact);
    let when = (contact.last_activity > 0).then(|| clock(contact.last_activity));
    view! {
        <button
            class="chat-item"
            class:request=request_accent
            class:warn=warn
            class:downgrade=has_downgrade
            class:active=move || ui.open.get() == Some(peer)
            on:click=move |_| open_chat(Some(peer))
        >
            <span class="avatar">{letters}</span>
            <span class="chat-text">
                <span class="chat-name">{label}</span>
                <span class="chat-sub">{sub}</span>
            </span>
            {match contact.unread {
                0 => view! { <span class="chat-when">{when}</span> }.into_any(),
                unread => view! { <span class="badge">{unread}</span> }.into_any(),
            }}
        </button>
    }
}

/// Recent activity log list shared by `Welcome` and the mobile `ActivityDialog`.
#[component]
fn ActivityList() -> impl IntoView {
    let ui = ui();
    view! {
        <ul class="activity">
            <For
                each=move || ui.log.get().into_iter().enumerate()
                // With the line too: once the oldest line goes, every index shifts.
                key=|(index, line)| (*index, line.clone())
                children=|(_, (at, text))| {
                    view! {
                        <li>
                            <time>{clock(at)}</time>
                            {text}
                        </li>
                    }
                }
            />
            <Show when=move || ui.log.with(Vec::is_empty)>
                <li>"No activity yet."</li>
            </Show>
        </ul>
    }
}

/// With no chat open: this client's key, and what happened.
#[component]
fn Welcome() -> impl IntoView {
    let ui = ui();
    let key = move || {
        ui.me
            .with(|me| me.as_ref().map(|me| key_to_text(&me.key)).unwrap_or_default())
    };
    let handshake = if !PqConfig::compiled_suites().is_empty() {
        "PQXDH / X3DH"
    } else {
        "X3DH"
    };
    view! {
        <section class="pane welcome">
            <div class="welcome-inner">
                <div>
                    <div class="eyebrow">"END-TO-END ENCRYPTED"</div>
                    <h1>"Your keys stay in this browser"</h1>
                </div>
                <p>
                    "Messages are encrypted here, with " {handshake} " and a double ratchet, "
                    "before they leave the page. The server, a Cloudflare Worker, only relays "
                    "what it cannot read: prekeys and sealed messages in its Durable Objects, the "
                    "large ones in R2."
                </p>
                <div>
                    <div class="section-label">"Your identity key"</div>
                    {move || view! { <Copyable text=key() what="your key" /> }}
                    <div class="section-label">"Your invitation link"</div>
                    {move || {
                        let link = ui.me.get().as_ref().map(invitation_link).unwrap_or_default();
                        view! { <Copyable text=link what="your invitation link" /> }
                    }}
                    <div class="row">
                        <button class="btn primary" on:click=move |_| new_chat()>
                            {icon(Icon::Compose)}
                            "New chat"
                        </button>
                    </div>
                </div>
                <div>
                    <div class="section-label">"Activity"</div>
                    <ActivityList />
                </div>
            </div>
        </section>
    }
}

#[component]
fn ActivityDialog() -> impl IntoView {
    view! {
        <div>
            <h2>"Activity"</h2>
            <p>"Recent vault, sync, and encryption events in this browser session."</p>
            <ActivityList />
            <div class="actions">
                <button type="button" class="btn primary" on:click=move |_| close_dialog()>
                    "Close"
                </button>
            </div>
        </div>
    }
}

/// Compute `(css_class, label, tooltip)` for a contact's security badge (`detailed` shows the full
/// label in `ContactInfo`).
fn security_badge_parts(contact: &ContactView, detailed: bool) -> (&'static str, String, String) {
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
fn contact_can_upgrade_to_pq(contact: &ContactView) -> bool {
    contact.has_downgrade()
        || contact.is_quarantined()
        || (contact.has_active_session && !contact.security.is_pq)
}

/// Render a security status badge for `contact` (`detailed` shows the full label in `ContactInfo`).
fn security_badge(contact: &ContactView, detailed: bool) -> AnyView {
    let (class, label, title) = security_badge_parts(contact, detailed);
    view! {
        <span class=class title=title>
            {label}
        </span>
    }
    .into_any()
}

#[component]
fn ChatPane(peer: PublicKey) -> impl IntoView {
    let ui = ui();
    let contact = move || ui.contact(&peer);
    let label = move || contact().map(|contact| contact.label()).unwrap_or_default();
    let request = move || contact().is_some_and(|contact| contact.request);
    let quarantined = move || contact().is_some_and(|contact| contact.is_quarantined());
    let composer_disabled = move || request() || quarantined();
    let composer_placeholder = move || {
        if quarantined() {
            "Allow classical or upgrade to PQ to write"
        } else if request() {
            "Accept the request to write"
        } else {
            "Write a message"
        }
    };
    let pq_available = move || {
        ui.me.with(|me| {
            me.as_ref().is_some_and(|me| {
                me.pq_config.pq_enabled && !me.pq_config.offered_suites().is_empty()
            })
        })
    };
    let server_pq_disabled = move || {
        ui.me.with(|me| {
            me.as_ref()
                .is_some_and(|me| me.server_pq == ServerPqStatus::Disabled)
        })
    };
    let pq_retry_ready = move || pq_available() && !server_pq_disabled();
    let upgrade_disabled_tip = move || {
        server_pq_disabled()
            .then_some("This server does not have post-quantum encryption enabled.")
    };
    let sec_busy = RwSignal::new(false);
    view! {
        <section class="pane">
            <header class="pane-head">
                <button
                    class="btn icon quiet back"
                    title="Back to the chats"
                    aria-label="Back to the chats"
                    on:click=move |_| open_chat(None)
                >
                    {icon(Icon::Back)}
                </button>
                <span class="avatar">{move || initials(&label())}</span>
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
                    on:click=move |_| open_chat(None)
                >
                    {icon(Icon::Close)}
                </button>
            </header>
            {move || {
                let c = contact()?;
                // Suppress standalone downgrade banner when the merged quarantine banner is active
                // so the user never sees two stacked "Upgrade to PQ" primary buttons.
                if c.has_downgrade() && !c.is_quarantined() {
                    Some(
                        view! {
                            <div class="banner danger" role="alert">
                                <span>
                                    "Downgrade detected: this peer supports or was pinned for post-quantum encryption, but a classical or tampered handshake was received."
                                </span>
                                <div class="banner-actions">
                                    <Show when=pq_available>
                                        <button
                                            type="button"
                                            class="btn primary small"
                                            title=upgrade_disabled_tip
                                            disabled=move || sec_busy.get() || server_pq_disabled()
                                            on:click=move |_| {
                                                act_while(sec_busy, async move {
                                                    engine().upgrade_to_pq(peer).await
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
                                                engine().dismiss_downgrade(peer).await
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
                                            "Downgrade detected — classical session quarantined: this peer was previously pinned as post-quantum capable. Its incoming message is held until you explicitly allow classical encryption or upgrade to PQ."
                                        } else {
                                            "Classical chat request quarantined: this peer initiated without post-quantum encryption. Its message is held until you allow classical encryption."
                                        }}
                                    </span>
                                    <div class="banner-actions">
                                        <button
                                            type="button"
                                            class="btn small"
                                            disabled=move || sec_busy.get()
                                            on:click=move |_| {
                                                act_while(sec_busy, async move {
                                                    engine().approve_classical(peer).await
                                                });
                                            }
                                        >
                                            "Allow classical"
                                        </button>
                                        <Show when=pq_available>
                                            <button
                                                type="button"
                                                class="btn primary small"
                                                title=upgrade_disabled_tip
                                                disabled=move || {
                                                    sec_busy.get() || server_pq_disabled()
                                                }
                                                on:click=move |_| {
                                                    act_while(sec_busy, async move {
                                                        engine().upgrade_to_pq(peer).await
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
                    ClassicalPrompt::Outbound { peer_signed_off } => Some(
                        view! {
                            <div class="banner warn" role="alert">
                                <span>
                                    {if peer_signed_off {
                                        "Sending paused: this peer published a signed manifest disabling post-quantum encryption. Allow classical fallback to send?"
                                    } else {
                                        "Sending paused: this peer has no post-quantum prekeys on the server. Allow classical encryption for this chat?"
                                    }}
                                </span>
                                <div class="banner-actions">
                                    <button
                                        type="button"
                                        class="btn small"
                                        disabled=move || sec_busy.get()
                                        on:click=move |_| {
                                            act_while(sec_busy, async move {
                                                engine().approve_classical(peer).await
                                            });
                                        }
                                    >
                                        "Allow classical"
                                    </button>
                                    <Show when=pq_retry_ready>
                                        <button
                                            type="button"
                                            class="btn primary small"
                                            disabled=move || sec_busy.get()
                                            on:click=move |_| {
                                                act_while(sec_busy, async move {
                                                    engine().retry_pq(peer).await
                                                });
                                            }
                                        >
                                            "Retry PQ"
                                        </button>
                                    </Show>
                                </div>
                            </div>
                        }
                        .into_any(),
                    ),
                    ClassicalPrompt::None => None,
                }
            }}
            {move || {
                let c = contact()?;
                match c.alert {
                    SecurityAlert::ManifestExpired => Some(
                        view! {
                            <div class="banner warn" role="alert">
                                <span>
                                    "Peer's signed post-quantum capability manifest has expired (they may have been offline for a while)."
                                </span>
                                <div class="banner-actions">
                                    <Show
                                        when=pq_retry_ready
                                        fallback=move || {
                                            view! {
                                                <button
                                                    type="button"
                                                    class="btn small"
                                                    disabled=move || sec_busy.get()
                                                    on:click=move |_| {
                                                        act_while(sec_busy, async move {
                                                            engine().dismiss_downgrade(peer).await
                                                        });
                                                    }
                                                >
                                                    "Dismiss"
                                                </button>
                                            }
                                        }
                                    >
                                        <button
                                            type="button"
                                            class="btn small"
                                            disabled=move || sec_busy.get()
                                            on:click=move |_| {
                                                act_while(sec_busy, async move {
                                                    engine().retry_pq(peer).await
                                                });
                                            }
                                        >
                                            "Retry"
                                        </button>
                                    </Show>
                                </div>
                            </div>
                        }
                        .into_any(),
                    ),
                    SecurityAlert::PqRequired => Some(
                        view! {
                            <div class="banner warn" role="alert">
                                <span>
                                    "Require PQ (strict mode) is enabled, and a post-quantum session could not be established with this peer."
                                </span>
                                <div class="banner-actions">
                                    <Show
                                        when=pq_retry_ready
                                        fallback=move || {
                                            view! {
                                                <button
                                                    type="button"
                                                    class="btn small"
                                                    disabled=move || sec_busy.get()
                                                    on:click=move |_| {
                                                        act_while(sec_busy, async move {
                                                            engine().dismiss_downgrade(peer).await
                                                        });
                                                    }
                                                >
                                                    "Dismiss"
                                                </button>
                                            }
                                        }
                                    >
                                        <button
                                            type="button"
                                            class="btn small"
                                            disabled=move || sec_busy.get()
                                            on:click=move |_| {
                                                act_while(sec_busy, async move {
                                                    engine().retry_pq(peer).await
                                                });
                                            }
                                        >
                                            "Retry"
                                        </button>
                                    </Show>
                                </div>
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
            <Messages label=Signal::derive(label) />
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

#[component]
fn Messages(label: Signal<String>) -> impl IntoView {
    let ui = ui();
    let list = NodeRef::<html::Div>::new();
    // Follow the latest message while at the bottom, so that what changes, as a sync goes,
    // does not move the history away from the user reading it; and on sending one.
    let follow = StoredValue::new(true);
    let newest = StoredValue::new(None::<u64>);
    Effect::new(move || {
        let sent = ui.messages.with(|messages| {
            let last = messages.iter().max_by_key(|message| message.index)?;
            let new = newest.get_value().is_some_and(|newest| last.index > newest);
            newest.set_value(Some(last.index));
            Some(new && last.outgoing)
        });
        if sent == Some(true) {
            follow.set_value(true);
        }
        if let Some(list) = list.get() {
            // Unless the chat went meanwhile.
            request_animation_frame(move || {
                if follow.try_get_value() == Some(true) {
                    list.set_scroll_top(list.scroll_height());
                }
            });
        }
    });
    let scrolled = move |_| {
        if let Some(list) = list.try_get_untracked().flatten() {
            let below = list.scroll_height() - list.scroll_top() - list.client_height();
            follow.try_set_value(below < FOLLOW_SLACK);
        }
    };
    view! {
        <div class="messages" node_ref=list aria-live="polite" on:scroll=scrolled>
            <For
                each=move || ui.messages.get()
                key=|message| message.index
                children=move |message| message_item(message, label)
            />
        </div>
    }
}

/// A message, as a bubble, an image, a file or a note.
/// The notes name the peer by `label`, which changes once a request is accepted.
/// Delivery ticks and held-attachment pointer upgrades update reactively without remounting
/// active `<InlineMedia>` players.
fn message_item(message: MessageView, label: Signal<String>) -> AnyView {
    let ui = ui();
    let index = message.index;
    let outgoing = message.outgoing;
    let initial_delivery = message.delivery;
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
        // Remote attachments track body updates via a fine-grained Memo so held attachments
        // (empty pointer before sign-in) transition seamlessly to live cards/inline media once
        // `start_waiting` populates their pointer, while ordinary delivery ticks never remount them.
        Body::Remote(_) => {
            let initial_body = message.body;
            let body = Memo::new(move |_| {
                ui.messages.with(|messages| {
                    messages
                        .iter()
                        .find(|m| m.index == index)
                        .map(|m| m.body.clone())
                        .unwrap_or_else(|| initial_body.clone())
                })
            });
            (move || {
                let current = body.get();
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
        Body::Hello(name) => {
            let note = move || match (outgoing, name.is_empty()) {
                (true, _) => format!("You started this chat · {time}"),
                (false, true) => format!("{} started this chat · {time}", label.get()),
                (false, false) => {
                    format!("{} started this chat, as “{name}” · {time}", label.get())
                }
            };
            return view! { <div class="note">{note}</div> }.into_any();
        }
        Body::Deleted => {
            let note = move || format!("{} deleted this chat · {time}", label.get());
            return view! { <div class="note">{note}</div> }.into_any();
        }
        Body::Evicted => {
            let note = move || {
                format!(
                    "A message from {} could not be decrypted (its key expired) · {time}",
                    label.get()
                )
            };
            return view! { <div class="note evicted">{note}</div> }.into_any();
        }
        Body::Unknown => {
            let note = move || {
                format!(
                    "{} sent something this client cannot show · {time}",
                    label.get()
                )
            };
            return view! { <div class="note">{note}</div> }.into_any();
        }
    };
    let delivery = Memo::new(move |_| {
        ui.messages.with(|messages| {
            messages
                .iter()
                .find(|m| m.index == index)
                .map(|m| m.delivery)
                .unwrap_or(initial_delivery)
        })
    });
    // How far it got, right of its time, as Telegram shows it: a clock while it waits, one tick
    // once the server has it, two once the peer read it, and three once it downloaded its
    // attachment; what that says, for its tooltip and screen readers; and whether the peer read
    // it.
    let status = move || match delivery.get() {
        Delivery::Received => None,
        Delivery::Pending => Some((Icon::Pending, "waiting to be sent", false)),
        Delivery::Failed => Some((Icon::Failed, "could not be sent", false)),
        Delivery::Sent => Some((Icon::Sent, "sent", false)),
        Delivery::Read => Some((Icon::Read, "read", true)),
        Delivery::Downloaded => Some((Icon::Downloaded, "read and downloaded", true)),
    };
    // Held until this browser signs in to the server, which keeps it only for those who do: it
    // can be cancelled, which lets what was sent after it go.
    let held = outgoing.then(|| {
        let cancelling = RwSignal::new(false);
        move || {
            let peer = ui.open.get()?;
            ui.held.with(|held| held.contains(&(peer, index))).then(|| {
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
                                async move { engine().cancel_held(peer, index).await },
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
        <div class="message" class:me=outgoing>
            {content}
            <span class="meta" class:failed=move || delivery.get() == Delivery::Failed>
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
    let name = initial.name.clone();
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
        let percent = upload.done * 100 / upload.size.max(1);
        match &upload.state {
            UploadState::Running => format!("uploading · {percent}%"),
            UploadState::Checking => format!("{percent}% · checking the file…"),
            UploadState::Retrying => format!("{percent}% · waiting for the server"),
            UploadState::Paused(reason) => format!("{percent}% · {reason}"),
        }
    };
    let paused = move || matches!(live.get().state, UploadState::Paused(_));
    let file_input = NodeRef::<html::Input>::new();
    // Without the file, which went with the page that chose it, the file is chosen again via a
    // declarative hidden `<input type="file">`.
    let resume = move |_| {
        if engine().has_file(&peer, &id) {
            act(async move { engine().resume_upload(peer, id, None).await });
        } else if let Some(input) = file_input.get_untracked() {
            input.click();
        }
    };
    let on_file_change = move |event: ev::Event| {
        let input: web_sys::HtmlInputElement = event_target(&event);
        if let Some(file) = input.files().and_then(|files| files.get(0)) {
            act(async move { engine().resume_upload(peer, id, Some(file)).await });
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

/// A file's extension, lowercase, for its card; `file` if it has none.
fn extension(name: &str) -> String {
    name.rsplit_once('.')
        .map_or("file".to_string(), |(_, extension)| {
            extension.to_lowercase()
        })
}

/// Show an attachment in the viewer, fetching it first unless it is kept here.
fn open_attachment(remote: RemoteFile) {
    let (ui, engine) = (ui(), engine());
    spawn_local(async move {
        // A video or audio plays as it is fetched, if a service worker can stream it.
        let sort = preview::sort(&remote.pointer.name, &remote.pointer.mime, &[]);
        if matches!(sort, Sort::Video | Sort::Audio)
            && let Some(url) = engine
                .stream(remote.peer, remote.index, &remote.pointer, remote.clock)
                .await
        {
            ui.viewer.set(None);
            ui.opening.set(None);
            let video = sort == Sort::Video;
            ui.streaming.set(Some(Streamed { url, remote, video }));
            return;
        }
        if let Err(e) = engine
            .open_attachment(remote.peer, remote.index, remote.pointer, remote.clock)
            .await
        {
            ui.notify(e);
        }
    });
}

/// How long a stream let go of still answers what its players asked for before they stopped.
const STREAM_GRACE: Duration = Duration::from_secs(10);

/// Let go of `url`, a blob URL or a stream's, as what showed it went. Players stop their own
/// `NodeRef` elements in `on_cleanup`, and what they asked for already is still answered for
/// [`STREAM_GRACE`], so that none fails.
fn release(url: &str) {
    if url.starts_with("/media/") {
        let url = url.to_string();
        set_timeout(move || engine().end_stream(&url), STREAM_GRACE);
    } else {
        let _ = Url::revoke_object_url(url);
    }
}

/// Stop a `<video>` or `<audio>` element directly via its `NodeRef`, cancelling in-flight range
/// fetches even if the element has already been detached during cleanup.
fn stop_media(player: &web_sys::HtmlMediaElement) {
    let _ = player.remove_attribute("src");
    player.load();
}

#[component]
fn Composer(
    peer: PublicKey,
    disabled: Signal<bool>,
    placeholder: Signal<&'static str>,
) -> impl IntoView {
    let text = RwSignal::new(String::new());
    let textarea = NodeRef::<html::Textarea>::new();
    let file_input = NodeRef::<html::Input>::new();
    // Typing goes to the composer when a chat opens.
    Effect::new(move || {
        if let Some(textarea) = textarea.get() {
            let _ = textarea.focus();
        }
    });
    let submit = move || {
        let message = text.get_untracked();
        if message.trim().is_empty() {
            return;
        }
        text.set(String::new());
        send(peer, content::Kind::Text(message.trim().to_string()));
    };
    let on_keydown = move |event: ev::KeyboardEvent| {
        if event.key() == "Enter" && !event.shift_key() && !event.is_composing() {
            event.prevent_default();
            submit();
        }
    };
    let on_files_change = move |event: ev::Event| {
        let input: web_sys::HtmlInputElement = event_target(&event);
        if let Some(files) = input.files() {
            send_files(files);
        }
        // So that picking the same file again sends it again.
        input.set_value("");
    };
    let rows = move || text.with(|text| text.split('\n').count().clamp(1, 6));
    view! {
        <div class="composer">
            <button
                class="btn icon"
                title="Attach files, or drop them on the page"
                aria-label="Attach files"
                disabled=disabled
                on:click=move |_| {
                    if let Some(input) = file_input.get_untracked() {
                        input.click();
                    }
                }
            >
                {icon(Icon::Attach)}
            </button>
            <textarea
                node_ref=textarea
                rows=rows
                placeholder=move || placeholder.get()
                disabled=disabled
                prop:value=move || text.get()
                on:input=move |event| text.set(event_target_value(&event))
                on:keydown=on_keydown
            ></textarea>
            <button
                class="btn icon primary"
                title="Send (Enter)"
                aria-label="Send"
                disabled=disabled
                on:click=move |_| submit()
            >
                {icon(Icon::Send)}
            </button>
            <input type="file" multiple hidden node_ref=file_input on:change=on_files_change />
        </div>
    }
}

/// Show `file`, of a chat's history, in the viewer, its bytes read unless they are here.
fn show_file(file: LocalFile) {
    let ui = ui();
    match file.data {
        Some(attachment) => ui.viewer.set(Some(attachment)),
        None => act(async move {
            let data = engine().file(file.peer, file.index).await?;
            ui.viewer.set(Some(Attachment {
                name: file.name,
                mime: file.mime,
                data,
            }));
            Ok(())
        }),
    }
}

/// Where a file of a chat's history is: in the vault, or here already, or an attachment.
#[derive(Debug, Clone, PartialEq)]
enum Source {
    Local(LocalFile),
    Remote(RemoteFile),
}

impl Source {
    /// The file `body` is, if any.
    fn of(body: &Body) -> Option<Self> {
        match body {
            Body::File(file) => Some(Self::Local(file.clone())),
            Body::Remote(remote) => Some(Self::Remote(remote.clone())),
            _ => None,
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Local(file) => &file.name,
            Self::Remote(remote) => &remote.pointer.name,
        }
    }

    fn size(&self) -> u64 {
        match self {
            Self::Local(file) => file.size,
            Self::Remote(remote) => remote.pointer.size,
        }
    }

    /// Show it in the viewer.
    fn open(&self) {
        match self {
            Self::Local(file) => show_file(file.clone()),
            Self::Remote(remote) => open_attachment(remote.clone()),
        }
    }

    /// Its bytes: read from the vault, or, an attachment's, fetched as long as `shows` says it
    /// shows; none if it stopped showing first.
    async fn read(&self, shows: &dyn Fn() -> bool) -> Result<Option<Attachment>, String> {
        match self {
            Self::Local(file) => match &file.data {
                Some(attachment) => Ok(Some(attachment.clone())),
                None => Ok(Some(Attachment {
                    name: file.name.clone(),
                    mime: file.mime.clone(),
                    data: engine().file(file.peer, file.index).await?,
                })),
            },
            Self::Remote(remote) => {
                engine()
                    .media(
                        remote.peer,
                        remote.index,
                        remote.pointer.clone(),
                        remote.clock,
                        shows,
                    )
                    .await
            }
        }
    }
}

/// The file `body` is, and its sort, if it is media small enough to show in place: one that came
/// in its message, as its bytes show, or an attachment up to [`MEDIA_INLINE_MAX`] bytes, as the
/// type its sender gave and its name say, until its bytes are fetched.
fn inline_media(body: &Body) -> Option<(Source, Sort)> {
    let sort = match body {
        Body::File(file) => match file.media.as_deref()?.split_once('/')? {
            ("image", _) => Sort::Image,
            ("video", _) => Sort::Video,
            _ => Sort::Audio,
        },
        // Not one whose upload waits to start, which has nothing to fetch yet.
        Body::Remote(remote)
            if remote.pointer.size <= MEDIA_INLINE_MAX && !remote.pointer.id.is_empty() =>
        {
            let pointer = &remote.pointer;
            match preview::sort(&pointer.name, &pointer.mime, &[]) {
                sort @ (Sort::Image | Sort::Video | Sort::Audio) => sort,
                _ => return None,
            }
        }
        _ => return None,
    };
    Some((Source::of(body)?, sort))
}

/// A file of a chat's history, as a card of its extension, name and size, which opens it in the
/// viewer.
fn file_card(source: Source) -> AnyView {
    let extension = extension(source.name());
    let name = source.name().to_string();
    let length = size_u64(source.size());
    view! {
        <button class="file-card" on:click=move |_| source.open()>
            <span class="file-icon">{extension}</span>
            <span>
                <strong>{name}</strong>
                <span>{length}</span>
            </span>
        </button>
    }
    .into_any()
}

/// Small media of a chat's history, `source`, shown in place as `sort` says it is: an image, or
/// a video or audio with its controls, which never plays by itself. Its bytes are read, or an
/// attachment's fetched, once it is about to show, so that a long history does not read them
/// all; an attachment's video or audio plays as it is fetched, if a service worker can stream
/// it. One that cannot be read, or whose bytes are no media after all, shows as a file.
#[component]
fn InlineMedia(source: Source, sort: Sort) -> impl IntoView {
    let ui = ui();
    let node = NodeRef::<html::Div>::new();
    let video_ref = NodeRef::<html::Video>::new();
    let audio_ref = NodeRef::<html::Audio>::new();
    // Its URL and MIME type, once read, and what the viewer shows of it.
    let shown = RwSignal::new(None::<(String, &'static str)>);
    let read = StoredValue::new(None::<Attachment>);
    let failed = RwSignal::new(false);
    // Gone with the media, e.g. as the chat closed: a read that ends after shows nothing, and a
    // URL made then is let go at once.
    let here = StoredValue::new(());
    let stop_active = move || {
        if let Some(video) = video_ref.get_untracked() {
            stop_media(&video);
        }
        if let Some(audio) = audio_ref.get_untracked() {
            stop_media(&audio);
        }
    };
    let play = move |url: String, mime: &'static str| {
        if let Some(Some((old_url, _))) = shown.try_set(Some((url, mime))) {
            stop_active();
            release(&old_url);
        }
    };
    let show = move |attachment: Attachment| {
        let data = &attachment.data;
        let Some(mime) = preview::media_mime(&attachment.name, &attachment.mime, data) else {
            failed.try_set(true);
            return;
        };
        let url = if mime.starts_with("image/") {
            image_url(data, mime)
        } else {
            blob_url(data, mime)
        };
        let Some(url) = url else {
            failed.try_set(true);
            return;
        };
        play(url, mime);
        read.try_set_value(Some(attachment));
    };
    let load = {
        let source = source.clone();
        move || {
            let source = source.clone();
            spawn_local(async move {
                if let Source::Remote(remote) = &source
                    && sort != Sort::Image
                    && let Some(url) = engine()
                        .stream(remote.peer, remote.index, &remote.pointer, remote.clock)
                        .await
                {
                    play(
                        url,
                        if sort == Sort::Video {
                            "video/"
                        } else {
                            "audio/"
                        },
                    );
                    return;
                }
                let shows = move || here.try_get_value().is_some();
                match source.read(&shows).await {
                    Ok(Some(attachment)) => show(attachment),
                    Ok(None) => {}
                    Err(_) => {
                        failed.try_set(true);
                    }
                }
            });
        }
    };
    match &source {
        Source::Local(LocalFile { data: Some(_), .. }) => load(),
        _ => when_shown(node, load),
    }
    on_cleanup(move || {
        stop_active();
        if let Some(Some((url, _))) = shown.try_get_untracked() {
            release(&url);
        }
    });
    let name = source.name().to_string();
    let caption = format!("{} · {}", source.name(), size_u64(source.size()));
    // What it read shows at once; a stream's opens as any attachment does.
    let opened = StoredValue::new(source.clone());
    let open = move |_| match read.get_value() {
        Some(attachment) => ui.viewer.set(Some(attachment)),
        None => opened.with_value(Source::open),
    };
    // One that turns out not to play, e.g. as it is no video after all, shows as a file.
    let unplayable = move |_| failed.set(true);
    view! {
        <div class="inline-media" node_ref=node>
            {move || {
                if failed.get() {
                    return file_card(source.clone());
                }
                match (shown.get(), sort) {
                    (Some((url, mime)), _) if mime.starts_with("image/") => {
                        view! {
                            <button class="thumb" title=name.clone() on:click=open>
                                <img src=url alt=name.clone() />
                            </button>
                        }
                            .into_any()
                    }
                    (Some((url, mime)), _) if mime.starts_with("video/") => {
                        view! {
                            <div class="clip">
                                <video
                                    node_ref=video_ref
                                    src=url
                                    controls
                                    preload="metadata"
                                    playsinline
                                    on:error=unplayable
                                ></video>
                                <button class="clip-name" on:click=open>
                                    {caption.clone()}
                                </button>
                            </div>
                        }
                            .into_any()
                    }
                    (Some((url, _)), _) => {
                        view! {
                            <div class="clip audio">
                                <audio
                                    node_ref=audio_ref
                                    src=url
                                    controls
                                    preload="metadata"
                                    on:error=unplayable
                                ></audio>
                                <button class="clip-name" on:click=open>
                                    {caption.clone()}
                                </button>
                            </div>
                        }
                            .into_any()
                    }
                    // Holding its place, so that it shows as it scrolls in.
                    (None, Sort::Image) => {
                        view! { <button class="thumb" title=name.clone()></button> }.into_any()
                    }
                    (None, Sort::Video) => {
                        view! { <div class="clip waiting">{caption.clone()}</div> }.into_any()
                    }
                    (None, _) => {
                        view! { <div class="clip audio waiting">{caption.clone()}</div> }
                            .into_any()
                    }
                }
            }}
        </div>
    }
}

/// Run `action` once `node` is about to show, as it scrolls into view, so that a long chat or
/// list does not run it for all; not at all if `node` goes first.
fn when_shown(node: NodeRef<html::Div>, action: impl Fn() + Clone + 'static) {
    // What watches it, and what that calls, until it goes.
    let watching = StoredValue::new_local(
        None::<(
            IntersectionObserver,
            Closure<dyn FnMut(js_sys::Array, IntersectionObserver)>,
        )>,
    );
    Effect::new(move || {
        let Some(element) = node.get() else {
            return;
        };
        let action = action.clone();
        let seen = Closure::<dyn FnMut(js_sys::Array, IntersectionObserver)>::new(
            move |entries: js_sys::Array, observer: IntersectionObserver| {
                let seen = entries.iter().any(|entry| {
                    entry
                        .unchecked_into::<IntersectionObserverEntry>()
                        .is_intersecting()
                });
                if seen {
                    observer.disconnect();
                    action();
                }
            },
        );
        let Ok(observer) = IntersectionObserver::new(seen.as_ref().unchecked_ref()) else {
            return;
        };
        observer.observe(&element);
        watching.set_value(Some((observer, seen)));
    });
    on_cleanup(move || {
        if let Some(Some((observer, _))) = watching.try_update_value(Option::take) {
            observer.disconnect();
        }
    });
}

/// What a preview of media shows, once read: an image or a video, by a blob URL of this origin,
/// or a video's stream, or an image's `data:` URL, as an SVG's or an audio file's cover.
#[derive(Debug, Clone, PartialEq)]
enum Preview {
    Image(String),
    Video(String),
}

/// A preview of media of a chat's history, of the sort `sort`, for the file browser: an image as
/// itself, a video as its first frames, under its length, and audio as its cover, if its tags
/// have one. `source` is read, or fetched, once it is about to show, as small media in the
/// chat; with none, as it is too large to fetch for this, or if it cannot be read, a glyph of
/// its sort shows.
#[component]
fn MediaThumb(source: Option<Source>, sort: Sort) -> impl IntoView {
    let node = NodeRef::<html::Div>::new();
    let video_ref = NodeRef::<html::Video>::new();
    let preview = RwSignal::new(None::<Preview>);
    let length = RwSignal::new(None::<String>);
    // Gone with the preview: a read that ends after shows nothing, and a URL made then is let
    // go at once.
    let here = StoredValue::new(());
    let stop_active = move || {
        if let Some(video) = video_ref.get_untracked() {
            stop_media(&video);
        }
    };
    let show = move |made: Preview| {
        if let Some(Some(Preview::Image(url) | Preview::Video(url))) = preview.try_set(Some(made)) {
            stop_active();
            release(&url);
        }
    };
    if let Some(source) = source {
        when_shown(node, move || {
            let source = source.clone();
            spawn_local(async move {
                // An attachment's video or audio streams, if it can, as far as its preview
                // needs: its first frames, or its tags.
                if let Source::Remote(remote) = &source
                    && sort != Sort::Image
                    && let Some(url) = engine()
                        .stream(remote.peer, remote.index, &remote.pointer, remote.clock)
                        .await
                {
                    if sort == Sort::Video {
                        show(Preview::Video(url));
                        return;
                    }
                    let head = engine().stream_head(&url).await;
                    engine().end_stream(&url);
                    if let Some(head) = head
                        && let Some(made) = cover(&head).await
                    {
                        show(made);
                    }
                    return;
                }
                let shows = move || here.try_get_value().is_some();
                let Ok(Some(attachment)) = source.read(&shows).await else {
                    return;
                };
                let data = &attachment.data;
                let made = match preview::media_mime(&attachment.name, &attachment.mime, data) {
                    Some(mime) if mime.starts_with("image/") => {
                        image_url(data, mime).map(Preview::Image)
                    }
                    Some(mime) if mime.starts_with("video/") => {
                        blob_url(data, mime).map(Preview::Video)
                    }
                    Some(_) => cover(data).await,
                    None => None,
                };
                if let Some(made) = made {
                    show(made);
                }
            });
        });
    }
    on_cleanup(move || {
        stop_active();
        if let Some(Some(Preview::Image(url) | Preview::Video(url))) = preview.try_get_untracked() {
            release(&url);
        }
    });
    // Its length, once the video knows it.
    let measured = move |event: ev::Event| {
        let seconds = event_target::<web_sys::HtmlMediaElement>(&event).duration();
        if seconds.is_finite() {
            length.set(Some(duration(seconds)));
        }
    };
    let glyph = match sort {
        Sort::Video => Icon::Resume,
        Sort::Audio => Icon::Music,
        _ => Icon::Document,
    };
    view! {
        <div class="preview" node_ref=node>
            {move || match preview.get() {
                Some(Preview::Image(url)) => view! { <img src=url alt="" /> }.into_any(),
                // Still, at its first frames: a fragment that has it show them, and no controls.
                Some(Preview::Video(url)) => {
                    view! {
                        <video
                            node_ref=video_ref
                            src=format!("{url}#t=0.1")
                            muted
                            preload="metadata"
                            playsinline
                            on:loadedmetadata=measured
                        ></video>
                    }
                        .into_any()
                }
                None => icon(glyph).into_any(),
            }}
            {(sort == Sort::Video)
                .then(|| {
                    view! { <span class="badge">{icon(Icon::Resume)} {move || length.get()}</span> }
                })}
        </div>
    }
}

/// The cover of the audio `data`, as its tags have it, if they do: a `data:` URL, which needs no
/// letting go, of an image, as the worker made sure.
async fn cover(data: &[u8]) -> Option<Preview> {
    let (mime, cover) = workers::audio_tags(data).await.ok()??.cover?;
    Some(Preview::Image(format!(
        "data:{mime};base64,{}",
        BASE64_STANDARD.encode(cover)
    )))
}

/// A length of time, as `m:ss`, or `h:mm:ss` from an hour.
fn duration(seconds: f64) -> String {
    let seconds = seconds.round() as u64;
    let (hours, minutes, seconds) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    }
}

/// Run `action`, telling what went wrong.
fn act(action: impl Future<Output = Result<(), String>> + 'static) {
    let ui = ui();
    spawn_local(async move {
        if let Err(e) = action.await {
            ui.notify(e);
        }
    });
}

/// Run `action` as [`act`] does, unless `busy` says one runs already, which it says meanwhile:
/// the buttons it disables, pressed again, start nothing twice.
fn act_while(busy: RwSignal<bool>, action: impl Future<Output = Result<(), String>> + 'static) {
    if busy.get_untracked() {
        return;
    }
    busy.set(true);
    act(async move {
        let done = action.await;
        busy.try_set(false);
        done
    });
}

fn open_chat(peer: Option<PublicKey>) {
    let engine = engine();
    spawn_local(async move { engine.open(peer).await });
}

fn new_chat() {
    ui().dialog.set(Some(Dialog::NewChat {
        key: String::new(),
        name: String::new(),
        server: None,
        pq_pinned: false,
    }));
}

/// Lock the vault: the page starts over, keeping nothing in memory.
fn lock() {
    let _ = window().location().reload();
}

/// How long a copy button shows that it copied, in milliseconds.
const COPIED_SHOWN: i32 = 1_500;

/// `text` in a box, with a button beside it that copies it, `what` it is, e.g. "your key": a
/// tick shows for a moment once it did, and a notice says if the browser would not.
#[component]
fn Copyable(text: String, what: &'static str) -> impl IntoView {
    let copied = RwSignal::new(false);
    let value = text.clone();
    let on_click = move |_| {
        let text = value.clone();
        spawn_local(async move {
            if !copy(&text).await {
                ui().notify(format!(
                    "The browser would not copy {what}; select it and copy it instead."
                ));
                return;
            }
            copied.set(true);
            sleep(COPIED_SHOWN).await;
            copied.try_set(false);
        });
    };
    let label = move || {
        if copied.get() {
            "Copied".to_string()
        } else {
            format!("Copy {what}")
        }
    };
    view! {
        <div class="copyable">
            <div class="key">{text}</div>
            <button
                type="button"
                class="btn icon"
                class:done=move || copied.get()
                title=label
                aria-label=label
                on:click=on_click
            >
                {move || icon(if copied.get() { Icon::Tick } else { Icon::Copy })}
            </button>
        </div>
    }
}

/// A link that opens a chat with `me`, with the name filled in, the server if it is not the
/// page's own, and `&pq=1` when post-quantum encryption is enabled.
fn invitation_link(me: &Me) -> String {
    build_invitation_link(&origin(), me)
}

/// The server an invitation link in the page's address names, to create the vault on.
fn invited_server() -> Option<String> {
    match invitation()? {
        Dialog::NewChat { server, .. } => server,
        _ => None,
    }
}

/// Send `content` to `peer`, after what was sent before it.
fn send(peer: PublicKey, content: content::Kind) {
    engine().queue(Sending::Content(peer, content));
}

/// Send `files` to the open chat, in their order, after what was sent before them: the small
/// ones in their messages, the others as attachments.
fn send_files(files: FileList) {
    let Some(peer) = ui().open.get_untracked() else {
        return;
    };
    let engine = engine();
    for file in (0..files.length()).filter_map(|i| files.get(i)) {
        engine.queue(Sending::File(peer, file));
    }
}

/// The modal dialog: the vault's while it is locked, then the one the page asks for.
#[component]
fn VaultDialog() -> impl IntoView {
    let ui = ui();
    let dialog = NodeRef::<html::Dialog>::new();
    let shown = move || match ui.phase.get() {
        Phase::Create | Phase::Locked | Phase::Elsewhere | Phase::Unavailable(_, _) => true,
        Phase::Unlocked => ui.dialog.get().is_some(),
        Phase::Loading => false,
    };
    Effect::new(move || {
        let shown = shown();
        if let Some(dialog) = dialog.get() {
            if shown && !dialog.open() {
                let _ = dialog.show_modal();
            } else if !shown && dialog.open() {
                dialog.close();
            }
        }
    });
    let on_cancel = move |event: ev::Event| {
        // The vault's dialog stays until the vault opens.
        if ui.phase.get_untracked() != Phase::Unlocked {
            event.prevent_default();
        } else if ui
            .dialog
            .with_untracked(|dialog| matches!(dialog, Some(Dialog::SignIn)))
        {
            // Dismissed, e.g. with Escape, the sign-in is put off, as "Not now" puts it off.
            // If an invitation / NewChat draft was waiting behind sign-in, restore it and keep
            // the native modal dialog open instead of letting it close and clear `ui.dialog`.
            if engine().dismiss_sign_in() {
                event.prevent_default();
            }
        }
    };
    let on_close = move |_| {
        // Ignore stale queued close events if a new modal dialog has already opened.
        if dialog.get_untracked().is_some_and(|d| !d.open()) {
            ui.dialog.set(None);
        }
    };
    view! {
        <dialog
            class="modal"
            class:wide=move || matches!(ui.dialog.get(), Some(Dialog::Files(_)))
            node_ref=dialog
            on:cancel=on_cancel
            on:close=on_close
        >
            {move || match (ui.phase.get(), ui.dialog.get()) {
                (Phase::Create, _) => view! { <CreateVault /> }.into_any(),
                (Phase::Locked, _) => view! { <UnlockVault /> }.into_any(),
                (Phase::Elsewhere, _) => view! { <Elsewhere /> }.into_any(),
                (Phase::Unavailable(reason, error), _) => {
                    view! { <Unavailable reason error /> }.into_any()
                }
                (
                    Phase::Unlocked,
                    Some(Dialog::NewChat {
                        key,
                        name,
                        server,
                        pq_pinned,
                    }),
                ) => view! { <NewChat key name server pq_pinned /> }.into_any(),
                (Phase::Unlocked, Some(Dialog::Identity)) => view! { <Identity /> }.into_any(),
                (Phase::Unlocked, Some(Dialog::Settings)) => view! { <Settings /> }.into_any(),
                (Phase::Unlocked, Some(Dialog::Contact(peer))) => {
                    view! { <ContactInfo peer /> }.into_any()
                }
                (Phase::Unlocked, Some(Dialog::Files(peer))) => {
                    view! { <FileBrowser peer /> }.into_any()
                }
                (Phase::Unlocked, Some(Dialog::SignIn)) => view! { <SignInDialog /> }.into_any(),
                (Phase::Unlocked, Some(Dialog::Activity)) => {
                    view! { <ActivityDialog /> }.into_any()
                }
                _ => ().into_any(),
            }}
            <Toast />
        </dialog>
    }
}

/// Move a secret string out of an `RwSignal<String>` into [`Zeroizing`] while clearing and
/// zeroizing the signal's buffer immediately.
fn take_secret(signal: RwSignal<String>) -> Zeroizing<String> {
    let mut secret = String::new();
    signal.update(|value| {
        std::mem::swap(value, &mut secret);
        value.zeroize();
    });
    Zeroizing::new(secret)
}

/// Zeroize and clear a secret `RwSignal<String>` in place.
fn clear_secret(signal: RwSignal<String>) {
    let _ = signal.try_update(|value| value.zeroize());
}

/// Sign in to the server with its password, which storing files there takes, as they cost it
/// storage: what waited for it goes then, and any pending invitation / new-chat draft resumes.
#[component]
fn SignInDialog() -> impl IntoView {
    let password = RwSignal::new(String::new());
    let password_input = NodeRef::<html::Input>::new();
    on_cleanup(move || clear_secret(password));
    // Focus explicitly on mount/swap inside the shared `<dialog>` (HTML `autofocus` only runs
    // when the native dialog first opens).
    Effect::new(move || {
        if let Some(input) = password_input.get() {
            let _ = input.focus();
        }
    });
    let progress = Progress::new();
    let pending_hint = engine()
        .pending_new_chat_hint()
        .map(|(auto_start, has_key)| match (auto_start, has_key) {
            (true, _) => {
                "Sign in to continue starting your chat — your invitation details are saved."
            }
            (false, true) => "After you sign in, your invitation will open automatically.",
            (false, false) => "After you sign in, you will return to starting your chat.",
        });
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        let engine = engine();
        let secret = take_secret(password);
        progress.start("Signing in…");
        spawn_local(async move {
            let result = engine.sign_in(&secret).await;
            drop(secret);
            match result {
                Ok(signed_in) => {
                    let until = day(signed_in.expires);
                    match engine.complete_sign_in_flow() {
                        SignInSuccessAction::Close => {
                            engine.close_dialog_if_sign_in();
                            engine.ui().notify(format!(
                                "Signed in until {until}: waiting messages and files go now."
                            ));
                        }
                        SignInSuccessAction::ReopenNewChat(dialog) => {
                            engine.ui().dialog.set(Some(dialog));
                            engine.ui().notify(format!("Signed in until {until}."));
                        }
                        SignInSuccessAction::AutoStartChat(pending) => {
                            progress.try_start("Starting chat…");
                            match engine
                                .start_chat(
                                    &pending.key,
                                    pending.name.clone(),
                                    pending.pq_pinned,
                                    pending.allow_classical,
                                )
                                .await
                            {
                                Ok(peer) => {
                                    engine.finish_auto_start_chat(None);
                                    engine.close_dialog_if_new_chat();
                                    engine.open(Some(peer)).await;
                                    // If sending the initial greeting hit a secondary
                                    // `SignInRequired` after persisting the chat, `SignInDialog`
                                    // intentionally stayed open — reset `progress` so buttons are
                                    // usable again.
                                    if engine
                                        .ui()
                                        .dialog
                                        .with_untracked(|d| matches!(d, Some(Dialog::SignIn)))
                                    {
                                        progress.try_fail(
                                            "Sign-in is still required by the server to send the \
                                             greeting.",
                                        );
                                    } else {
                                        progress.clear();
                                        engine.ui().notify(format!("Signed in until {until}."));
                                    }
                                }
                                Err(StartChatError::SignInRequired) => {
                                    engine.finish_auto_start_chat(Some(
                                        StartChatError::SignInRequired,
                                    ));
                                    progress.try_fail("Sign-in is still required by the server.");
                                }
                                Err(err) => {
                                    progress.clear();
                                    engine.finish_auto_start_chat(Some(err));
                                    engine.ui().notify(format!("Signed in until {until}."));
                                }
                            }
                        }
                    }
                }
                Err(e) => progress.try_fail(e),
            }
        });
    };
    view! {
        <form on:submit=submit>
            <h2>"Sign in to this server"</h2>
            <p>
                "This server is only for those signed in to it, as all that goes through it "
                "costs it storage. Enter the password its owner gave you; this browser stays "
                "signed in for a while. What you sent waits until then, unless you cancel it in "
                "its chat."
            </p>
            {pending_hint.map(|hint| view! { <p class="hint">{hint}</p> })}
            <label for="server-password">"The server's password"</label>
            <input
                id="server-password"
                node_ref=password_input
                type="password"
                autocomplete="current-password"
                required
                autofocus
                bind:value=password
            />
            {progress.view()}
            <div class="actions">
                <button
                    type="button"
                    class="btn"
                    disabled=move || progress.working.get()
                    on:click=move |_| {
                        engine().dismiss_sign_in();
                    }
                >
                    "Not now"
                </button>
                <button type="submit" class="btn primary" disabled=move || progress.working.get()>
                    "Sign in"
                </button>
            </div>
        </form>
    }
}

/// Closes the page's dialog.
fn close_dialog() {
    ui().dialog.set(None);
}

/// A form's error line, or what it is busy with.
#[derive(Clone, Copy)]
struct Progress {
    message: RwSignal<String>,
    working: RwSignal<bool>,
}

impl Progress {
    fn new() -> Self {
        Self {
            message: RwSignal::new(String::new()),
            working: RwSignal::new(false),
        }
    }

    fn start(&self, message: &str) {
        self.working.set(true);
        self.message.set(message.to_string());
    }

    fn try_start(&self, message: &str) {
        let _ = self.working.try_set(true);
        let _ = self.message.try_set(message.to_string());
    }

    fn fail(&self, error: impl Into<String>) {
        self.working.set(false);
        self.message.set(error.into());
    }

    fn try_fail(&self, error: impl Into<String>) {
        let _ = self.working.try_set(false);
        let _ = self.message.try_set(error.into());
    }

    fn clear(&self) {
        let _ = self.working.try_set(false);
        let _ = self.message.try_set(String::new());
    }

    fn view(self) -> impl IntoView {
        view! {
            <p class="error" class:working=move || self.working.get() role="alert">
                {move || self.message.get()}
            </p>
        }
    }
}

#[component]
fn CreateVault() -> impl IntoView {
    let name = RwSignal::new(String::new());
    let passphrase = RwSignal::new(String::new());
    let repeat = RwSignal::new(String::new());
    on_cleanup(move || {
        clear_secret(passphrase);
        clear_secret(repeat);
    });
    let pq_compiled = !PqConfig::compiled_suites().is_empty();
    let pq_enabled = RwSignal::new(pq_compiled);
    let invited = invited_server();
    let server = RwSignal::new(invited.clone().unwrap_or_else(origin));
    let progress = Progress::new();
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        if passphrase.with_untracked(|p| p.chars().count()) < 8 {
            return progress.fail("Use a passphrase of 8 characters or more.");
        }
        let matches = passphrase.with_untracked(|p| repeat.with_untracked(|r| p == r));
        if !matches {
            return progress.fail("The passphrases differ.");
        }
        let secret = take_secret(passphrase);
        clear_secret(repeat);
        let enable_pq = pq_enabled.get_untracked();
        let display_name = name.get_untracked();
        let target_server = server.get_untracked();
        progress.start("Deriving the key…");
        let engine = engine();
        spawn_local(async move {
            // Argon2 blocks the page for a moment; let it show why first.
            sleep(50).await;
            let result = engine
                .create(display_name, secret, target_server, enable_pq)
                .await;
            if let Err(e) = result {
                progress.fail(e);
            }
        });
    };
    view! {
        <form on:submit=submit>
            <h2>"Create your vault"</h2>
            <p>
                "A new identity key is made here and kept in this browser with your chats, "
                "sealed by a passphrase. There is no recovery: forget the passphrase, and the "
                "vault is lost."
            </p>
            <label for="name">"Your name, which new chats see"</label>
            <input id="name" autocomplete="nickname" maxlength=NAME_MAX bind:value=name />
            <label for="password">"Passphrase"</label>
            <input
                id="password"
                type="password"
                autocomplete="new-password"
                required
                bind:value=passphrase
            />
            <label for="repeat">"Passphrase, again"</label>
            <input
                id="repeat"
                type="password"
                autocomplete="new-password"
                required
                bind:value=repeat
            />
            <label for="server">"Server"</label>
            <input id="server" type="url" required bind:value=server />
            {invited
                .map(|_| {
                    view! {
                        <p class="hint">
                            "The server of your invitation: a chat needs both of you on one."
                        </p>
                    }
                })}
            {pq_compiled.then(|| {
                view! {
                    <div class="settings-card create-pq">
                        <ToggleSwitch
                            id="create-pq"
                            title="Post-quantum encryption"
                            description="Protects new chats against future quantum computers."
                            checked=Signal::derive(move || pq_enabled.get())
                            disabled=Signal::derive(move || progress.working.get())
                            on_toggle=move |on| pq_enabled.set(on)
                        />
                    </div>
                }
            })}
            {progress.view()}
            <div class="actions">
                <button class="btn primary" type="submit" disabled=move || progress.working.get()>
                    "Create"
                </button>
            </div>
        </form>
    }
}

#[component]
fn UnlockVault() -> impl IntoView {
    let passphrase = RwSignal::new(String::new());
    on_cleanup(move || clear_secret(passphrase));
    let progress = Progress::new();
    let confirm_reset = RwSignal::new(false);
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        let secret = take_secret(passphrase);
        progress.start("Deriving the key…");
        let engine = engine();
        spawn_local(async move {
            sleep(50).await;
            if let Err(e) = engine.unlock(secret).await {
                progress.fail(e);
            }
        });
    };
    let reset = move |_| {
        if progress.working.get_untracked() {
            return;
        }
        if !confirm_reset.get_untracked() {
            confirm_reset.set(true);
            set_timeout(
                move || {
                    if confirm_reset.try_get_untracked() == Some(true)
                        && progress.working.try_get_untracked() == Some(false)
                    {
                        confirm_reset.set(false);
                    }
                },
                ASKED_SHOWN,
            );
            return;
        }
        progress.start("Deleting the vault…");
        spawn_local(async move {
            match crate::vault::Vault::destroy().await {
                Ok(()) => lock(),
                Err(e) => progress.fail(e.to_string()),
            }
        });
    };
    view! {
        <form on:submit=submit>
            <h2>"Unlock your vault"</h2>
            <p>"Your identity key and chats are sealed in this browser by your passphrase."</p>
            <label for="password">"Passphrase"</label>
            <input
                id="password"
                type="password"
                autocomplete="current-password"
                required
                autofocus
                bind:value=passphrase
            />
            {progress.view()}
            <div class="actions">
                <button
                    type="button"
                    class="btn danger"
                    disabled=move || progress.working.get()
                    on:click=reset
                >
                    {move || {
                        if confirm_reset.get() {
                            "Delete it all, for good?"
                        } else {
                            "Forgot it: start over"
                        }
                    }}
                </button>
                <button class="btn primary" type="submit" disabled=move || progress.working.get()>
                    "Unlock"
                </button>
            </div>
        </form>
    }
}

#[component]
fn Elsewhere() -> impl IntoView {
    view! {
        <div>
            <h2>"Open in another tab"</h2>
            <p>
                "The vault is open in another tab or window of this browser. Two pages on one "
                "vault would tangle its sessions, so close the other one, then reload this page."
            </p>
            <div class="actions">
                <button class="btn primary" on:click=move |_| lock()>
                    "Reload"
                </button>
            </div>
        </div>
    }
}

#[component]
fn Unavailable(reason: UnavailableReason, error: String) -> impl IntoView {
    let (heading, copy) = match reason {
        UnavailableReason::InsecureContext => (
            "Secure context required",
            "Open this page over HTTPS (or localhost) so the browser provides the Web Locks API \
             needed to keep concurrent tabs from corrupting your vault.",
        ),
        UnavailableReason::LocksUnavailable => (
            "Web Locks unavailable",
            "This browser does not provide the Web Locks API needed to prevent concurrent tabs \
             from corrupting your vault. Try a modern browser or check site restrictions.",
        ),
        UnavailableReason::StorageUnavailable => (
            "Storage unavailable",
            "The browser would not open its storage, so whether a vault is here is unknown, and \
             nothing was changed. Private windows and blocked site data can cause this.",
        ),
    };
    view! {
        <div>
            <h2>{heading}</h2>
            <p>{copy}</p>
            <p class="error">{error}</p>
            <div class="actions">
                <button class="btn primary" on:click=move |_| lock()>
                    "Reload"
                </button>
            </div>
        </div>
    }
}

fn apply_start_chat_error(
    err: StartChatError,
    classical_needed: RwSignal<Option<bool>>,
    progress: Progress,
) {
    match err {
        StartChatError::SignInRequired => progress.clear(),
        StartChatError::ClassicalApprovalRequired { peer_signed_off } => {
            let _ = classical_needed.try_set(Some(peer_signed_off));
            progress.try_fail(if peer_signed_off {
                "This peer signed a manifest disabling post-quantum encryption."
            } else {
                "This peer has no post-quantum prekeys on the server."
            });
        }
        StartChatError::DowngradeDetected => {
            progress.try_fail(
                "Downgrade detected: this invitation pinned post-quantum encryption, but \
                 the server did not provide valid PQ prekeys.",
            );
        }
        StartChatError::PeerManifestExpired => {
            progress.try_fail(
                "This peer's signed post-quantum capability manifest has expired. Try \
                 again after they come online.",
            );
        }
        StartChatError::PqRequired => {
            progress.try_fail(
                "Require PQ (strict mode) is enabled, and a post-quantum session could not \
                 be established with this peer.",
            );
        }
        StartChatError::Other(e) => progress.try_fail(e),
    }
}

#[component]
fn NewChat(
    key: String,
    name: String,
    server: Option<String>,
    pq_pinned: bool,
) -> impl IntoView {
    // An invitation for another server than the vault's: the inviter's keys are not on it.
    let elsewhere = ui().me.get_untracked().and_then(|me| {
        server
            .as_ref()
            .filter(|server| !same_server(server, &me.server))
            .map(|server| (server.clone(), me.server))
    });
    engine().new_chat_mounted(key.clone(), name.clone(), server.clone(), pq_pinned);
    let key = RwSignal::new(key);
    let name = RwSignal::new(name);
    let server_saved = StoredValue::new(server);
    Effect::new(move || {
        engine().new_chat_edited(key.get(), name.get());
    });
    on_cleanup(move || {
        engine().new_chat_unmounted();
    });
    let progress = Progress::new();
    let classical_needed = RwSignal::new(None::<bool>);
    if let Some(feedback) = engine().take_new_chat_feedback() {
        apply_start_chat_error(feedback, classical_needed, progress);
    }
    let start = move |allow_classical: bool| {
        classical_needed.set(None);
        progress.start("Fetching their prekeys…");
        let engine = engine();
        let draft = PendingNewChat {
            key: key.get_untracked(),
            name: name.get_untracked(),
            server: server_saved.get_value(),
            pq_pinned,
            allow_classical,
            auto_start: true,
        };
        engine.begin_new_chat_submit(draft.clone());
        spawn_local(async move {
            let outcome = engine
                .start_chat(
                    &draft.key,
                    draft.name.clone(),
                    draft.pq_pinned,
                    draft.allow_classical,
                )
                .await;
            engine.end_new_chat_submit();
            match outcome {
                Ok(peer) => {
                    engine.close_dialog_if_new_chat();
                    engine.open(Some(peer)).await;
                }
                Err(StartChatError::SignInRequired) => {
                    progress.clear();
                    engine.require_sign_in_for_new_chat(draft);
                }
                Err(err) => apply_start_chat_error(err, classical_needed, progress),
            }
        });
    };
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        start(false);
    };
    let local_pq_enabled = ui().me.with_untracked(|me| {
        me.as_ref().is_some_and(|me| {
            me.pq_config.pq_enabled && !me.pq_config.offered_suites().is_empty()
        })
    });
    view! {
        <form on:submit=submit>
            <h2>"New chat"</h2>
            <p>
                "Paste their identity key. Their prekeys come from the server, and a greeting "
                "with your name starts the session."
            </p>
            {pq_pinned.then(|| {
                if local_pq_enabled {
                    view! {
                        <p class="pq-pin-hint">
                            <span class="sec-badge pq">"PQ pinned"</span>
                            " This invitation expects post-quantum encryption and will refuse classical downgrades."
                        </p>
                    }
                    .into_any()
                } else {
                    view! {
                        <p class="warning">
                            "This invitation expects post-quantum encryption, but post-quantum \
                             encryption is disabled or not compiled into this client; starting a \
                             chat here will use classical encryption only."
                        </p>
                    }
                    .into_any()
                }
            })}
            <label for="peer-key">"Their identity key"</label>
            <input id="peer-key" required autocomplete="off" spellcheck="false" bind:value=key />
            <label for="peer-name">"Their name, for you"</label>
            <input id="peer-name" autocomplete="off" bind:value=name />
            {elsewhere
                .map(|(theirs, yours)| {
                    view! {
                        <p class="warning">
                            "They are on " {theirs} ", and your vault on " {yours}
                            ": a chat needs both of you on one server, so it cannot start here."
                        </p>
                    }
                })}
            {move || {
                classical_needed.get().map(|peer_signed_off| {
                    view! {
                        <div class="classical-box" role="alert">
                            <p>
                                {if peer_signed_off {
                                    "The peer explicitly turned post-quantum encryption off. Only allow classical encryption if you expect that."
                                } else {
                                    "No post-quantum prekeys were returned for this peer. Allow a classical (non-PQ) chat?"
                                }}
                            </p>
                            <button
                                type="button"
                                class="btn small"
                                disabled=move || progress.working.get()
                                on:click=move |_| start(true)
                            >
                                "Allow classical"
                            </button>
                        </div>
                    }
                })
            }}
            {progress.view()}
            <div class="actions">
                <button
                    type="button"
                    class="btn"
                    disabled=move || progress.working.get()
                    on:click=move |_| close_dialog()
                >
                    "Cancel"
                </button>
                <button class="btn primary" type="submit" disabled=move || progress.working.get()>
                    "Start"
                </button>
            </div>
        </form>
    }
}

/// Accessible custom CSS pill toggle switch row.
#[component]
fn ToggleSwitch(
    id: &'static str,
    title: &'static str,
    description: &'static str,
    checked: Signal<bool>,
    disabled: Signal<bool>,
    on_toggle: impl Fn(bool) + 'static,
) -> impl IntoView {
    view! {
        <label class="switch-row" class:disabled=move || disabled.get() for=id>
            <span class="switch-copy">
                <strong>{title}</strong>
                <small>{description}</small>
            </span>
            <span class="switch">
                <input
                    id=id
                    type="checkbox"
                    role="switch"
                    disabled=move || disabled.get()
                    prop:checked=move || checked.get()
                    on:change=move |ev: ev::Event| {
                        on_toggle(event_target_checked(&ev));
                    }
                />
                <span class="switch-track" aria-hidden="true">
                    <span class="switch-thumb"></span>
                </span>
            </span>
        </label>
    }
}

/// Display label and concise hint for an ML-KEM suite in the segmented control.
fn pq_suite_option(suite: PqSuite) -> (&'static str, &'static str) {
    match suite {
        PqSuite::MlKem1024 => ("ML-KEM-1024", "Stronger"),
        PqSuite::MlKem768 => ("ML-KEM-768", "Smaller"),
    }
}

/// Compact pill `(css_class, label, tooltip)` for the server's advertised PQ support.
fn server_pq_pill(status: &ServerPqStatus) -> (&'static str, &'static str, String) {
    match status {
        ServerPqStatus::Enabled { suites, pq_ratchet } => {
            let names: Vec<_> = suites
                .iter()
                .map(|s| match s {
                    PqSuite::MlKem1024 => "ML-KEM-1024",
                    PqSuite::MlKem768 => "ML-KEM-768",
                })
                .collect();
            let list = if names.is_empty() {
                "enabled".to_string()
            } else {
                names.join(", ")
            };
            let title = if *pq_ratchet {
                format!("Server supports post-quantum encryption ({list}, continuous re-keying).")
            } else {
                format!("Server supports post-quantum encryption ({list}).")
            };
            ("sec-badge pq", "Server: PQ ready", title)
        }
        ServerPqStatus::Disabled => (
            "sec-badge classical",
            "Server: Classical only",
            "This server does not have post-quantum encryption enabled.".to_string(),
        ),
        ServerPqStatus::AudienceMismatch => (
            "sec-badge danger",
            "Server: ID mismatch",
            "Server ID did not match this server's expected audience.".to_string(),
        ),
        ServerPqStatus::Unknown => (
            "sec-badge neutral",
            "Server: Checking…",
            "Checking server post-quantum support…".to_string(),
        ),
    }
}

#[component]
fn Identity() -> impl IntoView {
    let ui = ui();
    let Some(me) = ui.me.get_untracked() else {
        return ().into_any();
    };
    let name = RwSignal::new(me.name.clone());
    // Saving or publishing prekeys, which its buttons wait for.
    let busy = RwSignal::new(false);
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        let engine = engine();
        let next_name = name.get_untracked();
        act_while(busy, async move {
            engine.set_name(next_name).await?;
            engine.ui().dialog.set(None);
            Ok(())
        });
    };
    let publish = move |_| {
        let engine = engine();
        act_while(busy, async move {
            engine.publish(true).await?;
            engine.ui().notify("Published new prekeys.");
            Ok(())
        });
    };
    view! {
        <form on:submit=submit>
            <h2>"Your identity"</h2>
            <p>
                "Others start a chat with your identity key, or by opening your invitation "
                "link. Both are public: only this browser can answer."
            </p>
            <label>"Identity key"</label>
            <Copyable text=key_to_text(&me.key) what="your key" />
            <label>"Invitation link"</label>
            {move || {
                let link = ui.me.get().as_ref().map(invitation_link).unwrap_or_default();
                view! { <Copyable text=link what="your invitation link" /> }
            }}
            <label for="my-name">"Your name, which new chats see"</label>
            <input id="my-name" autocomplete="nickname" maxlength=NAME_MAX bind:value=name />
            <div class="actions">
                <button
                    type="button"
                    class="btn aside"
                    title="publish a new signed prekey and one-time prekeys"
                    disabled=move || busy.get()
                    on:click=publish
                >
                    "New prekeys"
                </button>
                <button
                    type="button"
                    class="btn"
                    disabled=move || busy.get()
                    on:click=move |_| close_dialog()
                >
                    "Cancel"
                </button>
                <button type="submit" class="btn primary" disabled=move || busy.get()>
                    "Save"
                </button>
            </div>
        </form>
    }
    .into_any()
}

#[component]
fn Settings() -> impl IntoView {
    let ui = ui();
    let Some(me) = ui.me.get_untracked() else {
        return ().into_any();
    };
    let server_url = me.server.clone();
    let can_sign_in_here = same_server(&server_url, &origin());
    let compiled_suites = PqConfig::compiled_suites();
    let pq_compiled = !compiled_suites.is_empty();
    let initial_pq = me.pq_config.clone();
    let pq_enabled = RwSignal::new(pq_compiled && initial_pq.pq_enabled);
    let preferred_suite = RwSignal::new(if compiled_suites.contains(&initial_pq.preferred_suite) {
        initial_pq.preferred_suite
    } else {
        PqConfig::default_suite()
    });
    let pq_ratchet_enabled = RwSignal::new(pq_compiled && initial_pq.pq_ratchet_enabled);
    let strict_pq = RwSignal::new(pq_compiled && initial_pq.pq_enabled && initial_pq.strict_pq);
    let advanced_open = pq_compiled && (initial_pq.strict_pq || !initial_pq.pq_ratchet_enabled);
    let server_pq_disabled = Signal::derive(move || {
        ui.me.with(|me| {
            me.as_ref()
                .is_some_and(|m| m.server_pq == ServerPqStatus::Disabled)
        })
    });
    // Saving settings or signing out, which its buttons wait for.
    let busy = RwSignal::new(false);
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        if !pq_compiled {
            close_dialog();
            return;
        }
        let engine = engine();
        let next_pq = PqConfig {
            pq_enabled: pq_enabled.get_untracked(),
            preferred_suite: preferred_suite.get_untracked(),
            pq_ratchet_enabled: pq_ratchet_enabled.get_untracked(),
            strict_pq: pq_enabled.get_untracked() && strict_pq.get_untracked(),
        };
        act_while(busy, async move {
            // Always invoke `set_pq_config`: it compares against live vault state, rolls back
            // definitively refused configs, and reports durable local saves clearly.
            let outcome = engine.set_pq_config(next_pq).await?;
            engine.ui().dialog.set(None);
            match outcome {
                PqSaveOutcome::Published => engine
                    .ui()
                    .notify("Saved settings and published updated prekeys."),
                PqSaveOutcome::Unchanged => engine.ui().notify("Settings saved."),
                PqSaveOutcome::SavedLocallyNeedsSignIn => engine
                    .ui()
                    .notify("Saved locally; sign in to publish updated prekeys."),
                PqSaveOutcome::SavedLocallyPendingPublish => engine
                    .ui()
                    .notify("Saved locally; prekeys will publish once connected."),
            }
            Ok(())
        });
    };
    // Whether this browser is signed in to the server (only possible on the server's own origin).
    let signed_in = RwSignal::new(None::<Result<Option<SignIn>, String>>);
    if can_sign_in_here {
        spawn_local(async move {
            signed_in.try_set(Some(engine().signed_in().await));
        });
    }
    let sign_out = move |_| {
        let engine = engine();
        act_while(busy, async move {
            engine.sign_out().await?;
            signed_in.try_set(Some(Ok(None)));
            engine
                .ui()
                .notify("Signed out: messages and files wait for the next sign-in.");
            Ok(())
        });
    };
    let pq_controls_disabled = Signal::derive(move || busy.get() || !pq_enabled.get());
    let strict_pq_disabled = Signal::derive(move || {
        pq_controls_disabled.get() || (server_pq_disabled.get() && !strict_pq.get())
    });
    let server_row = move || {
        if !can_sign_in_here {
            return view! {
                <div class="settings-server-row">
                    <div class="settings-copy">
                        <strong>"Different server origin"</strong>
                        <small>
                            {format!(
                                "Your vault uses {server_url}. Open that server's own page to sign in or out."
                            )}
                        </small>
                    </div>
                </div>
            }
            .into_any();
        }
        match signed_in.get() {
            None => view! {
                <div class="settings-server-row">
                    <div class="settings-copy">
                        <span class="settings-muted">"Checking sign-in status…"</span>
                    </div>
                </div>
            }
            .into_any(),
            Some(Ok(Some(signed_in))) => view! {
                <div class="settings-server-row">
                    <div class="settings-copy">
                        <strong>{format!("Signed in until {}", day(signed_in.expires))}</strong>
                        <small>{server_url.clone()}</small>
                    </div>
                    <button
                        type="button"
                        class="btn small"
                        disabled=move || busy.get()
                        on:click=sign_out
                    >
                        "Sign out"
                    </button>
                </div>
            }
            .into_any(),
            Some(Ok(None)) => view! {
                <div class="settings-server-row">
                    <div class="settings-copy">
                        <strong>"Not signed in"</strong>
                        <small>"Sign in to send messages and files through this server."</small>
                    </div>
                    <button
                        type="button"
                        class="btn primary small"
                        disabled=move || busy.get()
                        on:click=move |_| ui.dialog.set(Some(Dialog::SignIn))
                    >
                        "Sign in"
                    </button>
                </div>
            }
            .into_any(),
            Some(Err(e)) => view! {
                <div class="settings-server-row">
                    <div class="settings-copy">
                        <span class="settings-error">{format!("Cannot reach server: {e}")}</span>
                    </div>
                </div>
            }
            .into_any(),
        }
    };
    let encryption_card = if pq_compiled {
        let suites_for_segments = compiled_suites.clone();
        view! {
            <div class="settings-card">
                <ToggleSwitch
                    id="pq-enabled"
                    title="Post-quantum encryption"
                    description="Protects new chats against future quantum computers."
                    checked=Signal::derive(move || pq_enabled.get())
                    disabled=Signal::derive(move || busy.get())
                    on_toggle=move |on| {
                        pq_enabled.set(on);
                        if !on {
                            strict_pq.set(false);
                        }
                    }
                />
                <div class="settings-block" class:disabled=move || pq_controls_disabled.get()>
                    <div id="pq-strength-label" class="settings-sublabel">
                        "Preferred key strength"
                    </div>
                    <div
                        class="segmented"
                        role="radiogroup"
                        aria-labelledby="pq-strength-label"
                    >
                        {suites_for_segments
                            .into_iter()
                            .map(|suite| {
                                let (label, hint) = pq_suite_option(suite);
                                view! {
                                    <button
                                        type="button"
                                        class="segment"
                                        class:active=move || preferred_suite.get() == suite
                                        role="radio"
                                        aria-checked=move || {
                                            if preferred_suite.get() == suite {
                                                "true"
                                            } else {
                                                "false"
                                            }
                                        }
                                        disabled=move || pq_controls_disabled.get()
                                        on:click=move |_| preferred_suite.set(suite)
                                    >
                                        <span class="segment-title">{label}</span>
                                        <span class="segment-hint">{hint}</span>
                                    </button>
                                }
                            })
                            .collect_view()}
                    </div>
                </div>
                <p class="settings-note">
                    "Changes apply to new or re-keyed chats; existing chats keep their current encryption."
                </p>
                <Show when=move || server_pq_disabled.get()>
                    <p class="settings-warn">
                        "This server does not have post-quantum encryption enabled. New chats will \
                         use classical encryption, and Require post-quantum cannot be turned on."
                    </p>
                </Show>
                <details class="settings-advanced" open=advanced_open>
                    <summary>"Advanced"</summary>
                    <div class="settings-advanced-body">
                        <ToggleSwitch
                            id="pq-ratchet"
                            title="Continuous PQ re-keying"
                            description="Refresh quantum-resistant keys during long chats so sessions recover if a device is ever compromised."
                            checked=Signal::derive(move || pq_ratchet_enabled.get())
                            disabled=pq_controls_disabled
                            on_toggle=move |on| pq_ratchet_enabled.set(on)
                        />
                        <ToggleSwitch
                            id="pq-strict"
                            title="Require post-quantum"
                            description="Block classical-only chats and refuse fallback."
                            checked=Signal::derive(move || strict_pq.get())
                            disabled=strict_pq_disabled
                            on_toggle=move |on| strict_pq.set(on)
                        />
                    </div>
                </details>
            </div>
        }
        .into_any()
    } else {
        view! {
            <div class="settings-card">
                <div class="settings-status-row">
                    <div class="settings-copy">
                        <strong>"Classical encryption only"</strong>
                        <small>"This client was built without post-quantum cryptography."</small>
                    </div>
                    <span class="sec-badge classical">"Classical"</span>
                </div>
            </div>
        }
        .into_any()
    };
    view! {
        <form class="settings-form" on:submit=submit>
            <h2>"Settings"</h2>
            <section class="settings-section">
                <div class="settings-section-head">
                    <h3>"Encryption"</h3>
                    {pq_compiled.then_some(move || {
                        ui.me.with(|me| {
                            me.as_ref().map(|m| {
                                let (class, label, title) = server_pq_pill(&m.server_pq);
                                view! {
                                    <span class=class title=title>
                                        {label}
                                    </span>
                                }
                            })
                        })
                    })}
                </div>
                {encryption_card}
            </section>
            <section class="settings-section">
                <div class="settings-section-head">
                    <h3>"Server"</h3>
                </div>
                <div class="settings-card">{server_row}</div>
            </section>
            <div class="actions">
                {if pq_compiled {
                    view! {
                        <button
                            type="button"
                            class="btn"
                            disabled=move || busy.get()
                            on:click=move |_| close_dialog()
                        >
                            "Cancel"
                        </button>
                        <button type="submit" class="btn primary" disabled=move || busy.get()>
                            "Save"
                        </button>
                    }
                    .into_any()
                } else {
                    view! {
                        <button
                            type="button"
                            class="btn primary"
                            disabled=move || busy.get()
                            on:click=move |_| close_dialog()
                        >
                            "Close"
                        </button>
                    }
                    .into_any()
                }}
            </div>
        </form>
    }
    .into_any()
}

#[component]
fn ContactInfo(peer: PublicKey) -> impl IntoView {
    let ui = ui();
    let Some((contact, me)) = ui.contact(&peer).zip(ui.me.get_untracked()) else {
        return ().into_any();
    };
    let live_contact = move || ui.contact(&peer);
    let is_request = move || live_contact().is_some_and(|c| c.request);
    let is_quarantined = move || live_contact().is_some_and(|c| c.is_quarantined());
    let name = RwSignal::new(if contact.request {
        contact.hello_name.clone()
    } else {
        contact.name.clone()
    });
    let confirm_delete = RwSignal::new(false);
    // Saving, accepting or deleting, which its buttons wait for.
    let busy = RwSignal::new(false);
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        let req = is_request();
        if req && is_quarantined() {
            ui.notify("Allow classical encryption or upgrade to PQ before accepting this request.");
            return;
        }
        let engine = engine();
        act_while(busy, async move {
            if req {
                engine.accept(peer, name.get_untracked()).await?;
            } else {
                engine.rename(peer, name.get_untracked()).await?;
            }
            engine.ui().dialog.set(None);
            Ok(())
        });
    };
    let delete = move |_| {
        if !confirm_delete.get_untracked() {
            confirm_delete.set(true);
            return;
        }
        let engine = engine();
        act_while(busy, async move {
            engine.delete(peer).await?;
            engine.ui().dialog.set(None);
            Ok(())
        });
    };
    let intro = move || match live_contact() {
        Some(c) if c.request => match c.hello_name.as_str() {
            "" => format!("{} wants to chat.", short(&peer)),
            hello => format!("{} wants to chat, and goes by “{hello}”.", short(&peer)),
        },
        Some(c) => format!("Your chat with {}.", c.label()),
        None => String::new(),
    };
    let pq_available = move || {
        ui.me.with(|me| {
            me.as_ref().is_some_and(|me| {
                me.pq_config.pq_enabled && !me.pq_config.offered_suites().is_empty()
            })
        })
    };
    let server_pq_disabled = move || {
        ui.me.with(|me| {
            me.as_ref()
                .is_some_and(|me| me.server_pq == ServerPqStatus::Disabled)
        })
    };
    let upgrade_disabled_tip = move || {
        server_pq_disabled()
            .then_some("This server does not have post-quantum encryption enabled.")
    };
    view! {
        <form on:submit=submit>
            <h2>{move || if is_request() { "Chat request" } else { "Chat" }}</h2>
            <p>
                {intro}
                " To be sure it is them, compare the safety number with them in person or over "
                "another channel: it is the same on both sides only if neither key was swapped."
            </p>
            <label>"Encryption"</label>
            {move || {
                live_contact().map(|c| {
                    let show_allow = c.classical_prompt != ClassicalPrompt::None;
                    let show_upgrade = pq_available() && contact_can_upgrade_to_pq(&c);
                    let show_dismiss = c.has_downgrade();
                    view! {
                        <div class="contact-security">
                            <div class="contact-security-row">
                                {security_badge(&c, true)}
                                {c.pq_pinned.then(|| view! { <span class="sec-meta">"PQ pinned"</span> })}
                                {c.allow_classical_exception.then(|| {
                                    view! { <span class="sec-meta">"Classical allowed"</span> }
                                })}
                            </div>
                            {(show_allow || show_upgrade || show_dismiss).then(|| {
                                view! {
                                    <div class="banner-actions">
                                        {show_allow.then(|| {
                                            view! {
                                                <button
                                                    type="button"
                                                    class="btn small"
                                                    disabled=move || busy.get()
                                                    on:click=move |_| {
                                                        act_while(busy, async move {
                                                            engine().approve_classical(peer).await
                                                        });
                                                    }
                                                >
                                                    "Allow classical"
                                                </button>
                                            }
                                        })}
                                        {show_upgrade.then(|| {
                                            view! {
                                                <button
                                                    type="button"
                                                    class="btn primary small"
                                                    title=upgrade_disabled_tip
                                                    disabled=move || {
                                                        busy.get() || server_pq_disabled()
                                                    }
                                                    on:click=move |_| {
                                                        act_while(busy, async move {
                                                            engine().upgrade_to_pq(peer).await
                                                        });
                                                    }
                                                >
                                                    "Upgrade to PQ"
                                                </button>
                                            }
                                        })}
                                        {show_dismiss.then(|| {
                                            view! {
                                                <button
                                                    type="button"
                                                    class="btn small"
                                                    disabled=move || busy.get()
                                                    on:click=move |_| {
                                                        act_while(busy, async move {
                                                            engine().dismiss_downgrade(peer).await
                                                        });
                                                    }
                                                >
                                                    "Dismiss warning"
                                                </button>
                                            }
                                        })}
                                    </div>
                                }
                            })}
                        </div>
                    }
                })
            }}
            <label>"Safety number"</label>
            // Twelve groups of five digits, four to a row, as Signal shows them.
            <div class="key safety">
                {safety_number(&me.key, &peer)
                    .as_bytes()
                    .chunks(5)
                    .map(|group| view! { <span>{String::from_utf8_lossy(group).into_owned()}</span> })
                    .collect_view()}
            </div>
            <label>"Their identity key"</label>
            <Copyable text=key_to_text(&peer) what="their key" />
            <label for="contact-name">"Their name, for you"</label>
            <input id="contact-name" autocomplete="off" bind:value=name />
            <div class="actions">
                <button
                    type="button"
                    class="btn danger"
                    disabled=move || busy.get()
                    on:click=delete
                >
                    {move || match (confirm_delete.get(), is_request()) {
                        (false, true) => "Delete request",
                        (false, false) => "Delete chat",
                        (true, _) => "Delete it and its history?",
                    }}
                </button>
                <button
                    type="button"
                    class="btn"
                    disabled=move || busy.get()
                    on:click=move |_| close_dialog()
                >
                    "Cancel"
                </button>
                <Show when=move || !(is_request() && is_quarantined())>
                    <button class="btn primary" type="submit" disabled=move || busy.get()>
                        {move || if is_request() { "Accept" } else { "Save" }}
                    </button>
                </Show>
            </div>
        </form>
    }
    .into_any()
}

/// The shelves of a chat's file browser, each holding files of some sorts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shelf {
    All,
    Media,
    Documents,
    Code,
    Archives,
    Other,
}

impl Shelf {
    const ALL: [Self; 6] = [
        Self::All,
        Self::Media,
        Self::Documents,
        Self::Code,
        Self::Archives,
        Self::Other,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Media => "Media",
            Self::Documents => "Documents",
            Self::Code => "Code",
            Self::Archives => "Archives",
            Self::Other => "Other",
        }
    }

    fn holds(self, sort: Sort) -> bool {
        match self {
            Self::All => true,
            Self::Media => matches!(sort, Sort::Image | Sort::Video | Sort::Audio),
            Self::Documents => sort == Sort::Document,
            Self::Code => sort == Sort::Code,
            Self::Archives => sort == Sort::Archive,
            Self::Other => matches!(sort, Sort::Other | Sort::Unknown),
        }
    }
}

/// The files of the chat with `peer`, on shelves by their sort, which their contents tell as
/// well as their names, and by month, newest first. Media shows as a grid, images as thumbnails;
/// the rest as a list. Each opens in the viewer.
#[component]
fn FileBrowser(peer: PublicKey) -> impl IntoView {
    let ui = ui();
    let label = ui
        .contact(&peer)
        .map(|contact| contact.label())
        .unwrap_or_default();
    let files = RwSignal::new(None::<Result<Vec<FileView>, String>>);
    spawn_local(async move {
        let listed = engine().files(peer).await;
        files.try_set(Some(listed));
    });
    // What was deleted from the server since, by history entry, which `files` does not say:
    // listed again, as the shelf changes, it stays deleted.
    let deleted = RwSignal::new(HashSet::<u64>::new());
    let shelf = RwSignal::new(Shelf::All);
    let count = move |of: Shelf| {
        files.with(|files| match files {
            Some(Ok(files)) => files.iter().filter(|file| of.holds(file.sort)).count(),
            _ => 0,
        })
    };
    let shelves = move || {
        Shelf::ALL
            .into_iter()
            .filter(|of| *of == Shelf::All || count(*of) > 0)
            .map(|of| {
                view! {
                    <button
                        type="button"
                        class="btn small toggle"
                        class:on=move || shelf.get() == of
                        on:click=move |_| shelf.set(of)
                    >
                        {format!("{} {}", of.label(), count(of))}
                    </button>
                }
            })
            .collect_view()
    };
    let from = label.clone();
    let months = move || {
        let shelf = shelf.get();
        let listed = files.get()?;
        let files = match listed {
            Ok(files) => files,
            Err(e) => return Some(view! { <p class="error">{e}</p> }.into_any()),
        };
        // Newest first, so that a month's files come together.
        let mut months: Vec<(String, Vec<FileView>)> = vec![];
        for file in files.into_iter().filter(|file| shelf.holds(file.sort)) {
            let month = month(file.at);
            match months.last_mut() {
                Some((last, files)) if *last == month => files.push(file),
                _ => months.push((month, vec![file])),
            }
        }
        if months.is_empty() {
            return Some(view! { <p class="empty">"No files here yet."</p> }.into_any());
        }
        let from = from.clone();
        Some(
            months
                .into_iter()
                .map(|(month, files)| {
                    let files = if shelf == Shelf::Media {
                        let tiles = files
                            .into_iter()
                            .map(|file| file_tile(peer, file, deleted))
                            .collect_view();
                        view! { <div class="file-grid">{tiles}</div> }.into_any()
                    } else {
                        let from = from.clone();
                        let rows = files
                            .into_iter()
                            .map(|file| file_row(peer, file, &from, deleted))
                            .collect_view();
                        view! { <div class="file-list">{rows}</div> }.into_any()
                    };
                    view! {
                        <section>
                            <h3>{month}</h3>
                            {files}
                        </section>
                    }
                })
                .collect_view()
                .into_any(),
        )
    };
    view! {
        <div class="files">
            <h2>"Files"</h2>
            <p>
                {format!(
                    "What you and {label} sent each other, newest first, sorted by what they are."
                )}
            </p>
            <p class="hint">
                "Small files (up to 1 MB) are stored locally in your vault and removed from the \
                 server upon delivery. Larger attachments stay on the server temporarily and can \
                 be deleted from the server by either peer."
            </p>
            <div class="shelves">{shelves}</div>
            <div class="file-months">
                {move || months().unwrap_or_else(|| view! { <p class="empty">"Reading the chat…"</p> }.into_any())}
            </div>
            <div class="actions">
                <button type="button" class="btn" on:click=move |_| close_dialog()>
                    "Close"
                </button>
            </div>
        </div>
    }
}

/// Compute the concise lifecycle status suffix for a file in `FileBrowser` (list row and tile).
fn file_status_suffix(
    is_local: bool,
    gone: bool,
    failed: bool,
    deletable: bool,
    outgoing: bool,
) -> Option<&'static str> {
    if is_local {
        Some(if failed { "not sent" } else { "stored locally" })
    } else if gone {
        Some("no longer on the server")
    } else if failed {
        Some("upload cancelled")
    } else if deletable {
        Some("on server")
    } else if outgoing {
        Some("waiting to upload")
    } else {
        None
    }
}

/// `file` as a tile of the file browser's grid of media: its preview, which for audio, which may
/// have no cover, goes with its name, plus gone/cancelled status and server-delete action matching
/// list rows.
fn file_tile(peer: PublicKey, file: FileView, deleted: RwSignal<HashSet<u64>>) -> AnyView {
    let Some(source) = Source::of(&file.body) else {
        return ().into_any();
    };
    let ui = ui();
    let shown = inline_media(&file.body).map(|(source, _)| source);
    let (index, listed_gone, failed, deletable, outgoing) = (
        file.index,
        file.gone,
        file.failed,
        file.deletable,
        file.outgoing,
    );
    let is_local = matches!(file.body, Body::File(_));
    let gone = move || {
        listed_gone
            || deleted.with(|deleted| deleted.contains(&index))
            || ui.gone.with(|gone| gone.contains(&(peer, index)))
    };
    let base_name = file.name.clone();
    let title = move || match file_status_suffix(is_local, gone(), failed, deletable, outgoing) {
        Some(status) => format!("{base_name} ({status})"),
        None => base_name.clone(),
    };
    let delete = match &file.body {
        Body::Remote(remote) if file.deletable => {
            let (remote_peer, pointer) = (remote.peer, remote.pointer.clone());
            Some(move || {
                (!gone()).then(|| {
                    view! { <DeleteFromServer peer=remote_peer index pointer=pointer.clone() deleted /> }
                })
            })
        }
        _ => None,
    };
    view! {
        <div class="tile" class:gone=move || gone() || failed>
            <button
                type="button"
                class="tile-open"
                title=title
                on:click=move |_| source.open()
            >
                <MediaThumb source=shown sort=file.sort />
                {(file.sort == Sort::Audio).then(|| view! { <span class="tile-name">{file.name}</span> })}
            </button>
            {move || {
                if gone() {
                    Some(
                        view! {
                            <span class="tile-status" title="No longer on the server">"Off server"</span>
                        }
                        .into_any(),
                    )
                } else if failed {
                    Some(
                        view! {
                            <span class="tile-status" title="Upload cancelled or failed">
                                {if is_local { "Not sent" } else { "Cancelled" }}
                            </span>
                        }
                        .into_any(),
                    )
                } else {
                    None
                }
            }}
            {delete}
        </div>
    }
    .into_any()
}

/// `file` as a row of the file browser's list: its extension, name, size and day, and who sent
/// it, the peer being `from`; whether it is stored locally or on the server (or gone/cancelled).
fn file_row(
    peer: PublicKey,
    file: FileView,
    from: &str,
    deleted: RwSignal<HashSet<u64>>,
) -> AnyView {
    let Some(source) = Source::of(&file.body) else {
        return ().into_any();
    };
    let ui = ui();
    let sender = if file.outgoing {
        "sent by you".to_string()
    } else {
        format!("from {from}")
    };
    let (index, listed_gone, failed, deletable, outgoing) = (
        file.index,
        file.gone,
        file.failed,
        file.deletable,
        file.outgoing,
    );
    let is_local = matches!(file.body, Body::File(_));
    let gone = move || {
        listed_gone
            || deleted.with(|deleted| deleted.contains(&index))
            || ui.gone.with(|gone| gone.contains(&(peer, index)))
    };
    let details = format!("{} · {} · {sender}", size_u64(file.size), day(file.at));
    let details = move || match file_status_suffix(is_local, gone(), failed, deletable, outgoing) {
        Some(status) => format!("{details} · {status}"),
        None => details.clone(),
    };
    // Media shows its preview, the rest its extension.
    let mark = match file.sort {
        sort @ (Sort::Image | Sort::Video | Sort::Audio) => {
            let shown = inline_media(&file.body).map(|(source, _)| source);
            view! {
                <span class="row-preview">
                    <MediaThumb source=shown sort />
                </span>
            }
            .into_any()
        }
        _ => view! { <span class="file-icon">{extension(&file.name)}</span> }.into_any(),
    };
    let title = file.name.clone();
    // An attachment on the server, sent or received, which either peer can delete, until it is.
    let delete = match &file.body {
        Body::Remote(remote) if file.deletable => {
            let (peer, pointer) = (remote.peer, remote.pointer.clone());
            Some(move || {
                (!gone()).then(|| {
                    view! { <DeleteFromServer peer index pointer=pointer.clone() deleted /> }
                })
            })
        }
        _ => None,
    };
    view! {
        <div class="file-entry">
            <button class="file-row" title=title on:click=move |_| source.open()>
                {mark}
                <span>
                    <strong>{file.name}</strong>
                    <span>{details}</span>
                </span>
            </button>
            {delete}
        </div>
    }
    .into_any()
}

/// How long a button that asks to be pressed again, to be sure, waits for it.
const ASKED_SHOWN: Duration = Duration::from_secs(6);

/// Deletes the attachment `pointer`, of the history entry `index` of the chat with `peer`, sent
/// or received, from the server, once pressed twice, which a notice asks for, as the button is
/// only an icon: neither of them can download it any more, though what they downloaded stays.
/// Its upload, if still going, stops. Once deleted, it is among `deleted`; the entry keeps it.
#[component]
fn DeleteFromServer(
    peer: PublicKey,
    index: u64,
    pointer: content::AttachmentPointer,
    deleted: RwSignal<HashSet<u64>>,
) -> impl IntoView {
    #[derive(Clone, Copy, PartialEq)]
    enum Step {
        Offered,
        Asked,
        Deleting,
    }
    let step = RwSignal::new(Step::Offered);
    let label = ui()
        .contact(&peer)
        .map(|contact| contact.label())
        .unwrap_or_default();
    let what = move || match step.get() {
        Step::Offered => "Delete from the server".to_string(),
        Step::Asked => format!("Delete it from the server, for you and {label}?"),
        Step::Deleting => "Deleting it from the server…".to_string(),
    };
    let click = move |_| match step.get_untracked() {
        Step::Offered => {
            step.set(Step::Asked);
            ui().notify(format!(
                "Press again to delete {} from the server: neither of you can download it any \
                 more; what you downloaded stays.",
                pointer.name
            ));
            // Not pressed again meanwhile, it asks no more.
            set_timeout(
                move || {
                    if step.try_get_untracked() == Some(Step::Asked) {
                        step.set(Step::Offered);
                    }
                },
                ASKED_SHOWN,
            );
        }
        Step::Asked => {
            step.set(Step::Deleting);
            let pointer = pointer.clone();
            spawn_local(async move {
                match engine().delete_attachment(peer, index, &pointer).await {
                    Ok(()) => {
                        deleted.try_update(|deleted| deleted.insert(index));
                        ui().notify(format!("{} is deleted from the server", pointer.name));
                    }
                    Err(e) => {
                        step.try_set(Step::Offered);
                        ui().notify(e);
                    }
                }
            });
        }
        Step::Deleting => {}
    };
    view! {
        <button
            type="button"
            class="btn icon small quiet delete-remote"
            class:asked=move || step.get() == Step::Asked
            title=what.clone()
            aria-label=what
            disabled=move || step.get() == Step::Deleting
            on:click=click
        >
            {icon(Icon::Delete)}
        </button>
    }
}

/// A blob URL of this origin for `data`, typed `mime`.
fn blob_url(data: &[u8], mime: &str) -> Option<String> {
    let parts = js_sys::Array::of1(&Uint8Array::from(data));
    let options = BlobPropertyBag::new();
    options.set_type(mime);
    Blob::new_with_u8_array_sequence_and_options(&parts, &options)
        .and_then(|blob| Url::create_object_url_with_blob(&blob))
        .ok()
}

/// A URL that shows the image `data`, of the MIME type `mime`: a blob URL of this origin, but for
/// SVG, which would open from one as a page of this origin, running its scripts; a `data:` URL
/// opens as no page.
fn image_url(data: &[u8], mime: &str) -> Option<String> {
    if mime == "image/svg+xml" {
        Some(format!(
            "data:{mime};base64,{}",
            BASE64_STANDARD.encode(data)
        ))
    } else {
        blob_url(data, mime)
    }
}

#[component]
fn Viewer() -> impl IntoView {
    let ui = ui();
    let dialog = NodeRef::<html::Dialog>::new();
    // The blob URL on screen, revoked once another file shows or the viewer closes.
    let shown_url = StoredValue::new(None::<String>);
    // Whether it waits for an attachment, which shows how far it got until it opens.
    let waiting = Memo::new(move |_| ui.opening.with(Option::is_some));
    // What it shows, and whether that is text, which can be searched.
    let shown_content = NodeRef::<html::Div>::new();
    let searchable = RwSignal::new(false);
    // The streamed attachments being downloaded whole, by ID, which their Download waits for.
    let downloading = RwSignal::new(HashSet::<Vec<u8>>::new());
    let fetching_whole = move || {
        ui.streaming.with(|streamed| {
            streamed.as_ref().is_some_and(|streamed| {
                downloading.with(|downloading| downloading.contains(&streamed.remote.pointer.id))
            })
        })
    };
    let close = move || {
        ui.viewer.set(None);
        ui.opening.set(None);
        ui.streaming.set(None);
    };
    // A stream plays until the viewer shows something else, or closes.
    Effect::new(move || {
        let other = ui.viewer.with(Option::is_some) || ui.opening.with(Option::is_some);
        if other && ui.streaming.with_untracked(Option::is_some) {
            ui.streaming.set(None);
        }
    });
    Effect::new(move |played: Option<Option<String>>| {
        let playing = ui
            .streaming
            .with(|streamed| streamed.as_ref().map(|streamed| streamed.url.clone()));
        if let Some(Some(played)) = played
            && playing.as_ref() != Some(&played)
        {
            release(&played);
        }
        playing
    });
    Effect::new(move || {
        let open =
            ui.viewer.with(Option::is_some) || waiting.get() || ui.streaming.with(Option::is_some);
        if let Some(dialog) = dialog.get() {
            if open && !dialog.open() {
                let _ = dialog.show_modal();
            } else if !open && dialog.open() {
                dialog.close();
            }
        }
    });
    let content = move || {
        if let Some(url) = shown_url.get_value() {
            let _ = Url::revoke_object_url(&url);
            shown_url.set_value(None);
        }
        let Some(attachment) = ui.viewer.get() else {
            searchable.set(false);
            if let Some(streamed) = ui.streaming.get() {
                return Some(view! { <StreamedView streamed /> }.into_any());
            }
            return waiting.get().then(opening_view);
        };
        let kind = preview::kind(&attachment.name, &attachment.mime, &attachment.data);
        searchable.set(matches!(
            kind,
            Kind::Code { .. }
                | Kind::Markdown { .. }
                | Kind::Diff(_)
                | Kind::Table(_)
                | Kind::Archive(_)
                | Kind::Cards(_)
        ));
        let shown = |url: Option<String>| {
            shown_url.set_value(url.clone().filter(|url| url.starts_with("blob:")));
            url
        };
        Some(match kind {
            Kind::Image(mime) => match shown(image_url(&attachment.data, mime)) {
                Some(url) => view! {
                    <div class="media">
                        <img src=url alt=attachment.name.clone() />
                    </div>
                }
                .into_any(),
                None => no_preview(),
            },
            Kind::Video(mime) => match shown(blob_url(&attachment.data, mime)) {
                Some(url) => view! { <VideoView url /> }.into_any(),
                None => no_preview(),
            },
            Kind::Audio(mime) => match shown(blob_url(&attachment.data, mime)) {
                Some(url) => view! {
                    <AudioView url name=attachment.name.clone() data=attachment.data.clone() />
                }
                .into_any(),
                None => no_preview(),
            },
            Kind::Pdf => view! { <PdfView data=attachment.data.clone() /> }.into_any(),
            Kind::Markdown { html, source } => view! { <MarkdownView html source /> }.into_any(),
            Kind::Code { text, language } => view! {
                <Enhanced>
                    <pre class="code">
                        <code data-lang=language>{text}</code>
                    </pre>
                </Enhanced>
            }
            .into_any(),
            Kind::Table(table) => table_view(table),
            Kind::Archive(listing) => archive_view(listing),
            Kind::Cards(cards) => cards_view(cards),
            Kind::Diff(lines) => diff_view(lines),
            Kind::None => no_preview(),
        })
    };
    let title = move || {
        ui.viewer
            .with(|attachment| {
                attachment
                    .as_ref()
                    .map(|a| format!("{} · {}", a.name, size(a.data.len())))
            })
            .or_else(|| {
                ui.streaming.with(|streamed| {
                    streamed.as_ref().map(|streamed| {
                        let pointer = &streamed.remote.pointer;
                        format!("{} · {}", pointer.name, size_u64(pointer.size))
                    })
                })
            })
            .or_else(|| {
                ui.opening.with(|opening| {
                    opening
                        .as_ref()
                        .map(|o| format!("{} · {}", o.name, size_u64(o.size)))
                })
            })
            .unwrap_or_default()
    };
    view! {
        <dialog class="viewer" node_ref=dialog on:close=move |_| close()>
            <div class="viewer-bar">
                <span>{title}</span>
                <div>
                    <Show when=move || searchable.get()>
                        <Search content=shown_content />
                    </Show>
                    <Show when=move || {
                        ui.viewer.with(Option::is_some) || ui.streaming.with(Option::is_some)
                    }>
                        <button
                            class="btn icon small"
                            title="Download"
                            aria-label="Download"
                            disabled=fetching_whole
                            on:click=move |_| {
                                if let Some(attachment) = ui.viewer.get_untracked() {
                                    download(&attachment);
                                } else if let Some(streamed) = ui.streaming.get_untracked() {
                                    download_whole(streamed.remote, downloading);
                                }
                            }
                        >
                            {icon(Icon::Download)}
                        </button>
                    </Show>
                    <button
                        class="btn icon small"
                        title="Close"
                        aria-label="Close"
                        on:click=move |_| close()
                    >
                        {icon(Icon::Close)}
                    </button>
                </div>
            </div>
            <div class="viewer-content" node_ref=shown_content>{content}</div>
            <Toast />
        </dialog>
    }
}

/// A video shown in the viewer, stopping playback via its own `NodeRef` on cleanup.
#[component]
fn VideoView(url: String) -> impl IntoView {
    let video_ref = NodeRef::<html::Video>::new();
    on_cleanup(move || {
        if let Some(video) = video_ref.get_untracked() {
            stop_media(&video);
        }
    });
    view! {
        <div class="media">
            <video node_ref=video_ref src=url controls></video>
        </div>
    }
}

/// A video or audio attachment playing as it is fetched, see [`Streamed`]. One that turns out
/// not to play, e.g. as its name said video but no browser plays it, is fetched whole, to show
/// as its bytes say, as one that does not stream.
#[component]
fn StreamedView(streamed: Streamed) -> impl IntoView {
    let video_ref = NodeRef::<html::Video>::new();
    on_cleanup(move || {
        if let Some(video) = video_ref.get_untracked() {
            stop_media(&video);
        }
    });
    let unplayable = {
        let (url, remote) = (streamed.url.clone(), streamed.remote.clone());
        move |_: ev::ErrorEvent| {
            // Unless the viewer went on meanwhile.
            let shown = ui()
                .streaming
                .with_untracked(|shown| shown.as_ref().is_some_and(|shown| shown.url == url));
            if shown {
                let remote = remote.clone();
                act(async move {
                    engine()
                        .open_attachment(remote.peer, remote.index, remote.pointer, remote.clock)
                        .await
                });
            }
        }
    };
    if streamed.video {
        view! {
            <div class="media">
                <video node_ref=video_ref src=streamed.url controls on:error=unplayable></video>
            </div>
        }
        .into_any()
    } else {
        let name = streamed.remote.pointer.name;
        let on_error = UnsyncCallback::new(unplayable);
        view! { <AudioView url=streamed.url name on_error /> }.into_any()
    }
}

/// Download the attachment `remote` whole, as a stream plays only what it needs of it, unless
/// it is among those `downloading` already, as it is meanwhile.
fn download_whole(remote: RemoteFile, downloading: RwSignal<HashSet<Vec<u8>>>) {
    let id = remote.pointer.id.clone();
    if downloading.with_untracked(|downloading| downloading.contains(&id)) {
        return;
    }
    downloading.update(|downloading| {
        downloading.insert(id.clone());
    });
    let ui = ui();
    act(async move {
        ui.notify(format!("Downloading {}…", remote.pointer.name));
        let fetched = engine()
            .media(
                remote.peer,
                remote.index,
                remote.pointer,
                remote.clock,
                &|| true,
            )
            .await;
        downloading.update(|downloading| {
            downloading.remove(&id);
        });
        if let Some(attachment) = fetched? {
            download(&attachment);
        }
        Ok(())
    });
}

/// Audio, named `name`, playing from `url` at once, and, once a worker read them from `data`,
/// what its tags say of it, if anything: its cover, title, artist, album and year. Without
/// `data`, as it plays as it is fetched, its tags are read from the start of its stream, where
/// they are in most files.
#[component]
fn AudioView(
    url: String,
    name: String,
    #[prop(optional)] data: Option<Arc<Vec<u8>>>,
    /// What to do if it does not play.
    #[prop(optional)]
    on_error: Option<UnsyncCallback<ev::ErrorEvent>>,
) -> impl IntoView {
    let audio_ref = NodeRef::<html::Audio>::new();
    on_cleanup(move || {
        if let Some(audio) = audio_ref.get_untracked() {
            stop_media(&audio);
        }
    });
    let tags = RwSignal::new(None::<preview::Tags>);
    let stream = url.clone();
    spawn_local(async move {
        let found = match data {
            Some(data) => workers::audio_tags(&data).await,
            None => match engine().stream_head(&stream).await {
                Some(head) => workers::audio_tags(&head).await,
                None => Ok(None),
            },
        };
        if let Ok(Some(found)) = found {
            tags.try_set(Some(found));
        }
    });
    let shown = move || {
        let found = tags.get()?;
        // A data: URL, which needs no revoking; the worker made sure it is an image.
        let cover = found
            .cover
            .map(|(mime, data)| format!("data:{mime};base64,{}", BASE64_STANDARD.encode(data)));
        let album = match (found.album, found.year) {
            (Some(album), Some(year)) => Some(format!("{album} · {year}")),
            (album, year) => album.or(year.map(|year| year.to_string())),
        };
        let title = found.title.unwrap_or_else(|| name.clone());
        Some(view! {
            {cover.map(|cover| view! { <img class="cover" src=cover alt="cover" /> })}
            <div class="track-text">
                <strong>{title}</strong>
                {found.artist.map(|artist| view! { <span class="artist">{artist}</span> })}
                {album.map(|album| view! { <span>{album}</span> })}
            </div>
        })
    };
    view! {
        <div class="media">
            <div class="track">
                {shown}
                <audio
                    node_ref=audio_ref
                    src=url
                    controls
                    on:error=move |event| {
                        if let Some(on_error) = on_error {
                            on_error.run(event);
                        }
                    }
                ></audio>
            </div>
        </div>
    }
}

/// How far opening an attachment got: how much of it is decrypted, on a native `<progress>` bar,
/// and whether it waits for its sender to upload the rest.
fn opening_view() -> AnyView {
    let ui = ui();
    let fraction = move || {
        ui.opening.with(|opening| {
            opening.as_ref().map_or(0.0, |opening| match opening.size {
                0 => 1.0,
                total => opening.done as f64 / total as f64,
            })
        })
    };
    let note = move || {
        ui.opening.with(|opening| {
            opening.as_ref().map_or_else(String::new, |opening| {
                let done = format!("{} of {}", size_u64(opening.done), size_u64(opening.size));
                if opening.waiting {
                    format!("{done}, waiting for its sender to upload the rest")
                } else {
                    done
                }
            })
        })
    };
    view! {
        <div class="media">
            <div class="opening">
                <div class="opening-bar">
                    <progress class="bar" max="1" prop:value=fraction></progress>
                </div>
                <span class="opening-note">{note}</span>
            </div>
        </div>
    }
    .into_any()
}

fn no_preview() -> AnyView {
    view! {
        <div class="media">
            <p class="no-preview">"No preview for this kind of file. Download it to open it."</p>
        </div>
    }
    .into_any()
}

/// What it shows, once shown, with its code blocks highlighted and its diagrams drawn.
#[component]
fn Enhanced(children: Children) -> impl IntoView {
    let node = NodeRef::<html::Div>::new();
    Effect::new(move || {
        if let Some(element) = node.get() {
            enhance(&element);
        }
    });
    view! {
        <div class="enhanced" node_ref=node>
            {children()}
        </div>
    }
}

/// The elements in `element` that `selector` selects.
fn select(element: &web_sys::Element, selector: &str) -> Vec<web_sys::Element> {
    let Ok(nodes) = element.query_selector_all(selector) else {
        return Vec::new();
    };
    (0..nodes.length())
        .filter_map(|i| nodes.item(i)?.dyn_into().ok())
        .collect()
}

/// Highlight `pre > code[data-lang]` blocks and draw Mermaid diagrams as images. Blocks that fail
/// stay as they are, saying why in `data-error`. External links already receive
/// `target="_blank" rel="noopener noreferrer"` during sanitization in `preview::sanitize_html`.
fn enhance(element: &web_sys::Element) {
    for code in select(element, "pre > code[data-lang]") {
        spawn_local(async move {
            let info = code.get_attribute("data-lang").unwrap_or_default();
            let text = code.text_content().unwrap_or_default();
            let shown = if info.eq_ignore_ascii_case("mermaid") {
                workers::diagram(&text).await.and_then(|svg| {
                    if !code.is_connected() {
                        return Ok(());
                    }
                    // A data: URL, not a blob: one of this origin, which would open as a page.
                    let image = document().create_element("img").map_err(js_error)?;
                    image.set_class_name("diagram");
                    let src = format!("data:image/svg+xml;base64,{}", BASE64_STANDARD.encode(svg));
                    let _ = image.set_attribute("alt", "diagram");
                    let _ = image.set_attribute("src", &src);
                    if let Some(block) = code.parent_element() {
                        block.replace_with_with_node_1(&image).map_err(js_error)?;
                    }
                    Ok(())
                })
            } else if let Some(language) = language::of_block(&info) {
                workers::highlight(language, &text).await.map(|html| {
                    if code.is_connected() {
                        code.set_inner_html(&html);
                    }
                })
            } else {
                Ok(())
            };
            if let (Err(e), true, Some(block)) = (shown, code.is_connected(), code.parent_element()) {
                let _ = block.set_attribute("data-error", &e);
            }
        });
    }
}

/// A Markdown file, as a document, or as reveal.js slides.
#[component]
fn MarkdownView(html: String, source: String) -> impl IntoView {
    let as_slides = RwSignal::new(false);
    view! {
        <div class="preview-bar">
            <button
                class="btn icon small"
                title=move || if as_slides.get() { "View as a document" } else { "View as slides" }
                aria-label=move || if as_slides.get() { "View as a document" } else { "View as slides" }
                on:click=move |_| as_slides.update(|slides| *slides = !*slides)
            >
                {move || icon(if as_slides.get() { Icon::Document } else { Icon::Slides })}
            </button>
        </div>
        {move || {
            if as_slides.get() {
                view! { <Slides source=source.clone() /> }.into_any()
            } else {
                let html = html.clone();
                view! {
                    <Enhanced>
                        <div class="markdown" inner_html=html></div>
                    </Enhanced>
                }
                    .into_any()
            }
        }}
    }
}

/// The size reveal.js lays a slide out at, which full screen scales to fill the screen.
const SLIDE_SIZE: (f64, f64) = (960.0, 700.0);
/// The height the slides' bar takes from the screen.
const SLIDES_BAR: f64 = 64.0;

/// Whether the browser shows `.slides` full screen.
fn slides_full_screen() -> bool {
    document()
        .fullscreen_element()
        .is_some_and(|element| element.matches(".slides").unwrap_or(false))
}

/// reveal.js slides: the arrow keys go to the next column, left and right, and to the next slide
/// in it, up and down. F shows them full screen, the browser's, or, where a page may not have it,
/// as on iPhones, the window's, scaled as reveal.js scales them; F or Esc leaves it.
#[component]
fn Slides(source: String) -> impl IntoView {
    let deck = StoredValue::new(preview::slides(&source));
    let position = RwSignal::new((0, 0));
    let node = NodeRef::<html::Div>::new();
    let full = RwSignal::new(false);
    let toggle = move || {
        let document = document();
        if slides_full_screen() {
            document.exit_fullscreen();
        } else if full.get_untracked() {
            full.set(false);
        } else if document.fullscreen_enabled()
            && let Some(slides) = node.get_untracked()
            && slides.request_fullscreen().is_ok()
        {
            // Full once the browser says so.
        } else {
            full.set(true);
        }
    };
    // The browser's full screen also ends as it decides, e.g. on Esc.
    let changes = window_event_listener_untyped("fullscreenchange", move |_| {
        full.set(slides_full_screen());
    });
    // Scaled to fit the screen declaratively via `--scale` CSS custom property, as it changes.
    let scale = RwSignal::new(None::<String>);
    let fit = move || {
        if full.get_untracked() {
            let window = window();
            let size = |size: Result<JsValue, JsValue>| size.ok()?.as_f64();
            let (Some(width), Some(height)) =
                (size(window.inner_width()), size(window.inner_height()))
            else {
                return;
            };
            let ratio = (width / SLIDE_SIZE.0).min((height - SLIDES_BAR) / SLIDE_SIZE.1);
            scale.set(Some(ratio.max(0.1).to_string()));
        } else {
            scale.set(None);
        }
    };
    Effect::new(move || {
        full.track();
        fit();
    });
    let resizes = window_event_listener(ev::resize, move |_| fit());
    let go = move |right: isize, down: isize| {
        position.update(|(column, row)| {
            deck.with_value(|deck| {
                let last = |len: usize| len.saturating_sub(1) as isize;
                if right != 0 {
                    let next = (*column as isize + right).clamp(0, last(deck.len())) as usize;
                    if next != *column {
                        (*column, *row) = (next, 0);
                    }
                } else {
                    *row = (*row as isize + down).clamp(0, last(deck[*column].len())) as usize;
                }
            })
        })
    };
    let keys = window_event_listener(ev::keydown, move |event| {
        // Typing, e.g. in the viewer's search box, is not for the slides.
        let typing = event
            .target()
            .and_then(|target| target.dyn_into::<web_sys::HtmlElement>().ok())
            .is_some_and(|element| {
                element.is_content_editable()
                    || matches!(element.tag_name().as_str(), "INPUT" | "TEXTAREA")
            });
        if typing {
            return;
        }
        let modified = event.ctrl_key() || event.meta_key() || event.alt_key();
        let (right, down) = match event.key().as_str() {
            "ArrowRight" | "PageDown" => (1, 0),
            "ArrowLeft" | "PageUp" => (-1, 0),
            "ArrowDown" => (0, 1),
            "ArrowUp" => (0, -1),
            "f" | "F" if !modified => {
                event.prevent_default();
                toggle();
                return;
            }
            // Leaving full screen, not the viewer, which Esc would close.
            "Escape" if full.get_untracked() => {
                event.prevent_default();
                toggle();
                return;
            }
            _ => return,
        };
        event.prevent_default();
        go(right, down);
    });
    on_cleanup(move || {
        keys.remove();
        changes.remove();
        resizes.remove();
        if slides_full_screen() {
            document().exit_fullscreen();
        }
    });
    // Whether `go(right, down)` goes anywhere.
    let can = move |right: isize, down: isize| {
        let (column, row) = position.get();
        deck.with_value(|deck| match (right, down) {
            (-1, _) => column > 0,
            (1, _) => column + 1 < deck.len(),
            (_, -1) => row > 0,
            _ => row + 1 < deck[column].len(),
        })
    };
    let slide = move || {
        let (column, row) = position.get();
        deck.with_value(|deck| deck[column][row].clone())
    };
    let counter = move || {
        let (column, row) = position.get();
        deck.with_value(|deck| match deck[column].len() {
            1 => format!("{} / {}", column + 1, deck.len()),
            rows => format!("{} / {} · {} / {rows}", column + 1, deck.len(), row + 1),
        })
    };
    view! {
        <div
            class="slides"
            class:full=move || full.get()
            style:--scale=move || scale.get()
            node_ref=node
        >
            {move || {
                // Read here, where it is tracked: a component's children are built untracked.
                let html = slide();
                view! {
                    <Enhanced>
                        <div class="slide markdown" inner_html=html></div>
                    </Enhanced>
                }
            }}
            <div class="slides-bar">
                <button
                    class="btn icon small"
                    title="Previous (←)"
                    aria-label="Previous"
                    disabled=move || !can(-1, 0)
                    on:click=move |_| go(-1, 0)
                >
                    {icon(Icon::Previous)}
                </button>
                <button
                    class="btn icon small"
                    title="Up (↑)"
                    aria-label="Up"
                    disabled=move || !can(0, -1)
                    on:click=move |_| go(0, -1)
                >
                    {icon(Icon::Up)}
                </button>
                <span>{counter}</span>
                <button
                    class="btn icon small"
                    title="Down (↓)"
                    aria-label="Down"
                    disabled=move || !can(0, 1)
                    on:click=move |_| go(0, 1)
                >
                    {icon(Icon::Down)}
                </button>
                <button
                    class="btn icon small"
                    title="Next (→)"
                    aria-label="Next"
                    disabled=move || !can(1, 0)
                    on:click=move |_| go(1, 0)
                >
                    {icon(Icon::Next)}
                </button>
                <button
                    class="btn icon small"
                    title=move || if full.get() { "Leave full screen (F)" } else { "Full screen (F)" }
                    aria-label=move || if full.get() { "Leave full screen" } else { "Full screen" }
                    on:click=move |_| toggle()
                >
                    {move || icon(if full.get() { Icon::LeaveFullScreen } else { Icon::FullScreen })}
                </button>
            </div>
        </div>
    }
}

/// A PDF, its pages declared via `<For>` and drawn by a worker once each canvas scrolls into view.
#[component]
fn PdfView(data: Arc<Vec<u8>>) -> impl IntoView {
    let container = NodeRef::<html::Div>::new();
    let pdf_handle = StoredValue::new_local(None::<workers::Pdf>);
    let pages = RwSignal::new(Vec::<(usize, f64, f64)>::new());
    let failed = RwSignal::new(None::<String>);
    let here = StoredValue::new(());
    spawn_local(async move {
        match workers::open_pdf(&data).await {
            Ok((pdf, dims)) => {
                if here.try_get_value().is_none() {
                    workers::close_pdf(pdf);
                    return;
                }
                if let Some(Some(previous)) = pdf_handle.try_set_value(Some(pdf)) {
                    workers::close_pdf(previous);
                }
                let _ = pages.try_set(
                    dims.into_iter()
                        .enumerate()
                        .map(|(index, (width, height))| (index, width, height))
                        .collect(),
                );
            }
            Err(e) => {
                let _ = failed.try_set(Some(e));
            }
        }
    });
    on_cleanup(move || {
        if let Some(Some(pdf)) = pdf_handle.try_update_value(Option::take) {
            workers::close_pdf(pdf);
        }
    });
    view! {
        <div class="pdf" node_ref=container>
            <For
                each=move || pages.get()
                key=|(index, _, _)| *index
                children=move |(index, width, height)| {
                    let pdf = pdf_handle.get_value();
                    view! { <PdfPage pdf index width height container /> }
                }
            />
        </div>
        {move || {
            failed.get().map(|e| view! { <p class="no-preview">{format!("The PDF does not show: {e}")}</p> })
        }}
    }
}

/// One declaratively mounted canvas page of a PDF, observed with `IntersectionObserver` via its
/// `NodeRef` so it draws only once about to scroll into view.
#[component]
fn PdfPage(
    pdf: Option<workers::Pdf>,
    index: usize,
    width: f64,
    height: f64,
    container: NodeRef<html::Div>,
) -> impl IntoView {
    let canvas = NodeRef::<html::Canvas>::new();
    let drawn = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let watching = StoredValue::new_local(
        None::<(
            IntersectionObserver,
            Closure<dyn FnMut(js_sys::Array, IntersectionObserver)>,
        )>,
    );
    Effect::new(move || {
        let (Some(pdf), Some(canvas_el)) = (pdf, canvas.get()) else {
            return;
        };
        let target: HtmlCanvasElement = canvas_el;
        let target_for_cb = target.clone();
        let draw = Closure::<dyn FnMut(js_sys::Array, IntersectionObserver)>::new(
            move |entries: js_sys::Array, observer: IntersectionObserver| {
                let visible = entries.iter().any(|entry| {
                    entry
                        .unchecked_into::<IntersectionObserverEntry>()
                        .is_intersecting()
                });
                if !visible {
                    return;
                }
                observer.disconnect();
                let canvas_el = target_for_cb.clone();
                spawn_local(async move {
                    match draw_page(pdf, index, &canvas_el).await {
                        Ok(()) => {
                            let _ = drawn.try_set(true);
                        }
                        Err(e) => {
                            let _ = error.try_set(Some(e));
                        }
                    }
                });
            },
        );
        let options = IntersectionObserverInit::new();
        let root = container
            .get_untracked()
            .and_then(|c| c.closest(".viewer-content").ok().flatten());
        options.set_root(root.as_ref());
        options.set_root_margin("200px");
        let Ok(observer) =
            IntersectionObserver::new_with_options(draw.as_ref().unchecked_ref(), &options)
        else {
            return;
        };
        observer.observe(&target);
        watching.set_value(Some((observer, draw)));
    });
    on_cleanup(move || {
        if let Some(Some((observer, _))) = watching.try_update_value(Option::take) {
            observer.disconnect();
        }
    });
    let aspect = format!("{width} / {height}");
    view! {
        <canvas
            class="pdf-page"
            node_ref=canvas
            style:aspect-ratio=aspect
            data-page=index.to_string()
            data-drawn=move || drawn.get().then_some("yes")
            data-error=move || error.get()
        ></canvas>
    }
}

/// Draw page `index` of `pdf` onto `canvas`, as sharp as the screen shows it, at most twice as
/// sharp as CSS pixels.
async fn draw_page(
    pdf: workers::Pdf,
    index: usize,
    canvas: &HtmlCanvasElement,
) -> Result<(), String> {
    let ratio = web_sys::window()
        .map_or(1.0, |window| window.device_pixel_ratio())
        .min(2.0);
    let width = (f64::from(canvas.client_width()) * ratio).round().max(1.0) as u32;
    let image = workers::render_pdf(pdf, index, width).await?;
    if !canvas.is_connected() {
        return Ok(());
    }
    canvas.set_width(image.width());
    canvas.set_height(image.height());
    let context: CanvasRenderingContext2d = canvas
        .get_context("2d")
        .map_err(js_error)?
        .ok_or("no 2D context")?
        .unchecked_into();
    context.put_image_data(&image, 0.0, 0.0).map_err(js_error)?;
    Ok(())
}

fn table_view(table: preview::Table) -> AnyView {
    let notice = table.notice();
    let mut rows = table.rows.into_iter();
    let header = rows.next().unwrap_or_default();
    view! {
        <div class="table-preview">
            <table>
                <thead>
                    <tr>{header.into_iter().map(|cell| view! { <th>{cell}</th> }).collect_view()}</tr>
                </thead>
                <tbody>
                    {rows
                        .map(|row| {
                            view! {
                                <tr>{row.into_iter().map(|cell| view! { <td>{cell}</td> }).collect_view()}</tr>
                            }
                        })
                        .collect_view()}
                </tbody>
            </table>
            {notice.map(|notice| {
                view! {
                    <p class="preview-note">{notice}</p>
                }
            })}
        </div>
    }
    .into_any()
}

fn archive_view(listing: preview::Listing) -> AnyView {
    let files = listing
        .entries
        .iter()
        .filter(|entry| !entry.directory)
        .count();
    let total: u64 = listing
        .entries
        .iter()
        .fold(0u64, |acc, entry| acc.saturating_add(entry.size));
    let note = if listing.complete {
        format!("{files} files, {} unpacked", size_u64(total))
    } else {
        format!(
            "The first {files} files, {} unpacked; listing the rest would take too long, or it is damaged.",
            size_u64(total)
        )
    };
    view! {
        <div class="archive">
            <p class="preview-note">{note}</p>
            <ul>
                {listing
                    .entries
                    .into_iter()
                    .map(|entry| {
                        let length = if entry.directory { String::new() } else { size_u64(entry.size) };
                        view! {
                            <li class:directory=entry.directory>
                                <span>{entry.path}</span>
                                <span>{length}</span>
                            </li>
                        }
                    })
                    .collect_view()}
            </ul>
        </div>
    }
    .into_any()
}

fn cards_view(cards: Vec<preview::Card>) -> AnyView {
    if cards.is_empty() {
        return no_preview();
    }
    view! {
        <div class="cards">
            {cards
                .into_iter()
                .map(|card| {
                    let title = if card.title.is_empty() { "Untitled".to_string() } else { card.title };
                    view! {
                        <section class="card">
                            <h3>{title}</h3>
                            <dl>
                                {card
                                    .fields
                                    .into_iter()
                                    .map(|(label, value)| view! { <dt>{label}</dt><dd>{value}</dd> })
                                    .collect_view()}
                            </dl>
                        </section>
                    }
                })
                .collect_view()}
        </div>
    }
    .into_any()
}

fn diff_view(lines: Vec<(DiffLine, String)>) -> AnyView {
    view! {
        <pre class="code diff">
            {lines
                .into_iter()
                .map(|(kind, line)| {
                    let class = match kind {
                        DiffLine::File => "diff-file",
                        DiffLine::Hunk => "diff-hunk",
                        DiffLine::Added => "diff-added",
                        DiffLine::Removed => "diff-removed",
                        DiffLine::Context => "diff-context",
                    };
                    view! { <span class=class>{line}</span> }
                })
                .collect_view()}
        </pre>
    }
    .into_any()
}

/// Save `attachment` as a file. Its blob is typeless, so the browser saves it rather than
/// opening it in this origin.
fn download(attachment: &Attachment) {
    let Some(url) = blob_url(&attachment.data, "application/octet-stream") else {
        return;
    };
    if let Ok(anchor) = document().create_element("a") {
        let anchor: HtmlAnchorElement = anchor.unchecked_into();
        anchor.set_href(&url);
        anchor.set_download(&attachment.name);
        anchor.click();
    }
    set_timeout(
        move || {
            let _ = Url::revoke_object_url(&url);
        },
        Duration::from_secs(60),
    );
}

/// The notice. An open modal dialog covers the page, above any z-index, and makes it inert, so
/// each dialog has a notice of its own, in the same place: the one seen and read out while the
/// dialog is open.
#[component]
fn Toast() -> impl IntoView {
    let ui = ui();
    view! {
        <div class="toast" role="status" class:visible=move || ui.notice.with(Option::is_some)>
            {move || ui.notice.get().map(|(_, text)| text).unwrap_or_default()}
        </div>
    }
}

/// Whether a drag event carries files (ignoring text selections or dragged page elements).
fn drag_has_files(event: &ev::DragEvent) -> bool {
    event
        .data_transfer()
        .is_some_and(|transfer| transfer.types().includes(&JsValue::from_str("Files"), 0))
}

/// Files dropped anywhere on the page go to the open chat (only when unlocked with no modal or
/// viewer open).
#[component]
fn Dropzone() -> impl IntoView {
    let ui = ui();
    // dragenter and dragleave come for every element passed over; the count says when the
    // drag leaves the page.
    let depth = RwSignal::new(0i32);
    let accepts = move |event: &ev::DragEvent| {
        drag_has_files(event)
            && ui.phase.get_untracked() == Phase::Unlocked
            && ui.dialog.with_untracked(Option::is_none)
            && ui.viewer.with_untracked(Option::is_none)
            && ui.opening.with_untracked(Option::is_none)
            && ui.streaming.with_untracked(Option::is_none)
            && ui
                .open
                .get_untracked()
                .and_then(|peer| ui.contact(&peer))
                .is_some_and(|contact| !contact.request && !contact.is_quarantined())
    };
    let _ = window_event_listener(ev::dragenter, move |event| {
        if accepts(&event) {
            event.prevent_default();
            depth.update(|depth| *depth += 1);
        }
    });
    let _ = window_event_listener(ev::dragover, move |event| {
        if accepts(&event) {
            event.prevent_default();
        }
    });
    let _ = window_event_listener(ev::dragleave, move |_| {
        depth.update(|depth| *depth = (*depth - 1).max(0));
    });
    let _ = window_event_listener(ev::drop, move |event| {
        depth.set(0);
        if accepts(&event) {
            event.prevent_default();
            if let Some(files) = event.data_transfer().and_then(|transfer| transfer.files()) {
                send_files(files);
            }
        }
    });
    let hidden = move || {
        depth.get() == 0
            || ui.phase.get() != Phase::Unlocked
            || ui.dialog.with(Option::is_some)
            || ui.viewer.with(Option::is_some)
            || ui.opening.with(Option::is_some)
            || ui.streaming.with(Option::is_some)
    };
    let to = move || {
        let name = ui
            .open
            .get()
            .and_then(|peer| ui.contact(&peer))
            .map(|contact| contact.label())
            .unwrap_or_default();
        format!("to {name} · up to {} each", size_u64(MAX_FILE_SIZE as u64))
    };
    view! {
        <div class="dropzone" hidden=hidden>
            "Drop to encrypt and send"
            <span>{to}</span>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SecurityView;

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
            (false, true, false, "classical chat (quarantined)".to_string())
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
}
