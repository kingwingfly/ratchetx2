//! The page: the chat list beside the open chat, the dialogs, the viewer and the dropzone.

mod auth;
mod chat;
mod common;
mod composer;
mod dialogs;
mod files;
mod media;
mod pdf;
mod settings;
mod sidebar;
#[cfg(test)]
mod tests;
mod viewer;

use std::{cell::OnceCell, rc::Rc};

use leptos::{ev, prelude::*, task::spawn_local};
use session::PqConfig;
use wasm_bindgen::JsValue;

use crate::{
    engine::{Engine, MAX_FILE_SIZE},
    icon::{Icon, icon},
    state::{Link, Phase, Ui, UnavailableReason},
    util::{clock, key_to_text, size_u64},
};

use self::{
    chat::ChatPane,
    common::{Copyable, invitation_link, new_chat, send_files},
    dialogs::VaultDialog,
    sidebar::Sidebar,
    viewer::Viewer,
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
        ui.me.with(|me| {
            me.as_ref()
                .map(|me| key_to_text(&me.key))
                .unwrap_or_default()
        })
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
