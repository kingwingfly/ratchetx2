//! The page: the chat list beside the open chat, the dialogs, the viewer and the dropzone.

use std::{cell::OnceCell, rc::Rc, sync::Arc, time::Duration};

use base64::{Engine as _, prelude::BASE64_STANDARD};
use e2ee_chat_preview::language;

use js_sys::Uint8Array;
use leptos::{ev, html, prelude::*, task::spawn_local};
use session::{PublicKey, safety_number};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{
    Blob, BlobPropertyBag, CanvasRenderingContext2d, FileList, HtmlAnchorElement,
    HtmlCanvasElement, IntersectionObserver, IntersectionObserverEntry, IntersectionObserverInit,
    Url,
};

use crate::{
    content,
    engine::{
        Engine, MAX_FILE_SIZE, MEDIA_INLINE_MAX, NAME_MAX, Sending, invitation, origin, same_server,
    },
    glue::copy,
    icon::{Icon, icon},
    preview::{self, DiffLine, Kind, Sort},
    search::Search,
    state::{
        Attachment, Body, ContactView, Delivery, Dialog, FileView, Link, LocalFile, Me,
        MessageView, Phase, RemoteFile, SignIn, Streamed, Ui, UploadState, UploadView,
    },
    util::{clock, day, js_error, key_to_text, key_to_url, month, short, size, sleep},
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
                                Phase::Elsewhere => "The vault is open in another tab.",
                                Phase::Unavailable(_) => "The browser's storage is not available.",
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
        Phase::Unavailable(_) => "storage unavailable".to_string(),
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
                <button
                    class="btn icon small"
                    title="New chat"
                    aria-label="New chat"
                    on:click=move |_| new_chat()
                >
                    {icon(Icon::Compose)}
                </button>
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
                    title="Your key"
                    aria-label="Your key"
                    on:click=move |_| ui.dialog.set(Some(Dialog::Identity))
                >
                    {icon(Icon::Key)}
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
    let sub = if contact.request {
        "wants to chat".to_string()
    } else {
        short(&peer)
    };
    let when = (contact.last_activity > 0).then(|| clock(contact.last_activity));
    view! {
        <button
            class="chat-item"
            class:request=contact.request
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

/// With no chat open: this client's key, and what happened.
#[component]
fn Welcome() -> impl IntoView {
    let ui = ui();
    let me = ui.me.get_untracked();
    let key = me
        .as_ref()
        .map(|me| key_to_text(&me.key))
        .unwrap_or_default();
    let link = me.as_ref().map(invitation_link).unwrap_or_default();
    view! {
        <section class="pane welcome">
            <div class="welcome-inner">
                <div>
                    <div class="eyebrow">"END-TO-END ENCRYPTED"</div>
                    <h1>"Your keys stay in this browser"</h1>
                </div>
                <p>
                    "Messages are encrypted here, with X3DH and a double ratchet, before they "
                    "leave the page. The server, a Cloudflare Worker, only relays what it cannot "
                    "read: prekeys and sealed messages in D1, the large ones in R2."
                </p>
                <div>
                    <div class="section-label">"Your identity key"</div>
                    <Copyable text=key what="your key" />
                    <div class="section-label">"Your invitation link"</div>
                    <Copyable text=link what="your invitation link" />
                    <div class="row">
                        <button class="btn primary" on:click=move |_| new_chat()>
                            {icon(Icon::Compose)}
                            "New chat"
                        </button>
                    </div>
                </div>
                <div>
                    <div class="section-label">"Activity"</div>
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
                    </ul>
                </div>
            </div>
        </section>
    }
}

#[component]
fn ChatPane(peer: PublicKey) -> impl IntoView {
    let ui = ui();
    let contact = move || ui.contact(&peer);
    let label = move || contact().map(|contact| contact.label()).unwrap_or_default();
    let request = move || contact().is_some_and(|contact| contact.request);
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
                    <span>{short(&peer)}</span>
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
            <Show when=request>
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
            <Composer peer disabled=Signal::derive(request) />
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
                key=|message| (message.index, message.delivery)
                children=move |message| message_item(message, label)
            />
        </div>
    }
}

/// A message, as a bubble, an image, a file or a note.
/// The notes name the peer by `label`, which changes once a request is accepted.
fn message_item(message: MessageView, label: Signal<String>) -> AnyView {
    let time = clock(message.at);
    let content = match message.body {
        Body::Text(text) => view! { <div class="bubble">{text}</div> }.into_any(),
        // Small media shows in place, other files as cards.
        Body::File(_) | Body::Remote(_) => match inline_media(&message.body) {
            Some((source, sort)) => view! { <InlineMedia source sort /> }.into_any(),
            None => match Source::of(&message.body) {
                Some(source) => file_card(source),
                None => ().into_any(),
            },
        },
        Body::Hello(name) => {
            let note = move || match (message.outgoing, name.is_empty()) {
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
    // How far it got, right of its time, as Telegram shows it: a clock while it waits, one tick
    // once the server has it, two once the peer read it, and three once it downloaded its
    // attachment; what that says, for its tooltip and screen readers; and whether the peer read
    // it.
    let status = match message.delivery {
        Delivery::Received => None,
        Delivery::Pending => Some((Icon::Pending, "waiting to be sent", false)),
        Delivery::Failed => Some((Icon::Failed, "could not be sent", false)),
        Delivery::Sent => Some((Icon::Sent, "sent", false)),
        Delivery::Read => Some((Icon::Read, "read", true)),
        Delivery::Downloaded => Some((Icon::Downloaded, "read and downloaded", true)),
    };
    // Held until this browser signs in to the server, which keeps it only for those who do: it
    // can be cancelled, which lets what was sent after it go.
    let index = message.index;
    let held = message.outgoing.then_some(move || {
        let ui = ui();
        let peer = ui.open.get()?;
        ui.held.with(|held| held.contains(&(peer, index))).then(|| {
            view! {
                <button
                    type="button"
                    class="link cancel-held"
                    title="Do not send it, so that what was sent after it goes"
                    on:click=move |_| act(async move { engine().cancel_held(peer, index).await })
                >
                    "Cancel"
                </button>
            }
        })
    });
    view! {
        <div class="message" class:me=message.outgoing>
            {content}
            <span class="meta" class:failed=message.delivery == Delivery::Failed>
                {held}
                {time}
                {status
                    .map(|(shown, title, read)| {
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
                    })}
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
            <For each=uploads key=|upload| upload.clone() children=upload_row />
        </div>
    }
}

fn upload_row(upload: UploadView) -> impl IntoView {
    let percent = upload.done * 100 / upload.size.max(1);
    let (status, paused) = match &upload.state {
        UploadState::Running => (format!("uploading · {percent}%"), false),
        UploadState::Retrying => (format!("{percent}% · waiting for the server"), false),
        UploadState::Paused(reason) => (format!("{percent}% · {reason}"), true),
    };
    let (peer, id) = (upload.peer, upload.id);
    // Without the file, which went with the page that chose it, the file is chosen again.
    let resume = move |_| {
        if engine().has_file(&id) {
            act(async move { engine().resume_upload(peer, id, None).await });
        } else {
            choose_file(move |file| {
                act(async move { engine().resume_upload(peer, id, Some(file)).await })
            });
        }
    };
    let cancel = move |_| act(async move { engine().cancel_upload(peer, id).await });
    view! {
        <div class="upload">
            <span class="file-icon">{extension(&upload.name)}</span>
            <span class="upload-text">
                <strong>{upload.name.clone()}</strong>
                <span>{status}</span>
            </span>
            {paused
                .then(|| {
                    view! {
                        <button
                            class="btn icon small"
                            title="Resume"
                            aria-label="Resume"
                            on:click=resume
                        >
                            {icon(Icon::Resume)}
                        </button>
                    }
                })}
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

/// Let the user choose a file, then call `chosen` with it.
fn choose_file(chosen: impl FnOnce(web_sys::File) + 'static) {
    let Ok(input) = document().create_element("input") else {
        return;
    };
    let input: web_sys::HtmlInputElement = input.unchecked_into();
    input.set_type("file");
    let picked = input.clone();
    let on_change = Closure::once_into_js(move || {
        if let Some(file) = picked.files().and_then(|files| files.get(0)) {
            chosen(file);
        }
    });
    input.set_onchange(Some(on_change.unchecked_ref()));
    input.click();
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
                .stream(remote.peer, &remote.pointer, remote.clock)
                .await
        {
            ui.viewer.set(None);
            ui.opening.set(None);
            let video = sort == Sort::Video;
            ui.streaming.set(Some(Streamed { url, remote, video }));
            return;
        }
        if let Err(e) = engine
            .open_attachment(remote.peer, remote.pointer, remote.clock)
            .await
        {
            ui.notify(e);
        }
    });
}

/// How long a stream let go of still answers what its players asked for before they stopped.
const STREAM_GRACE: Duration = Duration::from_secs(10);

/// Let go of `url`, a blob URL or a stream's, as what showed it went. A stream's players on the
/// page stop asking for it first, and what they asked for already is still answered for
/// [`STREAM_GRACE`], so that none fails.
fn release(url: &str) {
    if url.starts_with("/media/") {
        stop_players(url);
        let url = url.to_string();
        set_timeout(move || engine().end_stream(&url), STREAM_GRACE);
    } else {
        let _ = Url::revoke_object_url(url);
    }
}

/// Stop the players of the stream at `url` on the page, which cancels what they asked for.
fn stop_players(url: &str) {
    let selector = format!("video[src^=\"{url}\"], audio[src^=\"{url}\"]");
    let Ok(players) = document().query_selector_all(&selector) else {
        return;
    };
    for index in 0..players.length() {
        if let Some(player) = players
            .item(index)
            .and_then(|player| player.dyn_into::<web_sys::HtmlMediaElement>().ok())
        {
            let _ = player.remove_attribute("src");
            player.load();
        }
    }
}

#[component]
fn Composer(peer: PublicKey, disabled: Signal<bool>) -> impl IntoView {
    let text = RwSignal::new(String::new());
    let textarea = NodeRef::<html::Textarea>::new();
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
    let rows = move || text.with(|text| text.split('\n').count().clamp(1, 6));
    view! {
        <div class="composer">
            <button
                class="btn icon"
                title="Attach files, or drop them on the page"
                aria-label="Attach files"
                disabled=disabled
                on:click=move |_| pick_files()
            >
                {icon(Icon::Attach)}
            </button>
            <textarea
                node_ref=textarea
                rows=rows
                placeholder=move || {
                    if disabled.get() { "Accept the request to write" } else { "Write a message" }
                }
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
            <FilePicker />
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
                    .media(remote.peer, remote.pointer.clone(), remote.clock, shows)
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
    let length = size(source.size() as usize);
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
    // Its URL and MIME type, once read, and what the viewer shows of it.
    let shown = RwSignal::new(None::<(String, &'static str)>);
    let read = StoredValue::new(None::<Attachment>);
    let failed = RwSignal::new(false);
    // Gone with the media, e.g. as the chat closed or the message's delivery changed: a read
    // that ends after shows nothing, and a URL made then is let go at once.
    let here = StoredValue::new(());
    let play = move |url: String, mime: &'static str| {
        if let Some(Some((url, _))) = shown.try_set(Some((url, mime))) {
            release(&url);
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
                        .stream(remote.peer, &remote.pointer, remote.clock)
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
        if let Some(Some((url, _))) = shown.try_get_untracked() {
            release(&url);
        }
    });
    let name = source.name().to_string();
    let caption = format!("{} · {}", source.name(), size(source.size() as usize));
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
    let preview = RwSignal::new(None::<Preview>);
    let length = RwSignal::new(None::<String>);
    // Gone with the preview: a read that ends after shows nothing, and a URL made then is let
    // go at once.
    let here = StoredValue::new(());
    let show = move |made: Preview| {
        if let Some(Some(Preview::Image(url) | Preview::Video(url))) = preview.try_set(Some(made)) {
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
                        .stream(remote.peer, &remote.pointer, remote.clock)
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

fn open_chat(peer: Option<PublicKey>) {
    let engine = engine();
    spawn_local(async move { engine.open(peer).await });
}

fn new_chat() {
    ui().dialog.set(Some(Dialog::NewChat {
        key: String::new(),
        name: String::new(),
        server: None,
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

/// A link that opens a chat with `me`, with the name filled in, and the server if it is not the
/// page's own.
fn invitation_link(me: &Me) -> String {
    let mut link = format!("{}/#chat={}", origin(), key_to_url(&me.key));
    if !me.name.is_empty() {
        link.push_str(&format!("&name={}", js_sys::encode_uri_component(&me.name)));
    }
    if !same_server(&me.server, &origin()) {
        link.push_str(&format!(
            "&server={}",
            js_sys::encode_uri_component(&me.server)
        ));
    }
    link
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

/// Open the file picker.
fn pick_files() {
    if let Some(input) = document()
        .get_element_by_id("file-picker")
        .and_then(|input| input.dyn_into::<web_sys::HtmlInputElement>().ok())
    {
        input.click();
    }
}

#[component]
fn FilePicker() -> impl IntoView {
    let on_change = move |event: ev::Event| {
        let input: web_sys::HtmlInputElement = event_target(&event);
        if let Some(files) = input.files() {
            send_files(files);
        }
        // So that picking the same file again sends it again.
        input.set_value("");
    };
    view! { <input id="file-picker" type="file" multiple hidden on:change=on_change /> }
}

/// The modal dialog: the vault's while it is locked, then the one the page asks for.
#[component]
fn VaultDialog() -> impl IntoView {
    let ui = ui();
    let dialog = NodeRef::<html::Dialog>::new();
    let shown = move || match ui.phase.get() {
        Phase::Create | Phase::Locked | Phase::Elsewhere | Phase::Unavailable(_) => true,
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
        }
    };
    view! {
        <dialog
            class="modal"
            class:wide=move || matches!(ui.dialog.get(), Some(Dialog::Files(_)))
            node_ref=dialog
            on:cancel=on_cancel
            on:close=move |_| ui.dialog.set(None)
        >
            {move || match (ui.phase.get(), ui.dialog.get()) {
                (Phase::Create, _) => view! { <CreateVault /> }.into_any(),
                (Phase::Locked, _) => view! { <UnlockVault /> }.into_any(),
                (Phase::Elsewhere, _) => view! { <Elsewhere /> }.into_any(),
                (Phase::Unavailable(error), _) => view! { <Unavailable error /> }.into_any(),
                (Phase::Unlocked, Some(Dialog::NewChat { key, name, server })) => {
                    view! { <NewChat key name server /> }.into_any()
                }
                (Phase::Unlocked, Some(Dialog::Identity)) => view! { <Identity /> }.into_any(),
                (Phase::Unlocked, Some(Dialog::Contact(peer))) => {
                    view! { <ContactInfo peer /> }.into_any()
                }
                (Phase::Unlocked, Some(Dialog::Files(peer))) => {
                    view! { <FileBrowser peer /> }.into_any()
                }
                (Phase::Unlocked, Some(Dialog::SignIn)) => view! { <SignInDialog /> }.into_any(),
                _ => ().into_any(),
            }}
            <Toast />
        </dialog>
    }
}

/// Sign in to the server with its password, which storing files there takes, as they cost it
/// storage: what waited for it goes then.
#[component]
fn SignInDialog() -> impl IntoView {
    let password = RwSignal::new(String::new());
    let progress = Progress::new();
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        let engine = engine();
        progress.start("Signing in…");
        spawn_local(async move {
            match engine.sign_in(&password.get_untracked()).await {
                Ok(signed_in) => {
                    engine.ui().dialog.set(None);
                    engine.ui().notify(format!(
                        "Signed in until {}: your files go now.",
                        day(signed_in.expires)
                    ));
                }
                Err(e) => progress.fail(e),
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
            <label for="server-password">"The server's password"</label>
            <input
                id="server-password"
                type="password"
                autocomplete="current-password"
                required
                bind:value=password
            />
            {progress.view()}
            <div class="actions">
                <button
                    type="button"
                    class="btn"
                    on:click=move |_| {
                        engine().decline_sign_in();
                        close_dialog();
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

    fn fail(&self, error: impl Into<String>) {
        self.working.set(false);
        self.message.set(error.into());
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
    let invited = invited_server();
    let server = RwSignal::new(invited.clone().unwrap_or_else(origin));
    let progress = Progress::new();
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        if passphrase.with_untracked(|p| p.chars().count()) < 8 {
            return progress.fail("Use a passphrase of 8 characters or more.");
        }
        if passphrase.get_untracked() != repeat.get_untracked() {
            return progress.fail("The passphrases differ.");
        }
        progress.start("Deriving the key…");
        let engine = engine();
        spawn_local(async move {
            // Argon2 blocks the page for a moment; let it show why first.
            sleep(50).await;
            let result = engine
                .create(
                    name.get_untracked(),
                    passphrase.get_untracked(),
                    server.get_untracked(),
                )
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
    let progress = Progress::new();
    let confirm_reset = RwSignal::new(false);
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        progress.start("Deriving the key…");
        let engine = engine();
        spawn_local(async move {
            sleep(50).await;
            if let Err(e) = engine.unlock(passphrase.get_untracked()).await {
                progress.fail(e);
            }
        });
    };
    let reset = move |_| {
        if !confirm_reset.get_untracked() {
            confirm_reset.set(true);
            return;
        }
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
                <button type="button" class="btn danger" on:click=reset>
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
fn Unavailable(error: String) -> impl IntoView {
    view! {
        <div>
            <h2>"Storage unavailable"</h2>
            <p>
                "The browser would not open its storage, so whether a vault is here is unknown, "
                "and nothing was changed. Private windows and blocked site data can cause this."
            </p>
            <p class="error">{error}</p>
            <div class="actions">
                <button class="btn primary" on:click=move |_| lock()>
                    "Reload"
                </button>
            </div>
        </div>
    }
}

#[component]
fn NewChat(key: String, name: String, server: Option<String>) -> impl IntoView {
    // An invitation for another server than the vault's: the inviter's keys are not on it.
    let elsewhere = ui().me.get_untracked().and_then(|me| {
        server
            .filter(|server| !same_server(server, &me.server))
            .map(|server| (server, me.server))
    });
    let key = RwSignal::new(key);
    let name = RwSignal::new(name);
    let progress = Progress::new();
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        progress.start("Fetching their prekeys…");
        let engine = engine();
        spawn_local(async move {
            match engine
                .start_chat(&key.get_untracked(), name.get_untracked())
                .await
            {
                Ok(peer) => {
                    engine.ui().dialog.set(None);
                    engine.open(Some(peer)).await;
                }
                Err(e) => progress.fail(e),
            }
        });
    };
    view! {
        <form on:submit=submit>
            <h2>"New chat"</h2>
            <p>
                "Paste their identity key. Their prekeys come from the server, and a greeting "
                "with your name starts the session."
            </p>
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
            {progress.view()}
            <div class="actions">
                <button type="button" class="btn" on:click=move |_| close_dialog()>
                    "Cancel"
                </button>
                <button class="btn primary" type="submit" disabled=move || progress.working.get()>
                    "Start"
                </button>
            </div>
        </form>
    }
}

#[component]
fn Identity() -> impl IntoView {
    let ui = ui();
    let Some(me) = ui.me.get_untracked() else {
        return ().into_any();
    };
    let name = RwSignal::new(me.name.clone());
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        let engine = engine();
        act(async move {
            engine.set_name(name.get_untracked()).await?;
            engine.ui().dialog.set(None);
            engine.ui().notify("Saved your name.");
            Ok(())
        });
    };
    let publish = move |_| {
        let engine = engine();
        act(async move {
            engine.publish(true).await?;
            engine.ui().notify("Published new prekeys.");
            Ok(())
        });
    };
    // Whether the server keeps this browser's files, as it is signed in to it.
    let signed_in = RwSignal::new(None::<Result<Option<SignIn>, String>>);
    spawn_local(async move {
        signed_in.try_set(Some(engine().signed_in().await));
    });
    let sign_out = move |_| {
        let engine = engine();
        act(async move {
            engine.sign_out().await?;
            signed_in.try_set(Some(Ok(None)));
            engine
                .ui()
                .notify("Signed out: files wait for the next sign-in.");
            Ok(())
        });
    };
    let files = move || match signed_in.get() {
        None => view! { <p class="hint">"Asking the server…"</p> }.into_any(),
        Some(Ok(Some(signed_in))) => view! {
            <p class="hint">
                {format!(
                    "Signed in to the server until {}.",
                    day(signed_in.expires),
                )}
                " "
                <button type="button" class="link" on:click=sign_out>
                    "Sign out"
                </button>
            </p>
        }
        .into_any(),
        Some(Ok(None)) => view! {
            <p class="hint">
                "The server is only for those signed in to it: until then, nothing goes. "
                <button
                    type="button"
                    class="link"
                    on:click=move |_| ui.dialog.set(Some(Dialog::SignIn))
                >
                    "Sign in"
                </button>
            </p>
        }
        .into_any(),
        Some(Err(e)) => {
            view! { <p class="hint">{format!("Cannot ask the server: {e}")}</p> }.into_any()
        }
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
            <Copyable text=invitation_link(&me) what="your invitation link" />
            <label for="my-name">"Your name, which new chats see"</label>
            <input id="my-name" autocomplete="nickname" maxlength=NAME_MAX bind:value=name />
            <label>"Server"</label>
            {files}
            <div class="actions">
                <button
                    type="button"
                    class="btn aside"
                    title="publish a new signed prekey and one-time prekeys"
                    on:click=publish
                >
                    "New prekeys"
                </button>
                <button type="button" class="btn" on:click=move |_| close_dialog()>
                    "Cancel"
                </button>
                <button type="submit" class="btn primary">
                    "Save"
                </button>
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
    let request = contact.request;
    let name = RwSignal::new(if request {
        contact.hello_name.clone()
    } else {
        contact.name.clone()
    });
    let confirm_delete = RwSignal::new(false);
    let submit = move |event: ev::SubmitEvent| {
        event.prevent_default();
        let engine = engine();
        act(async move {
            if request {
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
        act(async move {
            engine.delete(peer).await?;
            engine.ui().dialog.set(None);
            Ok(())
        });
    };
    let intro = if request {
        match contact.hello_name.as_str() {
            "" => format!("{} wants to chat.", short(&peer)),
            hello => format!("{} wants to chat, and goes by “{hello}”.", short(&peer)),
        }
    } else {
        format!("Your chat with {}.", contact.label())
    };
    view! {
        <form on:submit=submit>
            <h2>{if request { "Chat request" } else { "Chat" }}</h2>
            <p>
                {intro}
                " To be sure it is them, compare the safety number with them in person or over "
                "another channel: it is the same on both sides only if neither key was swapped."
            </p>
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
                <button type="button" class="btn danger" on:click=delete>
                    {move || match (confirm_delete.get(), request) {
                        (false, true) => "Delete request",
                        (false, false) => "Delete chat",
                        (true, _) => "Delete it and its history?",
                    }}
                </button>
                <button type="button" class="btn" on:click=move |_| close_dialog()>
                    "Cancel"
                </button>
                <button class="btn primary" type="submit">
                    {if request { "Accept" } else { "Save" }}
                </button>
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
                        let tiles = files.into_iter().map(file_tile).collect_view();
                        view! { <div class="file-grid">{tiles}</div> }.into_any()
                    } else {
                        let from = from.clone();
                        let rows = files
                            .into_iter()
                            .map(|file| file_row(file, &from))
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

/// `file` as a tile of the file browser's grid of media: its preview, which for audio, which may
/// have no cover, goes with its name. It opens in the viewer.
fn file_tile(file: FileView) -> AnyView {
    let Some(source) = Source::of(&file.body) else {
        return ().into_any();
    };
    let shown = inline_media(&file.body).map(|(source, _)| source);
    let title = file.name.clone();
    view! {
        <button class="tile" title=title on:click=move |_| source.open()>
            <MediaThumb source=shown sort=file.sort />
            {(file.sort == Sort::Audio).then(|| view! { <span class="tile-name">{file.name}</span> })}
        </button>
    }
    .into_any()
}

/// `file` as a row of the file browser's list: its extension, name, size and day, and who sent
/// it, the peer being `from`.
fn file_row(file: FileView, from: &str) -> AnyView {
    let Some(source) = Source::of(&file.body) else {
        return ().into_any();
    };
    let sender = if file.outgoing {
        "sent by you".to_string()
    } else {
        format!("from {from}")
    };
    let details = format!("{} · {} · {sender}", size(file.size as usize), day(file.at));
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
    // An attachment this client uploaded, which it can delete from the server.
    let delete = match &file.body {
        Body::Remote(remote) if file.deletable => {
            <[u8; 16]>::try_from(remote.pointer.id.as_slice())
                .ok()
                .map(|id| view! { <DeleteFromServer peer=remote.peer id name=file.name.clone() /> })
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

/// Deletes the attachment `id`, named `name`, which this client uploaded for `peer`, from the
/// server, once asked twice: the peer can no longer download it, though what it downloaded
/// stays, and so does this client's copy.
#[component]
fn DeleteFromServer(peer: PublicKey, id: [u8; 16], name: String) -> impl IntoView {
    #[derive(Clone, Copy, PartialEq)]
    enum Step {
        Offered,
        Asked,
        Deleting,
        Deleted,
    }
    let step = RwSignal::new(Step::Offered);
    let label = ui()
        .contact(&peer)
        .map(|contact| contact.label())
        .unwrap_or_default();
    let title = format!("{label} can no longer download it; what they downloaded stays");
    let click = move |_| match step.get_untracked() {
        Step::Offered => step.set(Step::Asked),
        Step::Asked => {
            step.set(Step::Deleting);
            let name = name.clone();
            spawn_local(async move {
                match engine().delete_attachment(peer, id).await {
                    Ok(()) => {
                        step.try_set(Step::Deleted);
                        ui().notify(format!("{name} is deleted from the server"));
                    }
                    Err(e) => {
                        step.try_set(Step::Offered);
                        ui().notify(e);
                    }
                }
            });
        }
        Step::Deleting | Step::Deleted => {}
    };
    view! {
        <button
            type="button"
            class="link delete-remote"
            class:asked=move || step.get() == Step::Asked
            title=title
            disabled=move || matches!(step.get(), Step::Deleting | Step::Deleted)
            on:click=click
        >
            {move || match step.get() {
                Step::Offered => "Delete from server",
                Step::Asked => "Delete it for them?",
                Step::Deleting => "Deleting…",
                Step::Deleted => "Deleted from server",
            }}
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
    let close = move || {
        // Its player stops before it goes.
        if let Some(streamed) = ui.streaming.get_untracked() {
            stop_players(&streamed.url);
        }
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
                return Some(streamed_view(streamed));
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
                Some(url) => view! {
                    <div class="media">
                        <video src=url controls></video>
                    </div>
                }
                .into_any(),
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
                        format!("{} · {}", pointer.name, size(pointer.size as usize))
                    })
                })
            })
            .or_else(|| {
                ui.opening.with(|opening| {
                    opening
                        .as_ref()
                        .map(|o| format!("{} · {}", o.name, size(o.size as usize)))
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
                            on:click=move |_| {
                                if let Some(attachment) = ui.viewer.get_untracked() {
                                    download(&attachment);
                                } else if let Some(streamed) = ui.streaming.get_untracked() {
                                    download_whole(streamed.remote);
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

/// A video or audio attachment playing as it is fetched, see [`Streamed`]. One that turns out
/// not to play, e.g. as its name said video but no browser plays it, is fetched whole, to show
/// as its bytes say, as one that does not stream.
fn streamed_view(streamed: Streamed) -> AnyView {
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
                        .open_attachment(remote.peer, remote.pointer, remote.clock)
                        .await
                });
            }
        }
    };
    if streamed.video {
        view! {
            <div class="media">
                <video src=streamed.url controls on:error=unplayable></video>
            </div>
        }
        .into_any()
    } else {
        let name = streamed.remote.pointer.name;
        let on_error = UnsyncCallback::new(unplayable);
        view! { <AudioView url=streamed.url name on_error /> }.into_any()
    }
}

/// Download the attachment `remote` whole, as a stream plays only what it needs of it.
fn download_whole(remote: RemoteFile) {
    let ui = ui();
    act(async move {
        ui.notify(format!("Downloading {}…", remote.pointer.name));
        let fetched = engine()
            .media(remote.peer, remote.pointer, remote.clock, &|| true)
            .await?;
        if let Some(attachment) = fetched {
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

/// How far opening an attachment got: how much of it is decrypted, on a bar, and whether it
/// waits for its sender to upload the rest.
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
                let done = format!(
                    "{} of {}",
                    size(opening.done as usize),
                    size(opening.size as usize)
                );
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
            <div class="opening" role="progressbar" aria-valuemin="0" aria-valuemax="100"
                aria-valuenow=move || (fraction() * 100.0).round().to_string()>
                <div class="bar">
                    <div class="bar-fill" style:transform=move || format!("scaleX({})", fraction())></div>
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

/// Make the links in `element` leave in a tab of their own, telling nothing of this page;
/// highlight its code blocks, `pre > code[data-lang]`, and draw its Mermaid ones, as images.
/// Blocks that fail stay as they are, saying why in `data-error`.
fn enhance(element: &web_sys::Element) {
    for link in select(element, "a[href^='http']") {
        let _ = link.set_attribute("target", "_blank");
        let _ = link.set_attribute("rel", "noopener noreferrer");
    }
    for code in select(element, "pre > code[data-lang]") {
        spawn_local(async move {
            let info = code.get_attribute("data-lang").unwrap_or_default();
            let text = code.text_content().unwrap_or_default();
            let shown = if info.eq_ignore_ascii_case("mermaid") {
                workers::diagram(&text).await.and_then(|svg| {
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
                workers::highlight(language, &text)
                    .await
                    .map(|html| code.set_inner_html(&html))
            } else {
                Ok(())
            };
            if let (Err(e), Some(block)) = (shown, code.parent_element()) {
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
    // Scaled to fit the screen, as it changes.
    let fit = move || {
        let Some(slides) = node.get_untracked() else {
            return;
        };
        let style = web_sys::HtmlElement::style(&slides);
        if full.get_untracked() {
            let window = window();
            let size = |size: Result<JsValue, JsValue>| size.ok()?.as_f64();
            let (Some(width), Some(height)) =
                (size(window.inner_width()), size(window.inner_height()))
            else {
                return;
            };
            let scale = (width / SLIDE_SIZE.0).min((height - SLIDES_BAR) / SLIDE_SIZE.1);
            let _ = style.set_property("--scale", &scale.max(0.1).to_string());
        } else {
            let _ = style.remove_property("--scale");
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
        <div class="slides" class:full=move || full.get() node_ref=node>
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

/// A PDF, its pages drawn by a worker, each as it scrolls into view.
#[component]
fn PdfView(data: Arc<Vec<u8>>) -> impl IntoView {
    let node = NodeRef::<html::Div>::new();
    // The document, and what draws its pages, until the view goes.
    let shown = StoredValue::new_local(None::<(workers::Pdf, Drawing)>);
    let failed = RwSignal::new(None::<String>);
    Effect::new(move || {
        let Some(container) = node.get() else {
            return;
        };
        let data = data.clone();
        spawn_local(async move {
            match workers::open_pdf(&data).await {
                Ok((pdf, pages)) => {
                    let container: web_sys::Element = container.into();
                    match draw_pages(&container, pdf, &pages) {
                        // Unless the view went meanwhile.
                        Ok(drawing) => {
                            if let Some(Some((pdf, drawing))) =
                                shown.try_set_value(Some((pdf, drawing)))
                            {
                                drawing.observer.disconnect();
                                workers::close_pdf(pdf);
                            }
                        }
                        Err(e) => {
                            workers::close_pdf(pdf);
                            failed.try_set(Some(e));
                        }
                    }
                }
                Err(e) => {
                    failed.try_set(Some(e));
                }
            }
        });
    });
    on_cleanup(move || {
        if let Some(Some((pdf, drawing))) = shown.try_update_value(Option::take) {
            drawing.observer.disconnect();
            workers::close_pdf(pdf);
        }
    });
    view! {
        <div class="pdf" node_ref=node></div>
        {move || {
            failed.get().map(|e| view! { <p class="no-preview">{format!("The PDF does not show: {e}")}</p> })
        }}
    }
}

/// What draws a PDF's pages as they are about to show: an observer of their canvases, and what it
/// calls, which must live as long as it observes.
struct Drawing {
    observer: IntersectionObserver,
    _draw: Closure<dyn FnMut(js_sys::Array, IntersectionObserver)>,
}

/// Put a canvas a page of `pdf`, whose sizes are `pages`, in `container`, sized before it is
/// drawn, so that the pages after it are where they will be; each is drawn once it is about to
/// show.
fn draw_pages(
    container: &web_sys::Element,
    pdf: workers::Pdf,
    pages: &[(f64, f64)],
) -> Result<Drawing, String> {
    let draw = Closure::<dyn FnMut(js_sys::Array, IntersectionObserver)>::new(
        move |entries: js_sys::Array, observer: IntersectionObserver| {
            for entry in entries.iter() {
                let entry: IntersectionObserverEntry = entry.unchecked_into();
                let Ok(canvas) = entry.target().dyn_into::<HtmlCanvasElement>() else {
                    continue;
                };
                if !entry.is_intersecting() {
                    continue;
                }
                observer.unobserve(&canvas);
                spawn_local(async move {
                    if let Err(e) = draw_page(pdf, &canvas).await {
                        let _ = canvas.set_attribute("data-error", &e);
                    }
                });
            }
        },
    );
    let options = IntersectionObserverInit::new();
    options.set_root(container.closest(".viewer-content").ok().flatten().as_ref());
    options.set_root_margin("200px");
    let observer = IntersectionObserver::new_with_options(draw.as_ref().unchecked_ref(), &options)
        .map_err(js_error)?;
    for (index, (width, height)) in pages.iter().enumerate() {
        let canvas = document().create_element("canvas").map_err(js_error)?;
        canvas.set_class_name("pdf-page");
        let _ = canvas.set_attribute("data-page", &index.to_string());
        let style = canvas.unchecked_ref::<web_sys::HtmlElement>().style();
        let _ = style.set_property("aspect-ratio", &format!("{width} / {height}"));
        container.append_child(&canvas).map_err(js_error)?;
        observer.observe(&canvas);
    }
    Ok(Drawing {
        observer,
        _draw: draw,
    })
}

/// Draw the page of `pdf` that `canvas` shows, as sharp as the screen shows it, at most twice
/// as sharp as CSS pixels.
async fn draw_page(pdf: workers::Pdf, canvas: &HtmlCanvasElement) -> Result<(), String> {
    let index: usize = canvas
        .get_attribute("data-page")
        .and_then(|page| page.parse().ok())
        .ok_or("no page")?;
    let ratio = web_sys::window()
        .map_or(1.0, |window| window.device_pixel_ratio())
        .min(2.0);
    let width = (f64::from(canvas.client_width()) * ratio).round().max(1.0) as u32;
    let image = workers::render_pdf(pdf, index, width).await?;
    canvas.set_width(image.width());
    canvas.set_height(image.height());
    let context: CanvasRenderingContext2d = canvas
        .get_context("2d")
        .map_err(js_error)?
        .ok_or("no 2D context")?
        .unchecked_into();
    context.put_image_data(&image, 0.0, 0.0).map_err(js_error)?;
    let _ = canvas.set_attribute("data-drawn", "yes");
    Ok(())
}

fn table_view(table: preview::Table) -> AnyView {
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
            {table
                .more
                .then(|| {
                    view! {
                        <p class="preview-note">
                            {format!("Only the first {} rows show.", preview::ROWS_MAX)}
                        </p>
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
    let total: u64 = listing.entries.iter().map(|entry| entry.size).sum();
    let note = if listing.complete {
        format!("{files} files, {} unpacked", size(total as usize))
    } else {
        format!(
            "The first {files} files, {} unpacked; listing the rest would take too long, or it is damaged.",
            size(total as usize)
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
                        let length = if entry.directory { String::new() } else { size(entry.size as usize) };
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

/// Files dropped anywhere on the page go to the open chat.
#[component]
fn Dropzone() -> impl IntoView {
    let ui = ui();
    // dragenter and dragleave come for every element passed over; the count says when the
    // drag leaves the page.
    let depth = RwSignal::new(0i32);
    let accepts = move || {
        ui.open
            .get_untracked()
            .and_then(|peer| ui.contact(&peer))
            .is_some_and(|contact| !contact.request)
    };
    let _ = window_event_listener(ev::dragenter, move |event| {
        if accepts() {
            event.prevent_default();
            depth.update(|depth| *depth += 1);
        }
    });
    let _ = window_event_listener(ev::dragover, move |event| {
        if accepts() {
            event.prevent_default();
        }
    });
    let _ = window_event_listener(ev::dragleave, move |_| {
        depth.update(|depth| *depth = (*depth - 1).max(0));
    });
    let _ = window_event_listener(ev::drop, move |event| {
        depth.set(0);
        if accepts() {
            event.prevent_default();
            if let Some(files) = event.data_transfer().and_then(|transfer| transfer.files()) {
                send_files(files);
            }
        }
    });
    let to = move || {
        let name = ui
            .open
            .get()
            .and_then(|peer| ui.contact(&peer))
            .map(|contact| contact.label())
            .unwrap_or_default();
        format!("to {name} · up to {} each", size(MAX_FILE_SIZE))
    };
    view! {
        <div class="dropzone" hidden=move || depth.get() == 0>
            "Drop to encrypt and send"
            <span>{to}</span>
        </div>
    }
}
