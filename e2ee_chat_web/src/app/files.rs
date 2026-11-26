use std::collections::HashSet;

use leptos::{prelude::*, task::spawn_local};
use session::PublicKey;

use crate::{
    content,
    icon::{Icon, icon},
    preview::Sort,
    state::{Body, FileView},
    util::{day, month, sanitize_filename, size_u64},
};

use super::{
    common::{ConfirmGuard, close_dialog, extension},
    engine,
    media::{MediaThumb, Source, cancel_pending_previews, inline_media},
    ui,
};

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
pub(super) fn FileBrowser(peer: PublicKey) -> impl IntoView {
    // Closing Files invalidates any in-flight local-file or stream setup started from it.
    on_cleanup(cancel_pending_previews);
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
pub(super) fn file_status_suffix(
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
    let base_name = sanitize_filename(&file.name);
    let tile_name = base_name.clone();
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
                {(file.sort == Sort::Audio).then(|| view! { <span class="tile-name">{tile_name}</span> })}
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
    let display_name = sanitize_filename(&file.name);
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
        _ => view! { <span class="file-icon">{extension(&display_name)}</span> }.into_any(),
    };
    let title = display_name.clone();
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
                    <strong>{display_name}</strong>
                    <span>{details}</span>
                </span>
            </button>
            {delete}
        </div>
    }
    .into_any()
}

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
    let confirm = ConfirmGuard::new();
    let deleting = RwSignal::new(false);
    let safe_name = sanitize_filename(&pointer.name);
    let label = ui()
        .contact(&peer)
        .map(|contact| contact.label())
        .unwrap_or_default();
    let what = move || {
        if deleting.get() {
            "Deleting it from the server…".to_string()
        } else if confirm.is_armed() {
            format!("Delete it from the server, for you and {label}?")
        } else {
            "Delete from the server".to_string()
        }
    };
    let click = move |_| {
        if deleting.get_untracked() {
            return;
        }
        if !confirm.confirm_or_arm() {
            ui().notify(format!(
                "Press again to delete {safe_name} from the server: neither of you can download it \
                 any more; what you downloaded stays."
            ));
            return;
        }
        deleting.set(true);
        let pointer = pointer.clone();
        let safe_name = safe_name.clone();
        spawn_local(async move {
            match engine().delete_attachment(peer, index, &pointer).await {
                Ok(()) => {
                    deleted.try_update(|deleted| deleted.insert(index));
                    ui().notify(format!("{safe_name} is deleted from the server"));
                }
                Err(e) => {
                    deleting.try_set(false);
                    ui().notify(e);
                }
            }
        });
    };
    view! {
        <button
            type="button"
            class="btn icon small quiet delete-remote"
            class:asked=move || confirm.is_armed()
            title=what.clone()
            aria-label=what
            disabled=move || deleting.get()
            on:click=click
        >
            {icon(Icon::Delete)}
        </button>
    }
}
