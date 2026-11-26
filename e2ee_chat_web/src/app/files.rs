use std::{collections::HashSet, sync::Arc};

use leptos::{prelude::*, task::spawn_local};
use session::PublicKey;

use crate::{
    content,
    icon::{Icon, icon},
    preview::Sort,
    state::{Body, FileView, Ui},
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

    /// Classify a [`Sort`] into its concrete (non-`All`) shelf.
    fn of(sort: Sort) -> Self {
        match sort {
            Sort::Image | Sort::Video | Sort::Audio => Self::Media,
            Sort::Document => Self::Documents,
            Sort::Code => Self::Code,
            Sort::Archive => Self::Archives,
            Sort::Other | Sort::Unknown => Self::Other,
        }
    }

    fn matches_item(self, item_shelf: Self) -> bool {
        self == Self::All || self == item_shelf
    }
}

/// Precomputed item counts for each [`Shelf`], calculated once per loaded file list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ShelfCounts {
    all: usize,
    media: usize,
    documents: usize,
    code: usize,
    archives: usize,
    other: usize,
}

impl ShelfCounts {
    fn from_items(items: &[Arc<FileItemModel>]) -> Self {
        let mut counts = Self::default();
        for item in items {
            counts.all += 1;
            match item.shelf {
                Shelf::Media => counts.media += 1,
                Shelf::Documents => counts.documents += 1,
                Shelf::Code => counts.code += 1,
                Shelf::Archives => counts.archives += 1,
                Shelf::Other | Shelf::All => counts.other += 1,
            }
        }
        counts
    }

    fn get(self, shelf: Shelf) -> usize {
        match shelf {
            Shelf::All => self.all,
            Shelf::Media => self.media,
            Shelf::Documents => self.documents,
            Shelf::Code => self.code,
            Shelf::Archives => self.archives,
            Shelf::Other => self.other,
        }
    }
}

/// Target metadata for deleting a remote attachment from the server.
#[derive(Debug, Clone, PartialEq)]
struct DeleteTarget {
    peer: PublicKey,
    index: u64,
    pointer: content::AttachmentPointer,
}

/// Precomputed view model for a single entry in [`FileBrowser`].
///
/// Built once when the chat's file list loads so switching shelves or updating reactive
/// deletion/gone state never re-sanitizes filenames, re-classifies media, or re-formats sizes and
/// localized dates.
#[derive(Debug, Clone, PartialEq)]
struct FileItemModel {
    /// Stable history-entry index in the chat.
    index: u64,
    sort: Sort,
    /// Concrete non-`All` shelf classification derived from `sort`.
    shelf: Shelf,
    display_name: String,
    extension: String,
    formatted_size: String,
    day_label: String,
    sender_label: String,
    month_label: String,
    is_local: bool,
    listed_gone: bool,
    failed: bool,
    deletable: bool,
    outgoing: bool,
    source: Source,
    preview_source: Option<Source>,
    delete_target: Option<DeleteTarget>,
}

impl FileItemModel {
    fn from_view(
        file: &FileView,
        from: &str,
        format_month: &impl Fn(u64) -> String,
        format_day: &impl Fn(u64) -> String,
    ) -> Option<Self> {
        let source = Source::of(&file.body)?;
        let display_name = sanitize_filename(&file.name);
        let ext = extension(&display_name);
        let sender_label = if file.outgoing {
            "sent by you".to_string()
        } else {
            format!("from {from}")
        };
        let preview_source = inline_media(&file.body).map(|(src, _)| src);
        let delete_target = match &file.body {
            Body::Remote(remote) if file.deletable => Some(DeleteTarget {
                peer: remote.peer,
                index: file.index,
                pointer: remote.pointer.clone(),
            }),
            _ => None,
        };
        Some(Self {
            index: file.index,
            sort: file.sort,
            shelf: Shelf::of(file.sort),
            display_name,
            extension: ext,
            formatted_size: size_u64(file.size),
            day_label: format_day(file.at),
            sender_label,
            month_label: format_month(file.at),
            is_local: matches!(file.body, Body::File(_)),
            listed_gone: file.gone,
            failed: file.failed,
            deletable: file.deletable,
            outgoing: file.outgoing,
            source,
            preview_source,
            delete_target,
        })
    }

    fn details_base(&self) -> String {
        format!(
            "{} · {} · {}",
            self.formatted_size, self.day_label, self.sender_label
        )
    }

    fn reactive_state(
        &self,
        peer: PublicKey,
        deleted: RwSignal<HashSet<u64>>,
        ui: Ui,
    ) -> FileItemState {
        let index = self.index;
        let listed_gone = self.listed_gone;
        let is_local = self.is_local;
        let failed = self.failed;
        let deletable = self.deletable;
        let outgoing = self.outgoing;
        let gone = Signal::derive(move || {
            listed_gone
                || deleted.with(|deleted| deleted.contains(&index))
                || ui.gone.with(|gone| gone.contains(&(peer, index)))
        });
        let status = Signal::derive(move || {
            file_status_suffix(is_local, gone.get(), failed, deletable, outgoing)
        });
        FileItemState { gone, status }
    }
}

/// Reactive lifecycle signals shared by [`file_tile`] and [`file_row`].
#[derive(Clone, Copy)]
struct FileItemState {
    gone: Signal<bool>,
    status: Signal<Option<&'static str>>,
}

/// Files belonging to a single month heading in newest-first order.
#[derive(Debug, Clone, PartialEq)]
struct MonthGroup {
    month: String,
    items: Vec<Arc<FileItemModel>>,
}

/// Memoized view snapshot pairing the active [`Shelf`] with its grouped month sections so
/// switching between `All` and `Media` always triggers a layout change (`.file-list` vs
/// `.file-grid`) even when every file in the chat is media.
#[derive(Debug, Clone, PartialEq)]
struct ShelfGroups {
    shelf: Shelf,
    groups: Vec<MonthGroup>,
}

fn build_file_models(
    files: &[FileView],
    from: &str,
    format_month: impl Fn(u64) -> String,
    format_day: impl Fn(u64) -> String,
) -> Vec<Arc<FileItemModel>> {
    files
        .iter()
        .filter_map(|file| FileItemModel::from_view(file, from, &format_month, &format_day))
        .map(Arc::new)
        .collect()
}

/// Filter `items` to `shelf` and group contiguous entries sharing the same precomputed month
/// bucket while preserving newest-first order.
fn group_by_month(items: &[Arc<FileItemModel>], shelf: Shelf) -> Vec<MonthGroup> {
    let mut groups: Vec<MonthGroup> = Vec::new();
    for item in items.iter().filter(|item| shelf.matches_item(item.shelf)) {
        match groups.last_mut() {
            Some(last) if last.month == item.month_label => last.items.push(Arc::clone(item)),
            _ => groups.push(MonthGroup {
                month: item.month_label.clone(),
                items: vec![Arc::clone(item)],
            }),
        }
    }
    groups
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
    let from = label.clone();

    // Build precomputed `FileItemModel`s once when `files` loads so shelf switches never re-run
    // filename sanitization, media sniffing, or `Intl.DateTimeFormat`.
    let models = Memo::new(move |_| {
        files.with(|listed| {
            listed.as_ref().map(|res| {
                res.as_ref()
                    .map(|files| build_file_models(files, &from, month, day))
                    .map_err(Clone::clone)
            })
        })
    });
    let shelf_counts = Memo::new(move |_| {
        models.with(|listed| match listed {
            Some(Ok(items)) => ShelfCounts::from_items(items),
            _ => ShelfCounts::default(),
        })
    });
    let month_groups = Memo::new(move |_| {
        let current_shelf = shelf.get();
        models.with(|listed| {
            listed.as_ref().map(|res| {
                res.as_ref()
                    .map(|items| ShelfGroups {
                        shelf: current_shelf,
                        groups: group_by_month(items, current_shelf),
                    })
                    .map_err(Clone::clone)
            })
        })
    });

    let shelves = move || {
        let counts = shelf_counts.get();
        Shelf::ALL
            .into_iter()
            .filter(|of| *of == Shelf::All || counts.get(*of) > 0)
            .map(|of| {
                let count = counts.get(of);
                view! {
                    <button
                        type="button"
                        class="btn small toggle"
                        class:on=move || shelf.get() == of
                        on:click=move |_| shelf.set(of)
                    >
                        {format!("{} {count}", of.label())}
                    </button>
                }
            })
            .collect_view()
    };
    let months = move || match month_groups.get() {
        None => view! { <p class="empty">"Reading the chat…"</p> }.into_any(),
        Some(Err(e)) => view! { <p class="error">{e}</p> }.into_any(),
        Some(Ok(ShelfGroups { groups, .. })) if groups.is_empty() => {
            view! { <p class="empty">"No files here yet."</p> }.into_any()
        }
        Some(Ok(ShelfGroups { shelf, groups })) => groups
            .into_iter()
            .map(|group| {
                let files = if shelf == Shelf::Media {
                    let tiles = group
                        .items
                        .into_iter()
                        .map(|item| file_tile(peer, item, deleted))
                        .collect_view();
                    view! { <div class="file-grid">{tiles}</div> }.into_any()
                } else {
                    let rows = group
                        .items
                        .into_iter()
                        .map(|item| file_row(peer, item, deleted))
                        .collect_view();
                    view! { <div class="file-list">{rows}</div> }.into_any()
                };
                view! {
                    <section>
                        <h3>{group.month}</h3>
                        {files}
                    </section>
                }
            })
            .collect_view()
            .into_any(),
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
                "All files are sent as end-to-end encrypted attachments stored temporarily on the \
                 server, cached locally once downloaded, and deletable from the server by either \
                 peer."
            </p>
            <div class="shelves">{shelves}</div>
            <div class="file-months">{months}</div>
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

fn delete_button(
    target: Option<DeleteTarget>,
    gone: Signal<bool>,
    deleted: RwSignal<HashSet<u64>>,
) -> Option<impl Fn() -> Option<AnyView> + 'static> {
    target.map(|target| {
        move || {
            (!gone.get()).then(|| {
                view! {
                    <DeleteFromServer
                        peer=target.peer
                        index=target.index
                        pointer=target.pointer.clone()
                        deleted
                    />
                }
                .into_any()
            })
        }
    })
}

/// `item` as a tile of the file browser's grid of media: its preview, which for audio, which may
/// have no cover, goes with its name, plus gone/cancelled status and server-delete action matching
/// list rows.
fn file_tile(
    peer: PublicKey,
    item: Arc<FileItemModel>,
    deleted: RwSignal<HashSet<u64>>,
) -> AnyView {
    let state = item.reactive_state(peer, deleted, ui());
    let source = item.source.clone();
    let is_local = item.is_local;
    let failed = item.failed;
    let base_name = item.display_name.clone();
    let tile_name = base_name.clone();
    let title = move || match state.status.get() {
        Some(status) => format!("{base_name} ({status})"),
        None => base_name.clone(),
    };
    let delete = delete_button(item.delete_target.clone(), state.gone, deleted);
    view! {
        <div class="tile" class:gone=move || state.gone.get() || failed>
            <button
                type="button"
                class="tile-open"
                title=title
                on:click=move |_| source.open()
            >
                <MediaThumb source=item.preview_source.clone() sort=item.sort />
                {(item.sort == Sort::Audio).then(|| view! { <span class="tile-name">{tile_name}</span> })}
            </button>
            {move || {
                if state.gone.get() {
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

/// `item` as a row of the file browser's list: its extension, name, size and day, and who sent
/// it; whether it is stored locally or on the server (or gone/cancelled).
fn file_row(peer: PublicKey, item: Arc<FileItemModel>, deleted: RwSignal<HashSet<u64>>) -> AnyView {
    let state = item.reactive_state(peer, deleted, ui());
    let source = item.source.clone();
    let details_base = item.details_base();
    let details = move || match state.status.get() {
        Some(status) => format!("{details_base} · {status}"),
        None => details_base.clone(),
    };
    let display_name = item.display_name.clone();
    let title = display_name.clone();
    // Media shows its preview, the rest its extension.
    let mark = if item.shelf == Shelf::Media {
        view! {
            <span class="row-preview">
                <MediaThumb source=item.preview_source.clone() sort=item.sort />
            </span>
        }
        .into_any()
    } else {
        view! { <span class="file-icon">{item.extension.clone()}</span> }.into_any()
    };
    // An attachment on the server, sent or received, which either peer can delete, until it is.
    let delete = delete_button(item.delete_target.clone(), state.gone, deleted);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{LocalFile, RemoteFile};

    fn local_file_view(
        index: u64,
        at: u64,
        name: &str,
        sort: Sort,
        media: Option<&str>,
    ) -> FileView {
        let peer = [0x11; 32];
        FileView {
            index,
            at,
            outgoing: true,
            deletable: false,
            gone: false,
            failed: false,
            name: name.to_string(),
            size: 2_000,
            sort,
            body: Body::File(LocalFile {
                peer,
                index,
                name: name.to_string(),
                mime: "application/octet-stream".to_string(),
                size: 2_000,
                media: media.map(str::to_string),
                data: None,
            }),
        }
    }

    fn remote_file_view(
        index: u64,
        at: u64,
        name: &str,
        mime: &str,
        size: u64,
        sort: Sort,
        deletable: bool,
    ) -> FileView {
        let peer = [0x22; 32];
        let pointer = content::AttachmentPointer {
            id: vec![0xAA; 16],
            key: vec![0xBB; 32],
            size,
            name: name.to_string(),
            mime: mime.to_string(),
            expires: 0,
        };
        FileView {
            index,
            at,
            outgoing: false,
            deletable,
            gone: false,
            failed: false,
            name: name.to_string(),
            size,
            sort,
            body: Body::Remote(RemoteFile {
                peer,
                index,
                pointer,
                clock: index,
            }),
        }
    }

    fn stub_month(at: u64) -> String {
        match at / 100 {
            3 => "November 2026".to_string(),
            2 => "October 2026".to_string(),
            _ => "September 2026".to_string(),
        }
    }

    fn stub_day(at: u64) -> String {
        format!("Day {}", at % 100)
    }

    #[test]
    fn file_item_model_derives_sanitized_metadata_preview_and_delete_target() {
        let peer = [0x22; 32];
        // Remote deletable image within inline preview cap.
        let remote_img = remote_file_view(
            7,
            315,
            "holiday_\u{202E}gnp.PNG",
            "image/png",
            1_300_000,
            Sort::Image,
            true,
        );
        let model = FileItemModel::from_view(&remote_img, "Alice", &stub_month, &stub_day)
            .expect("valid remote file");
        assert_eq!(model.index, 7);
        assert_eq!(model.shelf, Shelf::Media);
        assert_eq!(model.display_name, "holiday_gnp.PNG");
        assert_eq!(model.extension, "png");
        assert_eq!(model.formatted_size, "1.3 MB");
        assert_eq!(model.day_label, "Day 15");
        assert_eq!(model.month_label, "November 2026");
        assert_eq!(model.details_base(), "1.3 MB · Day 15 · from Alice");
        assert!(!model.is_local);
        assert!(model.preview_source.is_some());
        assert_eq!(
            model.delete_target.as_ref().map(|t| (t.peer, t.index)),
            Some((peer, 7))
        );

        // Non-deletable remote document has no delete target and no media preview.
        let remote_doc = remote_file_view(
            8,
            310,
            "report.pdf",
            "application/pdf",
            512,
            Sort::Document,
            false,
        );
        let doc_model = FileItemModel::from_view(&remote_doc, "Alice", &stub_month, &stub_day)
            .expect("valid doc");
        assert_eq!(doc_model.shelf, Shelf::Documents);
        assert_eq!(doc_model.formatted_size, "512 B");
        assert!(doc_model.preview_source.is_none());
        assert!(doc_model.delete_target.is_none());

        // Local outgoing file marks `is_local`, formats `"sent by you"`, and omits delete target.
        let local_code = local_file_view(9, 205, "main.rs", Sort::Code, None);
        let local_model = FileItemModel::from_view(&local_code, "Alice", &stub_month, &stub_day)
            .expect("valid local file");
        assert!(local_model.is_local);
        assert_eq!(local_model.shelf, Shelf::Code);
        assert_eq!(local_model.extension, "rs");
        assert_eq!(local_model.details_base(), "2 KB · Day 5 · sent by you");
        assert!(local_model.delete_target.is_none());

        // Non-file body yields `None`.
        let mut non_file = local_code;
        non_file.body = Body::Unknown;
        assert!(FileItemModel::from_view(&non_file, "Alice", &stub_month, &stub_day).is_none());
    }

    #[test]
    fn shelf_counts_and_filtering_classify_all_sorts_accurately() {
        let views = vec![
            local_file_view(10, 320, "a.png", Sort::Image, Some("image/png")),
            local_file_view(9, 319, "b.mp4", Sort::Video, Some("video/mp4")),
            local_file_view(8, 318, "c.wav", Sort::Audio, Some("audio/wav")),
            local_file_view(7, 317, "d.md", Sort::Document, None),
            local_file_view(6, 316, "e.rs", Sort::Code, None),
            local_file_view(5, 315, "f.zip", Sort::Archive, None),
            local_file_view(4, 314, "g.bin", Sort::Other, None),
            local_file_view(3, 313, "h.dat", Sort::Unknown, None),
        ];
        let models = build_file_models(&views, "Bob", stub_month, stub_day);
        let counts = ShelfCounts::from_items(&models);
        assert_eq!(counts.get(Shelf::All), 8);
        assert_eq!(counts.get(Shelf::Media), 3);
        assert_eq!(counts.get(Shelf::Documents), 1);
        assert_eq!(counts.get(Shelf::Code), 1);
        assert_eq!(counts.get(Shelf::Archives), 1);
        assert_eq!(counts.get(Shelf::Other), 2);

        let media = group_by_month(&models, Shelf::Media);
        assert_eq!(media.len(), 1);
        let media_indices: Vec<u64> = media[0].items.iter().map(|m| m.index).collect();
        assert_eq!(media_indices, vec![10, 9, 8]);

        let other = group_by_month(&models, Shelf::Other);
        let other_indices: Vec<u64> = other[0].items.iter().map(|m| m.index).collect();
        assert_eq!(other_indices, vec![4, 3]);
    }

    #[test]
    fn month_grouping_preserves_newest_first_order_and_arc_identity_across_shelves() {
        let views = vec![
            local_file_view(50, 325, "nov-code.rs", Sort::Code, None),
            local_file_view(49, 320, "nov-pic.png", Sort::Image, Some("image/png")),
            local_file_view(40, 228, "oct-doc.pdf", Sort::Document, None),
            local_file_view(39, 210, "oct-code.rs", Sort::Code, None),
            local_file_view(38, 205, "oct-code-2.rs", Sort::Code, None),
            local_file_view(12, 115, "sep-zip.zip", Sort::Archive, None),
        ];
        let models = build_file_models(&views, "Carol", stub_month, stub_day);

        let all_groups = group_by_month(&models, Shelf::All);
        assert_eq!(
            all_groups
                .iter()
                .map(|g| (
                    g.month.as_str(),
                    g.items.iter().map(|i| i.index).collect::<Vec<_>>()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("November 2026", vec![50, 49]),
                ("October 2026", vec![40, 39, 38]),
                ("September 2026", vec![12]),
            ]
        );

        let code_groups = group_by_month(&models, Shelf::Code);
        assert_eq!(
            code_groups
                .iter()
                .map(|g| (
                    g.month.as_str(),
                    g.items.iter().map(|i| i.index).collect::<Vec<_>>()
                ))
                .collect::<Vec<_>>(),
            vec![("November 2026", vec![50]), ("October 2026", vec![39, 38])]
        );

        // Switching shelves shares the exact precomputed `Arc<FileItemModel>` allocations.
        assert!(Arc::ptr_eq(
            &all_groups[0].items[0],
            &code_groups[0].items[0]
        ));
        assert!(Arc::ptr_eq(
            &all_groups[1].items[1],
            &code_groups[1].items[0]
        ));
        assert!(Arc::ptr_eq(
            &all_groups[1].items[2],
            &code_groups[1].items[1]
        ));

        // Empty shelf returns zero month sections.
        assert!(group_by_month(&models, Shelf::Other).is_empty());
    }
}
