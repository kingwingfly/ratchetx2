use std::{collections::HashMap, ops::Range, sync::Arc};

use base64::{Engine as _, prelude::BASE64_STANDARD};
use e2ee_chat_preview::{
    language,
    rpc::{DIAGRAM_SOURCE_MAX, HIGHLIGHT_MAX},
};
use leptos::{ev, html, prelude::*, task::spawn_local};
use session::PublicKey;
use unicode_general_category::{GeneralCategory, get_general_category};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;
use web_sys::ResizeObserver;

use crate::{
    icon::{Icon, icon},
    preview::{self, DiffLine, Kind},
    search::{Search, VirtualLines, VirtualTextIndex},
    state::{Attachment, RemoteFile, Streamed},
    util::{js_error, percent_decode, sanitize_filename, size, size_u64},
    workers,
};

use super::{
    Toast,
    common::{act, download_blob},
    engine,
    media::{
        begin_preview_request, blob_url, cancel_pending_previews, image_url, release, stop_media,
        stop_media_on_cleanup,
    },
    pdf::PdfView,
    ui,
};

/// Maximum number of fenced code / Mermaid blocks enhanced per Markdown document or slide.
pub(super) const MAX_ENHANCE_BLOCKS: usize = 64;

#[derive(Clone)]
struct ViewedPreview {
    attachment: Attachment,
    kind: Kind,
}

impl PartialEq for ViewedPreview {
    fn eq(&self, other: &Self) -> bool {
        self.attachment == other.attachment && self.attachment.mime == other.attachment.mime
    }
}

#[component]
pub(super) fn Viewer() -> impl IntoView {
    let ui = ui();
    let dialog = NodeRef::<html::Dialog>::new();
    let download_anchor = NodeRef::<html::A>::new();
    // Whether it waits for an attachment, which shows how far it got until it opens.
    let waiting = Memo::new(move |_| ui.opening.with(Option::is_some));
    // What it shows, and whether that is text, which can be searched.
    let shown_content = NodeRef::<html::Div>::new();
    // Active virtualized search provider (set by large `DiffView`, `None` for DOM-walked views).
    let virtual_lines = RwSignal::new_local(None::<VirtualLines>);
    let slides_full = RwSignal::new(false);
    let preview_kind = Memo::new(move |_| {
        ui.viewer.with(|attachment| {
            attachment.as_ref().map(|a| ViewedPreview {
                attachment: a.clone(),
                kind: preview::kind(&a.name, &a.mime, &a.data),
            })
        })
    });
    let searchable = Memo::new(move |_| {
        preview_kind.with(|entry| {
            entry.as_ref().is_some_and(|entry| {
                matches!(
                    entry.kind,
                    Kind::Code { .. }
                        | Kind::Markdown { .. }
                        | Kind::Diff(_)
                        | Kind::Table(_)
                        | Kind::Archive(_)
                        | Kind::Cards(_)
                )
            })
        })
    });
    // The streamed attachments being downloaded whole, keyed by `(peer, id)` -> generation token
    // so closing the viewer or switching streams cancels in-flight downloads cleanly.
    let downloading = RwSignal::new(HashMap::<(PublicKey, Vec<u8>), u64>::new());
    let next_download_id = StoredValue::new(0u64);
    let fetching_whole = move || {
        ui.streaming.with(|streamed| {
            streamed.as_ref().is_some_and(|streamed| {
                downloading.with(|downloading| {
                    downloading
                        .contains_key(&(streamed.remote.peer, streamed.remote.pointer.id.clone()))
                })
            })
        })
    };
    let close = move || {
        // Only invalidate pending previews when closing an active viewer/opening/stream so a
        // queued native `close` event firing after a new file read starts cannot cancel it.
        let was_open = ui.viewer.with_untracked(Option::is_some)
            || ui.opening.with_untracked(Option::is_some)
            || ui.streaming.with_untracked(Option::is_some);
        if was_open {
            cancel_pending_previews();
        }
        if slides_full_screen() {
            document().exit_fullscreen();
        }
        slides_full.set(false);
        downloading.update(HashMap::clear);
        ui.viewer.set(None);
        ui.opening.set(None);
        ui.streaming.set(None);
    };
    // Clear `ui.opening` once a file shows, and stop any active stream when something else shows.
    Effect::new(move || {
        let has_viewer = ui.viewer.with(Option::is_some);
        let has_opening = ui.opening.with(Option::is_some);
        if has_viewer && has_opening {
            ui.opening.set(None);
        }
        if (has_viewer || has_opening) && ui.streaming.with_untracked(Option::is_some) {
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
        let Some(ViewedPreview { attachment, kind }) = preview_kind.get() else {
            if let Some(streamed) = ui.streaming.get() {
                return Some(view! { <StreamedView streamed /> }.into_any());
            }
            return waiting.get().then(opening_view);
        };
        let safe_name = sanitize_filename(&attachment.name);
        Some(match kind {
            Kind::Image(mime) => match image_url(&attachment.data, mime) {
                Some(url) => view! { <ImageView url alt=safe_name /> }.into_any(),
                None => no_preview(),
            },
            Kind::Video(mime) => match blob_url(&attachment.data, mime) {
                Some(url) => view! { <VideoView url /> }.into_any(),
                None => no_preview(),
            },
            Kind::Audio(mime) => match blob_url(&attachment.data, mime) {
                Some(url) => view! {
                    <AudioView url name=safe_name data=attachment.data.clone() own_url=true />
                }
                .into_any(),
                None => no_preview(),
            },
            Kind::Pdf => view! { <PdfView data=attachment.data.clone() /> }.into_any(),
            Kind::Markdown { html, source } => {
                view! { <MarkdownView html source slides_full /> }.into_any()
            }
            Kind::Code { text, language } => view! { <CodeView text language /> }.into_any(),
            Kind::Table(table) => table_view(table),
            Kind::Archive(listing) => archive_view(listing),
            Kind::Cards(cards) => cards_view(cards),
            Kind::Diff(diff) => view! { <DiffView diff virtual_lines /> }.into_any(),
            Kind::None => no_preview(),
        })
    };
    let title = move || {
        ui.viewer
            .with(|attachment| {
                attachment
                    .as_ref()
                    .map(|a| format!("{} · {}", sanitize_filename(&a.name), size(a.data.len())))
            })
            .or_else(|| {
                ui.streaming.with(|streamed| {
                    streamed.as_ref().map(|streamed| {
                        let pointer = &streamed.remote.pointer;
                        format!(
                            "{} · {}",
                            sanitize_filename(&pointer.name),
                            size_u64(pointer.size)
                        )
                    })
                })
            })
            .or_else(|| {
                ui.opening.with(|opening| {
                    opening
                        .as_ref()
                        .map(|o| format!("{} · {}", sanitize_filename(&o.name), size_u64(o.size)))
                })
            })
            .unwrap_or_default()
    };
    let on_cancel = move |event: ev::Event| {
        // Exit slide fullscreen first on Escape instead of closing the entire Viewer.
        if slides_full.get_untracked() || slides_full_screen() {
            event.prevent_default();
            if slides_full_screen() {
                document().exit_fullscreen();
            }
            slides_full.set(false);
            return;
        }
        // Invalidate pending previews immediately when native cancellation (e.g. Escape) begins,
        // before the queued `close` event runs, so an in-flight download finishing in that gap
        // cannot reopen the viewer and make `on_close` skip cleanup.
        close();
    };
    let on_close = move |_| {
        // Ignore stale queued native `close` events if the viewer has already reopened.
        if dialog.get_untracked().is_some_and(|d| !d.open()) {
            close();
        }
    };
    view! {
        <dialog class="viewer" node_ref=dialog on:cancel=on_cancel on:close=on_close>
            <div class="viewer-bar">
                <span>{title}</span>
                <div>
                    <Show when=move || searchable.get()>
                        <Search content=shown_content virtual_lines />
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
                                    download(&attachment, download_anchor);
                                } else if let Some(streamed) = ui.streaming.get_untracked() {
                                    download_whole(
                                        streamed.remote,
                                        downloading,
                                        next_download_id,
                                        download_anchor,
                                    );
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
        <a hidden node_ref=download_anchor></a>
    }
}

/// An image shown in the viewer, revoking its blob URL on cleanup (`data:` URLs are ignored).
#[component]
fn ImageView(url: String, alt: String) -> impl IntoView {
    let owned = url.clone();
    on_cleanup(move || release(&owned));
    view! {
        <div class="media">
            <img src=url alt=alt />
        </div>
    }
}

/// A video shown in the viewer, stopping playback via its own `NodeRef` before revoking its blob URL.
#[component]
fn VideoView(url: String) -> impl IntoView {
    let video_ref = NodeRef::<html::Video>::new();
    let owned = url.clone();
    on_cleanup(move || {
        if let Some(video) = video_ref.try_get_untracked().flatten() {
            stop_media(&video);
        }
        release(&owned);
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
    stop_media_on_cleanup(video_ref);
    let unplayable = {
        let (url, remote) = (streamed.url.clone(), streamed.remote.clone());
        move |_: ev::ErrorEvent| {
            // Unless the viewer went on or the chat closed meanwhile.
            let shown = ui()
                .streaming
                .with_untracked(|shown| shown.as_ref().is_some_and(|shown| shown.url == url));
            if shown && ui().open.get_untracked() == Some(remote.peer) {
                let remote = remote.clone();
                let token = begin_preview_request();
                act(async move {
                    engine()
                        .open_attachment(
                            token,
                            remote.peer,
                            remote.index,
                            remote.pointer,
                            remote.clock,
                        )
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
        let name = sanitize_filename(&streamed.remote.pointer.name);
        let on_error = UnsyncCallback::new(unplayable);
        view! { <AudioView url=streamed.url name on_error /> }.into_any()
    }
}

/// Download the attachment `remote` whole, as a stream plays only what it needs of it, unless
/// it is among those `downloading` already. Cancels cleanly if the viewer closes, switches streams,
/// or the contact is deleted.
fn download_whole(
    remote: RemoteFile,
    downloading: RwSignal<HashMap<(PublicKey, Vec<u8>), u64>>,
    next_download_id: StoredValue<u64>,
    download_anchor: NodeRef<html::A>,
) {
    let key = (remote.peer, remote.pointer.id.clone());
    if downloading.with_untracked(|downloading| downloading.contains_key(&key)) {
        return;
    }
    let dl_id = next_download_id.get_value().wrapping_add(1).max(1);
    next_download_id.set_value(dl_id);
    downloading.update(|downloading| {
        downloading.insert(key.clone(), dl_id);
    });
    let ui = ui();
    let display_name = sanitize_filename(&remote.pointer.name);
    act(async move {
        ui.notify(format!("Downloading {display_name}…"));
        let peer = remote.peer;
        let id = remote.pointer.id.clone();
        let still_active = {
            let key = key.clone();
            move || {
                downloading
                    .try_with_untracked(|map| map.get(&key) == Some(&dl_id))
                    .unwrap_or(false)
                    && ui
                        .contacts
                        .with_untracked(|contacts| contacts.iter().any(|c| c.peer == peer))
                    && ui.streaming.with_untracked(|streamed| {
                        streamed.as_ref().is_some_and(|streamed| {
                            streamed.remote.peer == peer && streamed.remote.pointer.id == id
                        })
                    })
            }
        };
        let fetched = engine()
            .media(
                remote.peer,
                remote.index,
                remote.pointer,
                remote.clock,
                &still_active,
            )
            .await;
        let should_save = still_active();
        let _ = downloading.try_update(|downloading| {
            if downloading.get(&key) == Some(&dl_id) {
                downloading.remove(&key);
            }
        });
        if should_save && let Some(attachment) = fetched? {
            download(&attachment, download_anchor);
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
    /// Revoke `url` on cleanup after stopping playback (true for blob URLs owned by this view).
    #[prop(default = false)]
    own_url: bool,
) -> impl IntoView {
    let audio_ref = NodeRef::<html::Audio>::new();
    let owned = url.clone();
    on_cleanup(move || {
        if let Some(audio) = audio_ref.try_get_untracked().flatten() {
            stop_media(&audio);
        }
        if own_url {
            release(&owned);
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

#[component]
fn CodeView(text: String, language: Option<&'static str>) -> impl IntoView {
    let Some(lang) = language
        .filter(|_| text.len() <= HIGHLIGHT_MAX)
        .and_then(language::of_block)
    else {
        return view! { <pre class="code"><code data-lang=language>{text}</code></pre> }.into_any();
    };
    let highlighted = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let plain = StoredValue::new(text.clone());
    let here = StoredValue::new(());
    spawn_local(async move {
        let result = match workers::highlight(lang, &text).await {
            Ok(html) => match preview::validate_highlight_html(&html) {
                Ok(()) => Ok(html),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        if here.try_get_value().is_some() {
            match result {
                Ok(html) => highlighted.set(Some(html)),
                Err(e) => error.set(Some(e)),
            }
        }
    });
    view! {
        <pre class="code" data-error=move || error.get()>
            {move || match highlighted.get() {
                Some(html) => view! { <code data-lang=language inner_html=html></code> }.into_any(),
                None => view! { <code data-lang=language>{plain.get_value()}</code> }.into_any(),
            }}
        </pre>
    }
    .into_any()
}

/// Resolve a same-document `#fragment` href into `(raw, percent_decoded)` target ID candidates,
/// matching native HTML fragment lookup without mutating `location.hash`.
pub(super) fn preview_fragment_candidates(href: &str) -> Option<(String, Option<String>)> {
    let raw = href.strip_prefix('#')?;
    if raw.is_empty() {
        return Some((String::new(), None));
    }
    let decoded = percent_decode(raw).filter(|decoded| decoded != raw);
    Some((raw.to_string(), decoded))
}

/// Highlight fenced code and draw diagrams inside a sanitized Markdown document or slide, and
/// scroll/focus same-document `#…` anchor links (such as footnotes) inside the preview without
/// mutating browser history or `location.hash`.
#[component]
fn Enhanced(children: Children) -> impl IntoView {
    let node = NodeRef::<html::Div>::new();
    Effect::new(move || {
        if let Some(element) = node.get() {
            enhance(&element);
        }
    });
    let on_click = move |event: ev::MouseEvent| {
        let Some(target) = event
            .target()
            .and_then(|target| target.dyn_into::<web_sys::Element>().ok())
        else {
            return;
        };
        let Ok(Some(anchor)) = target.closest("a[href]") else {
            return;
        };
        let Some(href) = anchor.get_attribute("href") else {
            return;
        };
        let Some((raw_id, decoded_id)) = preview_fragment_candidates(&href) else {
            return;
        };
        event.prevent_default();
        if raw_id.is_empty() {
            return;
        }
        if let Some(container) = node.get_untracked() {
            let candidates = select(&container, "[id]");
            let matched = candidates
                .iter()
                .find(|el| el.get_attribute("id").as_deref() == Some(raw_id.as_str()))
                .or_else(|| {
                    let decoded = decoded_id.as_deref()?;
                    candidates
                        .iter()
                        .find(|el| el.get_attribute("id").as_deref() == Some(decoded))
                });
            if let Some(element) = matched {
                element.scroll_into_view();
                // Move keyboard focus to the target (matching native fragment navigation) without
                // altering Tab order or mutating the URL.
                if let Ok(html_el) = element.clone().dyn_into::<web_sys::HtmlElement>() {
                    if !html_el.has_attribute("tabindex") {
                        let _ = html_el.set_attribute("tabindex", "-1");
                    }
                    let _ = html_el.focus();
                }
            }
        }
    };
    view! {
        <div class="enhanced" node_ref=node on:click=on_click>
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

/// Enhancement decision for a single `pre > code[data-lang]` block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EnhancePlan {
    Diagram,
    Highlight(&'static language::Language),
    Skip(&'static str),
}

/// Decide whether a fenced block with language tag `info` and `byte_len` bytes should be sent to
/// a worker, given `scheduled` blocks already queued in this document.
pub(super) fn plan_enhance_block(
    info: &str,
    byte_len: usize,
    scheduled: usize,
) -> Option<EnhancePlan> {
    if info.eq_ignore_ascii_case("mermaid") {
        if scheduled >= MAX_ENHANCE_BLOCKS {
            return Some(EnhancePlan::Skip("too many enhanced blocks in document"));
        }
        if byte_len > DIAGRAM_SOURCE_MAX {
            return Some(EnhancePlan::Skip("diagram source is too large"));
        }
        return Some(EnhancePlan::Diagram);
    }
    let language = language::of_block(info)?;
    if scheduled >= MAX_ENHANCE_BLOCKS {
        return Some(EnhancePlan::Skip("too many enhanced blocks in document"));
    }
    if byte_len > HIGHLIGHT_MAX {
        return Some(EnhancePlan::Skip("code block is too large to highlight"));
    }
    Some(EnhancePlan::Highlight(language))
}

/// Highlight `pre > code[data-lang]` blocks and draw Mermaid diagrams as images sequentially via a
/// bounded queue (up to [`MAX_ENHANCE_BLOCKS`] per document, enforcing [`HIGHLIGHT_MAX`] and
/// [`DIAGRAM_SOURCE_MAX`]). Validated HTML is required before setting `inner_html`; blocks that
/// fail or exceed limits stay plain text with `data-error`.
fn enhance(element: &web_sys::Element) {
    let mut queue = Vec::new();
    for code in select(element, "pre > code[data-lang]") {
        let info = code.get_attribute("data-lang").unwrap_or_default();
        let text = code.text_content().unwrap_or_default();
        match plan_enhance_block(&info, text.len(), queue.len()) {
            Some(EnhancePlan::Skip(reason)) => {
                if let Some(block) = code.parent_element() {
                    let _ = block.set_attribute("data-error", reason);
                }
            }
            Some(plan) => queue.push((code, plan, text)),
            None => {}
        }
    }
    if queue.is_empty() {
        return;
    }
    let container = element.clone();
    spawn_local(async move {
        for (code, plan, text) in queue {
            if !container.is_connected() {
                break;
            }
            if !code.is_connected() {
                continue;
            }
            let shown = match plan {
                EnhancePlan::Diagram => workers::diagram(&text).await.and_then(|svg| {
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
                }),
                EnhancePlan::Highlight(language) => {
                    workers::highlight(language, &text).await.and_then(|html| {
                        preview::validate_highlight_html(&html)?;
                        if code.is_connected() {
                            code.set_inner_html(&html);
                        }
                        Ok(())
                    })
                }
                EnhancePlan::Skip(_) => Ok(()),
            };
            if let (Err(e), true, Some(block)) = (shown, code.is_connected(), code.parent_element())
            {
                let _ = block.set_attribute("data-error", &e);
            }
        }
    });
}

/// A Markdown file, as a document, or as reveal.js slides.
#[component]
fn MarkdownView(html: String, source: String, slides_full: RwSignal<bool>) -> impl IntoView {
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
                view! { <Slides source=source.clone() full=slides_full /> }.into_any()
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

/// Invoke `element.requestFullscreen()` and return its Promise if the browser returns one, so
/// rejected fullscreen requests are caught cleanly and fall back to window fullscreen.
fn request_fullscreen_promise(
    element: &web_sys::Element,
) -> Result<Option<js_sys::Promise>, JsValue> {
    let method = js_sys::Reflect::get(element, &JsValue::from_str("requestFullscreen"))?
        .dyn_into::<js_sys::Function>()?;
    let result = method.call0(element)?;
    if result.is_undefined() || result.is_null() {
        Ok(None)
    } else {
        Ok(result.dyn_into::<js_sys::Promise>().ok())
    }
}

/// reveal.js slides: the arrow keys go to the next column, left and right, and to the next slide
/// in it, up and down. F shows them full screen, the browser's, or, where a page may not have it,
/// as on iPhones, the window's, scaled as reveal.js scales them; F or Esc leaves it.
#[component]
fn Slides(source: String, full: RwSignal<bool>) -> impl IntoView {
    let deck = StoredValue::new(preview::slides(&source));
    let position = RwSignal::new((0, 0));
    let node = NodeRef::<html::Div>::new();
    let here = StoredValue::new(());
    let toggle = move || {
        let document = document();
        if slides_full_screen() {
            document.exit_fullscreen();
        } else if full.get_untracked() {
            full.set(false);
        } else if document.fullscreen_enabled()
            && let Some(slides) = node.get_untracked()
        {
            match request_fullscreen_promise(&slides) {
                Ok(Some(promise)) => {
                    spawn_local(async move {
                        if JsFuture::from(promise).await.is_err() && here.try_get_value().is_some()
                        {
                            full.set(true);
                        }
                    });
                }
                Ok(None) => {}
                Err(_) => full.set(true),
            }
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
        let _ = full.try_set(false);
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

/// Strip control and Unicode format (including BiDi override) characters from an archive entry
/// path for safe display while preserving directory separators.
pub(super) fn sanitize_archive_path(path: &str) -> String {
    path.chars()
        .filter(|&ch| {
            !matches!(
                get_general_category(ch),
                GeneralCategory::Control | GeneralCategory::Format
            )
        })
        .collect()
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
                        let path = sanitize_archive_path(&entry.path);
                        let badge = entry.note.map(|tag| {
                            let safe_tag = sanitize_archive_path(&tag);
                            let tag_title = safe_tag.clone();
                            view! {
                                " "
                                <span class="sec-badge classical" title=tag_title>
                                    {safe_tag}
                                </span>
                            }
                        });
                        view! {
                            <li class:directory=entry.directory>
                                <span>{path}{badge}</span>
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

fn cards_view(cards: preview::Cards) -> AnyView {
    if cards.items.is_empty() {
        return no_preview();
    }
    let notice = cards.notice();
    view! {
        <div class="cards">
            {notice.map(|notice| view! { <p class="preview-note">{notice}</p> })}
            {cards
                .items
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

/// Diffs with more than this many lines switch from flat `<pre>` rendering to a fixed-line-height
/// virtualized viewport so up to `DIFF_LINES_MAX` (20,000) lines mount without freezing the UI.
const VIRTUAL_THRESHOLD: usize = 500;
/// Extra rows mounted above and below the visible band in a virtualized [`DiffView`].
const OVERSCAN: usize = 40;
/// Fallback row height in CSS pixels matching `--diff-line-height` until the DOM probe measures.
const DEFAULT_DIFF_LINE_HEIGHT: f64 = 22.0;

fn diff_line_class(kind: DiffLine) -> &'static str {
    match kind {
        DiffLine::File => "diff-file",
        DiffLine::Hunk => "diff-hunk",
        DiffLine::Added => "diff-added",
        DiffLine::Removed => "diff-removed",
        DiffLine::Context => "diff-context",
    }
}

/// Compute the half-open slice `start..end` of diff rows to mount for a list of `total_lines`
/// fixed-height rows, clamped to `0..total_lines` with `overscan` rows on either side.
fn virtual_window(
    total_lines: usize,
    scroll_top: f64,
    viewport_height: f64,
    line_height: f64,
    overscan: usize,
) -> Range<usize> {
    if total_lines == 0 {
        return 0..0;
    }
    let lh = if line_height.is_finite() && line_height > 0.0 {
        line_height
    } else {
        DEFAULT_DIFF_LINE_HEIGHT
    };
    let scroll = if scroll_top.is_finite() && scroll_top > 0.0 {
        scroll_top
    } else {
        0.0
    };
    let height = if viewport_height.is_finite() && viewport_height > 0.0 {
        viewport_height
    } else {
        0.0
    };
    let visible_start = ((scroll / lh).floor() as usize).min(total_lines);
    let visible_end = if height > 0.0 {
        (((scroll + height) / lh).ceil() as usize).min(total_lines)
    } else {
        visible_start
    };
    let start = visible_start.saturating_sub(overscan).min(total_lines);
    let end = visible_end.saturating_add(overscan).min(total_lines);
    start..end
}

/// Compute the viewport `scrollTop` that vertically centers `line_idx` inside a fixed-height
/// virtualized viewport whose line `0` starts at `top_offset` CSS pixels from the top of the
/// scrollable area.
fn scroll_top_for_line(
    line_idx: usize,
    line_height: f64,
    viewport_height: f64,
    top_offset: f64,
) -> f64 {
    let lh = if line_height.is_finite() && line_height > 0.0 {
        line_height
    } else {
        DEFAULT_DIFF_LINE_HEIGHT
    };
    let vh = if viewport_height.is_finite() && viewport_height > 0.0 {
        viewport_height
    } else {
        0.0
    };
    let offset = if top_offset.is_finite() && top_offset > 0.0 {
        top_offset
    } else {
        0.0
    };
    let center = offset + (line_idx as f64) * lh + lh * 0.5;
    (center - vh * 0.5).max(0.0)
}

/// RAII wrapper keeping a `ResizeObserver` and its JS callback alive until dropped.
struct DiffResizeGuard {
    observer: ResizeObserver,
    _callback: Closure<dyn FnMut(js_sys::Array)>,
}

impl Drop for DiffResizeGuard {
    fn drop(&mut self) {
        self.observer.disconnect();
    }
}

fn measure_diff_line_height(probe_ref: NodeRef<html::Span>, fallback: f64) -> f64 {
    probe_ref
        .try_get_untracked()
        .flatten()
        .map(|el| el.get_bounding_client_rect().height())
        .filter(|h| h.is_finite() && *h > 1.0)
        .unwrap_or(fallback)
}

fn measure_diff_top_offset(viewport: &web_sys::Element, spacer_ref: NodeRef<html::Div>) -> f64 {
    let Some(spacer) = spacer_ref.try_get_untracked().flatten() else {
        return 0.0;
    };
    let offset = spacer.get_bounding_client_rect().top()
        - viewport.get_bounding_client_rect().top()
        + f64::from(viewport.scroll_top());
    if offset.is_finite() && offset >= 0.0 {
        offset
    } else {
        0.0
    }
}

#[component]
fn DiffView(
    diff: preview::Diff,
    virtual_lines: RwSignal<Option<VirtualLines>, LocalStorage>,
) -> impl IntoView {
    let notice = diff.notice();
    if diff.lines.len() <= VIRTUAL_THRESHOLD {
        return view! {
            <div class="diff-preview">
                {notice.map(|notice| view! { <p class="preview-note">{notice}</p> })}
                <pre class="code diff">
                    {diff
                        .lines
                        .into_iter()
                        .map(|(kind, line)| {
                            view! { <span class=diff_line_class(kind)>{line}</span> }
                        })
                        .collect_view()}
                </pre>
            </div>
        }
        .into_any();
    }

    let lines = Arc::new(diff.lines);
    let total_lines = lines.len();
    let viewport_ref = NodeRef::<html::Div>::new();
    let spacer_ref = NodeRef::<html::Div>::new();
    let window_ref = NodeRef::<html::Div>::new();
    let probe_ref = NodeRef::<html::Span>::new();
    let line_height = RwSignal::new(DEFAULT_DIFF_LINE_HEIGHT);
    let initial_window =
        virtual_window(total_lines, 0.0, 800.0, DEFAULT_DIFF_LINE_HEIGHT, OVERSCAN);
    let window = RwSignal::new(initial_window);
    let resize_guard = StoredValue::new_local(None::<DiffResizeGuard>);
    let here = StoredValue::new(());

    let sync_viewport = move || {
        let Some(viewport) = viewport_ref.try_get_untracked().flatten() else {
            return;
        };
        let viewport_el: &web_sys::Element = viewport.as_ref();
        let lh = measure_diff_line_height(probe_ref, line_height.get_untracked());
        if (line_height.get_untracked() - lh).abs() > 0.01 {
            line_height.set(lh);
        }
        let vh = f64::from(viewport_el.client_height());
        if vh <= 0.0 {
            return;
        }
        let top_offset = measure_diff_top_offset(viewport_el, spacer_ref);
        let content_scroll = (f64::from(viewport_el.scroll_top()) - top_offset).max(0.0);
        let next = virtual_window(total_lines, content_scroll, vh, lh, OVERSCAN);
        if window.with_untracked(|cur| *cur != next) {
            window.set(next);
        }
    };

    let scroll_to_line = move |target_line: usize| {
        let Some(viewport) = viewport_ref.try_get_untracked().flatten() else {
            return;
        };
        let viewport_el: &web_sys::Element = viewport.as_ref();
        let lh = measure_diff_line_height(probe_ref, line_height.get_untracked());
        if (line_height.get_untracked() - lh).abs() > 0.01 {
            line_height.set(lh);
        }
        let top_offset = measure_diff_top_offset(viewport_el, spacer_ref);
        let vh = f64::from(viewport_el.client_height());
        let clamped_line = target_line.min(total_lines.saturating_sub(1));
        let target_scroll = scroll_top_for_line(clamped_line, lh, vh, top_offset);
        viewport_el.set_scroll_top(target_scroll.round() as i32);
        let actual_scroll = f64::from(viewport_el.scroll_top());
        let mut next = virtual_window(
            total_lines,
            (actual_scroll - top_offset).max(0.0),
            vh,
            lh,
            OVERSCAN,
        );
        if total_lines > 0 && !next.contains(&clamped_line) {
            next = virtual_window(
                total_lines,
                (target_scroll - top_offset).max(0.0),
                vh,
                lh,
                OVERSCAN,
            );
        }
        if window.with_untracked(|cur| *cur != next) {
            window.set(next);
        }
    };

    let search_lines = Arc::clone(&lines);
    let provider = VirtualLines::new(
        move || VirtualTextIndex::from_lines(search_lines.iter().map(|(_, line)| line.as_str())),
        viewport_ref,
        window_ref,
        window,
        scroll_to_line,
    );
    let provider_id = provider.id();
    virtual_lines.set(Some(provider));

    Effect::new(move || {
        resize_guard.set_value(None);
        let Some(viewport) = viewport_ref.get() else {
            return;
        };
        let on_resize = Closure::<dyn FnMut(js_sys::Array)>::new(move |_entries: js_sys::Array| {
            sync_viewport();
        });
        if let Ok(observer) = ResizeObserver::new(on_resize.as_ref().unchecked_ref()) {
            observer.observe(&viewport);
            resize_guard.set_value(Some(DiffResizeGuard {
                observer,
                _callback: on_resize,
            }));
        }
        sync_viewport();
        if viewport.client_height() <= 0 {
            request_animation_frame(move || {
                if here.try_get_value().is_some() {
                    sync_viewport();
                }
            });
        }
    });

    let window_resizes = window_event_listener(ev::resize, move |_| sync_viewport());

    on_cleanup(move || {
        window_resizes.remove();
        resize_guard.try_set_value(None);
        let _ = virtual_lines.try_update(|slot| {
            if slot.as_ref().is_some_and(|v| v.id() == provider_id) {
                *slot = None;
            }
        });
    });

    let total_height = move || format!("{}px", total_lines as f64 * line_height.get());
    let offset_y = move || {
        format!(
            "translateY({}px)",
            window.get().start as f64 * line_height.get()
        )
    };
    let render_lines = Arc::clone(&lines);

    view! {
        <div class="diff-preview virtual">
            {notice.map(|notice| view! { <p class="preview-note">{notice}</p> })}
            <div class="diff-viewport" node_ref=viewport_ref on:scroll=move |_| sync_viewport()>
                <pre class="code diff diff-virtual">
                    <span class="diff-probe" aria-hidden="true" node_ref=probe_ref></span>
                    <div class="diff-spacer" node_ref=spacer_ref style:height=total_height>
                        <div class="diff-window" node_ref=window_ref style:transform=offset_y>
                            <For
                                each=move || window.get()
                                key=|&idx| idx
                                children=move |idx| {
                                    let (kind, line) = &render_lines[idx];
                                    view! {
                                        <span class=diff_line_class(*kind) data-line=idx.to_string()>
                                            {line.clone()}
                                        </span>
                                    }
                                }
                            />
                        </div>
                    </div>
                </pre>
            </div>
        </div>
    }
    .into_any()
}

/// Save `attachment` as a file. Its blob is typeless, so the browser saves it rather than
/// opening it in this origin, and its filename is sanitized against BiDi/path spoofing.
fn download(attachment: &Attachment, download_anchor: NodeRef<html::A>) {
    let _ = download_blob(
        &attachment.data,
        "application/octet-stream",
        &attachment.name,
        download_anchor,
    );
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_DIFF_LINE_HEIGHT, OVERSCAN, VIRTUAL_THRESHOLD, scroll_top_for_line, virtual_window,
    };

    #[test]
    fn virtual_window_handles_empty_and_small_inputs() {
        assert_eq!(virtual_window(0, 0.0, 600.0, 22.0, OVERSCAN), 0..0);
        assert_eq!(virtual_window(0, 500.0, 600.0, 22.0, OVERSCAN), 0..0);
        assert_eq!(virtual_window(1, 0.0, 600.0, 22.0, OVERSCAN), 0..1);
        assert_eq!(virtual_window(25, 0.0, 600.0, 22.0, OVERSCAN), 0..25);
    }

    #[test]
    fn virtual_window_clamps_at_start_and_end_with_overscan_40() {
        assert_eq!(OVERSCAN, 40);
        assert_eq!(VIRTUAL_THRESHOLD, 500);

        // Top of a 20,000-line diff: 20 visible rows (440 / 22) + 40 overscan below, clamped at 0.
        assert_eq!(virtual_window(20_000, 0.0, 440.0, 22.0, OVERSCAN), 0..60);

        // Near top (line 20 visible): 40 overscan above clamps to 0.
        assert_eq!(virtual_window(20_000, 440.0, 440.0, 22.0, OVERSCAN), 0..80);

        // Middle (line 15,000 visible): 20 visible + 40 above + 40 below.
        let scroll_15k = 15_000.0 * 22.0;
        assert_eq!(
            virtual_window(20_000, scroll_15k, 440.0, 22.0, OVERSCAN),
            14_960..15_060
        );

        // Bottom (last 20 lines visible): 40 overscan below clamps to 20,000.
        let scroll_end = 19_980.0 * 22.0;
        assert_eq!(
            virtual_window(20_000, scroll_end, 440.0, 22.0, OVERSCAN),
            19_940..20_000
        );

        // Exact partial row boundary: 440.1px exposes 21 rows (0..21) + 40 overscan = 0..61.
        assert_eq!(virtual_window(20_000, 0.0, 440.1, 22.0, OVERSCAN), 0..61);
    }

    #[test]
    fn virtual_window_clamps_negative_overscroll_and_invalid_dimensions() {
        // Negative rubber-band scrollTop clamps to 0.
        assert_eq!(virtual_window(1_000, -120.0, 440.0, 22.0, OVERSCAN), 0..60);

        // Scroll past document end still returns a valid clamped range.
        assert_eq!(
            virtual_window(1_000, 1_000_000.0, 440.0, 22.0, OVERSCAN),
            960..1_000
        );

        // Zero viewport height (pre-layout) mounts overscan around the scroll anchor.
        assert_eq!(virtual_window(1_000, 0.0, 0.0, 22.0, OVERSCAN), 0..40);
        assert_eq!(virtual_window(1_000, 0.0, 0.0, 22.0, 0), 0..0);

        // Non-finite or zero line height falls back cleanly to DEFAULT_DIFF_LINE_HEIGHT.
        let expected = virtual_window(1_000, 0.0, 440.0, DEFAULT_DIFF_LINE_HEIGHT, OVERSCAN);
        assert_eq!(virtual_window(1_000, 0.0, 440.0, 0.0, OVERSCAN), expected);
        assert_eq!(virtual_window(1_000, 0.0, 440.0, -5.0, OVERSCAN), expected);
        assert_eq!(
            virtual_window(1_000, 0.0, 440.0, f64::NAN, OVERSCAN),
            expected
        );
        assert_eq!(
            virtual_window(1_000, f64::NAN, f64::INFINITY, f64::INFINITY, OVERSCAN),
            0..40
        );
    }

    #[test]
    fn scroll_top_for_line_centers_target_and_clamps_top() {
        // Line 0 near top clamps to 0 rather than going negative.
        assert_eq!(scroll_top_for_line(0, 22.0, 600.0, 24.0), 0.0);

        // Line 15,000 centered in a 600px viewport with 24px top padding.
        let target = scroll_top_for_line(15_000, 22.0, 600.0, 24.0);
        assert_eq!(target, 24.0 + 15_000.0 * 22.0 + 11.0 - 300.0);

        // Invalid dimensions fall back safely without NaN.
        let fallback = scroll_top_for_line(100, 0.0, -10.0, f64::NAN);
        assert!(fallback.is_finite());
        assert_eq!(
            fallback,
            100.0 * DEFAULT_DIFF_LINE_HEIGHT + DEFAULT_DIFF_LINE_HEIGHT * 0.5
        );
    }
}
