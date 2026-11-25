use std::{collections::HashSet, sync::Arc, time::Duration};

use base64::{Engine as _, prelude::BASE64_STANDARD};
use e2ee_chat_preview::language;
use leptos::{ev, html, prelude::*, task::spawn_local};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::Url;

use crate::{
    icon::{Icon, icon},
    preview::{self, DiffLine, Kind},
    search::Search,
    state::{Attachment, RemoteFile, Streamed},
    util::{js_error, percent_decode, size, size_u64},
    workers,
};

use super::{
    Toast,
    common::act,
    engine,
    media::{
        begin_preview_request, blob_url, cancel_pending_previews, image_url, release, stop_media,
    },
    pdf::PdfView,
    ui,
};

#[component]
pub(super) fn Viewer() -> impl IntoView {
    let ui = ui();
    let dialog = NodeRef::<html::Dialog>::new();
    let download_anchor = NodeRef::<html::A>::new();
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
        // Only invalidate pending previews when closing an active viewer/opening/stream so a
        // queued native `close` event firing after a new file read starts cannot cancel it.
        let was_open = ui.viewer.with_untracked(Option::is_some)
            || ui.opening.with_untracked(Option::is_some)
            || ui.streaming.with_untracked(Option::is_some);
        if was_open {
            cancel_pending_previews();
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
            Kind::Code { text, language } => view! { <CodeView text language /> }.into_any(),
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
    let on_cancel = move |_: ev::Event| {
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
                                    download(&attachment, download_anchor);
                                } else if let Some(streamed) = ui.streaming.get_untracked() {
                                    download_whole(streamed.remote, downloading, download_anchor);
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
        let name = streamed.remote.pointer.name;
        let on_error = UnsyncCallback::new(unplayable);
        view! { <AudioView url=streamed.url name on_error /> }.into_any()
    }
}

/// Download the attachment `remote` whole, as a stream plays only what it needs of it, unless
/// it is among those `downloading` already, as it is meanwhile.
fn download_whole(
    remote: RemoteFile,
    downloading: RwSignal<HashSet<Vec<u8>>>,
    download_anchor: NodeRef<html::A>,
) {
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
        downloading.try_update(|downloading| {
            downloading.remove(&id);
        });
        if let Some(attachment) = fetched? {
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

#[component]
fn CodeView(text: String, language: Option<&'static str>) -> impl IntoView {
    let Some(lang) = language.and_then(language::of_block) else {
        return view! { <pre class="code"><code data-lang=language>{text}</code></pre> }.into_any();
    };
    let highlighted = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let plain = StoredValue::new(text.clone());
    let here = StoredValue::new(());
    spawn_local(async move {
        let result = workers::highlight(lang, &text).await;
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
            if let (Err(e), true, Some(block)) = (shown, code.is_connected(), code.parent_element())
            {
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

fn diff_view(diff: preview::Diff) -> AnyView {
    let notice = diff.notice();
    view! {
        <div class="diff-preview">
            {notice.map(|notice| view! { <p class="preview-note">{notice}</p> })}
            <pre class="code diff">
                {diff
                    .lines
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
        </div>
    }
    .into_any()
}

/// Save `attachment` as a file. Its blob is typeless, so the browser saves it rather than
/// opening it in this origin.
fn download(attachment: &Attachment, download_anchor: NodeRef<html::A>) {
    let Some(anchor) = download_anchor.try_get_untracked().flatten() else {
        return;
    };
    let Some(url) = blob_url(&attachment.data, "application/octet-stream") else {
        return;
    };
    anchor.set_href(&url);
    anchor.set_download(&attachment.name);
    anchor.click();
    let _ = anchor.remove_attribute("href");
    let _ = anchor.remove_attribute("download");
    set_timeout(
        move || {
            let _ = Url::revoke_object_url(&url);
        },
        Duration::from_secs(60),
    );
}
