use std::{
    cell::{Cell, RefCell},
    collections::HashSet,
    time::Duration,
};

use base64::{Engine as _, prelude::BASE64_STANDARD};
use js_sys::Uint8Array;
use leptos::{ev, html, prelude::*, task::spawn_local};
use session::PublicKey;
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{Blob, BlobPropertyBag, IntersectionObserver, IntersectionObserverEntry, Url};

use crate::{
    engine::MEDIA_INLINE_MAX,
    icon::{Icon, icon},
    preview::{self, Sort},
    state::{Attachment, Body, LocalFile, RemoteFile, Streamed},
    util::{sanitize_filename, size_u64},
    workers,
};

use super::{
    common::{act, extension},
    engine, ui,
};

thread_local! {
    /// Monotonic generation for viewer-opening requests so leaving a chat or closing the viewer
    /// cancels any in-flight local file read or attachment stream setup before it opens the viewer.
    static PREVIEW_GEN: Cell<u64> = const { Cell::new(0) };
    /// Every live `blob:` object URL created by the app, tracked so `pagehide` can revoke all of
    /// them synchronously while normal `revoke_blob_url` calls keep the set leak-free.
    static LIVE_BLOB_URLS: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
}

pub(super) fn begin_preview_request() -> u64 {
    PREVIEW_GEN.with(|gen_cell| {
        let next = gen_cell.get().wrapping_add(1);
        gen_cell.set(next);
        next
    })
}

/// Invalidate any pending asynchronous viewer opens (local file reads or stream setups).
pub(crate) fn cancel_pending_previews() {
    let _ = begin_preview_request();
}

/// Record a newly minted `blob:` object URL for synchronous revocation on `pagehide`.
pub(crate) fn register_blob_url(url: &str) {
    if url.starts_with("blob:") {
        LIVE_BLOB_URLS.with(|urls| {
            urls.borrow_mut().insert(url.to_string());
        });
    }
}

/// Revoke `url` (if `blob:`) and remove it from `LIVE_BLOB_URLS` so long sessions never leak
/// tracked entries.
pub(crate) fn revoke_blob_url(url: &str) {
    if !url.starts_with("blob:") {
        return;
    }
    LIVE_BLOB_URLS.with(|urls| {
        urls.borrow_mut().remove(url);
    });
    #[cfg(target_arch = "wasm32")]
    {
        let _ = Url::revoke_object_url(url);
    }
}

/// Synchronously drain and revoke every remaining `blob:` object URL created by the app (invoked
/// inside `pagehide` teardown).
pub(crate) fn revoke_all_blob_urls() {
    let urls: Vec<String> = LIVE_BLOB_URLS.with(|urls| urls.borrow_mut().drain().collect());
    #[cfg(target_arch = "wasm32")]
    for url in urls {
        let _ = Url::revoke_object_url(&url);
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = urls;
}

#[cfg(test)]
pub(crate) fn live_blob_url_count() -> usize {
    LIVE_BLOB_URLS.with(|urls| urls.borrow().len())
}

fn is_preview_current(token: u64, peer: PublicKey) -> bool {
    PREVIEW_GEN.with(|gen_cell| gen_cell.get() == token) && ui().open.get_untracked() == Some(peer)
}

/// Show an attachment in the viewer, fetching it first unless it is kept here.
fn open_attachment(remote: RemoteFile) {
    let (ui, engine) = (ui(), engine());
    let token = begin_preview_request();
    spawn_local(async move {
        // A video or audio plays as it is fetched, if a service worker can stream it.
        let sort = preview::sort(&remote.pointer.name, &remote.pointer.mime, &[]);
        if matches!(sort, Sort::Video | Sort::Audio)
            && let Some(url) = engine
                .stream(remote.peer, remote.index, &remote.pointer, remote.clock)
                .await
        {
            if !is_preview_current(token, remote.peer) {
                engine.end_stream(&url);
                return;
            }
            ui.viewer.set(None);
            ui.opening.set(None);
            let video = sort == Sort::Video;
            ui.streaming.set(Some(Streamed { url, remote, video }));
            return;
        }
        if !is_preview_current(token, remote.peer) {
            return;
        }
        if let Err(e) = engine
            .open_attachment(
                token,
                remote.peer,
                remote.index,
                remote.pointer,
                remote.clock,
            )
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
/// [`STREAM_GRACE`], so that none fails. `data:` URLs are ignored.
pub(super) fn release(url: &str) {
    if url.starts_with("/media/") {
        let url = url.to_string();
        set_timeout(move || engine().end_stream(&url), STREAM_GRACE);
    } else if url.starts_with("blob:") {
        revoke_blob_url(url);
    }
}

/// Stop a `<video>` or `<audio>` element directly via its `NodeRef`, cancelling in-flight range
/// fetches even if the element has already been detached during cleanup.
pub(super) fn stop_media(player: &web_sys::HtmlMediaElement) {
    let _ = player.remove_attribute("src");
    player.load();
}

/// Register an `on_cleanup` hook that stops `node_ref`'s media element using
/// `try_get_untracked().flatten()` so component disposal never panics.
pub(super) fn stop_media_on_cleanup<E>(node_ref: NodeRef<E>)
where
    E: leptos::html::ElementType + 'static,
    E::Output: AsRef<web_sys::HtmlMediaElement> + JsCast + Clone + 'static,
{
    on_cleanup(move || {
        if let Some(el) = node_ref.try_get_untracked().flatten() {
            stop_media(el.as_ref());
        }
    });
}

/// Show `file`, of a chat's history, in the viewer, its bytes read unless they are here.
fn show_file(file: LocalFile) {
    let ui = ui();
    let token = begin_preview_request();
    ui.opening.set(None);
    match file.data {
        Some(attachment) => ui.viewer.set(Some(attachment)),
        None => act(async move {
            let data = engine().file(file.peer, file.index).await?;
            if !is_preview_current(token, file.peer) {
                return Ok(());
            }
            ui.opening.set(None);
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
pub(super) enum Source {
    Local(LocalFile),
    Remote(RemoteFile),
}

impl Source {
    /// The file `body` is, if any.
    pub(super) fn of(body: &Body) -> Option<Self> {
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
    pub(super) fn open(&self) {
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
pub(super) fn inline_media(body: &Body) -> Option<(Source, Sort)> {
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
pub(super) fn file_card(source: Source) -> AnyView {
    let name = sanitize_filename(source.name());
    let extension = extension(&name);
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
pub(super) fn InlineMedia(source: Source, sort: Sort) -> impl IntoView {
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
        if let Some(video) = video_ref.try_get_untracked().flatten() {
            stop_media(&video);
        }
        if let Some(audio) = audio_ref.try_get_untracked().flatten() {
            stop_media(&audio);
        }
    };
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
        if let Some(Some((url, _))) = shown.try_update(Option::take) {
            release(&url);
        }
    });
    let name = sanitize_filename(source.name());
    let caption = format!("{name} · {}", size_u64(source.size()));
    // What it read shows at once; a stream's opens as any attachment does.
    let opened = StoredValue::new(source.clone());
    let open = move |_| match read.get_value() {
        Some(attachment) => {
            let _ = begin_preview_request();
            ui.opening.set(None);
            ui.viewer.set(Some(attachment));
        }
        None => opened.with_value(Source::open),
    };
    // One that turns out not to play, e.g. as it is no video after all, stops playback, releases
    // its blob/stream URL, and falls back to a file card.
    let unplayable = move |_| {
        stop_active();
        if let Some(Some((url, _))) = shown.try_update(Option::take) {
            release(&url);
        }
        failed.set(true);
    };
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

type WatchingObserver = StoredValue<
    Option<(
        IntersectionObserver,
        Closure<dyn FnMut(js_sys::Array, IntersectionObserver)>,
    )>,
    LocalStorage,
>;

fn disconnect_watching(watching: WatchingObserver) {
    if let Some(Some((observer, _))) = watching.try_update_value(Option::take) {
        observer.disconnect();
        let _ = observer.take_records();
    }
}

/// Run `action` once `node` is about to show, as it scrolls into view, so that a long chat or
/// list does not run it for all; not at all if `node` goes first.
fn when_shown(node: NodeRef<html::Div>, action: impl Fn() + Clone + 'static) {
    // What watches it, and what that calls, until it fires or unmounts.
    let watching: WatchingObserver = StoredValue::new_local(None);
    Effect::new(move || {
        disconnect_watching(watching);
        let Some(element) = node.get() else {
            return;
        };
        let action = action.clone();
        let fired = Cell::new(false);
        let seen = Closure::<dyn FnMut(js_sys::Array, IntersectionObserver)>::new(
            move |entries: js_sys::Array, observer: IntersectionObserver| {
                if fired.get() {
                    return;
                }
                let seen = entries.iter().any(|entry| {
                    entry
                        .unchecked_into::<IntersectionObserverEntry>()
                        .is_intersecting()
                });
                if seen {
                    fired.set(true);
                    observer.disconnect();
                    let _ = observer.take_records();
                    action();
                    // Defer dropping this Closure until after the JS callback unwinds.
                    spawn_local(async move { disconnect_watching(watching) });
                }
            },
        );
        let Ok(observer) = IntersectionObserver::new(seen.as_ref().unchecked_ref()) else {
            return;
        };
        observer.observe(&element);
        watching.set_value(Some((observer, seen)));
    });
    on_cleanup(move || disconnect_watching(watching));
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
pub(super) fn MediaThumb(source: Option<Source>, sort: Sort) -> impl IntoView {
    let node = NodeRef::<html::Div>::new();
    let video_ref = NodeRef::<html::Video>::new();
    let preview = RwSignal::new(None::<Preview>);
    let length = RwSignal::new(None::<String>);
    // Gone with the preview: a read that ends after shows nothing, and a URL made then is let
    // go at once.
    let here = StoredValue::new(());
    let probe_stream = StoredValue::new(None::<String>);
    let stop_active = move || {
        if let Some(video) = video_ref.try_get_untracked().flatten() {
            stop_media(&video);
        }
    };
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
                        .stream(remote.peer, remote.index, &remote.pointer, remote.clock)
                        .await
                {
                    if here.try_get_value().is_none() {
                        engine().end_stream(&url);
                        return;
                    }
                    if sort == Sort::Video {
                        show(Preview::Video(url));
                        return;
                    }
                    probe_stream.set_value(Some(url.clone()));
                    let head = engine().stream_head(&url).await;
                    let _ = probe_stream.try_update_value(|slot| {
                        if slot.as_deref() == Some(url.as_str()) {
                            *slot = None;
                        }
                    });
                    engine().end_stream(&url);
                    if here.try_get_value().is_none() {
                        return;
                    }
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
                if here.try_get_value().is_none() {
                    return;
                }
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
        if let Some(url) = probe_stream.try_update_value(Option::take).flatten() {
            engine().end_stream(&url);
        }
        if let Some(Some(Preview::Image(url) | Preview::Video(url))) =
            preview.try_update(Option::take)
        {
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
    let thumb_unplayable = move |_| {
        stop_active();
        if let Some(Some(Preview::Image(url) | Preview::Video(url))) =
            preview.try_update(Option::take)
        {
            release(&url);
        }
        length.set(None);
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
                            on:error=thumb_unplayable
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
pub(super) fn duration(seconds: f64) -> String {
    let seconds = if !seconds.is_finite() || seconds <= 0.0 {
        0
    } else if seconds >= u64::MAX as f64 {
        u64::MAX
    } else {
        seconds.round() as u64
    };
    let (hours, minutes, seconds) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    }
}

/// A blob URL of this origin for `data`, typed `mime`, tracked for synchronous `pagehide`
/// revocation. Returns `None` once `pagehide` or manual lock teardown has begun.
pub(super) fn blob_url(data: &[u8], mime: &str) -> Option<String> {
    if crate::glue::lock_released() || super::is_shutting_down() {
        return None;
    }
    let parts = js_sys::Array::of1(&Uint8Array::from(data));
    let options = BlobPropertyBag::new();
    options.set_type(mime);
    let url = Blob::new_with_u8_array_sequence_and_options(&parts, &options)
        .and_then(|blob| Url::create_object_url_with_blob(&blob))
        .ok()?;
    register_blob_url(&url);
    Some(url)
}

/// A URL that shows the image `data`, of the MIME type `mime`: a blob URL of this origin, but for
/// SVG, which would open from one as a page of this origin, running its scripts; a `data:` URL
/// opens as no page.
pub(super) fn image_url(data: &[u8], mime: &str) -> Option<String> {
    if mime == "image/svg+xml" {
        Some(format!(
            "data:{mime};base64,{}",
            BASE64_STANDARD.encode(data)
        ))
    } else {
        blob_url(data, mime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_blob_urls_do_not_leak_and_drain_on_revoke_all() {
        revoke_all_blob_urls();
        assert_eq!(live_blob_url_count(), 0);

        // Non-blob URLs are ignored.
        register_blob_url("data:image/svg+xml;base64,AAAA");
        register_blob_url("/media/deadbeef");
        assert_eq!(live_blob_url_count(), 0);

        // Normal create + revoke cycles keep the registry at 0 entries (zero leak).
        for i in 0..256u32 {
            let url = format!("blob:https://chat.example/{i}");
            register_blob_url(&url);
            assert_eq!(live_blob_url_count(), 1);
            revoke_blob_url(&url);
            assert_eq!(live_blob_url_count(), 0);
        }

        // Remaining active URLs are drained synchronously on `revoke_all_blob_urls`.
        register_blob_url("blob:https://chat.example/a");
        register_blob_url("blob:https://chat.example/b");
        register_blob_url("blob:https://chat.example/c");
        assert_eq!(live_blob_url_count(), 3);
        revoke_blob_url("blob:https://chat.example/b");
        assert_eq!(live_blob_url_count(), 2);
        revoke_all_blob_urls();
        assert_eq!(live_blob_url_count(), 0);
    }
}
