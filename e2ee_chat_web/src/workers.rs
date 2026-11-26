//! The previews' web workers, of [`e2ee_chat_preview`], each started when a preview first needs
//! it: PDF pages, Mermaid diagrams, Markdown/MathML/slides, audio tags, search, and code
//! highlighted by four workers, a group of languages each. Calls to each worker are queued FIFO
//! client-side so only the active head-of-line call arms its [`TIMEOUT`] guard; a stalled or
//! failed worker is terminated, failing its pending calls, and the next call starts a fresh one.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};

use e2ee_chat_preview::{
    Worker,
    audio::Tags,
    language::Language,
    rpc::{
        AudioTagsCall, CodeHighlightCall, DiagramSvgCall, MarkdownCall, PdfCloseCall, PdfOpenCall,
        PdfRenderCall, RpcCall, SearchFindCall, SlidesCall, WirePayload, WorkerEvent,
        encode_request_frame,
    },
};
use futures_util::lock::Mutex;
use js_sys::{Function, Promise};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{ImageData, MessageEvent};

use crate::util::{EventListener, Timeout, js_error};

/// How long an active head-of-line call or worker start may take, in milliseconds.
const TIMEOUT: i32 = 60_000;
/// Call ID reserved for the worker's initial `READY` handshake.
const READY_ID: u32 = 0;
/// CSS selector for the build-injected worker script manifest `<meta>` tag.
const WORKER_MANIFEST_SELECTOR: &str = r#"meta[name="e2ee-worker-manifest"]"#;
/// Actionable notice surfaced when a worker fails before its initial `READY` handshake while the
/// browser is online (typically because a newer deploy replaced hashed worker assets).
const DEPLOY_SKEW_NOTICE: &str =
    "A newer version of this app was deployed — reload to open this preview";

#[cfg(all(test, target_arch = "wasm32"))]
thread_local! {
    static TEST_TIMEOUT_MS: Cell<Option<i32>> = const { Cell::new(None) };
    static TEST_ONLINE: Cell<Option<bool>> = const { Cell::new(None) };
    static TEST_SCRIPTS: RefCell<HashMap<Worker, std::collections::VecDeque<String>>> =
        RefCell::new(HashMap::new());
}

fn timeout_ms() -> i32 {
    #[cfg(all(test, target_arch = "wasm32"))]
    if let Some(ms) = TEST_TIMEOUT_MS.with(Cell::get) {
        return ms;
    }
    TIMEOUT
}

fn is_online() -> bool {
    #[cfg(all(test, target_arch = "wasm32"))]
    if let Some(online) = TEST_ONLINE.with(Cell::get) {
        return online;
    }
    web_sys::window().is_none_or(|window| window.navigator().on_line())
}

fn parse_worker_manifest(json: &str) -> Result<HashMap<String, String>, String> {
    let manifest: HashMap<String, String> =
        serde_json::from_str(json).map_err(|e| format!("invalid worker manifest: {e}"))?;
    if manifest.is_empty() {
        return Err("empty worker manifest".to_string());
    }
    for (key, url) in &manifest {
        if key.is_empty() || url.trim().is_empty() {
            return Err("invalid worker manifest entry".to_string());
        }
    }
    Ok(manifest)
}

fn load_worker_manifest() -> Result<HashMap<String, String>, String> {
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or_else(|| "worker manifest unavailable".to_string())?;
    let meta = document
        .query_selector(WORKER_MANIFEST_SELECTOR)
        .map_err(js_error)?
        .ok_or_else(|| "missing worker manifest".to_string())?;
    let content = meta
        .get_attribute("content")
        .ok_or_else(|| "missing worker manifest content".to_string())?;
    parse_worker_manifest(&content)
}

/// Resolve a logical worker key (e.g. `"pdf"`, `"diagram"`, `"vault_kdf"`) to its content-hashed
/// loader script URL from `<meta name="e2ee-worker-manifest">`, caching the parsed manifest once.
pub(crate) fn resolve_worker_script(key: &str) -> Result<String, String> {
    WORKER_MANIFEST.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.is_none() {
            *cache = Some(load_worker_manifest()?);
        }
        cache
            .as_ref()
            .and_then(|manifest| manifest.get(key))
            .cloned()
            .ok_or_else(|| format!("missing worker manifest entry for {key}"))
    })
}

fn worker_script(kind: Worker) -> Result<String, String> {
    #[cfg(all(test, target_arch = "wasm32"))]
    if let Some(url) = TEST_SCRIPTS.with(|scripts| {
        let mut scripts = scripts.borrow_mut();
        let queue = scripts.get_mut(&kind)?;
        if queue.len() > 1 {
            queue.pop_front()
        } else {
            queue.front().cloned()
        }
    }) {
        return Ok(url);
    }
    resolve_worker_script(kind.key())
}

/// Advance a non-zero call ID, skipping [`READY_ID`] (`0`) on 32-bit wraparound.
fn next_call_id(current: u32) -> u32 {
    let next = current.wrapping_add(1);
    if next == READY_ID { 1 } else { next }
}

/// Advance a non-zero worker start generation, skipping `0` on 32-bit wraparound.
fn next_start_id(current: u32) -> u32 {
    let next = current.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

/// Clears a browser timeout before dropping its closure, even if the awaiting future is cancelled.
struct TimeoutGuard {
    _timeout: Timeout,
}

impl TimeoutGuard {
    fn arm(kind: Worker, calls: &Rc<Calls>, id: u32, reason: &'static str) -> Self {
        let calls = Rc::downgrade(calls);
        let timeout = Timeout::new(timeout_ms(), move || {
            if let Some(calls) = calls.upgrade()
                && calls.pending.borrow().contains_key(&id)
            {
                stop(kind, &calls, reason);
            }
        });
        Self { _timeout: timeout }
    }
}

/// Removes an in-flight call entry from [`Calls::pending`] if the awaiting future is dropped.
struct PendingGuard {
    calls: Rc<Calls>,
    id: u32,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.calls.pending.borrow_mut().remove(&self.id);
    }
}

/// A worker, started.
struct Running {
    worker: web_sys::Worker,
    /// Which start of its worker this is, as a PDF document belongs to one.
    start: u32,
    /// Resolved once it listens: what it is sent before goes unheard.
    ready: Promise,
    /// Client-side FIFO serializer so queued calls wait without arming premature timeouts.
    queue: Rc<Mutex<()>>,
    calls: Rc<Calls>,
    // Its event listeners, detached on stop or automatically on drop.
    listeners: RefCell<Option<[EventListener; 3]>>,
}

/// The calls a worker has yet to answer: how to resolve and reject each, by ID. ID 0 is reserved
/// for its initial `READY` handshake and is never reused after wraparound.
#[derive(Default)]
struct Calls {
    pending: RefCell<HashMap<u32, (Function, Function)>>,
    next: Cell<u32>,
    ready: Cell<bool>,
    stopped: RefCell<Option<String>>,
}

impl Calls {
    /// Register the initial `READY` promise under [`READY_ID`].
    fn add_ready(&self) -> Promise {
        self.next.set(1);
        Promise::new(&mut |resolve, reject| {
            self.pending
                .borrow_mut()
                .insert(READY_ID, (resolve, reject));
        })
    }

    fn add(&self) -> (u32, Promise) {
        let mut id = self.next.get();
        if id == READY_ID {
            id = 1;
        }
        self.next.set(next_call_id(id));
        let promise = Promise::new(&mut |resolve, reject| {
            self.pending.borrow_mut().insert(id, (resolve, reject));
        });
        (id, promise)
    }

    fn settle(&self, id: u32, ok: bool, value: &JsValue) {
        let Some((resolve, reject)) = self.pending.borrow_mut().remove(&id) else {
            return;
        };
        let _ = if ok { resolve } else { reject }.call1(&JsValue::NULL, value);
    }

    fn fail_all(&self, reason: &str) {
        {
            let mut stopped = self.stopped.borrow_mut();
            if stopped.is_none() {
                *stopped = Some(reason.to_string());
            }
        }
        let pending: Vec<_> = self.pending.borrow_mut().drain().collect();
        for (_, (_, reject)) in pending {
            let _ = reject.call1(&JsValue::NULL, &reason.into());
        }
    }
}

thread_local! {
    static WORKER_MANIFEST: RefCell<Option<HashMap<String, String>>> = const { RefCell::new(None) };
    static RUNNING: RefCell<HashMap<Worker, Rc<Running>>> = RefCell::new(HashMap::new());
    static STARTS: Cell<u32> = const { Cell::new(0) };
}

/// The worker `kind`, started if it is not running (or if its previous instance was marked stopped).
fn running(kind: Worker) -> Result<Rc<Running>, String> {
    if let Some(running) = RUNNING.with(|running| running.borrow().get(&kind).cloned())
        && running.calls.stopped.borrow().is_none()
    {
        return Ok(running);
    }
    let script = worker_script(kind)?;
    let worker = web_sys::Worker::new(&script).map_err(js_error)?;
    let calls = Rc::new(Calls::default());
    let ready = calls.add_ready();
    let on_message = {
        let calls = calls.clone();
        EventListener::new(&worker, "message", move |event| {
            let Some(event) = event.dyn_ref::<MessageEvent>() else {
                return;
            };
            match WorkerEvent::decode(event.data()) {
                Ok(WorkerEvent::Ready) => {
                    calls.ready.set(true);
                    calls.settle(READY_ID, true, &JsValue::UNDEFINED);
                }
                Ok(WorkerEvent::Reply { id, result }) if id != READY_ID => match result {
                    Ok(value) => calls.settle(id, true, &value),
                    Err(error) => calls.settle(id, false, &error),
                },
                _ => {}
            }
        })
    };
    let on_message_error = {
        let calls = calls.clone();
        EventListener::new(&worker, "messageerror", move |_event| {
            // Mark stopped & fail pending synchronously so no same-tick call posts to this worker;
            // terminate & drop listeners on the next microtask to avoid dropping self inside handler.
            calls.fail_all("the preview reply could not be decoded");
            let calls = calls.clone();
            spawn_local(
                async move { stop(kind, &calls, "the preview reply could not be decoded") },
            );
        })
    };
    let on_error = {
        let calls = calls.clone();
        EventListener::new_cancellable(&worker, "error", move |event| {
            event.prevent_default();
            let reason = if !calls.ready.get() && is_online() {
                DEPLOY_SKEW_NOTICE
            } else {
                "the preview failed"
            };
            // Synchronously mark stopped & reject pending callers before yielding, preventing
            // same-tick posts to a crashed worker while deferring listener drop via `spawn_local`.
            calls.fail_all(reason);
            let calls = calls.clone();
            spawn_local(async move { stop(kind, &calls, reason) });
        })
    };
    let start = STARTS.with(|starts| {
        let next = next_start_id(starts.get());
        starts.set(next);
        next
    });
    let running = Rc::new(Running {
        worker,
        start,
        ready,
        queue: Rc::new(Mutex::new(())),
        calls,
        listeners: RefCell::new(Some([on_message, on_message_error, on_error])),
    });
    RUNNING.with(|all| all.borrow_mut().insert(kind, running.clone()));
    Ok(running)
}

/// Stop the worker `kind`, if `calls` are still its, failing them for `reason`.
fn stop(kind: Worker, calls: &Rc<Calls>, reason: &str) {
    let stopped = RUNNING.with(|running| {
        let mut running = running.borrow_mut();
        let current = running.get(&kind)?;
        Rc::ptr_eq(&current.calls, calls).then(|| running.remove(&kind))?
    });
    if let Some(stopped) = stopped {
        *stopped.listeners.borrow_mut() = None;
        stopped.worker.terminate();
    }
    calls.fail_all(reason);
}

/// What a call failed with, as text.
fn failure(error: JsValue) -> String {
    error.as_string().unwrap_or_else(|| js_error(error))
}

/// Send a typed [`RpcCall`] to its worker, queueing FIFO client-side so only the active
/// head-of-line call arms a timeout guard.
async fn call_typed<'a, C: RpcCall<'a>>(
    start: Option<u32>,
    call: C,
) -> Result<(C::Reply, u32), String> {
    let kind = call.worker();
    let running = match start {
        // What it opened went with the worker that opened it.
        Some(start) => RUNNING
            .with(|running| running.borrow().get(&kind).cloned())
            .filter(|running| running.start == start)
            .ok_or("the preview restarted: open the file again")?,
        None => running(kind)?,
    };
    let _turn = running.queue.lock().await;
    if let Some(reason) = running.calls.stopped.borrow().clone() {
        return Err(reason);
    }
    {
        let _ready_timeout = running
            .calls
            .pending
            .borrow()
            .contains_key(&READY_ID)
            .then(|| {
                TimeoutGuard::arm(
                    kind,
                    &running.calls,
                    READY_ID,
                    "the preview took too long to start",
                )
            });
        JsFuture::from(running.ready.clone())
            .await
            .map_err(failure)?;
    }
    if let Some(reason) = running.calls.stopped.borrow().clone() {
        return Err(reason);
    }
    let still_running = RUNNING.with(|all| {
        all.borrow()
            .get(&kind)
            .is_some_and(|current| Rc::ptr_eq(&current.calls, &running.calls))
    });
    if !still_running {
        return Err("the preview restarted: open the file again".to_string());
    }
    let (id, answer) = running.calls.add();
    let _pending_guard = PendingGuard {
        calls: running.calls.clone(),
        id,
    };
    let payload: WirePayload = encode_request_frame(id, call.into_request());
    let sent = match payload.transfer {
        Some(transfer) => running
            .worker
            .post_message_with_transfer(&payload.value, &transfer),
        None => running.worker.post_message(&payload.value),
    };
    if let Err(e) = sent {
        running.calls.settle(id, false, &e);
    }
    // Stuck, if it takes that long: whatever it is doing, it would not finish.
    let _call_timeout = TimeoutGuard::arm(kind, &running.calls, id, "the preview took too long");
    let answer = JsFuture::from(answer).await.map_err(failure);
    drop(_call_timeout);
    drop(_pending_guard);
    let reply = C::decode_reply(answer?)?;
    Ok((reply, running.start))
}

/// `text`, highlighted as `language`, as HTML: escaped text in spans.
pub async fn highlight(language: &Language, text: &str) -> Result<String, String> {
    let (html, _) = call_typed(
        None,
        CodeHighlightCall {
            group: language.group,
            language: language.name,
            text,
        },
    )
    .await?;
    Ok(html)
}

/// The Mermaid diagram `source`, as SVG.
pub async fn diagram(source: &str) -> Result<String, String> {
    let (svg, _) = call_typed(None, DiagramSvgCall(source)).await?;
    Ok(svg)
}

/// Markdown `source`, rendered as sanitized HTML (including MathML) in the Markdown worker.
pub async fn markdown(source: &str) -> Result<String, String> {
    let (html, _) = call_typed(None, MarkdownCall(source)).await?;
    Ok(html)
}

/// reveal.js Markdown `source`, rendered as columns of sanitized HTML slides in the Markdown worker.
pub async fn slides(source: &str) -> Result<Vec<Vec<String>>, String> {
    let (deck, _) = call_typed(None, SlidesCall(source)).await?;
    Ok(deck)
}

/// What the tags of the audio `data` say of it, if it has any.
pub async fn audio_tags(data: &[u8]) -> Result<Option<Tags>, String> {
    let (tags, _) = call_typed(None, AudioTagsCall(data)).await?;
    Ok(tags)
}

/// The matches of `pattern` in `text`, a regular expression unless `regex` says otherwise,
/// ignoring case unless `case` says otherwise: each one's start and end, in UTF-16 code units,
/// and whether there are more than these. An invalid pattern says why.
pub async fn find(
    text: &str,
    pattern: &str,
    case: bool,
    regex: bool,
) -> Result<(Vec<(u32, u32)>, bool), String> {
    let (found, _) = call_typed(
        None,
        SearchFindCall {
            text,
            pattern,
            case,
            regex,
        },
    )
    .await?;
    Ok((found.matches, found.more))
}

/// A PDF document a worker opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pdf {
    start: u32,
    id: u32,
}

/// Open the PDF `data`: the document, and its pages' sizes, in points.
pub async fn open_pdf(data: &[u8]) -> Result<(Pdf, Vec<(f64, f64)>), String> {
    let (opened, start) = call_typed(None, PdfOpenCall(data)).await?;
    Ok((
        Pdf {
            start,
            id: opened.doc_id,
        },
        opened.sizes,
    ))
}

/// The page `index` of `pdf`, drawn `width` pixels wide.
pub async fn render_pdf(pdf: Pdf, index: usize, width: u32) -> Result<ImageData, String> {
    let page = u32::try_from(index).map_err(|_| "invalid page index")?;
    let (rendered, _) = call_typed(
        Some(pdf.start),
        PdfRenderCall {
            doc_id: pdf.id,
            page,
            width,
        },
    )
    .await?;
    ImageData::new_with_js_u8_clamped_array_and_sh(
        &rendered.pixels,
        rendered.width,
        rendered.height,
    )
    .map_err(js_error)
}

/// Free `pdf`, if its worker still runs.
pub fn close_pdf(pdf: Pdf) {
    spawn_local(async move {
        let _ = call_typed(Some(pdf.start), PdfCloseCall { doc_id: pdf.id }).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_and_start_ids_wrap_without_reusing_zero() {
        assert_eq!(next_call_id(1), 2);
        assert_eq!(next_call_id(u32::MAX - 1), u32::MAX);
        assert_eq!(next_call_id(u32::MAX), 1);
        assert_ne!(next_call_id(u32::MAX), READY_ID);

        assert_eq!(next_start_id(0), 1);
        assert_eq!(next_start_id(u32::MAX), 1);
    }

    #[test]
    fn parse_worker_manifest_accepts_valid_map_and_rejects_malformed() {
        let parsed = parse_worker_manifest(
            r#"{"pdf":"/assets/preview_pdf-abc123_loader.js","vault_kdf":"/assets/vault_kdf-def456_loader.js"}"#,
        )
        .expect("valid manifest JSON");
        assert_eq!(
            parsed.get("pdf").map(String::as_str),
            Some("/assets/preview_pdf-abc123_loader.js")
        );
        assert_eq!(
            parsed.get("vault_kdf").map(String::as_str),
            Some("/assets/vault_kdf-def456_loader.js")
        );

        for invalid in [
            "",
            "{}",
            "[]",
            r#"{"":"\/assets\/x.js"}"#,
            r#"{"pdf":""}"#,
            r#"{"pdf":"   "}"#,
            r#"{"pdf":123}"#,
            "not json",
        ] {
            assert!(
                parse_worker_manifest(invalid).is_err(),
                "expected rejection for {invalid:?}"
            );
        }
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use std::collections::VecDeque;

    use futures_util::future::{join, join3};
    use js_sys::Array;
    use wasm_bindgen_test::*;
    use web_sys::{Blob, BlobPropertyBag, Element, Url};

    use super::*;

    fn reset_manifest_cache() {
        WORKER_MANIFEST.with(|cache| {
            *cache.borrow_mut() = None;
        });
    }

    struct ManifestMetaGuard {
        element: Element,
    }

    impl ManifestMetaGuard {
        fn install(content: &str) -> Self {
            reset_manifest_cache();
            let document = web_sys::window()
                .and_then(|w| w.document())
                .expect("test document");
            if let Ok(Some(existing)) = document.query_selector(WORKER_MANIFEST_SELECTOR) {
                existing.remove();
            }
            let meta = document.create_element("meta").expect("create meta");
            meta.set_attribute("name", "e2ee-worker-manifest")
                .expect("set meta name");
            meta.set_attribute("content", content)
                .expect("set meta content");
            let container = document
                .query_selector("head")
                .ok()
                .flatten()
                .or_else(|| document.document_element())
                .expect("document head or root");
            container.append_child(&meta).expect("append manifest meta");
            Self { element: meta }
        }
    }

    impl Drop for ManifestMetaGuard {
        fn drop(&mut self) {
            self.element.remove();
            reset_manifest_cache();
        }
    }

    fn make_blob_script(source: &str) -> String {
        let parts = Array::of1(&JsValue::from_str(source));
        let options = BlobPropertyBag::new();
        options.set_type("application/javascript");
        let blob = Blob::new_with_str_sequence_and_options(&parts, &options)
            .expect("create mock worker JS Blob");
        Url::create_object_url_with_blob(&blob).expect("create Blob URL for mock worker")
    }

    fn stop_kind(kind: Worker) {
        if let Some(current) = RUNNING.with(|running| running.borrow().get(&kind).cloned()) {
            stop(kind, &current.calls, "test cleanup");
        }
    }

    fn current_start_id(kind: Worker) -> Option<u32> {
        RUNNING.with(|running| running.borrow().get(&kind).map(|w| w.start))
    }

    struct MockWorkerHarness {
        kind: Worker,
        urls: Vec<String>,
    }

    impl MockWorkerHarness {
        fn new(kind: Worker, scripts: &[&str], timeout: Option<i32>) -> Self {
            stop_kind(kind);
            let urls: Vec<String> = scripts.iter().map(|src| make_blob_script(src)).collect();
            TEST_SCRIPTS.with(|map| {
                map.borrow_mut()
                    .insert(kind, VecDeque::from_iter(urls.iter().cloned()));
            });
            TEST_TIMEOUT_MS.with(|slot| slot.set(timeout));
            TEST_ONLINE.with(|slot| slot.set(None));
            Self { kind, urls }
        }
    }

    impl Drop for MockWorkerHarness {
        fn drop(&mut self) {
            TEST_TIMEOUT_MS.with(|slot| slot.set(None));
            TEST_ONLINE.with(|slot| slot.set(None));
            TEST_SCRIPTS.with(|map| {
                map.borrow_mut().remove(&self.kind);
            });
            stop_kind(self.kind);
            for url in &self.urls {
                let _ = Url::revoke_object_url(url);
            }
        }
    }

    #[wasm_bindgen_test]
    async fn resolve_worker_script_reads_caches_and_requires_meta_manifest() {
        stop_kind(Worker::Search);
        reset_manifest_cache();

        // No fallback to unhashed paths when the manifest meta tag is absent.
        let missing_err = resolve_worker_script("search")
            .expect_err("missing manifest must fail explicitly without fallback");
        assert!(
            missing_err.contains("missing worker manifest"),
            "{missing_err}"
        );

        // Invalid JSON fails explicitly and must not poison the cache.
        {
            let _bad = ManifestMetaGuard::install("{not-json");
            let invalid_err = resolve_worker_script("search")
                .expect_err("invalid JSON manifest must fail explicitly");
            assert!(
                invalid_err.contains("invalid worker manifest"),
                "{invalid_err}"
            );
        }

        // Valid manifest resolves both preview keys and arbitrary future keys (e.g. `vault_kdf`),
        // caches after the first read, and spawns workers through `resolve_worker_script`.
        const MANIFEST_SEARCH_WORKER: &str = r#"
            self.onmessage = (event) => {
                const [id] = event.data;
                const offsets = new Uint32Array([1, 4]);
                self.postMessage([id, true, [offsets, false]], [offsets.buffer]);
            };
            self.postMessage("ready");
        "#;
        let blob_url = make_blob_script(MANIFEST_SEARCH_WORKER);
        let manifest_json = serde_json::json!({
            "search": blob_url,
            "vault_kdf": "/assets/vault_kdf-deadbeef_loader.js",
        })
        .to_string();
        let meta_guard = ManifestMetaGuard::install(&manifest_json);

        assert_eq!(
            resolve_worker_script("search").as_deref(),
            Ok(blob_url.as_str())
        );
        assert_eq!(
            resolve_worker_script("vault_kdf").as_deref(),
            Ok("/assets/vault_kdf-deadbeef_loader.js")
        );
        assert!(resolve_worker_script("unknown").is_err());

        // Mutating the DOM meta tag after caching must not change the cached lookup.
        meta_guard
            .element
            .set_attribute("content", r#"{"search":"/assets/changed_loader.js"}"#)
            .expect("mutate meta tag");
        assert_eq!(
            resolve_worker_script("search").as_deref(),
            Ok(blob_url.as_str())
        );

        // Spawning a worker without `TEST_SCRIPTS` uses the manifest entry.
        let found = find("hello", "ell", false, false)
            .await
            .expect("worker loaded from meta manifest must succeed");
        assert_eq!(found, (vec![(1, 4)], false));

        stop_kind(Worker::Search);
        drop(meta_guard);
        let _ = Url::revoke_object_url(&blob_url);
    }

    #[wasm_bindgen_test]
    async fn workers_pre_ready_error_surfaces_deploy_skew_notice_only_when_online() {
        const PRE_READY_FAIL_WORKER: &str = r#"
            throw new Error("simulated pre-ready asset load failure");
        "#;
        const HEALTHY_WORKER: &str = r#"
            self.onmessage = (event) => {
                const [id] = event.data;
                const offsets = new Uint32Array([4, 9]);
                self.postMessage([id, true, [offsets, false]], [offsets.buffer]);
            };
            self.postMessage("ready");
        "#;

        // Online: failing before READY surfaces the actionable deploy-skew reload notice.
        {
            let _harness = MockWorkerHarness::new(
                Worker::Search,
                &[PRE_READY_FAIL_WORKER, HEALTHY_WORKER],
                Some(2_000),
            );
            TEST_ONLINE.with(|slot| slot.set(Some(true)));
            let err = find("online-skew", "q", false, false)
                .await
                .expect_err("pre-ready online error must fail");
            assert_eq!(err, DEPLOY_SKEW_NOTICE);

            let recovered = find("after-skew", "q", false, false)
                .await
                .expect("subsequent call after pre-ready error must spawn fresh worker");
            assert_eq!(recovered, (vec![(4, 9)], false));
        }

        // Offline: failing before READY must NOT claim a newer version was deployed.
        {
            let _harness =
                MockWorkerHarness::new(Worker::Search, &[PRE_READY_FAIL_WORKER], Some(2_000));
            TEST_ONLINE.with(|slot| slot.set(Some(false)));
            let err = find("offline-fail", "q", false, false)
                .await
                .expect_err("pre-ready offline error must fail");
            assert_eq!(err, "the preview failed");
        }
    }

    #[wasm_bindgen_test]
    async fn workers_ready_handshake_and_fifo_queue_ordering() {
        // Delays READY (after posting a bogus id=0 reply that must be ignored), enforces
        // single-flight non-overlap (proving client-side FIFO queue serialization), and sleeps
        // 180ms each for the first two requests so total queued time (~440ms) exceeds the 400ms
        // per-call timeout while each head-of-line call stays well under 400ms.
        const SCRIPT: &str = r#"
            let ready = false;
            let inFlight = false;
            let seq = 0;

            self.onmessage = (event) => {
                const [id, method, text] = event.data;
                if (!ready) {
                    self.postMessage([id, false, "received request before READY"]);
                    return;
                }
                if (method !== "find") {
                    self.postMessage([id, false, "unexpected method: " + method]);
                    return;
                }
                if (inFlight) {
                    self.postMessage([id, false, "concurrent request overlap detected"]);
                    return;
                }
                inFlight = true;
                seq += 1;
                const mySeq = seq;
                const delay = text === "third" ? 20 : 180;
                setTimeout(() => {
                    inFlight = false;
                    const offsets = new Uint32Array([mySeq, id]);
                    self.postMessage([id, true, [offsets, false]], [offsets.buffer]);
                }, delay);
            };

            // Bogus id=0 reply before READY must be ignored by `workers.rs` (`id != READY_ID`).
            self.postMessage([0, true, "spurious-zero-id"]);
            setTimeout(() => {
                ready = true;
                self.postMessage("ready");
            }, 60);
        "#;

        let _harness = MockWorkerHarness::new(Worker::Search, &[SCRIPT], Some(400));
        let (r1, r2, r3) = join3(
            find("first", "q", false, false),
            find("second", "q", false, false),
            find("third", "q", false, false),
        )
        .await;

        assert_eq!(r1, Ok((vec![(1, 1)], false)));
        assert_eq!(r2, Ok((vec![(2, 2)], false)));
        assert_eq!(r3, Ok((vec![(3, 3)], false)));
        assert!(current_start_id(Worker::Search).is_some());
    }

    #[wasm_bindgen_test]
    async fn workers_timeout_guard_terminates_and_restarts_cleanly() {
        // Subcase 1: worker never emits READY -> start timeout terminates & next call recovers.
        const SILENT_WORKER: &str = r#"
            self.onmessage = () => {};
        "#;
        const READY_OK_WORKER: &str = r#"
            self.onmessage = (event) => {
                const [id] = event.data;
                const offsets = new Uint32Array([10, 20]);
                self.postMessage([id, true, [offsets, false]], [offsets.buffer]);
            };
            self.postMessage("ready");
        "#;
        {
            let _harness = MockWorkerHarness::new(
                Worker::Search,
                &[SILENT_WORKER, READY_OK_WORKER],
                Some(150),
            );
            let err = find("boot", "q", false, false)
                .await
                .expect_err("silent worker must hit start timeout");
            assert_eq!(err, "the preview took too long to start");
            assert!(current_start_id(Worker::Search).is_none());

            TEST_TIMEOUT_MS.with(|slot| slot.set(Some(2_000)));
            let recovered = find("after-start-timeout", "q", false, false)
                .await
                .expect("fresh worker must succeed after start timeout");
            assert_eq!(recovered, (vec![(10, 20)], false));
            assert!(current_start_id(Worker::Search).is_some());
        }

        // Subcase 2: worker answers one call, then stalls on "stall" -> TimeoutGuard terminates
        // it, fails both head-of-line and queued callers, and the next call starts a fresh worker.
        const STALL_WORKER: &str = r#"
            self.onmessage = (event) => {
                const [id, _method, text] = event.data;
                if (text === "stall") {
                    return;
                }
                const offsets = new Uint32Array([1, 2]);
                self.postMessage([id, true, [offsets, false]], [offsets.buffer]);
            };
            self.postMessage("ready");
        "#;
        const RECOVERED_WORKER: &str = r#"
            self.onmessage = (event) => {
                const [id] = event.data;
                const offsets = new Uint32Array([7, 14]);
                self.postMessage([id, true, [offsets, true]], [offsets.buffer]);
            };
            self.postMessage("ready");
        "#;
        {
            let _harness = MockWorkerHarness::new(
                Worker::Search,
                &[STALL_WORKER, RECOVERED_WORKER],
                Some(2_000),
            );
            assert_eq!(
                find("ok", "q", false, false).await,
                Ok((vec![(1, 2)], false))
            );
            let start_1 = current_start_id(Worker::Search).expect("worker 1 running");

            TEST_TIMEOUT_MS.with(|slot| slot.set(Some(150)));
            let (stalled, queued) = join(
                find("stall", "q", false, false),
                find("queued-behind-stall", "q", false, false),
            )
            .await;
            assert_eq!(stalled, Err("the preview took too long".to_string()));
            assert_eq!(queued, Err("the preview took too long".to_string()));
            assert!(current_start_id(Worker::Search).is_none());

            TEST_TIMEOUT_MS.with(|slot| slot.set(Some(2_000)));
            let recovered = find("recovered", "q", false, false)
                .await
                .expect("fresh worker must succeed after call timeout");
            assert_eq!(recovered, (vec![(7, 14)], true));
            let start_2 = current_start_id(Worker::Search).expect("worker 2 running");
            assert_ne!(start_2, start_1);
        }
    }

    #[wasm_bindgen_test]
    async fn workers_on_error_crash_restarts_cleanly() {
        const CRASHING_WORKER: &str = r#"
            self.onmessage = (event) => {
                const [id, _method, text] = event.data;
                if (text === "crash") {
                    throw new Error("simulated preview worker crash");
                }
                const offsets = new Uint32Array([0, 2]);
                self.postMessage([id, true, [offsets, false]], [offsets.buffer]);
            };
            self.postMessage("ready");
        "#;
        const HEALTHY_WORKER: &str = r#"
            self.onmessage = (event) => {
                const [id] = event.data;
                const offsets = new Uint32Array([3, 8]);
                self.postMessage([id, true, [offsets, false]], [offsets.buffer]);
            };
            self.postMessage("ready");
        "#;

        let _harness = MockWorkerHarness::new(
            Worker::Search,
            &[CRASHING_WORKER, HEALTHY_WORKER],
            Some(2_000),
        );
        assert_eq!(
            find("ok", "q", false, false).await,
            Ok((vec![(0, 2)], false))
        );
        let start_1 = current_start_id(Worker::Search).expect("worker 1 started");

        let crash_err = find("crash", "q", false, false)
            .await
            .expect_err("uncaught worker exception must reject via on_error");
        assert_eq!(crash_err, "the preview failed");

        // Next call immediately restarts into a fresh worker even before deferred stop settles.
        let recovered = find("after-crash", "q", false, false)
            .await
            .expect("call after crash must spawn a healthy worker");
        assert_eq!(recovered, (vec![(3, 8)], false));
        let start_2 = current_start_id(Worker::Search).expect("worker 2 started");
        assert_ne!(start_2, start_1);
    }

    #[wasm_bindgen_test]
    async fn workers_pdf_generation_id_staleness_after_restart() {
        const PDF_WORKER_1: &str = r#"
            self.onmessage = (event) => {
                const [id, method, arg] = event.data;
                if (method === "open") {
                    if (arg.length > 0 && arg[0] === 0xff) {
                        throw new Error("simulated pdf worker crash");
                    }
                    const sizes = new Float64Array([612, 792]);
                    self.postMessage([id, true, [42, sizes]], [sizes.buffer]);
                } else if (method === "render") {
                    const pixels = new Uint8ClampedArray(2 * 2 * 4);
                    pixels.fill(128);
                    self.postMessage([id, true, [2, 2, pixels]], [pixels.buffer]);
                } else if (method === "close") {
                    self.postMessage([id, true, undefined]);
                } else {
                    self.postMessage([id, false, "unknown method"]);
                }
            };
            self.postMessage("ready");
        "#;
        const PDF_WORKER_2: &str = r#"
            self.onmessage = (event) => {
                const [id, method] = event.data;
                if (method === "open") {
                    const sizes = new Float64Array([300, 400]);
                    self.postMessage([id, true, [42, sizes]], [sizes.buffer]);
                } else if (method === "render") {
                    const pixels = new Uint8ClampedArray([10, 20, 30, 255]);
                    self.postMessage([id, true, [1, 1, pixels]], [pixels.buffer]);
                } else if (method === "close") {
                    self.postMessage([id, true, undefined]);
                } else {
                    self.postMessage([id, false, "unknown method"]);
                }
            };
            self.postMessage("ready");
        "#;

        let _harness =
            MockWorkerHarness::new(Worker::Pdf, &[PDF_WORKER_1, PDF_WORKER_2], Some(2_000));

        let (pdf1, sizes1) = open_pdf(b"%PDF-1.7").await.expect("open pdf1");
        assert_eq!(sizes1, vec![(612.0, 792.0)]);
        let img1 = render_pdf(pdf1, 0, 2).await.expect("render pdf1 page 0");
        assert_eq!((img1.width(), img1.height()), (2, 2));

        // Crash worker 1, then open a new PDF which spawns worker 2 with a new generation ID.
        let crash_err = open_pdf(&[0xff])
            .await
            .expect_err("sentinel bytes must crash pdf worker 1");
        assert_eq!(crash_err, "the preview failed");

        let (pdf2, sizes2) = open_pdf(b"%PDF-2.0")
            .await
            .expect("open pdf2 on restarted worker");
        assert_eq!(sizes2, vec![(300.0, 400.0)]);
        assert_ne!(pdf2.start, pdf1.start);

        // Stale handle from generation 1 must be rejected without reaching worker 2.
        let stale_err = render_pdf(pdf1, 0, 2)
            .await
            .expect_err("stale pdf handle must be rejected after restart");
        assert_eq!(stale_err, "the preview restarted: open the file again");

        // Fresh handle on generation 2 continues rendering normally.
        let img2 = render_pdf(pdf2, 0, 1).await.expect("render pdf2 page 0");
        assert_eq!((img2.width(), img2.height()), (1, 1));

        // Stopping the worker also invalidates pdf2 with the same staleness error.
        stop_kind(Worker::Pdf);
        let stopped_err = render_pdf(pdf2, 0, 1)
            .await
            .expect_err("stopped pdf worker must reject existing handle");
        assert_eq!(stopped_err, "the preview restarted: open the file again");
    }

    #[wasm_bindgen_test]
    async fn workers_markdown_and_slides_roundtrip_and_recover_from_crash() {
        const CRASHING_MD_WORKER: &str = r#"
            self.onmessage = (event) => {
                const [id, method, source] = event.data;
                if (source === "crash") {
                    throw new Error("simulated markdown worker crash");
                }
                if (method === "markdown") {
                    self.postMessage([id, true, "<h1>" + source + "</h1>"]);
                } else if (method === "slides") {
                    self.postMessage([id, true, [["<h1>" + source + "</h1>"], ["<p>two</p>"]]]);
                } else {
                    self.postMessage([id, false, "unknown method"]);
                }
            };
            self.postMessage("ready");
        "#;
        const HEALTHY_MD_WORKER: &str = r#"
            self.onmessage = (event) => {
                const [id, method, source] = event.data;
                if (method === "markdown") {
                    self.postMessage([id, true, "<p>" + source + "</p>"]);
                } else if (method === "slides") {
                    self.postMessage([id, true, [["<p>" + source + "</p>"]]]);
                } else {
                    self.postMessage([id, false, "unknown method"]);
                }
            };
            self.postMessage("ready");
        "#;

        let _harness = MockWorkerHarness::new(
            Worker::Markdown,
            &[CRASHING_MD_WORKER, HEALTHY_MD_WORKER],
            Some(2_000),
        );
        assert_eq!(markdown("hi").await.as_deref(), Ok("<h1>hi</h1>"));
        assert_eq!(
            slides("deck").await,
            Ok(vec![
                vec!["<h1>deck</h1>".to_string()],
                vec!["<p>two</p>".to_string()],
            ])
        );
        assert_eq!(
            markdown("crash").await,
            Err("the preview failed".to_string())
        );
        assert_eq!(
            markdown("recovered").await.as_deref(),
            Ok("<p>recovered</p>")
        );
    }
}
