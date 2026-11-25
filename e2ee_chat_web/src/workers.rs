//! The previews' web workers, of [`e2ee_chat_preview`], each started when a preview first needs
//! it: PDF pages, Mermaid diagrams, audio tags, search, and code highlighted by four workers, a
//! group of languages each. Calls to each worker are queued FIFO client-side so only the active
//! head-of-line call arms its [`TIMEOUT`] guard; a stalled or failed worker is terminated, failing
//! its pending calls, and the next call starts a fresh one.

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
        AudioTagsCall, CodeHighlightCall, DiagramSvgCall, PdfCloseCall, PdfOpenCall, PdfRenderCall,
        RpcCall, SearchFindCall, WirePayload, WorkerEvent, encode_request_frame,
    },
};
use futures_util::lock::Mutex;
use js_sys::{Function, Promise};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{Event, ImageData, MessageEvent};

use crate::util::js_error;

/// How long an active head-of-line call or worker start may take, in milliseconds.
const TIMEOUT: i32 = 60_000;
/// Call ID reserved for the worker's initial `READY` handshake.
const READY_ID: u32 = 0;

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
    window: web_sys::Window,
    timer: Option<i32>,
    _closure: Closure<dyn FnMut()>,
}

impl TimeoutGuard {
    fn arm(kind: Worker, calls: &Rc<Calls>, id: u32, reason: &'static str) -> Self {
        let calls = Rc::downgrade(calls);
        let closure = Closure::<dyn FnMut()>::new(move || {
            if let Some(calls) = calls.upgrade()
                && calls.pending.borrow().contains_key(&id)
            {
                stop(kind, &calls, reason);
            }
        });
        let window = web_sys::window().expect("a window");
        let timer = window
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                closure.as_ref().unchecked_ref(),
                TIMEOUT,
            )
            .ok();
        Self {
            window,
            timer,
            _closure: closure,
        }
    }
}

impl Drop for TimeoutGuard {
    fn drop(&mut self) {
        if let Some(timer) = self.timer.take() {
            self.window.clear_timeout_with_handle(timer);
        }
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
    // Its handlers, kept for as long as it runs.
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_message_error: Closure<dyn FnMut(MessageEvent)>,
    _on_error: Closure<dyn FnMut(Event)>,
}

/// The calls a worker has yet to answer: how to resolve and reject each, by ID. ID 0 is reserved
/// for its initial `READY` handshake and is never reused after wraparound.
#[derive(Default)]
struct Calls {
    pending: RefCell<HashMap<u32, (Function, Function)>>,
    next: Cell<u32>,
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
    let worker = web_sys::Worker::new(kind.script()).map_err(js_error)?;
    let calls = Rc::new(Calls::default());
    let ready = calls.add_ready();
    let on_message = {
        let calls = calls.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(
            move |event: MessageEvent| match WorkerEvent::decode(event.data()) {
                Ok(WorkerEvent::Ready) => calls.settle(READY_ID, true, &JsValue::UNDEFINED),
                Ok(WorkerEvent::Reply { id, result }) if id != READY_ID => match result {
                    Ok(value) => calls.settle(id, true, &value),
                    Err(error) => calls.settle(id, false, &error),
                },
                _ => {}
            },
        )
    };
    let on_message_error = {
        let calls = calls.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |_event: MessageEvent| {
            // Mark stopped & fail pending synchronously so no same-tick call posts to this worker;
            // terminate & drop closures on the next microtask to avoid dropping self inside handler.
            calls.fail_all("the preview reply could not be decoded");
            let calls = calls.clone();
            spawn_local(
                async move { stop(kind, &calls, "the preview reply could not be decoded") },
            );
        })
    };
    let on_error = {
        let calls = calls.clone();
        Closure::<dyn FnMut(Event)>::new(move |event: Event| {
            event.prevent_default();
            // Synchronously mark stopped & reject pending callers before yielding, preventing
            // same-tick posts to a crashed worker while deferring handler drop via `spawn_local`.
            calls.fail_all("the preview failed");
            let calls = calls.clone();
            spawn_local(async move { stop(kind, &calls, "the preview failed") });
        })
    };
    worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    worker.set_onmessageerror(Some(on_message_error.as_ref().unchecked_ref()));
    worker.set_onerror(Some(on_error.as_ref().unchecked_ref()));
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
        _on_message: on_message,
        _on_message_error: on_message_error,
        _on_error: on_error,
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
        stopped.worker.set_onmessage(None);
        stopped.worker.set_onmessageerror(None);
        stopped.worker.set_onerror(None);
        stopped.worker.terminate();
    }
    calls.fail_all(reason);
}

impl Drop for Running {
    fn drop(&mut self) {
        self.worker.set_onmessage(None);
        self.worker.set_onmessageerror(None);
        self.worker.set_onerror(None);
    }
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
}
