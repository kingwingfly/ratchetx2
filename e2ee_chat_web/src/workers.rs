//! The previews' web workers, of [`e2ee_chat_preview`], each started when a preview first needs
//! it: PDF pages, Mermaid diagrams, and code, highlighted by four workers, a group of languages
//! each. A call waits for its worker to be ready, however long it takes to load; one that then
//! takes more than [`TIMEOUT`], as a peer's file might make it, stops the worker, failing what it
//! was doing, and the next call starts it again.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};

use e2ee_chat_preview::{READY, Worker, language::Language};
use js_sys::{Array, Float64Array, Function, Promise, Uint8Array, Uint8ClampedArray};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{Event, ImageData, MessageEvent};

use crate::util::js_error;

/// How long a worker may take to answer: drawing a page or highlighting a file of the most it
/// highlights takes seconds.
const TIMEOUT: i32 = 60_000;

/// A worker, started.
struct Running {
    worker: web_sys::Worker,
    /// Which start of its worker this is, as a PDF document belongs to one.
    start: u32,
    /// Resolved once it listens: what it is sent before goes unheard.
    ready: Promise,
    calls: Rc<Calls>,
    // Its handlers, kept for as long as it runs.
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_error: Closure<dyn FnMut(Event)>,
}

/// The calls a worker has yet to answer: how to resolve and reject each, by ID. The first, 0, is
/// its being ready.
#[derive(Default)]
struct Calls {
    pending: RefCell<HashMap<u32, (Function, Function)>>,
    next: Cell<u32>,
}

impl Calls {
    fn add(&self) -> (u32, Promise) {
        let id = self.next.get();
        self.next.set(id + 1);
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

/// The worker `kind`, started if it is not running.
fn running(kind: Worker) -> Result<Rc<Running>, String> {
    if let Some(running) = RUNNING.with(|running| running.borrow().get(&kind).cloned()) {
        return Ok(running);
    }
    let worker = web_sys::Worker::new(kind.script()).map_err(js_error)?;
    let calls = Rc::new(Calls::default());
    let (_, ready) = calls.add();
    let on_message = {
        let calls = calls.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let data = event.data();
            if data.as_string().as_deref() == Some(READY) {
                calls.settle(0, true, &JsValue::UNDEFINED);
                return;
            }
            let reply = Array::from(&data);
            if let Some(id) = reply.get(0).as_f64() {
                calls.settle(id as u32, reply.get(1).is_truthy(), &reply.get(2));
            }
        })
    };
    let on_error = {
        let calls = calls.clone();
        Closure::<dyn FnMut(Event)>::new(move |event: Event| {
            event.prevent_default();
            // Later, as stopping drops this handler.
            let calls = calls.clone();
            spawn_local(async move { stop(kind, &calls, "the preview failed") });
        })
    };
    worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    worker.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    let start = STARTS.with(|starts| {
        starts.set(starts.get() + 1);
        starts.get()
    });
    let running = Rc::new(Running {
        worker,
        start,
        ready,
        calls,
        _on_message: on_message,
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
        stopped.worker.terminate();
        stopped.calls.fail_all(reason);
    }
}

/// What a call failed with, as text.
fn failure(error: JsValue) -> String {
    error.as_string().unwrap_or_else(|| js_error(error))
}

/// Call `method` of the worker `kind` with `arguments`, moving the buffers in `transfer` to it;
/// on its start `start` only, if given, which a call needs that names what it opened. Returns
/// the answer, and the start that gave it.
async fn call(
    kind: Worker,
    start: Option<u32>,
    method: &str,
    arguments: &[JsValue],
    transfer: Option<Array>,
) -> Result<(JsValue, u32), String> {
    let running = match start {
        // What it opened went with the worker that opened it.
        Some(start) => RUNNING
            .with(|running| running.borrow().get(&kind).cloned())
            .filter(|running| running.start == start)
            .ok_or("the preview restarted: open the file again")?,
        None => running(kind)?,
    };
    JsFuture::from(running.ready.clone())
        .await
        .map_err(failure)?;
    let (id, answer) = running.calls.add();
    let request = Array::of2(&id.into(), &method.into());
    for argument in arguments {
        request.push(argument);
    }
    let sent = match &transfer {
        Some(transfer) => running.worker.post_message_with_transfer(&request, transfer),
        None => running.worker.post_message(&request),
    };
    if let Err(e) = sent {
        running.calls.settle(id, false, &e);
    }
    // Stuck, if it takes that long: whatever it is doing, it would not finish.
    let calls = Rc::downgrade(&running.calls);
    let timeout = Closure::<dyn FnMut()>::new(move || {
        if let Some(calls) = calls.upgrade()
            && calls.pending.borrow().contains_key(&id)
        {
            stop(kind, &calls, "the preview took too long");
        }
    });
    let window = web_sys::window().expect("a window");
    let timer = window
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            timeout.as_ref().unchecked_ref(),
            TIMEOUT,
        )
        .ok();
    let answer = JsFuture::from(answer).await.map_err(failure);
    if let Some(timer) = timer {
        window.clear_timeout_with_handle(timer);
    }
    drop(timeout);
    Ok((answer?, running.start))
}

/// `text`, highlighted as `language`, as HTML: escaped text in spans.
pub async fn highlight(language: &Language, text: &str) -> Result<String, String> {
    let arguments = [language.name.into(), text.into()];
    call(Worker::Code(language.group), None, "highlight", &arguments, None)
        .await?
        .0
        .as_string()
        .ok_or_else(|| "no HTML".to_string())
}

/// The Mermaid diagram `source`, as SVG.
pub async fn diagram(source: &str) -> Result<String, String> {
    call(Worker::Diagram, None, "svg", &[source.into()], None)
        .await?
        .0
        .as_string()
        .ok_or_else(|| "no SVG".to_string())
}

/// A PDF document a worker opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pdf {
    start: u32,
    id: u32,
}

/// Open the PDF `data`: the document, and its pages' sizes, in points.
pub async fn open_pdf(data: &[u8]) -> Result<(Pdf, Vec<(f64, f64)>), String> {
    let bytes = Uint8Array::from(data);
    let transfer = Array::of1(&bytes.buffer());
    let (reply, start) = call(Worker::Pdf, None, "open", &[bytes.into()], Some(transfer)).await?;
    let reply = Array::from(&reply);
    let id = reply.get(0).as_f64().ok_or("no document")? as u32;
    let sizes = Float64Array::new(&reply.get(1)).to_vec();
    let (pages, _) = sizes.as_chunks::<2>();
    Ok((
        Pdf { start, id },
        pages.iter().map(|&[width, height]| (width, height)).collect(),
    ))
}

/// The page `index` of `pdf`, drawn `width` pixels wide.
pub async fn render_pdf(pdf: Pdf, index: usize, width: u32) -> Result<ImageData, String> {
    let arguments = [pdf.id.into(), (index as u32).into(), width.into()];
    let (reply, _) = call(Worker::Pdf, Some(pdf.start), "render", &arguments, None).await?;
    let reply = Array::from(&reply);
    let (Some(width), Some(height)) = (reply.get(0).as_f64(), reply.get(1).as_f64()) else {
        return Err("no page".to_string());
    };
    let pixels: Uint8ClampedArray = reply.get(2).unchecked_into();
    ImageData::new_with_js_u8_clamped_array_and_sh(&pixels, width as u32, height as u32)
        .map_err(js_error)
}

/// Free `pdf`, if its worker still runs.
pub fn close_pdf(pdf: Pdf) {
    spawn_local(async move {
        let _ = call(Worker::Pdf, Some(pdf.start), "close", &[pdf.id.into()], None).await;
    });
}
