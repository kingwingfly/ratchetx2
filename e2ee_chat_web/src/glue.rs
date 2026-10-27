//! Browser APIs that may be missing: the Web Locks API, in older browsers; the clipboard, outside
//! secure contexts; and service workers, there and in some private windows. Calling a missing one
//! would throw into the WebAssembly caller, so each is looked for first. web-sys has the Web Locks
//! API only among its unstable APIs, so it is called as JavaScript sees it.

use std::{cell::RefCell, rc::Rc};

use futures::channel::oneshot;
use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{MessageEvent, MessagePort, Navigator};

fn navigator() -> Navigator {
    web_sys::window().expect("a window").navigator()
}

/// Whether `navigator` has the API `name`.
fn has(navigator: &Navigator, name: &str) -> bool {
    Reflect::get(navigator, &name.into()).is_ok_and(|api| !api.is_undefined())
}

/// Take the lock `name` for as long as the page lives; `false` if another page holds it.
pub async fn take_lock(name: &str) -> bool {
    let navigator = navigator();
    // Without locks, there is no telling.
    let Some(locks) = Reflect::get(&navigator, &"locks".into())
        .ok()
        .filter(|locks| !locks.is_undefined())
    else {
        return true;
    };
    let Some(request) = Reflect::get(&locks, &"request".into())
        .ok()
        .and_then(|request| request.dyn_into::<Function>().ok())
    else {
        return true;
    };
    let (taken, told) = oneshot::channel();
    let taken = Rc::new(RefCell::new(Some(taken)));
    let tell = {
        let taken = taken.clone();
        move |held: bool| {
            if let Some(taken) = taken.borrow_mut().take() {
                let _ = taken.send(held);
            }
        }
    };
    let granted = {
        let tell = tell.clone();
        Closure::<dyn FnMut(JsValue) -> Promise>::new(move |lock: JsValue| {
            let held = !lock.is_null();
            tell(held);
            if held {
                // Held until the page goes.
                Promise::new(&mut |_, _| {})
            } else {
                Promise::resolve(&JsValue::UNDEFINED)
            }
        })
    };
    let options = Object::new();
    let _ = Reflect::set(&options, &"ifAvailable".into(), &JsValue::TRUE);
    let requested = request.call3(&locks, &name.into(), &options, granted.as_ref());
    // Called once, but the lock's promise lives with the page.
    granted.forget();
    // A request that fails, like no locks, must not keep the page loading forever.
    match requested.map(Promise::from) {
        Ok(requested) => spawn_local(async move {
            if JsFuture::from(requested).await.is_err() {
                tell(true);
            }
        }),
        Err(_) => tell(true),
    }
    told.await.unwrap_or(true)
}

/// Copy `text` to the clipboard; `false` if the browser refused.
pub async fn copy(text: &str) -> bool {
    let navigator = navigator();
    has(&navigator, "clipboard")
        && JsFuture::from(navigator.clipboard().write_text(text))
            .await
            .is_ok()
}

/// Register the service worker that streams media, `media-worker.js`, if the browser has them.
pub fn register_media_worker() {
    let navigator = navigator();
    if has(&navigator, "serviceWorker") {
        // Unregistered, it does nothing; its promise only tells so.
        let _ = navigator.service_worker().register("/media-worker.js");
    }
}

/// Whether the service worker controls the page, so that media streams through it; else it is
/// fetched whole before it plays.
pub fn streaming() -> bool {
    let navigator = navigator();
    has(&navigator, "serviceWorker") && navigator.service_worker().controller().is_some()
}

/// The service worker's request for the bytes of a stream from `start`, to `end` if given, for a
/// player of the page.
pub struct MediaRequest {
    pub token: String,
    pub start: u64,
    pub end: Option<u64>,
    reply: MessagePort,
}

/// What answers a [`MediaRequest`]: the stream's size, its MIME type, and bytes from where it
/// asked; or an HTTP status, e.g. 404 for a stream ended.
pub type MediaReply<'a> = Result<(u64, &'a str, &'a [u8]), u16>;

impl MediaRequest {
    pub fn reply(self, reply: MediaReply<'_>) {
        let message = Object::new();
        let transfer = Array::new();
        let set = |name: &str, value: &JsValue| {
            let _ = Reflect::set(&message, &name.into(), value);
        };
        match reply {
            Ok((size, mime, bytes)) => {
                // Moved to the service worker rather than copied.
                let buffer = Uint8Array::from(bytes).buffer();
                set("size", &(size as f64).into());
                set("mime", &mime.into());
                set("bytes", &buffer);
                transfer.push(&buffer);
            }
            Err(status) => set("error", &status.into()),
        }
        let _ = self
            .reply
            .post_message_with_transferable(&message, &transfer);
    }
}

/// Answer the service worker's requests for media, as they come, with `answer`.
pub fn serve_media(answer: impl Fn(MediaRequest) + 'static) {
    let navigator = navigator();
    if !has(&navigator, "serviceWorker") {
        return;
    }
    let container = navigator.service_worker();
    let listener = Closure::<dyn Fn(MessageEvent)>::new(move |event: MessageEvent| {
        let data = event.data();
        let field = |name: &str| Reflect::get(&data, &name.into()).ok();
        let token = field("media").and_then(|token| token.as_string());
        let start = field("start").and_then(|start| start.as_f64());
        let reply = event.ports().get(0).dyn_into::<MessagePort>().ok();
        if let (Some(token), Some(start), Some(reply)) = (token, start, reply) {
            let end = field("end")
                .and_then(|end| end.as_f64())
                .map(|end| end as u64);
            answer(MediaRequest {
                token,
                start: start as u64,
                end,
                reply,
            });
        }
    });
    let _ =
        container.add_event_listener_with_callback("message", listener.as_ref().unchecked_ref());
    // Messages are let through once the page loads, or once asked to, which web-sys cannot.
    if let Ok(start) = Reflect::get(&container, &"startMessages".into())
        .and_then(|start| start.dyn_into::<Function>())
    {
        let _ = start.call0(&container);
    }
    // Listening as long as the page lives.
    listener.forget();
}
