//! Browser APIs that may be missing: the Web Locks API, in older browsers; the clipboard, outside
//! secure contexts; and service workers, there and in some private windows. Calling a missing one
//! would throw into the WebAssembly caller, so each is looked for first. web-sys has the Web Locks
//! API only among its unstable APIs, so it is called as JavaScript sees it.

use std::{cell::RefCell, rc::Rc};

use futures::channel::oneshot;
use js_sys::{Array, ArrayBuffer, Object, Promise, Uint8Array};
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{Clipboard, MessageEvent, MessagePort, Navigator, ServiceWorkerContainer};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = Navigator)]
    type BrowserNavigator;
    #[wasm_bindgen(method, getter = clipboard, catch)]
    fn optional_clipboard(this: &BrowserNavigator) -> Result<Option<Clipboard>, JsValue>;
    #[wasm_bindgen(method, getter = serviceWorker, catch)]
    fn optional_service_worker(
        this: &BrowserNavigator,
    ) -> Result<Option<MediaServiceWorkers>, JsValue>;
    #[wasm_bindgen(method, getter = locks, catch)]
    fn optional_locks(this: &BrowserNavigator) -> Result<Option<WebLockManager>, JsValue>;

    type WebLockManager;
    #[wasm_bindgen(method, catch)]
    fn request(
        this: &WebLockManager,
        name: &str,
        options: &LockOptions,
        callback: &JsValue,
    ) -> Result<Promise, JsValue>;
    #[wasm_bindgen(extends = Object)]
    type LockOptions;
    #[wasm_bindgen(method, setter = ifAvailable)]
    fn set_if_available(this: &LockOptions, value: bool);

    #[wasm_bindgen(extends = ServiceWorkerContainer)]
    type MediaServiceWorkers;
    #[wasm_bindgen(method, js_name = startMessages, catch)]
    fn try_start_messages(this: &MediaServiceWorkers) -> Result<(), JsValue>;

    #[wasm_bindgen(extends = Object)]
    type MediaRequestMsg;
    #[wasm_bindgen(method, getter, catch)]
    fn media(this: &MediaRequestMsg) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, getter, catch)]
    fn start(this: &MediaRequestMsg) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, getter, catch)]
    fn end(this: &MediaRequestMsg) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(extends = Object)]
    type MediaReplyMsg;
    #[wasm_bindgen(method, setter = size)]
    fn set_size(this: &MediaReplyMsg, size: f64);
    #[wasm_bindgen(method, setter = mime)]
    fn set_mime(this: &MediaReplyMsg, mime: &str);
    #[wasm_bindgen(method, setter = bytes)]
    fn set_bytes(this: &MediaReplyMsg, bytes: &ArrayBuffer);
    #[wasm_bindgen(method, setter = error)]
    fn set_error(this: &MediaReplyMsg, status: u16);
}

fn navigator() -> BrowserNavigator {
    web_sys::window()
        .expect("a window")
        .navigator()
        .unchecked_into()
}

/// Result of attempting to acquire the exclusive tab lock for the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockStatus {
    /// Exclusive lock acquired for the lifetime of this page.
    Acquired,
    /// Another tab or window already holds the lock.
    HeldElsewhere,
    /// Web Locks API is unavailable (e.g. insecure non-HTTPS context or unsupported browser).
    Unavailable { insecure_context: bool },
}

/// Whether this page is running in a secure context (HTTPS or localhost).
fn is_secure_context() -> bool {
    web_sys::window().is_some_and(|window| window.is_secure_context())
}

/// Take the lock `name` for as long as the page lives, failing closed if another tab holds it
/// or if the Web Locks API is unavailable or fails (preventing concurrent vault corruption).
pub async fn take_lock(name: &str) -> LockStatus {
    let insecure_context = !is_secure_context();
    let unavailable = LockStatus::Unavailable { insecure_context };
    let Ok(Some(locks)) = navigator().optional_locks() else {
        return unavailable;
    };
    let (taken, told) = oneshot::channel();
    let taken = Rc::new(RefCell::new(Some(taken)));
    let tell = {
        let taken = taken.clone();
        move |status: LockStatus| {
            if let Some(taken) = taken.borrow_mut().take() {
                let _ = taken.send(status);
            }
        }
    };
    let granted = {
        let tell = tell.clone();
        Closure::<dyn FnMut(JsValue) -> Promise>::new(move |lock: JsValue| {
            let held = !lock.is_null() && !lock.is_undefined();
            tell(if held {
                LockStatus::Acquired
            } else {
                LockStatus::HeldElsewhere
            });
            if held {
                // Held until the page goes.
                Promise::new(&mut |_, _| {})
            } else {
                Promise::resolve(&JsValue::UNDEFINED)
            }
        })
    };
    let options: LockOptions = Object::new().unchecked_into();
    options.set_if_available(true);
    match locks.request(name, &options, granted.as_ref()) {
        Ok(requested) => {
            // Called once, and when held the lock's promise lives with the page.
            granted.forget();
            spawn_local(async move {
                // Fail closed if the request promise rejects or settles without granting the lock.
                let _ = JsFuture::from(requested).await;
                tell(unavailable);
            });
        }
        Err(_) => tell(unavailable),
    }
    told.await.unwrap_or(unavailable)
}

/// Copy `text` to the clipboard; `false` if the browser refused.
pub async fn copy(text: &str) -> bool {
    let Ok(Some(clipboard)) = navigator().optional_clipboard() else {
        return false;
    };
    JsFuture::from(clipboard.write_text(text)).await.is_ok()
}

/// Register the service worker that streams media, `media-worker.js`, if the browser has them.
pub fn register_media_worker() {
    if let Ok(Some(container)) = navigator().optional_service_worker() {
        // Unregistered, it does nothing; its promise only tells so.
        let _ = container.register("/media-worker.js");
    }
}

/// Whether the service worker controls the page, so that media streams through it; else it is
/// fetched whole before it plays.
pub fn streaming() -> bool {
    navigator()
        .optional_service_worker()
        .ok()
        .flatten()
        .is_some_and(|container| container.controller().is_some())
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
        let message: MediaReplyMsg = Object::new().unchecked_into();
        let transfer = Array::new();
        match reply {
            Ok((size, mime, bytes)) => {
                // Moved to the service worker rather than copied.
                let buffer = Uint8Array::from(bytes).buffer();
                message.set_size(size as f64);
                message.set_mime(mime);
                message.set_bytes(&buffer);
                transfer.push(&buffer);
            }
            Err(status) => message.set_error(status),
        }
        let _ = self
            .reply
            .post_message_with_transferable(&message, &transfer);
    }
}

/// Answer the service worker's requests for media, as they come, with `answer`.
pub fn serve_media(answer: impl Fn(MediaRequest) + 'static) {
    let Ok(Some(container)) = navigator().optional_service_worker() else {
        return;
    };
    let listener = Closure::<dyn Fn(MessageEvent)>::new(move |event: MessageEvent| {
        let data = event.data();
        if !data.is_object() || data.is_null() {
            return;
        }
        let request: MediaRequestMsg = data.unchecked_into();
        let token = request.media().ok().and_then(|v| v.as_string());
        let start = request.start().ok().and_then(|v| v.as_f64());
        let reply = event.ports().get(0).dyn_into::<MessagePort>().ok();
        if let (Some(token), Some(start), Some(reply)) = (token, start, reply) {
            let end = request
                .end()
                .ok()
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
    let _ = container.try_start_messages();
    // Listening as long as the page lives.
    listener.forget();
}
