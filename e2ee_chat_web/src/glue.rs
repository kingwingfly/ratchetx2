//! Browser APIs that may be missing: the Web Locks API, in older browsers; the clipboard, outside
//! secure contexts; and service workers, there and in some private windows. Calling a missing one
//! would throw into the WebAssembly caller, so each is looked for first. web-sys has the Web Locks
//! API only among its unstable APIs, so it is called as JavaScript sees it.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use futures_channel::oneshot;
use js_sys::{Array, ArrayBuffer, Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{
    AbortController, AbortSignal, Blob, BlobPropertyBag, Clipboard, MessageEvent, MessagePort,
    Navigator, PageTransitionEvent, ServiceWorkerContainer,
};

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
    #[wasm_bindgen(method, setter = signal)]
    fn set_signal(this: &LockOptions, value: &AbortSignal);

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
    #[wasm_bindgen(method, getter, catch)]
    fn suffix(this: &MediaRequestMsg) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, getter, catch)]
    fn whole(this: &MediaRequestMsg) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, getter, catch)]
    fn invalid(this: &MediaRequestMsg) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(extends = Object)]
    type MediaReplyMsg;
    #[wasm_bindgen(method, setter = size)]
    fn set_size(this: &MediaReplyMsg, size: f64);
    #[wasm_bindgen(method, setter = start)]
    fn set_start(this: &MediaReplyMsg, start: f64);
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

/// Grace period to wait for a freshly closing or reloading tab to release its Web Lock before
/// showing `Open in another tab`, avoiding brief IPC-teardown flashes on fast reloads.
const LOCK_RELOAD_GRACE_MS: i32 = 250;

/// Handler callback for media range requests forwarded from `media-worker.js`.
type MediaHandler = Rc<dyn Fn(MediaRequest)>;

thread_local! {
    /// Whether `pagehide` has fired for this page (unconditionally set so neither late lock grants
    /// nor vault writes can proceed once the page begins unloading or entering bfcache).
    static LOCK_RELEASED: Cell<bool> = const { Cell::new(false) };
    /// Whether this page currently holds the exclusive vault Web Lock.
    static LOCK_HELD: Cell<bool> = const { Cell::new(false) };
    /// Resolver for the currently held Web Lock promise, invoked synchronously on `pagehide` so
    /// shared-process tabs and bfcache entries release `"e2ee-chat"` immediately.
    static LOCK_RESOLVER: RefCell<Option<Function>> = const { RefCell::new(None) };
    /// Active abortable lock-wait request (reload grace window or `Elsewhere` wait), cancelled on
    /// `pagehide` so unloading/reloading tabs never linger in the browser's Web Lock queue.
    static LOCK_WAIT_ABORT: RefCell<Option<(Rc<Cell<bool>>, AbortController)>> =
        const { RefCell::new(None) };
    /// Optional wakeup callback for a paused background `Elsewhere` waiter so `pagehide` unblocks
    /// it immediately and lets it clean up its event listeners.
    static LOCK_INACTIVE_WAKE: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    static LOCK_LIFECYCLE_INSTALLED: Cell<bool> = const { Cell::new(false) };
    /// Replaceable media-request handler invoked by the one-time service-worker message listener.
    static MEDIA_HANDLER: RefCell<Option<MediaHandler>> = const { RefCell::new(None) };
    static MEDIA_LISTENER_INSTALLED: Cell<bool> = const { Cell::new(false) };
}

/// Whether `pagehide` has fired for this page (releasing or forfeiting its exclusive vault lock).
pub fn lock_released() -> bool {
    LOCK_RELEASED.with(Cell::get)
}

/// Whether this page currently owns the exclusive vault lock and may open IndexedDB write
/// transactions.
pub fn owns_lock() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        LOCK_HELD.with(Cell::get) && !LOCK_RELEASED.with(Cell::get)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        !LOCK_RELEASED.with(Cell::get)
    }
}

#[cfg(test)]
pub(crate) fn set_lock_released_for_test(released: bool) -> bool {
    LOCK_RELEASED.with(|slot| slot.replace(released))
}

/// Whether this tab is currently visible and focused (eligible to automatically claim the vault
/// lock when another tab releases it, without stealing it from a foreground tab on refresh).
fn is_tab_active() -> bool {
    web_sys::window()
        .and_then(|window| window.document())
        .is_some_and(|doc| !doc.hidden() && doc.has_focus().unwrap_or(false))
}

/// Install one-time `pagehide` / `pageshow` listeners so:
/// - `pagehide` unconditionally marks the page closed, aborts any queued wait, and releases any
///   held Web Lock promise immediately, preventing leaked locks across shared renderer/WebContent
///   processes or bfcache entries.
/// - `pageshow` with `event.persisted() == true` reloads a bfcache-restored page so it never
///   resumes unlocked vault state without re-acquiring the exclusive lock.
fn install_lock_lifecycle() {
    let already_installed = LOCK_LIFECYCLE_INSTALLED.with(|installed| installed.replace(true));
    if already_installed {
        return;
    }
    let Some(window) = web_sys::window() else {
        return;
    };
    let on_pagehide =
        Closure::<dyn FnMut(PageTransitionEvent)>::new(move |_event: PageTransitionEvent| {
            LOCK_RELEASED.with(|released| released.set(true));
            LOCK_HELD.with(|held| held.set(false));
            MEDIA_HANDLER.with(|handler| *handler.borrow_mut() = None);
            if let Some((cancelled, controller)) =
                LOCK_WAIT_ABORT.with(|slot| slot.borrow_mut().take())
            {
                cancelled.set(true);
                controller.abort();
            }
            if let Some(wake) = LOCK_INACTIVE_WAKE.with(|slot| slot.borrow_mut().take()) {
                wake();
            }
            if let Some(resolve) = LOCK_RESOLVER.with(|slot| slot.borrow_mut().take()) {
                let _ = resolve.call0(&JsValue::UNDEFINED);
            }
        });
    let _ =
        window.add_event_listener_with_callback("pagehide", on_pagehide.as_ref().unchecked_ref());
    on_pagehide.forget();

    let on_pageshow =
        Closure::<dyn FnMut(PageTransitionEvent)>::new(move |event: PageTransitionEvent| {
            if event.persisted()
                && let Some(window) = web_sys::window()
            {
                let _ = window.location().reload();
            }
        });
    let _ =
        window.add_event_listener_with_callback("pageshow", on_pageshow.as_ref().unchecked_ref());
    on_pageshow.forget();
}

/// Return a held Web Lock promise whose `resolve` callback is stored for `pagehide` release.
/// Returns `None` if `pagehide` already fired (caller must immediately release the lock).
fn hold_acquired_lock() -> Option<Promise> {
    if lock_released() {
        return None;
    }
    let mut stored = None;
    let promise = Promise::new(&mut |resolve, _| {
        stored = Some(resolve);
    });
    LOCK_HELD.with(|held| held.set(true));
    if let Some(previous) = LOCK_RESOLVER.with(|slot| {
        slot.borrow_mut()
            .replace(stored.expect("promise executor runs synchronously"))
    }) {
        let _ = previous.call0(&JsValue::UNDEFINED);
    }
    Some(promise)
}

fn clear_lock_wait_abort(cancelled: &Rc<Cell<bool>>) {
    LOCK_WAIT_ABORT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(current, _)| Rc::ptr_eq(current, cancelled))
        {
            *slot = None;
        }
    });
}

async fn request_lock_if_available(
    locks: &WebLockManager,
    name: &str,
    unavailable: LockStatus,
) -> LockStatus {
    if lock_released() {
        return LockStatus::HeldElsewhere;
    }
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
            if held && let Some(promise) = hold_acquired_lock() {
                tell(LockStatus::Acquired);
                promise
            } else {
                tell(LockStatus::HeldElsewhere);
                Promise::resolve(&JsValue::UNDEFINED)
            }
        })
    };
    let options: LockOptions = Object::new().unchecked_into();
    options.set_if_available(true);
    match locks.request(name, &options, granted.as_ref()) {
        Ok(requested) => {
            spawn_local(async move {
                let _ = JsFuture::from(requested).await;
                drop(granted);
                tell(unavailable);
            });
        }
        Err(_) => tell(unavailable),
    }
    told.await.unwrap_or(unavailable)
}

struct EventListenerGuard {
    window: web_sys::Window,
    window_event: &'static str,
    doc: Option<web_sys::Document>,
    on_window: Closure<dyn FnMut()>,
    on_vis: Closure<dyn FnMut()>,
    clear_inactive_wake: bool,
}

impl Drop for EventListenerGuard {
    fn drop(&mut self) {
        if self.clear_inactive_wake {
            LOCK_INACTIVE_WAKE.with(|slot| {
                *slot.borrow_mut() = None;
            });
        }
        let _ = self.window.remove_event_listener_with_callback(
            self.window_event,
            self.on_window.as_ref().unchecked_ref(),
        );
        if let Some(ref doc) = self.doc {
            let _ = doc.remove_event_listener_with_callback(
                "visibilitychange",
                self.on_vis.as_ref().unchecked_ref(),
            );
        }
    }
}

struct TimeoutGuard {
    window: web_sys::Window,
    handle: Rc<Cell<Option<i32>>>,
    _closure: Closure<dyn FnMut()>,
}

impl Drop for TimeoutGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.window.clear_timeout_with_handle(handle);
        }
    }
}

enum SignalWaitResult {
    Status(LockStatus),
    AbortedInactive,
}

async fn request_lock_with_signal(
    locks: &WebLockManager,
    name: &str,
    timeout_ms: Option<i32>,
    abort_when_inactive: bool,
    fallback_on_error: LockStatus,
) -> SignalWaitResult {
    if lock_released() {
        return SignalWaitResult::Status(LockStatus::HeldElsewhere);
    }
    if abort_when_inactive && !is_tab_active() {
        return SignalWaitResult::AbortedInactive;
    }
    let Ok(controller) = AbortController::new() else {
        return SignalWaitResult::Status(fallback_on_error);
    };
    let (taken, told) = oneshot::channel();
    let taken = Rc::new(RefCell::new(Some(taken)));
    let tell = {
        let taken = taken.clone();
        move |result: SignalWaitResult| {
            if let Some(taken) = taken.borrow_mut().take() {
                let _ = taken.send(result);
            }
        }
    };
    let cancelled = Rc::new(Cell::new(false));
    let aborted_inactive = Rc::new(Cell::new(false));
    let timer_handle = Rc::new(Cell::new(None::<i32>));
    let clear_timer = {
        let timer_handle = timer_handle.clone();
        move || {
            if let Some(handle) = timer_handle.take()
                && let Some(window) = web_sys::window()
            {
                window.clear_timeout_with_handle(handle);
            }
        }
    };
    LOCK_WAIT_ABORT.with(|slot| {
        if let Some((prev_cancelled, prev_controller)) = slot
            .borrow_mut()
            .replace((cancelled.clone(), controller.clone()))
        {
            prev_cancelled.set(true);
            prev_controller.abort();
        }
    });
    let settled = Rc::new(Cell::new(false));
    let _cancel_on_drop = scopeguard::guard(
        (settled.clone(), cancelled.clone(), controller.clone()),
        |(settled, cancelled, controller)| {
            if !settled.get() {
                cancelled.set(true);
                clear_lock_wait_abort(&cancelled);
                controller.abort();
            }
        },
    );
    let mut _inactive_listeners: Option<EventListenerGuard> = None;
    if abort_when_inactive && let Some(window) = web_sys::window() {
        let make_abort = || {
            let cancelled = cancelled.clone();
            let aborted_inactive = aborted_inactive.clone();
            let controller = controller.clone();
            let tell = tell.clone();
            Closure::<dyn FnMut()>::new(move || {
                if !is_tab_active() {
                    aborted_inactive.set(true);
                    cancelled.set(true);
                    clear_lock_wait_abort(&cancelled);
                    controller.abort();
                    tell(SignalWaitResult::AbortedInactive);
                }
            })
        };
        let on_blur = make_abort();
        let on_vis = make_abort();
        let _ = window.add_event_listener_with_callback("blur", on_blur.as_ref().unchecked_ref());
        let doc = window.document();
        if let Some(ref doc) = doc {
            let _ = doc.add_event_listener_with_callback(
                "visibilitychange",
                on_vis.as_ref().unchecked_ref(),
            );
        }
        _inactive_listeners = Some(EventListenerGuard {
            window,
            window_event: "blur",
            doc,
            on_window: on_blur,
            on_vis,
            clear_inactive_wake: false,
        });
    }
    let mut _timeout_guard: Option<TimeoutGuard> = None;
    if let Some(ms) = timeout_ms
        && let Some(window) = web_sys::window()
    {
        let cancelled = cancelled.clone();
        let controller = controller.clone();
        let tell = tell.clone();
        let timer_handle_fire = timer_handle.clone();
        let on_timeout = Closure::<dyn FnMut()>::new(move || {
            timer_handle_fire.set(None);
            cancelled.set(true);
            clear_lock_wait_abort(&cancelled);
            controller.abort();
            tell(SignalWaitResult::Status(LockStatus::HeldElsewhere));
        });
        if let Ok(handle) = window.set_timeout_with_callback_and_timeout_and_arguments_0(
            on_timeout.as_ref().unchecked_ref(),
            ms,
        ) {
            timer_handle.set(Some(handle));
            _timeout_guard = Some(TimeoutGuard {
                window,
                handle: timer_handle.clone(),
                _closure: on_timeout,
            });
        }
    }
    let granted = {
        let tell = tell.clone();
        let cancelled = cancelled.clone();
        let aborted_inactive = aborted_inactive.clone();
        let clear_timer = clear_timer.clone();
        Closure::<dyn FnMut(JsValue) -> Promise>::new(move |lock: JsValue| {
            clear_timer();
            clear_lock_wait_abort(&cancelled);
            let held = !lock.is_null() && !lock.is_undefined();
            let inactive = abort_when_inactive && !is_tab_active();
            if held
                && !cancelled.get()
                && !inactive
                && let Some(promise) = hold_acquired_lock()
            {
                tell(SignalWaitResult::Status(LockStatus::Acquired));
                promise
            } else {
                if inactive || aborted_inactive.get() {
                    tell(SignalWaitResult::AbortedInactive);
                } else {
                    tell(SignalWaitResult::Status(LockStatus::HeldElsewhere));
                }
                Promise::resolve(&JsValue::UNDEFINED)
            }
        })
    };
    let options: LockOptions = Object::new().unchecked_into();
    options.set_signal(&controller.signal());
    match locks.request(name, &options, granted.as_ref()) {
        Ok(requested) => {
            let cancelled = cancelled.clone();
            let aborted_inactive = aborted_inactive.clone();
            let clear_timer = clear_timer.clone();
            spawn_local(async move {
                let _ = JsFuture::from(requested).await;
                drop(granted);
                clear_timer();
                clear_lock_wait_abort(&cancelled);
                if aborted_inactive.get() {
                    tell(SignalWaitResult::AbortedInactive);
                } else if cancelled.get() || lock_released() {
                    tell(SignalWaitResult::Status(LockStatus::HeldElsewhere));
                } else {
                    tell(SignalWaitResult::Status(fallback_on_error));
                }
            });
        }
        Err(_) => {
            clear_timer();
            clear_lock_wait_abort(&cancelled);
            tell(SignalWaitResult::Status(fallback_on_error));
        }
    }
    let outcome = told
        .await
        .unwrap_or(SignalWaitResult::Status(fallback_on_error));
    settled.set(true);
    drop(_timeout_guard);
    drop(_inactive_listeners);
    outcome
}

/// Suspend until this tab is both visible and focused (or `pagehide` closes it), cleaning up all
/// temporary event listeners even if this future is dropped before completing.
async fn wait_until_tab_active() {
    if is_tab_active() || lock_released() {
        return;
    }
    let Some(window) = web_sys::window() else {
        return;
    };
    let (tx, rx) = oneshot::channel::<()>();
    let tx = Rc::new(RefCell::new(Some(tx)));
    let wake = {
        let tx = tx.clone();
        move || {
            if let Some(tx) = tx.borrow_mut().take() {
                let _ = tx.send(());
            }
        }
    };
    LOCK_INACTIVE_WAKE.with(|slot| {
        let wake = wake.clone();
        *slot.borrow_mut() = Some(Box::new(wake));
    });
    let on_focus = {
        let wake = wake.clone();
        Closure::<dyn FnMut()>::new(move || {
            if is_tab_active() || lock_released() {
                wake();
            }
        })
    };
    let on_vis = {
        let wake = wake.clone();
        Closure::<dyn FnMut()>::new(move || {
            if is_tab_active() || lock_released() {
                wake();
            }
        })
    };
    let _ = window.add_event_listener_with_callback("focus", on_focus.as_ref().unchecked_ref());
    let doc = window.document();
    if let Some(ref doc) = doc {
        let _ = doc
            .add_event_listener_with_callback("visibilitychange", on_vis.as_ref().unchecked_ref());
    }
    let _listeners = EventListenerGuard {
        window,
        window_event: "focus",
        doc,
        on_window: on_focus,
        on_vis,
        clear_inactive_wake: true,
    };
    if is_tab_active() || lock_released() {
        wake();
    }
    let _ = rx.await;
}

/// Take the lock `name` for as long as the page lives, failing closed if another tab holds it
/// or if the Web Locks API is unavailable or fails (preventing concurrent vault corruption).
///
/// Installs `pagehide` release and bfcache-restore reload handlers, and waits briefly if the lock
/// is busy so fast same-tab reloads or just-closed tabs do not flash `Open in another tab`.
pub async fn take_lock(name: &str) -> LockStatus {
    let insecure_context = !is_secure_context();
    let unavailable = LockStatus::Unavailable { insecure_context };
    let Ok(Some(locks)) = navigator().optional_locks() else {
        return unavailable;
    };
    install_lock_lifecycle();
    if lock_released() {
        return LockStatus::HeldElsewhere;
    }
    match request_lock_if_available(&locks, name, unavailable).await {
        LockStatus::HeldElsewhere if !lock_released() => match request_lock_with_signal(
            &locks,
            name,
            Some(LOCK_RELOAD_GRACE_MS),
            false,
            LockStatus::HeldElsewhere,
        )
        .await
        {
            SignalWaitResult::Status(status) => status,
            SignalWaitResult::AbortedInactive => LockStatus::HeldElsewhere,
        },
        status => status,
    }
}

/// Wait until the exclusive lock `name` becomes available while this tab is visible and focused
/// (e.g. while displaying `Open in another tab`), pausing whenever the tab moves to the background
/// or loses focus so refreshing or locking a foreground tab never hands the vault to an idle
/// background waiter.
pub async fn wait_for_lock_when_active(name: &str) -> LockStatus {
    let insecure_context = !is_secure_context();
    let unavailable = LockStatus::Unavailable { insecure_context };
    let Ok(Some(locks)) = navigator().optional_locks() else {
        return unavailable;
    };
    install_lock_lifecycle();
    loop {
        if lock_released() {
            return LockStatus::HeldElsewhere;
        }
        if !is_tab_active() {
            wait_until_tab_active().await;
            continue;
        }
        match request_lock_with_signal(&locks, name, None, true, LockStatus::HeldElsewhere).await {
            SignalWaitResult::AbortedInactive => continue,
            SignalWaitResult::Status(status) => return status,
        }
    }
}

/// Copy `text` to the clipboard; `false` if the browser refused.
pub async fn copy(text: &str) -> bool {
    let Ok(Some(clipboard)) = navigator().optional_clipboard() else {
        return false;
    };
    JsFuture::from(clipboard.write_text(text)).await.is_ok()
}

/// Start copying PNG `bytes` to the clipboard synchronously within a user gesture, returning the
/// pending clipboard write promise if `navigator.clipboard.write` and `ClipboardItem` are present.
pub fn start_copy_png(bytes: &[u8]) -> Option<Promise> {
    let clipboard = navigator().optional_clipboard().ok().flatten()?;
    let window = web_sys::window()?;
    let clipboard_item_ctor = Reflect::get(&window, &JsValue::from_str("ClipboardItem"))
        .ok()?
        .dyn_into::<Function>()
        .ok()?;
    let write_fn = Reflect::get(&clipboard, &JsValue::from_str("write"))
        .ok()?
        .dyn_into::<Function>()
        .ok()?;

    let parts = Array::of1(&Uint8Array::from(bytes));
    let options = BlobPropertyBag::new();
    options.set_type("image/png");
    let blob = Blob::new_with_u8_array_sequence_and_options(&parts, &options).ok()?;

    let entry = Object::new();
    Reflect::set(&entry, &JsValue::from_str("image/png"), &blob).ok()?;
    let item = Reflect::construct(&clipboard_item_ctor, &Array::of1(&entry)).ok()?;
    write_fn
        .call1(&clipboard, &Array::of1(&item))
        .ok()?
        .dyn_into::<Promise>()
        .ok()
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

/// The byte range requested by the service worker for a media stream.
pub enum MediaRange {
    Whole,
    From { start: u64, end: Option<u64> },
    Suffix(u64),
    Invalid,
}

/// An HTTP error replying to a [`MediaRequest`], including total size for `416` `Content-Range`.
pub enum MediaError {
    Status(u16),
    OutOfRange { size: u64 },
}

/// The service worker's request for the bytes of a stream for a player of the page.
pub struct MediaRequest {
    pub token: String,
    pub range: MediaRange,
    reply: MessagePort,
    aborted: Rc<Cell<bool>>,
    _on_abort: Option<Closure<dyn FnMut(MessageEvent)>>,
}

/// What answers a [`MediaRequest`]: the stream's total size, resolved start offset, MIME type,
/// and bytes; or a [`MediaError`].
pub type MediaReply<'a> = Result<(u64, u64, &'a str, &'a [u8]), MediaError>;

impl MediaRequest {
    /// Whether the service worker signalled that the underlying fetch request was aborted.
    #[allow(dead_code)] // Used by streaming range cancellation when wired.
    pub fn is_aborted(&self) -> bool {
        self.aborted.get()
    }

    pub fn reply(self, reply: MediaReply<'_>) {
        if self.aborted.get() {
            return;
        }
        let message: MediaReplyMsg = Object::new().unchecked_into();
        let transfer = Array::new();
        match reply {
            Ok((size, start, mime, bytes)) => {
                // Moved to the service worker rather than copied.
                let buffer = Uint8Array::from(bytes).buffer();
                message.set_size(size as f64);
                message.set_start(start as f64);
                message.set_mime(mime);
                message.set_bytes(&buffer);
                transfer.push(&buffer);
            }
            Err(MediaError::Status(status)) => message.set_error(status),
            Err(MediaError::OutOfRange { size }) => {
                message.set_error(416);
                message.set_size(size as f64);
            }
        }
        let _ = self
            .reply
            .post_message_with_transferable(&message, &transfer);
    }
}

impl Drop for MediaRequest {
    fn drop(&mut self) {
        self.reply.set_onmessage(None);
        self.reply.close();
    }
}

/// Answer the service worker's requests for media, as they come, with `answer`.
///
/// Idempotent: registers the underlying `serviceWorker` `message` event listener once per page
/// lifetime and atomically replaces the active handler so repeated unlocks never install
/// colliding listeners.
pub fn serve_media(answer: impl Fn(MediaRequest) + 'static) {
    MEDIA_HANDLER.with(|handler| {
        *handler.borrow_mut() = Some(Rc::new(answer));
    });
    if MEDIA_LISTENER_INSTALLED.with(|installed| installed.replace(true)) {
        return;
    }
    let Ok(Some(container)) = navigator().optional_service_worker() else {
        MEDIA_LISTENER_INSTALLED.with(|installed| installed.set(false));
        return;
    };
    let listener = Closure::<dyn Fn(MessageEvent)>::new(move |event: MessageEvent| {
        let data = event.data();
        if !data.is_object() || data.is_null() {
            return;
        }
        let request: MediaRequestMsg = data.unchecked_into();
        let token = request.media().ok().and_then(|v| v.as_string());
        let reply = event.ports().get(0).dyn_into::<MessagePort>().ok();
        let (Some(token), Some(reply)) = (token, reply) else {
            return;
        };
        let valid_u64 = |v: f64| {
            (v.is_finite() && (0.0..=9_007_199_254_740_991.0).contains(&v) && v.fract() == 0.0)
                .then_some(v as u64)
        };
        let range = if request.invalid().ok().and_then(|v| v.as_bool()) == Some(true) {
            MediaRange::Invalid
        } else if request.whole().ok().and_then(|v| v.as_bool()) == Some(true) {
            MediaRange::Whole
        } else if let Some(suffix) = request
            .suffix()
            .ok()
            .and_then(|v| v.as_f64())
            .and_then(valid_u64)
        {
            MediaRange::Suffix(suffix)
        } else if let Some(start) = request
            .start()
            .ok()
            .and_then(|v| v.as_f64())
            .and_then(valid_u64)
        {
            let end = request
                .end()
                .ok()
                .and_then(|v| v.as_f64())
                .and_then(valid_u64);
            MediaRange::From { start, end }
        } else {
            MediaRange::Invalid
        };
        let aborted = Rc::new(Cell::new(false));
        let on_abort = {
            let aborted = aborted.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |msg: MessageEvent| {
                let data = msg.data();
                if data.is_object()
                    && !data.is_null()
                    && Reflect::get(&data, &JsValue::from_str("aborted"))
                        .ok()
                        .and_then(|v| v.as_bool())
                        == Some(true)
                {
                    aborted.set(true);
                }
            })
        };
        reply.set_onmessage(Some(on_abort.as_ref().unchecked_ref()));
        let req = MediaRequest {
            token,
            range,
            reply,
            aborted,
            _on_abort: Some(on_abort),
        };
        if let Some(handler) = MEDIA_HANDLER.with(|h| h.borrow().clone()) {
            handler(req);
        } else {
            req.reply(Err(MediaError::Status(404)));
        }
    });
    let _ =
        container.add_event_listener_with_callback("message", listener.as_ref().unchecked_ref());
    // Messages are let through once the page loads, or once asked to, which web-sys cannot.
    let _ = container.try_start_messages();
    // Listening once for as long as the page lives.
    listener.forget();
}
