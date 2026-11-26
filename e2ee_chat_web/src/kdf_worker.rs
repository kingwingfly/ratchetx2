//! Ephemeral Argon2id KDF worker client (`vault_kdf`).
//!
//! Spawns a fresh dedicated Web Worker loaded from `<meta name="e2ee-worker-manifest">` under
//! key `"vault_kdf"`, transfers the passphrase and salt `ArrayBuffer`s to it, enforces a 30s
//! deadline and explicit cancellation, and **unconditionally** calls `worker.terminate()` on
//! completion, error, cancellation, timeout, future drop, or `pagehide` so the 64 MiB Argon2id
//! linear WASM memory is reclaimed immediately.
//!
//! # Passphrase Memory Hygiene Caveat
//!
//! In the browser, `SecretInput::take()` (`app/common.rs`) reads an immutable JavaScript `String`
//! from `HtmlInputElement::value()` before copying bytes into `Zeroizing<String>`. Transferring
//! and zeroing the `ArrayBuffer` views between the main thread and `vault_kdf` is therefore
//! best-effort hygiene rather than an absolute guarantee against JS engine heap retention until GC.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    fmt,
    rc::Rc,
};

use zeroize::Zeroizing;

#[cfg(target_arch = "wasm32")]
use futures_channel::oneshot;
#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Uint8Array};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
#[cfg(target_arch = "wasm32")]
use web_sys::{Event, MessageEvent};

use crate::vault::{
    ARGON2_ITERATIONS_MAX, ARGON2_ITERATIONS_MIN, ARGON2_MEMORY_MAX, ARGON2_MEMORY_MIN,
    ARGON2_PARALLELISM_MAX, ARGON2_PARALLELISM_MIN, ARGON2_SALT_MAX, ARGON2_SALT_MIN,
};

#[cfg(target_arch = "wasm32")]
use crate::util::js_error;

/// Worker manifest key injected by `scripts/post_build.sh` for `e2ee_chat_kdf`'s `vault_kdf` bin.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub const KDF_WORKER_KEY: &str = "vault_kdf";
/// Hard deadline covering worker startup (`"ready"`) plus Argon2id derivation (30 seconds).
#[cfg(target_arch = "wasm32")]
const KDF_TIMEOUT_MS: i32 = 30_000;
/// Maximum passphrase length accepted (1 MiB, matching `e2ee_chat_kdf::MAX_PASSPHRASE_BYTES`).
const MAX_PASSPHRASE_BYTES: usize = 1 << 20;
/// Actionable deploy-skew notice when `vault_kdf` fails before `"ready"` while online.
#[cfg(target_arch = "wasm32")]
const DEPLOY_SKEW_NOTICE: &str =
    "A newer version of this app was deployed — reload to unlock your vault";

/// Errors produced by ephemeral Argon2id key derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfError {
    /// Cancelled explicitly by the user or synchronously on `pagehide`.
    Cancelled,
    /// Exceeded the 30-second worker startup/derivation deadline.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    Timeout,
    /// Rejected parameter bounds before spawning or inside the KDF implementation.
    InvalidParams(String),
    /// Worker load, protocol, or runtime failure.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    Worker(String),
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "key derivation was cancelled"),
            Self::Timeout => write!(f, "key derivation timed out; try again"),
            Self::InvalidParams(msg) | Self::Worker(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for KdfError {}

/// Cooperative + synchronous-termination cancellation handle for an in-flight KDF operation.
#[derive(Clone)]
pub struct KdfCancelToken {
    inner: Rc<CancelInner>,
}

struct CancelInner {
    cancelled: Cell<bool>,
    on_cancel: RefCell<Vec<Box<dyn FnOnce()>>>,
}

impl Default for KdfCancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl KdfCancelToken {
    pub fn new() -> Self {
        Self {
            inner: Rc::new(CancelInner {
                cancelled: Cell::new(false),
                on_cancel: RefCell::new(Vec::new()),
            }),
        }
    }

    /// Synchronously mark cancelled and invoke all registered termination callbacks. Idempotent.
    pub fn cancel(&self) {
        if self.inner.cancelled.replace(true) {
            return;
        }
        let callbacks: Vec<_> = self.inner.on_cancel.borrow_mut().drain(..).collect();
        for cb in callbacks {
            cb();
        }
    }

    /// Whether [`cancel`](Self::cancel) has been called on this token.
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.get()
    }

    /// Identity comparison used by auth forms to clear only their own active token slot.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }

    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    fn register_on_cancel(&self, callback: impl FnOnce() + 'static) {
        if self.is_cancelled() {
            callback();
        } else {
            self.inner.on_cancel.borrow_mut().push(Box::new(callback));
        }
    }
}

thread_local! {
    /// Active KDF termination hooks so `pagehide` (`cancel_active()`) synchronously terminates
    /// every live KDF worker regardless of which UI form spawned it.
    static ACTIVE_KDF: RefCell<HashMap<u64, Box<dyn FnOnce()>>> = RefCell::new(HashMap::new());
    static NEXT_ACTIVE_ID: Cell<u64> = const { Cell::new(0) };
    #[cfg(target_arch = "wasm32")]
    static NEXT_REQ_ID: Cell<u32> = const { Cell::new(0) };
    #[cfg(all(test, target_arch = "wasm32"))]
    static TEST_KDF_SCRIPT: RefCell<Option<String>> = const { RefCell::new(None) };
    #[cfg(all(test, target_arch = "wasm32"))]
    static TEST_TIMEOUT_MS: Cell<Option<i32>> = const { Cell::new(None) };
    #[cfg(all(test, target_arch = "wasm32"))]
    static TEST_ONLINE: Cell<Option<bool>> = const { Cell::new(None) };
}

fn next_active_id() -> u64 {
    NEXT_ACTIVE_ID.with(|cell| {
        let next = cell.get().wrapping_add(1).max(1);
        cell.set(next);
        next
    })
}

/// Synchronously cancel and terminate every active KDF operation (invoked on `pagehide` and
/// manual vault lock).
pub fn cancel_active() {
    let callbacks: Vec<_> =
        ACTIVE_KDF.with(|map| map.borrow_mut().drain().map(|(_, cb)| cb).collect());
    for cb in callbacks {
        cb();
    }
}

#[cfg(test)]
pub(crate) fn active_kdf_count() -> usize {
    ACTIVE_KDF.with(|map| map.borrow().len())
}

/// Validate Argon2id bounds before spawning the worker.
fn validate_kdf_params(
    passphrase_len: usize,
    salt_len: usize,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<(), KdfError> {
    if passphrase_len > MAX_PASSPHRASE_BYTES {
        return Err(KdfError::InvalidParams(
            "passphrase exceeds maximum allowed length".to_string(),
        ));
    }
    if !(ARGON2_SALT_MIN..=ARGON2_SALT_MAX).contains(&salt_len) {
        return Err(KdfError::InvalidParams(format!(
            "invalid vault salt length {salt_len}"
        )));
    }
    if !(ARGON2_MEMORY_MIN..=ARGON2_MEMORY_MAX).contains(&memory_kib) {
        return Err(KdfError::InvalidParams(format!(
            "Argon2 memory {memory_kib} KiB outside allowed range [{ARGON2_MEMORY_MIN}..={ARGON2_MEMORY_MAX}]"
        )));
    }
    if !(ARGON2_ITERATIONS_MIN..=ARGON2_ITERATIONS_MAX).contains(&iterations) {
        return Err(KdfError::InvalidParams(format!(
            "Argon2 iterations {iterations} outside allowed range [{ARGON2_ITERATIONS_MIN}..={ARGON2_ITERATIONS_MAX}]"
        )));
    }
    if !(ARGON2_PARALLELISM_MIN..=ARGON2_PARALLELISM_MAX).contains(&parallelism) {
        return Err(KdfError::InvalidParams(format!(
            "Argon2 parallelism {parallelism} outside allowed range [{ARGON2_PARALLELISM_MIN}..={ARGON2_PARALLELISM_MAX}]"
        )));
    }
    Ok(())
}

/// Derive a 32-byte Argon2id KEK asynchronously.
///
/// - On `wasm32`, runs inside a freshly spawned ephemeral `vault_kdf` dedicated Web Worker and
///   unconditionally terminates the worker before returning or on drop/cancel/timeout/`pagehide`.
/// - On host targets, runs [`e2ee_chat_kdf::derive_kek`] directly while honoring `cancel` and
///   [`cancel_active`].
pub async fn derive_kek_async(
    passphrase: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    cancel: &KdfCancelToken,
) -> Result<Zeroizing<[u8; 32]>, KdfError> {
    validate_kdf_params(
        passphrase.len(),
        salt.len(),
        memory_kib,
        iterations,
        parallelism,
    )?;
    if cancel.is_cancelled() {
        return Err(KdfError::Cancelled);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let active_id = next_active_id();
        let token_for_global = cancel.clone();
        ACTIVE_KDF.with(|map| {
            map.borrow_mut().insert(
                active_id,
                Box::new(move || {
                    token_for_global.cancel();
                }),
            );
        });
        let _cleanup = scopeguard::guard(active_id, |id| {
            ACTIVE_KDF.with(|map| {
                map.borrow_mut().remove(&id);
            });
        });
        if cancel.is_cancelled() {
            return Err(KdfError::Cancelled);
        }
        let derived =
            e2ee_chat_kdf::derive_kek(passphrase, salt, memory_kib, iterations, parallelism)
                .map_err(KdfError::InvalidParams)?;
        if cancel.is_cancelled() {
            return Err(KdfError::Cancelled);
        }
        Ok(derived)
    }

    #[cfg(target_arch = "wasm32")]
    {
        wasm_impl::derive_in_worker(
            passphrase,
            salt,
            memory_kib,
            iterations,
            parallelism,
            cancel,
        )
        .await
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm_impl {
    use super::*;

    fn next_req_id() -> u32 {
        NEXT_REQ_ID.with(|cell| {
            let next = cell.get().wrapping_add(1).max(1);
            cell.set(next);
            next
        })
    }

    fn timeout_ms() -> i32 {
        #[cfg(test)]
        if let Some(ms) = TEST_TIMEOUT_MS.with(Cell::get) {
            return ms;
        }
        KDF_TIMEOUT_MS
    }

    fn is_online() -> bool {
        #[cfg(test)]
        if let Some(online) = TEST_ONLINE.with(Cell::get) {
            return online;
        }
        web_sys::window().is_none_or(|w| w.navigator().on_line())
    }

    fn resolve_kdf_script() -> Result<String, KdfError> {
        #[cfg(test)]
        if let Some(url) = TEST_KDF_SCRIPT.with(|slot| slot.borrow().clone()) {
            return Ok(url);
        }
        crate::workers::resolve_worker_script(KDF_WORKER_KEY).map_err(KdfError::Worker)
    }

    type KdfResultSender = oneshot::Sender<Result<Zeroizing<[u8; 32]>, KdfError>>;

    struct WorkerCleanup {
        worker: web_sys::Worker,
        active_id: u64,
        timer_handle: Cell<Option<i32>>,
        ready: Cell<bool>,
        terminated: Cell<bool>,
        ready_tx: RefCell<Option<oneshot::Sender<()>>>,
        result_tx: RefCell<Option<KdfResultSender>>,
    }

    impl WorkerCleanup {
        fn is_terminated(&self) -> bool {
            self.terminated.get()
        }

        fn mark_ready(&self) {
            if self.terminated.get() {
                return;
            }
            self.ready.set(true);
            if let Some(tx) = self.ready_tx.borrow_mut().take() {
                let _ = tx.send(());
            }
        }

        /// Unconditionally detach handlers, clear timeout, unregister from `ACTIVE_KDF`,
        /// terminate the worker (reclaiming 64 MiB WASM linear memory), and settle the waiter.
        fn finish(&self, outcome: Result<Zeroizing<[u8; 32]>, KdfError>) {
            if !self.terminated.replace(true) {
                if let Some(handle) = self.timer_handle.take()
                    && let Some(window) = web_sys::window()
                {
                    window.clear_timeout_with_handle(handle);
                }
                ACTIVE_KDF.with(|map| {
                    map.borrow_mut().remove(&self.active_id);
                });
                self.worker.set_onmessage(None);
                self.worker.set_onmessageerror(None);
                self.worker.set_onerror(None);
                self.worker.terminate();
            }
            // Drop any pending ready sender so `ready_rx.await` wakes up immediately.
            let _ = self.ready_tx.borrow_mut().take();
            if let Some(tx) = self.result_tx.borrow_mut().take() {
                let _ = tx.send(outcome);
            }
        }
    }

    pub(super) async fn derive_in_worker(
        passphrase: &[u8],
        salt: &[u8],
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        cancel: &KdfCancelToken,
    ) -> Result<Zeroizing<[u8; 32]>, KdfError> {
        let script = resolve_kdf_script()?;
        if cancel.is_cancelled() {
            return Err(KdfError::Cancelled);
        }
        let worker = web_sys::Worker::new(&script).map_err(|e| KdfError::Worker(js_error(e)))?;
        let req_id = next_req_id();
        let active_id = next_active_id();
        let (ready_tx, ready_rx) = oneshot::channel::<()>();
        let (result_tx, result_rx) = oneshot::channel::<Result<Zeroizing<[u8; 32]>, KdfError>>();

        let cleanup = Rc::new(WorkerCleanup {
            worker: worker.clone(),
            active_id,
            timer_handle: Cell::new(None),
            ready: Cell::new(false),
            terminated: Cell::new(false),
            ready_tx: RefCell::new(Some(ready_tx)),
            result_tx: RefCell::new(Some(result_tx)),
        });

        // Unconditional Drop guard: even if this future is dropped mid-await, the worker is
        // terminated immediately and its linear memory reclaimed.
        let _drop_guard = scopeguard::guard(cleanup.clone(), |c| {
            c.finish(Err(KdfError::Cancelled));
        });

        // Register synchronous cancellation hooks for both `pagehide` (`cancel_active`) and the
        // per-request `KdfCancelToken`.
        {
            let c = cleanup.clone();
            ACTIVE_KDF.with(|map| {
                map.borrow_mut().insert(
                    active_id,
                    Box::new(move || c.finish(Err(KdfError::Cancelled))),
                );
            });
        }
        {
            let c = cleanup.clone();
            cancel.register_on_cancel(move || c.finish(Err(KdfError::Cancelled)));
        }
        if cleanup.is_terminated() {
            return result_rx.await.unwrap_or(Err(KdfError::Cancelled));
        }

        // Closures live in this async stack frame and are never dropped from inside themselves.
        let on_timeout = {
            let c = cleanup.clone();
            Closure::<dyn FnMut()>::new(move || {
                c.timer_handle.set(None);
                c.finish(Err(KdfError::Timeout));
            })
        };
        if let Some(window) = web_sys::window()
            && let Ok(handle) = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                on_timeout.as_ref().unchecked_ref(),
                timeout_ms(),
            )
        {
            cleanup.timer_handle.set(Some(handle));
        }

        let on_message = {
            let c = cleanup.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                if c.is_terminated() {
                    return;
                }
                let data = event.data();
                if data.as_string().as_deref() == Some("ready") {
                    c.mark_ready();
                    return;
                }
                let Ok(arr) = data.dyn_into::<Array>() else {
                    c.finish(Err(KdfError::Worker(
                        "malformed reply from key derivation worker".to_string(),
                    )));
                    return;
                };
                if arr.length() != 3 {
                    c.finish(Err(KdfError::Worker(
                        "malformed reply from key derivation worker".to_string(),
                    )));
                    return;
                }
                let reply_id = arr.get(0).as_f64();
                if reply_id != Some(f64::from(req_id)) {
                    return;
                }
                match arr.get(1).as_bool() {
                    Some(true) => match arr.get(2).dyn_into::<Uint8Array>() {
                        Ok(out) if out.length() == 32 => {
                            let mut kek = Zeroizing::new([0u8; 32]);
                            out.copy_to(kek.as_mut_slice());
                            out.fill(0, 0, out.length());
                            c.finish(Ok(kek));
                        }
                        Ok(out) => {
                            out.fill(0, 0, out.length());
                            c.finish(Err(KdfError::Worker(
                                "key derivation worker returned wrong key length".to_string(),
                            )));
                        }
                        Err(_) => c.finish(Err(KdfError::Worker(
                            "key derivation worker returned invalid key buffer".to_string(),
                        ))),
                    },
                    Some(false) => {
                        let msg = arr
                            .get(2)
                            .as_string()
                            .unwrap_or_else(|| "key derivation failed".to_string());
                        c.finish(Err(KdfError::Worker(msg)));
                    }
                    None => c.finish(Err(KdfError::Worker(
                        "malformed status from key derivation worker".to_string(),
                    ))),
                }
            })
        };

        let on_message_error = {
            let c = cleanup.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |_event: MessageEvent| {
                c.finish(Err(KdfError::Worker(
                    "key derivation reply could not be decoded".to_string(),
                )));
            })
        };

        let on_error = {
            let c = cleanup.clone();
            Closure::<dyn FnMut(Event)>::new(move |event: Event| {
                event.prevent_default();
                let reason = if !c.ready.get() && is_online() {
                    DEPLOY_SKEW_NOTICE
                } else {
                    "key derivation worker failed"
                };
                c.finish(Err(KdfError::Worker(reason.to_string())));
            })
        };

        worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        worker.set_onmessageerror(Some(on_message_error.as_ref().unchecked_ref()));
        worker.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        // Wait for the worker's `"ready"` handshake before copying passphrase into JS buffers.
        if ready_rx.await.is_err() || cancel.is_cancelled() || cleanup.is_terminated() {
            return result_rx.await.unwrap_or(Err(KdfError::Cancelled));
        }

        let pass_u8 = Uint8Array::from(passphrase);
        let salt_u8 = Uint8Array::from(salt);
        let msg = Array::new_with_length(6);
        msg.set(0, JsValue::from(req_id));
        msg.set(1, pass_u8.clone().into());
        msg.set(2, salt_u8.clone().into());
        msg.set(3, JsValue::from(memory_kib));
        msg.set(4, JsValue::from(iterations));
        msg.set(5, JsValue::from(parallelism));
        let transfer = Array::of2(&pass_u8.buffer(), &salt_u8.buffer());

        if let Err(err) = worker.post_message_with_transfer(&msg, &transfer) {
            pass_u8.fill(0, 0, pass_u8.length());
            salt_u8.fill(0, 0, salt_u8.length());
            cleanup.finish(Err(KdfError::Worker(js_error(err))));
            return result_rx.await.unwrap_or(Err(KdfError::Cancelled));
        }

        let outcome = result_rx.await.unwrap_or(Err(KdfError::Cancelled));
        // Ensure closures stay alive until after `cleanup.finish` has detached all handlers.
        cleanup.finish(Err(KdfError::Cancelled));
        drop(on_message);
        drop(on_message_error);
        drop(on_error);
        drop(on_timeout);
        outcome
    }
}

/// Deterministic SubtleCrypto-backed test KDF worker implementing the exact `vault_kdf` wire
/// protocol (`"ready"`, `[id, pass_u8, salt_u8, mem, iter, par]` -> `[id, true, out]` with
/// transferable `ArrayBuffer`s) for browser `wasm-bindgen-test` harnesses that run without `dist/`.
#[cfg(all(test, target_arch = "wasm32"))]
pub(crate) struct TestKdfWorkerGuard {
    url: String,
    previous: Option<String>,
}

#[cfg(all(test, target_arch = "wasm32"))]
impl Drop for TestKdfWorkerGuard {
    fn drop(&mut self) {
        TEST_KDF_SCRIPT.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
        let _ = web_sys::Url::revoke_object_url(&self.url);
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
pub(crate) fn install_test_kdf_worker() -> TestKdfWorkerGuard {
    const DETERMINISTIC_TEST_KDF_WORKER: &str = r#"
        self.onmessage = async (event) => {
            const [id, pass, salt, mem, iter, par] = event.data;
            if (!(pass instanceof Uint8Array) || !(salt instanceof Uint8Array)) {
                self.postMessage([id, false, "invalid buffers"]);
                return;
            }
            const buf = new Uint8Array(pass.length + salt.length + 12);
            buf.set(pass, 0);
            buf.set(salt, pass.length);
            const dv = new DataView(buf.buffer);
            dv.setUint32(pass.length + salt.length, mem, false);
            dv.setUint32(pass.length + salt.length + 4, iter, false);
            dv.setUint32(pass.length + salt.length + 8, par, false);
            pass.fill(0);
            salt.fill(0);
            const digest = await crypto.subtle.digest("SHA-256", buf);
            buf.fill(0);
            const out = new Uint8Array(digest);
            self.postMessage([id, true, out], [out.buffer]);
        };
        self.postMessage("ready");
    "#;
    install_custom_test_kdf_worker(DETERMINISTIC_TEST_KDF_WORKER)
}

#[cfg(all(test, target_arch = "wasm32"))]
fn install_custom_test_kdf_worker(source: &str) -> TestKdfWorkerGuard {
    use web_sys::{Blob, BlobPropertyBag, Url};
    let parts = Array::of1(&JsValue::from_str(source));
    let opts = BlobPropertyBag::new();
    opts.set_type("application/javascript");
    let blob = Blob::new_with_str_sequence_and_options(&parts, &opts).expect("KDF test blob");
    let url = Url::create_object_url_with_blob(&blob).expect("KDF test blob URL");
    let previous = TEST_KDF_SCRIPT.with(|slot| slot.borrow_mut().replace(url.clone()));
    TestKdfWorkerGuard { url, previous }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn host_kdf_derives_deterministically_and_honors_cancel_and_bounds() {
        let salt = [0x42u8; 16];
        let token = KdfCancelToken::new();
        let k1 = futures::executor::block_on(derive_kek_async(
            b"secret passphrase",
            &salt,
            ARGON2_MEMORY_MIN,
            1,
            1,
            &token,
        ))
        .expect("derive_kek_async host");
        let direct =
            e2ee_chat_kdf::derive_kek(b"secret passphrase", &salt, ARGON2_MEMORY_MIN, 1, 1)
                .expect("direct derive_kek");
        assert_eq!(*k1, *direct);
        assert_eq!(active_kdf_count(), 0);

        // Pre-cancelled token aborts immediately without running Argon2id.
        let cancelled = KdfCancelToken::new();
        cancelled.cancel();
        assert_eq!(
            futures::executor::block_on(derive_kek_async(
                b"secret passphrase",
                &salt,
                ARGON2_MEMORY_MIN,
                1,
                1,
                &cancelled,
            )),
            Err(KdfError::Cancelled)
        );

        // Invalid parameter bounds fail cleanly with InvalidParams.
        assert!(matches!(
            futures::executor::block_on(derive_kek_async(
                b"secret",
                &[0u8; 8],
                ARGON2_MEMORY_MIN,
                1,
                1,
                &token,
            )),
            Err(KdfError::InvalidParams(_))
        ));
        assert!(matches!(
            futures::executor::block_on(derive_kek_async(
                b"secret",
                &salt,
                ARGON2_MEMORY_MAX + 1,
                1,
                1,
                &token,
            )),
            Err(KdfError::InvalidParams(_))
        ));
        assert!(matches!(
            futures::executor::block_on(derive_kek_async(
                b"secret",
                &salt,
                ARGON2_MEMORY_MIN,
                0,
                1,
                &token,
            )),
            Err(KdfError::InvalidParams(_))
        ));
        assert!(matches!(
            futures::executor::block_on(derive_kek_async(
                b"secret",
                &salt,
                ARGON2_MEMORY_MIN,
                1,
                0,
                &token,
            )),
            Err(KdfError::InvalidParams(_))
        ));
    }

    #[test]
    fn cancel_token_invokes_callbacks_synchronously_and_once() {
        let token = KdfCancelToken::new();
        let hits = Rc::new(Cell::new(0u32));
        let h1 = hits.clone();
        token.register_on_cancel(move || h1.set(h1.get() + 1));
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
        assert_eq!(hits.get(), 1);
        // Second cancel is idempotent.
        token.cancel();
        assert_eq!(hits.get(), 1);
        // Registering after cancel fires immediately.
        let h2 = hits.clone();
        token.register_on_cancel(move || h2.set(h2.get() + 1));
        assert_eq!(hits.get(), 2);
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::*;
    use web_sys::{Blob, BlobPropertyBag, Element, Url};

    use super::*;

    struct ManifestMetaGuard {
        element: Element,
    }

    impl ManifestMetaGuard {
        fn install(content: &str) -> Self {
            crate::workers::reset_manifest_cache();
            let document = web_sys::window()
                .and_then(|w| w.document())
                .expect("test document");
            if let Ok(Some(existing)) =
                document.query_selector(r#"meta[name="e2ee-worker-manifest"]"#)
            {
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
            crate::workers::reset_manifest_cache();
        }
    }

    fn make_blob_url(source: &str) -> String {
        let parts = Array::of1(&JsValue::from_str(source));
        let opts = BlobPropertyBag::new();
        opts.set_type("application/javascript");
        let blob = Blob::new_with_str_sequence_and_options(&parts, &opts).expect("worker blob");
        Url::create_object_url_with_blob(&blob).expect("worker blob URL")
    }

    #[wasm_bindgen_test]
    async fn kdf_worker_resolves_from_manifest_derives_and_reclaims() {
        TEST_KDF_SCRIPT.with(|slot| *slot.borrow_mut() = None);
        crate::workers::reset_manifest_cache();

        // Missing manifest fails explicitly with zero unhashed fallback.
        let salt = [0x11u8; 16];
        let token = KdfCancelToken::new();
        let err = derive_kek_async(b"passphrase", &salt, ARGON2_MEMORY_MIN, 1, 1, &token)
            .await
            .expect_err("missing manifest must fail");
        assert!(matches!(err, KdfError::Worker(ref m) if m.contains("missing worker manifest")));

        // Real dedicated worker resolved through `<meta name="e2ee-worker-manifest">`.
        const CHECK_PROTOCOL_WORKER: &str = r#"
            self.onmessage = (event) => {
                const [id, pass, salt, mem, iter, par] = event.data;
                if (!(pass instanceof Uint8Array) || !(salt instanceof Uint8Array)) {
                    self.postMessage([id, false, "expected Uint8Array buffers"]);
                    return;
                }
                const out = new Uint8Array(32);
                for (let i = 0; i < 32; i++) {
                    out[i] = (pass[i % pass.length] ^ salt[i % salt.length] ^ (mem & 0xff) ^ iter ^ par) & 0xff;
                }
                pass.fill(0);
                salt.fill(0);
                self.postMessage([id, true, out], [out.buffer]);
            };
            self.postMessage("ready");
        "#;
        let url = make_blob_url(CHECK_PROTOCOL_WORKER);
        let manifest = serde_json::json!({ "vault_kdf": url }).to_string();
        let _meta = ManifestMetaGuard::install(&manifest);

        let k1 = derive_kek_async(b"alpha-beta", &salt, ARGON2_MEMORY_MIN, 2, 1, &token)
            .await
            .expect("worker derive succeeds");
        let k2 = derive_kek_async(b"alpha-beta", &salt, ARGON2_MEMORY_MIN, 2, 1, &token)
            .await
            .expect("second ephemeral worker derive matches");
        let k_other = derive_kek_async(b"gamma-delta", &salt, ARGON2_MEMORY_MIN, 2, 1, &token)
            .await
            .expect("different passphrase derive succeeds");
        assert_eq!(*k1, *k2);
        assert_ne!(*k1, [0u8; 32]);
        assert_ne!(*k1, *k_other);
        assert_eq!(active_kdf_count(), 0);

        let _ = Url::revoke_object_url(&url);
    }

    #[wasm_bindgen_test]
    async fn kdf_worker_cancel_and_cancel_active_terminate_immediately() {
        const HUNG_WORKER: &str = r#"
            self.onmessage = (_event) => {
                // Intentionally never replies to simulate long Argon2id run.
            };
            self.postMessage("ready");
        "#;
        let _guard = install_custom_test_kdf_worker(HUNG_WORKER);
        let salt = [0x22u8; 16];

        // 1. Explicit KdfCancelToken::cancel() cancels in-flight worker immediately.
        let token = KdfCancelToken::new();
        let token_to_cancel = token.clone();
        wasm_bindgen_futures::spawn_local(async move {
            crate::util::sleep(25).await;
            assert_eq!(active_kdf_count(), 1);
            token_to_cancel.cancel();
        });
        let res = derive_kek_async(b"passphrase", &salt, ARGON2_MEMORY_MIN, 1, 1, &token).await;
        assert_eq!(res, Err(KdfError::Cancelled));
        assert_eq!(active_kdf_count(), 0);

        // 2. Global `cancel_active()` (pagehide path) cancels & terminates immediately.
        let token2 = KdfCancelToken::new();
        wasm_bindgen_futures::spawn_local(async move {
            crate::util::sleep(25).await;
            assert_eq!(active_kdf_count(), 1);
            cancel_active();
        });
        let res2 = derive_kek_async(b"passphrase", &salt, ARGON2_MEMORY_MIN, 1, 1, &token2).await;
        assert_eq!(res2, Err(KdfError::Cancelled));
        assert_eq!(active_kdf_count(), 0);
    }

    #[wasm_bindgen_test]
    async fn kdf_worker_enforces_timeout_and_error_handling() {
        const HUNG_WORKER: &str = r#"
            self.onmessage = (_event) => {};
            self.postMessage("ready");
        "#;
        let salt = [0x33u8; 16];
        let token = KdfCancelToken::new();

        // 1. Invalid parameter bounds reject before spawning any worker.
        assert!(matches!(
            derive_kek_async(b"pass", &[0u8; 4], ARGON2_MEMORY_MIN, 1, 1, &token).await,
            Err(KdfError::InvalidParams(_))
        ));
        assert!(matches!(
            derive_kek_async(b"pass", &salt, 1024, 1, 1, &token).await,
            Err(KdfError::InvalidParams(_))
        ));
        assert!(matches!(
            derive_kek_async(b"pass", &salt, ARGON2_MEMORY_MIN, 0, 1, &token).await,
            Err(KdfError::InvalidParams(_))
        ));
        assert!(matches!(
            derive_kek_async(b"pass", &salt, ARGON2_MEMORY_MIN, 1, 9, &token).await,
            Err(KdfError::InvalidParams(_))
        ));

        // 2. Worker-returned `[id, false, err]` surfaces as KdfError::Worker and terminates.
        const ERROR_WORKER: &str = r#"
            self.onmessage = (event) => {
                const [id] = event.data;
                self.postMessage([id, false, "simulated worker KDF error"]);
            };
            self.postMessage("ready");
        "#;
        {
            let _guard = install_custom_test_kdf_worker(ERROR_WORKER);
            let err = derive_kek_async(b"pass", &salt, ARGON2_MEMORY_MIN, 1, 1, &token)
                .await
                .expect_err("worker error must propagate");
            assert_eq!(err, KdfError::Worker("simulated worker KDF error".into()));
            assert_eq!(active_kdf_count(), 0);
        }

        // 3. Timeout fires and terminates hung worker.
        {
            let _guard = install_custom_test_kdf_worker(HUNG_WORKER);
            let _restore_timeout = scopeguard::guard(
                TEST_TIMEOUT_MS.with(|slot| slot.replace(Some(80))),
                |prev| TEST_TIMEOUT_MS.with(|slot| slot.set(prev)),
            );
            let err = derive_kek_async(b"pass", &salt, ARGON2_MEMORY_MIN, 1, 1, &token)
                .await
                .expect_err("hung worker must time out");
            assert_eq!(err, KdfError::Timeout);
            assert_eq!(active_kdf_count(), 0);
        }
    }
}
