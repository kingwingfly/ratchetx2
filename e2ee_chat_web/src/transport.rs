//! The Connect calls, over the browser's `XMLHttpRequest`, which, unlike `fetch`, tells how far
//! a request's body got.

#[cfg(any(target_arch = "wasm32", not(test)))]
use std::cell::Cell;
use std::{cell::RefCell, collections::HashMap, rc::Rc};

#[cfg(any(target_arch = "wasm32", not(test)))]
use futures_channel::oneshot;
#[cfg(any(target_arch = "wasm32", not(test)))]
use futures_util::future::{Either, select};
#[cfg(any(target_arch = "wasm32", not(test)))]
use js_sys::{ArrayBuffer, Uint8Array};
#[cfg(any(target_arch = "wasm32", not(test)))]
use session::protocol::connect::{CONTENT_TYPE, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use session::{
    ServerClock,
    protocol::{
        self, Error, ErrorKind,
        connect::{ConnectClient, LocalPost},
    },
};
#[cfg(any(target_arch = "wasm32", not(test)))]
use wasm_bindgen::{JsCast, closure::Closure};
#[cfg(any(target_arch = "wasm32", not(test)))]
use web_sys::{ProgressEvent, XmlHttpRequest, XmlHttpRequestResponseType, XmlHttpRequestUpload};

#[cfg(any(target_arch = "wasm32", not(test)))]
use crate::util::{js_error, monotonic_now_ms, sleep};

/// The handshake and mailbox client of a server.
pub type Connect = ConnectClient<Fetch>;

/// How long a call may go without moving, in milliseconds: sending nothing, receiving nothing,
/// and no answer. A large one over a slow link takes as long as it keeps moving.
#[cfg(any(target_arch = "wasm32", not(test)))]
const STALL_MILLIS: u64 = 30_000;
/// Milliseconds between checks of whether a call moves.
#[cfg(any(target_arch = "wasm32", not(test)))]
const STALL_CHECK: i32 = 1_000;
/// Maximum Connect HTTP response body size accepted before decoding (5 MiB, matching server max ~4 MiB + framing).
pub const MAX_CONNECT_RESPONSE_BYTES: usize = 5 << 20;
/// Maximum response size for non-Connect auxiliary calls (e.g. `/auth`).
const MAX_CALL_RESPONSE_BYTES: usize = 64 << 10;

/// Told how far the body of a request got: bytes sent, of how many.
pub type Progress = Rc<dyn Fn(u64, u64)>;

/// Told when a server response `Date` reveals clock drift exceeding the trusted threshold.
type ClockSkewHook = Rc<dyn Fn(i64)>;

thread_local! {
    /// The clocks of the servers called, by address, kept to their time by their responses.
    static CLOCKS: RefCell<HashMap<String, ServerClock>> = RefCell::default();
    /// Told when a server refuses a call for the sign-in, whichever call it was.
    static REFUSED: RefCell<Option<Rc<dyn Fn()>>> = RefCell::default();
    /// Told when the observed server clock differs from local time past the trusted drift cap.
    static CLOCK_SKEW: RefCell<Option<ClockSkewHook>> = RefCell::default();
}

/// Tell `refused` whenever a server refuses a call as this browser is not signed in to it.
pub fn on_sign_in_required(refused: impl Fn() + 'static) {
    REFUSED.with_borrow_mut(|hook| *hook = Some(Rc::new(refused)));
}

/// Tell `handler` whenever a server response `Date` reveals clock drift exceeding the trusted
/// threshold ([`session::DEFAULT_MAX_TRUSTED_DRIFT_MS`]).
pub fn on_clock_skew(handler: impl Fn(i64) + 'static) {
    CLOCK_SKEW.with_borrow_mut(|hook| *hook = Some(Rc::new(handler)));
}

/// Whether `status` and `body` are the server's own refusal of a call for the sign-in.
fn asks_sign_in(status: u16, body: &[u8]) -> bool {
    status == 403
        && serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|error| {
            error.get("code").and_then(serde_json::Value::as_str) == Some("permission_denied")
        })
}

/// Check that a Connect response body length does not exceed [`MAX_CONNECT_RESPONSE_BYTES`].
fn check_response_size(len: u64) -> protocol::Result<()> {
    if len > MAX_CONNECT_RESPONSE_BYTES as u64 {
        return Err(Error::ambiguous_response(
            ErrorKind::LimitExceeded,
            format!("response exceeds maximum size of {MAX_CONNECT_RESPONSE_BYTES} bytes"),
        ));
    }
    Ok(())
}

/// The clock of `server`, as its responses tell it, which signs the requests whose time it
/// checks: this device's may be off.
pub fn clock(server: &str) -> ServerClock {
    CLOCKS.with_borrow_mut(|clocks| {
        clocks
            .entry(server.trim_end_matches('/').to_string())
            .or_default()
            .clone()
    })
}

/// Learn the time of `server` from the `Date` of `request`'s response, if it tells it.
#[cfg(any(target_arch = "wasm32", not(test)))]
fn observe(server: &str, request: &XmlHttpRequest) {
    if let Ok(Some(date)) = request.get_response_header("date") {
        let clk = clock(server);
        if clk.observe_date(&date)
            && clk.is_drift_exceeded()
            && let Some(handler) = CLOCK_SKEW.with_borrow(Clone::clone)
        {
            handler(clk.offset_ms());
        }
    }
}

/// Posts to a server.
#[derive(Clone)]
pub struct Fetch {
    /// The server's address, without a trailing slash, e.g. `https://chat.example.com`.
    server: String,
    /// Told as each request's body goes, if anything is.
    progress: Option<Progress>,
    /// Whether a `403 permission_denied` response invokes the global `REFUSED` sign-in hook
    /// before returning to the caller (`false` for generation-validated greeting sends in
    /// `start_chat` Phase 4, `R18-P2-3`).
    notify_refused: bool,
}

impl std::fmt::Debug for Fetch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetch")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl Fetch {
    pub fn client(server: &str) -> Connect {
        ConnectClient::new(Self {
            server: server.trim_end_matches('/').to_string(),
            progress: None,
            notify_refused: true,
        })
    }

    /// A client that suppresses the global transport-level `REFUSED` sign-in hook so the caller
    /// can validate conversation generation/cancellation before opening `Dialog::SignIn`
    /// (`R18-P2-3`).
    pub fn client_without_refused_hook(server: &str) -> Connect {
        ConnectClient::new(Self {
            server: server.trim_end_matches('/').to_string(),
            progress: None,
            notify_refused: false,
        })
    }

    /// A progress-reporting client that suppresses the global transport-level `REFUSED` sign-in
    /// hook so the caller can validate liveness, cancellation, and conversation generation before
    /// opening `Dialog::SignIn` (`R23-P2-1`).
    pub fn reporting_without_refused_hook(server: &str, progress: Progress) -> Connect {
        ConnectClient::new(Self {
            server: server.trim_end_matches('/').to_string(),
            progress: Some(progress),
            notify_refused: false,
        })
    }
}

#[cfg(any(target_arch = "wasm32", not(test)))]
#[derive(Clone, Copy)]
enum XhrOutcome {
    Loaded,
    Failed,
    Oversized,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
type MockPostFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = protocol::Result<(u16, Vec<u8>)>>>>;

#[cfg(all(test, not(target_arch = "wasm32")))]
type MockPostHandler = Box<dyn FnMut(&str, &str, Vec<u8>) -> MockPostFuture>;

#[cfg(all(test, not(target_arch = "wasm32")))]
thread_local! {
    /// Thread-local mock responder for `impl LocalPost for Fetch` during native async tests.
    static MOCK_POST: RefCell<Option<MockPostHandler>> = RefCell::default();
}

/// RAII guard restoring any previous thread-local mock [`Fetch`] responder on drop.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub struct MockFetchGuard {
    previous: Option<MockPostHandler>,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
impl Drop for MockFetchGuard {
    fn drop(&mut self) {
        MOCK_POST.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

/// Install a thread-local mock responder for `impl LocalPost for Fetch` in native tests.
/// Any previous responder is restored automatically when the returned guard is dropped.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub fn mock_fetch(
    mut handler: impl FnMut(&str, &str, Vec<u8>) -> protocol::Result<(u16, Vec<u8>)> + 'static,
) -> MockFetchGuard {
    let previous = MOCK_POST.with(|slot| {
        slot.borrow_mut()
            .replace(Box::new(move |server, path, body| {
                let res = handler(server, path, body);
                Box::pin(std::future::ready(res))
            }))
    });
    MockFetchGuard { previous }
}

/// Install an async thread-local mock responder for `impl LocalPost for Fetch` in native tests,
/// releasing the `MOCK_POST` borrow before awaiting the returned future so concurrent RPCs can
/// progress while specific calls are deterministically suspended on a channel.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub fn mock_fetch_async<F>(
    mut handler: impl FnMut(String, String, Vec<u8>) -> F + 'static,
) -> MockFetchGuard
where
    F: std::future::Future<Output = protocol::Result<(u16, Vec<u8>)>> + 'static,
{
    let previous = MOCK_POST.with(|slot| {
        slot.borrow_mut()
            .replace(Box::new(move |server, path, body| {
                Box::pin(handler(server.to_string(), path.to_string(), body))
            }))
    });
    MockFetchGuard { previous }
}

impl LocalPost for Fetch {
    async fn post(&self, path: &str, body: Vec<u8>) -> protocol::Result<(u16, Vec<u8>)> {
        #[cfg(all(test, not(target_arch = "wasm32")))]
        {
            if let Some(progress) = &self.progress {
                let len = body.len() as u64;
                progress(len, len);
            }
            let fut = MOCK_POST.with(|slot| {
                let mut handler = slot.borrow_mut();
                match handler.as_mut() {
                    Some(respond) => respond(&self.server, path, body),
                    None => Box::pin(std::future::ready(Err(Error::new(
                        ErrorKind::Connect,
                        format!("no mock responder installed for POST {}{path}", self.server),
                    )))),
                }
            });
            let (status, resp_body) = fut.await?;
            check_response_size(resp_body.len() as u64)?;
            if self.notify_refused
                && asks_sign_in(status, &resp_body)
                && let Some(refused) = REFUSED.with_borrow(Clone::clone)
            {
                refused();
            }
            Ok((status, resp_body))
        }

        #[cfg(any(target_arch = "wasm32", not(test)))]
        {
            let failed = |error| Error::new(ErrorKind::Connect, js_error(error));
            let request = XmlHttpRequest::new().map_err(failed)?;
            request
                .open("POST", &format!("{}{path}", self.server))
                .map_err(failed)?;
            request
                .set_request_header("content-type", CONTENT_TYPE)
                .map_err(failed)?;
            request
                .set_request_header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION)
                .map_err(failed)?;
            request.set_response_type(XmlHttpRequestResponseType::Arraybuffer);
            let upload = request.upload().map_err(failed)?;
            // When it last moved (monotonic), and whether it ended with an answer, failed, or exceeded cap.
            let moved = Rc::new(Cell::new(monotonic_now_ms()));
            let (ended, mut end) = oneshot::channel::<XhrOutcome>();
            let ended = Rc::new(Cell::new(Some(ended)));
            let progress = {
                let moved = moved.clone();
                let ended = ended.clone();
                let req = request.clone();
                Closure::<dyn FnMut(ProgressEvent)>::new(move |event: ProgressEvent| {
                    moved.set(monotonic_now_ms());
                    let loaded = event.loaded();
                    let total = if event.length_computable() {
                        event.total()
                    } else {
                        0.0
                    };
                    if loaded > MAX_CONNECT_RESPONSE_BYTES as f64
                        || total > MAX_CONNECT_RESPONSE_BYTES as f64
                    {
                        let _ = req.abort();
                        if let Some(ended) = ended.take() {
                            let _ = ended.send(XhrOutcome::Oversized);
                        }
                    }
                })
            };
            let sent = {
                let (moved, progress) = (moved.clone(), self.progress.clone());
                Closure::<dyn FnMut(ProgressEvent)>::new(move |event: ProgressEvent| {
                    moved.set(monotonic_now_ms());
                    if let Some(progress) = &progress
                        && event.length_computable()
                    {
                        progress(event.loaded() as u64, event.total() as u64);
                    }
                })
            };
            let ends = |outcome: XhrOutcome| {
                let ended = ended.clone();
                Closure::<dyn FnMut()>::new(move || {
                    if let Some(ended) = ended.take() {
                        let _ = ended.send(outcome);
                    }
                })
            };
            let (load, error) = (ends(XhrOutcome::Loaded), ends(XhrOutcome::Failed));
            // Declared after the closures, so that it goes first.
            let _handlers = Handlers {
                request: &request,
                upload: Some(&upload),
            };
            request.set_onprogress(Some(progress.as_ref().unchecked_ref()));
            upload.set_onprogress(Some(sent.as_ref().unchecked_ref()));
            request.set_onload(Some(load.as_ref().unchecked_ref()));
            request.set_onerror(Some(error.as_ref().unchecked_ref()));
            request
                .send_with_opt_u8_array(Some(&body))
                .map_err(failed)?;
            let ended = loop {
                match select(end, Box::pin(sleep(STALL_CHECK))).await {
                    // Its sender lives as long as the closures.
                    Either::Left((Ok(XhrOutcome::Loaded), _)) => break Ok(()),
                    Either::Left((Ok(XhrOutcome::Oversized), _)) => {
                        break Err(Error::ambiguous_response(
                            ErrorKind::LimitExceeded,
                            format!(
                                "response exceeds maximum size of {MAX_CONNECT_RESPONSE_BYTES} bytes"
                            ),
                        ));
                    }
                    Either::Left(_) => {
                        break Err(Error::new(
                            ErrorKind::Connect,
                            "the server cannot be reached",
                        ));
                    }
                    Either::Right(_)
                        if monotonic_now_ms().saturating_sub(moved.get()) > STALL_MILLIS =>
                    {
                        break Err(Error::new(
                            ErrorKind::Connect,
                            format!("nothing moved for {} s", STALL_MILLIS / 1000),
                        ));
                    }
                    Either::Right((_, pending)) => end = pending,
                }
            };
            ended?;
            observe(&self.server, &request);
            let invalid = |e| Error::ambiguous_response(ErrorKind::InvalidResponse, js_error(e));
            let status = request.status().map_err(invalid)?;
            // Enforce bounded response size BEFORE copying into Rust memory or decoding.
            if let Ok(Some(cl)) = request.get_response_header("content-length")
                && let Ok(parsed) = cl.trim().parse::<u64>()
            {
                check_response_size(parsed)?;
            }
            let body: ArrayBuffer =
                request
                    .response()
                    .map_err(invalid)?
                    .dyn_into()
                    .map_err(|_| {
                        Error::ambiguous_response(
                            ErrorKind::InvalidResponse,
                            "unexpected response buffer type",
                        )
                    })?;
            check_response_size(u64::from(body.byte_length()))?;
            let body = Uint8Array::new(&body).to_vec();
            if self.notify_refused
                && asks_sign_in(status, &body)
                && let Some(refused) = REFUSED.with_borrow(Clone::clone)
            {
                refused();
            }
            Ok((status, body))
        }
    }
}

/// A request's handlers, detached when this goes, before the closures they call; and the
/// request stopped if it has not ended, as when nothing moved, or the call was dropped.
#[cfg(any(target_arch = "wasm32", not(test)))]
struct Handlers<'a> {
    request: &'a XmlHttpRequest,
    /// The request's upload, if its progress is handled.
    upload: Option<&'a XmlHttpRequestUpload>,
}

#[cfg(any(target_arch = "wasm32", not(test)))]
impl Drop for Handlers<'_> {
    fn drop(&mut self) {
        self.request.set_onprogress(None);
        if let Some(upload) = self.upload {
            upload.set_onprogress(None);
        }
        self.request.set_onload(None);
        self.request.set_onerror(None);
        self.request.set_ontimeout(None);
        if self.request.ready_state() != XmlHttpRequest::DONE {
            // It only fires events, whose handlers are gone.
            let _ = self.request.abort();
        }
    }
}

/// How long a call outside Connect may take, in milliseconds.
#[cfg(any(target_arch = "wasm32", not(test)))]
const CALL_TIMEOUT: u32 = 30_000;

/// Check that a non-Connect auxiliary response body length does not exceed
/// [`MAX_CALL_RESPONSE_BYTES`].
fn check_call_response_size(len: u64) -> Result<(), String> {
    if len > MAX_CALL_RESPONSE_BYTES as u64 {
        return Err("the server's response was too large".to_string());
    }
    Ok(())
}

/// Call `path` of `server` outside Connect, e.g. to sign in: `method`, with `body` if any.
/// Returns the server's status and text. Cookies come and go as with the page's own calls.
pub async fn call(
    server: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, String), String> {
    #[cfg(all(test, not(target_arch = "wasm32")))]
    {
        let fut = MOCK_POST.with(|slot| {
            let mut handler = slot.borrow_mut();
            match handler.as_mut() {
                Some(respond) => respond(
                    server.trim_end_matches('/'),
                    path,
                    body.unwrap_or_default().as_bytes().to_vec(),
                ),
                None => Box::pin(std::future::ready(Err(Error::new(
                    ErrorKind::Connect,
                    format!("no mock responder installed for {method} {server}{path}"),
                )))),
            }
        });
        let (status, resp_body) = fut.await.map_err(|e| e.to_string())?;
        check_call_response_size(resp_body.len() as u64)?;
        let text = String::from_utf8(resp_body).map_err(|e| e.to_string())?;
        Ok((status, text))
    }

    #[cfg(any(target_arch = "wasm32", not(test)))]
    {
        let request = XmlHttpRequest::new().map_err(js_error)?;
        request
            .open(method, &format!("{}{path}", server.trim_end_matches('/')))
            .map_err(js_error)?;
        request.set_timeout(CALL_TIMEOUT);
        let (ended, end) = oneshot::channel::<XhrOutcome>();
        let ended = Rc::new(Cell::new(Some(ended)));
        let progress = {
            let ended = ended.clone();
            let req = request.clone();
            Closure::<dyn FnMut(ProgressEvent)>::new(move |event: ProgressEvent| {
                let loaded = event.loaded();
                let total = if event.length_computable() {
                    event.total()
                } else {
                    0.0
                };
                if loaded > MAX_CALL_RESPONSE_BYTES as f64 || total > MAX_CALL_RESPONSE_BYTES as f64
                {
                    let _ = req.abort();
                    if let Some(ended) = ended.take() {
                        let _ = ended.send(XhrOutcome::Oversized);
                    }
                }
            })
        };
        let ends = |outcome: XhrOutcome| {
            let ended = ended.clone();
            Closure::<dyn FnMut()>::new(move || {
                if let Some(ended) = ended.take() {
                    let _ = ended.send(outcome);
                }
            })
        };
        let (load, error, timeout) = (
            ends(XhrOutcome::Loaded),
            ends(XhrOutcome::Failed),
            ends(XhrOutcome::Failed),
        );
        // Declared after the closures, so that it goes first, also if this call is dropped.
        let _handlers = Handlers {
            request: &request,
            upload: None,
        };
        request.set_onprogress(Some(progress.as_ref().unchecked_ref()));
        request.set_onload(Some(load.as_ref().unchecked_ref()));
        request.set_onerror(Some(error.as_ref().unchecked_ref()));
        request.set_ontimeout(Some(timeout.as_ref().unchecked_ref()));
        request.send_with_opt_str(body).map_err(js_error)?;
        match end.await.unwrap_or(XhrOutcome::Failed) {
            XhrOutcome::Loaded => {}
            XhrOutcome::Oversized => {
                return Err("the server's response was too large".to_string());
            }
            XhrOutcome::Failed => return Err("the server cannot be reached".to_string()),
        }
        observe(server, &request);
        let status = request.status().map_err(js_error)?;
        // Enforce Content-Length cap BEFORE copying responseText into WASM memory.
        if let Ok(Some(cl)) = request.get_response_header("content-length")
            && let Ok(parsed) = cl.trim().parse::<u64>()
        {
            check_call_response_size(parsed)?;
        }
        let text = request
            .response_text()
            .map_err(js_error)?
            .unwrap_or_default();
        check_call_response_size(text.len() as u64)?;
        Ok((status, text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_response_size_cap_is_enforced() {
        assert!(check_response_size(0).is_ok());
        assert!(check_response_size(MAX_CONNECT_RESPONSE_BYTES as u64).is_ok());
        let err = check_response_size(MAX_CONNECT_RESPONSE_BYTES as u64 + 1).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
        assert!(!err.is_server_refusal());

        assert!(check_call_response_size(0).is_ok());
        assert!(check_call_response_size(MAX_CALL_RESPONSE_BYTES as u64).is_ok());
        assert!(check_call_response_size(MAX_CALL_RESPONSE_BYTES as u64 + 1).is_err());
    }
}
