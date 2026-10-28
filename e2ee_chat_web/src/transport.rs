//! The Connect calls, over the browser's `XMLHttpRequest`, which, unlike `fetch`, tells how far
//! a request's body got.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};

use futures::{
    channel::oneshot,
    future::{Either, select},
};
use js_sys::{ArrayBuffer, Uint8Array};
use session::{
    ServerClock,
    protocol::{
        self, Error, ErrorKind,
        connect::{
            CONTENT_TYPE, ConnectClient, LocalPost, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER,
        },
    },
};
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{ProgressEvent, XmlHttpRequest, XmlHttpRequestResponseType, XmlHttpRequestUpload};

use crate::util::{js_error, now, sleep};

/// The handshake and mailbox client of a server.
pub type Connect = ConnectClient<Fetch>;

/// How long a call may go without moving, in milliseconds: sending nothing, receiving nothing,
/// and no answer. A large one over a slow link takes as long as it keeps moving.
const STALL_MILLIS: u64 = 30_000;
/// Milliseconds between checks of whether a call moves.
const STALL_CHECK: i32 = 1_000;

/// Told how far the body of a request got: bytes sent, of how many.
pub type Progress = Rc<dyn Fn(u64, u64)>;

thread_local! {
    /// The clocks of the servers called, by address, kept to their time by their responses.
    static CLOCKS: RefCell<HashMap<String, ServerClock>> = RefCell::default();
    /// Told when a server refuses a call for the sign-in, whichever call it was.
    static REFUSED: RefCell<Option<Rc<dyn Fn()>>> = RefCell::default();
}

/// Tell `refused` whenever a server refuses a call as this browser is not signed in to it.
pub fn on_sign_in_required(refused: impl Fn() + 'static) {
    REFUSED.with_borrow_mut(|hook| *hook = Some(Rc::new(refused)));
}

/// Whether `status` and `body` are the server's own refusal of a call for the sign-in.
fn asks_sign_in(status: u16, body: &[u8]) -> bool {
    status == 403
        && serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|error| {
            error.get("code").and_then(serde_json::Value::as_str) == Some("permission_denied")
        })
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
fn observe(server: &str, request: &XmlHttpRequest) {
    if let Ok(Some(date)) = request.get_response_header("date") {
        clock(server).observe_date(&date);
    }
}

/// Posts to a server.
#[derive(Clone)]
pub struct Fetch {
    /// The server's address, without a trailing slash, e.g. `https://chat.example.com`.
    server: String,
    /// Told as each request's body goes, if anything is.
    progress: Option<Progress>,
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
        })
    }

    /// A client whose requests tell `progress` how far their bodies got, e.g. an attachment's
    /// chunks.
    pub fn reporting(server: &str, progress: Progress) -> Connect {
        ConnectClient::new(Self {
            server: server.trim_end_matches('/').to_string(),
            progress: Some(progress),
        })
    }
}

impl LocalPost for Fetch {
    async fn post(&self, path: &str, body: Vec<u8>) -> protocol::Result<(u16, Vec<u8>)> {
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
        // When it last moved, and whether it ended with an answer, or failed.
        let moved = Rc::new(Cell::new(now()));
        let (ended, mut end) = oneshot::channel();
        let ended = Rc::new(Cell::new(Some(ended)));
        let progress = {
            let moved = moved.clone();
            Closure::<dyn FnMut()>::new(move || moved.set(now()))
        };
        let sent = {
            let (moved, progress) = (moved.clone(), self.progress.clone());
            Closure::<dyn FnMut(ProgressEvent)>::new(move |event: ProgressEvent| {
                moved.set(now());
                if let Some(progress) = &progress
                    && event.length_computable()
                {
                    progress(event.loaded() as u64, event.total() as u64);
                }
            })
        };
        let ends = |answered: bool| {
            let ended = ended.clone();
            Closure::<dyn FnMut()>::new(move || {
                if let Some(ended) = ended.take() {
                    let _ = ended.send(answered);
                }
            })
        };
        let (load, error) = (ends(true), ends(false));
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
                Either::Left((Ok(true), _)) => break Ok(()),
                Either::Left(_) => break Err("the server cannot be reached".to_string()),
                // The clock may go back, e.g. set by hand.
                Either::Right(_) if now().saturating_sub(moved.get()) > STALL_MILLIS => {
                    break Err(format!("nothing moved for {} s", STALL_MILLIS / 1000));
                }
                Either::Right((_, pending)) => end = pending,
            }
        };
        ended.map_err(|reason| Error::new(ErrorKind::Connect, reason))?;
        observe(&self.server, &request);
        let status = request.status().map_err(failed)?;
        let body: ArrayBuffer = request.response().map_err(failed)?.unchecked_into();
        let body = Uint8Array::new(&body).to_vec();
        if asks_sign_in(status, &body)
            && let Some(refused) = REFUSED.with_borrow(Clone::clone)
        {
            refused();
        }
        Ok((status, body))
    }
}

/// A request's handlers, detached when this goes, before the closures they call; and the
/// request stopped if it has not ended, as when nothing moved, or the call was dropped.
struct Handlers<'a> {
    request: &'a XmlHttpRequest,
    /// The request's upload, if its progress is handled.
    upload: Option<&'a XmlHttpRequestUpload>,
}

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
const CALL_TIMEOUT: u32 = 30_000;

/// Call `path` of `server` outside Connect, e.g. to sign in: `method`, with `body` if any.
/// Returns the server's status and text. Cookies come and go as with the page's own calls.
pub async fn call(
    server: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, String), String> {
    let request = XmlHttpRequest::new().map_err(js_error)?;
    request
        .open(method, &format!("{}{path}", server.trim_end_matches('/')))
        .map_err(js_error)?;
    request.set_timeout(CALL_TIMEOUT);
    let (ended, end) = oneshot::channel();
    let ended = Rc::new(Cell::new(Some(ended)));
    let ends = |answered: bool| {
        let ended = ended.clone();
        Closure::<dyn FnMut()>::new(move || {
            if let Some(ended) = ended.take() {
                let _ = ended.send(answered);
            }
        })
    };
    let (load, error, timeout) = (ends(true), ends(false), ends(false));
    // Declared after the closures, so that it goes first, also if this call is dropped.
    let _handlers = Handlers {
        request: &request,
        upload: None,
    };
    request.set_onload(Some(load.as_ref().unchecked_ref()));
    request.set_onerror(Some(error.as_ref().unchecked_ref()));
    request.set_ontimeout(Some(timeout.as_ref().unchecked_ref()));
    request.send_with_opt_str(body).map_err(js_error)?;
    if !end.await.unwrap_or(false) {
        return Err("the server cannot be reached".to_string());
    }
    observe(server, &request);
    let status = request.status().map_err(js_error)?;
    let text = request
        .response_text()
        .map_err(js_error)?
        .unwrap_or_default();
    Ok((status, text))
}
