//! The Connect calls, over the browser's `XMLHttpRequest`, which, unlike `fetch`, tells how far
//! a request's body got.

use std::{cell::Cell, rc::Rc};

use futures::{
    channel::oneshot,
    future::{Either, select},
};
use js_sys::{ArrayBuffer, Uint8Array};
use session::protocol::{
    self, Error, ErrorKind,
    connect::{CONTENT_TYPE, ConnectClient, LocalPost, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER},
};
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{XmlHttpRequest, XmlHttpRequestResponseType};

use crate::util::{js_error, now, sleep};

/// The handshake and mailbox client of a server.
pub type Connect = ConnectClient<Fetch>;

/// How long a call may go without moving, in milliseconds: sending nothing, receiving nothing,
/// and no answer. A large one over a slow link takes as long as it keeps moving.
const STALL_MILLIS: u64 = 30_000;
/// Milliseconds between checks of whether a call moves.
const STALL_CHECK: i32 = 1_000;

/// Posts to a server.
#[derive(Debug, Clone)]
pub struct Fetch {
    /// The server's address, without a trailing slash, e.g. `https://chat.example.com`.
    server: String,
}

impl Fetch {
    pub fn client(server: &str) -> Connect {
        ConnectClient::new(Self {
            server: server.trim_end_matches('/').to_string(),
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
        let (ended, end) = oneshot::channel();
        let ended = Rc::new(Cell::new(Some(ended)));
        let progress = {
            let moved = moved.clone();
            Closure::<dyn FnMut()>::new(move || moved.set(now()))
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
        request.set_onprogress(Some(progress.as_ref().unchecked_ref()));
        upload.set_onprogress(Some(progress.as_ref().unchecked_ref()));
        request.set_onload(Some(load.as_ref().unchecked_ref()));
        request.set_onerror(Some(error.as_ref().unchecked_ref()));
        request
            .send_with_opt_u8_array(Some(&body))
            .map_err(failed)?;
        let mut end = end;
        let ended = loop {
            match select(end, Box::pin(sleep(STALL_CHECK))).await {
                // Its sender lives as long as the closures.
                Either::Left((Ok(true), _)) => break Ok(()),
                Either::Left(_) => break Err("the server cannot be reached".to_string()),
                Either::Right((_, pending)) if now() - moved.get() > STALL_MILLIS => {
                    drop(pending);
                    request.abort().map_err(failed)?;
                    break Err(format!("nothing moved for {} s", STALL_MILLIS / 1000));
                }
                Either::Right((_, pending)) => end = pending,
            }
        };
        // Its handlers go before the closures they call.
        request.set_onprogress(None);
        upload.set_onprogress(None);
        request.set_onload(None);
        request.set_onerror(None);
        ended.map_err(|reason| Error::new(ErrorKind::Connect, reason))?;
        let status = request.status().map_err(failed)?;
        let body: ArrayBuffer = request.response().map_err(failed)?.unchecked_into();
        Ok((status, Uint8Array::new(&body).to_vec()))
    }
}
