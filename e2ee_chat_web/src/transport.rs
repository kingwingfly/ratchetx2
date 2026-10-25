//! The Connect calls, over the browser's `fetch`.

use js_sys::Uint8Array;
use session::protocol::{
    self, Error, ErrorKind,
    connect::{CONTENT_TYPE, ConnectClient, LocalPost, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER},
};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{AbortSignal, Request, RequestInit, Response};

use crate::util::js_error;

/// The handshake and mailbox client of a server.
pub type Connect = ConnectClient<Fetch>;

/// How long a call may take.
const TIMEOUT_MILLIS: u32 = 30_000;

/// Posts to a server with `fetch`.
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
        let init = RequestInit::new();
        init.set_method("POST");
        init.set_body(&Uint8Array::from(body.as_slice()));
        init.set_signal(Some(&AbortSignal::timeout_with_u32(TIMEOUT_MILLIS)));
        let request = Request::new_with_str_and_init(&format!("{}{path}", self.server), &init)
            .map_err(failed)?;
        let headers = request.headers();
        headers.set("content-type", CONTENT_TYPE).map_err(failed)?;
        headers
            .set(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION)
            .map_err(failed)?;
        let window = web_sys::window().expect("a window");
        let response: Response = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(failed)?
            .unchecked_into();
        let body = JsFuture::from(response.array_buffer().map_err(failed)?)
            .await
            .map_err(failed)?;
        Ok((response.status(), Uint8Array::new(&body).to_vec()))
    }
}
