//! Notifications over the server's WebSocket: the server says at once when something arrives,
//! so the client need not poll for it.
//!
//! Connects to `/notifications?identity=<64-hex>` and authenticates with `SubscribeRequest` in
//! the first WebSocket binary frame (never placing signed credentials in URL query parameters),
//! and bounds pending notification buffering against message floods.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use futures::{StreamExt, channel::mpsc};
use js_sys::{ArrayBuffer, Uint8Array};
use prost::Message;
use session::protocol::notify::{Notification, SubscribeRequest};
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{BinaryType, MessageEvent, WebSocket};

use crate::util::{hex, js_error, sleep};

/// Where the Worker takes subscriptions.
const PATH: &str = "/notifications";
/// What keeps the socket open through idle proxies, answered by the Worker without waking it,
/// and shows the Worker it is open still.
const PING: &str = "ping";
/// Text frame sent by the Worker immediately after verifying the first-frame `SubscribeRequest`.
const AUTH_OK: &str = "ok";
/// Milliseconds between pings, often enough for proxies that close idle connections.
const PING_EVERY: i32 = 60_000;
/// Maximum buffered notification events before coalescing into a resync (bounds memory under flood).
const MAX_PENDING_EVENTS: usize = 64;
/// Maximum accepted binary notification frame size in bytes (a `Notification` is at most ~64 bytes).
const MAX_NOTIFICATION_BYTES: usize = 1024;

/// What happens on a subscription's socket.
pub enum Event {
    /// The socket opened and the server acknowledged the signed first-frame `SubscribeRequest`.
    Open,
    Notification(Notification),
    /// Some notifications were dropped due to backpressure; the caller should run a sync.
    Resync,
    /// The socket closed, or never opened, e.g. as the server sends no notifications.
    Closed,
}

/// Process a text WebSocket frame against `authenticated`, returning `true` only on the first
/// `"ok"` auth acknowledgement (so subsequent `"ok"` frames or `"pong"` frames are ignored).
fn handle_auth_text_frame(authenticated: &Cell<bool>, text: &str) -> bool {
    text == AUTH_OK && !authenticated.replace(true)
}

#[derive(Default)]
struct FrameState {
    authenticated: Cell<bool>,
    open_pending: Cell<bool>,
    overflow: Cell<bool>,
}

impl FrameState {
    fn text(&self, tx: &mut mpsc::Sender<Event>, text: &str) {
        if handle_auth_text_frame(&self.authenticated, text)
            && tx.try_send(Event::Open).is_err_and(|e| e.is_full())
        {
            self.open_pending.set(true);
        }
    }

    fn binary(&self, tx: &mut mpsc::Sender<Event>, len: usize, bytes: impl FnOnce() -> Vec<u8>) {
        if !self.authenticated.get() || len > MAX_NOTIFICATION_BYTES {
            return;
        }
        if let Ok(notification) = Notification::decode(bytes().as_slice())
            && tx
                .try_send(Event::Notification(notification))
                .is_err_and(|e| e.is_full())
        {
            self.overflow.set(true);
        }
    }

    async fn next(&self, events: &mut mpsc::Receiver<Event>) -> Event {
        if self.open_pending.replace(false) {
            return Event::Open;
        }
        match events.try_recv() {
            Ok(Event::Closed) if self.overflow.replace(false) => Event::Resync,
            Ok(event) => event,
            Err(_) if self.overflow.replace(false) => Event::Resync,
            Err(e) if e.is_closed() => Event::Closed,
            Err(_) => events.next().await.unwrap_or(Event::Closed),
        }
    }
}

/// A WebSocket subscribed to a client's notifications. Closed when dropped.
pub struct Subscription {
    socket: WebSocket,
    events: mpsc::Receiver<Event>,
    frames: Rc<FrameState>,
    _on_open: Closure<dyn FnMut()>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_close: Closure<dyn FnMut()>,
}

/// Build the first-frame-auth WebSocket URL (`/notifications?identity=<64-hex>`).
/// Never embeds signed credentials in query parameters.
fn subscription_url(server: &str, identity_key: &[u8]) -> Result<String, String> {
    if identity_key.len() != 32 {
        return Err("invalid identity key length for notifications".to_string());
    }
    Ok(format!(
        "{}{PATH}?identity={}",
        socket_address(server),
        hex(identity_key)
    ))
}

impl Subscription {
    /// Open a socket to `server`, e.g. `https://chat.example.com`, authenticating with `request`
    /// in the first WebSocket binary frame once the socket opens.
    pub fn open(server: &str, request: &SubscribeRequest) -> Result<Self, String> {
        let url = subscription_url(server, &request.identity_key)?;
        let auth_frame = request.encode_to_vec();
        let socket = WebSocket::new(&url).map_err(js_error)?;
        socket.set_binary_type(BinaryType::Arraybuffer);
        let (sender, events) = mpsc::channel(MAX_PENDING_EVENTS);
        let sender = Rc::new(RefCell::new(Some(sender)));
        let frames = Rc::new(FrameState::default());

        let on_open = {
            let sender = sender.clone();
            let socket = socket.clone();
            Closure::<dyn FnMut()>::new(move || {
                if socket.send_with_u8_array(&auth_frame).is_err() {
                    let _ = socket.close();
                    if let Some(mut tx) = sender.borrow_mut().take() {
                        let _ = tx.try_send(Event::Closed);
                    }
                }
                // Wait for the server's `"ok"` auth-ack text frame before emitting `Event::Open`,
                // so first-frame auth failures (`1008`) never reset reconnect backoff.
            })
        };
        let on_message = {
            let sender = sender.clone();
            let frames = frames.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                let mut sender = sender.borrow_mut();
                let Some(tx) = sender.as_mut() else {
                    return;
                };
                let data = event.data();
                if let Some(text) = data.as_string() {
                    frames.text(tx, &text);
                } else if let Ok(buffer) = data.dyn_into::<ArrayBuffer>() {
                    frames.binary(tx, buffer.byte_length() as usize, || {
                        Uint8Array::new(&buffer).to_vec()
                    });
                }
            })
        };
        // An error is followed by a close. Dropping the shared sender guarantees the receiver ends.
        let on_close = Closure::<dyn FnMut()>::new(move || {
            if let Some(mut tx) = sender.borrow_mut().take() {
                let _ = tx.try_send(Event::Closed);
            }
        });
        socket.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));
        keep_alive(socket.clone());
        Ok(Self {
            socket,
            events,
            frames,
            _on_open: on_open,
            _on_message: on_message,
            _on_close: on_close,
        })
    }

    /// The next event; [`Event::Closed`] is the last.
    pub async fn next(&mut self) -> Event {
        self.frames.next(&mut self.events).await
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.socket.set_onopen(None);
        self.socket.set_onmessage(None);
        self.socket.set_onclose(None);
        let _ = self.socket.close();
    }
}

/// Ping on `socket` until it closes.
fn keep_alive(socket: WebSocket) {
    wasm_bindgen_futures::spawn_local(async move {
        loop {
            sleep(PING_EVERY).await;
            match socket.ready_state() {
                WebSocket::OPEN => {
                    let _ = socket.send_with_str(PING);
                }
                WebSocket::CONNECTING => {}
                _ => return,
            }
        }
    });
}

/// The WebSocket address of `server`: `ws` for `http`, `wss` for `https` (case-insensitive).
fn socket_address(server: &str) -> String {
    let server = server.trim().trim_end_matches('/');
    if let Some((scheme, rest)) = server.split_once("://") {
        if scheme.eq_ignore_ascii_case("https") {
            return format!("wss://{rest}");
        } else if scheme.eq_ignore_ascii_case("http") {
            return format!("ws://{rest}");
        }
    }
    server.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_frame_ws_url_uses_identity_hex_and_never_query_request() {
        let id = [0xABu8; 32];
        let url = subscription_url("https://chat.example.com/", &id).unwrap();
        assert_eq!(
            url,
            format!(
                "wss://chat.example.com/notifications?identity={}",
                "ab".repeat(32)
            )
        );
        assert!(!url.contains("request="));
        assert!(subscription_url("https://chat.example.com", &[0u8; 31]).is_err());
    }

    #[test]
    fn socket_address_matches_scheme_case_insensitively() {
        assert_eq!(
            socket_address("HTTPS://Chat.Example.COM/"),
            "wss://Chat.Example.COM"
        );
        assert_eq!(
            socket_address("HTTP://localhost:8787/"),
            "ws://localhost:8787"
        );
        assert_eq!(socket_address("HtTpS://[::1]:8443"), "wss://[::1]:8443");
        assert_eq!(
            socket_address("wss://already.example/"),
            "wss://already.example"
        );
    }

    #[test]
    fn auth_ok_text_frame_emits_open_once_and_ignores_pongs_and_repeats() {
        let authenticated = Cell::new(false);
        assert!(!handle_auth_text_frame(&authenticated, "pong"));
        assert!(!authenticated.get());
        assert!(!handle_auth_text_frame(&authenticated, "OK"));
        assert!(!authenticated.get());
        assert!(handle_auth_text_frame(&authenticated, "ok"));
        assert!(authenticated.get());
        // Subsequent "ok" or "pong" frames are ignored.
        assert!(!handle_auth_text_frame(&authenticated, "ok"));
        assert!(!handle_auth_text_frame(&authenticated, "pong"));
    }

    #[test]
    fn notifications_require_authentication_and_overflow_resyncs() {
        let state = FrameState::default();
        let (mut tx, mut rx) = mpsc::channel(0);
        state.binary(&mut tx, 0, || panic!("pre-auth frame read"));
        assert!(rx.try_recv().is_err());
        assert!(!state.overflow.get());
        state.text(&mut tx, "ok");
        state.text(&mut tx, "ok");
        state.text(&mut tx, "pong");
        assert!(matches!(rx.try_recv(), Ok(Event::Open)));
        assert!(rx.try_recv().is_err());
        let bytes = Notification::default().encode_to_vec();
        for _ in 0..2 {
            state.binary(&mut tx, bytes.len(), || bytes.clone());
        }
        assert!(matches!(
            futures::executor::block_on(state.next(&mut rx)),
            Event::Notification(_)
        ));
        assert!(matches!(
            futures::executor::block_on(state.next(&mut rx)),
            Event::Resync
        ));
        drop(tx);
        assert!(matches!(
            futures::executor::block_on(state.next(&mut rx)),
            Event::Closed
        ));
    }

    #[test]
    fn deferred_open_precedes_already_queued_events() {
        let state = FrameState::default();
        let (mut tx, mut rx) = mpsc::channel(0);
        assert!(tx.try_send(Event::Resync).is_ok());
        state.text(&mut tx, "ok");
        state.text(&mut tx, "ok");
        assert!(matches!(
            futures::executor::block_on(state.next(&mut rx)),
            Event::Open
        ));
        assert!(matches!(
            futures::executor::block_on(state.next(&mut rx)),
            Event::Resync
        ));
        assert!(rx.try_recv().is_err());
    }
}
