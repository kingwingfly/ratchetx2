//! Notifications over the server's WebSocket: the server says at once when something arrives,
//! so the client need not poll for it.
//!
//! Connects to `/notifications?identity=<64-hex>` and authenticates with `SubscribeRequest` in
//! the first WebSocket binary frame (never placing signed credentials in URL query parameters),
//! enforces auth-ack and pong liveness deadlines, caps incoming frame sizes before copying into
//! WASM memory, and bounds pending notification buffering against message floods.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use futures_channel::{mpsc, oneshot};
use futures_util::{
    StreamExt,
    future::{Either, select},
};
use js_sys::{ArrayBuffer, JsString, Uint8Array};
use prost::Message;
use session::protocol::notify::{Notification, SubscribeRequest};
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{BinaryType, CloseEvent, MessageEvent, WebSocket};

use crate::util::{hex, js_error, sleep};

/// Where the Worker takes subscriptions.
const PATH: &str = "/notifications";
/// What keeps the socket open through idle proxies, answered by the Worker without waking it,
/// and shows the Worker it is open still.
const PING: &str = "ping";
/// Text frame sent by the Worker in reply to [`PING`].
const PONG: &str = "pong";
/// Text frame sent by the Worker immediately after verifying the first-frame `SubscribeRequest`.
const AUTH_OK: &str = "ok";
/// WebSocket close code sent by the Worker when the client's notification protocol is deprecated
/// and the user must refresh/upgrade the app.
pub const CLOSE_DEPRECATED_PROTOCOL: u16 = 4010;
/// Milliseconds allowed for the server to acknowledge first-frame authentication with `"ok"`.
const AUTH_TIMEOUT_MS: i32 = 15_000;
/// Milliseconds between pings, often enough for proxies that close idle connections.
const PING_EVERY: i32 = 60_000;
/// Milliseconds allowed for `"pong"` after sending [`PING`] before declaring the socket dead.
const PONG_TIMEOUT_MS: i32 = 15_000;
/// Maximum buffered notification events before coalescing into a resync (bounds memory under flood).
const MAX_PENDING_EVENTS: usize = 64;
/// Maximum accepted binary notification frame size in bytes (a `Notification` is at most ~64 bytes).
const MAX_NOTIFICATION_BYTES: usize = 1024;
/// Maximum accepted text frame length in UTF-16 code units (valid frames are `"ok"` and `"pong"`).
const MAX_TEXT_FRAME_UNITS: usize = 64;

/// What happens on a subscription's socket.
pub enum Event {
    /// The socket opened and the server acknowledged the signed first-frame `SubscribeRequest`.
    Open,
    Notification(Notification),
    /// Some notifications were dropped due to backpressure; the caller should run a sync.
    Resync,
    /// The server closed the socket with [`CLOSE_DEPRECATED_PROTOCOL`] (`4010`), indicating that
    /// this app version must be refreshed/upgraded instead of reconnecting in a loop.
    UpgradeRequired(String),
    /// The socket closed, or never opened, e.g. as the server sends no notifications.
    Closed,
}

/// Outcome of processing a control text frame (`"ok"` or `"pong"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextOutcome {
    Authenticated,
    Pong,
    Ignored,
}

/// Process a text WebSocket frame against `authenticated` and `awaiting_pong`, enforcing
/// [`MAX_TEXT_FRAME_UNITS`] before decoding.
fn handle_text_frame(
    authenticated: &Cell<bool>,
    awaiting_pong: &Cell<bool>,
    len_units: usize,
    text: impl FnOnce() -> String,
) -> TextOutcome {
    if len_units > MAX_TEXT_FRAME_UNITS {
        return TextOutcome::Ignored;
    }
    let text = text();
    if text == AUTH_OK {
        if !authenticated.replace(true) {
            TextOutcome::Authenticated
        } else {
            TextOutcome::Ignored
        }
    } else if text == PONG && authenticated.get() {
        awaiting_pong.set(false);
        TextOutcome::Pong
    } else {
        TextOutcome::Ignored
    }
}

#[derive(Default)]
struct FrameState {
    authenticated: Cell<bool>,
    awaiting_pong: Cell<bool>,
    open_pending: Cell<bool>,
    overflow: Cell<bool>,
    upgrade_required: RefCell<Option<String>>,
}

impl FrameState {
    fn text(
        &self,
        tx: &mut mpsc::Sender<Event>,
        len_units: usize,
        text: impl FnOnce() -> String,
    ) -> TextOutcome {
        let outcome = handle_text_frame(&self.authenticated, &self.awaiting_pong, len_units, text);
        if outcome == TextOutcome::Authenticated
            && tx.try_send(Event::Open).is_err_and(|e| e.is_full())
        {
            self.open_pending.set(true);
        }
        outcome
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

    fn close(&self, mut tx: mpsc::Sender<Event>, code: u16, reason: String) {
        if code == CLOSE_DEPRECATED_PROTOCOL {
            let reason = if reason.trim().is_empty() {
                "This app version is no longer supported for live notifications. Refresh the page to continue."
                    .to_string()
            } else {
                reason
            };
            if tx.try_send(Event::UpgradeRequired(reason.clone())).is_err() {
                *self.upgrade_required.borrow_mut() = Some(reason);
            }
        } else {
            let _ = tx.try_send(Event::Closed);
        }
    }

    async fn next(&self, events: &mut mpsc::Receiver<Event>) -> Event {
        if let Some(reason) = self.upgrade_required.borrow_mut().take() {
            return Event::UpgradeRequired(reason);
        }
        if self.open_pending.replace(false) {
            return Event::Open;
        }
        match events.try_recv() {
            Ok(Event::Closed) if self.overflow.replace(false) => Event::Resync,
            Ok(event) => event,
            Err(_) if self.overflow.replace(false) => Event::Resync,
            Err(e) if e.is_closed() => self
                .upgrade_required
                .borrow_mut()
                .take()
                .map_or(Event::Closed, Event::UpgradeRequired),
            Err(_) => events.next().await.unwrap_or_else(|| {
                self.upgrade_required
                    .borrow_mut()
                    .take()
                    .map_or(Event::Closed, Event::UpgradeRequired)
            }),
        }
    }
}

/// A WebSocket subscribed to a client's notifications. Closed when dropped.
pub struct Subscription {
    socket: WebSocket,
    events: mpsc::Receiver<Event>,
    frames: Rc<FrameState>,
    /// Dropping this cancels the background auth-deadline & keep-alive task immediately.
    _cancel: oneshot::Sender<()>,
    _on_open: Closure<dyn FnMut()>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_close: Closure<dyn FnMut(CloseEvent)>,
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
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let (auth_tx, auth_rx) = oneshot::channel::<()>();
        let auth_tx = Rc::new(Cell::new(Some(auth_tx)));
        let pong_tx: Rc<Cell<Option<oneshot::Sender<()>>>> = Rc::new(Cell::new(None));

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
            let auth_tx = auth_tx.clone();
            let pong_tx = pong_tx.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                let mut sender = sender.borrow_mut();
                let Some(tx) = sender.as_mut() else {
                    return;
                };
                let data = event.data();
                if let Some(js_str) = data.dyn_ref::<JsString>() {
                    // Check UTF-16 length in JS BEFORE allocating a Rust `String`.
                    let len = js_str.length() as usize;
                    match frames.text(tx, len, || String::from(js_str)) {
                        TextOutcome::Authenticated => {
                            if let Some(done) = auth_tx.take() {
                                let _ = done.send(());
                            }
                        }
                        TextOutcome::Pong => {
                            if let Some(done) = pong_tx.take() {
                                let _ = done.send(());
                            }
                        }
                        TextOutcome::Ignored => {}
                    }
                } else if let Ok(buffer) = data.dyn_into::<ArrayBuffer>() {
                    frames.binary(tx, buffer.byte_length() as usize, || {
                        Uint8Array::new(&buffer).to_vec()
                    });
                }
            })
        };
        // An error is followed by a close. Dropping the shared sender guarantees the receiver ends.
        let on_close = {
            let frames = frames.clone();
            Closure::<dyn FnMut(CloseEvent)>::new(move |event: CloseEvent| {
                if let Some(tx) = sender.borrow_mut().take() {
                    frames.close(tx, event.code(), event.reason());
                }
            })
        };
        socket.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));
        keep_alive(socket.clone(), frames.clone(), cancel_rx, auth_rx, pong_tx);
        Ok(Self {
            socket,
            events,
            frames,
            _cancel: cancel_tx,
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

/// Enforce the initial auth-ack deadline and, once authenticated, ping periodically with a pong
/// timeout until the socket closes or `cancel` fires (cancelling all browser timers on drop).
fn keep_alive(
    socket: WebSocket,
    frames: Rc<FrameState>,
    mut cancel: oneshot::Receiver<()>,
    auth_ok: oneshot::Receiver<()>,
    pong_slot: Rc<Cell<Option<oneshot::Sender<()>>>>,
) {
    wasm_bindgen_futures::spawn_local(async move {
        // Phase 1: Require `"ok"` auth acknowledgement within `AUTH_TIMEOUT_MS`.
        let wait_auth = select(auth_ok, Box::pin(sleep(AUTH_TIMEOUT_MS)));
        match select(cancel, wait_auth).await {
            Either::Left(_) => return,
            Either::Right((Either::Left((Ok(()), _)), next_cancel)) => cancel = next_cancel,
            Either::Right(_) => {
                if !frames.authenticated.get() {
                    let _ = socket.close();
                }
                return;
            }
        }
        // Phase 2: Authenticated keep-alive pings with pong liveness checks.
        loop {
            match select(cancel, Box::pin(sleep(PING_EVERY))).await {
                Either::Left(_) => return,
                Either::Right((_, next_cancel)) => cancel = next_cancel,
            }
            if socket.ready_state() != WebSocket::OPEN {
                return;
            }
            let (tx, rx) = oneshot::channel::<()>();
            pong_slot.set(Some(tx));
            frames.awaiting_pong.set(true);
            if socket.send_with_str(PING).is_err() {
                pong_slot.set(None);
                let _ = socket.close();
                return;
            }
            let wait_pong = select(rx, Box::pin(sleep(PONG_TIMEOUT_MS)));
            match select(cancel, wait_pong).await {
                Either::Left(_) => {
                    pong_slot.set(None);
                    return;
                }
                Either::Right((Either::Left((Ok(()), _)), next_cancel)) => {
                    cancel = next_cancel;
                }
                Either::Right((_, _)) => {
                    pong_slot.set(None);
                    if frames.awaiting_pong.get() {
                        let _ = socket.close();
                        return;
                    }
                    return;
                }
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
    fn auth_ok_and_pong_frames_respect_state_and_size_cap() {
        let authenticated = Cell::new(false);
        let awaiting_pong = Cell::new(true);
        // Oversized text frames are dropped BEFORE invoking the allocator closure.
        assert_eq!(
            handle_text_frame(
                &authenticated,
                &awaiting_pong,
                MAX_TEXT_FRAME_UNITS + 1,
                || panic!("oversized text frame must not allocate"),
            ),
            TextOutcome::Ignored
        );
        // Pre-auth "pong" and wrong-case "OK" are ignored.
        assert_eq!(
            handle_text_frame(&authenticated, &awaiting_pong, 4, || "pong".into()),
            TextOutcome::Ignored
        );
        assert!(awaiting_pong.get());
        assert_eq!(
            handle_text_frame(&authenticated, &awaiting_pong, 2, || "OK".into()),
            TextOutcome::Ignored
        );
        assert!(!authenticated.get());
        // First "ok" authenticates.
        assert_eq!(
            handle_text_frame(&authenticated, &awaiting_pong, 2, || "ok".into()),
            TextOutcome::Authenticated
        );
        assert!(authenticated.get());
        // Repeated "ok" is ignored; post-auth "pong" clears awaiting_pong.
        assert_eq!(
            handle_text_frame(&authenticated, &awaiting_pong, 2, || "ok".into()),
            TextOutcome::Ignored
        );
        assert_eq!(
            handle_text_frame(&authenticated, &awaiting_pong, 4, || "pong".into()),
            TextOutcome::Pong
        );
        assert!(!awaiting_pong.get());
    }

    #[test]
    fn notifications_require_authentication_and_overflow_resyncs() {
        let state = FrameState::default();
        let (mut tx, mut rx) = mpsc::channel(0);
        state.binary(&mut tx, 0, || panic!("pre-auth frame read"));
        assert!(rx.try_recv().is_err());
        assert!(!state.overflow.get());
        assert_eq!(
            state.text(&mut tx, 2, || "ok".into()),
            TextOutcome::Authenticated
        );
        assert_eq!(state.text(&mut tx, 2, || "ok".into()), TextOutcome::Ignored);
        assert_eq!(state.text(&mut tx, 4, || "pong".into()), TextOutcome::Pong);
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
        state.text(&mut tx, 2, || "ok".into());
        state.text(&mut tx, 2, || "ok".into());
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

    #[test]
    fn close_4010_emits_upgrade_required_even_under_channel_backpressure() {
        let state = FrameState::default();
        let (tx, mut rx) = mpsc::channel(0);
        state.close(
            tx,
            CLOSE_DEPRECATED_PROTOCOL,
            "Legacy v1 notifications deprecated; refresh or upgrade the app".to_string(),
        );
        match futures::executor::block_on(state.next(&mut rx)) {
            Event::UpgradeRequired(reason) => {
                assert!(reason.contains("refresh or upgrade"));
            }
            _ => panic!("expected Event::UpgradeRequired"),
        }
        assert!(matches!(
            futures::executor::block_on(state.next(&mut rx)),
            Event::Closed
        ));

        // Empty close reason still yields a clear refresh message, even when the queue is full.
        let state = FrameState::default();
        let (mut tx, mut rx) = mpsc::channel(0);
        assert!(tx.try_send(Event::Resync).is_ok());
        state.close(tx, CLOSE_DEPRECATED_PROTOCOL, String::new());
        match futures::executor::block_on(state.next(&mut rx)) {
            Event::UpgradeRequired(reason) => assert!(reason.contains("Refresh")),
            _ => panic!("expected Event::UpgradeRequired under backpressure"),
        }

        // Ordinary close codes emit Event::Closed.
        let state = FrameState::default();
        let (tx, mut rx) = mpsc::channel(1);
        state.close(tx, 1008, "invalid signature".to_string());
        assert!(matches!(
            futures::executor::block_on(state.next(&mut rx)),
            Event::Closed
        ));
    }
}
