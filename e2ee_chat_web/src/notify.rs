//! Notifications over the server's WebSocket: the server says at once when something arrives,
//! so the client need not poll for it.
//!
//! Connects to `/notifications` (with zero identity key in the URL) and presents pre-upgrade
//! authentication via `Sec-WebSocket-Protocol: e2ee-notify.v2, e2ee-sub.<b64url_nopad(SubscribeRequest)>`.
//! Verifies `socket.protocol() == "e2ee-notify.v2"` on `on_open`, enforces open and pong liveness
//! deadlines, caps incoming frame sizes before copying into WASM memory, and bounds pending
//! notification buffering against message floods.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_channel::{mpsc, oneshot};
use futures_util::{
    StreamExt,
    future::{Either, select},
};
use js_sys::{Array, ArrayBuffer, JsString, Uint8Array};
use prost::Message;
use session::protocol::notify::{Notification, SubscribeRequest};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{BinaryType, CloseEvent, MessageEvent, WebSocket};

use crate::util::{js_error, sleep};

/// Where the Worker takes subscriptions (zero query parameters).
const PATH: &str = "/notifications";
/// Negotiated WebSocket subprotocol echoed by the Worker upon pre-auth acceptance.
pub const SUBPROTOCOL_V2: &str = "e2ee-notify.v2";
/// Prefix for the second offered subprotocol carrying unpadded base64url `SubscribeRequest`.
const SUBPROTOCOL_SUB_PREFIX: &str = "e2ee-sub.";
/// What keeps the socket open through idle proxies, answered by the Worker without waking it,
/// and shows the Worker it is open still.
const PING: &str = "ping";
/// Text frame sent by the Worker in reply to [`PING`].
const PONG: &str = "pong";
/// Milliseconds allowed for the pre-authenticated WebSocket handshake to reach `on_open`.
const OPEN_TIMEOUT_MS: i32 = 15_000;
/// Milliseconds between pings, often enough for proxies that close idle connections.
const PING_EVERY: i32 = 60_000;
/// Milliseconds allowed for `"pong"` after sending [`PING`] before declaring the socket dead.
const PONG_TIMEOUT_MS: i32 = 15_000;
/// Maximum buffered notification events before coalescing into a resync (bounds memory under flood).
const MAX_PENDING_EVENTS: usize = 64;
/// Maximum accepted binary notification frame size in bytes (a `Notification` is tiny).
const MAX_NOTIFICATION_BYTES: usize = 1024;
/// Maximum accepted text frame length in UTF-16 code units (valid frames are `"pong"`).
const MAX_TEXT_FRAME_UNITS: usize = 64;

/// What happens on a subscription's socket.
pub enum Event {
    /// The socket opened and negotiated [`SUBPROTOCOL_V2`].
    Open,
    Notification(Notification),
    /// Some notifications were dropped due to backpressure; the caller should run a sync.
    Resync,
    /// The socket closed, or never opened, e.g. as the server sends no notifications.
    Closed,
}

/// Outcome of processing a control text frame (`"pong"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextOutcome {
    Pong,
    Ignored,
}

/// Process a text WebSocket frame against `opened` and `awaiting_pong`, enforcing
/// [`MAX_TEXT_FRAME_UNITS`] before decoding.
fn handle_text_frame(
    opened: &Cell<bool>,
    awaiting_pong: &Cell<bool>,
    len_units: usize,
    text: impl FnOnce() -> String,
) -> TextOutcome {
    if !opened.get() || len_units > MAX_TEXT_FRAME_UNITS {
        return TextOutcome::Ignored;
    }
    if text() == PONG {
        awaiting_pong.set(false);
        TextOutcome::Pong
    } else {
        TextOutcome::Ignored
    }
}

#[derive(Default)]
struct FrameState {
    opened: Cell<bool>,
    awaiting_pong: Cell<bool>,
    open_pending: Cell<bool>,
    overflow: Cell<bool>,
}

impl FrameState {
    /// Verify the negotiated subprotocol upon `on_open`; returns `true` when accepted.
    fn open(&self, tx: &mut mpsc::Sender<Event>, negotiated_protocol: &str) -> bool {
        if negotiated_protocol != SUBPROTOCOL_V2 {
            return false;
        }
        if !self.opened.replace(true) && tx.try_send(Event::Open).is_err_and(|e| e.is_full()) {
            self.open_pending.set(true);
        }
        true
    }

    fn text(&self, len_units: usize, text: impl FnOnce() -> String) -> TextOutcome {
        handle_text_frame(&self.opened, &self.awaiting_pong, len_units, text)
    }

    fn binary(&self, tx: &mut mpsc::Sender<Event>, len: usize, bytes: impl FnOnce() -> Vec<u8>) {
        if !self.opened.get() || len > MAX_NOTIFICATION_BYTES {
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

    fn close(&self, mut tx: mpsc::Sender<Event>) {
        let _ = tx.try_send(Event::Closed);
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
    /// Dropping this cancels the background open-deadline & keep-alive task immediately.
    _cancel: oneshot::Sender<()>,
    _on_open: Closure<dyn FnMut()>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_close: Closure<dyn FnMut(CloseEvent)>,
}

/// Build the pre-auth WebSocket URL (`/notifications`, with zero query parameters).
fn subscription_url(server: &str) -> String {
    format!("{}{PATH}", socket_address(server))
}

/// Build the `Sec-WebSocket-Protocol` offer tokens: `["e2ee-notify.v2", "e2ee-sub.<b64url_nopad>"]`.
fn subscription_protocols(request: &SubscribeRequest) -> Result<[String; 2], String> {
    if request.identity_key.len() != 32 {
        return Err("invalid identity key length for notifications".to_string());
    }
    let encoded = URL_SAFE_NO_PAD.encode(request.encode_to_vec());
    Ok([
        SUBPROTOCOL_V2.to_string(),
        format!("{SUBPROTOCOL_SUB_PREFIX}{encoded}"),
    ])
}

impl Subscription {
    /// Open a pre-authenticated WebSocket to `server` (e.g. `https://chat.example.com`) carrying
    /// `request` in `Sec-WebSocket-Protocol` without any identity query parameter.
    pub fn open(server: &str, request: &SubscribeRequest) -> Result<Self, String> {
        let url = subscription_url(server);
        let [proto_v2, proto_sub] = subscription_protocols(request)?;
        let protocols = Array::of2(
            &JsValue::from_str(&proto_v2),
            &JsValue::from_str(&proto_sub),
        );
        let socket = WebSocket::new_with_str_sequence(&url, &protocols).map_err(js_error)?;
        socket.set_binary_type(BinaryType::Arraybuffer);
        let (sender, events) = mpsc::channel(MAX_PENDING_EVENTS);
        let sender = Rc::new(RefCell::new(Some(sender)));
        let frames = Rc::new(FrameState::default());
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let (open_tx, open_rx) = oneshot::channel::<()>();
        let open_tx = Rc::new(Cell::new(Some(open_tx)));
        let pong_tx: Rc<Cell<Option<oneshot::Sender<()>>>> = Rc::new(Cell::new(None));

        let on_open = {
            let sender = sender.clone();
            let frames = frames.clone();
            let socket = socket.clone();
            let open_tx = open_tx.clone();
            Closure::<dyn FnMut()>::new(move || {
                let negotiated = socket.protocol();
                let mut guard = sender.borrow_mut();
                let Some(tx) = guard.as_mut() else {
                    return;
                };
                if frames.open(tx, &negotiated) {
                    if let Some(done) = open_tx.take() {
                        let _ = done.send(());
                    }
                } else {
                    drop(guard);
                    let _ = socket.close();
                    if let Some(tx) = sender.borrow_mut().take() {
                        frames.close(tx);
                    }
                }
            })
        };
        let on_message = {
            let sender = sender.clone();
            let frames = frames.clone();
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
                    if frames.text(len, || String::from(js_str)) == TextOutcome::Pong
                        && let Some(done) = pong_tx.take()
                    {
                        let _ = done.send(());
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
            Closure::<dyn FnMut(CloseEvent)>::new(move |_event: CloseEvent| {
                if let Some(tx) = sender.borrow_mut().take() {
                    frames.close(tx);
                }
            })
        };
        socket.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));
        keep_alive(socket.clone(), frames.clone(), cancel_rx, open_rx, pong_tx);
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

/// Enforce the initial `on_open` handshake deadline and, once open, ping periodically with a pong
/// timeout until the socket closes or `cancel` fires (cancelling all browser timers on drop).
fn keep_alive(
    socket: WebSocket,
    frames: Rc<FrameState>,
    mut cancel: oneshot::Receiver<()>,
    opened: oneshot::Receiver<()>,
    pong_slot: Rc<Cell<Option<oneshot::Sender<()>>>>,
) {
    wasm_bindgen_futures::spawn_local(async move {
        // Phase 1: Require `on_open` with negotiated `e2ee-notify.v2` within `OPEN_TIMEOUT_MS`.
        let wait_open = select(opened, Box::pin(sleep(OPEN_TIMEOUT_MS)));
        match select(cancel, wait_open).await {
            Either::Left(_) => return,
            Either::Right((Either::Left((Ok(()), _)), next_cancel)) => cancel = next_cancel,
            Either::Right(_) => {
                if !frames.opened.get() {
                    let _ = socket.close();
                }
                return;
            }
        }
        // Phase 2: Keep-alive pings with pong liveness checks.
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
    use bytes::Bytes;

    use super::*;

    #[test]
    fn pre_auth_ws_url_has_no_query_and_subprotocols_encode_request() {
        let url = subscription_url("https://chat.example.com/");
        assert_eq!(url, "wss://chat.example.com/notifications");
        assert!(!url.contains('?'));
        assert!(!url.contains("identity"));

        let req = SubscribeRequest {
            identity_key: Bytes::from_static(&[0xABu8; 32]),
            timestamp: 1_700_000_000_000,
            signature: Bytes::from_static(&[0xCDu8; 64]),
            audience: "chat.example.com".to_string(),
            nonce: Bytes::from_static(&[0xEFu8; 16]),
        };
        let [p0, p1] = subscription_protocols(&req).unwrap();
        assert_eq!(p0, "e2ee-notify.v2");
        let b64 = p1.strip_prefix("e2ee-sub.").expect("e2ee-sub. prefix");
        assert!(!b64.contains('='));
        assert!(!b64.contains('+'));
        assert!(!b64.contains('/'));
        let decoded = SubscribeRequest::decode(URL_SAFE_NO_PAD.decode(b64).unwrap().as_slice())
            .expect("decode roundtrip");
        assert_eq!(decoded, req);

        let bad = SubscribeRequest {
            identity_key: Bytes::from_static(&[0u8; 31]),
            ..req
        };
        assert!(subscription_protocols(&bad).is_err());
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
    fn open_verifies_subprotocol_and_pong_respects_state_and_size_cap() {
        let state = FrameState::default();
        let (mut tx, mut rx) = mpsc::channel(4);

        // Wrong or empty negotiated subprotocol is rejected.
        assert!(!state.open(&mut tx, ""));
        assert!(!state.open(&mut tx, "e2ee-notify.v1"));
        assert!(!state.opened.get());
        assert!(rx.try_recv().is_err());

        // Pre-open text/binary frames are ignored.
        state.awaiting_pong.set(true);
        assert_eq!(state.text(4, || "pong".into()), TextOutcome::Ignored);
        assert!(state.awaiting_pong.get());
        state.binary(&mut tx, 0, || panic!("pre-open frame read"));

        // Matching subprotocol opens the socket and emits Event::Open.
        assert!(state.open(&mut tx, SUBPROTOCOL_V2));
        assert!(state.opened.get());
        assert!(matches!(rx.try_recv(), Ok(Event::Open)));

        // Oversized text frame dropped BEFORE invoking allocator closure.
        assert_eq!(
            state.text(MAX_TEXT_FRAME_UNITS + 1, || {
                panic!("oversized text frame must not allocate")
            }),
            TextOutcome::Ignored
        );
        // Legacy "ok" is ignored; "pong" clears awaiting_pong.
        assert_eq!(state.text(2, || "ok".into()), TextOutcome::Ignored);
        assert_eq!(state.text(4, || "pong".into()), TextOutcome::Pong);
        assert!(!state.awaiting_pong.get());
    }

    #[test]
    fn notifications_deliver_sender_blind_events_and_overflow_resyncs() {
        let state = FrameState::default();
        let (mut tx, mut rx) = mpsc::channel(0);
        assert!(state.open(&mut tx, SUBPROTOCOL_V2));
        assert!(matches!(rx.try_recv(), Ok(Event::Open)));

        let msg_bytes = Notification::message().encode_to_vec();
        let init_bytes = Notification::initial_message().encode_to_vec();
        state.binary(&mut tx, msg_bytes.len(), || msg_bytes.clone());
        state.binary(&mut tx, init_bytes.len(), || init_bytes.clone());

        match futures::executor::block_on(state.next(&mut rx)) {
            Event::Notification(note) => assert_eq!(note, Notification::message()),
            _ => panic!("expected message notification"),
        }
        assert!(matches!(
            futures::executor::block_on(state.next(&mut rx)),
            Event::Resync
        ));
        state.close(tx);
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
        assert!(state.open(&mut tx, SUBPROTOCOL_V2));
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
