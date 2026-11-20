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
/// Milliseconds between pings, often enough for proxies that close idle connections.
const PING_EVERY: i32 = 60_000;
/// Maximum buffered notification events before coalescing into a resync (bounds memory under flood).
const MAX_PENDING_EVENTS: usize = 64;
/// Maximum accepted binary notification frame size in bytes (a `Notification` is at most ~64 bytes).
const MAX_NOTIFICATION_BYTES: usize = 1024;

/// What happens on a subscription's socket.
pub enum Event {
    /// The socket opened and the signed first-frame `SubscribeRequest` was sent.
    Open,
    Notification(Notification),
    /// Some notifications were dropped due to backpressure; the caller should run a sync.
    Resync,
    /// The socket closed, or never opened, e.g. as the server sends no notifications.
    Closed,
}

/// A WebSocket subscribed to a client's notifications. Closed when dropped.
pub struct Subscription {
    socket: WebSocket,
    events: mpsc::Receiver<Event>,
    overflow: Rc<Cell<bool>>,
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
        let overflow = Rc::new(Cell::new(false));

        let on_open = {
            let sender = sender.clone();
            let socket = socket.clone();
            Closure::<dyn FnMut()>::new(move || {
                if socket.send_with_u8_array(&auth_frame).is_err() {
                    let _ = socket.close();
                    if let Some(mut tx) = sender.borrow_mut().take() {
                        let _ = tx.try_send(Event::Closed);
                    }
                    return;
                }
                if let Some(tx) = sender.borrow_mut().as_mut() {
                    let _ = tx.try_send(Event::Open);
                }
            })
        };
        let on_message = {
            let sender = sender.clone();
            let overflow = overflow.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                // Pongs come as text, notifications as binary frames.
                let Ok(data) = event.data().dyn_into::<ArrayBuffer>() else {
                    return;
                };
                if data.byte_length() as usize > MAX_NOTIFICATION_BYTES {
                    return;
                }
                if let Ok(notification) =
                    Notification::decode(Uint8Array::new(&data).to_vec().as_slice())
                    && let Some(tx) = sender.borrow_mut().as_mut()
                    && tx.try_send(Event::Notification(notification)).is_err()
                {
                    overflow.set(true);
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
            overflow,
            _on_open: on_open,
            _on_message: on_message,
            _on_close: on_close,
        })
    }

    /// The next event; [`Event::Closed`] is the last.
    pub async fn next(&mut self) -> Event {
        match self.events.try_recv() {
            Ok(event) => event,
            Err(e) if e.is_closed() => Event::Closed,
            Err(_) if self.overflow.replace(false) => Event::Resync,
            Err(_) => self.events.next().await.unwrap_or(Event::Closed),
        }
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

/// The WebSocket address of `server`: `ws` for `http`, `wss` for `https`.
fn socket_address(server: &str) -> String {
    let server = server.trim_end_matches('/');
    if let Some(rest) = server.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = server.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        server.to_string()
    }
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
            format!("wss://chat.example.com/notifications?identity={}", "ab".repeat(32))
        );
        assert!(!url.contains("request="));
        assert!(subscription_url("https://chat.example.com", &[0u8; 31]).is_err());
    }
}
