//! Notifications over the server's WebSocket: the server says at once when something arrives,
//! so the client need not poll for it.

use base64::prelude::*;
use futures::{StreamExt, channel::mpsc};
use js_sys::{ArrayBuffer, Uint8Array};
use prost::Message;
use session::protocol::notify::{Notification, SubscribeRequest};
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{BinaryType, MessageEvent, WebSocket};

use crate::util::{js_error, sleep};

/// Where the Worker takes subscriptions.
const PATH: &str = "/notifications";
/// What keeps the socket open through idle proxies, answered by the Worker without waking it,
/// and shows the Worker it is open still.
const PING: &str = "ping";
/// Milliseconds between pings, often enough for proxies that close idle connections.
const PING_EVERY: i32 = 60_000;

/// What happens on a subscription's socket.
pub enum Event {
    /// The server took the subscription.
    Open,
    Notification(Notification),
    /// The socket closed, or never opened, e.g. as the server sends no notifications.
    Closed,
}

/// A WebSocket subscribed to a client's notifications. Closed when dropped.
pub struct Subscription {
    socket: WebSocket,
    events: mpsc::UnboundedReceiver<Event>,
    _on_open: Closure<dyn FnMut()>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_close: Closure<dyn FnMut()>,
}

impl Subscription {
    /// Open a socket to `server`, e.g. `https://chat.example.com`, with the signed `request`.
    pub fn open(server: &str, request: &SubscribeRequest) -> Result<Self, String> {
        let url = format!(
            "{}{PATH}?request={}",
            socket_address(server),
            BASE64_URL_SAFE_NO_PAD.encode(request.encode_to_vec())
        );
        let socket = WebSocket::new(&url).map_err(js_error)?;
        socket.set_binary_type(BinaryType::Arraybuffer);
        let (sender, events) = mpsc::unbounded();
        let on_open = {
            let sender = sender.clone();
            Closure::<dyn FnMut()>::new(move || {
                let _ = sender.unbounded_send(Event::Open);
            })
        };
        let on_message = {
            let sender = sender.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                // Pongs come as text, notifications as binary frames.
                let Ok(data) = event.data().dyn_into::<ArrayBuffer>() else {
                    return;
                };
                if let Ok(notification) =
                    Notification::decode(Uint8Array::new(&data).to_vec().as_slice())
                {
                    let _ = sender.unbounded_send(Event::Notification(notification));
                }
            })
        };
        // An error is followed by a close.
        let on_close = Closure::<dyn FnMut()>::new(move || {
            let _ = sender.unbounded_send(Event::Closed);
        });
        socket.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));
        keep_alive(socket.clone());
        Ok(Self {
            socket,
            events,
            _on_open: on_open,
            _on_message: on_message,
            _on_close: on_close,
        })
    }

    /// The next event; [`Event::Closed`] is the last.
    pub async fn next(&mut self) -> Event {
        self.events.next().await.unwrap_or(Event::Closed)
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
