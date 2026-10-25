//! The notifier: a Durable Object per identity key, holding the WebSockets its client subscribed
//! with, and sending them a notification when something arrives for it.
//!
//! It costs nothing while it sleeps, as the hibernation API holds the sockets meanwhile and
//! answers their pings. A client keeps a socket open only while its user is on the page, and
//! closes it on leaving; one that dies without closing, e.g. as its device sleeps, is closed when
//! the object next wakes, to notify.

use worker::{
    DurableObject, Env, Error, Method, Request, Response, Result, State, WebSocket,
    WebSocketIncomingMessage, WebSocketPair, WebSocketRequestResponsePair, console_error,
    durable_object,
    js_sys::{Date, Function, Reflect},
    wasm_bindgen::{JsCast, JsValue},
};

/// What a client sends to keep its WebSocket open, and the answer, given without waking the
/// object.
const PING: &str = "ping";
const PONG: &str = "pong";
/// How long, in milliseconds, a socket may go without a ping: its client pings every minute.
const STALE: f64 = 3.0 * 60_000.0;

#[durable_object]
pub struct Notifier {
    state: State,
}

impl DurableObject for Notifier {
    fn new(state: State, _env: Env) -> Self {
        match WebSocketRequestResponsePair::new(PING, PONG) {
            Ok(pair) => state.set_websocket_auto_response(&pair),
            Err(e) => console_error!("cannot answer pings: {e:?}"),
        }
        Self { state }
    }

    async fn fetch(&self, mut request: Request) -> Result<Response> {
        match request.method() {
            // A subscription, which the Worker verified. The hibernation API keeps the socket
            // open while the object sleeps, so an idle one costs nothing.
            Method::Get => {
                let pair = WebSocketPair::new()?;
                self.state.accept_web_socket(&pair.server);
                // When it opened, which stands for its last ping until its first.
                let _ = pair.server.serialize_attachment(Date::now());
                Response::from_websocket(pair.client)
            }
            // A notification, from the Worker, for every subscriber.
            Method::Post => {
                let notification = request.bytes().await?;
                let now = Date::now();
                for socket in self.state.get_websockets() {
                    // No one is at the other end of one that stopped pinging.
                    if self
                        .last_seen(&socket)
                        .is_some_and(|seen| now - seen > STALE)
                    {
                        let _ = socket.close(Some(1001), Some("no pings"));
                        continue;
                    }
                    // One closing meanwhile misses it, as its client resyncs on reconnecting.
                    let _ = socket.send_with_bytes(&notification);
                }
                Response::empty()
            }
            _ => Response::error("method not allowed", 405),
        }
    }

    async fn websocket_message(
        &self,
        _socket: WebSocket,
        _message: WebSocketIncomingMessage,
    ) -> Result<()> {
        // Clients send nothing but pings, which are answered without this.
        Ok(())
    }

    async fn websocket_close(
        &self,
        socket: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        // Complete the closing handshake; the socket may be gone already.
        let _ = socket.close(Some(1000), Some("closed"));
        Ok(())
    }

    async fn websocket_error(&self, _socket: WebSocket, _error: Error) -> Result<()> {
        Ok(())
    }
}

impl Notifier {
    /// When `socket` last showed it is open, in milliseconds since the epoch: when it last
    /// pinged, which the runtime keeps without waking the object, or else when it opened. None
    /// if the runtime does not say, so that no socket is closed for want of knowing.
    fn last_seen(&self, socket: &WebSocket) -> Option<f64> {
        let state: &JsValue = self.state.as_raw().as_ref();
        let pinged = Reflect::get(state, &"getWebSocketAutoResponseTimestamp".into())
            .ok()?
            .dyn_into::<Function>()
            .ok()?
            .call1(state, socket.as_ref())
            .ok()?;
        match pinged.dyn_into::<Date>() {
            Ok(pinged) => Some(pinged.get_time()),
            Err(_) => socket.deserialize_attachment::<f64>().ok().flatten(),
        }
    }
}
