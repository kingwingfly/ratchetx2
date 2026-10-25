//! The notifier: a Durable Object per identity key, holding the WebSockets its client subscribed
//! with, and sending them a notification when something arrives for it.

use worker::{
    DurableObject, Env, Error, Method, Request, Response, Result, State, WebSocket,
    WebSocketIncomingMessage, WebSocketPair, WebSocketRequestResponsePair, console_error,
    durable_object,
};

/// What a client sends to keep its WebSocket open, and the answer, given without waking the
/// object.
const PING: &str = "ping";
const PONG: &str = "pong";

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
                Response::from_websocket(pair.client)
            }
            // A notification, from the Worker, for every subscriber.
            Method::Post => {
                let notification = request.bytes().await?;
                for socket in self.state.get_websockets() {
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
