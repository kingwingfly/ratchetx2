//! Notification subscriptions, replay protection, and hibernating WebSockets.

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use prost::Message as _;
use protocol::{
    MAX_CLOCK_SKEW,
    notify::{Notification, SubscribeRequest},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage::MAX_SAFE_INTEGER;
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use worker::{
    Date, Request, Response, Result, WebSocket, WebSocketIncomingMessage, WebSocketPair,
    console_error, js_sys,
};

use super::{Identity, rows::CountRow, schema::SCHEMA_SEEN_SUBSCRIBES};
use crate::objects::checked_integer;

/// Internal header carrying the hex-encoded signature of a query-param verified `SubscribeRequest`.
pub const HEADER_SUBSCRIBE_SIG: &str = "x-e2ee-subscribe-sig";
/// Internal header carrying the decimal timestamp of a query-param verified `SubscribeRequest`.
pub const HEADER_SUBSCRIBE_TS: &str = "x-e2ee-subscribe-ts";
/// Internal header carrying the hex-encoded expected identity key for first-frame WS auth.
pub const HEADER_PENDING_IDENTITY: &str = "x-e2ee-pending-identity";

/// Internal relay audience for first-frame subscription verification.
pub const HEADER_SUBSCRIBE_AUDIENCE: &str = "x-e2ee-subscribe-audience";

/// What a client sends to keep its WebSocket open, and the answer, given without waking the
/// object.
pub(super) const PING: &str = "ping";
pub(super) const PONG: &str = "pong";
/// Text frame sent once a first-frame-auth WebSocket's `SubscribeRequest` is verified.
const AUTH_OK: &str = "ok";
/// How long, in milliseconds, a socket may go without a ping: its client pings every minute.
const STALE: f64 = 3.0 * 60_000.0;
/// Maximum concurrent authenticated WebSocket connections per Identity DO.
const MAX_WEBSOCKETS: usize = 16;
/// Maximum concurrent unauthenticated first-frame-auth pending WebSockets per Identity DO.
const MAX_PENDING_WEBSOCKETS: usize = 8;
/// Maximum time (in ms) a first-frame-auth WebSocket may stay unauthenticated.
const MAX_UNAUTH_AGE_MS: f64 = 5_000.0;
/// Maximum bytes accepted in an authentication WebSocket frame.
const MAX_AUTH_FRAME_BYTES: usize = 1536;
/// Maximum unexpired subscription signatures stored by one identity.
const MAX_SEEN_SUBSCRIBES: usize = 256;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = worker::worker_sys::DurableObjectState, js_name = DurableObjectState)]
    type AutoResponseState;

    #[wasm_bindgen(method, catch, js_name = getWebSocketAutoResponseTimestamp)]
    fn get_websocket_auto_response_timestamp(
        this: &AutoResponseState,
        ws: &worker::web_sys::WebSocket,
    ) -> std::result::Result<Option<js_sys::Date>, JsValue>;
}

enum SubscribeRecordOutcome {
    Fresh,
    Replayed,
    CapacityExceeded,
}

/// Per-WebSocket attachment stored via hibernation API.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WsAttachment {
    opened_at: f64,
    authenticated: bool,
    #[serde(default)]
    expected_identity: Option<Vec<u8>>,
    #[serde(default)]
    expected_audience: Option<String>,
}

impl Identity {
    pub(super) async fn handle_websocket_message(
        &self,
        socket: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let Some(mut attachment) = read_ws_attachment(&socket) else {
            let _ = socket.close(Some(1008), Some("missing state"));
            return Ok(());
        };
        if attachment.authenticated {
            // Authenticated clients send nothing but pings (auto-responded).
            return Ok(());
        }
        let now_f64 = js_sys::Date::now();
        if now_f64 - attachment.opened_at > MAX_UNAUTH_AGE_MS {
            let _ = socket.close(Some(1008), Some("auth timeout"));
            return Ok(());
        }
        let (Some(expected_identity), Some(expected_audience)) = (
            attachment.expected_identity.take(),
            attachment.expected_audience.take(),
        ) else {
            let _ = socket.close(Some(1008), Some("unauthorized"));
            return Ok(());
        };
        let raw_bytes = match message {
            WebSocketIncomingMessage::Binary(bytes) => {
                if bytes.len() > MAX_AUTH_FRAME_BYTES {
                    let _ = socket.close(Some(1008), Some("frame too large"));
                    return Ok(());
                }
                bytes
            }
            WebSocketIncomingMessage::String(text) => {
                if text.len() > (MAX_AUTH_FRAME_BYTES * 4).div_ceil(3) {
                    let _ = socket.close(Some(1008), Some("frame too large"));
                    return Ok(());
                }
                match BASE64_URL_SAFE_NO_PAD.decode(text.trim().as_bytes()) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        let _ = socket.close(Some(1008), Some("malformed subscription"));
                        return Ok(());
                    }
                }
            }
        };
        let Ok(subscription) = SubscribeRequest::decode(raw_bytes.as_slice()) else {
            let _ = socket.close(Some(1008), Some("malformed subscription"));
            return Ok(());
        };
        let now_ms = Date::now().as_millis();
        let expected_audience = crate::subscribe_audience(expected_audience);
        let Ok(identity_key) = crate::verify_subscribe_request(
            &subscription,
            &expected_audience,
            crate::legacy_v1_enabled(&self.env),
            now_ms,
        ) else {
            let _ = socket.close(Some(1008), Some("invalid subscription"));
            return Ok(());
        };
        if identity_key.as_slice() != expected_identity.as_slice() {
            let _ = socket.close(Some(1008), Some("identity mismatch"));
            return Ok(());
        }
        let Ok(sig) = <[u8; 64]>::try_from(subscription.signature.as_ref()) else {
            let _ = socket.close(Some(1008), Some("invalid signature"));
            return Ok(());
        };
        match self
            .record_subscribe_signature(&sig, subscription.timestamp, now_ms)
            .await
        {
            Ok(SubscribeRecordOutcome::Fresh) => {}
            Ok(SubscribeRecordOutcome::CapacityExceeded) => {
                let _ = socket.close(Some(1008), Some("too many recent subscriptions"));
                return Ok(());
            }
            Ok(SubscribeRecordOutcome::Replayed) => {
                let _ = socket.close(Some(1008), Some("replayed subscription"));
                return Ok(());
            }
            Err(error) => {
                console_error!("cannot record subscription: {error}");
                let _ = socket.close(Some(1011), Some("state error"));
                return Ok(());
            }
        };
        attachment.authenticated = true;
        attachment.opened_at = now_f64;
        if socket.serialize_attachment(&attachment).is_err() {
            let _ = socket.close(Some(1011), Some("state error"));
            return Ok(());
        }
        if socket.send_with_str(AUTH_OK).is_err() {
            let _ = socket.close(Some(1011), Some("send error"));
            return Ok(());
        }
        self.prune_and_cap_authenticated(now_f64, MAX_WEBSOCKETS, Some(&socket));
        Ok(())
    }

    /// Keep the signature through the last millisecond at which verification can succeed.
    async fn record_subscribe_signature(
        &self,
        sig: &[u8; 64],
        timestamp: u64,
        now_ms: u64,
    ) -> Result<SubscribeRecordOutcome> {
        let expires_at = timestamp
            .saturating_add(MAX_CLOCK_SKEW)
            .min(MAX_SAFE_INTEGER);
        let sql = self.sql();
        sql.exec(SCHEMA_SEEN_SUBSCRIBES, None)?;
        sql.exec(
            "DELETE FROM seen_subscribes WHERE expires_at < ?",
            vec![checked_integer(now_ms)?],
        )?;
        let sig_hash = crate::hex(&Sha256::digest(sig));
        let existing: CountRow = sql
            .exec(
                "SELECT count(*) AS count FROM seen_subscribes WHERE sig_hash = ?",
                vec![sig_hash.as_str().into()],
            )?
            .one()?;
        if existing.count > 0 {
            return Ok(SubscribeRecordOutcome::Replayed);
        }
        let total: CountRow = sql
            .exec("SELECT count(*) AS count FROM seen_subscribes", None)?
            .one()?;
        if total.count >= MAX_SEEN_SUBSCRIBES as u64 {
            return Ok(SubscribeRecordOutcome::CapacityExceeded);
        }
        sql.exec(
            "INSERT INTO seen_subscribes (sig_hash, expires_at) VALUES (?, ?)",
            vec![sig_hash.into(), checked_integer(expires_at)?],
        )?;
        self.schedule_expiry(false).await?;
        Ok(SubscribeRecordOutcome::Fresh)
    }

    /// Accepts a WebSocket connection after checking replay protection (query-param auth) or
    /// setting up pending first-frame auth.
    ///
    /// Pending unauthenticated sockets are capped separately ([`MAX_PENDING_WEBSOCKETS`], HTTP
    /// 429) and NEVER evict authenticated sockets. Authenticated sockets are capped at
    /// [`MAX_WEBSOCKETS`], evicting the oldest authenticated socket only when an authenticated
    /// connection arrives.
    pub(super) async fn accept_websocket(&self, request: &Request) -> Result<Response> {
        let now_ms = Date::now().as_millis();
        let now_f64 = js_sys::Date::now();

        let attachment = if let (Some(sig_hex), Some(ts_str)) = (
            request.headers().get(HEADER_SUBSCRIBE_SIG)?,
            request.headers().get(HEADER_SUBSCRIBE_TS)?,
        ) {
            let Some(sig) = crate::decode_hex_fixed::<64>(&sig_hex) else {
                return Response::error("malformed subscription", 400);
            };
            let Ok(ts) = ts_str.parse::<u64>() else {
                return Response::error("malformed subscription", 400);
            };
            if ts.abs_diff(now_ms) > MAX_CLOCK_SKEW {
                return Response::error("invalid subscription", 403);
            }
            match self.record_subscribe_signature(&sig, ts, now_ms).await? {
                SubscribeRecordOutcome::Fresh => {}
                SubscribeRecordOutcome::Replayed => {
                    return Response::error("replayed subscription", 403);
                }
                SubscribeRecordOutcome::CapacityExceeded => {
                    return Response::error("too many recent subscriptions", 429);
                }
            }
            self.prune_and_cap_authenticated(now_f64, MAX_WEBSOCKETS - 1, None);
            WsAttachment {
                opened_at: now_f64,
                authenticated: true,
                expected_identity: None,
                expected_audience: None,
            }
        } else if let Some(id_hex) = request.headers().get(HEADER_PENDING_IDENTITY)? {
            let Some(id) = crate::decode_hex_fixed::<32>(&id_hex) else {
                return Response::error("malformed identity", 400);
            };
            let Some(raw) = request.headers().get(HEADER_SUBSCRIBE_AUDIENCE)? else {
                return Response::error("missing subscription audience", 400);
            };
            let Ok(audience) = protocol::normalize_audience(&crate::subscribe_audience(raw)) else {
                return Response::error("malformed subscription audience", 400);
            };
            if self.prune_and_count_pending(now_f64) >= MAX_PENDING_WEBSOCKETS {
                return Response::error("too many pending connections", 429);
            }
            WsAttachment {
                opened_at: now_f64,
                authenticated: false,
                expected_identity: Some(id.to_vec()),
                expected_audience: Some(audience),
            }
        } else {
            return Response::error("unauthorized", 403);
        };

        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);
        if let Err(e) = pair.server.serialize_attachment(&attachment) {
            let _ = pair.server.close(Some(1011), Some("state error"));
            return Err(e);
        }
        Response::from_websocket(pair.client)
    }

    /// Prunes expired pending sockets and sockets missing state, returning the remaining count of
    /// unauthenticated pending sockets. Never touches or evicts authenticated sockets.
    fn prune_and_count_pending(&self, now: f64) -> usize {
        let mut pending = 0usize;
        for socket in self.state.get_websockets() {
            let Some(att) = read_ws_attachment(&socket) else {
                let _ = socket.close(Some(1008), Some("missing state"));
                continue;
            };
            if !att.authenticated {
                if now - att.opened_at > MAX_UNAUTH_AGE_MS {
                    let _ = socket.close(Some(1008), Some("auth timeout"));
                } else {
                    pending += 1;
                }
            }
        }
        pending
    }

    /// Prunes stale authenticated sockets, expired pending sockets, and sockets missing state,
    /// then caps authenticated sockets at `keep_max` by closing the oldest authenticated sockets
    /// (never closing `preserve`, if supplied).
    fn prune_and_cap_authenticated(&self, now: f64, keep_max: usize, preserve: Option<&WebSocket>) {
        let mut authenticated: Vec<(f64, WebSocket)> = Vec::new();
        for socket in self.state.get_websockets() {
            let Some(att) = read_ws_attachment(&socket) else {
                let _ = socket.close(Some(1008), Some("missing state"));
                continue;
            };
            if !att.authenticated {
                if now - att.opened_at > MAX_UNAUTH_AGE_MS {
                    let _ = socket.close(Some(1008), Some("auth timeout"));
                }
                continue;
            }
            let is_preserved = preserve.is_some_and(|p| p.as_ref() == socket.as_ref());
            let seen = self.last_seen(&socket);
            if !is_preserved && seen.is_some_and(|s| now - s > STALE) {
                let _ = socket.close(Some(1001), Some("no pings"));
                continue;
            }
            if !is_preserved {
                authenticated.push((seen.unwrap_or(0.0), socket));
            }
        }
        let effective_cap = if preserve.is_some() {
            keep_max.saturating_sub(1)
        } else {
            keep_max
        };
        if authenticated.len() > effective_cap {
            authenticated.sort_by(|a, b| a.0.total_cmp(&b.0));
            let to_close = authenticated.len() - effective_cap;
            for (_, socket) in authenticated.into_iter().take(to_close) {
                let _ = socket.close(Some(1008), Some("too many connections"));
            }
        }
    }

    /// Tell every authenticated subscriber of `notification`, failing closed on missing state and
    /// pruning stale or unauthenticated timed-out sockets.
    pub(super) fn notify(&self, notification: &Notification) {
        let notification = notification.encode_to_vec();
        let now = js_sys::Date::now();
        for socket in self.state.get_websockets() {
            let Some(att) = read_ws_attachment(&socket) else {
                let _ = socket.close(Some(1008), Some("missing state"));
                continue;
            };
            if !att.authenticated {
                if now - att.opened_at > MAX_UNAUTH_AGE_MS {
                    let _ = socket.close(Some(1008), Some("auth timeout"));
                }
                continue;
            }
            if self
                .last_seen(&socket)
                .is_some_and(|seen| now - seen > STALE)
            {
                let _ = socket.close(Some(1001), Some("no pings"));
                continue;
            }
            let _ = socket.send_with_bytes(&notification);
        }
    }

    fn last_seen(&self, socket: &WebSocket) -> Option<f64> {
        let state: &AutoResponseState = self.state.as_raw().unchecked_ref();
        match state.get_websocket_auto_response_timestamp(socket.as_ref()) {
            Ok(Some(pinged)) => Some(pinged.get_time()),
            Ok(None) | Err(_) => read_ws_attachment(socket).map(|a| a.opened_at),
        }
    }
}

/// Reads the socket attachment, supporting both the new [`WsAttachment`] struct and legacy bare
/// `f64` attachments from sockets opened before upgrade.
fn read_ws_attachment(socket: &WebSocket) -> Option<WsAttachment> {
    if let Ok(Some(att)) = socket.deserialize_attachment::<WsAttachment>() {
        return Some(att);
    }
    socket
        .deserialize_attachment::<f64>()
        .ok()
        .flatten()
        .map(|opened_at| WsAttachment {
            opened_at,
            authenticated: true,
            expected_identity: None,
            expected_audience: None,
        })
}
