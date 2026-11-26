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

use super::{AlarmUpdate, Identity, IdentityStore, rows::CountRow, schema::SCHEMA_SEEN_SUBSCRIBES};
use crate::objects::sql::{SqlExec, params};

/// Internal header set to `"1"` when deployment password auth is satisfied (either `PASSWORD`
/// is not configured, or the request carried a valid sign-in cookie).
pub const HEADER_DEPLOYMENT_AUTH: &str = "x-e2ee-deployment-auth";
/// Internal header carrying the hex-encoded expected identity key for first-frame WS auth.
pub const HEADER_PENDING_IDENTITY: &str = "x-e2ee-pending-identity";
/// Internal header carrying the canonical relay audience for first-frame WS auth.
/// Forwarded by the Worker so older Durable Object instances during rolling deploys continue
/// accepting v2 subscribers seamlessly.
pub const HEADER_SUBSCRIBE_AUDIENCE: &str = "x-e2ee-subscribe-audience";
/// Internal header carrying the sign-in cookie's expiry timestamp (ms since Unix epoch) so
/// hibernated WebSockets are closed once the session expires.
pub const HEADER_SESSION_EXPIRES: &str = "x-e2ee-session-expires";
/// Retired internal header once used for query-param verified `SubscribeRequest` signatures.
/// Kept as a constant so the Worker strips any client-spoofed header before forwarding to an
/// older Durable Object instance during a rolling deploy.
pub const HEADER_SUBSCRIBE_SIG: &str = "x-e2ee-subscribe-sig";
/// Retired internal header once used for query-param verified `SubscribeRequest` timestamps.
/// Stripped at Worker ingress for rolling-deploy safety alongside [`HEADER_SUBSCRIBE_SIG`].
pub const HEADER_SUBSCRIBE_TS: &str = "x-e2ee-subscribe-ts";

/// What a client sends to keep its WebSocket open, and the answer, given without waking the
/// object.
pub(super) const PING: &str = "ping";
pub(super) const PONG: &str = "pong";
/// Text frame sent once a first-frame-auth WebSocket's `SubscribeRequest` is verified.
const AUTH_OK: &str = "ok";
/// WebSocket close code sent when a client attempts an unbound legacy v1 subscription.
const LEGACY_V1_WS_CLOSE_CODE: u16 = 4010;
/// WebSocket close reason sent with [`LEGACY_V1_WS_CLOSE_CODE`].
const LEGACY_V1_WS_CLOSE_REASON: &str =
    "Legacy v1 notifications deprecated; refresh or upgrade the app";
/// How long, in milliseconds, a socket may go without a ping: its client pings every minute.
const STALE: f64 = 3.0 * 60_000.0;
/// Maximum concurrent authenticated WebSocket connections per Identity DO.
const MAX_WEBSOCKETS: usize = 16;
/// Maximum concurrent unauthenticated first-frame-auth pending WebSockets per Identity DO.
const MAX_PENDING_WEBSOCKETS: usize = 8;
/// Maximum time (in ms) a first-frame-auth WebSocket may stay unauthenticated.
const MAX_UNAUTH_AGE_MS: u64 = 5_000;
/// Maximum bytes accepted in an authentication WebSocket frame.
const MAX_AUTH_FRAME_BYTES: usize = 1536;
/// Maximum unexpired subscription replay entries stored by one identity.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubscribeRecordOutcome {
    Fresh,
    Replayed,
    CapacityExceeded,
}

#[derive(Debug, PartialEq, Eq)]
struct WsClose {
    code: u16,
    reason: &'static str,
}

impl WsClose {
    const fn new(code: u16, reason: &'static str) -> Self {
        Self { code, reason }
    }
}

fn reject(socket: &WebSocket, close: WsClose) {
    let _ = socket.close(Some(close.code), Some(close.reason));
}

/// Computes the replay-protection key over `identity || audience || timestamp` rather than raw
/// signature bytes, preventing signature malleability replays.
fn subscribe_replay_key(identity: &[u8; 32], audience: &str, timestamp: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"notify.v2/replay\0");
    hasher.update(identity);
    hasher.update((audience.len() as u32).to_be_bytes());
    hasher.update(audience.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    crate::hex(&hasher.finalize())
}

/// Last millisecond at which a subscription signed at `timestamp` can still verify.
fn subscribe_replay_expiry(timestamp: u64) -> u64 {
    timestamp
        .saturating_add(MAX_CLOCK_SKEW)
        .min(MAX_SAFE_INTEGER)
}

/// Validates a first-frame [`SubscribeRequest`]: requires an audience-bound v2 request
/// unconditionally, returning close code `4010` when `audience` is empty.
fn verify_first_frame_subscribe(
    subscription: &SubscribeRequest,
    expected_identity: &[u8],
    expected_audience: &str,
    now_ms: u64,
) -> std::result::Result<([u8; 32], String), WsClose> {
    if !subscription.is_audience_bound() {
        return Err(WsClose::new(
            LEGACY_V1_WS_CLOSE_CODE,
            LEGACY_V1_WS_CLOSE_REASON,
        ));
    }
    let audience = crate::subscribe_audience(expected_audience.to_owned());
    let identity_key = crate::verify_subscribe_request(subscription, &audience, now_ms)
        .map_err(|_| WsClose::new(1008, "invalid subscription"))?;
    if identity_key.as_slice() != expected_identity {
        return Err(WsClose::new(1008, "identity mismatch"));
    }
    Ok((identity_key, subscription.audience.clone()))
}

fn decode_auth_frame(
    message: WebSocketIncomingMessage,
) -> std::result::Result<SubscribeRequest, WsClose> {
    let raw_bytes = match message {
        WebSocketIncomingMessage::Binary(bytes) => {
            if bytes.len() > MAX_AUTH_FRAME_BYTES {
                return Err(WsClose::new(1008, "frame too large"));
            }
            bytes
        }
        WebSocketIncomingMessage::String(text) => {
            if text.len() > (MAX_AUTH_FRAME_BYTES * 4).div_ceil(3) {
                return Err(WsClose::new(1008, "frame too large"));
            }
            BASE64_URL_SAFE_NO_PAD
                .decode(text.trim().as_bytes())
                .map_err(|_| WsClose::new(1008, "malformed subscription"))?
        }
    };
    SubscribeRequest::decode(raw_bytes.as_slice())
        .map_err(|_| WsClose::new(1008, "malformed subscription"))
}

/// Per-WebSocket attachment stored via hibernation API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct WsAttachment {
    opened_at: f64,
    authenticated: bool,
    #[serde(default)]
    expected_identity: Option<Vec<u8>>,
    #[serde(default)]
    expected_audience: Option<String>,
    #[serde(default)]
    session_expires: Option<u64>,
}

impl WsAttachment {
    fn is_pending_expired(&self, now_ms: u64) -> bool {
        !self.authenticated && (now_ms as f64) - self.opened_at > MAX_UNAUTH_AGE_MS as f64
    }

    fn is_session_expired(&self, now_ms: u64) -> bool {
        self.session_expires.is_some_and(|exp| now_ms >= exp)
    }

    fn close_if_expired(&self, now_ms: u64) -> Option<WsClose> {
        if self.is_session_expired(now_ms) {
            Some(WsClose::new(1008, "session expired"))
        } else if self.is_pending_expired(now_ms) {
            Some(WsClose::new(1008, "auth timeout"))
        } else {
            None
        }
    }

    fn next_deadline(&self) -> Option<u64> {
        let pending_deadline = (!self.authenticated).then(|| {
            (self.opened_at.max(0.0) as u64)
                .saturating_add(MAX_UNAUTH_AGE_MS)
                .saturating_add(1)
        });
        let session_deadline = self.session_expires.map(|exp| exp.saturating_add(1));
        match (pending_deadline, session_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

fn check_subscribe_capacity<S: SqlExec>(
    sql: &S,
    replay_key: &str,
) -> Result<SubscribeRecordOutcome> {
    let existing: CountRow = sql.query_one(
        "SELECT count(*) AS count FROM seen_subscribes WHERE sig_hash = ?",
        params![replay_key]?,
    )?;
    if existing.count > 0 {
        return Ok(SubscribeRecordOutcome::Replayed);
    }
    let total: CountRow = sql.query_one("SELECT count(*) AS count FROM seen_subscribes", vec![])?;
    if total.count >= MAX_SEEN_SUBSCRIBES as u64 {
        return Ok(SubscribeRecordOutcome::CapacityExceeded);
    }
    Ok(SubscribeRecordOutcome::Fresh)
}

impl<S: SqlExec> IdentityStore<'_, S> {
    /// Removes expired replay keys (`expires_at < now_ms`).
    pub(super) fn prune_seen_subscribes(&self, now_ms: u64) -> Result<()> {
        self.sql.exec(
            "DELETE FROM seen_subscribes WHERE expires_at < ?",
            params![now_ms]?,
        )
    }

    /// Initializes `seen_subscribes`, prunes expired entries, and checks replay & capacity before
    /// the DO arms the expiry alarm.
    pub(super) fn precheck_subscribe_replay(
        &self,
        replay_key: &str,
        now_ms: u64,
    ) -> Result<SubscribeRecordOutcome> {
        let precheck = self.sql.transaction_sync(|sql| {
            sql.exec_batch(SCHEMA_SEEN_SUBSCRIBES)?;
            sql.exec(
                "DELETE FROM seen_subscribes WHERE expires_at < ?",
                params![now_ms]?,
            )?;
            check_subscribe_capacity(sql, replay_key)
        })?;
        self.cache.seen_subscribes_ready.set(true);
        Ok(precheck)
    }

    /// Re-verifies replay & capacity and records `(replay_key, expires_at)` atomically.
    pub(super) fn commit_subscribe_replay(
        &self,
        replay_key: &str,
        expires_at: u64,
    ) -> Result<SubscribeRecordOutcome> {
        self.sql.transaction_sync(|sql| {
            let outcome = check_subscribe_capacity(sql, replay_key)?;
            if !matches!(outcome, SubscribeRecordOutcome::Fresh) {
                return Ok(outcome);
            }
            sql.exec(
                "INSERT INTO seen_subscribes (sig_hash, expires_at) VALUES (?, ?)",
                params![replay_key, expires_at]?,
            )?;
            Ok(SubscribeRecordOutcome::Fresh)
        })
    }
}

impl Identity {
    /// Iterates live, unexpired sockets while closing any socket that is missing state, past its
    /// sign-in cookie expiry, or past the pending first-frame auth deadline.
    fn sockets(&self, now_ms: u64) -> impl Iterator<Item = (WebSocket, WsAttachment)> {
        self.state
            .get_websockets()
            .into_iter()
            .filter_map(move |socket| {
                let Some(att) = read_ws_attachment(&socket) else {
                    reject(&socket, WsClose::new(1008, "missing state"));
                    return None;
                };
                if let Some(close) = att.close_if_expired(now_ms) {
                    reject(&socket, close);
                    return None;
                }
                Some((socket, att))
            })
    }

    /// Prunes expired pending sockets, cookie-expired sockets, and stale authenticated sockets.
    pub(super) fn prune_sockets(&self, now_ms: u64) {
        let now_f64 = now_ms as f64;
        for (socket, att) in self.sockets(now_ms) {
            if att.authenticated && now_f64 - self.last_seen(&socket, &att) > STALE {
                reject(&socket, WsClose::new(1001, "no pings"));
            }
        }
    }

    /// Earliest alarm deadline across currently open pending or cookie-bounded WebSockets.
    pub(super) fn next_socket_deadline(&self) -> Option<u64> {
        self.state
            .get_websockets()
            .into_iter()
            .filter_map(|socket| read_ws_attachment(&socket)?.next_deadline())
            .min()
    }

    pub(super) async fn handle_websocket_message(
        &self,
        socket: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let now_ms = Date::now().as_millis();
        let Some(mut attachment) = read_ws_attachment(&socket) else {
            reject(&socket, WsClose::new(1008, "missing state"));
            return Ok(());
        };
        if let Some(close) = attachment.close_if_expired(now_ms) {
            reject(&socket, close);
            return Ok(());
        }
        if attachment.authenticated {
            // Auto-response answers `"ping"` without waking the DO; close any other frame so an
            // authenticated client cannot repeatedly wake the Durable Object with junk frames.
            if !matches!(&message, WebSocketIncomingMessage::String(text) if text == PING) {
                reject(&socket, WsClose::new(1008, "unexpected message"));
            }
            return Ok(());
        }

        let (subscription, identity_key, canonical_audience) =
            match verify_pending_auth(&mut attachment, message, now_ms) {
                Ok(verified) => verified,
                Err(close) => {
                    reject(&socket, close);
                    return Ok(());
                }
            };
        let replay_key =
            subscribe_replay_key(&identity_key, &canonical_audience, subscription.timestamp);
        match self
            .record_subscribe_replay(&replay_key, subscription.timestamp, now_ms)
            .await
        {
            Ok(SubscribeRecordOutcome::Fresh) => {}
            Ok(SubscribeRecordOutcome::CapacityExceeded) => {
                reject(&socket, WsClose::new(1008, "too many recent subscriptions"));
                return Ok(());
            }
            Ok(SubscribeRecordOutcome::Replayed) => {
                reject(&socket, WsClose::new(1008, "replayed subscription"));
                return Ok(());
            }
            Err(error) => {
                console_error!("cannot record subscription: {error}");
                reject(&socket, WsClose::new(1011, "state error"));
                return Ok(());
            }
        }

        attachment.authenticated = true;
        attachment.opened_at = now_ms as f64;
        if socket.serialize_attachment(&attachment).is_err() {
            reject(&socket, WsClose::new(1011, "state error"));
            return Ok(());
        }
        if socket.send_with_str(AUTH_OK).is_err() {
            reject(&socket, WsClose::new(1011, "send error"));
            return Ok(());
        }
        if let Some(exp) = attachment.session_expires
            && let Err(e) = self
                .update_alarm(AlarmUpdate::PullEarlier(exp.saturating_add(1)))
                .await
        {
            console_error!("cannot schedule session expiry alarm: {e}");
        }
        self.prune_and_cap_authenticated(now_ms, MAX_WEBSOCKETS, Some(&socket));
        Ok(())
    }

    /// Keep the replay key through the last millisecond at which verification can succeed.
    async fn record_subscribe_replay(
        &self,
        replay_key: &str,
        timestamp: u64,
        now_ms: u64,
    ) -> Result<SubscribeRecordOutcome> {
        let expires_at = subscribe_replay_expiry(timestamp);
        let precheck =
            self.with_store(|store| store.precheck_subscribe_replay(replay_key, now_ms))?;
        if !matches!(precheck, SubscribeRecordOutcome::Fresh) {
            return Ok(precheck);
        }
        // Arm the expiry alarm BEFORE inserting the row so a transient alarm error cannot leave
        // an unexpiring `seen_subscribes` record behind.
        self.update_alarm(AlarmUpdate::PullEarlier(expires_at.saturating_add(1)))
            .await?;
        self.with_store(|store| store.commit_subscribe_replay(replay_key, expires_at))
    }

    /// Accepts a WebSocket connection for first-frame audience-bound v2 authentication.
    ///
    /// Pending unauthenticated sockets are capped separately ([`MAX_PENDING_WEBSOCKETS`], HTTP
    /// 429) and NEVER evict authenticated sockets. Authenticated sockets are capped at
    /// [`MAX_WEBSOCKETS`], evicting the oldest authenticated socket only when an authenticated
    /// connection completes verification.
    pub(super) async fn accept_websocket(&self, request: &Request) -> Result<Response> {
        let now_ms = Date::now().as_millis();
        if request.headers().get(HEADER_DEPLOYMENT_AUTH)?.as_deref() != Some("1") {
            return Response::error("sign in to this server to use it", 403);
        }
        let Some(id_hex) = request.headers().get(HEADER_PENDING_IDENTITY)? else {
            return Response::error("unauthorized", 403);
        };
        let Some(id) = crate::decode_hex_fixed::<32>(&id_hex) else {
            return Response::error("malformed identity", 400);
        };
        let Ok(audience) = crate::server_id(&self.env, request) else {
            return Response::error("malformed subscription audience", 400);
        };
        let session_expires = match request.headers().get(HEADER_SESSION_EXPIRES)? {
            Some(raw) => {
                let Ok(expires) = raw.parse::<u64>() else {
                    return Response::error("malformed session expiry", 400);
                };
                if expires <= now_ms {
                    return Response::error("session expired", 403);
                }
                Some(expires)
            }
            None => None,
        };
        if self.prune_and_count_pending(now_ms) >= MAX_PENDING_WEBSOCKETS {
            return Response::error("too many pending connections", 429);
        }
        // Pull the alarm earlier so idle pending sockets are always closed after MAX_UNAUTH_AGE_MS
        // even if no further events ever arrive on this Identity DO.
        let pending_deadline = now_ms.saturating_add(MAX_UNAUTH_AGE_MS).saturating_add(1);
        self.update_alarm(AlarmUpdate::PullEarlier(pending_deadline))
            .await?;

        let attachment = WsAttachment {
            opened_at: now_ms as f64,
            authenticated: false,
            expected_identity: Some(id.to_vec()),
            expected_audience: Some(audience),
            session_expires,
        };
        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);
        if let Err(e) = pair.server.serialize_attachment(&attachment) {
            reject(&pair.server, WsClose::new(1011, "state error"));
            return Err(e);
        }
        Response::from_websocket(pair.client)
    }

    /// Prunes expired pending sockets and sockets missing state, returning the remaining count of
    /// unauthenticated pending sockets. Never touches or evicts authenticated sockets.
    fn prune_and_count_pending(&self, now_ms: u64) -> usize {
        self.sockets(now_ms)
            .filter(|(_, att)| !att.authenticated)
            .count()
    }

    /// Prunes stale authenticated sockets, expired pending sockets, and sockets missing state,
    /// then caps authenticated sockets at `keep_max` by closing the oldest authenticated sockets
    /// (never closing `preserve`, if supplied).
    fn prune_and_cap_authenticated(
        &self,
        now_ms: u64,
        keep_max: usize,
        preserve: Option<&WebSocket>,
    ) {
        let now_f64 = now_ms as f64;
        let mut authenticated: Vec<(f64, WebSocket)> = Vec::new();
        for (socket, att) in self.sockets(now_ms) {
            if !att.authenticated {
                continue;
            }
            if preserve.is_some_and(|p| p.as_ref() == socket.as_ref()) {
                continue;
            }
            let seen = self.last_seen(&socket, &att);
            if now_f64 - seen > STALE {
                reject(&socket, WsClose::new(1001, "no pings"));
                continue;
            }
            authenticated.push((seen, socket));
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
                reject(&socket, WsClose::new(1008, "too many connections"));
            }
        }
    }

    /// Tell every authenticated subscriber of `notification`, failing closed on missing state and
    /// pruning stale, session-expired, or unauthenticated timed-out sockets.
    pub(super) fn notify(&self, notification: &Notification) {
        let notification = notification.encode_to_vec();
        let now_ms = Date::now().as_millis();
        let now_f64 = now_ms as f64;
        for (socket, att) in self.sockets(now_ms) {
            if !att.authenticated {
                continue;
            }
            if now_f64 - self.last_seen(&socket, &att) > STALE {
                reject(&socket, WsClose::new(1001, "no pings"));
                continue;
            }
            let _ = socket.send_with_bytes(&notification);
        }
    }

    fn last_seen(&self, socket: &WebSocket, att: &WsAttachment) -> f64 {
        let state: &AutoResponseState = self.state.as_raw().unchecked_ref();
        match state.get_websocket_auto_response_timestamp(socket.as_ref()) {
            Ok(Some(pinged)) => pinged.get_time(),
            Ok(None) | Err(_) => att.opened_at,
        }
    }
}

fn verify_pending_auth(
    attachment: &mut WsAttachment,
    message: WebSocketIncomingMessage,
    now_ms: u64,
) -> std::result::Result<(SubscribeRequest, [u8; 32], String), WsClose> {
    let (Some(expected_identity), Some(expected_audience)) = (
        attachment.expected_identity.take(),
        attachment.expected_audience.take(),
    ) else {
        return Err(WsClose::new(1008, "unauthorized"));
    };
    let subscription = decode_auth_frame(message)?;
    let (identity_key, canonical_audience) = verify_first_frame_subscribe(
        &subscription,
        &expected_identity,
        &expected_audience,
        now_ms,
    )?;
    Ok((subscription, identity_key, canonical_audience))
}

/// Reads the socket attachment strictly as [`WsAttachment`] (failing closed if missing or legacy).
fn read_ws_attachment(socket: &WebSocket) -> Option<WsAttachment> {
    socket
        .deserialize_attachment::<WsAttachment>()
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use xeddsa::XEdDSAPrivateKey;

    use super::*;
    use crate::tests::legacy_unbound_subscribe;

    #[test]
    fn first_frame_rejects_unbound_legacy_v1_subscribe_with_4010() {
        let identity = XEdDSAPrivateKey::generate();
        let key = identity.compute_public_key().to_bytes();
        let now = 1_000_000;
        let unbound = legacy_unbound_subscribe(&identity, now);

        assert_eq!(
            verify_first_frame_subscribe(&unbound, &key, "relay.example", now),
            Err(WsClose {
                code: 4010,
                reason: "Legacy v1 notifications deprecated; refresh or upgrade the app",
            })
        );
    }

    #[test]
    fn first_frame_accepts_valid_audience_bound_v2_and_rejects_mismatches() {
        let alice = XEdDSAPrivateKey::generate();
        let bob = XEdDSAPrivateKey::generate();
        let alice_key = alice.compute_public_key().to_bytes();
        let bob_key = bob.compute_public_key().to_bytes();
        let now = 1_000_000;

        let valid =
            SubscribeRequest::sign_for_audience(&alice, "https://Relay.Example", now).unwrap();
        let (verified_key, audience) =
            verify_first_frame_subscribe(&valid, &alice_key, "relay.example", now).unwrap();
        assert_eq!(verified_key, alice_key);
        assert_eq!(audience, "relay.example");

        // Wrong audience -> 1008 invalid subscription.
        assert_eq!(
            verify_first_frame_subscribe(&valid, &alice_key, "other.example", now),
            Err(WsClose::new(1008, "invalid subscription"))
        );

        // Wrong identity -> 1008 identity mismatch.
        assert_eq!(
            verify_first_frame_subscribe(&valid, &bob_key, "relay.example", now),
            Err(WsClose::new(1008, "identity mismatch"))
        );

        // Stale timestamp -> 1008 invalid subscription.
        assert_eq!(
            verify_first_frame_subscribe(
                &valid,
                &alice_key,
                "relay.example",
                now + MAX_CLOCK_SKEW + 1
            ),
            Err(WsClose::new(1008, "invalid subscription"))
        );

        // Tampered audience on a v1 signature -> 1008 invalid subscription (not 4010).
        let mut tampered = legacy_unbound_subscribe(&alice, now);
        tampered.audience = "relay.example".into();
        assert_eq!(
            verify_first_frame_subscribe(&tampered, &alice_key, "relay.example", now),
            Err(WsClose::new(1008, "invalid subscription"))
        );
    }

    #[test]
    fn ws_attachment_tracks_pending_and_session_expiry_and_deadlines() {
        let pending = WsAttachment {
            opened_at: 10_000.0,
            authenticated: false,
            expected_identity: None,
            expected_audience: None,
            session_expires: Some(50_000),
        };
        assert_eq!(pending.close_if_expired(10_000 + MAX_UNAUTH_AGE_MS), None);
        assert_eq!(
            pending.close_if_expired(10_000 + MAX_UNAUTH_AGE_MS + 1),
            Some(WsClose::new(1008, "auth timeout"))
        );
        assert_eq!(
            pending.next_deadline(),
            Some(10_000 + MAX_UNAUTH_AGE_MS + 1)
        );

        // Session expiry takes precedence when earlier than pending timeout.
        let short_session = WsAttachment {
            session_expires: Some(12_000),
            ..pending.clone()
        };
        assert_eq!(short_session.next_deadline(), Some(12_001));
        assert_eq!(
            short_session.close_if_expired(12_000),
            Some(WsClose::new(1008, "session expired"))
        );

        // Authenticated sockets ignore pending timeout and close at cookie expiry.
        let authed = WsAttachment {
            opened_at: 10_000.0,
            authenticated: true,
            expected_identity: None,
            expected_audience: None,
            session_expires: Some(50_000),
        };
        assert_eq!(authed.close_if_expired(49_999), None);
        assert_eq!(
            authed.close_if_expired(50_000),
            Some(WsClose::new(1008, "session expired"))
        );
        assert_eq!(authed.next_deadline(), Some(50_001));

        // Passwordless deployment (`session_expires: None`) never expires by session cookie.
        let no_cookie = WsAttachment {
            session_expires: None,
            ..authed
        };
        assert_eq!(no_cookie.close_if_expired(u64::MAX), None);
        assert_eq!(no_cookie.next_deadline(), None);
    }

    #[test]
    fn subscribe_replay_key_binds_identity_audience_and_timestamp() {
        let id_a = [1u8; 32];
        let id_b = [2u8; 32];
        let k1 = subscribe_replay_key(&id_a, "relay.example", 1_000);
        let k2 = subscribe_replay_key(&id_a, "relay.example", 1_000);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 64);
        assert_ne!(k1, subscribe_replay_key(&id_b, "relay.example", 1_000));
        assert_ne!(k1, subscribe_replay_key(&id_a, "other.example", 1_000));
        assert_ne!(k1, subscribe_replay_key(&id_a, "relay.example", 1_001));
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native_sqlite_tests {
        use super::*;
        use crate::objects::identity::TestIdentity;

        fn record(
            env: &TestIdentity,
            key: &str,
            timestamp: u64,
            now_ms: u64,
        ) -> SubscribeRecordOutcome {
            let store = env.store();
            let pre = store.precheck_subscribe_replay(key, now_ms).unwrap();
            if pre != SubscribeRecordOutcome::Fresh {
                return pre;
            }
            store
                .commit_subscribe_replay(key, subscribe_replay_expiry(timestamp))
                .unwrap()
        }

        #[test]
        fn seen_subscribes_rejects_replays_and_prunes_at_expiry_boundary() {
            let env = TestIdentity::new(50_000);
            let ts = 10_000;
            let expires_at = subscribe_replay_expiry(ts);

            assert!(!env.store().has_seen_subscribes().unwrap());
            assert_eq!(record(&env, "sig-1", ts, ts), SubscribeRecordOutcome::Fresh);
            assert!(env.cache.seen_subscribes_ready.get());
            assert!(env.store().has_seen_subscribes().unwrap());

            // Exact replay before and at `expires_at` is rejected.
            assert_eq!(
                record(&env, "sig-1", ts, ts + 100),
                SubscribeRecordOutcome::Replayed
            );
            assert_eq!(
                record(&env, "sig-1", ts, expires_at),
                SubscribeRecordOutcome::Replayed
            );

            // 1 ms past `expires_at`, precheck prunes the expired row so key becomes Fresh again.
            assert_eq!(
                record(&env, "sig-1", expires_at + 1, expires_at + 1),
                SubscribeRecordOutcome::Fresh
            );

            // Standalone alarm prune deletes only strictly expired entries (`expires_at < now_ms`).
            let next_exp = subscribe_replay_expiry(expires_at + 1);
            env.store().prune_seen_subscribes(next_exp).unwrap();
            let still_there: CountRow = env
                .sql
                .query_one("SELECT count(*) AS count FROM seen_subscribes", vec![])
                .unwrap();
            assert_eq!(still_there.count, 1);

            env.store().prune_seen_subscribes(next_exp + 1).unwrap();
            let gone: CountRow = env
                .sql
                .query_one("SELECT count(*) AS count FROM seen_subscribes", vec![])
                .unwrap();
            assert_eq!(gone.count, 0);
        }

        #[test]
        fn seen_subscribes_enforces_table_cap_and_reclaims_space_on_expiry() {
            let env = TestIdentity::new(50_000);
            let base_ts = 100_000;

            // Fill table to MAX_SEEN_SUBSCRIBES (256) with staggered timestamps.
            for i in 0..MAX_SEEN_SUBSCRIBES {
                let key = format!("key-{i:04}");
                let ts = base_ts + i as u64;
                assert_eq!(
                    record(&env, &key, ts, base_ts),
                    SubscribeRecordOutcome::Fresh
                );
            }

            // Replaying an existing key at cap still classifies as Replayed (checked before cap).
            assert_eq!(
                record(&env, "key-0000", base_ts, base_ts),
                SubscribeRecordOutcome::Replayed
            );

            // A 257th distinct key while all 256 are unexpired fails closed with CapacityExceeded.
            assert_eq!(
                record(&env, "key-overflow", base_ts, base_ts),
                SubscribeRecordOutcome::CapacityExceeded
            );

            // Advance now_ms past key-0000's expiry (base_ts + MAX_CLOCK_SKEW + 1):
            // precheck prunes key-0000, freeing 1 slot so key-overflow succeeds!
            let after_first_expiry = subscribe_replay_expiry(base_ts) + 1;
            assert_eq!(
                record(&env, "key-overflow", after_first_expiry, after_first_expiry),
                SubscribeRecordOutcome::Fresh
            );
            // Table is now back at MAX_SEEN_SUBSCRIBES (256), so another new key hits cap again.
            assert_eq!(
                record(
                    &env,
                    "key-overflow-2",
                    after_first_expiry,
                    after_first_expiry
                ),
                SubscribeRecordOutcome::CapacityExceeded
            );
        }
    }
}
