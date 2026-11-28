//! Pre-authenticated notification WebSockets, 16-byte nonce replay protection, and hibernation.

use prost::Message as _;
use protocol::{MAX_CLOCK_SKEW, notify::Notification};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage::MAX_SAFE_INTEGER;
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use worker::{
    Date, Headers, Request, Response, Result, WebSocket, WebSocketIncomingMessage, WebSocketPair,
    js_sys,
};

use super::{
    AlarmUpdate, IdentityStore, IdentityV2, rows::CountRow, schema::SCHEMA_SEEN_SUBSCRIBES,
};
use crate::objects::sql::{SqlExec, params};

/// Selected WebSocket subprotocol echoed on `101 Switching Protocols`.
pub const WS_SUBPROTOCOL_V2: &str = "e2ee-notify.v2";
/// Internal header set to `"1"` when deployment password auth is satisfied (either `PASSWORD`
/// is not configured, or the request carried a valid sign-in cookie).
pub const HEADER_DEPLOYMENT_AUTH: &str = "x-e2ee-deployment-auth";
/// Internal header carrying the Worker-verified hex-encoded identity key (32 bytes).
pub const HEADER_VERIFIED_IDENTITY: &str = "x-e2ee-verified-identity";
/// Internal header carrying the Worker-verified canonical relay audience.
pub const HEADER_VERIFIED_AUDIENCE: &str = "x-e2ee-verified-audience";
/// Internal header carrying the Worker-verified subscription timestamp (ms since Unix epoch).
pub const HEADER_VERIFIED_TS: &str = "x-e2ee-verified-ts";
/// Internal header carrying the Worker-verified hex-encoded 16-byte subscription nonce.
pub const HEADER_VERIFIED_NONCE: &str = "x-e2ee-verified-nonce";
/// Internal header carrying the sign-in cookie's expiry timestamp (ms since Unix epoch) so
/// hibernated WebSockets are closed once the session expires.
pub const HEADER_SESSION_EXPIRES: &str = "x-e2ee-session-expires";

/// What a client sends to keep its WebSocket open, and the answer, given without waking the
/// object.
pub(super) const PING: &str = "ping";
pub(super) const PONG: &str = "pong";
/// How long, in milliseconds, a socket may go without a ping: its client pings every minute.
const STALE: f64 = 3.0 * 60_000.0;
/// Maximum concurrent authenticated WebSocket connections per IdentityV2 DO.
const MAX_WEBSOCKETS: usize = 16;
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

/// Computes the replay-protection key over `identity || audience || timestamp || nonce` rather
/// than raw signature bytes, preventing signature malleability replays while allowing distinct
/// same-millisecond reconnects carrying fresh 128-bit nonces.
pub(super) fn subscribe_replay_key(
    identity: &[u8; 32],
    audience: &str,
    timestamp: u64,
    nonce: &[u8; 16],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"notify.v2/replay\0");
    hasher.update(identity);
    hasher.update((audience.len() as u32).to_be_bytes());
    hasher.update(audience.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(nonce);
    crate::hex(&hasher.finalize())
}

/// Last millisecond at which a subscription signed at `timestamp` can still verify.
fn subscribe_replay_expiry(timestamp: u64) -> u64 {
    timestamp
        .saturating_add(MAX_CLOCK_SKEW)
        .min(MAX_SAFE_INTEGER)
}

/// Per-WebSocket attachment stored via hibernation API (all accepted sockets are already
/// authenticated before `101 Switching Protocols`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct WsAttachment {
    opened_at: f64,
    #[serde(default)]
    session_expires: Option<u64>,
}

impl WsAttachment {
    fn is_session_expired(&self, now_ms: u64) -> bool {
        self.session_expires.is_some_and(|exp| now_ms >= exp)
    }

    fn close_if_expired(&self, now_ms: u64) -> Option<WsClose> {
        if self.is_session_expired(now_ms) {
            Some(WsClose::new(1008, "session expired"))
        } else {
            None
        }
    }

    fn next_deadline(&self) -> Option<u64> {
        self.session_expires.map(|exp| exp.saturating_add(1))
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

impl IdentityV2 {
    /// Iterates live, unexpired sockets while closing any socket that is missing state or past its
    /// sign-in cookie expiry.
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

    /// Prunes cookie-expired sockets and stale sockets that stopped sending pings.
    pub(super) fn prune_sockets(&self, now_ms: u64) {
        let now_f64 = now_ms as f64;
        for (socket, att) in self.sockets(now_ms) {
            if now_f64 - self.last_seen(&socket, &att) > STALE {
                reject(&socket, WsClose::new(1001, "no pings"));
            }
        }
    }

    /// Earliest alarm deadline across currently open cookie-bounded WebSockets.
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
        let Some(attachment) = read_ws_attachment(&socket) else {
            reject(&socket, WsClose::new(1008, "missing state"));
            return Ok(());
        };
        if let Some(close) = attachment.close_if_expired(now_ms) {
            reject(&socket, close);
            return Ok(());
        }
        // Auto-response answers `"ping"` without waking the DO; close any other frame so an
        // authenticated client cannot repeatedly wake the Durable Object with junk frames.
        if !matches!(&message, WebSocketIncomingMessage::String(text) if text == PING) {
            reject(&socket, WsClose::new(1008, "unexpected message"));
        }
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

    /// Accepts a pre-authenticated WebSocket upgrade after defense-in-depth header checks and
    /// replay-key registration BEFORE `101 Switching Protocols`.
    ///
    /// Echoes **only** `Sec-WebSocket-Protocol: e2ee-notify.v2` (never the credential subprotocol).
    pub(super) async fn accept_websocket(&self, request: &Request) -> Result<Response> {
        let now_ms = Date::now().as_millis();
        if request.headers().get(HEADER_DEPLOYMENT_AUTH)?.as_deref() != Some("1") {
            return Response::error("sign in to this server to use it", 403);
        }
        let Some(id_hex) = request.headers().get(HEADER_VERIFIED_IDENTITY)? else {
            return Response::error("unauthorized", 403);
        };
        let Some(identity_key) = crate::decode_hex_fixed::<32>(&id_hex) else {
            return Response::error("malformed identity", 400);
        };
        let Some(verified_audience) = request.headers().get(HEADER_VERIFIED_AUDIENCE)? else {
            return Response::error("unauthorized", 403);
        };
        let Ok(expected_audience) = crate::server_id(&self.env, request) else {
            return Response::error("malformed subscription audience", 400);
        };
        if verified_audience != expected_audience {
            return Response::error("invalid subscription audience", 403);
        }
        let Some(ts_raw) = request.headers().get(HEADER_VERIFIED_TS)? else {
            return Response::error("unauthorized", 403);
        };
        let Ok(verified_ts) = ts_raw.parse::<u64>() else {
            return Response::error("malformed subscription timestamp", 400);
        };
        if verified_ts > MAX_SAFE_INTEGER || verified_ts.abs_diff(now_ms) > MAX_CLOCK_SKEW {
            return Response::error("stale subscription timestamp", 403);
        }
        let Some(nonce_hex) = request.headers().get(HEADER_VERIFIED_NONCE)? else {
            return Response::error("unauthorized", 403);
        };
        let Some(verified_nonce) = crate::decode_hex_fixed::<16>(&nonce_hex) else {
            return Response::error("malformed subscription nonce", 400);
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

        // Check and record replay key BEFORE returning `101 Switching Protocols`.
        let replay_key = subscribe_replay_key(
            &identity_key,
            &verified_audience,
            verified_ts,
            &verified_nonce,
        );
        match self
            .record_subscribe_replay(&replay_key, verified_ts, now_ms)
            .await?
        {
            SubscribeRecordOutcome::Fresh => {}
            SubscribeRecordOutcome::Replayed => {
                return Response::error("replayed subscription", 403);
            }
            SubscribeRecordOutcome::CapacityExceeded => {
                return Response::error("too many recent subscriptions", 429);
            }
        }

        if let Some(exp) = session_expires {
            self.update_alarm(AlarmUpdate::PullEarlier(exp.saturating_add(1)))
                .await?;
        }

        let attachment = WsAttachment {
            opened_at: now_ms as f64,
            session_expires,
        };
        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);
        if let Err(e) = pair.server.serialize_attachment(&attachment) {
            reject(&pair.server, WsClose::new(1011, "state error"));
            return Err(e);
        }
        self.prune_and_cap_authenticated(now_ms, MAX_WEBSOCKETS, Some(&pair.server));

        let headers = Headers::new();
        headers.set("sec-websocket-protocol", WS_SUBPROTOCOL_V2)?;
        Ok(Response::from_websocket(pair.client)?.with_headers(headers))
    }

    /// Prunes stale sockets and sockets missing state, then caps authenticated sockets at
    /// `keep_max` by closing the oldest sockets (never closing `preserve`, if supplied).
    fn prune_and_cap_authenticated(
        &self,
        now_ms: u64,
        keep_max: usize,
        preserve: Option<&WebSocket>,
    ) {
        let now_f64 = now_ms as f64;
        let mut authenticated: Vec<(f64, WebSocket)> = Vec::new();
        for (socket, att) in self.sockets(now_ms) {
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
    /// pruning stale or session-expired sockets.
    pub(super) fn notify(&self, notification: &Notification) {
        let notification = notification.encode_to_vec();
        let now_ms = Date::now().as_millis();
        let now_f64 = now_ms as f64;
        for (socket, att) in self.sockets(now_ms) {
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

/// Reads the socket attachment strictly as [`WsAttachment`] (failing closed if missing or corrupt).
fn read_ws_attachment(socket: &WebSocket) -> Option<WsAttachment> {
    socket
        .deserialize_attachment::<WsAttachment>()
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_attachment_tracks_session_expiry_and_deadlines() {
        let authed = WsAttachment {
            opened_at: 10_000.0,
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
    fn subscribe_replay_key_binds_identity_audience_timestamp_and_nonce() {
        let id_a = [1u8; 32];
        let id_b = [2u8; 32];
        let nonce_a = [0xAA; 16];
        let nonce_b = [0xBB; 16];
        let k1 = subscribe_replay_key(&id_a, "relay.example", 1_000, &nonce_a);
        let k2 = subscribe_replay_key(&id_a, "relay.example", 1_000, &nonce_a);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 64);
        assert_ne!(
            k1,
            subscribe_replay_key(&id_b, "relay.example", 1_000, &nonce_a)
        );
        assert_ne!(
            k1,
            subscribe_replay_key(&id_a, "other.example", 1_000, &nonce_a)
        );
        assert_ne!(
            k1,
            subscribe_replay_key(&id_a, "relay.example", 1_001, &nonce_a)
        );
        // Same-millisecond reconnect with a distinct 16B nonce produces a distinct replay key!
        assert_ne!(
            k1,
            subscribe_replay_key(&id_a, "relay.example", 1_000, &nonce_b)
        );
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

            for i in 0..MAX_SEEN_SUBSCRIBES {
                let key = format!("key-{i:04}");
                let ts = base_ts + i as u64;
                assert_eq!(
                    record(&env, &key, ts, base_ts),
                    SubscribeRecordOutcome::Fresh
                );
            }

            assert_eq!(
                record(&env, "key-0000", base_ts, base_ts),
                SubscribeRecordOutcome::Replayed
            );
            assert_eq!(
                record(&env, "key-overflow", base_ts, base_ts),
                SubscribeRecordOutcome::CapacityExceeded
            );

            let after_first_expiry = subscribe_replay_expiry(base_ts) + 1;
            assert_eq!(
                record(&env, "key-overflow", after_first_expiry, after_first_expiry),
                SubscribeRecordOutcome::Fresh
            );
        }
    }
}
