//! The object of an identity key: its published bundle and one-time prekeys, optional v2 PQ
//! capability manifest and PQ prekeys, its inbox of initial messages, the queues of messages to
//! it, one per sender, and the WebSockets its client subscribed with, which hear at once of what
//! arrives.
//!
//! Its tables are created ONLY by calls that store data (never on unknown-identity reads or
//! `TakeInitialMessages` / `ListInitialMessages` / `AckInitialMessages`). Additive v2 side tables
//! isolate v1 and v2 handshakes while sharing the underlying mailbox `messages` queue.

use std::{cell::RefCell, collections::HashMap};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use prost::Message as _;
use protocol::{
    MAX_CLOCK_SKEW,
    notify::{Notification, SubscribeRequest},
};
use serde::{Deserialize, Serialize};
use storage::{MAX_QUEUE_BYTES, MAX_QUEUE_MESSAGES, MAX_SAFE_INTEGER};
use worker::{
    Date, DurableObject, Env, Error, Method, Request, Response, Result, SqlStorage,
    SqlStorageValue, State, WebSocket, WebSocketIncomingMessage, WebSocketPair,
    WebSocketRequestResponsePair, console_error, durable_object,
    js_sys::{self, Function, Reflect},
    wasm_bindgen::{JsCast, JsValue},
};

#[cfg(feature = "pq")]
use super::{
    ClaimedBundleWire, InitialMessageV2Wire, ManifestWire, PqCommitmentWire, PqPrekeyWire,
    PqSnapshotWire, PublishV2Outcome, RefillOutcome,
};
use super::{
    AppendOutcome, Content, IdentityCall, InitialMessage, RETRY_ALARM, StoredRow, TakenBundle,
    alarm_at, answer, blob, checked_integer, decode, has_table,
};

/// Internal header carrying the hex-encoded signature of a query-param verified `SubscribeRequest`.
pub const HEADER_SUBSCRIBE_SIG: &str = "x-e2ee-subscribe-sig";
/// Internal header carrying the decimal timestamp of a query-param verified `SubscribeRequest`.
pub const HEADER_SUBSCRIBE_TS: &str = "x-e2ee-subscribe-ts";
/// Internal header carrying the hex-encoded expected identity key for first-frame WS auth.
pub const HEADER_PENDING_IDENTITY: &str = "x-e2ee-pending-identity";

/// What a client sends to keep its WebSocket open, and the answer, given without waking the
/// object.
const PING: &str = "ping";
const PONG: &str = "pong";
/// How long, in milliseconds, a socket may go without a ping: its client pings every minute.
const STALE: f64 = 3.0 * 60_000.0;
/// Maximum concurrent authenticated WebSocket connections per Identity DO.
const MAX_WEBSOCKETS: usize = 16;
/// Maximum concurrent unauthenticated first-frame-auth pending WebSockets per Identity DO.
const MAX_PENDING_WEBSOCKETS: usize = 4;
/// Maximum time (in ms) a first-frame-auth WebSocket may stay unauthenticated.
const MAX_UNAUTH_AGE_MS: f64 = 15_000.0;
/// Maximum bytes accepted in an authentication WebSocket frame.
const MAX_AUTH_FRAME_BYTES: usize = 512;
/// Maximum entries kept in the in-memory subscribe-signature replay cache.
const MAX_SEEN_SUBSCRIBES: usize = 256;
/// Maximum expired R2 objects deleted in a single alarm tick.
const ALARM_R2_BATCH: u64 = 500;
/// How long messages and initial messages are kept, unless the `RETENTION_DAYS` variable says.
pub const DEFAULT_RETENTION_DAYS: u64 = 30;

/// Core v1 tables (unchanged layout for backwards compatibility with existing DO instances).
const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS bundle (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    signed_prekey BLOB NOT NULL,
    signature BLOB NOT NULL,
    timestamp INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    position INTEGER PRIMARY KEY,
    prekey BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS inbox (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    last_take INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS initial_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender BLOB NOT NULL,
    ephemeral_key BLOB NOT NULL,
    signed_prekey BLOB NOT NULL,
    one_time_prekey BLOB,
    header BLOB NOT NULL,
    content BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS queues (
    sender BLOB PRIMARY KEY,
    last_sequence INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    sender BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    header BLOB NOT NULL,
    content BLOB,
    object TEXT,
    size INTEGER NOT NULL,
    initial_message BLOB,
    delivery_hash BLOB,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (sender, sequence),
    CHECK ((content IS NULL) != (object IS NULL))
);
CREATE INDEX IF NOT EXISTS messages_by_age ON messages (created_at);
";

/// Additive v2 side tables and schema version marker. Never relies on SQLite foreign_keys pragma:
/// orphan cleanup is performed explicitly in take/ack/alarm/delete.
const SCHEMA_V2: &str = "
CREATE TABLE IF NOT EXISTS meta (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    schema_version INTEGER NOT NULL
);
INSERT INTO meta (only, schema_version) VALUES (0, 2)
    ON CONFLICT (only) DO UPDATE SET schema_version = excluded.schema_version;
CREATE TABLE IF NOT EXISTS capability_manifest (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    audience TEXT NOT NULL,
    identity_key BLOB NOT NULL,
    manifest_seq INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    pq_enabled INTEGER NOT NULL,
    strict_pq INTEGER NOT NULL,
    pq_ratchet_supported INTEGER NOT NULL,
    offered_suites BLOB NOT NULL,
    signed_prekey BLOB NOT NULL,
    pq_last_resort_commitments BLOB NOT NULL,
    signature BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS pq_last_resort (
    suite INTEGER PRIMARY KEY,
    prekey_id BLOB NOT NULL,
    encapsulation_key BLOB NOT NULL,
    signature BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS pq_one_time_prekeys (
    position INTEGER PRIMARY KEY AUTOINCREMENT,
    suite INTEGER NOT NULL,
    prekey_id BLOB NOT NULL UNIQUE,
    encapsulation_key BLOB NOT NULL,
    signature BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS initial_messages_pq (
    initial_message_id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL,
    pq_suite INTEGER NOT NULL,
    pq_last_resort INTEGER NOT NULL,
    pq_prekey_id BLOB NOT NULL,
    pq_ciphertext BLOB NOT NULL,
    manifest_digest BLOB
);
CREATE TABLE IF NOT EXISTS mailbox_dedup (
    sender BLOB NOT NULL,
    client_message_id BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (sender, client_message_id)
);
CREATE INDEX IF NOT EXISTS mailbox_dedup_by_age ON mailbox_dedup (created_at);
CREATE TABLE IF NOT EXISTS publish_watermarks (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    last_v1_publish_ts INTEGER NOT NULL DEFAULT 0,
    last_refill_ts INTEGER NOT NULL DEFAULT 0
);
";

/// Per-WebSocket attachment stored via hibernation API.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WsAttachment {
    opened_at: f64,
    authenticated: bool,
    #[serde(default)]
    expected_identity: Option<Vec<u8>>,
}

#[durable_object]
pub struct Identity {
    state: State,
    env: Env,
    /// In-memory replay cache of seen `SubscribeRequest` signatures -> timestamp (ms) over the
    /// `2 * MAX_CLOCK_SKEW` window.
    seen_subscribes: RefCell<HashMap<[u8; 64], u64>>,
}

impl DurableObject for Identity {
    fn new(state: State, env: Env) -> Self {
        match WebSocketRequestResponsePair::new(PING, PONG) {
            Ok(pair) => state.set_websocket_auto_response(&pair),
            Err(e) => console_error!("cannot answer pings: {e:?}"),
        }
        Self {
            state,
            env,
            seen_subscribes: RefCell::new(HashMap::new()),
        }
    }

    async fn fetch(&self, mut request: Request) -> Result<Response> {
        match request.method() {
            Method::Get => self.accept_websocket(&request),
            Method::Post => {
                let call = decode(&mut request).await?;
                self.serve(call).await
            }
            _ => Response::error("method not allowed", 405),
        }
    }

    /// Expires messages and initial messages older than `RETENTION_DAYS`, paging R2 deletions so
    /// a large backlog cannot OOM the alarm, and explicitly purging orphaned v2 side-table rows.
    async fn alarm(&self) -> Result<Response> {
        if !self.has_tables()? {
            return Response::empty();
        }
        let before = Date::now().as_millis().saturating_sub(self.retention());
        let before_val = checked_integer(before)?;
        let sql = self.sql();

        // Page R2 object deletions in bounded batches.
        let r2_rows: Vec<ExpiredObjectRow> = sql
            .exec(
                "SELECT sender, sequence, object FROM messages \
                 WHERE created_at < ? AND object IS NOT NULL LIMIT ?",
                vec![before_val.clone(), checked_integer(ALARM_R2_BATCH)?],
            )?
            .to_array()?;
        let had_full_r2_batch = r2_rows.len() as u64 >= ALARM_R2_BATCH;
        let objects: Vec<String> = r2_rows
            .iter()
            .filter_map(|row| row.object.clone())
            .collect();
        if !objects.is_empty() {
            let deleted = match self.env.bucket(crate::BUCKET) {
                Ok(bucket) => crate::store::delete_objects(&bucket, objects).await,
                Err(e) => Err(e),
            };
            if let Err(e) = deleted {
                console_error!("cannot delete the objects of expired messages: {e}");
                let at = Date::now().as_millis().saturating_add(RETRY_ALARM);
                self.state.storage().set_alarm(alarm_at(at)).await?;
                return Response::empty();
            }
            let sql = self.sql();
            for row in &r2_rows {
                sql.exec(
                    "DELETE FROM messages WHERE sender = ? AND sequence = ?",
                    vec![blob(&row.sender), checked_integer(row.sequence)?],
                )?;
            }
        }

        let sql = self.sql();
        // Delete expired inline messages.
        sql.exec(
            "DELETE FROM messages WHERE created_at < ? AND object IS NULL",
            vec![before_val.clone()],
        )?;
        // Delete expired initial messages and explicitly purge orphaned v2 PQ side rows.
        sql.exec(
            "DELETE FROM initial_messages WHERE created_at < ?",
            vec![before_val.clone()],
        )?;
        self.cleanup_orphan_pq_initials()?;
        if has_table(&sql, "mailbox_dedup")? {
            sql.exec(
                "DELETE FROM mailbox_dedup WHERE created_at < ?",
                vec![before_val],
            )?;
        }

        if had_full_r2_batch {
            // More expired R2 objects may remain; reschedule soon.
            let at = Date::now().as_millis().saturating_add(5_000);
            self.state.storage().set_alarm(alarm_at(at)).await?;
        } else {
            self.schedule_expiry(true).await?;
        }
        Response::empty()
    }

    async fn websocket_message(
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
        let Some(expected_identity) = attachment.expected_identity.take() else {
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
                if text.len() > MAX_AUTH_FRAME_BYTES * 2 {
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
        let Ok(identity_key) = subscription.verify(now_ms) else {
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
        if !self.record_subscribe_signature(sig, subscription.timestamp, now_ms) {
            let _ = socket.close(Some(1008), Some("replayed subscription"));
            return Ok(());
        }
        attachment.authenticated = true;
        attachment.opened_at = now_f64;
        if socket.serialize_attachment(&attachment).is_err() {
            let _ = socket.close(Some(1011), Some("state error"));
            return Ok(());
        }
        self.prune_and_cap_authenticated(now_f64, MAX_WEBSOCKETS, Some(&socket));
        Ok(())
    }

    async fn websocket_close(
        &self,
        socket: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        let _ = socket.close(Some(1000), Some("closed"));
        Ok(())
    }

    async fn websocket_error(&self, socket: WebSocket, _error: Error) -> Result<()> {
        let _ = socket.close(Some(1011), Some("error"));
        Ok(())
    }
}

impl Identity {
    fn sql(&self) -> SqlStorage {
        self.state.storage().sql()
    }

    /// Whether core tables exist (used to avoid allocating storage on unknown-identity reads).
    fn has_tables(&self) -> Result<bool> {
        has_table(&self.sql(), "messages")
    }

    /// Creates core v1 tables and additive v2 side tables on first write.
    fn create_tables(&self) -> Result<()> {
        let sql = self.sql();
        sql.exec(SCHEMA_V1, None)?;
        sql.exec(SCHEMA_V2, None)?;
        Ok(())
    }

    /// Ensures additive v2 side tables exist (for upgrading an existing v1 DO in-place on first v2
    /// write).
    #[cfg(feature = "pq")]
    fn ensure_v2_tables(&self) -> Result<()> {
        self.create_tables()
    }

    /// Explicit orphan cleanup for `initial_messages_pq` (no reliance on SQLite foreign_keys).
    fn cleanup_orphan_pq_initials(&self) -> Result<()> {
        let sql = self.sql();
        if has_table(&sql, "initial_messages_pq")? {
            sql.exec(
                "DELETE FROM initial_messages_pq \
                 WHERE NOT EXISTS (SELECT 1 FROM initial_messages WHERE id = initial_messages_pq.initial_message_id)",
                None,
            )?;
        }
        Ok(())
    }

    /// How long what was never delivered is kept, in milliseconds.
    fn retention(&self) -> u64 {
        crate::millis(crate::period(
            &self.env,
            "RETENTION_DAYS",
            DEFAULT_RETENTION_DAYS,
        ))
    }

    /// Records a subscribe signature in DO memory over the `2 * MAX_CLOCK_SKEW` window; returns
    /// `false` if this exact signature was already used.
    fn record_subscribe_signature(&self, sig: [u8; 64], timestamp: u64, now_ms: u64) -> bool {
        let mut seen = self.seen_subscribes.borrow_mut();
        let cutoff = now_ms.saturating_sub(MAX_CLOCK_SKEW.saturating_mul(2));
        seen.retain(|_, ts| *ts >= cutoff);
        if seen.contains_key(&sig) {
            return false;
        }
        if seen.len() >= MAX_SEEN_SUBSCRIBES
            && let Some(oldest_key) = seen
                .iter()
                .min_by_key(|&(_, ts)| *ts)
                .map(|(k, _)| *k)
        {
            seen.remove(&oldest_key);
        }
        seen.insert(sig, timestamp);
        true
    }

    /// Accepts a WebSocket connection after checking replay protection (query-param auth) or
    /// setting up pending first-frame auth.
    ///
    /// Pending unauthenticated sockets are capped separately ([`MAX_PENDING_WEBSOCKETS`], HTTP
    /// 429) and NEVER evict authenticated sockets. Authenticated sockets are capped at
    /// [`MAX_WEBSOCKETS`], evicting the oldest authenticated socket only when an authenticated
    /// connection arrives.
    fn accept_websocket(&self, request: &Request) -> Result<Response> {
        let now_ms = Date::now().as_millis();
        let now_f64 = js_sys::Date::now();

        let attachment = if let (Some(sig_hex), Some(ts_str)) = (
            request.headers().get(HEADER_SUBSCRIBE_SIG)?,
            request.headers().get(HEADER_SUBSCRIBE_TS)?,
        ) {
            let Some(sig) = decode_hex_fixed::<64>(&sig_hex) else {
                return Response::error("malformed subscription", 400);
            };
            let Ok(ts) = ts_str.parse::<u64>() else {
                return Response::error("malformed subscription", 400);
            };
            if !self.record_subscribe_signature(sig, ts, now_ms) {
                return Response::error("replayed subscription", 403);
            }
            self.prune_and_cap_authenticated(now_f64, MAX_WEBSOCKETS - 1, None);
            WsAttachment {
                opened_at: now_f64,
                authenticated: true,
                expected_identity: None,
            }
        } else if let Some(id_hex) = request.headers().get(HEADER_PENDING_IDENTITY)? {
            let Some(id) = decode_hex_fixed::<32>(&id_hex) else {
                return Response::error("malformed identity", 400);
            };
            if self.prune_and_count_pending(now_f64) >= MAX_PENDING_WEBSOCKETS {
                return Response::error("too many pending connections", 429);
            }
            WsAttachment {
                opened_at: now_f64,
                authenticated: false,
                expected_identity: Some(id.to_vec()),
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

    /// Serve `call`. Statements within each handler run with no intervening awaits (except
    /// storage alarm scheduling), preserving atomicity.
    async fn serve(&self, call: IdentityCall) -> Result<Response> {
        match call {
            IdentityCall::Publish {
                signed_prekey,
                signature,
                timestamp,
                one_time_prekeys,
            } => {
                if timestamp > MAX_SAFE_INTEGER {
                    return Err(Error::RustError("timestamp exceeds MAX_SAFE_INTEGER".into()));
                }
                self.create_tables()?;
                answer(self.publish(&signed_prekey, &signature, timestamp, &one_time_prekeys))
            }
            IdentityCall::TakeBundle => answer(self.take_bundle()),
            IdentityCall::AddInitialMessage { message, limit } => {
                self.create_tables()?;
                self.schedule_expiry(false).await?;
                let added = self.add_initial_message(&message, limit);
                if matches!(added, Ok(true)) {
                    self.notify(&Notification::initial_message());
                }
                answer(added)
            }
            IdentityCall::TakeInitialMessages { timestamp } => {
                // Check `has_tables()` FIRST so passwordless calls for arbitrary unknown keys
                // NEVER allocate SQLite tables or insert `inbox.last_take`!
                if timestamp > MAX_SAFE_INTEGER {
                    return Err(Error::RustError("timestamp exceeds MAX_SAFE_INTEGER".into()));
                }
                if !self.has_tables()? {
                    return answer(Ok(Some(Vec::<InitialMessage>::new())));
                }
                answer(self.take_initial_messages(timestamp))
            }
            IdentityCall::Append {
                sender,
                header,
                content,
                size,
                initial_message,
                delivery_hash,
            } => {
                self.create_tables()?;
                self.schedule_expiry(false).await?;
                let appended = self.append(
                    &sender,
                    &header,
                    &content,
                    size,
                    initial_message.as_deref(),
                    delivery_hash.as_deref(),
                    None,
                );
                if matches!(appended, Ok(AppendOutcome::Appended(_)))
                    && let Ok(sender) = <[u8; 32]>::try_from(sender.as_slice())
                {
                    self.notify(&Notification::message_from(&sender));
                }
                answer(appended)
            }
            IdentityCall::Read {
                sender,
                after,
                limit,
                max_size,
            } => answer(self.read(&sender, after, limit, max_size)),
            IdentityCall::DeliveredObjects { sender, hashes } => {
                answer(self.delivered_objects(&sender, &hashes))
            }
            IdentityCall::DeleteDelivered {
                sender,
                hashes,
                objects,
            } => answer(self.delete_delivered(&sender, &hashes, &objects)),
            #[cfg(feature = "pq")]
            IdentityCall::PublishV2 {
                manifest,
                signed_prekey_signature,
                one_time_prekeys,
                pq_last_resort,
                pq_one_time_prekeys,
                timestamp,
            } => {
                self.ensure_v2_tables()?;
                answer(self.publish_v2(
                    &manifest,
                    signed_prekey_signature.as_deref(),
                    &one_time_prekeys,
                    &pq_last_resort,
                    &pq_one_time_prekeys,
                    timestamp,
                ))
            }
            #[cfg(feature = "pq")]
            IdentityCall::RefillPrekeys {
                generation,
                one_time_prekeys,
                pq_one_time_prekeys,
                max_one_time_prekeys,
                max_pq_one_time_prekeys,
                timestamp,
            } => {
                if !self.has_tables()? {
                    return answer(Ok(RefillOutcome::NotFound));
                }
                self.ensure_v2_tables()?;
                answer(self.refill_prekeys(
                    generation,
                    &one_time_prekeys,
                    &pq_one_time_prekeys,
                    max_one_time_prekeys,
                    max_pq_one_time_prekeys,
                    timestamp,
                ))
            }
            #[cfg(feature = "pq")]
            IdentityCall::GetManifest => answer(self.get_manifest()),
            #[cfg(feature = "pq")]
            IdentityCall::ClaimBundle { preferred_suites } => {
                answer(self.claim_bundle(&preferred_suites))
            }
            #[cfg(feature = "pq")]
            IdentityCall::AddInitialMessageV2 { message, limit } => {
                self.ensure_v2_tables()?;
                self.schedule_expiry(false).await?;
                let added = self.add_initial_message_v2(&message, limit);
                if matches!(added, Ok(Some(_))) {
                    self.notify(&Notification::initial_message());
                }
                answer(added)
            }
            #[cfg(feature = "pq")]
            IdentityCall::ListInitialMessages { limit } => {
                answer(self.list_initial_messages(limit))
            }
            #[cfg(feature = "pq")]
            IdentityCall::AckInitialMessages { ids } => answer(self.ack_initial_messages(&ids)),
            #[cfg(feature = "pq")]
            IdentityCall::PqSnapshot => answer(self.pq_snapshot()),
            #[cfg(feature = "pq")]
            IdentityCall::AppendIdempotent {
                sender,
                header,
                content,
                size,
                initial_message,
                delivery_hash,
                client_message_id,
            } => {
                self.ensure_v2_tables()?;
                self.schedule_expiry(false).await?;
                let appended = self.append(
                    &sender,
                    &header,
                    &content,
                    size,
                    initial_message.as_deref(),
                    delivery_hash.as_deref(),
                    client_message_id.as_deref(),
                );
                if matches!(appended, Ok(AppendOutcome::Appended(_)))
                    && let Ok(sender) = <[u8; 32]>::try_from(sender.as_slice())
                {
                    self.notify(&Notification::message_from(&sender));
                }
                answer(appended)
            }
        }
    }

    /// Legacy v1 publish: refused once a v2 `capability_manifest` exists, and guarded by a
    /// persistent `last_v1_publish_ts` watermark that survives v1 bundle removal.
    fn publish(
        &self,
        signed_prekey: &[u8],
        signature: &[u8],
        timestamp: u64,
        one_time_prekeys: &[Vec<u8>],
    ) -> Result<bool> {
        let ts_val = checked_integer(timestamp)?;
        let sql = self.sql();
        if has_table(&sql, "capability_manifest")? {
            let manifests: CountRow = sql
                .exec("SELECT count(*) AS count FROM capability_manifest", None)?
                .one()?;
            if manifests.count > 0 {
                return Ok(false);
            }
        }
        if has_table(&sql, "publish_watermarks")? {
            let wm: Vec<WatermarkRow> = sql
                .exec(
                    "SELECT last_v1_publish_ts, last_refill_ts FROM publish_watermarks",
                    None,
                )?
                .to_array()?;
            if wm.first().is_some_and(|row| row.last_v1_publish_ts >= timestamp) {
                return Ok(false);
            }
        }
        let stored: Vec<TimestampRow> =
            sql.exec("SELECT timestamp FROM bundle", None)?.to_array()?;
        if stored.first().is_some_and(|row| row.timestamp >= timestamp) {
            return Ok(false);
        }
        let mut opk_positions = Vec::with_capacity(one_time_prekeys.len());
        for pos in 0..one_time_prekeys.len() {
            opk_positions.push(checked_integer(pos as u64)?);
        }
        sql.exec("DELETE FROM one_time_prekeys", None)?;
        for (pos_val, prekey) in opk_positions.into_iter().zip(one_time_prekeys.iter()) {
            sql.exec(
                "INSERT INTO one_time_prekeys (position, prekey) VALUES (?, ?)",
                vec![pos_val, blob(prekey)],
            )?;
        }
        sql.exec(
            "INSERT INTO bundle (only, signed_prekey, signature, timestamp) VALUES (0, ?, ?, ?) \
             ON CONFLICT (only) DO UPDATE SET signed_prekey = excluded.signed_prekey, \
             signature = excluded.signature, timestamp = excluded.timestamp",
            vec![blob(signed_prekey), blob(signature), ts_val.clone()],
        )?;
        if has_table(&sql, "publish_watermarks")? {
            sql.exec(
                "INSERT INTO publish_watermarks (only, last_v1_publish_ts, last_refill_ts) \
                 VALUES (0, ?, 0) \
                 ON CONFLICT (only) DO UPDATE SET \
                 last_v1_publish_ts = max(publish_watermarks.last_v1_publish_ts, excluded.last_v1_publish_ts)",
                vec![ts_val],
            )?;
        }
        Ok(true)
    }

    /// Legacy v1 `FetchBundle`: pops at most one classical OPK and NEVER consumes PQOPKs.
    fn take_bundle(&self) -> Result<Option<TakenBundle>> {
        if !self.has_tables()? {
            return Ok(None);
        }
        let sql = self.sql();
        let Some(bundle) = sql
            .exec(
                "SELECT signed_prekey, signature, timestamp FROM bundle",
                None,
            )?
            .to_array::<BundleRow>()?
            .pop()
        else {
            return Ok(None);
        };
        let prekey = sql
            .exec(
                "SELECT position, prekey FROM one_time_prekeys ORDER BY position LIMIT 1",
                None,
            )?
            .to_array::<PrekeyRow>()?
            .pop();
        if let Some(prekey) = &prekey {
            sql.exec(
                "DELETE FROM one_time_prekeys WHERE position = ?",
                vec![checked_integer(prekey.position)?],
            )?;
        }
        Ok(Some(TakenBundle {
            signed_prekey: bundle.signed_prekey,
            signature: bundle.signature,
            timestamp: bundle.timestamp,
            one_time_prekey: prekey.map(|prekey| prekey.prekey),
        }))
    }

    fn add_initial_message(&self, message: &InitialMessage, limit: u64) -> Result<bool> {
        let sql = self.sql();
        let count: CountRow = sql
            .exec("SELECT count(*) AS count FROM initial_messages", None)?
            .one()?;
        if count.count >= limit {
            return Ok(false);
        }
        sql.exec(
            "INSERT INTO initial_messages (sender, ephemeral_key, signed_prekey, \
             one_time_prekey, header, content, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                blob(&message.sender),
                blob(&message.ephemeral_key),
                blob(&message.signed_prekey),
                message
                    .one_time_prekey
                    .as_deref()
                    .map_or(SqlStorageValue::Null, blob),
                blob(&message.header),
                blob(&message.content),
                checked_integer(Date::now().as_millis())?,
            ],
        )?;
        Ok(true)
    }

    /// Legacy v1 `TakeInitialMessages`: ONLY selects and deletes classical v1 initial messages
    /// (`NOT EXISTS` in `initial_messages_pq`), so v1 `Take` can NEVER drain v2 PQ initials.
    fn take_initial_messages(&self, timestamp: u64) -> Result<Option<Vec<InitialMessage>>> {
        let ts_val = checked_integer(timestamp)?;
        let sql = self.sql();
        let last: Vec<LastTakeRow> = sql.exec("SELECT last_take FROM inbox", None)?.to_array()?;
        if last.first().is_some_and(|row| row.last_take >= timestamp) {
            return Ok(None);
        }
        sql.exec(
            "INSERT INTO inbox (only, last_take) VALUES (0, ?) \
             ON CONFLICT (only) DO UPDATE SET last_take = excluded.last_take",
            vec![ts_val],
        )?;
        let has_pq_table = has_table(&sql, "initial_messages_pq")?;
        let messages: Vec<InitialMessageRow> = if has_pq_table {
            sql.exec(
                "SELECT sender, ephemeral_key, signed_prekey, one_time_prekey, header, content \
                 FROM initial_messages \
                 WHERE NOT EXISTS (SELECT 1 FROM initial_messages_pq WHERE initial_message_id = initial_messages.id) \
                 ORDER BY id",
                None,
            )?
            .to_array()?
        } else {
            sql.exec(
                "SELECT sender, ephemeral_key, signed_prekey, one_time_prekey, header, content \
                 FROM initial_messages ORDER BY id",
                None,
            )?
            .to_array()?
        };
        if has_pq_table {
            sql.exec(
                "DELETE FROM initial_messages \
                 WHERE NOT EXISTS (SELECT 1 FROM initial_messages_pq WHERE initial_message_id = initial_messages.id)",
                None,
            )?;
            self.cleanup_orphan_pq_initials()?;
        } else {
            sql.exec("DELETE FROM initial_messages", None)?;
        }
        Ok(Some(
            messages
                .into_iter()
                .map(|row| InitialMessage {
                    sender: row.sender,
                    ephemeral_key: row.ephemeral_key,
                    signed_prekey: row.signed_prekey,
                    one_time_prekey: row.one_time_prekey,
                    header: row.header,
                    content: row.content,
                })
                .collect(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn append(
        &self,
        sender: &[u8],
        header: &[u8],
        content: &Content,
        size: u64,
        initial_message: Option<&[u8]>,
        delivery_hash: Option<&[u8]>,
        client_message_id: Option<&[u8]>,
    ) -> Result<AppendOutcome> {
        let sql = self.sql();
        // Optional idempotent deduplication before quota check or sequence increment.
        #[cfg(feature = "pq")]
        if let Some(cid) = client_message_id
            && has_table(&sql, "mailbox_dedup")?
        {
            let existing: Vec<SequenceRow> = sql
                .exec(
                    "SELECT sequence FROM mailbox_dedup WHERE sender = ? AND client_message_id = ?",
                    vec![blob(sender), blob(cid)],
                )?
                .to_array()?;
            if let Some(row) = existing.first() {
                return Ok(AppendOutcome::Deduplicated(row.sequence));
            }
        }
        #[cfg(not(feature = "pq"))]
        let _ = client_message_id;

        // Enforce per-queue row and total byte caps BEFORE allocating sequence or inserting.
        let incoming_bytes = (header.len() as u64)
            .saturating_add(size)
            .saturating_add(initial_message.map_or(0, |m| m.len() as u64));
        let usage: QueueUsageRow = sql
            .exec(
                "SELECT count(*) AS count, \
                 coalesce(sum(length(header) + size + coalesce(length(initial_message), 0)), 0) AS total_bytes \
                 FROM messages WHERE sender = ?",
                vec![blob(sender)],
            )?
            .one()?;
        if usage.count >= MAX_QUEUE_MESSAGES as u64
            || usage.total_bytes.saturating_add(incoming_bytes) > MAX_QUEUE_BYTES
        {
            return Ok(AppendOutcome::LimitExceeded);
        }

        let now = Date::now().as_millis();
        let queue: SequenceRow = sql
            .exec(
                "INSERT INTO queues (sender, last_sequence) VALUES (?, 1) \
                 ON CONFLICT (sender) DO UPDATE SET last_sequence = last_sequence + 1 \
                 RETURNING last_sequence AS sequence",
                vec![blob(sender)],
            )?
            .one()?;
        let (inline, object) = match content {
            Content::Inline(content) => (blob(content), SqlStorageValue::Null),
            Content::Object(object) => (SqlStorageValue::Null, object.as_str().into()),
        };
        sql.exec(
            "INSERT INTO messages (sender, sequence, header, content, object, size, \
             initial_message, delivery_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                blob(sender),
                checked_integer(queue.sequence)?,
                blob(header),
                inline,
                object,
                checked_integer(size)?,
                initial_message.map_or(SqlStorageValue::Null, blob),
                delivery_hash.map_or(SqlStorageValue::Null, blob),
                checked_integer(now)?,
            ],
        )?;
        if let Some(cid) = client_message_id
            && has_table(&sql, "mailbox_dedup")?
        {
            sql.exec(
                "INSERT OR IGNORE INTO mailbox_dedup (sender, client_message_id, sequence, created_at) \
                 VALUES (?, ?, ?, ?)",
                vec![
                    blob(sender),
                    blob(cid),
                    checked_integer(queue.sequence)?,
                    checked_integer(now)?,
                ],
            )?;
        }
        Ok(AppendOutcome::Appended(queue.sequence))
    }

    /// Reads messages incrementally without materializing all rows before enforcing `max_size`,
    /// counting `header.len() + initial_message.len() + size` accurately.
    fn read(&self, sender: &[u8], after: u64, limit: u32, max_size: u64) -> Result<Vec<StoredRow>> {
        if !self.has_tables()? || limit == 0 || after > MAX_SAFE_INTEGER {
            return Ok(vec![]);
        }
        let sql = self.sql();
        // Step 1: query lightweight integer metadata only (no BLOBs materialized!).
        let metas: Vec<MessageMetaRow> = sql
            .exec(
                "SELECT sequence, length(header) AS header_len, size, \
                 coalesce(length(initial_message), 0) AS init_len \
                 FROM messages WHERE sender = ? AND sequence > ? ORDER BY sequence LIMIT ?",
                vec![
                    blob(sender),
                    checked_integer(after)?,
                    checked_integer(limit.into())?,
                ],
            )?
            .to_array()?;
        if metas.is_empty() {
            return Ok(vec![]);
        }

        let mut total_bytes = 0u64;
        let mut cutoff_sequence = metas[0].sequence;
        for (take_count, meta) in metas.iter().enumerate() {
            let row_bytes = meta
                .header_len
                .saturating_add(meta.init_len)
                .saturating_add(meta.size);
            total_bytes = total_bytes.saturating_add(row_bytes);
            if take_count > 0 && total_bytes > max_size {
                break;
            }
            cutoff_sequence = meta.sequence;
        }

        // Step 2: materialize ONLY the exact rows that fit within the byte budget.
        let rows: Vec<MessageRow> = sql
            .exec(
                "SELECT sequence, header, content, object, size, initial_message FROM messages \
                 WHERE sender = ? AND sequence > ? AND sequence <= ? ORDER BY sequence",
                vec![
                    blob(sender),
                    checked_integer(after)?,
                    checked_integer(cutoff_sequence)?,
                ],
            )?
            .to_array()?;
        let mut page = Vec::with_capacity(rows.len());
        for row in rows {
            let content = match (row.content, row.object) {
                (Some(content), _) => Content::Inline(content),
                (None, Some(object)) => Content::Object(object),
                (None, None) => return Err(Error::RustError("a message without content".into())),
            };
            page.push(StoredRow {
                sequence: row.sequence,
                header: row.header,
                content,
                initial_message: row.initial_message,
            });
        }
        Ok(page)
    }

    fn delivered_objects(&self, sender: &[u8], hashes: &[Vec<u8>]) -> Result<Vec<String>> {
        if !self.has_tables()? {
            return Ok(vec![]);
        }
        let rows: Vec<ObjectRow> = self
            .sql()
            .exec(
                "SELECT object FROM messages WHERE sender = ? AND object IS NOT NULL \
                 AND delivery_hash IN (SELECT unhex(value) FROM json_each(?))",
                vec![blob(sender), hashes_json(hashes).into()],
            )?
            .to_array()?;
        Ok(rows.into_iter().filter_map(|row| row.object).collect())
    }

    fn delete_delivered(
        &self,
        sender: &[u8],
        hashes: &[Vec<u8>],
        objects: &[String],
    ) -> Result<()> {
        if !self.has_tables()? {
            return Ok(());
        }
        let objects =
            serde_json::to_string(objects).map_err(|e| Error::RustError(e.to_string()))?;
        self.sql().exec(
            "DELETE FROM messages WHERE sender = ? \
             AND delivery_hash IN (SELECT unhex(value) FROM json_each(?)) \
             AND (object IS NULL OR object IN (SELECT value FROM json_each(?)))",
            vec![blob(sender), hashes_json(hashes).into(), objects.into()],
        )?;
        let sql = self.sql();
        if has_table(&sql, "mailbox_dedup")? {
            sql.exec(
                "DELETE FROM mailbox_dedup WHERE sender = ? \
                 AND NOT EXISTS (SELECT 1 FROM messages m \
                 WHERE m.sender = mailbox_dedup.sender AND m.sequence = mailbox_dedup.sequence)",
                vec![blob(sender)],
            )?;
        }
        Ok(())
    }

    #[cfg(feature = "pq")]
    fn publish_v2(
        &self,
        manifest: &ManifestWire,
        signed_prekey_signature: Option<&[u8]>,
        one_time_prekeys: &[Vec<u8>],
        pq_last_resort: &[PqPrekeyWire],
        pq_one_time_prekeys: &[PqPrekeyWire],
        timestamp: u64,
    ) -> Result<PublishV2Outcome> {
        // Validate and prepare ALL fallible values BEFORE executing any mutating SQL statement so
        // no partial wipe can occur on a validation or serialization failure.
        let ts_val = checked_integer(timestamp)?;
        let seq_val = checked_integer(manifest.manifest_seq)?;
        let gen_val = checked_integer(manifest.generation)?;
        let issued_val = checked_integer(manifest.issued_at)?;
        let expires_val = checked_integer(manifest.expires_at)?;
        let pq_enabled_val = checked_integer(u64::from(manifest.pq_enabled))?;
        let strict_pq_val = checked_integer(u64::from(manifest.strict_pq))?;
        let pq_ratchet_val = checked_integer(u64::from(manifest.pq_ratchet_supported))?;

        // Check duplicate classical OPKs, duplicate PQ last-resort suites, and duplicate PQ IDs.
        let mut seen_opks = std::collections::HashSet::with_capacity(one_time_prekeys.len());
        let mut opk_positions = Vec::with_capacity(one_time_prekeys.len());
        for (pos, opk) in one_time_prekeys.iter().enumerate() {
            if !seen_opks.insert(opk.as_slice()) {
                return Ok(PublishV2Outcome::DuplicatePrekey);
            }
            opk_positions.push(checked_integer(pos as u64)?);
        }
        let mut seen_lr_suites = std::collections::HashSet::with_capacity(pq_last_resort.len());
        let mut seen_pq =
            std::collections::HashSet::with_capacity(pq_last_resort.len() + pq_one_time_prekeys.len());
        let mut lr_suite_vals = Vec::with_capacity(pq_last_resort.len());
        for lr in pq_last_resort {
            if !seen_lr_suites.insert(lr.suite) || !seen_pq.insert(lr.id.as_slice()) {
                return Ok(PublishV2Outcome::DuplicatePrekey);
            }
            lr_suite_vals.push(checked_integer(lr.suite.into())?);
        }
        let mut pq_opk_suite_vals = Vec::with_capacity(pq_one_time_prekeys.len());
        for opk in pq_one_time_prekeys {
            if !seen_pq.insert(opk.id.as_slice()) {
                return Ok(PublishV2Outcome::DuplicatePrekey);
            }
            pq_opk_suite_vals.push(checked_integer(opk.suite.into())?);
        }

        let commitments_blob = postcard::to_allocvec(&manifest.pq_last_resort)
            .map_err(|e| Error::RustError(e.to_string()))?;

        let sql = self.sql();
        let existing: Vec<ManifestSeqRow> = sql
            .exec("SELECT manifest_seq FROM capability_manifest", None)?
            .to_array()?;
        if existing
            .first()
            .is_some_and(|row| row.manifest_seq >= manifest.manifest_seq)
        {
            return Ok(PublishV2Outcome::StaleSequence);
        }

        // Prepare v1 bundle timestamp before any mutations.
        let next_v1_ts = if !manifest.strict_pq
            && signed_prekey_signature.is_some()
        {
            let prev: Vec<TimestampRow> =
                sql.exec("SELECT timestamp FROM bundle", None)?.to_array()?;
            let next_ts = prev.first().map_or(timestamp, |r| r.timestamp.max(timestamp));
            Some(checked_integer(next_ts)?)
        } else {
            None
        };

        // Update or clear legacy v1 bundle depending on strict_pq and signed_prekey_signature.
        if let (Some(sig), Some(next_ts_val)) = (signed_prekey_signature, next_v1_ts) {
            sql.exec(
                "INSERT INTO bundle (only, signed_prekey, signature, timestamp) VALUES (0, ?, ?, ?) \
                 ON CONFLICT (only) DO UPDATE SET signed_prekey = excluded.signed_prekey, \
                 signature = excluded.signature, timestamp = excluded.timestamp",
                vec![blob(&manifest.signed_prekey), blob(sig), next_ts_val],
            )?;
        } else {
            sql.exec("DELETE FROM bundle", None)?;
        }

        // Replace classical OPKs.
        sql.exec("DELETE FROM one_time_prekeys", None)?;
        for (pos_val, prekey) in opk_positions.into_iter().zip(one_time_prekeys.iter()) {
            sql.exec(
                "INSERT INTO one_time_prekeys (position, prekey) VALUES (?, ?)",
                vec![pos_val, blob(prekey)],
            )?;
        }

        // Replace or clear PQ prekeys depending on affirmative pq_enabled flag.
        sql.exec("DELETE FROM pq_last_resort", None)?;
        sql.exec("DELETE FROM pq_one_time_prekeys", None)?;
        if manifest.pq_enabled {
            for (suite_val, lr) in lr_suite_vals.into_iter().zip(pq_last_resort.iter()) {
                sql.exec(
                    "INSERT INTO pq_last_resort (suite, prekey_id, encapsulation_key, signature) \
                     VALUES (?, ?, ?, ?)",
                    vec![
                        suite_val,
                        blob(&lr.id),
                        blob(&lr.encapsulation_key),
                        blob(&lr.signature),
                    ],
                )?;
            }
            for (suite_val, opk) in pq_opk_suite_vals
                .into_iter()
                .zip(pq_one_time_prekeys.iter())
            {
                sql.exec(
                    "INSERT INTO pq_one_time_prekeys (suite, prekey_id, encapsulation_key, signature) \
                     VALUES (?, ?, ?, ?)",
                    vec![
                        suite_val,
                        blob(&opk.id),
                        blob(&opk.encapsulation_key),
                        blob(&opk.signature),
                    ],
                )?;
            }
        }

        sql.exec(
            "INSERT INTO capability_manifest \
             (only, audience, identity_key, manifest_seq, generation, issued_at, expires_at, \
              pq_enabled, strict_pq, pq_ratchet_supported, offered_suites, signed_prekey, \
              pq_last_resort_commitments, signature) \
             VALUES (0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (only) DO UPDATE SET \
              audience = excluded.audience, identity_key = excluded.identity_key, \
              manifest_seq = excluded.manifest_seq, generation = excluded.generation, \
              issued_at = excluded.issued_at, expires_at = excluded.expires_at, \
              pq_enabled = excluded.pq_enabled, strict_pq = excluded.strict_pq, \
              pq_ratchet_supported = excluded.pq_ratchet_supported, \
              offered_suites = excluded.offered_suites, signed_prekey = excluded.signed_prekey, \
              pq_last_resort_commitments = excluded.pq_last_resort_commitments, \
              signature = excluded.signature",
            vec![
                manifest.audience.as_str().into(),
                blob(&manifest.identity_key),
                seq_val,
                gen_val,
                issued_val,
                expires_val,
                pq_enabled_val,
                strict_pq_val,
                pq_ratchet_val,
                blob(&manifest.offered_suites),
                blob(&manifest.signed_prekey),
                blob(&commitments_blob),
                blob(&manifest.signature),
            ],
        )?;
        sql.exec(
            "INSERT INTO publish_watermarks (only, last_v1_publish_ts, last_refill_ts) \
             VALUES (0, ?, 0) \
             ON CONFLICT (only) DO UPDATE SET \
             last_v1_publish_ts = max(publish_watermarks.last_v1_publish_ts, excluded.last_v1_publish_ts)",
            vec![ts_val],
        )?;
        Ok(PublishV2Outcome::Stored)
    }

    #[cfg(feature = "pq")]
    fn refill_prekeys(
        &self,
        generation: u64,
        one_time_prekeys: &[Vec<u8>],
        pq_one_time_prekeys: &[PqPrekeyWire],
        max_one_time_prekeys: u64,
        max_pq_one_time_prekeys: u64,
        timestamp: u64,
    ) -> Result<RefillOutcome> {
        let _ = checked_integer(generation)?;
        let ts_val = checked_integer(timestamp)?;
        let Some(manifest) = self.get_manifest()? else {
            return Ok(RefillOutcome::NotFound);
        };
        if manifest.generation != generation {
            return Ok(RefillOutcome::StaleGeneration);
        }
        if !pq_one_time_prekeys.is_empty() && !manifest.pq_enabled {
            return Ok(RefillOutcome::StaleGeneration);
        }

        let sql = self.sql();
        let wm: Vec<WatermarkRow> = sql
            .exec(
                "SELECT last_v1_publish_ts, last_refill_ts FROM publish_watermarks",
                None,
            )?
            .to_array()?;
        if wm.first().is_some_and(|row| row.last_refill_ts >= timestamp) {
            return Ok(RefillOutcome::StaleTimestamp);
        }
        let existing_opks: Vec<PrekeyRow> = sql
            .exec(
                "SELECT position, prekey FROM one_time_prekeys ORDER BY position",
                None,
            )?
            .to_array()?;
        if (existing_opks.len() as u64).saturating_add(one_time_prekeys.len() as u64)
            > max_one_time_prekeys
        {
            return Ok(RefillOutcome::LimitExceeded);
        }
        let mut seen_opks: std::collections::HashSet<Vec<u8>> =
            existing_opks.iter().map(|r| r.prekey.clone()).collect();
        for opk in one_time_prekeys {
            if !seen_opks.insert(opk.clone()) {
                return Ok(RefillOutcome::DuplicatePrekey);
            }
        }

        let existing_pq_ids: Vec<IdBlobRow> = sql
            .exec("SELECT prekey_id FROM pq_one_time_prekeys", None)?
            .to_array()?;
        if (existing_pq_ids.len() as u64).saturating_add(pq_one_time_prekeys.len() as u64)
            > max_pq_one_time_prekeys
        {
            return Ok(RefillOutcome::LimitExceeded);
        }
        let mut seen_pq_ids: std::collections::HashSet<Vec<u8>> =
            existing_pq_ids.into_iter().map(|r| r.prekey_id).collect();
        let lr_ids: Vec<IdBlobRow> = sql
            .exec("SELECT prekey_id FROM pq_last_resort", None)?
            .to_array()?;
        for lr in lr_ids {
            seen_pq_ids.insert(lr.prekey_id);
        }
        for pq in pq_one_time_prekeys {
            if !manifest.offered_suites.contains(&pq.suite) {
                return Ok(RefillOutcome::StaleGeneration);
            }
            if !seen_pq_ids.insert(pq.id.clone()) {
                return Ok(RefillOutcome::DuplicatePrekey);
            }
        }

        // Pre-validate all integer bindings before mutating SQLite.
        let start_pos = existing_opks.last().map_or(0, |r| r.position + 1);
        let mut opk_positions = Vec::with_capacity(one_time_prekeys.len());
        for offset in 0..one_time_prekeys.len() {
            opk_positions.push(checked_integer(start_pos.saturating_add(offset as u64))?);
        }
        let mut pq_suite_vals = Vec::with_capacity(pq_one_time_prekeys.len());
        for pq in pq_one_time_prekeys {
            pq_suite_vals.push(checked_integer(pq.suite.into())?);
        }

        // Record monotonic refill watermark and append OPKs/PQOPKs without rotating SPK.
        sql.exec(
            "INSERT INTO publish_watermarks (only, last_v1_publish_ts, last_refill_ts) \
             VALUES (0, 0, ?) \
             ON CONFLICT (only) DO UPDATE SET last_refill_ts = excluded.last_refill_ts",
            vec![ts_val],
        )?;
        for (pos_val, opk) in opk_positions.into_iter().zip(one_time_prekeys.iter()) {
            sql.exec(
                "INSERT INTO one_time_prekeys (position, prekey) VALUES (?, ?)",
                vec![pos_val, blob(opk)],
            )?;
        }
        // Append PQOPKs.
        for (suite_val, pq) in pq_suite_vals.into_iter().zip(pq_one_time_prekeys.iter()) {
            sql.exec(
                "INSERT INTO pq_one_time_prekeys (suite, prekey_id, encapsulation_key, signature) \
                 VALUES (?, ?, ?, ?)",
                vec![
                    suite_val,
                    blob(&pq.id),
                    blob(&pq.encapsulation_key),
                    blob(&pq.signature),
                ],
            )?;
        }

        let classical_count = existing_opks.len() as u64 + one_time_prekeys.len() as u64;
        let pq_counts = self.pq_one_time_counts()?;
        Ok(RefillOutcome::Stored {
            classical_count,
            pq_counts,
        })
    }

    #[cfg(feature = "pq")]
    fn get_manifest(&self) -> Result<Option<ManifestWire>> {
        if !self.has_tables()? {
            return Ok(None);
        }
        let sql = self.sql();
        if !has_table(&sql, "capability_manifest")? {
            return Ok(None);
        }
        let Some(row) = sql
            .exec(
                "SELECT audience, identity_key, manifest_seq, generation, issued_at, expires_at, \
                 pq_enabled, strict_pq, pq_ratchet_supported, offered_suites, signed_prekey, \
                 pq_last_resort_commitments, signature FROM capability_manifest",
                None,
            )?
            .to_array::<ManifestRow>()?
            .pop()
        else {
            return Ok(None);
        };
        let pq_last_resort: Vec<PqCommitmentWire> =
            postcard::from_bytes(&row.pq_last_resort_commitments)
                .map_err(|e| Error::RustError(e.to_string()))?;
        Ok(Some(ManifestWire {
            audience: row.audience,
            identity_key: row.identity_key,
            manifest_seq: row.manifest_seq,
            generation: row.generation,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            pq_enabled: row.pq_enabled != 0,
            strict_pq: row.strict_pq != 0,
            pq_ratchet_supported: row.pq_ratchet_supported != 0,
            offered_suites: row.offered_suites,
            signed_prekey: row.signed_prekey,
            pq_last_resort,
            signature: row.signature,
        }))
    }

    #[cfg(feature = "pq")]
    fn claim_bundle(&self, preferred_suites: &[u8]) -> Result<Option<ClaimedBundleWire>> {
        if !self.has_tables()? {
            return Ok(None);
        }
        let sql = self.sql();
        if let Some(manifest) = self.get_manifest()? {
            let signed_prekey_signature = if manifest.strict_pq {
                None
            } else {
                sql.exec("SELECT signed_prekey, signature, timestamp FROM bundle", None)?
                    .to_array::<BundleRow>()?
                    .pop()
                    .filter(|b| b.signed_prekey == manifest.signed_prekey)
                    .map(|b| b.signature)
            };
            let one_time_prekey = self.pop_classical_opk()?;

            let (pq_last_resort, pq_one_time_prekey) = if manifest.pq_enabled
                && !preferred_suites.is_empty()
                && has_table(&sql, "pq_last_resort")?
            {
                let mut negotiated = None;
                for &suite in preferred_suites {
                    if !manifest.offered_suites.contains(&suite) {
                        continue;
                    }
                    let lr = sql
                        .exec(
                            "SELECT suite, prekey_id, encapsulation_key, signature \
                             FROM pq_last_resort WHERE suite = ?",
                            vec![checked_integer(suite.into())?],
                        )?
                        .to_array::<PqLastResortRow>()?
                        .pop();
                    if let Some(lr) = lr {
                        negotiated = Some((suite, lr));
                        break;
                    }
                }
                if let Some((suite, lr)) = negotiated {
                    let opk = if has_table(&sql, "pq_one_time_prekeys")? {
                        let row = sql
                            .exec(
                                "SELECT position, suite, prekey_id, encapsulation_key, signature \
                                 FROM pq_one_time_prekeys WHERE suite = ? ORDER BY position LIMIT 1",
                                vec![checked_integer(suite.into())?],
                            )?
                            .to_array::<PqOneTimeRow>()?
                            .pop();
                        if let Some(ref r) = row {
                            sql.exec(
                                "DELETE FROM pq_one_time_prekeys WHERE position = ?",
                                vec![checked_integer(r.position)?],
                            )?;
                        }
                        row.map(|r| PqPrekeyWire {
                            suite: r.suite as u8,
                            id: r.prekey_id,
                            encapsulation_key: r.encapsulation_key,
                            signature: r.signature,
                        })
                    } else {
                        None
                    };
                    (
                        Some(PqPrekeyWire {
                            suite: lr.suite as u8,
                            id: lr.prekey_id,
                            encapsulation_key: lr.encapsulation_key,
                            signature: lr.signature,
                        }),
                        opk,
                    )
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            return Ok(Some(ClaimedBundleWire {
                signed_prekey: manifest.signed_prekey.clone(),
                manifest: Some(manifest),
                signed_prekey_signature,
                one_time_prekey,
                pq_last_resort,
                pq_one_time_prekey,
            }));
        }

        // Graceful fallback for classical-only v1 users.
        let Some(bundle) = sql
            .exec(
                "SELECT signed_prekey, signature, timestamp FROM bundle",
                None,
            )?
            .to_array::<BundleRow>()?
            .pop()
        else {
            return Ok(None);
        };
        let one_time_prekey = self.pop_classical_opk()?;
        Ok(Some(ClaimedBundleWire {
            manifest: None,
            signed_prekey: bundle.signed_prekey,
            signed_prekey_signature: Some(bundle.signature),
            one_time_prekey,
            pq_last_resort: None,
            pq_one_time_prekey: None,
        }))
    }

    #[cfg(feature = "pq")]
    fn pop_classical_opk(&self) -> Result<Option<Vec<u8>>> {
        let sql = self.sql();
        let prekey = sql
            .exec(
                "SELECT position, prekey FROM one_time_prekeys ORDER BY position LIMIT 1",
                None,
            )?
            .to_array::<PrekeyRow>()?
            .pop();
        if let Some(ref prekey) = prekey {
            sql.exec(
                "DELETE FROM one_time_prekeys WHERE position = ?",
                vec![checked_integer(prekey.position)?],
            )?;
        }
        Ok(prekey.map(|p| p.prekey))
    }

    #[cfg(feature = "pq")]
    fn add_initial_message_v2(
        &self,
        message: &InitialMessageV2Wire,
        limit: u64,
    ) -> Result<Option<u64>> {
        let sql = self.sql();
        let count: CountRow = sql
            .exec("SELECT count(*) AS count FROM initial_messages", None)?
            .one()?;
        if count.count >= limit {
            return Ok(None);
        }
        let inserted: IdRow = sql
            .exec(
                "INSERT INTO initial_messages (sender, ephemeral_key, signed_prekey, \
                 one_time_prekey, header, content, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
                 RETURNING id",
                vec![
                    blob(&message.sender),
                    blob(&message.ephemeral_key),
                    blob(&message.signed_prekey),
                    message
                        .one_time_prekey
                        .as_deref()
                        .map_or(SqlStorageValue::Null, blob),
                    blob(&message.header),
                    blob(&message.content),
                    checked_integer(Date::now().as_millis())?,
                ],
            )?
            .one()?;
        if message.version != 1 {
            let suite = message.pq_suite.unwrap_or(0);
            let prekey_id = message.pq_prekey_id.as_deref().unwrap_or(&[]);
            let ciphertext = message.pq_ciphertext.as_deref().unwrap_or(&[]);
            sql.exec(
                "INSERT INTO initial_messages_pq \
                 (initial_message_id, version, pq_suite, pq_last_resort, pq_prekey_id, \
                  pq_ciphertext, manifest_digest) VALUES (?, ?, ?, ?, ?, ?, ?)",
                vec![
                    checked_integer(inserted.id)?,
                    checked_integer(u64::from(message.version))?,
                    checked_integer(u64::from(suite))?,
                    checked_integer(u64::from(message.pq_last_resort))?,
                    blob(prekey_id),
                    blob(ciphertext),
                    message
                        .manifest_digest
                        .as_deref()
                        .map_or(SqlStorageValue::Null, blob),
                ],
            )?;
        }
        Ok(Some(inserted.id))
    }

    #[cfg(feature = "pq")]
    fn list_initial_messages(&self, limit: u64) -> Result<Vec<InitialMessageV2Wire>> {
        if !self.has_tables()? || limit == 0 {
            return Ok(vec![]);
        }
        let sql = self.sql();
        let has_pq_table = has_table(&sql, "initial_messages_pq")?;
        if has_pq_table {
            let rows: Vec<InitialMessageJoinedRow> = sql
                .exec(
                    "SELECT m.id, m.sender, m.ephemeral_key, m.signed_prekey, m.one_time_prekey, \
                     m.header, m.content, p.version, p.pq_suite, p.pq_last_resort, \
                     p.pq_prekey_id, p.pq_ciphertext, p.manifest_digest \
                     FROM initial_messages m \
                     LEFT JOIN initial_messages_pq p ON p.initial_message_id = m.id \
                     ORDER BY m.id LIMIT ?",
                    vec![checked_integer(limit)?],
                )?
                .to_array()?;
            Ok(rows
                .into_iter()
                .map(|r| InitialMessageV2Wire {
                    id: r.id,
                    version: r.version.map_or(1, |v| v as u32),
                    sender: r.sender,
                    ephemeral_key: r.ephemeral_key,
                    signed_prekey: r.signed_prekey,
                    one_time_prekey: r.one_time_prekey,
                    header: r.header,
                    content: r.content,
                    pq_suite: r.pq_suite.map(|s| s as u8),
                    pq_last_resort: r.pq_last_resort.unwrap_or(0) != 0,
                    pq_prekey_id: r.pq_prekey_id,
                    pq_ciphertext: r.pq_ciphertext,
                    manifest_digest: r.manifest_digest,
                })
                .collect())
        } else {
            let rows: Vec<InitialMessageWithIdRow> = sql
                .exec(
                    "SELECT id, sender, ephemeral_key, signed_prekey, one_time_prekey, header, content \
                     FROM initial_messages ORDER BY id LIMIT ?",
                    vec![checked_integer(limit)?],
                )?
                .to_array()?;
            Ok(rows
                .into_iter()
                .map(|r| InitialMessageV2Wire {
                    id: r.id,
                    version: 1,
                    sender: r.sender,
                    ephemeral_key: r.ephemeral_key,
                    signed_prekey: r.signed_prekey,
                    one_time_prekey: r.one_time_prekey,
                    header: r.header,
                    content: r.content,
                    pq_suite: None,
                    pq_last_resort: false,
                    pq_prekey_id: None,
                    pq_ciphertext: None,
                    manifest_digest: None,
                })
                .collect())
        }
    }

    #[cfg(feature = "pq")]
    fn ack_initial_messages(&self, ids: &[u64]) -> Result<u64> {
        for &id in ids {
            let _ = checked_integer(id)?;
        }
        if !self.has_tables()? || ids.is_empty() {
            return Ok(0);
        }
        let sql = self.sql();
        let has_pq_table = has_table(&sql, "initial_messages_pq")?;
        let mut deleted = 0u64;
        for &id in ids {
            let id_val = checked_integer(id)?;
            if has_pq_table {
                sql.exec(
                    "DELETE FROM initial_messages_pq WHERE initial_message_id = ?",
                    vec![id_val.clone()],
                )?;
            }
            let res = sql.exec("DELETE FROM initial_messages WHERE id = ?", vec![id_val])?;
            deleted = deleted.saturating_add(res.rows_written() as u64);
        }
        self.cleanup_orphan_pq_initials()?;
        Ok(deleted)
    }

    #[cfg(feature = "pq")]
    fn pq_one_time_counts(&self) -> Result<Vec<(u8, u64)>> {
        let sql = self.sql();
        if !has_table(&sql, "pq_one_time_prekeys")? {
            return Ok(vec![]);
        }
        let rows: Vec<SuiteCountRow> = sql
            .exec(
                "SELECT suite, count(*) AS count FROM pq_one_time_prekeys GROUP BY suite ORDER BY suite",
                None,
            )?
            .to_array()?;
        Ok(rows.into_iter().map(|r| (r.suite as u8, r.count)).collect())
    }

    #[cfg(feature = "pq")]
    fn pq_snapshot(&self) -> Result<PqSnapshotWire> {
        if !self.has_tables()? {
            return Ok(PqSnapshotWire {
                manifest: None,
                classical_one_time_count: 0,
                pq_last_resort_suites: vec![],
                pq_one_time_counts: vec![],
                pending_initial_messages: 0,
            });
        }
        let sql = self.sql();
        let manifest = self.get_manifest()?;
        let classical: CountRow = sql
            .exec("SELECT count(*) AS count FROM one_time_prekeys", None)?
            .one()?;
        let pq_last_resort_suites = if has_table(&sql, "pq_last_resort")? {
            let rows: Vec<SuiteRow> = sql
                .exec("SELECT suite FROM pq_last_resort ORDER BY suite", None)?
                .to_array()?;
            rows.into_iter().map(|r| r.suite as u8).collect()
        } else {
            vec![]
        };
        let pq_one_time_counts = self.pq_one_time_counts()?;
        let pending: CountRow = sql
            .exec("SELECT count(*) AS count FROM initial_messages", None)?
            .one()?;
        Ok(PqSnapshotWire {
            manifest,
            classical_one_time_count: classical.count,
            pq_last_resort_suites,
            pq_one_time_counts,
            pending_initial_messages: pending.count,
        })
    }

    /// Set the alarm for when the oldest of what is kept expires (including `mailbox_dedup` rows
    /// so delivered-message deduplication entries do not grow unboundedly).
    async fn schedule_expiry(&self, again: bool) -> Result<()> {
        let storage = self.state.storage();
        if !again && storage.get_alarm().await?.is_some() {
            return Ok(());
        }
        let sql = self.sql();
        let query = if has_table(&sql, "mailbox_dedup")? {
            "SELECT min(created_at) AS oldest FROM \
             (SELECT created_at FROM messages \
              UNION ALL SELECT created_at FROM initial_messages \
              UNION ALL SELECT created_at FROM mailbox_dedup)"
        } else {
            "SELECT min(created_at) AS oldest FROM \
             (SELECT created_at FROM messages UNION ALL SELECT created_at FROM initial_messages)"
        };
        let oldest: OldestRow = sql.exec(query, None)?.one()?;
        let oldest = match (oldest.oldest, again) {
            (Some(oldest), _) => oldest,
            (None, false) => Date::now().as_millis(),
            (None, true) => return Ok(()),
        };
        storage
            .set_alarm(alarm_at(oldest.saturating_add(self.retention())))
            .await
    }

    /// Tell every authenticated subscriber of `notification`, failing closed on missing state and
    /// pruning stale or unauthenticated timed-out sockets.
    fn notify(&self, notification: &Notification) {
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
        let state: &JsValue = self.state.as_raw().as_ref();
        let pinged = Reflect::get(state, &"getWebSocketAutoResponseTimestamp".into())
            .ok()?
            .dyn_into::<Function>()
            .ok()?
            .call1(state, socket.as_ref())
            .ok()?;
        match pinged.dyn_into::<js_sys::Date>() {
            Ok(pinged) => Some(pinged.get_time()),
            Err(_) => read_ws_attachment(socket).map(|a| a.opened_at),
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
        })
}

fn decode_hex_fixed<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let (chunks, remainder) = hex.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    for (i, chunk) in chunks.iter().enumerate() {
        let s = core::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// `hashes` as a JSON array of hex strings, which need no escaping, for `json_each`.
fn hashes_json(hashes: &[Vec<u8>]) -> String {
    let quoted: Vec<_> = hashes
        .iter()
        .map(|hash| format!("\"{}\"", crate::hex(hash)))
        .collect();
    format!("[{}]", quoted.join(","))
}

#[derive(Deserialize)]
struct TimestampRow {
    timestamp: u64,
}

#[derive(Deserialize)]
struct WatermarkRow {
    last_v1_publish_ts: u64,
    #[cfg_attr(not(feature = "pq"), allow(dead_code))]
    last_refill_ts: u64,
}

#[derive(Deserialize)]
struct BundleRow {
    #[serde(with = "serde_bytes")]
    signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    timestamp: u64,
}

#[derive(Deserialize)]
struct PrekeyRow {
    position: u64,
    #[serde(with = "serde_bytes")]
    prekey: Vec<u8>,
}

#[derive(Deserialize)]
struct CountRow {
    count: u64,
}

#[derive(Deserialize)]
struct QueueUsageRow {
    count: u64,
    total_bytes: u64,
}

#[derive(Deserialize)]
struct LastTakeRow {
    last_take: u64,
}

#[derive(Deserialize)]
struct InitialMessageRow {
    #[serde(with = "serde_bytes")]
    sender: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ephemeral_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    one_time_prekey: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    content: Vec<u8>,
}

#[derive(Deserialize)]
struct SequenceRow {
    sequence: u64,
}

#[derive(Deserialize)]
struct MessageMetaRow {
    sequence: u64,
    header_len: u64,
    size: u64,
    init_len: u64,
}

#[derive(Deserialize)]
struct MessageRow {
    sequence: u64,
    #[serde(with = "serde_bytes")]
    header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    content: Option<Vec<u8>>,
    object: Option<String>,
    #[allow(dead_code)]
    size: u64,
    #[serde(with = "serde_bytes")]
    initial_message: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct ObjectRow {
    object: Option<String>,
}

#[derive(Deserialize)]
struct ExpiredObjectRow {
    #[serde(with = "serde_bytes")]
    sender: Vec<u8>,
    sequence: u64,
    object: Option<String>,
}

#[derive(Deserialize)]
struct OldestRow {
    oldest: Option<u64>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
struct ManifestSeqRow {
    manifest_seq: u64,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
struct ManifestRow {
    audience: String,
    #[serde(with = "serde_bytes")]
    identity_key: Vec<u8>,
    manifest_seq: u64,
    generation: u64,
    issued_at: u64,
    expires_at: u64,
    pq_enabled: u64,
    strict_pq: u64,
    pq_ratchet_supported: u64,
    #[serde(with = "serde_bytes")]
    offered_suites: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pq_last_resort_commitments: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
struct IdBlobRow {
    #[serde(with = "serde_bytes")]
    prekey_id: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
struct PqLastResortRow {
    suite: u64,
    #[serde(with = "serde_bytes")]
    prekey_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    encapsulation_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
struct PqOneTimeRow {
    position: u64,
    suite: u64,
    #[serde(with = "serde_bytes")]
    prekey_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    encapsulation_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
struct IdRow {
    id: u64,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
struct InitialMessageWithIdRow {
    id: u64,
    #[serde(with = "serde_bytes")]
    sender: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ephemeral_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    one_time_prekey: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    content: Vec<u8>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
struct InitialMessageJoinedRow {
    id: u64,
    #[serde(with = "serde_bytes")]
    sender: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ephemeral_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signed_prekey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    one_time_prekey: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    content: Vec<u8>,
    version: Option<u64>,
    pq_suite: Option<u64>,
    pq_last_resort: Option<u64>,
    #[serde(with = "serde_bytes")]
    pq_prekey_id: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pq_ciphertext: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    manifest_digest: Option<Vec<u8>>,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
struct SuiteCountRow {
    suite: u64,
    count: u64,
}

#[cfg(feature = "pq")]
#[derive(Deserialize)]
struct SuiteRow {
    suite: u64,
}
