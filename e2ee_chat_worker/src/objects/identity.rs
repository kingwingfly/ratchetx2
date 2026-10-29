//! The object of an identity key: its published bundle and one-time prekeys, its inbox of
//! initial messages, the queues of messages to it, one per sender, and the WebSockets its client
//! subscribed with, which hear at once of what arrives.
//!
//! Its sockets cost nothing while it sleeps, as the hibernation API holds them meanwhile and
//! answers their pings. A client keeps one open only while its user is on the page, and closes it
//! on leaving; one that dies without closing, e.g. as its device sleeps, is closed when the object
//! next notifies. An alarm deletes what was never delivered, or taken, once `RETENTION_DAYS` old.
//!
//! Its tables are created by the first call that keeps something: publishing, an initial message,
//! a message, or a take of the inbox, signed by the identity, whose timestamp the next take must
//! pass. Until then, reads, which anyone may make, find nothing, and keep nothing.

use prost::Message as _;
use protocol::notify::Notification;
use serde::Deserialize;
use worker::{
    Date, DurableObject, Env, Error, Method, Request, Response, Result, SqlStorage,
    SqlStorageValue, State, WebSocket, WebSocketIncomingMessage, WebSocketPair,
    WebSocketRequestResponsePair, console_error, durable_object,
    js_sys::{self, Function, Reflect},
    wasm_bindgen::{JsCast, JsValue},
};

use super::{
    Content, IdentityCall, InitialMessage, RETRY_ALARM, StoredRow, TakenBundle, alarm_at, answer,
    blob, decode, has_table, integer,
};

/// What a client sends to keep its WebSocket open, and the answer, given without waking the
/// object.
const PING: &str = "ping";
const PONG: &str = "pong";
/// How long, in milliseconds, a socket may go without a ping: its client pings every minute.
const STALE: f64 = 3.0 * 60_000.0;
/// How long messages and initial messages are kept, unless the `RETENTION_DAYS` variable says.
pub const DEFAULT_RETENTION_DAYS: u64 = 30;

/// Its tables. The bundle and the inbox's last take are single rows.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS bundle (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    signed_prekey BLOB NOT NULL,
    signature BLOB NOT NULL,
    -- The publish request's timestamp; the next publish must be newer.
    timestamp INTEGER NOT NULL
);
-- The one-time prekeys nobody took yet, taken in order of position.
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    position INTEGER PRIMARY KEY,
    prekey BLOB NOT NULL
);
-- The timestamp of the inbox's last take; the next take must be newer.
CREATE TABLE IF NOT EXISTS inbox (
    only INTEGER PRIMARY KEY CHECK (only = 0),
    last_take INTEGER NOT NULL
);
-- Initial messages waiting in the inbox, oldest first by id.
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
-- The last sequence number of each queue, so that numbers are not reused once messages go.
CREATE TABLE IF NOT EXISTS queues (
    sender BLOB PRIMARY KEY,
    last_sequence INTEGER NOT NULL
);
-- The messages of each queue, until delivered. A large content is in R2, named by `object`.
CREATE TABLE IF NOT EXISTS messages (
    sender BLOB NOT NULL,
    sequence INTEGER NOT NULL,
    header BLOB NOT NULL,
    content BLOB,
    object TEXT,
    -- The content's length, wherever it is.
    size INTEGER NOT NULL,
    -- The initial message its sender sent with it, while its session was unanswered.
    initial_message BLOB,
    -- SHA-256 of its delivery token, which its recipient gives back once it has it.
    delivery_hash BLOB,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (sender, sequence),
    CHECK ((content IS NULL) != (object IS NULL))
);
CREATE INDEX IF NOT EXISTS messages_by_age ON messages (created_at);
";

#[durable_object]
pub struct Identity {
    state: State,
    env: Env,
}

impl DurableObject for Identity {
    fn new(state: State, env: Env) -> Self {
        match WebSocketRequestResponsePair::new(PING, PONG) {
            Ok(pair) => state.set_websocket_auto_response(&pair),
            Err(e) => console_error!("cannot answer pings: {e:?}"),
        }
        Self { state, env }
    }

    async fn fetch(&self, mut request: Request) -> Result<Response> {
        match request.method() {
            // A subscription, which the Worker verified. The hibernation API keeps the socket
            // open while the object sleeps, so an idle one costs nothing.
            Method::Get => {
                let pair = WebSocketPair::new()?;
                self.state.accept_web_socket(&pair.server);
                // When it opened, which stands for its last ping until its first.
                let _ = pair.server.serialize_attachment(js_sys::Date::now());
                Response::from_websocket(pair.client)
            }
            Method::Post => {
                let call = decode(&mut request).await?;
                self.serve(call).await
            }
            _ => Response::error("method not allowed", 405),
        }
    }

    /// What was never delivered, or taken, goes once `RETENTION_DAYS` old, with its R2
    /// objects: the objects first, so that a failure leaves rows, which the alarm deletes when it
    /// tries again later, rather than objects no row names.
    async fn alarm(&self) -> Result<Response> {
        if !self.has_tables()? {
            return Response::empty();
        }
        let before = Date::now().as_millis().saturating_sub(self.retention());
        let sql = self.sql();
        let objects: Vec<ObjectRow> = sql
            .exec(
                "SELECT object FROM messages WHERE created_at < ? AND object IS NOT NULL",
                vec![integer(before)],
            )?
            .to_array()?;
        let objects: Vec<_> = objects.into_iter().filter_map(|row| row.object).collect();
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
        sql.exec(
            "DELETE FROM messages WHERE created_at < ?",
            vec![integer(before)],
        )?;
        sql.exec(
            "DELETE FROM initial_messages WHERE created_at < ?",
            vec![integer(before)],
        )?;
        self.schedule_expiry(true).await?;
        Response::empty()
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

impl Identity {
    fn sql(&self) -> SqlStorage {
        self.state.storage().sql()
    }

    /// Whether its tables are there, see the module's docs.
    fn has_tables(&self) -> Result<bool> {
        has_table(&self.sql(), "messages")
    }

    /// Its tables, for a call that keeps something.
    fn create_tables(&self) -> Result<()> {
        self.sql().exec(SCHEMA, None)?;
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

    /// Serve `call`. Its statements run with no await between them, but the storage's own, which
    /// let nothing else in meanwhile, so that it is atomic.
    async fn serve(&self, call: IdentityCall) -> Result<Response> {
        match call {
            IdentityCall::Publish {
                signed_prekey,
                signature,
                timestamp,
                one_time_prekeys,
            } => {
                self.create_tables()?;
                answer(self.publish(&signed_prekey, &signature, timestamp, &one_time_prekeys))
            }
            IdentityCall::TakeBundle => answer(self.take_bundle()),
            IdentityCall::AddInitialMessage { message, limit } => {
                self.create_tables()?;
                // Before it is kept, so that failing to set it keeps nothing, rather than what
                // never expires.
                self.schedule_expiry(false).await?;
                let added = self.add_initial_message(&message, limit);
                if matches!(added, Ok(true)) {
                    self.notify(&Notification::initial_message());
                }
                answer(added)
            }
            IdentityCall::TakeInitialMessages { timestamp } => {
                self.create_tables()?;
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
                // As for an initial message.
                self.schedule_expiry(false).await?;
                let appended = self.append(
                    &sender,
                    &header,
                    &content,
                    size,
                    initial_message.as_deref(),
                    delivery_hash.as_deref(),
                );
                if appended.is_ok()
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
        }
    }

    fn publish(
        &self,
        signed_prekey: &[u8],
        signature: &[u8],
        timestamp: u64,
        one_time_prekeys: &[Vec<u8>],
    ) -> Result<bool> {
        let sql = self.sql();
        let stored: Vec<TimestampRow> =
            sql.exec("SELECT timestamp FROM bundle", None)?.to_array()?;
        if stored.first().is_some_and(|row| row.timestamp >= timestamp) {
            return Ok(false);
        }
        sql.exec("DELETE FROM one_time_prekeys", None)?;
        for (position, prekey) in one_time_prekeys.iter().enumerate() {
            sql.exec(
                "INSERT INTO one_time_prekeys (position, prekey) VALUES (?, ?)",
                vec![integer(position as u64), blob(prekey)],
            )?;
        }
        sql.exec(
            "INSERT INTO bundle (only, signed_prekey, signature, timestamp) VALUES (0, ?, ?, ?) \
             ON CONFLICT (only) DO UPDATE SET signed_prekey = excluded.signed_prekey, \
             signature = excluded.signature, timestamp = excluded.timestamp",
            vec![blob(signed_prekey), blob(signature), integer(timestamp)],
        )?;
        Ok(true)
    }

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
                vec![integer(prekey.position)],
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
                integer(Date::now().as_millis()),
            ],
        )?;
        Ok(true)
    }

    fn take_initial_messages(&self, timestamp: u64) -> Result<Option<Vec<InitialMessage>>> {
        let sql = self.sql();
        let last: Vec<LastTakeRow> = sql.exec("SELECT last_take FROM inbox", None)?.to_array()?;
        if last.first().is_some_and(|row| row.last_take >= timestamp) {
            return Ok(None);
        }
        sql.exec(
            "INSERT INTO inbox (only, last_take) VALUES (0, ?) \
             ON CONFLICT (only) DO UPDATE SET last_take = excluded.last_take",
            vec![integer(timestamp)],
        )?;
        let messages: Vec<InitialMessageRow> = sql
            .exec(
                "SELECT sender, ephemeral_key, signed_prekey, one_time_prekey, header, content \
                 FROM initial_messages ORDER BY id",
                None,
            )?
            .to_array()?;
        sql.exec("DELETE FROM initial_messages", None)?;
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

    fn append(
        &self,
        sender: &[u8],
        header: &[u8],
        content: &Content,
        size: u64,
        initial_message: Option<&[u8]>,
        delivery_hash: Option<&[u8]>,
    ) -> Result<u64> {
        let sql = self.sql();
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
                integer(queue.sequence),
                blob(header),
                inline,
                object,
                integer(size),
                initial_message.map_or(SqlStorageValue::Null, blob),
                delivery_hash.map_or(SqlStorageValue::Null, blob),
                integer(Date::now().as_millis()),
            ],
        )?;
        Ok(queue.sequence)
    }

    fn read(&self, sender: &[u8], after: u64, limit: u32, max_size: u64) -> Result<Vec<StoredRow>> {
        if !self.has_tables()? {
            return Ok(vec![]);
        }
        let rows: Vec<MessageRow> = self
            .sql()
            .exec(
                "SELECT sequence, header, content, object, size, initial_message FROM messages \
                 WHERE sender = ? AND sequence > ? ORDER BY sequence LIMIT ?",
                vec![blob(sender), integer(after), integer(limit.into())],
            )?
            .to_array()?;
        // At most `max_size` bytes, headers and contents, but for the first, which always comes.
        let mut size = 0u64;
        let mut page = vec![];
        for row in rows {
            size = size.saturating_add(row.header.len() as u64 + row.size);
            if !page.is_empty() && size > max_size {
                break;
            }
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

    /// Delete the delivered messages: those without objects, and those whose objects went, of
    /// `objects`, which the Worker read before. A copy pushed again since, whose object it did
    /// not read, stays, and goes once its recipient gives its token again, or expires.
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
        Ok(())
    }

    /// Set the alarm for when the oldest of what is kept expires, unless one is set already,
    /// which it is from the first thing kept on: before something is kept, it counts as kept
    /// now. If `again`, after an alarm, for the oldest of what is left, if any.
    async fn schedule_expiry(&self, again: bool) -> Result<()> {
        let storage = self.state.storage();
        if !again && storage.get_alarm().await?.is_some() {
            return Ok(());
        }
        let oldest: OldestRow = self
            .sql()
            .exec(
                "SELECT min(created_at) AS oldest FROM \
                 (SELECT created_at FROM messages UNION ALL SELECT created_at FROM initial_messages)",
                None,
            )?
            .one()?;
        let oldest = match (oldest.oldest, again) {
            (Some(oldest), _) => oldest,
            (None, false) => Date::now().as_millis(),
            (None, true) => return Ok(()),
        };
        storage
            .set_alarm(alarm_at(oldest.saturating_add(self.retention())))
            .await
    }

    /// Tell every subscriber of `notification`.
    fn notify(&self, notification: &Notification) {
        let notification = notification.encode_to_vec();
        let now = js_sys::Date::now();
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
    }

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
        match pinged.dyn_into::<js_sys::Date>() {
            Ok(pinged) => Some(pinged.get_time()),
            Err(_) => socket.deserialize_attachment::<f64>().ok().flatten(),
        }
    }
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
struct MessageRow {
    sequence: u64,
    #[serde(with = "serde_bytes")]
    header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    content: Option<Vec<u8>>,
    object: Option<String>,
    size: u64,
    #[serde(with = "serde_bytes")]
    initial_message: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct ObjectRow {
    object: Option<String>,
}

#[derive(Deserialize)]
struct OldestRow {
    oldest: Option<u64>,
}
