//! The object of an identity key: its published bundle and one-time prekeys, optional v2 PQ
//! capability manifest and PQ prekeys, its inbox of initial messages, the queues of messages to
//! it, one per sender, and the WebSockets its client subscribed with, which hear at once of what
//! arrives.
//!
//! Reads of an unknown identity leave the core tables unallocated. On a password-protected server,
//! a cookie-free signed query subscription can create its replay table only if the core tables
//! already exist. V2 handshakes use side tables and share the mailbox message queues with v1.

mod handshake;
mod mailbox;
mod rows;
mod schema;
mod ws;

use protocol::notify::Notification;
use std::cell::Cell;
use storage::MAX_SAFE_INTEGER;
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use worker::{
    Date, DurableObject, Env, Error, Method, Request, Response, Result, SqlStorage, State,
    WebSocket, WebSocketIncomingMessage, WebSocketRequestResponsePair, console_error,
    durable_object,
};

#[cfg(feature = "pq")]
use super::RefillOutcome;
use super::{
    AppendOutcome, IdentityCall, InitialMessage, RETRY_ALARM, alarm_at, answer, blob,
    checked_integer, decode, has_table,
};
use rows::{ExpiredObjectRow, OldestRow};
pub use ws::{
    HEADER_DEPLOYMENT_AUTH, HEADER_PENDING_IDENTITY, HEADER_SUBSCRIBE_AUDIENCE,
    HEADER_SUBSCRIBE_SIG, HEADER_SUBSCRIBE_TS,
};

/// Maximum expired R2 objects deleted in a single alarm tick.
const ALARM_R2_BATCH: u64 = 500;
/// How long messages and initial messages are kept, unless the `RETENTION_DAYS` variable says.
pub const DEFAULT_RETENTION_DAYS: u64 = 30;

enum PendingExpiry {
    Message(u64),
    R2Retry(u64),
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = worker::worker_sys::DurableObjectStorage, js_name = DurableObjectStorage)]
    type TransactionalStorage;

    #[wasm_bindgen(method, catch, js_name = transactionSync)]
    fn storage_transaction_sync(
        this: &TransactionalStorage,
        callback: &mut dyn FnMut() -> std::result::Result<(), JsValue>,
    ) -> std::result::Result<JsValue, JsValue>;
}

#[durable_object]
pub struct Identity {
    state: State,
    env: Env,
    dedup_schema_ready: Cell<bool>,
}

impl DurableObject for Identity {
    fn new(state: State, env: Env) -> Self {
        match WebSocketRequestResponsePair::new(ws::PING, ws::PONG) {
            Ok(pair) => state.set_websocket_auto_response(&pair),
            Err(e) => console_error!("cannot answer pings: {e:?}"),
        }
        Self {
            state,
            env,
            dedup_schema_ready: Cell::new(false),
        }
    }

    async fn fetch(&self, mut request: Request) -> Result<Response> {
        match request.method() {
            Method::Get => self.accept_websocket(&request).await,
            Method::Post => {
                let call = decode(&mut request).await?;
                self.serve(call).await
            }
            _ => Response::error("method not allowed", 405),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        let sql = self.sql();
        let has_core = self.has_tables()?;
        let has_seen = has_table(&sql, "seen_subscribes")?;
        if !has_core && !has_seen {
            return Response::empty();
        }
        let now = Date::now().as_millis();
        if has_seen {
            sql.exec(
                "DELETE FROM seen_subscribes WHERE expires_at < ?",
                vec![checked_integer(now)?],
            )?;
        }
        if has_table(&sql, "mailbox_dedup")? {
            self.ensure_mailbox_dedup_schema(&sql)?;
            sql.exec(
                "DELETE FROM mailbox_dedup WHERE expires_at <= ?",
                vec![checked_integer(now)?],
            )?;
        }
        if has_core && let Some(delay) = self.expire_messages(now).await? {
            let at = Date::now().as_millis().saturating_add(delay);
            self.set_expiry_alarm(true, Some(PendingExpiry::R2Retry(at)))
                .await?;
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
        self.handle_websocket_message(socket, message).await
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

    fn transaction_sync<T>(&self, f: impl FnOnce(&SqlStorage) -> Result<T>) -> Result<T> {
        let storage = self.state.storage();
        let sql = storage.sql();
        let raw: &TransactionalStorage = storage.as_raw().unchecked_ref();
        let mut output = None;
        let mut operation = Some(f);
        let transaction = raw.storage_transaction_sync(&mut || {
            let run = operation
                .take()
                .ok_or_else(|| JsValue::from_str("transaction already ran"))?;
            let result = run(&sql);
            let failed = result.is_err();
            output = Some(result);
            if failed {
                // Throw across the JS boundary so SQLite rolls back every statement.
                return Err(JsValue::from_str("transaction rollback"));
            }
            Ok(())
        });
        match (transaction, output) {
            (_, Some(Err(error))) => Err(error),
            (Err(error), _) => Err(error.into()),
            (Ok(_), Some(Ok(value))) => Ok(value),
            (Ok(_), None) => Err(Error::RustError("transaction callback did not run".into())),
        }
    }

    /// How long what was never delivered is kept, in milliseconds.
    fn retention(&self) -> u64 {
        crate::millis(crate::period(
            &self.env,
            "RETENTION_DAYS",
            DEFAULT_RETENTION_DAYS,
        ))
    }

    /// Delete expired inbox rows and one batch of R2 objects. A delay requests another batch
    /// or a retry after an R2 failure.
    async fn expire_messages(&self, now: u64) -> Result<Option<u64>> {
        let sql = self.sql();
        let before = checked_integer(now.saturating_sub(self.retention()))?;
        sql.exec(
            "DELETE FROM messages WHERE created_at < ? AND object IS NULL",
            vec![before.clone()],
        )?;
        sql.exec(
            "DELETE FROM initial_messages WHERE created_at < ?",
            vec![before.clone()],
        )?;
        self.cleanup_orphan_pq_initials()?;

        let rows: Vec<ExpiredObjectRow> = sql
            .exec(
                "SELECT sender, sequence, object FROM messages \
             WHERE created_at < ? AND object IS NOT NULL LIMIT ?",
                vec![before, checked_integer(ALARM_R2_BATCH)?],
            )?
            .to_array()?;
        if rows.is_empty() {
            return Ok(None);
        }
        let objects = rows.iter().map(|row| row.object.clone()).collect();
        let deleted = match self.env.bucket(crate::BUCKET) {
            Ok(bucket) => crate::store::delete_objects(&bucket, objects).await,
            Err(e) => Err(e),
        };
        if let Err(e) = deleted {
            console_error!("cannot delete the objects of expired messages: {e}");
            return Ok(Some(RETRY_ALARM));
        }
        for row in &rows {
            sql.exec(
                "DELETE FROM messages WHERE sender = ? AND sequence = ?",
                vec![blob(&row.sender), checked_integer(row.sequence)?],
            )?;
        }
        Ok((rows.len() as u64 >= ALARM_R2_BATCH).then_some(5_000))
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
                    return Err(Error::RustError(
                        "timestamp exceeds MAX_SAFE_INTEGER".into(),
                    ));
                }
                self.create_tables()?;
                answer(self.publish(&signed_prekey, &signature, timestamp, &one_time_prekeys))
            }
            IdentityCall::TakeBundle => answer(self.take_bundle()),
            IdentityCall::AddInitialMessage { message, limit } => {
                self.create_tables()?;
                self.schedule_message_expiry(false).await?;
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
                    return Err(Error::RustError(
                        "timestamp exceeds MAX_SAFE_INTEGER".into(),
                    ));
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
                self.schedule_message_expiry(false).await?;
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
                self.schedule_message_expiry(false).await?;
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
                self.schedule_message_expiry(client_message_id.is_some())
                    .await?;
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

    /// Schedule the earliest outstanding expiry, including subscriptions on an otherwise empty identity.
    async fn schedule_expiry(&self, again: bool) -> Result<()> {
        self.set_expiry_alarm(again, None).await
    }

    /// Arm the alarm before inserting a message or inbox row. A new tombstone can introduce
    /// an earlier deadline even when the queue already has a retention alarm.
    async fn schedule_message_expiry(&self, with_tombstone: bool) -> Result<()> {
        let now = Date::now().as_millis();
        let mut at = now.saturating_add(self.retention());
        if with_tombstone {
            at = at.min(
                now.saturating_add(mailbox::DEDUP_TTL_MS)
                    .min(MAX_SAFE_INTEGER),
            );
        }
        self.set_expiry_alarm(false, Some(PendingExpiry::Message(at)))
            .await
    }

    async fn set_expiry_alarm(&self, again: bool, pending: Option<PendingExpiry>) -> Result<()> {
        let storage = self.state.storage();
        let existing = if again {
            None
        } else {
            storage.get_alarm().await?
        };
        let sql = self.sql();
        let has_core = self.has_tables()?;
        // An outstanding R2 batch has its own retry deadline. Inline data and replay records
        // can still expire sooner, including rows inserted during the R2 await.
        let (include_objects, pending_at) = match pending {
            Some(PendingExpiry::R2Retry(at)) => (false, Some(at)),
            Some(PendingExpiry::Message(at)) => (true, Some(at)),
            None => (true, None),
        };
        let retention_at = if has_core {
            let row: OldestRow = sql
                .exec(
                    "SELECT min(created_at) AS oldest FROM \
                     (SELECT created_at FROM messages WHERE ? OR object IS NULL \
                      UNION ALL SELECT created_at FROM initial_messages)",
                    vec![i32::from(include_objects).into()],
                )?
                .one()?;
            row.oldest
                .map(|ts| ts.saturating_add(self.retention()).saturating_add(1))
        } else {
            None
        };
        let subscribe_at = if has_table(&sql, "seen_subscribes")? {
            let row: OldestRow = sql
                .exec(
                    "SELECT min(expires_at) AS oldest FROM seen_subscribes",
                    None,
                )?
                .one()?;
            row.oldest.map(|ts| ts.saturating_add(1))
        } else {
            None
        };
        let dedup_at = if has_table(&sql, "mailbox_dedup")? {
            self.ensure_mailbox_dedup_schema(&sql)?;
            let row: OldestRow = sql
                .exec("SELECT min(expires_at) AS oldest FROM mailbox_dedup", None)?
                .one()?;
            row.oldest
        } else {
            None
        };
        let next_at = [retention_at, subscribe_at, dedup_at, pending_at]
            .into_iter()
            .flatten()
            .min()
            .or_else(|| {
                (!again && has_core)
                    .then(|| Date::now().as_millis().saturating_add(self.retention()))
            });
        if let Some(next_at) = next_at
            && existing.is_none_or(|at| i128::from(next_at) < i128::from(at))
        {
            storage.set_alarm(alarm_at(next_at)).await?;
        }
        Ok(())
    }
}
