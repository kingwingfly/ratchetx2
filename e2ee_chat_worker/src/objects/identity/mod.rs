//! The object of an identity key: its v2 capability manifest, classical and post-quantum prekeys,
//! its inbox of initial messages, the queues of messages to it, one per sender, and the WebSockets
//! its client subscribed with, which hear at once of what arrives.
//!
//! Reads of an unknown identity leave the core tables unallocated. Existing deployed v1/v2/v3 SQLite
//! Durable Objects auto-migrate in place to v4 without losing stored rows.

mod handshake;
mod mailbox;
mod rows;
mod schema;
mod ws;

use std::{cell::Cell, collections::HashMap};

use protocol::notify::Notification;
use storage::MAX_SAFE_INTEGER;
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use worker::{
    Date, DurableObject, Env, Error, Method, Request, Response, Result, SqlStorage, State,
    WebSocket, WebSocketIncomingMessage, WebSocketRequestResponsePair, console_error,
    durable_object,
};

use super::{
    AppendOutcome, ClaimBundleOutcome, IdentityCall, RETRY_ALARM, RefillOutcome, alarm_at,
    answer_rpc, decode, rpc,
    sql::{exec, params, query, query_opt},
};
use rows::{DeletedSenderBytesRow, ExpiredObjectRow, OldestRow, PendingObjectRow};
pub use ws::{
    HEADER_DEPLOYMENT_AUTH, HEADER_PENDING_IDENTITY, HEADER_SESSION_EXPIRES,
    HEADER_SUBSCRIBE_AUDIENCE, HEADER_SUBSCRIBE_SIG, HEADER_SUBSCRIBE_TS,
};

/// Maximum expired or pending-delete R2 objects processed in a single alarm tick.
const ALARM_R2_BATCH: u64 = 500;
/// Delay between consecutive R2 batch alarm ticks when more than [`ALARM_R2_BATCH`] objects remain.
const ALARM_NEXT_BATCH_DELAY_MS: u64 = 5_000;
/// How long messages and initial messages are kept, unless the `RETENTION_DAYS` variable says.
pub const DEFAULT_RETENTION_DAYS: u64 = 30;

/// Alarm scheduling mode for [`Identity::update_alarm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AlarmUpdate {
    /// Pull the alarm earlier to `at` if no earlier alarm is already scheduled.
    /// Does not scan SQLite tables.
    PullEarlier(u64),
    /// Recompute the next earliest deadline across all tables and open sockets (used after
    /// `alarm()` finishes). When `r2_retry` is `Some(at)`, it stands in for object-backed expiry
    /// and pending R2 deletes while inline rows, replay entries, and sockets can still fire sooner.
    Recompute { r2_retry: Option<u64> },
}

/// Pure decision helper for [`Identity::update_alarm`]: returns `Some(target_ms)` if `set_alarm`
/// should be called, or `None` if no alarm change is needed.
fn resolve_alarm_update(
    update: AlarmUpdate,
    existing: Option<i64>,
    recomputed_earliest: Option<u64>,
) -> Option<u64> {
    match update {
        AlarmUpdate::PullEarlier(at) => existing
            .is_none_or(|cur| i128::from(at) < i128::from(cur))
            .then_some(at),
        AlarmUpdate::Recompute { .. } => recomputed_earliest,
    }
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
    schema_ready: Cell<bool>,
    seen_subscribes_ready: Cell<bool>,
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
            schema_ready: Cell::new(false),
            seen_subscribes_ready: Cell::new(false),
        }
    }

    async fn fetch(&self, mut request: Request) -> Result<Response> {
        match request.method() {
            Method::Get => self.accept_websocket(&request).await,
            Method::Post => {
                let call = match decode(&mut request).await {
                    Ok(call) => call,
                    Err(_) => return Response::error("malformed internal request", 400),
                };
                self.serve(call).await
            }
            _ => Response::error("method not allowed", 405),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        if let Err(e) = self.run_alarm().await {
            console_error!("identity alarm failed, scheduling retry: {e}");
            let retry_at = Date::now().as_millis().saturating_add(RETRY_ALARM);
            if let Err(arm_err) = self.state.storage().set_alarm(alarm_at(retry_at)).await {
                console_error!("cannot re-arm identity alarm after error: {arm_err}");
            }
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

    async fn run_alarm(&self) -> Result<()> {
        let now = Date::now().as_millis();
        // Always prune timed-out pending sockets and session-expired sockets even when the DO has
        // no SQLite tables yet.
        self.prune_sockets(now);

        let sql = self.sql();
        let has_core = self.has_tables()?;
        let has_seen = self.has_seen_subscribes(&sql)?;
        if !has_core && !has_seen {
            return self
                .update_alarm(AlarmUpdate::Recompute { r2_retry: None })
                .await;
        }
        if has_seen {
            exec(
                &sql,
                "DELETE FROM seen_subscribes WHERE expires_at < ?",
                params![now]?,
            )?;
        }
        let mut r2_delay: Option<u64> = None;
        if has_core {
            self.ensure_v2_tables()?;
            self.expire_dedup(now)?;
            let pending_delay = self.drain_pending_r2_deletes().await?;
            // Expire inline messages and initial messages unconditionally; only run an expired-R2
            // batch when `pending_r2_deletes` did not exhaust the R2 batch/retry budget.
            let expire_delay = self.expire_messages(now, pending_delay.is_some()).await?;
            r2_delay = match (pending_delay, expire_delay) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        let r2_retry = r2_delay.map(|delay| Date::now().as_millis().saturating_add(delay));
        self.update_alarm(AlarmUpdate::Recompute { r2_retry }).await
    }

    /// Drains up to [`ALARM_R2_BATCH`] durably queued delivered R2 deletes.
    async fn drain_pending_r2_deletes(&self) -> Result<Option<u64>> {
        let sql = self.sql();
        let rows: Vec<PendingObjectRow> = query(
            &sql,
            "SELECT object FROM pending_r2_deletes ORDER BY created_at LIMIT ?",
            params![ALARM_R2_BATCH]?,
        )?;
        if rows.is_empty() {
            return Ok(None);
        }
        let objects: Vec<String> = rows.into_iter().map(|row| row.object).collect();
        let deleted = match self.env.bucket(crate::BUCKET) {
            Ok(bucket) => crate::store::delete_objects(&bucket, objects.clone()).await,
            Err(e) => Err(e),
        };
        if let Err(e) = deleted {
            console_error!("cannot delete queued R2 objects in alarm: {e}");
            return Ok(Some(RETRY_ALARM));
        }
        let objects_json =
            serde_json::to_string(&objects).map_err(|e| Error::RustError(e.to_string()))?;
        exec(
            &sql,
            "DELETE FROM pending_r2_deletes WHERE object IN (SELECT value FROM json_each(?))",
            params![objects_json]?,
        )?;
        Ok((objects.len() as u64 >= ALARM_R2_BATCH).then_some(ALARM_NEXT_BATCH_DELAY_MS))
    }

    /// Delete expired inline messages, expired inbox rows, and (unless `skip_r2`) one batch of
    /// expired R2-backed messages. Updates O(1) queue and recipient counters atomically.
    async fn expire_messages(&self, now: u64, skip_r2: bool) -> Result<Option<u64>> {
        let before = now.saturating_sub(self.retention());
        self.transaction_sync(|sql| {
            let deleted_inline: Vec<DeletedSenderBytesRow> = query(
                sql,
                "DELETE FROM messages WHERE created_at < ? AND object IS NULL \
                 RETURNING sender, (length(header) + size + coalesce(length(initial_message), 0)) AS bytes",
                params![before]?,
            )?;
            apply_deleted_usage(sql, deleted_inline)?;
            exec(
                sql,
                "DELETE FROM initial_messages WHERE created_at < ?",
                params![before]?,
            )?;
            Self::cleanup_orphan_pq_initials_sql(sql)
        })?;

        if skip_r2 {
            return Ok(None);
        }

        let sql = self.sql();
        let rows: Vec<ExpiredObjectRow> = query(
            &sql,
            "SELECT sender, sequence, object FROM messages \
             WHERE created_at < ? AND object IS NOT NULL LIMIT ?",
            params![before, ALARM_R2_BATCH]?,
        )?;
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

        // Batch-delete all expired rows in a single SQL statement instead of up to 500 DELETEs.
        let pairs_json = expired_pairs_json(&rows);
        self.transaction_sync(|sql| {
            let deleted_r2: Vec<DeletedSenderBytesRow> = query(
                sql,
                "DELETE FROM messages \
                 WHERE (sender, sequence) IN ( \
                     SELECT unhex(json_extract(value, '$[0]')), \
                            CAST(json_extract(value, '$[1]') AS INTEGER) \
                     FROM json_each(?) \
                 ) \
                 RETURNING sender, (length(header) + size + coalesce(length(initial_message), 0)) AS bytes",
                params![pairs_json]?,
            )?;
            apply_deleted_usage(sql, deleted_r2)
        })?;
        Ok((rows.len() as u64 >= ALARM_R2_BATCH).then_some(ALARM_NEXT_BATCH_DELAY_MS))
    }

    /// Serve `call`.
    ///
    /// Concurrency invariant: in a Cloudflare Durable Object, storage operations (`sql.exec`,
    /// `get_alarm`, `set_alarm`) close the input gate, so only storage awaits occur between
    /// precondition checks and SQL writes (no external network/R2 awaits interleave before commit).
    async fn serve(&self, call: IdentityCall) -> Result<Response> {
        match call {
            IdentityCall::RetiredPublishV1
            | IdentityCall::RetiredTakeBundleV1
            | IdentityCall::RetiredAddInitialMessageV1
            | IdentityCall::RetiredTakeInitialMessagesV1
            | IdentityCall::RetiredAppendV1 => {
                Response::error("legacy v1 IdentityCall is retired", 501)
            }
            IdentityCall::Read(req) => {
                answer_rpc::<rpc::Read>(self.read(&req.sender, req.after, req.limit, req.max_size))
            }
            IdentityCall::DeliveredObjects(req) => answer_rpc::<rpc::DeliveredObjects>(
                self.delivered_objects(&req.sender, &req.hashes),
            ),
            IdentityCall::DeleteDelivered(req) => answer_rpc::<rpc::DeleteDelivered>(
                self.delete_delivered(&req.sender, &req.hashes, &req.objects),
            ),
            IdentityCall::DeleteDeliveredAtomic(req) => answer_rpc::<rpc::DeleteDeliveredAtomic>(
                self.delete_delivered_atomic(&req.sender, &req.hashes).await,
            ),
            IdentityCall::PublishV2(req) => {
                self.ensure_v2_tables()?;
                answer_rpc::<rpc::PublishV2>(self.publish_v2(
                    &req.manifest,
                    req.signed_prekey_signature.as_deref(),
                    &req.one_time_prekeys,
                    &req.pq_last_resort,
                    &req.pq_one_time_prekeys,
                    req.timestamp,
                ))
            }
            IdentityCall::RefillPrekeys(req) => {
                if !self.has_tables()? {
                    return answer_rpc::<rpc::RefillPrekeys>(Ok(RefillOutcome::NotFound));
                }
                self.ensure_v2_tables()?;
                answer_rpc::<rpc::RefillPrekeys>(self.refill_prekeys(
                    req.generation,
                    &req.one_time_prekeys,
                    &req.pq_one_time_prekeys,
                    req.max_one_time_prekeys,
                    req.max_pq_one_time_prekeys,
                    req.timestamp,
                ))
            }
            IdentityCall::GetManifest(_) => answer_rpc::<rpc::GetManifest>(self.get_manifest()),
            IdentityCall::ClaimBundle(req) => {
                let outcome = self.claim_bundle_checked(&req.preferred_suites, false);
                let legacy = outcome.map(|o| match o {
                    ClaimBundleOutcome::Claimed(bundle) => Some(*bundle),
                    ClaimBundleOutcome::NotFound | ClaimBundleOutcome::PqDisabledForPqManifest => {
                        None
                    }
                });
                answer_rpc::<rpc::ClaimBundle>(legacy)
            }
            IdentityCall::ClaimBundleChecked(req) => answer_rpc::<rpc::ClaimBundleChecked>(
                self.claim_bundle_checked(&req.preferred_suites, req.reject_pq_on_manifest),
            ),
            IdentityCall::AddInitialMessageV2(req) => {
                self.ensure_v2_tables()?;
                self.schedule_message_expiry(false).await?;
                let added = self.add_initial_message_v2(&req.message, req.limit);
                if matches!(added, Ok(Some(_))) {
                    self.notify(&Notification::initial_message());
                }
                answer_rpc::<rpc::AddInitialMessageV2>(added)
            }
            IdentityCall::ListInitialMessages(req) => {
                answer_rpc::<rpc::ListInitialMessages>(self.list_initial_messages(req.limit))
            }
            IdentityCall::AckInitialMessages(req) => {
                answer_rpc::<rpc::AckInitialMessages>(self.ack_initial_messages(&req.ids))
            }
            IdentityCall::PqSnapshot(_) => answer_rpc::<rpc::PqSnapshot>(self.pq_snapshot()),
            IdentityCall::AppendIdempotent(req) => {
                self.ensure_v2_tables()?;
                self.schedule_message_expiry(req.client_message_id.is_some())
                    .await?;
                let appended = self.append(
                    &req.sender,
                    &req.header,
                    &req.content,
                    req.size,
                    req.initial_message.as_deref(),
                    req.delivery_hash.as_deref(),
                    req.client_message_id.as_deref(),
                );
                if matches!(appended, Ok(AppendOutcome::Appended(_)))
                    && let Ok(sender) = <[u8; 32]>::try_from(req.sender.as_slice())
                {
                    self.notify(&Notification::message_from(&sender));
                }
                answer_rpc::<rpc::AppendIdempotent>(appended)
            }
        }
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
        self.update_alarm(AlarmUpdate::PullEarlier(at)).await
    }

    /// Updates the Durable Object alarm according to `update`.
    ///
    /// Concurrency invariant: Cloudflare Durable Object storage operations (`get_alarm`,
    /// `set_alarm`, `sql.exec`) close the input gate, so no other request interleaves between
    /// reading the current alarm / earliest rows and calling `set_alarm`. After an R2 await inside
    /// `alarm()`, `AlarmUpdate::Recompute` rescans all indexed tables and live sockets so rows
    /// committed during the R2 await are always covered.
    pub(super) async fn update_alarm(&self, update: AlarmUpdate) -> Result<()> {
        let storage = self.state.storage();
        match update {
            AlarmUpdate::PullEarlier(_) => {
                let existing = storage.get_alarm().await?;
                if let Some(target) = resolve_alarm_update(update, existing, None) {
                    storage.set_alarm(alarm_at(target)).await?;
                }
                Ok(())
            }
            AlarmUpdate::Recompute { r2_retry } => {
                let earliest = self.compute_earliest_deadline(r2_retry)?;
                if let Some(target) = resolve_alarm_update(update, None, earliest) {
                    storage.set_alarm(alarm_at(target)).await?;
                }
                Ok(())
            }
        }
    }

    /// Computes the earliest upcoming expiry across all indexed tables and live WebSockets.
    fn compute_earliest_deadline(&self, r2_retry: Option<u64>) -> Result<Option<u64>> {
        let sql = self.sql();
        let has_core = self.has_tables()?;
        let retention = self.retention();

        let (inline_at, object_at, initial_at, pending_r2_at, dedup_at) = if has_core {
            // Split into two partial-indexed `min()` queries (`messages_inline_by_age` and
            // `messages_object_by_age`) so neither query defeats the index with `WHERE ? OR ...`.
            let inline = query_opt::<OldestRow>(
                &sql,
                "SELECT min(created_at) AS oldest FROM messages WHERE object IS NULL",
                vec![],
            )?
            .and_then(|row| row.oldest)
            .map(|ts| ts.saturating_add(retention).saturating_add(1));

            let object = if r2_retry.is_none() {
                query_opt::<OldestRow>(
                    &sql,
                    "SELECT min(created_at) AS oldest FROM messages WHERE object IS NOT NULL",
                    vec![],
                )?
                .and_then(|row| row.oldest)
                .map(|ts| ts.saturating_add(retention).saturating_add(1))
            } else {
                None
            };

            let initial = query_opt::<OldestRow>(
                &sql,
                "SELECT min(created_at) AS oldest FROM initial_messages",
                vec![],
            )?
            .and_then(|row| row.oldest)
            .map(|ts| ts.saturating_add(retention).saturating_add(1));

            let pending_r2 =
                if r2_retry.is_none() && self.has_v2_table(&sql, "pending_r2_deletes")? {
                    query_opt::<OldestRow>(
                        &sql,
                        "SELECT min(created_at) AS oldest FROM pending_r2_deletes",
                        vec![],
                    )?
                    .and_then(|row| row.oldest)
                    .map(|_| Date::now().as_millis().saturating_add(RETRY_ALARM))
                } else {
                    None
                };

            let dedup = if self.has_v2_table(&sql, "mailbox_dedup")? {
                query_opt::<OldestRow>(
                    &sql,
                    "SELECT min(expires_at) AS oldest FROM mailbox_dedup",
                    vec![],
                )?
                .and_then(|row| row.oldest)
            } else {
                None
            };

            (inline, object, initial, pending_r2, dedup)
        } else {
            (None, None, None, None, None)
        };

        let subscribe_at = if self.has_seen_subscribes(&sql)? {
            query_opt::<OldestRow>(
                &sql,
                "SELECT min(expires_at) AS oldest FROM seen_subscribes",
                vec![],
            )?
            .and_then(|row| row.oldest)
            .map(|ts| ts.saturating_add(1))
        } else {
            None
        };

        let socket_at = self.next_socket_deadline();

        Ok([
            r2_retry,
            inline_at,
            object_at,
            initial_at,
            pending_r2_at,
            dedup_at,
            subscribe_at,
            socket_at,
        ]
        .into_iter()
        .flatten()
        .min())
    }
}

fn apply_deleted_usage(sql: &SqlStorage, deleted: Vec<DeletedSenderBytesRow>) -> Result<()> {
    if deleted.is_empty() {
        return Ok(());
    }
    let mut by_sender: HashMap<Vec<u8>, (u64, u64)> = HashMap::new();
    for row in deleted {
        let entry = by_sender.entry(row.sender.into_vec()).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.saturating_add(row.bytes);
    }
    for (sender, (count, bytes)) in by_sender {
        mailbox::subtract_queue_usage(sql, &sender, count, bytes)?;
    }
    Ok(())
}

/// Encodes `(sender, sequence)` pairs as a compact JSON array `[["<hex>", seq], ...]` for a single
/// batched `json_each` DELETE statement.
fn expired_pairs_json(rows: &[ExpiredObjectRow]) -> String {
    let mut out = String::with_capacity(2 + rows.len() * 80);
    out.push('[');
    for (idx, row) in rows.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str("[\"");
        out.push_str(&crate::hex(&row.sender));
        out.push_str("\",");
        out.push_str(&row.sequence.to_string());
        out.push(']');
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alarm_update_pull_earlier_only_reschedules_when_sooner_or_unset() {
        assert_eq!(
            resolve_alarm_update(AlarmUpdate::PullEarlier(5_000), None, None),
            Some(5_000)
        );
        assert_eq!(
            resolve_alarm_update(AlarmUpdate::PullEarlier(5_000), Some(10_000), None),
            Some(5_000)
        );
        assert_eq!(
            resolve_alarm_update(AlarmUpdate::PullEarlier(10_000), Some(10_000), None),
            None
        );
        assert_eq!(
            resolve_alarm_update(AlarmUpdate::PullEarlier(15_000), Some(10_000), None),
            None
        );
    }

    #[test]
    fn alarm_update_recompute_uses_earliest_computed_deadline() {
        assert_eq!(
            resolve_alarm_update(
                AlarmUpdate::Recompute { r2_retry: None },
                Some(1_000),
                Some(20_000)
            ),
            Some(20_000)
        );
        assert_eq!(
            resolve_alarm_update(
                AlarmUpdate::Recompute {
                    r2_retry: Some(5_000)
                },
                None,
                Some(5_000)
            ),
            Some(5_000)
        );
        assert_eq!(
            resolve_alarm_update(AlarmUpdate::Recompute { r2_retry: None }, Some(1_000), None),
            None
        );
    }
}
