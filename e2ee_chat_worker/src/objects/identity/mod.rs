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
use worker::{
    Date, DurableObject, Env, Error, Method, Request, Response, Result, State, WebSocket,
    WebSocketIncomingMessage, WebSocketRequestResponsePair, console_error, durable_object,
};

use super::{
    AppendOutcome, ClaimBundleOutcome, IdentityCall, RETRY_ALARM, RefillOutcome, alarm_at,
    answer_rpc, decode, rpc,
    sql::{SqlExec, WorkerSql, params},
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

/// Per-instance schema readiness cache shared between [`Identity`] and [`IdentityStore`].
#[derive(Default)]
pub(crate) struct SchemaCache {
    pub(super) schema_ready: Cell<bool>,
    pub(super) seen_subscribes_ready: Cell<bool>,
}

/// SQL-backed core of [`Identity`], parameterized over [`SqlExec`] and timestamps so native
/// SQLite tests can drive every query, constraint, counter, budget, and rollback deterministically.
pub(crate) struct IdentityStore<'a, S: SqlExec> {
    pub(super) sql: &'a S,
    pub(super) cache: &'a SchemaCache,
    pub(super) retention_ms: u64,
}

impl<'a, S: SqlExec> IdentityStore<'a, S> {
    pub(crate) fn new(sql: &'a S, cache: &'a SchemaCache, retention_ms: u64) -> Self {
        Self {
            sql,
            cache,
            retention_ms,
        }
    }

    fn list_pending_r2_deletes(&self, limit: u64) -> Result<Vec<String>> {
        let rows: Vec<PendingObjectRow> = self.sql.query(
            "SELECT object FROM pending_r2_deletes ORDER BY created_at LIMIT ?",
            params![limit]?,
        )?;
        Ok(rows.into_iter().map(|row| row.object).collect())
    }

    /// Expires inline messages, inbox rows, and orphan PQ initial metadata atomically while
    /// updating O(1) queue and recipient counters.
    fn expire_inline_and_initials(&self, now_ms: u64) -> Result<()> {
        let before = now_ms.saturating_sub(self.retention_ms);
        self.sql.transaction_sync(|sql| {
            let deleted_inline: Vec<DeletedSenderBytesRow> = sql.query(
                "DELETE FROM messages WHERE created_at < ? AND object IS NULL \
                 RETURNING sender, (length(header) + size + coalesce(length(initial_message), 0)) AS bytes",
                params![before]?,
            )?;
            apply_deleted_usage(sql, deleted_inline)?;
            sql.exec(
                "DELETE FROM initial_messages WHERE created_at < ?",
                params![before]?,
            )?;
            Self::cleanup_orphan_pq_initials_sql(sql)
        })
    }

    /// Lists up to `limit` expired R2-backed message rows ready for R2 object deletion.
    fn list_expired_r2_messages(&self, now_ms: u64, limit: u64) -> Result<Vec<ExpiredObjectRow>> {
        let before = now_ms.saturating_sub(self.retention_ms);
        self.sql.query(
            "SELECT sender, sequence, object FROM messages \
             WHERE created_at < ? AND object IS NOT NULL LIMIT ?",
            params![before, limit]?,
        )
    }

    /// Batch-deletes expired R2-backed message rows in a single `json_each` statement and updates
    /// O(1) queue and recipient counters atomically.
    fn delete_expired_r2_messages(&self, rows: &[ExpiredObjectRow]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let pairs_json = expired_pairs_json(rows);
        self.sql.transaction_sync(|sql| {
            let deleted_r2: Vec<DeletedSenderBytesRow> = sql.query(
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
        })
    }

    /// Computes the earliest upcoming expiry across all indexed tables and live WebSockets.
    fn compute_earliest_deadline(
        &self,
        now_ms: u64,
        r2_retry: Option<u64>,
        socket_at: Option<u64>,
    ) -> Result<Option<u64>> {
        let has_core = self.has_tables()?;
        let retention = self.retention_ms;

        let (inline_at, object_at, initial_at, pending_r2_at, dedup_at) = if has_core {
            // Split into two partial-indexed `min()` queries (`messages_inline_by_age` and
            // `messages_object_by_age`) so neither query defeats the index with `WHERE ? OR ...`.
            let inline = self
                .sql
                .query_opt::<OldestRow>(
                    "SELECT min(created_at) AS oldest FROM messages WHERE object IS NULL",
                    vec![],
                )?
                .and_then(|row| row.oldest)
                .map(|ts| ts.saturating_add(retention).saturating_add(1));

            let object = if r2_retry.is_none() {
                self.sql
                    .query_opt::<OldestRow>(
                        "SELECT min(created_at) AS oldest FROM messages WHERE object IS NOT NULL",
                        vec![],
                    )?
                    .and_then(|row| row.oldest)
                    .map(|ts| ts.saturating_add(retention).saturating_add(1))
            } else {
                None
            };

            let initial = self
                .sql
                .query_opt::<OldestRow>(
                    "SELECT min(created_at) AS oldest FROM initial_messages",
                    vec![],
                )?
                .and_then(|row| row.oldest)
                .map(|ts| ts.saturating_add(retention).saturating_add(1));

            let pending_r2 =
                if r2_retry.is_none() && self.has_v2_table(self.sql, "pending_r2_deletes")? {
                    let oldest = self
                        .sql
                        .query_opt::<OldestRow>(
                            "SELECT min(created_at) AS oldest FROM pending_r2_deletes",
                            vec![],
                        )?
                        .and_then(|row| row.oldest);
                    pending_r2_deadline(oldest, now_ms)
                } else {
                    None
                };

            let dedup = if self.has_v2_table(self.sql, "mailbox_dedup")? {
                self.sql
                    .query_opt::<OldestRow>(
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

        let subscribe_at = if self.has_seen_subscribes()? {
            self.sql
                .query_opt::<OldestRow>(
                    "SELECT min(expires_at) AS oldest FROM seen_subscribes",
                    vec![],
                )?
                .and_then(|row| row.oldest)
                .map(|ts| ts.saturating_add(1))
        } else {
            None
        };

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

/// Computes the retry deadline for queued `pending_r2_deletes` rows based on the oldest queued
/// row's age (`oldest + RETRY_ALARM`), clamped to `>= now_ms`, so unrelated alarm recomputations
/// never keep pushing R2 retries out indefinitely.
fn pending_r2_deadline(oldest_created_at: Option<u64>, now_ms: u64) -> Option<u64> {
    oldest_created_at.map(|ts| ts.saturating_add(RETRY_ALARM).max(now_ms))
}

#[durable_object]
pub struct Identity {
    state: State,
    env: Env,
    cache: SchemaCache,
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
            cache: SchemaCache::default(),
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
            // Use PullEarlier semantics so a retry never pushes back an earlier deadline (e.g. a
            // 5 s pending-socket close or dedup expiry) armed meanwhile.
            if let Err(arm_err) = self.update_alarm(AlarmUpdate::PullEarlier(retry_at)).await {
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
    /// How long what was never delivered is kept, in milliseconds.
    fn retention(&self) -> u64 {
        crate::millis(crate::period(
            &self.env,
            "RETENTION_DAYS",
            DEFAULT_RETENTION_DAYS,
        ))
    }

    pub(super) fn with_store<T>(
        &self,
        f: impl FnOnce(&IdentityStore<'_, WorkerSql<'_>>) -> Result<T>,
    ) -> Result<T> {
        let sql = self.state.storage().sql();
        let worker_sql = WorkerSql(&self.state, &sql);
        let store = IdentityStore::new(&worker_sql, &self.cache, self.retention());
        f(&store)
    }

    async fn run_alarm(&self) -> Result<()> {
        let now = Date::now().as_millis();
        // Always prune timed-out pending sockets and session-expired sockets even when the DO has
        // no SQLite tables yet.
        self.prune_sockets(now);

        let (has_core, has_seen) = self.with_store(|store| {
            let has_core = store.has_tables()?;
            let has_seen = store.has_seen_subscribes()?;
            if has_seen {
                store.prune_seen_subscribes(now)?;
            }
            if has_core {
                store.ensure_v2_tables()?;
                store.expire_dedup(now)?;
            }
            Ok((has_core, has_seen))
        })?;
        if !has_core && !has_seen {
            return self
                .update_alarm(AlarmUpdate::Recompute { r2_retry: None })
                .await;
        }
        let mut r2_delay: Option<u64> = None;
        if has_core {
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
        let objects = self.with_store(|store| store.list_pending_r2_deletes(ALARM_R2_BATCH))?;
        if objects.is_empty() {
            return Ok(None);
        }
        let deleted = match self.env.bucket(crate::BUCKET) {
            Ok(bucket) => crate::store::delete_objects(&bucket, objects.clone()).await,
            Err(e) => Err(e),
        };
        if let Err(e) = deleted {
            console_error!("cannot delete queued R2 objects in alarm: {e}");
            return Ok(Some(RETRY_ALARM));
        }
        self.with_store(|store| store.clear_pending_r2_deletes(&objects))?;
        Ok((objects.len() as u64 >= ALARM_R2_BATCH).then_some(ALARM_NEXT_BATCH_DELAY_MS))
    }

    /// Delete expired inline messages, expired inbox rows, and (unless `skip_r2`) one batch of
    /// expired R2-backed messages. Updates O(1) queue and recipient counters atomically.
    async fn expire_messages(&self, now: u64, skip_r2: bool) -> Result<Option<u64>> {
        self.with_store(|store| store.expire_inline_and_initials(now))?;

        if skip_r2 {
            return Ok(None);
        }

        let rows = self.with_store(|store| store.list_expired_r2_messages(now, ALARM_R2_BATCH))?;
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

        self.with_store(|store| store.delete_expired_r2_messages(&rows))?;
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
            IdentityCall::Read(req) => answer_rpc::<rpc::Read>(self.with_store(|store| {
                store.read(
                    &req.sender,
                    req.after,
                    req.limit,
                    req.max_size,
                    Date::now().as_millis(),
                )
            })),
            IdentityCall::DeliveredObjects(req) => answer_rpc::<rpc::DeliveredObjects>(
                self.with_store(|store| store.delivered_objects(&req.sender, &req.hashes)),
            ),
            IdentityCall::DeleteDelivered(req) => {
                answer_rpc::<rpc::DeleteDelivered>(self.with_store(|store| {
                    store.delete_delivered(&req.sender, &req.hashes, &req.objects)
                }))
            }
            IdentityCall::DeleteDeliveredAtomic(req) => answer_rpc::<rpc::DeleteDeliveredAtomic>(
                self.delete_delivered_atomic(&req.sender, &req.hashes).await,
            ),
            IdentityCall::PublishV2(req) => {
                self.with_store(|store| store.ensure_v2_tables())?;
                answer_rpc::<rpc::PublishV2>(self.with_store(|store| {
                    store.publish_v2(
                        &req.manifest,
                        req.signed_prekey_signature.as_deref(),
                        &req.one_time_prekeys,
                        &req.pq_last_resort,
                        &req.pq_one_time_prekeys,
                        req.timestamp,
                    )
                }))
            }
            IdentityCall::RefillPrekeys(req) => {
                if !self.with_store(|store| store.has_tables())? {
                    return answer_rpc::<rpc::RefillPrekeys>(Ok(RefillOutcome::NotFound));
                }
                self.with_store(|store| store.ensure_v2_tables())?;
                answer_rpc::<rpc::RefillPrekeys>(self.with_store(|store| {
                    store.refill_prekeys(
                        req.generation,
                        &req.one_time_prekeys,
                        &req.pq_one_time_prekeys,
                        req.max_one_time_prekeys,
                        req.max_pq_one_time_prekeys,
                        req.timestamp,
                    )
                }))
            }
            IdentityCall::GetManifest(_) => {
                answer_rpc::<rpc::GetManifest>(self.with_store(|store| store.get_manifest()))
            }
            IdentityCall::ClaimBundle(req) => {
                let outcome = self.with_store(|store| {
                    store.claim_bundle_checked(
                        &req.preferred_suites,
                        false,
                        Date::now().as_millis(),
                    )
                });
                let legacy = outcome.map(|o| match o {
                    ClaimBundleOutcome::Claimed(bundle) => Some(*bundle),
                    ClaimBundleOutcome::NotFound | ClaimBundleOutcome::PqDisabledForPqManifest => {
                        None
                    }
                });
                answer_rpc::<rpc::ClaimBundle>(legacy)
            }
            IdentityCall::ClaimBundleChecked(req) => {
                answer_rpc::<rpc::ClaimBundleChecked>(self.with_store(|store| {
                    store.claim_bundle_checked(
                        &req.preferred_suites,
                        req.reject_pq_on_manifest,
                        Date::now().as_millis(),
                    )
                }))
            }
            IdentityCall::AddInitialMessageV2(req) => {
                self.with_store(|store| store.ensure_v2_tables())?;
                self.schedule_message_expiry(false).await?;
                let added = self.with_store(|store| {
                    store.add_initial_message_v2(&req.message, req.limit, Date::now().as_millis())
                });
                if matches!(added, Ok(Some(_))) {
                    self.notify(&Notification::initial_message());
                }
                answer_rpc::<rpc::AddInitialMessageV2>(added)
            }
            IdentityCall::ListInitialMessages(req) => {
                answer_rpc::<rpc::ListInitialMessages>(self.with_store(|store| {
                    store.list_initial_messages(req.limit, Date::now().as_millis())
                }))
            }
            IdentityCall::AckInitialMessages(req) => answer_rpc::<rpc::AckInitialMessages>(
                self.with_store(|store| store.ack_initial_messages(&req.ids)),
            ),
            IdentityCall::PqSnapshot(_) => answer_rpc::<rpc::PqSnapshot>(
                self.with_store(|store| store.pq_snapshot(Date::now().as_millis())),
            ),
            IdentityCall::AppendIdempotent(req) => {
                self.with_store(|store| store.ensure_v2_tables())?;
                self.schedule_message_expiry(req.client_message_id.is_some())
                    .await?;
                let appended = self.with_store(|store| {
                    store.append(
                        &req.sender,
                        &req.header,
                        &req.content,
                        req.size,
                        req.initial_message.as_deref(),
                        req.delivery_hash.as_deref(),
                        req.client_message_id.as_deref(),
                        Date::now().as_millis(),
                    )
                });
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
                let socket_at = self.next_socket_deadline();
                let now_ms = Date::now().as_millis();
                let earliest = self.with_store(|store| {
                    store.compute_earliest_deadline(now_ms, r2_retry, socket_at)
                })?;
                if let Some(target) = resolve_alarm_update(update, None, earliest) {
                    storage.set_alarm(alarm_at(target)).await?;
                }
                Ok(())
            }
        }
    }
}

fn apply_deleted_usage<S: SqlExec>(sql: &S, deleted: Vec<DeletedSenderBytesRow>) -> Result<()> {
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

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(super) struct TestIdentity {
    pub(super) sql: crate::objects::sql::TestSql,
    pub(super) cache: SchemaCache,
    pub(super) retention_ms: u64,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
impl TestIdentity {
    pub(super) fn new(retention_ms: u64) -> Self {
        Self {
            sql: crate::objects::sql::TestSql::in_memory(),
            cache: SchemaCache::default(),
            retention_ms,
        }
    }

    pub(super) fn store(&self) -> IdentityStore<'_, crate::objects::sql::TestSql> {
        IdentityStore::new(&self.sql, &self.cache, self.retention_ms)
    }

    pub(super) fn store_with_cache<'a>(
        &'a self,
        cache: &'a SchemaCache,
    ) -> IdentityStore<'a, crate::objects::sql::TestSql> {
        IdentityStore::new(&self.sql, cache, self.retention_ms)
    }
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

    #[test]
    fn pending_r2_deadline_tracks_oldest_row_age_and_clamps_to_now() {
        assert_eq!(pending_r2_deadline(None, 10_000), None);
        // Unrelated recompute 5 s after enqueue keeps the original created_at + RETRY_ALARM deadline.
        assert_eq!(
            pending_r2_deadline(Some(1_000), 6_000),
            Some(1_000 + RETRY_ALARM)
        );
        // Overdue rows clamp to `now` instead of scheduling in the past.
        let overdue_now = 1_000 + RETRY_ALARM + 50_000;
        assert_eq!(
            pending_r2_deadline(Some(1_000), overdue_now),
            Some(overdue_now)
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native_sqlite_tests {
        use super::*;
        use crate::objects::Content;

        #[test]
        fn compute_earliest_deadline_picks_minimum_across_tables_and_respects_r2_retry() {
            let retention = 100_000;
            let env = TestIdentity::new(retention);
            let store = env.store();

            // Unallocated DB with no sockets returns None without creating tables.
            assert_eq!(
                store.compute_earliest_deadline(1_000, None, None).unwrap(),
                None
            );
            assert!(!store.has_tables().unwrap());

            store.ensure_v2_tables().unwrap();

            // Inline message at t = 10_000 -> deadline 110_001.
            store
                .append(
                    &[1u8; 32],
                    b"hdr",
                    &Content::Inline(b"body".to_vec()),
                    4,
                    None,
                    None,
                    None,
                    10_000,
                )
                .unwrap();
            assert_eq!(
                store.compute_earliest_deadline(10_000, None, None).unwrap(),
                Some(10_000 + retention + 1)
            );

            // Older R2 object at t = 5_000 -> deadline 105_001 beats inline unless r2_retry set.
            store
                .append(
                    &[2u8; 32],
                    b"hdr",
                    &Content::Object("messages/obj-1".into()),
                    1024,
                    None,
                    None,
                    None,
                    5_000,
                )
                .unwrap();
            assert_eq!(
                store.compute_earliest_deadline(10_000, None, None).unwrap(),
                Some(5_000 + retention + 1)
            );
            // When r2_retry is set (e.g. 200_000), object expiry is suppressed so inline (110_001) wins.
            assert_eq!(
                store
                    .compute_earliest_deadline(10_000, Some(200_000), None)
                    .unwrap(),
                Some(10_000 + retention + 1)
            );

            // An earlier socket deadline wins over everything.
            assert_eq!(
                store
                    .compute_earliest_deadline(10_000, None, Some(20_000))
                    .unwrap(),
                Some(20_000)
            );
        }
    }
}
