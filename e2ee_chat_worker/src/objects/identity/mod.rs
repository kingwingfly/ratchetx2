//! The `IdentityV2` Durable Object of an identity key: its v2 capability manifest, classical and
//! post-quantum prekeys, idempotent handshake inbox, recipient-versioned write-token grants,
//! unified sealed-sender-lite inline mailbox queue (zero R2 dependency), and pre-authenticated
//! hibernating WebSockets.
//!
//! Reads and unauthorized writes of an unknown identity leave all tables unallocated.

mod handshake;
mod mailbox;
mod rows;
mod schema;
mod ws;

use std::cell::Cell;

use protocol::notify::Notification;
use storage::MAX_SAFE_INTEGER;
use worker::{
    Date, DurableObject, Env, Error, Method, Request, Response, Result, State, WebSocket,
    WebSocketIncomingMessage, WebSocketRequestResponsePair, console_error, durable_object,
};

use super::{
    AddInitialOutcome, AppendOutcome, IdentityCall, RETRY_ALARM, RevokeWriteTokenOutcome, alarm_at,
    answer_rpc, decode, rpc,
    sql::{SqlExec, WorkerSql, params},
};
use rows::{DeletedPeerBytesRow, OldestRow};
pub use ws::{
    HEADER_DEPLOYMENT_AUTH, HEADER_SESSION_EXPIRES, HEADER_VERIFIED_AUDIENCE,
    HEADER_VERIFIED_IDENTITY, HEADER_VERIFIED_NONCE, HEADER_VERIFIED_TS, WS_SUBPROTOCOL_V2,
};

/// How long messages and initial messages are kept, unless the `RETENTION_DAYS` variable says.
pub const DEFAULT_RETENTION_DAYS: u64 = 30;

/// Per-instance schema readiness cache shared between [`IdentityV2`] and [`IdentityStore`].
#[derive(Default)]
pub(crate) struct SchemaCache {
    pub(super) schema_ready: Cell<bool>,
    pub(super) seen_subscribes_ready: Cell<bool>,
}

/// SQL-backed core of [`IdentityV2`], parameterized over [`SqlExec`] and timestamps so native
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

    /// Expires inline mailbox messages, inbox initial messages, and ACKed-initial tombstones
    /// atomically while updating O(1) `peer_grants` and `recipient_stats` counters (preserving
    /// `last_sequence`).
    fn expire_messages_and_initials(&self, now_ms: u64) -> Result<()> {
        let before = now_ms.saturating_sub(self.retention_ms);
        self.sql.transaction_sync(|sql| {
            let deleted: Vec<DeletedPeerBytesRow> = sql.query(
                "DELETE FROM messages WHERE created_at < ? RETURNING peer_slot_id, bytes",
                params![before]?,
            )?;
            let _ = mailbox::apply_deleted_usage(sql, deleted)?;
            sql.exec(
                "DELETE FROM initial_messages WHERE created_at < ?",
                params![before]?,
            )?;
            sql.exec(
                "DELETE FROM acked_initial_messages WHERE expires_at <= ?",
                params![now_ms]?,
            )
        })
    }

    /// Computes the earliest upcoming expiry across all indexed tables and live WebSockets.
    fn compute_earliest_deadline(&self, socket_at: Option<u64>) -> Result<Option<u64>> {
        let has_core = self.has_tables()?;
        let retention = self.retention_ms;

        let (message_at, initial_at, acked_initial_at, dedup_at, revoke_tombstone_at) = if has_core
        {
            let msg = self
                .sql
                .query_opt::<OldestRow>("SELECT min(created_at) AS oldest FROM messages", vec![])?
                .and_then(|row| row.oldest)
                .map(|ts| ts.saturating_add(retention).saturating_add(1));

            let initial = self
                .sql
                .query_opt::<OldestRow>(
                    "SELECT min(created_at) AS oldest FROM initial_messages",
                    vec![],
                )?
                .and_then(|row| row.oldest)
                .map(|ts| ts.saturating_add(retention).saturating_add(1));

            let acked_initial = self
                .sql
                .query_opt::<OldestRow>(
                    "SELECT min(expires_at) AS oldest FROM acked_initial_messages",
                    vec![],
                )?
                .and_then(|row| row.oldest);

            let dedup = self
                .sql
                .query_opt::<OldestRow>(
                    "SELECT min(expires_at) AS oldest FROM mailbox_dedup",
                    vec![],
                )?
                .and_then(|row| row.oldest);

            let tombstone = self
                .sql
                .query_opt::<OldestRow>(
                    "SELECT min(revoked_at) AS oldest FROM peer_grants \
                     WHERE revoked_at > 0 AND message_count = 0 \
                       AND NOT EXISTS ( \
                           SELECT 1 FROM write_tokens w WHERE w.peer_slot_id = peer_grants.peer_slot_id \
                       )",
                    vec![],
                )?
                .and_then(|row| row.oldest)
                .map(|ts| {
                    ts.saturating_add(mailbox::REVOCATION_TOMBSTONE_TTL_MS)
                        .saturating_add(1)
                });

            (msg, initial, acked_initial, dedup, tombstone)
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
            message_at,
            initial_at,
            acked_initial_at,
            dedup_at,
            revoke_tombstone_at,
            subscribe_at,
            socket_at,
        ]
        .into_iter()
        .flatten()
        .min())
    }
}

/// Alarm scheduling mode for [`IdentityV2::update_alarm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AlarmUpdate {
    /// Pull the alarm earlier to `at` if no earlier alarm is already scheduled.
    /// Does not scan SQLite tables.
    PullEarlier(u64),
    /// Recompute the next earliest deadline across all tables and open sockets (used after
    /// `alarm()` finishes).
    Recompute,
}

/// Pure decision helper for [`IdentityV2::update_alarm`]: returns `Some(target_ms)` if `set_alarm`
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
        AlarmUpdate::Recompute => recomputed_earliest,
    }
}

#[durable_object]
pub struct IdentityV2 {
    state: State,
    env: Env,
    cache: SchemaCache,
}

impl DurableObject for IdentityV2 {
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

impl IdentityV2 {
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

    /// Purely local synchronous SQLite + WebSocket cleanup (zero R2 calls).
    async fn run_alarm(&self) -> Result<()> {
        let now = Date::now().as_millis();
        self.prune_sockets(now);

        self.with_store(|store| {
            if store.has_seen_subscribes()? {
                store.prune_seen_subscribes(now)?;
            }
            if store.has_tables()? {
                store.expire_dedup(now)?;
                store.expire_messages_and_initials(now)?;
                store.prune_expired_peer_grants(now)?;
            }
            Ok(())
        })?;

        self.update_alarm(AlarmUpdate::Recompute).await
    }

    /// Serve `call`.
    ///
    /// Concurrency invariant: in a Cloudflare Durable Object, storage operations (`sql.exec`,
    /// `get_alarm`, `set_alarm`) close the input gate, so only storage awaits occur between
    /// precondition checks and SQL writes (zero external network/R2 awaits).
    async fn serve(&self, call: IdentityCall) -> Result<Response> {
        match call {
            IdentityCall::PublishV2(req) => {
                answer_rpc::<rpc::PublishV2>(self.with_store(|store| store.publish_v2(&req.record)))
            }
            IdentityCall::RefillPrekeys(req) => answer_rpc::<rpc::RefillPrekeys>(
                self.with_store(|store| store.refill_prekeys(&req.record)),
            ),
            IdentityCall::GetManifest(_) => {
                answer_rpc::<rpc::GetManifest>(self.with_store(|store| store.get_manifest()))
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
                if !self.with_store(|store| store.has_manifest())? {
                    return answer_rpc::<rpc::AddInitialMessageV2>(Ok(AddInitialOutcome::NotFound));
                }
                let now = Date::now().as_millis();
                self.schedule_message_expiry(now, false).await?;
                let added = self
                    .with_store(|store| store.add_initial_message_v2(&req.message, req.limit, now));
                if matches!(added, Ok(AddInitialOutcome::Added { inserted: true, .. })) {
                    self.notify(&Notification::initial_message());
                }
                answer_rpc::<rpc::AddInitialMessageV2>(added)
            }
            IdentityCall::ListInitialMessages(req) => {
                answer_rpc::<rpc::ListInitialMessages>(self.with_store(|store| {
                    store.list_initial_messages(
                        req.recipient,
                        req.after_id,
                        req.limit,
                        Date::now().as_millis(),
                    )
                }))
            }
            IdentityCall::AckInitialMessages(req) => {
                let now = Date::now().as_millis();
                let acked = self.with_store(|store| store.ack_initial_messages(&req.ids, now));
                if matches!(acked, Ok(n) if n > 0) {
                    let prune_at = now
                        .saturating_add(handshake::ACKED_INITIAL_TOMBSTONE_TTL_MS)
                        .min(MAX_SAFE_INTEGER);
                    if let Err(e) = self.update_alarm(AlarmUpdate::PullEarlier(prune_at)).await {
                        console_error!("cannot schedule acked_initial_messages prune alarm: {e}");
                    }
                }
                answer_rpc::<rpc::AckInitialMessages>(acked)
            }
            IdentityCall::PqSnapshot(_) => answer_rpc::<rpc::PqSnapshot>(
                self.with_store(|store| store.pq_snapshot(Date::now().as_millis())),
            ),
            IdentityCall::AppendIdempotent(req) => {
                if !self.with_store(|store| store.has_write_token(&req.token_hash))? {
                    return answer_rpc::<rpc::AppendIdempotent>(Ok(
                        AppendOutcome::WriteTokenRejected,
                    ));
                }
                let now = Date::now().as_millis();
                self.schedule_message_expiry(now, req.client_message_id.is_some())
                    .await?;
                let appended = self.with_store(|store| {
                    store.append_idempotent(
                        &req.token_hash,
                        &req.header,
                        &req.content,
                        req.initial_message.as_deref(),
                        req.client_message_id.as_ref(),
                        now,
                    )
                });
                if matches!(appended, Ok(AppendOutcome::Appended(_))) {
                    self.notify(&Notification::message());
                }
                answer_rpc::<rpc::AppendIdempotent>(appended)
            }
            IdentityCall::ReadMailbox(req) => {
                answer_rpc::<rpc::ReadMailbox>(self.with_store(|store| {
                    store.read_mailbox(
                        req.after_sequence,
                        req.limit,
                        req.max_size,
                        req.ack_up_to_sequence,
                        Date::now().as_millis(),
                    )
                }))
            }
            IdentityCall::AckMessages(req) => answer_rpc::<rpc::AckMessages>(
                self.with_store(|store| store.ack_messages(req.up_to_sequence)),
            ),
            IdentityCall::RegisterWriteToken(req) => {
                answer_rpc::<rpc::RegisterWriteToken>(self.with_store(|store| {
                    store.register_write_token(&req.record, Date::now().as_millis())
                }))
            }
            IdentityCall::RevokeWriteToken(req) => {
                let now = Date::now().as_millis();
                let outcome = self.with_store(|store| store.revoke_write_token(&req.record, now));
                if matches!(outcome, Ok(RevokeWriteTokenOutcome::Revoked(_))) {
                    let prune_at = now
                        .saturating_add(mailbox::REVOCATION_TOMBSTONE_TTL_MS)
                        .saturating_add(1)
                        .min(MAX_SAFE_INTEGER);
                    if let Err(e) = self.update_alarm(AlarmUpdate::PullEarlier(prune_at)).await {
                        console_error!("cannot schedule peer_grants tombstone prune alarm: {e}");
                    }
                }
                answer_rpc::<rpc::RevokeWriteToken>(outcome)
            }
        }
    }

    /// Arm the alarm before inserting a message or inbox row, using the exact `now` timestamp that
    /// will be written to `created_at` so the alarm never wakes 1 ms before expiry across an await.
    async fn schedule_message_expiry(&self, now: u64, with_tombstone: bool) -> Result<()> {
        // `expire_messages_and_initials` deletes strictly older rows (`created_at < now - retention`),
        // so add +1 ms matching `compute_earliest_deadline` to avoid firing 1 ms early.
        let mut at = now
            .saturating_add(self.retention())
            .saturating_add(1)
            .min(MAX_SAFE_INTEGER);
        if with_tombstone {
            at = at.min(
                now.saturating_add(mailbox::DEDUP_TTL_MS)
                    .min(MAX_SAFE_INTEGER),
            );
        }
        self.update_alarm(AlarmUpdate::PullEarlier(at)).await
    }

    /// Updates the Durable Object alarm according to `update`.
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
            AlarmUpdate::Recompute => {
                let socket_at = self.next_socket_deadline();
                let earliest =
                    self.with_store(|store| store.compute_earliest_deadline(socket_at))?;
                if let Some(target) = resolve_alarm_update(update, None, earliest) {
                    storage.set_alarm(alarm_at(target)).await?;
                }
                Ok(())
            }
        }
    }
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
            resolve_alarm_update(AlarmUpdate::Recompute, Some(1_000), Some(20_000)),
            Some(20_000)
        );
        assert_eq!(
            resolve_alarm_update(AlarmUpdate::Recompute, Some(1_000), None),
            None
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native_sqlite_tests {
        use storage::{
            PublishV2Record, PublishV2Status, RegisterWriteTokenRecord, RevokeWriteTokenRecord,
            StoredCapabilityManifest,
        };

        use super::*;

        #[test]
        fn compute_earliest_deadline_tracks_messages_dedup_tombstones_subscribes_and_sockets() {
            let retention = 100_000;
            let env = TestIdentity::new(retention);
            let store = env.store();

            // Unallocated DB with no sockets returns None without creating tables.
            assert_eq!(store.compute_earliest_deadline(None).unwrap(), None);
            assert!(!store.has_tables().unwrap());

            let bob = [0x11; 32];
            assert_eq!(
                store
                    .publish_v2(&PublishV2Record {
                        manifest: StoredCapabilityManifest {
                            audience: "relay.example".into(),
                            identity_key: bob,
                            manifest_seq: 1,
                            generation: 1,
                            issued_at: 1_000,
                            expires_at: 100_000,
                            pq_enabled: false,
                            strict_pq: false,
                            pq_ratchet_supported: false,
                            offered_suites: vec![],
                            signed_prekey: [0x22; 32],
                            pq_last_resort: vec![],
                            signature: [0x33; 64],
                        },
                        signed_prekey_signature: Some([0x44; 64]),
                        one_time_prekeys: vec![],
                        pq_last_resort: vec![],
                        pq_one_time_prekeys: vec![],
                        timestamp: 1_000,
                    })
                    .unwrap(),
                PublishV2Status::Stored
            );

            let slot = [0xA0; 32];
            let token_hash = [0xA1; 32];
            assert_eq!(
                store
                    .register_write_token(
                        &RegisterWriteTokenRecord {
                            recipient: bob,
                            peer_slot_id: slot,
                            token_hash,
                            grant_version: 1,
                            pin_active: true,
                            timestamp: 1_000,
                        },
                        1_000,
                    )
                    .unwrap(),
                crate::objects::RegisterWriteTokenOutcome::Registered
            );

            // Inline message at t = 10_000 -> deadline 110_001.
            assert_eq!(
                store
                    .append_idempotent(&token_hash, b"hdr", b"body", None, None, 10_000)
                    .unwrap(),
                AppendOutcome::Appended(1)
            );
            assert_eq!(
                store.compute_earliest_deadline(None).unwrap(),
                Some(10_000 + retention + 1)
            );

            // Socket deadline beats message expiry when sooner.
            assert_eq!(
                store.compute_earliest_deadline(Some(50_000)).unwrap(),
                Some(50_000)
            );

            // Expire message -> counters drop to 0 and deadline clears.
            store
                .expire_messages_and_initials(10_000 + retention + 1)
                .unwrap();
            assert_eq!(store.compute_earliest_deadline(None).unwrap(), None);

            // Revoking the grant creates an empty tombstone whose deadline is
            // revoked_at + REVOCATION_TOMBSTONE_TTL_MS + 1.
            store
                .revoke_write_token(
                    &RevokeWriteTokenRecord {
                        recipient: bob,
                        peer_slot_id: slot,
                        token_hash: None,
                        min_grant_version: 2,
                    },
                    20_000,
                )
                .unwrap();
            assert_eq!(
                store.compute_earliest_deadline(None).unwrap(),
                Some(20_000 + mailbox::REVOCATION_TOMBSTONE_TTL_MS + 1)
            );

            // Pruning past TTL removes tombstone and clears deadline.
            store
                .prune_expired_peer_grants(20_000 + mailbox::REVOCATION_TOMBSTONE_TTL_MS + 1)
                .unwrap();
            assert_eq!(store.compute_earliest_deadline(None).unwrap(), None);
        }
    }
}
