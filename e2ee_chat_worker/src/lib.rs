//! The E2EE chat server as a Cloudflare Worker: the v2 handshake, unified sealed-sender-lite v2
//! mailbox, and attachment services over the Connect protocol, kept in `IdentityV2` /
//! `AttachmentV2` Durable Objects and R2 (attachments only), plus pre-authenticated notifications
//! over hibernating WebSockets. See the README.

mod auth;
mod objects;
mod store;

use std::{cell::Cell, time::Duration};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use futures_util::{Stream, StreamExt};
use prost::{Message as _, bytes::Bytes};
use protocol::{
    ErrorKind,
    attachment::{AttachmentLimits, AttachmentServer},
    connect::{self, AttachmentProcedure, PROTOCOL_VERSION_HEADER, ProcedureV2},
    handshake_v2::{HandshakeV2Server, ServerInfoConfig},
    mailbox_v2::{MailboxLimits, MailboxV2Server},
    notify::{SUBSCRIBE_NONCE_LENGTH, SubscribeRequest},
};
use worker::{
    Context, Cors, Date, Env, Headers, Method, Request, RequestInit, Response, Result, event,
};

pub use crate::objects::{AttachmentV2, IdentityV2};
use crate::store::Store;
pub(crate) use crate::store::{decode_hex_fixed, hex};

/// Where a client opens the WebSocket of its notifications.
const NOTIFICATIONS_PATH: &str = "/notifications";
/// Header advertising whether post-quantum suites are enabled at runtime (`"1"` or `"0"`).
const PQ_HEADER: &str = "x-e2ee-pq";
/// The binding of the R2 bucket (attachment chunks only).
pub(crate) const BUCKET: &str = "BUCKET";
/// Rate-limiter binding gating `GET /notifications` (`30 / 60s`).
const WS_RATE_LIMITER: &str = "WS_RATE_LIMITER";
/// Rate-limiter binding gating `ClaimBundle` and `SendInitialV2` (`30 / 60s`).
const HANDSHAKE_RATE_LIMITER: &str = "HANDSHAKE_RATE_LIMITER";
/// Rate-limiter binding gating `StartUpload` (`30 / 60s`).
const UPLOAD_RATE_LIMITER: &str = "UPLOAD_RATE_LIMITER";
/// Cap on speculative `Vec::with_capacity` from an untrusted `Content-Length` header.
const MAX_PREALLOC_BODY: usize = 64 << 10;
/// Maximum concurrent large-body operations (`PutChunk`, `GetChunk`, `FetchSigned`) per isolate.
const MAX_CONCURRENT_LARGE_OPS: usize = 4;
/// Subprotocol token prefix carrying the canonical unpadded base64url `SubscribeRequest`.
const WS_SUBPROTOCOL_SUB_PREFIX: &str = "e2ee-sub.";
/// Maximum byte length of the incoming `Sec-WebSocket-Protocol` header.
const MAX_WS_PROTOCOL_HEADER_BYTES: usize = 2560;
/// Maximum decoded protobuf byte length of a `SubscribeRequest`.
const MAX_SUBSCRIBE_PROTO_BYTES: usize = 1536;

thread_local! {
    static IN_FLIGHT_LARGE_OPS: Cell<usize> = const { Cell::new(0) };
}

/// RAII concurrency guard limiting concurrent large-body RPCs (`PutChunk`, `GetChunk`,
/// `FetchSigned`) to [`MAX_CONCURRENT_LARGE_OPS`] per isolate, acquired BEFORE reading the body.
struct LargeBodyPermit;

impl LargeBodyPermit {
    fn try_acquire() -> Option<Self> {
        IN_FLIGHT_LARGE_OPS.with(|count| {
            let current = count.get();
            if current >= MAX_CONCURRENT_LARGE_OPS {
                None
            } else {
                count.set(current + 1);
                Some(Self)
            }
        })
    }
}

impl Drop for LargeBodyPermit {
    fn drop(&mut self) {
        IN_FLIGHT_LARGE_OPS.with(|count| {
            count.set(count.get().saturating_sub(1));
        });
    }
}

/// Unified Connect RPC procedure abstraction shared by [`ProcedureV2`] and [`AttachmentProcedure`].
trait Procedure: Copy {
    fn max_body(self) -> usize;
    fn requires_sign_in(self) -> bool;
    fn uses_large_body_permit(self) -> bool {
        false
    }
    fn rate_limit(self) -> Option<(&'static str, &'static str)> {
        None
    }
    fn disabled_without_pq(self) -> bool {
        false
    }
    async fn dispatch(
        self,
        env: &Env,
        request: &Request,
        content_type: Option<&str>,
        body: Bytes,
        pq_enabled: bool,
    ) -> Result<connect::Response>;
}

impl Procedure for AttachmentProcedure {
    fn max_body(self) -> usize {
        match self {
            AttachmentProcedure::StartUpload
            | AttachmentProcedure::GetChunk
            | AttachmentProcedure::DeleteAttachment => 4 << 10,
            AttachmentProcedure::PutChunk => (2 << 20) + (4 << 10),
        }
    }

    fn requires_sign_in(self) -> bool {
        matches!(
            self,
            AttachmentProcedure::StartUpload | AttachmentProcedure::PutChunk
        )
    }

    fn uses_large_body_permit(self) -> bool {
        matches!(
            self,
            AttachmentProcedure::PutChunk | AttachmentProcedure::GetChunk
        )
    }

    fn rate_limit(self) -> Option<(&'static str, &'static str)> {
        match self {
            AttachmentProcedure::StartUpload => Some((UPLOAD_RATE_LIMITER, "upload")),
            _ => None,
        }
    }

    async fn dispatch(
        self,
        env: &Env,
        _request: &Request,
        content_type: Option<&str>,
        body: Bytes,
        _pq_enabled: bool,
    ) -> Result<connect::Response> {
        let limits = MailboxLimits::default();
        let store = Store::new(env, limits.max_fetch_bytes)?;
        let retention = period(
            env,
            "FILE_RETENTION_DAYS",
            objects::DEFAULT_FILE_RETENTION_DAYS,
        );
        let attachments = AttachmentServer::builder(store)
            .limits(AttachmentLimits {
                retention: Some(retention),
                ..AttachmentLimits::default()
            })
            .build()
            .map_err(|_| worker::Error::RustError("invalid attachment server limits".into()))?;
        Ok(connect::handle_attachments(&attachments, self, content_type, body).await)
    }
}

impl Procedure for ProcedureV2 {
    fn max_body(self) -> usize {
        match self {
            ProcedureV2::GetServerInfo
            | ProcedureV2::GetManifest
            | ProcedureV2::ClaimBundle
            | ProcedureV2::ListInitialMessages
            | ProcedureV2::FetchSigned
            | ProcedureV2::AckMessages
            | ProcedureV2::RegisterWriteToken
            | ProcedureV2::RevokeWriteToken => 4 << 10,
            ProcedureV2::AckInitialMessages => 8 << 10,
            ProcedureV2::SendInitialV2 => 16 << 10,
            ProcedureV2::PushV2 => 80 << 10,
            ProcedureV2::PublishV2 | ProcedureV2::RefillPrekeys => 256 << 10,
        }
    }

    fn requires_sign_in(self) -> bool {
        matches!(
            self,
            ProcedureV2::PublishV2
                | ProcedureV2::RefillPrekeys
                | ProcedureV2::ClaimBundle
                | ProcedureV2::SendInitialV2
                | ProcedureV2::PushV2
        )
    }

    fn uses_large_body_permit(self) -> bool {
        matches!(self, ProcedureV2::FetchSigned)
    }

    fn rate_limit(self) -> Option<(&'static str, &'static str)> {
        match self {
            ProcedureV2::ClaimBundle => Some((HANDSHAKE_RATE_LIMITER, "claim")),
            ProcedureV2::SendInitialV2 => Some((HANDSHAKE_RATE_LIMITER, "init")),
            _ => None,
        }
    }

    /// V2 procedures completely disabled when `PQ_ENABLED="false"` without inspecting the request
    /// body. Other v2 procedures enforce fine-grained rollback rules inside `HandshakeV2Server` /
    /// `MailboxV2Server` so existing PQ users can drain in-flight handshakes and publish signed
    /// OFF manifests.
    fn disabled_without_pq(self) -> bool {
        matches!(self, ProcedureV2::GetManifest)
    }

    async fn dispatch(
        self,
        env: &Env,
        request: &Request,
        content_type: Option<&str>,
        body: Bytes,
        pq_enabled: bool,
    ) -> Result<connect::Response> {
        let server_id = server_id(env, request)?;
        let limits = MailboxLimits::default();
        let store = Store::new(env, limits.max_fetch_bytes)?;
        let info = server_info_config(server_id.clone(), pq_enabled);
        let supported_suites = info.supported_suites.clone();
        let handshake = HandshakeV2Server::new(store.clone(), info);
        let mailbox = MailboxV2Server::builder(store)
            .server_id(server_id)
            .supported_suites(supported_suites)
            .allow_pq_drain(true)
            .limits(limits)
            .build();
        Ok(connect::handle_v2(&handshake, &mailbox, self, content_type, body).await)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    V2(ProcedureV2),
    Attachment(AttachmentProcedure),
}

fn resolve_route(path: &str) -> Option<Route> {
    if let Some(procedure) = ProcedureV2::from_path(path) {
        Some(Route::V2(procedure))
    } else {
        AttachmentProcedure::from_path(path).map(Route::Attachment)
    }
}

#[cfg(any(test, feature = "conformance"))]
fn extract_conformance_token<'a>(
    authorization: Option<&'a str>,
    explicit_header: Option<&'a str>,
) -> Option<&'a str> {
    if let Some(token) = explicit_header.map(str::trim).filter(|t| !t.is_empty()) {
        return Some(token);
    }
    let auth = authorization?.trim();
    let (scheme, token) = auth.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let token = token.trim();
        (!token.is_empty()).then_some(token)
    } else {
        None
    }
}

/// Strictly requires a matching `CONFORMANCE_TOKEN` secret (never bypassed by a sign-in cookie).
/// Fails closed if `CONFORMANCE_TOKEN` is unset/empty or does not match in constant time.
#[cfg(any(test, feature = "conformance"))]
fn conformance_authorized(expected_token: Option<&str>, presented_token: Option<&str>) -> bool {
    match (expected_token, presented_token) {
        (Some(expected), Some(presented)) => auth::constant_time_secret_eq(expected, presented),
        _ => false,
    }
}

/// Answers the Connect calls; the web client's files are served before the Worker runs.
#[event(fetch)]
async fn fetch(request: Request, env: Env, _context: Context) -> Result<Response> {
    #[cfg(feature = "conformance")]
    if request.path() == "/conformance" && request.method() == Method::Post {
        let expected_token = auth::secret(&env, "CONFORMANCE_TOKEN");
        let auth_header = request.headers().get("authorization")?;
        let token_header = request.headers().get("x-conformance-token")?;
        let presented = extract_conformance_token(auth_header.as_deref(), token_header.as_deref());
        if !conformance_authorized(expected_token.as_deref(), presented) {
            return with_security_headers(Response::error("unauthorized", 403)?);
        }
        // A failure panics, which fails the request.
        let store = Store::new(&env, MailboxLimits::default().max_fetch_bytes)?;
        storage::testing::attachment_store(&store).await;
        storage::testing::pq_handshake_store(&store).await;
        storage::testing::idempotent_mailbox_store(&store).await;
        return with_security_headers(Response::ok("the storage conformance suites passed")?);
    }
    if request.path() == NOTIFICATIONS_PATH {
        return subscribe(request, &env).await;
    }
    let pq_enabled = pq_runtime_enabled(&env);
    if request.path() == "/auth" || request.path().starts_with("/auth/") {
        return with_metadata(auth::handle(request, &env).await?, pq_enabled);
    }

    let path = request.path();
    // Answer CORS preflights before procedure lookup so cross-origin clients cleanly decode
    // Connect errors.
    if request.method() == Method::Options {
        return with_cors(Response::empty()?, pq_enabled);
    }

    let response = match resolve_route(&path) {
        Some(route) => match request.method() {
            Method::Post => match route {
                Route::V2(procedure) => call_connect(request, &env, procedure, pq_enabled).await?,
                Route::Attachment(procedure) => {
                    call_connect(request, &env, procedure, pq_enabled).await?
                }
            },
            _ => {
                let headers = Headers::new();
                headers.set("allow", "POST, OPTIONS")?;
                Response::error("method not allowed", 405)?.with_headers(headers)
            }
        },
        None => Response::error("not found", 404)?,
    };
    with_cors(response, pq_enabled)
}

async fn call_connect<P: Procedure>(
    mut request: Request,
    env: &Env,
    procedure: P,
    pq_enabled: bool,
) -> Result<Response> {
    if !pq_enabled && procedure.disabled_without_pq() {
        return respond(connect::error(
            ErrorKind::Unimplemented,
            "post-quantum routes are disabled",
        ));
    }
    // Check sign-in BEFORE buffering the request body or invoking rate limiters / DOs.
    let auth_info = auth::signed_in_with_tag(&request, env);
    if procedure.requires_sign_in() && auth_info.is_none() {
        let message = "sign in to this server to use it";
        return respond(connect::error(ErrorKind::SignInRequired, message));
    }
    let content_type = request.headers().get("content-type")?;
    if let Some(response) = connect::check_content_type(content_type.as_deref()) {
        return respond(response);
    }
    // Enforce Connect RPC rate limiters BEFORE buffering the body or routing to DOs.
    // Returns Connect `Code::Unavailable` (HTTP 503 JSON + `Retry-After: 60`) — NEVER
    // `Code::ResourceExhausted` (`LimitExceeded`), which clients treat as permanent refusal.
    if let Some((binding, prefix)) = procedure.rate_limit() {
        let ip_key = auth::client_ip_key(&request);
        let tag_hash = auth_info.as_ref().map(|(_, hash)| hash);
        if !auth::check_rate_limits(env, binding, prefix, &ip_key, tag_hash).await {
            let mut resp = respond(connect::error(
                ErrorKind::Storage,
                "rate limited; retry shortly",
            ))?;
            resp.headers_mut().set("retry-after", "60")?;
            return Ok(resp);
        }
    }
    // Acquire `LargeBodyPermit` BEFORE `read_body` so concurrent chunked uploads or large fetches
    // cannot OOM the isolate. Returns Connect `Code::Unavailable` (HTTP 503 JSON + `Retry-After: 1`).
    let _permit = if procedure.uses_large_body_permit() {
        match LargeBodyPermit::try_acquire() {
            Some(permit) => Some(permit),
            None => {
                let mut resp = respond(connect::error(
                    ErrorKind::Storage,
                    "server busy; retry shortly",
                ))?;
                resp.headers_mut().set("retry-after", "1")?;
                return Ok(resp);
            }
        }
    } else {
        None
    };

    let response = match read_body(&mut request, procedure.max_body()).await? {
        Some(body) => {
            let body = Bytes::from(body);
            procedure
                .dispatch(env, &request, content_type.as_deref(), body, pq_enabled)
                .await?
        }
        None => connect::error(ErrorKind::LimitExceeded, "request too large"),
    };
    respond(response)
}

/// Builds the runtime [`ServerInfoConfig`] for `server_id` and `pq_enabled`.
fn server_info_config(server_id: String, pq_enabled: bool) -> ServerInfoConfig {
    let mut info = ServerInfoConfig::new(server_id);
    info.pq_enabled = pq_enabled;
    if !pq_enabled {
        info.supported_suites.clear();
        info.pq_ratchet_supported = false;
    }
    info
}

/// Adds `Date`, `x-e2ee-pq`, security headers, and Connect CORS headers.
fn with_cors(response: Response, pq_enabled: bool) -> Result<Response> {
    with_metadata(response, pq_enabled)?.with_cors(&cors_policy([Method::Post, Method::Options]))
}

/// Adds `Date`, `x-e2ee-pq`, security headers, and `/notifications` CORS headers.
fn with_notifications_cors(response: Response, pq_enabled: bool) -> Result<Response> {
    with_metadata(response, pq_enabled)?.with_cors(&cors_policy([Method::Get, Method::Options]))
}

fn cors_policy(methods: impl IntoIterator<Item = Method>) -> Cors {
    Cors::new()
        .with_origins(["*"])
        .with_methods(methods)
        .with_allowed_headers(["content-type", PROTOCOL_VERSION_HEADER])
        .with_exposed_headers(["date", PQ_HEADER, "retry-after"])
        .with_max_age(86400)
}

/// Adds defensive security headers to Worker-generated responses.
fn with_security_headers(mut response: Response) -> Result<Response> {
    let headers = response.headers_mut();
    headers.set("x-content-type-options", "nosniff")?;
    headers.set("cache-control", "no-store")?;
    headers.set("referrer-policy", "no-referrer")?;
    Ok(response)
}

/// Adds `Date`, `x-e2ee-pq`, and defensive security response headers.
fn with_metadata(mut response: Response, pq_enabled: bool) -> Result<Response> {
    let now = worker::js_sys::Date::new_0().to_utc_string();
    response.headers_mut().set("date", &String::from(now))?;
    response
        .headers_mut()
        .set(PQ_HEADER, if pq_enabled { "1" } else { "0" })?;
    with_security_headers(response)
}

/// The HTTP response of a Connect call's `response`.
fn respond(response: connect::Response) -> Result<Response> {
    let headers = Headers::new();
    headers.set("content-type", response.content_type)?;
    Ok(Response::from_bytes(response.body)?
        .with_status(response.status)
        .with_headers(headers))
}

/// Whether post-quantum suites and manifest reads are enabled at runtime (`PQ_ENABLED`).
fn pq_runtime_enabled(env: &Env) -> bool {
    env_bool(env, "PQ_ENABLED", true)
}

/// The configured relay audience, falling back to the request's origin.
pub(crate) fn server_id(env: &Env, request: &Request) -> Result<String> {
    let configured = env.var("SERVER_ID").ok().map(|v| v.to_string());
    normalize_server_id(configured.as_deref(), &request.url()?)
}

fn normalize_server_id(configured: Option<&str>, request_url: &worker::Url) -> Result<String> {
    if let Some(id) = configured.map(str::trim).filter(|id| !id.is_empty()) {
        return protocol::normalize_audience(id)
            .map_err(|_| worker::Error::RustError("invalid SERVER_ID".into()));
    }
    if !matches!(request_url.scheme(), "http" | "https" | "ws" | "wss")
        || !request_url.username().is_empty()
        || request_url.password().is_some()
    {
        return Err(worker::Error::RustError(
            "invalid request URL audience".into(),
        ));
    }
    protocol::normalize_audience(&request_url.origin().ascii_serialization())
        .map_err(|_| worker::Error::RustError("invalid request URL audience".into()))
}

/// Keep a canonical authority unambiguous when the subscription verifier normalizes it again.
/// A bare authority would lose an explicit HTTP port 443 or HTTPS port 80.
pub(crate) fn subscribe_audience(authority: String) -> String {
    if authority.contains("://") {
        authority
    } else if authority.ends_with(":443") {
        format!("http://{authority}")
    } else if authority.ends_with(":80") {
        format!("https://{authority}")
    } else {
        authority
    }
}

fn env_bool(env: &Env, name: &str, default: bool) -> bool {
    env.var(name)
        .ok()
        .and_then(
            |v| match v.to_string().trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => Some(true),
                "0" | "false" | "no" | "off" => Some(false),
                _ => None,
            },
        )
        .unwrap_or(default)
}

/// Parses the offered `Sec-WebSocket-Protocol` header (`["e2ee-notify.v2", "e2ee-sub.<b64url>"]`):
/// - Total header length `<= MAX_WS_PROTOCOL_HEADER_BYTES` (2560 bytes).
/// - Exactly 2 non-empty comma-separated tokens: `e2ee-notify.v2` and `e2ee-sub.<b64url_nopad>`.
/// - Strict canonical unpadded base64url decoding (no padding, no non-canonical trailing bits).
/// - Decoded protobuf length `<= MAX_SUBSCRIBE_PROTO_BYTES` (1536 bytes).
///
/// NEVER logs or returns offered subprotocol tokens.
fn parse_ws_subprotocol(header: &str) -> Option<SubscribeRequest> {
    if header.len() > MAX_WS_PROTOCOL_HEADER_BYTES {
        return None;
    }
    let mut saw_v2 = false;
    let mut sub_b64: Option<&str> = None;
    let mut token_count = 0usize;
    for raw_token in header.split(',') {
        let token = raw_token.trim();
        if token.is_empty() {
            return None;
        }
        token_count += 1;
        if token_count > 2 {
            return None;
        }
        if token == objects::WS_SUBPROTOCOL_V2 {
            if saw_v2 {
                return None;
            }
            saw_v2 = true;
        } else {
            let b64 = token.strip_prefix(WS_SUBPROTOCOL_SUB_PREFIX)?;
            if b64.is_empty() || sub_b64.is_some() {
                return None;
            }
            sub_b64 = Some(b64);
        }
    }
    if token_count != 2 || !saw_v2 {
        return None;
    }
    let b64 = sub_b64?;
    let raw = BASE64_URL_SAFE_NO_PAD.decode(b64.as_bytes()).ok()?;
    if raw.len() > MAX_SUBSCRIBE_PROTO_BYTES {
        return None;
    }
    // Enforce canonical unpadded base64url encoding (no non-canonical trailing bits or padding).
    if BASE64_URL_SAFE_NO_PAD.encode(&raw) != b64 {
        return None;
    }
    SubscribeRequest::decode(raw.as_slice()).ok()
}

fn is_stripped_subscribe_header(name: &str) -> bool {
    [
        "sec-websocket-protocol",
        objects::HEADER_DEPLOYMENT_AUTH,
        objects::HEADER_VERIFIED_IDENTITY,
        objects::HEADER_VERIFIED_AUDIENCE,
        objects::HEADER_VERIFIED_TS,
        objects::HEADER_VERIFIED_NONCE,
        objects::HEADER_SESSION_EXPIRES,
    ]
    .iter()
    .any(|header| name.eq_ignore_ascii_case(header))
}

/// Strip incoming `Sec-WebSocket-Protocol` and all internal headers case-insensitively, then
/// append the trusted Worker-verified headers for forwarding to the `IdentityV2` Durable Object.
fn forwarded_subscribe_headers<'a>(
    incoming: impl IntoIterator<Item = (&'a str, &'a str)>,
    identity_key: &[u8; 32],
    audience: &str,
    timestamp: u64,
    nonce: &[u8; SUBSCRIBE_NONCE_LENGTH],
    session_expires: Option<u64>,
) -> Vec<(String, String)> {
    let mut forwarded: Vec<(String, String)> = incoming
        .into_iter()
        .filter(|(name, _)| !is_stripped_subscribe_header(name))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    forwarded.push((objects::HEADER_DEPLOYMENT_AUTH.to_owned(), "1".to_owned()));
    forwarded.push((
        objects::HEADER_VERIFIED_IDENTITY.to_owned(),
        hex(identity_key),
    ));
    forwarded.push((
        objects::HEADER_VERIFIED_AUDIENCE.to_owned(),
        audience.to_owned(),
    ));
    forwarded.push((
        objects::HEADER_VERIFIED_TS.to_owned(),
        timestamp.to_string(),
    ));
    forwarded.push((objects::HEADER_VERIFIED_NONCE.to_owned(), hex(nonce)));
    if let Some(expires) = session_expires {
        forwarded.push((
            objects::HEADER_SESSION_EXPIRES.to_owned(),
            expires.to_string(),
        ));
    }
    forwarded
}

/// Pre-authenticate a notification WebSocket upgrade at Worker ingress BEFORE routing to any
/// `IdentityV2` Durable Object.
///
/// Clients connect to `GET /notifications` offering
/// `Sec-WebSocket-Protocol: e2ee-notify.v2, e2ee-sub.<base64url_nopad(SubscribeRequest)>`.
/// Invalid signatures, bad audiences, stale timestamps, or malformed subprotocols are rejected at
/// the Worker edge without ever waking a victim DO.
async fn subscribe(request: Request, env: &Env) -> Result<Response> {
    let pq_enabled = pq_runtime_enabled(env);
    if request.method() == Method::Options {
        return with_notifications_cors(Response::empty()?, pq_enabled);
    }
    if request.method() != Method::Get {
        let headers = Headers::new();
        headers.set("allow", "GET, OPTIONS")?;
        return with_notifications_cors(
            Response::error("method not allowed", 405)?.with_headers(headers),
            pq_enabled,
        );
    }
    let upgrade = request.headers().get("upgrade")?;
    if !upgrade.is_some_and(|upgrade| upgrade.eq_ignore_ascii_case("websocket")) {
        return with_security_headers(Response::error("expected a WebSocket", 426)?);
    }
    let url = request.url()?;
    // Validate Origin on WebSocket upgrades whenever a browser sends one (CSWSH defense).
    let origin = request.headers().get("origin")?;
    let sec_fetch_site = request.headers().get("sec-fetch-site")?;
    let configured_server_id = env.var("SERVER_ID").ok().map(|v| v.to_string());
    if !auth::ws_upgrade_origin_allowed(
        origin.as_deref(),
        sec_fetch_site.as_deref(),
        &url,
        configured_server_id.as_deref(),
    ) {
        return with_security_headers(Response::error("cross-origin WebSocket refused", 403)?);
    }

    // Parse sign-in cookie (for both `WS_RATE_LIMITER` cookie-tag keying and auth enforcement).
    let auth_info = auth::signed_in_with_tag(&request, env);
    let ip_key = auth::client_ip_key(&request);
    let tag_hash = auth_info.as_ref().map(|(_, hash)| hash);
    if !auth::check_rate_limits(env, WS_RATE_LIMITER, "ws", &ip_key, tag_hash).await {
        let mut resp = Response::error("too many WebSocket upgrade attempts", 429)?;
        resp.headers_mut().set("retry-after", "60")?;
        return with_security_headers(resp);
    }
    if auth::password_configured(env) && auth_info.is_none() {
        return with_security_headers(Response::error("sign in to this server to use it", 403)?);
    }

    // Parse and cryptographically verify `SubscribeRequest` from `Sec-WebSocket-Protocol` BEFORE
    // instantiating or routing to any Durable Object. Never log the offered header value.
    let Some(protocol_header) = request.headers().get("sec-websocket-protocol")? else {
        return with_security_headers(Response::error("missing subscription subprotocol", 400)?);
    };
    let Some(subscription) = parse_ws_subprotocol(&protocol_header) else {
        return with_security_headers(Response::error("malformed subscription", 400)?);
    };
    let expected_authority = server_id(env, &request)?;
    let verify_audience = subscribe_audience(expected_authority.clone());
    let now_ms = Date::now().as_millis();
    let identity_key = match subscription.verify_for_audience(&verify_audience, now_ms) {
        Ok(key) => key,
        Err(err) => {
            let status = match err.kind() {
                ErrorKind::Malformed => 400,
                _ => 403,
            };
            return with_security_headers(Response::error("invalid subscription", status)?);
        }
    };
    let nonce: [u8; SUBSCRIBE_NONCE_LENGTH] = match subscription.nonce.as_ref().try_into() {
        Ok(nonce) => nonce,
        Err(_) => {
            return with_security_headers(Response::error("malformed subscription", 400)?);
        }
    };
    let verified_ts = subscription.timestamp;

    // Strip incoming `Sec-WebSocket-Protocol` and all internal headers so a client can never
    // spoof verified headers or leak credentials into the Durable Object.
    let incoming_headers: Vec<(String, String)> = request.headers().entries().collect();
    let forward_headers = Headers::new();
    for (name, value) in forwarded_subscribe_headers(
        incoming_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
        &identity_key,
        &expected_authority,
        verified_ts,
        &nonce,
        auth_info.map(|(claims, _)| claims.expires),
    ) {
        forward_headers.set(&name, &value)?;
    }

    let forwarded = Request::new_with_init(
        url.as_str(),
        RequestInit::new()
            .with_method(Method::Get)
            .with_headers(forward_headers),
    )?;
    objects::identity(env, &identity_key)?
        .fetch_with_request(forwarded)
        .await
}

fn parse_content_length(header: Option<&str>) -> Option<u64> {
    header?.trim().parse::<u64>().ok()
}

fn content_length_exceeds_limit(header: Option<&str>, limit: usize) -> bool {
    parse_content_length(header).is_some_and(|len| len > limit as u64)
}

async fn read_body_stream<S, E>(
    stream: S,
    limit: usize,
    initial_capacity: usize,
) -> std::result::Result<Option<Vec<u8>>, E>
where
    S: Stream<Item = std::result::Result<Vec<u8>, E>>,
{
    let mut stream = std::pin::pin!(stream);
    let mut body = Vec::with_capacity(initial_capacity.min(limit).min(MAX_PREALLOC_BODY));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// The body of `request`; `None` if `Content-Length` or the streamed bytes exceed `limit`,
/// rejecting oversized bodies before buffering them in memory.
pub(crate) async fn read_body(request: &mut Request, limit: usize) -> Result<Option<Vec<u8>>> {
    let content_length = request.headers().get("content-length")?;
    if content_length_exceeds_limit(content_length.as_deref(), limit) {
        return Ok(None);
    }
    if request.inner().body().is_none() {
        return Ok(Some(vec![]));
    }
    let hint = parse_content_length(content_length.as_deref())
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(0);
    let stream = request.stream()?;
    read_body_stream(stream, limit, hint).await
}

fn period_from_str(raw: Option<&str>, default: u64) -> Duration {
    let days = raw
        .and_then(|days| days.trim().parse::<f64>().ok())
        .filter(|days| days.is_finite() && *days >= 0.0)
        .unwrap_or(default as f64);
    Duration::try_from_secs_f64(days * 24.0 * 60.0 * 60.0).unwrap_or(Duration::MAX)
}

/// How long the variable `name` says, in days, which may be a fraction, e.g. `0.5`; `default`
/// days unless it says a number that is not negative.
pub(crate) fn period(env: &Env, name: &str, default: u64) -> Duration {
    let raw = env.var(name).ok().map(|days| days.to_string());
    period_from_str(raw.as_deref(), default)
}

/// `period` in milliseconds, as the runtime's clock counts.
pub(crate) fn millis(period: Duration) -> u64 {
    u64::try_from(period.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        future::Future,
        pin::pin,
        task::{Context as TaskContext, Poll, Waker},
    };

    use futures_util::stream;
    use worker::Url;
    use xeddsa::XEdDSAPrivateKey;

    use super::*;

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut cx = TaskContext::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("in-memory test future unexpectedly yielded Pending"),
        }
    }

    #[test]
    fn route_resolution_limits_permits_and_rate_limiters_match_v2_spec() {
        for legacy in [
            "/handshake.v1.HandshakeService/Publish",
            "/handshake.v1.HandshakeService/FetchBundle",
            "/mailbox.v1.MailboxService/Push",
            "/mailbox.v1.MailboxService/Fetch",
            "/unknown.v1.Service/Method",
        ] {
            assert_eq!(resolve_route(legacy), None);
        }

        for procedure in AttachmentProcedure::ALL {
            assert_eq!(
                resolve_route(procedure.path()),
                Some(Route::Attachment(procedure))
            );
        }
        assert_eq!(ProcedureV2::ALL.len(), 13);
        for procedure in ProcedureV2::ALL {
            assert_eq!(resolve_route(procedure.path()), Some(Route::V2(procedure)));
        }

        // Exact limits & sign-in requirements for mailbox v2 RPCs.
        assert_eq!(ProcedureV2::PushV2.max_body(), 80 << 10);
        assert!(ProcedureV2::PushV2.requires_sign_in());
        for proc in [
            ProcedureV2::FetchSigned,
            ProcedureV2::AckMessages,
            ProcedureV2::RegisterWriteToken,
            ProcedureV2::RevokeWriteToken,
        ] {
            assert_eq!(proc.max_body(), 4 << 10);
            assert!(!proc.requires_sign_in());
        }

        // LargeBodyPermit procedures.
        assert!(AttachmentProcedure::PutChunk.uses_large_body_permit());
        assert!(AttachmentProcedure::GetChunk.uses_large_body_permit());
        assert!(!AttachmentProcedure::StartUpload.uses_large_body_permit());
        assert!(!AttachmentProcedure::DeleteAttachment.uses_large_body_permit());
        assert!(ProcedureV2::FetchSigned.uses_large_body_permit());
        assert!(!ProcedureV2::PushV2.uses_large_body_permit());

        // Rate-limited Connect procedures.
        assert_eq!(
            ProcedureV2::ClaimBundle.rate_limit(),
            Some((HANDSHAKE_RATE_LIMITER, "claim"))
        );
        assert_eq!(
            ProcedureV2::SendInitialV2.rate_limit(),
            Some((HANDSHAKE_RATE_LIMITER, "init"))
        );
        assert_eq!(
            AttachmentProcedure::StartUpload.rate_limit(),
            Some((UPLOAD_RATE_LIMITER, "upload"))
        );
        assert_eq!(ProcedureV2::PushV2.rate_limit(), None);
        assert_eq!(ProcedureV2::FetchSigned.rate_limit(), None);
    }

    #[test]
    fn large_body_permit_caps_concurrency_at_four_and_releases_on_drop() {
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_LARGE_OPS {
            permits.push(LargeBodyPermit::try_acquire().expect("permit available"));
        }
        assert!(LargeBodyPermit::try_acquire().is_none());
        permits.pop();
        let acquired = LargeBodyPermit::try_acquire().expect("slot freed on drop");
        assert!(LargeBodyPermit::try_acquire().is_none());
        drop(acquired);
        drop(permits);
        assert!(LargeBodyPermit::try_acquire().is_some());
    }

    #[test]
    fn parse_ws_subprotocol_enforces_exact_two_tokens_bounds_and_canonical_base64url() {
        let id = XEdDSAPrivateKey::generate();
        let sub =
            SubscribeRequest::sign_for_audience(&id, "https://relay.example", 10_000).unwrap();
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(sub.encode_to_vec());

        // Both token orders accepted when exact 2 tokens match.
        let h1 = format!("e2ee-notify.v2, e2ee-sub.{encoded}");
        let h2 = format!("e2ee-sub.{encoded}, e2ee-notify.v2");
        assert_eq!(parse_ws_subprotocol(&h1), Some(sub.clone()));
        assert_eq!(parse_ws_subprotocol(&h2), Some(sub));

        // Reject missing token, extra token, duplicate token, wrong prefix, padding, oversized.
        assert_eq!(parse_ws_subprotocol("e2ee-notify.v2"), None);
        assert_eq!(parse_ws_subprotocol(&format!("e2ee-sub.{encoded}")), None);
        assert_eq!(
            parse_ws_subprotocol(&format!("e2ee-notify.v2, e2ee-sub.{encoded}, extra")),
            None
        );
        assert_eq!(parse_ws_subprotocol("e2ee-notify.v2, e2ee-notify.v2"), None);
        assert_eq!(
            parse_ws_subprotocol(&format!("e2ee-sub.{encoded}, e2ee-sub.{encoded}")),
            None
        );
        assert_eq!(parse_ws_subprotocol("e2ee-notify.v2, e2ee-sub."), None);
        // Padded base64url rejected.
        assert_eq!(
            parse_ws_subprotocol(&format!("e2ee-notify.v2, e2ee-sub.{encoded}=")),
            None
        );
        // Oversized header (> 2560 bytes) rejected.
        let huge = format!(
            "e2ee-notify.v2, e2ee-sub.{}",
            "A".repeat(MAX_WS_PROTOCOL_HEADER_BYTES)
        );
        assert!(huge.len() > MAX_WS_PROTOCOL_HEADER_BYTES);
        assert_eq!(parse_ws_subprotocol(&huge), None);
    }

    #[test]
    fn server_info_config_reflects_pq_enabled() {
        let on = server_info_config("relay.example".into(), true);
        assert!(on.pq_enabled);
        assert!(!on.supported_suites.is_empty());
        assert!(on.pq_ratchet_supported);

        let off = server_info_config("relay.example".into(), false);
        assert!(!off.pq_enabled);
        assert!(off.supported_suites.is_empty());
        assert!(!off.pq_ratchet_supported);

        assert!(ProcedureV2::GetManifest.disabled_without_pq());
        for proc in ProcedureV2::ALL {
            if proc != ProcedureV2::GetManifest {
                assert!(!proc.disabled_without_pq());
            }
        }
    }

    #[test]
    fn internal_and_subprotocol_headers_are_stripped_case_insensitively() {
        for header in [
            "sec-websocket-protocol",
            objects::HEADER_DEPLOYMENT_AUTH,
            objects::HEADER_VERIFIED_IDENTITY,
            objects::HEADER_VERIFIED_AUDIENCE,
            objects::HEADER_VERIFIED_TS,
            objects::HEADER_VERIFIED_NONCE,
            objects::HEADER_SESSION_EXPIRES,
        ] {
            assert!(is_stripped_subscribe_header(header));
            assert!(is_stripped_subscribe_header(&header.to_ascii_uppercase()));
        }
        assert!(!is_stripped_subscribe_header("upgrade"));
        assert!(!is_stripped_subscribe_header("cookie"));

        let id = [0x42u8; 32];
        let nonce = [0x99u8; SUBSCRIBE_NONCE_LENGTH];
        let forwarded = forwarded_subscribe_headers(
            [
                ("upgrade", "websocket"),
                ("Sec-WebSocket-Protocol", "e2ee-notify.v2, e2ee-sub.SECRET"),
                ("X-E2EE-Deployment-Auth", "0"),
                ("x-e2ee-verified-identity", "00"),
                ("X-E2EE-Verified-Audience", "evil.example"),
                ("X-E2EE-Verified-Ts", "1"),
                ("X-E2EE-Verified-Nonce", "00"),
                ("X-E2EE-Session-Expires", "999999999999"),
            ],
            &id,
            "relay.example:443",
            55_555,
            &nonce,
            Some(123_456),
        );
        assert!(forwarded.contains(&("upgrade".into(), "websocket".into())));
        assert!(
            !forwarded
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-protocol"))
        );
        assert!(
            !forwarded
                .iter()
                .any(|(_, v)| v.contains("SECRET") || v.contains("e2ee-sub"))
        );
        assert_eq!(
            forwarded
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(objects::HEADER_DEPLOYMENT_AUTH))
                .collect::<Vec<_>>(),
            vec![&(objects::HEADER_DEPLOYMENT_AUTH.to_string(), "1".to_string())]
        );
        assert_eq!(
            forwarded
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(objects::HEADER_VERIFIED_IDENTITY))
                .collect::<Vec<_>>(),
            vec![&(objects::HEADER_VERIFIED_IDENTITY.to_string(), hex(&id))]
        );
        assert_eq!(
            forwarded
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(objects::HEADER_VERIFIED_AUDIENCE))
                .collect::<Vec<_>>(),
            vec![&(
                objects::HEADER_VERIFIED_AUDIENCE.to_string(),
                "relay.example:443".to_string()
            )]
        );
        assert_eq!(
            forwarded
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(objects::HEADER_VERIFIED_TS))
                .collect::<Vec<_>>(),
            vec![&(objects::HEADER_VERIFIED_TS.to_string(), "55555".to_string())]
        );
        assert_eq!(
            forwarded
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(objects::HEADER_VERIFIED_NONCE))
                .collect::<Vec<_>>(),
            vec![&(objects::HEADER_VERIFIED_NONCE.to_string(), hex(&nonce))]
        );
        assert_eq!(
            forwarded
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(objects::HEADER_SESSION_EXPIRES))
                .collect::<Vec<_>>(),
            vec![&(
                objects::HEADER_SESSION_EXPIRES.to_string(),
                "123456".to_string()
            )]
        );
    }

    #[test]
    fn server_id_normalizes_configured_and_request_authorities() {
        for (url, expected) in [
            (
                "https://BÜCHER.example:443/path?q=a#f",
                "xn--bcher-kva.example",
            ),
            (
                "http://[2001:0DB8:0:0:0:0:0:1]:80/notifications",
                "[2001:db8::1]",
            ),
            ("wss://[2001:0DB8::1]:8443/ws", "[2001:db8::1]:8443"),
            ("https://Example.com:80", "example.com:80"),
            ("http://Example.com:443", "example.com:443"),
            ("ws://Example.com:80", "example.com"),
        ] {
            assert_eq!(
                normalize_server_id(Some("  "), &Url::parse(url).unwrap()).unwrap(),
                expected
            );
            let other = Url::parse("https://other.example").unwrap();
            assert_eq!(normalize_server_id(Some(url), &other).unwrap(), expected);
        }
        let other = Url::parse("https://other.example").unwrap();
        assert_eq!(
            normalize_server_id(Some(" BÜCHER.example:443 "), &other).unwrap(),
            "xn--bcher-kva.example"
        );
        assert!(normalize_server_id(Some("https://user@relay.example"), &other).is_err());
        for url in [
            "data:text/plain,hello",
            "ftp://relay.example",
            "https://user@relay.example",
        ] {
            assert!(normalize_server_id(None, &Url::parse(url).unwrap()).is_err());
        }
    }

    #[test]
    fn subscriptions_preserve_nondefault_ports_across_forwarding() {
        let identity = XEdDSAPrivateKey::generate();
        let now = 1_000_000;
        let plain_host =
            SubscribeRequest::sign_for_audience(&identity, "relay.example", now).unwrap();
        for url in ["https://relay.example:80", "http://relay.example:443"] {
            let signed = SubscribeRequest::sign_for_audience(&identity, url, now).unwrap();
            let authority = normalize_server_id(None, &Url::parse(url).unwrap()).unwrap();
            let verify_aud = subscribe_audience(authority.clone());
            assert!(signed.verify_for_audience(&verify_aud, now).is_ok());
            assert_eq!(signed.audience, authority);
            assert!(plain_host.verify_for_audience(&verify_aud, now).is_err());
        }
    }

    #[test]
    fn read_body_limits_reject_oversized_content_length_and_streams() {
        assert!(!content_length_exceeds_limit(None, 16));
        assert!(!content_length_exceeds_limit(Some("16"), 16));
        assert!(!content_length_exceeds_limit(Some(" 0 "), 16));
        assert!(!content_length_exceeds_limit(Some("not-a-number"), 16));
        assert!(content_length_exceeds_limit(Some("17"), 16));
        assert!(content_length_exceeds_limit(
            Some("18446744073709551615"),
            16
        ));

        block_on(async {
            let empty = read_body_stream(
                stream::iter(Vec::<std::result::Result<Vec<u8>, ()>>::new()),
                8,
                0,
            )
            .await
            .unwrap();
            assert_eq!(empty, Some(vec![]));

            let exact = read_body_stream(
                stream::iter([Ok::<_, ()>(b"abcd".to_vec()), Ok(b"efgh".to_vec())]),
                8,
                8,
            )
            .await
            .unwrap();
            assert_eq!(exact, Some(b"abcdefgh".to_vec()));

            let oversized = read_body_stream(
                stream::iter([
                    Ok::<_, &'static str>(b"12345".to_vec()),
                    Ok(b"6789".to_vec()),
                    Err("must not be polled after overflow"),
                ]),
                8,
                0,
            )
            .await
            .unwrap();
            assert_eq!(oversized, None);
        });
    }

    #[test]
    fn conformance_auth_is_strictly_conformance_token_only() {
        assert!(!conformance_authorized(None, None));
        assert!(!conformance_authorized(Some("secret"), None));
        assert!(!conformance_authorized(Some("secret"), Some("wrong")));
        assert!(!conformance_authorized(None, Some("secret")));
        assert!(conformance_authorized(Some("secret"), Some("secret")));

        assert_eq!(
            extract_conformance_token(Some("Bearer tok123"), None),
            Some("tok123")
        );
        assert_eq!(
            extract_conformance_token(Some("bearer   tok123 "), None),
            Some("tok123")
        );
        assert_eq!(extract_conformance_token(Some("Basic abc"), None), None);
        assert_eq!(
            extract_conformance_token(Some("Bearer a"), Some("b")),
            Some("b")
        );
    }

    #[test]
    fn period_parses_fractional_days_and_falls_back_on_invalid_values() {
        assert_eq!(
            period_from_str(Some("0.5"), 30),
            Duration::from_secs(12 * 3600)
        );
        assert_eq!(period_from_str(Some("0"), 30), Duration::ZERO);
        assert_eq!(period_from_str(None, 30), Duration::from_secs(30 * 86_400));
        assert_eq!(
            period_from_str(Some("-1"), 30),
            Duration::from_secs(30 * 86_400)
        );
        assert_eq!(
            period_from_str(Some("NaN"), 30),
            Duration::from_secs(30 * 86_400)
        );
        assert_eq!(
            period_from_str(Some("inf"), 30),
            Duration::from_secs(30 * 86_400)
        );
        assert_eq!(period_from_str(Some("1e300"), 30), Duration::MAX);
    }
}
