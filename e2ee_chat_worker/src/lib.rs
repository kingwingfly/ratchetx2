//! The E2EE chat server as a Cloudflare Worker: the v2 handshake, v2 mailbox, and attachment
//! services over the Connect protocol, kept in Durable Objects and R2, and notifications over
//! hibernating WebSockets. See the README.

mod auth;
mod objects;
mod store;

use std::time::Duration;

use futures_util::{Stream, StreamExt};
use prost::bytes::Bytes;
use protocol::{
    ErrorKind,
    attachment::{AttachmentLimits, AttachmentServer},
    connect::{self, AttachmentProcedure, PROTOCOL_VERSION_HEADER, ProcedureV2},
    handshake_v2::{HandshakeV2Server, ServerInfoConfig},
    mailbox::MailboxLimits,
    mailbox_v2::MailboxV2Server,
    notify::SubscribeRequest,
};
use worker::{Context, Cors, Env, Headers, Method, Request, RequestInit, Response, Result, event};
use xeddsa::XEdDSAPublicKey;

pub use crate::objects::{Attachment, Identity};
use crate::store::Store;
pub(crate) use crate::store::{decode_hex_fixed, hex};

/// Where a client opens the WebSocket of its notifications.
const NOTIFICATIONS_PATH: &str = "/notifications";
/// Header advertising whether post-quantum suites are enabled at runtime (`"1"` or `"0"`).
const PQ_HEADER: &str = "x-e2ee-pq";
/// Header identifying a deprecated protocol version rejected by this server.
const DEPRECATED_HEADER: &str = "x-e2ee-deprecated";
/// Value of [`DEPRECATED_HEADER`] for rejected legacy v1 requests.
const DEPRECATED_V1_VALUE: &str = "v1";
/// Error message returned on deprecated legacy v1 handshake/mailbox Connect requests.
const LEGACY_V1_CONNECT_MESSAGE: &str = "Legacy v1 protocol is deprecated and removed. Refresh the web app, or switch from an archived v1/TUI client to the web app.";
/// Body returned on deprecated legacy query-param `/notifications?request=...` requests.
const LEGACY_V1_NOTIFICATIONS_MESSAGE: &str = "Legacy v1 notifications are deprecated and removed. Please refresh or upgrade the app to continue.";
/// The binding of the R2 bucket.
pub(crate) const BUCKET: &str = "BUCKET";
/// The largest request body: the largest message, 4 MiB - 64 KiB, with room for the rest of a
/// push.
const MAX_BODY: usize = 4 << 20;
/// Cap on speculative `Vec::with_capacity` from an untrusted `Content-Length` header.
const MAX_PREALLOC_BODY: usize = 64 << 10;

/// Unified Connect RPC procedure abstraction shared by [`ProcedureV2`] and [`AttachmentProcedure`].
trait Procedure: Copy {
    fn max_body(self) -> usize;
    fn requires_sign_in(self) -> bool;
    fn disabled_without_pq(self) -> bool {
        false
    }
    async fn dispatch(
        self,
        env: &Env,
        request: &Request,
        content_type: Option<&str>,
        body: &Bytes,
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

    async fn dispatch(
        self,
        env: &Env,
        _request: &Request,
        content_type: Option<&str>,
        body: &Bytes,
        _pq_enabled: bool,
    ) -> Result<connect::Response> {
        let limits = MailboxLimits::default();
        let store = Store::new(env, limits.max_message_size)?;
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
            | ProcedureV2::ListInitialMessages => 4 << 10,
            ProcedureV2::AckInitialMessages => 8 << 10,
            ProcedureV2::SendInitialV2 => 16 << 10,
            ProcedureV2::FetchSigned => 32 << 10,
            ProcedureV2::PublishV2 | ProcedureV2::RefillPrekeys => 256 << 10,
            ProcedureV2::PushV2 => MAX_BODY,
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
        body: &Bytes,
        pq_enabled: bool,
    ) -> Result<connect::Response> {
        let server_id = server_id(env, request)?;
        let limits = MailboxLimits::default();
        let store = Store::new(env, limits.max_message_size)?;
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
    LegacyV1Deprecated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SubscribeQuery {
    LegacyRequest,
    Identity(String),
    Missing,
}

fn resolve_route(path: &str) -> Option<Route> {
    if let Some(procedure) = ProcedureV2::from_path(path) {
        Some(Route::V2(procedure))
    } else if let Some(procedure) = AttachmentProcedure::from_path(path) {
        Some(Route::Attachment(procedure))
    } else if connect::is_legacy_v1_path(path) {
        Some(Route::LegacyV1Deprecated)
    } else {
        None
    }
}

fn legacy_v1_connect_error() -> connect::Response {
    connect::error(ErrorKind::Unimplemented, LEGACY_V1_CONNECT_MESSAGE)
}

fn parse_subscribe_query(url: &worker::Url) -> SubscribeQuery {
    let mut identity = None;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "request" => return SubscribeQuery::LegacyRequest,
            "identity" => identity = Some(value.into_owned()),
            _ => {}
        }
    }
    match identity {
        Some(identity) => SubscribeQuery::Identity(identity),
        None => SubscribeQuery::Missing,
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

/// Requires either a valid sign-in cookie OR a matching `CONFORMANCE_TOKEN` secret.
/// Fails closed if neither is satisfied.
#[cfg(any(test, feature = "conformance"))]
fn conformance_authorized(
    expected_token: Option<&str>,
    presented_token: Option<&str>,
    signed_in: bool,
) -> bool {
    if signed_in {
        return true;
    }
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
        let is_signed_in = auth::signed_in(&request, &env).is_some();
        if !conformance_authorized(expected_token.as_deref(), presented, is_signed_in) {
            return with_security_headers(Response::error("unauthorized", 403)?);
        }
        // A failure panics, which fails the request.
        let store = Store::new(&env, MailboxLimits::default().max_message_size)?;
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
    // Connect errors (including legacy v1 deprecation responses).
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
                Route::LegacyV1Deprecated => {
                    let mut response = respond(legacy_v1_connect_error())?;
                    response
                        .headers_mut()
                        .set(DEPRECATED_HEADER, DEPRECATED_V1_VALUE)?;
                    response
                }
            },
            _ => {
                let headers = Headers::new();
                headers.set("allow", "POST, OPTIONS")?;
                let mut response =
                    Response::error("method not allowed", 405)?.with_headers(headers);
                if route == Route::LegacyV1Deprecated {
                    response
                        .headers_mut()
                        .set(DEPRECATED_HEADER, DEPRECATED_V1_VALUE)?;
                }
                response
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
    // Check sign-in BEFORE buffering the request body!
    if procedure.requires_sign_in() && auth::signed_in(&request, env).is_none() {
        let message = "sign in to this server to use it";
        return respond(connect::error(ErrorKind::SignInRequired, message));
    }
    let content_type = request.headers().get("content-type")?;
    if let Some(response) = connect::check_content_type(content_type.as_deref()) {
        return respond(response);
    }
    let response = match read_body(&mut request, procedure.max_body()).await? {
        Some(body) => {
            let body = Bytes::from(body);
            procedure
                .dispatch(env, &request, content_type.as_deref(), &body, pq_enabled)
                .await?
        }
        None => connect::error(ErrorKind::LimitExceeded, "request too large"),
    };
    respond(response)
}

/// Builds the runtime [`ServerInfoConfig`] for `server_id` and `pq_enabled`, keeping deprecated
/// legacy v1 flags (`legacy_v1_enabled`, `allow_unsigned_fetch`) permanently `false`.
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
        .with_exposed_headers(["date", PQ_HEADER, DEPRECATED_HEADER])
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

/// Verifies an audience-bound v2 [`SubscribeRequest`] against `audience` and `now_ms`.
pub(crate) fn verify_subscribe_request(
    subscription: &SubscribeRequest,
    audience: &str,
    now_ms: u64,
) -> protocol::Result<[u8; 32]> {
    if !subscription.is_audience_bound() {
        return Err(ErrorKind::InvalidSignature.into());
    }
    subscription.verify_for_audience(audience, now_ms)
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

fn is_internal_subscribe_header(name: &str) -> bool {
    [
        objects::HEADER_DEPLOYMENT_AUTH,
        objects::HEADER_PENDING_IDENTITY,
        objects::HEADER_SUBSCRIBE_AUDIENCE,
        objects::HEADER_SESSION_EXPIRES,
        objects::HEADER_SUBSCRIBE_SIG,
        objects::HEADER_SUBSCRIBE_TS,
    ]
    .iter()
    .any(|header| name.eq_ignore_ascii_case(header))
}

/// Strip all internal subscribe headers case-insensitively and append the trusted Worker-computed
/// auth, pending identity, canonical audience, and optional session expiry headers for forwarding
/// to the Identity Durable Object.
fn forwarded_subscribe_headers<'a>(
    incoming: impl IntoIterator<Item = (&'a str, &'a str)>,
    identity_key: &[u8; 32],
    audience: &str,
    session_expires: Option<u64>,
) -> Vec<(String, String)> {
    let mut forwarded: Vec<(String, String)> = incoming
        .into_iter()
        .filter(|(name, _)| !is_internal_subscribe_header(name))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    forwarded.push((objects::HEADER_DEPLOYMENT_AUTH.to_owned(), "1".to_owned()));
    forwarded.push((
        objects::HEADER_PENDING_IDENTITY.to_owned(),
        hex(identity_key),
    ));
    forwarded.push((
        objects::HEADER_SUBSCRIBE_AUDIENCE.to_owned(),
        audience.to_owned(),
    ));
    if let Some(expires) = session_expires {
        forwarded.push((
            objects::HEADER_SESSION_EXPIRES.to_owned(),
            expires.to_string(),
        ));
    }
    forwarded
}

/// Hand a WebSocket asking for an identity's notifications to its object.
///
/// Only first-frame audience-bound v2 authentication is supported:
/// `GET /notifications?identity=<64-hex-pubkey>`, followed by a first WebSocket binary or
/// base64url text frame carrying an audience-bound v2 `SubscribeRequest`.
/// Legacy query-param requests (`GET /notifications?request=...`) return HTTP `410 Gone`.
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
    let url = request.url()?;
    let identity_hex = match parse_subscribe_query(&url) {
        SubscribeQuery::LegacyRequest => {
            let mut response = Response::error(LEGACY_V1_NOTIFICATIONS_MESSAGE, 410)?;
            response
                .headers_mut()
                .set(DEPRECATED_HEADER, DEPRECATED_V1_VALUE)?;
            return with_notifications_cors(response, pq_enabled);
        }
        SubscribeQuery::Identity(identity_hex) => identity_hex,
        SubscribeQuery::Missing => {
            let upgrade = request.headers().get("upgrade")?;
            if !upgrade.is_some_and(|upgrade| upgrade.eq_ignore_ascii_case("websocket")) {
                return with_security_headers(Response::error("expected a WebSocket", 426)?);
            }
            return with_security_headers(Response::error("malformed subscription", 400)?);
        }
    };
    let upgrade = request.headers().get("upgrade")?;
    if !upgrade.is_some_and(|upgrade| upgrade.eq_ignore_ascii_case("websocket")) {
        return with_security_headers(Response::error("expected a WebSocket", 426)?);
    }
    // Validate Origin on WebSocket upgrades whenever a browser sends one (CSWSH defense).
    if let Some(origin) = request.headers().get("origin")?
        && !auth::ws_origin_matches(&origin, &url)
    {
        return with_security_headers(Response::error("cross-origin WebSocket refused", 403)?);
    }

    // Require a valid sign-in cookie before upgrading unauthenticated first-frame WS sockets
    // whenever server PASSWORD authentication is configured, preventing unauthenticated
    // third parties from exhausting an identity's pending WebSocket cap.
    let claims = auth::signed_in(&request, env);
    if auth::password_configured(env) && claims.is_none() {
        return with_security_headers(Response::error("sign in to this server to use it", 403)?);
    }
    let Some(identity_key) = crate::decode_hex_fixed::<32>(&identity_hex) else {
        return with_security_headers(Response::error("malformed identity", 400)?);
    };
    if XEdDSAPublicKey::new(&identity_key).is_err() {
        return with_security_headers(Response::error("invalid identity key", 400)?);
    }
    // Validate and normalize the relay audience before forwarding to the Durable Object.
    let audience = server_id(env, &request)?;

    // Clone incoming headers, stripping all internal auth headers so a client can never spoof
    // them toward the Durable Object.
    let incoming_headers: Vec<(String, String)> = request.headers().entries().collect();
    let forward_headers = Headers::new();
    for (name, value) in forwarded_subscribe_headers(
        incoming_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
        &identity_key,
        &audience,
        claims.map(|c| c.expires),
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

    pub(crate) fn legacy_unbound_subscribe(
        identity: &XEdDSAPrivateKey,
        timestamp: u64,
    ) -> SubscribeRequest {
        let key = identity.compute_public_key().to_bytes();
        let mut msg = b"notify.v1/subscribe".to_vec();
        msg.extend_from_slice(&key);
        msg.extend_from_slice(&timestamp.to_le_bytes());
        SubscribeRequest {
            identity_key: Bytes::copy_from_slice(&key),
            timestamp,
            signature: Bytes::copy_from_slice(&identity.sign(msg)),
            audience: String::new(),
        }
    }

    #[test]
    fn legacy_v1_paths_are_detected_and_return_deprecation_error() {
        for path in [
            "/handshake.v1.HandshakeService/Publish",
            "/handshake.v1.HandshakeService/FetchBundle",
            "/handshake.v1.HandshakeService/SendInitialMessage",
            "/handshake.v1.HandshakeService/TakeInitialMessages",
            "/mailbox.v1.MailboxService/Push",
            "/mailbox.v1.MailboxService/Fetch",
            "/handshake.v1.HandshakeService/Unknown",
            "/mailbox.v1.MailboxService/Unknown",
        ] {
            assert!(connect::is_legacy_v1_path(path));
            assert_eq!(resolve_route(path), Some(Route::LegacyV1Deprecated));
        }

        for procedure in AttachmentProcedure::ALL {
            assert!(!connect::is_legacy_v1_path(procedure.path()));
            assert_eq!(
                resolve_route(procedure.path()),
                Some(Route::Attachment(procedure))
            );
        }
        for procedure in ProcedureV2::ALL {
            assert!(!connect::is_legacy_v1_path(procedure.path()));
            assert_eq!(resolve_route(procedure.path()), Some(Route::V2(procedure)));
        }
        assert_eq!(resolve_route("/unknown.v1.Service/Method"), None);

        let err = legacy_v1_connect_error();
        assert_eq!(err.status, 501);
        assert_eq!(err.content_type, connect::ERROR_CONTENT_TYPE);
        let json: serde_json::Value = serde_json::from_slice(&err.body).unwrap();
        assert_eq!(json["code"], "unimplemented");
        assert_eq!(json["message"], LEGACY_V1_CONNECT_MESSAGE);
    }

    #[test]
    fn subscribe_query_rejects_legacy_request_param_and_accepts_identity() {
        let legacy_url = Url::parse("https://relay.example/notifications?request=abc123").unwrap();
        assert_eq!(
            parse_subscribe_query(&legacy_url),
            SubscribeQuery::LegacyRequest
        );

        let both_url =
            Url::parse("https://relay.example/notifications?identity=0011&request=legacy_payload")
                .unwrap();
        assert_eq!(
            parse_subscribe_query(&both_url),
            SubscribeQuery::LegacyRequest
        );

        let v2_url = Url::parse("https://relay.example/notifications?identity=deadbeef").unwrap();
        assert_eq!(
            parse_subscribe_query(&v2_url),
            SubscribeQuery::Identity("deadbeef".to_string())
        );

        let missing_url = Url::parse("https://relay.example/notifications").unwrap();
        assert_eq!(parse_subscribe_query(&missing_url), SubscribeQuery::Missing);
    }

    #[test]
    fn server_info_config_reflects_pq_enabled_and_disables_legacy_v1() {
        let on = server_info_config("relay.example".into(), true);
        assert!(on.pq_enabled);
        assert!(!on.supported_suites.is_empty());
        assert!(on.pq_ratchet_supported);
        assert!(!on.legacy_v1_enabled);
        assert!(!on.allow_unsigned_fetch);

        let off = server_info_config("relay.example".into(), false);
        assert!(!off.pq_enabled);
        assert!(off.supported_suites.is_empty());
        assert!(!off.pq_ratchet_supported);
        assert!(!off.legacy_v1_enabled);
        assert!(!off.allow_unsigned_fetch);

        assert!(ProcedureV2::GetManifest.disabled_without_pq());
        for proc in ProcedureV2::ALL {
            if proc != ProcedureV2::GetManifest {
                assert!(!proc.disabled_without_pq());
            }
        }
    }

    #[test]
    fn internal_subscribe_headers_are_filtered_case_insensitively() {
        for header in [
            objects::HEADER_DEPLOYMENT_AUTH,
            objects::HEADER_PENDING_IDENTITY,
            objects::HEADER_SUBSCRIBE_AUDIENCE,
            objects::HEADER_SESSION_EXPIRES,
            objects::HEADER_SUBSCRIBE_SIG,
            objects::HEADER_SUBSCRIBE_TS,
        ] {
            assert!(is_internal_subscribe_header(header));
            assert!(is_internal_subscribe_header(&header.to_ascii_uppercase()));
        }
        assert!(!is_internal_subscribe_header("upgrade"));
        assert!(!is_internal_subscribe_header("cookie"));

        let id = [0x42u8; 32];
        let forwarded = forwarded_subscribe_headers(
            [
                ("upgrade", "websocket"),
                ("cookie", "session=abc"),
                ("X-E2EE-Deployment-Auth", "0"),
                ("x-e2ee-pending-identity", "00"),
                ("X-E2EE-Session-Expires", "999999999999"),
                ("X-E2EE-Subscribe-Sig", "deadbeef"),
                ("x-e2ee-subscribe-ts", "9999999999"),
                ("X-E2EE-Subscribe-Audience", "evil.example"),
            ],
            &id,
            "relay.example:443",
            Some(123_456),
        );
        assert!(forwarded.contains(&("upgrade".into(), "websocket".into())));
        assert!(forwarded.contains(&("cookie".into(), "session=abc".into())));
        assert!(!forwarded.iter().any(
            |(k, _)| k.eq_ignore_ascii_case(objects::HEADER_SUBSCRIBE_SIG)
                || k.eq_ignore_ascii_case(objects::HEADER_SUBSCRIBE_TS)
        ));
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
                .filter(|(k, _)| k.eq_ignore_ascii_case(objects::HEADER_PENDING_IDENTITY))
                .collect::<Vec<_>>(),
            vec![&(objects::HEADER_PENDING_IDENTITY.to_string(), hex(&id))]
        );
        assert_eq!(
            forwarded
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(objects::HEADER_SUBSCRIBE_AUDIENCE))
                .collect::<Vec<_>>(),
            vec![&(
                objects::HEADER_SUBSCRIBE_AUDIENCE.to_string(),
                "relay.example:443".to_string()
            )]
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
    fn subscribe_requires_audience_bound_v2_and_rejects_legacy_unbound() {
        let identity = XEdDSAPrivateKey::generate();
        let key = identity.compute_public_key().to_bytes();
        let now = 1_000_000;
        let bound =
            SubscribeRequest::sign_for_audience(&identity, "https://Relay.Example", now).unwrap();
        let legacy = legacy_unbound_subscribe(&identity, now);
        let mut mislabeled = legacy.clone();
        mislabeled.audience = "relay.example".into();

        assert_eq!(
            verify_subscribe_request(&bound, "relay.example", now).unwrap(),
            key
        );
        assert_eq!(
            verify_subscribe_request(&bound, "other.example", now)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidSignature
        );
        assert_eq!(
            verify_subscribe_request(&mislabeled, "relay.example", now)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidSignature
        );
        assert_eq!(
            verify_subscribe_request(&legacy, "relay.example", now)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidSignature
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
            let query_audience = subscribe_audience(authority.clone());
            let attachment = protocol::normalize_audience(&subscribe_audience(authority)).unwrap();
            for audience in [query_audience, subscribe_audience(attachment)] {
                assert!(verify_subscribe_request(&signed, &audience, now).is_ok());
                assert!(verify_subscribe_request(&plain_host, &audience, now).is_err());
            }
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

            // Stops immediately once cumulative chunks cross `limit` (the error chunk is never polled).
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
    fn conformance_auth_requires_sign_in_or_valid_token() {
        assert!(!conformance_authorized(None, None, false));
        assert!(!conformance_authorized(Some("secret"), None, false));
        assert!(!conformance_authorized(
            Some("secret"),
            Some("wrong"),
            false
        ));
        assert!(!conformance_authorized(None, Some("secret"), false));
        assert!(conformance_authorized(
            Some("secret"),
            Some("secret"),
            false
        ));
        assert!(conformance_authorized(None, None, true));
        assert!(conformance_authorized(Some("secret"), Some("wrong"), true));

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
