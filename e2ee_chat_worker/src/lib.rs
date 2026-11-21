//! The E2EE chat server as a Cloudflare Worker: the v2 handshake, v2 mailbox, and attachment
//! services over the Connect protocol, kept in Durable Objects and R2, and notifications over
//! hibernating WebSockets. See the README.

mod auth;
mod objects;
mod store;

use std::time::Duration;

use futures_util::StreamExt;
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

/// Answers the Connect calls; the web client's files are served before the Worker runs.
#[event(fetch)]
async fn fetch(request: Request, env: Env, _context: Context) -> Result<Response> {
    #[cfg(feature = "conformance")]
    if request.path() == "/conformance" && request.method() == Method::Post {
        // A failure panics, which fails the request.
        let store = Store::new(&env, MailboxLimits::default().max_message_size)?;
        storage::testing::attachment_store(&store).await;
        storage::testing::pq_handshake_store(&store).await;
        storage::testing::idempotent_mailbox_store(&store).await;
        return Response::ok("the storage conformance suites passed");
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
                Route::V2(procedure) => call_v2(request, &env, procedure).await?,
                Route::Attachment(procedure) => call_attachment(request, &env, procedure).await?,
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

async fn call_attachment(
    mut request: Request,
    env: &Env,
    procedure: AttachmentProcedure,
) -> Result<Response> {
    // Check sign-in BEFORE buffering the request body!
    if writes_attachment(procedure) && auth::signed_in(&request, env).is_none() {
        let message = "sign in to this server to use it";
        return respond(connect::error(ErrorKind::SignInRequired, message));
    }
    let content_type = request.headers().get("content-type")?;
    let limits = MailboxLimits::default();
    let response = match read_body(&mut request, MAX_BODY).await? {
        Some(body) => {
            let body = Bytes::from(body);
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
                .map_err(|e| worker::Error::RustError(e.to_string()))?;
            connect::handle_attachments(&attachments, procedure, content_type.as_deref(), &body)
                .await
        }
        None => connect::error(ErrorKind::LimitExceeded, "request too large"),
    };
    respond(response)
}

async fn call_v2(mut request: Request, env: &Env, procedure: ProcedureV2) -> Result<Response> {
    let pq_enabled = pq_runtime_enabled(env);
    if !pq_enabled && is_pq_only_v2(procedure) {
        return respond(connect::error(
            ErrorKind::Unimplemented,
            "post-quantum routes are disabled",
        ));
    }
    // Check sign-in BEFORE buffering the request body!
    if writes_v2(procedure) && auth::signed_in(&request, env).is_none() {
        let message = "sign in to this server to use it";
        return respond(connect::error(ErrorKind::SignInRequired, message));
    }
    let content_type = request.headers().get("content-type")?;
    let server_id = server_id(env, &request)?;
    let limits = MailboxLimits::default();
    let response = match read_body(&mut request, MAX_BODY).await? {
        Some(body) => {
            let body = Bytes::from(body);
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
            connect::handle_v2(
                &handshake,
                &mailbox,
                procedure,
                content_type.as_deref(),
                &body,
            )
            .await
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

/// Adds `Date`, `x-e2ee-pq`, and Connect CORS headers (exposing `x-e2ee-deprecated`).
fn with_cors(response: Response, pq_enabled: bool) -> Result<Response> {
    with_metadata(response, pq_enabled)?.with_cors(&cors_policy([Method::Post, Method::Options]))
}

/// Adds `Date`, `x-e2ee-pq`, and `/notifications` CORS headers (exposing `x-e2ee-deprecated`).
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

/// Adds `Date` and `x-e2ee-pq` response headers.
fn with_metadata(mut response: Response, pq_enabled: bool) -> Result<Response> {
    let now = worker::js_sys::Date::new_0().to_utc_string();
    response.headers_mut().set("date", &String::from(now))?;
    response
        .headers_mut()
        .set(PQ_HEADER, if pq_enabled { "1" } else { "0" })?;
    Ok(response)
}

/// The HTTP response of a Connect call's `response`.
fn respond(response: connect::Response) -> Result<Response> {
    let headers = Headers::new();
    headers.set("content-type", response.content_type)?;
    Ok(Response::from_bytes(response.body)?
        .with_status(response.status)
        .with_headers(headers))
}

/// Whether calls to attachment `procedure` require sign-in.
fn writes_attachment(procedure: AttachmentProcedure) -> bool {
    matches!(procedure, AttachmentProcedure::StartUpload)
}

/// Whether calls to v2 `procedure` write or consume prekeys, requiring sign-in.
fn writes_v2(procedure: ProcedureV2) -> bool {
    matches!(
        procedure,
        ProcedureV2::PublishV2
            | ProcedureV2::RefillPrekeys
            | ProcedureV2::ClaimBundle
            | ProcedureV2::SendInitialV2
            | ProcedureV2::PushV2
    )
}

/// V2 procedures that are completely disabled when `PQ_ENABLED="false"` without inspecting the
/// request body. Other v2 procedures (`PublishV2`, `RefillPrekeys`, `ClaimBundle`,
/// `SendInitialV2`, `ListInitialMessages`, `AckInitialMessages`, `PushV2`, `FetchSigned`) enforce
/// fine-grained `PQ_ENABLED="false"` rollback rules inside `HandshakeV2Server` / `MailboxV2Server`
/// so existing PQ users can drain in-flight handshakes and publish signed OFF manifests.
fn is_pq_only_v2(procedure: ProcedureV2) -> bool {
    matches!(procedure, ProcedureV2::GetManifest)
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
        objects::HEADER_SUBSCRIBE_SIG,
        objects::HEADER_SUBSCRIBE_TS,
    ]
    .iter()
    .any(|header| name.eq_ignore_ascii_case(header))
}

/// Strip all 5 historical internal subscribe headers case-insensitively and append the trusted
/// Worker-computed auth, pending identity, and canonical audience headers for forwarding to the
/// Identity Durable Object (safe across rolling deploys with older DO instances).
fn forwarded_subscribe_headers<'a>(
    incoming: impl IntoIterator<Item = (&'a str, &'a str)>,
    identity_key: &[u8; 32],
    audience: &str,
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
    forwarded
}

fn deployment_auth_satisfied(password_configured: bool, signed_in: bool) -> bool {
    !password_configured || signed_in
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
                return Response::error("expected a WebSocket", 426);
            }
            return Response::error("malformed subscription", 400);
        }
    };
    let upgrade = request.headers().get("upgrade")?;
    if !upgrade.is_some_and(|upgrade| upgrade.eq_ignore_ascii_case("websocket")) {
        return Response::error("expected a WebSocket", 426);
    }

    // Require a valid sign-in cookie before upgrading unauthenticated first-frame WS sockets
    // whenever server PASSWORD authentication is configured, preventing unauthenticated
    // third parties from exhausting an identity's pending WebSocket cap.
    let deployment_authenticated = deployment_auth_satisfied(
        auth::password_configured(env),
        auth::signed_in(&request, env).is_some(),
    );
    if !deployment_authenticated {
        return Response::error("sign in to this server to use it", 403);
    }
    let Some(identity_key) = crate::decode_hex_fixed::<32>(&identity_hex) else {
        return Response::error("malformed identity", 400);
    };
    if XEdDSAPublicKey::new(&identity_key).is_err() {
        return Response::error("invalid identity key", 400);
    }
    // Validate and normalize the relay audience before forwarding to the Durable Object.
    let audience = server_id(env, &request)?;

    // Clone incoming headers, stripping all 5 historical internal auth headers so a client can
    // never spoof a retired header toward an older DO instance during rolling deploys, and attach
    // the canonical audience header so older DO instances continue accepting v2 subscribers.
    let incoming_headers: Vec<(String, String)> = request.headers().entries().collect();
    let forward_headers = Headers::new();
    for (name, value) in forwarded_subscribe_headers(
        incoming_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
        &identity_key,
        &audience,
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

/// The body of `request`; `None` once it grows past `limit` bytes, which stops reading it, so a
/// large body never sits in memory.
pub(crate) async fn read_body(request: &mut Request, limit: usize) -> Result<Option<Vec<u8>>> {
    if request.inner().body().is_none() {
        return Ok(Some(vec![]));
    }
    let mut stream = request.stream()?;
    let mut body = vec![];
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > limit {
            return Ok(None);
        }
        body.extend(chunk);
    }
    Ok(Some(body))
}

/// How long the variable `name` says, in days, which may be a fraction, e.g. `0.5`; `default`
/// days unless it says a number that is not negative.
pub(crate) fn period(env: &Env, name: &str, default: u64) -> Duration {
    let days = env
        .var(name)
        .ok()
        .and_then(|days| days.to_string().parse::<f64>().ok())
        .filter(|days| days.is_finite() && *days >= 0.0)
        .unwrap_or(default as f64);
    Duration::try_from_secs_f64(days * 24.0 * 60.0 * 60.0).unwrap_or(Duration::MAX)
}

/// `period` in milliseconds, as the runtime's clock counts.
pub(crate) fn millis(period: Duration) -> u64 {
    u64::try_from(period.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::pin,
        task::{Context as TaskContext, Poll, Waker},
    };

    use prost::Message as _;
    use protocol::{
        attachment::{
            DeleteAttachmentRequest, GetChunkRequest, GetChunkResponse, PutChunkRequest,
            StartUploadRequest, StartUploadResponse,
        },
        handshake_v2::{
            CapabilityManifest, ClaimBundleRequest, ClaimBundleResponse, GetServerInfoRequest,
            GetServerInfoResponse, PublishV2Request, sign_manifest,
        },
        mailbox_v2::{FetchSignedRequest, FetchSignedResponse, PushV2Request, PushV2Response},
    };
    use sha2::{Digest, Sha256};
    use storage::MemoryStore;
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

    fn legacy_unbound_subscribe(identity: &XEdDSAPrivateKey, timestamp: u64) -> SubscribeRequest {
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
        assert_eq!(DEPRECATED_HEADER, "x-e2ee-deprecated");
        assert_eq!(DEPRECATED_V1_VALUE, "v1");
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
        assert_eq!(
            LEGACY_V1_NOTIFICATIONS_MESSAGE,
            "Legacy v1 notifications are deprecated and removed. Please refresh or upgrade the app to continue."
        );
    }

    #[test]
    fn attachment_sign_in_is_required_only_for_start_upload() {
        assert!(writes_attachment(AttachmentProcedure::StartUpload));
        assert!(!writes_attachment(AttachmentProcedure::PutChunk));
        assert!(!writes_attachment(AttachmentProcedure::GetChunk));
        assert!(!writes_attachment(AttachmentProcedure::DeleteAttachment));
    }

    #[test]
    fn attachment_v1_connect_handlers_round_trip() {
        block_on(async {
            let store = MemoryStore::default();
            let attachments = AttachmentServer::builder(store).build().unwrap();

            let delete_token = Bytes::from_static(&[0x33; 32]);
            let delete_hash = Bytes::copy_from_slice(&Sha256::digest(&delete_token));
            let start_req = StartUploadRequest {
                chunks: 1,
                delete_hash,
            };
            let start_resp = connect::handle_attachments(
                &attachments,
                AttachmentProcedure::StartUpload,
                Some(connect::CONTENT_TYPE),
                &start_req.encode_to_vec(),
            )
            .await;
            assert_eq!(start_resp.status, 200);
            let started = StartUploadResponse::decode(start_resp.body.as_slice()).unwrap();

            let payload = Bytes::from_static(b"encrypted-attachment-chunk");
            let put_req = PutChunkRequest {
                id: started.id.clone(),
                index: 0,
                data: payload.clone(),
                upload_token: started.upload_token,
            };
            let put_resp = connect::handle_attachments(
                &attachments,
                AttachmentProcedure::PutChunk,
                Some(connect::CONTENT_TYPE),
                &put_req.encode_to_vec(),
            )
            .await;
            assert_eq!(put_resp.status, 200);

            let get_req = GetChunkRequest {
                id: started.id.clone(),
                index: 0,
            };
            let get_resp = connect::handle_attachments(
                &attachments,
                AttachmentProcedure::GetChunk,
                Some(connect::CONTENT_TYPE),
                &get_req.encode_to_vec(),
            )
            .await;
            assert_eq!(get_resp.status, 200);
            let got = GetChunkResponse::decode(get_resp.body.as_slice()).unwrap();
            assert_eq!(got.data, payload);

            let del_req = DeleteAttachmentRequest {
                id: started.id,
                token: delete_token,
            };
            let del_resp = connect::handle_attachments(
                &attachments,
                AttachmentProcedure::DeleteAttachment,
                Some(connect::CONTENT_TYPE),
                &del_req.encode_to_vec(),
            )
            .await;
            assert_eq!(del_resp.status, 200);
        });
    }

    #[test]
    fn pq_enabled_false_rollback_advertises_disabled_flags_and_serves_v2_classical_flow() {
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

        assert!(is_pq_only_v2(ProcedureV2::GetManifest));
        for proc in ProcedureV2::ALL {
            if proc != ProcedureV2::GetManifest {
                assert!(!is_pq_only_v2(proc));
            }
        }

        block_on(async {
            let server_id = "relay.example".to_string();
            let info = server_info_config(server_id.clone(), false);
            let handshake = HandshakeV2Server::new(MemoryStore::default(), info.clone());
            let mailbox = MailboxV2Server::builder(MemoryStore::default())
                .server_id(server_id.clone())
                .supported_suites(info.supported_suites)
                .allow_pq_drain(true)
                .build();

            let info_resp = connect::handle_v2(
                &handshake,
                &mailbox,
                ProcedureV2::GetServerInfo,
                Some(connect::CONTENT_TYPE),
                &GetServerInfoRequest {}.encode_to_vec(),
            )
            .await;
            assert_eq!(info_resp.status, 200);
            let server_info = GetServerInfoResponse::decode(info_resp.body.as_slice()).unwrap();
            assert!(!server_info.pq_enabled);
            assert!(server_info.supported_suites.is_empty());
            assert!(!server_info.pq_ratchet_supported);
            assert!(!server_info.legacy_v1_enabled);
            assert!(!server_info.allow_unsigned_fetch);

            // Publish signed OFF manifest while PQ_ENABLED="false".
            let bob = XEdDSAPrivateKey::generate();
            let alice = XEdDSAPrivateKey::generate();
            let spk = XEdDSAPrivateKey::generate().compute_public_key().to_bytes();
            let opk = XEdDSAPrivateKey::generate().compute_public_key().to_bytes();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let mut manifest = CapabilityManifest {
                audience: server_id.clone(),
                identity_key: Bytes::new(),
                manifest_seq: 1,
                generation: 1,
                issued_at: now,
                expires_at: now + 60_000,
                pq_enabled: false,
                strict_pq: false,
                pq_ratchet_supported: false,
                offered_suites: vec![],
                signed_prekey: Bytes::copy_from_slice(&spk),
                pq_last_resort: vec![],
                signature: Bytes::new(),
            };
            sign_manifest(&bob, &mut manifest).unwrap();
            let spk_sig = bob.sign(spk);
            let publish_req =
                PublishV2Request::sign(&bob, manifest, Some(spk_sig), &[opk], vec![], vec![], now)
                    .unwrap();
            let publish_resp = connect::handle_v2(
                &handshake,
                &mailbox,
                ProcedureV2::PublishV2,
                Some(connect::CONTENT_TYPE),
                &publish_req.encode_to_vec(),
            )
            .await;
            assert_eq!(publish_resp.status, 200);

            // ClaimBundle returns classical fallback bundle without PQ prekeys.
            let bob_pub = bob.compute_public_key().to_bytes();
            let claim_req = ClaimBundleRequest {
                identity_key: Bytes::copy_from_slice(&bob_pub),
                preferred_suites: vec![1, 2],
            };
            let claim_resp = connect::handle_v2(
                &handshake,
                &mailbox,
                ProcedureV2::ClaimBundle,
                Some(connect::CONTENT_TYPE),
                &claim_req.encode_to_vec(),
            )
            .await;
            assert_eq!(claim_resp.status, 200);
            let claimed = ClaimBundleResponse::decode(claim_resp.body.as_slice()).unwrap();
            assert_eq!(claimed.signed_prekey.as_ref(), &spk);
            assert_eq!(claimed.one_time_prekey.as_deref(), Some(opk.as_slice()));
            assert!(claimed.pq_last_resort.is_none());
            assert!(claimed.pq_one_time_prekey.is_none());

            // PushV2 and FetchSigned continue working cleanly during PQ_ENABLED="false" rollback.
            let alice_pub = alice.compute_public_key().to_bytes();
            let mut push_req = PushV2Request {
                sender: Bytes::copy_from_slice(&alice_pub),
                recipient: Bytes::copy_from_slice(&bob_pub),
                message: Some(Default::default()),
                initial_message: None,
                delivery_hash: Bytes::new(),
                client_message_id: Bytes::copy_from_slice(&[0x77; 16]),
            };
            let msg = push_req.message.as_mut().unwrap();
            msg.header = Bytes::from_static(b"hdr");
            msg.content = Bytes::from_static(b"ciphertext");
            let push_resp = connect::handle_v2(
                &handshake,
                &mailbox,
                ProcedureV2::PushV2,
                Some(connect::CONTENT_TYPE),
                &push_req.encode_to_vec(),
            )
            .await;
            assert_eq!(push_resp.status, 200);
            let pushed = PushV2Response::decode(push_resp.body.as_slice()).unwrap();
            assert_eq!(pushed.sequence, 1);

            let fetch_req =
                FetchSignedRequest::sign(&bob, &server_id, &alice_pub, 0, 10, 0, vec![], now)
                    .unwrap();
            let fetch_resp = connect::handle_v2(
                &handshake,
                &mailbox,
                ProcedureV2::FetchSigned,
                Some(connect::CONTENT_TYPE),
                &fetch_req.encode_to_vec(),
            )
            .await;
            assert_eq!(fetch_resp.status, 200);
            let fetched = FetchSignedResponse::decode(fetch_resp.body.as_slice()).unwrap();
            assert_eq!(fetched.messages.len(), 1);
            assert_eq!(
                fetched.messages[0]
                    .message
                    .as_ref()
                    .unwrap()
                    .content
                    .as_ref(),
                b"ciphertext"
            );
        });
    }

    #[test]
    fn internal_subscribe_headers_are_filtered_case_insensitively() {
        for header in [
            objects::HEADER_DEPLOYMENT_AUTH,
            objects::HEADER_PENDING_IDENTITY,
            objects::HEADER_SUBSCRIBE_AUDIENCE,
            objects::HEADER_SUBSCRIBE_SIG,
            objects::HEADER_SUBSCRIBE_TS,
        ] {
            assert!(is_internal_subscribe_header(header));
            assert!(is_internal_subscribe_header(&header.to_ascii_uppercase()));
        }
        assert!(is_internal_subscribe_header("X-E2EE-Deployment-Auth"));
        assert!(is_internal_subscribe_header("X-E2EE-Pending-Identity"));
        assert!(is_internal_subscribe_header("X-E2EE-Subscribe-Audience"));
        assert!(is_internal_subscribe_header("X-E2EE-Subscribe-Sig"));
        assert!(is_internal_subscribe_header("X-E2EE-Subscribe-Ts"));
        assert!(!is_internal_subscribe_header("upgrade"));
        assert!(!is_internal_subscribe_header("cookie"));

        let id = [0x42u8; 32];
        let forwarded = forwarded_subscribe_headers(
            [
                ("upgrade", "websocket"),
                ("cookie", "session=abc"),
                ("X-E2EE-Deployment-Auth", "0"),
                ("x-e2ee-pending-identity", "00"),
                ("X-E2EE-Subscribe-Sig", "deadbeef"),
                ("x-e2ee-subscribe-ts", "9999999999"),
                ("X-E2EE-Subscribe-Audience", "evil.example"),
            ],
            &id,
            "relay.example:443",
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
    }

    #[test]
    fn deployment_auth_requires_sign_in_when_a_password_is_configured() {
        assert!(deployment_auth_satisfied(false, false));
        assert!(deployment_auth_satisfied(false, true));
        assert!(!deployment_auth_satisfied(true, false));
        assert!(deployment_auth_satisfied(true, true));
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
}
