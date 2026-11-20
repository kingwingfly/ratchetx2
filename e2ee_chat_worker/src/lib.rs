//! The E2EE chat server as a Cloudflare Worker: the handshake, mailbox and attachment services
//! over the Connect protocol, kept in Durable Objects and R2, and notifications over WebSockets.
//! See the README.

mod auth;
mod objects;
mod store;

use std::time::Duration;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use prost::{Message, bytes::Bytes};
#[cfg(feature = "pq")]
use protocol::{
    connect::ProcedureV2,
    handshake_v2::{HandshakeV2Server, ServerInfoConfig},
    mailbox_v2::MailboxV2Server,
};
use protocol::{
    ErrorKind,
    attachment::{AttachmentLimits, AttachmentServer},
    connect::{self, PROTOCOL_VERSION_HEADER, Procedure},
    handshake::HandshakeServer,
    mailbox::{MailboxLimits, MailboxServer},
    notify::SubscribeRequest,
};
use worker::{
    Context, Cors, Date, Env, Headers, Method, Request, RequestInit, Response, Result, event,
};
use xeddsa::XEdDSAPublicKey;

pub use crate::objects::{Attachment, Identity};
use crate::store::Store;
pub(crate) use crate::store::hex;

/// Where a client opens the WebSocket of its notifications.
const NOTIFICATIONS_PATH: &str = "/notifications";
/// Header advertising whether post-quantum routes are enabled at runtime (`"1"` or `"0"`).
const PQ_HEADER: &str = "x-e2ee-pq";
/// The binding of the R2 bucket.
pub(crate) const BUCKET: &str = "BUCKET";
/// The largest request body: the largest message, 4 MiB - 64 KiB, with room for the rest of a
/// push.
const MAX_BODY: usize = 4 << 20;

enum Route {
    V1(Procedure),
    #[cfg(feature = "pq")]
    V2(ProcedureV2),
}

/// Answers the Connect calls; the web client's files are served before the Worker runs.
#[event(fetch)]
async fn fetch(request: Request, env: Env, _context: Context) -> Result<Response> {
    #[cfg(feature = "conformance")]
    if request.path() == "/conformance" && request.method() == Method::Post {
        // A failure panics, which fails the request.
        let store = Store::new(&env, MailboxLimits::default().max_message_size)?;
        storage::testing::handshake_store(&store).await;
        storage::testing::mailbox_store(&store).await;
        storage::testing::attachment_store(&store).await;
        #[cfg(feature = "pq")]
        {
            storage::testing::pq_handshake_store(&store).await;
            storage::testing::idempotent_mailbox_store(&store).await;
        }
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
    let route = Procedure::from_path(&path).map(Route::V1);
    #[cfg(feature = "pq")]
    let route = route.or_else(|| ProcedureV2::from_path(&path).map(Route::V2));
    let Some(route) = route else {
        return Response::error("not found", 404);
    };

    let response = match request.method() {
        // A CORS preflight, which the headers below answer.
        Method::Options => Response::empty()?,
        Method::Post => match route {
            Route::V1(procedure) => call_v1(request, &env, procedure).await?,
            #[cfg(feature = "pq")]
            Route::V2(procedure) => call_v2(request, &env, procedure).await?,
        },
        _ => {
            let headers = Headers::new();
            headers.set("allow", "POST, OPTIONS")?;
            Response::error("method not allowed", 405)?.with_headers(headers)
        }
    };
    with_metadata(response, pq_enabled)?.with_cors(
        &Cors::new()
            .with_origins(["*"])
            .with_methods([Method::Post, Method::Options])
            .with_allowed_headers(["content-type", PROTOCOL_VERSION_HEADER])
            .with_exposed_headers(["date", PQ_HEADER])
            .with_max_age(86400),
    )
}

async fn call_v1(mut request: Request, env: &Env, procedure: Procedure) -> Result<Response> {
    if !legacy_v1_enabled(env) && is_legacy_v1_handshake_or_mailbox(procedure) {
        return respond(connect::error(
            ErrorKind::Unimplemented,
            "legacy v1 routes are disabled",
        ));
    }
    if procedure == Procedure::Fetch && !allow_unsigned_fetch(env) {
        return respond(connect::error(
            ErrorKind::InvalidSignature,
            "unsigned mailbox fetch is disabled; use mailbox.v2 FetchSigned",
        ));
    }
    // Check sign-in BEFORE buffering the request body!
    if writes(procedure) && auth::signed_in(&request, env).is_none() {
        let message = "sign in to this server to use it";
        return respond(connect::error(ErrorKind::SignInRequired, message));
    }
    let content_type = request.headers().get("content-type")?;
    let limits = MailboxLimits::default();
    let response = match read_body(&mut request, MAX_BODY).await? {
        Some(body) => {
            let body = Bytes::from(body);
            let store = Store::new(env, limits.max_message_size)?;
            let handshake = HandshakeServer::new(store.clone());
            let mailbox = MailboxServer::builder(store.clone()).limits(limits).build();
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
            connect::handle(
                &handshake,
                &mailbox,
                &attachments,
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

#[cfg(feature = "pq")]
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
            let mut info = ServerInfoConfig::new(server_id.clone());
            info.pq_enabled = pq_enabled;
            info.legacy_v1_enabled = legacy_v1_enabled(env);
            info.allow_unsigned_fetch = allow_unsigned_fetch(env);
            if !pq_enabled {
                info.supported_suites.clear();
                info.pq_ratchet_supported = false;
            }
            let supported_suites = info.supported_suites.clone();
            let handshake = HandshakeV2Server::new(store.clone(), info);
            let mailbox = MailboxV2Server::builder(store)
                .server_id(server_id)
                .supported_suites(supported_suites)
                .limits(limits)
                .build();
            connect::handle_v2(&handshake, &mailbox, procedure, content_type.as_deref(), &body)
                .await
        }
        None => connect::error(ErrorKind::LimitExceeded, "request too large"),
    };
    respond(response)
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

/// Whether calls to v1 `procedure` write or consume prekeys, requiring sign-in.
fn writes(procedure: Procedure) -> bool {
    matches!(
        procedure,
        Procedure::Publish
            | Procedure::FetchBundle
            | Procedure::SendInitialMessage
            | Procedure::Push
            | Procedure::StartUpload
    )
}

fn is_legacy_v1_handshake_or_mailbox(procedure: Procedure) -> bool {
    matches!(
        procedure,
        Procedure::Publish
            | Procedure::FetchBundle
            | Procedure::SendInitialMessage
            | Procedure::TakeInitialMessages
            | Procedure::Push
            | Procedure::Fetch
    )
}

#[cfg(feature = "pq")]
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

#[cfg(feature = "pq")]
fn is_pq_only_v2(procedure: ProcedureV2) -> bool {
    matches!(
        procedure,
        ProcedureV2::PublishV2
            | ProcedureV2::RefillPrekeys
            | ProcedureV2::GetManifest
            | ProcedureV2::ClaimBundle
            | ProcedureV2::SendInitialV2
            | ProcedureV2::ListInitialMessages
            | ProcedureV2::AckInitialMessages
    )
}

/// Whether post-quantum routes and storage are enabled at runtime.
fn pq_runtime_enabled(env: &Env) -> bool {
    #[cfg(feature = "pq")]
    {
        env_bool(env, "PQ_ENABLED", true)
    }
    #[cfg(not(feature = "pq"))]
    {
        let _ = env;
        false
    }
}

/// Whether legacy v1 handshake/mailbox routes are enabled (default `"true"` for TUI compat).
fn legacy_v1_enabled(env: &Env) -> bool {
    env_bool(env, "LEGACY_V1", true)
}

/// Whether unsigned v1 `Mailbox::Fetch` is permitted (default `"true"` for TUI transition).
fn allow_unsigned_fetch(env: &Env) -> bool {
    env_bool(env, "ALLOW_UNSIGNED_FETCH", true)
}

/// Canonical server audience identifier: `SERVER_ID` env var if non-empty, else request URL host.
#[cfg(feature = "pq")]
fn server_id(env: &Env, request: &Request) -> Result<String> {
    if let Ok(var) = env.var("SERVER_ID") {
        let trimmed = var.to_string();
        let trimmed = trimmed.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let url = request.url()?;
    let host = url.host_str().unwrap_or("localhost");
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

fn env_bool(env: &Env, name: &str, default: bool) -> bool {
    env.var(name)
        .ok()
        .and_then(|v| match v.to_string().trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

/// Hand a WebSocket asking for an identity's notifications to its object.
///
/// Supports BOTH:
/// 1. Legacy query-param auth: `GET /notifications?request=<base64url(SubscribeRequest)>`
/// 2. First-frame auth: `GET /notifications?identity=<64-hex-pubkey>`, followed by a first
///    WebSocket binary or base64url text frame carrying `SubscribeRequest`.
async fn subscribe(request: Request, env: &Env) -> Result<Response> {
    if request.method() != Method::Get {
        let headers = Headers::new();
        headers.set("allow", "GET")?;
        return Ok(Response::error("method not allowed", 405)?.with_headers(headers));
    }
    let upgrade = request.headers().get("upgrade")?;
    if !upgrade.is_some_and(|upgrade| upgrade.eq_ignore_ascii_case("websocket")) {
        return Response::error("expected a WebSocket", 426);
    }
    let url = request.url()?;
    let mut query_request = None;
    let mut query_identity = None;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "request" => query_request = Some(value.into_owned()),
            "identity" => query_identity = Some(value.into_owned()),
            _ => {}
        }
    }

    // Clone incoming headers and strip any client-supplied internal auth headers.
    let forward_headers = Headers::new();
    for (name, value) in request.headers().entries() {
        let lower = name.to_ascii_lowercase();
        if lower == objects::HEADER_SUBSCRIBE_SIG
            || lower == objects::HEADER_SUBSCRIBE_TS
            || lower == objects::HEADER_PENDING_IDENTITY
        {
            continue;
        }
        forward_headers.set(&name, &value)?;
    }

    if let Some(encoded) = query_request {
        let subscription = BASE64_URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .ok()
            .and_then(|bytes| SubscribeRequest::decode(bytes.as_slice()).ok());
        let Some(subscription) = subscription else {
            return Response::error("malformed subscription", 400);
        };
        let identity_key = match subscription.verify(Date::now().as_millis()) {
            Ok(key) => key,
            Err(e) => return Response::error(e.to_string(), 403),
        };
        forward_headers.set(objects::HEADER_SUBSCRIBE_SIG, &hex(&subscription.signature))?;
        forward_headers.set(
            objects::HEADER_SUBSCRIBE_TS,
            &subscription.timestamp.to_string(),
        )?;
        let forwarded = Request::new_with_init(
            url.as_str(),
            RequestInit::new()
                .with_method(Method::Get)
                .with_headers(forward_headers),
        )?;
        objects::identity(env, &identity_key)?
            .fetch_with_request(forwarded)
            .await
    } else if let Some(identity_hex) = query_identity {
        let Some(identity_key) = decode_hex_32(&identity_hex) else {
            return Response::error("malformed identity", 400);
        };
        if XEdDSAPublicKey::new(&identity_key).is_err() {
            return Response::error("invalid identity key", 400);
        }
        forward_headers.set(objects::HEADER_PENDING_IDENTITY, &hex(&identity_key))?;
        let forwarded = Request::new_with_init(
            url.as_str(),
            RequestInit::new()
                .with_method(Method::Get)
                .with_headers(forward_headers),
        )?;
        objects::identity(env, &identity_key)?
            .fetch_with_request(forwarded)
            .await
    } else {
        Response::error("malformed subscription", 400)
    }
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
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
