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
use protocol::{
    ErrorKind,
    attachment::{AttachmentLimits, AttachmentServer},
    connect::{self, PROTOCOL_VERSION_HEADER, Procedure},
    handshake::HandshakeServer,
    mailbox::{MailboxLimits, MailboxServer},
    notify::SubscribeRequest,
};
use worker::{Context, Cors, Date, Env, Headers, Method, Request, Response, Result, event};

pub use crate::objects::{Attachment, Identity};
use crate::store::Store;
pub(crate) use crate::store::hex;

/// Where a client opens the WebSocket of its notifications.
const NOTIFICATIONS_PATH: &str = "/notifications";
/// The binding of the R2 bucket.
pub(crate) const BUCKET: &str = "BUCKET";
/// The largest request body: the largest message, 4 MiB - 64 KiB, with room for the rest of a
/// push.
const MAX_BODY: usize = 4 << 20;

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
        return Response::ok("the storage conformance suites passed");
    }
    if request.path() == NOTIFICATIONS_PATH {
        return subscribe(request, &env).await;
    }
    if request.path() == "/auth" || request.path().starts_with("/auth/") {
        return dated(auth::handle(request, &env).await?);
    }
    let Some(procedure) = Procedure::from_path(&request.path()) else {
        return Response::error("not found", 404);
    };
    let response = match request.method() {
        // A CORS preflight, which the headers below answer.
        Method::Options => Response::empty()?,
        Method::Post => call(request, &env, procedure).await?,
        _ => {
            let headers = Headers::new();
            headers.set("allow", "POST, OPTIONS")?;
            Response::error("method not allowed", 405)?.with_headers(headers)
        }
    };
    // Any page may call: requests that need authority are signed; and the sign-in for what costs
    // storage is a cookie kept to this host's pages, which no other page's calls carry.
    dated(response)?.with_cors(
        &Cors::new()
            .with_origins(["*"])
            .with_methods([Method::Post, Method::Options])
            .with_allowed_headers(["content-type", PROTOCOL_VERSION_HEADER])
            // The server's time, which clients sign the requests whose time it checks with.
            .with_exposed_headers(["date"])
            .with_max_age(86400),
    )
}

async fn call(mut request: Request, env: &Env, procedure: Procedure) -> Result<Response> {
    let content_type = request.headers().get("content-type")?;
    let limits = MailboxLimits::default();
    let response = match read_body(&mut request, MAX_BODY).await? {
        Some(body) => {
            let body = Bytes::from(body);
            if writes(procedure) && auth::signed_in(&request, env).is_none() {
                let message = "sign in to this server to use it";
                return respond(connect::error(ErrorKind::SignInRequired, message));
            }
            let store = Store::new(env, limits.max_message_size)?;
            let handshake = HandshakeServer::new(store.clone());
            let mailbox = MailboxServer::builder(store.clone()).limits(limits).build();
            // Uploaders learn how long it keeps their files, after which their tokens are no use.
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
                .build();
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

/// `response`, with the server's time in its `Date`, which clients sign the requests whose time
/// the server checks with, as their clocks may be off. Set here, as not every runtime sets it.
fn dated(mut response: Response) -> Result<Response> {
    let now = worker::js_sys::Date::new_0().to_utc_string();
    response.headers_mut().set("date", &String::from(now))?;
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

/// Whether calls to `procedure` write, so that only clients signed in may make them: publishing
/// keys, taking one of a bundle's one-time prekeys, starting a chat, sending a message, and
/// starting an upload, which hands out the token its chunks go with. As the server's password is
/// what keeps it for those who have it, whose keys anyone can make, each write needs it, however
/// small. Reading, taking one's own inbox, downloading, and what an attachment's tokens authorize
/// stay open.
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

/// Hand a WebSocket asking for an identity's notifications to its object, once its
/// subscription verifies: a `SubscribeRequest` in the `request` query parameter, as protobuf in
/// unpadded base64url, as a browser's WebSocket cannot send headers.
async fn subscribe(request: Request, env: &Env) -> Result<Response> {
    // Only a WebSocket handshake, a GET: the identity's object takes a POST as a call, which
    // only the Worker may make.
    if request.method() != Method::Get {
        let headers = Headers::new();
        headers.set("allow", "GET")?;
        return Ok(Response::error("method not allowed", 405)?.with_headers(headers));
    }
    let upgrade = request.headers().get("upgrade")?;
    if !upgrade.is_some_and(|upgrade| upgrade.eq_ignore_ascii_case("websocket")) {
        return Response::error("expected a WebSocket", 426);
    }
    let subscription = request
        .url()?
        .query_pairs()
        .find(|(name, _)| name == "request")
        .and_then(|(_, value)| BASE64_URL_SAFE_NO_PAD.decode(value.as_bytes()).ok())
        .and_then(|bytes| SubscribeRequest::decode(bytes.as_slice()).ok());
    let Some(subscription) = subscription else {
        return Response::error("malformed subscription", 400);
    };
    match subscription.verify(Date::now().as_millis()) {
        Ok(identity_key) => {
            objects::identity(env, &identity_key)?
                .fetch_with_request(request)
                .await
        }
        Err(e) => Response::error(e.to_string(), 403),
    }
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
