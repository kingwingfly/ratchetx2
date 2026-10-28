//! The E2EE chat server as a Cloudflare Worker: the handshake and mailbox services over the
//! Connect protocol, stored in D1 and R2, and notifications over WebSockets. See the README.

mod auth;
mod notifier;
mod store;

use std::time::Duration;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use prost::{Message, bytes::Bytes};
use protocol::{
    ErrorKind,
    attachment::{AttachmentLimits, AttachmentServer},
    connect::{self, PROTOCOL_VERSION_HEADER, Procedure},
    fixed,
    handshake::{HandshakeServer, SendInitialMessageRequest},
    mailbox::{MailboxLimits, MailboxServer, PushRequest},
    notify::{Notification, SubscribeRequest},
};
use storage::PublicKey;
use worker::{
    Context, Cors, Date, Env, Headers, Method, Request, RequestInit, Response, Result,
    ScheduleContext, ScheduledEvent, Stub, console_error, console_log, event, js_sys::Uint8Array,
};

use crate::store::Store;

/// Where a client opens the WebSocket of its notifications.
const NOTIFICATIONS_PATH: &str = "/notifications";
/// The binding of the notifiers' Durable Object namespace.
const NOTIFIER: &str = "NOTIFIER";

/// How long messages never delivered and initial messages never taken are kept, unless the
/// `RETENTION_DAYS` variable says.
const DEFAULT_RETENTION_DAYS: u64 = 30;
/// How long attachments are kept, unless the `FILE_RETENTION_DAYS` variable says: longer than
/// messages, as recipients may download them again, e.g. on a new device.
const DEFAULT_FILE_RETENTION_DAYS: u64 = 90;
/// The largest request body: the largest message, 4 MiB - 64 KiB, with room for the rest of a
/// push.
const MAX_BODY: usize = 4 << 20;

/// Answers the Connect calls; the web client's files are served before the Worker runs.
#[event(fetch)]
async fn fetch(request: Request, env: Env, context: Context) -> Result<Response> {
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
        Method::Post => call(request, &env, &context, procedure).await?,
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

async fn call(
    mut request: Request,
    env: &Env,
    context: &Context,
    procedure: Procedure,
) -> Result<Response> {
    let content_type = request.headers().get("content-type")?;
    let limits = MailboxLimits::default();
    let response = match read_body(&mut request, MAX_BODY).await? {
        Some(body) => {
            // Shared, so that `notify` decodes the call again without copying its message.
            let body = Bytes::from(body);
            if writes(procedure) && auth::signed_in(&request, env).is_none() {
                let message = "sign in to this server to use it";
                return respond(connect::error(ErrorKind::SignInRequired, message));
            }
            let store = Store::new(env, limits.max_message_size)?;
            let handshake = HandshakeServer::new(store.clone());
            let mailbox = MailboxServer::builder(store.clone()).limits(limits).build();
            // Uploaders learn how long it keeps their files, after which their tokens are no use.
            let retention = days(env, "FILE_RETENTION_DAYS", DEFAULT_FILE_RETENTION_DAYS);
            let attachments = AttachmentServer::builder(store)
                .limits(AttachmentLimits {
                    retention: Some(Duration::from_secs(retention.saturating_mul(24 * 60 * 60))),
                    ..AttachmentLimits::default()
                })
                .build();
            let response = connect::handle(
                &handshake,
                &mailbox,
                &attachments,
                procedure,
                content_type.as_deref(),
                &body,
            )
            .await;
            if response.status == 200
                && let Err(e) = notify(env, context, procedure, body)
            {
                console_error!("cannot notify: {e}");
            }
            response
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
/// small. Reading, taking one's own inbox, downloading, and what an upload's token authorizes
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

/// Hand a WebSocket asking for an identity's notifications to its notifier, once its
/// subscription verifies: a `SubscribeRequest` in the `request` query parameter, as protobuf in
/// unpadded base64url, as a browser's WebSocket cannot send headers.
async fn subscribe(request: Request, env: &Env) -> Result<Response> {
    // Only a WebSocket handshake, a GET: the notifier takes a POST as a notification for every
    // subscriber, which only the Worker may send.
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
            notifier(env, &identity_key)?
                .fetch_with_request(request)
                .await
        }
        Err(e) => Response::error(e.to_string(), 403),
    }
}

/// Tell the recipient of a message or an initial message, the call `body` made, that it arrived,
/// once the response has gone. Decoding from `Bytes`, the message the call carries is not copied.
fn notify(
    env: &Env,
    context: &Context,
    procedure: Procedure,
    body: Bytes,
) -> core::result::Result<(), String> {
    let (recipient, notification) = match procedure {
        Procedure::Push => {
            let request = PushRequest::decode(body).map_err(|e| e.to_string())?;
            let sender = fixed(&request.sender).map_err(|e| e.to_string())?;
            (request.recipient, Notification::message_from(&sender))
        }
        Procedure::SendInitialMessage => {
            let request = SendInitialMessageRequest::decode(body).map_err(|e| e.to_string())?;
            (request.recipient, Notification::initial_message())
        }
        _ => return Ok(()),
    };
    let recipient = fixed(&recipient).map_err(|e| e.to_string())?;
    let notifier = notifier(env, &recipient).map_err(|e| e.to_string())?;
    let body = Uint8Array::from(notification.encode_to_vec().as_slice());
    let request = Request::new_with_init(
        "https://notifier/notify",
        RequestInit::new()
            .with_method(Method::Post)
            .with_body(Some(body.into())),
    )
    .map_err(|e| e.to_string())?;
    context.wait_until(async move {
        if let Err(e) = notifier.fetch_with_request(request).await {
            console_error!("cannot notify: {e}");
        }
    });
    Ok(())
}

/// The notifier of `identity_key`, the Durable Object holding its client's WebSockets.
fn notifier(env: &Env, identity_key: &PublicKey) -> Result<Stub> {
    env.durable_object(NOTIFIER)?
        .id_from_name(&store::hex(identity_key))?
        .get_stub()
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

/// The days the variable `name` says, `default` unless it says a number.
pub(crate) fn days(env: &Env, name: &str, default: u64) -> u64 {
    env.var(name)
        .ok()
        .and_then(|days| days.to_string().parse().ok())
        .unwrap_or(default)
}

/// Deletes the messages never delivered, initial messages never taken and attachments older than
/// their retentions.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _context: ScheduleContext) {
    // What was created before the retention of the variable `name`, `default` days unless it says.
    let before = |name: &str, default: u64| {
        Date::now()
            .as_millis()
            // Saturating, so that a huge retention keeps everything rather than wrapping around
            // to a recent time and deleting what is new.
            .saturating_sub(days(&env, name, default).saturating_mul(24 * 60 * 60 * 1000))
    };
    let messages_before = before("RETENTION_DAYS", DEFAULT_RETENTION_DAYS);
    let files_before = before("FILE_RETENTION_DAYS", DEFAULT_FILE_RETENTION_DAYS);
    let store = match Store::new(&env, 0) {
        Ok(store) => store,
        Err(e) => return console_error!("cannot reach the storage: {e}"),
    };
    match store.expire(messages_before, files_before).await {
        Ok((messages, attachments)) => {
            console_log!("expired {messages} messages and {attachments} attachments")
        }
        // The cause is logged where it happened.
        Err(e) => console_error!("expiring messages failed: {e}"),
    }
}
