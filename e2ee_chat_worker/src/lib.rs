//! The E2EE chat server as a Cloudflare Worker: the handshake and mailbox services over the
//! Connect protocol, stored in D1 and R2, and notifications over WebSockets. See the README.

mod notifier;
mod store;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use prost::Message;
use protocol::{
    ErrorKind,
    attachment::AttachmentServer,
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

/// How long messages and initial messages are kept, unless the `RETENTION_DAYS` variable says.
const DEFAULT_RETENTION_DAYS: u64 = 30;
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
    // Any page may call: nothing here rests on cookies or the origin, as requests that need
    // authority are signed.
    response.with_cors(
        &Cors::new()
            .with_origins(["*"])
            .with_methods([Method::Post, Method::Options])
            .with_allowed_headers(["content-type", PROTOCOL_VERSION_HEADER])
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
    let response = match read_body(&mut request).await? {
        Some(body) => {
            let handshake = HandshakeServer::new(Store::new(env, limits.max_message_size)?);
            let mailbox = MailboxServer::builder(Store::new(env, limits.max_message_size)?)
                .limits(limits)
                .build();
            let attachments = AttachmentServer::new(Store::new(env, limits.max_message_size)?);
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
                && let Err(e) = notify(env, context, procedure, &body)
            {
                console_error!("cannot notify: {e}");
            }
            response
        }
        None => connect::error(ErrorKind::LimitExceeded, "request too large"),
    };
    let headers = Headers::new();
    headers.set("content-type", response.content_type)?;
    Ok(Response::from_bytes(response.body)?
        .with_status(response.status)
        .with_headers(headers))
}

/// Hand a WebSocket asking for an identity's notifications to its notifier, once its
/// subscription verifies: a `SubscribeRequest` in the `request` query parameter, as protobuf in
/// unpadded base64url, as a browser's WebSocket cannot send headers.
async fn subscribe(request: Request, env: &Env) -> Result<Response> {
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
/// once the response has gone.
fn notify(
    env: &Env,
    context: &Context,
    procedure: Procedure,
    body: &[u8],
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
    let name: String = identity_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    env.durable_object(NOTIFIER)?
        .id_from_name(&name)?
        .get_stub()
}

/// The body of `request`; `None` once it grows past [`MAX_BODY`], which stops reading it, so a
/// large body never sits in memory.
async fn read_body(request: &mut Request) -> Result<Option<Vec<u8>>> {
    if request.inner().body().is_none() {
        return Ok(Some(vec![]));
    }
    let mut stream = request.stream()?;
    let mut body = vec![];
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > MAX_BODY {
            return Ok(None);
        }
        body.extend(chunk);
    }
    Ok(Some(body))
}

/// Deletes the messages and initial messages older than the retention, as the protocol has no
/// way to acknowledge them.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _context: ScheduleContext) {
    let retention_days = env
        .var("RETENTION_DAYS")
        .ok()
        .and_then(|days| days.to_string().parse().ok())
        .unwrap_or(DEFAULT_RETENTION_DAYS);
    let before = Date::now()
        .as_millis()
        // Saturating, so that a huge RETENTION_DAYS keeps everything rather than wrapping
        // around to a recent time and deleting what is new.
        .saturating_sub(retention_days.saturating_mul(24 * 60 * 60 * 1000));
    let store = match Store::new(&env, 0) {
        Ok(store) => store,
        Err(e) => return console_error!("cannot reach the storage: {e}"),
    };
    match store.expire(before).await {
        Ok((messages, attachments)) => {
            console_log!("expired {messages} messages and {attachments} attachments")
        }
        // The cause is logged where it happened.
        Err(e) => console_error!("expiring messages failed: {e}"),
    }
}
