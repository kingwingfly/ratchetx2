//! Signing in, which every call that writes takes, as the server is only for those who have its
//! password. A client signs in once with the server's password, a secret, and gets
//! a cookie, signed with another secret, which it sends with its calls until it expires.
//!
//! `POST /auth/password` is gated by Cloudflare's GA `AUTH_RATE_LIMITER` binding (`20 / 60s` per
//! normalized `CF-Connecting-IP`) before buffering the body, backed by an isolate-local failure
//! tracker and 1–5 s wrong-password backoff.

use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv6Addr},
    time::Duration,
};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use worker::{
    Date, Delay, Env, Headers, Method, Request, Response, Result, Url, console_error, js_sys,
    wasm_bindgen_futures::JsFuture,
};

/// The cookie: `__Host-` keeps it to this host, over HTTPS, for all its paths.
const COOKIE: &str = "__Host-e2ee-chat";
/// Maximum `Cookie` header length parsed (protects against header-stuffing DoS).
const MAX_COOKIE_HEADER_BYTES: usize = 4096;
/// The secret that clients sign in with.
const PASSWORD: &str = "PASSWORD";
/// The secret that signs the cookies: apart from the password, so that a cookie cannot help
/// guess the password offline, and so that sign-ins without a password can sign them too.
const AUTH_KEY: &str = "AUTH_KEY";
/// Rate-limiter binding gating `POST /auth/password` (`20 / 60s`).
pub(crate) const AUTH_RATE_LIMITER: &str = "AUTH_RATE_LIMITER";
/// How long a sign-in lasts, unless the `SESSION_DAYS` variable says.
const DEFAULT_SESSION_DAYS: u64 = 30;
/// Base delay after a wrong password, which scales with recent failures from the same client.
const WRONG_PASSWORD_BASE_DELAY_MS: u64 = 1000;
/// Cap on per-request wrong-password delay.
const WRONG_PASSWORD_MAX_DELAY_MS: u64 = 5000;
/// Sliding window for best-effort per-client password failure throttling (60 seconds).
const THROTTLE_WINDOW_MS: u64 = 60_000;
/// Maximum failed password attempts permitted per client within [`THROTTLE_WINDOW_MS`].
const MAX_FAILURES_PER_WINDOW: usize = 20;
/// Maximum number of IP buckets retained by one isolate.
const MAX_TRACKED_CLIENTS: usize = 1024;
/// The longest password read.
const MAX_PASSWORD: usize = 1024;

thread_local! {
    static FAILED_ATTEMPTS: RefCell<FailureTracker> = RefCell::new(FailureTracker::default());
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = js_sys::Object)]
    type JsRateLimiter;

    #[wasm_bindgen(method, catch)]
    fn limit(
        this: &JsRateLimiter,
        options: js_sys::Object,
    ) -> std::result::Result<js_sys::Promise, JsValue>;
}

/// Checks a Cloudflare `[[ratelimits]]` binding for `key`, returning `true` if allowed and
/// `false` if rate-limited.
///
/// Tries `env.rate_limiter(binding)` first and falls back to direct JS FFI (`binding.limit({key})`)
/// if `workers-rs#700` rejects the binding's JS constructor name in `workerd`.
pub(crate) async fn check_rate_limit(env: &Env, binding: &str, key: String) -> bool {
    if let Ok(limiter) = env.rate_limiter(binding) {
        return match limiter.limit(key).await {
            Ok(outcome) => outcome.success,
            Err(error) => {
                console_error!("rate limiter `{binding}` failed: {error}");
                true
            }
        };
    }

    let Ok(val) = js_sys::Reflect::get(env.as_ref(), &JsValue::from_str(binding)) else {
        return true;
    };
    if val.is_undefined() || val.is_null() {
        return true;
    }
    let has_limit = js_sys::Reflect::get(&val, &JsValue::from_str("limit"))
        .map(|f| f.is_function())
        .unwrap_or(false);
    if !has_limit {
        console_error!("rate limiter binding `{binding}` has no limit() method");
        return true;
    }
    let opts = js_sys::Object::new();
    if js_sys::Reflect::set(&opts, &JsValue::from_str("key"), &JsValue::from_str(&key)).is_err() {
        return true;
    }
    let limiter: JsRateLimiter = val.unchecked_into();
    let promise = match limiter.limit(opts) {
        Ok(promise) => promise,
        Err(error) => {
            console_error!("rate limiter `{binding}` call threw: {error:?}");
            return true;
        }
    };
    match JsFuture::from(promise).await {
        Ok(outcome) => js_sys::Reflect::get(&outcome, &JsValue::from_str("success"))
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        Err(error) => {
            console_error!("rate limiter `{binding}` promise rejected: {error:?}");
            true
        }
    }
}

/// Checks both the normalized client IP key and (when signed in) the hashed cookie-tag key
/// against a `[[ratelimits]]` binding.
pub(crate) async fn check_rate_limits(
    env: &Env,
    binding: &str,
    prefix: &str,
    ip_key: &str,
    cookie_tag_hash: Option<&[u8; 32]>,
) -> bool {
    if !check_rate_limit(env, binding, format!("{prefix}:ip:{ip_key}")).await {
        return false;
    }
    if let Some(tag_hash) = cookie_tag_hash {
        let tok_hex = crate::hex(&tag_hash[..16]);
        if !check_rate_limit(env, binding, format!("{prefix}:tok:{tok_hex}")).await {
            return false;
        }
    }
    true
}

/// What a cookie says of who signed in.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Who: `password`, for the server's password.
    pub subject: String,
    /// When the sign-in expires, in milliseconds since the Unix epoch.
    pub expires: u64,
}

/// Whether server password sign-in is configured (`PASSWORD` secret is set and non-empty).
pub fn password_configured(env: &Env) -> bool {
    secret(env, PASSWORD).is_some()
}

/// Who `request` is signed in as, by its cookie, if this server signed it and it has not
/// expired.
pub fn signed_in(request: &Request, env: &Env) -> Option<Claims> {
    signed_in_with_tag(request, env).map(|(claims, _)| claims)
}

/// Who `request` is signed in as, alongside `SHA-256(b"rl:cookie-tag\0" || tag_bytes)` for
/// rate-limiter keying without exposing the raw HMAC tag.
pub fn signed_in_with_tag(request: &Request, env: &Env) -> Option<(Claims, [u8; 32])> {
    let key = secret(env, AUTH_KEY)?;
    let header = request.headers().get("cookie").ok()??;
    verify_cookie_with_tag(&key, &header, Date::now().as_millis())
}

/// Verifies the `__Host-e2ee-chat` cookie inside `cookie_header` against `key` and `now_ms`.
///
/// Hardened bounds:
/// - Rejects `Cookie` headers exceeding [`MAX_COOKIE_HEADER_BYTES`] (4096 bytes).
/// - Scans all `;`-separated pairs and rejects duplicate `__Host-e2ee-chat` cookies to eliminate
///   cookie-shadowing ambiguity.
pub(crate) fn verify_cookie_with_tag(
    key: &str,
    cookie_header: &str,
    now_ms: u64,
) -> Option<(Claims, [u8; 32])> {
    if key.is_empty() || cookie_header.len() > MAX_COOKIE_HEADER_BYTES {
        return None;
    }
    let mut found = None;
    for pair in cookie_header.split(';') {
        let Some((name, value)) = pair.trim().split_once('=') else {
            continue;
        };
        if name.trim() == COOKIE {
            if found.is_some() {
                return None;
            }
            found = Some(value.trim());
        }
    }
    let value = found?;
    let (claims_b64, tag_b64) = value.split_once('.')?;
    let tag = BASE64_URL_SAFE_NO_PAD.decode(tag_b64).ok()?;
    mac(key, b"cookie", claims_b64.as_bytes())
        .verify_slice(&tag)
        .ok()?;
    let claims_bytes = BASE64_URL_SAFE_NO_PAD.decode(claims_b64).ok()?;
    let claims: Claims = serde_json::from_slice(&claims_bytes).ok()?;
    if claims.expires <= now_ms {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"rl:cookie-tag\0");
    hasher.update(&tag);
    let tag_hash: [u8; 32] = hasher.finalize().into();
    Some((claims, tag_hash))
}

#[cfg(test)]
pub(crate) fn verify_cookie(key: &str, cookie_header: &str, now_ms: u64) -> Option<Claims> {
    verify_cookie_with_tag(key, cookie_header, now_ms).map(|(claims, _)| claims)
}

fn encode_cookie_value(key: &str, claims: &Claims) -> Result<String> {
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let tag = mac(key, b"cookie", encoded.as_bytes())
        .finalize()
        .into_bytes();
    Ok(format!("{encoded}.{}", BASE64_URL_SAFE_NO_PAD.encode(tag)))
}

/// Constant-time comparison of two secret tokens via HMAC verification (returns `false` when
/// `expected` is empty).
#[cfg(any(test, feature = "conformance"))]
pub(crate) fn constant_time_secret_eq(expected: &str, presented: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    let expected_mac = mac(expected, b"secret-token", expected.as_bytes())
        .finalize()
        .into_bytes();
    mac(expected, b"secret-token", presented.as_bytes())
        .verify_slice(&expected_mac)
        .is_ok()
}

/// Answer the calls under `/auth`, from the page of this server only, as the cookie is kept to
/// it: `GET /auth`, who the request is signed in as; `POST /auth/password`, sign in with the
/// server's password, the request's body; `POST /auth/sign-out`. Each answers who is signed in
/// then, as JSON: a [`Claims`], or `{}` for nobody.
pub async fn handle(request: Request, env: &Env) -> Result<Response> {
    // Signing in or out only from this server's own pages: a form another site submits to it,
    // which its browser tells, would sign its visitor out, or in.
    if request.method() == Method::Post && !same_origin(&request)? {
        return Response::error("not from this server's page", 403);
    }
    match (request.method(), request.path().as_str()) {
        (Method::Get, "/auth") => answer(signed_in(&request, env).as_ref(), None),
        (Method::Post, "/auth/password") => password(request, env).await,
        (Method::Post, "/auth/sign-out") => {
            answer(None, Some(format!("{COOKIE}=; {}", attributes(0))))
        }
        _ => Response::error("not found", 404),
    }
}

/// Whether `request` comes from this server's own page.
fn same_origin(request: &Request) -> Result<bool> {
    let sec_fetch_site = request.headers().get("sec-fetch-site")?;
    let origin = request.headers().get("origin")?;
    let referer = request.headers().get("referer")?;
    let req_url = request.url()?;
    Ok(same_origin_headers(
        sec_fetch_site.as_deref(),
        origin.as_deref(),
        referer.as_deref(),
        &req_url,
    ))
}

/// Pure origin check for `/auth` POST requests:
/// 1. If `Sec-Fetch-Site` is present, requires `same-origin` or `none`.
/// 2. If `Sec-Fetch-Site` is absent, falls back to checking `Origin` (and then `Referer`) against
///    the request's own scheme, host, and effective port.
/// 3. Non-browser clients omitting all three headers are allowed.
fn same_origin_headers(
    sec_fetch_site: Option<&str>,
    origin: Option<&str>,
    referer: Option<&str>,
    req_url: &Url,
) -> bool {
    if let Some(site) = sec_fetch_site {
        return matches!(site, "same-origin" | "none");
    }
    if let Some(origin) = origin {
        return url_matches_origin(origin, req_url);
    }
    if let Some(referer) = referer {
        return url_matches_origin(referer, req_url);
    }
    true
}

/// Returns `true` iff `candidate` parses as an `http(s)` URL with the exact same scheme, host, and
/// effective port as `target`.
pub(crate) fn url_matches_origin(candidate: &str, target: &Url) -> bool {
    let Ok(parsed) = Url::parse(candidate) else {
        return false;
    };
    matches!(parsed.scheme(), "http" | "https")
        && parsed.scheme() == target.scheme()
        && parsed.host_str() == target.host_str()
        && parsed.port_or_known_default() == target.port_or_known_default()
}

/// Returns `true` iff a WebSocket upgrade's `Origin` header matches `target` (treating `ws` as
/// `http` and `wss` as `https` on `target`, while requiring `origin` itself to be `http(s)`).
pub(crate) fn ws_origin_matches(origin: &str, target: &Url) -> bool {
    let Ok(parsed) = Url::parse(origin) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    let target_scheme = match target.scheme() {
        "ws" => "http",
        "wss" => "https",
        other => other,
    };
    parsed.scheme() == target_scheme
        && parsed.host_str() == target.host_str()
        && parsed.port_or_known_default() == target.port_or_known_default()
}

/// Returns `true` iff a WebSocket upgrade passes Origin validation:
/// - Non-browser clients omitting `Origin` are allowed.
/// - Browser same-origin requests (`Sec-Fetch-Site: same-origin`, including dev proxies such as
///   `trunk serve`) are allowed.
/// - Otherwise `Origin` must match either `request_url` or the configured `SERVER_ID` (keeping
///   scheme requirements intact so an `http://` origin cannot match an `https://` server).
pub(crate) fn ws_upgrade_origin_allowed(
    origin: Option<&str>,
    sec_fetch_site: Option<&str>,
    request_url: &Url,
    configured_server_id: Option<&str>,
) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    if sec_fetch_site == Some("same-origin") {
        return true;
    }
    if ws_origin_matches(origin, request_url) {
        return true;
    }
    let Some(server_id) = configured_server_id
        .map(str::trim)
        .filter(|id| !id.is_empty())
    else {
        return false;
    };
    if server_id.contains("://") {
        return Url::parse(server_id).is_ok_and(|url| ws_origin_matches(origin, &url));
    }
    let Ok(parsed_origin) = Url::parse(origin) else {
        return false;
    };
    let expected_scheme = match request_url.scheme() {
        "ws" => "http",
        "wss" => "https",
        other => other,
    };
    if !matches!(parsed_origin.scheme(), "http" | "https")
        || parsed_origin.scheme() != expected_scheme
    {
        return false;
    }
    let Ok(origin_audience) =
        protocol::normalize_audience(&parsed_origin.origin().ascii_serialization())
    else {
        return false;
    };
    let Ok(expected_audience) = protocol::normalize_audience(server_id) else {
        return false;
    };
    origin_audience == expected_audience
}

pub(crate) fn client_ip_key(request: &Request) -> String {
    let header = request.headers().get("CF-Connecting-IP").ok().flatten();
    normalize_client_ip_key(header.as_deref())
}

/// Normalizes `CF-Connecting-IP` into a rate-limit bucket key:
/// - IPv4 addresses are preserved canonically.
/// - IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) fold into their IPv4 bucket.
/// - IPv6 addresses are masked to their `/64` prefix so a single `/64` holder cannot rotate
///   through 2^64 independent rate-limit buckets.
/// - Missing, empty, or overly long headers share `"<unknown>"`.
fn normalize_client_ip_key(header: Option<&str>) -> String {
    let Some(raw) = header
        .map(str::trim)
        .filter(|ip| !ip.is_empty() && ip.len() <= 128)
    else {
        return "<unknown>".to_owned();
    };
    match raw.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.to_string()
            } else {
                let [a, b, c, d, ..] = v6.segments();
                let prefix = Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0);
                format!("{prefix}/64")
            }
        }
        Err(_) => raw.to_owned(),
    }
}

#[derive(Default)]
struct FailureTracker {
    clients: HashMap<String, VecDeque<u64>>,
}

#[derive(Debug, PartialEq, Eq)]
enum PasswordAttemptOutcome {
    RateLimited,
    WrongPassword { failures: usize },
    Accepted,
}

impl FailureTracker {
    fn prune(attempts: &mut VecDeque<u64>, now: u64) {
        let cutoff = now.saturating_sub(THROTTLE_WINDOW_MS);
        while attempts.front().is_some_and(|&ts| ts < cutoff) {
            attempts.pop_front();
        }
    }

    fn recent_failures(&mut self, client_key: &str, now: u64) -> usize {
        let Some(attempts) = self.clients.get_mut(client_key) else {
            return 0;
        };
        Self::prune(attempts, now);
        let count = attempts.len();
        if count == 0 {
            self.clients.remove(client_key);
        }
        count
    }

    /// Recheck the limit after reading the body and record any failure before yielding.
    fn verify_password_attempt(
        &mut self,
        client_key: &str,
        now: u64,
        key: &str,
        password: &str,
        given: Option<&[u8]>,
    ) -> PasswordAttemptOutcome {
        if self.recent_failures(client_key, now) >= MAX_FAILURES_PER_WINDOW {
            return PasswordAttemptOutcome::RateLimited;
        }
        // Compare MACs in constant time so the comparison reveals nothing about the password.
        let expected = mac(key, b"password", password.as_bytes())
            .finalize()
            .into_bytes();
        if given.is_some_and(|body| mac(key, b"password", body).verify_slice(&expected).is_ok()) {
            return PasswordAttemptOutcome::Accepted;
        }
        PasswordAttemptOutcome::WrongPassword {
            failures: self.record_failure(client_key, now),
        }
    }

    fn record_failure(&mut self, client_key: &str, now: u64) -> usize {
        if let Some(attempts) = self.clients.get_mut(client_key) {
            Self::prune(attempts, now);
            attempts.push_back(now);
            return attempts.len();
        }
        if self.clients.len() >= MAX_TRACKED_CLIENTS {
            self.clients.retain(|_, attempts| {
                Self::prune(attempts, now);
                !attempts.is_empty()
            });
            if self.clients.len() >= MAX_TRACKED_CLIENTS
                && let Some((key, _)) = self
                    .clients
                    .iter()
                    .min_by_key(|(_, q)| (q.len(), q.back().copied().unwrap_or(0)))
            {
                let key = key.clone();
                self.clients.remove(&key);
            }
        }
        self.clients
            .insert(client_key.to_owned(), VecDeque::from([now]));
        1
    }
}

fn rate_limited_response() -> Result<Response> {
    let mut response = Response::error("too many failed sign-in attempts", 429)?;
    response.headers_mut().set("retry-after", "60")?;
    Ok(response)
}

/// Sign `request` in with the server's password, its body.
async fn password(mut request: Request, env: &Env) -> Result<Response> {
    let (Some(password), Some(key)) = (secret(env, PASSWORD), secret(env, AUTH_KEY)) else {
        return Response::error(
            "this server takes no sign-ins: it has no PASSWORD and AUTH_KEY secrets",
            503,
        );
    };
    // Enforce Cloudflare `AUTH_RATE_LIMITER` AND isolate-local failure throttling BEFORE
    // buffering the request body.
    let client_key = client_ip_key(&request);
    if !check_rate_limit(env, AUTH_RATE_LIMITER, format!("auth:{client_key}")).await {
        return rate_limited_response();
    }
    let now = Date::now().as_millis();
    if FAILED_ATTEMPTS.with_borrow_mut(|tracker| tracker.recent_failures(&client_key, now))
        >= MAX_FAILURES_PER_WINDOW
    {
        return rate_limited_response();
    }
    let given = crate::read_body(&mut request, MAX_PASSWORD).await?;
    let now = Date::now().as_millis();
    let outcome = FAILED_ATTEMPTS.with_borrow_mut(|tracker| {
        tracker.verify_password_attempt(&client_key, now, &key, &password, given.as_deref())
    });
    match outcome {
        PasswordAttemptOutcome::RateLimited => {
            return rate_limited_response();
        }
        PasswordAttemptOutcome::WrongPassword { failures } => {
            let delay_ms = WRONG_PASSWORD_BASE_DELAY_MS
                .saturating_mul(1u64 << (failures.saturating_sub(1).min(3)))
                .min(WRONG_PASSWORD_MAX_DELAY_MS);
            Delay::from(Duration::from_millis(delay_ms)).await;
            return Response::error("wrong password", 403);
        }
        PasswordAttemptOutcome::Accepted => {}
    }
    let lasts = crate::period(env, "SESSION_DAYS", DEFAULT_SESSION_DAYS).as_secs();
    let claims = Claims {
        subject: "password".to_string(),
        expires: Date::now()
            .as_millis()
            .saturating_add(lasts.saturating_mul(1000)),
    };
    let cookie = format!(
        "{COOKIE}={}; {}",
        encode_cookie_value(&key, &claims)?,
        attributes(lasts)
    );
    answer(Some(&claims), Some(cookie))
}

/// The secret `name`, unless it is unset or empty: with an empty `AUTH_KEY`, anyone could sign a
/// cookie, and with an empty `PASSWORD`, sign in with nothing.
pub(crate) fn secret(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .ok()
        .map(|secret| secret.to_string())
        .filter(|secret| !secret.is_empty())
}

/// A cookie's attributes, for `max_age` seconds: only for this host's pages, not their scripts,
/// over HTTPS, and never sent from another site, which then cannot store files as the user.
fn attributes(max_age: u64) -> String {
    format!("Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict")
}

/// HMAC-SHA256 under `key`, of `data`, for `purpose`, so that one never passes for another.
fn mac(key: &str, purpose: &[u8], data: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC takes any key");
    mac.update(purpose);
    mac.update(b"\0");
    mac.update(data);
    mac
}

/// Who is signed in, as JSON, setting `cookie` if given.
fn answer(claims: Option<&Claims>, cookie: Option<String>) -> Result<Response> {
    let body = match claims {
        Some(claims) => serde_json::to_string(claims)?,
        None => "{}".to_string(),
    };
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "no-store")?;
    if let Some(cookie) = cookie {
        headers.set("set-cookie", &cookie)?;
    }
    Ok(Response::ok(body)?.with_headers(headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cookie_accepts_valid_signed_cookie_and_rejects_tampering_expiry_duplicates_and_oversized()
     {
        let key = "test-signing-key";
        let claims = Claims {
            subject: "password".to_string(),
            expires: 10_000,
        };
        let value = encode_cookie_value(key, &claims).unwrap();
        let header = format!("other=1; {COOKIE}={value}; theme=dark");

        let (verified, tag_hash) = verify_cookie_with_tag(key, &header, 9_999).unwrap();
        assert_eq!(verified, claims);
        // Tag hash is deterministic for the same signed cookie and differs for a rotated expiry.
        let (_, tag_hash_again) = verify_cookie_with_tag(key, &header, 9_998).unwrap();
        assert_eq!(tag_hash, tag_hash_again);
        let claims2 = Claims {
            subject: "password".to_string(),
            expires: 10_001,
        };
        let value2 = encode_cookie_value(key, &claims2).unwrap();
        let (_, tag_hash2) =
            verify_cookie_with_tag(key, &format!("{COOKIE}={value2}"), 9_999).unwrap();
        assert_ne!(tag_hash, tag_hash2);

        // Duplicate __Host-e2ee-chat cookies MUST be rejected (even if both are valid!).
        assert_eq!(
            verify_cookie(key, &format!("{COOKIE}={value}; {COOKIE}={value}"), 5_000),
            None
        );
        assert_eq!(
            verify_cookie(key, &format!("{COOKIE}=bogus; {COOKIE}={value}"), 5_000),
            None
        );
        assert_eq!(
            verify_cookie(key, &format!("{COOKIE}={value}; {COOKIE}=bogus"), 5_000),
            None
        );

        // Oversized Cookie header (> 4096 bytes) MUST be rejected.
        let pad_len = MAX_COOKIE_HEADER_BYTES - format!("{COOKIE}={value}; x=").len() + 1;
        let oversized = format!("{COOKIE}={value}; x={}", "a".repeat(pad_len));
        assert!(oversized.len() > MAX_COOKIE_HEADER_BYTES);
        assert_eq!(verify_cookie(key, &oversized, 5_000), None);
        // Exact boundary (4096 bytes) succeeds.
        let exact = format!("{COOKIE}={value}; x={}", "a".repeat(pad_len - 1));
        assert_eq!(exact.len(), MAX_COOKIE_HEADER_BYTES);
        assert_eq!(verify_cookie(key, &exact, 5_000), Some(claims));

        // Expired at boundary and past boundary.
        assert_eq!(verify_cookie(key, &header, 10_000), None);
        assert_eq!(verify_cookie(key, &header, 10_001), None);
        // Wrong key or empty key.
        assert_eq!(verify_cookie("wrong-key", &header, 5_000), None);
        assert_eq!(verify_cookie("", &header, 5_000), None);
        // Wrong cookie name.
        assert_eq!(
            verify_cookie(key, &format!("e2ee-chat={value}"), 5_000),
            None
        );
        // Tampered payload or tag.
        let (payload, tag) = value.split_once('.').unwrap();
        let tampered_tag = format!("{COOKIE}={payload}.{}A", &tag[..tag.len() - 1]);
        assert_eq!(verify_cookie(key, &tampered_tag, 5_000), None);
        let tampered_payload = format!("{COOKIE}={}A.{tag}", &payload[..payload.len() - 1]);
        assert_eq!(verify_cookie(key, &tampered_payload, 5_000), None);
        // Missing dot / malformed.
        assert_eq!(
            verify_cookie(key, &format!("{COOKIE}=not-a-cookie"), 5_000),
            None
        );
    }

    #[test]
    fn same_origin_and_url_matches_origin_enforce_browser_and_ws_origin_rules() {
        let target = Url::parse("https://chat.example/auth/password").unwrap();
        let target_port = Url::parse("https://chat.example:8443/auth/password").unwrap();

        assert!(same_origin_headers(
            Some("same-origin"),
            Some("https://evil.example"),
            None,
            &target
        ));
        assert!(same_origin_headers(Some("none"), None, None, &target));
        assert!(!same_origin_headers(
            Some("cross-site"),
            Some("https://chat.example"),
            None,
            &target
        ));
        assert!(!same_origin_headers(
            Some("same-site"),
            Some("https://chat.example"),
            None,
            &target
        ));

        assert!(same_origin_headers(
            None,
            Some("https://chat.example"),
            None,
            &target
        ));
        assert!(same_origin_headers(
            None,
            Some("https://chat.example:443"),
            None,
            &target
        ));
        assert!(!same_origin_headers(
            None,
            Some("http://chat.example"),
            None,
            &target
        ));
        assert!(!same_origin_headers(
            None,
            Some("https://chat.example:8443"),
            None,
            &target
        ));
        assert!(!same_origin_headers(None, Some("null"), None, &target));
        assert!(!same_origin_headers(
            None,
            Some("https://evil.example"),
            Some("https://chat.example/"),
            &target
        ));

        assert!(same_origin_headers(
            None,
            None,
            Some("https://chat.example/chat?id=1"),
            &target
        ));
        assert!(!same_origin_headers(
            None,
            None,
            Some("https://evil.example/chat"),
            &target
        ));
        assert!(same_origin_headers(
            None,
            None,
            Some("https://chat.example:8443/app"),
            &target_port
        ));

        assert!(same_origin_headers(None, None, None, &target));

        let wss_url = Url::parse("wss://chat.example/notifications").unwrap();
        let https_url = Url::parse("https://chat.example/notifications").unwrap();
        let ws_local = Url::parse("ws://localhost:8787/notifications").unwrap();
        assert!(ws_origin_matches("https://chat.example", &wss_url));
        assert!(ws_origin_matches("https://chat.example:443", &https_url));
        assert!(ws_origin_matches("http://localhost:8787", &ws_local));
        assert!(!ws_origin_matches("http://chat.example", &wss_url));
        assert!(!ws_origin_matches("https://evil.example", &https_url));
        assert!(!ws_origin_matches("wss://chat.example", &wss_url));
        assert!(!ws_origin_matches("null", &https_url));

        let wrangler_dev = Url::parse("http://localhost:8787/notifications").unwrap();
        assert!(ws_upgrade_origin_allowed(None, None, &https_url, None));
        assert!(ws_upgrade_origin_allowed(
            Some("http://localhost:8080"),
            Some("same-origin"),
            &wrangler_dev,
            None
        ));
        assert!(!ws_upgrade_origin_allowed(
            Some("http://localhost:8080"),
            Some("cross-site"),
            &wrangler_dev,
            None
        ));
        assert!(ws_upgrade_origin_allowed(
            Some("https://public.example"),
            None,
            &https_url,
            Some("https://public.example")
        ));
        assert!(ws_upgrade_origin_allowed(
            Some("https://public.example"),
            None,
            &https_url,
            Some("public.example")
        ));
        assert!(!ws_upgrade_origin_allowed(
            Some("http://public.example"),
            None,
            &https_url,
            Some("https://public.example")
        ));
        assert!(!ws_upgrade_origin_allowed(
            Some("http://public.example"),
            None,
            &https_url,
            Some("public.example")
        ));
        assert!(!ws_upgrade_origin_allowed(
            Some("https://evil.example"),
            Some("cross-site"),
            &https_url,
            Some("https://public.example")
        ));
    }

    #[test]
    fn client_ip_key_normalizes_ipv6_to_slash_64_and_folds_ipv4_mapped() {
        assert_eq!(normalize_client_ip_key(Some("192.0.2.1")), "192.0.2.1");
        assert_eq!(normalize_client_ip_key(Some(" 192.0.2.1 ")), "192.0.2.1");
        assert_eq!(
            normalize_client_ip_key(Some("::ffff:192.0.2.1")),
            "192.0.2.1"
        );
        let a = normalize_client_ip_key(Some("2001:0db8:abcd:0012:ffff:1111:2222:3333"));
        let b = normalize_client_ip_key(Some("2001:db8:abcd:12::1"));
        let c = normalize_client_ip_key(Some("2001:db8:abcd:13::1"));
        assert_eq!(a, "2001:db8:abcd:12::/64");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(normalize_client_ip_key(None), "<unknown>");
        assert_eq!(normalize_client_ip_key(Some("   ")), "<unknown>");
        assert_eq!(normalize_client_ip_key(Some(&"a".repeat(129))), "<unknown>");
    }

    #[test]
    fn constant_time_secret_eq_matches_only_identical_non_empty_tokens() {
        assert!(constant_time_secret_eq("secret-token", "secret-token"));
        assert!(!constant_time_secret_eq("secret-token", "secret-tokeN"));
        assert!(!constant_time_secret_eq("secret-token", "secret"));
        assert!(!constant_time_secret_eq("secret-token", ""));
        assert!(!constant_time_secret_eq("", ""));
    }

    #[test]
    fn in_flight_password_attempts_observe_the_limit_until_the_window_expires() {
        let mut tracker = FailureTracker::default();
        let now = 100;
        for _ in 0..MAX_FAILURES_PER_WINDOW + 2 {
            assert!(tracker.recent_failures("client", now) < MAX_FAILURES_PER_WINDOW);
        }
        for failures in 1..=MAX_FAILURES_PER_WINDOW {
            assert_eq!(
                tracker.verify_password_attempt("client", now, "key", "correct", Some(b"wrong")),
                PasswordAttemptOutcome::WrongPassword { failures }
            );
        }
        for body in [b"correct".as_slice(), b"wrong"] {
            assert_eq!(
                tracker.verify_password_attempt("client", now, "key", "correct", Some(body)),
                PasswordAttemptOutcome::RateLimited
            );
        }
        assert_eq!(
            tracker.recent_failures("client", now),
            MAX_FAILURES_PER_WINDOW
        );

        let later = now + THROTTLE_WINDOW_MS + 1;
        assert_eq!(
            tracker.verify_password_attempt("client", later, "key", "correct", Some(b"correct")),
            PasswordAttemptOutcome::Accepted
        );
        assert_eq!(tracker.recent_failures("client", later), 0);
    }

    #[test]
    fn oversized_bodies_count_as_failures_and_valid_passwords_preserve_the_count() {
        let mut tracker = FailureTracker::default();
        for failures in 1..=MAX_FAILURES_PER_WINDOW {
            assert_eq!(
                tracker.verify_password_attempt("client", 100, "key", "correct", Some(b"correct")),
                PasswordAttemptOutcome::Accepted
            );
            assert_eq!(tracker.recent_failures("client", 100), failures - 1);
            assert_eq!(
                tracker.verify_password_attempt("client", 100, "key", "correct", None),
                PasswordAttemptOutcome::WrongPassword { failures }
            );
            assert_eq!(tracker.recent_failures("client", 100), failures);
        }
    }

    #[test]
    fn password_failures_are_per_client() {
        let mut tracker = FailureTracker::default();
        for count in 1..=MAX_FAILURES_PER_WINDOW {
            assert_eq!(tracker.record_failure("192.0.2.1", 100), count);
        }
        assert_eq!(
            tracker.recent_failures("192.0.2.1", 100),
            MAX_FAILURES_PER_WINDOW
        );
        assert_eq!(tracker.recent_failures("192.0.2.2", 100), 0);
        assert_eq!(tracker.record_failure("192.0.2.2", 100), 1);
    }

    #[test]
    fn expired_timestamps_and_empty_buckets_are_removed() {
        let mut tracker = FailureTracker::default();
        tracker.record_failure("client", 10);
        tracker.record_failure("client", 20);
        assert_eq!(
            tracker.recent_failures("client", 10 + THROTTLE_WINDOW_MS),
            2
        );
        assert_eq!(
            tracker.recent_failures("client", 11 + THROTTLE_WINDOW_MS),
            1
        );
        assert_eq!(
            tracker.recent_failures("client", 21 + THROTTLE_WINDOW_MS),
            0
        );
        assert!(tracker.clients.is_empty());
    }

    #[test]
    fn a_full_tracker_retains_heavy_offenders_and_evicts_oldest_noise() {
        let mut tracker = FailureTracker::default();
        for _ in 0..MAX_FAILURES_PER_WINDOW {
            tracker.record_failure("locked", 0);
        }
        for n in 1..=2 * MAX_TRACKED_CLIENTS {
            tracker.record_failure(&n.to_string(), n as u64);
            assert!(tracker.clients.len() <= MAX_TRACKED_CLIENTS);
        }
        assert_eq!(tracker.clients.len(), MAX_TRACKED_CLIENTS);
        assert!(!tracker.clients.contains_key("1"));
        assert!(
            tracker
                .clients
                .contains_key(&(2 * MAX_TRACKED_CLIENTS).to_string())
        );
        assert_eq!(
            tracker.recent_failures("locked", 2 * MAX_TRACKED_CLIENTS as u64),
            MAX_FAILURES_PER_WINDOW
        );
        tracker.record_failure(
            "later",
            2 * MAX_TRACKED_CLIENTS as u64 + THROTTLE_WINDOW_MS + 1,
        );
        assert_eq!(tracker.clients.len(), 1);
    }
}
