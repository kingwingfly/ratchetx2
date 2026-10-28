//! Signing in, for what costs the server storage: attachments, and messages too large for their
//! D1 rows, which go to R2. A client signs in once with the server's password, a secret, and gets
//! a cookie, signed with another secret, which it sends with its calls until it expires. The
//! cookie names who signed in, its subject: `password`, for now; later, e.g. a blockchain account
//! that signed in with SIWE, SIWS or SIWX (CAIP-122), whose bought storage would be counted
//! against it.

use std::time::Duration;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use worker::{Date, Delay, Env, Headers, Method, Request, Response, Result};

/// The cookie: `__Host-` keeps it to this host, over HTTPS, for all its paths.
const COOKIE: &str = "__Host-e2ee-chat";
/// The secret that clients sign in with.
const PASSWORD: &str = "PASSWORD";
/// The secret that signs the cookies: apart from the password, so that a cookie cannot help
/// guess the password offline, and so that sign-ins without a password can sign them too.
const AUTH_KEY: &str = "AUTH_KEY";
/// How long a sign-in lasts, unless the `SESSION_DAYS` variable says.
const DEFAULT_SESSION_DAYS: u64 = 30;
/// How long a wrong password waits for its answer, which slows guessing it.
const WRONG_PASSWORD_DELAY: Duration = Duration::from_secs(1);
/// The longest password read.
const MAX_PASSWORD: usize = 1024;

/// What a cookie says of who signed in.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Who: `password`, for the server's password.
    pub subject: String,
    /// When the sign-in expires, in milliseconds since the Unix epoch.
    pub expires: u64,
}

/// Who `request` is signed in as, by its cookie, if this server signed it and it has not
/// expired.
pub fn signed_in(request: &Request, env: &Env) -> Option<Claims> {
    let key = secret(env, AUTH_KEY)?;
    let header = request.headers().get("cookie").ok()??;
    let value = header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == COOKIE).then_some(value)
    })?;
    let (claims, tag) = value.split_once('.')?;
    let tag = BASE64_URL_SAFE_NO_PAD.decode(tag).ok()?;
    mac(&key, b"cookie", claims.as_bytes())
        .verify_slice(&tag)
        .ok()?;
    let claims = BASE64_URL_SAFE_NO_PAD.decode(claims).ok()?;
    let claims: Claims = serde_json::from_slice(&claims).ok()?;
    (claims.expires > Date::now().as_millis()).then_some(claims)
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

/// Whether `request` comes from this server's own page, as its browser's `Sec-Fetch-Site` tells:
/// `same-origin`, or `none`, as the user's own, e.g. typed. Without the header, as from a client
/// that is no browser, or an old one, it is taken: forms are what the check is for, and every
/// browser now sends it. Through a development proxy, e.g. `trunk serve`, the page and its calls
/// share the proxy's origin, so they pass too.
fn same_origin(request: &Request) -> Result<bool> {
    Ok(match request.headers().get("sec-fetch-site")? {
        Some(site) => matches!(site.as_str(), "same-origin" | "none"),
        None => true,
    })
}

/// Sign `request` in with the server's password, its body.
async fn password(mut request: Request, env: &Env) -> Result<Response> {
    let (Some(password), Some(key)) = (secret(env, PASSWORD), secret(env, AUTH_KEY)) else {
        return Response::error(
            "this server takes no sign-ins: it has no PASSWORD and AUTH_KEY secrets",
            503,
        );
    };
    let Some(given) = crate::read_body(&mut request, MAX_PASSWORD).await? else {
        return Response::error("wrong password", 403);
    };
    // Compared as MACs, in constant time, so that the time it takes tells nothing of it.
    let expected = mac(&key, b"password", password.as_bytes())
        .finalize()
        .into_bytes();
    if mac(&key, b"password", &given)
        .verify_slice(&expected)
        .is_err()
    {
        Delay::from(WRONG_PASSWORD_DELAY).await;
        return Response::error("wrong password", 403);
    }
    let lasts = crate::days(env, "SESSION_DAYS", DEFAULT_SESSION_DAYS).saturating_mul(24 * 60 * 60);
    let claims = Claims {
        subject: "password".to_string(),
        expires: Date::now()
            .as_millis()
            .saturating_add(lasts.saturating_mul(1000)),
    };
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let tag = mac(&key, b"cookie", encoded.as_bytes())
        .finalize()
        .into_bytes();
    let cookie = format!(
        "{COOKIE}={encoded}.{}; {}",
        BASE64_URL_SAFE_NO_PAD.encode(tag),
        attributes(lasts)
    );
    answer(Some(&claims), Some(cookie))
}

/// The secret `name`, unless it is unset or empty: with an empty `AUTH_KEY`, anyone could sign a
/// cookie, and with an empty `PASSWORD`, sign in with nothing.
fn secret(env: &Env, name: &str) -> Option<String> {
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
