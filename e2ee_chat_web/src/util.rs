//! Small helpers: keys as text, time, sizes, errors and waiting.

use base64::prelude::*;
use session::PublicKey;
use wasm_bindgen::JsCast;

/// A key as the TUI client shows it: standard base64.
pub fn key_to_text(key: &PublicKey) -> String {
    BASE64_STANDARD.encode(key)
}

/// A key from standard or URL-safe base64, as in invitation links, or hex.
pub fn key_from_text(text: &str) -> Option<PublicKey> {
    let text = text.trim();
    // Text in one encoding may decode in another to the wrong length, e.g. 64 hex digits are
    // also 48 bytes of base64, so the first decoding of a key's length wins.
    [
        BASE64_STANDARD.decode(text).ok(),
        BASE64_URL_SAFE_NO_PAD.decode(text).ok(),
        from_hex(text),
    ]
    .into_iter()
    .flatten()
    .find_map(|bytes| bytes.try_into().ok())
}

/// A key in URL-safe base64, for invitation links.
pub fn key_to_url(key: &PublicKey) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(key)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The first bytes of a key, to tell keys apart at a glance; not enough to verify one.
pub fn short(key: &PublicKey) -> String {
    let hex = hex(&key[..4]);
    format!("{} {}", &hex[..4], &hex[4..])
}

/// Milliseconds since the Unix epoch.
pub fn now() -> u64 {
    js_sys::Date::now() as u64
}

/// A time as `HH:MM`, with the date unless it is today.
pub fn clock(millis: u64) -> String {
    let date = js_sys::Date::new(&(millis as f64).into());
    let today = js_sys::Date::new_0();
    let time = format!("{:02}:{:02}", date.get_hours(), date.get_minutes());
    if date.to_date_string() == today.to_date_string() {
        time
    } else {
        format!("{:02}-{:02} {time}", date.get_month() + 1, date.get_date())
    }
}

/// The month of a time, as the reader's language writes it, e.g. "October 2026".
pub fn month(millis: u64) -> String {
    local_date(millis, &[("month", "long"), ("year", "numeric")])
}

/// The day of a time, as the reader's language writes it, e.g. "27 Oct".
pub fn day(millis: u64) -> String {
    local_date(millis, &[("day", "numeric"), ("month", "short")])
}

/// The date of a time with the fields `fields` of `Intl.DateTimeFormat`, in the reader's
/// language.
fn local_date(millis: u64, fields: &[(&str, &str)]) -> String {
    let date = js_sys::Date::new(&(millis as f64).into());
    let options = js_sys::Object::new();
    for (field, value) in fields {
        let _ = js_sys::Reflect::set(&options, &(*field).into(), &(*value).into());
    }
    let language = web_sys::window()
        .and_then(|window| window.navigator().language())
        .unwrap_or_else(|| "en".to_string());
    date.to_locale_date_string(&language, &options).into()
}

/// A size in bytes, for people.
pub fn size(bytes: usize) -> String {
    match bytes {
        0..1_000 => format!("{bytes} B"),
        1_000..1_000_000 => format!("{:.0} KB", bytes as f64 / 1e3),
        _ => format!("{:.1} MB", bytes as f64 / 1e6),
    }
}

/// An error and its causes, e.g. "protocol error: limit exceeded: resource_exhausted: ...", as
/// an error's kind alone rarely says what to do.
pub fn describe(error: &dyn std::error::Error) -> String {
    let mut description = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        description.push_str(": ");
        description.push_str(&error.to_string());
        source = error.source();
    }
    description
}

/// Wait `millis` milliseconds.
pub async fn sleep(millis: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        web_sys::window()
            .expect("a window")
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, millis)
            .expect("setTimeout");
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// A JavaScript error as text.
pub fn js_error(error: wasm_bindgen::JsValue) -> String {
    match error.dyn_ref::<js_sys::Error>() {
        Some(error) => String::from(error.message()),
        None => format!("{error:?}"),
    }
}
