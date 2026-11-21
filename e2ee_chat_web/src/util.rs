//! Small helpers: keys as text, time, sizes, errors and waiting.

use base64::prelude::*;
use js_sys::Intl::{DateTimeFormatOptions, DayFormat, MonthFormat, YearFormat};
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

/// Saturating conversion from non-negative floating-point milliseconds to `u64`.
#[allow(dead_code)] // Used by `monotonic_now_ms` on wasm32 and unit tests on native.
fn saturating_f64_to_u64(value: f64) -> u64 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else if value >= u64::MAX as f64 {
        u64::MAX
    } else {
        value as u64
    }
}

/// Monotonic milliseconds for elapsed-time checks (grace windows, timeouts), immune to wall-clock
/// rollbacks. Uses `performance.now()` on `wasm32` (falling back to a non-decreasing wall clock if
/// unavailable) and `std::time::Instant` on native targets.
#[cfg(target_arch = "wasm32")]
pub fn monotonic_now_ms() -> u64 {
    use std::cell::Cell;

    thread_local! {
        static HIGH_WATER_MS: Cell<u64> = const { Cell::new(0) };
    }

    let perf_ms = web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .filter(|ms| ms.is_finite() && *ms >= 0.0);

    let raw = match perf_ms {
        Some(ms) => saturating_f64_to_u64(ms),
        None => saturating_f64_to_u64(js_sys::Date::now()),
    };
    HIGH_WATER_MS.with(|last| {
        let next = raw.max(last.get());
        last.set(next);
        next
    })
}

/// Monotonic milliseconds for elapsed-time checks (grace windows, timeouts), immune to wall-clock
/// rollbacks.
#[cfg(not(target_arch = "wasm32"))]
pub fn monotonic_now_ms() -> u64 {
    use std::{sync::OnceLock, time::Instant};

    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let elapsed = ORIGIN.get_or_init(Instant::now).elapsed().as_millis();
    elapsed.min(u128::from(u64::MAX)) as u64
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
    let options = DateTimeFormatOptions::new();
    options.set_month(MonthFormat::Long);
    options.set_year(YearFormat::Numeric);
    local_date(millis, &options)
}

/// The day of a time, as the reader's language writes it, e.g. "27 Oct".
pub fn day(millis: u64) -> String {
    let options = DateTimeFormatOptions::new();
    options.set_day(DayFormat::Numeric);
    options.set_month(MonthFormat::Short);
    local_date(millis, &options)
}

/// Format a date in the reader's language.
fn local_date(millis: u64, options: &DateTimeFormatOptions) -> String {
    let date = js_sys::Date::new(&(millis as f64).into());
    let language = web_sys::window()
        .and_then(|window| window.navigator().language())
        .unwrap_or_else(|| "en".to_string());
    date.to_locale_date_string(&language, options.as_ref())
        .into()
}

/// A size in bytes, for people.
pub fn size_u64(bytes: u64) -> String {
    match bytes {
        0..1_000 => format!("{bytes} B"),
        1_000..1_000_000 => format!("{:.0} KB", bytes as f64 / 1e3),
        1_000_000..1_000_000_000 => format!("{:.1} MB", bytes as f64 / 1e6),
        1_000_000_000..1_000_000_000_000 => format!("{:.1} GB", bytes as f64 / 1e9),
        _ => format!("{:.1} TB", bytes as f64 / 1e12),
    }
}

/// A size in bytes, for people. Delegates to [`size_u64`] so callers migrating off `usize` share
/// identical formatting.
pub fn size(bytes: usize) -> String {
    size_u64(bytes as u64)
}

/// An error and its causes, e.g. "protocol error: malformed message: ...", as
/// an error's kind alone rarely says what to do.
///
/// Consecutive layers that repeat the previous message (e.g. `session::Error` wrapping
/// `protocol::Error` with the same `SignInRequired`, `LimitExceeded`, or `Server` kind) are
/// collapsed so prefixes are never duplicated.
pub fn describe(error: &dyn std::error::Error) -> String {
    let mut description = error.to_string();
    let mut last = description.clone();
    let mut source = error.source();
    while let Some(error) = source {
        let next = error.to_string();
        let trimmed = next.trim();
        if trimmed.is_empty()
            || trimmed == last
            || description == trimmed
            || description.ends_with(&format!(": {trimmed}"))
        {
            source = error.source();
            continue;
        }
        let piece = if !last.is_empty() {
            trimmed
                .strip_prefix(&last)
                .and_then(|rest| rest.strip_prefix(": "))
                .unwrap_or(trimmed)
        } else {
            trimmed
        };
        if !piece.is_empty() {
            if !description.is_empty() {
                description.push_str(": ");
            }
            description.push_str(piece);
            last = piece.to_string();
        }
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn size_u64_formats_bytes_through_terabytes_without_32bit_truncation() {
        assert_eq!(size_u64(0), "0 B");
        assert_eq!(size_u64(999), "999 B");
        assert_eq!(size_u64(1_000), "1 KB");
        assert_eq!(size_u64(999_999), "1000 KB");
        assert_eq!(size_u64(1_000_000), "1.0 MB");
        assert_eq!(size_u64(500_000_000), "500.0 MB");
        assert_eq!(size_u64(1_000_000_000), "1.0 GB");
        // Strictly above 4 GiB (u32::MAX + 1): would wrap to 0 B if truncated via `as usize` on wasm32.
        let four_gib = u64::from(u32::MAX) + 1;
        assert_eq!(size_u64(four_gib), "4.3 GB");
        assert_eq!(size_u64(four_gib + 500_000_000), "4.8 GB");
        // TiB / TB scale and extreme values.
        assert_eq!(size_u64(1_000_000_000_000), "1.0 TB");
        assert_eq!(size_u64(1_u64 << 40), "1.1 TB");
        assert_eq!(size_u64(5 * (1_u64 << 40)), "5.5 TB");
        assert!(size_u64(u64::MAX).ends_with(" TB"));
        // Legacy usize wrapper matches size_u64.
        assert_eq!(size(12_345), size_u64(12_345));
    }

    #[test]
    fn saturating_f64_conversion_handles_edge_values() {
        assert_eq!(saturating_f64_to_u64(f64::NAN), 0);
        assert_eq!(saturating_f64_to_u64(f64::NEG_INFINITY), 0);
        assert_eq!(saturating_f64_to_u64(-10.0), 0);
        assert_eq!(saturating_f64_to_u64(0.0), 0);
        assert_eq!(saturating_f64_to_u64(1234.9), 1234);
        assert_eq!(saturating_f64_to_u64(f64::INFINITY), 0);
        assert_eq!(saturating_f64_to_u64(1e30), u64::MAX);
    }

    #[test]
    fn monotonic_clock_is_non_decreasing() {
        let first = monotonic_now_ms();
        let second = monotonic_now_ms();
        assert!(second >= first);
    }

    #[test]
    fn describe_deduplicates_repeated_sign_in_and_kind_prefixes() {
        // Exact error chain seen when a Connect 403 permission_denied travels through
        // `protocol::Error(SignInRequired)` -> `session::Error(SignInRequired)`.
        let proto_err = session::protocol::Error::new(
            session::protocol::ErrorKind::SignInRequired,
            "permission_denied: sign in to this server to use it",
        );
        let session_err = session::Error::from(proto_err);
        let formatted = describe(&session_err);
        assert_eq!(
            formatted,
            "sign-in required: permission_denied: sign in to this server to use it"
        );
        assert_eq!(
            formatted.matches("sign-in required").count(),
            1,
            "sign-in required prefix must never be duplicated: {formatted}"
        );

        // Bare `SignInRequired` without an inner server detail still formats once.
        let bare = session::Error::from(session::protocol::Error::from(
            session::protocol::ErrorKind::SignInRequired,
        ));
        assert_eq!(describe(&bare), "sign-in required");

        // Other matching kind pairs (`LimitExceeded`, `Server`) also collapse duplicates.
        let limit_err = session::Error::from(session::protocol::Error::new(
            session::protocol::ErrorKind::LimitExceeded,
            "resource_exhausted: inbox full",
        ));
        assert_eq!(
            describe(&limit_err),
            "limit exceeded: resource_exhausted: inbox full"
        );

        let server_err = session::Error::from(session::protocol::Error::new(
            session::protocol::ErrorKind::Server,
            "internal: upstream failed",
        ));
        assert_eq!(
            describe(&server_err),
            "server error: internal: upstream failed"
        );

        // Distinct layers stay preserved in full.
        let proto_malformed = session::Error::from(session::protocol::Error::new(
            session::protocol::ErrorKind::Malformed,
            "invalid key length",
        ));
        assert_eq!(
            describe(&proto_malformed),
            "protocol error: malformed message: invalid key length"
        );

        // Lower-layer error that already includes the outer prefix does not duplicate it.
        let prefixed = session::Error::new(
            session::ErrorKind::SignInRequired,
            "sign-in required: session expired",
        );
        assert_eq!(describe(&prefixed), "sign-in required: session expired");

        // Party error with identical message collapses to a single string.
        let party_err = session::Error::from(party::error::Error::from(
            party::error::ErrorKind::Undecryptable,
        ));
        assert_eq!(describe(&party_err), "cannot decrypt the message");
    }
}
