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

    let global: wasm_bindgen::JsValue = web_sys::window()
        .map(wasm_bindgen::JsValue::from)
        .unwrap_or_else(|| js_sys::global().into());
    let perf_ms = js_sys::Reflect::get(&global, &"performance".into())
        .ok()
        .filter(|perf| !perf.is_undefined() && !perf.is_null())
        .and_then(|perf| {
            let now = js_sys::Reflect::get(&perf, &"now".into())
                .ok()
                .and_then(|func| func.dyn_into::<js_sys::Function>().ok())?;
            now.call0(&perf).ok()?.as_f64()
        })
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
}
