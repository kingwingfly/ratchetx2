//! Small helpers: keys as text, time, sizes, errors and waiting.

use base64::prelude::*;
use js_sys::Intl::{DateTimeFormatOptions, DayFormat, MonthFormat, YearFormat};
use session::PublicKey;
use unicode_general_category::{GeneralCategory, get_general_category};
use url::{Host, Url};
use wasm_bindgen::JsCast;

/// The most characters in this client's name. It goes in the greeting, the first message of each
/// chat it starts, which the server takes up to 4 KiB of; at 4 bytes a character at most, this
/// leaves the greeting far below that.
pub const NAME_MAX: usize = 64;

/// Normalize a suggested contact or peer name for sharing/display: strip Unicode format (`Cf`,
/// including all bidirectional overrides/isolates, ZWJ/ZWNJ, BOM, and tag characters) and control
/// (`Cc`) characters, collapse whitespace runs into single spaces, trim, and cap at [`NAME_MAX`]
/// characters.
pub fn sanitize_shared_name(name: &str) -> String {
    collapse_inline_text(name, NAME_MAX, false, false)
}

/// Normalize untrusted message text into a safe, single-line sidebar preview capped at `max_chars`
/// Unicode scalar values (appending `…` when truncated). Strips Unicode control (`Cc`) and format
/// (`Cf`, including BiDi overrides/isolates, BOM, and tag characters) while preserving ZWJ (`U+200D`)
/// so multi-codepoint emoji render intact, and collapses whitespace runs into single ASCII spaces.
pub fn sanitize_preview_text(text: &str, max_chars: usize) -> String {
    collapse_inline_text(text, max_chars, true, true)
}

fn collapse_inline_text(
    input: &str,
    max_chars: usize,
    preserve_zwj: bool,
    ellipsis: bool,
) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(input.len().min(max_chars.saturating_mul(4)));
    let mut count = 0usize;
    let mut pending_space = false;
    let mut truncated = false;
    for ch in input.chars() {
        let cat = get_general_category(ch);
        if cat == GeneralCategory::Format && !(preserve_zwj && ch == '\u{200D}') {
            continue;
        }
        if ch.is_whitespace() {
            if count > 0 {
                pending_space = true;
            }
            continue;
        }
        if cat == GeneralCategory::Control {
            continue;
        }
        if pending_space {
            if count + 2 > max_chars {
                truncated = true;
                break;
            }
            out.push(' ');
            count += 1;
            pending_space = false;
        }
        if count >= max_chars {
            truncated = true;
            break;
        }
        out.push(ch);
        count += 1;
    }
    if ellipsis && truncated {
        if count >= max_chars {
            out.pop();
        }
        while out.ends_with(' ') {
            out.pop();
        }
        out.push('…');
    }
    out
}

/// Sanitize an untrusted peer-supplied filename for UI display and `<a download>`: strips Unicode
/// format/BiDi (`Cf`) and control (`Cc`) characters, replaces path separators and filesystem-unsafe
/// characters, strips leading/trailing dots and whitespace, guards Windows reserved device names,
/// and caps length (falling back to `"file"` if empty).
pub fn sanitize_filename(name: &str) -> String {
    const MAX_FILENAME_CHARS: usize = 200;
    let mut cleaned = String::with_capacity(name.len().min(MAX_FILENAME_CHARS * 4));
    let mut prev_space = false;
    for ch in name.chars() {
        let cat = get_general_category(ch);
        if matches!(cat, GeneralCategory::Control | GeneralCategory::Format) {
            continue;
        }
        let mapped = match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_whitespace() => ' ',
            c => c,
        };
        if mapped == ' ' {
            if !prev_space && !cleaned.is_empty() {
                cleaned.push(' ');
                prev_space = true;
            }
        } else {
            cleaned.push(mapped);
            prev_space = false;
        }
    }
    let trimmed = cleaned.trim_matches(|c: char| c == ' ' || c == '.');
    if trimmed.is_empty() {
        return "file".to_string();
    }
    let mut safe = if is_windows_reserved_filename(trimmed) {
        format!("_{trimmed}")
    } else {
        trimmed.to_string()
    };
    if safe.chars().count() > MAX_FILENAME_CHARS {
        let ext = safe
            .rsplit_once('.')
            .map(|(_, e)| e)
            .filter(|e| !e.is_empty() && e.chars().count() <= 32)
            .map(|e| format!(".{e}"));
        if let Some(ext) = ext {
            let ext_chars = ext.chars().count();
            let keep = MAX_FILENAME_CHARS.saturating_sub(ext_chars);
            let stem: String = safe.chars().take(keep).collect();
            let stem = stem.trim_end_matches([' ', '.']);
            safe = if stem.is_empty() {
                format!("file{ext}")
            } else {
                format!("{stem}{ext}")
            };
        } else {
            safe = safe.chars().take(MAX_FILENAME_CHARS).collect();
            safe = safe.trim_end_matches([' ', '.']).to_string();
        }
    }
    if safe.is_empty() {
        "file".to_string()
    } else {
        safe
    }
}

fn is_windows_reserved_filename(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// Validate and canonicalize a relay server URL: must be `https://` (or `http://` on localhost /
/// loopback for local development), with no credentials, query, fragment, or non-root path.
/// Returns the canonical origin (e.g. `https://chat.example.com`), stripping default ports.
pub fn validate_relay_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("server address is empty".to_string());
    }
    let parsed = Url::parse(trimmed)
        .map_err(|_| "server address must be a valid https:// URL".to_string())?;
    let is_local_http = parsed.scheme() == "http"
        && matches!(
            parsed.host(),
            Some(Host::Domain(h)) if h.eq_ignore_ascii_case("localhost")
        )
        || (parsed.scheme() == "http"
            && matches!(
                parsed.host(),
                Some(Host::Ipv4(ip)) if ip.is_loopback()
            ))
        || (parsed.scheme() == "http"
            && matches!(
                parsed.host(),
                Some(Host::Ipv6(ip)) if ip.is_loopback()
            ));
    if parsed.scheme() != "https" && !is_local_http {
        return Err("server address must use https:// (or http://localhost)".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("server address must not include credentials".to_string());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("server address must not include a query or fragment".to_string());
    }
    if !matches!(parsed.path(), "" | "/") {
        return Err("server address must be an origin without a path".to_string());
    }
    let origin = parsed.origin().ascii_serialization();
    if origin == "null" {
        return Err("server address must have a valid host".to_string());
    }
    Ok(origin)
}

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
    const_hex::encode(bytes)
}

pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.starts_with("0x") || text.starts_with("0X") {
        return None;
    }
    const_hex::decode(text).ok()
}

/// Percent-decode a URI component or fragment, pure Rust for native tests.
pub fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = bytes.get(i + 1..i + 3)?;
            let [byte] = const_hex::decode_to_array::<_, 1>(pair).ok()?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The first bytes of a key, to tell keys apart at a glance; not enough to verify one.
pub fn short(key: &PublicKey) -> String {
    let hex = hex(&key[..4]);
    format!("{} {}", &hex[..4], &hex[4..])
}

/// Milliseconds since the Unix epoch.
#[cfg(target_arch = "wasm32")]
pub fn now() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(not(target_arch = "wasm32"))]
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
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

/// Clamp a signed millisecond timeout to a non-negative `u32` so negative delays never wrap to
/// `u32::MAX` when passed to `gloo-timers`.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn clamp_timeout_ms(millis: i32) -> u32 {
    u32::try_from(millis.max(0)).unwrap_or(0)
}

/// RAII browser timer backed by `gloo_timers::callback::Timeout` on `wasm32` (no-op stub on
/// native targets so host tests compile cleanly without target-only dependencies).
pub(crate) struct Timeout {
    #[cfg(target_arch = "wasm32")]
    _inner: gloo_timers::callback::Timeout,
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for Timeout {
    fn drop(&mut self) {}
}

impl Timeout {
    pub(crate) fn new(millis: i32, callback: impl FnOnce() + 'static) -> Self {
        #[cfg(target_arch = "wasm32")]
        {
            Self {
                _inner: gloo_timers::callback::Timeout::new(clamp_timeout_ms(millis), callback),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (millis, callback);
            Self {}
        }
    }
}

/// RAII DOM event listener backed by `gloo_events::EventListener` on `wasm32` (no-op stub on
/// native targets so host tests compile cleanly without target-only dependencies).
pub(crate) struct EventListener {
    #[cfg(target_arch = "wasm32")]
    inner: gloo_events::EventListener,
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for EventListener {
    fn drop(&mut self) {}
}

impl EventListener {
    pub(crate) fn new(
        target: &web_sys::EventTarget,
        event_type: &'static str,
        callback: impl FnMut(&web_sys::Event) + 'static,
    ) -> Self {
        #[cfg(target_arch = "wasm32")]
        {
            Self {
                inner: gloo_events::EventListener::new(target, event_type, callback),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (target, event_type, callback);
            Self {}
        }
    }

    pub(crate) fn new_cancellable(
        target: &web_sys::EventTarget,
        event_type: &'static str,
        callback: impl FnMut(&web_sys::Event) + 'static,
    ) -> Self {
        #[cfg(target_arch = "wasm32")]
        {
            Self {
                inner: gloo_events::EventListener::new_with_options(
                    target,
                    event_type,
                    gloo_events::EventListenerOptions::enable_prevent_default(),
                    callback,
                ),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (target, event_type, callback);
            Self {}
        }
    }

    pub(crate) fn forget(self) {
        #[cfg(target_arch = "wasm32")]
        self.inner.forget();
    }
}

/// Wait `millis` milliseconds. Cancels the underlying browser timer via `clearTimeout` if the
/// returned future is dropped early (e.g. inside `futures_util::future::select`).
#[cfg(target_arch = "wasm32")]
pub async fn sleep(millis: i32) {
    gloo_timers::future::TimeoutFuture::new(clamp_timeout_ms(millis)).await;
}

/// Instant async yield on non-wasm32 targets so native tests run deterministically without real
/// wall-clock sleeps.
#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(_millis: i32) {
    struct YieldOnce(bool);

    impl std::future::Future for YieldOnce {
        type Output = ();

        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            if self.0 {
                std::task::Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }

    YieldOnce(false).await;
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

    #[test]
    fn hex_and_percent_decode_reject_plus_signs() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x0a, 0x1f, 0xff]), "0a1fff");
        assert_eq!(from_hex(""), Some(vec![]));
        assert_eq!(from_hex("0a1f"), Some(vec![0x0a, 0x1f]));
        assert_eq!(from_hex("0A1F"), Some(vec![0x0a, 0x1f]));
        assert_eq!(from_hex("0x0a1f"), None);
        assert_eq!(from_hex("0X0a1f"), None);
        assert_eq!(from_hex("0a1"), None);
        assert_eq!(from_hex("+a"), None);
        assert_eq!(from_hex("+a+b"), None);
        assert_eq!(percent_decode("foo%20bar"), Some("foo bar".into()));
        assert_eq!(percent_decode("foo%+a"), None);
    }

    #[test]
    fn clamp_timeout_ms_clamps_negative_values_without_wrapping() {
        assert_eq!(clamp_timeout_ms(i32::MIN), 0);
        assert_eq!(clamp_timeout_ms(-1), 0);
        assert_eq!(clamp_timeout_ms(0), 0);
        assert_eq!(clamp_timeout_ms(250), 250);
        assert_eq!(clamp_timeout_ms(i32::MAX), i32::MAX as u32);
    }

    #[test]
    fn sanitize_shared_name_strips_unicode_format_and_controls() {
        // BiDi RLO, ZWJ/ZWNJ, BOM, tag chars, and C0/C1 controls are removed; whitespace collapses.
        assert_eq!(
            sanitize_shared_name("  \u{FEFF}Ali\u{202E}ce\u{200D}\u{200C}\t\nBob\x07\x7F  "),
            "Alice Bob"
        );
        assert_eq!(sanitize_shared_name("\u{E0041}\u{E0042}Eve"), "Eve");
        let long = "a".repeat(NAME_MAX + 20);
        assert_eq!(sanitize_shared_name(&long).chars().count(), NAME_MAX);
    }

    #[test]
    fn sanitize_filename_blocks_bidi_separators_and_reserved_names() {
        assert_eq!(
            sanitize_filename("invoice_\u{202E}fdp.exe"),
            "invoice_fdp.exe"
        );
        assert_eq!(sanitize_filename("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(sanitize_filename("..\\..\\evil.bat"), "_.._evil.bat");
        assert_eq!(sanitize_filename("CON.txt"), "_CON.txt");
        assert_eq!(sanitize_filename("nul"), "_nul");
        assert_eq!(sanitize_filename("lpt9.pdf"), "_lpt9.pdf");
        assert_eq!(sanitize_filename("...   \u{202E}\x00 ..."), "file");
        let long = format!("{}.pdf", "x".repeat(250));
        let sanitized = sanitize_filename(&long);
        assert!(sanitized.chars().count() <= 200);
        assert!(sanitized.ends_with(".pdf"));
    }

    #[test]
    fn validate_relay_url_enforces_https_or_local_http_origin() {
        assert_eq!(
            validate_relay_url("https://Chat.Example.COM:443/").unwrap(),
            "https://chat.example.com"
        );
        assert_eq!(
            validate_relay_url("https://relay.example.com:8443").unwrap(),
            "https://relay.example.com:8443"
        );
        assert_eq!(
            validate_relay_url("http://localhost:8787/").unwrap(),
            "http://localhost:8787"
        );
        assert_eq!(
            validate_relay_url("http://127.0.0.1:8787").unwrap(),
            "http://127.0.0.1:8787"
        );
        assert_eq!(
            validate_relay_url("http://[::1]:8787").unwrap(),
            "http://[::1]:8787"
        );
        for bad in [
            "",
            "chat.example.com",
            "http://chat.example.com",
            "ws://localhost:8787",
            "wss://chat.example.com",
            "javascript:alert(1)",
            "https://user:pass@chat.example.com",
            "https://chat.example.com?x=1",
            "https://chat.example.com#frag",
            "https://chat.example.com/subpath",
        ] {
            assert!(validate_relay_url(bad).is_err(), "should reject {bad:?}");
        }
    }
}
