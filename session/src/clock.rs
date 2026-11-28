//! A server's clock, as this device sees it.

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

use crate::error::{ErrorKind, Result};

/// Maximum default absolute drift (24 hours, in milliseconds) tolerated between the local device
/// clock and the server's observed `Date` before security-sensitive manifest operations fail
/// closed with [`ErrorKind::ClockSkew`].
pub const DEFAULT_MAX_TRUSTED_DRIFT_MS: u64 = 24 * 60 * 60 * 1000;

/// A server's clock, as this device sees it from the `Date` of the server's responses.
///
/// The server takes the requests it checks the time of, such as a subscription, only within
/// `protocol::MAX_CLOCK_SKEW` of its own clock, as a signature would otherwise stay good
/// forever. A [`Client`](crate::Client) signs them with this clock, so that a device whose clock
/// is off, e.g. set by hand, still makes requests that the server takes. Until a response tells
/// the server's time, it is this device's clock. Its clones share it, so that a transport can
/// learn it for a client.
///
/// For security-sensitive capability-manifest freshness and issuance checks, callers use
/// [`Self::trusted_clock_pair`], which fails closed with [`ErrorKind::ClockSkew`] whenever the
/// local clock is invalid (`0` or above [`protocol::MAX_SAFE_INTEGER`]) or the observed drift
/// exceeds `max_trusted_drift_ms` (defaulting to [`DEFAULT_MAX_TRUSTED_DRIFT_MS`]).
#[derive(Debug, Clone)]
pub struct ServerClock {
    /// The server's clock less this device's, in milliseconds.
    offset: Arc<AtomicI64>,
    /// Maximum absolute drift (ms) trusted by [`Self::trusted_clock_pair`].
    max_trusted_drift_ms: u64,
}

impl Default for ServerClock {
    fn default() -> Self {
        Self::with_max_drift(DEFAULT_MAX_TRUSTED_DRIFT_MS)
    }
}

impl ServerClock {
    /// Create a clock with a custom maximum trusted drift threshold (in milliseconds) for
    /// [`Self::trusted_clock_pair`].
    pub fn with_max_drift(max_trusted_drift_ms: u64) -> Self {
        Self {
            offset: Arc::new(AtomicI64::new(0)),
            max_trusted_drift_ms,
        }
    }

    /// The server's time now, in milliseconds since the Unix epoch.
    ///
    /// Intended for relay-authenticated request timestamps checked within
    /// [`protocol::MAX_CLOCK_SKEW`]. Security-sensitive manifest checks use
    /// [`Self::trusted_clock_pair`].
    pub fn now(&self) -> u64 {
        crate::now().saturating_add_signed(self.offset.load(Ordering::Relaxed))
    }

    /// The observed offset (`server_time - local_time`) in milliseconds.
    pub fn offset_ms(&self) -> i64 {
        self.offset.load(Ordering::Relaxed)
    }

    /// Whether the observed offset exceeds this clock's maximum trusted drift threshold.
    pub fn is_drift_exceeded(&self) -> bool {
        self.offset_ms().unsigned_abs() > self.max_trusted_drift_ms
    }

    /// Return `(local_now, server_now)` in milliseconds since the Unix epoch, failing closed with
    /// [`ErrorKind::ClockSkew`] if the local clock is invalid (`0` or above
    /// [`protocol::MAX_SAFE_INTEGER`]), if `|server_now - local_now|` exceeds this clock's
    /// maximum trusted drift threshold, or if `server_now` is out of range.
    pub fn trusted_clock_pair(&self) -> Result<(u64, u64)> {
        self.trusted_clock_pair_at(crate::now())
    }

    pub(crate) fn trusted_clock_pair_at(&self, local: u64) -> Result<(u64, u64)> {
        if local == 0 || local > protocol::MAX_SAFE_INTEGER {
            return Err(ErrorKind::ClockSkew.into());
        }
        let offset = self.offset_ms();
        if offset.unsigned_abs() > self.max_trusted_drift_ms {
            return Err(ErrorKind::ClockSkew.into());
        }
        let server = local
            .checked_add_signed(offset)
            .ok_or(ErrorKind::ClockSkew)?;
        if server == 0 || server > protocol::MAX_SAFE_INTEGER {
            return Err(ErrorKind::ClockSkew.into());
        }
        Ok((local, server))
    }

    /// Learn that the server's time is `server_time`, in milliseconds since the Unix epoch.
    ///
    /// Ignores values exceeding [`protocol::MAX_SAFE_INTEGER`] so an attacker-controlled or
    /// corrupted clock observation cannot poison future signed timestamps.
    pub fn observe(&self, server_time: u64) {
        if server_time > protocol::MAX_SAFE_INTEGER {
            return;
        }
        let offset = i64::try_from(server_time)
            .unwrap_or(i64::MAX)
            .saturating_sub(i64::try_from(crate::now()).unwrap_or(i64::MAX));
        self.offset.store(offset, Ordering::Relaxed);
    }

    /// Learn the server's time from the `Date` header of a response it just gave, an HTTP date
    /// such as `Sun, 06 Nov 1994 08:49:37 GMT`. Returns whether it was one.
    pub fn observe_date(&self, date: &str) -> bool {
        match parse_http_date(date) {
            // To the second: half of one went by in it, on average.
            Some(seconds) => {
                let millis = seconds.saturating_mul(1000).saturating_add(500);
                if millis > protocol::MAX_SAFE_INTEGER {
                    return false;
                }
                self.observe(millis);
                true
            }
            None => false,
        }
    }
}

/// Parses an exact-width unsigned ASCII decimal field (rejecting `+`, `-`, whitespace, or wrong
/// width).
fn parse_fixed_digits(raw: &str, len: usize) -> Option<u64> {
    if raw.len() != len || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

/// Exact number of days in `month` (1..=12) of proleptic Gregorian `year`.
fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// The seconds since the Unix epoch of an HTTP date in the format servers send, IMF-fixdate:
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
fn parse_http_date(date: &str) -> Option<u64> {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (weekday, date) = date.trim().split_once(", ")?;
    let weekday_idx = WEEKDAYS.iter().position(|name| *name == weekday)? as u64;
    let mut parts = date.split(' ');
    let day = parse_fixed_digits(parts.next()?, 2)?;
    let month_str = parts.next()?;
    let month = MONTHS.iter().position(|name| *name == month_str)? as u64 + 1;
    let year = parse_fixed_digits(parts.next()?, 4)?;
    let mut time = parts.next()?.split(':');
    let hours = parse_fixed_digits(time.next()?, 2)?;
    let minutes = parse_fixed_digits(time.next()?, 2)?;
    let seconds = parse_fixed_digits(time.next()?, 2)?;
    if time.next().is_some() {
        return None;
    }
    if parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    if !(1970..=9999).contains(&year)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hours > 23
        || minutes > 59
        || seconds > 60
    {
        return None;
    }
    // Days since the epoch of a date in the proleptic Gregorian calendar, by Howard Hinnant's
    // algorithm, with years starting in March so that a leap day comes last.
    let y = if month <= 2 { year - 1 } else { year };
    let (era, year_of_era) = (y / 400, y % 400);
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = (era * 146_097 + day_of_era).checked_sub(719_468)?;
    // 1970-01-01 was a Thursday (index 4).
    if (days + 4) % 7 != weekday_idx {
        return None;
    }
    Some(((days * 24 + hours) * 60 + minutes) * 60 + seconds)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn http_dates() {
        for (date, seconds) in [
            ("Thu, 01 Jan 1970 00:00:00 GMT", Some(0)),
            ("Sun, 06 Nov 1994 08:49:37 GMT", Some(784_111_777)),
            ("Tue, 29 Feb 2000 12:00:00 GMT", Some(951_825_600)),
            ("Wed, 28 Oct 2026 04:33:38 GMT", Some(1_793_162_018)),
            // Not IMF-fixdate, invalid calendar dates, wrong weekdays, or bad syntax.
            ("Sunday, 06-Nov-94 08:49:37 GMT", None),
            ("Sun Nov  6 08:49:37 1994", None),
            ("Sun, 06 Nov 1994 08:49:37 UTC", None),
            ("Sun, 06 Foo 1994 08:49:37 GMT", None),
            ("Bogus, 31 Feb 2026 00:00:00:99 GMT", None),
            ("Sat, 31 Feb 2026 00:00:00 GMT", None),
            ("Sun, 29 Feb 2026 00:00:00 GMT", None),
            ("Thu, +01 Jan 1970 00:00:00 GMT", None),
            ("Thu, 1 Jan 1970 00:00:00 GMT", None),
            ("Mon, 01 Jan 1970 00:00:00 GMT", None),
            ("Sun, 06 Nov 1994 08:49:37:99 GMT", None),
            ("", None),
        ] {
            assert_eq!(parse_http_date(date), seconds, "{date}");
        }
    }

    #[test]
    fn tells_the_servers_time() {
        let clock = ServerClock::default();
        let shared = clock.clone();
        let now = crate::now();
        assert!(clock.now().abs_diff(now) < 1000);
        // Its clones learn it too.
        shared.observe(now + 10 * 60 * 1000);
        assert!(clock.now().abs_diff(now + 10 * 60 * 1000) < 1000);
        // Out-of-range observation above MAX_SAFE_INTEGER is ignored rather than poisoning offset.
        shared.observe(u64::MAX);
        shared.observe(protocol::MAX_SAFE_INTEGER + 1);
        assert!(clock.now().abs_diff(now + 10 * 60 * 1000) < 1000);
        assert!(clock.observe_date("Thu, 01 Jan 1970 00:00:10 GMT"));
        assert!(clock.now().abs_diff(10_500) < 1000);
        assert!(!clock.observe_date("yesterday"));
    }

    #[test]
    fn trusted_clock_pair_enforces_local_validity_and_drift_cap() {
        let clock = ServerClock::default();
        assert_eq!(clock.offset_ms(), 0);
        assert!(!clock.is_drift_exceeded());
        let (local, server) = clock.trusted_clock_pair().unwrap();
        assert_eq!(local, server);

        // Broken / pre-epoch or above-MAX_SAFE_INTEGER local clocks fail closed with ClockSkew.
        assert_eq!(
            clock.trusted_clock_pair_at(0).unwrap_err().kind(),
            ErrorKind::ClockSkew
        );
        assert_eq!(
            clock
                .trusted_clock_pair_at(protocol::MAX_SAFE_INTEGER + 1)
                .unwrap_err()
                .kind(),
            ErrorKind::ClockSkew
        );

        // Exact ±24h boundary passes; ±25h fails closed with ClockSkew (no silent clamping).
        let now = 1_750_000_000_000u64;
        clock
            .offset
            .store(DEFAULT_MAX_TRUSTED_DRIFT_MS as i64, Ordering::Relaxed);
        assert!(!clock.is_drift_exceeded());
        assert_eq!(
            clock.trusted_clock_pair_at(now).unwrap(),
            (now, now + DEFAULT_MAX_TRUSTED_DRIFT_MS)
        );
        clock
            .offset
            .store(-(DEFAULT_MAX_TRUSTED_DRIFT_MS as i64), Ordering::Relaxed);
        assert!(!clock.is_drift_exceeded());
        assert_eq!(
            clock.trusted_clock_pair_at(now).unwrap(),
            (now, now - DEFAULT_MAX_TRUSTED_DRIFT_MS)
        );

        let twenty_five_hours = 25 * 60 * 60 * 1000i64;
        for bad_offset in [twenty_five_hours, -twenty_five_hours] {
            clock.offset.store(bad_offset, Ordering::Relaxed);
            assert!(clock.is_drift_exceeded());
            assert_eq!(
                clock.trusted_clock_pair_at(now).unwrap_err().kind(),
                ErrorKind::ClockSkew
            );
        }

        // Custom drift threshold works as configured.
        let strict = ServerClock::with_max_drift(60_000);
        strict.offset.store(60_001, Ordering::Relaxed);
        assert!(strict.is_drift_exceeded());
        assert_eq!(
            strict.trusted_clock_pair_at(now).unwrap_err().kind(),
            ErrorKind::ClockSkew
        );
    }
}
