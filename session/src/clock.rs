//! A server's clock, as this device sees it.

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

/// A server's clock, as this device sees it from the `Date` of the server's responses.
///
/// The server takes the requests it checks the time of, such as a subscription, only within
/// `protocol::MAX_CLOCK_SKEW` of its own clock, as a signature would otherwise stay good
/// forever. A [`Client`](crate::Client) signs them with this clock, so that a device whose clock
/// is off, e.g. set by hand, still makes requests that the server takes. Until a response tells
/// the server's time, it is this device's clock. Its clones share it, so that a transport can
/// learn it for a client.
#[derive(Debug, Clone, Default)]
pub struct ServerClock {
    /// The server's clock less this device's, in milliseconds.
    offset: Arc<AtomicI64>,
}

impl ServerClock {
    /// The server's time now, in milliseconds since the Unix epoch.
    pub fn now(&self) -> u64 {
        crate::now().saturating_add_signed(self.offset.load(Ordering::Relaxed))
    }

    /// Learn that the server's time is `server_time`, in milliseconds since the Unix epoch.
    pub fn observe(&self, server_time: u64) {
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
                self.observe(seconds.saturating_mul(1000).saturating_add(500));
                true
            }
            None => false,
        }
    }
}

/// The seconds since the Unix epoch of an HTTP date in the format servers send, IMF-fixdate:
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
fn parse_http_date(date: &str) -> Option<u64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (_weekday, date) = date.trim().split_once(", ")?;
    let mut parts = date.split(' ');
    let day: u64 = parts.next()?.parse().ok()?;
    let month = parts.next()?;
    let month = MONTHS.iter().position(|name| *name == month)? as u64 + 1;
    let year: u64 = parts.next()?.parse().ok()?;
    let mut time = parts.next()?.split(':');
    let mut field = || time.next()?.parse::<u64>().ok();
    let (hours, minutes, seconds) = (field()?, field()?, field()?);
    if parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    if !(1970..=9999).contains(&year)
        || !(1..=31).contains(&day)
        || hours > 23
        || minutes > 59
        || seconds > 60
    {
        return None;
    }
    // Days since the epoch of a date in the proleptic Gregorian calendar, by Howard Hinnant's
    // algorithm, with years starting in March so that a leap day comes last.
    let year = if month <= 2 { year - 1 } else { year };
    let (era, year_of_era) = (year / 400, year % 400);
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = (era * 146_097 + day_of_era).checked_sub(719_468)?;
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
            // Not IMF-fixdate.
            ("Sunday, 06-Nov-94 08:49:37 GMT", None),
            ("Sun Nov  6 08:49:37 1994", None),
            ("Sun, 06 Nov 1994 08:49:37 UTC", None),
            ("Sun, 06 Foo 1994 08:49:37 GMT", None),
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
        assert!(clock.observe_date("Thu, 01 Jan 1970 00:00:10 GMT"));
        assert!(clock.now().abs_diff(10_500) < 1000);
        assert!(!clock.observe_date("yesterday"));
    }
}
