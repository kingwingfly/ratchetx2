#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

pub mod attachment;
#[cfg(feature = "connect")]
pub mod connect;
pub mod content;
pub mod error;
pub mod handshake;
#[cfg(feature = "pq")]
pub mod handshake_v2;
pub mod mailbox;
#[cfg(feature = "pq")]
pub mod mailbox_v2;
pub mod notify;

pub use error::{Error, ErrorKind, Result};

/// How far, in milliseconds, the timestamp of a signed request or subscription may be from the
/// server's clock, as a signature would otherwise stay good forever or lock out an identity.
/// Clients sign them with the server's time, as its responses tell it, since a device's clock
/// may be off.
pub const MAX_CLOCK_SKEW: u64 = 5 * 60 * 1000;

/// JavaScript's largest exact integer (`2^53 - 1`); timestamps, sequences, and IDs above this
/// are rejected rather than clamped.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Canonical relay audience (`host[:port]`) for a configured host or HTTP(S) / WS(S) URL.
/// Hosts use URL-standard IDNA and IP address serialization. Paths, queries, fragments and
/// default ports are omitted. With no scheme, both 80 and 443 are considered default ports.
/// Invalid authorities, userinfo, internal whitespace and control characters are malformed.
pub fn normalize_audience(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if raw.bytes().any(|b| b.is_ascii_control()) || trimmed.chars().any(char::is_whitespace) {
        return Err(ErrorKind::Malformed.into());
    }
    let (rest, default_port) = match trimmed
        .split_once("://")
        .filter(|(scheme, _)| !scheme.contains(['/', '?', '#']))
    {
        Some((scheme, rest))
            if scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss") =>
        {
            (rest, Some(443))
        }
        Some((scheme, rest))
            if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("ws") =>
        {
            (rest, Some(80))
        }
        Some(_) => return Err(ErrorKind::Malformed.into()),
        None => (trimmed, None),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // A bracketed IPv6 host ends in ']' unless a port follows it.
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !authority.ends_with(']') => (host, port),
        _ => (authority, ""),
    };
    let host = url::Host::parse(host).map_err(|_| ErrorKind::Malformed)?;
    if port.is_empty() {
        return Ok(host.to_string());
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ErrorKind::Malformed.into());
    }
    let port: u16 = port.parse().map_err(|_| ErrorKind::Malformed)?;
    if Some(port) == default_port || (default_port.is_none() && matches!(port, 80 | 443)) {
        Ok(host.to_string())
    } else {
        Ok(format!("{host}:{port}"))
    }
}

/// Read a fixed-size bytes field, such as a 32-byte key.
///
/// Fails with [`ErrorKind::Malformed`] if it has another length.
pub fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| ErrorKind::Malformed.into())
}

/// Validates that a 32-byte key is a canonical non-zero Curve25519 encoding.
#[cfg(any(feature = "server", feature = "pq"))]
pub(crate) fn check_canonical_key(key: &x3dh::PublicKey) -> Result<()> {
    if !xeddsa::is_canonical_public_key(key) || *key == [0u8; xeddsa::PUBLIC_KEY_LENGTH] {
        return Err(ErrorKind::Malformed.into());
    }
    Ok(())
}

/// Validates that `timestamp` does not exceed [`MAX_SAFE_INTEGER`].
pub(crate) fn check_safe_integer(value: u64) -> Result<()> {
    if value > MAX_SAFE_INTEGER {
        return Err(ErrorKind::Malformed.into());
    }
    Ok(())
}

/// Current wall-clock time in milliseconds since the Unix epoch.
#[cfg(feature = "server")]
pub(crate) fn now_millis() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(MAX_SAFE_INTEGER)
        })
}

/// Validates that a monotonically increasing timestamp does not exceed [`MAX_SAFE_INTEGER`] or
/// lie more than [`MAX_CLOCK_SKEW`] in the future.
#[cfg(feature = "server")]
pub(crate) fn check_monotonic_timestamp(timestamp: u64, now: u64) -> Result<()> {
    check_safe_integer(timestamp)?;
    if timestamp > now.saturating_add(MAX_CLOCK_SKEW) {
        return Err(ErrorKind::StaleTimestamp.into());
    }
    Ok(())
}

/// The identity key of a request it signed, such as a subscription or a v2 signed call, once
/// `signature`, by that key, of `message(identity key)` verifies and `timestamp` does not exceed
/// [`MAX_SAFE_INTEGER`] and is within [`MAX_CLOCK_SKEW`] of `now`, in milliseconds since the
/// Unix epoch.
pub(crate) fn verify_recent(
    identity_key: &[u8],
    signature: &[u8],
    timestamp: u64,
    now: u64,
    message: impl FnOnce(&x3dh::PublicKey) -> Result<Vec<u8>>,
) -> Result<x3dh::PublicKey> {
    check_safe_integer(timestamp)?;
    let identity_key = fixed(identity_key)?;
    xeddsa::XEdDSAPublicKey::new(&identity_key)?.verify(message(&identity_key)?, signature)?;
    if timestamp.abs_diff(now) > MAX_CLOCK_SKEW {
        return Err(ErrorKind::StaleTimestamp.into());
    }
    Ok(identity_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_audiences_match_url_hosts_and_ports() {
        for (input, expected) in [
            ("https://München.example:443/api", "xn--mnchen-3ya.example"),
            ("http://BÜCHER.example:80", "xn--bcher-kva.example"),
            ("wss://example。com:08080", "example.com:8080"),
            ("http://[::ffff:192.0.2.1]:", "[::ffff:c000:201]"),
            ("http://127.1:80", "127.0.0.1"),
        ] {
            let url = url::Url::parse(input).unwrap();
            assert_eq!(
                &url[url::Position::BeforeHost..url::Position::AfterPort],
                expected
            );
            assert_eq!(normalize_audience(input).unwrap(), expected);
        }
        assert_eq!(
            normalize_audience("münchen.example:8443").unwrap(),
            "xn--mnchen-3ya.example:8443"
        );
        assert_eq!(
            normalize_audience("example.com/path?to=https://example.org").unwrap(),
            "example.com"
        );
        for bad in [
            "xn--.example",
            "https://example.com/a\0b",
            "example.com\u{7f}",
            "ex%00ample.com",
            "https://user@example.com",
            "ftp://example.com",
            "example.com]",
            "[::1]x",
        ] {
            assert_eq!(
                normalize_audience(bad).unwrap_err().kind(),
                ErrorKind::Malformed
            );
        }
    }
}
