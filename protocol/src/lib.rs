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
pub mod handshake_v2;
pub mod mailbox_v2;
pub mod notify;

pub use error::{Error, ErrorKind, Result};

/// Prost's generated `mailbox.v2` code references `super::super::handshake::v2::InitialMessageV2`.
mod handshake {
    pub(crate) mod v2 {
        pub use crate::handshake_v2::proto::*;
    }
}

/// How far, in milliseconds, the timestamp of a signed request or subscription may be from the
/// server's clock, as a signature would otherwise stay good forever or lock out an identity.
/// Clients sign them with the server's time, as its responses tell it, since a device's clock
/// may be off.
pub const MAX_CLOCK_SKEW: u64 = 5 * 60 * 1000;

/// JavaScript's largest exact integer (`2^53 - 1`); timestamps, sequences, and IDs above this
/// are rejected rather than clamped.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Maximum length in bytes of a canonical relay audience string (`host[:port]`).
pub const MAX_AUDIENCE_LENGTH: usize = 1024;

/// A canonical relay host and optional port, normalized with the original URL's scheme.
/// Keep this value when signing or verifying multiple requests for the same relay. For
/// example, `http://relay.example:443` retains its port after the scheme is removed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormalizedAudience(String);

impl NormalizedAudience {
    /// Parse a configured host or HTTP(S) / WS(S) URL using [`normalize_audience`].
    pub fn parse(raw: &str) -> Result<Self> {
        normalize_audience(raw).map(Self)
    }

    /// Borrow the canonical audience used in signed requests.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Take ownership of the canonical audience string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for NormalizedAudience {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for NormalizedAudience {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for NormalizedAudience {
    type Err = Error;

    fn from_str(raw: &str) -> Result<Self> {
        Self::parse(raw)
    }
}

impl TryFrom<&str> for NormalizedAudience {
    type Error = Error;

    fn try_from(raw: &str) -> Result<Self> {
        Self::parse(raw)
    }
}

impl TryFrom<String> for NormalizedAudience {
    type Error = Error;

    fn try_from(raw: String) -> Result<Self> {
        Self::parse(&raw)
    }
}

impl From<NormalizedAudience> for String {
    fn from(audience: NormalizedAudience) -> Self {
        audience.into_string()
    }
}

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
    let normalized = if port.is_empty() {
        host.to_string()
    } else {
        if !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ErrorKind::Malformed.into());
        }
        let port: u16 = port.parse().map_err(|_| ErrorKind::Malformed)?;
        if Some(port) == default_port || (default_port.is_none() && matches!(port, 80 | 443)) {
            host.to_string()
        } else {
            format!("{host}:{port}")
        }
    };
    if normalized.len() > MAX_AUDIENCE_LENGTH {
        return Err(ErrorKind::Malformed.into());
    }
    Ok(normalized)
}

/// Read a fixed-size bytes field, such as a 32-byte key.
///
/// Fails with [`ErrorKind::Malformed`] if it has another length.
pub fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| ErrorKind::Malformed.into())
}

/// Zeroizes the backing buffer of `bytes` in place when uniquely owned (including prost-decoded
/// and [`bytes::Bytes::copy_from_slice`] allocations). Static or still-shared handles are detached
/// without panicking.
pub(crate) fn zeroize_bytes(bytes: &mut bytes::Bytes) {
    let owned = core::mem::take(bytes);
    if let Ok(mut buf) = owned.try_into_mut() {
        zeroize::Zeroize::zeroize(buf.as_mut());
    }
}

/// `N` cryptographically random bytes, failing with [`ErrorKind::Server`] if the OS RNG fails.
pub(crate) fn try_random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| ErrorKind::Server)?;
    Ok(bytes)
}

/// Validates that a 32-byte key is a canonical, prime-order Curve25519 public key.
pub(crate) fn check_canonical_key(key: &x3dh::PublicKey) -> Result<()> {
    if !xeddsa::is_canonical_public_key(key) {
        return Err(ErrorKind::Malformed.into());
    }
    xeddsa::XEdDSAPublicKey::new(key).map_err(|_| ErrorKind::Malformed)?;
    Ok(())
}

/// Verifies that an incoming `actual` audience string is non-empty, within
/// [`MAX_AUDIENCE_LENGTH`], and matches the canonicalized `expected_audience`.
pub(crate) fn verify_audience(actual: &str, expected_audience: &str) -> Result<()> {
    let expected = NormalizedAudience::parse(expected_audience)?;
    if actual.is_empty() || actual.len() > MAX_AUDIENCE_LENGTH {
        return Err(ErrorKind::Malformed.into());
    }
    if actual != expected.as_str() {
        return Err(ErrorKind::InvalidSignature.into());
    }
    Ok(())
}

/// Small checked cursor for building canonical domain-separated signing transcripts across
/// `handshake_v2`, `mailbox_v2`, and `notify`.
pub(crate) struct SigningBuf(Vec<u8>);

impl SigningBuf {
    pub(crate) fn with_domain(domain: &[u8], extra_capacity: usize) -> Self {
        let mut buf = Vec::with_capacity(domain.len().saturating_add(extra_capacity));
        buf.extend_from_slice(domain);
        Self(buf)
    }

    pub(crate) fn push_u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub(crate) fn push_u32_be(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn push_u64_be(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn push_u64_le(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn push_bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    pub(crate) fn push_len_bytes_be(&mut self, bytes: &[u8]) -> Result<()> {
        let len = u32::try_from(bytes.len()).map_err(|_| ErrorKind::Malformed)?;
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn push_len_bytes_le(&mut self, bytes: &[u8]) -> Result<()> {
        let len = u32::try_from(bytes.len()).map_err(|_| ErrorKind::Malformed)?;
        self.0.extend_from_slice(&len.to_le_bytes());
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn push_audience_be(&mut self, audience: &str) -> Result<()> {
        if audience.is_empty() || audience.len() > MAX_AUDIENCE_LENGTH {
            return Err(ErrorKind::Malformed.into());
        }
        self.push_len_bytes_be(audience.as_bytes())
    }

    pub(crate) fn push_audience_le(&mut self, audience: &str) -> Result<()> {
        if audience.is_empty() || audience.len() > MAX_AUDIENCE_LENGTH {
            return Err(ErrorKind::Malformed.into());
        }
        self.push_len_bytes_le(audience.as_bytes())
    }

    pub(crate) fn push_count_be(&mut self, count: usize) -> Result<()> {
        let count = u32::try_from(count).map_err(|_| ErrorKind::Malformed)?;
        self.0.extend_from_slice(&count.to_be_bytes());
        Ok(())
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

/// Validates that `value` does not exceed [`MAX_SAFE_INTEGER`].
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

#[cfg(all(test, feature = "server"))]
pub(crate) fn test_public_key(seed: u8) -> x3dh::PublicKey {
    assert_ne!(seed, 0, "seed must be non-zero");
    let mut scalar = [0u8; 32];
    scalar[0] = seed;
    scalar[1] = seed.wrapping_mul(37);
    xeddsa::XEdDSAPrivateKey::from_bytes(scalar)
        .expect("canonical non-zero scalar")
        .compute_public_key()
        .to_bytes()
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
            ("http://relay.example:443", "relay.example:443"),
            ("https://relay.example:80", "relay.example:80"),
        ] {
            let url = url::Url::parse(input).unwrap();
            assert_eq!(
                &url[url::Position::BeforeHost..url::Position::AfterPort],
                expected
            );
            assert_eq!(normalize_audience(input).unwrap(), expected);
            assert_eq!(NormalizedAudience::parse(input).unwrap().as_str(), expected);
        }
        for (input, expected) in [
            ("chat.example.com", "chat.example.com"),
            ("  Chat.Example.COM  ", "chat.example.com"),
            ("chat.example.com:8787", "chat.example.com:8787"),
            ("chat.example.com:08787", "chat.example.com:8787"),
            ("chat.example.com:443", "chat.example.com"),
            ("chat.example.com:80", "chat.example.com"),
            ("chat.example.com:0443", "chat.example.com"),
            ("chat.example.com:0080", "chat.example.com"),
            ("chat.example.com:", "chat.example.com"),
            ("chat.example.com/some/path?q=1#frag", "chat.example.com"),
            ("https://chat.example.com", "chat.example.com"),
            ("HTTPS://CHAT.EXAMPLE.COM:443/", "chat.example.com"),
            ("HTTPS://Chat.Example.com:0443/api", "chat.example.com"),
            ("HTTP://localhost:80/", "localhost"),
            ("HTTP://localhost:0080/path", "localhost"),
            ("http://localhost:8787/", "localhost:8787"),
            (
                "WSS://Chat.Example.com:443/notifications",
                "chat.example.com",
            ),
            ("WS://localhost:80/notifications", "localhost"),
            ("http://[0:0::1]:8787", "[::1]:8787"),
            ("https://[0:0::1]:0443/", "[::1]"),
            ("[0:0::1]:443", "[::1]"),
            ("[0:0::1]:80", "[::1]"),
            ("[2001:0DB8:0000::1]:08443", "[2001:db8::1]:8443"),
            ("[::1]:", "[::1]"),
            ("münchen.example:8443", "xn--mnchen-3ya.example:8443"),
            ("example.com/path?to=https://example.org", "example.com"),
        ] {
            assert_eq!(
                normalize_audience(input).unwrap(),
                expected,
                "input: {input:?}"
            );
        }
        let oversized = format!("{}.example", "a".repeat(MAX_AUDIENCE_LENGTH));
        for bad in [
            "",
            "   ",
            "xn--.example",
            "https://example.com/a\0b",
            "example.com\u{7f}",
            "ex%00ample.com",
            "https://user@example.com",
            "https://user:pass@chat.example.com",
            "user@chat.example.com",
            "ftp://example.com",
            "chat.example.com:99999",
            "chat.example.com:-1",
            "chat.example.com:+443",
            "chat.example.com:abc",
            ":8787",
            "http://",
            "[::1",
            "example.com]",
            "[::1]x",
            "::1",
            "chat example.com",
            oversized.as_str(),
        ] {
            assert_eq!(
                normalize_audience(bad).unwrap_err().kind(),
                ErrorKind::Malformed,
                "expected error for {bad:?}"
            );
        }
    }
}
