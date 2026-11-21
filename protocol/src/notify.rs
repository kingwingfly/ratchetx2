//! Notifications: a client learns at once that something arrived for it, instead of polling.
//!
//! They are only hints, carrying nothing secret: what arrived is still fetched with the
//! [handshake](crate::handshake) and [mailbox](crate::mailbox) services, so a lost notification
//! only delays it. How they travel is up to the server; the Worker sends each [`Notification`]
//! as a binary WebSocket frame to the sockets a [`SubscribeRequest`] opened.
//!
//! Legacy subscriptions sign `"notify.v1/subscribe"` ‖ identity key ‖ timestamp (u64 LE).
//! Audience-bound subscriptions sign `"notify.v2/subscribe"` ‖ audience length (u32 LE) ‖
//! canonical audience bytes ‖ identity key ‖ timestamp (u64 LE). Both versions must be
//! within [`MAX_CLOCK_SKEW`](crate::MAX_CLOCK_SKEW) of the relay's clock.

use bytes::Bytes;
use x3dh::PublicKey;
use xeddsa::XEdDSAPrivateKey;

use crate::{ErrorKind, NormalizedAudience, Result, check_safe_integer, verify_recent};

#[allow(missing_docs)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/notify.v1.rs"));
}

pub use proto::{notification::Event, *};

impl SubscribeRequest {
    /// A subscription to `identity`'s notifications, signed by it.
    pub fn sign(identity: &XEdDSAPrivateKey, timestamp: u64) -> Self {
        let identity_key = identity.compute_public_key().to_bytes();
        let signature = identity.sign(subscribe_message(&identity_key, timestamp));
        Self {
            identity_key: Bytes::copy_from_slice(&identity_key),
            timestamp,
            signature: Bytes::copy_from_slice(&signature),
            audience: String::new(),
        }
    }

    /// The identity key subscribing, once the signature by that key verifies and the timestamp
    /// is within [`MAX_CLOCK_SKEW`](crate::MAX_CLOCK_SKEW) of `now`, in milliseconds since the
    /// Unix epoch.
    pub fn verify(&self, now: u64) -> Result<PublicKey> {
        verify_recent(
            &self.identity_key,
            &self.signature,
            self.timestamp,
            now,
            |identity_key| Ok(subscribe_message(identity_key, self.timestamp)),
        )
    }

    /// Normalize a configured relay URL or host and sign a v2 subscription for it.
    /// Use [`Self::sign_for_canonical_audience`] with a previously parsed audience.
    pub fn sign_for_audience(
        identity: &XEdDSAPrivateKey,
        audience: &str,
        timestamp: u64,
    ) -> Result<Self> {
        Self::sign_for_canonical_audience(
            identity,
            &NormalizedAudience::parse(audience)?,
            timestamp,
        )
    }

    /// Sign a v2 subscription using the exact bytes of an already normalized audience.
    pub fn sign_for_canonical_audience(
        identity: &XEdDSAPrivateKey,
        audience: &NormalizedAudience,
        timestamp: u64,
    ) -> Result<Self> {
        check_safe_integer(timestamp)?;
        let identity_key = identity.compute_public_key().to_bytes();
        let signature = identity.sign(subscribe_message_v2(
            audience.as_str(),
            &identity_key,
            timestamp,
        )?);
        Ok(Self {
            identity_key: Bytes::copy_from_slice(&identity_key),
            timestamp,
            signature: Bytes::copy_from_slice(&signature),
            audience: audience.as_str().to_owned(),
        })
    }

    /// Verify a recent v2 subscription for a configured relay URL or host. An empty audience is
    /// malformed. A different audience or an invalid signature yields [`ErrorKind::InvalidSignature`].
    /// Use [`Self::verify_for_canonical_audience`] with a previously parsed audience.
    pub fn verify_for_audience(&self, expected_audience: &str, now: u64) -> Result<PublicKey> {
        self.verify_for_canonical_audience(&NormalizedAudience::parse(expected_audience)?, now)
    }

    /// Verify a recent v2 subscription against an already normalized relay audience.
    pub fn verify_for_canonical_audience(
        &self,
        expected_audience: &NormalizedAudience,
        now: u64,
    ) -> Result<PublicKey> {
        if self.audience.is_empty() {
            return Err(ErrorKind::Malformed.into());
        }
        if self.audience != expected_audience.as_str() {
            return Err(ErrorKind::InvalidSignature.into());
        }
        verify_recent(
            &self.identity_key,
            &self.signature,
            self.timestamp,
            now,
            |identity_key| subscribe_message_v2(&self.audience, identity_key, self.timestamp),
        )
    }

    /// Whether the request carries an audience for v2 verification.
    pub fn is_audience_bound(&self) -> bool {
        !self.audience.is_empty()
    }
}

fn subscribe_message_v2(
    audience: &str,
    identity_key: &PublicKey,
    timestamp: u64,
) -> Result<Vec<u8>> {
    // A DNS hostname or IP literal plus a port fits well within this bound.
    const MAX_AUDIENCE_LENGTH: usize = 1024;
    if audience.len() > MAX_AUDIENCE_LENGTH {
        return Err(ErrorKind::Malformed.into());
    }
    let len = u32::try_from(audience.len()).map_err(|_| ErrorKind::Malformed)?;
    let mut message = b"notify.v2/subscribe".to_vec();
    message.extend(len.to_le_bytes());
    message.extend(audience.as_bytes());
    message.extend(identity_key);
    message.extend(timestamp.to_le_bytes());
    Ok(message)
}

/// The bytes a subscription's signature covers.
fn subscribe_message(identity_key: &PublicKey, timestamp: u64) -> Vec<u8> {
    let mut message = b"notify.v1/subscribe".to_vec();
    message.extend(identity_key);
    message.extend(timestamp.to_le_bytes());
    message
}

impl Notification {
    /// A message from `sender` arrived.
    pub fn message_from(sender: &PublicKey) -> Self {
        Self {
            event: Some(Event::MessageFrom(Bytes::copy_from_slice(sender))),
        }
    }

    /// An initial message arrived.
    pub fn initial_message() -> Self {
        Self {
            event: Some(Event::InitialMessage(true)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{MAX_CLOCK_SKEW, error::ErrorKind};

    #[test]
    fn sign_and_verify() {
        let alice = XEdDSAPrivateKey::generate();
        let request = SubscribeRequest::sign(&alice, 1_000_000);
        assert_eq!(
            request.verify(1_000_000 + MAX_CLOCK_SKEW).unwrap(),
            alice.compute_public_key().to_bytes()
        );
        // Too far from the server's clock, either way.
        for now in [1_000_000 + MAX_CLOCK_SKEW + 1, 0] {
            assert_eq!(
                request.verify(now).unwrap_err().kind(),
                ErrorKind::StaleTimestamp
            );
        }
        // Another identity cannot subscribe for Alice.
        let mut forged = SubscribeRequest::sign(&XEdDSAPrivateKey::generate(), 1_000_000);
        forged.identity_key = request.identity_key.clone();
        assert_eq!(
            forged.verify(1_000_000).unwrap_err().kind(),
            ErrorKind::InvalidSignature
        );
    }

    #[test]
    fn legacy_subscription_keeps_its_wire_layout() {
        use prost::Message;

        let request = SubscribeRequest::sign(&XEdDSAPrivateKey::generate(), 1);
        let mut wire = vec![0x0a, 32];
        wire.extend_from_slice(&request.identity_key);
        wire.extend([0x10, 1, 0x1a, 64]);
        wire.extend_from_slice(&request.signature);
        assert_eq!(request.encode_to_vec(), wire);
        assert_eq!(SubscribeRequest::decode(wire.as_slice()).unwrap(), request);
        #[cfg(all(feature = "serde", feature = "connect"))]
        {
            let json = serde_json::to_value(&request).unwrap();
            assert!(json.get("audience").is_none());
            assert_eq!(
                serde_json::from_value::<SubscribeRequest>(json).unwrap(),
                request
            );
        }
    }

    #[test]
    fn canonical_subscriptions_preserve_scheme_specific_ports() {
        let identity = XEdDSAPrivateKey::generate();
        let bare = NormalizedAudience::parse("relay.example").unwrap();
        for (url, expected) in [
            ("http://relay.example:443", "relay.example:443"),
            ("https://relay.example:80", "relay.example:80"),
        ] {
            let audience = NormalizedAudience::parse(url).unwrap();
            let request =
                SubscribeRequest::sign_for_canonical_audience(&identity, &audience, 5).unwrap();
            assert_eq!(request.audience, expected);
            assert_eq!(
                request.verify_for_canonical_audience(&audience, 5).unwrap(),
                identity.compute_public_key().to_bytes()
            );
            assert_eq!(
                request
                    .verify_for_canonical_audience(&bare, 5)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSignature
            );
            assert_eq!(
                request.verify_for_audience(url, 5).unwrap(),
                identity.compute_public_key().to_bytes()
            );
        }
    }

    #[test]
    fn audience_bound_subscriptions_verify_only_for_the_signed_version_and_relay() {
        let identity = XEdDSAPrivateKey::generate();
        let now = 1_000_000;
        for (url, expected) in [
            ("https://Relay.Example:443/", "relay.example"),
            ("https://München.example", "xn--mnchen-3ya.example"),
        ] {
            let request = SubscribeRequest::sign_for_audience(&identity, url, now).unwrap();
            assert_eq!(request.audience, expected);
            // Verify the documented transcript independently of the protocol's verifier.
            let transcript = [
                b"notify.v2/subscribe".as_slice(),
                &(expected.len() as u32).to_le_bytes(),
                expected.as_bytes(),
                &identity.compute_public_key().to_bytes(),
                &now.to_le_bytes(),
            ]
            .concat();
            identity
                .compute_public_key()
                .verify(transcript, &request.signature)
                .unwrap();
            assert!(request.is_audience_bound());
            assert_eq!(
                request.verify_for_audience(expected, now).unwrap(),
                identity.compute_public_key().to_bytes()
            );
            assert_eq!(
                request
                    .verify_for_audience("relay-b.example", now)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSignature
            );
            assert_eq!(
                request.verify(now).unwrap_err().kind(),
                ErrorKind::InvalidSignature
            );
            assert_eq!(
                request
                    .verify_for_audience(url, now + MAX_CLOCK_SKEW + 1)
                    .unwrap_err()
                    .kind(),
                ErrorKind::StaleTimestamp
            );
            let mut tampered = request.clone();
            tampered.audience = "relay-b.example".into();
            assert_eq!(
                tampered
                    .verify_for_audience("relay-b.example", now)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSignature
            );
            tampered = request;
            tampered.signature = Bytes::from_static(&[0; 64]);
            assert_eq!(
                tampered
                    .verify_for_audience(expected, now)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSignature
            );
            assert_eq!(
                tampered.verify_for_audience("", now).unwrap_err().kind(),
                ErrorKind::Malformed
            );
        }
        let legacy = SubscribeRequest::sign(&identity, now);
        assert!(!legacy.is_audience_bound());
        assert_eq!(
            legacy
                .verify_for_audience("relay.example", now)
                .unwrap_err()
                .kind(),
            ErrorKind::Malformed
        );
        for bad in ["", "ftp://relay.example", &"a".repeat(1025)] {
            assert_eq!(
                SubscribeRequest::sign_for_audience(&identity, bad, now)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
        }
        assert_eq!(
            SubscribeRequest::sign_for_audience(
                &identity,
                "relay.example",
                crate::MAX_SAFE_INTEGER + 1
            )
            .unwrap_err()
            .kind(),
            ErrorKind::Malformed
        );
    }
}
