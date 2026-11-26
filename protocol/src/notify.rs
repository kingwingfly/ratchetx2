//! Notifications: a client learns at once that something arrived for it, instead of polling.
//!
//! They are only hints, carrying nothing secret and zero sender metadata: what arrived is still
//! fetched with the [handshake](crate::handshake_v2) and [mailbox](crate::mailbox_v2) services,
//! so a lost notification only delays it. How they travel is up to the server; the Worker sends
//! each [`Notification`] as a binary WebSocket frame to the sockets a [`SubscribeRequest`] opened.
//!
//! Subscriptions sign `"notify.v2/subscribe"` ‖ audience length (u32 LE) ‖ canonical audience
//! bytes ‖ identity key (32 B) ‖ timestamp (u64 LE) ‖ nonce (16 B), and must be within
//! [`MAX_CLOCK_SKEW`](crate::MAX_CLOCK_SKEW) of the relay's clock.

use bytes::Bytes;
use x3dh::PublicKey;
use xeddsa::XEdDSAPrivateKey;

use crate::{
    ErrorKind, NormalizedAudience, Result, SigningBuf, check_safe_integer, fixed, try_random,
    verify_recent,
};

#[allow(missing_docs)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/notify.v1.rs"));
}

pub use proto::{notification::Event, *};

/// Required length in bytes of a [`SubscribeRequest::nonce`].
pub const SUBSCRIBE_NONCE_LENGTH: usize = 16;

impl SubscribeRequest {
    /// Normalize a configured relay URL or host and sign a v2 subscription with a fresh random
    /// 16-byte nonce. Use [`Self::sign_for_canonical_audience`] with a previously parsed audience.
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

    /// Sign a v2 subscription using an already normalized audience and a fresh CSPRNG 16-byte nonce.
    pub fn sign_for_canonical_audience(
        identity: &XEdDSAPrivateKey,
        audience: &NormalizedAudience,
        timestamp: u64,
    ) -> Result<Self> {
        let nonce = try_random::<SUBSCRIBE_NONCE_LENGTH>()?;
        Self::sign_for_canonical_audience_with_nonce(identity, audience, timestamp, nonce)
    }

    /// Sign a v2 subscription using an already normalized audience and an explicit 16-byte nonce
    /// (for deterministic tests).
    pub fn sign_for_canonical_audience_with_nonce(
        identity: &XEdDSAPrivateKey,
        audience: &NormalizedAudience,
        timestamp: u64,
        nonce: [u8; SUBSCRIBE_NONCE_LENGTH],
    ) -> Result<Self> {
        check_safe_integer(timestamp)?;
        let identity_key = identity.compute_public_key().to_bytes();
        let signature = identity.sign(subscribe_message_v2(
            audience.as_str(),
            &identity_key,
            timestamp,
            &nonce,
        )?);
        Ok(Self {
            identity_key: Bytes::copy_from_slice(&identity_key),
            timestamp,
            signature: Bytes::copy_from_slice(&signature),
            audience: audience.as_str().to_owned(),
            nonce: Bytes::copy_from_slice(&nonce),
        })
    }

    /// Verify a recent v2 subscription for a configured relay URL or host. An empty audience or
    /// non-16-byte nonce is malformed. A different audience or an invalid signature yields
    /// [`ErrorKind::InvalidSignature`]. Use [`Self::verify_for_canonical_audience`] with a
    /// previously parsed audience.
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
        let nonce: [u8; SUBSCRIBE_NONCE_LENGTH] = fixed(&self.nonce)?;
        if self.audience != expected_audience.as_str() {
            return Err(ErrorKind::InvalidSignature.into());
        }
        verify_recent(
            &self.identity_key,
            &self.signature,
            self.timestamp,
            now,
            |identity_key| {
                subscribe_message_v2(&self.audience, identity_key, self.timestamp, &nonce)
            },
        )
    }
}

fn subscribe_message_v2(
    audience: &str,
    identity_key: &PublicKey,
    timestamp: u64,
    nonce: &[u8; SUBSCRIBE_NONCE_LENGTH],
) -> Result<Vec<u8>> {
    let mut buf = SigningBuf::with_domain(
        b"notify.v2/subscribe",
        4 + audience.len() + 32 + 8 + SUBSCRIBE_NONCE_LENGTH,
    );
    buf.push_audience_le(audience)?;
    buf.push_bytes(identity_key);
    buf.push_u64_le(timestamp);
    buf.push_bytes(nonce);
    Ok(buf.into_vec())
}

impl Notification {
    /// A message arrived in the subscriber's unified mailbox (zero sender metadata).
    pub fn message() -> Self {
        Self {
            event: Some(Event::Message(true)),
        }
    }

    /// An initial message arrived in the subscriber's inbox.
    pub fn initial_message() -> Self {
        Self {
            event: Some(Event::InitialMessage(true)),
        }
    }
}

#[cfg(test)]
mod test {
    use prost::Message as _;

    use super::*;
    use crate::{MAX_CLOCK_SKEW, error::ErrorKind};

    #[test]
    fn canonical_subscriptions_preserve_scheme_specific_ports_and_distinct_nonces() {
        let identity = XEdDSAPrivateKey::generate();
        let bare = NormalizedAudience::parse("relay.example").unwrap();
        for (url, expected) in [
            ("http://relay.example:443", "relay.example:443"),
            ("https://relay.example:80", "relay.example:80"),
        ] {
            let audience = NormalizedAudience::parse(url).unwrap();
            let req1 =
                SubscribeRequest::sign_for_canonical_audience(&identity, &audience, 5).unwrap();
            let req2 =
                SubscribeRequest::sign_for_canonical_audience(&identity, &audience, 5).unwrap();
            assert_eq!(req1.audience, expected);
            assert_eq!(req1.nonce.len(), SUBSCRIBE_NONCE_LENGTH);
            assert_ne!(req1.nonce, req2.nonce);
            assert_eq!(
                req1.verify_for_canonical_audience(&audience, 5).unwrap(),
                identity.compute_public_key().to_bytes()
            );
            assert_eq!(
                req1.verify_for_canonical_audience(&bare, 5)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSignature
            );
            assert_eq!(
                req1.verify_for_audience(url, 5).unwrap(),
                identity.compute_public_key().to_bytes()
            );
        }
    }

    #[test]
    fn audience_and_nonce_bound_subscriptions_verify_strictly() {
        let identity = XEdDSAPrivateKey::generate();
        let now = 1_000_000;
        let fixed_nonce = [0x42u8; SUBSCRIBE_NONCE_LENGTH];
        for (url, expected) in [
            ("https://Relay.Example:443/", "relay.example"),
            ("https://München.example", "xn--mnchen-3ya.example"),
        ] {
            let audience = NormalizedAudience::parse(url).unwrap();
            let request = SubscribeRequest::sign_for_canonical_audience_with_nonce(
                &identity,
                &audience,
                now,
                fixed_nonce,
            )
            .unwrap();
            assert_eq!(request.audience, expected);
            assert_eq!(request.nonce.as_ref(), &fixed_nonce);
            // Verify the documented transcript independently of the protocol's verifier.
            let transcript = [
                b"notify.v2/subscribe".as_slice(),
                &(expected.len() as u32).to_le_bytes(),
                expected.as_bytes(),
                &identity.compute_public_key().to_bytes(),
                &now.to_le_bytes(),
                &fixed_nonce,
            ]
            .concat();
            identity
                .compute_public_key()
                .verify(transcript, &request.signature)
                .unwrap();

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
                request
                    .verify_for_audience(url, now + MAX_CLOCK_SKEW + 1)
                    .unwrap_err()
                    .kind(),
                ErrorKind::StaleTimestamp
            );
            // Mutating nonce invalidates signature; wrong nonce length is Malformed.
            let mut flipped_nonce = request.clone();
            flipped_nonce.nonce = Bytes::from_static(&[0x43; SUBSCRIBE_NONCE_LENGTH]);
            assert_eq!(
                flipped_nonce
                    .verify_for_audience(expected, now)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSignature
            );
            let mut short_nonce = request.clone();
            short_nonce.nonce = Bytes::from_static(&[0x42; SUBSCRIBE_NONCE_LENGTH - 1]);
            assert_eq!(
                short_nonce
                    .verify_for_audience(expected, now)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
            let mut missing_nonce = request.clone();
            missing_nonce.nonce = Bytes::new();
            assert_eq!(
                missing_nonce
                    .verify_for_audience(expected, now)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
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

        // Another identity cannot subscribe for `identity`.
        let other = XEdDSAPrivateKey::generate();
        let mut forged = SubscribeRequest::sign_for_audience(&other, "relay.example", now).unwrap();
        forged.identity_key = Bytes::copy_from_slice(&identity.compute_public_key().to_bytes());
        assert_eq!(
            forged
                .verify_for_audience("relay.example", now)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidSignature
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

        // Notification carries zero sender metadata.
        let msg_note = Notification::message();
        assert_eq!(msg_note.event, Some(Event::Message(true)));
        assert_eq!(
            Notification::decode(msg_note.encode_to_vec().as_slice()).unwrap(),
            msg_note
        );
        let init_note = Notification::initial_message();
        assert_eq!(init_note.event, Some(Event::InitialMessage(true)));
        assert_eq!(
            Notification::decode(init_note.encode_to_vec().as_slice()).unwrap(),
            init_note
        );
    }
}
