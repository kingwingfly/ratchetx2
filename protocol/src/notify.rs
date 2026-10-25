//! Notifications: a client learns at once that something arrived for it, instead of polling.
//!
//! They are only hints, carrying nothing secret: what arrived is still fetched with the
//! [handshake](crate::handshake) and [mailbox](crate::mailbox) services, so a lost notification
//! only delays it. How they travel is up to the server; the Worker sends each [`Notification`]
//! as a binary WebSocket frame to the sockets a [`SubscribeRequest`] opened.
//!
//! A subscription is signed like the handshake's requests: the signature covers
//! `"notify.v1/subscribe"` ‖ identity key ‖ timestamp (u64, little-endian). The server takes it
//! only within [`MAX_CLOCK_SKEW`](crate::MAX_CLOCK_SKEW) of its own clock.

use bytes::Bytes;
use x3dh::PublicKey;
use xeddsa::XEdDSAPrivateKey;

use crate::{error::Result, verify_recent};

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
            |identity_key| subscribe_message(identity_key, self.timestamp),
        )
    }
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
}
