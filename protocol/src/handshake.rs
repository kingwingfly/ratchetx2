//! The handshake service: Bob publishes prekeys, Alice fetches them and leaves her initial
//! message in Bob's inbox, and Bob takes it from there.
//!
//! Its messages carry X3DH's, and convert to and from [`x3dh`]'s types; converting from the
//! wire fails with [`ErrorKind::Malformed`](crate::ErrorKind::Malformed) if a key or signature
//! has the wrong length.

use bytes::Bytes;
use x3dh::{PrekeyBundle, PublicKey, PublishedPrekeys};

use crate::{
    error::{Error, Result},
    fixed,
};

#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/handshake.v1.rs"));
}

pub use generated::*;
#[cfg(feature = "server")]
pub use server::{HandshakeLimits, HandshakeServer};

/// Client side of the handshake service.
#[trait_variant::make(Handshake: Send)]
pub trait LocalHandshake {
    /// Publish Bob's prekeys, replacing his previous ones. See [`crate::signing`].
    async fn publish(&self, request: PublishRequest) -> Result<PublishResponse>;
    /// Fetch Bob's prekey bundle, consuming one of his one-time prekeys.
    async fn fetch_bundle(&self, request: FetchBundleRequest) -> Result<FetchBundleResponse>;
    /// Leave Alice's initial message in Bob's inbox.
    async fn introduce(&self, request: IntroduceRequest) -> Result<IntroduceResponse>;
    /// Take the initial messages in Bob's inbox. See [`crate::signing`].
    async fn take_introductions(
        &self,
        request: TakeIntroductionsRequest,
    ) -> Result<TakeIntroductionsResponse>;
}

impl PublishRequest {
    /// A request publishing `prekeys` as `identity_key`'s, not signed yet: sign it with
    /// [`sign_publish`](crate::signing::sign_publish).
    pub fn new(identity_key: &PublicKey, prekeys: &PublishedPrekeys, timestamp: u64) -> Self {
        Self {
            identity_key: Bytes::copy_from_slice(identity_key),
            signed_prekey: Bytes::copy_from_slice(&prekeys.signed_prekey),
            signed_prekey_signature: Bytes::copy_from_slice(&prekeys.signed_prekey_signature),
            one_time_prekeys: prekeys
                .one_time_prekeys
                .iter()
                .map(|key| Bytes::copy_from_slice(key))
                .collect(),
            timestamp,
            signature: Bytes::new(),
        }
    }
}

impl TryFrom<&PublishRequest> for PublishedPrekeys {
    type Error = Error;

    fn try_from(request: &PublishRequest) -> Result<Self> {
        Ok(Self {
            signed_prekey: fixed(&request.signed_prekey)?,
            signed_prekey_signature: fixed(&request.signed_prekey_signature)?,
            one_time_prekeys: request
                .one_time_prekeys
                .iter()
                .map(|key| fixed(key))
                .collect::<Result<_>>()?,
        })
    }
}

impl From<&PrekeyBundle> for FetchBundleResponse {
    fn from(bundle: &PrekeyBundle) -> Self {
        Self {
            signed_prekey: Bytes::copy_from_slice(&bundle.signed_prekey),
            signed_prekey_signature: Bytes::copy_from_slice(&bundle.signed_prekey_signature),
            one_time_prekey: bundle
                .one_time_prekey
                .map(|key| Bytes::copy_from_slice(&key)),
        }
    }
}

impl TryFrom<&FetchBundleResponse> for PrekeyBundle {
    type Error = Error;

    fn try_from(response: &FetchBundleResponse) -> Result<Self> {
        Ok(Self {
            signed_prekey: fixed(&response.signed_prekey)?,
            signed_prekey_signature: fixed(&response.signed_prekey_signature)?,
            one_time_prekey: response.one_time_prekey.as_deref().map(fixed).transpose()?,
        })
    }
}

impl From<&x3dh::InitialMessage> for InitialMessage {
    fn from(message: &x3dh::InitialMessage) -> Self {
        Self {
            identity_key: Bytes::copy_from_slice(&message.identity_key),
            ephemeral_key: Bytes::copy_from_slice(&message.ephemeral_key),
            signed_prekey: Bytes::copy_from_slice(&message.signed_prekey),
            one_time_prekey: message
                .one_time_prekey
                .map(|key| Bytes::copy_from_slice(&key)),
        }
    }
}

impl TryFrom<&InitialMessage> for x3dh::InitialMessage {
    type Error = Error;

    fn try_from(message: &InitialMessage) -> Result<Self> {
        Ok(Self {
            identity_key: fixed(&message.identity_key)?,
            ephemeral_key: fixed(&message.ephemeral_key)?,
            signed_prekey: fixed(&message.signed_prekey)?,
            one_time_prekey: message.one_time_prekey.as_deref().map(fixed).transpose()?,
        })
    }
}

#[cfg(feature = "server")]
mod server {
    use bon::Builder;
    use storage::{Bundle, Introduction, LocalHandshakeStore};
    use xeddsa::XEdDSAPublicKey;

    use super::*;
    use crate::error::ErrorKind;
    use crate::signing;

    /// Limits of a [`HandshakeServer`].
    #[derive(Debug, Clone, Copy)]
    pub struct HandshakeLimits {
        /// Most one-time prekeys in one publish.
        pub max_one_time_prekeys: usize,
        /// Most initial messages waiting in one inbox.
        pub max_introductions: usize,
    }

    impl Default for HandshakeLimits {
        fn default() -> Self {
            Self {
                max_one_time_prekeys: 100,
                max_introductions: 100,
            }
        }
    }

    /// The handshake server's logic, over any handshake store.
    ///
    /// [`HandshakeServer::new`] gives it the default limits, and [`HandshakeServer::builder`] can
    /// set them: `HandshakeServer::builder(store).limits(limits).build()`.
    #[derive(Debug, Builder)]
    pub struct HandshakeServer<S> {
        #[builder(start_fn)]
        store: S,
        /// The limits; the default ones unless set.
        #[builder(default)]
        limits: HandshakeLimits,
    }

    impl<S> HandshakeServer<S> {
        /// A server over `store`, with the default limits.
        pub fn new(store: S) -> Self {
            Self::builder(store).build()
        }
    }

    impl<S: LocalHandshakeStore> LocalHandshake for HandshakeServer<S> {
        /// Check and store Bob's prekeys.
        async fn publish(&self, request: PublishRequest) -> Result<PublishResponse> {
            if request.one_time_prekeys.len() > self.limits.max_one_time_prekeys {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let identity_key = fixed(&request.identity_key)?;
            let prekeys = PublishedPrekeys::try_from(&request)?;
            XEdDSAPublicKey::new(&identity_key)?
                .verify(prekeys.signed_prekey, &prekeys.signed_prekey_signature)?;
            signing::verify_publish(&request)?;
            let bundle = Bundle {
                identity_key,
                signed_prekey: prekeys.signed_prekey,
                signed_prekey_signature: prekeys.signed_prekey_signature,
                timestamp: request.timestamp,
            };
            if !self.store.publish(bundle, prekeys.one_time_prekeys).await? {
                return Err(ErrorKind::StaleTimestamp.into());
            }
            Ok(PublishResponse {})
        }

        /// Bob's bundle, with one of his one-time prekeys, which is removed.
        async fn fetch_bundle(&self, request: FetchBundleRequest) -> Result<FetchBundleResponse> {
            let (bundle, one_time_prekey) = self
                .store
                .take_bundle(&fixed(&request.identity_key)?)
                .await?
                .ok_or(ErrorKind::NotFound)?;
            Ok(FetchBundleResponse::from(&PrekeyBundle {
                signed_prekey: bundle.signed_prekey,
                signed_prekey_signature: bundle.signed_prekey_signature,
                one_time_prekey,
            }))
        }

        /// Store Alice's initial message in Bob's inbox.
        async fn introduce(&self, request: IntroduceRequest) -> Result<IntroduceResponse> {
            let message = request.message.as_ref().ok_or(ErrorKind::Malformed)?;
            let message = x3dh::InitialMessage::try_from(message)?;
            let introduction = Introduction {
                sender: message.identity_key,
                recipient: fixed(&request.recipient)?,
                ephemeral_key: message.ephemeral_key,
                signed_prekey: message.signed_prekey,
                one_time_prekey: message.one_time_prekey,
            };
            if !self
                .store
                .add_introduction(introduction, self.limits.max_introductions)
                .await?
            {
                return Err(ErrorKind::LimitExceeded.into());
            }
            Ok(IntroduceResponse {})
        }

        /// Take the initial messages in Bob's inbox.
        async fn take_introductions(
            &self,
            request: TakeIntroductionsRequest,
        ) -> Result<TakeIntroductionsResponse> {
            let identity_key = fixed(&request.identity_key)?;
            signing::verify_take_introductions(&request)?;
            let introductions = self
                .store
                .take_introductions(&identity_key, request.timestamp)
                .await?
                .ok_or(ErrorKind::StaleTimestamp)?;
            let messages = introductions
                .into_iter()
                .map(|introduction| {
                    InitialMessage::from(&x3dh::InitialMessage {
                        identity_key: introduction.sender,
                        ephemeral_key: introduction.ephemeral_key,
                        signed_prekey: introduction.signed_prekey,
                        one_time_prekey: introduction.one_time_prekey,
                    })
                })
                .collect();
            Ok(TakeIntroductionsResponse { messages })
        }
    }

    #[cfg(test)]
    mod test {
        use storage::MemoryStore;
        use xeddsa::XEdDSAPrivateKey;

        use super::*;
        use crate::signing::{sign_publish, sign_take_introductions};

        fn key(identity: &XEdDSAPrivateKey) -> Bytes {
            Bytes::copy_from_slice(identity.compute_public_key().as_ref())
        }

        fn publish_request(
            bob: &XEdDSAPrivateKey,
            timestamp: u64,
            one_time: usize,
        ) -> PublishRequest {
            let mut request = PublishRequest {
                identity_key: key(bob),
                signed_prekey: Bytes::from_static(&[3; 32]),
                signed_prekey_signature: Bytes::copy_from_slice(&bob.sign([3; 32])),
                one_time_prekeys: vec![Bytes::from_static(&[4; 32]); one_time],
                timestamp,
                signature: Bytes::new(),
            };
            sign_publish(bob, &mut request).unwrap();
            request
        }

        fn kind<T: core::fmt::Debug>(result: Result<T>) -> ErrorKind {
            result.unwrap_err().kind()
        }

        #[tokio::test]
        async fn publish_and_fetch() {
            let server = HandshakeServer::new(MemoryStore::default());
            let bob = XEdDSAPrivateKey::generate();

            server.publish(publish_request(&bob, 1, 1)).await.unwrap();
            // Replaying, or changing a signed request, is rejected.
            assert_eq!(
                kind(server.publish(publish_request(&bob, 1, 1)).await),
                ErrorKind::StaleTimestamp
            );
            let mut changed = publish_request(&bob, 2, 1);
            changed.timestamp = 3;
            assert_eq!(
                kind(server.publish(changed).await),
                ErrorKind::InvalidSignature
            );
            // So is a signed prekey not signed by the identity key.
            let mut request = publish_request(&bob, 2, 0);
            request.signed_prekey_signature = Bytes::copy_from_slice(&bob.sign([9; 32]));
            sign_publish(&bob, &mut request).unwrap();
            assert_eq!(
                kind(server.publish(request).await),
                ErrorKind::InvalidSignature
            );
            assert_eq!(
                kind(server.publish(publish_request(&bob, 2, 101)).await),
                ErrorKind::LimitExceeded
            );

            let fetch = FetchBundleRequest {
                identity_key: key(&bob),
            };
            let bundle = server.fetch_bundle(fetch).await.unwrap();
            assert_eq!(bundle.signed_prekey, Bytes::from_static(&[3; 32]));
            assert_eq!(bundle.one_time_prekey, Some(Bytes::from_static(&[4; 32])));
        }

        #[tokio::test]
        async fn introduce_and_take() {
            let server = HandshakeServer::builder(MemoryStore::default())
                .limits(HandshakeLimits {
                    max_one_time_prekeys: 100,
                    max_introductions: 1,
                })
                .build();
            let (alice, bob) = (XEdDSAPrivateKey::generate(), XEdDSAPrivateKey::generate());
            let message = InitialMessage {
                identity_key: key(&alice),
                ephemeral_key: Bytes::from_static(&[5; 32]),
                signed_prekey: Bytes::from_static(&[3; 32]),
                one_time_prekey: None,
            };
            let introduce = || IntroduceRequest {
                recipient: key(&bob),
                message: Some(message.clone()),
            };
            server.introduce(introduce()).await.unwrap();
            assert_eq!(
                kind(server.introduce(introduce()).await),
                ErrorKind::LimitExceeded
            );
            let missing = IntroduceRequest {
                recipient: key(&bob),
                message: None,
            };
            assert_eq!(kind(server.introduce(missing).await), ErrorKind::Malformed);

            let take = |identity: &XEdDSAPrivateKey, timestamp| {
                let mut request = TakeIntroductionsRequest {
                    identity_key: key(&bob),
                    timestamp,
                    signature: Bytes::new(),
                };
                sign_take_introductions(identity, &mut request).unwrap();
                request
            };
            // Only Bob can take his introductions.
            assert_eq!(
                kind(server.take_introductions(take(&alice, 1)).await),
                ErrorKind::InvalidSignature
            );
            let taken = server.take_introductions(take(&bob, 1)).await.unwrap();
            assert_eq!(taken.messages, [message]);
            assert_eq!(
                kind(server.take_introductions(take(&bob, 1)).await),
                ErrorKind::StaleTimestamp
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn initial_message_round_trip() {
        for one_time_prekey in [None, Some([4; 32])] {
            let message = x3dh::InitialMessage {
                identity_key: [1; 32],
                ephemeral_key: [2; 32],
                signed_prekey: [3; 32],
                one_time_prekey,
            };
            let wire = InitialMessage::from(&message);
            assert_eq!(x3dh::InitialMessage::try_from(&wire).unwrap(), message);
        }
        let short = InitialMessage {
            ephemeral_key: Bytes::from_static(&[2; 31]),
            ..InitialMessage::from(&x3dh::InitialMessage {
                identity_key: [1; 32],
                ephemeral_key: [2; 32],
                signed_prekey: [3; 32],
                one_time_prekey: None,
            })
        };
        assert_eq!(
            x3dh::InitialMessage::try_from(&short).unwrap_err().kind(),
            ErrorKind::Malformed
        );
    }

    #[test]
    fn bundle_round_trip() {
        for one_time_prekey in [None, Some([3; 32])] {
            let bundle = PrekeyBundle {
                signed_prekey: [1; 32],
                signed_prekey_signature: [2; 64],
                one_time_prekey,
            };
            let wire = FetchBundleResponse::from(&bundle);
            assert_eq!(PrekeyBundle::try_from(&wire).unwrap(), bundle);
        }
        let mut wire = FetchBundleResponse::from(&PrekeyBundle {
            signed_prekey: [1; 32],
            signed_prekey_signature: [2; 64],
            one_time_prekey: None,
        });
        wire.signed_prekey_signature = Bytes::from_static(&[2; 63]);
        assert_eq!(
            PrekeyBundle::try_from(&wire).unwrap_err().kind(),
            ErrorKind::Malformed
        );
    }

    #[test]
    fn publish_request_round_trip() {
        let prekeys = PublishedPrekeys {
            signed_prekey: [1; 32],
            signed_prekey_signature: [2; 64],
            one_time_prekeys: vec![[3; 32], [4; 32]],
        };
        let mut request = PublishRequest::new(&[9; 32], &prekeys, 7);
        assert_eq!(request.identity_key, Bytes::from_static(&[9; 32]));
        assert_eq!(request.timestamp, 7);
        assert!(request.signature.is_empty());
        assert_eq!(PublishedPrekeys::try_from(&request).unwrap(), prekeys);
        request.one_time_prekeys.push(Bytes::from_static(&[5; 33]));
        assert_eq!(
            PublishedPrekeys::try_from(&request).unwrap_err().kind(),
            ErrorKind::Malformed
        );
    }
}
