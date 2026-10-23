//! The handshake service: Bob publishes prekeys, Alice fetches them and leaves her initial
//! message in Bob's inbox, and Bob takes it from there.
//!
//! Its messages carry X3DH's, and convert to and from [`x3dh`]'s types; converting from the
//! wire fails with [`ErrorKind::Malformed`] if a key or signature has the wrong length.
//!
//! # Signed requests
//!
//! Bob signs the requests that change or read his data with his identity key (XEdDSA): build
//! them with [`PublishRequest::sign`] and [`TakeIntroductionsRequest::sign`], and read them
//! through their `verify`, which checks the signature first. The signature covers fixed bytes
//! rather than the protobuf encoding, so every implementation signs exactly the same bytes:
//!
//! - publish: `"handshake.v1/publish"` ‖ identity key ‖ signed prekey ‖ its signature ‖
//!   number of one-time prekeys (u32, little-endian) ‖ the one-time prekeys ‖ timestamp
//!   (u64, little-endian)
//! - take introductions: `"handshake.v1/take-introductions"` ‖ identity key ‖ timestamp
//!   (u64, little-endian)
//!
//! Keys are 32 bytes and signatures 64, so fields cannot shift into each other.

use bytes::Bytes;
use x3dh::{PrekeyBundle, PublicKey, PublishedPrekeys};
use xeddsa::{XEdDSAPrivateKey, XEdDSAPublicKey};

use crate::{
    error::{Error, ErrorKind, Result},
    fixed,
};

#[allow(missing_docs)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/handshake.v1.rs"));
}

pub use proto::*;
#[cfg(feature = "server")]
pub use server::{HandshakeLimits, HandshakeServer};

/// Client side of the handshake service.
#[trait_variant::make(Handshake: Send)]
pub trait LocalHandshake {
    /// Publish Bob's prekeys, replacing his previous ones; see [`PublishRequest::sign`].
    async fn publish(&self, request: PublishRequest) -> Result<PublishResponse>;
    /// Fetch Bob's prekey bundle, consuming one of his one-time prekeys.
    async fn fetch_bundle(&self, request: FetchBundleRequest) -> Result<FetchBundleResponse>;
    /// Leave Alice's initial message in Bob's inbox.
    async fn introduce(&self, request: IntroduceRequest) -> Result<IntroduceResponse>;
    /// Take the initial messages in Bob's inbox; see [`TakeIntroductionsRequest::sign`].
    async fn take_introductions(
        &self,
        request: TakeIntroductionsRequest,
    ) -> Result<TakeIntroductionsResponse>;
}

impl PublishRequest {
    /// A request publishing `prekeys` as `identity`'s, signed by it.
    pub fn sign(
        identity: &XEdDSAPrivateKey,
        prekeys: &PublishedPrekeys,
        timestamp: u64,
    ) -> Result<Self> {
        let identity_key = identity.compute_public_key().to_bytes();
        let signature = identity.sign(publish_message(&identity_key, prekeys, timestamp)?);
        Ok(Self {
            identity_key: Bytes::copy_from_slice(&identity_key),
            signed_prekey: Bytes::copy_from_slice(&prekeys.signed_prekey),
            signed_prekey_signature: Bytes::copy_from_slice(&prekeys.signed_prekey_signature),
            one_time_prekeys: prekeys
                .one_time_prekeys
                .iter()
                .map(|key| Bytes::copy_from_slice(key))
                .collect(),
            timestamp,
            signature: Bytes::copy_from_slice(&signature),
        })
    }

    /// The identity key and prekeys this request publishes, once its signature by that
    /// identity key verifies.
    pub fn verify(&self) -> Result<(PublicKey, PublishedPrekeys)> {
        let identity_key = fixed(&self.identity_key)?;
        let prekeys = PublishedPrekeys {
            signed_prekey: fixed(&self.signed_prekey)?,
            signed_prekey_signature: fixed(&self.signed_prekey_signature)?,
            one_time_prekeys: self
                .one_time_prekeys
                .iter()
                .map(|key| fixed(key))
                .collect::<Result<_>>()?,
        };
        XEdDSAPublicKey::new(&identity_key)?.verify(
            publish_message(&identity_key, &prekeys, self.timestamp)?,
            &self.signature,
        )?;
        Ok((identity_key, prekeys))
    }
}

impl TakeIntroductionsRequest {
    /// A request taking `identity`'s initial messages, signed by it.
    pub fn sign(identity: &XEdDSAPrivateKey, timestamp: u64) -> Self {
        let identity_key = identity.compute_public_key().to_bytes();
        let signature = identity.sign(take_introductions_message(&identity_key, timestamp));
        Self {
            identity_key: Bytes::copy_from_slice(&identity_key),
            timestamp,
            signature: Bytes::copy_from_slice(&signature),
        }
    }

    /// The identity key whose initial messages this request takes, once its signature by that
    /// key verifies.
    pub fn verify(&self) -> Result<PublicKey> {
        let identity_key = fixed(&self.identity_key)?;
        XEdDSAPublicKey::new(&identity_key)?.verify(
            take_introductions_message(&identity_key, self.timestamp),
            &self.signature,
        )?;
        Ok(identity_key)
    }
}

/// The bytes a publish request's signature covers.
fn publish_message(
    identity_key: &PublicKey,
    prekeys: &PublishedPrekeys,
    timestamp: u64,
) -> Result<Vec<u8>> {
    let mut message = b"handshake.v1/publish".to_vec();
    message.extend(identity_key);
    message.extend(prekeys.signed_prekey);
    message.extend(prekeys.signed_prekey_signature);
    let count = u32::try_from(prekeys.one_time_prekeys.len()).map_err(|_| ErrorKind::Malformed)?;
    message.extend(count.to_le_bytes());
    for one_time_prekey in &prekeys.one_time_prekeys {
        message.extend(one_time_prekey);
    }
    message.extend(timestamp.to_le_bytes());
    Ok(message)
}

/// The bytes a take-introductions request's signature covers.
fn take_introductions_message(identity_key: &PublicKey, timestamp: u64) -> Vec<u8> {
    let mut message = b"handshake.v1/take-introductions".to_vec();
    message.extend(identity_key);
    message.extend(timestamp.to_le_bytes());
    message
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

    use super::*;

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
            let (identity_key, prekeys) = request.verify()?;
            XEdDSAPublicKey::new(&identity_key)?
                .verify(prekeys.signed_prekey, &prekeys.signed_prekey_signature)?;
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
            let identity_key = request.verify()?;
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

        use super::*;

        fn key(identity: &XEdDSAPrivateKey) -> Bytes {
            Bytes::copy_from_slice(identity.compute_public_key().as_ref())
        }

        fn publish_request(
            bob: &XEdDSAPrivateKey,
            timestamp: u64,
            one_time: usize,
        ) -> PublishRequest {
            let prekeys = PublishedPrekeys {
                signed_prekey: [3; 32],
                signed_prekey_signature: bob.sign([3; 32]),
                one_time_prekeys: vec![[4; 32]; one_time],
            };
            PublishRequest::sign(bob, &prekeys, timestamp).unwrap()
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
            let prekeys = PublishedPrekeys {
                signed_prekey: [3; 32],
                signed_prekey_signature: bob.sign([9; 32]),
                one_time_prekeys: vec![],
            };
            let request = PublishRequest::sign(&bob, &prekeys, 2).unwrap();
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

            // Only Bob can take his introductions.
            let mut forged = TakeIntroductionsRequest::sign(&alice, 1);
            forged.identity_key = key(&bob);
            assert_eq!(
                kind(server.take_introductions(forged).await),
                ErrorKind::InvalidSignature
            );
            let taken = server
                .take_introductions(TakeIntroductionsRequest::sign(&bob, 1))
                .await
                .unwrap();
            assert_eq!(taken.messages, [message]);
            assert_eq!(
                kind(
                    server
                        .take_introductions(TakeIntroductionsRequest::sign(&bob, 1))
                        .await
                ),
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
    fn sign_and_verify() {
        let bob = XEdDSAPrivateKey::generate();
        let identity_key = bob.compute_public_key().to_bytes();
        let prekeys = PublishedPrekeys {
            signed_prekey: [3; 32],
            signed_prekey_signature: [4; 64],
            one_time_prekeys: vec![[5; 32]],
        };
        let request = PublishRequest::sign(&bob, &prekeys, 7).unwrap();
        assert_eq!(request.verify().unwrap(), (identity_key, prekeys.clone()));
        // Any change breaks the signature.
        let mut changed = request.clone();
        changed.timestamp = 8;
        assert_eq!(
            changed.verify().unwrap_err().kind(),
            ErrorKind::InvalidSignature
        );
        let mut changed = request.clone();
        changed.one_time_prekeys.clear();
        assert_eq!(
            changed.verify().unwrap_err().kind(),
            ErrorKind::InvalidSignature
        );
        // Another identity cannot sign for Bob.
        let mut forged = PublishRequest::sign(&XEdDSAPrivateKey::generate(), &prekeys, 7).unwrap();
        forged.identity_key = request.identity_key.clone();
        assert_eq!(
            forged.verify().unwrap_err().kind(),
            ErrorKind::InvalidSignature
        );
        // Malformed fields are rejected.
        let mut malformed = request.clone();
        malformed
            .one_time_prekeys
            .push(Bytes::from_static(&[5; 33]));
        assert_eq!(malformed.verify().unwrap_err().kind(), ErrorKind::Malformed);

        let request = TakeIntroductionsRequest::sign(&bob, 9);
        assert_eq!(request.verify().unwrap(), identity_key);
        let mut changed = request.clone();
        changed.timestamp = 10;
        assert_eq!(
            changed.verify().unwrap_err().kind(),
            ErrorKind::InvalidSignature
        );
    }
}
