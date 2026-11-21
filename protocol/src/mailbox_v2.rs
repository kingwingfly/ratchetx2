//! The v2 hardened mailbox service: recipient-signed `FetchSigned` and idempotent `PushV2` with
//! per-field 8 KiB caps, sharing the same underlying mailbox storage as [`crate::mailbox`] so
//! legacy v1 and upgraded v2 clients seamlessly exchange messages.

use bytes::Bytes;
use prost::Message as _;
use x3dh::PublicKey;
use xeddsa::XEdDSAPrivateKey;

use crate::{
    check_safe_integer,
    error::{ErrorKind, Result},
    fixed,
    handshake::InitialMessage as InitialMessageV1,
    handshake_v2::{InitialMessageV2, push_count, push_len_bytes},
    mailbox::DELIVERY_TOKEN_LENGTH,
    verify_recent,
};

#[allow(missing_docs)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/mailbox.v2.rs"));
}

pub use proto::*;
#[cfg(feature = "server")]
pub use server::MailboxV2Server;

/// Domain separator for canonical [`FetchSignedRequest`] signatures.
pub const FETCH_SIGNED_DOMAIN: &[u8] = b"ratchetx2.fetch.v2\0";
/// Length of an idempotent [`PushV2Request::client_message_id`].
pub const CLIENT_MESSAGE_ID_LENGTH: usize = 16;

/// Prefix marking a v2 [`InitialMessageV2`] carried inside shared mailbox storage.
///
/// Starts with byte `0x00`, which is an illegal protobuf field tag (field number 0), guaranteeing
/// legacy v1 [`crate::mailbox::MailboxServer::fetch`] never misparses a v2 PQ carried initial
/// message as a v1 [`InitialMessageV1`].
const V2_CARRIED_INITIAL_MAGIC: &[u8] = b"\0IMV2";

/// Client side of the v2 mailbox service.
#[trait_variant::make(MailboxV2: Send)]
pub trait LocalMailboxV2 {
    /// Append a message to a queue with per-field caps and optional idempotent deduplication.
    async fn push_v2(&self, request: PushV2Request) -> Result<PushV2Response>;
    /// Read messages from a queue with recipient signature authentication.
    async fn fetch_signed(&self, request: FetchSignedRequest) -> Result<FetchSignedResponse>;
}

/// Encodes a carried [`InitialMessageV2`] for storage in the shared mailbox queue:
/// - `version == 1`: raw [`InitialMessageV1`] protobuf bytes (readable by BOTH v1 and v2 clients).
/// - `version == 2`: `b"\0IMV2" || InitialMessageV2` bytes (ignored by v1 clients, decoded by v2).
pub fn encode_carried_initial(initial: &InitialMessageV2) -> Result<Bytes> {
    if initial.version == 1 {
        let v1 = InitialMessageV1::try_from(initial)?;
        Ok(Bytes::from(v1.encode_to_vec()))
    } else {
        let encoded = initial.encode_to_vec();
        let mut out = Vec::with_capacity(V2_CARRIED_INITIAL_MAGIC.len() + encoded.len());
        out.extend_from_slice(V2_CARRIED_INITIAL_MAGIC);
        out.extend_from_slice(&encoded);
        Ok(Bytes::from(out))
    }
}

/// Decodes a carried initial message from shared mailbox storage into [`InitialMessageV2`],
/// seamlessly normalizing both v2 (`b"\0IMV2"`-prefixed) and legacy v1 payloads.
pub fn decode_carried_initial(bytes: &[u8]) -> Option<InitialMessageV2> {
    if let Some(rest) = bytes.strip_prefix(V2_CARRIED_INITIAL_MAGIC) {
        InitialMessageV2::decode(rest).ok()
    } else {
        InitialMessageV1::decode(bytes)
            .ok()
            .map(|v1| InitialMessageV2::from(&v1))
    }
}

/// Builds the canonical signing input for a [`FetchSignedRequest`]:
///
/// `b"ratchetx2.fetch.v2\0" || len_u32be(audience) || audience || sender(32) || recipient(32) ||`
/// `after(u64be) || limit(u32be) || max_size(u32be) || count_u32be(delivered) ||`
/// `[token(16)]* || timestamp(u64be)`.
pub fn fetch_signed_signing_input(request: &FetchSignedRequest) -> Result<Vec<u8>> {
    let sender: PublicKey = fixed(&request.sender)?;
    let recipient: PublicKey = fixed(&request.recipient)?;
    let mut out = Vec::with_capacity(
        FETCH_SIGNED_DOMAIN.len()
            + 4
            + request.audience.len()
            + 64
            + 8
            + 4
            + 4
            + 4
            + request.delivered.len() * DELIVERY_TOKEN_LENGTH
            + 8,
    );
    out.extend_from_slice(FETCH_SIGNED_DOMAIN);
    push_len_bytes(&mut out, request.audience.as_bytes())?;
    out.extend_from_slice(&sender);
    out.extend_from_slice(&recipient);
    out.extend_from_slice(&request.after.to_be_bytes());
    out.extend_from_slice(&request.limit.to_be_bytes());
    out.extend_from_slice(&request.max_size.to_be_bytes());
    push_count(&mut out, request.delivered.len())?;
    for token in &request.delivered {
        let token: [u8; DELIVERY_TOKEN_LENGTH] = fixed(token)?;
        out.extend_from_slice(&token);
    }
    out.extend_from_slice(&request.timestamp.to_be_bytes());
    Ok(out)
}

impl FetchSignedRequest {
    /// Constructs and signs a [`FetchSignedRequest`] as `recipient_identity`.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        recipient_identity: &XEdDSAPrivateKey,
        audience: impl Into<String>,
        sender: &PublicKey,
        after: u64,
        limit: u32,
        max_size: u32,
        delivered: Vec<Bytes>,
        timestamp: u64,
    ) -> Result<Self> {
        check_safe_integer(timestamp)?;
        let recipient = recipient_identity.compute_public_key().to_bytes();
        let mut request = Self {
            audience: audience.into(),
            sender: Bytes::copy_from_slice(sender),
            recipient: Bytes::copy_from_slice(&recipient),
            after,
            limit,
            max_size,
            delivered,
            timestamp,
            signature: Bytes::new(),
        };
        let input = fetch_signed_signing_input(&request)?;
        request.signature = Bytes::copy_from_slice(&recipient_identity.sign(input));
        Ok(request)
    }

    /// Verifies audience binding, recipient XEdDSA signature, and timestamp freshness against
    /// `now`. Returns `(sender, recipient)` on success.
    pub fn verify(&self, expected_audience: &str, now: u64) -> Result<(PublicKey, PublicKey)> {
        if self.audience.is_empty() || expected_audience.is_empty() {
            return Err(ErrorKind::Malformed.into());
        }
        if self.audience != expected_audience {
            return Err(ErrorKind::InvalidSignature.into());
        }
        let sender: PublicKey = fixed(&self.sender)?;
        let recipient = verify_recent(
            &self.recipient,
            &self.signature,
            self.timestamp,
            now,
            |_| fetch_signed_signing_input(self),
        )?;
        Ok((sender, recipient))
    }
}

#[cfg(feature = "server")]
mod server {
    use bon::Builder;
    use party::EncryptedMessage;
    use sha2::{Digest, Sha256};
    use storage::LocalIdempotentMailboxStore;
    use x3dh::PqSuite;

    use super::*;
    use crate::{
        check_canonical_key,
        handshake_v2::validate_initial_message_v2,
        mailbox::{MAX_DELIVERED, MailboxLimits},
        now_millis,
    };

    /// The v2 mailbox server logic over any store implementing [`LocalIdempotentMailboxStore`].
    #[derive(Debug, Builder)]
    pub struct MailboxV2Server<S> {
        #[builder(start_fn)]
        store: S,
        /// Canonical server audience identifier bound into signed fetches.
        server_id: String,
        /// Supported PQ suites for carried v2 initial messages (empty when PQ is disabled).
        #[builder(default = vec![u32::from(PqSuite::MlKem1024.as_u8()), u32::from(PqSuite::MlKem768.as_u8())])]
        supported_suites: Vec<u32>,
        /// Allow draining in-flight carried `version == 2` PQ initial messages validated against
        /// known [`PqSuite::from_u8`] even when `supported_suites` is empty (e.g. during a
        /// `PQ_ENABLED="false"` rollback so unacknowledged PQ outboxes never wedge).
        #[builder(default = true)]
        allow_pq_drain: bool,
        /// Size and pagination limits (shared with v1 [`MailboxLimits`]).
        #[builder(default)]
        limits: MailboxLimits,
    }

    impl<S> MailboxV2Server<S> {
        /// A v2 mailbox server over `store` with `server_id` and default limits.
        pub fn new(store: S, server_id: impl Into<String>) -> Self {
            Self::builder(store).server_id(server_id.into()).build()
        }
    }

    impl<S: LocalIdempotentMailboxStore> LocalMailboxV2 for MailboxV2Server<S> {
        async fn push_v2(&self, request: PushV2Request) -> Result<PushV2Response> {
            let sender: PublicKey = fixed(&request.sender)?;
            let recipient: PublicKey = fixed(&request.recipient)?;
            check_canonical_key(&sender)?;
            check_canonical_key(&recipient)?;

            let message = request.message.ok_or(ErrorKind::Malformed)?;
            if message.header.len() > self.limits.max_header_size {
                return Err(ErrorKind::LimitExceeded.into());
            }

            let initial_message = match request.initial_message {
                Some(ref init) => {
                    validate_initial_message_v2(init, &self.supported_suites, self.allow_pq_drain)?;
                    let encoded = encode_carried_initial(init)?;
                    if encoded.len() > self.limits.max_initial_message_size {
                        return Err(ErrorKind::LimitExceeded.into());
                    }
                    Some(encoded)
                }
                None => None,
            };

            let size = message.header.len()
                + message.content.len()
                + initial_message.as_ref().map_or(0, Bytes::len);
            if size > self.limits.max_message_size {
                return Err(ErrorKind::LimitExceeded.into());
            }

            let delivery_hash = if request.delivery_hash.is_empty() {
                None
            } else {
                Some(fixed(&request.delivery_hash)?)
            };
            let client_message_id = if request.client_message_id.is_empty() {
                None
            } else {
                Some(fixed(&request.client_message_id)?)
            };

            let sequence = self
                .store
                .append_idempotent(
                    &sender,
                    &recipient,
                    message.header,
                    message.content,
                    initial_message,
                    delivery_hash,
                    client_message_id,
                )
                .await?;
            Ok(PushV2Response { sequence })
        }

        async fn fetch_signed(&self, request: FetchSignedRequest) -> Result<FetchSignedResponse> {
            if request.delivered.len() > MAX_DELIVERED {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let (sender, recipient) = request.verify(&self.server_id, now_millis())?;

            if !request.delivered.is_empty() {
                let hashes = request
                    .delivered
                    .iter()
                    .map(|token| {
                        let token: [u8; DELIVERY_TOKEN_LENGTH] = fixed(token)?;
                        Ok(Sha256::digest(token).into())
                    })
                    .collect::<Result<Vec<_>>>()?;
                self.store
                    .delete_delivered(&sender, &recipient, &hashes)
                    .await?;
            }

            let limit = match request.limit {
                0 => self.limits.max_fetch,
                limit => limit.min(self.limits.max_fetch),
            };
            let max_size = match request.max_size {
                0 => self.limits.max_message_size,
                requested => (requested as usize).min(self.limits.max_message_size),
            };
            let stored = self
                .store
                .read(&sender, &recipient, request.after, limit)
                .await?;

            let mut messages = Vec::with_capacity(stored.len());
            let mut size = 0;
            for stored in stored {
                let envelope = EnvelopeV2 {
                    sequence: stored.sequence,
                    message: stored.content.map(|content| EncryptedMessage {
                        header: stored.header,
                        content,
                    }),
                    initial_message: stored
                        .initial_message
                        .as_deref()
                        .and_then(decode_carried_initial),
                };
                size += prost::encoding::message::encoded_len(1, &envelope);
                if !messages.is_empty() && size > max_size {
                    break;
                }
                messages.push(envelope);
            }
            Ok(FetchSignedResponse { messages })
        }
    }

    #[cfg(test)]
    #[allow(deprecated)]
    mod test {
        use std::sync::Arc;

        use storage::{IdempotentMailboxStore, LocalMailboxStore, MailboxStore, MemoryStore};
        use x3dh::PQXDH_VERSION;

        use super::*;
        use crate::mailbox::{
            FetchRequest, LocalMailbox, MAX_HEADER_SIZE, MailboxServer, PushRequest,
        };

        #[derive(Clone)]
        struct SharedStore(Arc<MemoryStore>);

        impl LocalMailboxStore for SharedStore {
            async fn append(
                &self,
                sender: &PublicKey,
                recipient: &PublicKey,
                header: Bytes,
                content: Bytes,
                initial_message: Option<Bytes>,
                delivery_hash: Option<[u8; 32]>,
            ) -> storage::Result<u64> {
                MailboxStore::append(
                    &*self.0,
                    sender,
                    recipient,
                    header,
                    content,
                    initial_message,
                    delivery_hash,
                )
                .await
            }
            async fn delete_delivered(
                &self,
                sender: &PublicKey,
                recipient: &PublicKey,
                hashes: &[[u8; 32]],
            ) -> storage::Result<()> {
                MailboxStore::delete_delivered(&*self.0, sender, recipient, hashes).await
            }
            async fn read(
                &self,
                sender: &PublicKey,
                recipient: &PublicKey,
                after: u64,
                limit: u32,
            ) -> storage::Result<Vec<storage::StoredMessage>> {
                MailboxStore::read(&*self.0, sender, recipient, after, limit).await
            }
        }

        impl LocalIdempotentMailboxStore for SharedStore {
            async fn append_idempotent(
                &self,
                sender: &PublicKey,
                recipient: &PublicKey,
                header: Bytes,
                content: Bytes,
                initial_message: Option<Bytes>,
                delivery_hash: Option<[u8; 32]>,
                client_message_id: Option<[u8; 16]>,
            ) -> storage::Result<u64> {
                IdempotentMailboxStore::append_idempotent(
                    &*self.0,
                    sender,
                    recipient,
                    header,
                    content,
                    initial_message,
                    delivery_hash,
                    client_message_id,
                )
                .await
            }
            async fn delete_delivered(
                &self,
                sender: &PublicKey,
                recipient: &PublicKey,
                hashes: &[[u8; 32]],
            ) -> storage::Result<()> {
                IdempotentMailboxStore::delete_delivered(&*self.0, sender, recipient, hashes).await
            }
            async fn read(
                &self,
                sender: &PublicKey,
                recipient: &PublicKey,
                after: u64,
                limit: u32,
            ) -> storage::Result<Vec<storage::StoredMessage>> {
                IdempotentMailboxStore::read(&*self.0, sender, recipient, after, limit).await
            }
        }

        #[tokio::test]
        async fn fetch_signed_auth_and_shared_v1_v2_queue_interop() {
            let shared = SharedStore(Arc::new(MemoryStore::default()));
            let v1 = MailboxServer::new(shared.clone());
            let v2 = MailboxV2Server::new(shared.clone(), "relay.example");
            let now = now_millis();

            let alice = XEdDSAPrivateKey::generate();
            let bob = XEdDSAPrivateKey::generate();
            let eve = XEdDSAPrivateKey::generate();
            let alice_pk = alice.compute_public_key().to_bytes();
            let bob_pk = bob.compute_public_key().to_bytes();

            // 1. V1 push lands in shared queue (sequence 1).
            let seq1 = v1
                .push(PushRequest {
                    sender: Bytes::copy_from_slice(&alice_pk),
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    message: Some(EncryptedMessage {
                        header: Bytes::from_static(b"v1-h"),
                        content: Bytes::from_static(b"v1-c"),
                    }),
                    initial_message: None,
                    delivery_hash: Bytes::new(),
                })
                .await
                .unwrap()
                .sequence;
            assert_eq!(seq1, 1);

            // 2. V2 push with PQ carried initial and client_message_id deduplicates retries.
            let pq_init = InitialMessageV2 {
                id: 0,
                version: PQXDH_VERSION,
                identity_key: Bytes::copy_from_slice(&alice_pk),
                ephemeral_key: Bytes::from_static(&[0x11; 32]),
                signed_prekey: Bytes::from_static(&[0x22; 32]),
                one_time_prekey: None,
                first_message: None,
                pq_suite: u32::from(PqSuite::MlKem768.as_u8()),
                pq_last_resort: false,
                pq_prekey_id: Bytes::from_static(&[0x33; 32]),
                pq_ciphertext: Bytes::from(vec![0x55; PqSuite::MlKem768.ct_len()]),
                manifest_digest: Bytes::from_static(&[0x44; 32]),
            };
            let push2 = PushV2Request {
                sender: Bytes::copy_from_slice(&alice_pk),
                recipient: Bytes::copy_from_slice(&bob_pk),
                message: Some(EncryptedMessage {
                    header: Bytes::from_static(b"v2-h"),
                    content: Bytes::from_static(b"v2-c"),
                }),
                initial_message: Some(pq_init.clone()),
                delivery_hash: Bytes::new(),
                client_message_id: Bytes::from_static(&[0x77; CLIENT_MESSAGE_ID_LENGTH]),
            };
            assert_eq!(v2.push_v2(push2.clone()).await.unwrap().sequence, 2);
            assert_eq!(v2.push_v2(push2).await.unwrap().sequence, 2);

            // 3. Oversized header (> 8 KiB) rejected.
            let bad_header = PushV2Request {
                sender: Bytes::copy_from_slice(&alice_pk),
                recipient: Bytes::copy_from_slice(&bob_pk),
                message: Some(EncryptedMessage {
                    header: Bytes::from(vec![0xAA; MAX_HEADER_SIZE + 1]),
                    content: Bytes::from_static(b"c"),
                }),
                initial_message: None,
                delivery_hash: Bytes::new(),
                client_message_id: Bytes::new(),
            };
            assert_eq!(
                v2.push_v2(bad_header).await.unwrap_err().kind(),
                ErrorKind::LimitExceeded
            );

            // 4. Eve cannot fetch Bob's mailbox; wrong audience and stale timestamp rejected.
            let mut forged =
                FetchSignedRequest::sign(&eve, "relay.example", &alice_pk, 0, 10, 0, vec![], now)
                    .unwrap();
            forged.recipient = Bytes::copy_from_slice(&bob_pk);
            assert_eq!(
                v2.fetch_signed(forged).await.unwrap_err().kind(),
                ErrorKind::InvalidSignature
            );
            let wrong_aud =
                FetchSignedRequest::sign(&bob, "wrong.example", &alice_pk, 0, 10, 0, vec![], now)
                    .unwrap();
            assert_eq!(
                v2.fetch_signed(wrong_aud).await.unwrap_err().kind(),
                ErrorKind::InvalidSignature
            );
            let stale = FetchSignedRequest::sign(
                &bob,
                "relay.example",
                &alice_pk,
                0,
                10,
                0,
                vec![],
                now - crate::MAX_CLOCK_SKEW - 5_000,
            )
            .unwrap();
            assert_eq!(
                v2.fetch_signed(stale).await.unwrap_err().kind(),
                ErrorKind::StaleTimestamp
            );

            // 5. Bob's signed fetch sees BOTH v1 (seq 1) and v2 (seq 2 with PQ initial).
            let fetched = v2
                .fetch_signed(
                    FetchSignedRequest::sign(
                        &bob,
                        "relay.example",
                        &alice_pk,
                        0,
                        10,
                        0,
                        vec![],
                        now,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(fetched.messages.len(), 2);
            assert_eq!(fetched.messages[0].sequence, 1);
            assert_eq!(fetched.messages[1].sequence, 2);
            assert_eq!(fetched.messages[1].initial_message, Some(pq_init));

            // 6. Legacy v1 Fetch reads seq 1 and seq 2 without misparsing the v2 PQ carried initial.
            let v1_fetched = v1
                .fetch(FetchRequest {
                    sender: Bytes::copy_from_slice(&alice_pk),
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    after: 0,
                    limit: 10,
                    delivered: vec![],
                })
                .await
                .unwrap();
            assert_eq!(v1_fetched.messages.len(), 2);
            assert_eq!(v1_fetched.messages[1].initial_message, None);
        }

        #[tokio::test]
        async fn push_v2_drains_carried_pq_initial_when_pq_disabled_and_validates_lengths() {
            let shared = SharedStore(Arc::new(MemoryStore::default()));
            let alice = XEdDSAPrivateKey::generate();
            let bob = XEdDSAPrivateKey::generate();
            let alice_pk = alice.compute_public_key().to_bytes();
            let bob_pk = bob.compute_public_key().to_bytes();

            let drain_server = MailboxV2Server::builder(shared.clone())
                .server_id("relay.example".to_string())
                .supported_suites(vec![])
                .build();

            let pq_init = InitialMessageV2 {
                id: 0,
                version: PQXDH_VERSION,
                identity_key: Bytes::copy_from_slice(&alice_pk),
                ephemeral_key: Bytes::from_static(&[0x11; 32]),
                signed_prekey: Bytes::from_static(&[0x22; 32]),
                one_time_prekey: None,
                first_message: None,
                pq_suite: u32::from(PqSuite::MlKem1024.as_u8()),
                pq_last_resort: false,
                pq_prekey_id: Bytes::from_static(&[0x33; 32]),
                pq_ciphertext: Bytes::from(vec![0x55; PqSuite::MlKem1024.ct_len()]),
                manifest_digest: Bytes::from_static(&[0x44; 32]),
            };
            let push = |init: InitialMessageV2| PushV2Request {
                sender: Bytes::copy_from_slice(&alice_pk),
                recipient: Bytes::copy_from_slice(&bob_pk),
                message: Some(EncryptedMessage {
                    header: Bytes::from_static(b"h"),
                    content: Bytes::from_static(b"c"),
                }),
                initial_message: Some(init),
                delivery_hash: Bytes::new(),
                client_message_id: Bytes::new(),
            };

            // Valid known PQ suite drains cleanly even with supported_suites = [].
            assert_eq!(
                drain_server
                    .push_v2(push(pq_init.clone()))
                    .await
                    .unwrap()
                    .sequence,
                1
            );

            // Unknown suite or wrong ciphertext length is STILL rejected as Malformed.
            let mut bad_suite = pq_init.clone();
            bad_suite.pq_suite = 99;
            assert_eq!(
                drain_server
                    .push_v2(push(bad_suite))
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
            let mut bad_ct = pq_init.clone();
            bad_ct.pq_ciphertext = Bytes::from(vec![0x55; 10]);
            assert_eq!(
                drain_server.push_v2(push(bad_ct)).await.unwrap_err().kind(),
                ErrorKind::Malformed
            );

            // Explicitly disabling allow_pq_drain enforces supported_suites strictly.
            let strict_server = MailboxV2Server::builder(shared)
                .server_id("relay.example".to_string())
                .supported_suites(vec![])
                .allow_pq_drain(false)
                .build();
            assert_eq!(
                strict_server
                    .push_v2(push(pq_init))
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
        }
    }
}
