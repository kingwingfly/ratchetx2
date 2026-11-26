//! The v2 sealed-sender-lite unified mailbox service: recipient-registered deniable write tokens,
//! idempotent `PushV2` (64 KiB inline envelope cap), recipient-signed `FetchSigned` (1 MiB fetch
//! page cap with optional piggybacked monotonic prefix ACK), and explicit `AckMessages`.

use core::fmt;

use bytes::Bytes;
use prost::Message as _;
use x3dh::{PQXDH_VERSION, PublicKey};
use xeddsa::XEdDSAPrivateKey;

use crate::{
    SigningBuf, check_safe_integer,
    error::{ErrorKind, Result},
    fixed,
    handshake_v2::InitialMessageV2,
    verify_audience, verify_recent,
};

#[allow(missing_docs)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/mailbox.v2.rs"));
}

pub use proto::*;
#[cfg(feature = "server")]
pub use server::{MailboxLimits, MailboxV2Server};

/// Domain separator for canonical [`FetchSignedRequest`] signatures.
pub const FETCH_SIGNED_DOMAIN: &[u8] = b"ratchetx2.fetch.v2\0";
/// Domain separator for canonical [`AckMessagesRequest`] signatures.
pub const ACK_MESSAGES_DOMAIN: &[u8] = b"ratchetx2.ack.v2\0";
/// Domain separator for canonical [`RegisterWriteTokenRequest`] signatures.
pub const REGISTER_WRITE_TOKEN_DOMAIN: &[u8] = b"ratchetx2.register-write-token.v2\0";
/// Domain separator for canonical [`RevokeWriteTokenRequest`] signatures.
pub const REVOKE_WRITE_TOKEN_DOMAIN: &[u8] = b"ratchetx2.revoke-write-token.v2\0";

/// Length of an idempotent [`PushV2Request::client_message_id`].
pub const CLIENT_MESSAGE_ID_LENGTH: usize = 16;
/// Length of a deniable write-capability token ([`PushV2Request::write_token`]).
pub const WRITE_TOKEN_LENGTH: usize = 32;
/// Length of `SHA-256(write_token)` ([`EnvelopeV2::token_hash`], [`RegisterWriteTokenRequest::token_hash`]).
pub const WRITE_TOKEN_HASH_LENGTH: usize = 32;
/// Length of an opaque per-peer slot identifier (`peer_slot_id`).
pub const PEER_SLOT_ID_LENGTH: usize = 32;
/// Maximum encrypted header size in bytes (8 KiB: fits encrypted PQ ratchet headers while
/// preventing Durable Object OOM / queue bricking).
pub const MAX_HEADER_SIZE: usize = 8 << 10;
/// Maximum encoded carried initial message size in bytes (12 KiB: accommodates
/// `HandshakeV2Limits::max_first_message_size` (8 KiB) plus ML-KEM-1024 `InitialMessageV2`
/// framing while preventing Durable Object OOM / queue bricking).
pub const MAX_INITIAL_MESSAGE_SIZE: usize = 12 << 10;
/// Maximum inline envelope size (`header + content + carried_initial_message`) for `PushV2` (64 KiB).
pub const MAX_INLINE_MESSAGE_SIZE: usize = 64 << 10;
/// Maximum response byte budget for a single `FetchSigned` page (1 MiB).
pub const MAX_FETCH_BYTES: usize = 1 << 20;

impl Drop for PushV2Request {
    fn drop(&mut self) {
        crate::zeroize_bytes(&mut self.write_token);
    }
}

impl zeroize::ZeroizeOnDrop for PushV2Request {}

impl fmt::Debug for PushV2Request {
    /// Redacts `write_token`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushV2Request")
            .field("recipient_len", &self.recipient.len())
            .field("has_message", &self.message.is_some())
            .field("has_initial_message", &self.initial_message.is_some())
            .field("client_message_id_len", &self.client_message_id.len())
            .finish_non_exhaustive()
    }
}

/// Client side of the v2 mailbox service.
#[trait_variant::make(MailboxV2: Send)]
pub trait LocalMailboxV2 {
    /// Append a message to a recipient's unified queue authorized by a deniable write token.
    async fn push_v2(&self, request: PushV2Request) -> Result<PushV2Response>;
    /// Read messages from a recipient's unified queue with signature auth and optional prefix ACK.
    async fn fetch_signed(&self, request: FetchSignedRequest) -> Result<FetchSignedResponse>;
    /// Explicitly acknowledge and delete all messages up to `up_to_sequence`.
    async fn ack_messages(&self, request: AckMessagesRequest) -> Result<AckMessagesResponse>;
    /// Register a write-token hash for an opaque peer slot.
    async fn register_write_token(
        &self,
        request: RegisterWriteTokenRequest,
    ) -> Result<RegisterWriteTokenResponse>;
    /// Revoke one or all write tokens for an opaque peer slot and advance the version floor.
    async fn revoke_write_token(
        &self,
        request: RevokeWriteTokenRequest,
    ) -> Result<RevokeWriteTokenResponse>;
}

/// Encodes a carried [`InitialMessageV2`] for storage in the mailbox queue (normalizing `id = 0`).
///
/// Fails with [`ErrorKind::Malformed`] for any protocol version other than `1` or
/// [`PQXDH_VERSION`].
pub fn encode_carried_initial(initial: &InitialMessageV2) -> Result<Bytes> {
    match initial.version {
        1 | PQXDH_VERSION => {
            if initial.id == 0 {
                Ok(Bytes::from(initial.encode_to_vec()))
            } else {
                let mut carried = initial.clone();
                carried.id = 0;
                Ok(Bytes::from(carried.encode_to_vec()))
            }
        }
        _ => Err(ErrorKind::Malformed.into()),
    }
}

/// Decodes a carried [`InitialMessageV2`] from mailbox storage (normalizing `id = 0`).
pub fn decode_carried_initial(bytes: &[u8]) -> Option<InitialMessageV2> {
    let mut msg = InitialMessageV2::decode(bytes).ok()?;
    msg.id = 0;
    Some(msg)
}

/// Builds the canonical signing input for a [`FetchSignedRequest`]:
///
/// `b"ratchetx2.fetch.v2\0" || len_u32be(audience) || audience || recipient(32) ||`
/// `after_sequence(u64be) || limit(u32be) || max_size(u32be) || ack_up_to_sequence(u64be) ||`
/// `timestamp(u64be)`.
pub fn fetch_signed_signing_input(request: &FetchSignedRequest) -> Result<Vec<u8>> {
    let recipient: PublicKey = fixed(&request.recipient)?;
    let extra = 68usize.saturating_add(request.audience.len());
    let mut out = SigningBuf::with_domain(FETCH_SIGNED_DOMAIN, extra);
    out.push_audience_be(&request.audience)?;
    out.push_bytes(&recipient);
    out.push_u64_be(request.after_sequence);
    out.push_u32_be(request.limit);
    out.push_u32_be(request.max_size);
    out.push_u64_be(request.ack_up_to_sequence);
    out.push_u64_be(request.timestamp);
    Ok(out.into_vec())
}

/// Builds the canonical signing input for an [`AckMessagesRequest`]:
///
/// `b"ratchetx2.ack.v2\0" || len_u32be(audience) || audience || recipient(32) ||`
/// `up_to_sequence(u64be) || timestamp(u64be)`.
pub fn ack_messages_signing_input(request: &AckMessagesRequest) -> Result<Vec<u8>> {
    let recipient: PublicKey = fixed(&request.recipient)?;
    let extra = 52usize.saturating_add(request.audience.len());
    let mut out = SigningBuf::with_domain(ACK_MESSAGES_DOMAIN, extra);
    out.push_audience_be(&request.audience)?;
    out.push_bytes(&recipient);
    out.push_u64_be(request.up_to_sequence);
    out.push_u64_be(request.timestamp);
    Ok(out.into_vec())
}

/// Builds the canonical signing input for a [`RegisterWriteTokenRequest`]:
///
/// `b"ratchetx2.register-write-token.v2\0" || len_u32be(audience) || audience || recipient(32) ||`
/// `peer_slot_id(32) || token_hash(32) || grant_version(u64be) || pin_active(u8) ||`
/// `timestamp(u64be)`.
pub fn register_write_token_signing_input(request: &RegisterWriteTokenRequest) -> Result<Vec<u8>> {
    let recipient: PublicKey = fixed(&request.recipient)?;
    let peer_slot_id: [u8; PEER_SLOT_ID_LENGTH] = fixed(&request.peer_slot_id)?;
    let token_hash: [u8; WRITE_TOKEN_HASH_LENGTH] = fixed(&request.token_hash)?;
    let extra = 117usize.saturating_add(request.audience.len());
    let mut out = SigningBuf::with_domain(REGISTER_WRITE_TOKEN_DOMAIN, extra);
    out.push_audience_be(&request.audience)?;
    out.push_bytes(&recipient);
    out.push_bytes(&peer_slot_id);
    out.push_bytes(&token_hash);
    out.push_u64_be(request.grant_version);
    out.push_u8(u8::from(request.pin_active));
    out.push_u64_be(request.timestamp);
    Ok(out.into_vec())
}

/// Builds the canonical signing input for a [`RevokeWriteTokenRequest`]:
///
/// `b"ratchetx2.revoke-write-token.v2\0" || len_u32be(audience) || audience || recipient(32) ||`
/// `peer_slot_id(32) || has_token_hash(u8) || [token_hash(32)] || min_grant_version(u64be) ||`
/// `timestamp(u64be)`.
pub fn revoke_write_token_signing_input(request: &RevokeWriteTokenRequest) -> Result<Vec<u8>> {
    let recipient: PublicKey = fixed(&request.recipient)?;
    let peer_slot_id: [u8; PEER_SLOT_ID_LENGTH] = fixed(&request.peer_slot_id)?;
    let token_hash = if request.token_hash.is_empty() {
        None
    } else {
        Some(fixed::<WRITE_TOKEN_HASH_LENGTH>(&request.token_hash)?)
    };
    let extra = 117usize.saturating_add(request.audience.len());
    let mut out = SigningBuf::with_domain(REVOKE_WRITE_TOKEN_DOMAIN, extra);
    out.push_audience_be(&request.audience)?;
    out.push_bytes(&recipient);
    out.push_bytes(&peer_slot_id);
    match token_hash {
        Some(hash) => {
            out.push_u8(1);
            out.push_bytes(&hash);
        }
        None => out.push_u8(0),
    }
    out.push_u64_be(request.min_grant_version);
    out.push_u64_be(request.timestamp);
    Ok(out.into_vec())
}

impl FetchSignedRequest {
    /// Constructs and signs a [`FetchSignedRequest`] as `recipient_identity`.
    pub fn sign(
        recipient_identity: &XEdDSAPrivateKey,
        audience: impl Into<String>,
        after_sequence: u64,
        limit: u32,
        max_size: u32,
        ack_up_to_sequence: u64,
        timestamp: u64,
    ) -> Result<Self> {
        check_safe_integer(after_sequence)?;
        check_safe_integer(ack_up_to_sequence)?;
        check_safe_integer(timestamp)?;
        let recipient = recipient_identity.compute_public_key().to_bytes();
        let mut request = Self {
            audience: audience.into(),
            recipient: Bytes::copy_from_slice(&recipient),
            after_sequence,
            limit,
            max_size,
            ack_up_to_sequence,
            timestamp,
            signature: Bytes::new(),
        };
        let input = fetch_signed_signing_input(&request)?;
        request.signature = Bytes::copy_from_slice(&recipient_identity.sign(input));
        Ok(request)
    }

    /// Verifies audience binding, sequence bounds, recipient XEdDSA signature, and timestamp
    /// freshness against `now`. Returns `recipient` on success.
    pub fn verify(&self, expected_audience: &str, now: u64) -> Result<PublicKey> {
        verify_audience(&self.audience, expected_audience)?;
        check_safe_integer(self.after_sequence)?;
        check_safe_integer(self.ack_up_to_sequence)?;
        verify_recent(
            &self.recipient,
            &self.signature,
            self.timestamp,
            now,
            |_| fetch_signed_signing_input(self),
        )
    }
}

impl AckMessagesRequest {
    /// Constructs and signs an [`AckMessagesRequest`] as `recipient_identity`.
    pub fn sign(
        recipient_identity: &XEdDSAPrivateKey,
        audience: impl Into<String>,
        up_to_sequence: u64,
        timestamp: u64,
    ) -> Result<Self> {
        if up_to_sequence == 0 {
            return Err(ErrorKind::Malformed.into());
        }
        check_safe_integer(up_to_sequence)?;
        check_safe_integer(timestamp)?;
        let recipient = recipient_identity.compute_public_key().to_bytes();
        let mut request = Self {
            audience: audience.into(),
            recipient: Bytes::copy_from_slice(&recipient),
            up_to_sequence,
            timestamp,
            signature: Bytes::new(),
        };
        let input = ack_messages_signing_input(&request)?;
        request.signature = Bytes::copy_from_slice(&recipient_identity.sign(input));
        Ok(request)
    }

    /// Verifies audience binding, sequence bounds (`1..=MAX_SAFE_INTEGER`), recipient XEdDSA
    /// signature, and timestamp freshness against `now`. Returns `recipient` on success.
    pub fn verify(&self, expected_audience: &str, now: u64) -> Result<PublicKey> {
        verify_audience(&self.audience, expected_audience)?;
        if self.up_to_sequence == 0 {
            return Err(ErrorKind::Malformed.into());
        }
        check_safe_integer(self.up_to_sequence)?;
        verify_recent(
            &self.recipient,
            &self.signature,
            self.timestamp,
            now,
            |_| ack_messages_signing_input(self),
        )
    }
}

impl RegisterWriteTokenRequest {
    /// Constructs and signs a [`RegisterWriteTokenRequest`] as `recipient_identity`.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        recipient_identity: &XEdDSAPrivateKey,
        audience: impl Into<String>,
        peer_slot_id: &[u8; PEER_SLOT_ID_LENGTH],
        token_hash: &[u8; WRITE_TOKEN_HASH_LENGTH],
        grant_version: u64,
        pin_active: bool,
        timestamp: u64,
    ) -> Result<Self> {
        if grant_version == 0 {
            return Err(ErrorKind::Malformed.into());
        }
        check_safe_integer(grant_version)?;
        check_safe_integer(timestamp)?;
        let recipient = recipient_identity.compute_public_key().to_bytes();
        let mut request = Self {
            audience: audience.into(),
            recipient: Bytes::copy_from_slice(&recipient),
            peer_slot_id: Bytes::copy_from_slice(peer_slot_id),
            token_hash: Bytes::copy_from_slice(token_hash),
            grant_version,
            pin_active,
            timestamp,
            signature: Bytes::new(),
        };
        let input = register_write_token_signing_input(&request)?;
        request.signature = Bytes::copy_from_slice(&recipient_identity.sign(input));
        Ok(request)
    }

    /// Verifies audience binding, grant version bounds (`1..=MAX_SAFE_INTEGER`), fixed-length
    /// fields, recipient XEdDSA signature, and timestamp freshness against `now`.
    /// Returns `(recipient, peer_slot_id, token_hash)` on success.
    pub fn verify(
        &self,
        expected_audience: &str,
        now: u64,
    ) -> Result<(
        PublicKey,
        [u8; PEER_SLOT_ID_LENGTH],
        [u8; WRITE_TOKEN_HASH_LENGTH],
    )> {
        verify_audience(&self.audience, expected_audience)?;
        if self.grant_version == 0 {
            return Err(ErrorKind::Malformed.into());
        }
        check_safe_integer(self.grant_version)?;
        let peer_slot_id: [u8; PEER_SLOT_ID_LENGTH] = fixed(&self.peer_slot_id)?;
        let token_hash: [u8; WRITE_TOKEN_HASH_LENGTH] = fixed(&self.token_hash)?;
        let recipient = verify_recent(
            &self.recipient,
            &self.signature,
            self.timestamp,
            now,
            |_| register_write_token_signing_input(self),
        )?;
        Ok((recipient, peer_slot_id, token_hash))
    }
}

impl RevokeWriteTokenRequest {
    /// Constructs and signs a [`RevokeWriteTokenRequest`] as `recipient_identity`.
    pub fn sign(
        recipient_identity: &XEdDSAPrivateKey,
        audience: impl Into<String>,
        peer_slot_id: &[u8; PEER_SLOT_ID_LENGTH],
        token_hash: Option<&[u8; WRITE_TOKEN_HASH_LENGTH]>,
        min_grant_version: u64,
        timestamp: u64,
    ) -> Result<Self> {
        if min_grant_version == 0 {
            return Err(ErrorKind::Malformed.into());
        }
        check_safe_integer(min_grant_version)?;
        check_safe_integer(timestamp)?;
        let recipient = recipient_identity.compute_public_key().to_bytes();
        let mut request = Self {
            audience: audience.into(),
            recipient: Bytes::copy_from_slice(&recipient),
            peer_slot_id: Bytes::copy_from_slice(peer_slot_id),
            token_hash: token_hash.map_or_else(Bytes::new, |h| Bytes::copy_from_slice(h)),
            min_grant_version,
            timestamp,
            signature: Bytes::new(),
        };
        let input = revoke_write_token_signing_input(&request)?;
        request.signature = Bytes::copy_from_slice(&recipient_identity.sign(input));
        Ok(request)
    }

    /// Verifies audience binding, version floor bounds (`1..=MAX_SAFE_INTEGER`), fixed-length
    /// fields, recipient XEdDSA signature, and timestamp freshness against `now`.
    /// Returns `(recipient, peer_slot_id, token_hash)` on success.
    pub fn verify(
        &self,
        expected_audience: &str,
        now: u64,
    ) -> Result<(
        PublicKey,
        [u8; PEER_SLOT_ID_LENGTH],
        Option<[u8; WRITE_TOKEN_HASH_LENGTH]>,
    )> {
        verify_audience(&self.audience, expected_audience)?;
        if self.min_grant_version == 0 {
            return Err(ErrorKind::Malformed.into());
        }
        check_safe_integer(self.min_grant_version)?;
        let peer_slot_id: [u8; PEER_SLOT_ID_LENGTH] = fixed(&self.peer_slot_id)?;
        let token_hash = if self.token_hash.is_empty() {
            None
        } else {
            Some(fixed::<WRITE_TOKEN_HASH_LENGTH>(&self.token_hash)?)
        };
        let recipient = verify_recent(
            &self.recipient,
            &self.signature,
            self.timestamp,
            now,
            |_| revoke_write_token_signing_input(self),
        )?;
        Ok((recipient, peer_slot_id, token_hash))
    }
}

#[cfg(feature = "server")]
mod server {
    use bon::Builder;
    use party::EncryptedMessage;
    use sha2::{Digest, Sha256};
    use storage::{LocalIdempotentMailboxStore, RegisterWriteTokenRecord, RevokeWriteTokenRecord};
    use x3dh::PqSuite;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{check_canonical_key, handshake_v2::validate_initial_message_v2, now_millis};

    /// Size and pagination limits of a [`MailboxV2Server`].
    #[derive(Debug, Clone, Copy)]
    pub struct MailboxLimits {
        /// Largest single inline envelope (`header + content + carried_initial_message`), in bytes.
        pub max_message_size: usize,
        /// Largest byte budget returned in a single `FetchSigned` page.
        pub max_fetch_bytes: usize,
        /// Most messages in one fetch.
        pub max_fetch: u32,
        /// Largest encrypted header, in bytes.
        pub max_header_size: usize,
        /// Largest encoded carried initial message, in bytes.
        pub max_initial_message_size: usize,
    }

    impl Default for MailboxLimits {
        fn default() -> Self {
            Self {
                max_message_size: MAX_INLINE_MESSAGE_SIZE,
                max_fetch_bytes: MAX_FETCH_BYTES,
                max_fetch: 100,
                max_header_size: MAX_HEADER_SIZE,
                max_initial_message_size: MAX_INITIAL_MESSAGE_SIZE,
            }
        }
    }

    fn page_envelopes<E: prost::Message>(
        stored: Vec<storage::StoredMessage>,
        max_size: usize,
        build: impl Fn(storage::StoredMessage) -> E,
    ) -> (Vec<E>, bool) {
        let mut messages = Vec::with_capacity(stored.len());
        let mut size = 0usize;
        let mut truncated = false;
        for stored in stored {
            let envelope = build(stored);
            size = size.saturating_add(prost::encoding::message::encoded_len(1, &envelope));
            if !messages.is_empty() && size > max_size {
                truncated = true;
                break;
            }
            messages.push(envelope);
        }
        (messages, truncated)
    }

    /// The v2 mailbox server logic over any store implementing [`LocalIdempotentMailboxStore`].
    #[derive(Debug, Builder)]
    pub struct MailboxV2Server<S> {
        #[builder(start_fn)]
        store: S,
        /// Canonical server audience identifier bound into signed requests.
        server_id: String,
        /// Supported PQ suites for carried v2 initial messages (empty when PQ is disabled).
        #[builder(default = vec![u32::from(PqSuite::MlKem1024.as_u8()), u32::from(PqSuite::MlKem768.as_u8())])]
        supported_suites: Vec<u32>,
        /// Allow draining in-flight carried `version == 2` PQ initial messages validated against
        /// known [`PqSuite::from_u8`] even when `supported_suites` is empty (e.g. during a
        /// `PQ_ENABLED="false"` rollback so unacknowledged PQ outboxes never wedge).
        #[builder(default = true)]
        allow_pq_drain: bool,
        /// Size and pagination limits.
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
        async fn push_v2(&self, mut request: PushV2Request) -> Result<PushV2Response> {
            // Destructure upfront so raw `write_token` is hashed + zeroized and outer `Bytes`
            // handles are dropped BEFORE awaiting `self.store.append_idempotent`.
            let recipient_bytes = core::mem::take(&mut request.recipient);
            let message = request.message.take();
            let initial_message_proto = request.initial_message.take();
            let client_message_id_bytes = core::mem::take(&mut request.client_message_id);
            let mut write_token_bytes = core::mem::take(&mut request.write_token);
            drop(request);

            let token_hash_res = fixed::<WRITE_TOKEN_LENGTH>(&write_token_bytes).map(|raw| {
                let raw = Zeroizing::new(raw);
                <[u8; WRITE_TOKEN_HASH_LENGTH]>::from(Sha256::digest(raw.as_slice()))
            });
            crate::zeroize_bytes(&mut write_token_bytes);
            drop(write_token_bytes);

            let recipient_res: Result<PublicKey> = fixed(&recipient_bytes);
            drop(recipient_bytes);
            let client_message_id_res = if client_message_id_bytes.is_empty() {
                Ok(None)
            } else {
                fixed::<CLIENT_MESSAGE_ID_LENGTH>(&client_message_id_bytes).map(Some)
            };
            drop(client_message_id_bytes);

            let recipient = recipient_res?;
            check_canonical_key(&recipient)?;
            let token_hash = token_hash_res?;
            let client_message_id = client_message_id_res?;

            let message = message.ok_or(ErrorKind::Malformed)?;
            if message.header.len() > self.limits.max_header_size {
                return Err(ErrorKind::LimitExceeded.into());
            }

            let initial_message = match initial_message_proto {
                Some(init) => {
                    if init.id != 0 {
                        return Err(ErrorKind::Malformed.into());
                    }
                    let _validated = validate_initial_message_v2(
                        &init,
                        &self.supported_suites,
                        self.allow_pq_drain,
                    )?;
                    // Check encoded size BEFORE allocating a carried-initial buffer.
                    if init.encoded_len() > self.limits.max_initial_message_size {
                        return Err(ErrorKind::LimitExceeded.into());
                    }
                    let encoded = encode_carried_initial(&init)?;
                    drop(init);
                    Some(encoded)
                }
                None => None,
            };

            let size = message
                .header
                .len()
                .saturating_add(message.content.len())
                .saturating_add(initial_message.as_ref().map_or(0, Bytes::len));
            if size > self.limits.max_message_size {
                return Err(ErrorKind::LimitExceeded.into());
            }

            let EncryptedMessage { header, content } = message;
            let sequence = self
                .store
                .append_idempotent(
                    &recipient,
                    &token_hash,
                    header,
                    content,
                    initial_message,
                    client_message_id,
                )
                .await?;
            Ok(PushV2Response { sequence })
        }

        async fn fetch_signed(&self, request: FetchSignedRequest) -> Result<FetchSignedResponse> {
            let recipient = request.verify(&self.server_id, now_millis())?;
            let after_sequence = request.after_sequence;
            let ack_up_to_sequence = request.ack_up_to_sequence;
            let limit = match request.limit {
                0 => self.limits.max_fetch,
                limit => limit.min(self.limits.max_fetch),
            };
            let max_size = match request.max_size {
                0 => self.limits.max_fetch_bytes,
                requested => (requested as usize).min(self.limits.max_fetch_bytes),
            };
            drop(request);

            let page = self
                .store
                .read_mailbox(
                    &recipient,
                    after_sequence,
                    limit,
                    max_size,
                    ack_up_to_sequence,
                )
                .await?;

            let (messages, truncated) =
                page_envelopes(page.messages, max_size, |stored| EnvelopeV2 {
                    sequence: stored.sequence,
                    token_hash: Bytes::copy_from_slice(&stored.token_hash),
                    message: Some(EncryptedMessage {
                        header: stored.header,
                        content: stored.content,
                    }),
                    initial_message: stored
                        .initial_message
                        .as_deref()
                        .and_then(decode_carried_initial),
                });
            Ok(FetchSignedResponse {
                messages,
                has_more: page.has_more || truncated,
            })
        }

        async fn ack_messages(&self, request: AckMessagesRequest) -> Result<AckMessagesResponse> {
            let recipient = request.verify(&self.server_id, now_millis())?;
            let up_to_sequence = request.up_to_sequence;
            drop(request);
            let deleted = self.store.ack_messages(&recipient, up_to_sequence).await?;
            Ok(AckMessagesResponse { deleted })
        }

        async fn register_write_token(
            &self,
            request: RegisterWriteTokenRequest,
        ) -> Result<RegisterWriteTokenResponse> {
            let (recipient, peer_slot_id, token_hash) =
                request.verify(&self.server_id, now_millis())?;
            let grant_version = request.grant_version;
            let pin_active = request.pin_active;
            drop(request);
            self.store
                .register_write_token(RegisterWriteTokenRecord {
                    recipient,
                    peer_slot_id,
                    token_hash,
                    grant_version,
                    pin_active,
                })
                .await?;
            Ok(RegisterWriteTokenResponse {})
        }

        async fn revoke_write_token(
            &self,
            request: RevokeWriteTokenRequest,
        ) -> Result<RevokeWriteTokenResponse> {
            let (recipient, peer_slot_id, token_hash) =
                request.verify(&self.server_id, now_millis())?;
            let min_grant_version = request.min_grant_version;
            drop(request);
            let revoked = self
                .store
                .revoke_write_token(RevokeWriteTokenRecord {
                    recipient,
                    peer_slot_id,
                    token_hash,
                    min_grant_version,
                })
                .await?;
            Ok(RevokeWriteTokenResponse { revoked })
        }
    }

    #[cfg(test)]
    mod test {
        use std::sync::Arc;

        use storage::{
            IdempotentMailboxStore, MailboxPage, MemoryStore, PqHandshakeStore, PublishV2Record,
            StoredCapabilityManifest,
        };
        use x3dh::PQXDH_VERSION;

        use super::*;

        #[derive(Clone)]
        struct SharedStore(Arc<MemoryStore>);

        impl LocalIdempotentMailboxStore for SharedStore {
            async fn append_idempotent(
                &self,
                recipient: &PublicKey,
                token_hash: &[u8; 32],
                header: Bytes,
                content: Bytes,
                initial_message: Option<Bytes>,
                client_message_id: Option<[u8; 16]>,
            ) -> storage::Result<u64> {
                IdempotentMailboxStore::append_idempotent(
                    &*self.0,
                    recipient,
                    token_hash,
                    header,
                    content,
                    initial_message,
                    client_message_id,
                )
                .await
            }
            async fn read_mailbox(
                &self,
                recipient: &PublicKey,
                after_sequence: u64,
                limit: u32,
                max_size: usize,
                ack_up_to_sequence: u64,
            ) -> storage::Result<MailboxPage> {
                IdempotentMailboxStore::read_mailbox(
                    &*self.0,
                    recipient,
                    after_sequence,
                    limit,
                    max_size,
                    ack_up_to_sequence,
                )
                .await
            }
            async fn ack_messages(
                &self,
                recipient: &PublicKey,
                up_to_sequence: u64,
            ) -> storage::Result<u64> {
                IdempotentMailboxStore::ack_messages(&*self.0, recipient, up_to_sequence).await
            }
            async fn register_write_token(
                &self,
                record: RegisterWriteTokenRecord,
            ) -> storage::Result<()> {
                IdempotentMailboxStore::register_write_token(&*self.0, record).await
            }
            async fn revoke_write_token(
                &self,
                record: RevokeWriteTokenRecord,
            ) -> storage::Result<u32> {
                IdempotentMailboxStore::revoke_write_token(&*self.0, record).await
            }
        }

        async fn register_identity(store: &MemoryStore, id: PublicKey) {
            store
                .publish_v2(PublishV2Record {
                    manifest: StoredCapabilityManifest {
                        audience: "relay.example".to_string(),
                        identity_key: id,
                        manifest_seq: 1,
                        generation: 1,
                        issued_at: 1000,
                        expires_at: 100_000,
                        pq_enabled: false,
                        strict_pq: false,
                        pq_ratchet_supported: false,
                        offered_suites: vec![],
                        signed_prekey: crate::test_public_key(0x22),
                        pq_last_resort: vec![],
                        signature: [0x55; 64],
                    },
                    signed_prekey_signature: Some([0x44; 64]),
                    one_time_prekeys: vec![],
                    pq_last_resort: vec![],
                    pq_one_time_prekeys: vec![],
                    timestamp: 1001,
                })
                .await
                .unwrap();
        }

        fn hash_token(token: &[u8; WRITE_TOKEN_LENGTH]) -> [u8; WRITE_TOKEN_HASH_LENGTH] {
            Sha256::digest(token).into()
        }

        #[tokio::test]
        async fn unified_mailbox_grants_push_fetch_ack_and_revocation() {
            let raw_store = Arc::new(MemoryStore::default());
            let v2 = MailboxV2Server::new(SharedStore(raw_store.clone()), "relay.example");
            let now = now_millis();

            let alice = XEdDSAPrivateKey::generate();
            let bob = XEdDSAPrivateKey::generate();
            let eve = XEdDSAPrivateKey::generate();
            let alice_pk = alice.compute_public_key().to_bytes();
            let bob_pk = bob.compute_public_key().to_bytes();
            let peer_slot_alice = [0xA1; PEER_SLOT_ID_LENGTH];
            let token_alice = [0x11; WRITE_TOKEN_LENGTH];
            let hash_alice = hash_token(&token_alice);
            let peer_slot_carol = [0xC1; PEER_SLOT_ID_LENGTH];
            let token_carol = [0x22; WRITE_TOKEN_LENGTH];
            let hash_carol = hash_token(&token_carol);

            // 1. Unregistered Bob cannot register write tokens (NotFound) and pushes fail with WriteTokenRejected.
            assert_eq!(
                v2.register_write_token(
                    RegisterWriteTokenRequest::sign(
                        &bob,
                        "relay.example",
                        &peer_slot_alice,
                        &hash_alice,
                        1,
                        true,
                        now,
                    )
                    .unwrap()
                )
                .await
                .unwrap_err()
                .kind(),
                ErrorKind::NotFound
            );
            assert_eq!(
                v2.push_v2(PushV2Request {
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    message: Some(EncryptedMessage {
                        header: Bytes::from_static(b"h"),
                        content: Bytes::from_static(b"c"),
                    }),
                    initial_message: None,
                    client_message_id: Bytes::new(),
                    write_token: Bytes::copy_from_slice(&token_alice),
                })
                .await
                .unwrap_err()
                .kind(),
                ErrorKind::WriteTokenRejected
            );

            // 2. Register Bob and authorize Alice and Carol.
            register_identity(&raw_store, bob_pk).await;
            v2.register_write_token(
                RegisterWriteTokenRequest::sign(
                    &bob,
                    "relay.example",
                    &peer_slot_alice,
                    &hash_alice,
                    1,
                    true,
                    now,
                )
                .unwrap(),
            )
            .await
            .unwrap();
            v2.register_write_token(
                RegisterWriteTokenRequest::sign(
                    &bob,
                    "relay.example",
                    &peer_slot_carol,
                    &hash_carol,
                    1,
                    true,
                    now,
                )
                .unwrap(),
            )
            .await
            .unwrap();

            // 3. Push with carried PQ initial and client_message_id deduplicates retries.
            let pq_init = InitialMessageV2 {
                id: 0,
                version: PQXDH_VERSION,
                identity_key: Bytes::copy_from_slice(&alice_pk),
                ephemeral_key: Bytes::copy_from_slice(&crate::test_public_key(0x11)),
                signed_prekey: Bytes::copy_from_slice(&crate::test_public_key(0x22)),
                one_time_prekey: None,
                first_message: None,
                pq_suite: u32::from(PqSuite::MlKem768.as_u8()),
                pq_last_resort: false,
                pq_prekey_id: Bytes::from_static(&[0x33; 32]),
                pq_ciphertext: Bytes::from(vec![0x55; PqSuite::MlKem768.ct_len()]),
                manifest_digest: Bytes::from_static(&[0x44; 32]),
            };
            let push1 = PushV2Request {
                recipient: Bytes::copy_from_slice(&bob_pk),
                message: Some(EncryptedMessage {
                    header: Bytes::from_static(b"v2-h1"),
                    content: Bytes::from_static(b"v2-c1"),
                }),
                initial_message: Some(pq_init.clone()),
                client_message_id: Bytes::from_static(&[0x77; CLIENT_MESSAGE_ID_LENGTH]),
                write_token: Bytes::copy_from_slice(&token_alice),
            };
            assert_eq!(v2.push_v2(push1.clone()).await.unwrap().sequence, 1);
            assert_eq!(v2.push_v2(push1).await.unwrap().sequence, 1);

            // Carol's message lands at unified sequence 2 with Carol's token_hash.
            assert_eq!(
                v2.push_v2(PushV2Request {
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    message: Some(EncryptedMessage {
                        header: Bytes::from_static(b"v2-h2"),
                        content: Bytes::from_static(b"v2-c2"),
                    }),
                    initial_message: None,
                    client_message_id: Bytes::from_static(&[0x77; CLIENT_MESSAGE_ID_LENGTH]),
                    write_token: Bytes::copy_from_slice(&token_carol),
                })
                .await
                .unwrap()
                .sequence,
                2
            );

            // 4. Oversized header (> 8 KiB) and oversized inline envelope (> 64 KiB) rejected.
            assert_eq!(
                v2.push_v2(PushV2Request {
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    message: Some(EncryptedMessage {
                        header: Bytes::from(vec![0xAA; MAX_HEADER_SIZE + 1]),
                        content: Bytes::from_static(b"c"),
                    }),
                    initial_message: None,
                    client_message_id: Bytes::new(),
                    write_token: Bytes::copy_from_slice(&token_alice),
                })
                .await
                .unwrap_err()
                .kind(),
                ErrorKind::LimitExceeded
            );
            assert_eq!(
                v2.push_v2(PushV2Request {
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    message: Some(EncryptedMessage {
                        header: Bytes::from_static(b"h"),
                        content: Bytes::from(vec![0xBB; MAX_INLINE_MESSAGE_SIZE]),
                    }),
                    initial_message: None,
                    client_message_id: Bytes::new(),
                    write_token: Bytes::copy_from_slice(&token_alice),
                })
                .await
                .unwrap_err()
                .kind(),
                ErrorKind::LimitExceeded
            );
            // Wrong write_token length -> Malformed.
            assert_eq!(
                v2.push_v2(PushV2Request {
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    message: Some(EncryptedMessage {
                        header: Bytes::from_static(b"h"),
                        content: Bytes::from_static(b"c"),
                    }),
                    initial_message: None,
                    client_message_id: Bytes::new(),
                    write_token: Bytes::from_static(&[0x11; 16]),
                })
                .await
                .unwrap_err()
                .kind(),
                ErrorKind::Malformed
            );

            // 5. Eve cannot fetch Bob's mailbox; wrong audience and stale timestamp rejected.
            let mut forged =
                FetchSignedRequest::sign(&eve, "relay.example", 0, 10, 0, 0, now).unwrap();
            forged.recipient = Bytes::copy_from_slice(&bob_pk);
            assert_eq!(
                v2.fetch_signed(forged).await.unwrap_err().kind(),
                ErrorKind::InvalidSignature
            );
            let wrong_aud =
                FetchSignedRequest::sign(&bob, "wrong.example", 0, 10, 0, 0, now).unwrap();
            assert_eq!(
                v2.fetch_signed(wrong_aud).await.unwrap_err().kind(),
                ErrorKind::InvalidSignature
            );
            let stale = FetchSignedRequest::sign(
                &bob,
                "relay.example",
                0,
                10,
                0,
                0,
                now - crate::MAX_CLOCK_SKEW - 5_000,
            )
            .unwrap();
            assert_eq!(
                v2.fetch_signed(stale).await.unwrap_err().kind(),
                ErrorKind::StaleTimestamp
            );

            // 6. Paginated FetchSigned returns has_more = true on page 1 and token_hash per envelope.
            let page1 = v2
                .fetch_signed(
                    FetchSignedRequest::sign(&bob, "relay.example", 0, 1, 0, 0, now).unwrap(),
                )
                .await
                .unwrap();
            assert!(page1.has_more);
            assert_eq!(page1.messages.len(), 1);
            assert_eq!(page1.messages[0].sequence, 1);
            assert_eq!(page1.messages[0].token_hash.as_ref(), &hash_alice);
            assert_eq!(page1.messages[0].initial_message, Some(pq_init));

            // Page 2 piggybacks ack_up_to_sequence = 1 and reads seq 2 with has_more = false.
            let page2 = v2
                .fetch_signed(
                    FetchSignedRequest::sign(&bob, "relay.example", 1, 10, 0, 1, now).unwrap(),
                )
                .await
                .unwrap();
            assert!(!page2.has_more);
            assert_eq!(page2.messages.len(), 1);
            assert_eq!(page2.messages[0].sequence, 2);
            assert_eq!(page2.messages[0].token_hash.as_ref(), &hash_carol);

            // 7. AckMessages rejects > last_sequence (3), deletes seq 2, and is idempotent.
            assert_eq!(
                v2.ack_messages(AckMessagesRequest::sign(&bob, "relay.example", 3, now).unwrap())
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
            assert_eq!(
                v2.ack_messages(AckMessagesRequest::sign(&bob, "relay.example", 2, now).unwrap())
                    .await
                    .unwrap()
                    .deleted,
                1
            );
            assert_eq!(
                v2.ack_messages(AckMessagesRequest::sign(&bob, "relay.example", 2, now).unwrap())
                    .await
                    .unwrap()
                    .deleted,
                0
            );

            // 8. RevokeWriteToken invalidates Alice's token (auth-before-dedup!) and advances floor.
            assert_eq!(
                v2.revoke_write_token(
                    RevokeWriteTokenRequest::sign(
                        &bob,
                        "relay.example",
                        &peer_slot_alice,
                        None,
                        5,
                        now,
                    )
                    .unwrap()
                )
                .await
                .unwrap()
                .revoked,
                1
            );
            // Even with the old client_message_id, revoked token returns WriteTokenRejected.
            assert_eq!(
                v2.push_v2(PushV2Request {
                    recipient: Bytes::copy_from_slice(&bob_pk),
                    message: Some(EncryptedMessage {
                        header: Bytes::from_static(b"retry"),
                        content: Bytes::from_static(b"retry"),
                    }),
                    initial_message: None,
                    client_message_id: Bytes::from_static(&[0x77; CLIENT_MESSAGE_ID_LENGTH]),
                    write_token: Bytes::copy_from_slice(&token_alice),
                })
                .await
                .unwrap_err()
                .kind(),
                ErrorKind::WriteTokenRejected
            );
            // Stale grant_version <= 5 maps storage::ErrorKind::StaleVersion -> StaleTimestamp.
            assert_eq!(
                v2.register_write_token(
                    RegisterWriteTokenRequest::sign(
                        &bob,
                        "relay.example",
                        &peer_slot_alice,
                        &hash_alice,
                        5,
                        true,
                        now,
                    )
                    .unwrap()
                )
                .await
                .unwrap_err()
                .kind(),
                ErrorKind::StaleTimestamp
            );
        }

        #[tokio::test]
        async fn push_v2_drains_carried_pq_initial_when_pq_disabled_and_validates_lengths() {
            let raw_store = Arc::new(MemoryStore::default());
            let alice = XEdDSAPrivateKey::generate();
            let bob = XEdDSAPrivateKey::generate();
            let alice_pk = alice.compute_public_key().to_bytes();
            let bob_pk = bob.compute_public_key().to_bytes();
            let token = [0x33; WRITE_TOKEN_LENGTH];
            let now = now_millis();

            register_identity(&raw_store, bob_pk).await;
            let drain_server = MailboxV2Server::builder(SharedStore(raw_store.clone()))
                .server_id("relay.example".to_string())
                .supported_suites(vec![])
                .build();
            drain_server
                .register_write_token(
                    RegisterWriteTokenRequest::sign(
                        &bob,
                        "relay.example",
                        &[0x01; PEER_SLOT_ID_LENGTH],
                        &hash_token(&token),
                        1,
                        true,
                        now,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();

            let pq_init = InitialMessageV2 {
                id: 0,
                version: PQXDH_VERSION,
                identity_key: Bytes::copy_from_slice(&alice_pk),
                ephemeral_key: Bytes::copy_from_slice(&crate::test_public_key(0x11)),
                signed_prekey: Bytes::copy_from_slice(&crate::test_public_key(0x22)),
                one_time_prekey: None,
                first_message: None,
                pq_suite: u32::from(PqSuite::MlKem1024.as_u8()),
                pq_last_resort: false,
                pq_prekey_id: Bytes::from_static(&[0x33; 32]),
                pq_ciphertext: Bytes::from(vec![0x55; PqSuite::MlKem1024.ct_len()]),
                manifest_digest: Bytes::from_static(&[0x44; 32]),
            };
            let push = |init: InitialMessageV2| PushV2Request {
                recipient: Bytes::copy_from_slice(&bob_pk),
                message: Some(EncryptedMessage {
                    header: Bytes::from_static(b"h"),
                    content: Bytes::from_static(b"c"),
                }),
                initial_message: Some(init),
                client_message_id: Bytes::new(),
                write_token: Bytes::copy_from_slice(&token),
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
            let strict_server = MailboxV2Server::builder(SharedStore(raw_store))
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

        #[tokio::test]
        async fn fetch_pages_by_encoded_byte_budget_and_sets_has_more() {
            let raw_store = Arc::new(MemoryStore::default());
            let bob = XEdDSAPrivateKey::generate();
            let bob_pk = bob.compute_public_key().to_bytes();
            let token = [0x44; WRITE_TOKEN_LENGTH];
            let now = now_millis();

            register_identity(&raw_store, bob_pk).await;
            let server = MailboxV2Server::builder(SharedStore(raw_store))
                .server_id("relay.example".to_string())
                .limits(MailboxLimits {
                    // Raw bytes of all 3 messages (4 + 4 + 63 = 71 B) fit within 110 B, while
                    // encoded protobuf envelopes (~48 + ~48 + ~107 B) exceed 110 B, verifying
                    // that encoded-size truncation in `page_envelopes` still sets `has_more = true`.
                    max_fetch_bytes: 110,
                    ..MailboxLimits::default()
                })
                .build();
            server
                .register_write_token(
                    RegisterWriteTokenRequest::sign(
                        &bob,
                        "relay.example",
                        &[0x01; PEER_SLOT_ID_LENGTH],
                        &hash_token(&token),
                        1,
                        true,
                        now,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();

            for content in [&b"a"[..], b"b", &[0xEE; 60]] {
                server
                    .push_v2(PushV2Request {
                        recipient: Bytes::copy_from_slice(&bob_pk),
                        message: Some(EncryptedMessage {
                            header: Bytes::from_static(b"hdr"),
                            content: Bytes::copy_from_slice(content),
                        }),
                        initial_message: None,
                        client_message_id: Bytes::new(),
                        write_token: Bytes::copy_from_slice(&token),
                    })
                    .await
                    .unwrap();
            }

            // First page holds messages 1 & 2, stops before the 3rd envelope, and sets has_more = true.
            let p1 = server
                .fetch_signed(
                    FetchSignedRequest::sign(&bob, "relay.example", 0, 10, 0, 0, now).unwrap(),
                )
                .await
                .unwrap();
            assert!(p1.has_more);
            assert_eq!(p1.messages.len(), 2);
            assert_eq!(p1.messages[0].sequence, 1);
            assert_eq!(p1.messages[1].sequence, 2);

            // Second page returns message 3 (even if a smaller max_size is requested, always >= 1 msg).
            let p2 = server
                .fetch_signed(
                    FetchSignedRequest::sign(&bob, "relay.example", 2, 10, 10, 0, now).unwrap(),
                )
                .await
                .unwrap();
            assert!(!p2.has_more);
            assert_eq!(p2.messages.len(), 1);
            assert_eq!(p2.messages[0].sequence, 3);
        }

        #[test]
        fn signing_and_bounds_checks_enforce_invariants() {
            let mut bad_ver = InitialMessageV2 {
                version: 0,
                ..Default::default()
            };
            assert_eq!(
                encode_carried_initial(&bad_ver).unwrap_err().kind(),
                ErrorKind::Malformed
            );
            bad_ver.version = 3;
            assert_eq!(
                encode_carried_initial(&bad_ver).unwrap_err().kind(),
                ErrorKind::Malformed
            );

            let bob = XEdDSAPrivateKey::generate();
            let now = now_millis();
            let slot = [0x11; PEER_SLOT_ID_LENGTH];
            let hash = [0x22; WRITE_TOKEN_HASH_LENGTH];

            assert_eq!(
                AckMessagesRequest::sign(&bob, "relay.example", 0, now)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
            assert_eq!(
                AckMessagesRequest::sign(&bob, "relay.example", crate::MAX_SAFE_INTEGER + 1, now)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
            assert_eq!(
                RegisterWriteTokenRequest::sign(&bob, "relay.example", &slot, &hash, 0, true, now)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
            assert_eq!(
                RevokeWriteTokenRequest::sign(&bob, "relay.example", &slot, Some(&hash), 0, now)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
            assert_eq!(
                FetchSignedRequest::sign(
                    &bob,
                    "relay.example",
                    crate::MAX_SAFE_INTEGER + 1,
                    10,
                    0,
                    0,
                    now
                )
                .unwrap_err()
                .kind(),
                ErrorKind::Malformed
            );
            assert_eq!(
                FetchSignedRequest::sign(
                    &bob,
                    "relay.example",
                    0,
                    10,
                    0,
                    crate::MAX_SAFE_INTEGER + 1,
                    now
                )
                .unwrap_err()
                .kind(),
                ErrorKind::Malformed
            );
        }
    }
}

#[cfg(test)]
mod write_token_security_tests {
    use zeroize::ZeroizeOnDrop;

    use super::*;

    #[test]
    fn push_v2_request_redacts_debug_and_implements_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<PushV2Request>();

        let req = PushV2Request {
            recipient: Bytes::from_static(&[0x11; 32]),
            message: None,
            initial_message: None,
            client_message_id: Bytes::from_static(&[0x22; CLIENT_MESSAGE_ID_LENGTH]),
            write_token: Bytes::copy_from_slice(&[0xAB; WRITE_TOKEN_LENGTH]),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("write_token"), "{dbg}");
        assert!(!dbg.contains("171"), "{dbg}");
        assert!(!dbg.contains("ab"), "{dbg}");
    }
}
