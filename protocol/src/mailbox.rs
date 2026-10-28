//! The mailbox service: one queue of encrypted messages per sender and recipient.
//!
//! Pushing and fetching are open, as what they carry is encrypted end to end. A message goes once
//! its recipient has it: the push gives the server SHA-256 of the message's delivery token, a
//! secret only the two peers can compute, and the recipient gives the token back with a later
//! fetch, once it kept the message, so that the server deletes it. One never delivered expires.

use crate::error::Result;

#[allow(missing_docs)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/mailbox.v1.rs"));
}

pub use proto::*;
#[cfg(feature = "server")]
pub use server::{MailboxLimits, MailboxServer};

/// Length of a delivery token.
pub const DELIVERY_TOKEN_LENGTH: usize = 16;
/// Most delivery tokens of one fetch.
pub const MAX_DELIVERED: usize = 1000;

/// Client side of the mailbox service.
#[trait_variant::make(Mailbox: Send)]
pub trait LocalMailbox {
    /// Append a message to the queue from its sender to its recipient.
    async fn push(&self, request: PushRequest) -> Result<PushResponse>;
    /// Read messages from a queue, after a sequence number, first deleting those whose delivery
    /// tokens it gives.
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse>;
}

#[cfg(feature = "server")]
mod server {
    use bon::Builder;
    use bytes::Bytes;
    use party::EncryptedMessage;
    use prost::Message as _;
    use sha2::{Digest, Sha256};
    use storage::LocalMailboxStore;

    use super::*;
    use crate::{error::ErrorKind, fixed, handshake::InitialMessage};

    /// Limits of a [`MailboxServer`].
    #[derive(Debug, Clone, Copy)]
    pub struct MailboxLimits {
        /// Largest message, header and content together, in bytes.
        ///
        /// Also the most bytes one fetch returns, unless its first message alone is larger, so
        /// a page of messages fits wherever one message does.
        pub max_message_size: usize,
        /// Most messages in one fetch.
        pub max_fetch: u32,
    }

    impl Default for MailboxLimits {
        fn default() -> Self {
            Self {
                // Below 4 MiB per request or response, a common limit of transports (gRPC's
                // default, the Worker's), leaving room for the rest of a push request or a fetch
                // response.
                max_message_size: (4 << 20) - (64 << 10),
                max_fetch: 100,
            }
        }
    }

    /// The mailbox server's logic, over any mailbox store.
    ///
    /// [`MailboxServer::new`] gives it the default limits, and [`MailboxServer::builder`] can
    /// set them: `MailboxServer::builder(store).limits(limits).build()`.
    #[derive(Debug, Builder)]
    pub struct MailboxServer<S> {
        #[builder(start_fn)]
        store: S,
        /// The limits; the default ones unless set.
        #[builder(default)]
        limits: MailboxLimits,
    }

    impl<S> MailboxServer<S> {
        /// A server over `store`, with the default limits.
        pub fn new(store: S) -> Self {
            Self::builder(store).build()
        }
    }

    impl<S: LocalMailboxStore> LocalMailbox for MailboxServer<S> {
        /// Append a message to its queue.
        async fn push(&self, request: PushRequest) -> Result<PushResponse> {
            let (sender, recipient) = (fixed(&request.sender)?, fixed(&request.recipient)?);
            let message = request.message.ok_or(ErrorKind::Malformed)?;
            let initial_message = request
                .initial_message
                .map(|initial_message| Bytes::from(initial_message.encode_to_vec()));
            let size = message.header.len()
                + message.content.len()
                + initial_message.as_ref().map_or(0, Bytes::len);
            if size > self.limits.max_message_size {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let delivery_hash = match request.delivery_hash.len() {
                0 => None,
                _ => Some(fixed(&request.delivery_hash)?),
            };
            let sequence = self
                .store
                .append(
                    &sender,
                    &recipient,
                    message.header,
                    message.content,
                    initial_message,
                    delivery_hash,
                )
                .await?;
            Ok(PushResponse { sequence })
        }

        /// Delete the messages of a queue whose delivery tokens the request gives, then read
        /// the queue.
        async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse> {
            let (sender, recipient) = (fixed(&request.sender)?, fixed(&request.recipient)?);
            if request.delivered.len() > MAX_DELIVERED {
                return Err(ErrorKind::LimitExceeded.into());
            }
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
            let stored = self
                .store
                .read(&sender, &recipient, request.after, limit)
                .await?;
            // Count the encoded size too, so a few large messages cannot make a page too
            // large for the transport; the first message always fits, so fetching progresses.
            let mut messages = Vec::with_capacity(stored.len());
            let mut size = 0;
            for stored in stored {
                let envelope = Envelope {
                    sequence: stored.sequence,
                    // None once its content expired, which the recipient goes past.
                    message: stored.content.map(|content| EncryptedMessage {
                        header: stored.header,
                        content,
                    }),
                    // As stored from a push, which decoded it.
                    initial_message: stored
                        .initial_message
                        .and_then(|bytes| InitialMessage::decode(bytes).ok()),
                };
                size += prost::encoding::message::encoded_len(1, &envelope);
                if !messages.is_empty() && size > self.limits.max_message_size {
                    break;
                }
                messages.push(envelope);
            }
            Ok(FetchResponse { messages })
        }
    }

    #[cfg(test)]
    mod test {
        use bytes::Bytes;
        use storage::MemoryStore;

        use super::*;

        const ALICE: [u8; 32] = [1; 32];
        const BOB: [u8; 32] = [2; 32];

        fn push(content: &'static [u8]) -> PushRequest {
            PushRequest {
                sender: Bytes::from_static(&ALICE),
                recipient: Bytes::from_static(&BOB),
                message: Some(EncryptedMessage {
                    header: Bytes::from_static(b"header"),
                    content: Bytes::from_static(content),
                }),
                initial_message: None,
                delivery_hash: Bytes::new(),
            }
        }

        #[tokio::test]
        async fn delivered_messages_go() {
            let server = MailboxServer::new(MemoryStore::default());
            let token = |byte| [byte; DELIVERY_TOKEN_LENGTH];
            let hash = |byte| Bytes::from(Sha256::digest(token(byte)).to_vec());
            for (content, delivery_hash) in
                [(&b"a"[..], hash(1)), (b"b", hash(2)), (b"c", Bytes::new())]
            {
                let pushed = PushRequest {
                    delivery_hash,
                    ..push(content)
                };
                server.push(pushed).await.unwrap();
            }
            // A hash of another length is refused.
            let malformed = PushRequest {
                delivery_hash: Bytes::from_static(&[0; 31]),
                ..push(b"d")
            };
            assert_eq!(
                server.push(malformed).await.unwrap_err().kind(),
                ErrorKind::Malformed
            );
            // Bob has the first, and gives a token that names none: the first goes.
            let delivered = |tokens: Vec<[u8; DELIVERY_TOKEN_LENGTH]>| FetchRequest {
                delivered: tokens
                    .into_iter()
                    .map(|t| Bytes::copy_from_slice(&t))
                    .collect(),
                ..fetch(0, 0)
            };
            let messages = server
                .fetch(delivered(vec![token(1), token(9)]))
                .await
                .unwrap()
                .messages;
            let sequences: Vec<_> = messages.iter().map(|m| m.sequence).collect();
            assert_eq!(sequences, [2, 3]);
            // Tokens of another length, or too many: refused.
            for (request, kind) in [
                (
                    FetchRequest {
                        delivered: vec![Bytes::from_static(&[2; 15])],
                        ..fetch(0, 0)
                    },
                    ErrorKind::Malformed,
                ),
                (
                    delivered(vec![token(2); MAX_DELIVERED + 1]),
                    ErrorKind::LimitExceeded,
                ),
            ] {
                assert_eq!(server.fetch(request).await.unwrap_err().kind(), kind);
            }
            assert_eq!(server.fetch(fetch(0, 0)).await.unwrap().messages.len(), 2);
            // Numbers go on after those deleted.
            server.fetch(delivered(vec![token(2)])).await.unwrap();
            assert_eq!(server.push(push(b"e")).await.unwrap().sequence, 4);
        }

        #[tokio::test]
        async fn messages_keep_their_initial_message() {
            let server = MailboxServer::new(MemoryStore::default());
            let initial_message = InitialMessage {
                identity_key: Bytes::from_static(&ALICE),
                ..InitialMessage::default()
            };
            let pushed = server
                .push(PushRequest {
                    initial_message: Some(initial_message.clone()),
                    ..push(b"a")
                })
                .await
                .unwrap();
            assert_eq!(pushed.sequence, 1);
            let messages = server.fetch(fetch(0, 0)).await.unwrap().messages;
            assert_eq!(messages[0].initial_message, Some(initial_message));
        }

        fn fetch(after: u64, limit: u32) -> FetchRequest {
            FetchRequest {
                sender: Bytes::from_static(&ALICE),
                recipient: Bytes::from_static(&BOB),
                after,
                limit,
                delivered: vec![],
            }
        }

        #[tokio::test]
        async fn fetch_pages_by_size() {
            let server = MailboxServer::builder(MemoryStore::default())
                .limits(MailboxLimits {
                    max_message_size: 40,
                    ..MailboxLimits::default()
                })
                .build();
            for content in [&b"a"[..], b"b", &[0; 30]] {
                server.push(push(content)).await.unwrap();
            }
            // A page stays within the message size: a large message starts the next page, and
            // a page always holds at least one message.
            let messages = server.fetch(fetch(1, 0)).await.unwrap().messages;
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].sequence, 2);
            let messages = server.fetch(fetch(2, 0)).await.unwrap().messages;
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].sequence, 3);
        }
    }
}
