//! The mailbox service: one queue of encrypted messages per sender and recipient.

use crate::error::Result;

#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/mailbox.v1.rs"));
}

pub use generated::*;
#[cfg(feature = "server")]
pub use server::{MailboxLimits, MailboxServer};

/// Client side of the mailbox service.
#[trait_variant::make(Mailbox: Send)]
pub trait LocalMailbox {
    /// Append a message to the queue from its sender to its recipient.
    async fn push(&self, request: PushRequest) -> Result<PushResponse>;
    /// Read messages from a queue, after a sequence number.
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse>;
}

#[cfg(feature = "server")]
mod server {
    use bon::Builder;
    use party::EncryptedMessage;
    use storage::LocalMailboxStore;

    use super::*;
    use crate::error::ErrorKind;
    use crate::fixed;

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
                // Below gRPC's default limit of 4 MiB per request or response, leaving room
                // for the rest of a push request or a fetch response.
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
            if message.header.len() + message.content.len() > self.limits.max_message_size {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let sequence = self
                .store
                .append(&sender, &recipient, message.header, message.content)
                .await?;
            Ok(PushResponse { sequence })
        }

        /// Read messages from a queue.
        async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse> {
            let (sender, recipient) = (fixed(&request.sender)?, fixed(&request.recipient)?);
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
                    message: Some(EncryptedMessage {
                        header: stored.header,
                        content: stored.content,
                    }),
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
            }
        }

        fn fetch(after: u64, limit: u32) -> FetchRequest {
            FetchRequest {
                sender: Bytes::from_static(&ALICE),
                recipient: Bytes::from_static(&BOB),
                after,
                limit,
            }
        }

        #[tokio::test]
        async fn push_and_fetch() {
            let server = MailboxServer::builder(MemoryStore::default())
                .limits(MailboxLimits {
                    max_message_size: 40,
                    max_fetch: 2,
                })
                .build();
            for (i, content) in [b"a", b"b", b"c"].into_iter().enumerate() {
                let response = server.push(push(content)).await.unwrap();
                assert_eq!(response.sequence, i as u64 + 1);
            }
            // The 6-byte header and 35 bytes of content exceed 40 bytes.
            assert_eq!(
                server.push(push(&[0; 35])).await.unwrap_err().kind(),
                ErrorKind::LimitExceeded
            );
            let mut missing = push(b"a");
            missing.message = None;
            assert_eq!(
                server.push(missing).await.unwrap_err().kind(),
                ErrorKind::Malformed
            );

            // 0 asks for the server's maximum, and larger limits are capped by it.
            for limit in [0, 9] {
                let messages = server.fetch(fetch(0, limit)).await.unwrap().messages;
                assert_eq!(messages.len(), 2);
            }

            // A page stays within the message size: a large message starts the next page, and
            // a page always holds at least one message.
            server.push(push(&[0; 30])).await.unwrap();
            let messages = server.fetch(fetch(2, 0)).await.unwrap().messages;
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].sequence, 3);
            let messages = server.fetch(fetch(3, 0)).await.unwrap().messages;
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].sequence, 4);
        }
    }
}
