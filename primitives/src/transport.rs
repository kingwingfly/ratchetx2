//! Message transport.

pub mod channel;
#[cfg(feature = "grpc")]
pub mod grpc;

pub use channel::ChannelTransport;
#[cfg(feature = "grpc")]
pub use grpc::{RpcMessageServer, RpcTransport};

use prost::Message as _;

use crate::error::{Error, ErrorKind, Result};

/// Encrypted message.
#[derive(Clone, prost::Message)]
#[cfg_attr(test, derive(PartialEq))]
pub struct EncryptedMessage {
    /// Encrypted header.
    #[prost(bytes = "vec", tag = "1")]
    pub enc_header: Vec<u8>,
    /// Encrypted content.
    #[prost(bytes = "vec", tag = "2")]
    pub enc_content: Vec<u8>,
}

/// To send/recv encrtpted data.
///
/// Implement [`Transport`] for transports whose futures are `Send` (needed to share a party
/// across threads, e.g. with tokio); it implies [`LocalTransport`]. Implement [`LocalTransport`]
/// directly for transports whose futures are not `Send`, e.g. in the browser.
#[trait_variant::make(Transport: Send)]
pub trait LocalTransport {
    /// Push bytes to A-B message bucket.
    async fn push_bytes(&mut self, bytes: Vec<u8>) -> Result<()>;
    /// Fetch bytes from B-A message bucket.
    async fn fetch_bytes(&mut self, limit: Option<usize>) -> Result<Vec<Vec<u8>>>;
    // trait_variant does not rewrite default bodies, so these return the future explicitly.
    /// Push encrypted message to A-B message bucket.
    fn push(&mut self, enc_msg: EncryptedMessage) -> impl Future<Output = Result<()>> {
        async move { self.push_bytes(enc_msg.encode_to_vec()).await }
    }
    /// Fetch encrypted message from B-A message bucket.
    ///
    /// Bytes that are not an [`EncryptedMessage`] give an error for that message only, so the
    /// valid messages fetched with them are not lost.
    fn fetch(
        &mut self,
        limit: Option<usize>,
    ) -> impl Future<Output = Result<Vec<Result<EncryptedMessage>>>> {
        async move {
            Ok(self
                .fetch_bytes(limit)
                .await?
                .into_iter()
                .map(|bytes| {
                    EncryptedMessage::decode(bytes.as_slice())
                        .map_err(|e| Error::new(ErrorKind::InvalidMessage, e))
                })
                .collect())
        }
    }
}
