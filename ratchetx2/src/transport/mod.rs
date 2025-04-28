//! Message transport.

pub mod channel;
#[cfg(feature = "grpc")]
pub mod grpc;

pub use channel::ChannelTransport;
#[cfg(feature = "grpc")]
pub use grpc::{RpcMessageServer, RpcTransport};

use bincode::{Decode, Encode, config};

use crate::error::{Result, TransportError};

/// Encrypted message.
#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(test, derive(PartialEq))]
pub struct EncryptedMessage {
    /// Encrypted header.
    pub enc_header: Vec<u8>,
    /// Encrypted content.
    pub enc_content: Vec<u8>,
}

/// To send/recv encrtpted data.
pub trait Transport {
    /// Push bytes to A-B message bucket.
    fn push_bytes(&mut self, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + Send + 'static;
    /// Fetch bytes from B-A message bucket.
    fn fetch_bytes(
        &mut self,
        limit: Option<usize>,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>>> + Send + 'static;
    /// Push encrypted message to A-B message bucket.
    fn push(
        &mut self,
        enc_msg: EncryptedMessage,
    ) -> impl Future<Output = Result<()>> + Send + 'static {
        let config = config::standard();
        let bytes = bincode::encode_to_vec(enc_msg, config).unwrap();
        self.push_bytes(bytes)
    }
    /// Fetch encrypted message from B-A message bucket.
    fn fetch(
        &mut self,
        limit: Option<usize>,
    ) -> impl Future<Output = Result<Vec<EncryptedMessage>>> + Send + 'static {
        let enc_msgs_fut = self.fetch_bytes(limit);
        async {
            let enc_msgs = enc_msgs_fut.await?;
            let mut ret = vec![];
            for bytes in enc_msgs {
                let (enc_msg, _): (EncryptedMessage, _) =
                    bincode::decode_from_slice(&bytes, config::standard())
                        .map_err(|_| TransportError::Fetch)?;
                ret.push(enc_msg);
            }
            Ok(ret)
        }
    }
}
