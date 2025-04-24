//! Message transport.

pub mod channel;
pub mod grpc;

pub use channel::ChannelTransport;
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
    /// Push bytes to target message bucket.
    fn push_bytes(
        &mut self,
        target: impl AsRef<[u8]>,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<()>> + Send + 'static;
    /// Fetch bytes from target message bucket.
    fn fetch_bytes(
        &mut self,
        target: impl AsRef<[u8]>,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>>> + Send + 'static;
    /// Push encrypted message to target message bucket.
    fn push(
        &mut self,
        target: impl AsRef<[u8]>,
        enc_msg: EncryptedMessage,
    ) -> impl Future<Output = Result<()>> + Send + 'static {
        let config = config::standard();
        let bytes = bincode::encode_to_vec(enc_msg, config).unwrap();
        self.push_bytes(target, bytes)
    }
    /// Fetch encrypted message from target message bucket.
    fn fetch(
        &mut self,
        target: impl AsRef<[u8]>,
    ) -> impl Future<Output = Result<Vec<EncryptedMessage>>> + Send + 'static {
        let enc_msgs_fut = self.fetch_bytes(target);
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
