//! Message transport.

pub mod channel;
pub mod error;
pub mod grpc;

pub use channel::ChannelTransport;
pub use grpc::{RpcServer, RpcTransport};

use bincode::{Decode, Encode, config};
use error::{Result, TransportError};

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
    /// Send bytes.
    fn send_bytes(&mut self, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + Send + 'static;
    /// Receive bytes.
    fn recv_bytes(&mut self) -> impl Future<Output = Result<Vec<Vec<u8>>>> + Send + 'static;
    /// Send encrypted message
    fn send(
        &mut self,
        enc_msg: EncryptedMessage,
    ) -> impl Future<Output = Result<()>> + Send + 'static {
        let config = config::standard();
        let bytes = bincode::encode_to_vec(enc_msg, config).unwrap();
        self.send_bytes(bytes)
    }
    /// Receive encrypted message.
    fn recv(&mut self) -> impl Future<Output = Result<Vec<EncryptedMessage>>> + Send + 'static {
        let enc_msgs_fut = self.recv_bytes();
        async {
            let enc_msgs = enc_msgs_fut.await?;
            let mut ret = vec![];
            for bytes in enc_msgs {
                let (enc_msg, _): (EncryptedMessage, _) =
                    bincode::decode_from_slice(&bytes, config::standard())
                        .map_err(|_| TransportError::Recv)?;
                ret.push(enc_msg);
            }
            Ok(ret)
        }
    }
}
