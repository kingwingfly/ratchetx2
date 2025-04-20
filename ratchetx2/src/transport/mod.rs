//! Message transport.

pub mod channel;
pub mod error;

use bincode::{Decode, Encode, config};
use error::Result;

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
    fn send_bytes(&self, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + Send + 'static;
    /// Receive bytes.
    fn recv_bytes(&self) -> impl Future<Output = Result<Vec<u8>>> + Send + 'static;
    /// Send encrypted message
    fn send(&self, enc_msg: EncryptedMessage) -> impl Future<Output = Result<()>> + Send + 'static {
        let config = config::standard();
        let bytes = bincode::encode_to_vec(enc_msg, config).unwrap();
        self.send_bytes(bytes)
    }
    /// Receive encrypted message.
    fn recv(&self) -> impl Future<Output = Result<EncryptedMessage>> + Send + 'static {
        let bytes_fut = self.recv_bytes();
        async {
            let bytes = bytes_fut.await?;
            let (enc_msg, _) = bincode::decode_from_slice(&bytes, config::standard()).unwrap();
            Ok(enc_msg)
        }
    }
}
