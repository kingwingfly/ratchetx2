//! Transport implementation with futures::channel::mpsc.

use futures::channel::mpsc::{Receiver, Sender, channel};

use super::Transport;
use crate::error::Result;

/// Transport implementation with futures::channel::mpsc.
#[derive(Debug)]
pub struct ChannelTransport {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl ChannelTransport {
    /// New send/recv pairs.
    pub fn new() -> (Self, Self) {
        let (tx_alice, rx_bob) = channel(1024);
        let (tx_bob, rx_alice) = channel(1024);
        (
            Self {
                tx: tx_alice,
                rx: rx_alice,
            },
            Self {
                tx: tx_bob,
                rx: rx_bob,
            },
        )
    }
}

#[allow(clippy::manual_async_fn)]
impl Transport for ChannelTransport {
    fn push_bytes(&mut self, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + Send + 'static {
        self.tx.try_send(bytes).unwrap();
        async { Ok(()) }
    }

    fn fetch_bytes(&mut self) -> impl Future<Output = Result<Vec<Vec<u8>>>> + Send + 'static {
        let mut ret = vec![];
        while let Ok(Some(enc_msg)) = self.rx.try_next() {
            ret.push(enc_msg);
        }
        async { Ok(ret) }
    }
}

#[cfg(test)]
mod test {
    use crate::transport::EncryptedMessage;

    use super::*;

    #[tokio::test]
    async fn channel_transport() {
        let (mut alice, mut bob) = ChannelTransport::new();
        let msg = EncryptedMessage {
            enc_header: vec![1, 2, 3],
            enc_content: vec![4, 5, 6],
        };
        alice.push(msg.clone()).await.unwrap();
        assert_eq!(bob.fetch().await.unwrap()[0], msg);
        let msg = EncryptedMessage {
            enc_header: vec![4, 5, 6],
            enc_content: vec![1, 2, 3],
        };
        alice.push(msg.clone()).await.unwrap();
        assert_eq!(bob.fetch().await.unwrap()[0], msg);
    }
}
