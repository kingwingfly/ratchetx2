//! Transport implementation by futures::channel::mpsc.

use futures::channel::mpsc::{Receiver, Sender, channel};
use std::sync::Mutex;

use super::Transport;
use super::error::Result;

/// Transport implementation by futures::channel::mpsc.
#[derive(Debug)]
pub struct ChannelTransport {
    tx: Mutex<Sender<Vec<u8>>>,
    rx: Mutex<Receiver<Vec<u8>>>,
}

impl ChannelTransport {
    /// New send/recv pairs.
    pub fn new() -> (Self, Self) {
        let (tx_alice, rx_bob) = channel(1024);
        let (tx_bob, rx_alice) = channel(1024);
        (
            Self {
                tx: Mutex::new(tx_alice),
                rx: Mutex::new(rx_alice),
            },
            Self {
                tx: Mutex::new(tx_bob),
                rx: Mutex::new(rx_bob),
            },
        )
    }
}

#[allow(clippy::manual_async_fn)]
impl Transport for ChannelTransport {
    fn send_bytes(&self, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + Send + 'static {
        let mut tx = self.tx.lock().unwrap();
        tx.try_send(bytes).unwrap();
        async { Ok(()) }
    }

    fn recv_bytes(&self) -> impl Future<Output = Result<Vec<u8>>> + Send + 'static {
        let mut rx = self.rx.lock().unwrap();
        let ret = loop {
            if let Ok(Some(ret)) = rx.try_next() {
                break ret;
            }
        };
        async { Ok(ret) }
    }
}

#[cfg(test)]
mod test {
    use crate::transport::EncryptedMessage;

    use super::*;

    #[tokio::test]
    async fn channel_transport() {
        let (alice, bob) = ChannelTransport::new();
        let msg = EncryptedMessage {
            enc_header: vec![1, 2, 3],
            enc_content: vec![4, 5, 6],
        };
        alice.send(msg.clone()).await.unwrap();
        assert_eq!(bob.recv().await.unwrap(), msg);
        let msg = EncryptedMessage {
            enc_header: vec![4, 5, 6],
            enc_content: vec![1, 2, 3],
        };
        alice.send(msg.clone()).await.unwrap();
        assert_eq!(bob.recv().await.unwrap(), msg);
    }
}
