//! Transport implementation with futures::channel::mpsc.

use futures::channel::mpsc::{Receiver, Sender, channel};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::Transport;
use crate::error::Result;

/// Transport implementation with futures::channel::mpsc.
#[allow(clippy::type_complexity)]
#[derive(Debug, Default, Clone)]
pub struct ChannelTransport {
    channels: Arc<RwLock<HashMap<Vec<u8>, (Sender<Vec<u8>>, Receiver<Vec<u8>>)>>>,
}

impl ChannelTransport {
    /// New send/recv pairs.
    pub fn new() -> (Self, Self) {
        let channel = ChannelTransport::default();
        (channel.clone(), channel)
    }
}

#[allow(clippy::manual_async_fn)]
impl Transport for ChannelTransport {
    fn push_bytes(
        &mut self,
        target: impl AsRef<[u8]>,
        bytes: impl AsRef<[u8]>,
    ) -> impl Future<Output = Result<()>> + Send + 'static {
        let mut tx = {
            self.channels
                .write()
                .unwrap()
                .entry(target.as_ref().to_vec())
                .or_insert(channel(1024))
                .0
                .clone()
        };
        tx.try_send(bytes.as_ref().to_vec()).unwrap();
        async { Ok(()) }
    }

    fn fetch_bytes(
        &mut self,
        target: impl AsRef<[u8]>,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>>> + Send + 'static {
        let mut ret = vec![];
        let mut channels = self.channels.write().unwrap();
        let rx = &mut channels
            .entry(target.as_ref().to_vec())
            .or_insert(channel(1024))
            .1;
        while let Ok(Some(enc_msg)) = rx.try_next() {
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
        alice.push("AliceBob", msg.clone()).await.unwrap();
        assert_eq!(bob.fetch("AliceBob").await.unwrap()[0], msg);
        let msg = EncryptedMessage {
            enc_header: vec![4, 5, 6],
            enc_content: vec![1, 2, 3],
        };
        alice.push("AliceBob", msg.clone()).await.unwrap();
        assert_eq!(bob.fetch("AliceBob").await.unwrap()[0], msg);
    }
}
