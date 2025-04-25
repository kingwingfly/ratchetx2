//! Transport implementation with futures::channel::mpsc.

use futures::channel::mpsc::{Receiver, Sender, channel};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use super::Transport;
use crate::error::Result;

/// Transport implementation with futures::channel::mpsc.
#[allow(clippy::type_complexity)]
#[derive(Debug, Default, Clone)]
pub struct ChannelTransport {
    channels: Arc<RwLock<HashMap<u8, (Sender<Vec<u8>>, Receiver<Vec<u8>>)>>>,
    push_target: u8,
    fetch_target: u8,
}

impl ChannelTransport {
    /// New send/recv pairs.
    pub fn new() -> (Self, Self) {
        let channels = Arc::new(RwLock::new(HashMap::default()));
        (
            ChannelTransport {
                channels: channels.clone(),
                push_target: 0,
                fetch_target: 1,
            },
            ChannelTransport {
                channels,
                push_target: 1,
                fetch_target: 0,
            },
        )
    }
}

#[allow(clippy::manual_async_fn)]
impl Transport for ChannelTransport {
    fn push_bytes(&mut self, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + Send + 'static {
        let mut tx = {
            self.channels
                .write()
                .entry(self.push_target)
                .or_insert(channel(1024))
                .0
                .clone()
        };
        tx.try_send(bytes).unwrap();
        async { Ok(()) }
    }

    fn fetch_bytes(
        &mut self,
        limit: Option<usize>,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>>> + Send + 'static {
        let mut ret = vec![];
        let mut channels = self.channels.write();
        let rx = &mut channels.entry(self.fetch_target).or_insert(channel(1024)).1;
        while let Ok(Some(enc_msg)) = rx.try_next() {
            ret.push(enc_msg);
            if let Some(limit) = limit {
                if ret.len() == limit {
                    break;
                }
            }
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
        assert_eq!(bob.fetch(None).await.unwrap()[0], msg);
        let msg = EncryptedMessage {
            enc_header: vec![4, 5, 6],
            enc_content: vec![1, 2, 3],
        };
        alice.push(msg.clone()).await.unwrap();
        assert_eq!(bob.fetch(None).await.unwrap()[0], msg);
    }
}
