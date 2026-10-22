//! In-memory backend.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use parking_lot::Mutex;

use crate::{Bundle, HandshakeStore, Introduction, MailboxStore, PublicKey, Result, StoredMessage};

/// Keeps everything in memory until dropped. Implements both [`HandshakeStore`] and
/// [`MailboxStore`].
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    bundles: HashMap<PublicKey, (Bundle, VecDeque<PublicKey>)>,
    inboxes: HashMap<PublicKey, Inbox>,
    queues: HashMap<(PublicKey, PublicKey), Vec<StoredMessage>>,
}

#[derive(Debug, Default)]
struct Inbox {
    last_take: Option<u64>,
    introductions: Vec<Introduction>,
}

impl HandshakeStore for MemoryStore {
    async fn publish(&self, bundle: Bundle, one_time_prekeys: Vec<PublicKey>) -> Result<bool> {
        let mut inner = self.inner.lock();
        if let Some((stored, _)) = inner.bundles.get(&bundle.identity_key)
            && stored.timestamp >= bundle.timestamp
        {
            return Ok(false);
        }
        inner
            .bundles
            .insert(bundle.identity_key, (bundle, one_time_prekeys.into()));
        Ok(true)
    }

    async fn take_bundle(
        &self,
        identity_key: &PublicKey,
    ) -> Result<Option<(Bundle, Option<PublicKey>)>> {
        let mut inner = self.inner.lock();
        Ok(inner
            .bundles
            .get_mut(identity_key)
            .map(|(bundle, one_time_prekeys)| (bundle.clone(), one_time_prekeys.pop_front())))
    }

    async fn add_introduction(&self, introduction: Introduction, limit: usize) -> Result<bool> {
        let mut inner = self.inner.lock();
        let inbox = inner.inboxes.entry(introduction.recipient).or_default();
        if inbox.introductions.len() >= limit {
            return Ok(false);
        }
        inbox.introductions.push(introduction);
        Ok(true)
    }

    async fn take_introductions(
        &self,
        recipient: &PublicKey,
        timestamp: u64,
    ) -> Result<Option<Vec<Introduction>>> {
        let mut inner = self.inner.lock();
        let inbox = inner.inboxes.entry(*recipient).or_default();
        if inbox.last_take.is_some_and(|last| last >= timestamp) {
            return Ok(None);
        }
        inbox.last_take = Some(timestamp);
        Ok(Some(std::mem::take(&mut inbox.introductions)))
    }
}

impl MailboxStore for MemoryStore {
    async fn append(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
    ) -> Result<u64> {
        let mut inner = self.inner.lock();
        let queue = inner.queues.entry((*sender, *recipient)).or_default();
        let sequence = queue.last().map_or(1, |last| last.sequence + 1);
        queue.push(StoredMessage {
            sender: *sender,
            recipient: *recipient,
            sequence,
            header,
            content,
        });
        Ok(sequence)
    }

    async fn read(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        after: u64,
        limit: u32,
    ) -> Result<Vec<StoredMessage>> {
        let inner = self.inner.lock();
        let Some(queue) = inner.queues.get(&(*sender, *recipient)) else {
            return Ok(vec![]);
        };
        // Sequence numbers increase by 1, so the messages after `after`, at most `limit`, are
        // the ones numbered up to `after + limit`.
        let last = after.saturating_add(limit.into());
        let start = queue.partition_point(|message| message.sequence <= after);
        let end = queue.partition_point(|message| message.sequence <= last);
        Ok(queue[start..end].to_vec())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn conformance() {
        futures::executor::block_on(async {
            crate::testing::handshake_store(&MemoryStore::default()).await;
            crate::testing::mailbox_store(&MemoryStore::default()).await;
        });
    }
}
