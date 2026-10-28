//! In-memory backend.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use parking_lot::Mutex;

use crate::{
    AttachmentId, AttachmentStore, Bundle, ErrorKind, HandshakeStore, MailboxStore, PublicKey,
    Result, StoredAttachment, StoredInitialMessage, StoredMessage,
};

/// Keeps everything in memory until dropped. Implements [`HandshakeStore`], [`MailboxStore`] and
/// [`AttachmentStore`].
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    bundles: HashMap<PublicKey, (Bundle, VecDeque<PublicKey>)>,
    inboxes: HashMap<PublicKey, Inbox>,
    queues: HashMap<(PublicKey, PublicKey), Vec<Queued>>,
    /// The last sequence number of each queue, which goes on once its messages are deleted.
    last_sequences: HashMap<(PublicKey, PublicKey), u64>,
    attachments: HashMap<AttachmentId, (StoredAttachment, HashMap<u32, Bytes>)>,
}

/// A message of a queue, with SHA-256 of its delivery token, if any.
#[derive(Debug)]
struct Queued {
    message: StoredMessage,
    delivery_hash: Option<[u8; 32]>,
}

#[derive(Debug, Default)]
struct Inbox {
    last_take: Option<u64>,
    initial_messages: Vec<StoredInitialMessage>,
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

    async fn add_initial_message(
        &self,
        initial_message: StoredInitialMessage,
        limit: usize,
    ) -> Result<bool> {
        let mut inner = self.inner.lock();
        let inbox = inner.inboxes.entry(initial_message.recipient).or_default();
        if inbox.initial_messages.len() >= limit {
            return Ok(false);
        }
        inbox.initial_messages.push(initial_message);
        Ok(true)
    }

    async fn take_initial_messages(
        &self,
        recipient: &PublicKey,
        timestamp: u64,
    ) -> Result<Option<Vec<StoredInitialMessage>>> {
        let mut inner = self.inner.lock();
        let inbox = inner.inboxes.entry(*recipient).or_default();
        if inbox.last_take.is_some_and(|last| last >= timestamp) {
            return Ok(None);
        }
        inbox.last_take = Some(timestamp);
        Ok(Some(std::mem::take(&mut inbox.initial_messages)))
    }
}

impl MailboxStore for MemoryStore {
    async fn append(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        header: Bytes,
        content: Bytes,
        initial_message: Option<Bytes>,
        delivery_hash: Option<[u8; 32]>,
    ) -> Result<u64> {
        let mut inner = self.inner.lock();
        let last = inner
            .last_sequences
            .entry((*sender, *recipient))
            .or_default();
        *last += 1;
        let sequence = *last;
        let message = StoredMessage {
            sender: *sender,
            recipient: *recipient,
            sequence,
            header,
            content: Some(content),
            initial_message,
        };
        inner
            .queues
            .entry((*sender, *recipient))
            .or_default()
            .push(Queued {
                message,
                delivery_hash,
            });
        Ok(sequence)
    }

    async fn delete_delivered(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
        hashes: &[[u8; 32]],
    ) -> Result<()> {
        let mut inner = self.inner.lock();
        if let Some(queue) = inner.queues.get_mut(&(*sender, *recipient)) {
            queue.retain(|queued| {
                !queued
                    .delivery_hash
                    .is_some_and(|hash| hashes.contains(&hash))
            });
        }
        Ok(())
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
        // In order, with gaps where messages were delivered or expired.
        let start = queue.partition_point(|queued| queued.message.sequence <= after);
        Ok(queue[start..]
            .iter()
            .take(limit as usize)
            .map(|queued| queued.message.clone())
            .collect())
    }
}

impl AttachmentStore for MemoryStore {
    async fn add_attachment(&self, attachment: StoredAttachment) -> Result<bool> {
        let mut inner = self.inner.lock();
        if inner.attachments.contains_key(&attachment.id) {
            return Ok(false);
        }
        inner
            .attachments
            .insert(attachment.id, (attachment, HashMap::new()));
        Ok(true)
    }

    async fn attachment(&self, id: &AttachmentId) -> Result<Option<StoredAttachment>> {
        let inner = self.inner.lock();
        Ok(inner
            .attachments
            .get(id)
            .map(|(attachment, _)| attachment.clone()))
    }

    async fn put_chunk(&self, id: &AttachmentId, index: u32, data: Bytes) -> Result<()> {
        let mut inner = self.inner.lock();
        let (attachment, chunks) = inner.attachments.get_mut(id).ok_or(ErrorKind::Other)?;
        chunks.entry(index).or_insert(data);
        attachment.uploaded |= crate::uploaded_bit(index);
        Ok(())
    }

    async fn chunk(&self, id: &AttachmentId, index: u32) -> Result<Option<Bytes>> {
        let inner = self.inner.lock();
        Ok(inner
            .attachments
            .get(id)
            .and_then(|(_, chunks)| chunks.get(&index).cloned()))
    }

    async fn delete_attachment(&self, id: &AttachmentId) -> Result<()> {
        self.inner.lock().attachments.remove(id);
        Ok(())
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
            crate::testing::attachment_store(&MemoryStore::default()).await;
        });
    }
}
