//! Cohesive runtime state sub-structs owned by [`super::Engine`].
//!
//! Each sub-struct encapsulates a single domain's interior-mutable runtime state with focused
//! helper methods and an explicit `clear_on_teardown` hook invoked synchronously by
//! [`super::Engine::teardown_on_pagehide`]. Keeping fine-grained `RefCell`/`Cell` fields inside
//! each sub-struct preserves exact re-entrancy and borrow lifetimes (especially across Leptos
//! signal writes and async boundaries).

use super::attachments::{ChunkSource, Fetching};
use super::contact::{Contact, DisplayedEntry};
use super::streaming::Stream;
use super::{
    AttachmentKey, CHUNKS_DECRYPTED_KEPT, ChunkOf, DecryptedChunk, Sending, StartChatError,
};
use crate::preview;
use crate::state::{
    Body, Delivery, Dialog, MessageRow, MessageView, PendingNewChat, SignInFlow,
    SignInSuccessAction, Ui,
};
use crate::util::monotonic_now_ms;
use crate::vault::HistoryEntry;
use futures_channel::oneshot;
use futures_util::lock::{Mutex, MutexGuard};
use leptos::prelude::*;
use session::PublicKey;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque, hash_map};
use std::rc::{Rc, Weak};

// ---------------------------------------------------------------------------
// 1. UploadRegistry
// ---------------------------------------------------------------------------

/// Cancelled promoted upload whose atomic local rollback transaction failed transiently
/// (`R11-P2-1`): blocks `Engine::flush` from announcing the cancelled pointer and lets `flush`
/// complete the atomic vault rollback + server `DeleteAttachment` once storage recovers.
#[derive(Clone)]
pub(super) struct PendingCancelRollback {
    pub(super) conversation_gen: u64,
    pub(super) pending: crate::vault::PendingUpload,
    pub(super) failed_entry: crate::vault::HistoryEntry,
}

/// Active attachment upload state: local plaintext file handles, in-flight upload task IDs, and
/// cancelled upload IDs.
#[derive(Default)]
pub(super) struct UploadRegistry {
    /// Files of uploads started or resumed on this page, keyed by `(peer, id, key_hash)`, which
    /// can continue without re-selecting the file.
    files: RefCell<HashMap<AttachmentKey, ChunkSource>>,
    /// Uploads currently running or being resumed.
    running: RefCell<HashSet<[u8; 16]>>,
    /// Uploads cancelled, or whose chat was deleted, on this page: running tasks stop before their
    /// next chunk and are never persisted to the vault again.
    cancelled: RefCell<HashSet<[u8; 16]>>,
    /// Promoted uploads cancelled after promotion whose rollback transaction failed transiently.
    pending_cancel_rollbacks: RefCell<HashMap<(PublicKey, u64), PendingCancelRollback>>,
    /// Cancellations requested on this page whose local vault settlement failed transiently
    /// (`R16-P2-9`), retried by `Engine::flush` and `Engine::sync` until committed.
    pending_cancellations: RefCell<HashSet<(PublicKey, [u8; 16])>>,
    /// Uploads whose final `PutChunk` succeeded on the server (`R20-P2-4`, `R21-P2-6`, `R21-P2-8`),
    /// keyed by attachment ID to its peer, so a subsequent local chunk-cache or `forget_upload`
    /// storage failure never causes `delete_inner` to cancel an already-complete attachment for
    /// the recipient, while `delete_inner` can still retain delete keys if explicitly cancelled.
    server_completed: RefCell<HashMap<[u8; 16], PublicKey>>,
    /// Attachments confirmed deleted/missing on the server whose local `HistoryEntry.gone = true`
    /// save failed transiently (`R20-P2-8`), keyed by `(peer, conversation_gen, id)`. Retried by
    /// `sync()` and excluded from unread requeue until durably persisted.
    pending_gone: RefCell<HashSet<(PublicKey, u64, [u8; 16])>>,
    /// Monotonic request/completion epochs for `restore_uploads_from_vault()` (`R16-P2-10`,
    /// `R20-P2-7`): incrementing `uploads_restore_epoch` while a restore pass is in flight prevents
    /// the older pass from overwriting a newer `run_upload` cleanup request with `false`.
    uploads_restore_epoch: Cell<u64>,
    uploads_restore_completed: Cell<u64>,
    /// Whether at least one `UPLOAD_STATE_WAITING` upload was parked for server sign-in and has
    /// not yet been retried after a subsequent origin auth proof (`R28-P2-2`).
    waiting_uploads_wait_sign_in: Cell<bool>,
    /// One-shot flag consumed by `Engine::sync()` / `start_waiting_uploads()` to promote waiting
    /// uploads once cross-tab sign-in is proven by an authenticated RPC (`R28-P2-2`).
    start_waiting_needed: Cell<bool>,
}

impl UploadRegistry {
    pub(super) fn insert_file(&self, key: AttachmentKey, file: ChunkSource) {
        self.files.borrow_mut().insert(key, file);
    }

    pub(super) fn get_file(&self, key: &AttachmentKey) -> Option<ChunkSource> {
        self.files.borrow().get(key).cloned()
    }

    pub(super) fn has_file(&self, peer: &PublicKey, id: &[u8; 16]) -> bool {
        self.files
            .borrow()
            .keys()
            .any(|(p, i, _)| p == peer && i == id)
    }

    pub(super) fn remove_attachment_files(&self, peer: &PublicKey, id: &[u8; 16]) {
        self.files
            .borrow_mut()
            .retain(|(p, i, _), _| !(p == peer && i == id));
    }

    pub(super) fn remove_peer_files(&self, peer: &PublicKey) {
        self.files.borrow_mut().retain(|(p, _, _), _| p != peer);
    }

    pub(super) fn is_running(&self, id: &[u8; 16]) -> bool {
        self.running.borrow().contains(id)
    }

    #[cfg(test)]
    pub(super) fn snapshot_running(&self) -> HashSet<[u8; 16]> {
        self.running.borrow().clone()
    }

    pub(super) fn start_running(&self, id: [u8; 16]) -> bool {
        self.running.borrow_mut().insert(id)
    }

    pub(super) fn stop_running(&self, id: &[u8; 16]) {
        self.running.borrow_mut().remove(id);
    }

    pub(super) fn is_cancelled(&self, id: &[u8; 16]) -> bool {
        self.cancelled.borrow().contains(id)
    }

    pub(super) fn mark_cancelled(&self, id: [u8; 16]) {
        self.cancelled.borrow_mut().insert(id);
    }

    pub(super) fn insert_pending_cancel_rollback(
        &self,
        key: (PublicKey, u64),
        rollback: PendingCancelRollback,
    ) {
        self.pending_cancel_rollbacks
            .borrow_mut()
            .insert(key, rollback);
    }

    pub(super) fn get_pending_cancel_rollback(
        &self,
        peer: &PublicKey,
        history_index: u64,
    ) -> Option<PendingCancelRollback> {
        self.pending_cancel_rollbacks
            .borrow()
            .get(&(*peer, history_index))
            .cloned()
    }

    pub(super) fn remove_pending_cancel_rollback(&self, peer: &PublicKey, history_index: u64) {
        self.pending_cancel_rollbacks
            .borrow_mut()
            .remove(&(*peer, history_index));
    }

    pub(super) fn remove_peer_cancel_rollbacks(&self, peer: &PublicKey) {
        self.pending_cancel_rollbacks
            .borrow_mut()
            .retain(|(p, _), _| p != peer);
    }

    pub(super) fn pending_cancel_rollbacks_for_peer(
        &self,
        peer: &PublicKey,
    ) -> Vec<PendingCancelRollback> {
        self.pending_cancel_rollbacks
            .borrow()
            .iter()
            .filter(|((p, _), _)| p == peer)
            .map(|(_, rb)| rb.clone())
            .collect()
    }

    pub(super) fn insert_pending_cancel(&self, peer: PublicKey, id: [u8; 16]) {
        self.pending_cancellations.borrow_mut().insert((peer, id));
    }

    pub(super) fn remove_pending_cancel(&self, peer: &PublicKey, id: &[u8; 16]) {
        self.pending_cancellations
            .borrow_mut()
            .remove(&(*peer, *id));
    }

    pub(super) fn remove_peer_pending_cancels(&self, peer: &PublicKey) {
        self.pending_cancellations
            .borrow_mut()
            .retain(|(p, _)| p != peer);
    }

    pub(super) fn pending_cancels_for_peer(&self, peer: &PublicKey) -> Vec<[u8; 16]> {
        self.pending_cancellations
            .borrow()
            .iter()
            .filter_map(|(p, id)| (p == peer).then_some(*id))
            .collect()
    }

    pub(super) fn pending_cancels(&self) -> Vec<(PublicKey, [u8; 16])> {
        self.pending_cancellations
            .borrow()
            .iter()
            .copied()
            .collect()
    }

    pub(super) fn mark_server_completed(&self, peer: PublicKey, id: [u8; 16]) {
        self.server_completed.borrow_mut().insert(id, peer);
    }

    pub(super) fn is_server_completed(&self, id: &[u8; 16]) -> bool {
        self.server_completed.borrow().contains_key(id)
    }

    pub(super) fn clear_server_completed(&self, id: &[u8; 16]) {
        self.server_completed.borrow_mut().remove(id);
    }

    pub(super) fn server_completed_for_peer(&self, peer: &PublicKey) -> Vec<[u8; 16]> {
        self.server_completed
            .borrow()
            .iter()
            .filter_map(|(id, p)| (p == peer).then_some(*id))
            .collect()
    }

    pub(super) fn insert_pending_gone(&self, peer: PublicKey, conv_gen: u64, id: [u8; 16]) {
        self.pending_gone.borrow_mut().insert((peer, conv_gen, id));
    }

    pub(super) fn remove_pending_gone(&self, peer: &PublicKey, conv_gen: u64, id: &[u8; 16]) {
        self.pending_gone
            .borrow_mut()
            .remove(&(*peer, conv_gen, *id));
    }

    pub(super) fn remove_peer_pending_gone(&self, peer: &PublicKey) {
        self.pending_gone.borrow_mut().retain(|(p, _, _)| p != peer);
    }

    pub(super) fn pending_gone(&self) -> Vec<(PublicKey, u64, [u8; 16])> {
        self.pending_gone.borrow().iter().copied().collect()
    }

    pub(super) fn pending_gone_ids_for_peer(
        &self,
        peer: &PublicKey,
        conv_gen: u64,
    ) -> HashSet<[u8; 16]> {
        self.pending_gone
            .borrow()
            .iter()
            .filter_map(|(p, g, id)| (p == peer && *g == conv_gen).then_some(*id))
            .collect()
    }

    pub(super) fn set_restore_needed(&self, needed: bool) {
        if needed {
            let next = self.uploads_restore_epoch.get().wrapping_add(1);
            self.uploads_restore_epoch.set(next);
            if next == self.uploads_restore_completed.get() {
                self.uploads_restore_epoch.set(next.wrapping_add(1));
            }
        } else {
            self.uploads_restore_completed
                .set(self.uploads_restore_epoch.get());
        }
    }

    pub(super) fn restore_epoch(&self) -> u64 {
        self.uploads_restore_epoch.get()
    }

    pub(super) fn finish_restore(&self, started_epoch: u64, incomplete: bool) {
        if !incomplete && self.uploads_restore_epoch.get() == started_epoch {
            self.uploads_restore_completed.set(started_epoch);
        }
    }

    pub(super) fn restore_needed(&self) -> bool {
        self.uploads_restore_completed.get() != self.uploads_restore_epoch.get()
    }

    pub(super) fn waiting_uploads_wait_sign_in(&self) -> bool {
        self.waiting_uploads_wait_sign_in.get()
    }

    pub(super) fn set_waiting_uploads_wait_sign_in(&self, waits: bool) -> bool {
        self.waiting_uploads_wait_sign_in.replace(waits)
    }

    pub(super) fn mark_start_waiting_needed(&self) {
        self.start_waiting_needed.set(true);
    }

    pub(super) fn start_waiting_needed(&self) -> bool {
        self.start_waiting_needed.get()
    }

    pub(super) fn take_start_waiting_needed(&self) -> bool {
        self.start_waiting_needed.replace(false)
    }

    pub(super) fn clear_on_teardown(&self) {
        self.files.borrow_mut().clear();
        self.running.borrow_mut().clear();
        self.cancelled.borrow_mut().clear();
        self.pending_cancel_rollbacks.borrow_mut().clear();
        self.pending_cancellations.borrow_mut().clear();
        self.server_completed.borrow_mut().clear();
        self.pending_gone.borrow_mut().clear();
        self.uploads_restore_epoch.set(0);
        self.uploads_restore_completed.set(0);
        self.waiting_uploads_wait_sign_in.set(false);
        self.start_waiting_needed.set(false);
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(super) fn file_peers(&self) -> Vec<PublicKey> {
        self.files.borrow().keys().map(|(p, _, _)| *p).collect()
    }
}

// ---------------------------------------------------------------------------
// 2. MediaStreams
// ---------------------------------------------------------------------------

/// Active service-worker media streams, bounded LRU plaintext chunk cache (zeroized on eviction or
/// drop), and single-flight chunk download waiters.
#[derive(Default)]
pub(super) struct MediaStreams {
    /// Attachments playing as they are fetched, keyed by their `/media/<token>` URL token.
    streams: RefCell<HashMap<String, Stream>>,
    /// Recently decrypted stream chunks, keyed by `(peer, id, key_hash, index)`, oldest first;
    /// shared only across streams with matching peer, attachment ID, and key; zeroized on drop.
    decrypted: RefCell<VecDeque<(ChunkOf, DecryptedChunk)>>,
    /// Chunks currently being fetched by a stream, with waiters notified once loading finishes.
    loading: RefCell<HashMap<ChunkOf, Vec<oneshot::Sender<()>>>>,
}

impl MediaStreams {
    pub(super) fn insert_stream(&self, token: String, stream: Stream) {
        self.streams.borrow_mut().insert(token, stream);
    }

    pub(super) fn remove_stream(&self, token: &str) {
        self.streams.borrow_mut().remove(token);
    }

    pub(super) fn contains_stream(&self, token: &str) -> bool {
        self.streams.borrow().contains_key(token)
    }

    pub(super) fn stream_size(&self, token: &str) -> Option<u64> {
        self.streams
            .borrow()
            .get(token)
            .map(|stream| stream.fetching.size)
    }

    pub(super) fn stream_mime(&self, token: &str) -> Option<String> {
        self.streams
            .borrow()
            .get(token)
            .map(|stream| stream.mime.clone())
    }

    pub(super) fn stream_fetching_and_clock(&self, token: &str) -> Option<(Rc<Fetching>, u64)> {
        self.streams
            .borrow()
            .get(token)
            .map(|stream| (stream.fetching.clone(), stream.clock))
    }

    /// Update the stream's served MIME type from chunk 0's magic bytes (strictly `video/*` or
    /// `audio/*`, as streams are served from the page's origin).
    pub(super) fn sniff_stream_mime(&self, token: &str, fetching: &Fetching, chunk: &[u8]) {
        if let Some(stream) = self.streams.borrow_mut().get_mut(token)
            && let Some(mime) = preview::media_mime(&fetching.name, &stream.mime, chunk)
                .filter(|mime| mime.starts_with("video/") || mime.starts_with("audio/"))
        {
            stream.mime = mime.to_string();
        }
    }

    /// Look up `chunk_of` in the decrypted LRU cache, promoting it to most-recently-used on hit.
    pub(super) fn get_decrypted(&self, chunk_of: &ChunkOf) -> Option<DecryptedChunk> {
        let mut decrypted = self.decrypted.borrow_mut();
        let at = decrypted.iter().position(|(of, _)| of == chunk_of)?;
        let kept = decrypted.remove(at)?;
        let chunk = kept.1.clone();
        decrypted.push_back(kept);
        Some(chunk)
    }

    /// Cache a newly decrypted chunk, evicting the oldest entry if the cache exceeds
    /// [`CHUNKS_DECRYPTED_KEPT`].
    pub(super) fn cache_decrypted(&self, chunk_of: ChunkOf, chunk: DecryptedChunk) {
        let mut decrypted = self.decrypted.borrow_mut();
        decrypted.push_back((chunk_of, chunk));
        if decrypted.len() > CHUNKS_DECRYPTED_KEPT {
            decrypted.pop_front();
        }
    }

    /// Claim single-flight ownership for loading `chunk_of` (returning `None`), or attach a waiter
    /// to an in-flight load (returning `Some(receiver)`).
    pub(super) fn begin_or_wait_loading(&self, chunk_of: ChunkOf) -> Option<oneshot::Receiver<()>> {
        match self.loading.borrow_mut().entry(chunk_of) {
            hash_map::Entry::Occupied(mut waiters) => {
                let (done, waiting) = oneshot::channel();
                waiters.get_mut().push(done);
                Some(waiting)
            }
            hash_map::Entry::Vacant(vacant) => {
                vacant.insert(vec![]);
                None
            }
        }
    }

    /// Finish a single-flight chunk load and wake all waiters by dropping their oneshot senders.
    pub(super) fn finish_loading(&self, chunk_of: &ChunkOf) {
        self.loading.borrow_mut().remove(chunk_of);
    }

    pub(super) fn remove_attachment_chunks(&self, peer: &PublicKey, id: &[u8; 16]) {
        self.decrypted
            .borrow_mut()
            .retain(|((p, i, _, _), _)| !(p == peer && i == id));
    }

    pub(super) fn remove_peer(&self, peer: &PublicKey) {
        self.decrypted
            .borrow_mut()
            .retain(|((p, _, _, _), _)| p != peer);
        self.streams
            .borrow_mut()
            .retain(|_, stream| stream.fetching.peer != *peer);
    }

    pub(super) fn clear_on_teardown(&self) {
        self.streams.borrow_mut().clear();
        self.decrypted.borrow_mut().clear();
        self.loading.borrow_mut().clear();
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(super) fn clear_decrypted_cache(&self) {
        self.decrypted.borrow_mut().clear();
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(super) fn stream_fetching(&self, token: &str) -> Option<Rc<Fetching>> {
        self.streams
            .borrow()
            .get(token)
            .map(|stream| stream.fetching.clone())
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(super) fn decrypted_peers(&self) -> Vec<PublicKey> {
        self.decrypted
            .borrow()
            .iter()
            .map(|((p, _, _, _), _)| *p)
            .collect()
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(super) fn stream_peers(&self) -> Vec<PublicKey> {
        self.streams
            .borrow()
            .values()
            .map(|stream| stream.fetching.peer)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// 3. SendQueue
// ---------------------------------------------------------------------------

/// RAII handle to a per-peer outbox flush mutex stored as a [`Weak`] entry in [`SendQueue`].
///
/// Guarantees that the caller's [`Rc<Mutex<()>>`] is dropped *before* pruning the map entry so
/// `strong_count() == 0` holds strictly once the last active or queued flush for `peer` exits,
/// preserving PR 29.3's delete+recreate serialization invariant.
pub(super) struct PeerFlushLock<'a> {
    queue: &'a SendQueue,
    peer: PublicKey,
    lock: Option<Rc<Mutex<()>>>,
}

impl PeerFlushLock<'_> {
    pub(super) async fn lock(&self) -> MutexGuard<'_, ()> {
        self.lock
            .as_ref()
            .expect("PeerFlushLock held until Drop")
            .lock()
            .await
    }
}

impl Drop for PeerFlushLock<'_> {
    fn drop(&mut self) {
        // Release our `Rc<Mutex<()>>` BEFORE checking `strong_count() == 0` so the entry is pruned
        // immediately when this was the last holder, while concurrent waiters keep it alive.
        drop(self.lock.take());
        self.queue.prune_peer_flush_lock(&self.peer);
    }
}

/// Outbox send queue, sync wake flag, per-peer sign-in holds, approval backoff, and per-peer
/// `Weak<Mutex<()>>` flush serialization locks.
#[derive(Default)]
pub(super) struct SendQueue {
    /// Queued outgoing messages/files awaiting ordered transmission.
    sending: RefCell<VecDeque<Sending>>,
    /// Whether a drain task is currently consuming `sending`.
    draining: Cell<bool>,
    /// Sync now, e.g. after sending, as a reply may follow.
    wake: Cell<bool>,
    /// Chats whose next message waits for this browser to sign in to the server.
    waits_sign_in: RefCell<HashSet<PublicKey>>,
    /// Per-peer exponential backoff after `WriteTokenRejected` while awaiting peer approval:
    /// maps `peer -> (next_try_monotonic_ms, current_delay_ms)`.
    approval_backoff: RefCell<HashMap<PublicKey, (u64, u64)>>,
    /// Per-peer exponential backoff for empty-outbox `CONFIRMED`-greeting manifest SPK-rotation
    /// probes so polling stays bounded without delaying outbound `flush()` when the user writes.
    confirmed_probe_backoff: RefCell<HashMap<PublicKey, (u64, u64)>>,
    /// Per-peer serialization mutexes for outbox flushes (`ClaimBundle`, `RegisterWriteToken`,
    /// `SendInitialV2`, `PushV2`, `push_events`), stored as `Weak` handles so an in-flight flush's
    /// mutex remains uniquely shared across concurrent delete+recreate cycles and is pruned cleanly
    /// once the last holder drops.
    peer_flush_locks: RefCell<HashMap<PublicKey, Weak<Mutex<()>>>>,
}

impl SendQueue {
    /// Push `item` onto the FIFO send queue and return `true` if the caller must spawn a drain
    /// task (transitions `draining` from `false` -> `true`).
    pub(super) fn enqueue(&self, item: Sending) -> bool {
        self.sending.borrow_mut().push_back(item);
        !self.draining.replace(true)
    }

    pub(super) fn pop_front(&self) -> Option<Sending> {
        self.sending.borrow_mut().pop_front()
    }

    pub(super) fn finish_draining(&self) {
        self.draining.set(false);
    }

    pub(super) fn purge_peer_sending(&self, peer: &PublicKey) {
        self.sending
            .borrow_mut()
            .retain(|item| item.peer() != *peer);
    }

    pub(super) fn request_wake(&self) {
        self.wake.set(true);
    }

    pub(super) fn take_wake(&self) -> bool {
        self.wake.replace(false)
    }

    pub(super) fn waits_for_sign_in(&self, peer: &PublicKey) -> bool {
        self.waits_sign_in.borrow().contains(peer)
    }

    pub(super) fn mark_waits_sign_in(&self, peer: PublicKey) {
        self.waits_sign_in.borrow_mut().insert(peer);
    }

    pub(super) fn clear_peer_sign_in_wait(&self, peer: &PublicKey) {
        self.waits_sign_in.borrow_mut().remove(peer);
    }

    pub(super) fn has_any_sign_in_wait(&self) -> bool {
        !self.waits_sign_in.borrow().is_empty()
    }

    pub(super) fn clear_all_sign_in_waits(&self) -> bool {
        let mut set = self.waits_sign_in.borrow_mut();
        let had_any = !set.is_empty();
        set.clear();
        had_any
    }

    /// Return an RAII handle to the per-peer serialization mutex for `peer`'s outbox flush,
    /// upgrading any live `Weak` entry so concurrent delete+recreate cycles strictly serialize
    /// behind an in-flight flush. Always acquired BEFORE `Engine::lock_inner()`.
    pub(super) fn peer_flush_lock(&self, peer: &PublicKey) -> PeerFlushLock<'_> {
        let mut map = self.peer_flush_locks.borrow_mut();
        let lock = if let Some(existing) = map.get(peer).and_then(Weak::upgrade) {
            existing
        } else {
            let lock = Rc::new(Mutex::new(()));
            map.insert(*peer, Rc::downgrade(&lock));
            lock
        };
        PeerFlushLock {
            queue: self,
            peer: *peer,
            lock: Some(lock),
        }
    }

    /// Remove `peer`'s entry from `peer_flush_locks` only once no active or queued flush holds an
    /// `Rc` to that mutex (`strong_count() == 0`).
    pub(super) fn prune_peer_flush_lock(&self, peer: &PublicKey) {
        let mut map = self.peer_flush_locks.borrow_mut();
        if map.get(peer).is_some_and(|weak| weak.strong_count() == 0) {
            map.remove(peer);
        }
    }

    pub(super) fn clear_approval_backoff(&self, peer: &PublicKey) {
        self.approval_backoff.borrow_mut().remove(peer);
        self.confirmed_probe_backoff.borrow_mut().remove(peer);
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(super) fn clear_approval_backoff_only(&self, peer: &PublicKey) {
        self.approval_backoff.borrow_mut().remove(peer);
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(super) fn clear_confirmed_probe_backoff(&self, peer: &PublicKey) {
        self.confirmed_probe_backoff.borrow_mut().remove(peer);
    }

    pub(super) fn clear_all_approval_backoffs(&self) {
        self.approval_backoff.borrow_mut().clear();
        self.confirmed_probe_backoff.borrow_mut().clear();
    }

    pub(super) fn has_approval_backoff(&self, peer: &PublicKey) -> bool {
        self.approval_backoff.borrow().contains_key(peer)
    }

    pub(super) fn is_approval_backed_off(&self, peer: &PublicKey) -> bool {
        self.approval_backoff
            .borrow()
            .get(peer)
            .is_some_and(|&(next_try, _)| monotonic_now_ms() < next_try)
    }

    /// Record or advance per-peer approval backoff (`15s -> 30s -> 60s -> 5m`).
    pub(super) fn record_approval_backoff(&self, peer: &PublicKey) -> u64 {
        let mut map = self.approval_backoff.borrow_mut();
        let delay = match map.get(peer).map(|&(_, prev)| prev) {
            None => 15_000,
            Some(15_000) => 30_000,
            Some(30_000) => 60_000,
            Some(_) => 300_000,
        };
        map.insert(*peer, (monotonic_now_ms().saturating_add(delay), delay));
        delay
    }

    pub(super) fn is_confirmed_probe_backed_off(&self, peer: &PublicKey) -> bool {
        self.confirmed_probe_backoff
            .borrow()
            .get(peer)
            .is_some_and(|&(next_try, _)| monotonic_now_ms() < next_try)
    }

    /// Record or advance per-peer backoff for empty-outbox `CONFIRMED` greeting SPK-rotation
    /// probes (`15s -> 30s -> 60s -> 5m`) independently of `approval_backoff`.
    pub(super) fn record_confirmed_probe_backoff(&self, peer: &PublicKey) -> u64 {
        let mut map = self.confirmed_probe_backoff.borrow_mut();
        let delay = match map.get(peer).map(|&(_, prev)| prev) {
            None => 15_000,
            Some(15_000) => 30_000,
            Some(30_000) => 60_000,
            Some(_) => 300_000,
        };
        map.insert(*peer, (monotonic_now_ms().saturating_add(delay), delay));
        delay
    }

    pub(super) fn clear_on_teardown(&self) {
        self.wake.set(false);
        self.sending.borrow_mut().clear();
        self.waits_sign_in.borrow_mut().clear();
        self.approval_backoff.borrow_mut().clear();
        self.confirmed_probe_backoff.borrow_mut().clear();
        self.peer_flush_locks.borrow_mut().clear();
    }

    #[cfg(test)]
    pub(super) fn push_sending(&self, item: Sending) {
        self.sending.borrow_mut().push_back(item);
    }

    #[cfg(test)]
    pub(super) fn sending_peers(&self) -> Vec<PublicKey> {
        self.sending.borrow().iter().map(Sending::peer).collect()
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(super) fn peer_flush_lock_strong_count(&self, peer: &PublicKey) -> Option<usize> {
        self.peer_flush_locks
            .borrow()
            .get(peer)
            .map(Weak::strong_count)
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(super) fn has_peer_flush_lock(&self, peer: &PublicKey) -> bool {
        self.peer_flush_locks.borrow().contains_key(peer)
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(super) fn peer_flush_locks_is_empty(&self) -> bool {
        self.peer_flush_locks.borrow().is_empty()
    }
}

// ---------------------------------------------------------------------------
// 4. StartupFlow
// ---------------------------------------------------------------------------

/// RAII guard for single-unlock / single-create re-entrancy protection in [`StartupFlow`].
pub(super) struct UnlockGuard<'a> {
    startup: &'a StartupFlow,
}

impl Drop for UnlockGuard<'_> {
    fn drop(&mut self) {
        self.startup.unlocking.set(false);
    }
}

/// Startup, authentication, `NewChat`/`SignIn` submission cancellation, prekey publish-wait flags,
/// and clock-skew warning state.
#[derive(Default)]
pub(super) struct StartupFlow {
    /// Single-unlock / single-create re-entrancy guard preventing overlapping unlocks or
    /// duplicate sync/notification/service-worker loops.
    unlocking: Cell<bool>,
    /// Whether this page can sign in to the unlocked vault's server (same origin).
    can_sign_in_here: Cell<bool>,
    /// Coordinates sign-in dialogs with invitation / `NewChat` drafts so signing in or dismissing
    /// never discards a parsed invitation or user edits.
    sign_in_flow: RefCell<SignInFlow>,
    /// Actionable feedback (e.g. classical fallback prompt or error) to display when `NewChat`
    /// reopens after an automatic post-sign-in `start_chat` attempt needs user attention.
    new_chat_feedback: RefCell<Option<StartChatError>>,
    /// Submission ID of a `start_chat` call currently awaiting network RPCs, together with whether
    /// the chat has already been persisted (`greeting_only == true`), used to suppress late
    /// transport 403 sign-in prompts for discarded submissions and prevent greeting-only 403s from
    /// re-attaching an auto-start draft.
    in_flight_start_chat: Cell<Option<(u64, bool)>>,
    /// Startup submission IDs with active async tasks, reference-counted so overlapping `NewChat`
    /// and `SignInDialog` tasks sharing an ID keep cancellation live until the last task finishes.
    live_submissions: RefCell<HashMap<u64, usize>>,
    /// Live startup submission IDs cancelled by browser Back or native dialog dismissal.
    cancelled_submissions: RefCell<HashSet<u64>>,
    /// Whether publishing prekeys was refused for sign-in: waits for sign-in rather than retrying
    /// every sync round.
    publish_waits_sign_in: Cell<bool>,
    /// Whether pushing queued deletion farewells was refused for sign-in: waits for sign-in rather
    /// than hitting `403 SignInRequired` on every background `sync()` round (`R25-P3-2`).
    farewells_wait_sign_in: Cell<bool>,
    /// Whether publishing prekeys was definitively refused for the current settings with no
    /// rollback snapshot: background publishing pauses until the user adjusts settings or retries.
    publish_waits_settings: Cell<bool>,
    /// Whether a clock-skew warning has already been surfaced during the current drift episode.
    clock_skew_warned: Cell<bool>,
    /// Verified signed `PQ-OFF` manifest `(seq, digest)` observed during a New Chat attempt for
    /// `peer` (`R20-P2-2`), retained monotonically across the `"Allow classical"` consent dialog
    /// so the follow-up `ClaimBundle` rejects rolled-back or equivocating manifests.
    pending_new_chat_off_pins: RefCell<HashMap<PublicKey, (u64, [u8; 32])>>,
}

impl StartupFlow {
    /// Acquire the single-unlock / single-create guard, returning `None` if already opening.
    pub(super) fn try_begin_unlock(&self) -> Option<UnlockGuard<'_>> {
        if self.unlocking.replace(true) {
            None
        } else {
            Some(UnlockGuard { startup: self })
        }
    }

    pub(super) fn can_sign_in_here(&self) -> bool {
        self.can_sign_in_here.get()
    }

    pub(super) fn set_can_sign_in_here(&self, value: bool) {
        self.can_sign_in_here.set(value);
    }

    pub(super) fn publish_waits_settings(&self) -> bool {
        self.publish_waits_settings.get()
    }

    pub(super) fn publish_waits_sign_in(&self) -> bool {
        self.publish_waits_sign_in.get()
    }

    pub(super) fn set_publish_waits_sign_in(&self, waits: bool) -> bool {
        self.publish_waits_sign_in.replace(waits)
    }

    pub(super) fn farewells_wait_sign_in(&self) -> bool {
        self.farewells_wait_sign_in.get()
    }

    pub(super) fn set_farewells_wait_sign_in(&self, waits: bool) -> bool {
        self.farewells_wait_sign_in.replace(waits)
    }

    pub(super) fn reset_declined(&self) {
        self.sign_in_flow.borrow_mut().reset_declined();
    }

    pub(super) fn set_publish_waits_settings(&self, waits: bool) {
        self.publish_waits_settings.set(waits);
    }

    pub(super) fn is_publish_paused(&self) -> bool {
        self.publish_waits_sign_in.get() || self.publish_waits_settings.get()
    }

    pub(super) fn on_publish_succeeded(&self) {
        self.publish_waits_sign_in.set(false);
        self.publish_waits_settings.set(false);
    }

    /// Mark that a clock-skew warning is being shown, returning `true` only on the first call of
    /// the current drift episode.
    pub(super) fn mark_clock_skew_warned(&self) -> bool {
        !self.clock_skew_warned.replace(true)
    }

    pub(super) fn clear_clock_skew_warned(&self) {
        self.clock_skew_warned.set(false);
    }

    pub(super) fn on_resume_after_sign_in(&self) {
        self.sign_in_flow.borrow_mut().reset_declined();
        self.publish_waits_sign_in.set(false);
        self.farewells_wait_sign_in.set(false);
    }

    pub(super) fn on_ask_sign_in(&self, current_dialog: Option<&Dialog>) -> Option<Dialog> {
        // R25-P2-3: When a persisted `start_chat` / existing-contact acceptance flush hits
        // `SignInRequired` while `Dialog::NewChat` is still mounted, route directly through
        // `on_chat_created_greeting_needs_sign_in` instead of letting `SignInFlow::on_ask_sign_in`
        // mint a fresh orphan `pending_new_chat` ID from `active_new_chat`.
        if let Some((id, true)) = self.in_flight_start_chat.get()
            && !self.is_submission_cancelled(id)
        {
            return self.can_sign_in_here.get().then(|| {
                self.sign_in_flow
                    .borrow_mut()
                    .on_chat_created_greeting_needs_sign_in(id)
            });
        }
        self.sign_in_flow.borrow_mut().on_ask_sign_in(
            current_dialog,
            self.can_sign_in_here.get(),
            false,
        )
    }

    /// Background sign-in prompt (`R24-P1-1`, `R24-P2-4`, `R25-P2-2`): honors `declined_sign_in`
    /// ("Not now" / Escape) and skips whenever an unrelated active (non-cancelled) `start_chat`
    /// submission is currently in flight so background sync/publish/refill/farewell/auto-upgrade
    /// 403s never hijack or cancel it.
    pub(super) fn on_ask_sign_in_background(
        &self,
        current_dialog: Option<&Dialog>,
    ) -> Option<Dialog> {
        if self
            .in_flight_start_chat
            .get()
            .is_some_and(|(id, _)| !self.is_submission_cancelled(id))
        {
            return None;
        }
        self.sign_in_flow.borrow_mut().on_ask_sign_in(
            current_dialog,
            self.can_sign_in_here.get(),
            true,
        )
    }

    pub(super) fn on_refused_for_sign_in(&self, current_dialog: Option<&Dialog>) -> Option<Dialog> {
        if let Some((id, greeting_only)) = self.in_flight_start_chat.get() {
            if self.is_submission_cancelled(id) {
                return None;
            }
            if greeting_only {
                return self.can_sign_in_here.get().then(|| {
                    self.sign_in_flow
                        .borrow_mut()
                        .on_chat_created_greeting_needs_sign_in(id)
                });
            }
        }
        self.sign_in_flow.borrow_mut().on_ask_sign_in(
            current_dialog,
            self.can_sign_in_here.get(),
            true,
        )
    }

    fn mark_submission_cancelled(&self, submission_id: u64) {
        if self.live_submissions.borrow().contains_key(&submission_id) {
            self.cancelled_submissions
                .borrow_mut()
                .insert(submission_id);
        }
    }

    pub(super) fn decline_background_prompts(&self) {
        self.sign_in_flow.borrow_mut().decline_background_prompts();
    }

    pub(super) fn dismiss_sign_in(&self) -> Option<Dialog> {
        let (cancelled_id, restored) = self.sign_in_flow.borrow_mut().on_dismiss_sign_in();
        if let Some(id) = cancelled_id {
            self.mark_submission_cancelled(id);
        }
        restored
    }

    pub(super) fn new_chat_mounted(
        &self,
        key: String,
        name: String,
        server: Option<String>,
        pq_pinned: bool,
    ) {
        self.sign_in_flow
            .borrow_mut()
            .on_new_chat_mounted(key, name, server, pq_pinned);
    }

    pub(super) fn new_chat_edited(
        &self,
        key: String,
        name: String,
        server: Option<String>,
        pq_pinned: bool,
    ) {
        self.sign_in_flow
            .borrow_mut()
            .on_new_chat_edited(key, name, server, pq_pinned);
    }

    pub(super) fn new_chat_unmounted(&self) {
        self.sign_in_flow.borrow_mut().on_new_chat_unmounted();
    }

    pub(super) fn begin_new_chat_submit(&self, draft: PendingNewChat) -> u64 {
        let id = self.sign_in_flow.borrow_mut().begin_new_chat_submit(draft);
        *self.live_submissions.borrow_mut().entry(id).or_insert(0) += 1;
        id
    }

    pub(super) fn begin_sign_in_auto_start(&self, submission_id: u64) {
        *self
            .live_submissions
            .borrow_mut()
            .entry(submission_id)
            .or_insert(0) += 1;
    }

    pub(super) fn finish_submission(&self, submission_id: u64) {
        let mut live = self.live_submissions.borrow_mut();
        if let Some(count) = live.get_mut(&submission_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                live.remove(&submission_id);
                self.cancelled_submissions
                    .borrow_mut()
                    .remove(&submission_id);
            }
        } else {
            self.cancelled_submissions
                .borrow_mut()
                .remove(&submission_id);
        }
        self.sign_in_flow
            .borrow_mut()
            .end_new_chat_submit(submission_id);
    }

    pub(super) fn cancel_submission(&self, submission_id: u64) {
        self.mark_submission_cancelled(submission_id);
        self.sign_in_flow
            .borrow_mut()
            .cancel_submission(submission_id);
    }

    pub(super) fn cancel_active_submissions(&self) {
        let cancelled = self.sign_in_flow.borrow_mut().cancel_active_submissions();
        for id in cancelled {
            self.mark_submission_cancelled(id);
        }
        if let Some((id, _)) = self.in_flight_start_chat.get() {
            self.mark_submission_cancelled(id);
        }
    }

    pub(super) fn is_submission_cancelled(&self, submission_id: u64) -> bool {
        self.cancelled_submissions.borrow().contains(&submission_id)
    }

    pub(super) fn clear_pending_new_chat(&self, submission_id: u64) {
        self.sign_in_flow
            .borrow_mut()
            .cancel_submission(submission_id);
    }

    pub(super) fn end_new_chat_submit(&self, submission_id: u64) {
        self.sign_in_flow
            .borrow_mut()
            .end_new_chat_submit(submission_id);
    }

    pub(super) fn on_chat_created_greeting_needs_sign_in(&self, submission_id: u64) -> Dialog {
        self.sign_in_flow
            .borrow_mut()
            .on_chat_created_greeting_needs_sign_in(submission_id)
    }

    pub(super) fn require_sign_in_for_new_chat(
        &self,
        submission_id: u64,
        draft: PendingNewChat,
    ) -> Dialog {
        self.sign_in_flow
            .borrow_mut()
            .on_start_chat_sign_in_required(submission_id, draft)
    }

    pub(super) fn pending_new_chat_hint(&self) -> Option<(bool, bool)> {
        self.sign_in_flow.borrow().pending_new_chat_hint()
    }

    pub(super) fn pending_auto_start_id(&self) -> Option<u64> {
        self.sign_in_flow.borrow().pending_auto_start_id()
    }

    pub(super) fn complete_sign_in_flow(&self) -> SignInSuccessAction {
        self.sign_in_flow.borrow_mut().on_sign_in_succeeded()
    }

    pub(super) fn finish_auto_start_chat(
        &self,
        submission_id: u64,
        err: Option<StartChatError>,
    ) -> (bool, Option<Dialog>) {
        let (succeeded, still_needs_sign_in) = match &err {
            None => (true, false),
            Some(StartChatError::SignInRequired) => (false, true),
            Some(_) => (false, false),
        };
        let (close_sign_in, reopened) = self.sign_in_flow.borrow_mut().on_auto_start_finished(
            submission_id,
            succeeded,
            still_needs_sign_in,
        );
        if !close_sign_in && reopened.is_some() {
            *self.new_chat_feedback.borrow_mut() = err;
        }
        (close_sign_in, reopened)
    }

    pub(super) fn take_new_chat_feedback(&self) -> Option<StartChatError> {
        self.new_chat_feedback.borrow_mut().take()
    }

    pub(super) fn on_unlock_with_invitation(
        &self,
        dialog: Dialog,
        can_sign_in_here: bool,
        signed_in: Option<bool>,
    ) -> Dialog {
        self.sign_in_flow.borrow_mut().on_unlock_with_invitation(
            dialog,
            can_sign_in_here,
            signed_in,
        )
    }

    pub(super) fn set_in_flight_start_chat(&self, submission_id: u64, greeting_only: bool) {
        self.in_flight_start_chat
            .set(Some((submission_id, greeting_only)));
    }

    pub(super) fn clear_in_flight_start_chat(&self, submission_id: u64) {
        if self
            .in_flight_start_chat
            .get()
            .is_some_and(|(id, _)| id == submission_id)
        {
            self.in_flight_start_chat.set(None);
        }
    }

    /// Record a verified signed `PQ-OFF` manifest `(seq, digest)` observed during New Chat
    /// (`R20-P2-2`). Rejects rollbacks (`seq < prev`) or equivocation (`seq == prev && digest !=
    /// prev`) with `Err(())` without mutating stored state.
    pub(super) fn record_new_chat_signed_pq_off(
        &self,
        peer: PublicKey,
        seq: u64,
        digest: [u8; 32],
    ) -> Result<(), ()> {
        if seq == 0 {
            return Err(());
        }
        let mut pins = self.pending_new_chat_off_pins.borrow_mut();
        if let Some(&(prev_seq, prev_digest)) = pins.get(&peer)
            && (seq < prev_seq || (seq == prev_seq && digest != prev_digest))
        {
            return Err(());
        }
        pins.insert(peer, (seq, digest));
        Ok(())
    }

    pub(super) fn new_chat_signed_pq_off(&self, peer: &PublicKey) -> Option<(u64, [u8; 32])> {
        self.pending_new_chat_off_pins.borrow().get(peer).copied()
    }

    pub(super) fn clear_new_chat_signed_pq_off(&self, peer: &PublicKey) {
        self.pending_new_chat_off_pins.borrow_mut().remove(peer);
    }

    pub(super) fn clear_on_teardown(&self) {
        self.unlocking.set(false);
        self.publish_waits_sign_in.set(false);
        self.farewells_wait_sign_in.set(false);
        self.publish_waits_settings.set(false);
        self.clock_skew_warned.set(false);
        *self.new_chat_feedback.borrow_mut() = None;
        self.pending_new_chat_off_pins.borrow_mut().clear();
        self.cancel_active_submissions();
        // R25-P2-2: Drop any stale `in_flight_start_chat` from a locked/torn-down vault generation
        // so it cannot suppress `on_ask_sign_in_background` after a new vault unlocks.
        self.in_flight_start_chat.set(None);
    }
}

// ---------------------------------------------------------------------------
// 5. OpenChatState
// ---------------------------------------------------------------------------

/// Per-row reactive signal handles owned by the currently rendered chat.
#[derive(Debug, Clone, Copy)]
struct RowSignals {
    place: u64,
    delivery: Option<RwSignal<Delivery>>,
    remote_body: Option<RwSignal<Body>>,
}

impl RowSignals {
    fn from_row(row: &MessageRow) -> Self {
        Self {
            place: row.place,
            delivery: row.delivery_signal,
            remote_body: row.remote_body_signal,
        }
    }

    fn dispose(self) {
        if let Some(signal) = self.delivery {
            signal.dispose();
        }
        if let Some(signal) = self.remote_body {
            signal.dispose();
        }
    }
}

/// Index map of rendered message rows for the active chat.
#[derive(Default)]
struct DisplayedRows {
    peer: Option<PublicKey>,
    rows: HashMap<u64, RowSignals>,
}

/// Tracks what is currently displayed in `ui.messages` for an open chat so read acknowledgments
/// are idempotent by history index and older history pages remain reachable.
#[derive(Debug, Clone)]
pub(super) struct DisplayedHistory {
    pub(super) peer: PublicKey,
    /// Whether the latest history window load (`load_history` / `show_history`) succeeded.
    pub(super) history_loaded: bool,
    /// Oldest history index boundary loaded so far (`0` means the start of history is reached).
    pub(super) loaded_start: u64,
    /// Displayed entries whose unread/receipt state has not yet been acknowledged on screen.
    pub(super) pending_entries: Vec<DisplayedEntry>,
}

/// Tracks the latest requested chat open/close generation and target peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct OpenTracker {
    generation: u64,
    target: Option<PublicKey>,
    /// If the previous target generation was invalidated by deleting that peer (rather than by a
    /// newer navigation), record that generation so its queued `Engine::open` returns
    /// [`super::OpenOutcome::Ignored`] and reconciles browser history instead of leaving the list
    /// on a deleted chat entry.
    deleted_generation: Option<u64>,
}

impl OpenTracker {
    pub(super) fn begin_open(&mut self, peer: PublicKey) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.target = Some(peer);
        self.deleted_generation = None;
        self.generation
    }

    pub(super) fn close(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.target = None;
        self.deleted_generation = None;
    }

    pub(super) fn is_current(&self, generation: u64) -> bool {
        self.generation == generation
    }

    pub(super) fn was_deleted(&self, generation: u64) -> bool {
        self.deleted_generation == Some(generation)
    }

    pub(super) fn is_settled_on(&self, displayed: Option<PublicKey>, peer: PublicKey) -> bool {
        displayed == Some(peer) && self.target == Some(peer)
    }

    pub(super) fn invalidate_peer(&mut self, peer: PublicKey) {
        if self.target == Some(peer) {
            let invalidated = self.generation;
            self.generation = self.generation.wrapping_add(1);
            self.target = None;
            self.deleted_generation = Some(invalidated);
        }
    }
}

/// Currently displayed chat tracking: open/close generation tracker, displayed history window for
/// idempotent read receipts, per-row reactive signals, and monotonic deleted-peer sequence counter.
#[derive(Default)]
pub(super) struct OpenChatState {
    /// Monotonic generation and target peer (`None` for chat list) for [`super::Engine::open`],
    /// [`super::Engine::close_chat`], and open-chat deletion.
    open_tracker: Cell<OpenTracker>,
    /// Exact set of history entries currently rendered on screen for the open chat.
    displayed_history: RefCell<Option<DisplayedHistory>>,
    /// Per-row reactive signals for the currently displayed chat, enabling O(1) delivery and
    /// remote-attachment updates without scanning `ui.messages` per row.
    displayed_rows: RefCell<DisplayedRows>,
    /// Monotonic counter tagging `Ui::deleted_peer` notifications.
    deleted_peer_seq: Cell<u64>,
}

impl OpenChatState {
    pub(super) fn tracker(&self) -> OpenTracker {
        self.open_tracker.get()
    }

    pub(super) fn begin_open(&self, peer: PublicKey) -> u64 {
        let mut tracker = self.open_tracker.get();
        let generation = tracker.begin_open(peer);
        self.open_tracker.set(tracker);
        generation
    }

    pub(super) fn cancel_pending_open(&self) {
        let mut tracker = self.open_tracker.get();
        tracker.close();
        self.open_tracker.set(tracker);
    }

    pub(super) fn is_settled_on(&self, displayed_open: Option<PublicKey>, peer: PublicKey) -> bool {
        self.open_tracker.get().is_settled_on(displayed_open, peer)
            && self.is_history_loaded_for(peer)
    }

    pub(super) fn is_history_loaded_for(&self, peer: PublicKey) -> bool {
        self.displayed_history
            .borrow()
            .as_ref()
            .is_some_and(|d| d.peer == peer && d.history_loaded)
    }

    pub(super) fn loaded_start_for(&self, peer: PublicKey) -> Option<u64> {
        self.displayed_history
            .borrow()
            .as_ref()
            .filter(|d| d.peer == peer && d.history_loaded)
            .map(|d| d.loaded_start)
    }

    pub(super) fn set_displayed_history(&self, history: DisplayedHistory) {
        *self.displayed_history.borrow_mut() = Some(history);
    }

    pub(super) fn extend_earlier_history(
        &self,
        peer: PublicKey,
        loaded_start: u64,
        entries: Vec<DisplayedEntry>,
    ) {
        if let Some(displayed) = self
            .displayed_history
            .borrow_mut()
            .as_mut()
            .filter(|d| d.peer == peer)
        {
            displayed.loaded_start = loaded_start;
            displayed.pending_entries.extend(entries);
        }
    }

    pub(super) fn record_displayed_entries(&self, peer: &PublicKey, entries: &[DisplayedEntry]) {
        if entries.is_empty() {
            return;
        }
        let mut slot = self.displayed_history.borrow_mut();
        let displayed = match slot.as_mut().filter(|d| d.peer == *peer) {
            Some(d) => d,
            None => slot.insert(DisplayedHistory {
                peer: *peer,
                history_loaded: false,
                loaded_start: 0,
                pending_entries: Vec::new(),
            }),
        };
        displayed.pending_entries.extend_from_slice(entries);
    }

    pub(super) fn take_pending_entries(&self, peer: &PublicKey) -> Option<Vec<DisplayedEntry>> {
        let mut slot = self.displayed_history.borrow_mut();
        let displayed = slot.as_mut().filter(|d| d.peer == *peer)?;
        Some(std::mem::take(&mut displayed.pending_entries))
    }

    /// Clear `ui.messages` FIRST, then dispose every per-row reactive signal owned by the previous
    /// chat so mounted Leptos views never observe disposed signals.
    pub(super) fn clear_displayed_messages(&self, ui: &Ui) {
        let _ = ui.messages.try_set(vec![]);
        let old = {
            let mut displayed = self.displayed_rows.borrow_mut();
            displayed.peer = None;
            std::mem::take(&mut displayed.rows)
        };
        for signals in old.into_values() {
            signals.dispose();
        }
    }

    /// Replace the displayed message list for `peer`, reusing existing per-row reactive signals on
    /// same-peer refreshes and disposing removed/old signals after updating `ui.messages`.
    pub(super) fn set_displayed_messages(
        &self,
        ui: &Ui,
        peer: PublicKey,
        views: Vec<MessageView>,
        open_peer: bool,
    ) {
        let mut displayed = self.displayed_rows.borrow_mut();
        let same_peer = displayed.peer == Some(peer);
        let mut old_rows = std::mem::take(&mut displayed.rows);
        let mut next_rows = HashMap::with_capacity(views.len());
        let mut rows = Vec::with_capacity(views.len());
        for view in views {
            if same_peer && let Some(existing) = old_rows.remove(&view.index) {
                if let Some(sig) = existing.delivery
                    && sig.get_untracked() != view.delivery
                {
                    sig.set(view.delivery);
                }
                if let Some(sig) = existing.remote_body
                    && sig.with_untracked(|current| *current != view.body)
                {
                    sig.set(view.body.clone());
                }
                let row = MessageRow {
                    index: view.index,
                    place: view.place,
                    outgoing: view.outgoing,
                    at: view.at,
                    body: view.body,
                    delivery: view.delivery,
                    delivery_signal: existing.delivery,
                    remote_body_signal: existing.remote_body,
                };
                next_rows.insert(
                    row.index,
                    RowSignals {
                        place: row.place,
                        delivery: existing.delivery,
                        remote_body: existing.remote_body,
                    },
                );
                rows.push(row);
            } else {
                let row = MessageRow::from_view(view);
                next_rows.insert(row.index, RowSignals::from_row(&row));
                rows.push(row);
            }
        }
        displayed.peer = Some(peer);
        displayed.rows = next_rows;
        drop(displayed);

        ui.messages.set(rows);
        if open_peer {
            ui.open.set(Some(peer));
        }
        for signals in old_rows.into_values() {
            signals.dispose();
        }
    }

    /// Register rows for an earlier history page without overwriting rows already displayed for
    /// `peer`, returning the newly created rows to merge into `ui.messages`.
    pub(super) fn register_earlier_rows(
        &self,
        peer: PublicKey,
        views: Vec<MessageView>,
    ) -> Vec<MessageRow> {
        let mut displayed = self.displayed_rows.borrow_mut();
        if displayed.peer != Some(peer) {
            displayed.peer = Some(peer);
            let old = std::mem::take(&mut displayed.rows);
            for signals in old.into_values() {
                signals.dispose();
            }
        }
        views
            .into_iter()
            .filter_map(|view| {
                if displayed.rows.contains_key(&view.index) {
                    None
                } else {
                    let row = MessageRow::from_view(view);
                    displayed.rows.insert(row.index, RowSignals::from_row(&row));
                    Some(row)
                }
            })
            .collect()
    }

    /// Upsert newly arrived/sent rows for `peer`, updating existing per-row signals in place and
    /// returning newly inserted rows to merge into `ui.messages`.
    pub(super) fn upsert_new_rows(
        &self,
        peer: PublicKey,
        views: Vec<MessageView>,
    ) -> Vec<MessageRow> {
        let mut displayed = self.displayed_rows.borrow_mut();
        if displayed.peer != Some(peer) {
            displayed.peer = Some(peer);
            let old = std::mem::take(&mut displayed.rows);
            for signals in old.into_values() {
                signals.dispose();
            }
        }
        views
            .into_iter()
            .filter_map(|view| {
                if let Some(existing) = displayed.rows.get_mut(&view.index) {
                    if let Some(sig) = existing.delivery
                        && sig.get_untracked() != view.delivery
                    {
                        sig.set(view.delivery);
                    }
                    if let Some(sig) = existing.remote_body
                        && sig.with_untracked(|current| *current != view.body)
                    {
                        sig.set(view.body);
                    }
                    None
                } else {
                    let row = MessageRow::from_view(view);
                    displayed.rows.insert(row.index, RowSignals::from_row(&row));
                    Some(row)
                }
            })
            .collect()
    }

    /// Apply delivery, remote-body, and `place` updates for `entries` in `peer`'s active chat,
    /// returning any `(index, new_place)` updates that require re-ordering `ui.messages`.
    pub(super) fn apply_row_changes(
        &self,
        peer: &PublicKey,
        contact: Option<&Contact>,
        entries: &[(u64, HistoryEntry)],
        server_now: u64,
    ) -> Vec<(u64, u64)> {
        let mut place_updates = Vec::new();
        let mut displayed = self.displayed_rows.borrow_mut();
        if displayed.peer != Some(*peer) {
            return place_updates;
        }
        for (index, entry) in entries {
            let Some(signals) = displayed.rows.get_mut(index) else {
                continue;
            };
            if entry.outgoing
                && let Some(sig) = signals.delivery
            {
                let next_delivery = entry.delivery();
                if sig.get_untracked() != next_delivery {
                    sig.set(next_delivery);
                }
            }
            if let Some(sig) = signals.remote_body
                && let Some(contact) = contact
            {
                let updated = contact.message_at(*index, entry.clone(), server_now).body;
                if sig.with_untracked(|current| *current != updated) {
                    sig.set(updated);
                }
            }
            if signals.place != entry.place {
                signals.place = entry.place;
                place_updates.push((*index, entry.place));
            }
        }
        place_updates
    }

    pub(super) fn close(&self, ui: &Ui) {
        self.cancel_pending_open();
        *self.displayed_history.borrow_mut() = None;
        ui.has_older_messages.set(false);
        ui.open.set(None);
        self.clear_displayed_messages(ui);
    }

    /// Invalidate open-chat state for a deleted `peer` (preserving queued opens targeting another
    /// peer) and emit a monotonic `Ui::deleted_peer` notification.
    pub(super) fn on_peer_deleted(&self, peer: PublicKey, ui: &Ui) {
        let mut tracker = self.open_tracker.get();
        tracker.invalidate_peer(peer);
        self.open_tracker.set(tracker);
        if self
            .displayed_history
            .borrow()
            .as_ref()
            .is_some_and(|d| d.peer == peer)
        {
            *self.displayed_history.borrow_mut() = None;
        }
        if ui.open.get_untracked() == Some(peer) {
            ui.has_older_messages.set(false);
            ui.open.set(None);
            self.clear_displayed_messages(ui);
        }
        let seq = self.deleted_peer_seq.get().wrapping_add(1).max(1);
        self.deleted_peer_seq.set(seq);
        ui.deleted_peer.set(Some((seq, peer)));
    }

    pub(super) fn clear_on_teardown(&self, ui: &Ui) {
        *self.displayed_history.borrow_mut() = None;
        self.cancel_pending_open();
        self.clear_displayed_messages(ui);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::content::Kind;
    use zeroize::Zeroizing;

    #[test]
    fn upload_registry_tracks_files_running_cancelled_and_teardown() {
        let reg = UploadRegistry::default();
        let peer_a = [0x11u8; 32];
        let peer_b = [0x22u8; 32];
        let id_a = [0xAAu8; 16];
        let id_b = [0xBBu8; 16];
        let hash = [0xCCu8; 32];

        reg.insert_file(
            (peer_a, id_a, hash),
            ChunkSource::from_bytes("a.bin", "application/octet-stream", vec![1, 2]),
        );
        reg.insert_file(
            (peer_b, id_b, hash),
            ChunkSource::from_bytes("b.bin", "application/octet-stream", vec![3, 4]),
        );
        assert!(reg.has_file(&peer_a, &id_a));
        assert!(reg.get_file(&(peer_a, id_a, hash)).is_some());

        assert!(reg.start_running(id_a));
        assert!(
            !reg.start_running(id_a),
            "duplicate start must return false"
        );
        assert!(reg.is_running(&id_a));
        assert!(reg.snapshot_running().contains(&id_a));
        reg.stop_running(&id_a);
        assert!(!reg.is_running(&id_a));

        reg.mark_cancelled(id_a);
        assert!(reg.is_cancelled(&id_a));
        assert!(!reg.is_cancelled(&id_b));

        reg.remove_peer_files(&peer_a);
        assert!(!reg.has_file(&peer_a, &id_a));
        assert!(reg.has_file(&peer_b, &id_b));

        reg.start_running(id_b);
        reg.clear_on_teardown();
        assert!(!reg.has_file(&peer_b, &id_b));
        assert!(!reg.is_running(&id_b));
        assert!(!reg.is_cancelled(&id_a));
    }

    #[test]
    fn media_streams_lru_eviction_single_flight_waiters_and_teardown() {
        let media = MediaStreams::default();
        let peer = [0x33u8; 32];
        let id = [0x44u8; 16];
        let hash = [0x55u8; 32];

        // Fill LRU cache up to CHUNKS_DECRYPTED_KEPT, touch index 0 so index 1 becomes oldest.
        for idx in 0..CHUNKS_DECRYPTED_KEPT as u32 {
            media.cache_decrypted(
                (peer, id, hash, idx),
                Rc::new(Zeroizing::new(vec![idx as u8])),
            );
        }
        assert_eq!(
            media
                .get_decrypted(&(peer, id, hash, 0))
                .map(|c| c.as_slice().to_vec()),
            Some(vec![0])
        );
        // Inserting one more chunk evicts index 1 (not index 0, which was promoted to MRU).
        media.cache_decrypted(
            (peer, id, hash, CHUNKS_DECRYPTED_KEPT as u32),
            Rc::new(Zeroizing::new(vec![99])),
        );
        assert!(media.get_decrypted(&(peer, id, hash, 0)).is_some());
        assert!(media.get_decrypted(&(peer, id, hash, 1)).is_none());

        // Single-flight loading: first caller owns load, second waits and wakes on finish_loading.
        let key = (peer, id, hash, 7);
        assert!(media.begin_or_wait_loading(key).is_none());
        let mut waiter = media
            .begin_or_wait_loading(key)
            .expect("second caller waits");
        assert!(waiter.try_recv().ok().flatten().is_none());
        media.finish_loading(&key);
        assert!(
            waiter.try_recv().is_err(),
            "dropping senders must wake waiter"
        );

        // Teardown clears cache and wakes any inflight waiters.
        let key2 = (peer, id, hash, 8);
        assert!(media.begin_or_wait_loading(key2).is_none());
        let mut waiter2 = media.begin_or_wait_loading(key2).expect("waiter");
        media.clear_on_teardown();
        assert!(media.get_decrypted(&(peer, id, hash, 0)).is_none());
        assert!(waiter2.try_recv().is_err());
    }

    #[test]
    fn send_queue_weak_flush_lock_raii_pruning_backoff_and_teardown() {
        let queue = SendQueue::default();
        let peer_a = [0xAAu8; 32];
        let peer_b = [0xBBu8; 32];

        // RAII Weak flush lock upgrades across overlapping holders and prunes only once all drop.
        {
            let lock1 = queue.peer_flush_lock(&peer_a);
            assert_eq!(queue.peer_flush_lock_strong_count(&peer_a), Some(1));
            queue.prune_peer_flush_lock(&peer_a);
            assert_eq!(
                queue.peer_flush_lock_strong_count(&peer_a),
                Some(1),
                "prune must not remove a live Weak entry"
            );
            {
                let lock2 = queue.peer_flush_lock(&peer_a);
                assert_eq!(queue.peer_flush_lock_strong_count(&peer_a), Some(2));
                drop(lock2);
            }
            assert_eq!(queue.peer_flush_lock_strong_count(&peer_a), Some(1));
            drop(lock1);
        }
        assert!(
            !queue.has_peer_flush_lock(&peer_a),
            "dropping final PeerFlushLock must auto-prune the Weak entry"
        );

        // Exponential approval backoff ladder: 15s -> 30s -> 60s -> 300s -> 300s.
        assert!(!queue.is_approval_backed_off(&peer_a));
        assert_eq!(queue.record_approval_backoff(&peer_a), 15_000);
        assert!(queue.is_approval_backed_off(&peer_a));
        assert_eq!(queue.record_approval_backoff(&peer_a), 30_000);
        assert_eq!(queue.record_approval_backoff(&peer_a), 60_000);
        assert_eq!(queue.record_approval_backoff(&peer_a), 300_000);
        assert_eq!(queue.record_approval_backoff(&peer_a), 300_000);
        queue.clear_approval_backoff(&peer_a);
        assert!(!queue.is_approval_backed_off(&peer_a));

        // FIFO enqueue / draining / wake / teardown.
        assert!(queue.enqueue(Sending::Content(peer_a, Kind::Text("1".into()))));
        assert!(!queue.enqueue(Sending::Content(peer_b, Kind::Text("2".into()))));
        queue.request_wake();
        assert!(queue.take_wake());
        assert!(!queue.take_wake());
        queue.mark_waits_sign_in(peer_a);
        assert!(queue.waits_for_sign_in(&peer_a));
        let _held = queue.peer_flush_lock(&peer_b);
        queue.request_wake();
        queue.record_approval_backoff(&peer_b);

        queue.clear_on_teardown();
        assert!(queue.pop_front().is_none());
        assert!(!queue.take_wake());
        assert!(!queue.waits_for_sign_in(&peer_a));
        assert!(!queue.is_approval_backed_off(&peer_b));
        assert!(queue.peer_flush_locks_is_empty());
        queue.finish_draining();
    }

    #[test]
    fn startup_flow_unlock_guard_refcounted_submissions_publish_pause_and_teardown() {
        let startup = StartupFlow::default();

        // Single-unlock RAII guard prevents overlapping unlocks and releases on drop.
        {
            let _guard = startup.try_begin_unlock().expect("first unlock acquires");
            assert!(startup.try_begin_unlock().is_none());
        }
        assert!(startup.try_begin_unlock().is_some());

        // Publish-wait pause flags and clock-skew dedup.
        assert!(!startup.is_publish_paused());
        startup.set_publish_waits_sign_in(true);
        assert!(startup.is_publish_paused());
        startup.set_publish_waits_settings(true);
        startup.on_publish_succeeded();
        assert!(!startup.is_publish_paused());

        assert!(startup.mark_clock_skew_warned());
        assert!(!startup.mark_clock_skew_warned());
        startup.clear_clock_skew_warned();
        assert!(startup.mark_clock_skew_warned());

        // Ref-counted live submissions keep cancellation active until the last task finishes.
        let draft = PendingNewChat {
            key: "peer".into(),
            name: "Peer".into(),
            server: None,
            pq_pinned: false,
            allow_classical: false,
            auto_start: true,
        };
        let id = startup.begin_new_chat_submit(draft);
        startup.begin_sign_in_auto_start(id);
        startup.set_in_flight_start_chat(id, false);
        startup.set_publish_waits_settings(true);
        startup.clear_on_teardown();

        assert!(
            startup.is_submission_cancelled(id),
            "teardown must cancel active startup submissions"
        );
        assert!(!startup.is_publish_paused());
        assert!(startup.mark_clock_skew_warned());
        // First task finishes -> second overlapping task still observes cancellation.
        startup.finish_submission(id);
        assert!(startup.is_submission_cancelled(id));
        // Second task finishes -> tombstone is pruned cleanly.
        startup.finish_submission(id);
        assert!(!startup.is_submission_cancelled(id));
    }

    #[test]
    fn open_chat_state_tracks_navigation_delete_signals_and_teardown() {
        let ui = Ui::new();
        let open_chat = OpenChatState::default();
        let peer_a = [0x11u8; 32];
        let peer_b = [0x22u8; 32];

        let gen_a = open_chat.begin_open(peer_a);
        assert!(open_chat.tracker().is_current(gen_a));
        open_chat.set_displayed_history(DisplayedHistory {
            peer: peer_a,
            history_loaded: true,
            loaded_start: 10,
            pending_entries: vec![],
        });
        assert_eq!(open_chat.loaded_start_for(peer_a), Some(10));

        let view = MessageView {
            index: 0,
            place: 1,
            outgoing: true,
            at: 100,
            body: Body::Text("hello".into()),
            delivery: Delivery::Pending,
        };
        open_chat.set_displayed_messages(&ui, peer_a, vec![view], true);
        assert!(open_chat.is_settled_on(ui.open.get_untracked(), peer_a));

        // Deleting peer_b does NOT invalidate peer_a's open tracker or history, but bumps seq.
        open_chat.on_peer_deleted(peer_b, &ui);
        assert!(open_chat.tracker().is_current(gen_a));
        assert!(open_chat.is_settled_on(ui.open.get_untracked(), peer_a));
        assert_eq!(ui.deleted_peer.get_untracked(), Some((1, peer_b)));

        // Deleting peer_a invalidates gen_a, clears ui.open/messages, and bumps seq monotonically.
        open_chat.on_peer_deleted(peer_a, &ui);
        assert!(open_chat.tracker().was_deleted(gen_a));
        assert!(!open_chat.is_history_loaded_for(peer_a));
        assert_eq!(ui.open.get_untracked(), None);
        assert!(ui.messages.with_untracked(Vec::is_empty));
        assert_eq!(ui.deleted_peer.get_untracked(), Some((2, peer_a)));

        // Teardown invalidates any queued open and scrubs displayed history & rows.
        let gen_b = open_chat.begin_open(peer_b);
        open_chat.set_displayed_history(DisplayedHistory {
            peer: peer_b,
            history_loaded: true,
            loaded_start: 0,
            pending_entries: vec![],
        });
        open_chat.clear_on_teardown(&ui);
        assert!(!open_chat.tracker().is_current(gen_b));
        assert!(!open_chat.is_history_loaded_for(peer_b));
        assert!(ui.messages.with_untracked(Vec::is_empty));
    }
}
